// SPDX-License-Identifier: GPL-2.0-only
/*
 * srcdynroute -- nftables expressions for dynamic per-direction source routing.
 *
 * Kernel: 6.12.111 with the in-tree extensions P1..P5 (see README.md,
 * ops-inversion design):
 *
 *   P1  NF_CT_EXT_SRC_DYN_RT in enum nf_ct_ext_id (+ struct src_dyn_rt_slot/ext
 *       ABI in include/net/netfilter/dynrt.h);
 *   P2  built-in helper net/netfilter/nf_dynrt.c: RCU ops pointer,
 *       zero conntrack symbols, wrappers dynrt_force_oif_skb/fl4/fl6,
 *       dynrt_force_mac, dynrt_register/unregister;
 *   P3/P4  FIB oif forcing in net/ipv4/route.c, net/ipv6/route.c;
 *   P5  neighbour L2 override in net/core/neighbour.c.
 *
 * This module (P6) is the *only* component that may reference conntrack
 * symbols.  It provides two nftables expressions and the dynrt_ops table:
 *
 *   DYNSRCROUTE  (target)
 *       Determine the packet direction D w.r.t. its conntrack entry and
 *       store in the "opposite" slot D^1 of the NF_CT_EXT_SRC_DYN_RT
 *       conntrack extension the routing record for that opposite
 *       direction: egress ifindex and, when available, the peer L2
 *       address (h_source).  Slot is overwritten if already present
 *       (report §3.2).  Additionally, the reverse flow (in packet
 *       order) is anchored in a small in-module TTL table, so the FIB
 *       (flowi-only) ops can still force the egress for protocols
 *       whose conntrack identity is not determined by the flowi
 *       (ICMP echo id/type), and the neighbour L2 override can still
 *       supply the stored peer address for flows that have no usable
 *       conntrack entry at all (raw ICMP on a kernel without the ICMP
 *       conntrack protocol) -- see the anchor table below.
 *
 *   DYNRT        (match)
 *       Check that a valid routing record exists for the current packet
 *       direction D (slot[D]); on a negative verdict emit NFT_BREAK so
 *       that the current rule evaluation stops (nft_ct.c idiom, 6.12).
 *
 *   ops table    (dynrt_ops from dynrt.h)
 *       oif_skb / oif_fl4 / oif_fl6: the FIB funnels (P3/P4) ask "which
 *       ifindex to force for this packet/flow"; the module resolves the
 *       ct + direction and returns slot[dir].ifindex, or 0 to fall back
 *       to the plain lookup.
 *       mac: neighbour code (P5) asks for an L2 override; the module
 *       returns a per-CPU copy of slot[dir].hw (see dynrt_mac_buf) --
 *       or, when no conntrack entry with a valid slot exists (e.g.
 *       conntrack-less ICMP on this kernel), a per-CPU copy of the
 *       anchor's hw -- or NULL to run the ordinary ARP/ND path.
 *
 * Direction algebra (dynrt.h, report §3.2):
 *   writer packet dir D  -> writes  slot[D ^ 1]
 *   reader packet dir R  -> reads   slot[R]
 *
 * Lifetime note: every conntrack reference taken here is dropped before
 * the function returns.  dynrt_ops::mac() therefore *cannot* return a
 * pointer into the conntrack extension: the module copies the peer MAC
 * into the per-CPU buffer dynrt_mac_buf and returns a pointer to that.
 * It is valid until the next dynrt_ops::mac() call from the same CPU;
 * the only consumer is the neighbour wrapper (dev_hard_header
 * immediately after the call).
 *
 * Load order does not matter: when the module is not loaded, P2 wrapper
 * pointers are NULL (no-op) and the nft expression lookup simply fails
 * with ENOENT.
 */

#include <linux/module.h>
#include <linux/etherdevice.h>	/* ETH_P_IP, ETH_P_IPV6 */
#include <linux/in.h>		/* IPPROTO_ICMP */
#include <linux/ipv6.h>		/* IPPROTO_ICMPV6 */
#include <linux/ktime.h>
#include <linux/percpu.h>
#include <linux/skbuff.h>
#include <linux/string.h>
#include <linux/timer.h>
#include <linux/netfilter.h>	/* struct nf_hook_state */
#include <net/flow.h>		/* struct flowi4 / flowi6 */
#include <net/netfilter/dynrt.h>
#include <net/netfilter/nf_tables.h>
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_tuple.h>
#include <net/netfilter/nf_conntrack_core.h>
#include <net/netfilter/nf_conntrack_extend.h>
#include <linux/netfilter/nf_conntrack_zones_common.h>

#define pr_fmt(fmt) "srcdynroute: " fmt

/* -----------------------------------------------------------------------
 * Per-CPU storage for the pointer returned by dynrt_ops::mac().
 *
 * The module may not return ct->ext memory (see the file header).  A
 * per-CPU 8-byte buffer is enough: struct src_dyn_rt_slot.hw is 8 bytes.
 * --------------------------------------------------------------------- */
static DEFINE_PER_CPU(u8[8], dynrt_mac_buf);

/* -----------------------------------------------------------------------
 * Direction and conntrack lookup helpers.
 * --------------------------------------------------------------------- */

/*
 * Return the conntrack direction of the packet/flow that is identified by
 * tuple @t (in packet order, src/dst as on the wire).  nf_ct_tuple_equal()
 * ignores the .dir field, so both tuple hashes must be compared manually
 * (6.12 has no nf_ct_key_equal()).
 *
 * Returns IP_CT_DIR_MAX when @t matches neither hash (ambiguous: the
 * caller has to treat the packet as unresolvable).
 */
static enum ip_conntrack_dir
dynrt_dir_of(const struct nf_conn *ct, const struct nf_conntrack_tuple *t)
{
	if (nf_ct_tuple_equal(t, &ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple))
		return IP_CT_DIR_ORIGINAL;
	if (nf_ct_tuple_equal(t, &ct->tuplehash[IP_CT_DIR_REPLY].tuple))
		return IP_CT_DIR_REPLY;
	return IP_CT_DIR_MAX;
}

#define dynrt_ct_put_owned(ct, owned)				\
do {								\
	if (owned)						\
		nf_ct_put(ct);					\
} while (0)

/*
 * Resolve the layer-3 family of the packet from skb->protocol, with a
 * 4/6 version-nibble fallback.  Returns AF_INET / AF_INET6, or 0 when it
 * cannot be determined (all callers then make the operation a no-op).
 */
static unsigned int dynrt_skb_l3num(const struct sk_buff *skb)
{
	const u8 *nh;

	if (skb->protocol == htons(ETH_P_IP))
		return AF_INET;
	if (skb->protocol == htons(ETH_P_IPV6))
		return AF_INET6;

	nh = skb_header_pointer(skb, skb_network_offset(skb), 1, NULL);
	if (nh) {
		unsigned int v = *nh >> 4;

		if (v == 4)
			return AF_INET;
		if (v == 6)
			return AF_INET6;
	}
	return 0;
}

/*
 * Same as dynrt_skb_l3num(), but from the nftables pktinfo.
 * Prefer the hook family when it is a real IP family; fall back to the
 * packet contents (covers NFPROTO_BRIDGE hooks etc.).
 */
static unsigned int dynrt_pktinfo_l3num(const struct nft_pktinfo *pkt)
{
	unsigned int pf = nft_pf(pkt);

	if (pf == NFPROTO_IPV4)
		return AF_INET;
	if (pf == NFPROTO_IPV6)
		return AF_INET6;
	return dynrt_skb_l3num(pkt->skb);
}

/*
 * Find the conntrack entry for the packet and the direction the packet
 * belongs to.  On success, set *ct_out / *dir_out / *owned_out.
 *
 *  - attached, non-template ct (nft_ct.c model): use as-is, do not take
 *    a reference (its lifetime is tied to the skb/sk that is still
 *    valid for the whole hook invocation).
 *  - otherwise: resolve with nf_ct_get_tuplepr() +
 *    nf_conntrack_find_get() (default zone), take the reference
 *    (nf_ct_put() when done), set *owned_out = true.
 */
static bool
dynrt_ct_dir_skb(const struct sk_buff *skb, unsigned int l3num,
		 struct net *net, struct nf_conn **ct_out,
		 enum ip_conntrack_dir *dir_out, bool *owned_out)
{
	struct nf_conn *ct;
	enum ip_conntrack_info ctinfo;
	struct nf_conntrack_tuple tuple;
	struct nf_conntrack_tuple_hash *h;
	enum ip_conntrack_dir dir;

	*ct_out   = NULL;
	*dir_out  = IP_CT_DIR_MAX;
	*owned_out = false;

	if (!nf_ct_get_tuplepr(skb, skb_network_offset(skb), l3num, net,
			       &tuple))
		return false;

	ct = nf_ct_get(skb, &ctinfo);
	if (ct && !nf_ct_is_template(ct)) {
		dir = dynrt_dir_of(ct, &tuple);
		if (dir == IP_CT_DIR_MAX)
			return false;
		*ct_out  = ct;
		*dir_out = dir;
		return true;
	}

	h = nf_conntrack_find_get(net, &nf_ct_zone_dflt, &tuple);
	if (!h)
		return false;

	ct = nf_ct_tuplehash_to_ctrack(h);
	*owned_out = true;

	dir = dynrt_dir_of(ct, &tuple);
	if (dir == IP_CT_DIR_MAX) {
		dynrt_ct_put_owned(ct, *owned_out);
		*owned_out = false;
		return false;
	}
	*ct_out  = ct;
	*dir_out = dir;
	return true;
}

/*
 * Acquire the conntrack entry for the packet WITHOUT requiring a
 * resolvable direction.  After nf_ct_invert_tuplehash() at REPLY time,
 * or when the (NAT-inverted) wire tuple matches neither stored tuple
 * hash any more, dynrt_dir_of() yields IP_CT_DIR_MAX and the strict
 * readers give up -- but the connection is still the right one: the
 * slot written by DYNSRCROUTE lives somewhere in this ct's ext area.
 * Combine with dynrt_slot_pick() on the reader side.
 */
static bool
dynrt_ct_acquire(const struct sk_buff *skb, unsigned int l3num,
		 struct net *net, struct nf_conn **ct_out,
		 bool *owned_out)
{
	struct nf_conn *ct;
	enum ip_conntrack_info ctinfo;
	struct nf_conntrack_tuple tuple;
	struct nf_conntrack_tuple_hash *h;

	*ct_out    = NULL;
	*owned_out = false;

	if (!nf_ct_get_tuplepr(skb, skb_network_offset(skb), l3num, net,
			       &tuple))
		return false;

	ct = nf_ct_get(skb, &ctinfo);
	if (ct && !nf_ct_is_template(ct)) {
		*ct_out = ct;
		return true;
	}

	h = nf_conntrack_find_get(net, &nf_ct_zone_dflt, &tuple);
	if (!h)
		return false;

	ct = nf_ct_tuplehash_to_ctrack(h);
	*ct_out    = ct;
	*owned_out = true;
	return true;
}

/* flowi4 -> 5-tuple in packet order -> find ct + direction. */
static bool
dynrt_ct_dir_fl4(struct net *net, const struct flowi4 *fl4,
		 struct nf_conn **ct_out, enum ip_conntrack_dir *dir_out)
{
	struct nf_conntrack_tuple tuple = { 0 };
	struct nf_conntrack_tuple_hash *h;
	struct nf_conn *ct;

	tuple.src.l3num = AF_INET;
	tuple.src.u3.ip = fl4->saddr;
	tuple.src.u.udp.port = fl4->fl4_sport;
	tuple.dst.u3.ip = fl4->daddr;
	tuple.dst.u.udp.port = fl4->fl4_dport;
	tuple.dst.protonum = fl4->flowi4_proto;

	h = nf_conntrack_find_get(net, &nf_ct_zone_dflt, &tuple);
	if (!h)
		return false;

	ct = nf_ct_tuplehash_to_ctrack(h);          /* ref taken */
	if (dynrt_dir_of(ct, &tuple) == IP_CT_DIR_MAX) {
		nf_ct_put(ct);
		return false;
	}
	*ct_out  = ct;                              /* caller must nf_ct_put */
	*dir_out = dynrt_dir_of(ct, &tuple);
	return true;
}

static bool
dynrt_ct_dir_fl6(struct net *net, const struct flowi6 *fl6,
		 struct nf_conn **ct_out, enum ip_conntrack_dir *dir_out)
{
	struct nf_conntrack_tuple tuple = { 0 };
	struct nf_conntrack_tuple_hash *h;
	struct nf_conn *ct;

	tuple.src.l3num = AF_INET6;
	tuple.src.u3.in6 = fl6->saddr;
	tuple.src.u.udp.port = fl6->fl6_sport;
	tuple.dst.u3.in6 = fl6->daddr;
	tuple.dst.u.udp.port = fl6->fl6_dport;
	tuple.dst.protonum = fl6->flowi6_proto;

	h = nf_conntrack_find_get(net, &nf_ct_zone_dflt, &tuple);
	if (!h)
		return false;

	ct = nf_ct_tuplehash_to_ctrack(h);          /* ref taken */
	if (dynrt_dir_of(ct, &tuple) == IP_CT_DIR_MAX) {
		nf_ct_put(ct);
		return false;
	}
	*ct_out  = ct;                              /* caller must nf_ct_put */
	*dir_out = dynrt_dir_of(ct, &tuple);
	return true;
}

/* flowi4 -> 5-tuple in packet order -> find ct (no direction required). */
static bool
dynrt_ct_acquire_fl4(struct net *net, const struct flowi4 *fl4,
		     struct nf_conn **ct_out)
{
	struct nf_conntrack_tuple tuple = { 0 };
	struct nf_conntrack_tuple_hash *h;

	tuple.src.l3num = AF_INET;
	tuple.src.u3.ip = fl4->saddr;
	tuple.src.u.udp.port = fl4->fl4_sport;
	tuple.dst.u3.ip = fl4->daddr;
	tuple.dst.u.udp.port = fl4->fl4_dport;
	tuple.dst.protonum = fl4->flowi4_proto;

	h = nf_conntrack_find_get(net, &nf_ct_zone_dflt, &tuple);
	if (!h)
		return false;

	*ct_out = nf_ct_tuplehash_to_ctrack(h);	/* ref taken, caller puts */
	return true;
}

/* flowi6 -> 5-tuple in packet order -> find ct (no direction required). */
static bool
dynrt_ct_acquire_fl6(struct net *net, const struct flowi6 *fl6,
		     struct nf_conn **ct_out)
{
	struct nf_conntrack_tuple tuple = { 0 };
	struct nf_conntrack_tuple_hash *h;

	tuple.src.l3num = AF_INET6;
	tuple.src.u3.in6 = fl6->saddr;
	tuple.src.u.udp.port = fl6->fl6_sport;
	tuple.dst.u3.in6 = fl6->daddr;
	tuple.dst.u.udp.port = fl6->fl6_dport;
	tuple.dst.protonum = fl6->flowi6_proto;

	h = nf_conntrack_find_get(net, &nf_ct_zone_dflt, &tuple);
	if (!h)
		return false;

	*ct_out = nf_ct_tuplehash_to_ctrack(h);	/* ref taken, caller puts */
	return true;
}

/* -----------------------------------------------------------------------
 * Slot access / write.
 * --------------------------------------------------------------------- */

static bool
dynrt_slot_valid(const struct src_dyn_rt_slot *slot)
{
	return slot != NULL && (slot->flags & SRC_DYN_RT_SLOT_VALID);
}

/*
 * Direction-tolerant slot pick (reader side).
 *
 * Slot indexes are relative to the *uninverted* ct: DYNSRCROUTE on a
 * packet of direction D writes the reverse-side route into slot[D ^ 1].
 * By the time the reverse-direction packet reaches a FIB/peer hook the
 * ct may have been inverted (nf_ct_invert_tuplehash() at REPLY time), or
 * its wire tuple may not resolve to any stored direction at all
 * (NAT-inverted reply), so the reader's direction can disagree with the
 * index the record actually sits at -- or be IP_CT_DIR_MAX.  Precede
 * with the packet's direction when it resolved; otherwise fall back to
 * any valid slot.
 */
static struct src_dyn_rt_slot *
dynrt_slot_pick(const struct nf_conn *ct, enum ip_conntrack_dir dir)
{
	struct src_dyn_rt_ext *ext =
		nf_ct_ext_find(ct, NF_CT_EXT_SRC_DYN_RT);

	if (!ext)
		return NULL;

	if (dir != IP_CT_DIR_MAX && dynrt_slot_valid(&ext->slot[dir]))
		return &ext->slot[dir];
	if (dynrt_slot_valid(&ext->slot[IP_CT_DIR_ORIGINAL]))
		return &ext->slot[IP_CT_DIR_ORIGINAL];
	if (dynrt_slot_valid(&ext->slot[IP_CT_DIR_REPLY]))
		return &ext->slot[IP_CT_DIR_REPLY];
	return NULL;
}

/*
 * Return the slot for writing.  Creates the extension when it does not
 * exist yet.  @ct must be held (attached or ref'ed) for the duration of
 * the call -- cf. nf_ct_get_tuplepr()/find_get above.
 *
 * The extension is *only* created for unconfirmed connections:
 * nf_ct_ext_add() does WARN_ON(nf_ct_is_confirmed()) and would risk a
 * realloc race on live traffic.  Writing into an already created slot
 * is fine in both (the pointer is stable in the ct's ext area, and the
 * ct itself is what we hold).
 */
static struct src_dyn_rt_slot *
dynrt_slot_for_write(struct nf_conn *ct, unsigned int dir)
{
	struct src_dyn_rt_ext *ext;

	ext = (struct src_dyn_rt_ext *)nf_ct_ext_find(ct,
						       NF_CT_EXT_SRC_DYN_RT);
	if (ext)
		return &ext->slot[dir];

	if (nf_ct_is_confirmed(ct)) {
		pr_debug("ct already confirmed; refuse nf_ct_ext_add()\n");
		return NULL;
	}

	ext = (struct src_dyn_rt_ext *)
		nf_ct_ext_add(ct, NF_CT_EXT_SRC_DYN_RT, GFP_ATOMIC);
	if (!ext) {
		pr_debug("nf_ct_ext_add() failed (OOM or already present)\n");
		return NULL;
	}
	return &ext->slot[dir];
}

/* -----------------------------------------------------------------------
 * Anchor table (flowi-level fallback for FIB egress forcing *and*
 * conntrack-less L2 override).
 *
 * dynrt_op_oif_fl4()/oif_fl6() see only a struct flowi.  For protocols
 * whose conntrack tuple carries identity *beyond* the flowi -- ICMPv4
 * echo: the packet id lands in tuple src.u.icmp.id and the type/code
 * in dst.u; ICMPv6 keeps type/code in dst.u as well -- the handcrafted
 * 5-tuple built from the flowi can never match the stored tuple: 6.12
 * hashes (siphash over the raw tuple bytes up to
 * dst.__nfct_hash_offsetend) and compares those very bytes, and the
 * echo id is *not* part of any flowi (icmp echoes are generated by
 * icmp_reply() with flowi4 carrying no id).  nf_conntrack_find_get()
 * therefore cannot find an ICMP connection from the flowi alone, and
 * the ct-slot path cannot force ICMP echo replies back onto the
 * request ingress interface.  (TCP/UDP tuples are fully determined by
 * the flowi and resolve correctly.)
 *
 * Fallback: whenever DYNSRCROUTE fires it additionally records the
 * *reverse* flow in packet order -- (l3num, proto, saddr, daddr, L4
 * ports for TCP/UDP, 0/0 for ICMP/ICMPv6) -- with the forced egress
 * ifindex *and, when available, the peer L2 address* in a small TTL
 * table.  The FIB ops consult that table
 * whenever the ct-slot path has no answer, and dynrt_op_mac() uses
 * the stored L2 as a last resort when no conntrack entry at all
 * exists for the flow (a kernel whose conntrack hooks are not
 * registered never creates a ct for echo traffic, so the ct-slot path
 * alone can neither force the reply egress nor its L2).
 *
 * Protocol scope (B4, 2026-10-10; supersedes B1): the key now
 * carries the L4 ports for TCP/UDP (see dynrt_anchor_key_ports()),
 * so one entry covers exactly one 4-tuple + interface -- a fresh
 * management connection between the same two addresses can no longer
 * inherit a stored egress.  The table is therefore consulted, on the
 * read AND write side, for the eligible set: ICMP/ICMPv6 (pair-only,
 * ports forced to 0 -- the flowi never carries the echo id) and
 * TCP/UDP.  On the 6.12.111/ deb13 configuration plain TCP is
 * *required* to be eligible, not just allowed: the conntrack hooks
 * are registered lazily (nf_ct_netns_get(), only produced by
 * nftables `ct` / xt_* on that tree, none active here) and no ct is
 * created for the flow, so the ct-slot path -- primary whenever it
 * can resolve -- is structurally dead and the anchor is the carrier.
 * Protocols outside the set are slot-only (B1 policy, kept).
 *
 * Known limits, by design (report §6): several ICMP flows between the
 * same address pair (different echo ids) share one anchor entry -- the
 * flowi simply does not carry the id, so they cannot be told apart at
 * FIB time within one anchor TTL.  TCP/UDP entries are per-4-tuple
 * exact; a re-connect after the previous one closed allocates a fresh
 * ephemeral (TIME_WAIT on the closed socket blocks the kernel from
 * reusing the old one), so it does not inherit the stale record --
 * which is exactly what makes S8 b4 a clean discriminating NEG under
 * B4.  The ct-slot path stays primary and remains exact everywhere it
 * can resolve (kernels / configurations where the ct hooks are
 * registered).
 * --------------------------------------------------------------------- */

#define DYNRT_ANCHOR_MAX	128
#define DYNRT_ANCHOR_TTL_MS	60000

struct dynrt_anchor {
	struct list_head	next;	/* dynrt_anchor_list node */
	unsigned int	l3num;
	u8		proto;
	union nf_inet_addr	saddr;
	union nf_inet_addr	daddr;
	__be16		sport;	/* B4: key L4 ports, network order, stored
				 * in reply-flow packet order (reply src
				 * port first); 0/0 for ICMP/ICMPv6 */
	__be16		dport;
	u32		oif;		/* forced egress ifindex */
	u16		hwtype;	/* ARPHRD_* of stored L2 (0 = oif-only) */
	u8		hwlen;	/* stored L2 length, 0..8 (0 => oif-only) */
	u8		hw[8];	/* peer L2 address, from the *incoming* frame */
	ktime_t		expires;
	struct rcu_head	rcu;	/* kfree_rcu() deferred-free head (kept
				 * separate: kfree_rcu() needs an rcu_head
				 * member, list_del_rcu() a list_head) */
};

static LIST_HEAD(dynrt_anchor_list);
static DEFINE_SPINLOCK(dynrt_anchor_lock);
static unsigned int dynrt_anchor_count;
static struct timer_list dynrt_anchor_sweep;

/* Purge expired entries; caller holds dynrt_anchor_lock. */
static void dynrt_anchor_sweep_locked(void)
{
	struct dynrt_anchor *a, *tmp;

	list_for_each_entry_safe(a, tmp, &dynrt_anchor_list, next) {
		if (!ktime_before(ktime_get(), a->expires)) {
			list_del_rcu(&a->next);
			dynrt_anchor_count--;
			kfree_rcu(a, rcu);
		}
	}
}

static void dynrt_anchor_sweep_fn(struct timer_list *t)
{
	spin_lock_irq(&dynrt_anchor_lock);
	dynrt_anchor_sweep_locked();
	spin_unlock_irq(&dynrt_anchor_lock);

	/* Re-arm: timer_setup() armed this only once (init + 10 s).  A
	 * one-shot sweep leaves expired entries in the table for the
	 * lifetime of the module (they are still filtered on every read --
	 * cf. dynrt_anchor_lookup()/dynrt_anchor_mac() -- but they occupy
	 * the DYNRT_ANCHOR_MAX budget and delay victim eviction of LIVE
	 * entries).  Walking an empty list is one comparison; the periodic
	 * 10 s wake is the price of the simple invariant "the table is
	 * drained of expired entries at least every period". */
	mod_timer(&dynrt_anchor_sweep, jiffies + 10 * HZ);
}

/*
 * True when a lookup key address is the unspecified address
 * (0.0.0.0 / ::).  A locally-generated flow (raw ICMP, an unbound UDP
 * source, ...) performs its output lookup *before* the kernel picks a
 * source address (source selection is done after the FIB lookup), so the
 * flowi's saddr is still any/zero here.  The stored anchor's saddr, on
 * the other hand, is the concrete egress source learned from the inbound
 * packet, so an exact-byte compare would never match.  Treating a
 * lookup saddr of 0 as a wildcard (any stored saddr) closes that gap
 * without weakening the exact match for flows that already carry a
 * source (connected sockets, inbound replies).
 */
static bool
dynrt_anchor_saddr_unspec(const union nf_inet_addr *s)
{
	return !s->ip &&
	       !s->in6.s6_addr32[1] &&
	       !s->in6.s6_addr32[2] &&
	       !s->in6.s6_addr32[3];
}

/*
 * Protocol gate for the anchor table (B4, 2026-10-10; supersedes
 * B1's ICMP/ICMPv6-only read gate).
 *
 * B1 rationale, still true: a key without L4 ports matches ANY flow
 * between two pinned address pairs, so a fresh 4-tuple that never
 * went through the target must not inherit the stored egress for the
 * anchor TTL (the false S8 b4 "rescues" observed on 2026-10-10 at
 * +26 s and +81 s are exactly this).
 *
 * B4 change: the key now carries the L4 ports for TCP/UDP (see
 * dynrt_anchor_key_ports()), so the over-approximation disappears for
 * them and they are admitted.  TCP is *required* to be eligible, not
 * just allowed: on the 6.12.111 "standalone conntrack" refactor the
 * IPv4/IPv6 conntrack hooks are registered lazily by
 * nf_ct_netns_get() (net/netfilter/nf_conntrack_proto.c,
 * nf_ct_netns_do_get()) whose only producers are the nftables `ct`
 * expression, xt_* matches and friends -- none of which are active on
 * deb13, so the ct-slot path is structurally dead there for plain
 * TCP (probe 2026-10-10: a clean .67->.12:9977 TCP handshake completes
 * but /proc/net/nf_conntrack stays at 0 entries).  The anchor table is
 * the carrier for the reply leg in that configuration; exactness comes
 * from the ports, not from excluding the protocol.
 *
 * The gate now applies on BOTH sides:
 *   - read sites (dynrt_op_oif_skb/fl4/fl6, dynrt_op_mac, DYNRT match)
 *     consult the table only for eligible protocols;
 *   - the write site (dynrt_srcroute_eval) records only eligible
 *     protocols, so SCTP and friends never churn the
 *     DYNRT_ANCHOR_MAX budget with entries nothing can read.
 * Protocols outside the set keep the B1 slot-only policy.
 */
static bool dynrt_anchor_eligible(u8 proto)
{
	return proto == IPPROTO_ICMP ||
	       proto == IPPROTO_ICMPV6 ||
	       proto == IPPROTO_TCP ||
	       proto == IPPROTO_UDP;
}

/*
 * B4 key normalization, called only for eligible protocols.
 * TCP/UDP: the real L4 ports (network order, passed in by the caller --
 * flowi4->fl4_sport/fl4_dport, flowi6->fl6_sport/fl6_dport or the
 * nf_conntrack_tuple .u.udp.port fields -- already are network order,
 * no conversion).  ICMP/ICMPv6: the key ports are forced to 0/0 on BOTH
 * the read and the write side, which keeps today's byte-for-byte
 * per-pair semantics for echo traffic (the flowi carries no echo id).
 */
static inline void
dynrt_anchor_key_ports(u8 proto, __be16 *sport, __be16 *dport)
{
	switch (proto) {
	case IPPROTO_TCP:
	case IPPROTO_UDP:
		break;	/* keep the real ports */
	default:
		*sport = 0;
		*dport = 0;
	}
}

/* RCU-safe lookup, called from the FIB ops (see dynrt_op_oif_fl*).
 * @sport/@dport are the looked-up flow's own L4 ports in packet order
 * (src port first), already normalized by dynrt_anchor_key_ports().
 */
static u32
dynrt_anchor_lookup(unsigned int l3num, u8 proto,
		    const union nf_inet_addr *saddr,
		    const union nf_inet_addr *daddr,
		    __be16 sport, __be16 dport)
{
	struct dynrt_anchor *a;
	ktime_t now = ktime_get();
	u32 oif = 0;
	bool sw = dynrt_anchor_saddr_unspec(saddr);

	rcu_read_lock();
	list_for_each_entry_rcu(a, &dynrt_anchor_list, next) {
		if (a->l3num != l3num || a->proto != proto ||
		    (!sw && !nf_inet_addr_cmp(&a->saddr, saddr)) ||
		    !nf_inet_addr_cmp(&a->daddr, daddr) ||
		    a->sport != sport || a->dport != dport)
			continue;
		if (ktime_before(now, a->expires))
			oif = a->oif;
		break;
	}
	rcu_read_unlock();

	return oif;
}

/* RCU-safe lookup of the stored peer L2 for conntrack-less flows,
 * called from dynrt_op_mac().  Same key (in packet order, i.e. exactly
 * the reply-side tuple) as dynrt_anchor_lookup(); returns a valid stored
 * L2 of the right type/length as a pointer into the per-CPU copy buffer
 * (lifetime: valid until the next mac() call from the same CPU, cf.
 * dynrt.h ops::mac contract), or NULL.
 */
static const u8 *
dynrt_anchor_mac(unsigned int l3num, u8 proto,
		 const union nf_inet_addr *saddr,
		 const union nf_inet_addr *daddr,
		 __be16 sport, __be16 dport,
		 const struct net_device *dev)
{
	struct dynrt_anchor *a;
	ktime_t now = ktime_get();
	bool sw = dynrt_anchor_saddr_unspec(saddr);
	const u8 *ret = NULL;

	rcu_read_lock();
	list_for_each_entry_rcu(a, &dynrt_anchor_list, next) {
		if (a->l3num != l3num || a->proto != proto ||
		    (!sw && !nf_inet_addr_cmp(&a->saddr, saddr)) ||
		    !nf_inet_addr_cmp(&a->daddr, daddr) ||
		    a->sport != sport || a->dport != dport)
			continue;
		if (ktime_before(now, a->expires) &&
		    a->hwlen > 0 &&
		    a->hwlen == dev->addr_len &&
		    a->hwtype == dev->type) {
			u8 *buf = get_cpu_var(dynrt_mac_buf);

			memcpy(buf, a->hw, a->hwlen);
			put_cpu_var(dynrt_mac_buf);
			ret = buf;
		}
		break;
	}
	rcu_read_unlock();

	return ret;
}

/*
 * Record / refresh the anchor of the *reverse* flow of a packet given
 * in packet order @saddr -> @daddr, @sport -> @dport (both stored
 * swapped, i.e. exactly as the reverse-flow / reply 5-tuple would look;
 * for ICMP/ICMPv6 both port arguments are 0, cf.
 * dynrt_anchor_key_ports()).  @hwtype/@hwlen/@hw carry the peer L2 of
 * the incoming frame (0/0/{} when it cannot be determined); the entry
 * degrades to an oif-only record in that case.  Called from
 * target eval (softirq or process context, no sleep).
 */
static void
dynrt_anchor_update(unsigned int l3num, u8 proto,
		    const union nf_inet_addr *saddr,
		    const union nf_inet_addr *daddr,
		    __be16 sport, __be16 dport, u32 oif,
		    u16 hwtype, u8 hwlen, const u8 *hw)
{
	struct dynrt_anchor *a;
	bool found = false;
	ktime_t now = ktime_get();

	spin_lock_irq(&dynrt_anchor_lock);
	dynrt_anchor_sweep_locked();

	list_for_each_entry(a, &dynrt_anchor_list, next) {
		if (a->l3num == l3num && a->proto == proto &&
		    nf_inet_addr_cmp(&a->saddr, daddr) &&
		    nf_inet_addr_cmp(&a->daddr, saddr) &&
		    a->sport == dport && a->dport == sport) {
			a->oif     = oif;
			a->hwtype  = hwtype;
			a->hwlen   = hwlen;
			if (hw && hwlen > 0)
				memcpy(a->hw, hw, hwlen);
			a->expires = ktime_add_ms(now, DYNRT_ANCHOR_TTL_MS);
			found = true;
			break;
		}
	}

	if (!found) {
		a = kzalloc(sizeof(*a), GFP_ATOMIC);
		if (a) {
			/* oldest entry = list tail (newest at the head) */
			if (dynrt_anchor_count >= DYNRT_ANCHOR_MAX) {
				struct dynrt_anchor *victim =
					list_last_entry(&dynrt_anchor_list,
						struct dynrt_anchor, next);

				list_del_rcu(&victim->next);
				dynrt_anchor_count--;
				kfree_rcu(victim, rcu);
			}
			a->l3num   = l3num;
			a->proto   = proto;
			a->saddr   = *daddr;
			a->daddr   = *saddr;
			a->sport   = dport;	/* reply src port = pkt dst
						 * port (same swap as L3) */
			a->dport   = sport;
			a->oif     = oif;
			a->hwtype  = hwtype;
			a->hwlen   = hwlen;
			if (hw && hwlen > 0)
				memcpy(a->hw, hw, hwlen);
			a->expires = ktime_add_ms(now, DYNRT_ANCHOR_TTL_MS);
			list_add(&a->next, &dynrt_anchor_list);
			dynrt_anchor_count++;
		}
	}
	spin_unlock_irq(&dynrt_anchor_lock);
}

/* Module exit: free everything (no readers left after dynrt_unregister()). */
static void dynrt_anchor_flush(void)
{
	struct dynrt_anchor *a, *tmp;

	spin_lock_irq(&dynrt_anchor_lock);
	list_for_each_entry_safe(a, tmp, &dynrt_anchor_list, next) {
		list_del_rcu(&a->next);
		kfree_rcu(a, rcu);
	}
	dynrt_anchor_count = 0;
	spin_unlock_irq(&dynrt_anchor_lock);
}

/* -----------------------------------------------------------------------
 * dynrt_ops table (P2 wrapper callbacks).
 *
 * All of them are called under rcu_read_lock() + try_module_get() by
 * net/netfilter/nf_dynrt.c, and the returned value / pointer must be
 * self-contained (no ct reference outlives the call, except the
 * per-CPU mac copy which has its own lifetime documented above).
 * --------------------------------------------------------------------- */

static u32 dynrt_op_oif_skb(struct sk_buff *skb)
{
	unsigned int l3num;
	struct net *net;
	struct nf_conn *ct;
	enum ip_conntrack_dir dir = IP_CT_DIR_MAX;
	struct src_dyn_rt_slot *slot;
	struct nf_conntrack_tuple tuple;
	bool owned = false;

	if (!skb->dev)
		return 0;

	net = dev_net(skb->dev);
	l3num = dynrt_skb_l3num(skb);
	if (l3num == 0)
		return 0;

	if (dynrt_ct_dir_skb(skb, l3num, net, &ct, &dir, &owned) ||
	    dynrt_ct_acquire(skb, l3num, net, &ct, &owned)) {
		slot = dynrt_slot_pick(ct, dir);
		dynrt_ct_put_owned(ct, owned);
		if (slot) {
			return slot->ifindex;
		}
	}

	/*
	 * Anchor fallback (see the anchor table / dynrt_op_oif_fl4()):
	 * the ct identity may be unresolvable from the skb (inverted
	 * or NAT-inverted reply), but DYNSRCROUTE anchored the reverse
	 * flow with its egress ifindex when it fired.  0 when unknown or
	 * expired -> plain FIB decides.
	 */
	if (nf_ct_get_tuplepr(skb, skb_network_offset(skb), l3num, net,
			      &tuple) &&
	    dynrt_anchor_eligible(tuple.dst.protonum)) {
		__be16 sp = tuple.src.u.udp.port;
		__be16 dp = tuple.dst.u.udp.port;

		dynrt_anchor_key_ports(tuple.dst.protonum, &sp, &dp);
		return dynrt_anchor_lookup(l3num, tuple.dst.protonum,
					   &tuple.src.u3, &tuple.dst.u3,
					   sp, dp);
	}
	return 0;
}

static u32 dynrt_op_oif_fl4(struct net *net, const struct flowi4 *fl4)
{
	struct nf_conn *ct;
	enum ip_conntrack_dir dir = IP_CT_DIR_MAX;
	struct src_dyn_rt_slot *slot;

	ct = NULL;
	if (dynrt_ct_dir_fl4(net, fl4, &ct, &dir) ||
	    dynrt_ct_acquire_fl4(net, fl4, &ct)) {
		slot = dynrt_slot_pick(ct, dir);
		nf_ct_put(ct);
		if (slot)
			return slot->ifindex;
	}

	/*
	 * Anchor fallback (see the anchor table above): flows whose ct
	 * identity cannot be resolved from conntrack here (ICMP echo
	 * id/type beyond the flowi; TCP on a kernel where the ct hooks
	 * are not registered -- the 6.12.111/ deb13 configuration, see
	 * dynrt_anchor_eligible()) fall back to the reverse-flow anchor,
	 * which carries the L4 ports for TCP/UDP (B4).  0 when the flow
	 * is unknown or its anchor expired -> plain FIB decides.
	 */
	if (dynrt_anchor_eligible(fl4->flowi4_proto)) {
		union nf_inet_addr s, d;
		__be16 sp = fl4->fl4_sport;
		__be16 dp = fl4->fl4_dport;

		s.ip = fl4->saddr;
		d.ip = fl4->daddr;
		dynrt_anchor_key_ports(fl4->flowi4_proto, &sp, &dp);
		return dynrt_anchor_lookup(AF_INET, fl4->flowi4_proto,
					   &s, &d, sp, dp);
	}
	return 0;
}

static u32 dynrt_op_oif_fl6(struct net *net, const struct flowi6 *fl6)
{
	struct nf_conn *ct;
	enum ip_conntrack_dir dir = IP_CT_DIR_MAX;
	struct src_dyn_rt_slot *slot;

	ct = NULL;
	if (dynrt_ct_dir_fl6(net, fl6, &ct, &dir) ||
	    dynrt_ct_acquire_fl6(net, fl6, &ct)) {
		slot = dynrt_slot_pick(ct, dir);
		nf_ct_put(ct);
		if (slot)
			return slot->ifindex;
	}

	/* Anchor fallback (see dynrt_op_oif_fl4 / the anchor table). */
	if (dynrt_anchor_eligible(fl6->flowi6_proto)) {
		union nf_inet_addr s, d;
		__be16 sp = fl6->fl6_sport;
		__be16 dp = fl6->fl6_dport;

		s.in6 = fl6->saddr;
		d.in6 = fl6->daddr;
		dynrt_anchor_key_ports(fl6->flowi6_proto, &sp, &dp);
		return dynrt_anchor_lookup(AF_INET6, fl6->flowi6_proto,
					   &s, &d, sp, dp);
	}
	return 0;
}

static const u8 *dynrt_op_mac(struct sk_buff *skb, struct net_device *dev)
{
	unsigned int l3num;
	struct net *net;
	struct nf_conn *ct;
	enum ip_conntrack_dir dir = IP_CT_DIR_MAX;
	struct src_dyn_rt_slot *slot;
	const u8 *ret = NULL;
	bool owned = false;

	if (!skb->dev || !dev)
		return NULL;

	net = dev_net(skb->dev);
	l3num = dynrt_skb_l3num(skb);
	if (l3num == 0)
		return NULL;

	if (dynrt_ct_dir_skb(skb, l3num, net, &ct, &dir, &owned) ||
	    dynrt_ct_acquire(skb, l3num, net, &ct, &owned)) {
		slot = dynrt_slot_pick(ct, dir);
		if (slot &&
		    slot->hwlen > 0 &&
		    slot->hwlen == dev->addr_len &&
		    slot->hwtype == dev->type) {
			u8 *buf = get_cpu_var(dynrt_mac_buf);

			memcpy(buf, slot->hw, slot->hwlen);
			put_cpu_var(dynrt_mac_buf);
			ret = buf;
		}
		dynrt_ct_put_owned(ct, owned);
	}

	/*
	 * Anchor fallback: flows with no conntrack entry at all (echo
	 * traffic on a kernel without the ICMP conntrack protocol) have
	 * no ct-slot to read -- DYNSRCROUTE still anchored the reverse
	 * flow with the peer L2, so use that (see the anchor table).
	 * The key is the packet's wire tuple (in packet order), which
	 * equals the stored reverse-flow key for a reply.
	 */
	if (!ret) {
		struct nf_conntrack_tuple atup;

		if (nf_ct_get_tuplepr(skb, skb_network_offset(skb), l3num,
				     net, &atup) &&
		    dynrt_anchor_eligible(atup.dst.protonum)) {
			__be16 sp = atup.src.u.udp.port;
			__be16 dp = atup.dst.u.udp.port;

			dynrt_anchor_key_ports(atup.dst.protonum, &sp, &dp);
			ret = dynrt_anchor_mac(l3num, atup.dst.protonum,
					       &atup.src.u3, &atup.dst.u3,
					       sp, dp, dev);
		}
	}
	return ret;
}

static const struct dynrt_ops dynrt_ops_table = {
	.oif_skb	= dynrt_op_oif_skb,
	.oif_fl4	= dynrt_op_oif_fl4,
	.oif_fl6	= dynrt_op_oif_fl6,
	.mac		= dynrt_op_mac,
	.owner		= THIS_MODULE,
};

/* -----------------------------------------------------------------------
 * nftables expressions: DYNSRCROUTE (target) and DYNRT (match).
 * --------------------------------------------------------------------- */

/*
 * DYNSRCROUTE: evaluate against the current packet (whatever its
 * direction D is).  Store {ifindex, peer L2, valid} into slot[D ^ 1].
 * Overwrite the slot if it is already set (report §3.2: a *later* packet
 * in the same direction re-anchors the route of the opposite side;
 * e.g. path switch, new source, or a simple refresh).
 *
 * Degrade rules (report §6): store ifindex-only (hwlen = 0) when the
 * peer L2 cannot be determined: dev->addr_len == 0, or > 8, or
 * skb_mac_header was never set (loopback / non-L2).  The slot stays
 * valid and usable at L3 (FIB oif forcing) in that case, and the
 * neighbour fallback takes the ordinary ARP/ND path at L2.
 */
static void dynrt_srcroute_eval(const struct nft_expr *expr,
				struct nft_regs *regs,
				const struct nft_pktinfo *pkt)
{
	struct sk_buff *skb = pkt->skb;
	struct net *net = nft_net(pkt);
	const struct net_device *dev;
	unsigned int l3num;
	struct nf_conn *ct;
	unsigned int dir;
	struct src_dyn_rt_slot *slot;
	bool owned = false;

	dev = nft_in(pkt) ? nft_in(pkt) : nft_out(pkt);
	if (!dev)		/* no interface context at all: nothing to store */
		return;

	l3num = dynrt_pktinfo_l3num(pkt);
	if (l3num == 0)
		return;

	/*
	 * Peer L2 = h_source of the frame as it arrived (the
	 * second address field of the L2 header).  Bounds: the
	 * L2 header region [mac_header, mac_header + 2*len)
	 * must end at or before the L3 header (skb->data).  Hoisted
	 * before the anchor write below: the anchor stores it too
	 * (conntrack-less fallback), and the ct-slot path reuses it.
	 */
	const u8 *peer = NULL;
	u8 hw[8] = {0};

	if (dev->addr_len != 0 &&
	    dev->addr_len <= 8 &&
	    skb_mac_header_was_set(skb) &&
	    skb_mac_header(skb) + 2 * dev->addr_len <= skb->data)
		peer = skb_mac_header(skb) + dev->addr_len;
	if (peer)
		memcpy(hw, peer, dev->addr_len);

	/*
	 * Anchor the reverse flow (packet order) for the FIB (flowi)
	 * forcing fallback -- primary carrier for ICMP (whose ct
	 * identity, echo id/type, a flowi cannot reproduce) and, on
	 * kernels where the conntrack hooks are not registered (the
	 * 6.12.111/ deb13 configuration: lazy nf_ct_netns_get()
	 * registration, see dynrt_anchor_eligible()), for plain TCP/UDP
	 * as well.  The B4 key carries the L4 ports for TCP/UDP and
	 * 0/0 for ICMP/ICMPv6 (dynrt_anchor_key_ports()), so only the
	 * exact 4-tuple (or the exact pair, for echo) matches.  Needs
	 * only the packet tuple + the chosen interface, so it runs even
	 * when the ct-slot path below cannot apply (no ct --
	 * confirmed ct, OOM, ...).  The peer L2 rides along:
	 * dynrt_op_mac() consults it when there is no ct to read a
	 * slot from.  The write is gated on the same eligibility list
	 * as the reads so ineligible protocols never allocate budget.
	 */
	{
		struct nf_conntrack_tuple atup;

		if (nf_ct_get_tuplepr(skb, skb_network_offset(skb), l3num,
				     net, &atup) &&
		    dynrt_anchor_eligible(atup.dst.protonum)) {
			__be16 sp = atup.src.u.udp.port;
			__be16 dp = atup.dst.u.udp.port;

			dynrt_anchor_key_ports(atup.dst.protonum, &sp, &dp);
			dynrt_anchor_update(l3num, atup.dst.protonum,
					    &atup.src.u3, &atup.dst.u3,
					    sp, dp,
					    dev->ifindex,
					    peer ? dev->type : 0,
					    peer ? dev->addr_len : 0,
					    hw);
		}
	}

	if (!dynrt_ct_dir_skb(skb, l3num, net, &ct, &dir, &owned))
		return;		/* no ct, or ambiguous direction: no-op */

	slot = dynrt_slot_for_write(ct, dir ^ 1);
	if (slot)
		slot->ifindex = dev->ifindex;

	if (slot) {
		if (peer) {
			slot->hwtype = dev->type;
			slot->hwlen  = dev->addr_len;
			memcpy(slot->hw, hw, dev->addr_len);
		} else {
			/* degrade to ifindex-only (report §6) */
			slot->hwtype = 0;
			slot->hwlen  = 0;
			memset(slot->hw, 0, sizeof(slot->hw));
		}
		slot->flags |= SRC_DYN_RT_SLOT_VALID;
	}
	dynrt_ct_put_owned(ct, owned);
}

/*
 * DYNRT: match "a valid route is recorded for this flow" (either
 * direction slot, see dynrt_slot_pick(), or the anchor table).
 *
 * Positive: keep the default verdict (NFT_CONTINUE) untouched.
 * Negative (no ct, no valid slot in either direction, no anchor):
 * emit NFT_BREAK.  This is the nft idiom in 6.12 for "match failed,
 * stop the rest of this rule" (cf. nft_ct.c).  Rules that want the
 * classic "fall through to the next rule" semantics should use the
 * usual nft negation / chain control instead of relying on a special
 * verdict.
 *
 * The direction leniency is mandatory for REPLY packets of NAT-ed
 * flows: after nf_ct_invert_tuplehash() / NAT inversion the wire tuple
 * no longer resolves to a stored direction, but a previously recorded
 * route (or anchor) still applies to the flow.
 */
static void dynrt_match_eval(const struct nft_expr *expr,
			     struct nft_regs *regs,
			     const struct nft_pktinfo *pkt)
{
	struct sk_buff *skb = pkt->skb;
	struct net *net = nft_net(pkt);
	unsigned int l3num;
	struct nf_conn *ct;
	enum ip_conntrack_dir dir = IP_CT_DIR_MAX;
	struct src_dyn_rt_slot *slot;
	struct nf_conntrack_tuple tuple;
	bool ok = false;
	bool owned = false;

	l3num = dynrt_pktinfo_l3num(pkt);
	if (l3num == 0)
		goto out;

	if (nf_ct_get_tuplepr(skb, skb_network_offset(skb), l3num, net,
			      &tuple)) {
		if (dynrt_ct_dir_skb(skb, l3num, net, &ct, &dir, &owned) ||
		    dynrt_ct_acquire(skb, l3num, net, &ct, &owned)) {
			slot = dynrt_slot_pick(ct, dir);
			ok = slot != NULL;
			dynrt_ct_put_owned(ct, owned);
		}

		/* anchor fallback, cf. dynrt_op_oif_skb() (eligible
		 * protocols, B4 key = 4-tuple exact for TCP/UDP) */
		if (!ok && dynrt_anchor_eligible(tuple.dst.protonum)) {
			__be16 sp = tuple.src.u.udp.port;
			__be16 dp = tuple.dst.u.udp.port;

			dynrt_anchor_key_ports(tuple.dst.protonum, &sp, &dp);
			ok = dynrt_anchor_lookup(l3num, tuple.dst.protonum,
						&tuple.src.u3,
						&tuple.dst.u3,
						sp, dp) != 0;
		}
	}

out:
	if (!ok)
		regs->verdict.code = NFT_BREAK;
}

/* -----------------------------------------------------------------------
 * Expression registration.
 * --------------------------------------------------------------------- */

static struct nft_expr_type dynrt_srcroute_type;
static struct nft_expr_type dynrt_match_type;
static const struct nft_expr_ops dynrt_srcroute_ops = {
	.type		= &dynrt_srcroute_type,
	.size		= NFT_EXPR_SIZE(0),
	.eval		= dynrt_srcroute_eval,
};
static const struct nft_expr_ops dynrt_match_ops = {
	.type		= &dynrt_match_type,
	.size		= NFT_EXPR_SIZE(0),
	.eval		= dynrt_match_eval,
};

static struct nft_expr_type dynrt_srcroute_type __read_mostly = {
	.name		= "DYNSRCROUTE",
	.ops		= &dynrt_srcroute_ops,
	.owner		= THIS_MODULE,
};

static struct nft_expr_type dynrt_match_type __read_mostly = {
	.name		= "DYNRT",
	.ops		= &dynrt_match_ops,
	.owner		= THIS_MODULE,
};

/* -----------------------------------------------------------------------
 * Module init/exit.
 * --------------------------------------------------------------------- */

static int __init srcdynroute_init(void)
{
	int err;

	timer_setup(&dynrt_anchor_sweep, dynrt_anchor_sweep_fn, 0);

	/*
	 * Order: the nft exprs first, then the ops registration.
	 * If ops registration fails (which cannot happen in practice --
	 * P2 only rejects NULL fields), both exprs are un-registered
	 * again to leave the nftables state alone.
	 */
	err = nft_register_expr(&dynrt_srcroute_type);
	if (err < 0)
		goto err0;

	err = nft_register_expr(&dynrt_match_type);
	if (err < 0)
		goto err1;

	err = dynrt_register(&dynrt_ops_table);
	if (err < 0)
		goto err2;

	/* periodic anchor-table purge (TTLs are also enforced on read) */
	mod_timer(&dynrt_anchor_sweep, jiffies + 10 * HZ);

	pr_info("DYNSRCROUTE target + DYNRT match + dynrt_ops registered\n");
	return 0;

err2:
	nft_unregister_expr(&dynrt_match_type);
err1:
	nft_unregister_expr(&dynrt_srcroute_type);
err0:
	del_timer_sync(&dynrt_anchor_sweep);
	return err;
}

static void __exit srcdynroute_exit(void)
{
	/*
	 * dynrt_unregister() does synchronize_rcu() (P2), so once it
	 * returns no wrapper has a live (ops, owner) pair and it is safe
	 * to drop the nft exprs (their owners are the same module, so
	 * the nftables layer will not call us again after that) and to
	 * flush the anchor table (no lookups left).
	 */
	dynrt_unregister();
	nft_unregister_expr(&dynrt_match_type);
	nft_unregister_expr(&dynrt_srcroute_type);
	del_timer_sync(&dynrt_anchor_sweep);
	dynrt_anchor_flush();
}

module_init(srcdynroute_init);
module_exit(srcdynroute_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("srcdynroute");
MODULE_DESCRIPTION("nftables DYNSRCROUTE target / DYNRT match + per-direction "
		   "source-route FIB and neighbour forcing (kernel 6.12.111)");
MODULE_VERSION("0.1");
/*
 * Autoload aliases: nf_tables_api.c requests "nft-expr-<family>-<name>"
 * and "nft-expr-<name>" when a rule refers to an unknown expr -- these
 * two aliases are the generic (family-less) form, same as nft_ct.c does
 * for "ct" and "notrack".  Keep the token case byte-for-byte identical
 * to the nft expression name in dynrt_srcroute_type / dynrt_match_type.
 */
MODULE_ALIAS_NFT_EXPR("DYNSRCROUTE");
MODULE_ALIAS_NFT_EXPR("DYNRT");
