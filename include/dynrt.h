/* SPDX-License-Identifier: GPL-2.0 */
/*
 * dynrt.h -- per-direction dynamic source-route extension for conntrack.
 *
 * This header is intentionally conntrack-free: it defines the on-wire slot
 * layout (shared between the built-in "ops" helper and the out-of-tree
 * target/match module) and the ops interface the out-of-tree module fills in.
 * None of the symbols referenced here are conntrack (or any other netfilter)
 * symbols, so the built-in helper can be linked into vmlinux without pulling
 * in nf_conntrack (see the ops-inversion design, report §4.3).
 *
 * Direction algebra (report §3.2):
 *   writer (target, packet dir W) writes slot[W ^ 1]   (the "other" side)
 *   reader (route/neighbor, packet dir R) reads slot[R]
 *   They coincide when  W == R ^ 1, i.e. the *reply* uses the slot that the
 *   *request* wrote.
 *
 * NOTE: this file in the repo is a copy of the ABI header as built into the
 * kernel (include/net/netfilter/dynrt.h of the patched tree).  The module
 * #includes the kernel's header, not this copy; keep the two in sync when
 * the ABI changes (the slot layout is the stable part).
 */
#ifndef _NETFILTER_DYNRT_H
#define _NETFILTER_DYNRT_H

#include <linux/types.h>
#include <linux/build_bug.h>

/* Forward declarations; only used as pointers here. */
struct sk_buff;
struct net;
struct flowi4;
struct flowi6;
struct net_device;
struct module;

/*
 * One per-direction slot. 16 bytes, packed (no padding: 4+2+1+1+8 == 16).
 */
struct src_dyn_rt_slot {
	__u32 ifindex;	/* forced output ifindex; 0 = "not set by this slot" */
	__u16 hwtype;	/* ARPHRD_* of the stored L2 address */
	__u8  hwlen;	/* stored L2 length, 0..8 (0 => ifindex-only) */
	__u8  flags;	/* bit0 (SRC_DYN_RT_SLOT_VALID) = slot is valid */
	__u8  hw[8];	/* peer L2 address, from the *incoming* packet */
} __packed;

#define SRC_DYN_RT_SLOT_VALID	0x01	/* slot contains usable data */

/*
 * The extension value: two slots (ORIG / REPLY), 32 bytes total.
 * Stored via the standard nf_ct_ext API under id NF_CT_EXT_SRC_DYN_RT.
 */
struct src_dyn_rt_ext {
	struct src_dyn_rt_slot slot[2];
};


/*
 * Ops interface implemented by the out-of-tree module (which links
 * nf_conntrack). The built-in helper holds an RCU pointer to this struct and
 * calls through it under rcu_read_lock() + try_module_get().
 *
 * oif_*  : return the forced output ifindex for this packet's direction,
 *          or 0 if the slot is absent/invalid (caller falls back to the
 *          normal route lookup).
 * mac    : return a pointer to a valid stored L2 address of the right length
 *          for @dev, or NULL to let the caller use the ordinary neighbor
 *          address (ARP/ND still runs in that case).
 *
 * mac() lifetime: the returned pointer MUST NOT point into conntrack
 * extension memory -- the caller may invoke it in a context where the
 * conntrack entry is no longer held, and the neighbour code uses the
 * pointer immediately after the call (for dev_hard_header()).  The
 * implementation therefore copies the address out (the module uses a
 * per-CPU buffer) and the pointer is valid only until the next mac() call
 * from the same CPU.  The only consumer is the neighbour override, which
 * satisfies this contract.
 */
struct dynrt_ops {
	u32	(*oif_skb)(struct sk_buff *skb);
	u32	(*oif_fl4)(struct net *net, const struct flowi4 *fl4);
	u32	(*oif_fl6)(struct net *net, const struct flowi6 *fl6);
	const u8 *(*mac)(struct sk_buff *skb, struct net_device *dev);
	struct module *owner;
};

/* Built-in wrappers (no-op returning 0/NULL when no module is registered). */
u32	dynrt_force_oif_skb(struct sk_buff *skb);
u32	dynrt_force_oif_fl4(struct net *net, const struct flowi4 *fl4);
u32	dynrt_force_oif_fl6(struct net *net, const struct flowi6 *fl6);
const u8 *dynrt_force_mac(struct sk_buff *skb, struct net_device *dev);

/* Registration, called by the out-of-tree module at load/exit time. */
int	dynrt_register(const struct dynrt_ops *ops);
void	dynrt_unregister(void);

#endif /* _NETFILTER_DYNRT_H */
