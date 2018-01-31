/*******************************************************
 * Linux PPP Bridge over Ethernet device
 *
 * Author:	khls27 <khls27@126.com>
 * License:
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 */
#include <linux/string.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/errno.h>
#include <linux/netdevice.h>
#include <linux/net.h>
#include <linux/inetdevice.h>
#include <linux/etherdevice.h>
#include <linux/skbuff.h>
#include <linux/init.h>
#include <linux/if_ether.h>
#include <linux/notifier.h>
#include <linux/file.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>

#include <linux/nsproxy.h>
#include <net/net_namespace.h>
#include <net/netns/generic.h>

#include <asm/uaccess.h>
#include <linux/rculist.h>
#include <linux/spinlock.h>
#include <linux/times.h>
#include <linux/netdevice.h>
#include <linux/jhash.h>
#include <linux/random.h>
#include <linux/slab.h>
#include <linux/atomic.h>
#include <asm/unaligned.h>
#include <linux/version.h>

#define PBOE_FDB_CACHE_NAME "pboe_fdb_cache"
#define PBOE_VERSION "v.0.0.2"

#define PBOE_HASH_BITS 8
#define PBOE_HASH_SIZE (1 << PBOE_HASH_BITS)
#define PBOE_HASH_MASK (PBOE_HASH_SIZE - 1)

/*
* This best way to define a new protocol of ETHERNET is defining it
* in "linux/if_ether.h", to strive for consistency.
* But, um, someone does NOT want to create a patch 
*/
#ifndef ETH_P_PBOE
#define ETH_P_PBOE 0x8865
#endif

struct pboe_peer_desc;

#define PBOE_ST_MK_MTSET        (1)
#define PBOE_ST_MK_BOUND        (1 << 1)        // bind a ether device
#define PBOE_ST_MK_UNBOUND      (1 << 2)        // unbind caused by ethx down
#define PBOE_ST_MK_CONNECTED    (1 << 3)        // at least one peer added
#define PBOE_ST_MK_STOPING      (1 << 4)        // the worker is stoping
#define PBOE_ST_MK_STOPED       (1 << 5)        // the worker had stoped
#define PBOE_ST_MK_FORWARD      (1 << 6)        // support to forward
#define PBOE_ST_MK_EDEVUP       (1 << 7)        // the ether dev is up

enum pboe_modle_type_e
{
    PBOE_MT_SINGLE = 0,         // single peer, default
    PBOE_MT_MULTI               // with multi peers
};

enum pboe_status_e
{
    PBOE_ST_INIT = 0,
    PBOE_ST_CONFIG,
    PBOE_ST_ESTABLISH,
    PBOE_ST_STOPING,
    PBOE_ST_STOPED,
};

struct pboe_worker {
    enum pboe_modle_type_e type;
    u32 flags;
    atomic_t status;

    struct net_device		*pbdev;
    struct net_device		*edev;
    unsigned char bdev_name[IFNAMSIZ];

    /* hash table lock*/
    spinlock_t hash_lock;
    struct hlist_head fdb_hd[PBOE_HASH_SIZE];
    union {
        struct list_head peer_hd;
        struct pboe_peer_desc *peer;
    }upeers;

    atomic_t user;
    struct timer_list		gc_timer;   // fdb entry gc timer
    u32 ageing_time;                    // the fdb entry ageing time, default 120s
    struct kmem_cache *fdb_cache;       // forward data base cache
};

struct pboe_peer_desc {
    struct list_head	list;
    struct rcu_head			rcu;
    struct pboe_worker		*worker;
    u8 peermac[ETH_ALEN];
};

struct pboe_fdb_entry {
    struct hlist_node		hlist;
    struct pboe_peer_desc *peer;
    struct pboe_worker *worker;
    struct rcu_head			rcu;
    u8 stamac[ETH_ALEN];
    unsigned long			timestamp;
};

struct pboe_devpriv_warp {
    struct pboe_worker *worker;
};

static void worker_unbind_dev(struct pboe_worker *wk);

#if (LINUX_VERSION_CODE < KERNEL_VERSION(3, 10, 1))

/**
 * ether_addr_equal - Compare two Ethernet addresses
 * @addr1: Pointer to a six-byte array containing the Ethernet address
 * @addr2: Pointer other six-byte array containing the Ethernet address
 *
 * Compare two Ethernet addresses, returns true if equal
 *
 * This is copy from kernel 3.18.29
 * Please make sure: addr1 & addr2 must both be aligned to u16.
 */
static inline bool ether_addr_equal(const u8 *addr1, const u8 *addr2)
{
#if defined(CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS)
    u32 fold = ((*(const u32 *)addr1) ^ (*(const u32 *)addr2)) |
        ((*(const u16 *)(addr1 + 4)) ^ (*(const u16 *)(addr2 + 4)));

    return fold == 0;
#else
    const u16 *a = (const u16 *)addr1;
    const u16 *b = (const u16 *)addr2;

    return ((a[0] ^ b[0]) | (a[1] ^ b[1]) | (a[2] ^ b[2])) == 0;
#endif
}
#endif


static inline int mac_hash(const unsigned char *mac)
{
    static u32 hash_salt = 0;
    u32 key, key2;

    if (hash_salt == 0)
    {
        get_random_bytes(&hash_salt, sizeof(hash_salt));
    }

    /* mac[1] - mac[4]: use 1 byte of OUI and 3 bytes of NIC */
    key = get_unaligned((u32 *)(mac + 2));
    /* mac[0] & mac[5]:*/
    key2 = ((u32)(*mac) << 24) + ((u32)(*(mac + 5)));

    return jhash_2words(key, key2, hash_salt) & PBOE_HASH_MASK;
}

static inline void on_worker_flag_changed(struct pboe_worker *wk)
{
    if (wk->flags & PBOE_ST_MK_STOPING || wk->flags & PBOE_ST_MK_STOPED)
    {
        atomic_set(&wk->status, PBOE_ST_STOPED);
        return;
    }
    if (wk->flags & PBOE_ST_MK_MTSET
        && ((wk->flags & PBOE_ST_MK_BOUND) && !(wk->flags & PBOE_ST_MK_UNBOUND))
        && wk->flags & PBOE_ST_MK_CONNECTED
        && wk->flags & PBOE_ST_MK_EDEVUP)
    {
        atomic_set(&wk->status, PBOE_ST_ESTABLISH);
        return;
    }
    atomic_set(&wk->status, PBOE_ST_CONFIG);
}

static inline void worker_flag_set(struct pboe_worker *wk, int mask)
{
    wk->flags |= mask;
    on_worker_flag_changed(wk);
}

static inline void worker_flag_cleanup(struct pboe_worker *wk, int mask)
{
    wk->flags &= ~mask;
    on_worker_flag_changed(wk);
}

static inline int is_worker_established(struct pboe_worker *wk)
{
    return atomic_read(&wk->status) == PBOE_ST_ESTABLISH;
}

static int worker_fdbcache_init(struct pboe_worker *wk)
{
    struct kmem_cache *fdb_cache;
    fdb_cache = kmem_cache_create(PBOE_FDB_CACHE_NAME,
                                  sizeof(struct pboe_fdb_entry),
                                  0,
                                  SLAB_HWCACHE_ALIGN, NULL);
    if (!fdb_cache)
        return -ENOMEM;

    wk->fdb_cache = fdb_cache;
    printk(KERN_INFO "[PBOE] success init forward data base\n");
    return 0;
}

static void worker_fdbcache_fini(struct pboe_worker *wk)
{
    if (wk->fdb_cache)
    {
        kmem_cache_destroy(wk->fdb_cache);
        wk->fdb_cache = NULL;
    }
}

static inline unsigned long hold_time(const struct pboe_worker *wk)
{
    return wk->ageing_time ? wk->ageing_time : (120 * HZ);
}

static struct pboe_fdb_entry* __fdb_find(struct hlist_head *head, const u8 *stamac)
{
    struct pboe_fdb_entry *fdb;
#if (LINUX_VERSION_CODE > KERNEL_VERSION(3, 10, 1))
    hlist_for_each_entry_rcu(fdb, head, hlist)
#else
    struct hlist_node *h;
    hlist_for_each_entry_rcu(fdb, h, head, hlist)
#endif
    {
        if (ether_addr_equal(fdb->stamac, stamac))
            return fdb;
    }
    return NULL;
}

static struct pboe_fdb_entry* __fdb_create(struct pboe_worker *wk, struct hlist_head *head, struct pboe_peer_desc *peer, const u8 *stamac)
{
    struct pboe_fdb_entry *fdb;

    fdb = kmem_cache_alloc(wk->fdb_cache, GFP_ATOMIC);
    if (fdb)
    {
        memset(fdb, 0, sizeof(struct pboe_fdb_entry));
        memcpy(fdb->stamac, stamac, ETH_ALEN);
        fdb->peer = peer;
        fdb->worker = peer->worker;
        // TO-DO other initial
        hlist_add_head_rcu(&fdb->hlist, head);
        printk(KERN_INFO "[PBOE] new fdb entry added for <%02x:%02x:%02x:%02x:%02x:%02x>\n", stamac[0], stamac[1], stamac[2], stamac[3], stamac[4], stamac[5]);
    }
    return fdb;
}

static struct pboe_fdb_entry* __fdb_update(struct pboe_fdb_entry *fdb, struct pboe_peer_desc *peer)
{
    if (fdb->peer != peer)
    {
        fdb->peer = peer;
        fdb->worker = peer->worker;
    }
    fdb->timestamp = jiffies;
    return fdb;
}

static void fdb_rcu_free(struct rcu_head *head)
{
    struct pboe_fdb_entry *ent = container_of(head, struct pboe_fdb_entry, rcu);
    struct pboe_worker *wk = ent->worker;
    if (wk->fdb_cache)
    {
        kmem_cache_free(wk->fdb_cache, ent);
    }
}

static void __fdb_delete(struct pboe_worker *wk, struct pboe_fdb_entry *fdb)
{
    hlist_del_rcu(&fdb->hlist);
    call_rcu(&fdb->rcu, fdb_rcu_free);
}

// the GC timer call-back fucntion, cleanup the entrys which is timeout
static void worker_fdb_gc_cleanup(unsigned long _data)
{
    struct pboe_worker *wk = (struct pboe_worker *)_data;
    unsigned long delay = hold_time(wk);
    unsigned long next_timer = jiffies + wk->ageing_time;
    int i;

    spin_lock(&wk->hash_lock);
    for (i = 0; i < PBOE_HASH_SIZE; i++)
    {
        struct pboe_fdb_entry *f;
        struct hlist_node *n;
#if (LINUX_VERSION_CODE > KERNEL_VERSION(3, 10, 1))
        hlist_for_each_entry_safe(f, n, &wk->fdb_hd[i], hlist)
#else
        struct hlist_node *h;
        hlist_for_each_entry_safe(f, h, n, &wk->fdb_hd[i], hlist)
#endif
        {
            unsigned long this_timer;
            this_timer = f->timestamp + delay;
            if (time_before_eq(this_timer, jiffies))
                __fdb_delete(wk, f);
            else if (time_before(this_timer, next_timer))
                next_timer = this_timer;
        }
    }
    spin_unlock(&wk->hash_lock);
    mod_timer(&wk->gc_timer, round_jiffies_up(next_timer));
}

/* Completely flush all dynamic entries in forwarding database.*/
void worker_fdb_flush(struct pboe_worker *wk)
{
    int i;
    spin_lock_bh(&wk->hash_lock);
    for (i = 0; i < PBOE_HASH_SIZE; i++)
    {
        struct pboe_fdb_entry *f;
        struct hlist_node *n;
#if (LINUX_VERSION_CODE > KERNEL_VERSION(3, 10, 1))
        hlist_for_each_entry_safe(f, n, &wk->fdb_hd[i], hlist)
#else
        struct hlist_node *h;
        hlist_for_each_entry_safe(f, h, n, &wk->fdb_hd[i], hlist)
#endif
        {
            __fdb_delete(wk, f);
        }
    }
    spin_unlock_bh(&wk->hash_lock);
}

static inline int has_expired(const struct pboe_worker *wk, const struct pboe_fdb_entry *fdb)
{
    return time_before_eq(fdb->timestamp + hold_time(wk), jiffies);
}

/* No locking or refcounting, assumes caller has rcu_read_lock */
struct pboe_fdb_entry* __worker_fdb_get(struct pboe_worker *wk, const unsigned char *stamac)
{
    struct pboe_fdb_entry *fdb;
#if (LINUX_VERSION_CODE > KERNEL_VERSION(3, 10, 1))
    hlist_for_each_entry_rcu(fdb, &wk->fdb_hd[mac_hash(stamac)], hlist)
#else
    struct hlist_node *h;
    hlist_for_each_entry_rcu(fdb, h, &wk->fdb_hd[mac_hash(stamac)], hlist)
#endif
    {
        if (ether_addr_equal(fdb->stamac, stamac))
        {
            if (unlikely(has_expired(wk, fdb)))
                break;
            return fdb;
        }
    }

    return NULL;
}

/**
 * The find func to get a PPPoE-bridge forward entry
 */
struct pboe_fdb_entry* worker_fdb_get(struct pboe_worker *wk, const unsigned char *stamac)
{
    struct pboe_fdb_entry *fdb;
    rcu_read_lock();
    fdb = __worker_fdb_get(wk, stamac);
    rcu_read_unlock();
    return fdb;
}

static int worker_peerdesc_add(struct pboe_worker *wk, const u8 *peermac)
{
    struct pboe_peer_desc *peer;

    if (!is_valid_ether_addr(peermac))
        return -EINVAL;

    peer = (struct pboe_peer_desc *)kmalloc(sizeof(struct pboe_peer_desc), GFP_ATOMIC);
    if (!peer)
        return -ENOMEM;

    memset(peer, 0, sizeof(struct pboe_peer_desc));
    peer->worker = wk;
    memcpy(peer->peermac, peermac, ETH_ALEN);
    if (PBOE_MT_MULTI ==  wk->type)
    {
        list_add_tail_rcu(&peer->list, &wk->upeers.peer_hd);
    }
    else
    {
        if (wk->upeers.peer)
        {
            printk(KERN_ERR "[PBOE] the worker is in SINGLE-PEER type, and the peer had been set, now replease it...");
            kfree(wk->upeers.peer);
        }
        wk->upeers.peer = peer;
    }
    return 0;
}

static struct pboe_peer_desc* worker_peerdesc_get(struct pboe_worker *wk, const u8 *peermac)
{
    struct pboe_peer_desc *peer;

    list_for_each_entry_rcu(peer, &wk->upeers.peer_hd, list)
    {
        if (ether_addr_equal(peer->peermac, peermac))
        {
            return peer;
        }
    }
    return NULL;
}

static int worker_fdb_update(struct pboe_worker *wk, const u8 *peermac, const u8 *stamac)
{
    struct hlist_head *head = &wk->fdb_hd[mac_hash(stamac)];
    struct pboe_fdb_entry *fdb;
    struct pboe_peer_desc *peer;

    if (!is_valid_ether_addr(stamac))
        return -EINVAL;

    fdb = __fdb_find(head, stamac);
    if (fdb)
    {
        if (unlikely(!ether_addr_equal(fdb->peer->peermac, peermac)))
        {
            peer = worker_peerdesc_get(wk, peermac);
            if (unlikely(!peer))
            {
                return -EINVAL;
            }
        }
        else
        {
            peer = fdb->peer;
        }
        __fdb_update(fdb, peer);
        return 0;
    }
    else
    {
        peer = worker_peerdesc_get(wk, peermac);
        if (unlikely(!peer))
            return -EINVAL;
        spin_lock_bh(&wk->hash_lock);
        fdb = __fdb_create(wk, head, peer, stamac);
        spin_unlock_bh(&wk->hash_lock);
    }
    return 0;
}

static void __peerdesc_rcu_free(struct rcu_head *head)
{
    struct pboe_peer_desc *peer = container_of(head, struct pboe_peer_desc, rcu);
    kfree(peer);
}

static inline void __peerdesc_delete(struct pboe_peer_desc *peer)
{
    list_del_rcu(&peer->list);
    call_rcu(&peer->rcu, __peerdesc_rcu_free);
}

static void worker_peerdesc_delete(struct pboe_worker *wk, struct pboe_peer_desc *peer)
{
    if (PBOE_MT_MULTI == wk->type)
    {
        __peerdesc_delete(peer);
    }
    else
    {
        BUG_ON((peer !=  wk->upeers.peer));
        kfree(peer);
        wk->upeers.peer = NULL;
    }
}

static void worker_peerdesc_flush(struct pboe_worker *wk)
{
    struct pboe_peer_desc *peer;
    if (PBOE_MT_MULTI == wk->type)
    {
        struct pboe_peer_desc *tmp;
        list_for_each_entry_safe(peer, tmp, &wk->upeers.peer_hd, list)
        {
            __peerdesc_delete(peer);
        }
    }
    else
    {
        worker_peerdesc_delete(wk, wk->upeers.peer);
    }
}

static int worker_peerdesc_send_skb(struct pboe_peer_desc *peer, struct sk_buff *skb)
{
    struct pboe_worker *wk = peer->worker;
    struct net_device *edev = wk->edev;
    int data_len = skb->len;

    if (!edev)
        goto abort;

    /* Copy the data if there is no space for the header or if it's read-only.*/
    if (skb_cow_head(skb, edev->hard_header_len))
        goto abort;

    skb_reset_network_header(skb);
    skb->protocol = cpu_to_be16(ETH_P_PBOE);
    skb->dev = edev;

    dev_hard_header(skb, edev, ETH_P_PBOE, peer->peermac, NULL, data_len);
    dev_queue_xmit(skb);
    return 1;

abort:
    kfree_skb(skb);
    return 1;
}

static int worker_flood_skb(struct pboe_worker *wk, struct sk_buff *skb)
{
    struct net_device *edev = wk->edev;
    struct pboe_peer_desc *peer;
    struct sk_buff *nskb;

    if (!edev)
        goto abort;

    list_for_each_entry_rcu(peer, &wk->upeers.peer_hd, list)
    {
        nskb = skb_clone(skb, GFP_ATOMIC);
        if (nskb)
        {
            worker_peerdesc_send_skb(peer, nskb);
        }
    }

abort:
    kfree_skb(skb);
    return 1;
}

static int worker_fdb_send_skb(struct pboe_fdb_entry *fdb, struct sk_buff *skb)
{
    struct pboe_worker *wk = fdb->worker;
    struct net_device *edev;
    int data_len = skb->len;

    if (unlikely(!wk))
        goto abort;

    if (!(edev = wk->edev))
        goto abort;

    /* Copy the data if there is no space for the header or if it's read-only.*/
    if (skb_cow_head(skb, edev->hard_header_len))
        goto abort;

    skb_reset_network_header(skb);
    skb->protocol = cpu_to_be16(ETH_P_PBOE);
    skb->dev = edev;
    dev_hard_header(skb, edev, ETH_P_PBOE, fdb->peer->peermac, NULL, data_len);
    dev_queue_xmit(skb);
    return 1;

abort:
    kfree_skb(skb);
    return 1;
}

static int worker_conf_setmode(struct pboe_worker *wk, enum pboe_modle_type_e mt)
{
    // the work mode had been set tobe MULTI_PEER, clean it and reset
    if (wk->flags & PBOE_ST_MK_MTSET)
    {
        worker_peerdesc_flush(wk);
        worker_flag_cleanup(wk, PBOE_ST_MK_CONNECTED);
        if (PBOE_MT_MULTI == wk->type)
        {
            worker_fdb_flush(wk);
            /* Wait for completion of call_rcu()'s */
            rcu_barrier();
            worker_fdbcache_fini(wk);
        }
    }

    if (PBOE_MT_MULTI == mt)
    {
        INIT_LIST_HEAD(&wk->upeers.peer_hd);
        worker_fdbcache_init(wk);
    }

    wk->type = mt;
    worker_flag_set(wk, PBOE_ST_MK_MTSET);
    printk(KERN_INFO "[PBOE] worker:%p work mode had been set to %s\n", wk, (mt) ? "MULTI_PEER" : "SINGLE_PEER");
    return 0;
}

static int worker_conf_binddev(struct pboe_worker *wk, const u8 *edev_name)
{
    /*NOTICE: dev_get_by_name will hold the dev refcnt*/
    struct net_device *edev = dev_get_by_name(&init_net, edev_name);

    if (wk->flags & PBOE_ST_MK_BOUND)
    {
        // must unbind the dev, becase we hold a refcnt of the dev we bound
        worker_unbind_dev(wk);
    }

    if (!edev)
    {
        printk(KERN_ERR "[PBOE] worker:%p fail to get the device by name:%s, device bound error\n", wk, edev_name);
        return -EINVAL;
    }

    wk->edev = edev;
    memcpy(wk->bdev_name, edev_name, IFNAMSIZ - 1);

    worker_flag_set(wk, PBOE_ST_MK_BOUND);

    if (edev->flags & IFF_UP)
    {
        worker_flag_set(wk, PBOE_ST_MK_EDEVUP);
    }
    printk(KERN_INFO "[PBOE] work:%p success to bind dev:%s\n", wk, edev_name);
    return 0;
}

static int worker_conf_addpeer(struct pboe_worker *wk, const u8 *mac)
{
    if (!(wk->flags & PBOE_ST_MK_BOUND) || !(wk->flags & PBOE_ST_MK_MTSET))
    {
        printk(KERN_ERR "[PBOE] worker:%p had NOT setup a working mode or had NOT bound to a ether device\n", wk);
        return -EINVAL;
    }
    if (worker_peerdesc_add(wk, mac))
    {
        printk(KERN_ERR "[PBOE] fail to add %02x:%02x:%02x:%02x:%02x:%02x as the peer\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
        return -EINVAL;
    }
    printk(KERN_INFO "[PBOE] worker:%p success add peer:%02x:%02x:%02x:%02x:%02x:%02x\n", wk, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    worker_flag_set(wk, PBOE_ST_MK_CONNECTED);
    return 0;
}

static void worker_unbind_dev(struct pboe_worker *wk)
{
    if (unlikely(!(wk->flags & PBOE_ST_MK_BOUND) || !wk->edev))
    {
        printk(KERN_INFO "[PBOE] this worker had bound none ether device...\n");
        return;
    }
    worker_flag_cleanup(wk, PBOE_ST_MK_BOUND);
    worker_flag_cleanup(wk, PBOE_ST_MK_EDEVUP);
    dev_put(wk->edev);
    wk->edev = NULL;
}

static struct pboe_worker *g_def_worker __read_mostly;

static int pboe_worker_init(struct pboe_worker **work)
{
    struct pboe_worker *wk;
    int i;

    wk = (struct pboe_worker *)kmalloc(sizeof(struct pboe_worker), GFP_KERNEL);
    if (!wk)
    {
        printk(KERN_ERR "[PBOE] malloc for worker fail, memery was low\n");
        return -ENOMEM;
    }
    memset(wk, 0, sizeof(struct pboe_worker));
    atomic_set(&wk->status, 0);
    atomic_set(&wk->user, 0);
    spin_lock_init(&wk->hash_lock);
    for (i = 0; i < PBOE_HASH_SIZE; i++)
    {
        INIT_HLIST_HEAD(&wk->fdb_hd[i]);
    }
    setup_timer(&wk->gc_timer, worker_fdb_gc_cleanup, (unsigned long)wk);
    *work = wk;
    return 0;
}

static struct pboe_worker* PBOE_get_def_worker(void)
{
    if (!g_def_worker)
    {
        pboe_worker_init(&g_def_worker);
    }
    return g_def_worker;
}

/**----------------------------------------the pppoe bridge netdev init -----------------------------------___________________________________________--*/

//static struct lock_class_key pboe_tx_busylock;
static int pboe_netdev_init(struct net_device *dev)
{
    // dev->qdisc_tx_busylock = &pboe_tx_busylock;
    return 0;
}

static netdev_tx_t pboe_netdev_start_xmit(struct sk_buff *skb, struct net_device *dev)
{
    struct pboe_worker *wk = PBOE_get_def_worker();
    struct ethhdr *ethh = (struct ethhdr *)skb_mac_header(skb);
    //todo: do tx statistic here

    if (unlikely(!wk))
        goto outf;

    if (!is_worker_established(wk))
        goto outf;

    //atomic_inc(&wk->user);
    if (PBOE_MT_MULTI == wk->type)
    {
        struct pboe_fdb_entry *fdb = worker_fdb_get(wk, ethh->h_dest);
        if (fdb)
        {
            worker_fdb_send_skb(fdb, skb);
        }
        else
        {
            worker_flood_skb(wk, skb);
        }
        //atomic_dec(&wk->user);
        return NETDEV_TX_OK;
    }
    else if (PBOE_MT_SINGLE == wk->type)
    {
        /*in single-peer mode, all the package just send to the UNIT peer*/
        struct pboe_peer_desc *peer = wk->upeers.peer;
        if (unlikely(!peer))
        {
            printk(KERN_ERR "[PBOE] worker:%p was MT_SINGLE_PEER, but peer had NOT been seted!\n", wk);
            //atomic_dec(&wk->user);
            goto outf;
        }
        worker_peerdesc_send_skb(peer, skb);
        //atomic_dec(&wk->user);
        return NETDEV_TX_OK;
    }
    // else, fall thourgh
outf:
    kfree_skb(skb);
    ++dev->stats.tx_dropped;
    return NETDEV_TX_OK;
}

#define SIOCDEVPRIVATE	0x89F0	/* private ioctl cmds: from 0x89f0 to 0x89FF */
#define PBOE_IOS_MODE_TYPE  (SIOCDEVPRIVATE + 1)
#define PBOE_IOS_BINDDEV    (SIOCDEVPRIVATE + 2)
#define PBOE_IOS_ADDPEER    (SIOCDEVPRIVATE + 3)
#define PBOE_IOS_SHOW       (SIOCDEVPRIVATE + 4)

static int pboe_netdev_ioctl(struct net_device *dev, struct ifreq *ifr, int cmd)
{
    struct pboe_worker *wk = PBOE_get_def_worker();

    if (unlikely(!wk || wk->flags & PBOE_ST_MK_STOPING || wk->flags & PBOE_ST_MK_STOPED))
    {
        printk(KERN_INFO "[PBOE] the worker is going to die...\n");
        return -ENODEV;
    }

    switch (cmd)
    {
    case PBOE_IOS_MODE_TYPE:
        {
            enum pboe_modle_type_e mt = (enum pboe_modle_type_e)ifr->ifr_ifindex;
            return worker_conf_setmode(wk, mt);
        }
    case PBOE_IOS_ADDPEER:
        {
            struct sockaddr addr =  ifr->ifr_ifru.ifru_hwaddr;
            return worker_conf_addpeer(wk, addr.sa_data);
        }
    case PBOE_IOS_BINDDEV:
        {
            const u8 *devname = ifr->ifr_ifru.ifru_newname;
            return worker_conf_binddev(wk, devname);
        }
    case PBOE_IOS_SHOW:
        {
            printk(KERN_INFO "[PBOE] show status:\n");
            printk(KERN_INFO "\t flags:%s%s%s%s%s\n",
                   (wk->flags & PBOE_ST_MK_MTSET) ? "|mode" : "",
                   (wk->flags & PBOE_ST_MK_BOUND) ? "|bound" : "",
                   (wk->flags & PBOE_ST_MK_EDEVUP) ? "|up" : "",
                   (wk->flags & PBOE_ST_MK_CONNECTED) ? "|connected" : "",
                   (wk->flags & (PBOE_ST_MK_STOPED | PBOE_ST_MK_STOPING)) ? "|stop" : "");
            printk(KERN_INFO "\t status :%x\n", (unsigned int)atomic_read(&wk->status));
            return  0;
        }
    default:
        printk(KERN_INFO "[PBOE] device ioctl Not supported: %d!", cmd);
        return -EINVAL;
    }
    return -EINVAL;
}

static const struct net_device_ops pboe_netdev_ops = {
    .ndo_init	 = pboe_netdev_init,
    .ndo_start_xmit  = pboe_netdev_start_xmit,
    .ndo_do_ioctl    = pboe_netdev_ioctl,
    .ndo_set_mac_address = eth_mac_addr,
};

static struct net_device* pboe_netdev_create_interface(struct net *net)
{
    struct net_device *dev;
    struct pboe_devpriv_warp *wp;

#if (LINUX_VERSION_CODE > KERNEL_VERSION(3, 10, 1))
    dev = alloc_netdev(sizeof(struct pboe_devpriv_warp), "pb0", NET_NAME_UNKNOWN, ether_setup);
#else
    dev = alloc_netdev(sizeof(struct pboe_devpriv_warp), "pb0", ether_setup);
#endif

    if (!dev)
    {
        printk(KERN_ERR "[PBOE] alloc net_device fail\n");
        goto failed;
    }
    dev_net_set(dev, net);

    dev->netdev_ops = &pboe_netdev_ops;
    if (register_netdev(dev))
    {
        printk(KERN_INFO "[PBOE] register net_device fail\n");
        goto failed_free;
    }

    wp = netdev_priv(dev);
    memset(wp, 0, sizeof(struct pboe_devpriv_warp));
    printk(KERN_INFO "[PBOE] create net_device done\n");
    return dev;

failed_free:
    free_netdev(dev);
failed:
    return NULL;
}

static inline int __ptype_rcv_deliver_up(struct pboe_worker *wk, struct sk_buff *skb)
{
    struct ethhdr *org_ethh = (struct ethhdr *)skb_mac_header(skb);

    skb_pull(skb, sizeof(struct ethhdr));
    skb_reset_network_header(skb);
    skb->dev = wk->pbdev;
    skb->protocol = org_ethh->h_proto;

    if (wk->pbdev->rx_handler)
        wk->pbdev->rx_handler(&skb);
    else
        netif_receive_skb(skb);
    return NET_RX_SUCCESS;
}

static inline int __ptype_rcv_fdb_forward_skb(struct pboe_fdb_entry *fdb, struct sk_buff *skb)
{
    skb_forward_csum(skb);
    worker_fdb_send_skb(fdb, skb);
    return NET_RX_SUCCESS;
}

static inline int __ptype_rcv_peerdesc_forward_skb(struct pboe_peer_desc *peer, struct sk_buff *skb)
{
    skb_forward_csum(skb);
    worker_peerdesc_send_skb(peer, skb);
    return NET_RX_SUCCESS;
}

static int ptype_rcv_try_forward_skb(struct pboe_worker *wk, struct sk_buff **pskb, struct ethhdr *ap_ethh, struct ethhdr *org_ethh)
{
    struct sk_buff *nskb = *pskb;
    struct sk_buff *cskb;
    struct pboe_peer_desc *peer;
    struct pboe_peer_desc *in_peer;
    struct pboe_fdb_entry *fdb;

    // if the dest of this skb is someone AP's STATION, forward from fdb
    fdb = worker_fdb_get(wk, org_ethh->h_dest);
    if (fdb)
    {
        __ptype_rcv_fdb_forward_skb(fdb, nskb);
        *pskb = NULL;
        return NET_RX_SUCCESS;
    }

    // eles flood this skb to all other APs
    in_peer = worker_peerdesc_get(wk, ap_ethh->h_source);
    if (unlikely(!in_peer))
    {
        printk(KERN_ERR "[PBOE] recv package with NONE peer matched\n");
        kfree(nskb);
        *pskb = NULL;
        return NET_RX_DROP;
    }

    list_for_each_entry_rcu(peer, &wk->upeers.peer_hd, list)
    {
        if (peer != in_peer)
        {
            cskb = skb_clone(nskb, GFP_ATOMIC);
            if (cskb)
            {
                __ptype_rcv_peerdesc_forward_skb(peer, cskb);
            }
        }
    }

    // do NOT clean the pskb, so this skb would deliver up
    return NET_RX_SUCCESS;
}

/************************************************************************
 *
 * Receive wrapper called in BH context.
 *
 ***********************************************************************/
static int pboe_packet_rcv(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt, struct net_device *orig_dev)
{
    struct pboe_worker *wk = PBOE_get_def_worker();     // right now, worker is singleto
    struct ethhdr *ethh = (struct ethhdr *)skb_mac_header(skb);
    struct ethhdr *org_ethh = NULL;
    struct sk_buff **deliver_skb = &skb;

    if (unlikely(!wk || !is_worker_established(wk)))
    {
        goto drop;
    }
    skb_reset_mac_header(skb);
    org_ethh = (struct ethhdr *)skb_mac_header(skb);

    if (!ethh || !org_ethh)
    {
        printk(KERN_INFO "[PB] recv get mac header error\n");
        goto drop;
    }

    if (unlikely(!wk->pbdev))
    {
        goto drop;
    }

    if (PBOE_MT_MULTI == wk->type)
    {
        worker_fdb_update(wk, ethh->h_source, org_ethh->h_source);
        if (wk->flags & PBOE_ST_MK_FORWARD)
        {
            ptype_rcv_try_forward_skb(wk, deliver_skb, ethh, org_ethh);
            if (NULL == deliver_skb)
            {
                return NET_RX_SUCCESS;
            }
        }
    }

    return __ptype_rcv_deliver_up(wk, skb);

drop:
    kfree_skb(skb);
    return NET_RX_DROP;
}

static int pboe_edev_event(struct notifier_block *this, unsigned long event, void *ptr)
{
#if (LINUX_VERSION_CODE > KERNEL_VERSION(3, 10, 1))
    struct net_device *dev = netdev_notifier_info_to_dev(ptr);
#else
    struct net_device *dev = (struct net_device *)ptr;
#endif

    struct pboe_worker *wk = PBOE_get_def_worker();

    if (!wk || !dev || !(wk->flags & PBOE_ST_MK_BOUND))
    {
        return NOTIFY_DONE;
    }

    if (strncmp(dev->name, wk->bdev_name, IFNAMSIZ - 1))
    {
        return NOTIFY_DONE;
    }

    /* Only look at sockets that are using this specific device. */
    switch (event)
    {
    case NETDEV_CHANGEADDR:
        // TO-DO
        printk(KERN_WARNING "[PBOE] the device PBOE bound to changed hw addr, try to notify the peers\n");
        break;
    case NETDEV_CHANGEMTU:
        /* A change in mtu or address is a bad thing, requiring
         * LCP re-negotiation.
         */
        printk(KERN_WARNING "[PBOE] the device PBOE bound to changed MTU\n");
        break;

    case NETDEV_GOING_DOWN:
        worker_flag_cleanup(wk, PBOE_ST_MK_EDEVUP);
        printk(KERN_WARNING "[PBOE] the device<%p, %s> going down, disable PBOE process\n", dev, dev->name);
        if (atomic_read(&wk->user))
        {
            printk(KERN_WARNING "[PBOE] the device<%p, %s> going down, but there was %x packages in sending\n", dev, dev->name, (unsigned int)atomic_read(&wk->user));
        }
        else
        {
            worker_flag_set(wk, PBOE_ST_MK_UNBOUND);
            dev_put(dev);
            wk->edev = NULL;
        }
        break;

    case NETDEV_DOWN:
        if (wk->flags & PBOE_ST_MK_UNBOUND)
        {
            break;
        }
        worker_flag_cleanup(wk, PBOE_ST_MK_EDEVUP);
        printk(KERN_WARNING "[PBOE] the device<%p, %s> was down, disable PBOE process...\n", dev, dev->name);
        if (atomic_read(&wk->user))
        {
            printk(KERN_WARNING "[PBOE] the device<%p, %s> going down, but there was %x packages in sending\n", dev, dev->name, (unsigned int)atomic_read(&wk->user));
        }
        else
        {
            worker_flag_set(wk, PBOE_ST_MK_UNBOUND);
            dev_put(dev);
            wk->edev = NULL;
        }
        break;

    case NETDEV_UP:
        if (wk->flags & PBOE_ST_MK_UNBOUND)
        {
            worker_flag_cleanup(wk, PBOE_ST_MK_UNBOUND);
            dev_hold(dev);
            wk->edev = dev;
            printk(KERN_WARNING "[PBOE] the device<%p, %s> was UP from UNBOUND, try resume PBOE process...\n", dev, dev->name);
        }
        else
            printk(KERN_WARNING "[PBOE] the device<%p, %s> was UP, try resume PBOE process...\n", dev, dev->name);
        worker_flag_set(wk, PBOE_ST_MK_EDEVUP);
        break;

    default:
        break;
    }

    return NOTIFY_DONE;
}

static struct notifier_block pboe_edev_notifier = {
    .notifier_call = pboe_edev_event,
};

static void PBOE_release_worker(struct pboe_worker *wk)
{
    wk->flags |= PBOE_ST_MK_STOPED;

    // unbind edev
    worker_unbind_dev(wk);

    // release all fdb node
    worker_fdb_flush(wk);

    /* Wait for completion of call_rcu()'s */
    rcu_barrier();

    // release the fdb cache
    worker_fdbcache_fini(wk);

    // release all then peer-desc
    worker_peerdesc_flush(wk);

    kfree(wk);
    printk(KERN_INFO "[PBOE] worker had beed released...\n");
}


static struct packet_type pboe_ptype __read_mostly = {
    .type	= cpu_to_be16(ETH_P_PBOE),
    .func	= pboe_packet_rcv,
};

static int __init PPPoE_bridge_init(void)
{
    struct net_device *pbdev;
    struct pboe_devpriv_warp *wp;

    if (pboe_worker_init(&g_def_worker))
    {
        printk(KERN_ERR "[PBOE] fail to init the default worker, exit...\n");
        return -1;
    }

    pbdev = pboe_netdev_create_interface(&init_net);
    if (!pbdev)
    {
        printk(KERN_ERR "[PBOE] fail to create pppoe-bridge device, exit...\n");
        return -1;
    }

    wp = netdev_priv(pbdev);
    wp->worker = g_def_worker;
    g_def_worker->pbdev = pbdev;

    register_netdevice_notifier(&pboe_edev_notifier);
    dev_add_pack(&pboe_ptype);
    printk(KERN_INFO "[PBOE] ppp bridge over ether init done, version:%s\n", PBOE_VERSION);
    return 0;
}

static void __exit PPPoE_bridge_finit(void)
{
    worker_flag_set(g_def_worker, PBOE_ST_MK_STOPING);

    unregister_netdevice_notifier(&pboe_edev_notifier);
    dev_remove_pack(&pboe_ptype);
    unregister_netdev(g_def_worker->pbdev);
    PBOE_release_worker(g_def_worker);
    printk(KERN_INFO "[PBOE] ppp bridge over ether finit done,exit...\n");
}

module_init(PPPoE_bridge_init);
module_exit(PPPoE_bridge_finit);

MODULE_AUTHOR("khls27 <khls27@126.com>");
MODULE_DESCRIPTION("PPP Bridge over Ethernet driver");
MODULE_LICENSE("GPL");

