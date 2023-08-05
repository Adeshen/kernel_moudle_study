#include <linux/init.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/socket.h>        /*PF_INET*/
#include <linux/netfilter_ipv4.h>/*NF_IP_PRE_FIRST*/
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/inet.h> /*in_aton()*/
#include <net/ip.h>
#include <net/tcp.h>
#include <linux/version.h>
#include <linux/module.h>

#define MAC_FMT "%02x:%02x:%02x:%02x:%02x:%02x"
#define MAC_ARG(x)
((u8 *)(x))[0], ((u8 *)(x))[1], ((u8 *)(x))[2], ((u8 *)(x))[3], ((u8 *)(x))[4], ((u8 *)(x))[5]

    MODULE_LICENSE("GPL");
MODULE_AUTHOR("bbo");
struct nf_hook_ops nfho;
struct nf_hook_ops nfout;

static char *vip = "192.168.2.99";
static char server_mac[ETH_ALEN] = {0x90, 0xFB, 0xA6, 0x03, 0x06, 0x61};

static char *client_ip = "192.168.2.16";

static char *rs_ip = "192.168.2.245";

#define MY_XMIT(pf, skb, rt)                        \
    do                                              \
    {                                               \
        skb_forward_csum(skb);                      \
        NF_HOOK(pf, NF_INET_LOCAL_OUT, (skb), NULL, \
                (rt)->u.dst.dev, dst_output);       \
    } while (0)

void print_mac_buf(char *buf)
{

    printk("DEST:" MAC_FMT "\n", MAC_ARG(buf));
    printk("SOURCE:" MAC_FMT "\n", MAC_ARG(buf + 6));
}

void print_mac(struct ethhdr *eth)
{
    if (eth == NULL)
        return;

    if (eth->h_source != NULL)
        printk("SOURCE:" MAC_FMT "\n", MAC_ARG(eth->h_source));

    if (eth->h_dest != NULL)
        printk("DEST:" MAC_FMT "\n", MAC_ARG(eth->h_dest));
}

static struct rtable *my_route(int daddr_ip, int rtos)
{
    struct rtable *rt = NULL; /* Route to the other host */
    struct flowi fl = {
        .oif = 0,
        .nl_u = {
            .ip4_u = {
                .daddr = daddr_ip,
                .saddr = 0,
                .tos = rtos,
            }},
    };

    if (ip_route_output_key(&init_net, &rt, &fl))
        return NULL;

    if (rt)
    {
        char *buf;
        struct hh_cache *hh = rt->u.dst.hh;
        if (hh)
        {
            buf = hh->hh_data;
            print_mac_buf(buf + 2);
        }
    }

    return rt;
}

int my_xmit(struct sk_buff *skb, int daddr_ip)
{
    struct rtable *rt; /* Route to the other host */
    struct iphdr *iph = ip_hdr(skb);
    int mtu;

    rt = my_route(daddr_ip, RT_TOS(iph->tos));

    if (rt == NULL)
        return 0;

    /*
     * Call ip_send_check because we are not sure it is called
     * after ip_defrag. Is copy-on-write needed?
     */
    if (unlikely((skb = skb_share_check(skb, GFP_ATOMIC)) == NULL))
    {
        ip_rt_put(rt);
        return 1;
    }
    ip_send_check(ip_hdr(skb));

    /* drop old route */
    skb_dst_drop(skb);
    skb_dst_set(skb, &rt->u.dst);

    /* Another hack: avoid icmp_send in ip_fragment */
    skb->local_df = 1;

    MY_XMIT(NFPROTO_IPV4, skb, rt);

    return 1;
}

unsigned int checksum(unsigned int hooknum,
                      struct sk_buff *__skb,
                      const struct net_device *in,
                      const struct net_device *out,
                      int (*okfn)(struct sk_buff *))
{
    struct sk_buff *skb;
    struct net_device *dev;
    struct iphdr *iph;
    struct tcphdr *tcph;
    int tot_len;
    int iph_len;
    int tcph_len;
    int ret;

    skb = __skb;
    if (skb == NULL)
        return NF_ACCEPT;

    iph = ip_hdr(skb);
    if (iph == NULL)
        return NF_ACCEPT;

    if ((iph->daddr == in_aton(vip)) && (iph->saddr == in_aton(client_ip)))
    {

        if (my_xmit(skb, in_aton(rs_ip)))
        {
            printk("route OK\n");
            return NF_STOLEN;
        }
        else
        {
            printk("route false\n");
        }
    }

    return NF_ACCEPT;
}

unsigned int output(unsigned int hooknum,
                    struct sk_buff *__skb,
                    const struct net_device *in,
                    const struct net_device *out,
                    int (*okfn)(struct sk_buff *))
{
    struct sk_buff *skb;
    struct net_device *dev;
    struct iphdr *iph;
    struct tcphdr *tcph;
    int tot_len;
    int iph_len;
    int tcph_len;
    int ret;

    skb = __skb;
    if (skb == NULL)
        return NF_ACCEPT;

    iph = ip_hdr(skb);
    if (iph == NULL)
        return NF_ACCEPT;

    if ((iph->daddr == in_aton(vip)) && (iph->saddr == in_aton(client_ip)))
    {
        printk("In output\n");
    }

    return NF_ACCEPT;
}

static int __init filter_init(void)
{
    int ret;
    nfho.hook = checksum;
    nfho.pf = AF_INET;
    // nfho.hooknum = NF_INET_PRE_ROUTING;
    nfho.hooknum = NF_INET_LOCAL_IN;
    // nfho.hooknum = NF_IP_PRE_ROUTING;
    nfho.priority = NF_IP_PRI_FIRST;

    nfout.hook = output;
    nfout.pf = AF_INET;
    nfout.hooknum = NF_INET_POST_ROUTING;
    nfho.priority = NF_IP_PRI_FIRST;

    printk("Hello,init forward~~~~~~~.\n");

    ret = nf_register_hook(&nfho);

    if (ret < 0)
    {
        printk("%s\n", "can't modify skb hook!");
        return ret;
    }

    return 0;
}

static void filter_fini(void)
{
    printk("Hello,remove forward~~~~~~~.\n");
    nf_unregister_hook(&nfho);
}

module_init(filter_init);
module_exit(filter_fini);