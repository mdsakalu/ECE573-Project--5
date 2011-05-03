#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <net/tcp.h>
#include <linux/proc_fs.h>	
#include <asm/uaccess.h>	
#include <linux/string.h>
#include <linux/socket.h>
#include <linux/net.h>
#include <net/sock.h>
#include <asm/processor.h>
#include <linux/kthread.h>
#include <linux/slab.h>
#include <linux/signal.h>
#include <linux/delay.h>
#include <linux/file.h>
#include <net/ksocket.h>

#define PKT_INFO(iph, tcph) NIPQUAD (iph->saddr), ntohs(tcph->source), NIPQUAD(iph->daddr), ntohs(tcph->dest)
#define PKT_INFO_FMT "(src: " NIPQUAD_FMT ":%u, dst: " NIPQUAD_FMT ":%u)"

#define PORT 80

static int start = 0;
module_param(start, int, 0755);

static int time = 3600;
static int size = 16384;

static struct nf_hook_ops netfilter_ops_in;
static struct nf_hook_ops netfilter_ops_out;
struct task_struct *main_thread;

/** main caching functionality */
void kcache_handle_request(char *request)
{
	// XXX
}

/** munge outgoing port 80 TCP packet's source address */
void kcache_mangle_outgoing(struct iphdr *iph, struct tcphdr *tcph)
{
	// XXX
}

/** munge incoming port 80 TCP packet's destination address */
void kcache_mangle_incoming(struct iphdr *iph, struct tcphdr *tcph)
{
	// XXX

	//iph->daddr = htonl(0x7F000001);
}

struct tcphdr* get_tcp_hdr(struct iphdr *iph)
{
    return (struct tcphdr *)&(((char*)iph)[iph->ihl*4]);
}

/** handle a socket connection (short-running thread) */
int kcache_handler(void *sock)
{
    char request[512];
    int len;
	
	if (!start) goto clean;

    // read raw data (presumed HTTP request)
    memset(request, 0, sizeof(request));
    len = krecv(sock, request, sizeof(request), 0);
    if (len < 0) goto clean;

    printk("kcache: received request:[\n%s\n]\n", request);
	kcache_handle_request(request);

clean:
    msleep(10);
    kclose(sock);
    return 0;
}

/** main HTTP web server (long-running thread) */
int kcache_main(void *arg)
{
    ksocket_t sockfd_srv, sockfd_cli;
    struct sockaddr_in addr_srv;
    struct sockaddr_in addr_cli;
    int addr_len;
    char *tmp;

    // prepare sockets
    sockfd_srv = sockfd_cli = NULL;
    memset(&addr_cli, 0, sizeof(addr_cli));
    memset(&addr_srv, 0, sizeof(addr_srv));
    addr_srv.sin_family = AF_INET;
    addr_srv.sin_port = htons(PORT);
    addr_srv.sin_addr.s_addr = INADDR_ANY;
    addr_len = sizeof(struct sockaddr_in);

    // create server socket, bind(), and listen()
    if (NULL == (sockfd_srv = ksocket(AF_INET, SOCK_STREAM, 0))) {
        printk("kcache: socket failed\n");
        goto quit;
    }
    if (kbind(sockfd_srv, (struct sockaddr *)&addr_srv, addr_len) < 0) {
        printk("kcache: bind failed\n");
        goto quit;
    }
    if (klisten(sockfd_srv, 10) < 0) {
        printk("kcache: listen failed\n");
        goto quit;
    }

    // accept connections until it kthread_should_stop() tells us not to
    while ((sockfd_cli = kaccept(sockfd_srv, (struct sockaddr *)&addr_cli, &addr_len)) != NULL) {
        tmp = inet_ntoa(&addr_cli.sin_addr);
        kfree(tmp);
        
        kthread_run(kcache_handler, sockfd_cli, "kcache_handler");
    }

quit:
    kclose(sockfd_srv);
    return 0;
}

/** NF_IP_POST_ROUTING netfilter hook */
unsigned int out_hook(unsigned int hooknum, struct sk_buff **sb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff*))
{
    struct sk_buff *skb = *sb;
    struct iphdr *iph;
    struct tcphdr *tcph;
	
	if (!start) return NF_ACCEPT;

    if (!skb) return NF_ACCEPT;
    if (! (iph = ip_hdr(skb))) return NF_ACCEPT;

    if ((iph->protocol == IPPROTO_TCP)) {
        tcph = get_tcp_hdr(iph);
		if (ntohs(tcph->dest) == PORT) {
			printk("kcache: outgoing packet (TCP/port 80) intercepted -> " PKT_INFO_FMT ".\n", PKT_INFO(iph, tcph));
			
			kcache_mangle_outgoing(iph, tcph);
		}
    }
    
    return NF_ACCEPT;
}

/** NF_IP_PRE_ROUTING netfilter hook to */
unsigned int in_hook(unsigned int hooknum, struct sk_buff **sb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff*))
{
    struct sk_buff *skb = *sb;
	struct iphdr *iph;
	struct tcphdr *tcph;
	unsigned int len;
	
	if (!start) return NF_ACCEPT;
	
	if (!skb) return NF_ACCEPT;

	iph = ip_hdr(skb);
    if (! (iph = ip_hdr(skb))) return NF_ACCEPT;

    if (iph->protocol == IPPROTO_TCP) {
        tcph = get_tcp_hdr(iph);
		if (ntohs(tcph->dest) == PORT) {
			printk("kcache: incoming packet (TCP/port 80) intercepted -> " PKT_INFO_FMT ".\n", PKT_INFO(iph, tcph));
			
			kcache_mangle_incoming(iph, tcph);
			
			// re-calculate checksums, as packet changed
			iph->check = 0;
			iph->check = ip_fast_csum((u8 *)iph, iph->ihl); 
			len = skb->len;
			tcph->check = 0;
			tcph->check = tcp_v4_check(tcph, len-4*iph->ihl, iph->saddr, iph->daddr, csum_partial((char *)tcph, len-4*iph->ihl, 0));
		}
	}

	return NF_ACCEPT;
}

int size_write(struct file *filp, const char __user *buff, unsigned long len, void *data)
{
    char* buf = kmalloc(len, GFP_KERNEL);

    if (copy_from_user(buf, buff, len)) return -EFAULT;
    buf[len] = '\0';
    size = (int) simple_strtol(buf, NULL, 10);

    kfree(buf);
    return len;
}

int size_read(char* page, char** start, off_t off, int count, int* eof, void* data)
{
    sprintf(page, "%d", size);
    return strlen(page)+1;
}

int time_write(struct file *filp, const char __user *buff, unsigned long len, void *data)
{
    char* buf = kmalloc(len, GFP_KERNEL);

    if (copy_from_user(buf, buff, len)) return -EFAULT;
    buf[len] = '\0';
    time = (int) simple_strtol(buf, NULL, 10);

    kfree(buf);
    return len;
}

int time_read(char* page, char** start, off_t off, int count, int* eof, void* data)
{
    sprintf(page, "%d", time);
    return strlen(page)+1;
}

static int __init init(void)
{
    struct proc_dir_entry *kcache_dir, *time, *size;

    kcache_dir = proc_mkdir("kcache", NULL);

    time = create_proc_entry("time", 0755, kcache_dir);
    time->write_proc = time_write;
    time->read_proc = time_read;

    size = create_proc_entry("size", 0755, kcache_dir);
    size->write_proc = size_write;
    size->read_proc = size_read;
	
    main_thread = kthread_run(kcache_main, NULL, "kcache_main");
	
	netfilter_ops_in.hook = in_hook;
	netfilter_ops_in.pf = PF_INET;                              
	netfilter_ops_in.hooknum = NF_IP_PRE_ROUTING;
	netfilter_ops_in.priority = NF_IP_PRI_FIRST;
	
	netfilter_ops_out.hook = out_hook;
	netfilter_ops_out.pf = PF_INET;
	netfilter_ops_out.hooknum = NF_IP_POST_ROUTING;
	netfilter_ops_out.priority = NF_IP_PRI_LAST;

	nf_register_hook(&netfilter_ops_in);
    nf_register_hook(&netfilter_ops_out);

    printk("kcache: module started.\n");
	return 0;
}

static void __exit cleanup(void)
{
    if (TASK_RUNNING == main_thread->state) send_sig(9, main_thread, 0);

	nf_unregister_hook(&netfilter_ops_in);
    nf_unregister_hook(&netfilter_ops_out);
	
    printk("kcache: module stopped.\n");
}

module_init(init);
module_exit(cleanup);

MODULE_LICENSE("GPL");
