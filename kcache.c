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

#define PORT 9001

static int start = 1;
module_param(start, int, 0755);

static int time = 3600;
static int size = 16384;

static struct nf_hook_ops netfilter_ops_in;
static struct nf_hook_ops netfilter_ops_out;
struct task_struct *main_thread;

// XXX test struct / message passing shit in dev-c++
// xXX need to implement LRU-type replacement policy?...no, not in spec / no config
// XXXXXXX cache_write() and http_get() are the two main functions for cacheing

struct cache_entry {
	char* data;
	char *last_modified;
	int expiry;
};

/** parse a raw request string, concatenate the host and path fields to form tag */
char *get_tag(char *request)
{
	// XXX just a little string mangling
}

/** locate the entry in the cache */
unsigned int cache_locate(char *request, struct cache_entry *dest)
{
	char* tag;
	
	tag = get_tag(request);

	// XXX need linked list for cache data structure
	// XXX traverse the list, look for one with entry.tag == 
	// XXX must honor NULL $dest
}

/** does the cache contain corresponding response? */
unsigned int cache_contains(char *request)
{
	return cache_locate(request. NULL);
}

/** does the cache's entry for response have a valid "last modified" field */
unsigned int cache_has_modified_date(char *request)
{
	struct cache_entry entry;
	cache_locate(request, &entry);
	if (entry.last_modified) return 1; // XXX it's a string...this won't work
	else return 0;
}

/** retrieve the "last modified" date associated with a request */
char * cache_get_modified_date(char *request)
{
	struct cache_entry entry;
	cache_locate(request, &entry);
	return entry.last_modified;
}

/** is the cache entry for request expired? */
unsigned int cache_is_expired(char *request)
{
	struct cache_entry entry;
	cache_locate(request, &entry);
	
	// XXX time compare should be easy with LKM ktime() functionality
	if (/* entry.expiry > time() */) return 1;
	else return 0;
}

/** read response data from the cache */
void cache_read(char *request, char *data)
{
	struct cache_entry entry;
	cache_locate(request, &entry);
	data = entry.data;
}

/** write the response into the cache, return the "data" placed in the cache */
void cache_write(char *request, char *response, char *data)
{
	struct cache_entry entry;
	
	// XXX allocate new cache entry if need be...reuse cache_locate function?
	// XXX pull body/headers out of response
	// xXX write to cache
	
	data = entry.data;
}

/** send an HTTP GET request to a remote server */
// XXX document conditional / return val behavior
unsigned int http_get(char *request, ??? if_modified_since, char *response)
{
	// XXXXX since "last modified" date is only useful for sending to conditional GET as "if modified since", we can store it as a string
	// XXX do addr_info() stuff to get IP of dest.
	// XXX ksocket_request() similar to kcache_send_response()
	// XXX other shit
}

/** send an HTTP response */
void kcache_send_response(void *sock, char *data, int len)
{
	// XXX add HTTP 200 prefix
	// XXX currently doesn't work

    ksend(sock, data, len, 0);
}

/** get a HTTP response for a particular request (use cache or web) */
unsigned int kcache_get_response(char *request, char *data)
{
	char *web_response;
	char *data;
	unsigned int modified;

	if (cache_contains(request)) {
		if (cache_has_modified_date(request)) {
			modified = http_get(request, cache_get_modified_date(request), web_response);
			if (modified) {
				cache_write(request, web_response, data)
			} else {
				cache_read(request, data);
			}
		} else if (cache_is_expired(request)) {
			http_get(request, NULL, web_response);
			cache_write(request, web_response, data);
		} else {
			cache_read(request, data);
		}
	} else {
		http_get(request, NULL, web_response);
		cache_write(request, web_response, data);
	}
	
	return strlen(data);
}

/** main caching functionality */
void kcache_handle_request(void *sock, char *request)
{
	char *data;
	unsigned int len;

	len = kcache_get_response(request, data);
	kcache_send_response(sock, data, len);
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
	kcache_handle_request(sock, request);

clean:
    msleep(100);
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
	printk("kcache: listening...\n");
    while ((sockfd_cli = kaccept(sockfd_srv, (struct sockaddr *)&addr_cli, &addr_len)) != NULL) {
		printk("kcache: received connection...\n");        
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
	
    printk("kcache: module started.\n");

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
