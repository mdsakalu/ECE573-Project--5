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
#define time_since_add(entry) (CURRENT_TIME.tv_sec)-(entry->timestamp)

//#define PORT 8072
#define PORT 80
#define MAX_RESPONSE_LEN 1024
//#define LOCALHOST htonl(0x7F000001);
#define LOCALHOST htonl(0x0A010101);
#define TABLE_SIZE 1024;

//struct to hold source/destination pairs
typedef struct {
	unsigned int dest_ip;
	unsigned int src_ip;
	//unsigned short int src_port;
} address_pair;

static address_pair table;
//address_pair address_table[TABLE_SIZE];
//static unsigned int table_index;

static int start = 1;
module_param(start, int, 0755);

struct cache {
    struct list_head list;
    char *tag;
    unsigned long int timestamp;
    char *modified;
    char *data;
} response_cache;

static int time = 3600;
static int size = 16384;

static struct nf_hook_ops netfilter_ops_in;
static struct nf_hook_ops netfilter_ops_out;
struct task_struct *main_thread;


/** Get the total size of the cache */
unsigned int cache_size()
{
    struct cache *tmp;
	unsigned int size = 0;

    list_for_each_entry(tmp, &response_cache.list, list) {
        size += strlen(tmp->data);
    }

    return size;
}


/** get the value of a particular HTTP header */
unsigned int get_header(char *http, char *key, char *destbuf)
{
	char buf[256];
    char *tmp;
	
	strcpy(buf, key);
	strcat(buf, ": %s");
	
    tmp = strstr(http, key);
    if (tmp) {
		sscanf(tmp, buf, destbuf);
		return 1;
	}
	else return 0;
}


/** Make room for new data */
void cache_make_room(unsigned int size)
{
    struct list_head *pos, *q;
    struct cache *tmp;
	
	// just blast away everything
    list_for_each_safe(pos, q, &response_cache.list) {
        tmp = list_entry(pos, struct cache, list);
        list_del(pos);
        kfree(tmp->tag);
        kfree(tmp->modified);
        kfree(tmp->data);
        kfree(tmp);
    }
}

/** Get the entry added long ago to the cache */
struct cache *cache_locate(char *tag)
{
    struct cache *tmp;

    list_for_each_entry(tmp, &response_cache.list, list) {
        if (0 == strcmp(tag, tmp->tag)) return tmp;
    }

    return 0;
}

#define MAX_TAG_LEN 512
#define MAX_MODIFIED_LEN 512

/** write buffer data to cache */
void cache_write(char *tag, char *data)
{
    struct cache *entry;
	char *tmp;
	
	printk("writing cache data '%s' for tag '%s'\n", data, tag);
	
	// replacement policy - if there's no room...destroy everything
	if (strlen(data) > size) { // data too big to fit in cache
		printk("unable to write data...larger than cache size\n");
		return;
	} else if ((size-cache_size()) < strlen(data)) { // cache is big enough...but has no room
		printk("evicting blocks\n");
		cache_make_room(strlen(data));
	}
	
	// XXX TODO replacement policy

	if ( (entry = cache_locate(tag))) {
	
		// _update_ the cache
		kfree(entry->data);
		entry->data = kmalloc(strlen(data)+1, GFP_KERNEL); // XXX +1 needed?
		strcpy(entry->data, data);
		
	} else {
		entry = (struct cache *) kmalloc(sizeof(struct cache), GFP_KERNEL);
		
		// set tag
		entry->tag = kmalloc(MAX_TAG_LEN, GFP_KERNEL);
		strcpy(entry->tag, tag);
		
		// set timestamp
		entry->timestamp = CURRENT_TIME.tv_sec;
		
		// set "last modified" date <--XXX use get_header()
		if ( (tmp = strstr(data, "Last-Modified: "))) {
			entry->modified = kmalloc(MAX_MODIFIED_LEN, GFP_KERNEL);
			sscanf(tmp, "Last-Modified: %s", entry->modified);
		} else {
			entry->modified = 0;
		}
		
		// set data
		entry->data = kmalloc(strlen(data)+1, GFP_KERNEL); // XXX +1 needed?
		strcpy(entry->data, data);
		
		list_add(&(entry->list), &(response_cache.list));
	}
}

/** read an entry to the cache into buffer $data */
char *cache_read(char *tag)
{
    struct cache *entry;
    entry = cache_locate(tag);
    return entry->data;
}

/**
 * Sends the specified raw HTTP request to a remote server.
 * If modified is set, it will be added to the request as the "If-Modified-Since"
 * header for a conditional GET request.
 *
 * The raw response given by the remote server will be copied into the response buffer.
 *
 * Function returns 1 if the resource was modified (or if a traditional GET request was sent).
 */
unsigned int __http_get(char *request, char *modified, char *data) // data must be of size MAX_RESPONSE_LEN
{
	unsigned int is_modified = 1;
	
	char host[256];
	char tmp[512]; // <-- max req len
	char newRequest[512]; // <-- max req len
	unsigned int port;
	
    ksocket_t sockfd_cli;
    struct sockaddr_in addr_srv;
    int addr_len;
	
	// if this is a conditional GET, add the modified date to the HTTP request headers
	if (modified) {
		strncpy(tmp, request, strlen(request)-2);
		tmp[strlen(request)-2] = '\0';
		sprintf(newRequest, "%sIf-Modified-Since: %s\r\n\r\n", tmp, modified);
	}
	
	// XXX Use get_addr_info() to resolve hostnames
	
	if (get_header(newRequest, "Host", host)) {
		printk("HTTP WWW GET request, host is %s\n", host);
	} else {
		// ERROR
		//strcpy(host,"152.1.226.20");
	}
	port = 80;
	
    memset(&addr_srv, 0, sizeof(addr_srv));
    addr_srv.sin_family = AF_INET;
    addr_srv.sin_port = htons(port);
    addr_srv.sin_addr.s_addr = inet_addr(host);
    addr_len = sizeof(struct sockaddr_in);

    sockfd_cli = ksocket(AF_INET, SOCK_STREAM, 0);
    if (sockfd_cli == NULL) {
        printk("socket failed\n");
		goto fail;
    }
    if (kconnect(sockfd_cli, (struct sockaddr*)&addr_srv, addr_len) < 0) {
        printk("connect failed\n");
		goto fail;
    }

	// XXX write response to buffer, check for 304 response
    printk("sent message : [[%s]]\n", newRequest);
	ksend(sockfd_cli, newRequest, strlen(newRequest), 0);
	krecv(sockfd_cli, data, MAX_RESPONSE_LEN, 0);
    printk("got message : %s\n", data);

    kclose(sockfd_cli);

	if (0 != strstr(data, "304 Not Modified")) { // it is not modified
		is_modified = 0;
		// not modified
	}
	
	return is_modified;

fail:
	printk("error performing WWW HTTP request...falling back to stale data\n");
	return -1;
}

unsigned int http_conditional_get(char *request, char *modified, char *data)
{
	int ret;
	if (-1 == (ret = __http_get(request, modified, data))) {
		return 0; // fall back to stale data
	} else {
		return ret;
	}
}

void http_get(char *request, char *data)
{
	if (-1 == __http_get(request, 0, data)) {
		printk("Error fetching data!\n");
		
		strcpy(data, "HTTP/1.0 404 Not Found\nLast-Modified: -\r\nThe server encountered an internal error.");
	}
}


/** send an HTTP response to the client */
void kcache_send_response(void *cli_sock, char *data, int len)
{	
    ksend(cli_sock, data, len, 0);
}

/** get the tag based on a HTTP request **/
// TODO error checking (request parsing + allocation
void get_tag(char *request, char *tag)
{
    char *host, *path;

    path = kmalloc(512, GFP_KERNEL);
    host = kmalloc(512, GFP_KERNEL);
    
    // get the path
    sscanf(request, "GET %s", path);

    // get the host
	get_header(request, "Host", host);

    strcpy(tag, host);
    strcat(tag, path);

    kfree(path);
    kfree(host);
}

/** get a HTTP response for a particular request (use cache or web) */
unsigned int kcache_get_response(char *request, char *data)
{
    struct cache *entry;
    char *tag;
    unsigned int modified;
	char *cached_data; // xxx can eliminate after testing

    tag = kmalloc(1024, GFP_KERNEL);
    get_tag(request, tag);
	printk("kcache: getting response for tag '%s'\n", tag);

	// general caching logic
	if ( (entry = cache_locate(tag))) {
		if (entry->modified) {
			modified = http_conditional_get(request, entry->modified, data);
			if (modified) {
				cache_write(tag, data);
			} else {
				cached_data = cache_read(tag);
				strcpy(data, cached_data);
			}
		} else if (time_since_add(entry) > time) {
			http_get(request, data);
			cache_write(tag, data);
		} else {
			cached_data = cache_read(tag);
			strcpy(data, cached_data);
		}
	} else {
		http_get(request, data);
		cache_write(tag, data);
	}

//done: // read data from cache
    kfree(tag);
	return strlen(data);
}

/** main caching functionality */
void kcache_handle_request(void *sock, char *request)
{
	char *buf;
	unsigned int len;

    if ( 0 == (buf = kmalloc(MAX_RESPONSE_LEN, GFP_KERNEL))) {
		printk("unable to allocate memory for response\n");
		return;
	}

	len = kcache_get_response(request, buf);
	kcache_send_response(sock, buf, len);

    kfree(buf);
}

void add_to_table(address_pair dest) {
	/*unsigned int i;
	for(i = 0; i < TABLE_SIZE; i++) {
		if(address_table[i].src_ip == dest.src_ip || address_table[i].src_ip == 0) {
			address_table[i] = dest;
			table_index++;
			break;
		}
	}*/
	table = dest;
}

unsigned int src_from_dest(unsigned int daddr) {
	/*unsigned int i;
	for(i = 0; i < TABLE_SIZE; i++) {
		if(address_table[i].src_ip == daddr) {
			return address_table[i].dest_ip;
		}
	}
	return 0;*/
	
	if(table.src_ip == daddr) {
		return table.dest_ip;
	}
	
	return 0;
}

void recalc_checksums(struct iphdr *iph, struct tcphdr *tcph, unsigned int len)
{
	iph->check = 0;
	iph->check = ip_fast_csum((u8 *)iph, iph->ihl);
	tcph->check = 0;
	tcph->check = tcp_v4_check(tcph, len-4*iph->ihl, iph->saddr, iph->daddr, csum_partial((char *)tcph, len-4*iph->ihl, 0));
	printk("checksum!\n");
}

/** munge outgoing port 80 TCP packet's source address */
void kcache_mangle_outgoing(struct iphdr *iph, struct tcphdr *tcph)
{
	unsigned int src;
	printk("Mangling outgoing packet. ");
	//see if this entry is in the table
	src = src_from_dest(iph->daddr);
	if(src != 0) {
		printk("Destination is in table, changing source to %d\n", src);
		//if it is, change the source address what is in the table
		iph->saddr = src;
			
	}
}

/** munge incoming port 80 TCP packet's destination address*/
void kcache_mangle_incoming(struct iphdr *iph, struct tcphdr *tcph)
{
	address_pair dest;
	
	//get destination  and source addresses
	dest.src_ip = iph->saddr;
	dest.dest_ip = iph->daddr;
	
	//add (or overwrite) entry in the table
	add_to_table(dest);
	
	printk("Mangling incoming packet, setting destination to localhost. Source is %d", dest.src_ip);
	/**	adjust the destination address
		this will make the request go to the caching proxy */
	iph->daddr = LOCALHOST; //localhost
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
		//printk("kcache: received connection...\n");        
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
	
	//printk("out_hook called\n");
	if (!start) return NF_ACCEPT;

    if (!skb) return NF_ACCEPT;
    if (! (iph = ip_hdr(skb))) return NF_ACCEPT;
	
    if ((iph->protocol == IPPROTO_TCP)) {
        tcph = get_tcp_hdr(iph);

		if (ntohs(tcph->source) == PORT) {
			printk("kcache: outgoing packet (TCP/port 80) intercepted -> " PKT_INFO_FMT ".\n", PKT_INFO(iph, tcph));
			
			kcache_mangle_outgoing(iph, tcph);
			//printk("kcache: outgoing packet (TCP/port 80) mangled     -> " PKT_INFO_FMT ".\n", PKT_INFO(iph, tcph));
			printk("initial ip csum: %x	initial tcp csum: %x\n",ntohs(iph->check), ntohs(tcph->check));
			recalc_checksums(iph, tcph, skb->len);
			printk("recalcd ip csum: %x	recalcd tcp csum: %x\n",ntohs(iph->check), ntohs(tcph->check));
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
	
	//printk("in_hook called\n");
	if (!start) return NF_ACCEPT;
	if (!skb) return NF_ACCEPT;
	iph = ip_hdr(skb);
    if (! (iph = ip_hdr(skb))) return NF_ACCEPT;
    if (iph->protocol == IPPROTO_TCP) {
        tcph = get_tcp_hdr(iph);
		if (ntohs(tcph->dest) == PORT) {
			//printk("kcache: incoming packet (TCP/port 80) intercepted -> " PKT_INFO_FMT ".\n", PKT_INFO(iph, tcph));
			
			kcache_mangle_incoming(iph, tcph);
			recalc_checksums(iph, tcph, skb->len);
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
	//unsigned int i;
    printk("kcache: module started.\n");

    INIT_LIST_HEAD(&response_cache.list);

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
    struct list_head *pos, *q;
    struct cache *tmp;

	// stop main thread
    if (TASK_RUNNING == main_thread->state) send_sig(9, main_thread, 0);

	// unregister netfilter hooks
	nf_unregister_hook(&netfilter_ops_in);
    nf_unregister_hook(&netfilter_ops_out);
	
	// free memory occupied by cache
    list_for_each_safe(pos, q, &response_cache.list) {
        tmp = list_entry(pos, struct cache, list);
        list_del(pos);
        kfree(tmp->tag);
        kfree(tmp->modified);
        kfree(tmp->data);
        kfree(tmp);
    }

	
    printk("kcache: module stopped.\n");
}

module_init(init);
module_exit(cleanup);

MODULE_LICENSE("GPL");
