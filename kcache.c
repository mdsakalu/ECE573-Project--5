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

#define MAX_REQUEST_LEN 512

#define SOURCE_PORT 8082

static struct nf_hook_ops netfilter_ops_in;

void http_err404(void *sock)
{
    char *buf;
    int len;

    buf = kmalloc(512, GFP_KERNEL);
    len = sprintf(buf, "HTTP/1.0 404 Not Found\r\n");
    ksend(sock, buf, len, 0);
    kfree(buf);
 
}

int conn_handler(void *sock)
{
    char request[MAX_REQUEST_LEN];
    int len;

    // read raw request
    memset(request, 0, sizeof(request));
    len = krecv(sock, request, sizeof(request), 0);

    if (len < 0) goto clean;

    printk("Received Request:[\n%s\n]\n", request);

    http_err404(sock);

clean:
    msleep(10);
    kclose(sock);
    return 0;
}

int entry(void)
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
    addr_srv.sin_port = htons(SOURCE_PORT);
    addr_srv.sin_addr.s_addr = INADDR_ANY;
    addr_len = sizeof(struct sockaddr_in);

    // create server socket, bind(), and listen()
    if (NULL == (sockfd_srv = ksocket(AF_INET, SOCK_STREAM, 0))) {
        printk("socket failed\n");
        goto quit;
    }
    if (kbind(sockfd_srv, (struct sockaddr *)&addr_srv, addr_len) < 0) {
        printk("bind failed\n");
        goto quit;
    }
    if (klisten(sockfd_srv, 10) < 0) {
        printk("listen failed\n");
        goto quit;
    }

    // accept connections until it kthread_should_stop() tells us not to
    while ((sockfd_cli = kaccept(sockfd_srv, (struct sockaddr *)&addr_cli, &addr_len)) != NULL) {
        tmp = inet_ntoa(&addr_cli.sin_addr);
        printk("Client connected from %s:%d.\n", tmp, ntohs(addr_cli.sin_port));
        kfree(tmp);
        
        kthread_run(conn_handler, sockfd_cli, "httpcon");
    }

quit:
    kclose(sockfd_srv);
    return 0;
}

//incoming hook
unsigned int in_hook(unsigned int hooknum, struct sk_buff **sb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff*))
{
    struct sk_buff *skb = *sb;
	struct iphdr *iph;
	struct tcphdr *tcph;
	unsigned int len;
	
	//printk("in hook called\n");
	if (!skb) return NF_ACCEPT;

	iph = ip_hdr(skb);
	if (!iph) return NF_ACCEPT;

	if (iph->protocol==IPPROTO_TCP){
		tcph = (struct tcphdr *)&(((char*)iph)[iph->ihl*4]);

		//printk("got a TCP packet, dest port %d\n", ntohs(tcph->dest));
		
		//see if packet is an http packet (port 80)
		if(ntohs(tcph->dest) == SOURCE_PORT) {

            printk("Incoming port 80 packet intercepted: " PKT_INFO_FMT ".\n", PKT_INFO(iph, tcph));

			//if it is, change the destination address to localhost (our cache)
			//printk("Changing destination to 127.0.0.1\n");
			iph->daddr = htonl(0x7F000001); //127.0.0.1
			//printk("changed to " NIPQUAD_FMT "\n",NIPQUAD(iph->daddr));
			
			//checksum ip header
			iph->check = 0;
			iph->check = ip_fast_csum((u8 *)iph, iph->ihl); 
			
			//checksum tcp header
			len = skb->len;
			tcph->check = 0;
            tcph->check = tcp_v4_check(tcph, len-4*iph->ihl, iph->saddr, iph->daddr, csum_partial((char *)tcph, len-4*iph->ihl, 0));

            printk("Packet transmogrified to: " PKT_INFO_FMT ".\n", PKT_INFO(iph, tcph));
		}
	}

	return NF_ACCEPT;
}

static int __init init(void)
{
    printk("kcache started.\n");
	
	//configure NF_IP_PRE_ROUTING struct and register hook
	netfilter_ops_in.hook = in_hook;
	netfilter_ops_in.pf = PF_INET;                              
	netfilter_ops_in.hooknum = NF_IP_PRE_ROUTING;//NF_INET_PRE_ROUTING;                 
	netfilter_ops_in.priority = NF_IP_PRI_FIRST;                    
	//nf_register_hook(&netfilter_ops_in);     

	entry();
                     
	return 0;
}

static void __exit cleanup(void)
{
    printk("kcache stopped.\n");

	//unregister hook
	nf_unregister_hook(&netfilter_ops_in);
	
}

module_init(init);
module_exit(cleanup);

MODULE_LICENSE("GPL");
