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

static struct nf_hook_ops netfilter_ops_in;

//incoming hook
unsigned int in_hook(
	unsigned int hooknum,
	struct sk_buff *skb,
	const struct net_device *in,
	const struct net_device *out,
	int (*okfn)(struct sk_buff*))
{
	struct iphdr *iph;
	struct tcphdr *tcph;
	unsigned int len;
	
	printk("in hook called\n");
	if (!skb) return NF_ACCEPT;

	iph = ip_hdr(skb);
	if (!iph) return NF_ACCEPT;

	if (iph->protocol==IPPROTO_TCP){
		tcph = (struct tcphdr *)&(((char*)iph)[iph->ihl*4]);
		printk("got a TCP packet, dest port %d\n", ntohs(tcph->dest));
		
		//see if packet is an http packet (port 80)
		if(ntohs(tcph->dest) == 80) {
			printk("Packet has dest port 80\n");
			//if it is, change the destination address to localhost (our cache)
			printk("Changing destination to 127.0.0.1\n");
			iph->daddr = htonl(0x7F000001); //127.0.0.1
			printk("changed to %d\n",ntohl(iph->daddr));
			
			//checksum ip header
			iph->check = 0;
			iph->check = ip_fast_csum((u8 *)iph, iph->ihl); 
			
			//checksum tcp header
			len = skb->len;
			tcph->check = 0;
			tcph->check = tcp_v4_check(
				len - 4*iph->ihl,
				iph->saddr,
				iph->daddr,
				csum_partial((char *)tcph, len-4*iph->ihl, 0)
			);
		}
	}

	return NF_ACCEPT;
}

static int __init init(void)
{
	
	//configure NF_IP_PRE_ROUTING struct and register hook
	netfilter_ops_in.hook = in_hook;
	netfilter_ops_in.pf = PF_INET;                              
	netfilter_ops_in.hooknum = NF_INET_PRE_ROUTING;                 
	netfilter_ops_in.priority = NF_IP_PRI_FIRST;                    
	nf_register_hook(&netfilter_ops_in);                            
                     
	return 0;
}

static void __exit cleanup(void)
{
	//unregister hook
	nf_unregister_hook(&netfilter_ops_in);
	
}

module_init(init);
module_exit(cleanup);

MODULE_LICENSE("GPL");