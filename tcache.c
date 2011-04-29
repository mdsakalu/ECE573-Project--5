#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/socket.h>
#include <linux/net.h>
#include <net/sock.h>
#include <asm/processor.h>
#include <asm/uaccess.h>
#include <linux/in.h>
#include <linux/kthread.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/signal.h>
#include <linux/delay.h>
#include <linux/file.h>
#include <net/ksocket.h>
#include <linux/proc_fs.h>

#define MAX_REQUEST_LEN 512

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
    addr_srv.sin_port = htons(80);
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
        //printk("Client connected from %s:%d.\n", tmp, ntohs(addr_cli.sin_port));
        kfree(tmp);
        
        kthread_run(conn_handler, sockfd_cli, "httpcon");
    }

quit:
    kclose(sockfd_srv);
    return 0;
}

static int __init tcache_init(void)
{
    printk("Entered\n");
    entry();
    return 0;
}

static void __exit tcache_exit(void)
{
    printk("Exited\n");
}

module_init(tcache_init);
module_exit(tcache_exit);

MODULE_LICENSE("Dual BSD/GPL");
