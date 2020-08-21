#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/queue.h>
#include <netinet/in.h>
#include <setjmp.h>
#include <stdarg.h>
#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdbool.h>
#include <sys/time.h>
#include"pkts_analysis.h"

#include <rte_common.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_memzone.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_launch.h>
#include <rte_atomic.h>
#include <rte_cycles.h>
#include <rte_prefetch.h>
#include <rte_lcore.h>
#include <rte_per_lcore.h>
#include <rte_branch_prediction.h>
#include <rte_interrupts.h>
#include <rte_pci.h>
#include <rte_random.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_hash_crc.h>

int fd;

#define MAX_TIMER_PERIOD 86400 /* 1 day max */
/* A tsc-based timer responsible for triggering statistics printout */
static uint64_t timer_period = 10; /* default period is 10 seconds */

/* MAC updating enabled by default */
static int mac_updating = 1;

static volatile bool force_quit;
static unsigned int l2fwd_rx_queue_per_lcore = 1;

#define RTE_LOGTYPE_MYPDUMP RTE_LOGTYPE_USER1

/*内存池开出的mbuf的个数*/
#define NB_MBUF 32768

#define MAX_PKT_BURST 32
#define BURST_TX_DRAIN_US 100 /* TX drain every ~100us */
#define MEMPOOL_CACHE_SIZE 256

struct rte_mempool *mbuf_pool = NULL;   

/*
 * Configurable number of RX/TX ring descriptors
 */
#define RTE_TEST_RX_DESC_DEFAULT 128
#define RTE_TEST_TX_DESC_DEFAULT 512
static uint16_t nb_rxd = RTE_TEST_RX_DESC_DEFAULT;
static uint16_t nb_txd = RTE_TEST_TX_DESC_DEFAULT;

#define MAX_RX_QUEUE_PER_LCORE 16
#define MAX_TX_QUEUE_PER_PORT 16
struct lcore_queue_conf {
    unsigned n_rx_port;
    unsigned rx_port_list[MAX_RX_QUEUE_PER_LCORE];
} __rte_cache_aligned;
struct lcore_queue_conf lcore_queue_conf[RTE_MAX_LCORE];

static const struct rte_eth_conf port_conf = {
    .rxmode = {
        .split_hdr_size = 0,
        .header_split   = 0, /**< Header Split disabled */
        .hw_ip_checksum = 0, /**< IP checksum offload disabled */
        .hw_vlan_filter = 0, /**< VLAN filtering disabled */
        .jumbo_frame    = 0, /**< Jumbo Frame Support disabled */
        .hw_strip_crc   = 1, /**< CRC stripped by hardware */
    },
    .txmode = {
        .mq_mode = ETH_MQ_TX_NONE,
    },
};

/*全局变量：统计值*/
struct l2fwd_port_statistics port_statistics[RTE_MAX_ETHPORTS];

/* mask of enabled ports */
static uint32_t l2fwd_enabled_port_mask = 0;


/* display usage */
    static void
l2fwd_usage(const char *prgname)
{
    printf("%s [EAL options] -- -p PORTMASK [-q NQ]\n"
            "  -p PORTMASK: hexadecimal bitmask of ports to configure\n"
            "  -q NQ: number of queue (=ports) per lcore (default is 1)\n"
            "  -T PERIOD: statistics will be refreshed each PERIOD seconds (0 to disable, 10 default, 86400 maximum)\n"
            "  --[no-]mac-updating: Enable or disable MAC addresses updating (enabled by default)\n"
            "      When enabled:\n"
            "       - The source MAC address is replaced by the TX port MAC address\n"
            "       - The destination MAC address is replaced by 02:00:00:00:00:TX_PORT_ID\n",
            prgname);
}

    static int
l2fwd_parse_portmask(const char *portmask)
{
    char *end = NULL;
    unsigned long pm;

    /* parse hexadecimal string */
    pm = strtoul(portmask, &end, 16);
    if ((portmask[0] == '\0') || (end == NULL) || (*end != '\0'))
        return -1;

    if (pm == 0)
        return -1;

    return pm;
}

    static unsigned int
l2fwd_parse_nqueue(const char *q_arg)
{
    char *end = NULL;
    unsigned long n;

    /* parse hexadecimal string */
    n = strtoul(q_arg, &end, 10);
    if ((q_arg[0] == '\0') || (end == NULL) || (*end != '\0'))
        return 0;
    if (n == 0)
        return 0;
    if (n >= MAX_RX_QUEUE_PER_LCORE)
        return 0;

    return n;
}

    static int
l2fwd_parse_timer_period(const char *q_arg)
{
    char *end = NULL;
    int n;

    /* parse number string */
    n = strtol(q_arg, &end, 10);
    if ((q_arg[0] == '\0') || (end == NULL) || (*end != '\0'))
        return -1;
    if (n >= MAX_TIMER_PERIOD)
        return -1;

    return n;
}

/* Parse the argument given in the command line of the application */
    static int
l2fwd_parse_args(int argc, char **argv)
{
    int opt, ret, timer_secs;
    char **argvopt;
    int option_index;
    char *prgname = argv[0];
    static struct option lgopts[] = {
        { "mac-updating", no_argument, &mac_updating, 1},
        { "no-mac-updating", no_argument, &mac_updating, 0},
        {NULL, 0, 0, 0}
    };

    argvopt = argv;

    while ((opt = getopt_long(argc, argvopt, "p:q:T:",
                    lgopts, &option_index)) != EOF) {

        switch (opt) {
            /* portmask */
            case 'p':
                l2fwd_enabled_port_mask = l2fwd_parse_portmask(optarg);
                if (l2fwd_enabled_port_mask == 0) {
                    printf("invalid portmask\n");
                    l2fwd_usage(prgname);
                    return -1;
                }
                break;

                /* nqueue */
            case 'q':
                l2fwd_rx_queue_per_lcore = l2fwd_parse_nqueue(optarg);
                if (l2fwd_rx_queue_per_lcore == 0) {
                    printf("invalid queue number\n");
                    l2fwd_usage(prgname);
                    return -1;
                }
                break;

                /* timer period */

            case 'T':
                timer_secs = l2fwd_parse_timer_period(optarg);
                if (timer_secs < 0) {
                    printf("invalid timer period\n");
                    l2fwd_usage(prgname);
                    return -1;
                }
                timer_period = timer_secs;
                break;

                /* long options */
            case 0:
                break;

            default:
                l2fwd_usage(prgname);
                return -1;
        }
    }

    if (optind >= 0)
        argv[optind-1] = prgname;

    ret = optind-1;
    optind = 0; /* reset getopt lib */
    return ret;
}


/* Check the link status of all ports in up to 9s, and print them finally */
    static void
check_all_ports_link_status(uint8_t port_num, uint32_t port_mask)
{
#define CHECK_INTERVAL 100 /* 100ms */
#define MAX_CHECK_TIME 90 /* 9s (90 * 100ms) in total */
    uint8_t portid, count, all_ports_up, print_flag = 0;
    struct rte_eth_link link;

    printf("\nChecking link status");
    fflush(stdout);
    for (count = 0; count <= MAX_CHECK_TIME; count++) {
        if (force_quit)
            return;
        all_ports_up = 1;
        for (portid = 0; portid < port_num; portid++) {
            if (force_quit)
                return;
            if ((port_mask & (1 << portid)) == 0)
                continue;
            memset(&link, 0, sizeof(link));
            rte_eth_link_get_nowait(portid, &link);
            /* print link status if flag set */
            if (print_flag == 1) {
                if (link.link_status)
                    printf("Port %d Link Up - speed %u "
                            "Mbps - %s\n", (uint8_t)portid,
                            (unsigned)link.link_speed,
                            (link.link_duplex == ETH_LINK_FULL_DUPLEX) ?
                            ("full-duplex") : ("half-duplex\n"));
                else
                    printf("Port %d Link Down\n",
                            (uint8_t)portid);
                continue;
            }
            /* clear all_ports_up flag if any link down */
            if (link.link_status == ETH_LINK_DOWN) {
                all_ports_up = 0;
                break;
            }
        }
        /* after finally printing all link status, get out */
        if (print_flag == 1)
            break;

        if (all_ports_up == 0) {
            printf(".");
            fflush(stdout);
            rte_delay_ms(CHECK_INTERVAL);
        }

        /* set the print_flag if all ports up or timeout */
        if (all_ports_up == 1 || count == (MAX_CHECK_TIME - 1)) {
            print_flag = 1;
            printf("done\n");
        }
    }
}


static void signal_handler(int signum)
{
    if (signum == SIGINT || signum == SIGTERM) {
        printf("\n\nSignal %d received, preparing to exit...\n",
                signum);
        force_quit = true;
    }
}

/*统计server port*/
static int serverPort_statistics(unsigned portid)
{
    int i,pos,key;
    port_statistics[portid].unique_port_count = 0;
    memset(&port_statistics[portid].unique_serv_port, 0, sizeof(port_statistics[portid].unique_serv_port));

    for (pos = 0; pos < MAX_FLOW_NUMBER; pos++){
        if (flow[pos].count == 0)
            continue;
        key = rte_hash_crc((void *)&flow[pos].tuple.port_dst,sizeof(flow[pos].tuple.port_dst),0) & 0x000003ff;
        if (port_statistics[portid].unique_serv_port[key] == 0){
            port_statistics[portid].unique_serv_port[key] = flow[pos].tuple.port_dst;
            port_statistics[portid].unique_port_count++;
        }
        else if (port_statistics[portid].unique_serv_port[key] == flow[pos].tuple.port_dst)
            continue;
        else if (port_statistics[portid].unique_serv_port[key] != flow[pos].tuple.port_dst){
            for (i = key + 1; i < 2048; i++)//冲突处理
            {
                if (port_statistics[portid].unique_serv_port[i % 1024] == 0){
                    port_statistics[portid].unique_serv_port[i % 1024] = flow[pos].tuple.port_dst;
                    port_statistics[portid].unique_port_count++;
                    break;
                }
                else if (port_statistics[portid].unique_serv_port[key] == flow[i % 1024].tuple.port_dst)
                    break;
                else if (port_statistics[portid].unique_serv_port[key] != flow[i % 1024].tuple.port_dst)
                    continue;
            }
        }
    }
    return 0;

}

/*统计前20个最常见的server IP*/
static int f20_serverIP_sort(void)
{
    int i,k;
    for (k = 0; k < MAX_SERVERIP; k++)
    {
        if (serverIP[k].count == 0)
            continue;

        for (i = 19; i >= 0; i--)
        {
            if (f20_serverIP[i].count < serverIP[k].count && i != 19)
                f20_serverIP[i + 1] = f20_serverIP[i];
            else if (f20_serverIP[i].count < serverIP[k].count && i == 19)
                continue;
            else
                break;
        }
        if (i >= -1 && i < 19 && f20_serverIP[i + 1].count < serverIP[k].count)
            f20_serverIP[i + 1] = serverIP[k];

    }
    return 0;

}

/*统计前20个传输字节数最多的的server IP*/
static int f20_bytes_serverIP_sort(void)
{
    int i,k;
    for (k = 0; k < MAX_SERVERIP; k++)
    {
        if (serverIP[k].count == 0)
            continue;

        for (i = 19; i >= 0; i--)
        {
            if (f20_bytes_serverIP[i].total_bytes < serverIP[k].total_bytes && i != 19)
                f20_bytes_serverIP[i + 1] = f20_bytes_serverIP[i];
            else if (f20_bytes_serverIP[i].total_bytes < serverIP[k].total_bytes && i == 19)
                continue;
            else
                break;
        }
        if (i >= -1 && i < 19 && f20_bytes_serverIP[i + 1].total_bytes < serverIP[k].total_bytes)
            f20_bytes_serverIP[i + 1] = serverIP[k];

    }
    return 0;

}


/* Print out statistics on packets dropped */
    static void
print_stats(void)
{
    uint64_t total_packets_dropped, total_packets_rx;
    unsigned portid;
    int i;

    total_packets_dropped = 0;
    total_packets_rx = 0;

    const char clr[] = { 27, '[', '2', 'J', '\0' };
    const char topLeft[] = { 27, '[', '1', ';', '1', 'H','\0' };

    /* Clear screen and move to top left */
    printf("%s%s", clr, topLeft);
    
    /*统计前20个最常见的serverIP*/
    f20_serverIP_sort();
    /*统计前20个传输字节数最多的的server IP*/
    f20_bytes_serverIP_sort();
    
    gettimeofday(&port_statistics[0].end_time,NULL);//获取跟踪结束时间
    printf("\nPort statistics ====================================");

    for (portid = 0; portid < RTE_MAX_ETHPORTS; portid++) {
        /* skip disabled ports */
        if ((l2fwd_enabled_port_mask & (1 << portid)) == 0)
            continue;

        /*统计server port*/
        serverPort_statistics(portid);

        printf("\nStatistics for port %u ------------------------------"
                "\nPackets received: %20"PRIu64
                "\nPackets dropped: %21"PRIu64
                "\nPackets udp_pkts: %21"PRIu64
                "\nPackets tcp_pkts: %21"PRIu64
                "\nPackets FIN_pkts: %21"PRIu64
                "\nPackets SYN_pkts: %21"PRIu64
                "\nPackets RST_pkts: %21"PRIu64
                "\nPackets DNS_pkts: %21"PRIu64
                "\nPackets ICMP_pkts: %21"PRIu64,
                portid,
                port_statistics[portid].rx,
                port_statistics[portid].dropped,
                port_statistics[portid].udp_pkts,
                port_statistics[portid].tcp_pkts,
                port_statistics[portid].FIN_pkts,
                port_statistics[portid].SYN_pkts,
                port_statistics[portid].RST_pkts,
                port_statistics[portid].DNS_pkts,
                port_statistics[portid].ICMP_pkts);

        total_packets_dropped += port_statistics[portid].dropped;
        total_packets_rx += port_statistics[portid].rx;
    }
    printf("\nAggregate statistics ==============================="
            "\nTotal packets received: %14"PRIu64
            "\nTotal packets dropped: %15"PRIu64,
            total_packets_rx,
            total_packets_dropped);
    printf("\n====================================================\n");


    printf("\n\nPacket-level statistics ====================================\n");

    for (portid = 0; portid < RTE_MAX_ETHPORTS; portid++) {
        /* skip disabled ports */
        if ((l2fwd_enabled_port_mask & (1 << portid)) == 0)
            continue;
        printf("\nStatistics for port %u ------------------------------"
                "\nPackets total_pkts_size: %21"PRIu64
                "\nPackets f100_pkts_size: %22"PRIu64
                "\nPackets f100_size_with_direction: %12ld"
                "\nPackets unique_port_number: %18d",
                portid,
                port_statistics[portid].total_pkts_size,
                port_statistics[portid].f100_pkts_size,
                port_statistics[portid].f100sz_with_dir,
                port_statistics[portid].unique_port_count);

        printf("\nf30_pkts:\t");
        for (i = 0; i < 30; i++){
            printf("%4d ",port_statistics[portid].f30_pkts[i]);
        }
        printf("\nf30_in_pkts:\t");
        for (i = 0; i < 30; i++){
            printf("%4d ",port_statistics[portid].f30_in_pkts[i]);
        }
        printf("\nf30_out_pkts:\t");
        for (i = 0; i < 30; i++){
            printf("%4d ",port_statistics[portid].f30_out_pkts[i]);
        }
        printf("\nf30_pkts_fTCP:\t");
        for (i =0; i < 30; i++){
            printf("%4d ",port_statistics[portid].f30_pkts_fTCP[i]);
        }
        printf("\nf30_inpkts_fTCP:\t");
        for (i = 0; i < 30; i++){
            printf("%4d ",port_statistics[portid].f30_inpkts_fTCP[i]);
        }
        printf("\nf30_outpkts_fTCP:\t");
        for (i = 0; i < 30; i++){
            printf("%4d ",port_statistics[portid].f30_outpkts_fTCP[i]);
        }
        printf("\nf300_outpkts_pos:\t");
        for (i = 0; i < 300; i++){
            printf("%4d ",port_statistics[portid].f300_outpkts_pos[i]);
        }
        printf("\nf300_outpkts_prepos:\t");
        for (i = 0; i < 300; i++){
            printf("%4d ",port_statistics[portid].f300_outpkts_prepos[i]);
        }
        printf("\nf300_inpkts_pos:\t");
        for (i = 0; i < 300; i++){
            printf("%4d ",port_statistics[portid].f300_inpkts_pos[i]);
        }
        printf("\nf300_inpkts_prepos:\t");
        for (i = 0; i < 300; i++){
            printf("%4d ",port_statistics[portid].f300_inpkts_prepos[i]);
        }

        printf("\nunique_serverIP_count: %d",port_statistics[portid].unique_serverIP_count);
        printf("\nserverIP\tserverIP_count\n");
        for (i = 0; i < 20; i++){
            printf("%d.%d.%d.%d\t\t%d\n",f20_serverIP[i].server_ip[0],f20_serverIP[i].server_ip[1],f20_serverIP[i].server_ip[2],f20_serverIP[i].server_ip[3],f20_serverIP[i].count);
        }
        printf("\nserverIP\tserverIP_totalbytes\n");
        for (i = 0; i < 20; i++){
            printf("%d.%d.%d.%d\t\t%lu\n",f20_bytes_serverIP[i].server_ip[0],f20_bytes_serverIP[i].server_ip[1],f20_bytes_serverIP[i].server_ip[2],f20_bytes_serverIP[i].server_ip[3]f20_bytes_serverIP[i].total_bytes);
        }
        /*清零f20_serverIP计数*/
        memset(&f20_serverIP, 0, sizeof(f20_serverIP));
        memset(&f20_bytes_serverIP, 0, sizeof(f20_bytes_serverIP));

    }

    printf("\n==============================================================\n");


    printf("\n\nFlow statistics,have %lu flows ====================================\n",port_statistics[portid].flow_count);

    char ip_src[16],ip_dst[16];
    double ratio_of_innumber;//每条TCP连接的入向包所占比例
    int j;

    for (i = 0; i < MAX_FLOW_NUMBER; i++)
    {
        if (flow[i].count == 0)
            continue;
        inet_ntop(AF_INET,&(flow[i].tuple.ip_src),ip_src,sizeof(ip_src));
        inet_ntop(AF_INET,&(flow[i].tuple.ip_dst),ip_dst,sizeof(ip_dst));
        printf("%dth flow:\thave %d pkts\thost_ip:%s\tserver_ip:%s\thost_port:%d\tserver_port:%d\n",flow[i].flow_id,flow[i].count,ip_src,ip_dst,ntohs(flow[i].tuple.port_src),ntohs(flow[i].tuple.port_dst));

        ratio_of_innumber = (double)flow[i].incoming_number / (double)flow[i].count;
        printf("total_number: %d\toutgoing_number: %d\tincoming_number: %d\tratio_of_innumber: %.2f\n",flow[i].count,flow[i].outgoing_number,flow[i].incoming_number,ratio_of_innumber);

        flow[i].ratio_of_inbytes = (double)flow[i].incoming_bytes / (double)flow[i].total_bytes;//统计每条流的入向字节数所占比例
        printf("total_bytes: %d\toutgoing_bytes: %d\tincoming_bytes: %d\tratio_of_inbytes: %.2f",flow[i].total_bytes,flow[i].outgoing_bytes,flow[i].incoming_bytes,flow[i].ratio_of_inbytes);

        printf("\nf20_largest_bytes:\t");
        for (j = 0; j < 20; j++)
        {
            printf("%4d ",flow[i].f20_largest_bytes[j]);
        }
        printf("\nf20_largest_inbytes:\t");
        for (j = 0; j < 20; j++)
        {
            printf("%4d ",flow[i].f20_largest_inbytes[j]);
        }
        printf("\nf20_largest_outbytes:\t");
        for (j = 0; j < 20; j++)
        {
            printf("%4d ",flow[i].f20_largest_outbytes[j]);
        }

        flow[i].ratio_inbytes_by80_443 = (double)flow[i].inbytes_by80_443 / (double)flow[i].totalbytes_by80_443;//统计每条流通过80/443传输的入向字节数所占比例
        printf("\ntotalbytes_by80_443: %lu\tinbytes_by80_443: %lu\toutbytes_by80_443: %lu\tratio_inbytes_by80_443: %.2f",flow[i].totalbytes_by80_443,flow[i].inbytes_by80_443,flow[i].outbytes_by80_443,flow[i].ratio_inbytes_by80_443);
        printf("\n\n");

    }
    printf("\n====================================================\n");
}


/* main processing loop */
static void l2fwd_main_loop(void)
{
    struct rte_mbuf *pkts_burst[MAX_PKT_BURST];
    struct rte_mbuf *m;
    unsigned char *start_addr;
    unsigned lcore_id;
    uint64_t prev_tsc, diff_tsc, cur_tsc, timer_tsc;
    unsigned i, j, portid, nb_rx;
    struct lcore_queue_conf *qconf;
    int ip_hdr_len;
    //const uint64_t drain_tsc = (rte_get_tsc_hz() + US_PER_S - 1) / US_PER_S * BURST_TX_DRAIN_US;

    struct timeval time_now = {0};
    struct timeval timestamp = {0};

    //m -> ol_flags |= PKT_RX_IEEE1588_TMST ;

    /*初始化流计数*/
    memset(&flow, 0, sizeof(flow));

    /*初始化serverIP计数*/
    memset(&serverIP, 0, sizeof(serverIP));
    memset(&f20_serverIP, 0, sizeof(f20_serverIP));
    memset(&f20_bytes_serverIP, 0, sizeof(f20_bytes_serverIP));

    prev_tsc = 0;
    timer_tsc = 0;

    //获取自己的lcore_id
    lcore_id = rte_lcore_id();
    qconf = &lcore_queue_conf[lcore_id];

    //分配后多余的lcore，无事可做，orz

    if (qconf->n_rx_port == 0) {
        RTE_LOG(INFO, MYPDUMP, "lcore %u has nothing to do\n", lcore_id);//生成日志消息
        return;
    }

    //有事做的核，很开心的进入了主循环~
    RTE_LOG(INFO, MYPDUMP, "entering main loop on lcore %u\n", lcore_id);

    for (i = 0; i < qconf->n_rx_port; i++) {

        portid = qconf->rx_port_list[i];
        RTE_LOG(INFO, MYPDUMP, " -- lcoreid=%u portid=%u\n", lcore_id, portid);

    }

    gettimeofday(&port_statistics[0].start_time,NULL);//获取跟踪起始时间
    //直到发生了强制退出，在这里就是ctrl+c或者kill了这个进程
    while (!force_quit) {

        gettimeofday(&time_now,NULL);
        cur_tsc = time_now.tv_sec;

        //cur_tsc = rte_rdtsc();//获取当前时间

        //计算时间片
        diff_tsc = cur_tsc - prev_tsc;
        //到了时间片了打印各端口的数据
        /* if timer is enabled */
        if (timer_period > 0) {

            /* advance the timer */
            timer_tsc += diff_tsc;

            /* if timer has reached its timeout */
            if (timer_tsc >= timer_period) {

                /* do this only on master core */
                //打印让master主线程来做
                if (lcore_id == rte_get_master_lcore()) {
                    print_stats();
                    /* reset the timer */
                    timer_tsc = 0;
                }
            }
        }


        /*
         * Read packet from RX queues
         */
        //没有到发送时间片的话，读接收队列里的报文
        for (i = 0; i < qconf->n_rx_port; i++) {

            portid = qconf->rx_port_list[i];
            //从以太网设备的接收队列中检索输入数据包的突发。检索到的数据包存储在rte_mbuf结构中，其指针在rx_pkts数组中提供。
            nb_rx = rte_eth_rx_burst((uint8_t) portid, 0,
                    pkts_burst, MAX_PKT_BURST);
            if (nb_rx == 0)
                continue;

            //计数，收到的报文数
            port_statistics[portid].rx += nb_rx;

            for (j = 0; j < nb_rx; j++) {
                gettimeofday(&timestamp,NULL);//收包时间戳
                printf("收包时间：%ld\n",timestamp.tv_sec * 1000000 + timestamp.tv_usec);
                m = pkts_burst[j];
                start_addr = rte_pktmbuf_mtod(m,void *);//rte_pktmbuf_mtod(m, void *)获取data区域首地址
                rte_prefetch0(start_addr);


                //write(fd,start_addr,m -> pkt_len);

                if (start_addr != NULL){
                    analyse((unsigned char *)start_addr,portid,m -> pkt_len);
                }
            }
        }

        prev_tsc = cur_tsc;
    }
}

static int l2fwd_launch_one_lcore(__attribute__((unused)) void *dummy)
{
    l2fwd_main_loop();
    return 0;
}


int main(int argc, char **argv)
{
    struct lcore_queue_conf *qconf;//端口配置信息
    int ret;
    uint8_t nb_ports;//端口总数
    uint8_t nb_ports_available;//可用端口数
    uint8_t portid;
    unsigned lcore_id, rx_lcore_id;

    fd = open("a.hex",O_RDWR | O_CREAT | O_TRUNC, 0644);
    if(fd == -1){
        perror("open error");
        exit(1);
    }
    printf("fd = %d\n",fd);

    ret = rte_eal_init(argc, argv);//初始化eal
    if (ret < 0)
        rte_panic("Cannot init EAL\n");
    argc -= ret;
    argv += ret;    //保证后面解析程序参数的时候跳过了前面的EAL参数!!!

    /* catch ctrl-c so we can print on exit */
    force_quit = false;
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    /* parse application arguments (after the EAL ones) */
    ret = l2fwd_parse_args(argc, argv);     //解析程序参数
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Invalid L2FWD arguments\n");

    /* create the mbuf pool */
    mbuf_pool = rte_pktmbuf_pool_create("mbuf_pool",NB_MBUF,MEMPOOL_CACHE_SIZE,0,RTE_MBUF_DEFAULT_BUF_SIZE,rte_socket_id());
    if (mbuf_pool == NULL)
        rte_exit(EXIT_FAILURE,"创建内存池失败 - bye\n");

    /*统计端口总数*/
    nb_ports = rte_eth_dev_count();
    if (nb_ports == 0)
        rte_exit(EXIT_FAILURE, "No Ethernet ports - bye\n");

    rx_lcore_id = 0;
    qconf = NULL;

    /* Initialize the port/queue configuration of each logical core */
    for (portid = 0; portid < nb_ports; portid++) {
        /* skip ports that are not enabled */
        if ((l2fwd_enabled_port_mask & (1 << portid)) == 0)
            continue;

        /* get the lcore_id for this port */
        while (rte_lcore_is_enabled(rx_lcore_id) == 0 ||
                lcore_queue_conf[rx_lcore_id].n_rx_port ==
                l2fwd_rx_queue_per_lcore) {
            rx_lcore_id++;
            if (rx_lcore_id >= RTE_MAX_LCORE)
                rte_exit(EXIT_FAILURE, "Not enough cores\n");
        }

        if (qconf != &lcore_queue_conf[rx_lcore_id])
            /* Assigned a new logical core in the loop above. */
            qconf = &lcore_queue_conf[rx_lcore_id];

        qconf->rx_port_list[qconf->n_rx_port] = portid;
        qconf->n_rx_port++;
        printf("Lcore %u: RX port %u\n", rx_lcore_id, (unsigned) portid);
    }

    nb_ports_available = nb_ports;

    /* Initialise each port */
    for (portid = 0; portid < nb_ports; portid++) {
        /* skip ports that are not enabled */
        if ((l2fwd_enabled_port_mask & (1 << portid)) == 0) {
            printf("Skipping disabled port %u\n", (unsigned) portid);
            nb_ports_available--;
            continue;
        }

        /* init port */

        printf("Initializing port %u... ", (unsigned) portid);
        fflush(stdout);//清除读写缓冲区
        //端口配置，将一些配置写进设备dev的一些字段，以及检查设备支持什么类型的中断、支持的包大小
        ret = rte_eth_dev_configure(portid, 1, 1, &port_conf);
        if (ret < 0)
            rte_exit(EXIT_FAILURE, "Cannot configure device: err=%d, port=%u\n",
                    ret, (unsigned) portid);

        //获取设备的MAC地址，写在后一个参数里
        //rte_eth_macaddr_get(portid,&l2fwd_ports_eth_addr[portid]);

        /* init one RX queue */

        fflush(stdout);//清除缓冲区

        //设置接收队列
        ret = rte_eth_rx_queue_setup(portid, 0, nb_rxd,
                rte_eth_dev_socket_id(portid),
                NULL,
                mbuf_pool);//初始化一个接收队列
        if (ret < 0)
            rte_exit(EXIT_FAILURE, "rte_eth_rx_queue_setup:err=%d, port=%u\n",
                    ret, (unsigned) portid);

        fflush(stdout);//清除缓冲区


        //设置发送队列
        ret = rte_eth_tx_queue_setup(portid, 0, nb_txd,
                rte_eth_dev_socket_id(portid),
                NULL);//初始化一个发送队列
        if (ret < 0)
            rte_exit(EXIT_FAILURE, "rte_eth_tx_queue_setup:err=%d, port=%u\n",
                    ret, (unsigned) portid);

        /* Start device */
        //启用端口
        ret = rte_eth_dev_start(portid);
        if (ret < 0)
            rte_exit(EXIT_FAILURE, "rte_eth_dev_start:err=%d, port=%u\n",
                    ret, (unsigned) portid);

        printf("done: \n");

        //rte_eth_promiscuous_enable(portid);//在混杂模式下为以太网设备启用回执。

        /* initialize port stats */
        //初始化端口数据，就是后面要打印的，接收、发送、drop的包数
        memset(&port_statistics, 0, sizeof(port_statistics));
    }

    if (!nb_ports_available) {
        rte_exit(EXIT_FAILURE,
                "All available ports are disabled. Please set portmask.\n");
    }

    check_all_ports_link_status(nb_ports, l2fwd_enabled_port_mask);//检查每个端口的连接状态

    ret = 0;
    /* launch per-lcore init on every lcore */  //这段代码需记住，DPDK任务分发
    rte_eal_mp_remote_launch(l2fwd_launch_one_lcore, NULL, CALL_MASTER);//启动slave从线程执行l2fwd_launch_one_lcore函数
    RTE_LCORE_FOREACH_SLAVE(lcore_id) {
        if (rte_eal_wait_lcore(lcore_id) < 0) {
            ret = -1;
            break;
        }
    }

    for (portid = 0; portid < nb_ports; portid++) {
        if ((l2fwd_enabled_port_mask & (1 << portid)) == 0)
            continue;
        printf("Closing port %d...", portid);
        rte_eth_dev_stop(portid);
        rte_eth_dev_close(portid);
        printf(" Done\n");
    }
    printf("Bye...\n");

    return ret;
}
