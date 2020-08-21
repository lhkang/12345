#ifndef _PKTS_ANALYSIS_H_
#define _PKTS_ANALYSIS_H_

#define MAX_FLOW_NUMBER 1<<16
#define MAX_SERVERIP 1<<13
struct ipv4_5tuple {
    uint32_t ip_dst;
    uint32_t ip_src;
    uint16_t port_dst;
    uint16_t port_src;
    uint8_t  proto;
} __attribute__((__packed__));

struct TCP_flow {
    struct ipv4_5tuple tuple;
    uint64_t flow_id;

    int count;//每条流的数据包数
    int incoming_number;//入向包数量
    int outgoing_number;//出向包数量

    uint64_t incoming_bytes;//入向字节数
    uint64_t outgoing_bytes;//出向字节数
    uint64_t total_bytes;//总字节数
    double ratio_of_inbytes;//入向字节数所占比例
    int f20_largest_bytes[20];//前20个最大字节数的包
    int f20_largest_inbytes[20];//前20个最大字节数的入向包
    int f20_largest_outbytes[20];//前20个最大字节数的出向包

    uint64_t totalbytes_by80_443;//transmitted bytes per TCP conn. w.r.t. port 80/443
    uint64_t inbytes_by80_443;//incoming bytes per TCP conn. w.r.t. port 80/443
    uint64_t outbytes_by80_443;//outgoing bytes per TCP conn. w.r.t. port 80/443
    double ratio_inbytes_by80_443;//ratio of incoming bytes w.r.t. port 80/443

} __attribute__((__packed__));
struct TCP_flow flow[MAX_FLOW_NUMBER];

struct serverIP_addr{
    uint8_t server_ip[3];
    int count;//计数
    uint64_t total_bytes;
    uint64_t incoming_bytes;
    uint64_t outgoing_bytes;
} __attribute__((__packed__));
struct serverIP_addr serverIP[MAX_SERVERIP];
struct serverIP_addr f20_serverIP[20];//前20个最常见的serverIP
struct serverIP_addr f20_bytes_serverIP[20];//前20个最大字节数的serverIP
struct serverIP_addr f20_inbytes_serverIP[20];//前20个最大字节数的入向serverIP
struct serverIP_addr f20_outbytes_serverIP[20];//前20个最大字节数的出向serverIP

/* Per-port statistics struct */
struct l2fwd_port_statistics {
    uint64_t rx;
    uint64_t dropped;
    uint64_t pkts_count;//挨个包计数
    uint64_t in_count;//入向包计数
    uint64_t out_count;//出向包计数
    uint64_t flow_count;//记录流的数量
    struct timeval start_time;//开始跟踪的时间
    struct timeval end_time;//结束跟踪的时间


    uint64_t udp_pkts;
    uint64_t tcp_pkts;
    uint64_t FIN_pkts;
    uint64_t SYN_pkts;
    uint64_t RST_pkts;
    uint64_t DNS_pkts;
    uint64_t ICMP_pkts;

    /*Packet-level*/
    double pkts_frequency;//数据包总数与持续时间的比例
    double inpkts_frequency;//入向数据包总数与持续时间的比例
    double outpkts_frequency;//出向数据包总数与持续时间的比例
    uint64_t total_pkts_size;//包大小总和
    uint64_t f100_pkts_size;//前100个包大小总和
    long f100sz_with_dir;//前100个带方向的包累计大小
    int f30_pkts[30];//前30个包的集合，包括大小和方向
    int f30_in_pkts[30];//前30个入向包的集合
    int f30_out_pkts[30];//前30个出向包的集合
    int f30_pkts_fTCP[30];//第一个TCP连接的前30个数据包集合
    int f30_inpkts_fTCP[30];//第一个TCP连接的前30个入向数据包集合
    int f30_outpkts_fTCP[30];//第一个TCP连接的前30个出向包集合
    uint64_t f300_outpkts_pos[300];//前300个出向数据包的位置（每个出向数据包前的数据包总数）
    uint64_t f300_outpkts_prepos[300];//前300个出向数据包的pre位置（当前出向数据包和上一个出向数据包之间的入向数据包个数）
    uint64_t f300_inpkts_pos[300];//前300个入向数据包的位置（每个入向数据包前的数据包总数）
    uint64_t f300_inpkts_prepos[300];//前300个入向数据包的pre位置（当前入向数据包和上一个入向数据包之间的出向数据包个数）

    int unique_serv_port[1024];//服务器端口数组，用于计算不同端口数量，以及使用端口传输的TCP连接数量
    int unique_port_count;//server port计数
    int TCPnum_by80_443;//通过80/443传输的TCP连接数量

    int unique_serverIP_count;//不同的serverIP计数
} __rte_cache_aligned;
extern struct l2fwd_port_statistics port_statistics[RTE_MAX_ETHPORTS];

int analyse(unsigned char *,unsigned,uint32_t);

#endif
