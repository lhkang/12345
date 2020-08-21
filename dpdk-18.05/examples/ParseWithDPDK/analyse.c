#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <stdint.h>

#include <rte_common.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_hash_crc.h>
#include "pkts_analysis.h"


struct ether_hdr * ether_analyse(void * eth_addr)
{   
    struct ether_hdr *eth = (struct ether_hdr *)eth_addr;
    char *type = "unknown";

    if (ntohs(eth -> ether_type) == 0x0800)
        type = "IP";
    else if (ntohs(eth -> ether_type) == 0x0806)
        type = "ARP";
    else if (ntohs(eth -> ether_type) == 0x8035)
        type = "RARP";
    else
        type = "unknown";

    printf("数据链路层：    目的MAC：%02X:%02X:%02X:%02X:%02X:%02X\t源MAC：%02X:%02X:%02X:%02X:%02X:%02X\t帧协议类型：%s\n",
            eth -> d_addr.addr_bytes[0],
            eth -> d_addr.addr_bytes[1],
            eth -> d_addr.addr_bytes[2],
            eth -> d_addr.addr_bytes[3],
            eth -> d_addr.addr_bytes[4],
            eth -> d_addr.addr_bytes[5],
            eth -> s_addr.addr_bytes[0],
            eth -> s_addr.addr_bytes[1],
            eth -> s_addr.addr_bytes[2],
            eth -> s_addr.addr_bytes[3],
            eth -> s_addr.addr_bytes[4],
            eth -> s_addr.addr_bytes[5],
            type);

    if (ntohs(eth -> ether_type) != 0x0800)
        printf("\n");

    return eth;
}

struct ipv4_hdr *ip_analyse(unsigned char *ip_addr,unsigned portid)
{
    struct ipv4_hdr *ip = (struct ipv4_hdr *)ip_addr;
    char ip_src[16],ip_dst[16];
    char *proto = "unknown";
    int RF = 0,DF = 0,MF = 0;

    inet_ntop(AF_INET,&(ip -> src_addr),ip_src,sizeof(ip_src));
    inet_ntop(AF_INET,&(ip -> dst_addr),ip_dst,sizeof(ip_dst));

    switch(ip -> next_proto_id)//判断协议类型
    {
        case 0x01:
            proto = "ICMP";
            port_statistics[portid].ICMP_pkts++;
            break;

        case 0x02:
            proto = "IGMP";
            break;

        case 0x06:
            proto = "TCP";
            port_statistics[portid].tcp_pkts++;
            break;

        case 0x11:
            proto = "UDP";
            port_statistics[portid].udp_pkts++;
            break;

        case 0x59:
            proto = "OSPF";
            break;

        default :
            proto = "other type";
            break;
    }

    if ((ip -> fragment_offset) & 0x0080)
        RF = 1;
    if ((ip -> fragment_offset) & 0x0040)
        DF = 1;
    if ((ip -> fragment_offset) & 0x0020)
        MF = 1;

    int ip_hdr_len = ((ip -> version_ihl) & 0x0f) * 4;

    printf("网络层：        源IP地址：%s\t目的IP地址：%s\t"
            "高层协议：%s\t"
            "生存时间TTL：%d\t"
            "片偏移：%04X RF:%d DF:%d MF:%d\t"
            "IP首部长度：%d\t"
            "数据报总长度：%d\t"
            "IP数据报标识：%d\n",
            ip_src,ip_dst,
            proto,
            ip -> time_to_live,
            ip -> fragment_offset,RF,DF,MF,
            ip_hdr_len,
            ntohs(ip -> total_length),
            ntohs(ip -> packet_id));

    return ip;
}

struct tcp_hdr *tcp_analyse(unsigned char *tcp_addr,unsigned portid)
{
    struct tcp_hdr *tcp = (struct tcp_hdr *)tcp_addr;
    int SYN = 0,FIN = 0,ACK = 0,RST = 0,PSH = 0,URG = 0;

    int tcp_hdr_len = ((tcp -> data_off) >> 4) * 4;

    if ((tcp -> tcp_flags) & 0x01){
        FIN = 1;
        port_statistics[portid].FIN_pkts++;
    }
    if ((tcp -> tcp_flags) & 0x02){
        SYN = 1;
        port_statistics[portid].SYN_pkts++;
    }
    if ((tcp -> tcp_flags) & 0x04){
        RST = 1;
        port_statistics[portid].RST_pkts++;
    }
    if ((tcp -> tcp_flags) & 0x08)
        PSH = 1;
    if ((tcp -> tcp_flags) & 0x10)
        ACK = 1;
    if ((tcp -> tcp_flags) & 0x20)
        URG = 1;

    printf("传输层：        源端口号：%d\t目的端口号：%d\t"
            "seq: %u\t"
            "ack: %u\t"
            "首部长度：%d\t"
            "SYN:%d FIN:%d ACK:%d RST:%d PSH:%d URG:%d\t"
            "窗口大小：%d\t"
            "TCP首部长度：%d\n\n",
            ntohs(tcp -> src_port),
            ntohs(tcp -> dst_port),
            ntohl(tcp -> sent_seq),
            ntohl(tcp -> recv_ack),
            tcp_hdr_len,
            SYN,FIN,ACK,RST,PSH,URG,
            tcp -> rx_win,
            tcp_hdr_len);
    return tcp;

}

struct udp_hdr *udp_analyse(unsigned char *udp_addr)
{
    struct udp_hdr *udp = (struct udp_hdr *)udp_addr;

    printf("传输层：    源端口号：%d\t目的端口号：%d\tUDP段长度：%d\n\n",ntohs(udp -> src_port),ntohs(udp -> dst_port),udp -> dgram_len);

    return udp;
}

/*统计第一个TCP连接的前30个数据包、前30个出向和入向数据包的集合*/
int f30_fTCP(uint16_t hash_key,int dir,uint32_t pkt_len,unsigned portid)
{
    if (dir == 1){
        if (flow[hash_key].flow_id == 1 && flow[hash_key].count <= 30){//统计第一个TCP连接的前30个数据包集合
            port_statistics[portid].f30_pkts_fTCP[flow[hash_key].count - 1] = (int)pkt_len;
        }

        if (flow[hash_key].flow_id == 1 && flow[hash_key].outgoing_number <= 30){//统计第一个TCP连接的前30个出向数据包集合
            port_statistics[portid].f30_outpkts_fTCP[flow[hash_key].outgoing_number - 1] = (int)pkt_len;
        }

    } 
    else if(dir == 0){
        if (flow[hash_key].flow_id == 1 && flow[hash_key].count <= 30){//统计第一个TCP连接的前30个数据包集合
            port_statistics[portid].f30_pkts_fTCP[flow[hash_key].count - 1] = 0 - (int)pkt_len;
        }

        if (flow[hash_key].flow_id == 1 && flow[hash_key].incoming_number <= 30){//统计第一个TCP连接的前30个入向数据包集合
            port_statistics[portid].f30_inpkts_fTCP[flow[hash_key].incoming_number - 1] = 0 - (int)pkt_len;
        }

    }
    return 0;
}

/*插入排序统计每条流的前20个最大包、最大出向包、最大入向包*/
int f20_largest_statistics(uint16_t hash_key,int dir,uint32_t pkt_len)
{
    int i;
    switch(dir){
        case 0:
            {
                /*插入排序统计每条流的前20个最大包*/
                for (i = 19; i >= 0; i--)
                {
                    if (flow[hash_key].f20_largest_bytes[i] < (int)pkt_len && i != 19)
                        flow[hash_key].f20_largest_bytes[i + 1] = flow[hash_key].f20_largest_bytes[i];
                    else if (flow[hash_key].f20_largest_bytes[i] < (int)pkt_len && i == 19)
                        continue;
                    else
                        break;
                }
                if (i >= -1 && i < 19 && flow[hash_key].f20_largest_bytes[i + 1] < (int)pkt_len)
                    flow[hash_key].f20_largest_bytes[i + 1] = (int)pkt_len;
                break;
            }
        case 1:
            {
                /*插入排序统计每条流的前20个最大出向包*/
                for (i = 19; i >= 0; i--)
                {
                    if (flow[hash_key].f20_largest_outbytes[i] < (int)pkt_len && i != 19)
                        flow[hash_key].f20_largest_outbytes[i + 1] = flow[hash_key].f20_largest_outbytes[i];
                    else if (flow[hash_key].f20_largest_outbytes[i] < (int)pkt_len && i == 19)
                        continue;
                    else
                        break;
                }
                if (i >= -1 && i < 19 && flow[hash_key].f20_largest_outbytes[i + 1] < (int)pkt_len)
                    flow[hash_key].f20_largest_outbytes[i + 1] = (int)pkt_len;
                break;
            }
        case -1:
            {
                /*插入排序统计每条流的前20个最大入向包*/
                for (i = 19; i >= 0; i--)
                {
                    if (flow[hash_key].f20_largest_inbytes[i] < (int)pkt_len && i != 19)
                        flow[hash_key].f20_largest_inbytes[i + 1] = flow[hash_key].f20_largest_inbytes[i];
                    else if (flow[hash_key].f20_largest_inbytes[i] < (int)pkt_len && i == 19)
                        continue;
                    else
                        break;
                }
                if (i >= -1 && i < 19 && flow[hash_key].f20_largest_inbytes[i + 1] < (int)pkt_len)
                    flow[hash_key].f20_largest_inbytes[i + 1] = (int)pkt_len;
                break;
            }
    }
    return 0;
}

int serverIP_analyse(uint32_t ip_addr,unsigned portid,int dir,uint32_t pkt_len)
{
    uint32_t key = 0,i;
    uint8_t *ptr = (uint8_t *)&ip_addr;
    key = rte_hash_crc_1byte(ptr[0],key);
    key = rte_hash_crc_1byte(ptr[1],key);
    key = rte_hash_crc_1byte(ptr[2],key);
    key = key & 0x00001fff;//取低13位作为key

    if (serverIP[key].count == 0){//新建serverIP
        serverIP[key].server_ip[0] = ptr[0];
        serverIP[key].server_ip[1] = ptr[1];
        serverIP[key].server_ip[2] = ptr[2];
        serverIP[key].count += 1;
        serverIP[key].total_bytes += pkt_len;
        if (dir == 1)
            serverIP[key].outgoing_bytes += pkt_len;
        else 
            serverIP[key].incoming_bytes += pkt_len;


        port_statistics[portid].unique_serverIP_count += 1;//统计不同的serverIP数

    }
    else if (serverIP[key].count != 0 &&
            serverIP[key].server_ip[0] == ptr[0] &&
            serverIP[key].server_ip[1] == ptr[1] &&
            serverIP[key].server_ip[2] == ptr[2] 
            ){//已有serverIP，更新count
        serverIP[key].count += 1;
        serverIP[key].total_bytes += pkt_len;
        if (dir == 1)
            serverIP[key].outgoing_bytes += pkt_len;
        else 
            serverIP[key].incoming_bytes += pkt_len;
    }
    else {//发生冲突，线性探测法解决
        for (i = key + 1; i < MAX_SERVERIP * 2; i++)
        {
            if (serverIP[i % MAX_SERVERIP].count == 0){
                serverIP[i % MAX_SERVERIP].server_ip[0] = ptr[0];
                serverIP[i % MAX_SERVERIP].server_ip[1] = ptr[1];
                serverIP[i % MAX_SERVERIP].server_ip[2] = ptr[2];
                serverIP[i % MAX_SERVERIP].count += 1;
                serverIP[i % MAX_SERVERIP].total_bytes += pkt_len;
                if (dir == 1)
                    serverIP[i % MAX_SERVERIP].outgoing_bytes += pkt_len;
                else 
                    serverIP[i % MAX_SERVERIP].incoming_bytes += pkt_len;

                port_statistics[portid].unique_serverIP_count += 1;//统计不同的serverIP数
                break;
            }
            else if (serverIP[i % MAX_SERVERIP].count != 0 &&
                    serverIP[i % MAX_SERVERIP].server_ip[0] == ptr[0] &&
                    serverIP[i % MAX_SERVERIP].server_ip[1] == ptr[1] &&
                    serverIP[i % MAX_SERVERIP].server_ip[2] == ptr[2] 
                    ){
                serverIP[i % MAX_SERVERIP].count += 1;
                serverIP[i % MAX_SERVERIP].total_bytes += pkt_len;
                if (dir == 1)
                    serverIP[i % MAX_SERVERIP].outgoing_bytes += pkt_len;
                else 
                    serverIP[i % MAX_SERVERIP].incoming_bytes += pkt_len;
                break;
            }
            else 
                continue;
        }
    }
}

/*数据包分析*/
int analyse(unsigned char *addr,unsigned portid,uint32_t pkt_len)
{
    int ip_hdr_len,i;
    struct ipv4_hdr *ip = NULL;
    struct tcp_hdr *tcp = NULL;
    struct udp_hdr *udp = NULL;
    struct ipv4_5tuple tuple;

    printf("数据包大小：%d\n",pkt_len);

    struct ether_hdr *eth = ether_analyse(addr);

    if (ntohs(eth -> ether_type) == 0x0800)
    {
        ip = ip_analyse(addr + 14,portid);
        ip_hdr_len = ((ip -> version_ihl) & 0x0f) * 4;

        if ((ip -> next_proto_id) == 0x06)
            tcp = tcp_analyse(addr + ip_hdr_len + 14,portid);
        else if((ip -> next_proto_id) == 0x11)
            udp = udp_analyse(addr + ip_hdr_len + 14);
        else 
            return 0;
    }

    /*迭代比较法分流*/
    /*
       for (i = 0;i < MAX_FLOW_NUMBER; i++)
       {
       if ((flow[i].count == 0) && (tcp != NULL) && ip != NULL){
       tuple.ip_src = ip -> src_addr;
       tuple.ip_dst = ip -> dst_addr;
       tuple.port_src = tcp -> src_port;
       tuple.port_dst = tcp -> dst_port;
       tuple.proto = ip -> next_proto_id;
       flow[i].count += 1;
       flow[i].tuple = tuple;
       break;
       }
       else if (flow[i].count != 0 && tcp != NULL && ip != NULL &&
       flow[i].tuple.ip_src == ip -> src_addr &&
       flow[i].tuple.ip_dst == ip -> dst_addr &&
       flow[i].tuple.port_src == tcp -> src_port &&
       flow[i].tuple.port_dst == tcp -> dst_port &&
       flow[i].tuple.proto == ip -> next_proto_id 
       ){
       flow[i].count += 1;
       break;
       }
       else if (flow[i].count != 0 && tcp != NULL && ip != NULL &&
       flow[i].tuple.ip_src == ip -> dst_addr &&
       flow[i].tuple.ip_dst == ip -> src_addr &&
       flow[i].tuple.port_src == tcp -> dst_port &&
       flow[i].tuple.port_dst == tcp -> src_port &&
       flow[i].tuple.proto == ip -> next_proto_id 
       ){
       flow[i].count += 1;
       break;
       }
       else 
       continue;
       }*/

    /*利用hash算法分流*/
    uint32_t hash_key;
    uint32_t ip_addr;
    inet_pton(AF_INET,"192.168.153.131",(void *)&ip_addr);

    if (ip == NULL)//是IP数据报，则继续
        return 0;

    port_statistics[portid].total_pkts_size += pkt_len;//统计包大小
    port_statistics[portid].pkts_count += 1;//数据包计数

//    if (port_statistics[portid].pkts_count <= 100)
//        port_statistics[portid].f100_pkts_size += pkt_len;//统计前100个数据包累计大小

    /*统计带方向的IP数据包*/
    if (ip -> src_addr == ip_addr)//判断方向为出
    {
        port_statistics[portid].out_count += 1;//计数

        if (port_statistics[portid].pkts_count <= 100){
            port_statistics[portid].f100sz_with_dir += (int)pkt_len;//统计前100个带方向数据包累计大小
        }

        if (port_statistics[portid].pkts_count <= 30){//数组从1开始计
            port_statistics[portid].f30_pkts[port_statistics[portid].pkts_count - 1] = (int)pkt_len;//统计前30个带方向数据包
        }

        if (port_statistics[portid].out_count <= 30){
            port_statistics[portid].f30_out_pkts[port_statistics[portid].out_count - 1] = (int)pkt_len;//统计前30个出向数据包
        }

        if (port_statistics[portid].out_count <= 300){
            port_statistics[portid].f300_outpkts_pos[port_statistics[portid].out_count - 1] = port_statistics[portid].pkts_count;//统计前300个出向数据包的位置

            port_statistics[portid].f300_outpkts_prepos[port_statistics[portid].out_count - 1] = port_statistics[portid].pkts_count - 
                port_statistics[portid].f300_outpkts_pos[port_statistics[portid].out_count - 1 - 1] - 1;//统计前300个出向数据包的preposition

        }

        /*统计serverIP*/
        serverIP_analyse(ip -> dst_addr,portid,1,pkt_len);

    }
    else {//判断方向为入
        port_statistics[portid].in_count += 1;//计数

        if (port_statistics[portid].pkts_count <= 100){
            port_statistics[portid].f100sz_with_dir += (0 - (int)pkt_len);//统计前100个带方向数据包累计大小
        }

        if (port_statistics[portid].pkts_count <= 30){
            port_statistics[portid].f30_pkts[port_statistics[portid].pkts_count - 1] = 0 - (int)pkt_len;//统计前30个带方向数据包
        }

        if (port_statistics[portid].in_count <= 30){
            port_statistics[portid].f30_in_pkts[port_statistics[portid].in_count - 1] = 0 - (int)pkt_len;//统计前30个入向数据包
        }

        if (port_statistics[portid].in_count <= 300){
            port_statistics[portid].f300_inpkts_pos[port_statistics[portid].in_count -1] = port_statistics[portid].pkts_count;//统计前300个出向数据包的位置

            port_statistics[portid].f300_inpkts_prepos[port_statistics[portid].in_count - 1] = port_statistics[portid].pkts_count - 
                port_statistics[portid].f300_inpkts_pos[port_statistics[portid].in_count - 1 - 1] - 1;//统计前300个出向数据包的preposition

        }

        /*统计serverIP*/
        serverIP_analyse(ip -> src_addr,portid,-1,pkt_len);
    }

    if (tcp == NULL)//是TCP数据报，则继续
        return 0;


    /*TCP流处理*/
    if (ip -> src_addr == ip_addr && tcp -> src_port > 1023)//判断是否为出向流
    {
        tuple.ip_src = ip -> src_addr;
        tuple.ip_dst = ip -> dst_addr;
        tuple.port_src = tcp -> src_port;
        tuple.port_dst = tcp -> dst_port;
        tuple.proto = ip -> next_proto_id;
        hash_key = rte_hash_crc((void *)&tuple,sizeof(tuple),0) & 0x0000ffff;//计算哈希值

        if (flow[hash_key].count == 0)//新建出向流
        {
            port_statistics[portid].flow_count += 1;

            flow[hash_key].flow_id = port_statistics[portid].flow_count;
            flow[hash_key].tuple = tuple;
            flow[hash_key].count += 1;
            flow[hash_key].outgoing_number += 1;
            flow[hash_key].total_bytes += pkt_len;//统计每条流的总字节数
            flow[hash_key].outgoing_bytes += pkt_len;//统计每条流的出向字节数
            flow[hash_key].f20_largest_bytes[0] = pkt_len;//统计每条流的前20个最大包的第一个
            flow[hash_key].f20_largest_outbytes[0] = pkt_len;//统计每条流的前20个最大出向包的第一个
            if (ntohs(flow[hash_key].tuple.port_dst) == 80 || ntohs(flow[hash_key].tuple.port_dst) == 443){
                flow[hash_key].totalbytes_by80_443 += pkt_len;//统计每条流通过80/443传输的总字节数
                flow[hash_key].outbytes_by80_443 += pkt_len;//统计每条流通过80/443传输的出向字节数
            }

            f30_fTCP(hash_key,1,pkt_len,portid);//统计第一个TCP连接的数据包
        }
        else if (flow[hash_key].count != 0 && 
                flow[hash_key].tuple.ip_src == ip -> src_addr &&
                flow[hash_key].tuple.ip_dst == ip -> dst_addr &&
                flow[hash_key].tuple.port_src == tcp -> src_port &&
                flow[hash_key].tuple.port_dst == tcp -> dst_port &&
                flow[hash_key].tuple.proto == ip -> next_proto_id 
                ) {//增加出向包
            flow[hash_key].count += 1;
            flow[hash_key].outgoing_number += 1;
            flow[hash_key].total_bytes += pkt_len;//统计每条流的总字节数
            flow[hash_key].outgoing_bytes += pkt_len;//统计每条流的出向字节数
            if (ntohs(flow[hash_key].tuple.port_dst) == 80 || ntohs(flow[hash_key].tuple.port_dst) == 443){
                flow[hash_key].totalbytes_by80_443 += pkt_len;//统计每条流通过80/443传输的总字节数
                flow[hash_key].outbytes_by80_443 += pkt_len;//统计每条流通过80/443传输的出向字节数
            }

            /*插入排序统计每条流的前20个最大包*/
            f20_largest_statistics(hash_key,0,pkt_len);
            /*插入排序统计每条流的前20个最大出向包*/
            f20_largest_statistics(hash_key,1,pkt_len);

            f30_fTCP(hash_key,1,pkt_len,portid);//统计第一个TCP连接的数据包
        }
        else {//发生冲突
            for (i = hash_key + 1; i < MAX_FLOW_NUMBER * 2; i++)//线性探测法处理冲突
            {
                if (flow[i % MAX_FLOW_NUMBER].count == 0){
                    flow[i % MAX_FLOW_NUMBER].count += 1;
                    flow[i % MAX_FLOW_NUMBER].outgoing_number += 1;
                    flow[i % MAX_FLOW_NUMBER].tuple = tuple;
                    flow[i % MAX_FLOW_NUMBER].total_bytes += pkt_len;//统计每条流的总字节数
                    flow[i % MAX_FLOW_NUMBER].outgoing_bytes += pkt_len;//统计每条流的出向字节数
                    flow[i % MAX_FLOW_NUMBER].f20_largest_bytes[0] = pkt_len;//统计每条流的前20个最大包的第一个
                    flow[i % MAX_FLOW_NUMBER].f20_largest_outbytes[0] = pkt_len;//统计每条流的前20个最大出向包的第一个
                    if (ntohs(flow[i % MAX_FLOW_NUMBER].tuple.port_dst) == 80 || ntohs(flow[i % MAX_FLOW_NUMBER].tuple.port_dst) == 443){
                        flow[i % MAX_FLOW_NUMBER].totalbytes_by80_443 += pkt_len;//统计每条流通过80/443传输的总字节数
                        flow[i % MAX_FLOW_NUMBER].outbytes_by80_443 += pkt_len;//统计每条流通过80/443传输的出向字节数
                    }

                    break;
                }
                else if (flow[i % MAX_FLOW_NUMBER].count != 0 && 
                        flow[i % MAX_FLOW_NUMBER].tuple.ip_src == ip -> src_addr &&
                        flow[i % MAX_FLOW_NUMBER].tuple.ip_dst == ip -> dst_addr &&
                        flow[i % MAX_FLOW_NUMBER].tuple.port_src == tcp -> src_port &&
                        flow[i % MAX_FLOW_NUMBER].tuple.port_dst == tcp -> dst_port &&
                        flow[i % MAX_FLOW_NUMBER].tuple.proto == ip -> next_proto_id 
                        ){
                    flow[i % MAX_FLOW_NUMBER].count += 1;
                    flow[i % MAX_FLOW_NUMBER].outgoing_number += 1;
                    flow[i % MAX_FLOW_NUMBER].total_bytes += pkt_len;//统计每条流的总字节数
                    flow[i % MAX_FLOW_NUMBER].outgoing_bytes += pkt_len;//统计每条流的出向字节数
                    if (ntohs(flow[i % MAX_FLOW_NUMBER].tuple.port_dst) == 80 || ntohs(flow[i % MAX_FLOW_NUMBER].tuple.port_dst) == 443){
                        flow[i % MAX_FLOW_NUMBER].totalbytes_by80_443 += pkt_len;//统计每条流通过80/443传输的总字节数
                        flow[i % MAX_FLOW_NUMBER].outbytes_by80_443 += pkt_len;//统计每条流通过80/443传输的出向字节数
                    }

                    /*插入排序统计每条流的前20个最大包*/
                    f20_largest_statistics(i % MAX_FLOW_NUMBER,0,pkt_len);
                    /*插入排序统计每条流的前20个最大出向包*/
                    f20_largest_statistics(i % MAX_FLOW_NUMBER,1,pkt_len);

                    break;
                }
                else 
                    continue;
            }
        }
    }
    else if (ip -> dst_addr == ip_addr && tcp -> dst_port > 1023)//判断是否为入向流
    {
        tuple.ip_src = ip -> dst_addr;
        tuple.ip_dst = ip -> src_addr;
        tuple.port_src = tcp -> dst_port;
        tuple.port_dst = tcp -> src_port;
        tuple.proto = ip -> next_proto_id;
        hash_key = rte_hash_crc((void *)&tuple,sizeof(tuple),0) & 0x0000ffff;//计算哈希值

        if (flow[hash_key].count == 0)//新建入向流
        {
            flow[hash_key].tuple = tuple;
            flow[hash_key].count += 1;
            flow[hash_key].incoming_number += 1;
            flow[hash_key].total_bytes += pkt_len;//统计每条流的总字节数
            flow[hash_key].incoming_bytes += pkt_len;//统计每条流的入向字节数
            flow[hash_key].f20_largest_bytes[0] = pkt_len;//统计每条流的前20个最大包的第一个
            flow[hash_key].f20_largest_inbytes[0] = pkt_len;//统计每条流的前20个最大入向包的第一个
            if (ntohs(flow[hash_key].tuple.port_dst) == 80 || ntohs(flow[hash_key].tuple.port_dst) == 443){
                flow[hash_key].totalbytes_by80_443 += pkt_len;//统计每条流通过80/443传输的总字节数
                flow[hash_key].inbytes_by80_443 += pkt_len;//统计每条流通过80/443传输的入向字节数
            }

            f30_fTCP(hash_key,0,pkt_len,portid);//统计第一个TCP连接的数据包
        }
        else if (flow[hash_key].count != 0 && 
                flow[hash_key].tuple.ip_src == ip -> dst_addr &&
                flow[hash_key].tuple.ip_dst == ip -> src_addr &&
                flow[hash_key].tuple.port_src == tcp -> dst_port &&
                flow[hash_key].tuple.port_dst == tcp -> src_port &&
                flow[hash_key].tuple.proto == ip -> next_proto_id 
                ) {//添加入向包
            flow[hash_key].count += 1;
            flow[hash_key].incoming_number += 1;
            flow[hash_key].total_bytes += pkt_len;//统计每条流的总字节数
            flow[hash_key].incoming_bytes += pkt_len;//统计每条流的入向字节数
            if (ntohs(flow[hash_key].tuple.port_dst) == 80 || ntohs(flow[hash_key].tuple.port_dst) == 443){
                flow[hash_key].totalbytes_by80_443 += pkt_len;//统计每条流通过80/443传输的总字节数
                flow[hash_key].inbytes_by80_443 += pkt_len;//统计每条流通过80/443传输的入向字节数
            }

            /*插入排序统计每条流的前20个最大包*/
            f20_largest_statistics(hash_key,0,pkt_len);
            /*插入排序统计每条流的前20个最大入向包*/
            f20_largest_statistics(hash_key,-1,pkt_len);

            f30_fTCP(hash_key,0,pkt_len,portid);//统计第一个TCP连接的数据包
        }
        else {//发生冲突
            for (i = hash_key + 1; i < MAX_FLOW_NUMBER * 2; i++)//线性探测法处理冲突
            {
                if (flow[i % MAX_FLOW_NUMBER].count == 0){
                    flow[i % MAX_FLOW_NUMBER].count += 1;
                    flow[i % MAX_FLOW_NUMBER].incoming_number += 1;
                    flow[i % MAX_FLOW_NUMBER].tuple = tuple;
                    flow[i % MAX_FLOW_NUMBER].total_bytes += pkt_len;//统计每条流的总字节数
                    flow[i % MAX_FLOW_NUMBER].incoming_bytes += pkt_len;//统计每条流的入向字节数
                    flow[i % MAX_FLOW_NUMBER].f20_largest_bytes[0] = pkt_len;//统计每条流的前20个最大包的第一个
                    flow[i % MAX_FLOW_NUMBER].f20_largest_inbytes[0] = pkt_len;//统计每条流的前20个最大入向包的第一个
                    if (ntohs(flow[i % MAX_FLOW_NUMBER].tuple.port_dst) == 80 || ntohs(flow[i % MAX_FLOW_NUMBER].tuple.port_dst) == 443){
                        flow[i % MAX_FLOW_NUMBER].totalbytes_by80_443 += pkt_len;//统计每条流通过80/443传输的总字节数
                        flow[i % MAX_FLOW_NUMBER].inbytes_by80_443 += pkt_len;//统计每条流通过80/443传输的入向字节数
                    }

                    break;
                }
                else if (flow[i % MAX_FLOW_NUMBER].count != 0 && 
                        flow[i % MAX_FLOW_NUMBER].tuple.ip_src == ip -> dst_addr &&
                        flow[i % MAX_FLOW_NUMBER].tuple.ip_dst == ip -> src_addr &&
                        flow[i % MAX_FLOW_NUMBER].tuple.port_src == tcp -> dst_port &&
                        flow[i % MAX_FLOW_NUMBER].tuple.port_dst == tcp -> src_port &&
                        flow[i % MAX_FLOW_NUMBER].tuple.proto == ip -> next_proto_id 
                        ){
                    flow[i % MAX_FLOW_NUMBER].count += 1;
                    flow[i % MAX_FLOW_NUMBER].incoming_number += 1;
                    flow[i % MAX_FLOW_NUMBER].total_bytes += pkt_len;//统计每条流的总字节数
                    flow[i % MAX_FLOW_NUMBER].incoming_bytes += pkt_len;//统计每条流的入向字节数
                    flow[i % MAX_FLOW_NUMBER].ratio_of_inbytes = (double)flow[hash_key].incoming_bytes / (double)flow[hash_key].total_bytes;//统计入向字节数所占比例
                    if (ntohs(flow[i % MAX_FLOW_NUMBER].tuple.port_dst) == 80 || ntohs(flow[i % MAX_FLOW_NUMBER].tuple.port_dst) == 443){
                        flow[i % MAX_FLOW_NUMBER].totalbytes_by80_443 += pkt_len;//统计每条流通过80/443传输的总字节数
                        flow[i % MAX_FLOW_NUMBER].inbytes_by80_443 += pkt_len;//统计每条流通过80/443传输的入向字节数
                    }

                    /*插入排序统计每条流的前20个最大包*/
                    f20_largest_statistics(i % MAX_FLOW_NUMBER,0,pkt_len);
                    /*插入排序统计每条流的前20个最大入向包*/
                    f20_largest_statistics(i % MAX_FLOW_NUMBER,-1,pkt_len);

                    break;
                }
                else 
                    continue;
            }
        }

    }
    return 0;

} if (ip -> src_addr == ip_addr)//判断方向为出
    {
        port_statistics[portid].out_count += 1;//计数

        if (port_statistics[portid].pkts_count <= 100){
            port_statistics[portid].f100sz_with_dir += (int)pkt_len;//统计前100个带方向数据包累计大小
        }

        if (port_statistics[portid].pkts_count <= 30){//数组从1开始计
            port_statistics[portid].f30_pkts[port_statistics[portid].pkts_count - 1] = (int)pkt_len;//统计前30个带方向数据包
        }

        if (port_statistics[portid].out_count <= 30){
            port_statistics[portid].f30_out_pkts[port_statistics[portid].out_count - 1] = (int)pkt_len;//统计前30个出向数据包
        }

        if (port_statistics[portid].out_count <= 300){
            port_statistics[portid].f300_outpkts_pos[port_statistics[portid].out_count - 1] = port_statistics[portid].pkts_count;//统计前300个出向数据包的位置

            port_statistics[portid].f300_outpkts_prepos[port_statistics[portid].out_count - 1] = port_statistics[portid].pkts_count -
                port_statistics[portid].f300_outpkts_pos[port_statistics[portid].out_count - 1 - 1] - 1;//统计前300个出向数据包的preposition

        }

        /*统计serverIP*/
        serverIP_analyse(ip -> dst_addr,portid,1,pkt_len);

    }
    else {//判断方向为入
        port_statistics[portid].in_count += 1;//计数

        if (port_statistics[portid].pkts_count <= 100){
            port_statistics[portid].f100sz_with_dir += (0 - (int)pkt_len);//统计前100个带方向数据包累计大小
        }

        if (port_statistics[portid].pkts_count <= 30){
            port_statistics[portid].f30_pkts[port_statistics[portid].pkts_count - 1] = 0 - (int)pkt_len;//统计前30个带方向数据包
        }

        if (port_statistics[portid].in_count <= 30){
            port_statistics[portid].f30_in_pkts[port_statistics[portid].in_count - 1] = 0 - (int)pkt_len;//统计前30个入向数据包
        }

        if (port_statistics[portid].in_count <= 300){
            port_statistics[portid].f300_inpkts_pos[port_statistics[portid].in_count -1] = port_statistics[portid].pkts_count;//统计前300个出向数据包的位置

            port_statistics[portid].f300_inpkts_prepos[port_statistics[portid].in_count - 1] = port_statistics[portid].pkts_count -
                port_statistics[portid].f300_inpkts_pos[port_statistics[portid].in_count - 1 - 1] - 1;//统计前300个出向数据包的preposition

        }

        /*统计serverIP*/
        serverIP_analyse(ip -> src_addr,portid,-1,pkt_len);
    }







