//
//  PacketHandler.cpp
//  sniffer
//
//  Created by ziteng on 18-11-12
//

#include <ctype.h>
#include <time.h>
#include <arpa/inet.h>
#include <string>
#include <stdarg.h>
#include "PacketHandler.h"
#include "Util.h"

using namespace std;

#define SIZE_LOOPBACK 4  /* loopback headers are always exactly 4 bytes */
#define SIZE_ETHERNET 14 /* ethernet headers are always exactly 14 bytes */

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6

/* Ethernet header */
struct sniff_ethernet {
    u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
    u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
    u_short ether_type;                     /* IPv4/ARP/RARP/IPv6 etc */
};
#define ETHER_TYPE_IPV4 0x0800
#define ETHER_TYPE_IPV6 0x86dd
#define ETHER_TYPE_ARP  0x0806
#define ETHER_TYPE_RARP 0x8035

/* IP header */
struct sniff_ip {
    u_char  ip_vhl;             /* version << 4 | header length >> 2 */
    u_char  ip_tos;             /* type of service */
    u_short ip_len;             /* total length */
    u_short ip_id;              /* identification */
    u_short ip_off;             /* fragment offset field */
    u_char  ip_ttl;             /* time to live */
    u_char  ip_protocol;        /* protocol */
    u_short ip_sum;             /* checksum */
    u_int   ip_src;             /* source address */
    u_int   ip_dst;             /* destination address */
};
#define IP_RF 0x8000            /* reserved fragment flag */
#define IP_DF 0x4000            /* dont fragment flag */
#define IP_MF 0x2000            /* more fragments flag */
#define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */

#define PROTO_ICMP  1
#define PROTO_IGMP  2
#define PROTO_TCP   6
#define PROTO_UDP   17

#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

/* TCP header */
struct sniff_tcp {
    u_short th_sport;               /* source port */
    u_short th_dport;               /* destination port */
    u_int   th_seq;                 /* sequence number */
    u_int   th_ack;                 /* acknowledgement number */
    u_char  th_offx2;               /* data offset, rsvd */
    u_char  th_flags;
    u_short th_win;                 /* window */
    u_short th_sum;                 /* checksum */
    u_short th_urp;                 /* urgent pointer */
};
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_ECE  0x40
#define TH_CWR  0x80
#define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)

#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)


// global variables
char*       g_save_file_name = NULL;
char*       g_filter_content = NULL;
long        g_max_file_size = 0;
FILE*       g_sniffer_file = stderr;
CLock       g_file_lock;    // lock for multiple thread to write the same file;

// help functions
static void long2ip(u_int ip, char* buf, int len)
{
    snprintf(buf, len, "%d.%d.%d.%d", ip >> 24, (ip >> 16) & 0xFF, (ip >> 8) & 0xFF, ip & 0xFF);
}

static void get_strtime(timeval tv, char* buf, int len)
{
    struct tm t;
    localtime_r(&(tv.tv_sec), &t);
    
    snprintf(buf, len, "%02d:%02d:%02d.%06d", t.tm_hour, t.tm_min, t.tm_sec, tv.tv_usec);
}

static string tcp_flags(u_char flags)
{
    string str_flags = "[";
    
    
    if (flags & TH_FIN) {
        str_flags += "F";
    }
    
    if (flags & TH_SYN) {
        if (str_flags.size() != 1) {
            str_flags += "|";
        }
        str_flags += "S";
    }

    if (flags & TH_RST) {
        if (str_flags.size() != 1) {
            str_flags += "|";
        }
        str_flags += "R";
    }
    
    if (flags & TH_PUSH) {
        if (str_flags.size() != 1) {
            str_flags += "|";
        }
        str_flags += "P";
    }
    
    if (flags & TH_ACK) {
        if (str_flags.size() != 1) {
            str_flags += "|";
        }
        str_flags += "A";
    }
    
    if (flags & TH_URG) {
        if (str_flags.size() != 1) {
            str_flags += "|";
        }
        str_flags += "U";
    }
    
    str_flags += "]";
    
    return str_flags;
}

// print format similar to tcpdump
static void print_payload_packet(const u_char* payload_packet, int payload_len)
{
    if (payload_len == 0) {
        return;
    }
    
    for (int i = 0; i < payload_len; i++) {
        if (i % 16 == 0) {
            fprintf(g_sniffer_file, "%04x:  ", i);
        }
        
        fprintf(g_sniffer_file, "%02x", payload_packet[i]);
        
        if ((i+1) % 2 == 0) {
            fprintf(g_sniffer_file, " ");
        }
        
        if ((i + 1) % 16 == 0) {
            fprintf(g_sniffer_file, " ");
            for (int j = i - 15; j <= i; j++) {
                if (isprint(payload_packet[j])) {
                    fprintf(g_sniffer_file, "%c", payload_packet[j]);
                } else {
                    fprintf(g_sniffer_file, ".");
                }
            }
            
            fprintf(g_sniffer_file, "\n");
        }
    }
    
    fprintf(g_sniffer_file, "\n");
}


int CPacketHandler::Init(char* save_file, uint32_t max_file_size, char* content)
{
    g_save_file_name = save_file;
    g_max_file_size = max_file_size;
    g_filter_content = content;
    
    if (g_save_file_name) {
        g_sniffer_file = fopen(save_file, "w");
        if (g_sniffer_file == NULL) {
            fprintf(stderr, "can't open file: %s\n", save_file);
            g_sniffer_file = stderr;
            return -1;
        }
        
        // unit MB, max 8GB, min 100MB
        if (g_max_file_size > 8 * 1024) {
            g_max_file_size = 8 * 1024;
        } else if (g_max_file_size < 100) {
            g_max_file_size = 100;
        }
        
        g_max_file_size *= 1024 * 1024; // scale to bytes
    } else {
        g_sniffer_file = stderr;
        g_max_file_size = 0;
    }
    
    return 0;
}

void CPacketHandler::ReceivePacket(u_char* arg, const struct pcap_pkthdr* ph, const u_char* packet)
{
    int ip_offset = 0;
    long device_type = (long)arg;
    if (device_type == DLT_NULL) {
        ip_offset = SIZE_LOOPBACK;
        
        uint32_t type = *(uint32_t*)packet;
        if (type != PF_INET) {
            // filter non-ipv4 data
            // see http://www.tcpdump.org/linktypes.html for the meaning of 4 byte loopback type
            return;
        }
    } else if (device_type == DLT_EN10MB) {
        ip_offset = SIZE_ETHERNET;
        
        sniff_ethernet* ether = (sniff_ethernet*)packet;
        ether->ether_type = ntohs(ether->ether_type);
        if (ether->ether_type != ETHER_TYPE_IPV4) {
            // filter non-ipv4 data
            return;
        }
    } else {
        printf("not loopback or ethernet\n");
        return;
    }
    
    sniff_ip* ip = (sniff_ip*)(packet + ip_offset);
    int size_ip = IP_HL(ip) * 4;
    if (size_ip < 20) {
        printf("wrong ip len, size_ip=%d, ip_vhl=0x%x\n", size_ip, ip->ip_vhl);
        return;
    }

    // filter non-tcp data
    if (ip->ip_protocol != PROTO_TCP) {
        return;
    }
    
    ip->ip_src = ntohl(ip->ip_src);
    ip->ip_dst = ntohl(ip->ip_dst);
    
    sniff_tcp* tcp = (sniff_tcp*)(packet + ip_offset + IP_HL(ip) * 4);
    int size_tcp = TH_OFF(tcp) * 4;
    if (size_tcp < 20) {
        printf("wrong tcp len, size_tcp=%d\n", size_tcp);
        return;
    }
    
    tcp->th_sport = ntohs(tcp->th_sport);
    tcp->th_dport = ntohs(tcp->th_dport);
    tcp->th_seq = ntohl(tcp->th_seq);
    tcp->th_ack = ntohl(tcp->th_ack);
    
    char src_ip[16], dst_ip[16];
    long2ip(ip->ip_src, src_ip, 16);
    long2ip(ip->ip_dst, dst_ip, 16);
    
    int payload_offset = ip_offset + size_ip + size_tcp;
    int payload_len = ph->caplen - payload_offset;
    
    char strtime[32];
    get_strtime(ph->ts, strtime, 32);
    string flags = tcp_flags(tcp->th_flags);
    
    g_file_lock.lock();
    
    // rewind the file position if exceed the predefined max file size
    if (g_sniffer_file != stderr) {
        long file_size = ftell(g_sniffer_file);
        if (file_size >= g_max_file_size) {
            rewind(g_sniffer_file);
        }
    }
    
    if (g_filter_content != NULL) {
        if (payload_len > 0) {
            string payload((char*)packet + payload_offset, payload_len);
            if (payload.find(g_filter_content) != string::npos) {
                fprintf(g_sniffer_file, "%s %s:%d -> %s:%d Flags=%s, seq=%u, ack=%u, len=%d\n", strtime,
                        src_ip, tcp->th_sport, dst_ip, tcp->th_dport, flags.c_str(), tcp->th_seq, tcp->th_ack, payload_len);
                for (int i = 0; i < payload_len; i++) {
                    int pos = payload_offset + i;
                    if (isprint(packet[pos])) {
                        fprintf(g_sniffer_file, "%c", packet[pos]);
                    } else {
                        fprintf(g_sniffer_file, ".");
                    }
                }
                
                fprintf(g_sniffer_file, "\n");
            }
        }
    } else {
        fprintf(g_sniffer_file, "%s %s:%d -> %s:%d Flags=%s, seq=%u, ack=%u, len=%d\n", strtime,
                src_ip, tcp->th_sport, dst_ip, tcp->th_dport, flags.c_str(), tcp->th_seq, tcp->th_ack, payload_len);
    
        if (payload_len > 0) {
            print_payload_packet(packet + payload_offset, payload_len);
        }
     }
    
    g_file_lock.unlock();
}

