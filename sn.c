#define APP_NAME        "sniffex"
#define APP_DESC        "Sniffer example using libpcap"
#define APP_COPYRIGHT    "Copyright (c) 2005 The Tcpdump Group"
#define APP_DISCLAIMER    "THERE IS ABSOLUTELY NO WARRANTY FOR THIS PROGRAM."

#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "picohttpparser.h"
#include "hash.h"

/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN    6

#ifdef DEBUG
#define DEBUG_PRINT(fmt, args...)    fprintf(stderr, fmt, ## args)
#else
#define DEBUG_PRINT(fmt, args...)    /* Don't do anything in release builds */
#endif

u_char g_packet[2048];
hashtable_t *g_dict;
char g_config[] = "url.ini";
char g_http_payload[128];

//u_char g_send_mac[] = {'0x00', '0x00','0x00','0x00','0x00','0x00'};

typedef struct pseudo_hdr {
    uint32_t src;
    uint32_t dst;
    unsigned char mbz;
    unsigned char proto;
    uint16_t len;
} pseudo_hdr;

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

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

void print_payload(const u_char *payload, int len);

void print_hex_ascii_line(const u_char *payload, int len, int offset);

void print_app_banner(void);

void print_app_usage(void);

void swap_bytes(void *a, void *b, size_t width);

int build_packet(u_char *packet, char *relocation_url);

void read_config(hashtable_t *hash, char *config);

int get_url_from(const char *header, size_t header_len, char *url, int *url_len);


uint16_t ip_chksum(uint16_t initcksum, uint8_t *ptr, int len);

uint16_t tcp_chksum(uint16_t initcksum, uint8_t *tcphead, int tcplen, uint32_t *srcaddr, uint32_t *destaddr);

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
    char *key, *value;
    char *search = "=";

    FILE *file = fopen(config, "r");
    if (file != NULL) {
        char line[128]; /* or other suitable maximum line size */
        while (fgets(line, sizeof line, file) != NULL) {
            key = strtok(line, search);
            value = strtok(NULL, search);
            DEBUG_PRINT("%s --> %s", key, value);
            ht_set(hash, key, value);
        }
        fclose(file);
    } else {
        printf("file %s not exist!\n", g_config);
    }
}


int get_url_from(const char *header, size_t header_len, char *url, int *url_len) {
    const char *method, *path;
    struct phr_header headers[1024];
    size_t method_len, path_len, num_headers;
    int ret = 0, i, minor_version;

    num_headers = sizeof(headers) / sizeof(headers[0]);
    ret = phr_parse_request(header, header_len, &method, &method_len, &path, &path_len,
                            &minor_version, headers, &num_headers, 0);
    if (ret == header_len) {
        for (i = 0; i != num_headers; ++i) {
            if (headers[i].name_len == 4) {
                if (memcmp("Host", headers[i].name, 4) == 0) {
                    sprintf(url, "http://%.*s%.*s", (int) headers[i].value_len, headers[i].value, (int) path_len, path);
                    *url_len = 7 + (int) headers[i].value_len + (int) path_len;
                    DEBUG_PRINT("%s\n", url);
                    return *url_len;
                }
            }
        }
    }
    return 0;
}

/*
 * app name/banner
 */
void print_app_banner(void) {

    printf("%s - %s\n", APP_NAME, APP_DESC);
    printf("%s\n", APP_COPYRIGHT);
    printf("%s\n", APP_DISCLAIMER);
    printf("\n");

    return;
}

/*
 * print help text
 */
void print_app_usage(void) {

    printf("Usage: %s [interface]\n", APP_NAME);
    printf("\n");
    printf("Options:\n");
    printf("    interface    Listen on <interface> for packets.\n");
    printf("\n");

    return;
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

    return;
}

const char *sstrstr(const char *haystack, const char *needle, size_t length) {
    size_t needle_length = strlen(needle);
    size_t i;

    for (i = 0; i < length; i++) {
        if (i + needle_length > length) {
            return NULL;
        }

        if (strncmp(&haystack[i], needle, needle_length) == 0) {
            return &haystack[i];
        }
    }
    return NULL;
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
    char  payload302[256];
    int packet_len;
    int size_ip, size_tcp, size_option, size_payload, new_size_payload;
    u_int16_t sport, dport, sum;
    u_int32_t seq, ack;

    // set mac
    ethernet = (struct sniff_ethernet *) (packet);
    swap_bytes(ethernet->ether_dhost, ethernet->ether_shost, ETHER_ADDR_LEN);

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

    DEBUG_PRINT("option len: %d\n", size_option);

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

    DEBUG_PRINT("payload302:%s\n", payload302);
    DEBUG_PRINT("size_payload:%d, size_eth: %d, size_ip: %d, size_tcp: %d, packet_len: %d\n",
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
    char req_url[512];

    int size_ip;
    int size_tcp;
    int size_payload;
    int size_packet;
    int size_send;
    int size_req_url;

    pcap_t *handle = (pcap_t *) args;



    /* define/compute ip header offset */
    ip = (struct sniff_ip *) (packet + SIZE_ETHERNET);
    size_ip = IP_HL(ip) * 4;
    if (size_ip < 20) {
        printf("   * Invalid IP header length: %u bytes\n", size_ip);
        return;
    }

    /* print source and destination IP addresses */
    DEBUG_PRINT("       From: %s\n", inet_ntoa(ip->ip_src));
    DEBUG_PRINT("         To: %s\n", inet_ntoa(ip->ip_dst));


    /* define/compute tcp header offset */
    tcp = (struct sniff_tcp *) (packet + SIZE_ETHERNET + size_ip);
    size_tcp = TH_OFF(tcp) * 4;

    if (size_tcp < 20) {
        printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
        return;
    }


    DEBUG_PRINT("   Src port: %d\n", ntohs(tcp->th_sport));
    DEBUG_PRINT("   Dst port: %d\n", ntohs(tcp->th_dport));

    /* define/compute tcp payload (segment) offset */
    payload = (char *) (packet + SIZE_ETHERNET + size_ip + size_tcp);

    /* compute tcp payload (segment) size */
    size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);

    size_packet = SIZE_ETHERNET + size_ip + size_tcp + size_payload;
    if (size_payload > 0) {
        DEBUG_PRINT("   Payload (%d bytes):\n", size_payload);
        get_url_from(payload, size_payload, req_url, &size_req_url);

        relocation_url = ht_get(g_dict, req_url);
        DEBUG_PRINT("relocation_url:%s\n", relocation_url);
        if (relocation_url == NULL) {
            return;
        }

        memset(g_packet, 2048, 0);
        memcpy(g_packet, packet, size_packet);
        size_send = build_packet(g_packet, relocation_url);
        if (size_send > 0) {
            pcap_sendpacket(handle, g_packet, size_send);
            DEBUG_PRINT("send packat\n");
        }

    }

    return;
}

int main(int argc, char **argv) {

    char *dev = NULL;            /* capture device name */
    char errbuf[PCAP_ERRBUF_SIZE];        /* error buffer */
    pcap_t *handle;                /* packet capture handle */

    char filter_exp[] = "tcp dst  port 8080  and tcp[tcpflags] & tcp-push == tcp-push";        /* filter expression [3] */
    struct bpf_program fp;            /* compiled filter program (expression) */
    bpf_u_int32 mask;            /* subnet mask */
    bpf_u_int32 net;            /* ip */
    int num_packets = -1;            /* number of packets to capture */

    print_app_banner();

    /* check for capture device name on command-line */
    if (argc == 2) {
        dev = argv[1];
    } else if (argc > 2) {
        fprintf(stderr, "error: unrecognized command-line options\n\n");
        print_app_usage();
        exit(EXIT_FAILURE);
    } else {
        /* find a capture device if not specified on command-line */
        dev = pcap_lookupdev(errbuf);
        if (dev == NULL) {
            fprintf(stderr, "Couldn't find default device: %s\n",
                    errbuf);
            exit(EXIT_FAILURE);
        }
    }

    /* get network number and mask associated with capture device */
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n",
                dev, errbuf);
        net = 0;
        mask = 0;
    }

    /* print capture info */
    printf("Device: %s\n", dev);
    printf("Number of packets: %d\n", num_packets);
    printf("Filter expression: %s\n", filter_exp);

    g_dict = ht_create(65536);
    read_config(g_dict, g_config);

    /* open capture device */
    handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        exit(EXIT_FAILURE);
    }

    /* make sure we're capturing on an Ethernet device [2] */
    if (pcap_datalink(handle) != DLT_EN10MB) {
        fprintf(stderr, "%s is not an Ethernet\n", dev);
        exit(EXIT_FAILURE);
    }

    /* compile the filter expression */
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n",
                filter_exp, pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }

    /* apply the compiled filter */
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n",
                filter_exp, pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }

    /* now we can set our callback function */
    pcap_loop(handle, num_packets, got_packet, (u_char *) handle);

    /* cleanup */
    pcap_freecode(&fp);
    pcap_close(handle);

    printf("\nCapture complete.\n");

    return 0;
}



