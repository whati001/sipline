#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include "siplinePackages.h"
#include <osipparser2/osip_headers.h>
#include <osip2/osip.h>

#define DEBUG 1

#define MAX_INTERFACE_LEN 100
#define BPF_SIP_FILTER "(port 6050) and (udp)"

/**
 * Simple c enum for boolean return value
 */
typedef enum {
    TRUE, FALSE
} boolean;

/**
 * Check if package is ethernet, define static inline which may results into better performance
 * @param packet to check if ethernet
 * @return sipline_ether_header if ether packet else NULL
 */
static inline struct sipline_ethernet_header *getEthernetHeader(const u_char *packet) {
    struct sipline_ethernet_header *eth_header;
    eth_header = (struct sipline_ethernet_header *) packet;
    return eth_header;
}

/**
 * Check if package is ip, define static inline which may result into better performance
 * @param packet to check if ip
 * @return sipline_ip_header if ip packet else NULL
 */
static inline struct sipline_ip_header *getIpHeader(const u_char *packet) {
    struct sipline_ethernet_header *ethernet_header = getEthernetHeader(packet);
    if (NULL == ethernet_header) {
        fprintf(stdout, "No Ethernet package found, skip package\n");
        return NULL;
    }
    printf("ether ip type: %x\n", ntohs(ethernet_header->ether_type));
    if (ETHER_IP != ntohs(ethernet_header->ether_type)) {
        fprintf(stdout, "No IP4 in ethernet package, skip packet\n");
        return NULL;
    }

    struct sipline_ip_header *ip_header;
    ip_header = (struct sipline_ip_header *) (((u_char *) ethernet_header) + SIZE_ETHERNET);
    u_int size_ip = IP_HL(ip_header) * 4;
    if (IP_MIN_LENGHT > size_ip) {
        printf("   * Invalid IP header length: %u bytes\n", size_ip);
        return NULL;
    }
    return ip_header;
}

static inline struct sipline_udp_header *getUdpHeader(const u_char *packet) {
    struct sipline_ip_header *ip_header = getIpHeader(packet);
    if (NULL == ip_header) {
        fprintf(stdout, "No IP packet received, this should not happen within sipline application\n");
        return NULL;
    }
    if (IP_PROTO_UDP != ip_header->ip_p) {
        return NULL;
    }

    const uint16_t size_ip = IP_HL(ip_header) * 4;
    struct sipline_udp_header *udp_header = (struct sipline_udp_header *) (((u_char *) ip_header) + size_ip);
    if (SIZE_UDP > udp_header->uh_len) {
        printf("Invalid IP header length: %u bytes\n", size_ip);
        return NULL;
    }
    return udp_header;
}

/**
 * SIP callback handler
 * @param args passed by listener to callback
 * @param header including some stuff
 * @param packet raw package to analyze
 */
void sipPacketHandler(
        u_char *args,
        const struct pcap_pkthdr *header,
        const u_char *packet
) {
    fprintf(stdout, "Total packet available: %d bytes\n", header->caplen);
    fprintf(stdout, "Expected packet size: %d bytes\n", header->len);

    const struct sipline_udp_header *udp_header = getUdpHeader(packet);
    if (NULL == udp_header) {
        fprintf(stdout, "Not UDP header found in received package, skip it");
        return;
    }
    u_char *payload = ((u_char *) udp_header) + SIZE_UDP;

#ifdef DEBUG
    fprintf(stdout, "Parsed UdpHeader from package");
    fprintf(stdout, "UdpHeader{sport: %d, dport: %d, len: %d, sum: %d}\n", ntohs(udp_header->uh_sport),
            ntohs(udp_header->uh_dport),
            ntohs(udp_header->uh_len), ntohs(udp_header->uh_sum));
    fprintf(stdout, "Some Payload: %s\n", payload);
#endif


    return;
}

/**
 * Simple program argument parser, parse network interface name from argument with index 1
 * @param argc program argument count
 * @param argv program argument values
 * @param interface char pointer to parsed interface, on failure set to NULL
 * @return on Success return EXIT_SUCCESS, on Failure EXIT_FAILURE
 */
int parseInterfaceFromParams(int argc, char *argv[], char **interface) {
    free(*interface);
    *interface = NULL;

    if (argc != 2 || NULL == argv[1]) {
        return EXIT_FAILURE;
    }

    size_t params_len = strlen(argv[1]);
    if (MAX_INTERFACE_LEN <= params_len) {
        fprintf(stderr, "Interface length longer than 100 character, are you sure?\n");
        return EXIT_FAILURE;
    }

    char *buf = (char *) calloc(params_len + 1, sizeof(char));
    if (NULL == buf) {
        fprintf(stderr, "Failed to allocated buffer for interface name\n");
        return EXIT_FAILURE;
    }

    memcpy(buf, argv[1], params_len);
    *interface = buf;
    buf = NULL;

    return EXIT_SUCCESS;
}

/**
 * Compile and apply SIP filter to pcap_t handle
 * @param handle
 * @return on Success return EXIT_SUCCESS, on Failure EXIT_FAILURE
 */
int applySipFilter(pcap_t *handle) {
    struct bpf_program filter;
    fprintf(stdout, "Start to compile BPF filter for SIP packages\n");
    if (pcap_compile(handle, &filter, BPF_SIP_FILTER, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "Bad filter expression supplied - %s\n", pcap_geterr(handle));
        return EXIT_FAILURE;
    }

    fprintf(stdout, "Start applying BPF filter against pcap handle\n");
    if (pcap_setfilter(handle, &filter) == -1) {
        fprintf(stderr, "Failed to apply filter - %s\n", pcap_geterr(handle));
        return EXIT_FAILURE;
    }

    fprintf(stdout, "Done compiling and applying BPF filter.\n");
    return EXIT_SUCCESS;
}

/**
 * Setup live network traffic parsing via libpcap
 * @param interface name to start sniffing
 * @return on Success return EXIT_SUCCESS, on Failure EXIT_FAILURE
 */
int setupLivePcapParsing(char *interface) {
    return EXIT_SUCCESS;
}

/**
 * Setup file network traffic parsing via libpcap
 * @param parent_handler pcap_t handle set after opening file and apply filter
 * @param filename to pcap file for analysing
 * @return on Success return EXIT_SUCCESS, on Failure EXIT_FAILURE
 */
int setupFilePcapParsing(pcap_t **parent_handler, const char const *filename) {
    fprintf(stdout, "Start setup pcap file: %s\n", filename);

    char err_buf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    fprintf(stdout, "Try to open pcap file for reading packages\n");
    handle = pcap_open_offline(filename, err_buf);
    if (NULL == handle) {
        fprintf(stderr, "Failed to open pcap file: %s\n", filename);
        return EXIT_FAILURE;
    }

    if (EXIT_FAILURE == applySipFilter(handle)) {
        fprintf(stderr, "Failed to apply sip filter");
        return EXIT_FAILURE;
    }

    *parent_handler = handle;
    fprintf(stdout, "Done setup pcap file: %s\n", filename);
    return EXIT_SUCCESS;
}

/**
 * Start PCAP SIP listener and sniff until we kill the program
 * @param handle to start listen on
 * @param callback to call for each packages
 * @param callback_args to pass to callback function
 * @return on Success return EXIT_SUCCESS, on Failure EXIT_FAILURE
 */
int startSipListener(pcap_t *handle, pcap_handler callback, u_char *callback_args) {
    if (NULL == handle) {
        fprintf(stderr, "Please provide a proper pcap handle to start SIP listening");
        return EXIT_FAILURE;
    }
    if (NULL == callback) {
        fprintf(stdout, "No callback function for pcap loop passed, are you sure you want to burn engergy?");
    }

    int ret_loop = pcap_loop(handle, 0, callback, callback_args);
    fprintf(stdout, "Pcap loop ended with return code: %d\n", ret_loop);
    return 0 == ret_loop ? EXIT_SUCCESS : EXIT_FAILURE;
}

/**
 * Register osip state machine with all callbacks
 * @return
 */
int registerOsip() {
    fprintf(stdout, "Start to register osip state machine started\n");
    int i;
    osip_t *osip;
    i = osip_init(&osip);

    if (0 != i) {
        fprintf(stdout, "Failed to register osip state machine\n");
        return EXIT_FAILURE;
    }
    fprintf(stdout, "Registered osip state machine properly\n");
    return EXIT_SUCCESS;
}

int main(int argc, char *argv[]) {

    char *interface = NULL;
    if (EXIT_FAILURE == parseInterfaceFromParams(argc, argv, &interface)) {
        fprintf(stdout, "Usage: ./sipline <interface_name>\n");
        exit(EXIT_FAILURE);
    }
    fprintf(stdout, "Start analysing SIP traffic on interface: %s\n", interface);

    // TODO: add relative addressing
    pcap_t *handle;
    if (EXIT_FAILURE == setupFilePcapParsing(&handle, "/home/akarner/rehka/sipline/test/testPackages.pcap")) {
        fprintf(stderr, "Failed to analyze provided pcap file\n");
        exit(EXIT_FAILURE);
    }

    if (EXIT_FAILURE == startSipListener(handle, sipPacketHandler, NULL)) {
        fprintf(stderr, "Something failed during package analysis");
        return EXIT_FAILURE;
    }

    // TODO: move to proper location
    if (EXIT_FAILURE == registerOsip()) {
        fprintf(stderr, "Failed to register osip watch properly");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
