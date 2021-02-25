#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>

#define MAX_INTERFACE_LEN 100
#define BPF_SIP_FILTER "(port 6050) and (udp)"

void sipPacketHandler(
        u_char *args,
        const struct pcap_pkthdr *header,
        const u_char *packet
) {
    /* First, lets make sure we have an IP packet */
    struct ether_header *eth_header;
    eth_header = (struct ether_header *) packet;
    if (ntohs(eth_header->ether_type) != ETHERTYPE_IP) {
        printf("Not an IP packet. Skipping...\n\n");
        return;
    }

    /* The total packet length, including all headers
       and the data payload is stored in
       header->len and header->caplen. Caplen is
       the amount actually available, and len is the
       total packet length even if it is larger
       than what we currently have captured. If the snapshot
       length set with pcap_open_live() is too small, you may
       not have the whole packet. */
    printf("Total packet available: %d bytes\n", header->caplen);
    printf("Expected packet size: %d bytes\n", header->len);
//
//    /* Pointers to start point of various headers */
//    const u_char *ip_header;
//    const u_char *tcp_header;
//    const u_char *payload;
//
//    /* Header lengths in bytes */
//    int ethernet_header_length = 14; /* Doesn't change */
//    int ip_header_length;
//    int tcp_header_length;
//    int payload_length;
//
//    /* Find start of IP header */
//    ip_header = packet + ethernet_header_length;
//    /* The second-half of the first byte in ip_header
//       contains the IP header length (IHL). */
//    ip_header_length = ((*ip_header) & 0x0F);
//    /* The IHL is number of 32-bit segments. Multiply
//       by four to get a byte count for pointer arithmetic */
//    ip_header_length = ip_header_length * 4;
//    printf("IP header length (IHL) in bytes: %d\n", ip_header_length);
//
//    /* Now that we know where the IP header is, we can
//       inspect the IP header for a protocol number to
//       make sure it is TCP before going any further.
//       Protocol is always the 10th byte of the IP header */
//    u_char protocol = *(ip_header + 9);
//    if (protocol != IPPROTO_TCP) {
//        printf("Not a TCP packet. Skipping...\n\n");
//        return;
//    }
//
//    /* Add the ethernet and ip header length to the start of the packet
//       to find the beginning of the TCP header */
//    tcp_header = packet + ethernet_header_length + ip_header_length;
//    /* TCP header length is stored in the first half
//       of the 12th byte in the TCP header. Because we only want
//       the value of the top half of the byte, we have to shift it
//       down to the bottom half otherwise it is using the most
//       significant bits instead of the least significant bits */
//    tcp_header_length = ((*(tcp_header + 12)) & 0xF0) >> 4;
//    /* The TCP header length stored in those 4 bits represents
//       how many 32-bit words there are in the header, just like
//       the IP header length. We multiply by four again to get a
//       byte count. */
//    tcp_header_length = tcp_header_length * 4;
//    printf("TCP header length in bytes: %d\n", tcp_header_length);
//
//    /* Add up all the header sizes to find the payload offset */
//    int total_headers_size = ethernet_header_length + ip_header_length + tcp_header_length;
//    printf("Size of all headers combined: %d bytes\n", total_headers_size);
//    payload_length = header->caplen -
//                     (ethernet_header_length + ip_header_length + tcp_header_length);
//    printf("Payload size: %d bytes\n", payload_length);
//    payload = packet + total_headers_size;
//    printf("Memory address where payload begins: %p\n\n", payload);
//
//    /* Print payload in ASCII */
//    /*
//    if (payload_length > 0) {
//        const u_char *temp_pointer = payload;
//        int byte_count = 0;
//        while (byte_count++ < payload_length) {
//            printf("%c", *temp_pointer);
//            temp_pointer++;
//        }
//        printf("\n");
//    }
//    */

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
 * @param parentHandle pcap_t handle set after opening file and apply filter
 * @param filename to pcap file for analysing
 * @return on Success return EXIT_SUCCESS, on Failure EXIT_FAILURE
 */
int setupFilePcapParsing(pcap_t **parentHandle, const char const *filename) {
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

    *parentHandle = handle;
    fprintf(stdout, "Done setup pcap file: %s\n", filename);
    return EXIT_SUCCESS;
}

/**
 * Start PCAP SIP listener and sniff until we kill the program
 * @param handle to start listen on
 * @param callback to call for each packages
 * @param callbackArgs to pass to callback function
 * @return on Success return EXIT_SUCCESS, on Failure EXIT_FAILURE
 */
int startSipListener(pcap_t *handle, pcap_handler callback, u_char callbackArgs) {
    if (NULL == handle) {
        fprintf(stderr, "Please provide a proper pcap handle to start SIP listening");
        return EXIT_FAILURE;
    }
    if (NULL == callback) {
        fprintf(stdout, "No callback function for pcap loop passed, are you sure you want to burn engergy?");
    }

    int retLoop = pcap_loop(handle, 0, callback, callbackArgs);
    fprintf(stdout, "Pcap loop ended with return code: %d\n", retLoop);
    return 0 == retLoop ? EXIT_SUCCESS : EXIT_FAILURE;
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

    return EXIT_SUCCESS;
}
