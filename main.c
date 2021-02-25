#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include "siplinePackages.h"
#include <osip2/osip.h>
#include <curl/curl.h>

#define DEBUG 1

#define MAX_INTERFACE_LEN 100
#define BPF_SIP_FILTER "(port 6050) and (udp)"
#define TARGET_URL "http://localhost:2711/ringBell"
#define SIP_INVITE_CODE 0
#define SIP_INVITE_LABEL "INVITE"
#define SIP_CANCEL_CODE 1
#define SIP_CANCEL_LABEL "CANCEL"
#define SIP_ANSWER_CODE 2


char *getCallInfoString(struct sipline_call_info *call_info) {
    size_t needed = snprintf(NULL, 0, "{\"type\":%d,\"from\":%s,\"to\":%s}", call_info->type,
                             call_info->from, call_info->to);
    char *buffer = (char *) calloc(sizeof(char), needed + 1);
    sprintf(buffer, "{\"type\":%d,\"from\":%s,\"to\":%s}", call_info->type, call_info->from, call_info->to);
    return buffer;
}

/**
 * Send call information to remove server as API request
 * @param call_info
 * @return on Success return EXIT_SUCCESS, on Failure EXIT_FAILURE
 */
int informServer(struct sipline_call_info *call_info) {
    int ret_curl = EXIT_SUCCESS;
    CURL *curl;
    CURLcode res;

    curl = curl_easy_init();
    if (curl) {
        char *post_body = getCallInfoString(call_info);

        struct curl_slist *chunk = NULL;
        chunk = curl_slist_append(chunk, "Content-Type: application/json");
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, chunk);
        curl_easy_setopt(curl, CURLOPT_URL, TARGET_URL);
        curl_easy_setopt(curl, CURLOPT_POST, 1);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_body);

        res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            fprintf(stderr, "curl_easy_perform() failed: %s\n",
                    curl_easy_strerror(res));
            ret_curl = EXIT_FAILURE;
        }
        curl_easy_cleanup(curl);
        curl_slist_free_all(chunk);
        free(post_body);
    }
    curl_global_cleanup();
    return ret_curl;
}

/**
 * Parse SIP message via osip lib
 * @param payload buffer to parse into sip message
 * @param payload_length buffer length to parse
 * @return on Success return sipline_call_info struct else NULL
 */
struct sipline_call_info *parseSipMessage(u_char *payload, uint32_t payload_length) {
    int ret_code = EXIT_SUCCESS;
    osip_message_t *sip = NULL;
    struct sipline_call_info *call_info = NULL;

    if (EXIT_SUCCESS != osip_message_init(&sip)) {
        fprintf(stderr, "Failed to allocate new osip message\n");
        return NULL;
    }

    if (EXIT_SUCCESS != osip_message_parse(sip, ((const char *) payload), payload_length)) {
        fprintf(stderr, "Failed to parse sip message\n");
        osip_message_free(sip);
        return NULL;
    }

    char *sip_method = osip_message_get_method(sip);
    if (NULL == sip_method) {
        fprintf(stdout, "SIP Answer {status: %d}\n", osip_message_get_status_code(sip));
        // TODO: parse SIP Answer status or what we need here
        // call_info = (struct sipline_call_info *) calloc(sizeof(struct sipline_call_info), 1);
    } else {
#ifdef DEBUG
        printf("SIP Request {method: %s, from: %s, to: %s}\n",
               osip_message_get_method(sip),
               osip_message_get_from(sip)->displayname,
               osip_message_get_to(sip)->displayname);
#endif
        if (strncmp(SIP_INVITE_LABEL, sip_method, strlen(SIP_INVITE_LABEL)) == 0) {
            call_info = (struct sipline_call_info *) calloc(sizeof(struct sipline_call_info), 1);
            *call_info = (struct sipline_call_info) {
                    SIP_INVITE_CODE, strdup(osip_message_get_from(sip)->displayname),
                    strdup(osip_message_get_to(sip)->displayname)};
            fprintf(stdout, "%s Request{from: %s, to: %s}\n", SIP_INVITE_LABEL, call_info->from, call_info->to);
        } else if (strncmp(SIP_CANCEL_LABEL, sip_method, strlen(SIP_CANCEL_LABEL)) == 0) {
            call_info = (struct sipline_call_info *) calloc(sizeof(struct sipline_call_info), 1);
            *call_info = (struct sipline_call_info) {
                    SIP_CANCEL_CODE, strdup(osip_message_get_from(sip)->displayname),
                    strdup(osip_message_get_to(sip)->displayname)};
            fprintf(stdout, "%s Request{from: %s, to: %s}\n", SIP_CANCEL_LABEL, call_info->from, call_info->to);
        }
    }

    osip_message_free(sip);
    return call_info;
}

/**
 * Parse package payload into ethernet struct
 * @param packet to check if ethernet
 * @return sipline_ether_header if ether packet else NULL
 */
static inline struct sipline_ethernet_header *getEthernetHeader(const u_char *packet) {
    struct sipline_ethernet_header *eth_header;
    eth_header = (struct sipline_ethernet_header *) packet;
    return eth_header;
}

/**
 * Parse package payload int ip package and check if it is a valid IP4
 * @param packet to check if ip
 * @return sipline_ip_header if ip packet else NULL
 */
static inline struct sipline_ip_header *getIpHeader(const u_char *packet) {
    struct sipline_ethernet_header *ethernet_header = getEthernetHeader(packet);
    if (NULL == ethernet_header) {
        fprintf(stdout, "No Ethernet package found, skip package\n");
        return NULL;
    }

    if (ETHER_IP != ntohs(ethernet_header->ether_type)) {
        fprintf(stdout, "No IP4 in ethernet package, skip packet\n");
        return NULL;
    }

    struct sipline_ip_header *ip_header;
    ip_header = (struct sipline_ip_header *) (((u_char *) ethernet_header) + SIZE_ETHERNET);
    u_int size_ip = IP_HL(ip_header) * 4;
    if (IP_MIN_LENGHT > size_ip) {
        printf("IP4 packet size is smaller than minimum, properly not a valid IP4 packet\n");
        return NULL;
    }
    return ip_header;
}

/**
 * Parse UDP package from package payload and check if valid IP4 and UDP
 * @param packet to check if ip
 * @return sipline_ip_header if ip packet else NULL
 */
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
#ifdef DEBUG
    fprintf(stdout, "Total packet available: %d bytes\n", header->caplen);
    fprintf(stdout, "Expected packet size: %d bytes\n", header->len);
#endif

    const struct sipline_udp_header *udp_header = getUdpHeader(packet);
    if (NULL == udp_header) {
        fprintf(stdout, "Not UDP header found in received package, skip it\n");
        return;
    }
    u_char *payload = ((u_char *) udp_header) + SIZE_UDP;
    uint32_t payload_length = ntohs(udp_header->uh_len) - SIZE_UDP;
    printf("Payload length: %d\n", payload_length);

#ifdef DEBUG
    fprintf(stdout, "Parsed UdpHeader from package\n");
    fprintf(stdout, "UdpHeader{sport: %d, dport: %d, len: %d, sum: %d}\n", ntohs(udp_header->uh_sport),
            ntohs(udp_header->uh_dport),
            ntohs(udp_header->uh_len), ntohs(udp_header->uh_sum));
//    fprintf(stdout, "Some Payload: %s\n", payload);
#endif

    struct sipline_call_info *call_info = parseSipMessage(payload, payload_length);
    if (NULL == call_info) {
        fprintf(stdout, "Something unrealted sniffed, ignore package\n");
        return;
    }

    if (EXIT_FAILURE == informServer(call_info)) {
        fprintf(stderr, "Failed to post data to remove server\n");
    }

    free(call_info->from);
    free(call_info->to);
    free(call_info);
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
int applySipFilter(pcap_t **handle) {
    int ret_code = EXIT_SUCCESS;
    struct bpf_program filter;

    fprintf(stdout, "Start to compile BPF filter for SIP packages\n");
    if (pcap_compile(*handle, &filter, BPF_SIP_FILTER, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "Bad filter expression supplied - %s\n", pcap_geterr(*handle));
        ret_code = EXIT_FAILURE;
        goto cleanup;
    }

    fprintf(stdout, "Start applying BPF filter against pcap handle\n");
    if (pcap_setfilter(*handle, &filter) == -1) {
        fprintf(stderr, "Failed to apply filter - %s\n", pcap_geterr(*handle));
        ret_code = EXIT_FAILURE;
        goto cleanup;
    }

    fprintf(stdout, "Done compiling and applying BPF filter.\n");

    cleanup:
    if (EXIT_SUCCESS == ret_code) {
        pcap_freecode(&filter);
    }
    return ret_code;
}

/**
 * Setup live network traffic parsing via libpcap
 * @param interface name to start sniffing
 * @return on Success return EXIT_SUCCESS, on Failure EXIT_FAILURE
 */
int setupLivePcapParsing(char *interface) {
    fprintf(stdout, "Setup live monitoring on interface: %s\n", interface);
    return EXIT_SUCCESS;
}

/**
 * Setup file network traffic parsing via libpcap
 * @param parent_handler pcap_t handle set after opening file and apply filter
 * @param filename to pcap file for analysing
 * @return on Success return EXIT_SUCCESS, on Failure EXIT_FAILURE
 */
int setupFilePcapParsing(pcap_t **parent_handler, const char *filename) {
    fprintf(stdout, "Start setup pcap file: %s\n", filename);

    pcap_t *handle;
    char err_buf[PCAP_ERRBUF_SIZE];

    fprintf(stdout, "Try to open pcap file for reading packages\n");
    handle = pcap_open_offline(filename, err_buf);
    if (NULL == handle) {
        fprintf(stderr, "Failed to open pcap file: %s\n", filename);
        return EXIT_FAILURE;
    }

    if (EXIT_FAILURE == applySipFilter(&handle)) {
        fprintf(stderr, "Failed to apply sip filter");
        pcap_close(handle);
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
 * @return on Success return EXIT_SUCCESS, on Failure EXIT_FAILURE
 */
int registerOsip(osip_t **osip) {
    fprintf(stdout, "Start to register osip state machine started\n");
    int ret_osip = osip_init(osip);
    if (0 != ret_osip) {
        fprintf(stdout, "Failed to register osip state machine\n");
        return EXIT_FAILURE;
    }

    fprintf(stdout, "Registered osip state machine properly\n");
    return EXIT_SUCCESS;
}

int main(int argc, char *argv[]) {
    int ret_code = EXIT_SUCCESS;
    char *interface = NULL;
    osip_t *osip = NULL;
    pcap_t *handle = NULL;


    ret_code = parseInterfaceFromParams(argc, argv, &interface);
    if (EXIT_FAILURE == ret_code) {
        fprintf(stdout, "Usage: ./sipline <interface_name>\n");
        goto cleanup;
    }
    fprintf(stdout, "Start analysing SIP traffic on interface: %s\n", interface);

    ret_code = registerOsip(&osip);
    if (EXIT_FAILURE == ret_code) {
        fprintf(stderr, "Failed to register osip watch properly");
        goto cleanup;
    }

    // TODO: add relative addressing
    ret_code = setupFilePcapParsing(&handle, "/home/akarner/rehka/sipline/test/testPackages.pcap");
    if (EXIT_FAILURE == ret_code) {
        fprintf(stderr, "Failed to analyze provided pcap file\n");
        goto cleanup;
    }

    ret_code = startSipListener(handle, sipPacketHandler, NULL);
    if (EXIT_FAILURE == ret_code) {
        fprintf(stderr, "Something failed during package analysis");
        goto cleanup;
    }

    cleanup:
    pcap_close(handle);
    osip_release(osip);
    free(interface);

    return ret_code;
}
