//
// Created by akarner on 4/4/21.
//

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
#include <sipline.h>
#include <osipparser2/osip_parser.h>

#include "siplib.h"
#include "sipnet.h"

char *stringifyCallInfo(sipline_call_info *call_info) {
    size_t needed = snprintf(NULL, 0, "{\"type\":%d,\"from\":%s,\"to\":%s}", call_info->type,
                             call_info->from, call_info->to);
    char *buffer = (char *) calloc(sizeof(char), needed + 1);
    sprintf(buffer, "{\"type\":%d,\"from\":%s,\"to\":%s}", call_info->type, call_info->from, call_info->to);
    return buffer;
}

sipline_call_info *parseSipMessage(u_char *payload, uint32_t payload_length) {
    osip_message_t *sip = NULL;
    sipline_call_info *call_info = NULL;

    if (EXIT_SUCCESS != osip_message_init(&sip)) {
        fprintf(stderr, "Failed to allocate new osip message\n");
        return NULL;
    }

    if (EXIT_SUCCESS != osip_message_parse(sip, ((const char *) payload), payload_length)) {
        call_info = NULL;
        goto cleanup;
    }

    char *sip_method = osip_message_get_method(sip);
    if (NULL == sip_method) {
//        fprintf(stdout, "SIP Answer received, ignored by sipline application\n");
        call_info = NULL;
        goto cleanup;
    }

    if (strncmp(SIP_INVITE_LABEL, sip_method, strlen(SIP_INVITE_LABEL)) == 0) {
        if (NULL == osip_message_get_to(sip)->displayname) {
            call_info = NULL;
            goto cleanup;
        }

        call_info = (sipline_call_info *) malloc(sizeof(sipline_call_info));
        call_info->type = SIP_INVITE_CODE;
        call_info->to = strdup(osip_message_get_to(sip)->displayname);
        call_info->from = (NULL == osip_message_get_from(sip)->displayname) ? strdup("\"UNKNOWN\"") : strdup(
                osip_message_get_from(sip)->displayname);
        fprintf(stdout, "%s Request{from: %s, to: %s}\n", SIP_INVITE_LABEL, call_info->from, call_info->to);
    }

    cleanup:
    osip_message_free(sip);
    return call_info;
}

struct sipline_ethernet_header *getEthernetHeader(const u_char *packet) {
    struct sipline_ethernet_header *eth_header;
    eth_header = (struct sipline_ethernet_header *) packet;
    return eth_header;
}

struct sipline_ip_header *getIpHeader(const u_char *packet) {
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

struct sipline_udp_header *getUdpHeader(const u_char *packet) {
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

void pcapSipPackageHandler(
        u_char *args,
        const struct pcap_pkthdr *header,
        const u_char *packet
) {
    (void) header;
    const struct sipline_udp_header *udp_header = getUdpHeader(packet);
    if (NULL == udp_header) {
        fprintf(stdout, "Not UDP header found in received package, skip it\n");
        return;
    }
    u_char *payload = ((u_char *) udp_header) + SIZE_UDP;
    uint32_t payload_length = ntohs(udp_header->uh_len) - SIZE_UDP;

    sipline_call_info *call_info = parseSipMessage(payload, payload_length);
    if (NULL == call_info) {
        return;
    }

#ifndef USE_CURL
    ping_queue_t *queue = (ping_queue_t *) args;
    ping_task_t *task = (ping_task_t *) malloc(sizeof(ping_task_t));
    *task = (ping_task_t) {
            HTTP,
            strdup(PING_HOST),
            PING_PORT,
            POST,
            strdup(PING_QUERY),
            stringifyCallInfo(call_info),
            NULL
    };
    fprintf(stdout, "Created new task, push to ping queue\n");


    if (EXIT_FAILURE == pushPingTask(queue, task)) {
        fprintf(stdout, "Failed to push  new signal task to queue, let's hope next one works\n");
    }
#else
    CURL *curl;
    CURLcode res;

    curl = curl_easy_init();
    if (curl) {
        char *post_body = stringifyCallInfo(call_info);
        free(call_info->from);
        free(call_info->to);
        free(call_info);

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
        }
        curl_easy_cleanup(curl);
        curl_slist_free_all(chunk);
        free(post_body);
    }
    curl_global_cleanup();
#endif
}


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

int applyPcapSipFilter(pcap_t **handle) {
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

int setupLivePcapParsing(pcap_t **parent_handler, char *interface) {
    fprintf(stdout, "Setup live monitoring on interface: %s\n", interface);

    pcap_t *handle;
    char err_buf[PCAP_ERRBUF_SIZE];

    fprintf(stdout, "Try to open interface for package readling\n");
    handle = pcap_open_live(interface, BUFSIZ, 1, 1000, err_buf);
    if (NULL == handle) {
        fprintf(stderr, "Failed to open network interface: %s\n", interface);
        fprintf(stderr, "PcapError: %s\n", err_buf);
        return EXIT_FAILURE;
    }

    if (EXIT_FAILURE == applyPcapSipFilter(&handle)) {
        fprintf(stderr, "Failed to apply sip filter");
        pcap_close(handle);
        return EXIT_FAILURE;
    }

    *parent_handler = handle;
    fprintf(stdout, "Done setup interface: %s\n", interface);

    fprintf(stdout, "Setup live monitoring on interface: %s\n", interface);
    return EXIT_SUCCESS;
}

int setupFilePcapParsing(pcap_t **parent_handler, const char *filename) {
    fprintf(stdout, "Start setup pcap file: %s\n", filename);

    pcap_t *handle;
    char err_buf[PCAP_ERRBUF_SIZE];

    fprintf(stdout, "Try to open pcap file for reading packages\n");
    handle = pcap_open_offline(filename, err_buf);
    if (NULL == handle) {
        fprintf(stderr, "Failed to open pcap file: %s\n", filename);
        fprintf(stderr, "PcapError: %s\n", err_buf);
        return EXIT_FAILURE;
    }

    if (EXIT_FAILURE == applyPcapSipFilter(&handle)) {
        fprintf(stderr, "Failed to apply sip filter");
        pcap_close(handle);
        return EXIT_FAILURE;
    }

    *parent_handler = handle;
    fprintf(stdout, "Done setup pcap file: %s\n", filename);
    return EXIT_SUCCESS;
}

int startPcapCaptureLoop(pcap_t *handle, u_char *params) {
    if (NULL == handle) {
        fprintf(stderr, "Please provide a proper pcap handle to start SIP listening");
        return EXIT_FAILURE;
    }

    int ret_loop = pcap_loop(handle, 0, pcapSipPackageHandler, params);
    fprintf(stdout, "Pcap loop ended with return code: %d\n", ret_loop);
    return 0 == ret_loop ? EXIT_SUCCESS : EXIT_FAILURE;
}

int initializeOsipParser() {
    fprintf(stdout, "Start to register osip state machine started\n");
    int ret_osip = parser_init();
    if (0 != ret_osip) {
        fprintf(stdout, "Failed to register osip parser\n");
        return EXIT_FAILURE;
    }

    fprintf(stdout, "Registered osip state machine properly\n");
    return EXIT_SUCCESS;
}

