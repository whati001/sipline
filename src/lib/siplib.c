//
// Created by akarner on 4/4/21.
//

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <osip2/osip.h>

#include "siplib.h"

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

    if (EXIT_FAILURE == applySipFilter(&handle)) {
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

    if (EXIT_FAILURE == applySipFilter(&handle)) {
        fprintf(stderr, "Failed to apply sip filter");
        pcap_close(handle);
        return EXIT_FAILURE;
    }

    *parent_handler = handle;
    fprintf(stdout, "Done setup pcap file: %s\n", filename);
    return EXIT_SUCCESS;
}

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