//
// Created by akarner on 2/25/21.
//

#ifndef SIPLINE_SIPLINE_H
#define SIPLINE_SIPLINE_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap/pcap.h>
#include <osip2/osip.h>
#include <curl/curl.h>

#include "siplinenet.h"

// enable/disable some more login -> please do not use in production
#define DEBUG 0

// maximal interface length
#define MAX_INTERFACE_LEN 100
// BPF filter expression for SIP messages -> port may vary
#define BPF_SIP_FILTER "(port 6050) and (udp)"
// define API endpoint to send SIP signals to
#define TARGET_URL "http://localhost:2711/ringBell"

// define some stuff to clean up code
#define SIP_INVITE_CODE 0
#define SIP_INVITE_LABEL "INVITE"
#define SIP_CANCEL_CODE 1
#define SIP_CANCEL_LABEL "CANCEL"
#define SIP_ANSWER_CODE 2

/**
 * Generate JSON representation fo call_info struct
 * @param call_info
 * @return char* to json version call_info struct
 */
char *getCallInfoString(struct sipline_call_info *call_info);

/**
 * Send call information to remove server as API request
 * @param call_info
 * @return on Success return EXIT_SUCCESS, on Failure EXIT_FAILURE
 */
int informServer(struct sipline_call_info *call_info);

/**
 * Parse SIP message via osip lib
 * @param payload buffer to parse into sip message
 * @param payload_length buffer length to parse
 * @return on Success return sipline_call_info struct else NULL
 */
struct sipline_call_info *parseSipMessage(u_char *payload, uint32_t payload_length);


/**
 * Parse package payload into ethernet struct
 * @param packet to check if ethernet
 * @return sipline_ether_header if ether packet else NULL
 */
static inline struct sipline_ethernet_header *getEthernetHeader(const u_char *packet);

/**
 * Parse package payload int ip package and check if it is a valid IP4
 * @param packet to check if ip
 * @return sipline_ip_header if ip packet else NULL
 */
static inline struct sipline_ip_header *getIpHeader(const u_char *packet);

/**
 * Parse UDP package from package payload and check if valid IP4 and UDP
 * @param packet to check if ip
 * @return sipline_ip_header if ip packet else NULL
 */
static inline struct sipline_udp_header *getUdpHeader(const u_char *packet);

/**
 * SIP callback handler
 * @param args passed by listener to callback
 * @param header including some stuff
 * @param packet raw package to analyze
 */
void sipPacketHandler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);


/**
 * Simple program argument parser, parse network interface name from argument with index 1
 * @param argc program argument count
 * @param argv program argument values
 * @param interface char pointer to parsed interface, on failure set to NULL
 * @return on Success return EXIT_SUCCESS, on Failure EXIT_FAILURE
 */
int parseInterfaceFromParams(int argc, char *argv[], char **interface);

/**
 * Compile and apply SIP filter to pcap_t handle
 * @param handle
 * @return on Success return EXIT_SUCCESS, on Failure EXIT_FAILURE
 */
int applySipFilter(pcap_t **handle);

/**
 * Setup live network traffic parsing via libpcap
 * @param interface name to start sniffing
 * @return on Success return EXIT_SUCCESS, on Failure EXIT_FAILURE
 */
int setupLivePcapParsing(pcap_t **parent_handler, char *interface);

/**
 * Setup file network traffic parsing via libpcap
 * @param parent_handler pcap_t handle set after opening file and apply filter
 * @param filename to pcap file for analysing
 * @return on Success return EXIT_SUCCESS, on Failure EXIT_FAILURE
 */
int setupFilePcapParsing(pcap_t **parent_handler, const char *filename);

/**
 * Start PCAP SIP listener and sniff until we kill the program
 * @param handle to start listen on
 * @param callback to call for each packages
 * @param callback_args to pass to callback function
 * @return on Success return EXIT_SUCCESS, on Failure EXIT_FAILURE
 */
int startSipListener(pcap_t *handle, pcap_handler callback, u_char *callback_args);

/**
 * Register osip state machine with all callbacks
 * @return on Success return EXIT_SUCCESS, on Failure EXIT_FAILURE
 */
int registerOsip(osip_t **osip);

#endif //SIPLINE_SIPLINE_H
