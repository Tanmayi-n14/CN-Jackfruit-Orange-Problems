/*
 * icmp_core.h — ICMP Raw Socket Core Module (C Reference Implementation)
 * =========================================================================
 *
 * Header file declaring structs and function prototypes for the C companion
 * implementation of the ICMP diagnostic suite.
 *
 * This C implementation mirrors the Python icmp_core.py module and serves as:
 *   1. A reference for understanding raw ICMP at the systems level
 *   2. A high-performance alternative for latency-sensitive probing
 *   3. Educational material showing C socket programming
 *
 * Compile: gcc -Wall -Wextra -std=c11 -O2 -o icmp_core icmp_core.c
 * Run:     sudo ./icmp_core <hostname_or_ip> [ttl]
 *
 * Author:  Person 1 (Core Module)
 * Platform: Linux / macOS (requires root)
 */

#ifndef ICMP_CORE_H
#define ICMP_CORE_H

#include <stdint.h>
#include <netinet/in.h>

/* ═══════════════════════════════════════════════════════════════════════
 *  CONSTANTS
 * ═══════════════════════════════════════════════════════════════════════ */

#define ICMP_ECHO_REQ         8     /* Echo Request type                     */
#define ICMP_ECHO_REP         0     /* Echo Reply type                       */
#define ICMP_TIME_EXCEEDED_T  11    /* Time Exceeded (TTL expired in transit) */
#define ICMP_DEST_UNREACH_T   3     /* Destination Unreachable               */
#define DEFAULT_TIMEOUT_MS    2000  /* Default receive timeout (milliseconds)*/
#define DEFAULT_PAYLOAD_SIZE  56    /* Payload bytes (64 total with header)  */
#define DEFAULT_TTL_VAL       64    /* Standard TTL for ping                 */
#define MAX_HOPS_VAL          30    /* Maximum hops for traceroute           */
#define ICMP_HDR_SIZE         8     /* ICMP header is always 8 bytes         */
#define RECV_BUFFER_SIZE      1024  /* Buffer size for recvfrom              */


/* ═══════════════════════════════════════════════════════════════════════
 *  DATA STRUCTURES
 * ═══════════════════════════════════════════════════════════════════════ */

/*
 * ICMP header structure (8 bytes)
 *
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |     Type      |     Code      |          Checksum             |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |           Identifier          |        Sequence Number        |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
typedef struct {
    uint8_t  type;         /* ICMP message type (0, 3, 8, 11, ...)    */
    uint8_t  code;         /* Sub-type code (usually 0)               */
    uint16_t checksum;     /* Internet checksum of ICMP message       */
    uint16_t id;           /* Identifier — match requests to replies  */
    uint16_t sequence;     /* Sequence number for ordering             */
} icmp_header_t;


/*
 * Probe result — returned by probe_host() after each ICMP probe.
 *
 * This mirrors Python's ProbeResult dataclass and carries all information
 * needed by ping and traceroute implementations.
 */
typedef struct {
    char     destination[256];                /* Original hostname/IP         */
    char     resolved_ip[INET_ADDRSTRLEN];   /* Resolved IPv4 address       */
    int      ttl;                            /* TTL used for this probe      */
    int      sequence;                       /* ICMP sequence number         */
    double   rtt_ms;                         /* RTT in ms (-1.0 = timeout)   */
    int      received;                       /* 1 = reply received, 0 = not  */
    int      icmp_type;                      /* Reply ICMP type (-1 on timeout)*/
    int      icmp_code;                      /* Reply ICMP code              */
    char     responding_host[INET_ADDRSTRLEN]; /* IP of actual responder     */
    char     error[256];                     /* Error message (empty = none) */
} probe_result_t;


/* ═══════════════════════════════════════════════════════════════════════
 *  FUNCTION PROTOTYPES
 * ═══════════════════════════════════════════════════════════════════════ */

/*
 * calculate_checksum — RFC 1071 Internet Checksum.
 *
 * Computes the 16-bit one's complement checksum over 'len' bytes of 'data'.
 * Used for the ICMP header checksum field.
 *
 * @param data  Pointer to the data buffer.
 * @param len   Number of bytes in the buffer.
 * @return      16-bit checksum.
 */
uint16_t calculate_checksum(void *data, int len);

/*
 * create_raw_socket — Create a raw ICMP socket with timeout.
 *
 * Creates AF_INET / SOCK_RAW / IPPROTO_ICMP socket and sets SO_RCVTIMEO.
 * Requires root privileges.
 *
 * @param timeout_ms  Receive timeout in milliseconds.
 * @return            Socket file descriptor, or -1 on error.
 */
int create_raw_socket(int timeout_ms);

/*
 * set_ttl — Set the IP TTL on a raw socket.
 *
 * @param sockfd  Socket file descriptor.
 * @param ttl     TTL value (1–255).
 */
void set_ttl(int sockfd, int ttl);

/*
 * build_icmp_packet — Construct an ICMP Echo Request packet.
 *
 * Allocates and fills a complete ICMP packet with header, timestamp payload,
 * and valid checksum.  Caller must free() the returned buffer.
 *
 * @param id            ICMP identifier (usually getpid() & 0xFFFF).
 * @param seq           Sequence number.
 * @param payload_size  Payload size in bytes (typically 56 for 64-byte total).
 * @param out_len       [out] Total packet length in bytes.
 * @return              Heap-allocated packet buffer (caller frees), or NULL.
 */
uint8_t* build_icmp_packet(int id, int seq, int payload_size, int *out_len);

/*
 * send_and_receive — Send an ICMP packet and wait for a reply.
 *
 * Sends the packet via sendto(), then blocks on recvfrom() until a reply
 * arrives or the socket timeout expires.
 *
 * @param sockfd         Socket file descriptor.
 * @param dest_ip        Destination IPv4 address string.
 * @param packet         Pre-built ICMP packet bytes.
 * @param pkt_len        Length of packet in bytes.
 * @param expected_id    ICMP ID we expect in replies.
 * @param expected_seq   Sequence number we expect.
 * @param out_sender_ip  [out] Buffer to store the sender's IP (INET_ADDRSTRLEN).
 * @param out_type       [out] ICMP type of the received reply.
 * @return               RTT in milliseconds, or -1.0 on timeout/error.
 */
double send_and_receive(int sockfd, const char *dest_ip,
                        uint8_t *packet, int pkt_len,
                        int expected_id, int expected_seq,
                        char *out_sender_ip, int *out_type);

/*
 * probe_host — High-level probe function (main entry point).
 *
 * Performs a complete ICMP probe: DNS resolve → socket → set TTL →
 * build packet → send → receive → return result.
 *
 * @param destination  Hostname or IP address to probe.
 * @param ttl          TTL value for this probe.
 * @param sequence     Sequence number.
 * @return             Populated probe_result_t struct.
 */
probe_result_t probe_host(const char *destination, int ttl, int sequence);


#endif /* ICMP_CORE_H */
