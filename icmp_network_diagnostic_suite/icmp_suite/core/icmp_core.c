/*
 * icmp_core.c — ICMP Raw Socket Core Module (C Reference Implementation)
 * =========================================================================
 *
 * Complete C implementation of the ICMP diagnostic core, mirroring the
 * Python icmp_core.py module.  Provides raw ICMP socket creation, packet
 * construction, checksum computation, and a high-level probe_host() function.
 *
 * Compile:
 *   gcc -Wall -Wextra -std=c11 -O2 -o icmp_core icmp_core.c
 *
 * Run (requires root):
 *   sudo ./icmp_core google.com
 *   sudo ./icmp_core 8.8.8.8 10     # 10 probes
 *
 * Author:  Person 1 (Core Module)
 * Platform: Linux / macOS
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netdb.h>

#include "icmp_core.h"


/* ═══════════════════════════════════════════════════════════════════════
 *  1. CHECKSUM — RFC 1071 Internet Checksum
 * ═══════════════════════════════════════════════════════════════════════
 *
 * The Internet Checksum algorithm (RFC 1071) works as follows:
 *   1. Treat the data as a stream of 16-bit words.
 *   2. Sum all words using 32-bit arithmetic.
 *   3. If the data has an odd byte, treat it as a 16-bit word with
 *      the low byte zero.
 *   4. Fold any carry (upper 16 bits) back into the lower 16 bits.
 *   5. Return the bitwise NOT (one's complement) of the result.
 *
 * This checksum is used in ICMP, IP, TCP, and UDP headers.
 */

uint16_t calculate_checksum(void *data, int len) {
    uint16_t *buf = (uint16_t *)data;
    uint32_t sum  = 0;
    uint16_t result;

    /* Sum all 16-bit words */
    while (len > 1) {
        sum += *buf++;
        len -= 2;
    }

    /* If there's a leftover byte, pad it with zero and add */
    if (len == 1) {
        sum += *(uint8_t *)buf;
    }

    /* Fold 32-bit sum into 16 bits: add the carry bits back */
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    /* One's complement */
    result = (uint16_t)(~sum & 0xFFFF);
    return result;
}


/* ═══════════════════════════════════════════════════════════════════════
 *  2. CREATE RAW SOCKET
 * ═══════════════════════════════════════════════════════════════════════
 *
 * Creates a raw ICMP socket.  Raw sockets bypass the kernel's transport
 * layer, giving us direct access to craft and receive ICMP packets.
 *
 * Key system call: socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)
 *   - AF_INET     = IPv4
 *   - SOCK_RAW    = raw socket (no TCP/UDP processing)
 *   - IPPROTO_ICMP = we're speaking ICMP protocol
 *
 * The SO_RCVTIMEO option sets a receive timeout so recvfrom() doesn't
 * block forever if no reply arrives.
 */

int create_raw_socket(int timeout_ms) {
    int sockfd;
    struct timeval tv;

    /* Create the raw ICMP socket */
    sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sockfd < 0) {
        if (errno == EPERM || errno == EACCES) {
            fprintf(stderr,
                "[ERROR] Permission denied — run with sudo:\n"
                "        sudo ./icmp_core <host>\n");
        } else {
            perror("[ERROR] socket() failed");
        }
        return -1;
    }

    /* Set receive timeout using SO_RCVTIMEO.
     * This converts milliseconds → struct timeval {seconds, microseconds} */
    tv.tv_sec  = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;

    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO,
                   &tv, sizeof(tv)) < 0) {
        perror("[WARNING] setsockopt(SO_RCVTIMEO) failed");
        /* Non-fatal — continue without timeout (will use select() fallback) */
    }

    return sockfd;
}


/* ═══════════════════════════════════════════════════════════════════════
 *  3. SET TTL
 * ═══════════════════════════════════════════════════════════════════════
 *
 * TTL (Time-To-Live) controls how many router hops a packet can traverse.
 * Each router decrements TTL by 1.  When TTL reaches 0, the router:
 *   1. Drops the packet
 *   2. Sends back an ICMP Time Exceeded (type 11) message
 *
 * This is the fundamental mechanism behind traceroute:
 *   TTL=1 → first router replies with Time Exceeded
 *   TTL=2 → second router replies
 *   TTL=N → Nth hop (or destination) replies
 *
 * For normal ping, TTL is typically set to 64 or 128.
 */

void set_ttl(int sockfd, int ttl) {
    if (ttl < 1 || ttl > 255) {
        fprintf(stderr, "[WARNING] TTL %d out of range (1-255), clamping.\n", ttl);
        ttl = (ttl < 1) ? 1 : 255;
    }

    if (setsockopt(sockfd, IPPROTO_IP, IP_TTL,
                   &ttl, sizeof(ttl)) < 0) {
        perror("[ERROR] setsockopt(IP_TTL) failed");
    }
}


/* ═══════════════════════════════════════════════════════════════════════
 *  4. BUILD ICMP PACKET
 * ═══════════════════════════════════════════════════════════════════════
 *
 * Constructs a complete ICMP Echo Request packet ready to send.
 *
 * Packet layout:
 *   [8 bytes ICMP header] [payload_size bytes payload]
 *
 * The payload embeds a timestamp (struct timeval) in the first bytes
 * so we can calculate RTT on the reply side.  Remaining bytes are
 * filled with 'Q' as a recognizable pattern.
 *
 * The checksum is computed over the entire ICMP message (header + payload)
 * with the checksum field initially set to 0, then written back.
 */

uint8_t* build_icmp_packet(int id, int seq, int payload_size, int *out_len) {
    int total_len = ICMP_HDR_SIZE + payload_size;
    uint8_t *packet;
    icmp_header_t *header;
    struct timeval tv;

    /* Allocate the packet buffer (caller must free) */
    packet = (uint8_t *)calloc(1, total_len);
    if (!packet) {
        fprintf(stderr, "[ERROR] malloc failed for ICMP packet\n");
        *out_len = 0;
        return NULL;
    }

    /* ── Fill the ICMP header ──────────────────────────────────── */
    header = (icmp_header_t *)packet;
    header->type     = ICMP_ECHO_REQ;    /* Type 8 = Echo Request    */
    header->code     = 0;                /* Code 0 (standard)        */
    header->checksum = 0;                /* Set to 0 before computing*/
    header->id       = htons((uint16_t)(id & 0xFFFF));
    header->sequence = htons((uint16_t)(seq & 0xFFFF));

    /* ── Fill the payload ──────────────────────────────────────── */
    uint8_t *payload = packet + ICMP_HDR_SIZE;

    /* Embed a timestamp in the first bytes of payload for RTT calc.
     * gettimeofday() gives microsecond resolution. */
    gettimeofday(&tv, NULL);
    if (payload_size >= (int)sizeof(struct timeval)) {
        memcpy(payload, &tv, sizeof(struct timeval));
        /* Fill remaining payload with 'Q' bytes */
        memset(payload + sizeof(struct timeval), 'Q',
               payload_size - sizeof(struct timeval));
    } else {
        /* Payload too small for full timestamp — fill with 'Q' */
        memset(payload, 'Q', payload_size);
    }

    /* ── Compute and set the checksum ──────────────────────────── */
    header->checksum = calculate_checksum(packet, total_len);

    *out_len = total_len;
    return packet;
}


/* ═══════════════════════════════════════════════════════════════════════
 *  5. SEND AND RECEIVE
 * ═══════════════════════════════════════════════════════════════════════
 *
 * Sends an ICMP packet and waits for a reply.  Uses gettimeofday() for
 * high-resolution RTT measurement:
 *
 *   RTT = (recv.tv_sec - send.tv_sec) * 1000.0
 *       + (recv.tv_usec - send.tv_usec) / 1000.0
 *
 * Reply validation:
 *   - Echo Reply (type 0): verify ID matches what we sent
 *   - Time Exceeded (type 11): accept (traceroute hop)
 *   - Dest Unreachable (type 3): accept (host down)
 *   - Anything else: ignore
 *
 * The received packet includes the IP header (usually 20 bytes), so we
 * must skip it to reach the ICMP data.
 */

double send_and_receive(int sockfd, const char *dest_ip,
                        uint8_t *packet, int pkt_len,
                        int expected_id, int expected_seq,
                        char *out_sender_ip, int *out_type) {
    struct sockaddr_in dest_addr, recv_addr;
    socklen_t addr_len = sizeof(recv_addr);
    struct timeval send_time, recv_time;
    uint8_t recv_buf[RECV_BUFFER_SIZE];
    ssize_t bytes_received;
    int ip_hdr_len;
    icmp_header_t *reply_hdr;

    /* Initialize output parameters */
    if (out_sender_ip) out_sender_ip[0] = '\0';
    if (out_type) *out_type = -1;

    /* ── Set up destination address structure ──────────────────── */
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    if (inet_pton(AF_INET, dest_ip, &dest_addr.sin_addr) <= 0) {
        fprintf(stderr, "[ERROR] Invalid IP address: %s\n", dest_ip);
        return -1.0;
    }

    /* ── Send the packet ──────────────────────────────────────── */
    gettimeofday(&send_time, NULL);

    if (sendto(sockfd, packet, pkt_len, 0,
               (struct sockaddr *)&dest_addr,
               sizeof(dest_addr)) <= 0) {
        perror("[ERROR] sendto() failed");
        return -1.0;
    }

    /* ── Receive the reply ────────────────────────────────────── */
    bytes_received = recvfrom(sockfd, recv_buf, sizeof(recv_buf), 0,
                              (struct sockaddr *)&recv_addr, &addr_len);

    gettimeofday(&recv_time, NULL);

    if (bytes_received <= 0) {
        /* Timeout or error */
        return -1.0;
    }

    /* Extract the sender's IP address */
    if (out_sender_ip) {
        inet_ntop(AF_INET, &recv_addr.sin_addr,
                  out_sender_ip, INET_ADDRSTRLEN);
    }

    /* ── Parse the reply ──────────────────────────────────────── */
    /* Skip the IP header.  IHL (Internet Header Length) is stored in the
     * lower nibble of the first byte, in units of 4 bytes. */
    ip_hdr_len = (recv_buf[0] & 0x0F) * 4;

    if (bytes_received < ip_hdr_len + ICMP_HDR_SIZE) {
        fprintf(stderr, "[WARNING] Packet too short to contain ICMP header\n");
        return -1.0;
    }

    reply_hdr = (icmp_header_t *)(recv_buf + ip_hdr_len);

    if (out_type) {
        *out_type = reply_hdr->type;
    }

    /* ── Validate by ICMP type ────────────────────────────────── */
    if (reply_hdr->type == ICMP_ECHO_REP) {
        /* Echo Reply — verify ID matches ours */
        uint16_t reply_id = ntohs(reply_hdr->id);
        if (reply_id != (uint16_t)(expected_id & 0xFFFF)) {
            /* Not our packet — another process's ping reply */
            return -1.0;
        }
        /* ID matches — this is our reply */
    } else if (reply_hdr->type == ICMP_TIME_EXCEEDED_T) {
        /* Time Exceeded — TTL reached 0 at an intermediate router.
         * The router embeds our original ICMP header in the payload.
         * We accept this for traceroute. */
    } else if (reply_hdr->type == ICMP_DEST_UNREACH_T) {
        /* Destination Unreachable — host/network not reachable */
    } else {
        /* Unknown/irrelevant ICMP type — ignore */
        return -1.0;
    }

    /* ── Compute RTT ──────────────────────────────────────────── */
    double rtt = (recv_time.tv_sec  - send_time.tv_sec)  * 1000.0
               + (recv_time.tv_usec - send_time.tv_usec) / 1000.0;

    return rtt;
}


/* ═══════════════════════════════════════════════════════════════════════
 *  6. PROBE HOST — High-Level Entry Point
 * ═══════════════════════════════════════════════════════════════════════
 *
 * Performs a complete ICMP probe in one call:
 *   1. DNS resolution (hostname → IP)
 *   2. Create raw socket
 *   3. Set TTL
 *   4. Build ICMP packet
 *   5. Send + receive
 *   6. Package result
 *
 * This is the C equivalent of Python's probe_host() — the main interface
 * that ping and traceroute code should call.
 */

probe_result_t probe_host(const char *destination, int ttl, int sequence) {
    probe_result_t result;
    struct hostent *host_entry;
    struct in_addr addr;
    int sockfd;
    uint8_t *packet;
    int pkt_len;
    int icmp_id = getpid() & 0xFFFF;
    char sender_ip[INET_ADDRSTRLEN] = {0};
    int reply_type = -1;
    double rtt;

    /* ── Initialize result struct ──────────────────────────────── */
    memset(&result, 0, sizeof(result));
    strncpy(result.destination, destination, sizeof(result.destination) - 1);
    result.ttl      = ttl;
    result.sequence  = sequence;
    result.rtt_ms    = -1.0;
    result.received  = 0;
    result.icmp_type = -1;
    result.icmp_code = 0;
    result.error[0]  = '\0';

    /* ── Step 1: DNS Resolution ────────────────────────────────── */
    /* First try to parse as dotted-decimal IP (e.g. "8.8.8.8") */
    if (inet_pton(AF_INET, destination, &addr) == 1) {
        /* Already an IP address — no DNS needed */
        strncpy(result.resolved_ip, destination,
                sizeof(result.resolved_ip) - 1);
    } else {
        /* Hostname — resolve via DNS */
        host_entry = gethostbyname(destination);
        if (!host_entry) {
            snprintf(result.error, sizeof(result.error),
                     "Cannot resolve hostname '%s': %s",
                     destination, hstrerror(h_errno));
            return result;
        }
        /* Convert binary address to string */
        inet_ntop(AF_INET, host_entry->h_addr_list[0],
                  result.resolved_ip, sizeof(result.resolved_ip));
    }

    /* ── Step 2: Create raw socket ─────────────────────────────── */
    sockfd = create_raw_socket(DEFAULT_TIMEOUT_MS);
    if (sockfd < 0) {
        snprintf(result.error, sizeof(result.error),
                 "Failed to create raw socket (need root?)");
        return result;
    }

    /* ── Step 3: Set TTL ───────────────────────────────────────── */
    set_ttl(sockfd, ttl);

    /* ── Step 4: Build ICMP packet ─────────────────────────────── */
    packet = build_icmp_packet(icmp_id, sequence, DEFAULT_PAYLOAD_SIZE, &pkt_len);
    if (!packet) {
        snprintf(result.error, sizeof(result.error),
                 "Failed to build ICMP packet");
        close(sockfd);
        return result;
    }

    /* ── Step 5: Send and receive ──────────────────────────────── */
    rtt = send_and_receive(sockfd, result.resolved_ip,
                           packet, pkt_len,
                           icmp_id, sequence,
                           sender_ip, &reply_type);

    /* ── Step 6: Package result ────────────────────────────────── */
    if (rtt >= 0.0) {
        result.received  = 1;
        result.rtt_ms    = rtt;
        result.icmp_type = reply_type;
        strncpy(result.responding_host, sender_ip,
                sizeof(result.responding_host) - 1);
    }
    /* If rtt < 0 → timeout, result.received stays 0 */

    /* Cleanup */
    free(packet);
    close(sockfd);

    return result;
}


/* ═══════════════════════════════════════════════════════════════════════
 *  MAIN — CLI Entry Point
 * ═══════════════════════════════════════════════════════════════════════ */

int main(int argc, char *argv[]) {
    int count = 4;   /* default number of probes */

    if (argc < 2) {
        fprintf(stderr,
            "╔══════════════════════════════════════════════════════════╗\n"
            "║        ICMP Core — Raw Socket Diagnostic Tool           ║\n"
            "╚══════════════════════════════════════════════════════════╝\n"
            "\n"
            "Usage: sudo %s <hostname|ip> [count]\n"
            "\n"
            "Examples:\n"
            "  sudo %s google.com\n"
            "  sudo %s 8.8.8.8 10\n",
            argv[0], argv[0], argv[0]);
        return 1;
    }

    if (argc >= 3) {
        count = atoi(argv[2]);
        if (count < 1) count = 1;
        if (count > 100) count = 100;
    }

    printf("\n");
    printf("  ╔══════════════════════════════════════════════════════╗\n");
    printf("  ║     [ ICMP DIAGNOSTIC SUITE — RAW SOCKET CORE ]     ║\n");
    printf("  ╚══════════════════════════════════════════════════════╝\n");
    printf("\n");
    printf("  Target: %s | Probes: %d | TTL: %d\n\n",
           argv[1], count, DEFAULT_TTL_VAL);

    /* ── Send probes ──────────────────────────────────────────── */
    int received_count = 0;
    double total_rtt   = 0.0;
    double min_rtt     = 999999.0;
    double max_rtt     = 0.0;

    for (int i = 1; i <= count; i++) {
        probe_result_t result = probe_host(argv[1], DEFAULT_TTL_VAL, i);

        if (result.error[0] != '\0') {
            printf("  [ERROR] %s\n", result.error);
            return 1;
        }

        if (result.received) {
            printf("  [SEQ %2d] Reply from %-15s  RTT: %.3f ms  type=%d\n",
                   i, result.responding_host, result.rtt_ms, result.icmp_type);
            received_count++;
            total_rtt += result.rtt_ms;
            if (result.rtt_ms < min_rtt) min_rtt = result.rtt_ms;
            if (result.rtt_ms > max_rtt) max_rtt = result.rtt_ms;
        } else {
            printf("  [SEQ %2d] TIMEOUT ✗\n", i);
        }

        /* Brief delay between probes (1 second, like standard ping) */
        if (i < count) {
            usleep(1000000);
        }
    }

    /* ── Print statistics ─────────────────────────────────────── */
    printf("\n  ─────────────────────────────────────────────────────\n");
    double loss = 100.0 * (count - received_count) / count;
    printf("  STATS: Sent=%d  Recv=%d  Loss=%.1f%%",
           count, received_count, loss);
    if (received_count > 0) {
        double avg_rtt = total_rtt / received_count;
        printf("  Min=%.3fms  Avg=%.3fms  Max=%.3fms",
               min_rtt, avg_rtt, max_rtt);
    }
    printf("\n\n");

    return 0;
}
