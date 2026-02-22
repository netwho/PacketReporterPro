#ifndef PACKET_COLLECTOR_H
#define PACKET_COLLECTOR_H

#include <glib.h>
#include <epan/epan.h>
#include <epan/packet.h>
#include <epan/tap.h>

typedef struct _capture_file capture_file;

#ifdef __cplusplus
extern "C" {
#endif

/* ----------------------------------------------------------------
 * Paper size configuration
 * ---------------------------------------------------------------- */
typedef enum {
    PAPER_A4,
    PAPER_LEGAL
} paper_size_id_t;

typedef struct {
    paper_size_id_t id;
    double          width_pt;   /* points (1/72 inch) */
    double          height_pt;
    const char     *name;
} paper_size_t;

/* A4 = 595.28 x 841.89 pt, Legal = 612 x 1008 pt */
extern const paper_size_t PAPER_A4_SIZE;
extern const paper_size_t PAPER_LEGAL_SIZE;

/* ----------------------------------------------------------------
 * Collected statistics — mirrors the Lua plugin's data model
 * ---------------------------------------------------------------- */

/* Per-IP address statistics */
typedef struct {
    char    *address;       /* IP address string */
    guint64  packets_src;   /* packets as source */
    guint64  packets_dst;   /* packets as destination */
    guint64  bytes_src;
    guint64  bytes_dst;
} ip_stats_t;

/* Protocol distribution entry */
typedef struct {
    char    *name;
    guint64  count;
} protocol_entry_t;

/* Protocol hierarchy tree node */
typedef struct proto_tree_node_s {
    char    *name;
    guint64  packets;
    guint64  bytes;
    GHashTable *children;   /* name -> proto_tree_node_t* */
} proto_tree_node_t;

/* Flattened row for rendering the hierarchy tree */
typedef struct {
    int      depth;
    gboolean is_last;       /* last child at this depth */
    char    *name;
    guint64  packets;
    double   pct;           /* percentage of total packets */
} proto_hier_row_t;

/* Port statistics entry */
typedef struct {
    guint16  port;
    char    *service;       /* resolved name or NULL */
    guint64  count;
} port_entry_t;

/* DNS query record */
typedef struct {
    char    *name;
    guint16  type;          /* A=1, AAAA=28, … */
    guint64  count;
} dns_query_t;

/* DNS response record */
typedef struct {
    char    *query;
    char    *answer;        /* resolved IP or CNAME */
    guint64  count;
} dns_response_t;

/* TLS/SSL info */
typedef struct {
    char    *sni;
    guint64  count;
} tls_sni_t;

typedef struct {
    guint16  version;       /* 0x0301 = TLS 1.0, 0x0303 = TLS 1.2, 0x0304 = TLS 1.3 */
    guint64  count;
} tls_version_t;

typedef struct {
    guint16  id;
    char    *name;
    guint64  count;
} tls_cipher_t;

typedef struct {
    char    *cn;            /* Subject dNSName or CN */
    char    *issuer;        /* Issuer CN (may be NULL) */
    double   not_before;    /* epoch seconds, 0 if unknown */
    double   not_after;     /* epoch seconds, 0 if unknown */
    guint64  count;
} tls_cert_t;

/* Per-stream TCP RTT stats */
typedef struct {
    guint32  stream_id;
    char    *endpoints;     /* "src_ip:port -> dst_ip:port" */
    double   rtt_min;
    double   rtt_max;
    double   rtt_sum;
    guint64  rtt_samples;
    guint64  packets;
} tcp_stream_rtt_t;

/* HTTP info */
typedef struct {
    char    *user_agent;
    guint64  count;
} http_ua_t;

typedef struct {
    char    *host;
    guint64  count;
} http_host_t;

typedef struct {
    guint16  code;
    guint64  count;
} http_status_t;

/* MAC layer info */
typedef struct {
    char    *mac;
    char    *oui;           /* resolved vendor or NULL */
    guint64  packets;
    guint64  bytes;
} mac_entry_t;

/* Communication pair (IP-to-IP or MAC-to-MAC) */
typedef struct {
    char    *src;
    char    *dst;
    guint64  packets;
    guint64  bytes;
} comm_pair_t;

/* ----------------------------------------------------------------
 * Aggregate collection result
 * ---------------------------------------------------------------- */
typedef struct {
    /* Basic frame stats */
    guint64     total_packets;
    guint64     total_bytes;
    double      first_time;     /* epoch seconds */
    double      last_time;
    double      duration;       /* seconds */

    /* File metadata (populated by packet_collector_run) */
    char       *capture_filename;   /* full path to the pcap file */

    /* IP stats — hash: address string → ip_stats_t* */
    GHashTable *ip_table;

    /* Protocol distribution — hash: name → protocol_entry_t* */
    GHashTable *protocol_table;

    /* Protocol hierarchy — every layer counted per-packet; name → protocol_entry_t* */
    GHashTable *proto_hierarchy_table;

    /* Protocol hierarchy tree (parent-child relationships) */
    proto_tree_node_t *proto_hier_root;

    /* TCP/UDP port stats — hash: port(guint16 key) → port_entry_t* */
    GHashTable *tcp_port_table;
    GHashTable *udp_port_table;

    /* DNS */
    GHashTable *dns_queries;     /* name → dns_query_t* */
    GHashTable *dns_responses;   /* query → dns_response_t* */
    guint64     dns_total_queries;
    guint64     dns_total_responses;
    guint64     dns_authoritative;
    GHashTable *dns_type_counts; /* type(guint16) → count */

    /* TLS */
    GHashTable *tls_sni_table;       /* sni → tls_sni_t* */
    GHashTable *tls_version_table;   /* version(guint16) → tls_version_t* */
    GHashTable *tls_cipher_table;    /* id(guint16) → tls_cipher_t* (selected in ServerHello) */
    GHashTable *tls_cipher_offered_table; /* id(guint16) → tls_cipher_t* (offered in ClientHello) */
    GHashTable *tls_cert_table;      /* cn → tls_cert_t* */
    GHashTable *tls13_streams;       /* tcp_stream(guint) → TRUE — internal tracking */
    guint64     tls_quic_count;      /* QUIC connections (always TLS 1.3) */
    guint64     tls_handshakes;      /* total TLS handshakes observed */
    guint64     tls_total_records;   /* total TLS records (all types) */

    /* HTTP */
    GHashTable *http_ua_table;       /* ua → http_ua_t* */
    GHashTable *http_host_table;     /* host → http_host_t* */
    GHashTable *http_status_table;   /* code(guint16) → http_status_t* */

    /* MAC layer */
    GHashTable *mac_table;           /* mac → mac_entry_t* */
    guint64     mac_unicast;
    guint64     mac_multicast;
    guint64     mac_broadcast;

    /* IP layer detail */
    GHashTable *ip_ttl_table;        /* ttl(guint) → count */
    guint64     ip_fragmented;
    GHashTable *ip_dsfield_table;    /* dsfield(guint) → count */
    GHashTable *ip_proto_table;      /* proto(guint) → count */

    /* TCP layer detail */
    double      tcp_window_min;
    double      tcp_window_max;
    double      tcp_window_sum;
    guint64     tcp_window_count;
    double      tcp_seglen_min;
    double      tcp_seglen_max;
    double      tcp_seglen_sum;
    guint64     tcp_seglen_count;
    double      tcp_rtt_min;
    double      tcp_rtt_max;
    double      tcp_rtt_sum;
    guint64     tcp_rtt_count;

    /* TCP distribution buckets */
#define TCP_WIN_BUCKETS  9
    /* [0]=0-64 [1]=65-256 [2]=257-1K [3]=1K-4K [4]=4K-8K
     * [5]=8K-16K [6]=16K-32K [7]=32K-64K [8]=64K+ */
    guint64     tcp_win_dist[TCP_WIN_BUCKETS];

#define TCP_SEG_BUCKETS  7
    /* [0]=0 [1]=1-64 [2]=65-256 [3]=257-512
     * [4]=513-1024 [5]=1025-1460 [6]=1461+ */
    guint64     tcp_seg_dist[TCP_SEG_BUCKETS];

#define TCP_RTT_BUCKETS  8
    /* [0]<1ms [1]=1-5ms [2]=5-10ms [3]=10-20ms
     * [4]=20-50ms [5]=50-100ms [6]=100-200ms [7]=200ms+ */
    guint64     tcp_rtt_dist[TCP_RTT_BUCKETS];

    /* TCP flags & connection stats */
    guint64     tcp_syn_count;
    guint64     tcp_fin_count;
    guint64     tcp_rst_count;
    guint64     tcp_total_segments;
    GHashTable *tcp_streams;    /* stream_id → TRUE (for unique count) */
    GHashTable *tcp_stream_rtt; /* conn_key → tcp_stream_rtt_t* */

    /* TCP options: per-kind packet count (indexed by option kind 0-255) */
    guint64     tcp_opt_counts[256];
    guint64     tcp_opt_syn_packets; /* SYN packets examined for options */

    /* Frame size distribution buckets:
     * [0]=0-64  [1]=65-128  [2]=129-256  [3]=257-512
     * [4]=513-1024  [5]=1025-1518  [6]=1519+ */
#define FRAME_SIZE_BUCKETS 7
    guint64     frame_size_counts[FRAME_SIZE_BUCKETS];

    /* Communication matrix — hash: "src|dst" → comm_pair_t* */
    GHashTable *comm_pair_table;

} collection_result_t;

/* ----------------------------------------------------------------
 * Public API
 * ---------------------------------------------------------------- */

void                 packet_collector_init(void);
void                 packet_collector_cleanup(void);

/**
 * Run all tap listeners over the current capture and return
 * collected statistics.  The caller must free with
 * packet_collector_free_result().
 *
 * @param cf         Wireshark capture file handle
 * @param detailed   TRUE for detailed report taps, FALSE for summary only
 * @return freshly-allocated result (never NULL)
 */
collection_result_t *packet_collector_run(capture_file *cf, gboolean detailed);

void                 packet_collector_free_result(collection_result_t *r);

/* Sorting helpers — return newly-allocated GLists (caller frees list, not data) */
GList *collector_top_ips_by_packets(collection_result_t *r, guint top_n);
GList *collector_top_protocols(collection_result_t *r, guint top_n);
GList *collector_top_hierarchy_protocols(collection_result_t *r, guint top_n);

/**
 * Flatten the protocol hierarchy tree into a list of proto_hier_row_t
 * suitable for rendering.  Prunes branches below min_pct (0-100) and
 * limits depth.  Caller must free each row and the list.
 */
GList *collector_flatten_proto_hierarchy(collection_result_t *r,
                                         int max_depth,
                                         double min_pct);
GList *collector_top_tcp_ports(collection_result_t *r, guint top_n);
GList *collector_top_udp_ports(collection_result_t *r, guint top_n);
GList *collector_top_dns_queries(collection_result_t *r, guint top_n);
GList *collector_top_http_hosts(collection_result_t *r, guint top_n);
GList *collector_top_http_status(collection_result_t *r, guint top_n);
GList *collector_top_comm_pairs(collection_result_t *r, guint top_n);
GList *collector_top_stream_rtts(collection_result_t *r, guint top_n);
GList *collector_top_tls_snis(collection_result_t *r, guint top_n);
GList *collector_top_tls_ciphers_selected(collection_result_t *r, guint top_n);
GList *collector_top_tls_ciphers_offered(collection_result_t *r, guint top_n);
GList *collector_all_tls_versions(collection_result_t *r);
GList *collector_all_tls_certs(collection_result_t *r);

const char *collector_frame_size_label(int bucket);
const char *collector_ip_proto_name(guint proto);
const char *collector_dscp_name(guint dscp);
const char *collector_tls_version_name(guint16 version);
const char *collector_tls_cipher_name(guint16 id);
const char *collector_tcp_win_label(int bucket);
const char *collector_tcp_seg_label(int bucket);
const char *collector_tcp_rtt_label(int bucket);

/* ----------------------------------------------------------------
 * Quick file summary — reads the pcap file directly via wtap,
 * no capture_file pointer needed.
 * ---------------------------------------------------------------- */
typedef struct {
    guint32  packets;
    guint64  bytes;
    double   duration_s;
    double   avg_pps;
    double   avg_packet_size;
    double   avg_bytes_per_sec;
    gboolean valid;             /* FALSE if file could not be read */

    /* File properties (Wireshark-style) */
    char    *filename;          /* full path */
    guint64  file_length;       /* file size in bytes */
    char     sha256[65];        /* hex string (64 chars + NUL) */
    char    *file_format;       /* e.g. "Wireshark/tcpdump/... - pcap" */
    char    *encapsulation;     /* e.g. "Ethernet" */
    guint    snaplen;           /* snapshot length */
    double   first_packet_time; /* epoch seconds */
    double   last_packet_time;
} file_summary_t;

file_summary_t packet_collector_file_summary(const char *filename);
void           packet_collector_free_file_summary(file_summary_t *s);

#ifdef __cplusplus
}
#endif

#endif /* PACKET_COLLECTOR_H */
