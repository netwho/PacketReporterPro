#include <config.h>
#include <wireshark.h>

#include "packet_collector.h"
#include "reporter_plugin.h"

#include <epan/epan_dissect.h>
#include <epan/epan.h>
#include <epan/proto.h>
#include <epan/tap.h>
#include <epan/stat_tap_ui.h>
#include <epan/to_str.h>
#include <epan/ftypes/ftypes.h>
#include <epan/dissectors/packet-ip.h>
#include <epan/dissectors/packet-tcp.h>
#include <epan/dissectors/packet-http.h>
#include <file.h>
#include <cfile.h>
#include <wiretap/wtap.h>
#include <wsutil/wslog.h>

#if VERSION_MINOR < 6
#include <wsutil/buffer.h>
#endif

#include <string.h>
#include <math.h>
#include <stdio.h>
#include <sys/stat.h>

#ifndef MIN
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#endif

/* DNS tap struct — copied from packet-dns.c (not exported in a header).
 * Layout changed between Wireshark 4.2 and 4.4: qname (and later fields)
 * were added in 4.4+. */
#if VERSION_MINOR >= 4
struct DnsTap {
    unsigned packet_qr;
    unsigned packet_qtype;
    int      packet_qclass;
    unsigned packet_rcode;
    unsigned packet_opcode;
    unsigned payload_size;
    unsigned qname_len;
    unsigned qname_labels;
    char    *qname;
    unsigned nquestions;
    unsigned nanswers;
    unsigned nauthorities;
    unsigned nadditionals;
    gboolean unsolicited;
    gboolean retransmission;
    nstime_t rrt;
    wmem_list_t *rr_types;
    char     source[256];
    char     qhost[256];
    char     qdomain[256];
    unsigned flags;
};
#else
struct DnsTap {
    unsigned packet_qr;
    unsigned packet_qtype;
    int      packet_qclass;
    unsigned packet_rcode;
    unsigned packet_opcode;
    unsigned payload_size;
    unsigned qname_len;
    unsigned qname_labels;
    unsigned nquestions;
    unsigned nanswers;
    unsigned nauthorities;
    unsigned nadditionals;
    gboolean unsolicited;
    gboolean retransmission;
    nstime_t rrt;
};
#endif

/* ----------------------------------------------------------------
 * Paper size constants
 * ---------------------------------------------------------------- */
const paper_size_t PAPER_A4_SIZE = {
    PAPER_A4, 595.28, 841.89, "A4"
};

const paper_size_t PAPER_LEGAL_SIZE = {
    PAPER_LEGAL, 612.0, 1008.0, "Legal"
};

/* ----------------------------------------------------------------
 * Internal tap data structures
 * ---------------------------------------------------------------- */

typedef struct {
    collection_result_t *result;
    gboolean             detailed;
} tap_context_t;

/* ----------------------------------------------------------------
 * Hash table helpers
 * ---------------------------------------------------------------- */

static void free_ip_stats(gpointer data)
{
    ip_stats_t *s = (ip_stats_t *)data;
    g_free(s->address);
    g_free(s);
}

static void free_protocol_entry(gpointer data)
{
    protocol_entry_t *e = (protocol_entry_t *)data;
    g_free(e->name);
    g_free(e);
}

static void free_proto_tree_node(gpointer data);

static proto_tree_node_t *proto_tree_node_new(const char *name)
{
    proto_tree_node_t *n = g_new0(proto_tree_node_t, 1);
    n->name = g_strdup(name);
    n->children = g_hash_table_new_full(g_str_hash, g_str_equal,
                                         NULL, free_proto_tree_node);
    return n;
}

static void free_proto_tree_node(gpointer data)
{
    proto_tree_node_t *n = (proto_tree_node_t *)data;
    if (!n) return;
    g_hash_table_destroy(n->children);
    g_free(n->name);
    g_free(n);
}

static void free_port_entry(gpointer data)
{
    port_entry_t *e = (port_entry_t *)data;
    g_free(e->service);
    g_free(e);
}

static void free_dns_query(gpointer data)
{
    dns_query_t *q = (dns_query_t *)data;
    g_free(q->name);
    g_free(q);
}

static void free_dns_response(gpointer data)
{
    dns_response_t *r = (dns_response_t *)data;
    g_free(r->query);
    g_free(r->answer);
    g_free(r);
}

static void free_tls_sni(gpointer data)
{
    tls_sni_t *s = (tls_sni_t *)data;
    g_free(s->sni);
    g_free(s);
}

static void free_tls_version(gpointer data) { g_free(data); }

static void free_tls_cipher(gpointer data)
{
    tls_cipher_t *c = (tls_cipher_t *)data;
    g_free(c->name);
    g_free(c);
}

static void free_tls_cert(gpointer data)
{
    tls_cert_t *c = (tls_cert_t *)data;
    g_free(c->cn);
    g_free(c);
}

static void free_http_ua(gpointer data)
{
    http_ua_t *u = (http_ua_t *)data;
    g_free(u->user_agent);
    g_free(u);
}

static void free_http_host(gpointer data)
{
    http_host_t *h = (http_host_t *)data;
    g_free(h->host);
    g_free(h);
}

static void free_http_status(gpointer data) { g_free(data); }

static void free_mac_entry(gpointer data)
{
    mac_entry_t *m = (mac_entry_t *)data;
    g_free(m->mac);
    g_free(m->oui);
    g_free(m);
}

static void free_comm_pair(gpointer data)
{
    comm_pair_t *p = (comm_pair_t *)data;
    g_free(p->src);
    g_free(p->dst);
    g_free(p);
}

static void free_stream_rtt(gpointer data)
{
    tcp_stream_rtt_t *s = (tcp_stream_rtt_t *)data;
    g_free(s->endpoints);
    g_free(s);
}

/* ----------------------------------------------------------------
 * TLS proto-tree field extraction
 * ---------------------------------------------------------------- */

static int hf_tls_hs_type      = -1;
static int hf_tls_hs_version   = -1;
static int hf_tls_sup_version  = -1;
static int hf_tls_record_ver   = -1;
static int hf_tls_ciphersuite  = -1;
static int hf_tls_server_name  = -1;
static int hf_tcp_stream       = -1;
static int hf_x509_not_before  = -1;
static int hf_x509_not_after   = -1;
static int hf_x509_dns_name    = -1;
static int hf_x509_utf8        = -1;
static int hf_x509_printable   = -1;
static int hf_quic_version     = -1;
static int hf_tcp_ack_rtt      = -1;
static int hf_tcp_option_kind  = -1;
static int hf_tcp_flags_syn    = -1;
static gboolean tls_fields_resolved = FALSE;

static void
resolve_tls_field_ids(void)
{
    if (tls_fields_resolved) return;
    tls_fields_resolved = TRUE;

    hf_tls_hs_type     = proto_registrar_get_id_byname("tls.handshake.type");
    hf_tls_hs_version  = proto_registrar_get_id_byname("tls.handshake.version");
    hf_tls_sup_version = proto_registrar_get_id_byname("tls.handshake.extensions.supported_version");
    hf_tls_record_ver  = proto_registrar_get_id_byname("tls.record.version");
    hf_tls_ciphersuite = proto_registrar_get_id_byname("tls.handshake.ciphersuite");
    hf_tls_server_name = proto_registrar_get_id_byname("tls.handshake.extensions_server_name");
    hf_tcp_stream      = proto_registrar_get_id_byname("tcp.stream");
    hf_x509_not_before = proto_registrar_get_id_byname("x509af.notBefore");
    hf_x509_not_after  = proto_registrar_get_id_byname("x509af.notAfter");
    hf_x509_dns_name   = proto_registrar_get_id_byname("x509ce.dNSName");
    hf_x509_utf8       = proto_registrar_get_id_byname("x509sat.uTF8String");
    hf_x509_printable  = proto_registrar_get_id_byname("x509sat.printableString");
    hf_quic_version    = proto_registrar_get_id_byname("quic.version");
    hf_tcp_ack_rtt     = proto_registrar_get_id_byname("tcp.analysis.ack_rtt");
    hf_tcp_option_kind = proto_registrar_get_id_byname("tcp.option_kind");
    hf_tcp_flags_syn   = proto_registrar_get_id_byname("tcp.flags.syn");

    ws_log(WS_LOG_DOMAIN, LOG_LEVEL_INFO,
           "TLS field IDs: hs_type=%d rec_ver=%d sup_ver=%d cipher=%d "
           "sni=%d tcp_stream=%d x509_utf8=%d x509_print=%d quic=%d",
           hf_tls_hs_type, hf_tls_record_ver, hf_tls_sup_version,
           hf_tls_ciphersuite, hf_tls_server_name, hf_tcp_stream,
           hf_x509_utf8, hf_x509_printable, hf_quic_version);
}

const char *
collector_tls_version_name(guint16 version)
{
    switch (version) {
    case 0x0300: return "SSL 3.0";
    case 0x0301: return "TLS 1.0";
    case 0x0302: return "TLS 1.1";
    case 0x0303: return "TLS 1.2";
    case 0x0304: return "TLS 1.3";
    default: {
        static char buf[16];
        snprintf(buf, sizeof(buf), "0x%04X", version);
        return buf;
    }
    }
}

const char *
collector_tls_cipher_name(guint16 id)
{
    switch (id) {
    /* TLS 1.3 */
    case 0x1301: return "TLS_AES_128_GCM_SHA256";
    case 0x1302: return "TLS_AES_256_GCM_SHA384";
    case 0x1303: return "TLS_CHACHA20_POLY1305_SHA256";
    case 0x1304: return "TLS_AES_128_CCM_SHA256";
    case 0x1305: return "TLS_AES_128_CCM_8_SHA256";
    /* ECDHE-ECDSA */
    case 0xC02B: return "ECDHE-ECDSA-AES128-GCM-SHA256";
    case 0xC02C: return "ECDHE-ECDSA-AES256-GCM-SHA384";
    case 0xC023: return "ECDHE-ECDSA-AES128-SHA256";
    case 0xC024: return "ECDHE-ECDSA-AES256-SHA384";
    case 0xC009: return "ECDHE-ECDSA-AES128-SHA";
    case 0xC00A: return "ECDHE-ECDSA-AES256-SHA";
    case 0xCCA9: return "ECDHE-ECDSA-CHACHA20-POLY1305";
    /* ECDHE-RSA */
    case 0xC02F: return "ECDHE-RSA-AES128-GCM-SHA256";
    case 0xC030: return "ECDHE-RSA-AES256-GCM-SHA384";
    case 0xC027: return "ECDHE-RSA-AES128-SHA256";
    case 0xC028: return "ECDHE-RSA-AES256-SHA384";
    case 0xC013: return "ECDHE-RSA-AES128-SHA";
    case 0xC014: return "ECDHE-RSA-AES256-SHA";
    case 0xCCA8: return "ECDHE-RSA-CHACHA20-POLY1305";
    /* DHE-RSA */
    case 0x009E: return "DHE-RSA-AES128-GCM-SHA256";
    case 0x009F: return "DHE-RSA-AES256-GCM-SHA384";
    case 0x0067: return "DHE-RSA-AES128-SHA256";
    case 0x006B: return "DHE-RSA-AES256-SHA256";
    case 0x0033: return "DHE-RSA-AES128-SHA";
    case 0x0039: return "DHE-RSA-AES256-SHA";
    case 0xCCAA: return "DHE-RSA-CHACHA20-POLY1305";
    /* RSA */
    case 0x009C: return "RSA-AES128-GCM-SHA256";
    case 0x009D: return "RSA-AES256-GCM-SHA384";
    case 0x003C: return "RSA-AES128-SHA256";
    case 0x003D: return "RSA-AES256-SHA256";
    case 0x002F: return "RSA-AES128-SHA";
    case 0x0035: return "RSA-AES256-SHA";
    /* Legacy / weak */
    case 0x000A: return "RSA-3DES-EDE-SHA";
    case 0x0004: return "RSA-RC4-128-MD5";
    case 0x0005: return "RSA-RC4-128-SHA";
    case 0x00FF: return "EMPTY_RENEGOTIATION_INFO";
    default: {
        static char buf[16];
        snprintf(buf, sizeof(buf), "0x%04X", id);
        return buf;
    }
    }
}

static void
prime_tls_fields(epan_dissect_t *edt)
{
    if (hf_tls_hs_type >= 0)     epan_dissect_prime_with_hfid(edt, hf_tls_hs_type);
    if (hf_tls_hs_version >= 0)  epan_dissect_prime_with_hfid(edt, hf_tls_hs_version);
    if (hf_tls_sup_version >= 0) epan_dissect_prime_with_hfid(edt, hf_tls_sup_version);
    if (hf_tls_record_ver >= 0)  epan_dissect_prime_with_hfid(edt, hf_tls_record_ver);
    if (hf_tls_ciphersuite >= 0) epan_dissect_prime_with_hfid(edt, hf_tls_ciphersuite);
    if (hf_tls_server_name >= 0) epan_dissect_prime_with_hfid(edt, hf_tls_server_name);
    if (hf_tcp_stream >= 0)      epan_dissect_prime_with_hfid(edt, hf_tcp_stream);
    if (hf_x509_not_before >= 0) epan_dissect_prime_with_hfid(edt, hf_x509_not_before);
    if (hf_x509_not_after >= 0)  epan_dissect_prime_with_hfid(edt, hf_x509_not_after);
    if (hf_x509_dns_name >= 0)   epan_dissect_prime_with_hfid(edt, hf_x509_dns_name);
    if (hf_x509_utf8 >= 0)       epan_dissect_prime_with_hfid(edt, hf_x509_utf8);
    if (hf_x509_printable >= 0)  epan_dissect_prime_with_hfid(edt, hf_x509_printable);
    if (hf_quic_version >= 0)    epan_dissect_prime_with_hfid(edt, hf_quic_version);
    if (hf_tcp_ack_rtt >= 0)     epan_dissect_prime_with_hfid(edt, hf_tcp_ack_rtt);
    if (hf_tcp_option_kind >= 0) epan_dissect_prime_with_hfid(edt, hf_tcp_option_kind);
    if (hf_tcp_flags_syn >= 0)   epan_dissect_prime_with_hfid(edt, hf_tcp_flags_syn);
}

static void
record_tls_version(collection_result_t *r, guint16 version)
{
    gpointer key = GUINT_TO_POINTER((guint)version);
    tls_version_t *v = (tls_version_t *)g_hash_table_lookup(
                            r->tls_version_table, key);
    if (!v) {
        v = g_new0(tls_version_t, 1);
        v->version = version;
        g_hash_table_insert(r->tls_version_table, key, v);
    }
    v->count++;
}

static void
record_cipher(GHashTable *table, guint16 cipher_id)
{
    gpointer key = GUINT_TO_POINTER((guint)cipher_id);
    tls_cipher_t *c = (tls_cipher_t *)g_hash_table_lookup(table, key);
    if (!c) {
        c = g_new0(tls_cipher_t, 1);
        c->id = cipher_id;
        c->name = g_strdup(collector_tls_cipher_name(cipher_id));
        g_hash_table_insert(table, key, c);
    }
    c->count++;
}

static double
nstime_to_epoch(const nstime_t *ts)
{
    return (double)ts->secs + (double)ts->nsecs / 1e9;
}

static const char *
extract_string_field(GPtrArray *arr)
{
    if (!arr || arr->len == 0) return NULL;
    field_info *fi = (field_info *)arr->pdata[0];
    if (fi->hfinfo->type == FT_STRING || fi->hfinfo->type == FT_STRINGZ)
        return fvalue_get_string(fi->value);
    return NULL;
}

static guint32
safe_get_uinteger(field_info *fi)
{
    if (!fi || !fi->value || !fi->hfinfo) return 0;
    enum ftenum ft = fi->hfinfo->type;
    switch (ft) {
    case FT_CHAR:
    case FT_UINT8:
    case FT_UINT16:
    case FT_UINT24:
    case FT_UINT32:
    case FT_FRAMENUM:
    case FT_IPXNET:
    case FT_IEEE_11073_SFLOAT:
    case FT_IEEE_11073_FLOAT:
        return fvalue_get_uinteger(fi->value);
    case FT_BOOLEAN:
        return (guint32)fvalue_get_uinteger64(fi->value);
    default:
        return 0;
    }
}

static void
extract_proto_tree_fields(epan_dissect_t *edt, collection_result_t *r)
{
    GPtrArray *arr;
    gboolean has_ch = FALSE, has_sh = FALSE;
    gboolean is_quic = FALSE;
    gboolean is_tls_packet = FALSE;
    guint16  record_ver = 0;
    guint32  tcp_stream_id = G_MAXUINT32;

    /* ---- Get TCP stream ID (needed for both RTT and TLS tracking) ---- */
    if (hf_tcp_stream >= 0) {
        arr = proto_get_finfo_ptr_array(edt->tree, hf_tcp_stream);
        if (arr && arr->len > 0) {
            field_info *fi = (field_info *)arr->pdata[0];
            tcp_stream_id = safe_get_uinteger(fi);
        }
    }

    /* ---- TCP options (count option kinds on SYN packets) ---- */
    if (hf_tcp_flags_syn >= 0 && hf_tcp_option_kind >= 0) {
        arr = proto_get_finfo_ptr_array(edt->tree, hf_tcp_flags_syn);
        if (arr && arr->len > 0) {
            field_info *fi = (field_info *)arr->pdata[0];
            gboolean is_syn = (safe_get_uinteger(fi) != 0);
            if (is_syn) {
                r->tcp_opt_syn_packets++;
                GPtrArray *oarr = proto_get_finfo_ptr_array(
                    edt->tree, hf_tcp_option_kind);
                if (oarr) {
                    gboolean seen[256] = {0};
                    for (guint oi = 0; oi < oarr->len; oi++) {
                        field_info *ofi = (field_info *)oarr->pdata[oi];
                        guint kind = safe_get_uinteger(ofi);
                        if (kind < 256 && !seen[kind]) {
                            r->tcp_opt_counts[kind]++;
                            seen[kind] = TRUE;
                        }
                    }
                }
            }
        }
    }

    /* ---- TCP RTT from tcp.analysis.ack_rtt ---- */
    if (hf_tcp_ack_rtt >= 0) {
        arr = proto_get_finfo_ptr_array(edt->tree, hf_tcp_ack_rtt);
        if (arr && arr->len > 0) {
            field_info *fi = (field_info *)arr->pdata[0];
            double rtt = 0.0;
            if (fi->hfinfo->type == FT_RELATIVE_TIME) {
                const nstime_t *ts = fvalue_get_time(fi->value);
                if (ts) rtt = (double)ts->secs + (double)ts->nsecs / 1e9;
            } else if (fi->hfinfo->type == FT_DOUBLE) {
                rtt = fvalue_get_floating(fi->value);
            }
            if (rtt > 0.0) {
                if (rtt < r->tcp_rtt_min) r->tcp_rtt_min = rtt;
                if (rtt > r->tcp_rtt_max) r->tcp_rtt_max = rtt;
                r->tcp_rtt_sum += rtt;
                r->tcp_rtt_count++;

                double ms = rtt * 1000.0;
                int bucket;
                if      (ms <    1.0) bucket = 0;
                else if (ms <    5.0) bucket = 1;
                else if (ms <   10.0) bucket = 2;
                else if (ms <   20.0) bucket = 3;
                else if (ms <   50.0) bucket = 4;
                else if (ms <  100.0) bucket = 5;
                else if (ms <  200.0) bucket = 6;
                else                  bucket = 7;
                r->tcp_rtt_dist[bucket]++;

                /* Per-connection RTT tracking (keyed by endpoint addresses) */
                {
                    packet_info *pi = &edt->pi;
                    char src_buf[64], dst_buf[64];
                    address_to_str_buf(&pi->src, src_buf, sizeof(src_buf));
                    address_to_str_buf(&pi->dst, dst_buf, sizeof(dst_buf));

                    char conn_key[192];
                    if (strcmp(src_buf, dst_buf) < 0 ||
                        (strcmp(src_buf, dst_buf) == 0 &&
                         pi->srcport <= pi->destport))
                        g_snprintf(conn_key, sizeof(conn_key),
                                   "%s:%u <-> %s:%u",
                                   src_buf, pi->srcport,
                                   dst_buf, pi->destport);
                    else
                        g_snprintf(conn_key, sizeof(conn_key),
                                   "%s:%u <-> %s:%u",
                                   dst_buf, pi->destport,
                                   src_buf, pi->srcport);

                    tcp_stream_rtt_t *sr = (tcp_stream_rtt_t *)
                        g_hash_table_lookup(r->tcp_stream_rtt, conn_key);
                    if (!sr) {
                        sr = g_new0(tcp_stream_rtt_t, 1);
                        sr->stream_id = tcp_stream_id;
                        sr->rtt_min = G_MAXDOUBLE;
                        sr->endpoints = g_strdup(conn_key);
                        g_hash_table_insert(r->tcp_stream_rtt,
                                            g_strdup(conn_key), sr);
                    }
                    if (rtt < sr->rtt_min) sr->rtt_min = rtt;
                    if (rtt > sr->rtt_max) sr->rtt_max = rtt;
                    sr->rtt_sum += rtt;
                    sr->rtt_samples++;
                }
            }
        }
    }

    /* ---- Detect QUIC (always TLS 1.3) ---- */
    if (hf_quic_version >= 0) {
        arr = proto_get_finfo_ptr_array(edt->tree, hf_quic_version);
        if (arr && arr->len > 0)
            is_quic = TRUE;
    }

    /* ---- Check for TLS record version (present in every TLS packet) ---- */
    if (hf_tls_record_ver >= 0) {
        arr = proto_get_finfo_ptr_array(edt->tree, hf_tls_record_ver);
        if (arr && arr->len > 0) {
            is_tls_packet = TRUE;
            field_info *fi = (field_info *)arr->pdata[0];
            record_ver = (guint16)safe_get_uinteger(fi);
        }
    }

    if (!is_tls_packet && !is_quic)
        return;

    r->tls_total_records++;

    /* ---- Check for handshake types ---- */
    if (hf_tls_hs_type >= 0) {
        arr = proto_get_finfo_ptr_array(edt->tree, hf_tls_hs_type);
        if (arr) {
            for (guint i = 0; i < arr->len; i++) {
                field_info *fi = (field_info *)arr->pdata[i];
                guint32 t = safe_get_uinteger(fi);
                if (t == 1) has_ch = TRUE;
                if (t == 2) has_sh = TRUE;
            }
        }
    }

    if (has_ch || has_sh)
        r->tls_handshakes++;

    /* ---- Detect TLS 1.3 from ServerHello supported_versions ---- */
    gboolean tls13_here = FALSE;
    if (has_sh && hf_tls_sup_version >= 0) {
        arr = proto_get_finfo_ptr_array(edt->tree, hf_tls_sup_version);
        if (arr) {
            for (guint i = 0; i < arr->len; i++) {
                field_info *fi = (field_info *)arr->pdata[i];
                guint16 v = (guint16)safe_get_uinteger(fi);
                if (v == 0x0304) { tls13_here = TRUE; break; }
            }
        }
    }

    /* Mark this TCP stream as TLS 1.3 (persists for all future packets) */
    if (tls13_here && tcp_stream_id != G_MAXUINT32)
        g_hash_table_insert(r->tls13_streams,
                            GUINT_TO_POINTER(tcp_stream_id),
                            GINT_TO_POINTER(1));

    /* Check if current stream was previously identified as TLS 1.3 */
    gboolean stream_is_tls13 = tls13_here || is_quic;
    if (!stream_is_tls13 && tcp_stream_id != G_MAXUINT32) {
        if (g_hash_table_contains(r->tls13_streams,
                                  GUINT_TO_POINTER(tcp_stream_id)))
            stream_is_tls13 = TRUE;
    }

    /* ---- Record TLS version for every TLS packet ---- */
    {
        guint16 effective_ver;
        if (stream_is_tls13)
            effective_ver = 0x0304;
        else if (record_ver > 0)
            effective_ver = record_ver;
        else
            effective_ver = 0;

        if (effective_ver > 0) {
            record_tls_version(r, effective_ver);
            if (is_quic) r->tls_quic_count++;
        }
    }

    /* ---- Cipher suites ---- */
    if (hf_tls_ciphersuite >= 0) {
        arr = proto_get_finfo_ptr_array(edt->tree, hf_tls_ciphersuite);
        if (arr && arr->len > 0) {
            if (has_ch && !has_sh) {
                for (guint i = 0; i < arr->len; i++) {
                    field_info *fi = (field_info *)arr->pdata[i];
                    guint16 cid = (guint16)safe_get_uinteger(fi);
                    if (cid == 0x00FF) continue;
                    record_cipher(r->tls_cipher_offered_table, cid);
                }
            } else if (has_sh && !has_ch) {
                field_info *fi = (field_info *)arr->pdata[0];
                guint16 cid = (guint16)safe_get_uinteger(fi);
                record_cipher(r->tls_cipher_table, cid);
            } else if (has_sh && has_ch) {
                for (guint i = 0; i < arr->len - 1; i++) {
                    field_info *fi = (field_info *)arr->pdata[i];
                    guint16 cid = (guint16)safe_get_uinteger(fi);
                    if (cid == 0x00FF) continue;
                    record_cipher(r->tls_cipher_offered_table, cid);
                }
                field_info *fi = (field_info *)arr->pdata[arr->len - 1];
                record_cipher(r->tls_cipher_table,
                              (guint16)safe_get_uinteger(fi));
            }
        }
    }

    /* ---- SNI (from any TLS packet, like the Lua plugin) ---- */
    if (hf_tls_server_name >= 0) {
        arr = proto_get_finfo_ptr_array(edt->tree, hf_tls_server_name);
        if (arr) {
            for (guint i = 0; i < arr->len; i++) {
                field_info *fi = (field_info *)arr->pdata[i];
                if (fi->hfinfo->type == FT_STRING ||
                    fi->hfinfo->type == FT_STRINGZ) {
                    const char *name = fvalue_get_string(fi->value);
                    if (name && *name) {
                        tls_sni_t *s = (tls_sni_t *)g_hash_table_lookup(
                                           r->tls_sni_table, name);
                        if (!s) {
                            s = g_new0(tls_sni_t, 1);
                            s->sni = g_strdup(name);
                            g_hash_table_insert(r->tls_sni_table, s->sni, s);
                        }
                        s->count++;
                    }
                }
            }
        }
    }

    /* ---- Certificate CN (use x509sat fields like the Lua plugin) ---- */
    {
        const char *cert_cn = NULL;

        /* Try x509sat.uTF8String first, then printableString, then dNSName */
        if (hf_x509_utf8 >= 0) {
            arr = proto_get_finfo_ptr_array(edt->tree, hf_x509_utf8);
            cert_cn = extract_string_field(arr);
        }
        if (!cert_cn && hf_x509_printable >= 0) {
            arr = proto_get_finfo_ptr_array(edt->tree, hf_x509_printable);
            cert_cn = extract_string_field(arr);
        }
        if (!cert_cn && hf_x509_dns_name >= 0) {
            arr = proto_get_finfo_ptr_array(edt->tree, hf_x509_dns_name);
            cert_cn = extract_string_field(arr);
        }

        if (cert_cn && *cert_cn) {
            tls_cert_t *ct = (tls_cert_t *)g_hash_table_lookup(
                                 r->tls_cert_table, cert_cn);
            if (!ct) {
                ct = g_new0(tls_cert_t, 1);
                ct->cn = g_strdup(cert_cn);
                g_hash_table_insert(r->tls_cert_table, ct->cn, ct);
            }
            ct->count++;

            /* Try to get certificate expiry dates */
            if (ct->not_after == 0.0 && hf_x509_not_after >= 0) {
                arr = proto_get_finfo_ptr_array(edt->tree, hf_x509_not_after);
                if (arr && arr->len > 0) {
                    field_info *fi = (field_info *)arr->pdata[0];
                    if (fi->hfinfo->type == FT_ABSOLUTE_TIME) {
                        const nstime_t *ts = fvalue_get_time(fi->value);
                        if (ts) ct->not_after = nstime_to_epoch(ts);
                    }
                }
            }
            if (ct->not_before == 0.0 && hf_x509_not_before >= 0) {
                arr = proto_get_finfo_ptr_array(edt->tree, hf_x509_not_before);
                if (arr && arr->len > 0) {
                    field_info *fi = (field_info *)arr->pdata[0];
                    if (fi->hfinfo->type == FT_ABSOLUTE_TIME) {
                        const nstime_t *ts = fvalue_get_time(fi->value);
                        if (ts) ct->not_before = nstime_to_epoch(ts);
                    }
                }
            }
        }
    }
}

/* ----------------------------------------------------------------
 * Result allocation / free
 * ---------------------------------------------------------------- */

static collection_result_t *alloc_result(void)
{
    collection_result_t *r = g_new0(collection_result_t, 1);

    r->ip_table        = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, free_ip_stats);
    r->protocol_table  = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, free_protocol_entry);
    r->proto_hierarchy_table = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, free_protocol_entry);
    r->proto_hier_root       = proto_tree_node_new("Frame");
    r->tcp_port_table  = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, free_port_entry);
    r->udp_port_table  = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, free_port_entry);

    r->dns_queries     = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, free_dns_query);
    r->dns_responses   = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, free_dns_response);
    r->dns_type_counts = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, g_free);

    r->tls_sni_table           = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, free_tls_sni);
    r->tls_version_table       = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, free_tls_version);
    r->tls_cipher_table        = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, free_tls_cipher);
    r->tls_cipher_offered_table = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, free_tls_cipher);
    r->tls_cert_table          = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, free_tls_cert);
    r->tls13_streams           = g_hash_table_new(g_direct_hash, g_direct_equal);
    r->tcp_streams             = g_hash_table_new(g_direct_hash, g_direct_equal);
    r->tcp_stream_rtt          = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, free_stream_rtt);

    r->http_ua_table     = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, free_http_ua);
    r->http_host_table   = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, free_http_host);
    r->http_status_table = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, free_http_status);

    r->mac_table       = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, free_mac_entry);

    r->ip_ttl_table    = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, g_free);
    r->ip_dsfield_table = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, g_free);
    r->ip_proto_table  = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, g_free);

    r->tcp_window_min  = G_MAXDOUBLE;
    r->tcp_seglen_min  = G_MAXDOUBLE;
    r->tcp_rtt_min     = G_MAXDOUBLE;

    r->comm_pair_table = g_hash_table_new_full(g_str_hash, g_str_equal,
                                                g_free, free_comm_pair);

    return r;
}

void packet_collector_free_result(collection_result_t *r)
{
    if (!r) return;

    g_free(r->capture_filename);
    g_hash_table_destroy(r->ip_table);
    g_hash_table_destroy(r->protocol_table);
    g_hash_table_destroy(r->proto_hierarchy_table);
    free_proto_tree_node(r->proto_hier_root);
    g_hash_table_destroy(r->tcp_port_table);
    g_hash_table_destroy(r->udp_port_table);

    g_hash_table_destroy(r->dns_queries);
    g_hash_table_destroy(r->dns_responses);
    g_hash_table_destroy(r->dns_type_counts);

    g_hash_table_destroy(r->tls_sni_table);
    g_hash_table_destroy(r->tls_version_table);
    g_hash_table_destroy(r->tls_cipher_table);
    g_hash_table_destroy(r->tls_cipher_offered_table);
    g_hash_table_destroy(r->tls_cert_table);
    g_hash_table_destroy(r->tls13_streams);
    g_hash_table_destroy(r->tcp_streams);
    g_hash_table_destroy(r->tcp_stream_rtt);

    g_hash_table_destroy(r->http_ua_table);
    g_hash_table_destroy(r->http_host_table);
    g_hash_table_destroy(r->http_status_table);

    g_hash_table_destroy(r->mac_table);

    g_hash_table_destroy(r->ip_ttl_table);
    g_hash_table_destroy(r->ip_dsfield_table);
    g_hash_table_destroy(r->ip_proto_table);

    g_hash_table_destroy(r->comm_pair_table);

    g_free(r);
}

/* ----------------------------------------------------------------
 * Frame tap — basic packet stats, IP, protocol, ports
 *
 * This is the core tap that mirrors the Lua plugin's "frame"
 * listener.  It processes every packet to collect:
 *   - total packets / bytes / timestamps
 *   - per-IP address statistics
 *   - protocol distribution (highest-layer protocol)
 *   - TCP/UDP port statistics
 *   - communication pairs (src→dst)
 * ---------------------------------------------------------------- */

static tap_packet_status
frame_tap_packet(void *tapdata, packet_info *pinfo,
                 epan_dissect_t *edt G_GNUC_UNUSED,
                 const void *data G_GNUC_UNUSED,
                 tap_flags_t flags G_GNUC_UNUSED)
{
    tap_context_t *ctx = (tap_context_t *)tapdata;
    collection_result_t *r = ctx->result;
    const char *src_str = NULL, *dst_str = NULL;
    ip_stats_t *ip_src, *ip_dst;
    const char *highest_proto;
    protocol_entry_t *pe;

    r->total_packets++;
    r->total_bytes += pinfo->fd->pkt_len;

    /* Timestamps */
    double pkt_time = nstime_to_sec(&pinfo->abs_ts);
    if (r->total_packets == 1 || pkt_time < r->first_time)
        r->first_time = pkt_time;
    if (pkt_time > r->last_time)
        r->last_time = pkt_time;

    /* IP addresses — only collect IPv4 and IPv6, skip MAC/other */
    if (pinfo->src.type == AT_IPv4 || pinfo->src.type == AT_IPv6) {
        src_str = address_to_str(pinfo->pool, &pinfo->src);
        if (src_str && *src_str) {
            ip_src = (ip_stats_t *)g_hash_table_lookup(r->ip_table, src_str);
            if (!ip_src) {
                ip_src = g_new0(ip_stats_t, 1);
                ip_src->address = g_strdup(src_str);
                g_hash_table_insert(r->ip_table, ip_src->address, ip_src);
            }
            ip_src->packets_src++;
            ip_src->bytes_src += pinfo->fd->pkt_len;
        }
    }

    if (pinfo->dst.type == AT_IPv4 || pinfo->dst.type == AT_IPv6) {
        dst_str = address_to_str(pinfo->pool, &pinfo->dst);
        if (dst_str && *dst_str) {
            ip_dst = (ip_stats_t *)g_hash_table_lookup(r->ip_table, dst_str);
            if (!ip_dst) {
                ip_dst = g_new0(ip_stats_t, 1);
                ip_dst->address = g_strdup(dst_str);
                g_hash_table_insert(r->ip_table, ip_dst->address, ip_dst);
            }
            ip_dst->packets_dst++;
            ip_dst->bytes_dst += pinfo->fd->pkt_len;
        }
    }

    /* Protocol distribution — walk layers backwards, skip Lua/custom plugins.
     *
     * Built-in Wireshark protocols ALWAYS use all-lowercase filter names
     * (e.g. "tcp", "http", "dns").  Lua and custom plugins typically use
     * uppercase or mixed-case filter names (e.g. "SCANDEDECTOR",
     * "vulnerscvss_final").  We also skip protocols whose short name is
     * all-uppercase and unusually long (> 8 chars). */
    {
        wmem_list_frame_t *lframe = wmem_list_tail(pinfo->layers);
        highest_proto = NULL;
        while (lframe) {
            int pid = GPOINTER_TO_INT(wmem_list_frame_data(lframe));
            const char *name = proto_get_protocol_short_name(
                                   find_protocol_by_id(pid));
            if (name && *name) {
                const char *filter = proto_get_protocol_filter_name(pid);
                gboolean skip = FALSE;

                if (filter && *filter) {
                    const char *p;
                    for (p = filter; *p; p++) {
                        if (*p >= 'A' && *p <= 'Z') {
                            skip = TRUE;
                            break;
                        }
                    }
                    if (!skip && strchr(filter, '_'))
                        skip = TRUE;
                }

                if (!skip) {
                    size_t nlen = strlen(name);
                    if (nlen > 8) {
                        gboolean all_upper = TRUE;
                        const char *p;
                        for (p = name; *p; p++) {
                            if (*p >= 'a' && *p <= 'z') {
                                all_upper = FALSE;
                                break;
                            }
                        }
                        if (all_upper)
                            skip = TRUE;
                    }
                }

                if (!skip) {
                    highest_proto = name;
                    break;
                }
            }
            lframe = wmem_list_frame_prev(lframe);
        }
    }
    if (highest_proto && *highest_proto) {
        pe = (protocol_entry_t *)g_hash_table_lookup(r->protocol_table, highest_proto);
        if (!pe) {
            pe = g_new0(protocol_entry_t, 1);
            pe->name = g_strdup(highest_proto);
            g_hash_table_insert(r->protocol_table, pe->name, pe);
        }
        pe->count++;
    }

    /* Protocol hierarchy - flat counts + tree structure.
     * Walks the full layer stack building both a flat per-protocol counter
     * and a parent-child tree matching Wireshark's Protocol Hierarchy. */
    {
        wmem_list_frame_t *lf = wmem_list_head(pinfo->layers);
        GHashTable *seen = g_hash_table_new(g_str_hash, g_str_equal);
        proto_tree_node_t *parent_node = r->proto_hier_root;
        guint32 pkt_bytes = pinfo->fd->pkt_len;
        r->proto_hier_root->packets++;
        r->proto_hier_root->bytes += pkt_bytes;

        while (lf) {
            int pid = GPOINTER_TO_INT(wmem_list_frame_data(lf));
            const char *name = proto_get_protocol_short_name(
                                   find_protocol_by_id(pid));
            if (name && *name && !g_hash_table_contains(seen, name)) {
                g_hash_table_add(seen, (gpointer)name);

                /* Flat table */
                protocol_entry_t *he = (protocol_entry_t *)
                    g_hash_table_lookup(r->proto_hierarchy_table, name);
                if (!he) {
                    he = g_new0(protocol_entry_t, 1);
                    he->name = g_strdup(name);
                    g_hash_table_insert(r->proto_hierarchy_table,
                                        he->name, he);
                }
                he->count++;

                /* Tree: find or create child under current parent */
                proto_tree_node_t *child = (proto_tree_node_t *)
                    g_hash_table_lookup(parent_node->children, name);
                if (!child) {
                    child = proto_tree_node_new(name);
                    g_hash_table_insert(parent_node->children,
                                        child->name, child);
                }
                child->packets++;
                child->bytes += pkt_bytes;
                parent_node = child;
            }
            lf = wmem_list_frame_next(lf);
        }
        g_hash_table_destroy(seen);
    }

    /* TCP ports */
    if (pinfo->ptype == PT_TCP) {
        port_entry_t *pe_port;
        gpointer key;

        key = GUINT_TO_POINTER((guint)pinfo->destport);
        pe_port = (port_entry_t *)g_hash_table_lookup(r->tcp_port_table, key);
        if (!pe_port) {
            pe_port = g_new0(port_entry_t, 1);
            pe_port->port = (guint16)pinfo->destport;
            g_hash_table_insert(r->tcp_port_table, key, pe_port);
        }
        pe_port->count++;
    }

    /* UDP ports */
    if (pinfo->ptype == PT_UDP) {
        port_entry_t *pe_port;
        gpointer key;

        key = GUINT_TO_POINTER((guint)pinfo->destport);
        pe_port = (port_entry_t *)g_hash_table_lookup(r->udp_port_table, key);
        if (!pe_port) {
            pe_port = g_new0(port_entry_t, 1);
            pe_port->port = (guint16)pinfo->destport;
            g_hash_table_insert(r->udp_port_table, key, pe_port);
        }
        pe_port->count++;
    }

    /* Frame size distribution */
    {
        guint32 flen = pinfo->fd->pkt_len;
        int bucket;
        if      (flen <=   64) bucket = 0;
        else if (flen <=  128) bucket = 1;
        else if (flen <=  256) bucket = 2;
        else if (flen <=  512) bucket = 3;
        else if (flen <= 1024) bucket = 4;
        else if (flen <= 1518) bucket = 5;
        else                   bucket = 6;
        r->frame_size_counts[bucket]++;
    }

    /* MAC layer: broadcast / multicast / unicast */
    if (pinfo->dl_dst.type == AT_ETHER && pinfo->dl_dst.len == 6) {
        const guint8 *mac = (const guint8 *)pinfo->dl_dst.data;
        if (mac[0] == 0xFF && mac[1] == 0xFF && mac[2] == 0xFF &&
            mac[3] == 0xFF && mac[4] == 0xFF && mac[5] == 0xFF)
            r->mac_broadcast++;
        else if (mac[0] & 0x01)
            r->mac_multicast++;
        else
            r->mac_unicast++;
    }

    /* Communication pair for matrix (merged by key) */
    if (src_str && *src_str && dst_str && *dst_str) {
        gchar *pair_key = g_strdup_printf("%s|%s", src_str, dst_str);
        comm_pair_t *cp = (comm_pair_t *)g_hash_table_lookup(
                              r->comm_pair_table, pair_key);
        if (cp) {
            cp->packets++;
            cp->bytes += pinfo->fd->pkt_len;
            g_free(pair_key);
        } else {
            cp = g_new0(comm_pair_t, 1);
            cp->src     = g_strdup(src_str);
            cp->dst     = g_strdup(dst_str);
            cp->packets = 1;
            cp->bytes   = pinfo->fd->pkt_len;
            g_hash_table_insert(r->comm_pair_table, pair_key, cp);
        }
    }

    return TAP_PACKET_DONT_REDRAW;
}

static void frame_tap_reset(void *tapdata)
{
    (void)tapdata;
    /* Reset is a no-op; we create a fresh result each run */
}

static void frame_tap_draw(void *tapdata)
{
    tap_context_t *ctx = (tap_context_t *)tapdata;
    collection_result_t *r = ctx->result;
    r->duration = r->last_time - r->first_time;
}

/* ----------------------------------------------------------------
 * IP tap — TTL, fragmentation, DSCP, IP protocol
 * ---------------------------------------------------------------- */

static tap_packet_status
ip_tap_packet(void *tapdata, packet_info *pinfo G_GNUC_UNUSED,
              epan_dissect_t *edt G_GNUC_UNUSED,
              const void *data,
              tap_flags_t flags G_GNUC_UNUSED)
{
    tap_context_t *ctx = (tap_context_t *)tapdata;
    collection_result_t *r = ctx->result;
    const ws_ip4 *iph = (const ws_ip4 *)data;
    gpointer key;
    guint64 *cnt;

    if (!iph) return TAP_PACKET_DONT_REDRAW;

    /* TTL */
    key = GUINT_TO_POINTER((guint)iph->ip_ttl);
    cnt = (guint64 *)g_hash_table_lookup(r->ip_ttl_table, key);
    if (!cnt) { cnt = g_new0(guint64, 1); g_hash_table_insert(r->ip_ttl_table, key, cnt); }
    (*cnt)++;

    /* DSCP (top 6 bits of TOS) */
    {
        guint dscp = (iph->ip_tos >> 2) & 0x3F;
        key = GUINT_TO_POINTER(dscp);
        cnt = (guint64 *)g_hash_table_lookup(r->ip_dsfield_table, key);
        if (!cnt) { cnt = g_new0(guint64, 1); g_hash_table_insert(r->ip_dsfield_table, key, cnt); }
        (*cnt)++;
    }

    /* IP protocol number */
    key = GUINT_TO_POINTER((guint)iph->ip_proto);
    cnt = (guint64 *)g_hash_table_lookup(r->ip_proto_table, key);
    if (!cnt) { cnt = g_new0(guint64, 1); g_hash_table_insert(r->ip_proto_table, key, cnt); }
    (*cnt)++;

    /* Fragmentation */
    if (iph->ip_off & 0x2000 /* MF flag */ || (iph->ip_off & 0x1FFF) != 0)
        r->ip_fragmented++;

    return TAP_PACKET_DONT_REDRAW;
}

/* ----------------------------------------------------------------
 * TCP tap — window size, segment length, flags, distributions
 * ---------------------------------------------------------------- */

static tap_packet_status
tcp_tap_packet(void *tapdata, packet_info *pinfo G_GNUC_UNUSED,
               epan_dissect_t *edt G_GNUC_UNUSED,
               const void *data,
               tap_flags_t flags G_GNUC_UNUSED)
{
    tap_context_t *ctx = (tap_context_t *)tapdata;
    collection_result_t *r = ctx->result;
    const struct tcpheader *tcph = (const struct tcpheader *)data;

    if (!tcph) return TAP_PACKET_DONT_REDRAW;

    r->tcp_total_segments++;

    /* Track unique streams */
    g_hash_table_insert(r->tcp_streams,
                        GUINT_TO_POINTER(tcph->th_stream),
                        GINT_TO_POINTER(1));

    /* TCP flags */
    if (tcph->th_flags & 0x02) r->tcp_syn_count++;
    if (tcph->th_flags & 0x01) r->tcp_fin_count++;
    if (tcph->th_flags & 0x04) r->tcp_rst_count++;

    /* Window size — min/max/avg + distribution */
    {
        double win = (double)tcph->th_win;
        if (win < r->tcp_window_min) r->tcp_window_min = win;
        if (win > r->tcp_window_max) r->tcp_window_max = win;
        r->tcp_window_sum += win;
        r->tcp_window_count++;

        guint32 w = tcph->th_win;
        int bucket;
        if      (w <=    64) bucket = 0;
        else if (w <=   256) bucket = 1;
        else if (w <=  1024) bucket = 2;
        else if (w <=  4096) bucket = 3;
        else if (w <=  8192) bucket = 4;
        else if (w <= 16384) bucket = 5;
        else if (w <= 32768) bucket = 6;
        else if (w <= 65536) bucket = 7;
        else                 bucket = 8;
        r->tcp_win_dist[bucket]++;
    }

    /* Segment length — min/max/avg + distribution */
    if (tcph->th_have_seglen) {
        double slen = (double)tcph->th_seglen;
        if (slen < r->tcp_seglen_min) r->tcp_seglen_min = slen;
        if (slen > r->tcp_seglen_max) r->tcp_seglen_max = slen;
        r->tcp_seglen_sum += slen;
        r->tcp_seglen_count++;

        guint32 s = tcph->th_seglen;
        int bucket;
        if      (s ==    0) bucket = 0;
        else if (s <=   64) bucket = 1;
        else if (s <=  256) bucket = 2;
        else if (s <=  512) bucket = 3;
        else if (s <= 1024) bucket = 4;
        else if (s <= 1460) bucket = 5;
        else                bucket = 6;
        r->tcp_seg_dist[bucket]++;
    }

    return TAP_PACKET_DONT_REDRAW;
}

/* ----------------------------------------------------------------
 * DNS tap — queries, record types, authoritative
 * ---------------------------------------------------------------- */

static tap_packet_status
dns_tap_packet(void *tapdata, packet_info *pinfo G_GNUC_UNUSED,
               epan_dissect_t *edt G_GNUC_UNUSED,
               const void *data,
               tap_flags_t flags G_GNUC_UNUSED)
{
    tap_context_t *ctx = (tap_context_t *)tapdata;
    collection_result_t *r = ctx->result;
    const struct DnsTap *dns = (const struct DnsTap *)data;

    if (!dns) return TAP_PACKET_DONT_REDRAW;

    if (dns->packet_qr == 0) {
        /* Query */
        r->dns_total_queries++;

#if VERSION_MINOR >= 4
        if (dns->qname && *dns->qname) {
            dns_query_t *q = (dns_query_t *)g_hash_table_lookup(
                                 r->dns_queries, dns->qname);
            if (!q) {
                q = g_new0(dns_query_t, 1);
                q->name = g_strdup(dns->qname);
                q->type = (guint16)dns->packet_qtype;
                g_hash_table_insert(r->dns_queries, q->name, q);
            }
            q->count++;
        }
#endif

        /* Record type */
        {
            gpointer key = GUINT_TO_POINTER(dns->packet_qtype);
            guint64 *cnt = (guint64 *)g_hash_table_lookup(r->dns_type_counts, key);
            if (!cnt) { cnt = g_new0(guint64, 1); g_hash_table_insert(r->dns_type_counts, key, cnt); }
            (*cnt)++;
        }
    } else {
        /* Response */
        r->dns_total_responses++;

        if (dns->packet_rcode == 0 && !(dns->packet_opcode & 0x0400))
            r->dns_authoritative++;
    }

    return TAP_PACKET_DONT_REDRAW;
}

/* ----------------------------------------------------------------
 * HTTP tap — host, response code
 * ---------------------------------------------------------------- */

static tap_packet_status
http_tap_packet(void *tapdata, packet_info *pinfo G_GNUC_UNUSED,
                epan_dissect_t *edt G_GNUC_UNUSED,
                const void *data,
                tap_flags_t flags G_GNUC_UNUSED)
{
    tap_context_t *ctx = (tap_context_t *)tapdata;
    collection_result_t *r = ctx->result;
    const http_info_value_t *http = (const http_info_value_t *)data;

    if (!http) return TAP_PACKET_DONT_REDRAW;

    /* Host */
    if (http->http_host && *http->http_host) {
        http_host_t *h = (http_host_t *)g_hash_table_lookup(
                             r->http_host_table, http->http_host);
        if (!h) {
            h = g_new0(http_host_t, 1);
            h->host = g_strdup(http->http_host);
            g_hash_table_insert(r->http_host_table, h->host, h);
        }
        h->count++;
    }

    /* Response code */
    if (http->response_code > 0) {
        gpointer key = GUINT_TO_POINTER((guint)http->response_code);
        http_status_t *st = (http_status_t *)g_hash_table_lookup(
                                r->http_status_table, key);
        if (!st) {
            st = g_new0(http_status_t, 1);
            st->code = (guint16)http->response_code;
            g_hash_table_insert(r->http_status_table, key, st);
        }
        st->count++;
    }

    return TAP_PACKET_DONT_REDRAW;
}

static void noop_tap_reset(void *tapdata) { (void)tapdata; }
static void noop_tap_draw(void *tapdata)  { (void)tapdata; }

/* ----------------------------------------------------------------
 * Public API
 * ---------------------------------------------------------------- */

void packet_collector_init(void)
{
    ws_log(WS_LOG_DOMAIN, LOG_LEVEL_DEBUG, "Packet collector initialised");
}

void packet_collector_cleanup(void)
{
    ws_log(WS_LOG_DOMAIN, LOG_LEVEL_DEBUG, "Packet collector cleaned up");
}

static GString *
register_tap_safe(const char *name, void *tapdata,
                  tap_packet_cb pkt_cb, tap_draw_cb draw_cb)
{
    return register_tap_listener(
        name, tapdata, NULL,
        TL_REQUIRES_NOTHING,
        noop_tap_reset, pkt_cb,
        draw_cb ? draw_cb : noop_tap_draw, NULL);
}

collection_result_t *
packet_collector_run(capture_file *cf, gboolean detailed)
{
    collection_result_t *result;
    tap_context_t ctx;
    tap_context_t ip_ctx, tcp_ctx, dns_ctx, http_ctx;
    GString *err_str;
    gboolean have_ip = FALSE, have_tcp = FALSE,
             have_dns = FALSE, have_http = FALSE;

    if (!cf) {
        ws_log(WS_LOG_DOMAIN, LOG_LEVEL_WARNING,
               "packet_collector_run: no capture file");
        return alloc_result();
    }

    result = alloc_result();
    if (cf->filename)
        result->capture_filename = g_strdup(cf->filename);
    ctx.result   = result;
    ctx.detailed = detailed;

    /* Frame tap (always) */
    err_str = register_tap_listener(
        "frame", &ctx, NULL, TL_REQUIRES_NOTHING,
        frame_tap_reset, frame_tap_packet, frame_tap_draw, NULL);
    if (err_str) {
        ws_log(WS_LOG_DOMAIN, LOG_LEVEL_WARNING,
               "Failed to register frame tap: %s", err_str->str);
        g_string_free(err_str, TRUE);
        return result;
    }

    /* Protocol-specific taps for detailed reports */
    ip_ctx.result = result;  ip_ctx.detailed = detailed;
    tcp_ctx.result = result; tcp_ctx.detailed = detailed;
    dns_ctx.result = result; dns_ctx.detailed = detailed;
    http_ctx.result = result; http_ctx.detailed = detailed;

    err_str = register_tap_safe("ip", &ip_ctx, ip_tap_packet, NULL);
    if (err_str) { g_string_free(err_str, TRUE); }
    else { have_ip = TRUE; }

    err_str = register_tap_safe("tcp", &tcp_ctx, tcp_tap_packet, NULL);
    if (err_str) { g_string_free(err_str, TRUE); }
    else { have_tcp = TRUE; }

    err_str = register_tap_safe("dns", &dns_ctx, dns_tap_packet, NULL);
    if (err_str) { g_string_free(err_str, TRUE); }
    else { have_dns = TRUE; }

    err_str = register_tap_safe("http", &http_ctx, http_tap_packet, NULL);
    if (err_str) { g_string_free(err_str, TRUE); }
    else { have_http = TRUE; }

    /* Process all packets — use full dissection so protocol taps fire */
    ws_log(WS_LOG_DOMAIN, LOG_LEVEL_INFO,
           "packet_collector_run: cf=%p state=%d count=%u frames=%p",
           (void *)cf, cf->state, cf->count,
           (void *)cf->provider.frames);

    /* Resolve TLS proto-tree field IDs (once) */
    resolve_tls_field_ids();

    if (cf->state == FILE_READ_DONE && cf->provider.frames && cf->count > 0) {
        epan_dissect_t *edt = epan_dissect_new(cf->epan, TRUE, TRUE);
        guint32 framenum;

        /* Prime the proto tree for TLS/TCP field extraction.
         * proto_tree_visible must be TRUE above so that the TCP dissector's
         * sequence-analysis code actually runs and generates fields like
         * tcp.analysis.ack_rtt (it skips the analysis subtree when the
         * tree is invisible, regardless of priming). */
        prime_tls_fields(edt);

        for (framenum = 1; framenum <= cf->count; framenum++) {
            frame_data *fdata = frame_data_sequence_find(
                                    cf->provider.frames, framenum);
            if (!fdata || fdata->file_off < 0)
                continue;

            int err = 0;
            gchar *err_info = NULL;
            wtap_rec rec;
#if VERSION_MINOR >= 6
            wtap_rec_init(&rec, fdata->cap_len);
            if (wtap_seek_read(cf->provider.wth, fdata->file_off,
                               &rec, &err, &err_info)) {
                int fts = wtap_file_type_subtype(cf->provider.wth);
                epan_dissect_run_with_taps(edt, fts, &rec, fdata, NULL);
                extract_proto_tree_fields(edt, result);
            } else if (err_info) {
                g_free(err_info);
            }
#else
            {
                Buffer buf;
                ws_buffer_init(&buf, fdata->cap_len);
                wtap_rec_init(&rec);
                if (wtap_seek_read(cf->provider.wth, fdata->file_off,
                                   &rec, &buf, &err, &err_info)) {
                    int fts = wtap_file_type_subtype(cf->provider.wth);
                    tvbuff_t *tvb = tvb_new_real_data(
                        ws_buffer_start_ptr(&buf),
                        rec.rec_header.packet_header.caplen,
                        rec.rec_header.packet_header.len);
                    epan_dissect_run_with_taps(edt, fts, &rec, tvb, fdata, NULL);
                    extract_proto_tree_fields(edt, result);
                } else if (err_info) {
                    g_free(err_info);
                }
                wtap_rec_cleanup(&rec);
                epan_dissect_reset(edt);
                ws_buffer_free(&buf);
                continue;
            }
#endif
            wtap_rec_cleanup(&rec);
            epan_dissect_reset(edt);
        }
        epan_dissect_free(edt);
    }

    /* Remove all tap listeners */
    remove_tap_listener(&ctx);
    if (have_ip)   remove_tap_listener(&ip_ctx);
    if (have_tcp)  remove_tap_listener(&tcp_ctx);
    if (have_dns)  remove_tap_listener(&dns_ctx);
    if (have_http) remove_tap_listener(&http_ctx);

    ws_log(WS_LOG_DOMAIN, LOG_LEVEL_INFO,
           "Collected: %" G_GUINT64_FORMAT " pkts, %" G_GUINT64_FORMAT " bytes, %.1fs, %u IPs, %u protos, "
           "%u TCP ports, %u comm pairs, %u DNS queries, %u HTTP hosts, "
           "%" G_GUINT64_FORMAT " TLS handshakes, %u TLS versions, %u ciphers offered, "
           "%u ciphers selected, %u SNIs, %u certs, %" G_GUINT64_FORMAT " QUIC, "
           "RTT: %" G_GUINT64_FORMAT " samples across %u connections",
           result->total_packets,
           result->total_bytes,
           result->duration,
           g_hash_table_size(result->ip_table),
           g_hash_table_size(result->protocol_table),
           g_hash_table_size(result->tcp_port_table),
           g_hash_table_size(result->comm_pair_table),
           g_hash_table_size(result->dns_queries),
           g_hash_table_size(result->http_host_table),
           result->tls_handshakes,
           g_hash_table_size(result->tls_version_table),
           g_hash_table_size(result->tls_cipher_offered_table),
           g_hash_table_size(result->tls_cipher_table),
           g_hash_table_size(result->tls_sni_table),
           g_hash_table_size(result->tls_cert_table),
           result->tls_quic_count,
           result->tcp_rtt_count,
           g_hash_table_size(result->tcp_stream_rtt));

    return result;
}

/* ----------------------------------------------------------------
 * Sorting helpers
 * ---------------------------------------------------------------- */

static gint compare_ip_by_packets(gconstpointer a, gconstpointer b)
{
    const ip_stats_t *ia = *(const ip_stats_t **)a;
    const ip_stats_t *ib = *(const ip_stats_t **)b;
    guint64 total_a = ia->packets_src + ia->packets_dst;
    guint64 total_b = ib->packets_src + ib->packets_dst;
    if (total_a > total_b) return -1;
    if (total_a < total_b) return  1;
    return 0;
}

GList *collector_top_ips_by_packets(collection_result_t *r, guint top_n)
{
    GPtrArray *arr = g_ptr_array_new();
    GHashTableIter iter;
    gpointer key, value;
    GList *result_list = NULL;
    guint i;

    g_hash_table_iter_init(&iter, r->ip_table);
    while (g_hash_table_iter_next(&iter, &key, &value))
        g_ptr_array_add(arr, value);

    g_ptr_array_sort(arr, compare_ip_by_packets);

    for (i = 0; i < MIN(top_n, arr->len); i++)
        result_list = g_list_append(result_list, arr->pdata[i]);

    g_ptr_array_free(arr, TRUE);
    return result_list;
}

static gint compare_protocol_by_count(gconstpointer a, gconstpointer b)
{
    const protocol_entry_t *pa = *(const protocol_entry_t **)a;
    const protocol_entry_t *pb = *(const protocol_entry_t **)b;
    if (pa->count > pb->count) return -1;
    if (pa->count < pb->count) return  1;
    return 0;
}

GList *collector_top_protocols(collection_result_t *r, guint top_n)
{
    GPtrArray *arr = g_ptr_array_new();
    GHashTableIter iter;
    gpointer key, value;
    GList *result_list = NULL;
    guint i;

    g_hash_table_iter_init(&iter, r->protocol_table);
    while (g_hash_table_iter_next(&iter, &key, &value))
        g_ptr_array_add(arr, value);

    g_ptr_array_sort(arr, compare_protocol_by_count);

    for (i = 0; i < MIN(top_n, arr->len); i++)
        result_list = g_list_append(result_list, arr->pdata[i]);

    g_ptr_array_free(arr, TRUE);
    return result_list;
}

static gint compare_port_by_count(gconstpointer a, gconstpointer b)
{
    const port_entry_t *pa = *(const port_entry_t **)a;
    const port_entry_t *pb = *(const port_entry_t **)b;
    if (pa->count > pb->count) return -1;
    if (pa->count < pb->count) return  1;
    return 0;
}

static GList *
top_n_from_table(GHashTable *ht, GCompareFunc cmp, guint top_n)
{
    GPtrArray *arr = g_ptr_array_new();
    GHashTableIter iter;
    gpointer key, value;
    GList *result_list = NULL;
    guint i;

    g_hash_table_iter_init(&iter, ht);
    while (g_hash_table_iter_next(&iter, &key, &value))
        g_ptr_array_add(arr, value);

    g_ptr_array_sort(arr, cmp);

    for (i = 0; i < MIN(top_n, arr->len); i++)
        result_list = g_list_append(result_list, arr->pdata[i]);

    g_ptr_array_free(arr, TRUE);
    return result_list;
}

GList *collector_top_hierarchy_protocols(collection_result_t *r, guint top_n)
{
    return top_n_from_table(r->proto_hierarchy_table,
                            compare_protocol_by_count, top_n);
}

static gint compare_tree_node_by_packets(gconstpointer a, gconstpointer b)
{
    const proto_tree_node_t *na = *(const proto_tree_node_t **)a;
    const proto_tree_node_t *nb = *(const proto_tree_node_t **)b;
    if (na->packets > nb->packets) return -1;
    if (na->packets < nb->packets) return  1;
    return 0;
}

static void
flatten_node(proto_tree_node_t *node, int depth, gboolean is_last,
             guint64 total_pkts, int max_depth, double min_pct,
             GList **out)
{
    if (depth > 0) {
        double pct = total_pkts > 0
            ? (double)node->packets / total_pkts * 100.0 : 0.0;
        if (pct < min_pct) return;

        proto_hier_row_t *row = g_new0(proto_hier_row_t, 1);
        row->depth   = depth;
        row->is_last = is_last;
        row->name    = g_strdup(node->name);
        row->packets = node->packets;
        row->pct     = pct;
        *out = g_list_append(*out, row);
    }

    if (depth >= max_depth) return;

    /* Sort children by packet count descending */
    GPtrArray *kids = g_ptr_array_new();
    GHashTableIter iter;
    gpointer key, value;
    g_hash_table_iter_init(&iter, node->children);
    while (g_hash_table_iter_next(&iter, &key, &value))
        g_ptr_array_add(kids, value);
    g_ptr_array_sort(kids, compare_tree_node_by_packets);

    for (guint i = 0; i < kids->len; i++) {
        proto_tree_node_t *child = (proto_tree_node_t *)kids->pdata[i];
        flatten_node(child, depth + 1, (i == kids->len - 1),
                     total_pkts, max_depth, min_pct, out);
    }
    g_ptr_array_free(kids, TRUE);
}

GList *collector_flatten_proto_hierarchy(collection_result_t *r,
                                          int max_depth,
                                          double min_pct)
{
    GList *rows = NULL;
    if (!r->proto_hier_root) return NULL;
    flatten_node(r->proto_hier_root, 0, TRUE,
                 r->total_packets, max_depth, min_pct, &rows);
    return rows;
}

GList *collector_top_tcp_ports(collection_result_t *r, guint top_n)
{
    return top_n_from_table(r->tcp_port_table, compare_port_by_count, top_n);
}

GList *collector_top_udp_ports(collection_result_t *r, guint top_n)
{
    return top_n_from_table(r->udp_port_table, compare_port_by_count, top_n);
}

static gint compare_dns_query_by_count(gconstpointer a, gconstpointer b)
{
    const dns_query_t *qa = *(const dns_query_t **)a;
    const dns_query_t *qb = *(const dns_query_t **)b;
    if (qa->count > qb->count) return -1;
    if (qa->count < qb->count) return  1;
    return 0;
}

GList *collector_top_dns_queries(collection_result_t *r, guint top_n)
{
    return top_n_from_table(r->dns_queries, compare_dns_query_by_count, top_n);
}

static gint compare_http_host_by_count(gconstpointer a, gconstpointer b)
{
    const http_host_t *ha = *(const http_host_t **)a;
    const http_host_t *hb = *(const http_host_t **)b;
    if (ha->count > hb->count) return -1;
    if (ha->count < hb->count) return  1;
    return 0;
}

GList *collector_top_http_hosts(collection_result_t *r, guint top_n)
{
    return top_n_from_table(r->http_host_table, compare_http_host_by_count, top_n);
}

static gint compare_http_status_by_count(gconstpointer a, gconstpointer b)
{
    const http_status_t *sa = *(const http_status_t **)a;
    const http_status_t *sb = *(const http_status_t **)b;
    if (sa->count > sb->count) return -1;
    if (sa->count < sb->count) return  1;
    return 0;
}

GList *collector_top_http_status(collection_result_t *r, guint top_n)
{
    return top_n_from_table(r->http_status_table, compare_http_status_by_count, top_n);
}

static gint compare_comm_pair_by_packets(gconstpointer a, gconstpointer b)
{
    const comm_pair_t *pa = *(const comm_pair_t **)a;
    const comm_pair_t *pb = *(const comm_pair_t **)b;
    if (pa->packets > pb->packets) return -1;
    if (pa->packets < pb->packets) return  1;
    return 0;
}

GList *collector_top_comm_pairs(collection_result_t *r, guint top_n)
{
    return top_n_from_table(r->comm_pair_table, compare_comm_pair_by_packets, top_n);
}

static gint compare_stream_rtt_by_avg(gconstpointer a, gconstpointer b)
{
    const tcp_stream_rtt_t *sa = *(const tcp_stream_rtt_t **)a;
    const tcp_stream_rtt_t *sb = *(const tcp_stream_rtt_t **)b;
    double avg_a = sa->rtt_samples > 0 ? sa->rtt_sum / sa->rtt_samples : 0;
    double avg_b = sb->rtt_samples > 0 ? sb->rtt_sum / sb->rtt_samples : 0;
    if (avg_a > avg_b) return -1;
    if (avg_a < avg_b) return  1;
    return 0;
}

GList *collector_top_stream_rtts(collection_result_t *r, guint top_n)
{
    return top_n_from_table(r->tcp_stream_rtt, compare_stream_rtt_by_avg, top_n);
}

/* ----------------------------------------------------------------
 * Label helpers
 * ---------------------------------------------------------------- */

static const char *frame_size_labels[FRAME_SIZE_BUCKETS] = {
    "0-64", "65-128", "129-256", "257-512",
    "513-1024", "1025-1518", "1519+"
};

const char *collector_frame_size_label(int bucket)
{
    if (bucket >= 0 && bucket < FRAME_SIZE_BUCKETS)
        return frame_size_labels[bucket];
    return "?";
}

const char *collector_ip_proto_name(guint proto)
{
    switch (proto) {
    case 1:  return "ICMP";
    case 2:  return "IGMP";
    case 6:  return "TCP";
    case 17: return "UDP";
    case 41: return "IPv6-in-IPv4";
    case 47: return "GRE";
    case 50: return "ESP";
    case 51: return "AH";
    case 58: return "ICMPv6";
    case 89: return "OSPF";
    case 132:return "SCTP";
    default: {
        static char buf[16];
        snprintf(buf, sizeof(buf), "Proto %u", proto);
        return buf;
    }
    }
}

const char *collector_dscp_name(guint dscp)
{
    switch (dscp) {
    case 0:  return "Best Effort (0)";
    case 8:  return "CS1";
    case 10: return "AF11";
    case 12: return "AF12";
    case 14: return "AF13";
    case 16: return "CS2";
    case 18: return "AF21";
    case 20: return "AF22";
    case 22: return "AF23";
    case 24: return "CS3";
    case 26: return "AF31";
    case 34: return "AF41";
    case 46: return "EF";
    case 48: return "CS6";
    case 56: return "CS7";
    default: {
        static char buf[16];
        snprintf(buf, sizeof(buf), "DSCP %u", dscp);
        return buf;
    }
    }
}

/* ----------------------------------------------------------------
 * TLS sorting helpers
 * ---------------------------------------------------------------- */

static gint compare_tls_sni_by_count(gconstpointer a, gconstpointer b)
{
    const tls_sni_t *sa = *(const tls_sni_t **)a;
    const tls_sni_t *sb = *(const tls_sni_t **)b;
    if (sa->count > sb->count) return -1;
    if (sa->count < sb->count) return  1;
    return 0;
}

GList *collector_top_tls_snis(collection_result_t *r, guint top_n)
{
    return top_n_from_table(r->tls_sni_table, compare_tls_sni_by_count, top_n);
}

static gint compare_tls_cipher_by_count(gconstpointer a, gconstpointer b)
{
    const tls_cipher_t *ca = *(const tls_cipher_t **)a;
    const tls_cipher_t *cb = *(const tls_cipher_t **)b;
    if (ca->count > cb->count) return -1;
    if (ca->count < cb->count) return  1;
    return 0;
}

GList *collector_top_tls_ciphers_selected(collection_result_t *r, guint top_n)
{
    return top_n_from_table(r->tls_cipher_table, compare_tls_cipher_by_count, top_n);
}

GList *collector_top_tls_ciphers_offered(collection_result_t *r, guint top_n)
{
    return top_n_from_table(r->tls_cipher_offered_table, compare_tls_cipher_by_count, top_n);
}

static gint compare_tls_version_by_count(gconstpointer a, gconstpointer b)
{
    const tls_version_t *va = *(const tls_version_t **)a;
    const tls_version_t *vb = *(const tls_version_t **)b;
    if (va->count > vb->count) return -1;
    if (va->count < vb->count) return  1;
    return 0;
}

GList *collector_all_tls_versions(collection_result_t *r)
{
    return top_n_from_table(r->tls_version_table, compare_tls_version_by_count, 100);
}

static gint compare_tls_cert_by_count(gconstpointer a, gconstpointer b)
{
    const tls_cert_t *ca = *(const tls_cert_t **)a;
    const tls_cert_t *cb = *(const tls_cert_t **)b;
    if (ca->count > cb->count) return -1;
    if (ca->count < cb->count) return  1;
    return 0;
}

GList *collector_all_tls_certs(collection_result_t *r)
{
    return top_n_from_table(r->tls_cert_table, compare_tls_cert_by_count, 100);
}

/* ----------------------------------------------------------------
 * TCP distribution labels
 * ---------------------------------------------------------------- */

static const char *tcp_win_labels[TCP_WIN_BUCKETS] = {
    "0-64", "65-256", "257-1K", "1K-4K", "4K-8K",
    "8K-16K", "16K-32K", "32K-64K", "64K+"
};

const char *collector_tcp_win_label(int bucket)
{
    if (bucket >= 0 && bucket < TCP_WIN_BUCKETS) return tcp_win_labels[bucket];
    return "?";
}

static const char *tcp_seg_labels[TCP_SEG_BUCKETS] = {
    "0", "1-64", "65-256", "257-512", "513-1024", "1025-1460", "1461+"
};

const char *collector_tcp_seg_label(int bucket)
{
    if (bucket >= 0 && bucket < TCP_SEG_BUCKETS) return tcp_seg_labels[bucket];
    return "?";
}

static const char *tcp_rtt_labels[TCP_RTT_BUCKETS] = {
    "<1ms", "1-5ms", "5-10ms", "10-20ms",
    "20-50ms", "50-100ms", "100-200ms", "200ms+"
};

const char *collector_tcp_rtt_label(int bucket)
{
    if (bucket >= 0 && bucket < TCP_RTT_BUCKETS) return tcp_rtt_labels[bucket];
    return "?";
}

/* ----------------------------------------------------------------
 * SHA-256 helper — compute hash of a file
 * ---------------------------------------------------------------- */
static void
compute_sha256(const char *path, char out[65])
{
    out[0] = '\0';
    FILE *fp = fopen(path, "rb");
    if (!fp) return;

    GChecksum *cksum = g_checksum_new(G_CHECKSUM_SHA256);
    guchar buf[8192];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), fp)) > 0)
        g_checksum_update(cksum, buf, n);
    fclose(fp);

    const gchar *hex = g_checksum_get_string(cksum);
    if (hex) {
        strncpy(out, hex, 64);
        out[64] = '\0';
    }
    g_checksum_free(cksum);
}

/* ----------------------------------------------------------------
 * Quick file summary — reads pcap directly via wtap
 * ---------------------------------------------------------------- */
file_summary_t
packet_collector_file_summary(const char *filename)
{
    file_summary_t s;
    memset(&s, 0, sizeof(s));

    if (!filename || !filename[0])
        return s;

    s.filename = g_strdup(filename);

    /* File size */
    {
        struct stat st;
        if (stat(filename, &st) == 0)
            s.file_length = (guint64)st.st_size;
    }

    /* SHA-256 hash */
    compute_sha256(filename, s.sha256);

    int err = 0;
    gchar *err_info = NULL;

    wtap *wth = wtap_open_offline(filename, WTAP_TYPE_AUTO,
                                  &err, &err_info, FALSE);
    if (!wth) {
        ws_log(WS_LOG_DOMAIN, LOG_LEVEL_WARNING,
               "file_summary: cannot open '%s': err=%d %s",
               filename, err, err_info ? err_info : "");
        g_free(err_info);
        return s;
    }

    /* File format and encapsulation */
    {
        int fts = wtap_file_type_subtype(wth);
        const char *desc = wtap_file_type_subtype_description(fts);
        const char *name = wtap_file_type_subtype_name(fts);
        if (desc && name)
            s.file_format = g_strdup_printf("%s - %s", desc, name);
        else if (desc)
            s.file_format = g_strdup(desc);
        else
            s.file_format = g_strdup("Unknown");

        int encap = wtap_file_encap(wth);
        const char *encap_desc = wtap_encap_description(encap);
        s.encapsulation = g_strdup(encap_desc ? encap_desc : "Unknown");

        s.snaplen = wtap_snapshot_length(wth);
    }

    wtap_rec rec;
    int64_t  offset;
    double   first_ts = 0.0, last_ts = 0.0;
    gboolean first = TRUE;

#if VERSION_MINOR >= 6
    wtap_rec_init(&rec, 1514);
    while (wtap_read(wth, &rec, &err, &err_info, &offset)) {
#else
    Buffer rbuf;
    ws_buffer_init(&rbuf, 1514);
    wtap_rec_init(&rec);
    while (wtap_read(wth, &rec, &rbuf, &err, &err_info, &offset)) {
#endif
        if (rec.rec_type == REC_TYPE_PACKET) {
            s.packets++;
            s.bytes += rec.rec_header.packet_header.len;

            if (rec.presence_flags & WTAP_HAS_TS) {
                double ts = (double)rec.ts.secs +
                            (double)rec.ts.nsecs / 1e9;
                if (first) {
                    first_ts = ts;
                    first = FALSE;
                }
                last_ts = ts;
            }
        }
        wtap_rec_reset(&rec);
    }

    if (err_info)
        g_free(err_info);
    wtap_rec_cleanup(&rec);
#if VERSION_MINOR < 6
    ws_buffer_free(&rbuf);
#endif
    wtap_close(wth);

    s.first_packet_time = first_ts;
    s.last_packet_time  = last_ts;

    if (s.packets > 0 && !first) {
        s.duration_s = last_ts - first_ts;
        if (s.duration_s > 0.0) {
            s.avg_pps          = (double)s.packets / s.duration_s;
            s.avg_bytes_per_sec = (double)s.bytes  / s.duration_s;
        }
        s.avg_packet_size = (double)s.bytes / (double)s.packets;
    }
    s.valid = TRUE;

    ws_log(WS_LOG_DOMAIN, LOG_LEVEL_INFO,
           "file_summary: %u pkts, %" G_GUINT64_FORMAT " bytes, %.1fs, format=%s, encap=%s",
           s.packets, s.bytes, s.duration_s,
           s.file_format ? s.file_format : "?",
           s.encapsulation ? s.encapsulation : "?");

    return s;
}

void
packet_collector_free_file_summary(file_summary_t *s)
{
    if (!s) return;
    g_free(s->filename);
    g_free(s->file_format);
    g_free(s->encapsulation);
    s->filename = NULL;
    s->file_format = NULL;
    s->encapsulation = NULL;
}
