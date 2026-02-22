#include <config.h>
#include <wireshark.h>

#include "wifi_collector.h"
#include "reporter_plugin.h"

#include <epan/epan_dissect.h>
#include <epan/proto.h>
#include <epan/tap.h>
#include <epan/to_str.h>
#include <epan/ftypes/ftypes.h>
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

#ifndef MIN
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#endif

/* ----------------------------------------------------------------
 * Free helpers
 * ---------------------------------------------------------------- */

static void free_guint64(gpointer p) { g_free(p); }

static void free_bssid_stats(gpointer p)
{
    wifi_bssid_stats_t *b = (wifi_bssid_stats_t *)p;
    g_free(b->bssid);
    g_free(b->ssid);
    g_free(b->vendor);
    if (b->clients) g_hash_table_destroy(b->clients);
    g_free(b);
}

static void free_client_stats(gpointer p)
{
    wifi_client_stats_t *c = (wifi_client_stats_t *)p;
    g_free(c->mac);
    g_free(c->vendor);
    g_free(c);
}

/* ----------------------------------------------------------------
 * Allocation
 * ---------------------------------------------------------------- */

static wifi_collection_result_t *alloc_wifi_result(void)
{
    wifi_collection_result_t *r = g_new0(wifi_collection_result_t, 1);

    r->rssi_buckets   = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, free_guint64);
    r->snr_buckets    = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, free_guint64);
    r->channel_usage  = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, free_guint64);
    r->datarate_usage = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, free_guint64);
    r->ht_mcs_usage   = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, free_guint64);
    r->vht_mcs_usage  = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, free_guint64);
    r->frame_subtypes = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, free_guint64);
    r->reason_codes   = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, free_guint64);
    r->status_codes   = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, free_guint64);
    r->bssid_table    = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, free_bssid_stats);
    r->client_table   = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, free_client_stats);
    r->qos_tids       = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, free_guint64);

    return r;
}

void wifi_collector_free_result(wifi_collection_result_t *r)
{
    if (!r) return;

    g_hash_table_destroy(r->rssi_buckets);
    g_hash_table_destroy(r->snr_buckets);
    g_hash_table_destroy(r->channel_usage);
    g_hash_table_destroy(r->datarate_usage);
    g_hash_table_destroy(r->ht_mcs_usage);
    g_hash_table_destroy(r->vht_mcs_usage);
    g_hash_table_destroy(r->frame_subtypes);
    g_hash_table_destroy(r->reason_codes);
    g_hash_table_destroy(r->status_codes);
    g_hash_table_destroy(r->bssid_table);
    g_hash_table_destroy(r->client_table);
    g_hash_table_destroy(r->qos_tids);

    g_free(r);
}

/* ----------------------------------------------------------------
 * Increment helpers for hash tables with guint64* values
 * ---------------------------------------------------------------- */

static void incr_int_counter(GHashTable *ht, gint key)
{
    gpointer pk = GINT_TO_POINTER(key);
    guint64 *val = (guint64 *)g_hash_table_lookup(ht, pk);
    if (val) {
        (*val)++;
    } else {
        val = g_new(guint64, 1);
        *val = 1;
        g_hash_table_insert(ht, pk, val);
    }
}

static void incr_uint_counter(GHashTable *ht, guint key)
{
    gpointer pk = GUINT_TO_POINTER(key);
    guint64 *val = (guint64 *)g_hash_table_lookup(ht, pk);
    if (val) {
        (*val)++;
    } else {
        val = g_new(guint64, 1);
        *val = 1;
        g_hash_table_insert(ht, pk, val);
    }
}

static void incr_str_counter(GHashTable *ht, const char *key)
{
    guint64 *val = (guint64 *)g_hash_table_lookup(ht, key);
    if (val) {
        (*val)++;
    } else {
        val = g_new(guint64, 1);
        *val = 1;
        g_hash_table_insert(ht, g_strdup(key), val);
    }
}

/* ----------------------------------------------------------------
 * Proto-tree field IDs for WiFi extraction
 * ---------------------------------------------------------------- */

static int hf_radiotap_signal = -1;
static int hf_radiotap_noise  = -1;
static int hf_radiotap_freq   = -1;
static int hf_radiotap_rate   = -1;
static int hf_radiotap_mcs_idx = -1;
static int hf_radiotap_mcs_bw  = -1;
static int hf_radiotap_mcs_gi  = -1;
static int hf_radiotap_vht_mcs = -1;
static int hf_radiotap_vht_nss = -1;
static int hf_radiotap_vht_bw  = -1;

static int hf_wlan_fc_type    = -1;
static int hf_wlan_fc_subtype = -1;
static int hf_wlan_fc_retry   = -1;
static int hf_wlan_bssid      = -1;
static int hf_wlan_sa         = -1;
static int hf_wlan_da         = -1;
static int hf_wlan_ta         = -1;
static int hf_wlan_ssid       = -1;
static int hf_wlan_ssid_alt   = -1;
static int hf_wlan_sa_resolved = -1;
static int hf_wlan_ta_resolved = -1;
static int hf_wlan_bssid_resolved = -1;
static int hf_wlan_fcs_status = -1;
static int hf_wlan_qos_tid    = -1;
static int hf_wlan_reason_code = -1;
static int hf_wlan_status_code = -1;
static int hf_frame_len        = -1;
static int hf_eapol             = -1;

static gboolean wifi_field_ids_resolved = FALSE;

static void resolve_wifi_field_ids(void)
{
    if (wifi_field_ids_resolved) return;
    wifi_field_ids_resolved = TRUE;

    hf_radiotap_signal  = proto_registrar_get_id_byname("radiotap.dbm_antsignal");
    hf_radiotap_noise   = proto_registrar_get_id_byname("radiotap.dbm_antnoise");
    hf_radiotap_freq    = proto_registrar_get_id_byname("radiotap.channel.freq");
    hf_radiotap_rate    = proto_registrar_get_id_byname("radiotap.datarate");
    hf_radiotap_mcs_idx = proto_registrar_get_id_byname("radiotap.mcs.index");
    hf_radiotap_mcs_bw  = proto_registrar_get_id_byname("radiotap.mcs.bw");
    hf_radiotap_mcs_gi  = proto_registrar_get_id_byname("radiotap.mcs.gi");
    hf_radiotap_vht_mcs = proto_registrar_get_id_byname("radiotap.vht.mcs");
    hf_radiotap_vht_nss = proto_registrar_get_id_byname("radiotap.vht.nss");
    hf_radiotap_vht_bw  = proto_registrar_get_id_byname("radiotap.vht.bw");

    hf_wlan_fc_type     = proto_registrar_get_id_byname("wlan.fc.type");
    hf_wlan_fc_subtype  = proto_registrar_get_id_byname("wlan.fc.subtype");
    hf_wlan_fc_retry    = proto_registrar_get_id_byname("wlan.fc.retry");
    hf_wlan_bssid       = proto_registrar_get_id_byname("wlan.bssid");
    hf_wlan_sa          = proto_registrar_get_id_byname("wlan.sa");
    hf_wlan_da          = proto_registrar_get_id_byname("wlan.da");
    hf_wlan_ta          = proto_registrar_get_id_byname("wlan.ta");
    hf_wlan_ssid        = proto_registrar_get_id_byname("wlan_mgt.ssid");
    hf_wlan_ssid_alt    = proto_registrar_get_id_byname("wlan.ssid");
    hf_wlan_sa_resolved = proto_registrar_get_id_byname("wlan.sa_resolved");
    hf_wlan_ta_resolved = proto_registrar_get_id_byname("wlan.ta_resolved");
    hf_wlan_bssid_resolved = proto_registrar_get_id_byname("wlan.bssid_resolved");
    hf_wlan_fcs_status  = proto_registrar_get_id_byname("wlan.fcs.status");
    hf_wlan_qos_tid     = proto_registrar_get_id_byname("wlan.qos.tid");
    hf_wlan_reason_code = proto_registrar_get_id_byname("wlan_mgt.fixed.reason_code");
    hf_wlan_status_code = proto_registrar_get_id_byname("wlan_mgt.fixed.status_code");
    hf_frame_len        = proto_registrar_get_id_byname("frame.len");
    hf_eapol            = proto_registrar_get_id_byname("eapol.type");

    ws_log(WS_LOG_DOMAIN, LOG_LEVEL_INFO,
           "WiFi field IDs: signal=%d noise=%d freq=%d rate=%d "
           "mcs=%d fc_type=%d fc_sub=%d retry=%d bssid=%d sa=%d ssid=%d/%d",
           hf_radiotap_signal, hf_radiotap_noise, hf_radiotap_freq,
           hf_radiotap_rate, hf_radiotap_mcs_idx,
           hf_wlan_fc_type, hf_wlan_fc_subtype, hf_wlan_fc_retry,
           hf_wlan_bssid, hf_wlan_sa, hf_wlan_ssid, hf_wlan_ssid_alt);
}

static void prime_wifi_fields(epan_dissect_t *edt)
{
    static const int *fields[] = {
        &hf_radiotap_signal, &hf_radiotap_noise, &hf_radiotap_freq,
        &hf_radiotap_rate, &hf_radiotap_mcs_idx, &hf_radiotap_mcs_bw,
        &hf_radiotap_mcs_gi, &hf_radiotap_vht_mcs, &hf_radiotap_vht_nss,
        &hf_radiotap_vht_bw,
        &hf_wlan_fc_type, &hf_wlan_fc_subtype, &hf_wlan_fc_retry,
        &hf_wlan_bssid, &hf_wlan_sa, &hf_wlan_da, &hf_wlan_ta,
        &hf_wlan_ssid, &hf_wlan_ssid_alt,
        &hf_wlan_sa_resolved, &hf_wlan_ta_resolved, &hf_wlan_bssid_resolved,
        &hf_wlan_fcs_status, &hf_wlan_qos_tid,
        &hf_wlan_reason_code, &hf_wlan_status_code,
        &hf_frame_len, &hf_eapol,
    };
    for (size_t i = 0; i < sizeof(fields) / sizeof(fields[0]); i++) {
        if (*fields[i] >= 0)
            epan_dissect_prime_with_hfid(edt, *fields[i]);
    }
}

/* ----------------------------------------------------------------
 * Type-safe field accessors for proto tree extraction.
 *
 * These check the actual field type before calling fvalue_get_*
 * to avoid crashes when a field's type doesn't match expectations
 * (e.g. wlan.ssid may be FT_BYTES instead of FT_STRING).
 * ---------------------------------------------------------------- */

#define FT_IS_UINT_COMPAT(ft) \
    ((ft) == FT_UINT8 || (ft) == FT_UINT16 || (ft) == FT_UINT24 || \
     (ft) == FT_UINT32 || (ft) == FT_BOOLEAN || (ft) == FT_FRAMENUM)

#define FT_IS_INT_COMPAT(ft) \
    ((ft) == FT_INT8 || (ft) == FT_INT16 || (ft) == FT_INT24 || (ft) == FT_INT32)

#define FT_IS_STRING_COMPAT(ft) \
    ((ft) == FT_STRING || (ft) == FT_STRINGZ || (ft) == FT_STRINGZPAD || \
     (ft) == FT_STRINGZTRUNC || (ft) == FT_UINT_STRING)

static gboolean
get_uint_field(epan_dissect_t *edt, int hfid, guint *out)
{
    if (hfid < 0) return FALSE;
    GPtrArray *arr = proto_get_finfo_ptr_array(edt->tree, hfid);
    if (!arr || arr->len == 0) return FALSE;
    field_info *fi = (field_info *)g_ptr_array_index(arr, 0);
    if (!fi || !fi->value || !fi->hfinfo) return FALSE;
    enum ftenum ft = fi->hfinfo->type;
    if (ft == FT_BOOLEAN) {
        *out = (guint)fvalue_get_uinteger64(fi->value);
        return TRUE;
    }
    if (FT_IS_UINT_COMPAT(ft)) {
        *out = fvalue_get_uinteger(fi->value);
        return TRUE;
    }
    return FALSE;
}

static gboolean
get_int_field(epan_dissect_t *edt, int hfid, gint *out)
{
    if (hfid < 0) return FALSE;
    GPtrArray *arr = proto_get_finfo_ptr_array(edt->tree, hfid);
    if (!arr || arr->len == 0) return FALSE;
    field_info *fi = (field_info *)g_ptr_array_index(arr, 0);
    if (!fi || !fi->value || !fi->hfinfo) return FALSE;
    enum ftenum ft = fi->hfinfo->type;
    if (FT_IS_INT_COMPAT(ft)) {
        *out = (gint)fvalue_get_sinteger(fi->value);
        return TRUE;
    }
    return FALSE;
}

/*
 * Safe string extraction: uses fvalue_to_string_repr as a universal
 * fallback so it works for FT_STRING, FT_BYTES, FT_ETHER, etc.
 */
static const char *
get_field_as_str(epan_dissect_t *edt, int hfid, char *buf, size_t bufsz)
{
    if (hfid < 0) return NULL;
    GPtrArray *arr = proto_get_finfo_ptr_array(edt->tree, hfid);
    if (!arr || arr->len == 0) return NULL;
    field_info *fi = (field_info *)g_ptr_array_index(arr, 0);
    if (!fi || !fi->value || !fi->hfinfo) return NULL;

    enum ftenum ft = fi->hfinfo->type;

    if (FT_IS_STRING_COMPAT(ft)) {
        const char *s = fvalue_get_string(fi->value);
        if (s) {
            g_strlcpy(buf, s, bufsz);
            return buf;
        }
        return NULL;
    }

    char *repr = fvalue_to_string_repr(NULL, fi->value,
                                       FTREPR_DISPLAY, fi->hfinfo->display);
    if (repr) {
        g_strlcpy(buf, repr, bufsz);
        wmem_free(NULL, repr);
        return buf;
    }
    return NULL;
}

/* ----------------------------------------------------------------
 * Extract vendor from resolved MAC string.
 * The resolved string is often "VendorName_xx:xx:xx"; we want
 * the part before the underscore.
 * ---------------------------------------------------------------- */
static char *
extract_vendor(const char *resolved)
{
    if (!resolved || !*resolved) return NULL;
    const char *us = strchr(resolved, '_');
    if (us && us > resolved) {
        return g_strndup(resolved, (gsize)(us - resolved));
    }
    return g_strdup(resolved);
}

/* ----------------------------------------------------------------
 * Extract all WiFi fields from the proto tree for one packet
 * ---------------------------------------------------------------- */
static void
extract_wifi_fields(epan_dissect_t *edt, wifi_collection_result_t *r,
                    guint frame_len)
{
    guint fc_type = 99, fc_subtype = 99;
    guint retry = 0;
    gint  rssi = 0;
    gint  noise = 0;
    guint freq = 0;
    guint datarate = 0;
    guint mcs_idx = 0;
    guint fcs_status = 0;
    guint qos_tid = 0;
    guint reason_code = 0, status_code = 0;
    gboolean has_rssi = FALSE, has_noise = FALSE;
    gboolean has_freq = FALSE, has_rate = FALSE;
    gboolean has_mcs = FALSE, has_vht_mcs = FALSE;
    char bssid_buf[64] = {0};
    char sa_buf[64] = {0};
    char ta_buf[64] = {0};
    char ssid_buf[128] = {0};
    char sa_res_buf[128] = {0};
    char ta_res_buf[128] = {0};
    char bssid_res_buf[128] = {0};
    const char *bssid_str = NULL, *sa_str = NULL, *ta_str = NULL;
    const char *ssid_str = NULL;
    const char *sa_resolved = NULL, *ta_resolved = NULL, *bssid_resolved = NULL;

    /* ---- Frame type / subtype ---- */
    gboolean has_type = get_uint_field(edt, hf_wlan_fc_type, &fc_type);
    get_uint_field(edt, hf_wlan_fc_subtype, &fc_subtype);
    get_uint_field(edt, hf_wlan_fc_retry, &retry);

    if (has_type) {
        switch (fc_type) {
        case 0: r->frame_mgmt++;    break;
        case 1: r->frame_control++; break;
        case 2: r->frame_data++;    break;
        }

        /* Subtype distribution */
        char key[16];
        snprintf(key, sizeof(key), "%u-%u", fc_type, fc_subtype);
        incr_str_counter(r->frame_subtypes, key);

        /* Data frame retry tracking */
        if (fc_type == 2) {
            r->total_data_frames++;
            if (retry) r->retry_count++;
        }

        /* Association / deauth tracking (Management subtypes) */
        if (fc_type == 0) {
            switch (fc_subtype) {
            case 0:  r->assoc_req++;    break;
            case 1:  r->assoc_resp++;   break;
            case 2:  r->reassoc_req++;  break;
            case 3:  r->reassoc_resp++; break;
            case 10: r->disassoc++;     break;
            case 12: r->deauth++;       break;
            }
            if (fc_subtype == 10 || fc_subtype == 12) {
                if (get_uint_field(edt, hf_wlan_reason_code, &reason_code))
                    incr_uint_counter(r->reason_codes, reason_code);
            }
            if (fc_subtype == 1 || fc_subtype == 3) {
                if (get_uint_field(edt, hf_wlan_status_code, &status_code))
                    incr_uint_counter(r->status_codes, status_code);
            }
        }
    }

    /* ---- EAPOL ---- */
    {
        guint eapol_type = 0;
        if (get_uint_field(edt, hf_eapol, &eapol_type))
            r->eapol_frames++;
    }

    /* ---- FCS ---- */
    if (get_uint_field(edt, hf_wlan_fcs_status, &fcs_status)) {
        if (fcs_status == 0) r->fcs_good++;
        else                 r->fcs_bad++;
    }

    /* ---- QoS TID ---- */
    if (get_uint_field(edt, hf_wlan_qos_tid, &qos_tid))
        incr_uint_counter(r->qos_tids, qos_tid);

    /* ---- RSSI ---- */
    has_rssi = get_int_field(edt, hf_radiotap_signal, &rssi);
    has_noise = get_int_field(edt, hf_radiotap_noise, &noise);

    if (has_rssi) {
        gint bucket = (gint)(floor((double)rssi / 5.0) * 5);
        incr_int_counter(r->rssi_buckets, bucket);
    }

    /* ---- SNR ---- */
    if (has_rssi && has_noise) {
        gint snr = rssi - noise;
        gint bucket = (gint)(floor((double)snr / 5.0) * 5);
        incr_int_counter(r->snr_buckets, bucket);
    }

    /* ---- Channel frequency ---- */
    has_freq = get_uint_field(edt, hf_radiotap_freq, &freq);
    if (has_freq && freq > 0) {
        guint ch = wifi_freq_to_channel(freq);
        if (ch > 0)
            incr_uint_counter(r->channel_usage, ch);
    }

    /* ---- Data rate (legacy) ---- */
    has_rate = get_uint_field(edt, hf_radiotap_rate, &datarate);
    if (has_rate && datarate > 0)
        incr_uint_counter(r->datarate_usage, datarate);

    /* ---- HT MCS (802.11n) ---- */
    has_mcs = get_uint_field(edt, hf_radiotap_mcs_idx, &mcs_idx);
    if (has_mcs)
        incr_uint_counter(r->ht_mcs_usage, mcs_idx);

    /* ---- VHT MCS (802.11ac) ---- */
    {
        guint vht_mcs = 0;
        has_vht_mcs = get_uint_field(edt, hf_radiotap_vht_mcs, &vht_mcs);
        if (has_vht_mcs)
            incr_uint_counter(r->vht_mcs_usage, vht_mcs);
    }

    /* ---- Addresses ---- */
    bssid_str = get_field_as_str(edt, hf_wlan_bssid, bssid_buf, sizeof(bssid_buf));
    sa_str    = get_field_as_str(edt, hf_wlan_sa, sa_buf, sizeof(sa_buf));
    ta_str    = get_field_as_str(edt, hf_wlan_ta, ta_buf, sizeof(ta_buf));

    /* Resolved names for vendor extraction */
    sa_resolved    = get_field_as_str(edt, hf_wlan_sa_resolved, sa_res_buf, sizeof(sa_res_buf));
    ta_resolved    = get_field_as_str(edt, hf_wlan_ta_resolved, ta_res_buf, sizeof(ta_res_buf));
    bssid_resolved = get_field_as_str(edt, hf_wlan_bssid_resolved, bssid_res_buf, sizeof(bssid_res_buf));

    /* ---- SSID (from management frames) ---- */
    ssid_str = get_field_as_str(edt, hf_wlan_ssid, ssid_buf, sizeof(ssid_buf));
    if (!ssid_str)
        ssid_str = get_field_as_str(edt, hf_wlan_ssid_alt, ssid_buf, sizeof(ssid_buf));

    /* ---- Per-BSSID stats ---- */
    if (bssid_str && *bssid_str &&
        strcmp(bssid_str, "ff:ff:ff:ff:ff:ff") != 0) {
        wifi_bssid_stats_t *bs =
            (wifi_bssid_stats_t *)g_hash_table_lookup(r->bssid_table, bssid_str);
        if (!bs) {
            bs = g_new0(wifi_bssid_stats_t, 1);
            bs->bssid = g_strdup(bssid_str);
            bs->clients = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);
            if (bssid_resolved)
                bs->vendor = extract_vendor(bssid_resolved);
            g_hash_table_insert(r->bssid_table, bs->bssid, bs);
        }
        bs->frames++;
        bs->bytes += frame_len;

        if (ssid_str && *ssid_str && (!bs->ssid || !*bs->ssid)) {
            g_free(bs->ssid);
            bs->ssid = g_strdup(ssid_str);
        }

        /* Track clients per BSSID */
        const char *client_mac = sa_str;
        if (!client_mac) client_mac = ta_str;
        if (client_mac && strcmp(client_mac, bssid_str) != 0 &&
            strcmp(client_mac, "ff:ff:ff:ff:ff:ff") != 0) {
            if (!g_hash_table_contains(bs->clients, client_mac))
                g_hash_table_insert(bs->clients, g_strdup(client_mac), NULL);
        }
    }

    /* ---- Per-client stats ---- */
    const char *client_mac = sa_str ? sa_str : ta_str;
    const char *client_resolved = sa_str ? sa_resolved : ta_resolved;

    if (client_mac && *client_mac &&
        strcmp(client_mac, "ff:ff:ff:ff:ff:ff") != 0) {
        wifi_client_stats_t *cs =
            (wifi_client_stats_t *)g_hash_table_lookup(r->client_table, client_mac);
        if (!cs) {
            cs = g_new0(wifi_client_stats_t, 1);
            cs->mac = g_strdup(client_mac);
            cs->rssi_min = 0;
            cs->rssi_max = -200;
            if (client_resolved)
                cs->vendor = extract_vendor(client_resolved);
            g_hash_table_insert(r->client_table, cs->mac, cs);
        }
        cs->frames++;
        cs->bytes += frame_len;

        if (has_rssi) {
            cs->rssi_total += rssi;
            cs->rssi_count++;
            if (cs->rssi_count == 1 || rssi < cs->rssi_min)
                cs->rssi_min = rssi;
            if (rssi > cs->rssi_max)
                cs->rssi_max = rssi;
        }

        if (retry) cs->retries++;

        /* Airtime estimation: (frame_len_bytes * 8) / datarate_mbps → us */
        double rate_mbps = 0.0;
        if (has_rate && datarate > 0)
            rate_mbps = (double)datarate * 0.5;
        if (rate_mbps > 0 && frame_len > 0) {
            double airtime = ((double)frame_len * 8.0) / rate_mbps;
            cs->airtime_us += airtime;
            r->airtime_total_us += airtime;
        }
    }
}

/* ----------------------------------------------------------------
 * Frame tap (just counts packets/bytes/time)
 * ---------------------------------------------------------------- */

typedef struct {
    wifi_collection_result_t *result;
} wifi_tap_ctx_t;

static tap_packet_status
wifi_tap_packet(void *tapdata, packet_info *pinfo,
                epan_dissect_t *edt G_GNUC_UNUSED,
                const void *data G_GNUC_UNUSED,
                tap_flags_t flags G_GNUC_UNUSED)
{
    wifi_tap_ctx_t *ctx = (wifi_tap_ctx_t *)tapdata;
    wifi_collection_result_t *r = ctx->result;

    r->total_packets++;
    if (pinfo->fd) {
        r->total_bytes += pinfo->fd->pkt_len;
    }

    double pkt_time = nstime_to_sec(&pinfo->abs_ts);
    if (r->total_packets == 1 || pkt_time < r->first_time)
        r->first_time = pkt_time;
    if (pkt_time > r->last_time)
        r->last_time = pkt_time;

    return TAP_PACKET_DONT_REDRAW;
}

static void wifi_tap_reset(void *tapdata)
{
    (void)tapdata;
}

static void wifi_tap_draw(void *tapdata)
{
    wifi_tap_ctx_t *ctx = (wifi_tap_ctx_t *)tapdata;
    ctx->result->duration = ctx->result->last_time - ctx->result->first_time;
}

/* ----------------------------------------------------------------
 * Public API
 * ---------------------------------------------------------------- */

void wifi_collector_init(void)
{
    ws_log(WS_LOG_DOMAIN, LOG_LEVEL_DEBUG, "WiFi collector initialised");
}

void wifi_collector_cleanup(void)
{
    ws_log(WS_LOG_DOMAIN, LOG_LEVEL_DEBUG, "WiFi collector cleaned up");
}

wifi_collection_result_t *wifi_collector_run(capture_file *cf)
{
    wifi_collection_result_t *result;
    wifi_tap_ctx_t ctx;
    GString *err_str;

    result = alloc_wifi_result();
    ctx.result = result;

    resolve_wifi_field_ids();

    err_str = register_tap_listener(
        "frame", &ctx, NULL,
        TL_REQUIRES_NOTHING,
        wifi_tap_reset,
        wifi_tap_packet,
        wifi_tap_draw,
        NULL
    );

    if (err_str) {
        ws_log(WS_LOG_DOMAIN, LOG_LEVEL_WARNING,
               "Failed to register WiFi tap: %s", err_str->str);
        g_string_free(err_str, TRUE);
        return result;
    }

    if (cf->state == FILE_READ_DONE && cf->provider.frames && cf->count > 0) {
        epan_dissect_t *edt = epan_dissect_new(cf->epan, TRUE, FALSE);
        guint32 framenum;

        prime_wifi_fields(edt);

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
                extract_wifi_fields(edt, result, fdata->pkt_len);
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
                    extract_wifi_fields(edt, result, fdata->pkt_len);
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

    remove_tap_listener(&ctx);

    ws_log(WS_LOG_DOMAIN, LOG_LEVEL_INFO,
           "WiFi stats: %" G_GUINT64_FORMAT " packets, %" G_GUINT64_FORMAT " bytes, %.3f s, "
           "mgmt=%" G_GUINT64_FORMAT " ctrl=%" G_GUINT64_FORMAT " data=%" G_GUINT64_FORMAT ", "
           "BSSIDs=%u clients=%u channels=%u retries=%" G_GUINT64_FORMAT,
           result->total_packets,
           result->total_bytes,
           result->duration,
           result->frame_mgmt,
           result->frame_control,
           result->frame_data,
           g_hash_table_size(result->bssid_table),
           g_hash_table_size(result->client_table),
           g_hash_table_size(result->channel_usage),
           result->retry_count);

    return result;
}

/* ----------------------------------------------------------------
 * Frequency -> Channel conversion
 * ---------------------------------------------------------------- */

guint wifi_freq_to_channel(guint freq_mhz)
{
    /* 2.4 GHz band */
    if (freq_mhz >= 2412 && freq_mhz <= 2484) {
        if (freq_mhz == 2484) return 14;
        return (freq_mhz - 2407) / 5;
    }
    /* 5 GHz band */
    if (freq_mhz >= 5170 && freq_mhz <= 5835)
        return (freq_mhz - 5000) / 5;
    /* 6 GHz band (Wi-Fi 6E) */
    if (freq_mhz >= 5955 && freq_mhz <= 7115)
        return (freq_mhz - 5950) / 5;
    return 0;
}

/* ----------------------------------------------------------------
 * Quality ratings
 * ---------------------------------------------------------------- */

wifi_quality_t wifi_rssi_quality(gint rssi)
{
    if (rssi >= -50) return WIFI_QUALITY_EXCELLENT;
    if (rssi >= -60) return WIFI_QUALITY_GOOD;
    if (rssi >= -70) return WIFI_QUALITY_FAIR;
    return WIFI_QUALITY_WEAK;
}

wifi_quality_t wifi_snr_quality(gint snr)
{
    if (snr >= 40) return WIFI_QUALITY_EXCELLENT;
    if (snr >= 25) return WIFI_QUALITY_GOOD;
    if (snr >= 15) return WIFI_QUALITY_FAIR;
    return WIFI_QUALITY_WEAK;
}

/* ----------------------------------------------------------------
 * Frame type / subtype names (802.11)
 * ---------------------------------------------------------------- */

const char *wifi_frame_type_name(guint type, guint subtype)
{
    switch (type) {
    case 0: /* Management */
        switch (subtype) {
        case 0:  return "Association Request";
        case 1:  return "Association Response";
        case 2:  return "Reassociation Request";
        case 3:  return "Reassociation Response";
        case 4:  return "Probe Request";
        case 5:  return "Probe Response";
        case 8:  return "Beacon";
        case 9:  return "ATIM";
        case 10: return "Disassociation";
        case 11: return "Authentication";
        case 12: return "Deauthentication";
        case 13: return "Action";
        default: return "Management (other)";
        }
    case 1: /* Control */
        switch (subtype) {
        case 8:  return "Block Ack Request";
        case 9:  return "Block Ack";
        case 10: return "PS-Poll";
        case 11: return "RTS";
        case 12: return "CTS";
        case 13: return "ACK";
        case 14: return "CF-End";
        default: return "Control (other)";
        }
    case 2: /* Data */
        switch (subtype) {
        case 0:  return "Data";
        case 4:  return "Null";
        case 8:  return "QoS Data";
        case 12: return "QoS Null";
        default: return "Data (other)";
        }
    default:
        return "Unknown";
    }
}

/* ----------------------------------------------------------------
 * Deauth / Disassoc reason code names
 * ---------------------------------------------------------------- */

const char *wifi_reason_code_name(guint code)
{
    switch (code) {
    case 1:  return "Unspecified";
    case 2:  return "Auth no longer valid";
    case 3:  return "Leaving BSS";
    case 4:  return "Inactivity";
    case 5:  return "AP overloaded";
    case 6:  return "Class 2 from non-auth";
    case 7:  return "Class 3 from non-assoc";
    case 8:  return "Leaving BSS (disassoc)";
    case 9:  return "Not authenticated";
    case 10: return "Power capability unacceptable";
    case 11: return "Supported channels unacceptable";
    case 13: return "Invalid information element";
    case 14: return "MIC failure";
    case 15: return "4-way handshake timeout";
    case 16: return "Group key handshake timeout";
    case 17: return "IE in 4-way differs";
    case 18: return "Invalid group cipher";
    case 19: return "Invalid pairwise cipher";
    case 20: return "Invalid AKMP";
    case 23: return "IEEE 802.1X auth failed";
    case 24: return "Cipher suite rejected";
    case 34: return "TDLS teardown unreachable";
    case 35: return "TDLS teardown unspecified";
    case 39: return "Mechanism not supported";
    default: return "Other";
    }
}

/* ----------------------------------------------------------------
 * Sorting helpers
 * ---------------------------------------------------------------- */

static gint cmp_client_airtime(gconstpointer a, gconstpointer b)
{
    const wifi_client_stats_t *ca = *(const wifi_client_stats_t **)a;
    const wifi_client_stats_t *cb = *(const wifi_client_stats_t **)b;
    if (ca->airtime_us > cb->airtime_us) return -1;
    if (ca->airtime_us < cb->airtime_us) return  1;
    return 0;
}

GList *wifi_top_clients_by_airtime(wifi_collection_result_t *r, guint top_n)
{
    GPtrArray *arr = g_ptr_array_new();
    GHashTableIter iter;
    gpointer key, value;
    GList *out = NULL;
    guint i;

    g_hash_table_iter_init(&iter, r->client_table);
    while (g_hash_table_iter_next(&iter, &key, &value))
        g_ptr_array_add(arr, value);

    g_ptr_array_sort(arr, cmp_client_airtime);

    for (i = 0; i < MIN(top_n, arr->len); i++)
        out = g_list_append(out, arr->pdata[i]);

    g_ptr_array_free(arr, TRUE);
    return out;
}

static gint cmp_client_frames(gconstpointer a, gconstpointer b)
{
    const wifi_client_stats_t *ca = *(const wifi_client_stats_t **)a;
    const wifi_client_stats_t *cb = *(const wifi_client_stats_t **)b;
    if (ca->frames > cb->frames) return -1;
    if (ca->frames < cb->frames) return  1;
    return 0;
}

GList *wifi_top_macs_by_frames(wifi_collection_result_t *r, guint top_n)
{
    GPtrArray *arr = g_ptr_array_new();
    GHashTableIter iter;
    gpointer key, value;
    GList *out = NULL;
    guint i;

    g_hash_table_iter_init(&iter, r->client_table);
    while (g_hash_table_iter_next(&iter, &key, &value))
        g_ptr_array_add(arr, value);

    g_ptr_array_sort(arr, cmp_client_frames);

    for (i = 0; i < MIN(top_n, arr->len); i++)
        out = g_list_append(out, arr->pdata[i]);

    g_ptr_array_free(arr, TRUE);
    return out;
}
