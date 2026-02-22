#ifndef WIFI_COLLECTOR_H
#define WIFI_COLLECTOR_H

#include <glib.h>
#include <epan/epan.h>
#include <epan/packet.h>
#include <epan/tap.h>
#include "packet_collector.h"   /* paper_size_t */

typedef struct _capture_file capture_file;

#ifdef __cplusplus
extern "C" {
#endif

/* ----------------------------------------------------------------
 * RSSI / SNR quality thresholds (matching WiFi Reporter Lua)
 * ---------------------------------------------------------------- */

typedef enum {
    WIFI_QUALITY_EXCELLENT,   /* RSSI >= -50, SNR >= 40 */
    WIFI_QUALITY_GOOD,        /* RSSI >= -60, SNR >= 25 */
    WIFI_QUALITY_FAIR,        /* RSSI >= -70, SNR >= 15 */
    WIFI_QUALITY_WEAK         /* below */
} wifi_quality_t;

/* ----------------------------------------------------------------
 * Per-BSSID statistics
 * ---------------------------------------------------------------- */
typedef struct {
    char    *bssid;            /* BSSID string (e.g. "aa:bb:cc:dd:ee:ff") */
    char    *ssid;             /* SSID (may be empty for hidden networks) */
    char    *vendor;           /* OUI vendor name or NULL */
    guint64  frames;
    guint64  bytes;
    GHashTable *clients;       /* set of client MACs (char* → NULL) */
} wifi_bssid_stats_t;

/* ----------------------------------------------------------------
 * Per-client statistics
 * ---------------------------------------------------------------- */
typedef struct {
    char    *mac;
    char    *vendor;           /* OUI vendor name or NULL */
    guint64  frames;
    guint64  bytes;
    gint64   rssi_total;       /* sum of RSSI samples (for avg) */
    guint64  rssi_count;
    gint     rssi_min;
    gint     rssi_max;
    guint64  retries;
    double   airtime_us;       /* estimated airtime in microseconds */
} wifi_client_stats_t;

/* ----------------------------------------------------------------
 * WiFi collection result
 * ---------------------------------------------------------------- */
typedef struct {
    /* Basic capture info */
    guint64  total_packets;
    guint64  total_bytes;
    double   first_time;       /* epoch seconds */
    double   last_time;
    double   duration;

    /* RSSI distribution: bucket (floor(rssi/5)*5) → count
     * e.g. key -70 means range [-70..-66] dBm */
    GHashTable *rssi_buckets;  /* gint → guint64* */

    /* SNR distribution: bucket (floor(snr/5)*5) → count */
    GHashTable *snr_buckets;   /* gint → guint64* */

    /* Channel usage: channel number → frame count */
    GHashTable *channel_usage; /* guint → guint64* */

    /* Data rates: rate_mbps*10 (integer) → count */
    GHashTable *datarate_usage;

    /* MCS usage (802.11n HT) : mcs_index → count */
    GHashTable *ht_mcs_usage;  /* guint → guint64* */

    /* MCS usage (802.11ac VHT) : mcs_index → count */
    GHashTable *vht_mcs_usage; /* guint → guint64* */

    /* Frame type counters */
    guint64  frame_mgmt;
    guint64  frame_control;
    guint64  frame_data;

    /* Frame subtype distribution: "type-subtype" string → count */
    GHashTable *frame_subtypes; /* char* → guint64* */

    /* Retry stats */
    guint64  total_data_frames;
    guint64  retry_count;

    /* FCS stats */
    guint64  fcs_good;
    guint64  fcs_bad;

    /* Association / deauth counters */
    guint64  assoc_req;
    guint64  assoc_resp;
    guint64  reassoc_req;
    guint64  reassoc_resp;
    guint64  deauth;
    guint64  disassoc;
    guint64  eapol_frames;

    /* Deauth/disassoc reason codes: code(guint) → count */
    GHashTable *reason_codes;  /* guint → guint64* */

    /* Status codes: code(guint) → count */
    GHashTable *status_codes;  /* guint → guint64* */

    /* Per-BSSID: bssid string → wifi_bssid_stats_t* */
    GHashTable *bssid_table;

    /* Per-client: mac string → wifi_client_stats_t* */
    GHashTable *client_table;

    /* Airtime totals */
    double   airtime_total_us;

    /* QoS TID distribution: tid(guint) → count */
    GHashTable *qos_tids;      /* guint → guint64* */

} wifi_collection_result_t;

/* ----------------------------------------------------------------
 * Public API
 * ---------------------------------------------------------------- */

void wifi_collector_init(void);
void wifi_collector_cleanup(void);

/**
 * Run WiFi-specific tap listeners and return collected statistics.
 * Caller must free with wifi_collector_free_result().
 */
wifi_collection_result_t *wifi_collector_run(capture_file *cf);

void wifi_collector_free_result(wifi_collection_result_t *r);

/* ----------------------------------------------------------------
 * Helpers
 * ---------------------------------------------------------------- */

/** Convert frequency (MHz) to WiFi channel number */
guint    wifi_freq_to_channel(guint freq_mhz);

/** Get quality rating for an RSSI value */
wifi_quality_t wifi_rssi_quality(gint rssi);

/** Get quality rating for an SNR value */
wifi_quality_t wifi_snr_quality(gint snr);

/** Get human-readable 802.11 frame type/subtype name */
const char *wifi_frame_type_name(guint type, guint subtype);

/** Get human-readable deauth/disassoc reason string */
const char *wifi_reason_code_name(guint code);

/** Sorting: top N clients by airtime. Returns GList of wifi_client_stats_t* */
GList *wifi_top_clients_by_airtime(wifi_collection_result_t *r, guint top_n);

/** Sorting: top N MACs by frame count */
GList *wifi_top_macs_by_frames(wifi_collection_result_t *r, guint top_n);

#ifdef __cplusplus
}
#endif

#endif /* WIFI_COLLECTOR_H */
