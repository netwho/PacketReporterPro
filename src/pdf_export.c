#include <config.h>
#include <wireshark.h>

#include "pdf_export.h"
#include "report_renderer.h"
#include "packet_collector.h"
#include "config_reader.h"
#include "reporter_plugin.h"

#define BRAND_NAME "PacketReporter Pro"

#include <cairo.h>
#include <cairo-pdf.h>
#include <wsutil/wslog.h>

#include <stdio.h>
#include <string.h>
#include <math.h>
#include <time.h>
#include <sys/stat.h>
#include <errno.h>

#ifdef _WIN32
#include <windows.h>
#include <shlobj.h>
#include <shellapi.h>
#else
#include <stdlib.h>
#include <unistd.h>
#endif

#ifndef MIN
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#endif

/* ----------------------------------------------------------------
 * Reports directory
 * ---------------------------------------------------------------- */

char *pdf_export_get_reports_dir(void)
{
    char *dir = NULL;

#ifdef _WIN32
    const char *profile = g_getenv("USERPROFILE");
    if (profile)
        dir = g_build_filename(profile, "Documents",
                               "PacketReporter Reports", NULL);
#else
    const char *home = g_getenv("HOME");
    if (home)
        dir = g_build_filename(home, "Documents",
                               "PacketReporter Reports", NULL);
#endif

    if (!dir)
        dir = g_build_filename(g_get_tmp_dir(),
                               "PacketReporter Reports", NULL);

    g_mkdir_with_parents(dir, 0755);
    return dir;
}

static char *make_output_path(const char *requested, const char *suffix)
{
    if (requested)
        return g_strdup(requested);

    char *dir = pdf_export_get_reports_dir();
    char ts[64];
    time_t now = time(NULL);
    struct tm *tm_now = localtime(&now);
    if (!tm_now) {
        g_snprintf(ts, sizeof(ts), "Unknown");
    } else {
        strftime(ts, sizeof(ts), "%Y%m%d_%H%M%S", tm_now);
    }

    char *path = g_strdup_printf("%s%spacketreporter_pro_%s_%s.pdf",
                                 dir, G_DIR_SEPARATOR_S, suffix, ts);
    g_free(dir);
    return path;
}

/* ----------------------------------------------------------------
 * Open file with default app
 * ---------------------------------------------------------------- */

void pdf_export_open_file(const char *path)
{
    char *cmd;

#ifdef _WIN32
    ShellExecuteA(NULL, "open", path, NULL, NULL, SW_SHOWNORMAL);
#elif defined(__APPLE__)
    cmd = g_strdup_printf("open \"%s\"", path);
    if (system(cmd) != 0)
        ws_log(WS_LOG_DOMAIN, LOG_LEVEL_WARNING,
               "Failed to open: %s", path);
    g_free(cmd);
#else
    cmd = g_strdup_printf("xdg-open \"%s\" &", path);
    if (system(cmd) != 0)
        ws_log(WS_LOG_DOMAIN, LOG_LEVEL_WARNING,
               "Failed to open: %s", path);
    g_free(cmd);
#endif
}

/* ----------------------------------------------------------------
 * Summary report — single page
 *
 * Layout (roughly matches the Lua plugin):
 *   - Header: title + basic stats
 *   - Bar chart: Top 10 IPs by packet count
 *   - Pie chart: Protocol distribution
 *   - Bar chart: Top 5 TCP ports
 * ---------------------------------------------------------------- */

char *pdf_export_summary(const collection_result_t *result,
                         const reporter_config_t *cfg,
                         const char *out_path)
{
    const paper_size_t *paper = &PAPER_A4_SIZE;
    char *path;
    cairo_surface_t *surface;
    cairo_t *cr;
    double y;
    char buf[128];
    GList *top_ips, *top_protos, *top_ports;
    GList *l;
    int i, count;

    path = make_output_path(out_path, "summary");

    surface = cairo_pdf_surface_create(path,
                                       paper->width_pt,
                                       paper->height_pt);
    if (cairo_surface_status(surface) != CAIRO_STATUS_SUCCESS) {
        ws_log(WS_LOG_DOMAIN, LOG_LEVEL_WARNING,
               "Could not create PDF surface: %s", path);
        g_free(path);
        return NULL;
    }

    cr = cairo_create(surface);

    /* White background */
    cairo_set_source_rgb(cr, 1, 1, 1);
    cairo_paint(cr);

    y = 50;

    /* Report title */
    renderer_set_font(cr, "sans-serif",
                      CAIRO_FONT_SLANT_NORMAL,
                      CAIRO_FONT_WEIGHT_BOLD, 20.0);
    cairo_set_source_rgb(cr, CLR_PRIMARY_R, CLR_PRIMARY_G, CLR_PRIMARY_B);
    cairo_move_to(cr, 50, y);
    cairo_show_text(cr, BRAND_NAME " " PLUGIN_VERSION_STR " \xe2\x80\x94 Summary Report");
    y += 30;

    /* Basic statistics */
    renderer_set_font(cr, "sans-serif",
                      CAIRO_FONT_SLANT_NORMAL,
                      CAIRO_FONT_WEIGHT_NORMAL, 10.0);
    cairo_set_source_rgb(cr, 0.2, 0.2, 0.2);

    snprintf(buf, sizeof(buf), "Total Packets: %" G_GUINT64_FORMAT,
             result->total_packets);
    cairo_move_to(cr, 50, y); cairo_show_text(cr, buf); y += 16;

    format_bytes_str(result->total_bytes, buf, sizeof(buf));
    {
        char line[160];
        snprintf(line, sizeof(line), "Total Bytes: %s", buf);
        cairo_move_to(cr, 50, y); cairo_show_text(cr, line); y += 16;
    }

    format_duration_str(result->duration, buf, sizeof(buf));
    {
        char line[160];
        snprintf(line, sizeof(line), "Duration: %s", buf);
        cairo_move_to(cr, 50, y); cairo_show_text(cr, line); y += 16;
    }

    snprintf(buf, sizeof(buf), "Unique IPs: %u",
             g_hash_table_size(result->ip_table));
    cairo_move_to(cr, 50, y); cairo_show_text(cr, buf); y += 16;

    snprintf(buf, sizeof(buf), "Protocols: %u",
             g_hash_table_size(result->protocol_table));
    cairo_move_to(cr, 50, y); cairo_show_text(cr, buf); y += 30;

    /* --- Bar chart: Top 10 IPs --- */
    top_ips = collector_top_ips_by_packets((collection_result_t *)result, 10);
    count   = (int)g_list_length(top_ips);

    if (count > 0) {
        bar_item_t *items = g_new0(bar_item_t, count);
        for (l = top_ips, i = 0; l; l = l->next, i++) {
            ip_stats_t *ip = (ip_stats_t *)l->data;
            items[i].label = ip->address;
            items[i].value = (double)(ip->packets_src + ip->packets_dst);
        }
        renderer_draw_bar_chart(cr, "Top 10 IP Addresses (by packets)",
                                items, count, 50, y, 500, 200);
        g_free(items);
        y += 210;
    }
    g_list_free(top_ips);

    /* --- Pie chart: Protocols --- */
    top_protos = collector_top_protocols((collection_result_t *)result, 10);
    count      = (int)g_list_length(top_protos);

    if (count > 0) {
        pie_item_t *items = g_new0(pie_item_t, count);
        for (l = top_protos, i = 0; l; l = l->next, i++) {
            protocol_entry_t *pe = (protocol_entry_t *)l->data;
            items[i].label = pe->name;
            items[i].value = (double)pe->count;
        }
        renderer_draw_pie_chart(cr, "Protocol Distribution",
                                items, count, 50, y, 500, 210);
        g_free(items);
        y += 220;
    }
    g_list_free(top_protos);

    /* --- Bar chart: Top 5 TCP ports --- */
    top_ports = collector_top_tcp_ports((collection_result_t *)result, 5);
    count     = (int)g_list_length(top_ports);

    if (count > 0) {
        bar_item_t *items = g_new0(bar_item_t, count);
        char port_labels[5][16];
        for (l = top_ports, i = 0; l && i < 5; l = l->next, i++) {
            port_entry_t *pe = (port_entry_t *)l->data;
            snprintf(port_labels[i], sizeof(port_labels[i]),
                     "%u", (unsigned)pe->port);
            items[i].label = port_labels[i];
            items[i].value = (double)pe->count;
        }
        renderer_draw_bar_chart(cr, "Top 5 TCP Destination Ports",
                                items, count, 50, y, 500, 180);
        g_free(items);
    }
    g_list_free(top_ports);

    /* Page footer */
    renderer_draw_page_footer(cr, paper, 1);

    /* Finalise */
    cairo_show_page(cr);
    cairo_destroy(cr);
    cairo_surface_destroy(surface);

    ws_log(WS_LOG_DOMAIN, LOG_LEVEL_INFO,
           "Summary PDF written to %s", path);
    return path;
}

/* ----------------------------------------------------------------
 * Detailed report — multi-page with cover
 *
 * Section order:
 *   1. PCAP File Summary
 *   2. Top 10 IP Addresses
 *   3. Protocol Distribution
 *   4. IP Communication Matrix (chord diagram + table)
 *   5. Port Analysis
 *   6. Protocol Hierarchy
 *   7. DNS Analysis
 *   8. TLS/SSL Analysis
 *      8.1 TLS Version Distribution
 *      8.2 Cipher Suites: Offered vs Selected
 *      8.3 Top Server Names (SNI)
 *      8.4 Certificate Health Summary
 *      8.5 Certificate Details
 *   9. HTTP Analysis
 *  10. MAC Layer Analysis
 *  11. IP Layer Analysis
 *  12. TCP Analysis
 * ---------------------------------------------------------------- */

/* Helper: start a new white page with section header */
#define NEW_SECTION_PAGE(section_title) do { \
    cairo_set_source_rgb(cr, 1, 1, 1); cairo_paint(cr); \
    y = margin; \
    renderer_draw_section_header(cr, (section_title), margin, y, content_w); \
    y += 50; \
} while(0)

/* Place a named PDF destination for TOC linking */
#define TAG_DEST(dest_name) do { \
    char _attr[128]; \
    snprintf(_attr, sizeof(_attr), "name='%s'", (dest_name)); \
    cairo_tag_begin(cr, CAIRO_TAG_DEST, _attr); \
    cairo_tag_end(cr, CAIRO_TAG_DEST); \
} while(0)

#define FINISH_PAGE() do { \
    renderer_draw_page_footer(cr, paper, page_num); \
    cairo_show_page(cr); page_num++; \
} while(0)

char *pdf_export_detailed(const collection_result_t *result,
                          const reporter_config_t *cfg,
                          const paper_size_t *paper,
                          const char *out_path)
{
    char *path;
    cairo_surface_t *surface;
    cairo_t *cr;
    double y;
    double margin     = 50.0;
    double content_w  = paper->width_pt - 2 * margin;
    int    page_num   = 1;
    char   buf[128];

    const char *toc_titles[] = {
        "1. PCAP File Summary",
        "2. Top 10 IP Addresses",
        "3. Protocol Distribution",
        "4. IP Communication Matrix",
        "5. Port Analysis",
        "6. Protocol Hierarchy",
        "7. DNS Analysis",
        "8. TLS/SSL Analysis",
        "9. HTTP Analysis",
        "10. MAC Layer Analysis",
        "11. IP Layer Analysis",
        "12. TCP Analysis",
    };
    int toc_pages[] = { 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13 };
    int toc_count   = 12;

    path = make_output_path(out_path, paper->id == PAPER_A4 ? "detailed_A4" : "detailed_Legal");

    surface = cairo_pdf_surface_create(path,
                                       paper->width_pt,
                                       paper->height_pt);
    if (cairo_surface_status(surface) != CAIRO_STATUS_SUCCESS) {
        ws_log(WS_LOG_DOMAIN, LOG_LEVEL_WARNING,
               "Could not create PDF surface: %s", path);
        g_free(path);
        return NULL;
    }

    cr = cairo_create(surface);

    /* ==== Page 1: Cover ==== */
    renderer_draw_cover_page(cr, paper, cfg,
                             toc_titles, toc_pages, toc_count);
    cairo_show_page(cr);
    page_num++;

    /* ==== Page 2: 1. PCAP File Summary ==== */
    NEW_SECTION_PAGE("1. PCAP File Summary");
    TAG_DEST("section1");
    {
        /* Get detailed file metadata */
        file_summary_t fs = {0};
        if (result->capture_filename)
            fs = packet_collector_file_summary(result->capture_filename);

        /* Helper macro: draw a label/value pair */
        #define KV_LINE(label, value) do { \
            renderer_set_font(cr, "sans-serif", CAIRO_FONT_SLANT_NORMAL, \
                              CAIRO_FONT_WEIGHT_BOLD, 9.0); \
            cairo_set_source_rgb(cr, 0.3, 0.3, 0.3); \
            cairo_move_to(cr, margin, y); \
            cairo_show_text(cr, (label)); \
            renderer_set_font(cr, "sans-serif", CAIRO_FONT_SLANT_NORMAL, \
                              CAIRO_FONT_WEIGHT_NORMAL, 9.0); \
            cairo_set_source_rgb(cr, 0.15, 0.15, 0.15); \
            cairo_move_to(cr, margin + 150, y); \
            cairo_show_text(cr, (value)); \
            y += 15; \
        } while (0)

        #define SECTION_HEADING(text) do { \
            y += 6; \
            renderer_set_font(cr, "sans-serif", CAIRO_FONT_SLANT_NORMAL, \
                              CAIRO_FONT_WEIGHT_BOLD, 11.0); \
            cairo_set_source_rgb(cr, 0.17, 0.48, 0.71); \
            cairo_move_to(cr, margin, y); \
            cairo_show_text(cr, (text)); \
            y += 4; \
            cairo_set_source_rgb(cr, 0.8, 0.8, 0.8); \
            cairo_set_line_width(cr, 0.5); \
            cairo_move_to(cr, margin, y); \
            cairo_line_to(cr, margin + content_w, y); \
            cairo_stroke(cr); \
            y += 10; \
        } while (0)

        char vbuf[256];

        /* ---- File ---- */
        SECTION_HEADING("File");

        if (fs.filename) {
            KV_LINE("Name:", fs.filename);
        } else if (result->capture_filename) {
            KV_LINE("Name:", result->capture_filename);
        }

        if (fs.file_length > 0) {
            format_bytes_str(fs.file_length, buf, sizeof(buf));
            snprintf(vbuf, sizeof(vbuf), "%s (%" G_GUINT64_FORMAT " bytes)", buf, fs.file_length);
            KV_LINE("Length:", vbuf);
        }

        if (fs.sha256[0]) {
            KV_LINE("Hash (SHA256):", fs.sha256);
        }

        if (fs.file_format) {
            KV_LINE("Format:", fs.file_format);
        }

        if (fs.encapsulation) {
            KV_LINE("Encapsulation:", fs.encapsulation);
        }

        if (fs.snaplen > 0) {
            snprintf(vbuf, sizeof(vbuf), "%u bytes", fs.snaplen);
            KV_LINE("Snapshot length:", vbuf);
        }

        /* ---- Time ---- */
        SECTION_HEADING("Time");

        if (fs.first_packet_time > 0) {
            time_t t = (time_t)fs.first_packet_time;
            struct tm *tm = localtime(&t);
            if (!tm) {
                g_snprintf(vbuf, sizeof(vbuf), "Unknown");
            } else {
                strftime(vbuf, sizeof(vbuf), "%Y-%m-%d %H:%M:%S", tm);
            }
            KV_LINE("First packet:", vbuf);
        } else if (result->first_time > 0) {
            time_t t = (time_t)result->first_time;
            struct tm *tm = localtime(&t);
            if (!tm) {
                g_snprintf(vbuf, sizeof(vbuf), "Unknown");
            } else {
                strftime(vbuf, sizeof(vbuf), "%Y-%m-%d %H:%M:%S", tm);
            }
            KV_LINE("First packet:", vbuf);
        }

        if (fs.last_packet_time > 0) {
            time_t t = (time_t)fs.last_packet_time;
            struct tm *tm = localtime(&t);
            if (!tm) {
                g_snprintf(vbuf, sizeof(vbuf), "Unknown");
            } else {
                strftime(vbuf, sizeof(vbuf), "%Y-%m-%d %H:%M:%S", tm);
            }
            KV_LINE("Last packet:", vbuf);
        } else if (result->last_time > 0) {
            time_t t = (time_t)result->last_time;
            struct tm *tm = localtime(&t);
            if (!tm) {
                g_snprintf(vbuf, sizeof(vbuf), "Unknown");
            } else {
                strftime(vbuf, sizeof(vbuf), "%Y-%m-%d %H:%M:%S", tm);
            }
            KV_LINE("Last packet:", vbuf);
        }

        {
            double dur = result->duration;
            int days  = (int)(dur / 86400.0);
            int hours = (int)(fmod(dur, 86400.0) / 3600.0);
            int mins  = (int)(fmod(dur, 3600.0)  / 60.0);
            double secs = fmod(dur, 60.0);
            if (days > 0)
                snprintf(vbuf, sizeof(vbuf), "%d days %02d:%02d:%05.2f", days, hours, mins, secs);
            else
                snprintf(vbuf, sizeof(vbuf), "%02d:%02d:%05.2f", hours, mins, secs);
            KV_LINE("Elapsed:", vbuf);
        }

        /* ---- Statistics ---- */
        SECTION_HEADING("Statistics");

        snprintf(vbuf, sizeof(vbuf), "%" G_GUINT64_FORMAT, result->total_packets);
        KV_LINE("Packets:", vbuf);

        format_bytes_str(result->total_bytes, buf, sizeof(buf));
        snprintf(vbuf, sizeof(vbuf), "%s (%" G_GUINT64_FORMAT " bytes)", buf, result->total_bytes);
        KV_LINE("Bytes:", vbuf);

        if (result->total_packets > 0) {
            snprintf(vbuf, sizeof(vbuf), "%.0f B",
                     (double)result->total_bytes / result->total_packets);
            KV_LINE("Avg packet size:", vbuf);
        }

        if (result->duration > 0) {
            snprintf(vbuf, sizeof(vbuf), "%.1f",
                     (double)result->total_packets / result->duration);
            KV_LINE("Avg packets/s:", vbuf);

            format_bytes_str((guint64)((double)result->total_bytes / result->duration),
                             buf, sizeof(buf));
            snprintf(vbuf, sizeof(vbuf), "%s/s", buf);
            KV_LINE("Avg throughput:", vbuf);

            snprintf(vbuf, sizeof(vbuf), "%.0f bits/s",
                     (double)result->total_bytes * 8.0 / result->duration);
            KV_LINE("Avg bits/s:", vbuf);
        }

        /* ---- Capture Overview ---- */
        SECTION_HEADING("Capture Overview");

        snprintf(vbuf, sizeof(vbuf), "%u", g_hash_table_size(result->ip_table));
        KV_LINE("Unique IPs:", vbuf);

        snprintf(vbuf, sizeof(vbuf), "%u", g_hash_table_size(result->protocol_table));
        KV_LINE("Protocols:", vbuf);

        snprintf(vbuf, sizeof(vbuf), "%u TCP  /  %u UDP",
                 g_hash_table_size(result->tcp_port_table),
                 g_hash_table_size(result->udp_port_table));
        KV_LINE("Ports seen:", vbuf);

        snprintf(vbuf, sizeof(vbuf), "%" G_GUINT64_FORMAT " queries  /  %u hosts",
                 result->dns_total_queries,
                 g_hash_table_size(result->http_host_table));
        KV_LINE("DNS / HTTP:", vbuf);

        if (result->tls_handshakes > 0) {
            snprintf(vbuf, sizeof(vbuf), "%" G_GUINT64_FORMAT " handshakes  /  %u SNIs",
                     result->tls_handshakes,
                     g_hash_table_size(result->tls_sni_table));
            KV_LINE("TLS:", vbuf);
        }

        snprintf(vbuf, sizeof(vbuf), "%u pairs",
                 g_hash_table_size(result->comm_pair_table));
        KV_LINE("Comm pairs:", vbuf);

        #undef KV_LINE
        #undef SECTION_HEADING

        packet_collector_free_file_summary(&fs);
    }
    FINISH_PAGE();

    /* ==== Page 3: 2. Top 10 IP Addresses ==== */
    NEW_SECTION_PAGE("2. Top 10 IP Addresses");
    TAG_DEST("section2");
    {
        GList *top_ips = collector_top_ips_by_packets(
                             (collection_result_t *)result, 10);
        int count = (int)g_list_length(top_ips);
        if (count > 0) {
            bar_item_t *items = g_new0(bar_item_t, count);
            GList *l; int i;
            for (l = top_ips, i = 0; l; l = l->next, i++) {
                ip_stats_t *ip = (ip_stats_t *)l->data;
                items[i].label = ip->address;
                items[i].value = (double)(ip->packets_src + ip->packets_dst);
            }
            renderer_draw_bar_chart(cr, "Top 10 IP Addresses (by packets)",
                                    items, count,
                                    margin, y, content_w, 280);
            g_free(items);
            y += 300;

            /* Also show a table */
            const char *hdrs[] = {"#", "IP Address", "Packets (Src)", "Packets (Dst)", "Total"};
            char ***rows = (char ***)g_new0(gpointer, count);
            for (l = top_ips, i = 0; l; l = l->next, i++) {
                ip_stats_t *ip = (ip_stats_t *)l->data;
                rows[i] = (char **)g_new0(gpointer, 5);
                rows[i][0] = g_strdup_printf("%d", i + 1);
                rows[i][1] = g_strdup(ip->address);
                rows[i][2] = g_strdup_printf("%" G_GUINT64_FORMAT, ip->packets_src);
                rows[i][3] = g_strdup_printf("%" G_GUINT64_FORMAT, ip->packets_dst);
                rows[i][4] = g_strdup_printf("%" G_GUINT64_FORMAT, (ip->packets_src + ip->packets_dst));
            }
            table_def_t tbl = {hdrs, 5, (const char ***)rows, count};
            renderer_draw_table(cr, NULL, &tbl, margin, y, content_w);
            for (i = 0; i < count; i++) {
                for (int c = 0; c < 5; c++) g_free(rows[i][c]);
                g_free(rows[i]);
            }
            g_free(rows);
        }
        g_list_free(top_ips);
    }
    FINISH_PAGE();

    /* ==== Page 4: 3. Protocol Distribution ==== */
    NEW_SECTION_PAGE("3. Protocol Distribution");
    TAG_DEST("section3");
    {
        GList *top_protos = collector_top_protocols(
                                (collection_result_t *)result, 10);
        int count = (int)g_list_length(top_protos);
        if (count > 0) {
            pie_item_t *items = g_new0(pie_item_t, count);
            GList *l; int i;
            for (l = top_protos, i = 0; l; l = l->next, i++) {
                protocol_entry_t *pe = (protocol_entry_t *)l->data;
                items[i].label = pe->name;
                items[i].value = (double)pe->count;
            }
            renderer_draw_pie_chart(cr, "Top Protocols and Applications",
                                    items, count,
                                    margin, y, content_w, 280);
            g_free(items);
            y += 300;

            /* Protocol table */
            const char *hdrs[] = {"#", "Protocol", "Packets", "%"};
            char ***rows = (char ***)g_new0(gpointer, count);
            for (l = top_protos, i = 0; l; l = l->next, i++) {
                protocol_entry_t *pe = (protocol_entry_t *)l->data;
                rows[i] = (char **)g_new0(gpointer, 4);
                rows[i][0] = g_strdup_printf("%d", i + 1);
                rows[i][1] = g_strdup(pe->name);
                rows[i][2] = g_strdup_printf("%" G_GUINT64_FORMAT, pe->count);
                rows[i][3] = g_strdup_printf("%.1f%%",
                    result->total_packets > 0
                        ? (double)pe->count / result->total_packets * 100.0 : 0.0);
            }
            table_def_t tbl = {hdrs, 4, (const char ***)rows, count};
            renderer_draw_table(cr, NULL, &tbl, margin, y, content_w);
            for (i = 0; i < count; i++) {
                for (int c = 0; c < 4; c++) g_free(rows[i][c]);
                g_free(rows[i]);
            }
            g_free(rows);
        }
        g_list_free(top_protos);
    }
    FINISH_PAGE();

    /* ==== Page 5: 4. IP Communication Matrix ==== */
    NEW_SECTION_PAGE("4. IP Communication Matrix");
    TAG_DEST("section4");
    {
        /* Fetch enough directional pairs so we get ~10 unique undirected
         * connections (A->B and B->A merge into one chord line). */
        GList *top_pairs = collector_top_comm_pairs(
                               (collection_result_t *)result, 30);
        int pair_count = (int)g_list_length(top_pairs);

        /* Deduplicate into unique undirected connections, keep top 10 */
        GPtrArray *unique_ips = g_ptr_array_new();
        int unique_connections = 0;
        GList *used_pairs = NULL;
        {
            GList *l;
            for (l = top_pairs; l && unique_connections < 10; l = l->next) {
                comm_pair_t *cp = (comm_pair_t *)l->data;

                /* Check if the reverse (dst->src) was already counted */
                gboolean already = FALSE;
                GList *u;
                for (u = used_pairs; u; u = u->next) {
                    comm_pair_t *prev = (comm_pair_t *)u->data;
                    if (g_strcmp0(prev->src, cp->dst) == 0 &&
                        g_strcmp0(prev->dst, cp->src) == 0) {
                        already = TRUE;
                        break;
                    }
                }
                if (already) continue;

                used_pairs = g_list_prepend(used_pairs, cp);
                unique_connections++;

                /* Add unique IPs as nodes */
                gboolean found_s = FALSE, found_d = FALSE;
                for (guint k = 0; k < unique_ips->len; k++) {
                    if (g_strcmp0(cp->src, (char *)unique_ips->pdata[k]) == 0) found_s = TRUE;
                    if (g_strcmp0(cp->dst, (char *)unique_ips->pdata[k]) == 0) found_d = TRUE;
                }
                if (!found_s) g_ptr_array_add(unique_ips, cp->src);
                if (!found_d) g_ptr_array_add(unique_ips, cp->dst);
            }
        }
        int num_nodes = (int)unique_ips->len;

        if (num_nodes >= 2 && pair_count > 0 && result->comm_pair_table) {
            const char **labels = (const char **)g_new0(gpointer, num_nodes);
            int i;
            for (i = 0; i < num_nodes; i++)
                labels[i] = (const char *)unique_ips->pdata[i];

            /* Build NxN matrix — include both directions of each pair
             * so chord widths reflect total bidirectional traffic */
            guint64 *mx = g_new0(guint64, num_nodes * num_nodes);
            {
                GHashTableIter hiter;
                gpointer hkey, hval;
                g_hash_table_iter_init(&hiter, result->comm_pair_table);
                while (g_hash_table_iter_next(&hiter, &hkey, &hval)) {
                    comm_pair_t *cp = (comm_pair_t *)hval;
                    int si = -1, di = -1;
                    for (i = 0; i < num_nodes; i++) {
                        if (si < 0 && g_strcmp0(cp->src, labels[i]) == 0) si = i;
                        if (di < 0 && g_strcmp0(cp->dst, labels[i]) == 0) di = i;
                    }
                    if (si >= 0 && di >= 0 && si != di)
                        mx[si * num_nodes + di] += cp->packets;
                }
            }

            renderer_draw_chord_diagram(cr,
                "IP Communications (Top 10 Pairs)",
                labels, num_nodes, mx,
                margin, y, content_w,
                paper->height_pt - margin - y - 60);

            g_free(mx);
            g_free(labels);

            /* Table on next page */
            FINISH_PAGE();
            NEW_SECTION_PAGE("4. IP Communication Matrix (continued)");

            {
                GList *all_pairs = collector_top_comm_pairs(
                                       (collection_result_t *)result, 20);
                int pcount = (int)g_list_length(all_pairs);
                if (pcount > 0) {
                    const char *hdrs[] = {"#", "Source", "Destination", "Packets", "Bytes"};
                    char ***rows = (char ***)g_new0(gpointer, pcount);
                    GList *l;
                    for (l = all_pairs, i = 0; l; l = l->next, i++) {
                        comm_pair_t *cp = (comm_pair_t *)l->data;
                        rows[i] = (char **)g_new0(gpointer, 5);
                        rows[i][0] = g_strdup_printf("%d", i + 1);
                        rows[i][1] = g_strdup(cp->src);
                        rows[i][2] = g_strdup(cp->dst);
                        rows[i][3] = g_strdup_printf("%" G_GUINT64_FORMAT, cp->packets);
                        char bb[64]; format_bytes_str(cp->bytes, bb, sizeof(bb));
                        rows[i][4] = g_strdup(bb);
                    }
                    table_def_t tbl = {hdrs, 5, (const char ***)rows, pcount};
                    renderer_draw_table(cr, "Top 20 Communication Pairs", &tbl,
                                        margin, y, content_w);
                    for (i = 0; i < pcount; i++) {
                        for (int c = 0; c < 5; c++) g_free(rows[i][c]);
                        g_free(rows[i]);
                    }
                    g_free(rows);
                }
                g_list_free(all_pairs);
            }
        } else {
            renderer_set_font(cr, "sans-serif", CAIRO_FONT_SLANT_ITALIC,
                              CAIRO_FONT_WEIGHT_NORMAL, 10.0);
            cairo_set_source_rgb(cr, 0.5, 0.5, 0.5);
            cairo_move_to(cr, margin, y);
            cairo_show_text(cr, "Not enough communication pairs for a matrix.");
        }
        g_list_free(used_pairs);
        g_list_free(top_pairs);
        g_ptr_array_free(unique_ips, TRUE);
    }
    FINISH_PAGE();

    /* ==== Page: 5. Port Analysis ==== */
    NEW_SECTION_PAGE("5. Port Analysis");
    TAG_DEST("section5");

    /* Top TCP ports */
    {
        GList *top_tcp = collector_top_tcp_ports((collection_result_t *)result, 5);
        int count = (int)g_list_length(top_tcp);
        if (count > 0) {
            bar_item_t *items = g_new0(bar_item_t, count);
            GList *l; int i;
            static char tcp_labels[10][32];
            for (l = top_tcp, i = 0; l; l = l->next, i++) {
                port_entry_t *pe = (port_entry_t *)l->data;
                snprintf(tcp_labels[i], sizeof(tcp_labels[i]), "TCP/%u", pe->port);
                items[i].label = tcp_labels[i];
                items[i].value = (double)pe->count;
            }
            renderer_draw_bar_chart(cr, "Top 5 TCP Destination Ports",
                                    items, count, margin, y, content_w, 220);
            g_free(items);
            y += 235;
        }
        g_list_free(top_tcp);
    }

    /* Top UDP ports */
    {
        GList *top_udp = collector_top_udp_ports((collection_result_t *)result, 5);
        int count = (int)g_list_length(top_udp);
        if (count > 0) {
            bar_item_t *items = g_new0(bar_item_t, count);
            GList *l; int i;
            static char udp_labels[10][32];
            for (l = top_udp, i = 0; l; l = l->next, i++) {
                port_entry_t *pe = (port_entry_t *)l->data;
                snprintf(udp_labels[i], sizeof(udp_labels[i]), "UDP/%u", pe->port);
                items[i].label = udp_labels[i];
                items[i].value = (double)pe->count;
            }
            renderer_draw_bar_chart(cr, "Top 5 UDP Destination Ports",
                                    items, count, margin, y, content_w, 220);
            g_free(items);
        }
        g_list_free(top_udp);
    }
    FINISH_PAGE();

    /* ==== Page: 6. Protocol Hierarchy ==== */
    NEW_SECTION_PAGE("6. Protocol Hierarchy");
    TAG_DEST("section6");
    {
        GList *rows = collector_flatten_proto_hierarchy(
                          (collection_result_t *)result, 7, 0.5);
        int count = (int)g_list_length(rows);

        if (count > 0) {
            /* Layout constants */
            double row_h    = 16.0;
            double indent_w = 18.0;
            double bar_max  = 130.0;
            double bar_h    = 10.0;
            double bar_x0   = margin + 210.0;
            double pkt_x    = bar_x0 + bar_max + 8.0;
            double pct_x    = pkt_x + 60.0;

            /* Column headers */
            renderer_set_font(cr, "sans-serif", CAIRO_FONT_SLANT_NORMAL,
                              CAIRO_FONT_WEIGHT_BOLD, 8.0);
            cairo_set_source_rgb(cr, 0.4, 0.4, 0.4);
            cairo_move_to(cr, margin + 4, y);
            cairo_show_text(cr, "Protocol");
            cairo_move_to(cr, bar_x0, y);
            cairo_show_text(cr, "Distribution");
            cairo_move_to(cr, pkt_x, y);
            cairo_show_text(cr, "Packets");
            cairo_move_to(cr, pct_x, y);
            cairo_show_text(cr, "%");
            y += 6;

            /* Thin separator */
            cairo_set_source_rgb(cr, 0.8, 0.8, 0.8);
            cairo_set_line_width(cr, 0.5);
            cairo_move_to(cr, margin, y);
            cairo_line_to(cr, margin + content_w, y);
            cairo_stroke(cr);
            y += 8;

            double max_y = paper->height_pt - 60;

            GList *l;
            for (l = rows; l; l = l->next) {
                proto_hier_row_t *row = (proto_hier_row_t *)l->data;
                if (y + row_h > max_y) break;

                double x0 = margin + (row->depth - 1) * indent_w;

                /* Tree connector lines */
                cairo_set_source_rgb(cr, 0.7, 0.7, 0.7);
                cairo_set_line_width(cr, 0.8);
                if (row->depth > 1) {
                    double cx = x0 - indent_w + 7;
                    double cy = y - 2;
                    cairo_move_to(cr, cx, cy - row_h * 0.4);
                    cairo_line_to(cr, cx, cy);
                    cairo_line_to(cr, cx + indent_w - 7, cy);
                    cairo_stroke(cr);
                }

                /* Protocol name (bold for depth 1, normal for deeper) */
                if (row->depth <= 1) {
                    renderer_set_font(cr, "sans-serif",
                                      CAIRO_FONT_SLANT_NORMAL,
                                      CAIRO_FONT_WEIGHT_BOLD, 8.5);
                } else {
                    renderer_set_font(cr, "sans-serif",
                                      CAIRO_FONT_SLANT_NORMAL,
                                      CAIRO_FONT_WEIGHT_NORMAL, 8.0);
                }
                cairo_set_source_rgb(cr, 0.15, 0.15, 0.15);
                cairo_move_to(cr, x0 + 4, y);
                cairo_show_text(cr, row->name);

                /* Percentage bar */
                double bar_w = bar_max * (row->pct / 100.0);
                if (bar_w < 1.0) bar_w = 1.0;
                int cidx = (row->depth - 1) % 10;
                cairo_set_source_rgba(cr,
                    CHART_PALETTE[cidx].r,
                    CHART_PALETTE[cidx].g,
                    CHART_PALETTE[cidx].b,
                    0.75);
                cairo_rectangle(cr, bar_x0, y - bar_h + 2,
                                bar_w, bar_h);
                cairo_fill(cr);

                /* Bar outline */
                cairo_set_source_rgb(cr, 0.85, 0.85, 0.85);
                cairo_set_line_width(cr, 0.4);
                cairo_rectangle(cr, bar_x0, y - bar_h + 2,
                                bar_max, bar_h);
                cairo_stroke(cr);

                /* Packet count + percentage text */
                renderer_set_font(cr, "sans-serif",
                                  CAIRO_FONT_SLANT_NORMAL,
                                  CAIRO_FONT_WEIGHT_NORMAL, 7.5);
                cairo_set_source_rgb(cr, 0.3, 0.3, 0.3);
                {
                    char pbuf[32];
                    snprintf(pbuf, sizeof(pbuf),
                             "%" G_GUINT64_FORMAT, row->packets);
                    cairo_move_to(cr, pkt_x, y);
                    cairo_show_text(cr, pbuf);
                    snprintf(pbuf, sizeof(pbuf), "%.1f%%", row->pct);
                    cairo_move_to(cr, pct_x, y);
                    cairo_show_text(cr, pbuf);
                }

                y += row_h;
            }

            /* Free rows */
            for (l = rows; l; l = l->next) {
                proto_hier_row_t *row = (proto_hier_row_t *)l->data;
                g_free(row->name);
                g_free(row);
            }
        } else {
            renderer_set_font(cr, "sans-serif",
                              CAIRO_FONT_SLANT_ITALIC,
                              CAIRO_FONT_WEIGHT_NORMAL, 10.0);
            cairo_set_source_rgb(cr, 0.5, 0.5, 0.5);
            cairo_move_to(cr, margin, y);
            cairo_show_text(cr, "No protocol hierarchy data available.");
        }
        g_list_free(rows);
    }
    FINISH_PAGE();

    /* ==== Page: 7. DNS Analysis ==== */
    NEW_SECTION_PAGE("7. DNS Analysis");
    TAG_DEST("section7");
    {
        GList *top_dns = collector_top_dns_queries((collection_result_t *)result, 10);
        int count = (int)g_list_length(top_dns);
        if (count > 0) {
            const char *hdrs[] = {"#", "Domain", "Queries"};
            char ***rows = (char ***)g_new0(gpointer, count);
            GList *l; int i;
            for (l = top_dns, i = 0; l; l = l->next, i++) {
                dns_query_t *q = (dns_query_t *)l->data;
                rows[i] = (char **)g_new0(gpointer, 3);
                rows[i][0] = g_strdup_printf("%d", i + 1);
                rows[i][1] = g_strdup(q->name);
                rows[i][2] = g_strdup_printf("%" G_GUINT64_FORMAT, q->count);
            }
            table_def_t tbl = {hdrs, 3, (const char ***)rows, count};
            y = renderer_draw_table(cr, "Top 10 DNS Queries", &tbl,
                                    margin, y, content_w);
            y += 20;
            for (i = 0; i < count; i++) {
                g_free(rows[i][0]); g_free(rows[i][1]); g_free(rows[i][2]);
                g_free(rows[i]);
            }
            g_free(rows);
        } else {
            renderer_set_font(cr, "sans-serif", CAIRO_FONT_SLANT_ITALIC,
                              CAIRO_FONT_WEIGHT_NORMAL, 10.0);
            cairo_set_source_rgb(cr, 0.5, 0.5, 0.5);
            cairo_move_to(cr, margin, y);
            cairo_show_text(cr, "No DNS traffic detected in this capture.");
            y += 20;
        }
        g_list_free(top_dns);
    }

    renderer_set_font(cr, "sans-serif", CAIRO_FONT_SLANT_NORMAL,
                      CAIRO_FONT_WEIGHT_NORMAL, 10.0);
    cairo_set_source_rgb(cr, 0.2, 0.2, 0.2);
    snprintf(buf, sizeof(buf),
             "Total DNS Queries: %" G_GUINT64_FORMAT "    Responses: %" G_GUINT64_FORMAT "    Authoritative: %" G_GUINT64_FORMAT,
             result->dns_total_queries,
             result->dns_total_responses,
             result->dns_authoritative);
    cairo_move_to(cr, margin, y); cairo_show_text(cr, buf);
    FINISH_PAGE();

    /* ==== Page: 8. TLS/SSL Analysis ==== */
    NEW_SECTION_PAGE("8. TLS/SSL Analysis");
    TAG_DEST("section8");
    {
        /* ---- Summary stats ---- */
        renderer_set_font(cr, "sans-serif", CAIRO_FONT_SLANT_NORMAL,
                          CAIRO_FONT_WEIGHT_NORMAL, 10.0);
        cairo_set_source_rgb(cr, 0.2, 0.2, 0.2);

        snprintf(buf, sizeof(buf), "Total TLS Handshakes: %" G_GUINT64_FORMAT,
                 result->tls_handshakes);
        cairo_move_to(cr, margin, y); cairo_show_text(cr, buf); y += 16;

        if (result->tls_quic_count > 0) {
            snprintf(buf, sizeof(buf),
                     "QUIC Connections (TLS 1.3): %" G_GUINT64_FORMAT,
                     result->tls_quic_count);
            cairo_move_to(cr, margin, y); cairo_show_text(cr, buf); y += 16;
        }

        snprintf(buf, sizeof(buf), "Unique SNIs: %u   Unique Certificates: %u",
                 g_hash_table_size(result->tls_sni_table),
                 g_hash_table_size(result->tls_cert_table));
        cairo_move_to(cr, margin, y); cairo_show_text(cr, buf); y += 24;

        /* ---- TLS Version Distribution (pie chart) ---- */
        GList *tls_versions = collector_all_tls_versions(
                                  (collection_result_t *)result);
        int ver_count = (int)g_list_length(tls_versions);

        if (ver_count > 0) {
            pie_item_t *vitems = g_new0(pie_item_t, ver_count);
            GList *l;
            int idx = 0;
            for (l = tls_versions; l; l = l->next, idx++) {
                tls_version_t *v = (tls_version_t *)l->data;
                vitems[idx].label = collector_tls_version_name(v->version);
                vitems[idx].value = (double)v->count;
            }

            renderer_draw_pie_chart(cr, "8.1 TLS Version Distribution",
                                    vitems, ver_count,
                                    margin, y, content_w, 280);
            y += 300;

            /* Version table */
            {
                guint64 total_ver = 0;
                for (l = tls_versions; l; l = l->next)
                    total_ver += ((tls_version_t *)l->data)->count;

                const char *vhdrs[] = {"Version", "Connections", "%"};
                char ***vrows = (char ***)g_new0(gpointer, ver_count);
                idx = 0;
                for (l = tls_versions; l; l = l->next, idx++) {
                    tls_version_t *v = (tls_version_t *)l->data;
                    double pct = total_ver ? 100.0 * v->count / total_ver : 0;
                    vrows[idx] = (char **)g_new0(gpointer, 3);
                    vrows[idx][0] = g_strdup(collector_tls_version_name(v->version));
                    vrows[idx][1] = g_strdup_printf("%" G_GUINT64_FORMAT, v->count);
                    vrows[idx][2] = g_strdup_printf("%.1f%%", pct);
                }

                table_def_t vtbl = {vhdrs, 3, (const char ***)vrows, ver_count};
                renderer_draw_table(cr, NULL, &vtbl, margin, y, content_w);
                for (idx = 0; idx < ver_count; idx++) {
                    for (int c = 0; c < 3; c++) g_free(vrows[idx][c]);
                    g_free(vrows[idx]);
                }
                g_free(vrows);
            }

            g_free(vitems);
            g_list_free(tls_versions);
        } else {
            renderer_set_font(cr, "sans-serif", CAIRO_FONT_SLANT_ITALIC,
                              CAIRO_FONT_WEIGHT_NORMAL, 10.0);
            cairo_set_source_rgb(cr, 0.5, 0.5, 0.5);
            cairo_move_to(cr, margin, y);
            cairo_show_text(cr, "No TLS traffic detected in this capture.");
        }
    }
    FINISH_PAGE();

    /* ==== Page: 8.2 TLS/SSL Cipher Suites ==== */
    NEW_SECTION_PAGE("8. TLS/SSL Analysis (cont.)");
    {
        GList *offered = collector_top_tls_ciphers_offered(
                             (collection_result_t *)result, 15);
        int off_count = (int)g_list_length(offered);

        GList *selected = collector_top_tls_ciphers_selected(
                              (collection_result_t *)result, 15);
        int sel_count = (int)g_list_length(selected);

        if (off_count > 0 || sel_count > 0) {
            /* Build combined cipher list */
            GHashTable *seen = g_hash_table_new(g_direct_hash, g_direct_equal);
            GPtrArray *all_ciphers = g_ptr_array_new();
            GList *l;

            for (l = offered; l; l = l->next) {
                tls_cipher_t *c = (tls_cipher_t *)l->data;
                if (!g_hash_table_contains(seen, GUINT_TO_POINTER((guint)c->id))) {
                    g_hash_table_insert(seen, GUINT_TO_POINTER((guint)c->id),
                                        GINT_TO_POINTER(1));
                    g_ptr_array_add(all_ciphers, c);
                }
            }
            for (l = selected; l; l = l->next) {
                tls_cipher_t *c = (tls_cipher_t *)l->data;
                if (!g_hash_table_contains(seen, GUINT_TO_POINTER((guint)c->id))) {
                    g_hash_table_insert(seen, GUINT_TO_POINTER((guint)c->id),
                                        GINT_TO_POINTER(1));
                    g_ptr_array_add(all_ciphers, c);
                }
            }

            int nrows = (int)all_ciphers->len;
            if (nrows > 20) nrows = 20;

            const char *chdrs[] = {"Cipher Suite", "Offered", "Selected"};
            char ***crows = (char ***)g_new0(gpointer, nrows);

            for (int i = 0; i < nrows; i++) {
                tls_cipher_t *c = (tls_cipher_t *)all_ciphers->pdata[i];
                crows[i] = (char **)g_new0(gpointer, 3);
                crows[i][0] = g_strdup(c->name);

                tls_cipher_t *co = (tls_cipher_t *)g_hash_table_lookup(
                    result->tls_cipher_offered_table, GUINT_TO_POINTER((guint)c->id));
                tls_cipher_t *cs = (tls_cipher_t *)g_hash_table_lookup(
                    result->tls_cipher_table, GUINT_TO_POINTER((guint)c->id));

                crows[i][1] = g_strdup_printf("%" G_GUINT64_FORMAT, co ? co->count : (guint64)0);
                crows[i][2] = g_strdup_printf("%" G_GUINT64_FORMAT, cs ? cs->count : (guint64)0);
            }

            table_def_t ctbl = {chdrs, 3, (const char ***)crows, nrows};
            renderer_draw_table(cr, "8.2 Cipher Suites: Offered vs Selected",
                                &ctbl, margin, y, content_w);
            y += (nrows + 2) * 18 + 20;

            for (int i = 0; i < nrows; i++) {
                for (int c = 0; c < 3; c++) g_free(crows[i][c]);
                g_free(crows[i]);
            }
            g_free(crows);
            g_hash_table_destroy(seen);
            g_ptr_array_free(all_ciphers, TRUE);

            /* Bar chart of selected ciphers if space allows */
            if (sel_count > 0 && y + 260 < paper->height_pt - margin) {
                int chart_n = MIN(sel_count, 10);
                bar_item_t *bitems = g_new0(bar_item_t, chart_n);
                int idx = 0;
                for (l = selected; l && idx < chart_n; l = l->next, idx++) {
                    tls_cipher_t *c = (tls_cipher_t *)l->data;
                    bitems[idx].label = c->name;
                    bitems[idx].value = (double)c->count;
                }

                renderer_draw_bar_chart(cr, "8.2 Selected Cipher Distribution",
                                        bitems, chart_n,
                                        margin, y, content_w, 220);
                g_free(bitems);
            }
        } else {
            renderer_set_font(cr, "sans-serif", CAIRO_FONT_SLANT_ITALIC,
                              CAIRO_FONT_WEIGHT_NORMAL, 10.0);
            cairo_set_source_rgb(cr, 0.5, 0.5, 0.5);
            cairo_move_to(cr, margin, y);
            cairo_show_text(cr, "No TLS cipher suite data available.");
        }

        g_list_free(offered);
        g_list_free(selected);
    }
    FINISH_PAGE();

    /* ==== Page: 8.3 TLS/SSL SNI & Certificates ==== */
    NEW_SECTION_PAGE("8. TLS/SSL Analysis (cont.)");
    {
        /* ---- Top SNIs ---- */
        GList *snis = collector_top_tls_snis((collection_result_t *)result, 20);
        int sni_count = (int)g_list_length(snis);

        if (sni_count > 0) {
            int nrows = MIN(sni_count, 20);
            const char *shdrs[] = {"#", "Server Name (SNI)", "Connections"};
            char ***srows = (char ***)g_new0(gpointer, nrows);
            GList *l;
            int idx = 0;

            for (l = snis; l && idx < nrows; l = l->next, idx++) {
                tls_sni_t *s = (tls_sni_t *)l->data;
                srows[idx] = (char **)g_new0(gpointer, 3);
                srows[idx][0] = g_strdup_printf("%d", idx + 1);
                srows[idx][1] = g_strdup(s->sni);
                srows[idx][2] = g_strdup_printf("%" G_GUINT64_FORMAT, s->count);
            }

            table_def_t stbl = {shdrs, 3, (const char ***)srows, nrows};
            renderer_draw_table(cr, "8.3 Top Server Names (SNI)",
                                &stbl, margin, y, content_w);
            y += (nrows + 2) * 18 + 20;

            for (int i = 0; i < nrows; i++) {
                for (int c = 0; c < 3; c++) g_free(srows[i][c]);
                g_free(srows[i]);
            }
            g_free(srows);
        }

        g_list_free(snis);

        /* ---- 8.4 Certificate Health & Expiry ---- */
        GList *certs = collector_all_tls_certs((collection_result_t *)result);
        int cert_count = (int)g_list_length(certs);

        {
            double capture_time = result->last_time;
            GList *l;

            /* Compute aggregate stats across all certs */
            int n_expired = 0, n_30d = 0, n_90d = 0, n_valid = 0, n_unknown = 0;
            double min_remaining = 1e18, max_remaining = 0;
            for (l = certs; l; l = l->next) {
                tls_cert_t *ct = (tls_cert_t *)l->data;
                if (ct->not_after <= 0.0) { n_unknown++; continue; }
                double remaining_days =
                    (ct->not_after - capture_time) / 86400.0;
                if (ct->not_after < capture_time)
                    n_expired++;
                else if (ct->not_after < capture_time + 30 * 86400)
                    n_30d++;
                else if (ct->not_after < capture_time + 90 * 86400)
                    n_90d++;
                else
                    n_valid++;
                if (remaining_days < min_remaining)
                    min_remaining = remaining_days;
                if (remaining_days > max_remaining)
                    max_remaining = remaining_days;
            }

            /* Certificate health summary table */
            if (y + 160 > paper->height_pt - margin) {
                FINISH_PAGE();
                NEW_SECTION_PAGE("8. TLS/SSL Analysis (cont.)");
            }
            {
                const char *hhdrs[] = {"Metric", "Value"};
                char **hrows_data[7];
                char hbuf[7][2][64];
                int hn = 0;

                #define ADD_CERT_ROW(label, fmt, ...) do { \
                    snprintf(hbuf[hn][0], 64, "%s", (label)); \
                    snprintf(hbuf[hn][1], 64, fmt, __VA_ARGS__); \
                    hrows_data[hn] = (char **)g_new0(gpointer, 2); \
                    hrows_data[hn][0] = hbuf[hn][0]; \
                    hrows_data[hn][1] = hbuf[hn][1]; \
                    hn++; \
                } while(0)

                ADD_CERT_ROW("Unique Certificates", "%d", cert_count);
                if (n_expired > 0)
                    ADD_CERT_ROW("Expired", "%d", n_expired);
                if (n_30d > 0)
                    ADD_CERT_ROW("Expiring < 30 days", "%d", n_30d);
                if (n_90d > 0)
                    ADD_CERT_ROW("Expiring < 90 days", "%d", n_90d);
                ADD_CERT_ROW("Valid (> 90 days)", "%d", n_valid);
                if (n_unknown > 0)
                    ADD_CERT_ROW("Expiry Unknown", "%d", n_unknown);
                if (min_remaining < 1e17) {
                    if (min_remaining < 0)
                        ADD_CERT_ROW("Shortest Remaining", "%.0f days (expired)", min_remaining);
                    else
                        ADD_CERT_ROW("Shortest Remaining", "%.0f days", min_remaining);
                }
                #undef ADD_CERT_ROW

                char ***hrows = (char ***)g_new0(gpointer, hn);
                for (int i = 0; i < hn; i++) hrows[i] = hrows_data[i];
                table_def_t htbl = {hhdrs, 2, (const char ***)hrows, hn};
                renderer_draw_table(cr, "8.4 Certificate Health Summary",
                                    &htbl, margin, y, content_w);
                y += (hn + 2) * 18 + 16;
                for (int i = 0; i < hn; i++) g_free(hrows_data[i]);
                g_free(hrows);
            }

            /* Per-certificate detail table */
            if (cert_count > 0) {
                int nrows = MIN(cert_count, 20);

                if (y + (nrows + 2) * 18 + 30 > paper->height_pt - margin) {
                    FINISH_PAGE();
                    NEW_SECTION_PAGE("8. TLS/SSL Analysis (cont.)");
                }

                const char *certhdrs[] = {"Domain", "Not After",
                                           "Remaining", "Status", "Seen"};
                char ***certrows = (char ***)g_new0(gpointer, nrows);
                int idx = 0;

                for (l = certs; l && idx < nrows; l = l->next, idx++) {
                    tls_cert_t *ct = (tls_cert_t *)l->data;
                    certrows[idx] = (char **)g_new0(gpointer, 5);
                    certrows[idx][0] = g_strdup(ct->cn);

                    if (ct->not_after > 0.0) {
                        time_t t = (time_t)ct->not_after;
                        struct tm *tm_info = gmtime(&t);
                        char datebuf[32];
                        if (!tm_info)
                            g_snprintf(datebuf, sizeof(datebuf), "Unknown");
                        else
                            strftime(datebuf, sizeof(datebuf), "%Y-%m-%d",
                                     tm_info);
                        certrows[idx][1] = g_strdup(datebuf);

                        double rem_days =
                            (ct->not_after - capture_time) / 86400.0;
                        if (rem_days < 0)
                            certrows[idx][2] = g_strdup_printf(
                                "%.0f days ago", -rem_days);
                        else
                            certrows[idx][2] = g_strdup_printf(
                                "%.0f days", rem_days);

                        if (ct->not_after < capture_time)
                            certrows[idx][3] = g_strdup("EXPIRED");
                        else if (ct->not_after < capture_time + 30 * 86400)
                            certrows[idx][3] = g_strdup("< 30 days");
                        else if (ct->not_after < capture_time + 90 * 86400)
                            certrows[idx][3] = g_strdup("< 90 days");
                        else
                            certrows[idx][3] = g_strdup("Valid");
                    } else {
                        certrows[idx][1] = g_strdup("N/A");
                        certrows[idx][2] = g_strdup("N/A");
                        certrows[idx][3] = g_strdup("N/A");
                    }

                    certrows[idx][4] = g_strdup_printf(
                        "%" G_GUINT64_FORMAT, ct->count);
                }

                table_def_t certtbl = {certhdrs, 5,
                                       (const char ***)certrows, nrows};
                renderer_draw_table(cr, "8.5 Certificate Details",
                                    &certtbl, margin, y, content_w);

                for (int i = 0; i < nrows; i++) {
                    for (int c = 0; c < 5; c++) g_free(certrows[i][c]);
                    g_free(certrows[i]);
                }
                g_free(certrows);
            } else {
                renderer_set_font(cr, "sans-serif",
                                  CAIRO_FONT_SLANT_ITALIC,
                                  CAIRO_FONT_WEIGHT_NORMAL, 9.0);
                cairo_set_source_rgb(cr, 0.5, 0.5, 0.5);
                cairo_move_to(cr, margin, y);
                cairo_show_text(cr,
                    "No certificate data extracted from this capture. "
                    "Certificate details require TLS handshakes with "
                    "x509 fields visible during analysis.");
            }
        }

        g_list_free(certs);
    }
    FINISH_PAGE();

    /* ==== Page: 9. HTTP Analysis ==== */
    NEW_SECTION_PAGE("9. HTTP Analysis");
    TAG_DEST("section9");
    {
        GList *top_hosts = collector_top_http_hosts((collection_result_t *)result, 10);
        int count = (int)g_list_length(top_hosts);
        if (count > 0) {
            const char *hdrs[] = {"#", "Host", "Requests"};
            char ***rows = (char ***)g_new0(gpointer, count);
            GList *l; int i;
            for (l = top_hosts, i = 0; l; l = l->next, i++) {
                http_host_t *h = (http_host_t *)l->data;
                rows[i] = (char **)g_new0(gpointer, 3);
                rows[i][0] = g_strdup_printf("%d", i + 1);
                rows[i][1] = g_strdup(h->host);
                rows[i][2] = g_strdup_printf("%" G_GUINT64_FORMAT, h->count);
            }
            table_def_t tbl = {hdrs, 3, (const char ***)rows, count};
            y = renderer_draw_table(cr, "Top 10 HTTP Hosts", &tbl,
                                    margin, y, content_w);
            y += 30;
            for (i = 0; i < count; i++) {
                g_free(rows[i][0]); g_free(rows[i][1]); g_free(rows[i][2]);
                g_free(rows[i]);
            }
            g_free(rows);
        } else {
            renderer_set_font(cr, "sans-serif", CAIRO_FONT_SLANT_ITALIC,
                              CAIRO_FONT_WEIGHT_NORMAL, 10.0);
            cairo_set_source_rgb(cr, 0.5, 0.5, 0.5);
            cairo_move_to(cr, margin, y);
            cairo_show_text(cr, "No HTTP traffic detected in this capture.");
            y += 20;
        }
        g_list_free(top_hosts);
    }

    /* HTTP status codes */
    {
        GList *top_status = collector_top_http_status((collection_result_t *)result, 10);
        int count = (int)g_list_length(top_status);
        if (count > 0) {
            bar_item_t *items = g_new0(bar_item_t, count);
            GList *l; int i;
            static char status_labels[10][16];
            for (l = top_status, i = 0; l; l = l->next, i++) {
                http_status_t *st = (http_status_t *)l->data;
                snprintf(status_labels[i], sizeof(status_labels[i]), "%u", st->code);
                items[i].label = status_labels[i];
                items[i].value = (double)st->count;
            }
            renderer_draw_bar_chart(cr, "HTTP Status Codes",
                                    items, count, margin, y, content_w, 220);
            g_free(items);
        }
        g_list_free(top_status);
    }
    FINISH_PAGE();

    /* ==== Page: 10. MAC Layer Analysis ==== */
    NEW_SECTION_PAGE("10. MAC Layer Analysis");
    TAG_DEST("section10");

    /* Traffic type pie */
    {
        pie_item_t items[3]; int n = 0;
        if (result->mac_unicast > 0)   { items[n].label = "Unicast";   items[n].value = (double)result->mac_unicast;   n++; }
        if (result->mac_broadcast > 0) { items[n].label = "Broadcast"; items[n].value = (double)result->mac_broadcast; n++; }
        if (result->mac_multicast > 0) { items[n].label = "Multicast"; items[n].value = (double)result->mac_multicast; n++; }
        if (n > 0)
            renderer_draw_pie_chart(cr, "Traffic Type Distribution",
                                    items, n, margin, y, content_w, 210);
        y += 225;
    }

    /* Frame size distribution bar */
    {
        bar_item_t items[FRAME_SIZE_BUCKETS]; int n = 0, i;
        for (i = 0; i < FRAME_SIZE_BUCKETS; i++) {
            if (result->frame_size_counts[i] > 0) {
                items[n].label = collector_frame_size_label(i);
                items[n].value = (double)result->frame_size_counts[i];
                n++;
            }
        }
        if (n > 0)
            renderer_draw_bar_chart(cr, "Frame Size Distribution (bytes)",
                                    items, n, margin, y, content_w, 210);
    }
    FINISH_PAGE();

    /* ==== Page: 11. IP Layer Analysis ==== */
    NEW_SECTION_PAGE("11. IP Layer Analysis");
    TAG_DEST("section11");

    /* IP fragmentation text */
    renderer_set_font(cr, "sans-serif", CAIRO_FONT_SLANT_NORMAL,
                      CAIRO_FONT_WEIGHT_NORMAL, 10.0);
    cairo_set_source_rgb(cr, 0.2, 0.2, 0.2);
    if (result->ip_fragmented > 0) {
        double frag_rate = result->total_packets > 0
            ? (double)result->ip_fragmented / result->total_packets * 100.0 : 0.0;
        snprintf(buf, sizeof(buf), "Fragmented Packets: %" G_GUINT64_FORMAT " (%.1f%%)",
                 result->ip_fragmented, frag_rate);
    } else {
        snprintf(buf, sizeof(buf), "No IP fragmentation detected.");
    }
    cairo_move_to(cr, margin, y); cairo_show_text(cr, buf); y += 25;

    /* IP protocol distribution bar */
    {
        GHashTableIter iter; gpointer key, value;
        GPtrArray *protos = g_ptr_array_new();
        if (result->ip_proto_table) {
            g_hash_table_iter_init(&iter, result->ip_proto_table);
            while (g_hash_table_iter_next(&iter, &key, &value))
                g_ptr_array_add(protos, key);
        }

        if (protos->len > 0) {
            int n = MIN((int)protos->len, 10);
            bar_item_t *items = g_new0(bar_item_t, n);
            for (int i = 0; i < n; i++) {
                guint64 best_cnt = 0; int best_j = i;
                for (guint j = i; j < protos->len; j++) {
                    guint64 *c = (guint64 *)g_hash_table_lookup(
                        result->ip_proto_table, protos->pdata[j]);
                    if (c && *c > best_cnt) { best_cnt = *c; best_j = j; }
                }
                gpointer tmp = protos->pdata[i];
                protos->pdata[i] = protos->pdata[best_j];
                protos->pdata[best_j] = tmp;

                guint proto_num = GPOINTER_TO_UINT(protos->pdata[i]);
                guint64 *c = (guint64 *)g_hash_table_lookup(
                    result->ip_proto_table, protos->pdata[i]);
                items[i].label = collector_ip_proto_name(proto_num);
                items[i].value = c ? (double)*c : 0;
            }
            renderer_draw_bar_chart(cr, "IP Protocol Distribution",
                                    items, n, margin, y, content_w, 210);
            g_free(items);
            y += 225;
        }
        g_ptr_array_free(protos, TRUE);
    }

    /* DSCP pie chart */
    {
        GHashTableIter iter; gpointer key, value;
        int n = 0; pie_item_t items[10];
        GPtrArray *dscp_arr = g_ptr_array_new();
        if (result->ip_dsfield_table) {
            g_hash_table_iter_init(&iter, result->ip_dsfield_table);
            while (g_hash_table_iter_next(&iter, &key, &value))
                g_ptr_array_add(dscp_arr, key);
        }
        for (guint i = 0; i < dscp_arr->len && n < 10; i++) {
            guint dscp = GPOINTER_TO_UINT(dscp_arr->pdata[i]);
            guint64 *c = (guint64 *)g_hash_table_lookup(
                result->ip_dsfield_table, dscp_arr->pdata[i]);
            if (c && *c > 0) {
                items[n].label = collector_dscp_name(dscp);
                items[n].value = (double)*c;
                n++;
            }
        }
        if (n > 0) {
            renderer_draw_pie_chart(cr, "DSCP Distribution",
                                    items, n, margin, y, content_w, 210);
            y += 225;
        }
        g_ptr_array_free(dscp_arr, TRUE);
    }

    /* TTL distribution bar chart - group into common ranges */
    {
        GHashTableIter iter; gpointer key, value;
        guint64 ttl_buckets[8] = {0};
        /* [0]=1  [1]=2-31  [2]=32  [3]=33-63  [4]=64  [5]=65-127  [6]=128  [7]=129-255 */
        if (result->ip_ttl_table) {
            g_hash_table_iter_init(&iter, result->ip_ttl_table);
            while (g_hash_table_iter_next(&iter, &key, &value)) {
                guint ttl = GPOINTER_TO_UINT(key);
                guint64 cnt = *(guint64 *)value;
                int b;
                if      (ttl <= 1)   b = 0;
                else if (ttl < 32)   b = 1;
                else if (ttl == 32)  b = 2;
                else if (ttl < 64)   b = 3;
                else if (ttl == 64)  b = 4;
                else if (ttl < 128)  b = 5;
                else if (ttl == 128) b = 6;
                else                 b = 7;
                ttl_buckets[b] += cnt;
            }
        }
        static const char *ttl_labels[8] = {
            "1", "2-31", "32", "33-63", "64", "65-127", "128", "129-255"
        };
        bar_item_t titems[8]; int tn = 0;
        for (int i = 0; i < 8; i++) {
            if (ttl_buckets[i] > 0) {
                titems[tn].label = ttl_labels[i];
                titems[tn].value = (double)ttl_buckets[i];
                tn++;
            }
        }
        if (tn > 0)
            renderer_draw_bar_chart(cr, "TTL Distribution",
                                    titems, tn, margin, y, content_w, 210);
    }
    FINISH_PAGE();

    /* ==== Page: 12. TCP Analysis ==== */
    NEW_SECTION_PAGE("12. TCP Analysis");
    TAG_DEST("section12");
    {
        if (result->tcp_total_segments == 0) {
            renderer_set_font(cr, "sans-serif", CAIRO_FONT_SLANT_ITALIC,
                              CAIRO_FONT_WEIGHT_NORMAL, 10.0);
            cairo_set_source_rgb(cr, 0.5, 0.5, 0.5);
            cairo_move_to(cr, margin, y);
            cairo_show_text(cr, "No TCP traffic detected in this capture.");
            FINISH_PAGE();
            goto tcp_done;
        }

        /* ---- TCP Summary table ---- */
        {
            const char *thdrs[] = {"Metric", "Value"};
            char ***trows;
            int nrows = 0;
            char **metric_rows[12];
            char row_buf[12][2][64];

            #define ADD_TCP_ROW(label, fmt, ...) do { \
                snprintf(row_buf[nrows][0], 64, "%s", (label)); \
                snprintf(row_buf[nrows][1], 64, fmt, __VA_ARGS__); \
                metric_rows[nrows] = (char **)g_new0(gpointer, 2); \
                metric_rows[nrows][0] = row_buf[nrows][0]; \
                metric_rows[nrows][1] = row_buf[nrows][1]; \
                nrows++; \
            } while(0)

            ADD_TCP_ROW("Total Segments", "%" G_GUINT64_FORMAT, result->tcp_total_segments);
            ADD_TCP_ROW("Unique Streams", "%u", result->tcp_streams ? g_hash_table_size(result->tcp_streams) : 0);
            ADD_TCP_ROW("SYN Packets", "%" G_GUINT64_FORMAT, result->tcp_syn_count);
            ADD_TCP_ROW("FIN Packets", "%" G_GUINT64_FORMAT, result->tcp_fin_count);
            ADD_TCP_ROW("RST Packets", "%" G_GUINT64_FORMAT, result->tcp_rst_count);
            if (result->tcp_window_count > 0) {
                ADD_TCP_ROW("Window Size (Min / Max / Avg)", "%.0f / %.0f / %.0f bytes",
                            result->tcp_window_min, result->tcp_window_max,
                            result->tcp_window_sum / result->tcp_window_count);
            }
            if (result->tcp_seglen_count > 0) {
                ADD_TCP_ROW("Segment Length (Min / Max / Avg)", "%.0f / %.0f / %.0f bytes",
                            result->tcp_seglen_min, result->tcp_seglen_max,
                            result->tcp_seglen_sum / result->tcp_seglen_count);
            }
            #undef ADD_TCP_ROW

            if (nrows > 0) {
                trows = (char ***)g_new0(gpointer, nrows);
                for (int i = 0; i < nrows; i++) trows[i] = metric_rows[i];
                table_def_t ttbl = {thdrs, 2, (const char ***)trows, nrows};
                renderer_draw_table(cr, "TCP Summary", &ttbl, margin, y, content_w);
                y += (nrows + 2) * 18 + 28;
                for (int i = 0; i < nrows; i++) g_free(metric_rows[i]);
                g_free(trows);
            }
        }

        /* ---- TCP Options Negotiated (on SYN packets) ---- */
        if (result->tcp_opt_syn_packets > 0) {
            static const struct { guint8 kind; const char *name; } known_opts[] = {
                {  2, "MSS (Maximum Segment Size)" },
                {  3, "Window Scale" },
                {  4, "SACK Permitted" },
                {  5, "SACK" },
                {  8, "Timestamps" },
                { 30, "Multipath TCP (MPTCP)" },
                { 28, "User Timeout" },
                { 34, "TCP Fast Open" },
                {  1, "NOP (No-Operation)" },
                {  0, "EOL (End of Option List)" },
            };
            int nk = sizeof(known_opts) / sizeof(known_opts[0]);
            const char *ohdrs[] = {"Option", "SYN Packets", "% of SYN"};
            int orows_n = 0;
            char ***orows = (char ***)g_new0(gpointer, nk);

            for (int i = 0; i < nk; i++) {
                guint64 cnt = result->tcp_opt_counts[known_opts[i].kind];
                if (cnt == 0) continue;
                double pct = (double)cnt / result->tcp_opt_syn_packets * 100.0;
                orows[orows_n] = (char **)g_new0(gpointer, 3);
                orows[orows_n][0] = g_strdup(known_opts[i].name);
                orows[orows_n][1] = g_strdup_printf("%" G_GUINT64_FORMAT, cnt);
                orows[orows_n][2] = g_strdup_printf("%.1f%%", pct);
                orows_n++;
            }
            if (orows_n > 0) {
                table_def_t otbl = {ohdrs, 3, (const char ***)orows, orows_n};
                renderer_draw_table(cr,
                    "12.1 TCP Options Negotiated (SYN packets)",
                    &otbl, margin, y, content_w);
                y += (orows_n + 2) * 18 + 28;
            }
            for (int i = 0; i < orows_n; i++) {
                for (int c = 0; c < 3; c++) g_free(orows[i][c]);
                g_free(orows[i]);
            }
            g_free(orows);
        }

        /* ---- 12.2 TCP Window Size Distribution ---- */
        {
            bar_item_t witems[TCP_WIN_BUCKETS];
            int wcount = 0;
            for (int i = 0; i < TCP_WIN_BUCKETS; i++) {
                if (result->tcp_win_dist[i] > 0) {
                    witems[wcount].label = collector_tcp_win_label(i);
                    witems[wcount].value = (double)result->tcp_win_dist[i];
                    wcount++;
                }
            }
            if (wcount > 0) {
                renderer_draw_bar_chart(cr, "12.2 TCP Window Size Distribution",
                                        witems, wcount,
                                        margin, y, content_w, 150);
                y += 170;
            }
        }

        /* ---- 12.3 TCP Segment Size Distribution ---- */
        {
            bar_item_t sitems[TCP_SEG_BUCKETS];
            int scount = 0;
            for (int i = 0; i < TCP_SEG_BUCKETS; i++) {
                if (result->tcp_seg_dist[i] > 0) {
                    sitems[scount].label = collector_tcp_seg_label(i);
                    sitems[scount].value = (double)result->tcp_seg_dist[i];
                    scount++;
                }
            }
            if (scount > 0) {
                if (y + 170 > paper->height_pt - margin) {
                    FINISH_PAGE();
                    NEW_SECTION_PAGE("12. TCP Analysis (cont.)");
                }
                renderer_draw_bar_chart(cr, "12.3 TCP Segment Size Distribution",
                                        sitems, scount,
                                        margin, y, content_w, 150);
                y += 170;
            }
        }
    }
    FINISH_PAGE();
    tcp_done:
    ;

    /* ==== Summary Page ==== */
    {
        cairo_set_source_rgb(cr, 1, 1, 1);
        cairo_paint(cr);
        y = margin;
        renderer_draw_section_header(cr, "Summary", margin, y, content_w);
        y += 50;

        char vbuf[256];

        renderer_set_font(cr, "sans-serif", CAIRO_FONT_SLANT_NORMAL,
                          CAIRO_FONT_WEIGHT_BOLD, 12.0);
        cairo_set_source_rgb(cr, 0.17, 0.48, 0.71);
        cairo_move_to(cr, margin, y);
        cairo_show_text(cr, "Capture at a Glance");
        y += 24;

        renderer_set_font(cr, "sans-serif", CAIRO_FONT_SLANT_NORMAL,
                          CAIRO_FONT_WEIGHT_NORMAL, 10.0);
        cairo_set_source_rgb(cr, 0.15, 0.15, 0.15);

        snprintf(vbuf, sizeof(vbuf),
                 "This capture contains %" G_GUINT64_FORMAT " packets totaling ",
                 result->total_packets);
        cairo_move_to(cr, margin, y);
        cairo_show_text(cr, vbuf);
        y += 16;

        format_bytes_str(result->total_bytes, buf, sizeof(buf));
        {
            double dur = result->duration;
            int hours = (int)(dur / 3600.0);
            int mins  = (int)(fmod(dur, 3600.0) / 60.0);
            double secs = fmod(dur, 60.0);
            snprintf(vbuf, sizeof(vbuf),
                     "%s over a duration of %02d:%02d:%05.2f.",
                     buf, hours, mins, secs);
        }
        cairo_move_to(cr, margin, y);
        cairo_show_text(cr, vbuf);
        y += 28;

        renderer_set_font(cr, "sans-serif", CAIRO_FONT_SLANT_NORMAL,
                          CAIRO_FONT_WEIGHT_BOLD, 12.0);
        cairo_set_source_rgb(cr, 0.17, 0.48, 0.71);
        cairo_move_to(cr, margin, y);
        cairo_show_text(cr, "Key Metrics");
        y += 20;

        #define SL(label, fmt, ...) do { \
            renderer_set_font(cr, "sans-serif", CAIRO_FONT_SLANT_NORMAL, \
                              CAIRO_FONT_WEIGHT_BOLD, 9.0); \
            cairo_set_source_rgb(cr, 0.3, 0.3, 0.3); \
            cairo_move_to(cr, margin + 10, y); \
            cairo_show_text(cr, (label)); \
            renderer_set_font(cr, "sans-serif", CAIRO_FONT_SLANT_NORMAL, \
                              CAIRO_FONT_WEIGHT_NORMAL, 9.0); \
            cairo_set_source_rgb(cr, 0.15, 0.15, 0.15); \
            snprintf(vbuf, sizeof(vbuf), fmt, __VA_ARGS__); \
            cairo_move_to(cr, margin + 180, y); \
            cairo_show_text(cr, vbuf); \
            y += 16; \
        } while(0)

        SL("Unique IP Addresses:", "%u",
           g_hash_table_size(result->ip_table));
        SL("Protocols Detected:", "%u",
           g_hash_table_size(result->protocol_table));
        SL("TCP Ports:", "%u",
           g_hash_table_size(result->tcp_port_table));
        SL("UDP Ports:", "%u",
           g_hash_table_size(result->udp_port_table));
        SL("Communication Pairs:", "%u",
           g_hash_table_size(result->comm_pair_table));
        SL("DNS Queries:", "%" G_GUINT64_FORMAT,
           result->dns_total_queries);
        SL("TLS Handshakes:", "%" G_GUINT64_FORMAT,
           result->tls_handshakes);
        if (result->tcp_total_segments > 0)
            SL("TCP Segments:", "%" G_GUINT64_FORMAT,
               result->tcp_total_segments);
        #undef SL

        y += 20;

        renderer_set_font(cr, "sans-serif", CAIRO_FONT_SLANT_NORMAL,
                          CAIRO_FONT_WEIGHT_NORMAL, 9.0);
        cairo_set_source_rgb(cr, 0.2, 0.2, 0.2);
        cairo_move_to(cr, margin, y);
        cairo_show_text(cr,
            "This report was generated by PacketReporter Pro "
            PLUGIN_VERSION_STR ".");
        y += 14;
        cairo_move_to(cr, margin, y);
        cairo_show_text(cr,
            "For more information visit https://github.com/netwho/PacketCirclePro");

        FINISH_PAGE();
    }

    /* Finalise */
    cairo_destroy(cr);
    cairo_surface_destroy(surface);

    ws_log(WS_LOG_DOMAIN, LOG_LEVEL_INFO,
           "Detailed %s PDF (%d pages) written to %s",
           paper->name, page_num - 1, path);
    return path;
}

#undef NEW_SECTION_PAGE
#undef TAG_DEST
#undef FINISH_PAGE

/* ================================================================
 * Annotated Report — same content as detailed, but with a
 * 2/3 + 1/3 annotation sidebar layout plus a summary page.
 * ================================================================ */

static double draw_wrapped_text(cairo_t *cr, const char *text,
                                double x, double y, double max_w,
                                double font_size, double line_h)
{
    renderer_set_font(cr, "sans-serif", CAIRO_FONT_SLANT_NORMAL,
                      CAIRO_FONT_WEIGHT_NORMAL, font_size);

    char *dup = g_strdup(text);
    char *p = dup;
    char line_buf[512];
    line_buf[0] = '\0';

    while (*p) {
        /* Extract next word */
        while (*p == ' ') p++;
        if (!*p) break;
        char *word_start = p;
        while (*p && *p != ' ' && *p != '\n') p++;
        gboolean newline = (*p == '\n');
        char saved = *p;
        *p = '\0';

        /* Test if adding this word overflows */
        char test[512];
        if (line_buf[0])
            snprintf(test, sizeof(test), "%s %s", line_buf, word_start);
        else
            snprintf(test, sizeof(test), "%s", word_start);

        double tw = renderer_text_width(cr, test);
        if (tw > max_w && line_buf[0]) {
            cairo_move_to(cr, x, y);
            cairo_show_text(cr, line_buf);
            y += line_h;
            snprintf(line_buf, sizeof(line_buf), "%s", word_start);
        } else {
            snprintf(line_buf, sizeof(line_buf), "%s", test);
        }

        *p = saved;
        if (newline && *p) {
            p++;
            cairo_move_to(cr, x, y);
            cairo_show_text(cr, line_buf);
            y += line_h;
            line_buf[0] = '\0';
        }
    }

    if (line_buf[0]) {
        cairo_move_to(cr, x, y);
        cairo_show_text(cr, line_buf);
        y += line_h;
    }

    g_free(dup);
    return y;
}

typedef struct {
    const char *source;
    const char *datapoints;
    const char *interpretation;
} annotation_t;

static void draw_annotation_sidebar(cairo_t *cr,
                                    double x, double y_top,
                                    double width, double y_bottom,
                                    const annotation_t *ann)
{
    double pad = 6.0;
    double box_h = y_bottom - y_top;
    if (box_h < 40) box_h = 40;

    /* Light background frame */
    cairo_set_source_rgba(cr, 0.95, 0.96, 0.98, 1.0);
    cairo_rectangle(cr, x, y_top, width, box_h);
    cairo_fill(cr);

    cairo_set_source_rgb(cr, 0.75, 0.80, 0.85);
    cairo_set_line_width(cr, 0.6);
    cairo_rectangle(cr, x, y_top, width, box_h);
    cairo_stroke(cr);

    double tx = x + pad;
    double tw = width - 2 * pad;
    double ty = y_top + pad + 8;

    if (ann->source && ann->source[0]) {
        renderer_set_font(cr, "sans-serif", CAIRO_FONT_SLANT_NORMAL,
                          CAIRO_FONT_WEIGHT_BOLD, 8.0);
        cairo_set_source_rgb(cr, 0.17, 0.48, 0.71);
        cairo_move_to(cr, tx, ty);
        cairo_show_text(cr, "Source:");
        ty += 11;
        cairo_set_source_rgb(cr, 0.25, 0.25, 0.25);
        ty = draw_wrapped_text(cr, ann->source, tx, ty, tw, 7.5, 10.5);
        ty += 5;
    }

    if (ann->datapoints && ann->datapoints[0]) {
        renderer_set_font(cr, "sans-serif", CAIRO_FONT_SLANT_NORMAL,
                          CAIRO_FONT_WEIGHT_BOLD, 8.0);
        cairo_set_source_rgb(cr, 0.17, 0.48, 0.71);
        cairo_move_to(cr, tx, ty);
        cairo_show_text(cr, "Data Points:");
        ty += 11;
        cairo_set_source_rgb(cr, 0.25, 0.25, 0.25);
        ty = draw_wrapped_text(cr, ann->datapoints, tx, ty, tw, 7.5, 10.5);
        ty += 5;
    }

    if (ann->interpretation && ann->interpretation[0]) {
        renderer_set_font(cr, "sans-serif", CAIRO_FONT_SLANT_NORMAL,
                          CAIRO_FONT_WEIGHT_BOLD, 8.0);
        cairo_set_source_rgb(cr, 0.17, 0.48, 0.71);
        cairo_move_to(cr, tx, ty);
        cairo_show_text(cr, "How to Read:");
        ty += 11;
        cairo_set_source_rgb(cr, 0.25, 0.25, 0.25);
        draw_wrapped_text(cr, ann->interpretation, tx, ty, tw, 7.5, 10.5);
    }
}

/* Annotations for sections with a single sidebar */
static const annotation_t ann_matrix = {
    "Wireshark fields: ip.src + ip.dst pairs, aggregated per conversation.",
    "Top 10 unique bidirectional IP pairs by packet count, visualized as a "
    "chord diagram. Each node is an IP; arcs show traffic volume.",
    "The communication matrix reveals which hosts are talking to each other "
    "and how heavily. Thick chords in the diagram indicate high-volume "
    "conversations. Look for unexpected connections between internal hosts "
    "and external IPs, or for asymmetric conversations that might indicate "
    "data transfers or C2 beaconing."
};

static const annotation_t ann_proto_hierarchy = {
    "Wireshark dissector tree: each packet's full protocol stack.",
    "Hierarchical tree showing protocol layering, with packet counts and "
    "percentage bars at each level (e.g. Ethernet > IP > TCP > TLS).",
    "The protocol hierarchy shows how traffic is encapsulated. Read from top "
    "to bottom: each indent level is one encapsulation layer deeper. This "
    "helps identify tunneled traffic (e.g. IP-in-IP, GRE) and see which "
    "fraction of TCP carries TLS vs. plain-text protocols."
};

static const annotation_t ann_dns = {
    "Wireshark fields: dns.qry.name, dns.flags (QR, AA bits).",
    "Top 10 queried domain names with query counts; total queries, "
    "responses, and authoritative answer counts.",
    "DNS queries reveal which domains the network resolves most often. Frequent "
    "queries to unknown or suspicious domains may indicate malware beaconing. "
    "A high query count with low response count suggests DNS failures or "
    "filtering. Authoritative responses come from the domain's own name servers."
};

static const annotation_t ann_http = {
    "Wireshark fields: http.host, http.request.method, http.response.code.",
    "Top 10 HTTP hosts by request count (table), HTTP status code distribution "
    "(bar chart).",
    "HTTP host data shows which web servers are being contacted. If you see HTTP "
    "(not HTTPS) to sensitive sites, that is a security concern -- credentials "
    "may be transmitted in clear text. Status codes: 200 = success, 3xx = "
    "redirects, 4xx = client errors (404 = not found), 5xx = server errors. "
    "Many 4xx/5xx codes suggest misconfigured clients or failing services."
};

/* Annotations for sections that get TWO sidebar boxes */
static const annotation_t ann_ip_chart = {
    "Wireshark fields: ip.src, ip.dst (counted per frame).",
    "Packet count per IP address (source + destination) as a bar chart.",
    "The bar chart gives a quick visual comparison of traffic volume per host. "
    "Use it to instantly spot which IPs dominate. Tall bars stand out -- "
    "if an unexpected IP is at the top, investigate further."
};

static const annotation_t ann_ip_table = {
    "Same data as the chart above, in tabular form.",
    "Ranked table with Source, Destination and Total packet counts per IP.",
    "The table is more informative when you need exact numbers, or want to "
    "compare source vs. destination counts. A large imbalance suggests "
    "one-way traffic (backups, streaming, exfiltration)."
};

static const annotation_t ann_proto_chart = {
    "Wireshark field: frame.protocols (highest-layer protocol per packet).",
    "Packet count per protocol as a pie chart.",
    "The pie chart shows relative proportions at a glance. If a single "
    "protocol slice dominates (>80%%), check if that is expected. Small "
    "slices of unusual protocols may signal tunneling."
};

static const annotation_t ann_proto_table = {
    "Same protocol data in tabular form.",
    "Ranked table with protocol name, absolute packet count, and percentage.",
    "The table provides exact numbers and percentages. Use it to compare "
    "protocols numerically. Unknown or unusual protocols may signal "
    "unauthorized applications."
};

static const annotation_t ann_port_tcp = {
    "Wireshark field: tcp.dstport.",
    "Top 5 TCP destination ports by packet count.",
    "TCP ports reveal which services are being accessed. Common: 443 (HTTPS), "
    "80 (HTTP), 22 (SSH). Unusual high-traffic ports may indicate tunneling, "
    "unauthorized services, or malware C2 channels."
};

static const annotation_t ann_port_udp = {
    "Wireshark field: udp.dstport.",
    "Top 5 UDP destination ports by packet count.",
    "Heavy UDP on non-DNS ports can signal streaming, VPN, or QUIC traffic. "
    "Compare with TCP: if UDP dominates, look for real-time applications "
    "or potential exfiltration over UDP."
};

static const annotation_t ann_tls_versions = {
    "Wireshark fields: tls.handshake, tls.record.version.",
    "TLS version distribution pie chart and table.",
    "TLS 1.0 and 1.1 are deprecated -- any presence indicates legacy systems "
    "that should be upgraded. A healthy network shows predominantly TLS 1.3. "
    "TLS 1.2 is still acceptable but watch cipher choices."
};

static const annotation_t ann_tls_certs = {
    "Wireshark fields: tls.handshake.extensions_server_name, x509 cert fields.",
    "Top SNI hostnames, certificate CN/expiry.",
    "SNIs identify which services are being accessed. Expired certificates "
    "cause connection failures and should be renewed. Certificates expiring "
    "within 30 days need attention."
};

static const annotation_t ann_mac_traffic = {
    "Wireshark fields: eth.src, eth.dst.",
    "Traffic type distribution: unicast / broadcast / multicast pie chart.",
    "The pie chart shows how much traffic is unicast (host-to-host) "
    "vs. broadcast (to all) vs. multicast (to groups). High broadcast "
    "ratios (>5%%) may indicate ARP storms, network discovery, or "
    "misconfigured devices."
};

static const annotation_t ann_mac_framesize = {
    "Wireshark field: frame.len.",
    "Frame size distribution bar chart by size ranges.",
    "Frame sizes reveal the workload type: many small frames (<128 B) suggest "
    "interactive traffic (SSH, gaming); frames near 1500 B indicate bulk "
    "transfers (backups, large downloads)."
};

static const annotation_t ann_ip_frag_proto = {
    "Wireshark fields: ip.proto, ip.flags.mf.",
    "IP fragmentation count, IP protocol distribution bar chart.",
    "IP fragmentation is rare on modern networks -- if present, it may indicate "
    "MTU mismatches or tunneling overhead. The protocol bar chart shows the "
    "transport-layer mix (TCP, UDP, ICMP, etc.)."
};

static const annotation_t ann_ip_ttl = {
    "Wireshark fields: ip.ttl, ip.dsfield.",
    "TTL distribution bar chart.",
    "TTL values hint at the OS and hop count: Linux defaults to 64, Windows "
    "to 128. Low TTL values reaching your network suggest many hops or "
    "TTL-based traceroute activity. DSCP values show QoS markings."
};

static const annotation_t ann_tcp_summary = {
    "Wireshark tap: tcp.analysis. Fields: tcp.flags.",
    "TCP summary table: segments, streams, SYN/FIN/RST counts.",
    "High RST counts indicate rejected connections (firewalls, closed ports). "
    "SYN without SYN-ACK suggests scanning. A healthy ratio is many FIN "
    "vs. few RST packets."
};

static const annotation_t ann_tcp_window = {
    "Wireshark field: tcp.window_size.",
    "TCP window size distribution bar chart.",
    "Window size distribution reveals receiver buffer capacity. Very small "
    "windows (<4 KB) cause throughput bottlenecks. Modern stacks use "
    "window scaling to advertise large windows (>64 KB)."
};

static const annotation_t ann_tcp_segment = {
    "Wireshark field: tcp.len.",
    "TCP segment size distribution bar chart.",
    "Segment sizes near MSS (typically 1460 bytes) indicate efficient bulk "
    "transfers. Many small segments suggest interactive or "
    "acknowledgment-heavy traffic."
};

char *pdf_export_annotated(const collection_result_t *result,
                           const reporter_config_t *cfg,
                           const paper_size_t *paper,
                           const char *out_path)
{
    char *path;
    cairo_surface_t *surface;
    cairo_t *cr;
    double y, y_section_top, y_ann_split;
    double margin     = 50.0;
    double full_w     = paper->width_pt - 2 * margin;
    double gap        = 10.0;
    double content_w  = full_w * 0.60 - gap / 2.0;
    double annot_x    = margin + content_w + gap;
    double annot_w    = full_w - content_w - gap;
    int    page_num   = 1;
    char   buf[128];

    const char *toc_titles[] = {
        "1. PCAP File Summary",
        "2. Top 10 IP Addresses",
        "3. Protocol Distribution",
        "4. IP Communication Matrix",
        "5. Port Analysis",
        "6. Protocol Hierarchy",
        "7. DNS Analysis",
        "8. TLS/SSL Analysis",
        "9. HTTP Analysis",
        "10. MAC Layer Analysis",
        "11. IP Layer Analysis",
        "12. TCP Analysis",
        "Summary",
    };
    int toc_pages[] = { 2, 3, 4, 5, 6, 7, 8, 9, 11, 12, 13, 14, 15 };
    int toc_count   = 13;

    path = make_output_path(out_path, paper->id == PAPER_A4
                            ? "annotated_A4" : "annotated_Legal");

    surface = cairo_pdf_surface_create(path,
                                       paper->width_pt,
                                       paper->height_pt);
    if (cairo_surface_status(surface) != CAIRO_STATUS_SUCCESS) {
        ws_log(WS_LOG_DOMAIN, LOG_LEVEL_WARNING,
               "Could not create PDF surface: %s", path);
        g_free(path);
        return NULL;
    }

    cr = cairo_create(surface);

    /* Macros for the annotated layout */
    #define ANN_NEW_PAGE(title) do { \
        cairo_set_source_rgb(cr, 1, 1, 1); cairo_paint(cr); \
        y = margin; \
        renderer_draw_section_header(cr, (title), margin, y, full_w); \
        y += 50; \
        y_section_top = y; \
        y_ann_split = y; \
    } while(0)

    #define ANN_SIDEBAR(ann_ptr) do { \
        draw_annotation_sidebar(cr, annot_x, y_section_top, annot_w, \
                                paper->height_pt - margin - 20, (ann_ptr)); \
    } while(0)

    #define ANN_SIDEBAR_RANGE(ann_ptr, ytop, ybot) do { \
        draw_annotation_sidebar(cr, annot_x, (ytop), annot_w, (ybot), (ann_ptr)); \
    } while(0)

    #define ANN_PAGE_END() do { \
        renderer_draw_page_footer(cr, paper, page_num); \
        cairo_show_page(cr); page_num++; \
    } while(0)

    #define ANN_TAG_DEST(dest_name) do { \
        char _attr[128]; \
        snprintf(_attr, sizeof(_attr), "name='%s'", (dest_name)); \
        cairo_tag_begin(cr, CAIRO_TAG_DEST, _attr); \
        cairo_tag_end(cr, CAIRO_TAG_DEST); \
    } while(0)

    /* ==== Cover ==== */
    renderer_draw_cover_page(cr, paper, cfg,
                             toc_titles, toc_pages, toc_count);
    cairo_show_page(cr);
    page_num++;

    /* ==== 1. PCAP File Summary (no annotation sidebar) ==== */
    ANN_NEW_PAGE("1. PCAP File Summary");
    ANN_TAG_DEST("section1");
    {
        file_summary_t fs = {0};
        if (result->capture_filename)
            fs = packet_collector_file_summary(result->capture_filename);

        #define AKV(label, value) do { \
            renderer_set_font(cr, "sans-serif", CAIRO_FONT_SLANT_NORMAL, \
                              CAIRO_FONT_WEIGHT_BOLD, 8.0); \
            cairo_set_source_rgb(cr, 0.3, 0.3, 0.3); \
            cairo_move_to(cr, margin, y); \
            cairo_show_text(cr, (label)); \
            renderer_set_font(cr, "sans-serif", CAIRO_FONT_SLANT_NORMAL, \
                              CAIRO_FONT_WEIGHT_NORMAL, 8.0); \
            cairo_set_source_rgb(cr, 0.15, 0.15, 0.15); \
            cairo_move_to(cr, margin + 120, y); \
            cairo_show_text(cr, (value)); \
            y += 13; \
        } while (0)

        #define AHEADING(text) do { \
            y += 4; \
            renderer_set_font(cr, "sans-serif", CAIRO_FONT_SLANT_NORMAL, \
                              CAIRO_FONT_WEIGHT_BOLD, 9.0); \
            cairo_set_source_rgb(cr, 0.17, 0.48, 0.71); \
            cairo_move_to(cr, margin, y); \
            cairo_show_text(cr, (text)); \
            y += 3; \
            cairo_set_source_rgb(cr, 0.8, 0.8, 0.8); \
            cairo_set_line_width(cr, 0.5); \
            cairo_move_to(cr, margin, y); \
            cairo_line_to(cr, margin + content_w, y); \
            cairo_stroke(cr); \
            y += 8; \
        } while (0)

        char vbuf[256];

        AHEADING("File");
        if (fs.filename)
            AKV("Name:", fs.filename);
        else if (result->capture_filename)
            AKV("Name:", result->capture_filename);
        if (fs.file_length > 0) {
            format_bytes_str(fs.file_length, buf, sizeof(buf));
            snprintf(vbuf, sizeof(vbuf), "%s (%" G_GUINT64_FORMAT " bytes)",
                     buf, fs.file_length);
            AKV("Length:", vbuf);
        }
        if (fs.sha256[0])
            AKV("Hash (SHA256):", fs.sha256);
        if (fs.file_format)
            AKV("Format:", fs.file_format);
        if (fs.encapsulation)
            AKV("Encapsulation:", fs.encapsulation);
        if (fs.snaplen > 0) {
            snprintf(vbuf, sizeof(vbuf), "%u bytes", fs.snaplen);
            AKV("Snapshot length:", vbuf);
        }

        AHEADING("Time");
        if (fs.first_packet_time > 0 || result->first_time > 0) {
            double t_val = fs.first_packet_time > 0
                ? fs.first_packet_time : result->first_time;
            time_t t = (time_t)t_val;
            struct tm *tm_p = localtime(&t);
            if (tm_p) strftime(vbuf, sizeof(vbuf), "%Y-%m-%d %H:%M:%S", tm_p);
            else g_snprintf(vbuf, sizeof(vbuf), "Unknown");
            AKV("First packet:", vbuf);
        }
        if (fs.last_packet_time > 0 || result->last_time > 0) {
            double t_val = fs.last_packet_time > 0
                ? fs.last_packet_time : result->last_time;
            time_t t = (time_t)t_val;
            struct tm *tm_p = localtime(&t);
            if (tm_p) strftime(vbuf, sizeof(vbuf), "%Y-%m-%d %H:%M:%S", tm_p);
            else g_snprintf(vbuf, sizeof(vbuf), "Unknown");
            AKV("Last packet:", vbuf);
        }
        {
            double dur = result->duration;
            int hours = (int)(dur / 3600.0);
            int mins  = (int)(fmod(dur, 3600.0) / 60.0);
            double secs = fmod(dur, 60.0);
            snprintf(vbuf, sizeof(vbuf), "%02d:%02d:%05.2f", hours, mins, secs);
            AKV("Elapsed:", vbuf);
        }

        AHEADING("Statistics");
        snprintf(vbuf, sizeof(vbuf), "%" G_GUINT64_FORMAT, result->total_packets);
        AKV("Packets:", vbuf);
        format_bytes_str(result->total_bytes, buf, sizeof(buf));
        snprintf(vbuf, sizeof(vbuf), "%s (%" G_GUINT64_FORMAT " bytes)",
                 buf, result->total_bytes);
        AKV("Bytes:", vbuf);
        if (result->total_packets > 0) {
            snprintf(vbuf, sizeof(vbuf), "%.0f B",
                     (double)result->total_bytes / result->total_packets);
            AKV("Avg packet size:", vbuf);
        }
        if (result->duration > 0) {
            snprintf(vbuf, sizeof(vbuf), "%.1f",
                     (double)result->total_packets / result->duration);
            AKV("Avg packets/s:", vbuf);
            format_bytes_str((guint64)((double)result->total_bytes / result->duration),
                             buf, sizeof(buf));
            snprintf(vbuf, sizeof(vbuf), "%s/s", buf);
            AKV("Avg throughput:", vbuf);
        }

        AHEADING("Capture Overview");
        snprintf(vbuf, sizeof(vbuf), "%u", g_hash_table_size(result->ip_table));
        AKV("Unique IPs:", vbuf);
        snprintf(vbuf, sizeof(vbuf), "%u", g_hash_table_size(result->protocol_table));
        AKV("Protocols:", vbuf);
        snprintf(vbuf, sizeof(vbuf), "%u TCP / %u UDP",
                 g_hash_table_size(result->tcp_port_table),
                 g_hash_table_size(result->udp_port_table));
        AKV("Ports seen:", vbuf);

        #undef AKV
        #undef AHEADING

        packet_collector_free_file_summary(&fs);
    }
    ANN_PAGE_END();

    /* ==== 2. Top 10 IP Addresses ==== */
    ANN_NEW_PAGE("2. Top 10 IP Addresses");
    ANN_TAG_DEST("section2");
    {
        GList *top_ips = collector_top_ips_by_packets(
                             (collection_result_t *)result, 10);
        int count = (int)g_list_length(top_ips);
        if (count > 0) {
            bar_item_t *items = g_new0(bar_item_t, count);
            GList *l; int i;
            for (l = top_ips, i = 0; l; l = l->next, i++) {
                ip_stats_t *ip = (ip_stats_t *)l->data;
                items[i].label = ip->address;
                items[i].value = (double)(ip->packets_src + ip->packets_dst);
            }
            renderer_draw_bar_chart(cr, "Top 10 IP Addresses (by packets)",
                                    items, count,
                                    margin, y, content_w - 28, 250);
            g_free(items);
            y += 268;

            y_ann_split = y;

            const char *hdrs[] = {"#", "IP Address", "Src", "Dst", "Total"};
            char ***rows = (char ***)g_new0(gpointer, count);
            for (l = top_ips, i = 0; l; l = l->next, i++) {
                ip_stats_t *ip = (ip_stats_t *)l->data;
                rows[i] = (char **)g_new0(gpointer, 5);
                rows[i][0] = g_strdup_printf("%d", i + 1);
                rows[i][1] = g_strdup(ip->address);
                rows[i][2] = g_strdup_printf("%" G_GUINT64_FORMAT, ip->packets_src);
                rows[i][3] = g_strdup_printf("%" G_GUINT64_FORMAT, ip->packets_dst);
                rows[i][4] = g_strdup_printf("%" G_GUINT64_FORMAT,
                                             ip->packets_src + ip->packets_dst);
            }
            table_def_t tbl = {hdrs, 5, (const char ***)rows, count};
            renderer_draw_table(cr, NULL, &tbl, margin, y, content_w - 28);
            for (i = 0; i < count; i++) {
                for (int c = 0; c < 5; c++) g_free(rows[i][c]);
                g_free(rows[i]);
            }
            g_free(rows);
        }
        g_list_free(top_ips);
    }
    ANN_SIDEBAR_RANGE(&ann_ip_chart, y_section_top, y_ann_split - 4);
    ANN_SIDEBAR_RANGE(&ann_ip_table, y_ann_split, paper->height_pt - margin - 20);
    ANN_PAGE_END();

    /* ==== 3. Protocol Distribution ==== */
    ANN_NEW_PAGE("3. Protocol Distribution");
    ANN_TAG_DEST("section3");
    {
        GList *top_protos = collector_top_protocols(
                                (collection_result_t *)result, 10);
        int count = (int)g_list_length(top_protos);
        if (count > 0) {
            pie_item_t *items = g_new0(pie_item_t, count);
            GList *l; int i;
            for (l = top_protos, i = 0; l; l = l->next, i++) {
                protocol_entry_t *pe = (protocol_entry_t *)l->data;
                items[i].label = pe->name;
                items[i].value = (double)pe->count;
            }
            renderer_draw_pie_chart(cr, "Top Protocols",
                                    items, count,
                                    margin, y, content_w, 250);
            g_free(items);
            y += 268;

            y_ann_split = y;

            const char *hdrs[] = {"#", "Protocol", "Packets", "%"};
            char ***rows = (char ***)g_new0(gpointer, count);
            for (l = top_protos, i = 0; l; l = l->next, i++) {
                protocol_entry_t *pe = (protocol_entry_t *)l->data;
                rows[i] = (char **)g_new0(gpointer, 4);
                rows[i][0] = g_strdup_printf("%d", i + 1);
                rows[i][1] = g_strdup(pe->name);
                rows[i][2] = g_strdup_printf("%" G_GUINT64_FORMAT, pe->count);
                rows[i][3] = g_strdup_printf("%.1f%%",
                    result->total_packets > 0
                        ? (double)pe->count / result->total_packets * 100.0
                        : 0.0);
            }
            table_def_t tbl = {hdrs, 4, (const char ***)rows, count};
            renderer_draw_table(cr, NULL, &tbl, margin, y, content_w);
            for (i = 0; i < count; i++) {
                for (int c = 0; c < 4; c++) g_free(rows[i][c]);
                g_free(rows[i]);
            }
            g_free(rows);
        }
        g_list_free(top_protos);
    }
    ANN_SIDEBAR_RANGE(&ann_proto_chart, y_section_top, y_ann_split - 4);
    ANN_SIDEBAR_RANGE(&ann_proto_table, y_ann_split, paper->height_pt - margin - 20);
    ANN_PAGE_END();

    /* ==== 4. IP Communication Matrix — full width, annotation at bottom ==== */
    ANN_NEW_PAGE("4. IP Communication Matrix");
    ANN_TAG_DEST("section4");
    {
        GList *top_pairs = collector_top_comm_pairs(
                               (collection_result_t *)result, 30);
        int pair_count = (int)g_list_length(top_pairs);
        GPtrArray *unique_ips = g_ptr_array_new();
        int unique_connections = 0;
        GList *used_pairs = NULL;
        {
            GList *l;
            for (l = top_pairs; l && unique_connections < 10; l = l->next) {
                comm_pair_t *cp = (comm_pair_t *)l->data;
                gboolean already = FALSE;
                GList *u;
                for (u = used_pairs; u; u = u->next) {
                    comm_pair_t *prev = (comm_pair_t *)u->data;
                    if (g_strcmp0(prev->src, cp->dst) == 0 &&
                        g_strcmp0(prev->dst, cp->src) == 0) {
                        already = TRUE; break;
                    }
                }
                if (already) continue;
                used_pairs = g_list_prepend(used_pairs, cp);
                unique_connections++;
                gboolean found_s = FALSE, found_d = FALSE;
                for (guint k = 0; k < unique_ips->len; k++) {
                    if (g_strcmp0(cp->src, (char *)unique_ips->pdata[k]) == 0) found_s = TRUE;
                    if (g_strcmp0(cp->dst, (char *)unique_ips->pdata[k]) == 0) found_d = TRUE;
                }
                if (!found_s) g_ptr_array_add(unique_ips, cp->src);
                if (!found_d) g_ptr_array_add(unique_ips, cp->dst);
            }
        }
        int num_nodes = (int)unique_ips->len;

        double ann_bottom_h = 110;
        double chart_avail = paper->height_pt - margin - y - ann_bottom_h - 30;

        if (num_nodes >= 2 && pair_count > 0 && result->comm_pair_table) {
            const char **labels = (const char **)g_new0(gpointer, num_nodes);
            int i;
            for (i = 0; i < num_nodes; i++)
                labels[i] = (const char *)unique_ips->pdata[i];

            guint64 *mx = g_new0(guint64, num_nodes * num_nodes);
            {
                GHashTableIter hiter;
                gpointer hkey, hval;
                g_hash_table_iter_init(&hiter, result->comm_pair_table);
                while (g_hash_table_iter_next(&hiter, &hkey, &hval)) {
                    comm_pair_t *cp = (comm_pair_t *)hval;
                    int si = -1, di = -1;
                    for (i = 0; i < num_nodes; i++) {
                        if (si < 0 && g_strcmp0(cp->src, labels[i]) == 0) si = i;
                        if (di < 0 && g_strcmp0(cp->dst, labels[i]) == 0) di = i;
                    }
                    if (si >= 0 && di >= 0 && si != di)
                        mx[si * num_nodes + di] += cp->packets;
                }
            }
            renderer_draw_chord_diagram(cr,
                "IP Communications (Top 10 Pairs)",
                labels, num_nodes, mx,
                margin, y, full_w, chart_avail);
            g_free(mx);
            g_free(labels);
        } else {
            renderer_set_font(cr, "sans-serif", CAIRO_FONT_SLANT_ITALIC,
                              CAIRO_FONT_WEIGHT_NORMAL, 9.0);
            cairo_set_source_rgb(cr, 0.5, 0.5, 0.5);
            cairo_move_to(cr, margin, y);
            cairo_show_text(cr, "Not enough communication pairs.");
        }
        g_list_free(used_pairs);
        g_list_free(top_pairs);
        g_ptr_array_free(unique_ips, TRUE);

        /* Annotation box at the bottom of the page */
        double ann_y = paper->height_pt - margin - 20 - ann_bottom_h;
        draw_annotation_sidebar(cr, margin, ann_y, full_w, paper->height_pt - margin - 20,
                                &ann_matrix);
    }
    ANN_PAGE_END();

    /* ==== 5. Port Analysis (separate TCP/UDP annotations) ==== */
    ANN_NEW_PAGE("5. Port Analysis");
    ANN_TAG_DEST("section5");
    {
        GList *top_tcp = collector_top_tcp_ports((collection_result_t *)result, 5);
        int count = (int)g_list_length(top_tcp);
        if (count > 0) {
            bar_item_t *items = g_new0(bar_item_t, count);
            GList *l; int i;
            static char tcp_lbl[10][32];
            for (l = top_tcp, i = 0; l; l = l->next, i++) {
                port_entry_t *pe = (port_entry_t *)l->data;
                snprintf(tcp_lbl[i], sizeof(tcp_lbl[i]), "TCP/%u", pe->port);
                items[i].label = tcp_lbl[i];
                items[i].value = (double)pe->count;
            }
            renderer_draw_bar_chart(cr, "Top 5 TCP Ports",
                                    items, count, margin, y, content_w, 200);
            g_free(items);
            y += 215;
        }
        g_list_free(top_tcp);
    }
    y_ann_split = y;
    {
        GList *top_udp = collector_top_udp_ports((collection_result_t *)result, 5);
        int count = (int)g_list_length(top_udp);
        if (count > 0) {
            bar_item_t *items = g_new0(bar_item_t, count);
            GList *l; int i;
            static char udp_lbl[10][32];
            for (l = top_udp, i = 0; l; l = l->next, i++) {
                port_entry_t *pe = (port_entry_t *)l->data;
                snprintf(udp_lbl[i], sizeof(udp_lbl[i]), "UDP/%u", pe->port);
                items[i].label = udp_lbl[i];
                items[i].value = (double)pe->count;
            }
            renderer_draw_bar_chart(cr, "Top 5 UDP Ports",
                                    items, count, margin, y, content_w, 200);
            g_free(items);
        }
        g_list_free(top_udp);
    }
    ANN_SIDEBAR_RANGE(&ann_port_tcp, y_section_top, y_ann_split - 4);
    ANN_SIDEBAR_RANGE(&ann_port_udp, y_ann_split, paper->height_pt - margin - 20);
    ANN_PAGE_END();

    /* ==== 6. Protocol Hierarchy ==== */
    ANN_NEW_PAGE("6. Protocol Hierarchy");
    ANN_TAG_DEST("section6");
    {
        GList *rows = collector_flatten_proto_hierarchy(
                          (collection_result_t *)result, 7, 0.5);
        int count = (int)g_list_length(rows);
        if (count > 0) {
            double row_h = 14.0, indent_w = 12.0;
            double bar_max = 60.0, bar_h = 9.0;
            double bar_x0 = margin + 120.0;
            double pkt_x = bar_x0 + bar_max + 4.0;
            double pct_x = pkt_x + 45.0;

            renderer_set_font(cr, "sans-serif", CAIRO_FONT_SLANT_NORMAL,
                              CAIRO_FONT_WEIGHT_BOLD, 7.0);
            cairo_set_source_rgb(cr, 0.4, 0.4, 0.4);
            cairo_move_to(cr, margin + 4, y);
            cairo_show_text(cr, "Protocol");
            cairo_move_to(cr, bar_x0, y);
            cairo_show_text(cr, "Distribution");
            cairo_move_to(cr, pkt_x, y);
            cairo_show_text(cr, "Packets");
            cairo_move_to(cr, pct_x, y);
            cairo_show_text(cr, "%");
            y += 5;

            cairo_set_source_rgb(cr, 0.8, 0.8, 0.8);
            cairo_set_line_width(cr, 0.5);
            cairo_move_to(cr, margin, y);
            cairo_line_to(cr, margin + content_w, y);
            cairo_stroke(cr);
            y += 6;

            double max_y = paper->height_pt - 60;
            GList *l;
            for (l = rows; l; l = l->next) {
                proto_hier_row_t *row = (proto_hier_row_t *)l->data;
                if (y + row_h > max_y) break;

                double x0 = margin + (row->depth - 1) * indent_w;

                if (row->depth > 1) {
                    cairo_set_source_rgb(cr, 0.7, 0.7, 0.7);
                    cairo_set_line_width(cr, 0.8);
                    double cx = x0 - indent_w + 5;
                    double cy = y - 2;
                    cairo_move_to(cr, cx, cy - row_h * 0.4);
                    cairo_line_to(cr, cx, cy);
                    cairo_line_to(cr, cx + indent_w - 5, cy);
                    cairo_stroke(cr);
                }

                renderer_set_font(cr, "sans-serif", CAIRO_FONT_SLANT_NORMAL,
                    row->depth <= 1 ? CAIRO_FONT_WEIGHT_BOLD : CAIRO_FONT_WEIGHT_NORMAL,
                    row->depth <= 1 ? 7.5 : 7.0);
                cairo_set_source_rgb(cr, 0.15, 0.15, 0.15);
                cairo_move_to(cr, x0 + 3, y);
                cairo_show_text(cr, row->name);

                double bar_w = bar_max * (row->pct / 100.0);
                if (bar_w < 1.0) bar_w = 1.0;
                int cidx = (row->depth - 1) % 10;
                cairo_set_source_rgba(cr, CHART_PALETTE[cidx].r,
                    CHART_PALETTE[cidx].g, CHART_PALETTE[cidx].b, 0.75);
                cairo_rectangle(cr, bar_x0, y - bar_h + 2, bar_w, bar_h);
                cairo_fill(cr);
                cairo_set_source_rgb(cr, 0.85, 0.85, 0.85);
                cairo_set_line_width(cr, 0.4);
                cairo_rectangle(cr, bar_x0, y - bar_h + 2, bar_max, bar_h);
                cairo_stroke(cr);

                renderer_set_font(cr, "sans-serif", CAIRO_FONT_SLANT_NORMAL,
                                  CAIRO_FONT_WEIGHT_NORMAL, 6.5);
                cairo_set_source_rgb(cr, 0.3, 0.3, 0.3);
                {
                    char pbuf[32];
                    snprintf(pbuf, sizeof(pbuf), "%" G_GUINT64_FORMAT, row->packets);
                    cairo_move_to(cr, pkt_x, y);
                    cairo_show_text(cr, pbuf);
                    snprintf(pbuf, sizeof(pbuf), "%.1f%%", row->pct);
                    cairo_move_to(cr, pct_x, y);
                    cairo_show_text(cr, pbuf);
                }
                y += row_h;
            }

            for (l = rows; l; l = l->next) {
                proto_hier_row_t *row = (proto_hier_row_t *)l->data;
                g_free(row->name);
                g_free(row);
            }
        } else {
            renderer_set_font(cr, "sans-serif", CAIRO_FONT_SLANT_ITALIC,
                              CAIRO_FONT_WEIGHT_NORMAL, 9.0);
            cairo_set_source_rgb(cr, 0.5, 0.5, 0.5);
            cairo_move_to(cr, margin, y);
            cairo_show_text(cr, "No protocol hierarchy data available.");
        }
        g_list_free(rows);
    }
    ANN_SIDEBAR(&ann_proto_hierarchy);
    ANN_PAGE_END();

    /* ==== 7. DNS Analysis ==== */
    ANN_NEW_PAGE("7. DNS Analysis");
    ANN_TAG_DEST("section7");
    {
        GList *top_dns = collector_top_dns_queries(
                             (collection_result_t *)result, 10);
        int count = (int)g_list_length(top_dns);
        if (count > 0) {
            const char *hdrs[] = {"#", "Domain", "Queries"};
            char ***rows = (char ***)g_new0(gpointer, count);
            GList *l; int i;
            for (l = top_dns, i = 0; l; l = l->next, i++) {
                dns_query_t *q = (dns_query_t *)l->data;
                rows[i] = (char **)g_new0(gpointer, 3);
                rows[i][0] = g_strdup_printf("%d", i + 1);
                rows[i][1] = g_strdup(q->name);
                rows[i][2] = g_strdup_printf("%" G_GUINT64_FORMAT, q->count);
            }
            table_def_t tbl = {hdrs, 3, (const char ***)rows, count};
            renderer_draw_table(cr, "Top 10 DNS Queries", &tbl,
                                margin, y, content_w);
            y += (count + 2) * 18 + 16;
            for (i = 0; i < count; i++) {
                g_free(rows[i][0]); g_free(rows[i][1]); g_free(rows[i][2]);
                g_free(rows[i]);
            }
            g_free(rows);
        } else {
            renderer_set_font(cr, "sans-serif", CAIRO_FONT_SLANT_ITALIC,
                              CAIRO_FONT_WEIGHT_NORMAL, 9.0);
            cairo_set_source_rgb(cr, 0.5, 0.5, 0.5);
            cairo_move_to(cr, margin, y);
            cairo_show_text(cr, "No DNS traffic detected.");
        }
        g_list_free(top_dns);

        renderer_set_font(cr, "sans-serif", CAIRO_FONT_SLANT_NORMAL,
                          CAIRO_FONT_WEIGHT_NORMAL, 8.0);
        cairo_set_source_rgb(cr, 0.2, 0.2, 0.2);
        snprintf(buf, sizeof(buf),
                 "Queries: %" G_GUINT64_FORMAT "  Responses: %" G_GUINT64_FORMAT
                 "  Authoritative: %" G_GUINT64_FORMAT,
                 result->dns_total_queries,
                 result->dns_total_responses,
                 result->dns_authoritative);
        cairo_move_to(cr, margin, y);
        cairo_show_text(cr, buf);
    }
    ANN_SIDEBAR(&ann_dns);
    ANN_PAGE_END();

    /* ==== 8. TLS/SSL Analysis (version + ciphers page) ==== */
    ANN_NEW_PAGE("8. TLS/SSL Analysis");
    ANN_TAG_DEST("section8");
    {
        renderer_set_font(cr, "sans-serif", CAIRO_FONT_SLANT_NORMAL,
                          CAIRO_FONT_WEIGHT_NORMAL, 8.0);
        cairo_set_source_rgb(cr, 0.2, 0.2, 0.2);

        snprintf(buf, sizeof(buf), "TLS Handshakes: %" G_GUINT64_FORMAT
                 "   SNIs: %u   Certificates: %u",
                 result->tls_handshakes,
                 g_hash_table_size(result->tls_sni_table),
                 g_hash_table_size(result->tls_cert_table));
        cairo_move_to(cr, margin, y);
        cairo_show_text(cr, buf);
        y += 18;

        GList *tls_versions = collector_all_tls_versions(
                                  (collection_result_t *)result);
        int ver_count = (int)g_list_length(tls_versions);
        if (ver_count > 0) {
            pie_item_t *vitems = g_new0(pie_item_t, ver_count);
            GList *l; int idx = 0;
            for (l = tls_versions; l; l = l->next, idx++) {
                tls_version_t *v = (tls_version_t *)l->data;
                vitems[idx].label = collector_tls_version_name(v->version);
                vitems[idx].value = (double)v->count;
            }
            renderer_draw_pie_chart(cr, "TLS Version Distribution",
                                    vitems, ver_count,
                                    margin, y, content_w, 220);
            g_free(vitems);
            y += 236;

            /* Version table */
            {
                guint64 total_ver = 0;
                for (l = tls_versions; l; l = l->next)
                    total_ver += ((tls_version_t *)l->data)->count;
                const char *vhdrs[] = {"Version", "Count", "%"};
                char ***vrows = (char ***)g_new0(gpointer, ver_count);
                idx = 0;
                for (l = tls_versions; l; l = l->next, idx++) {
                    tls_version_t *v = (tls_version_t *)l->data;
                    double pct = total_ver ? 100.0 * v->count / total_ver : 0;
                    vrows[idx] = (char **)g_new0(gpointer, 3);
                    vrows[idx][0] = g_strdup(collector_tls_version_name(v->version));
                    vrows[idx][1] = g_strdup_printf("%" G_GUINT64_FORMAT, v->count);
                    vrows[idx][2] = g_strdup_printf("%.1f%%", pct);
                }
                table_def_t vtbl = {vhdrs, 3, (const char ***)vrows, ver_count};
                renderer_draw_table(cr, NULL, &vtbl, margin, y, content_w);
                for (idx = 0; idx < ver_count; idx++) {
                    for (int c = 0; c < 3; c++) g_free(vrows[idx][c]);
                    g_free(vrows[idx]);
                }
                g_free(vrows);
            }
            g_list_free(tls_versions);
        } else {
            renderer_set_font(cr, "sans-serif", CAIRO_FONT_SLANT_ITALIC,
                              CAIRO_FONT_WEIGHT_NORMAL, 9.0);
            cairo_set_source_rgb(cr, 0.5, 0.5, 0.5);
            cairo_move_to(cr, margin, y);
            cairo_show_text(cr, "No TLS traffic detected.");
        }
    }
    ANN_SIDEBAR(&ann_tls_versions);
    ANN_PAGE_END();

    /* ==== 8 cont. — SNIs + Certs ==== */
    ANN_NEW_PAGE("8. TLS/SSL Analysis (cont.)");
    {
        GList *snis = collector_top_tls_snis((collection_result_t *)result, 15);
        int sni_count = (int)g_list_length(snis);
        if (sni_count > 0) {
            int nrows = MIN(sni_count, 15);
            const char *shdrs[] = {"#", "Server Name (SNI)", "Count"};
            char ***srows = (char ***)g_new0(gpointer, nrows);
            GList *l; int idx = 0;
            for (l = snis; l && idx < nrows; l = l->next, idx++) {
                tls_sni_t *s = (tls_sni_t *)l->data;
                srows[idx] = (char **)g_new0(gpointer, 3);
                srows[idx][0] = g_strdup_printf("%d", idx + 1);
                srows[idx][1] = g_strdup(s->sni);
                srows[idx][2] = g_strdup_printf("%" G_GUINT64_FORMAT, s->count);
            }
            table_def_t stbl = {shdrs, 3, (const char ***)srows, nrows};
            renderer_draw_table(cr, "Top Server Names (SNI)",
                                &stbl, margin, y, content_w);
            y += (nrows + 2) * 18 + 16;
            for (int i = 0; i < nrows; i++) {
                for (int c = 0; c < 3; c++) g_free(srows[i][c]);
                g_free(srows[i]);
            }
            g_free(srows);
        }
        g_list_free(snis);

        GList *certs = collector_all_tls_certs((collection_result_t *)result);
        int cert_count = (int)g_list_length(certs);
        if (cert_count > 0) {
            int nrows = MIN(cert_count, 12);
            double capture_time = result->last_time;
            const char *certhdrs[] = {"Domain", "Expiry", "Status"};
            char ***certrows = (char ***)g_new0(gpointer, nrows);
            GList *l; int idx = 0;
            for (l = certs; l && idx < nrows; l = l->next, idx++) {
                tls_cert_t *ct = (tls_cert_t *)l->data;
                certrows[idx] = (char **)g_new0(gpointer, 3);
                certrows[idx][0] = g_strdup(ct->cn);
                if (ct->not_after > 0.0) {
                    time_t t = (time_t)ct->not_after;
                    struct tm *tm_p = gmtime(&t);
                    char datebuf[32];
                    if (tm_p) strftime(datebuf, sizeof(datebuf), "%Y-%m-%d", tm_p);
                    else g_snprintf(datebuf, sizeof(datebuf), "N/A");
                    certrows[idx][1] = g_strdup(datebuf);
                    if (ct->not_after < capture_time)
                        certrows[idx][2] = g_strdup("EXPIRED");
                    else if (ct->not_after < capture_time + 30 * 86400)
                        certrows[idx][2] = g_strdup("< 30d");
                    else
                        certrows[idx][2] = g_strdup("Valid");
                } else {
                    certrows[idx][1] = g_strdup("N/A");
                    certrows[idx][2] = g_strdup("N/A");
                }
            }
            table_def_t certtbl = {certhdrs, 3, (const char ***)certrows, nrows};
            renderer_draw_table(cr, "Certificate Summary",
                                &certtbl, margin, y, content_w);
            for (int i = 0; i < nrows; i++) {
                for (int c = 0; c < 3; c++) g_free(certrows[i][c]);
                g_free(certrows[i]);
            }
            g_free(certrows);
        }
        g_list_free(certs);
    }
    ANN_SIDEBAR(&ann_tls_certs);
    ANN_PAGE_END();

    /* ==== 9. HTTP Analysis ==== */
    ANN_NEW_PAGE("9. HTTP Analysis");
    ANN_TAG_DEST("section9");
    {
        GList *top_hosts = collector_top_http_hosts(
                               (collection_result_t *)result, 10);
        int count = (int)g_list_length(top_hosts);
        if (count > 0) {
            const char *hdrs[] = {"#", "Host", "Requests"};
            char ***rows = (char ***)g_new0(gpointer, count);
            GList *l; int i;
            for (l = top_hosts, i = 0; l; l = l->next, i++) {
                http_host_t *h = (http_host_t *)l->data;
                rows[i] = (char **)g_new0(gpointer, 3);
                rows[i][0] = g_strdup_printf("%d", i + 1);
                rows[i][1] = g_strdup(h->host);
                rows[i][2] = g_strdup_printf("%" G_GUINT64_FORMAT, h->count);
            }
            table_def_t tbl = {hdrs, 3, (const char ***)rows, count};
            renderer_draw_table(cr, "Top 10 HTTP Hosts", &tbl,
                                margin, y, content_w);
            y += (count + 2) * 18 + 20;
            for (i = 0; i < count; i++) {
                g_free(rows[i][0]); g_free(rows[i][1]); g_free(rows[i][2]);
                g_free(rows[i]);
            }
            g_free(rows);
        } else {
            renderer_set_font(cr, "sans-serif", CAIRO_FONT_SLANT_ITALIC,
                              CAIRO_FONT_WEIGHT_NORMAL, 9.0);
            cairo_set_source_rgb(cr, 0.5, 0.5, 0.5);
            cairo_move_to(cr, margin, y);
            cairo_show_text(cr, "No HTTP traffic detected.");
            y += 16;
        }
        g_list_free(top_hosts);

        GList *top_status = collector_top_http_status(
                                (collection_result_t *)result, 10);
        int scount = (int)g_list_length(top_status);
        if (scount > 0) {
            bar_item_t *items = g_new0(bar_item_t, scount);
            GList *l; int i;
            static char stlbl[10][16];
            for (l = top_status, i = 0; l; l = l->next, i++) {
                http_status_t *st = (http_status_t *)l->data;
                snprintf(stlbl[i], sizeof(stlbl[i]), "%u", st->code);
                items[i].label = stlbl[i];
                items[i].value = (double)st->count;
            }
            renderer_draw_bar_chart(cr, "HTTP Status Codes",
                                    items, scount, margin, y, content_w, 200);
            g_free(items);
        }
        g_list_free(top_status);
    }
    ANN_SIDEBAR(&ann_http);
    ANN_PAGE_END();

    /* ==== 10. MAC Layer Analysis (two annotation frames) ==== */
    ANN_NEW_PAGE("10. MAC Layer Analysis");
    ANN_TAG_DEST("section10");
    {
        pie_item_t items[3]; int n = 0;
        if (result->mac_unicast > 0)   { items[n].label = "Unicast";   items[n].value = (double)result->mac_unicast;   n++; }
        if (result->mac_broadcast > 0) { items[n].label = "Broadcast"; items[n].value = (double)result->mac_broadcast; n++; }
        if (result->mac_multicast > 0) { items[n].label = "Multicast"; items[n].value = (double)result->mac_multicast; n++; }
        if (n > 0)
            renderer_draw_pie_chart(cr, "Traffic Type",
                                    items, n, margin, y, content_w, 190);
        y += 205;

        y_ann_split = y;

        bar_item_t fitems[FRAME_SIZE_BUCKETS]; int fn = 0;
        for (int i = 0; i < FRAME_SIZE_BUCKETS; i++) {
            if (result->frame_size_counts[i] > 0) {
                fitems[fn].label = collector_frame_size_label(i);
                fitems[fn].value = (double)result->frame_size_counts[i];
                fn++;
            }
        }
        if (fn > 0)
            renderer_draw_bar_chart(cr, "Frame Size Distribution",
                                    fitems, fn, margin, y, content_w, 190);
    }
    ANN_SIDEBAR_RANGE(&ann_mac_traffic, y_section_top, y_ann_split - 4);
    ANN_SIDEBAR_RANGE(&ann_mac_framesize, y_ann_split, paper->height_pt - margin - 20);
    ANN_PAGE_END();

    /* ==== 11. IP Layer Analysis (two annotation frames) ==== */
    ANN_NEW_PAGE("11. IP Layer Analysis");
    ANN_TAG_DEST("section11");
    {
        renderer_set_font(cr, "sans-serif", CAIRO_FONT_SLANT_NORMAL,
                          CAIRO_FONT_WEIGHT_NORMAL, 8.0);
        cairo_set_source_rgb(cr, 0.2, 0.2, 0.2);
        if (result->ip_fragmented > 0) {
            double frag_rate = result->total_packets > 0
                ? (double)result->ip_fragmented / result->total_packets * 100.0 : 0;
            snprintf(buf, sizeof(buf), "Fragmented: %" G_GUINT64_FORMAT " (%.1f%%)",
                     result->ip_fragmented, frag_rate);
        } else {
            snprintf(buf, sizeof(buf), "No IP fragmentation detected.");
        }
        cairo_move_to(cr, margin, y);
        cairo_show_text(cr, buf);
        y += 18;

        /* IP protocol bar */
        {
            GHashTableIter iter; gpointer key, value;
            GPtrArray *protos = g_ptr_array_new();
            if (result->ip_proto_table) {
                g_hash_table_iter_init(&iter, result->ip_proto_table);
                while (g_hash_table_iter_next(&iter, &key, &value))
                    g_ptr_array_add(protos, key);
            }
            if (protos->len > 0) {
                int n = MIN((int)protos->len, 8);
                bar_item_t *items = g_new0(bar_item_t, n);
                for (int i = 0; i < n; i++) {
                    guint64 best_cnt = 0; int best_j = i;
                    for (guint j = i; j < protos->len; j++) {
                        guint64 *c = (guint64 *)g_hash_table_lookup(
                            result->ip_proto_table, protos->pdata[j]);
                        if (c && *c > best_cnt) { best_cnt = *c; best_j = j; }
                    }
                    gpointer tmp = protos->pdata[i];
                    protos->pdata[i] = protos->pdata[best_j];
                    protos->pdata[best_j] = tmp;
                    guint pn = GPOINTER_TO_UINT(protos->pdata[i]);
                    guint64 *c = (guint64 *)g_hash_table_lookup(
                        result->ip_proto_table, protos->pdata[i]);
                    items[i].label = collector_ip_proto_name(pn);
                    items[i].value = c ? (double)*c : 0;
                }
                renderer_draw_bar_chart(cr, "IP Protocol Distribution",
                                        items, n, margin, y, content_w, 180);
                g_free(items);
                y += 195;
            }
            g_ptr_array_free(protos, TRUE);
        }

        y_ann_split = y;

        /* TTL distribution */
        {
            GHashTableIter iter; gpointer key, value;
            guint64 ttl_buckets[8] = {0};
            if (result->ip_ttl_table) {
                g_hash_table_iter_init(&iter, result->ip_ttl_table);
                while (g_hash_table_iter_next(&iter, &key, &value)) {
                    guint ttl = GPOINTER_TO_UINT(key);
                    guint64 cnt = *(guint64 *)value;
                    int b;
                    if      (ttl <= 1)   b = 0;
                    else if (ttl < 32)   b = 1;
                    else if (ttl == 32)  b = 2;
                    else if (ttl < 64)   b = 3;
                    else if (ttl == 64)  b = 4;
                    else if (ttl < 128)  b = 5;
                    else if (ttl == 128) b = 6;
                    else                 b = 7;
                    ttl_buckets[b] += cnt;
                }
            }
            static const char *ttl_labels[8] = {
                "1", "2-31", "32", "33-63", "64", "65-127", "128", "129-255"
            };
            bar_item_t titems[8]; int tn = 0;
            for (int i = 0; i < 8; i++) {
                if (ttl_buckets[i] > 0) {
                    titems[tn].label = ttl_labels[i];
                    titems[tn].value = (double)ttl_buckets[i];
                    tn++;
                }
            }
            if (tn > 0)
                renderer_draw_bar_chart(cr, "TTL Distribution",
                                        titems, tn, margin, y, content_w, 180);
        }
    }
    ANN_SIDEBAR_RANGE(&ann_ip_frag_proto, y_section_top, y_ann_split - 4);
    ANN_SIDEBAR_RANGE(&ann_ip_ttl, y_ann_split, paper->height_pt - margin - 20);
    ANN_PAGE_END();

    /* ==== 12. TCP Analysis (three annotation frames) ==== */
    ANN_NEW_PAGE("12. TCP Analysis");
    ANN_TAG_DEST("section12");
    {
        if (result->tcp_total_segments == 0) {
            renderer_set_font(cr, "sans-serif", CAIRO_FONT_SLANT_ITALIC,
                              CAIRO_FONT_WEIGHT_NORMAL, 9.0);
            cairo_set_source_rgb(cr, 0.5, 0.5, 0.5);
            cairo_move_to(cr, margin, y);
            cairo_show_text(cr, "No TCP traffic detected.");
            ANN_PAGE_END();
            goto ann_tcp_done;
        }

        double y_tcp_sum_top = y;

        /* TCP Summary table */
        {
            const char *thdrs[] = {"Metric", "Value"};
            char **metric_rows[10];
            char row_buf[10][2][64];
            int nrows = 0;

            #define ATCP(label, fmt, ...) do { \
                snprintf(row_buf[nrows][0], 64, "%s", (label)); \
                snprintf(row_buf[nrows][1], 64, fmt, __VA_ARGS__); \
                metric_rows[nrows] = (char **)g_new0(gpointer, 2); \
                metric_rows[nrows][0] = row_buf[nrows][0]; \
                metric_rows[nrows][1] = row_buf[nrows][1]; \
                nrows++; \
            } while(0)

            ATCP("Total Segments", "%" G_GUINT64_FORMAT, result->tcp_total_segments);
            ATCP("Unique Streams", "%u",
                 result->tcp_streams ? g_hash_table_size(result->tcp_streams) : 0);
            ATCP("SYN Packets", "%" G_GUINT64_FORMAT, result->tcp_syn_count);
            ATCP("FIN Packets", "%" G_GUINT64_FORMAT, result->tcp_fin_count);
            ATCP("RST Packets", "%" G_GUINT64_FORMAT, result->tcp_rst_count);
            #undef ATCP

            if (nrows > 0) {
                char ***trows = (char ***)g_new0(gpointer, nrows);
                for (int i = 0; i < nrows; i++) trows[i] = metric_rows[i];
                table_def_t ttbl = {thdrs, 2, (const char ***)trows, nrows};
                renderer_draw_table(cr, "TCP Summary", &ttbl, margin, y, content_w);
                y += (nrows + 2) * 18 + 16;
                for (int i = 0; i < nrows; i++) g_free(metric_rows[i]);
                g_free(trows);
            }
        }

        double y_tcp_win_top = y;

        /* TCP Window Size Distribution */
        {
            bar_item_t witems[TCP_WIN_BUCKETS];
            int wcount = 0;
            for (int i = 0; i < TCP_WIN_BUCKETS; i++) {
                if (result->tcp_win_dist[i] > 0) {
                    witems[wcount].label = collector_tcp_win_label(i);
                    witems[wcount].value = (double)result->tcp_win_dist[i];
                    wcount++;
                }
            }
            if (wcount > 0) {
                renderer_draw_bar_chart(cr, "Window Size Distribution",
                                        witems, wcount,
                                        margin, y, content_w, 130);
                y += 148;
            }
        }

        double y_tcp_seg_top = y;

        /* TCP Segment Size Distribution */
        {
            bar_item_t sitems[TCP_SEG_BUCKETS];
            int scount = 0;
            for (int i = 0; i < TCP_SEG_BUCKETS; i++) {
                if (result->tcp_seg_dist[i] > 0) {
                    sitems[scount].label = collector_tcp_seg_label(i);
                    sitems[scount].value = (double)result->tcp_seg_dist[i];
                    scount++;
                }
            }
            if (scount > 0) {
                if (y + 150 > paper->height_pt - margin) {
                    /* Draw annotations for summary and window on this page */
                    ANN_SIDEBAR_RANGE(&ann_tcp_summary, y_tcp_sum_top, y_tcp_win_top - 4);
                    ANN_SIDEBAR_RANGE(&ann_tcp_window, y_tcp_win_top, paper->height_pt - margin - 20);
                    ANN_PAGE_END();
                    ANN_NEW_PAGE("12. TCP Analysis (cont.)");
                    y_tcp_seg_top = y;
                }
                renderer_draw_bar_chart(cr, "Segment Size Distribution",
                                        sitems, scount,
                                        margin, y, content_w, 130);
            }
        }

        ANN_SIDEBAR_RANGE(&ann_tcp_summary, y_tcp_sum_top, y_tcp_win_top - 4);
        ANN_SIDEBAR_RANGE(&ann_tcp_window, y_tcp_win_top, y_tcp_seg_top - 4);
        ANN_SIDEBAR_RANGE(&ann_tcp_segment, y_tcp_seg_top, paper->height_pt - margin - 20);
    }
    ANN_PAGE_END();
    ann_tcp_done:
    ;

    /* ==== Summary Page ==== */
    cairo_set_source_rgb(cr, 1, 1, 1);
    cairo_paint(cr);
    y = margin;
    renderer_draw_section_header(cr, "Summary", margin, y, full_w);
    y += 50;
    ANN_TAG_DEST("section13");

    {
        renderer_set_font(cr, "sans-serif", CAIRO_FONT_SLANT_NORMAL,
                          CAIRO_FONT_WEIGHT_BOLD, 12.0);
        cairo_set_source_rgb(cr, 0.17, 0.48, 0.71);
        cairo_move_to(cr, margin, y);
        cairo_show_text(cr, "Capture at a Glance");
        y += 24;

        char vbuf[256];
        renderer_set_font(cr, "sans-serif", CAIRO_FONT_SLANT_NORMAL,
                          CAIRO_FONT_WEIGHT_NORMAL, 10.0);
        cairo_set_source_rgb(cr, 0.15, 0.15, 0.15);

        snprintf(vbuf, sizeof(vbuf),
                 "This capture contains %" G_GUINT64_FORMAT " packets totaling ",
                 result->total_packets);
        cairo_move_to(cr, margin, y);
        cairo_show_text(cr, vbuf);
        y += 16;

        format_bytes_str(result->total_bytes, buf, sizeof(buf));
        {
            double dur = result->duration;
            int hours = (int)(dur / 3600.0);
            int mins = (int)(fmod(dur, 3600.0) / 60.0);
            double secs = fmod(dur, 60.0);
            snprintf(vbuf, sizeof(vbuf),
                     "%s over a duration of %02d:%02d:%05.2f.",
                     buf, hours, mins, secs);
        }
        cairo_move_to(cr, margin, y);
        cairo_show_text(cr, vbuf);
        y += 28;

        /* Key findings */
        renderer_set_font(cr, "sans-serif", CAIRO_FONT_SLANT_NORMAL,
                          CAIRO_FONT_WEIGHT_BOLD, 12.0);
        cairo_set_source_rgb(cr, 0.17, 0.48, 0.71);
        cairo_move_to(cr, margin, y);
        cairo_show_text(cr, "Key Metrics");
        y += 20;

        renderer_set_font(cr, "sans-serif", CAIRO_FONT_SLANT_NORMAL,
                          CAIRO_FONT_WEIGHT_NORMAL, 10.0);
        cairo_set_source_rgb(cr, 0.15, 0.15, 0.15);

        #define SUMMARY_LINE(label, fmt, ...) do { \
            renderer_set_font(cr, "sans-serif", CAIRO_FONT_SLANT_NORMAL, \
                              CAIRO_FONT_WEIGHT_BOLD, 9.0); \
            cairo_set_source_rgb(cr, 0.3, 0.3, 0.3); \
            cairo_move_to(cr, margin + 10, y); \
            cairo_show_text(cr, (label)); \
            renderer_set_font(cr, "sans-serif", CAIRO_FONT_SLANT_NORMAL, \
                              CAIRO_FONT_WEIGHT_NORMAL, 9.0); \
            cairo_set_source_rgb(cr, 0.15, 0.15, 0.15); \
            snprintf(vbuf, sizeof(vbuf), fmt, __VA_ARGS__); \
            cairo_move_to(cr, margin + 180, y); \
            cairo_show_text(cr, vbuf); \
            y += 16; \
        } while(0)

        SUMMARY_LINE("Unique IP Addresses:", "%u",
                     g_hash_table_size(result->ip_table));
        SUMMARY_LINE("Protocols Detected:", "%u",
                     g_hash_table_size(result->protocol_table));
        SUMMARY_LINE("TCP Ports:", "%u",
                     g_hash_table_size(result->tcp_port_table));
        SUMMARY_LINE("UDP Ports:", "%u",
                     g_hash_table_size(result->udp_port_table));
        SUMMARY_LINE("Communication Pairs:", "%u",
                     g_hash_table_size(result->comm_pair_table));
        SUMMARY_LINE("DNS Queries:", "%" G_GUINT64_FORMAT,
                     result->dns_total_queries);
        SUMMARY_LINE("TLS Handshakes:", "%" G_GUINT64_FORMAT,
                     result->tls_handshakes);

        if (result->tcp_total_segments > 0)
            SUMMARY_LINE("TCP Segments:", "%" G_GUINT64_FORMAT,
                         result->tcp_total_segments);

        #undef SUMMARY_LINE

        y += 20;

        /* Interpretation guidance */
        renderer_set_font(cr, "sans-serif", CAIRO_FONT_SLANT_NORMAL,
                          CAIRO_FONT_WEIGHT_BOLD, 12.0);
        cairo_set_source_rgb(cr, 0.17, 0.48, 0.71);
        cairo_move_to(cr, margin, y);
        cairo_show_text(cr, "Reading This Report");
        y += 20;

        cairo_set_source_rgb(cr, 0.2, 0.2, 0.2);
        y = draw_wrapped_text(cr,
            "Each section of this report includes an annotation sidebar on the "
            "right side of the page. The sidebar explains where the data comes "
            "from (which Wireshark fields or dissectors), what data points are "
            "being measured (e.g. bytes vs. packets), and how to interpret the "
            "results even if you are not a network analysis expert.",
            margin, y, full_w, 9.0, 14.0);
        y += 10;

        y = draw_wrapped_text(cr,
            "Look for outliers: a single IP generating most of the traffic, "
            "deprecated TLS versions still in use, expired certificates, "
            "unusual port numbers, or high TCP RST counts. These are typically "
            "the most actionable findings in a network capture analysis.",
            margin, y, full_w, 9.0, 14.0);
        y += 10;

        y = draw_wrapped_text(cr,
            "This report was generated by PacketReporter Pro "
            PLUGIN_VERSION_STR ". For more information visit "
            "https://github.com/netwho/PacketCirclePro",
            margin, y, full_w, 9.0, 14.0);
    }

    renderer_draw_page_footer(cr, paper, page_num);
    cairo_show_page(cr);
    page_num++;

    #undef ANN_NEW_PAGE
    #undef ANN_SIDEBAR
    #undef ANN_SIDEBAR_RANGE
    #undef ANN_PAGE_END
    #undef ANN_TAG_DEST

    {
        cairo_status_t cr_st = cairo_status(cr);
        cairo_status_t sf_st = cairo_surface_status(surface);
        if (cr_st != CAIRO_STATUS_SUCCESS || sf_st != CAIRO_STATUS_SUCCESS)
            ws_log(WS_LOG_DOMAIN, LOG_LEVEL_WARNING,
                   "Annotated PDF Cairo error: cr=%d(%s) surface=%d(%s)",
                   cr_st, cairo_status_to_string(cr_st),
                   sf_st, cairo_status_to_string(sf_st));
    }

    cairo_destroy(cr);
    cairo_surface_finish(surface);
    {
        cairo_status_t sf_st = cairo_surface_status(surface);
        if (sf_st != CAIRO_STATUS_SUCCESS)
            ws_log(WS_LOG_DOMAIN, LOG_LEVEL_WARNING,
                   "Annotated PDF surface finish error: %d(%s)",
                   sf_st, cairo_status_to_string(sf_st));
    }
    cairo_surface_destroy(surface);

    ws_log(WS_LOG_DOMAIN, LOG_LEVEL_INFO,
           "Annotated %s PDF (%d pages) written to %s",
           paper->name, page_num - 1, path);
    return path;
}

/* ================================================================
 * Management / Executive Summary — single page
 *
 * Large-font key metrics, protocol pie chart, top-5 talkers
 * bar chart.  Designed for printing and handing to management.
 * ================================================================ */

char *pdf_export_management(const collection_result_t *result,
                            const reporter_config_t *cfg,
                            const char *out_path)
{
    const paper_size_t *paper = &PAPER_A4_SIZE;
    char *path;
    cairo_surface_t *surface;
    cairo_t *cr;
    double y;
    double margin    = 50.0;
    double content_w = paper->width_pt - 2 * margin;
    char buf[128];

    path = make_output_path(out_path, "management");

    surface = cairo_pdf_surface_create(path,
                                       paper->width_pt, paper->height_pt);
    if (cairo_surface_status(surface) != CAIRO_STATUS_SUCCESS) {
        ws_log(WS_LOG_DOMAIN, LOG_LEVEL_WARNING,
               "Could not create PDF: %s", path);
        g_free(path);
        return NULL;
    }
    cr = cairo_create(surface);

    /* White background */
    cairo_set_source_rgb(cr, 1, 1, 1);
    cairo_paint(cr);

    y = margin;

    /* Logo or title */
    if (cfg && cfg->logo_loaded && cfg->logo_surface) {
        double img_w  = (double)cfg->logo_width;
        double img_h  = (double)cfg->logo_height;
        double max_h  = 60.0;
        double scale  = max_h / img_h;
        double draw_w = img_w * scale;

        cairo_save(cr);
        cairo_translate(cr, margin, y);
        cairo_scale(cr, scale, scale);
        cairo_set_source_surface(cr, cfg->logo_surface, 0, 0);
        cairo_paint(cr);
        cairo_restore(cr);

        y += max_h + 10;
    }

    renderer_set_font(cr, "sans-serif",
                      CAIRO_FONT_SLANT_NORMAL,
                      CAIRO_FONT_WEIGHT_BOLD, 24.0);
    cairo_set_source_rgb(cr, CLR_PRIMARY_R, CLR_PRIMARY_G, CLR_PRIMARY_B);
    cairo_move_to(cr, margin, y);
    cairo_show_text(cr, "Executive Summary");
    y += 16;

    /* Subtitle (description line 1) */
    if (cfg && cfg->desc_line1 && *cfg->desc_line1) {
        renderer_set_font(cr, "sans-serif",
                          CAIRO_FONT_SLANT_NORMAL,
                          CAIRO_FONT_WEIGHT_NORMAL, 11.0);
        cairo_set_source_rgb(cr, 0.3, 0.3, 0.3);
        cairo_move_to(cr, margin, y + 14);
        cairo_show_text(cr, cfg->desc_line1);
        y += 20;
    }

    /* Separator */
    y += 10;
    cairo_set_source_rgb(cr, CLR_PRIMARY_R, CLR_PRIMARY_G, CLR_PRIMARY_B);
    cairo_set_line_width(cr, 1.5);
    cairo_move_to(cr, margin, y);
    cairo_line_to(cr, margin + content_w, y);
    cairo_stroke(cr);
    y += 25;

    /* ── Key metrics in large tiles ── */
    {
        double tile_w = content_w / 3.0 - 10;
        double tile_h = 60;
        double tile_x = margin;
        int col;

        struct { const char *label; char value[64]; } metrics[6];
        int n_metrics = 0;

        snprintf(metrics[n_metrics].value, 64, "%" G_GUINT64_FORMAT,
                 result->total_packets);
        metrics[n_metrics].label = "Packets";
        n_metrics++;

        format_bytes_str(result->total_bytes,
                         metrics[n_metrics].value, 64);
        metrics[n_metrics].label = "Bytes";
        n_metrics++;

        format_duration_str(result->duration,
                            metrics[n_metrics].value, 64);
        metrics[n_metrics].label = "Duration";
        n_metrics++;

        snprintf(metrics[n_metrics].value, 64, "%u",
                 g_hash_table_size(result->ip_table));
        metrics[n_metrics].label = "Unique IPs";
        n_metrics++;

        snprintf(metrics[n_metrics].value, 64, "%u",
                 g_hash_table_size(result->protocol_table));
        metrics[n_metrics].label = "Protocols";
        n_metrics++;

        if (result->duration > 0) {
            snprintf(metrics[n_metrics].value, 64, "%.0f pkt/s",
                     (double)result->total_packets / result->duration);
            metrics[n_metrics].label = "Avg Rate";
            n_metrics++;
        }

        for (col = 0; col < n_metrics; col++) {
            double tx = margin + (col % 3) * (tile_w + 10);
            double ty = y + (col / 3) * (tile_h + 8);

            /* Tile background */
            cairo_set_source_rgb(cr, 0.96, 0.96, 0.96);
            cairo_rectangle(cr, tx, ty, tile_w, tile_h);
            cairo_fill(cr);

            /* Value */
            renderer_set_font(cr, "sans-serif",
                              CAIRO_FONT_SLANT_NORMAL,
                              CAIRO_FONT_WEIGHT_BOLD, 20.0);
            cairo_set_source_rgb(cr, CLR_PRIMARY_R, CLR_PRIMARY_G,
                                 CLR_PRIMARY_B);
            cairo_move_to(cr, tx + 10, ty + 30);
            cairo_show_text(cr, metrics[col].value);

            /* Label */
            renderer_set_font(cr, "sans-serif",
                              CAIRO_FONT_SLANT_NORMAL,
                              CAIRO_FONT_WEIGHT_NORMAL, 9.0);
            cairo_set_source_rgb(cr, 0.4, 0.4, 0.4);
            cairo_move_to(cr, tx + 10, ty + 48);
            cairo_show_text(cr, metrics[col].label);
        }

        y += ((n_metrics + 2) / 3) * (tile_h + 8) + 20;
    }

    /* ── Protocol distribution pie chart ── */
    {
        GList *top_protos = collector_top_protocols(
                                (collection_result_t *)result, 8);
        int count = (int)g_list_length(top_protos);
        if (count > 0) {
            pie_item_t *items = g_new0(pie_item_t, count);
            GList *l;
            int i;
            for (l = top_protos, i = 0; l; l = l->next, i++) {
                protocol_entry_t *pe = (protocol_entry_t *)l->data;
                items[i].label = pe->name;
                items[i].value = (double)pe->count;
            }
            renderer_draw_pie_chart(cr, "Protocol Distribution",
                                    items, count,
                                    margin, y, content_w, 210);
            g_free(items);
            y += 225;
        }
        g_list_free(top_protos);
    }

    /* ── Top 5 talkers bar chart ── */
    {
        GList *top_ips = collector_top_ips_by_packets(
                             (collection_result_t *)result, 5);
        int count = (int)g_list_length(top_ips);
        if (count > 0) {
            bar_item_t *items = g_new0(bar_item_t, count);
            GList *l;
            int i;
            for (l = top_ips, i = 0; l; l = l->next, i++) {
                ip_stats_t *ip = (ip_stats_t *)l->data;
                items[i].label = ip->address;
                items[i].value = (double)(ip->packets_src + ip->packets_dst);
            }
            renderer_draw_bar_chart(cr, "Top 5 Talkers (by packets)",
                                    items, count,
                                    margin, y, content_w, 200);
            g_free(items);
        }
        g_list_free(top_ips);
    }

    /* Footer */
    {
        char date_buf[64];
        time_t now = time(NULL);
        struct tm *tm_now = localtime(&now);
        if (!tm_now) {
            g_snprintf(date_buf, sizeof(date_buf), "Unknown");
        } else {
            strftime(date_buf, sizeof(date_buf), "%Y-%m-%d %H:%M:%S", tm_now);
        }
        char footer[128];
        snprintf(footer, sizeof(footer),
                 BRAND_NAME " " PLUGIN_VERSION_STR " Executive Summary \xe2\x80\x94 %s", date_buf);
        renderer_set_font(cr, "sans-serif",
                          CAIRO_FONT_SLANT_NORMAL,
                          CAIRO_FONT_WEIGHT_NORMAL, 8.0);
        cairo_set_source_rgb(cr, 0.6, 0.6, 0.6);
        double fw = renderer_text_width(cr, footer);
        cairo_move_to(cr, (paper->width_pt - fw) / 2.0,
                      paper->height_pt - 30);
        cairo_show_text(cr, footer);
    }

    cairo_show_page(cr);
    cairo_destroy(cr);
    cairo_surface_destroy(surface);

    ws_log(WS_LOG_DOMAIN, LOG_LEVEL_INFO,
           "Management PDF written to %s", path);
    return path;
}

/* ================================================================
 * WiFi Detailed Report — multi-page
 *
 * Sections (matching WiFi Reporter Lua):
 *   1. PCAP Summary + discovered SSIDs
 *   2. Top 10 MACs by frames
 *   3. RSSI distribution
 *   4. SNR distribution
 *   5. Channel usage
 *   6. MCS usage (HT + VHT)
 *   7. Frame type distribution + top subtypes
 *   8. Deauth/Disassoc reasons
 *   9. Retry analysis
 *  10. Top airtime talkers
 * ================================================================ */

/* Quality-colour helpers for RSSI / SNR bars */
static rgb_t rssi_bar_color(gint bucket)
{
    if (bucket >= -50) return (rgb_t){0.18, 0.80, 0.34};      /* green  - excellent */
    if (bucket >= -60) return (rgb_t){0.40, 0.85, 0.55};      /* light green - good */
    if (bucket >= -70) return (rgb_t){1.00, 0.76, 0.03};      /* amber  - fair */
    return (rgb_t){1.00, 0.34, 0.34};                          /* red    - weak */
}

static rgb_t snr_bar_color(gint bucket)
{
    if (bucket >= 40) return (rgb_t){0.18, 0.80, 0.34};
    if (bucket >= 25) return (rgb_t){0.40, 0.85, 0.55};
    if (bucket >= 15) return (rgb_t){1.00, 0.76, 0.03};
    return (rgb_t){1.00, 0.34, 0.34};
}

/* Sorting helper: hash table int key → sorted array of {key, count} */
typedef struct { gint key; guint64 count; } int_count_pair_t;

static gint cmp_int_key(gconstpointer a, gconstpointer b)
{
    const int_count_pair_t *pa = (const int_count_pair_t *)a;
    const int_count_pair_t *pb = (const int_count_pair_t *)b;
    return (pa->key > pb->key) - (pa->key < pb->key);
}

typedef struct { guint key; guint64 count; } uint_count_pair_t;

static gint cmp_uint_key(gconstpointer a, gconstpointer b)
{
    const uint_count_pair_t *pa = (const uint_count_pair_t *)a;
    const uint_count_pair_t *pb = (const uint_count_pair_t *)b;
    return (pa->key > pb->key) - (pa->key < pb->key);
}

static gint cmp_uint_count_desc(gconstpointer a, gconstpointer b)
{
    const uint_count_pair_t *pa = (const uint_count_pair_t *)a;
    const uint_count_pair_t *pb = (const uint_count_pair_t *)b;
    if (pa->count > pb->count) return -1;
    if (pa->count < pb->count) return  1;
    return 0;
}

/* Collect int-keyed hash into sorted array */
static GArray *collect_int_hash_sorted(GHashTable *ht)
{
    GArray *arr = g_array_new(FALSE, FALSE, sizeof(int_count_pair_t));
    GHashTableIter iter;
    gpointer key, val;
    g_hash_table_iter_init(&iter, ht);
    while (g_hash_table_iter_next(&iter, &key, &val)) {
        int_count_pair_t p = { GPOINTER_TO_INT(key), *(guint64 *)val };
        g_array_append_val(arr, p);
    }
    g_array_sort(arr, cmp_int_key);
    return arr;
}

static GArray *collect_uint_hash_sorted(GHashTable *ht)
{
    GArray *arr = g_array_new(FALSE, FALSE, sizeof(uint_count_pair_t));
    GHashTableIter iter;
    gpointer key, val;
    g_hash_table_iter_init(&iter, ht);
    while (g_hash_table_iter_next(&iter, &key, &val)) {
        uint_count_pair_t p = { GPOINTER_TO_UINT(key), *(guint64 *)val };
        g_array_append_val(arr, p);
    }
    g_array_sort(arr, cmp_uint_key);
    return arr;
}

static GArray *collect_uint_hash_sorted_by_count(GHashTable *ht)
{
    GArray *arr = g_array_new(FALSE, FALSE, sizeof(uint_count_pair_t));
    GHashTableIter iter;
    gpointer key, val;
    g_hash_table_iter_init(&iter, ht);
    while (g_hash_table_iter_next(&iter, &key, &val)) {
        uint_count_pair_t p = { GPOINTER_TO_UINT(key), *(guint64 *)val };
        g_array_append_val(arr, p);
    }
    g_array_sort(arr, cmp_uint_count_desc);
    return arr;
}

/* String-keyed hash (frame subtypes) sorted by count desc */
typedef struct { const char *key; guint64 count; } str_count_pair_t;

static gint cmp_str_count_desc(gconstpointer a, gconstpointer b)
{
    const str_count_pair_t *pa = (const str_count_pair_t *)a;
    const str_count_pair_t *pb = (const str_count_pair_t *)b;
    if (pa->count > pb->count) return -1;
    if (pa->count < pb->count) return  1;
    return 0;
}

static GArray *collect_str_hash_by_count(GHashTable *ht)
{
    GArray *arr = g_array_new(FALSE, FALSE, sizeof(str_count_pair_t));
    GHashTableIter iter;
    gpointer key, val;
    g_hash_table_iter_init(&iter, ht);
    while (g_hash_table_iter_next(&iter, &key, &val)) {
        str_count_pair_t p = { (const char *)key, *(guint64 *)val };
        g_array_append_val(arr, p);
    }
    g_array_sort(arr, cmp_str_count_desc);
    return arr;
}

/* WiFi NEW_SECTION_PAGE / FINISH_PAGE macros (same as detailed report) */
#define WIFI_NEW_PAGE(title) do { \
    cairo_set_source_rgb(cr, 1, 1, 1); cairo_paint(cr); \
    y = margin; \
    renderer_draw_section_header(cr, (title), margin, y, content_w); \
    y += 40; \
} while(0)

#define WIFI_FINISH_PAGE() do { \
    renderer_draw_page_footer(cr, paper, page_num); \
    cairo_show_page(cr); page_num++; \
} while(0)

#define WIFI_TAG_DEST(dest_name) do { \
    char _attr[128]; \
    snprintf(_attr, sizeof(_attr), "name='%s'", (dest_name)); \
    cairo_tag_begin(cr, CAIRO_TAG_DEST, _attr); \
    cairo_tag_end(cr, CAIRO_TAG_DEST); \
} while(0)

char *pdf_export_wifi(const wifi_collection_result_t *result,
                      const reporter_config_t *cfg,
                      const paper_size_t *paper,
                      const char *out_path)
{
    char *path;
    cairo_surface_t *surface;
    cairo_t *cr;
    double y;
    double margin    = 50.0;
    double content_w = paper->width_pt - 2 * margin;
    int    page_num  = 1;
    char   buf[256];

    const char *toc_titles[] = {
        "1. PCAP Summary & Discovered SSIDs",
        "2. Top 10 MAC Addresses by Frames",
        "3. RSSI Distribution",
        "4. SNR Distribution",
        "5. Channel Usage",
        "6. MCS Usage (802.11n/ac)",
        "7. Frame Type Distribution",
        "8. Deauth / Disassoc Reasons",
        "9. Retry Analysis",
        "10. Top Airtime Talkers",
    };
    int toc_pages[] = { 2, 3, 4, 4, 5, 5, 6, 7, 7, 8 };
    int toc_count   = 10;

    path = make_output_path(out_path,
                            paper->id == PAPER_A4 ? "wifi_A4" : "wifi_Legal");

    surface = cairo_pdf_surface_create(path,
                                       paper->width_pt, paper->height_pt);
    if (cairo_surface_status(surface) != CAIRO_STATUS_SUCCESS) {
        ws_log(WS_LOG_DOMAIN, LOG_LEVEL_WARNING,
               "Could not create WiFi PDF: %s", path);
        g_free(path);
        return NULL;
    }
    cr = cairo_create(surface);

    /* ── Page 1: Cover ── */
    renderer_draw_cover_page(cr, paper, cfg,
                             toc_titles, toc_pages, toc_count);
    cairo_show_page(cr);
    page_num++;

    /* ==== Page 2: 1. PCAP Summary & Discovered SSIDs ==== */
    WIFI_NEW_PAGE("1. PCAP Summary & Discovered SSIDs");
    WIFI_TAG_DEST("section1");
    {
        renderer_set_font(cr, "sans-serif", CAIRO_FONT_SLANT_NORMAL,
                          CAIRO_FONT_WEIGHT_NORMAL, 10.0);
        cairo_set_source_rgb(cr, 0.2, 0.2, 0.2);

        snprintf(buf, sizeof(buf), "Total Packets: %" G_GUINT64_FORMAT,
                 result->total_packets);
        cairo_move_to(cr, margin, y); cairo_show_text(cr, buf); y += 16;

        {
            char bbuf[64];
            format_bytes_str(result->total_bytes, bbuf, sizeof(bbuf));
            snprintf(buf, sizeof(buf), "Total Bytes: %s", bbuf);
            cairo_move_to(cr, margin, y); cairo_show_text(cr, buf); y += 16;
        }

        {
            char dbuf[64];
            format_duration_str(result->duration, dbuf, sizeof(dbuf));
            snprintf(buf, sizeof(buf), "Duration: %s", dbuf);
            cairo_move_to(cr, margin, y); cairo_show_text(cr, buf); y += 16;
        }

        {
            time_t st = (time_t)result->first_time;
            struct tm *tm = localtime(&st);
            if (tm) {
                strftime(buf, sizeof(buf), "First Packet: %Y-%m-%d %H:%M:%S", tm);
                cairo_move_to(cr, margin, y); cairo_show_text(cr, buf); y += 16;
            }
        }
        {
            time_t et = (time_t)result->last_time;
            struct tm *tm = localtime(&et);
            if (tm) {
                strftime(buf, sizeof(buf), "Last Packet: %Y-%m-%d %H:%M:%S", tm);
                cairo_move_to(cr, margin, y); cairo_show_text(cr, buf); y += 16;
            }
        }

        snprintf(buf, sizeof(buf), "Management: %" G_GUINT64_FORMAT "   Control: %" G_GUINT64_FORMAT "   Data: %" G_GUINT64_FORMAT,
                 result->frame_mgmt,
                 result->frame_control,
                 result->frame_data);
        cairo_move_to(cr, margin, y); cairo_show_text(cr, buf); y += 16;

        snprintf(buf, sizeof(buf), "BSSIDs discovered: %u   Client MACs: %u",
                 result->bssid_table ? g_hash_table_size(result->bssid_table) : 0,
                 result->client_table ? g_hash_table_size(result->client_table) : 0);
        cairo_move_to(cr, margin, y); cairo_show_text(cr, buf); y += 24;

        /* Discovered SSIDs */
        renderer_set_font(cr, "sans-serif", CAIRO_FONT_SLANT_NORMAL,
                          CAIRO_FONT_WEIGHT_BOLD, 11.0);
        cairo_set_source_rgb(cr, 0.17, 0.48, 0.71);
        cairo_move_to(cr, margin, y);
        cairo_show_text(cr, "Discovered SSIDs:"); y += 18;

        if (!result->bssid_table || g_hash_table_size(result->bssid_table) == 0) {
            renderer_set_font(cr, "sans-serif", CAIRO_FONT_SLANT_ITALIC,
                              CAIRO_FONT_WEIGHT_NORMAL, 10.0);
            cairo_set_source_rgb(cr, 0.5, 0.5, 0.5);
            cairo_move_to(cr, margin + 10, y);
            cairo_show_text(cr, "No SSIDs discovered (non-WiFi capture?)");
        } else {
            GHashTableIter iter;
            gpointer key, val;
            g_hash_table_iter_init(&iter, result->bssid_table);
            int ssid_count = 0;
            while (g_hash_table_iter_next(&iter, &key, &val) && ssid_count < 20) {
                wifi_bssid_stats_t *bs = (wifi_bssid_stats_t *)val;
                const char *ssid = (bs->ssid && *bs->ssid) ? bs->ssid : "(hidden)";

                renderer_set_font(cr, "sans-serif", CAIRO_FONT_SLANT_NORMAL,
                                  CAIRO_FONT_WEIGHT_BOLD, 9.5);
                cairo_set_source_rgb(cr, 0.2, 0.2, 0.2);
                snprintf(buf, sizeof(buf), "  %s", ssid);
                cairo_move_to(cr, margin + 10, y); cairo_show_text(cr, buf); y += 14;

                renderer_set_font(cr, "sans-serif", CAIRO_FONT_SLANT_NORMAL,
                                  CAIRO_FONT_WEIGHT_NORMAL, 8.5);
                cairo_set_source_rgb(cr, 0.4, 0.4, 0.4);
                snprintf(buf, sizeof(buf), "    BSSID: %s   Frames: %" G_GUINT64_FORMAT "   Clients: %u",
                         bs->bssid, bs->frames,
                         bs->clients ? g_hash_table_size(bs->clients) : 0);
                cairo_move_to(cr, margin + 10, y); cairo_show_text(cr, buf); y += 16;
                ssid_count++;

                if (y > paper->height_pt - margin - 40) break;
            }
        }
    }
    WIFI_FINISH_PAGE();

    /* ==== Page 3: 2. Top 10 MAC Addresses by Frames ==== */
    WIFI_NEW_PAGE("2. Top 10 MAC Addresses by Frames");
    WIFI_TAG_DEST("section2");
    {
        GList *top_macs = wifi_top_macs_by_frames(
                            (wifi_collection_result_t *)result, 10);
        int n = g_list_length(top_macs);
        if (n > 0) {
            pie_item_t pitems[10];
            char labels[10][80];
            int i = 0;
            for (GList *l = top_macs; l && i < 10; l = l->next, i++) {
                wifi_client_stats_t *cs = (wifi_client_stats_t *)l->data;
                if (cs->vendor)
                    snprintf(labels[i], sizeof(labels[i]), "%s (%s)",
                             cs->mac, cs->vendor);
                else
                    g_strlcpy(labels[i], cs->mac, sizeof(labels[i]));
                pitems[i].label = labels[i];
                pitems[i].value = (double)cs->frames;
            }
            renderer_draw_pie_chart(cr, "Top 10 MAC Addresses",
                                    pitems, i, margin, y, content_w, 350);
            y += 370;
        } else {
            renderer_set_font(cr, "sans-serif", CAIRO_FONT_SLANT_ITALIC,
                              CAIRO_FONT_WEIGHT_NORMAL, 10.0);
            cairo_set_source_rgb(cr, 0.5, 0.5, 0.5);
            cairo_move_to(cr, margin, y);
            cairo_show_text(cr, "No client MAC addresses found.");
        }
        g_list_free(top_macs);
    }
    WIFI_FINISH_PAGE();

    /* ==== Page 4: 3. RSSI Distribution ==== */
    WIFI_NEW_PAGE("3. RSSI Distribution");
    WIFI_TAG_DEST("section3");
    {
        renderer_set_font(cr, "sans-serif", CAIRO_FONT_SLANT_ITALIC,
                          CAIRO_FONT_WEIGHT_NORMAL, 9.0);
        cairo_set_source_rgb(cr, 0.4, 0.4, 0.4);
        cairo_move_to(cr, margin, y);
        cairo_show_text(cr, "RSSI (Received Signal Strength Indicator) measures "
                       "WiFi signal power in dBm. Higher values = stronger signal.");
        y += 18;

        GArray *rssi_arr = collect_int_hash_sorted(result->rssi_buckets);
        if (rssi_arr->len > 0) {
            int n = (int)rssi_arr->len;
            bar_item_t *items = g_new0(bar_item_t, n);
            rgb_t *colors = g_new0(rgb_t, n);
            char *lbls = (char *)g_malloc0(n * 16);

            for (int i = 0; i < n; i++) {
                int_count_pair_t *p = &g_array_index(rssi_arr, int_count_pair_t, i);
                snprintf(lbls + i * 16, 16, "%d dBm", p->key);
                items[i].label = lbls + i * 16;
                items[i].value = (double)p->count;
                colors[i] = rssi_bar_color(p->key);
            }

            renderer_draw_bar_chart_colored(cr, "RSSI Distribution (frames per bucket)",
                                            items, colors, n,
                                            margin, y, content_w, 250);
            y += 270;
            g_free(items); g_free(colors); g_free(lbls);
        } else {
            renderer_set_font(cr, "sans-serif", CAIRO_FONT_SLANT_ITALIC,
                              CAIRO_FONT_WEIGHT_NORMAL, 10.0);
            cairo_set_source_rgb(cr, 0.5, 0.5, 0.5);
            cairo_move_to(cr, margin, y);
            cairo_show_text(cr, "No RSSI data available (no radiotap header).");
            y += 20;
        }
        g_array_free(rssi_arr, TRUE);

        /* Signal quality guide */
        y += 10;
        renderer_set_font(cr, "sans-serif", CAIRO_FONT_SLANT_NORMAL,
                          CAIRO_FONT_WEIGHT_BOLD, 10.0);
        cairo_set_source_rgb(cr, 0.2, 0.2, 0.2);
        cairo_move_to(cr, margin, y);
        cairo_show_text(cr, "Signal Quality Guide:"); y += 16;

        renderer_set_font(cr, "sans-serif", CAIRO_FONT_SLANT_NORMAL,
                          CAIRO_FONT_WEIGHT_NORMAL, 9.0);
        static const struct { const char *label; rgb_t c; } sq[] = {
            {"Excellent: >= -50 dBm",  {0.18, 0.80, 0.34}},
            {"Good: -60 to -50 dBm",   {0.40, 0.85, 0.55}},
            {"Fair: -70 to -60 dBm",   {1.00, 0.76, 0.03}},
            {"Weak: < -70 dBm",        {1.00, 0.34, 0.34}},
        };
        for (int i = 0; i < 4; i++) {
            cairo_set_source_rgb(cr, sq[i].c.r, sq[i].c.g, sq[i].c.b);
            cairo_rectangle(cr, margin + 10, y - 8, 12, 12);
            cairo_fill(cr);
            cairo_set_source_rgb(cr, 0.2, 0.2, 0.2);
            cairo_move_to(cr, margin + 28, y);
            cairo_show_text(cr, sq[i].label);
            y += 16;
        }
    }
    WIFI_FINISH_PAGE();

    /* ==== Page 5: 4. SNR Distribution ==== */
    WIFI_NEW_PAGE("4. SNR Distribution");
    WIFI_TAG_DEST("section4");
    {
        renderer_set_font(cr, "sans-serif", CAIRO_FONT_SLANT_ITALIC,
                          CAIRO_FONT_WEIGHT_NORMAL, 9.0);
        cairo_set_source_rgb(cr, 0.4, 0.4, 0.4);
        cairo_move_to(cr, margin, y);
        cairo_show_text(cr, "SNR (Signal-to-Noise Ratio) = RSSI - Noise. "
                       "Higher SNR means cleaner signal.");
        y += 18;

        GArray *snr_arr = collect_int_hash_sorted(result->snr_buckets);
        if (snr_arr->len > 0) {
            int n = (int)snr_arr->len;
            bar_item_t *items = g_new0(bar_item_t, n);
            rgb_t *colors = g_new0(rgb_t, n);
            char *lbls = (char *)g_malloc0(n * 16);

            for (int i = 0; i < n; i++) {
                int_count_pair_t *p = &g_array_index(snr_arr, int_count_pair_t, i);
                snprintf(lbls + i * 16, 16, "%d dB", p->key);
                items[i].label = lbls + i * 16;
                items[i].value = (double)p->count;
                colors[i] = snr_bar_color(p->key);
            }

            renderer_draw_bar_chart_colored(cr, "SNR Distribution (frames per bucket)",
                                            items, colors, n,
                                            margin, y, content_w, 250);
            y += 270;
            g_free(items); g_free(colors); g_free(lbls);
        } else {
            renderer_set_font(cr, "sans-serif", CAIRO_FONT_SLANT_ITALIC,
                              CAIRO_FONT_WEIGHT_NORMAL, 10.0);
            cairo_set_source_rgb(cr, 0.5, 0.5, 0.5);
            cairo_move_to(cr, margin, y);
            cairo_show_text(cr, "No SNR data (requires both RSSI and noise floor).");
            y += 20;
        }
        g_array_free(snr_arr, TRUE);

        /* SNR quality guide */
        y += 10;
        renderer_set_font(cr, "sans-serif", CAIRO_FONT_SLANT_NORMAL,
                          CAIRO_FONT_WEIGHT_BOLD, 10.0);
        cairo_set_source_rgb(cr, 0.2, 0.2, 0.2);
        cairo_move_to(cr, margin, y);
        cairo_show_text(cr, "SNR Quality Guide:"); y += 16;

        renderer_set_font(cr, "sans-serif", CAIRO_FONT_SLANT_NORMAL,
                          CAIRO_FONT_WEIGHT_NORMAL, 9.0);
        static const struct { const char *label; rgb_t c; } snq[] = {
            {"Excellent: >= 40 dB - Very reliable",     {0.18, 0.80, 0.34}},
            {"Good: 25-40 dB - Solid performance",      {0.40, 0.85, 0.55}},
            {"Fair: 15-25 dB - Marginal, some issues",  {1.00, 0.76, 0.03}},
            {"Poor: < 15 dB - Unreliable",              {1.00, 0.34, 0.34}},
        };
        for (int i = 0; i < 4; i++) {
            cairo_set_source_rgb(cr, snq[i].c.r, snq[i].c.g, snq[i].c.b);
            cairo_rectangle(cr, margin + 10, y - 8, 12, 12);
            cairo_fill(cr);
            cairo_set_source_rgb(cr, 0.2, 0.2, 0.2);
            cairo_move_to(cr, margin + 28, y);
            cairo_show_text(cr, snq[i].label);
            y += 16;
        }
    }
    WIFI_FINISH_PAGE();

    /* ==== Page 6: 5. Channel Usage ==== */
    WIFI_NEW_PAGE("5. Channel Usage");
    WIFI_TAG_DEST("section5");
    {
        GArray *ch_arr = collect_uint_hash_sorted_by_count(result->channel_usage);
        if (ch_arr->len > 0) {
            int n = MIN((int)ch_arr->len, 20);
            pie_item_t pitems[20];
            char labels[20][32];
            for (int i = 0; i < n; i++) {
                uint_count_pair_t *p = &g_array_index(ch_arr, uint_count_pair_t, i);
                snprintf(labels[i], sizeof(labels[i]), "Channel %u", p->key);
                pitems[i].label = labels[i];
                pitems[i].value = (double)p->count;
            }
            renderer_draw_pie_chart(cr, "Channel Usage",
                                    pitems, n, margin, y, content_w, 350);
            y += 370;
        } else {
            renderer_set_font(cr, "sans-serif", CAIRO_FONT_SLANT_ITALIC,
                              CAIRO_FONT_WEIGHT_NORMAL, 10.0);
            cairo_set_source_rgb(cr, 0.5, 0.5, 0.5);
            cairo_move_to(cr, margin, y);
            cairo_show_text(cr, "No channel data available.");
        }
        g_array_free(ch_arr, TRUE);
    }
    WIFI_FINISH_PAGE();

    /* ==== Page 7: 6. MCS Usage (802.11n/ac) ==== */
    WIFI_NEW_PAGE("6. MCS Usage (802.11n/ac)");
    WIFI_TAG_DEST("section6");
    {
        renderer_set_font(cr, "sans-serif", CAIRO_FONT_SLANT_ITALIC,
                          CAIRO_FONT_WEIGHT_NORMAL, 9.0);
        cairo_set_source_rgb(cr, 0.4, 0.4, 0.4);
        cairo_move_to(cr, margin, y);
        cairo_show_text(cr, "MCS (Modulation and Coding Scheme) index determines "
                       "the data rate in 802.11n/ac.");
        y += 18;

        gboolean has_ht  = (result->ht_mcs_usage && g_hash_table_size(result->ht_mcs_usage) > 0);
        gboolean has_vht = (result->vht_mcs_usage && g_hash_table_size(result->vht_mcs_usage) > 0);

        if (!has_ht && !has_vht) {
            renderer_set_font(cr, "sans-serif", CAIRO_FONT_SLANT_ITALIC,
                              CAIRO_FONT_WEIGHT_NORMAL, 10.0);
            cairo_set_source_rgb(cr, 0.5, 0.5, 0.5);
            cairo_move_to(cr, margin, y);
            cairo_show_text(cr, "No MCS data available (legacy rates only).");
        } else {
            if (has_ht) {
                GArray *ht_arr = collect_uint_hash_sorted(result->ht_mcs_usage);
                int n = MIN((int)ht_arr->len, 32);
                bar_item_t items[32];
                char lbls[32][8];
                for (int i = 0; i < n; i++) {
                    uint_count_pair_t *p = &g_array_index(ht_arr, uint_count_pair_t, i);
                    snprintf(lbls[i], sizeof(lbls[i]), "MCS %u", p->key);
                    items[i].label = lbls[i];
                    items[i].value = (double)p->count;
                }
                renderer_draw_bar_chart(cr, "HT MCS (802.11n)",
                                        items, n, margin, y, content_w, 200);
                y += 220;
                g_array_free(ht_arr, TRUE);
            }

            if (has_vht) {
                GArray *vht_arr = collect_uint_hash_sorted(result->vht_mcs_usage);
                int n = MIN((int)vht_arr->len, 12);
                bar_item_t items[12];
                char lbls[12][8];
                for (int i = 0; i < n; i++) {
                    uint_count_pair_t *p = &g_array_index(vht_arr, uint_count_pair_t, i);
                    snprintf(lbls[i], sizeof(lbls[i]), "MCS %u", p->key);
                    items[i].label = lbls[i];
                    items[i].value = (double)p->count;
                }
                renderer_draw_bar_chart(cr, "VHT MCS (802.11ac)",
                                        items, n, margin, y, content_w, 200);
                y += 220;
                g_array_free(vht_arr, TRUE);
            }
        }
    }
    WIFI_FINISH_PAGE();

    /* ==== Page 8: 7. Frame Type Distribution ==== */
    WIFI_NEW_PAGE("7. Frame Type Distribution");
    WIFI_TAG_DEST("section7");
    {
        guint64 total = result->frame_mgmt + result->frame_control + result->frame_data;
        if (total > 0) {
            pie_item_t ftype_items[3];
            int fn = 0;
            if (result->frame_mgmt > 0) {
                ftype_items[fn].label = "Management";
                ftype_items[fn].value = (double)result->frame_mgmt;
                fn++;
            }
            if (result->frame_control > 0) {
                ftype_items[fn].label = "Control";
                ftype_items[fn].value = (double)result->frame_control;
                fn++;
            }
            if (result->frame_data > 0) {
                ftype_items[fn].label = "Data";
                ftype_items[fn].value = (double)result->frame_data;
                fn++;
            }
            renderer_draw_pie_chart(cr, "Frame Type Distribution",
                                    ftype_items, fn,
                                    margin, y, content_w, 250);
            y += 270;
        }

        /* 7.1 Top 10 802.11 Message Types (table) */
        GArray *subtype_arr = collect_str_hash_by_count(result->frame_subtypes);
        if (subtype_arr->len > 0) {
            int n = MIN((int)subtype_arr->len, 10);
            const char *thdrs[] = {"Message Type", "Frame Count"};
            char ***trows = (char ***)g_new0(gpointer, n);
            char row_data[10][2][64];

            for (int i = 0; i < n; i++) {
                str_count_pair_t *p = &g_array_index(subtype_arr, str_count_pair_t, i);
                guint type = 0, subtype = 0;
                if (sscanf(p->key, "%u-%u", &type, &subtype) == 2) {
                    g_strlcpy(row_data[i][0],
                              wifi_frame_type_name(type, subtype),
                              sizeof(row_data[i][0]));
                } else {
                    g_strlcpy(row_data[i][0], p->key, sizeof(row_data[i][0]));
                }
                snprintf(row_data[i][1], sizeof(row_data[i][1]),
                         "%" G_GUINT64_FORMAT, p->count);
                trows[i] = (char **)g_new0(gpointer, 2);
                trows[i][0] = row_data[i][0];
                trows[i][1] = row_data[i][1];
            }

            table_def_t tbl = { thdrs, 2, (const char ***)trows, n };
            renderer_draw_table(cr, "7.1 Top 10 802.11 Message Types",
                                &tbl, margin, y, content_w);
            for (int i = 0; i < n; i++) g_free(trows[i]);
            g_free(trows);
        }
        g_array_free(subtype_arr, TRUE);
    }
    WIFI_FINISH_PAGE();

    /* ==== Page 9: 8. Deauth / Disassoc Reasons ==== */
    WIFI_NEW_PAGE("8. Deauth / Disassoc Reasons");
    WIFI_TAG_DEST("section8");
    {
        if (result->deauth == 0 && result->disassoc == 0) {
            renderer_set_font(cr, "sans-serif", CAIRO_FONT_SLANT_ITALIC,
                              CAIRO_FONT_WEIGHT_NORMAL, 10.0);
            cairo_set_source_rgb(cr, 0.5, 0.5, 0.5);
            cairo_move_to(cr, margin, y);
            cairo_show_text(cr,
                "No deauthentication or disassociation frames detected.");
        } else {
            renderer_set_font(cr, "sans-serif", CAIRO_FONT_SLANT_ITALIC,
                              CAIRO_FONT_WEIGHT_NORMAL, 9.0);
            cairo_set_source_rgb(cr, 0.4, 0.4, 0.4);
            cairo_move_to(cr, margin, y);
            cairo_show_text(cr,
                "Deauth/disassociation frames indicate clients leaving "
                "the network. Frequent occurrences may signal issues.");
            y += 18;

            snprintf(buf, sizeof(buf), "Deauthentications: %" G_GUINT64_FORMAT "   Disassociations: %" G_GUINT64_FORMAT,
                     result->deauth, result->disassoc);
            renderer_set_font(cr, "sans-serif", CAIRO_FONT_SLANT_NORMAL,
                              CAIRO_FONT_WEIGHT_NORMAL, 10.0);
            cairo_set_source_rgb(cr, 0.2, 0.2, 0.2);
            cairo_move_to(cr, margin, y);
            cairo_show_text(cr, buf); y += 20;

            GArray *reason_arr = collect_uint_hash_sorted_by_count(result->reason_codes);
            if (reason_arr->len > 0) {
                int n = MIN((int)reason_arr->len, 10);
                pie_item_t pitems[10];
                char labels[10][80];
                for (int i = 0; i < n; i++) {
                    uint_count_pair_t *p = &g_array_index(reason_arr, uint_count_pair_t, i);
                    snprintf(labels[i], sizeof(labels[i]), "%u: %s",
                             p->key, wifi_reason_code_name(p->key));
                    pitems[i].label = labels[i];
                    pitems[i].value = (double)p->count;
                }
                renderer_draw_pie_chart(cr, "Deauth/Disassoc Reason Codes",
                                        pitems, n, margin, y, content_w, 280);
            }
            g_array_free(reason_arr, TRUE);
        }
    }
    WIFI_FINISH_PAGE();

    /* ==== Page 10: 9. Retry Analysis ==== */
    WIFI_NEW_PAGE("9. Retry Analysis");
    WIFI_TAG_DEST("section9");
    {
        if (result->total_data_frames == 0) {
            renderer_set_font(cr, "sans-serif", CAIRO_FONT_SLANT_ITALIC,
                              CAIRO_FONT_WEIGHT_NORMAL, 10.0);
            cairo_set_source_rgb(cr, 0.5, 0.5, 0.5);
            cairo_move_to(cr, margin, y);
            cairo_show_text(cr, "No data frames detected for retry analysis.");
            y += 20;
        } else {
            renderer_set_font(cr, "sans-serif", CAIRO_FONT_SLANT_NORMAL,
                              CAIRO_FONT_WEIGHT_NORMAL, 10.0);
            cairo_set_source_rgb(cr, 0.2, 0.2, 0.2);

            snprintf(buf, sizeof(buf), "Total Data Frames: %" G_GUINT64_FORMAT,
                     result->total_data_frames);
            cairo_move_to(cr, margin, y); cairo_show_text(cr, buf); y += 16;

            snprintf(buf, sizeof(buf), "Retried Frames: %" G_GUINT64_FORMAT,
                     result->retry_count);
            cairo_move_to(cr, margin, y); cairo_show_text(cr, buf); y += 16;

            double retry_pct = 0.0;
            if (result->total_data_frames > 0)
                retry_pct = (double)result->retry_count * 100.0 /
                            (double)result->total_data_frames;
            snprintf(buf, sizeof(buf), "Retry Rate: %.1f%%", retry_pct);
            cairo_move_to(cr, margin, y); cairo_show_text(cr, buf); y += 20;

            if (result->fcs_good > 0 || result->fcs_bad > 0) {
                snprintf(buf, sizeof(buf), "FCS Good: %" G_GUINT64_FORMAT "   FCS Bad: %" G_GUINT64_FORMAT,
                         result->fcs_good,
                         result->fcs_bad);
                cairo_move_to(cr, margin, y); cairo_show_text(cr, buf); y += 16;
            }

            snprintf(buf, sizeof(buf), "EAPOL Frames: %" G_GUINT64_FORMAT,
                     result->eapol_frames);
            cairo_move_to(cr, margin, y); cairo_show_text(cr, buf); y += 20;

            /* Association summary */
            snprintf(buf, sizeof(buf),
                     "Assoc Req/Resp: %" G_GUINT64_FORMAT "/%" G_GUINT64_FORMAT "   Reassoc Req/Resp: %" G_GUINT64_FORMAT "/%" G_GUINT64_FORMAT,
                     result->assoc_req,
                     result->assoc_resp,
                     result->reassoc_req,
                     result->reassoc_resp);
            cairo_move_to(cr, margin, y); cairo_show_text(cr, buf); y += 20;
        }

        /* 10. Top Airtime Talkers on same page if space allows */
        if (y + 300 < paper->height_pt - margin) {
            WIFI_TAG_DEST("section10");
            renderer_draw_section_header(cr, "10. Top Airtime Talkers",
                                         margin, y + 10, content_w);
            y += 50;

            if (result->airtime_total_us <= 0.0) {
                renderer_set_font(cr, "sans-serif", CAIRO_FONT_SLANT_ITALIC,
                                  CAIRO_FONT_WEIGHT_NORMAL, 10.0);
                cairo_set_source_rgb(cr, 0.5, 0.5, 0.5);
                cairo_move_to(cr, margin, y);
                cairo_show_text(cr,
                    "No airtime data (requires data rate in radiotap header).");
            } else {
                renderer_set_font(cr, "sans-serif", CAIRO_FONT_SLANT_ITALIC,
                                  CAIRO_FONT_WEIGHT_NORMAL, 9.0);
                cairo_set_source_rgb(cr, 0.4, 0.4, 0.4);
                snprintf(buf, sizeof(buf),
                         "Total estimated airtime: %.1f seconds",
                         result->airtime_total_us / 1e6);
                cairo_move_to(cr, margin, y);
                cairo_show_text(cr, buf); y += 18;

                GList *top_at = wifi_top_clients_by_airtime(
                                    (wifi_collection_result_t *)result, 10);
                int n = g_list_length(top_at);
                if (n > 0) {
                    bar_item_t items[10];
                    char labels[10][80];
                    int i = 0;
                    for (GList *l = top_at; l && i < 10; l = l->next, i++) {
                        wifi_client_stats_t *cs = (wifi_client_stats_t *)l->data;
                        if (cs->vendor)
                            snprintf(labels[i], sizeof(labels[i]),
                                     "%s (%s)", cs->mac, cs->vendor);
                        else
                            g_strlcpy(labels[i], cs->mac, sizeof(labels[i]));
                        items[i].label = labels[i];
                        items[i].value = cs->airtime_us / 1000.0;
                    }
                    renderer_draw_bar_chart(cr, "Top Airtime Talkers (ms)",
                                            items, i,
                                            margin, y, content_w, 250);
                }
                g_list_free(top_at);
            }
        }
    }
    WIFI_FINISH_PAGE();

    cairo_destroy(cr);
    cairo_surface_destroy(surface);

    ws_log(WS_LOG_DOMAIN, LOG_LEVEL_INFO,
           "WiFi %s PDF (%d pages) written to %s",
           paper->name, page_num - 1, path);
    return path;
}

#undef WIFI_NEW_PAGE
#undef WIFI_FINISH_PAGE
#undef WIFI_TAG_DEST

/* ================================================================
 * WiFi Annotated Report
 *
 * Same content as the WiFi detailed report, but each section has a
 * 60% content + 40% annotation sidebar layout.
 * ================================================================ */

static const annotation_t wann_pcap_ssids = {
    "Wireshark: radiotap header, 802.11 management frames (beacons, probes).",
    "Total packets/bytes, duration, frame type counts (mgmt/ctrl/data), "
    "discovered BSSIDs and SSIDs with associated client counts.",
    "This is the identity card of the WiFi capture. Check that the capture "
    "was in monitor mode (you should see management and control frames). "
    "The SSID list shows all visible networks; hidden SSIDs appear as "
    "'(hidden)'. Client counts indicate network popularity."
};

static const annotation_t wann_top_macs = {
    "Wireshark field: wlan.addr (source and destination MACs).",
    "Top 10 MAC addresses ranked by frame count, shown as a pie chart.",
    "These are the most active wireless stations. BSSIDs (access points) "
    "often dominate due to beacon frames. If a client MAC appears at the "
    "top, it may be a heavy user or performing scanning. The vendor OUI "
    "helps identify device manufacturers."
};

static const annotation_t wann_rssi = {
    "Radiotap field: radiotap.dbm_antsignal (per-frame RSSI in dBm).",
    "RSSI distribution histogram with color-coded signal quality.",
    "RSSI measures received signal strength. Values closer to 0 are stronger. "
    "Typical ranges: >= -50 dBm (excellent), -60 to -50 (good), -70 to -60 "
    "(fair), < -70 (weak). A wide spread suggests mixed near/far clients. "
    "Many weak signals indicate coverage issues."
};

static const annotation_t wann_snr = {
    "Computed: RSSI - Noise floor (from radiotap.dbm_antnoise).",
    "SNR distribution histogram with quality-coded colors.",
    "SNR (Signal-to-Noise Ratio) is more meaningful than RSSI alone because "
    "it accounts for the noise floor. >= 40 dB is excellent; < 15 dB is "
    "unreliable. If RSSI is decent but SNR is low, the environment is noisy "
    "(interference from other devices or channels)."
};

static const annotation_t wann_channels = {
    "Radiotap field: wlan_radio.channel or radiotap.channel.freq.",
    "Channel usage pie chart showing frame counts per WiFi channel.",
    "This reveals which channels are in use and how traffic is distributed. "
    "Ideal 2.4 GHz channels are 1, 6, and 11 (non-overlapping). Crowded "
    "channels cause interference and lower throughput. 5 GHz channels "
    "offer more capacity with less overlap."
};

static const annotation_t wann_mcs = {
    "Radiotap fields: radiotap.mcs.index (HT), radiotap.vht.mcs (VHT).",
    "MCS index distribution bar charts for 802.11n (HT) and 802.11ac (VHT).",
    "Higher MCS indices mean faster data rates but require better signal "
    "quality. MCS 0-3 are robust but slow; MCS 7+ indicates strong signals. "
    "If most traffic uses low MCS, clients may be at the edge of coverage "
    "or experiencing interference."
};

static const annotation_t wann_frame_types = {
    "Wireshark field: wlan.fc.type (0=Management, 1=Control, 2=Data).",
    "Frame type pie chart and top 10 802.11 message subtypes table.",
    "In monitor mode, you see all three frame types. Management frames "
    "(beacons, probes) are overhead; a healthy network has more data frames. "
    "High management:data ratio suggests many APs or aggressive scanning. "
    "Subtypes like Deauth or Disassoc indicate connection disruptions."
};

static const annotation_t wann_deauth = {
    "Wireshark fields: wlan.fc.type_subtype (0x0c = deauth, 0x0a = disassoc), "
    "wlan_mgt.fixed.reason_code.",
    "Deauth/disassoc counts and reason code distribution pie chart.",
    "These frames terminate client connections. Occasional occurrences are "
    "normal (roaming, idle timeout). Frequent deauths from the same source "
    "may indicate a deauthentication attack. Reason codes help diagnose: "
    "code 1 = unspecified, code 3 = leaving, code 7 = not authenticated."
};

static const annotation_t wann_retry = {
    "Wireshark field: wlan.fc.retry, wlan.fcs_good, frame.len.",
    "Retry rate, FCS errors, EAPOL frames, association statistics.",
    "Retry rate > 10%% indicates significant packet loss over the air. "
    "Causes include interference, weak signal, or congestion. FCS (Frame "
    "Check Sequence) errors confirm corrupted frames. EAPOL frames show "
    "WPA/WPA2 authentication activity. High assoc/reassoc counts suggest "
    "frequent roaming."
};

static const annotation_t wann_airtime = {
    "Computed: frame length (bytes) / data rate (bits/s) from radiotap.",
    "Estimated airtime per MAC address shown as a bar chart (milliseconds).",
    "Airtime is the most meaningful metric for WiFi capacity planning. "
    "A slow client (low MCS) sending many frames consumes disproportionate "
    "airtime, affecting all other clients on the same channel. Top airtime "
    "consumers should be investigated for signal/rate issues."
};

char *pdf_export_wifi_annotated(const wifi_collection_result_t *result,
                                const reporter_config_t *cfg,
                                const paper_size_t *paper,
                                const char *out_path)
{
    char *path;
    cairo_surface_t *surface;
    cairo_t *cr;
    double y, y_section_top;
    double margin     = 50.0;
    double full_w     = paper->width_pt - 2 * margin;
    double gap        = 10.0;
    double content_w  = full_w * 0.60 - gap / 2.0;
    double annot_x    = margin + content_w + gap;
    double annot_w    = full_w - content_w - gap;
    int    page_num   = 1;
    char   buf[256];

    const char *toc_titles[] = {
        "1. PCAP Summary & Discovered SSIDs",
        "2. Top 10 MAC Addresses by Frames",
        "3. RSSI Distribution",
        "4. SNR Distribution",
        "5. Channel Usage",
        "6. MCS Usage (802.11n/ac)",
        "7. Frame Type Distribution",
        "8. Deauth / Disassoc Reasons",
        "9. Retry Analysis",
        "10. Top Airtime Talkers",
        "Summary",
    };
    int toc_pages[] = { 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 };
    int toc_count   = 11;

    path = make_output_path(out_path,
                            paper->id == PAPER_A4 ? "wifi_annotated_A4"
                                                  : "wifi_annotated_Legal");

    surface = cairo_pdf_surface_create(path,
                                       paper->width_pt, paper->height_pt);
    if (cairo_surface_status(surface) != CAIRO_STATUS_SUCCESS) {
        ws_log(WS_LOG_DOMAIN, LOG_LEVEL_WARNING,
               "Could not create WiFi annotated PDF: %s", path);
        g_free(path);
        return NULL;
    }
    cr = cairo_create(surface);

    #define WANN_NEW_PAGE(title) do { \
        cairo_set_source_rgb(cr, 1, 1, 1); cairo_paint(cr); \
        y = margin; \
        renderer_draw_section_header(cr, (title), margin, y, full_w); \
        y += 50; \
        y_section_top = y; \
    } while(0)

    #define WANN_SIDEBAR(ann_ptr) do { \
        draw_annotation_sidebar(cr, annot_x, y_section_top, annot_w, \
                                paper->height_pt - margin - 20, (ann_ptr)); \
    } while(0)

    #define WANN_PAGE_END() do { \
        renderer_draw_page_footer(cr, paper, page_num); \
        cairo_show_page(cr); page_num++; \
    } while(0)

    #define WANN_TAG_DEST(dest_name) do { \
        char _attr[128]; \
        snprintf(_attr, sizeof(_attr), "name='%s'", (dest_name)); \
        cairo_tag_begin(cr, CAIRO_TAG_DEST, _attr); \
        cairo_tag_end(cr, CAIRO_TAG_DEST); \
    } while(0)

    /* ── Page 1: Cover ── */
    renderer_draw_cover_page(cr, paper, cfg,
                             toc_titles, toc_pages, toc_count);
    cairo_show_page(cr);
    page_num++;

    /* ==== 1. PCAP Summary & Discovered SSIDs (no annotation — same as network) ==== */
    WANN_NEW_PAGE("1. PCAP Summary & Discovered SSIDs");
    WANN_TAG_DEST("section1");
    {
        renderer_set_font(cr, "sans-serif", CAIRO_FONT_SLANT_NORMAL,
                          CAIRO_FONT_WEIGHT_NORMAL, 10.0);
        cairo_set_source_rgb(cr, 0.2, 0.2, 0.2);

        snprintf(buf, sizeof(buf), "Total Packets: %" G_GUINT64_FORMAT,
                 result->total_packets);
        cairo_move_to(cr, margin, y); cairo_show_text(cr, buf); y += 16;
        {
            char bbuf[64];
            format_bytes_str(result->total_bytes, bbuf, sizeof(bbuf));
            snprintf(buf, sizeof(buf), "Total Bytes: %s", bbuf);
            cairo_move_to(cr, margin, y); cairo_show_text(cr, buf); y += 16;
        }
        {
            char dbuf[64];
            format_duration_str(result->duration, dbuf, sizeof(dbuf));
            snprintf(buf, sizeof(buf), "Duration: %s", dbuf);
            cairo_move_to(cr, margin, y); cairo_show_text(cr, buf); y += 16;
        }
        {
            time_t st = (time_t)result->first_time;
            struct tm *tm = localtime(&st);
            if (tm) {
                strftime(buf, sizeof(buf), "First Packet: %Y-%m-%d %H:%M:%S", tm);
                cairo_move_to(cr, margin, y); cairo_show_text(cr, buf); y += 16;
            }
        }
        {
            time_t et = (time_t)result->last_time;
            struct tm *tm = localtime(&et);
            if (tm) {
                strftime(buf, sizeof(buf), "Last Packet: %Y-%m-%d %H:%M:%S", tm);
                cairo_move_to(cr, margin, y); cairo_show_text(cr, buf); y += 16;
            }
        }

        snprintf(buf, sizeof(buf), "Management: %" G_GUINT64_FORMAT
                 "   Control: %" G_GUINT64_FORMAT "   Data: %" G_GUINT64_FORMAT,
                 result->frame_mgmt, result->frame_control, result->frame_data);
        cairo_move_to(cr, margin, y); cairo_show_text(cr, buf); y += 16;

        snprintf(buf, sizeof(buf), "BSSIDs discovered: %u   Client MACs: %u",
                 result->bssid_table ? g_hash_table_size(result->bssid_table) : 0,
                 result->client_table ? g_hash_table_size(result->client_table) : 0);
        cairo_move_to(cr, margin, y); cairo_show_text(cr, buf); y += 24;

        renderer_set_font(cr, "sans-serif", CAIRO_FONT_SLANT_NORMAL,
                          CAIRO_FONT_WEIGHT_BOLD, 11.0);
        cairo_set_source_rgb(cr, 0.17, 0.48, 0.71);
        cairo_move_to(cr, margin, y);
        cairo_show_text(cr, "Discovered SSIDs:"); y += 18;

        if (!result->bssid_table || g_hash_table_size(result->bssid_table) == 0) {
            renderer_set_font(cr, "sans-serif", CAIRO_FONT_SLANT_ITALIC,
                              CAIRO_FONT_WEIGHT_NORMAL, 10.0);
            cairo_set_source_rgb(cr, 0.5, 0.5, 0.5);
            cairo_move_to(cr, margin + 10, y);
            cairo_show_text(cr, "No SSIDs discovered (non-WiFi capture?)");
        } else {
            GHashTableIter iter;
            gpointer key, val;
            g_hash_table_iter_init(&iter, result->bssid_table);
            int ssid_count = 0;
            while (g_hash_table_iter_next(&iter, &key, &val) && ssid_count < 20) {
                wifi_bssid_stats_t *bs = (wifi_bssid_stats_t *)val;
                const char *ssid = (bs->ssid && *bs->ssid) ? bs->ssid : "(hidden)";

                renderer_set_font(cr, "sans-serif", CAIRO_FONT_SLANT_NORMAL,
                                  CAIRO_FONT_WEIGHT_BOLD, 9.5);
                cairo_set_source_rgb(cr, 0.2, 0.2, 0.2);
                snprintf(buf, sizeof(buf), "  %s", ssid);
                cairo_move_to(cr, margin + 10, y); cairo_show_text(cr, buf); y += 14;

                renderer_set_font(cr, "sans-serif", CAIRO_FONT_SLANT_NORMAL,
                                  CAIRO_FONT_WEIGHT_NORMAL, 8.5);
                cairo_set_source_rgb(cr, 0.4, 0.4, 0.4);
                snprintf(buf, sizeof(buf),
                         "    BSSID: %s   Frames: %" G_GUINT64_FORMAT "   Clients: %u",
                         bs->bssid, bs->frames,
                         bs->clients ? g_hash_table_size(bs->clients) : 0);
                cairo_move_to(cr, margin + 10, y); cairo_show_text(cr, buf); y += 16;
                ssid_count++;
                if (y > paper->height_pt - margin - 40) break;
            }
        }
    }
    WANN_SIDEBAR(&wann_pcap_ssids);
    WANN_PAGE_END();

    /* ==== 2. Top 10 MAC Addresses by Frames ==== */
    WANN_NEW_PAGE("2. Top 10 MAC Addresses by Frames");
    WANN_TAG_DEST("section2");
    {
        GList *top_macs = wifi_top_macs_by_frames(
                            (wifi_collection_result_t *)result, 10);
        int n = g_list_length(top_macs);
        if (n > 0) {
            pie_item_t pitems[10];
            char labels[10][80];
            int i = 0;
            for (GList *l = top_macs; l && i < 10; l = l->next, i++) {
                wifi_client_stats_t *cs = (wifi_client_stats_t *)l->data;
                if (cs->vendor)
                    snprintf(labels[i], sizeof(labels[i]), "%s (%s)",
                             cs->mac, cs->vendor);
                else
                    g_strlcpy(labels[i], cs->mac, sizeof(labels[i]));
                pitems[i].label = labels[i];
                pitems[i].value = (double)cs->frames;
            }
            renderer_draw_pie_chart(cr, "Top 10 MAC Addresses",
                                    pitems, i, margin, y, content_w, 350);
        } else {
            renderer_set_font(cr, "sans-serif", CAIRO_FONT_SLANT_ITALIC,
                              CAIRO_FONT_WEIGHT_NORMAL, 10.0);
            cairo_set_source_rgb(cr, 0.5, 0.5, 0.5);
            cairo_move_to(cr, margin, y);
            cairo_show_text(cr, "No client MAC addresses found.");
        }
        g_list_free(top_macs);
    }
    WANN_SIDEBAR(&wann_top_macs);
    WANN_PAGE_END();

    /* ==== 3. RSSI Distribution ==== */
    WANN_NEW_PAGE("3. RSSI Distribution");
    WANN_TAG_DEST("section3");
    {
        renderer_set_font(cr, "sans-serif", CAIRO_FONT_SLANT_ITALIC,
                          CAIRO_FONT_WEIGHT_NORMAL, 9.0);
        cairo_set_source_rgb(cr, 0.4, 0.4, 0.4);
        cairo_move_to(cr, margin, y);
        cairo_show_text(cr, "RSSI (Received Signal Strength Indicator) measures "
                       "WiFi signal power in dBm. Higher values = stronger signal.");
        y += 18;

        GArray *rssi_arr = collect_int_hash_sorted(result->rssi_buckets);
        if (rssi_arr->len > 0) {
            int n = (int)rssi_arr->len;
            bar_item_t *items = g_new0(bar_item_t, n);
            rgb_t *colors = g_new0(rgb_t, n);
            char *lbls = (char *)g_malloc0(n * 16);
            for (int i = 0; i < n; i++) {
                int_count_pair_t *p = &g_array_index(rssi_arr, int_count_pair_t, i);
                snprintf(lbls + i * 16, 16, "%d dBm", p->key);
                items[i].label = lbls + i * 16;
                items[i].value = (double)p->count;
                colors[i] = rssi_bar_color(p->key);
            }
            renderer_draw_bar_chart_colored(cr, "RSSI Distribution (frames per bucket)",
                                            items, colors, n,
                                            margin, y, content_w, 250);
            y += 270;
            g_free(items); g_free(colors); g_free(lbls);
        } else {
            renderer_set_font(cr, "sans-serif", CAIRO_FONT_SLANT_ITALIC,
                              CAIRO_FONT_WEIGHT_NORMAL, 10.0);
            cairo_set_source_rgb(cr, 0.5, 0.5, 0.5);
            cairo_move_to(cr, margin, y);
            cairo_show_text(cr, "No RSSI data available (no radiotap header).");
            y += 20;
        }
        g_array_free(rssi_arr, TRUE);

        y += 10;
        renderer_set_font(cr, "sans-serif", CAIRO_FONT_SLANT_NORMAL,
                          CAIRO_FONT_WEIGHT_BOLD, 10.0);
        cairo_set_source_rgb(cr, 0.2, 0.2, 0.2);
        cairo_move_to(cr, margin, y);
        cairo_show_text(cr, "Signal Quality Guide:"); y += 16;
        renderer_set_font(cr, "sans-serif", CAIRO_FONT_SLANT_NORMAL,
                          CAIRO_FONT_WEIGHT_NORMAL, 9.0);
        static const struct { const char *label; rgb_t c; } wann_sq[] = {
            {"Excellent: >= -50 dBm",  {0.18, 0.80, 0.34}},
            {"Good: -60 to -50 dBm",   {0.40, 0.85, 0.55}},
            {"Fair: -70 to -60 dBm",   {1.00, 0.76, 0.03}},
            {"Weak: < -70 dBm",        {1.00, 0.34, 0.34}},
        };
        for (int i = 0; i < 4; i++) {
            cairo_set_source_rgb(cr, wann_sq[i].c.r, wann_sq[i].c.g, wann_sq[i].c.b);
            cairo_rectangle(cr, margin + 10, y - 8, 12, 12);
            cairo_fill(cr);
            cairo_set_source_rgb(cr, 0.2, 0.2, 0.2);
            cairo_move_to(cr, margin + 28, y);
            cairo_show_text(cr, wann_sq[i].label);
            y += 16;
        }
    }
    WANN_SIDEBAR(&wann_rssi);
    WANN_PAGE_END();

    /* ==== 4. SNR Distribution ==== */
    WANN_NEW_PAGE("4. SNR Distribution");
    WANN_TAG_DEST("section4");
    {
        renderer_set_font(cr, "sans-serif", CAIRO_FONT_SLANT_ITALIC,
                          CAIRO_FONT_WEIGHT_NORMAL, 9.0);
        cairo_set_source_rgb(cr, 0.4, 0.4, 0.4);
        cairo_move_to(cr, margin, y);
        cairo_show_text(cr, "SNR (Signal-to-Noise Ratio) = RSSI - Noise. "
                       "Higher SNR means cleaner signal.");
        y += 18;

        GArray *snr_arr = collect_int_hash_sorted(result->snr_buckets);
        if (snr_arr->len > 0) {
            int n = (int)snr_arr->len;
            bar_item_t *items = g_new0(bar_item_t, n);
            rgb_t *colors = g_new0(rgb_t, n);
            char *lbls = (char *)g_malloc0(n * 16);
            for (int i = 0; i < n; i++) {
                int_count_pair_t *p = &g_array_index(snr_arr, int_count_pair_t, i);
                snprintf(lbls + i * 16, 16, "%d dB", p->key);
                items[i].label = lbls + i * 16;
                items[i].value = (double)p->count;
                colors[i] = snr_bar_color(p->key);
            }
            renderer_draw_bar_chart_colored(cr, "SNR Distribution (frames per bucket)",
                                            items, colors, n,
                                            margin, y, content_w, 250);
            y += 270;
            g_free(items); g_free(colors); g_free(lbls);
        } else {
            renderer_set_font(cr, "sans-serif", CAIRO_FONT_SLANT_ITALIC,
                              CAIRO_FONT_WEIGHT_NORMAL, 10.0);
            cairo_set_source_rgb(cr, 0.5, 0.5, 0.5);
            cairo_move_to(cr, margin, y);
            cairo_show_text(cr, "No SNR data (requires both RSSI and noise floor).");
            y += 20;
        }
        g_array_free(snr_arr, TRUE);

        y += 10;
        renderer_set_font(cr, "sans-serif", CAIRO_FONT_SLANT_NORMAL,
                          CAIRO_FONT_WEIGHT_BOLD, 10.0);
        cairo_set_source_rgb(cr, 0.2, 0.2, 0.2);
        cairo_move_to(cr, margin, y);
        cairo_show_text(cr, "SNR Quality Guide:"); y += 16;
        renderer_set_font(cr, "sans-serif", CAIRO_FONT_SLANT_NORMAL,
                          CAIRO_FONT_WEIGHT_NORMAL, 9.0);
        static const struct { const char *label; rgb_t c; } wann_snq[] = {
            {"Excellent: >= 40 dB - Very reliable",     {0.18, 0.80, 0.34}},
            {"Good: 25-40 dB - Solid performance",      {0.40, 0.85, 0.55}},
            {"Fair: 15-25 dB - Marginal, some issues",  {1.00, 0.76, 0.03}},
            {"Poor: < 15 dB - Unreliable",              {1.00, 0.34, 0.34}},
        };
        for (int i = 0; i < 4; i++) {
            cairo_set_source_rgb(cr, wann_snq[i].c.r, wann_snq[i].c.g, wann_snq[i].c.b);
            cairo_rectangle(cr, margin + 10, y - 8, 12, 12);
            cairo_fill(cr);
            cairo_set_source_rgb(cr, 0.2, 0.2, 0.2);
            cairo_move_to(cr, margin + 28, y);
            cairo_show_text(cr, wann_snq[i].label);
            y += 16;
        }
    }
    WANN_SIDEBAR(&wann_snr);
    WANN_PAGE_END();

    /* ==== 5. Channel Usage ==== */
    WANN_NEW_PAGE("5. Channel Usage");
    WANN_TAG_DEST("section5");
    {
        GArray *ch_arr = collect_uint_hash_sorted_by_count(result->channel_usage);
        if (ch_arr->len > 0) {
            int n = MIN((int)ch_arr->len, 20);
            pie_item_t pitems[20];
            char labels[20][32];
            for (int i = 0; i < n; i++) {
                uint_count_pair_t *p = &g_array_index(ch_arr, uint_count_pair_t, i);
                snprintf(labels[i], sizeof(labels[i]), "Channel %u", p->key);
                pitems[i].label = labels[i];
                pitems[i].value = (double)p->count;
            }
            renderer_draw_pie_chart(cr, "Channel Usage",
                                    pitems, n, margin, y, content_w, 350);
        } else {
            renderer_set_font(cr, "sans-serif", CAIRO_FONT_SLANT_ITALIC,
                              CAIRO_FONT_WEIGHT_NORMAL, 10.0);
            cairo_set_source_rgb(cr, 0.5, 0.5, 0.5);
            cairo_move_to(cr, margin, y);
            cairo_show_text(cr, "No channel data available.");
        }
        g_array_free(ch_arr, TRUE);
    }
    WANN_SIDEBAR(&wann_channels);
    WANN_PAGE_END();

    /* ==== 6. MCS Usage (802.11n/ac) ==== */
    WANN_NEW_PAGE("6. MCS Usage (802.11n/ac)");
    WANN_TAG_DEST("section6");
    {
        renderer_set_font(cr, "sans-serif", CAIRO_FONT_SLANT_ITALIC,
                          CAIRO_FONT_WEIGHT_NORMAL, 9.0);
        cairo_set_source_rgb(cr, 0.4, 0.4, 0.4);
        cairo_move_to(cr, margin, y);
        cairo_show_text(cr, "MCS (Modulation and Coding Scheme) index determines "
                       "the data rate in 802.11n/ac.");
        y += 18;

        gboolean has_ht  = (result->ht_mcs_usage && g_hash_table_size(result->ht_mcs_usage) > 0);
        gboolean has_vht = (result->vht_mcs_usage && g_hash_table_size(result->vht_mcs_usage) > 0);

        if (!has_ht && !has_vht) {
            renderer_set_font(cr, "sans-serif", CAIRO_FONT_SLANT_ITALIC,
                              CAIRO_FONT_WEIGHT_NORMAL, 10.0);
            cairo_set_source_rgb(cr, 0.5, 0.5, 0.5);
            cairo_move_to(cr, margin, y);
            cairo_show_text(cr, "No MCS data available (legacy rates only).");
        } else {
            if (has_ht) {
                GArray *ht_arr = collect_uint_hash_sorted(result->ht_mcs_usage);
                int n = MIN((int)ht_arr->len, 32);
                bar_item_t items[32];
                char lbls[32][8];
                for (int i = 0; i < n; i++) {
                    uint_count_pair_t *p = &g_array_index(ht_arr, uint_count_pair_t, i);
                    snprintf(lbls[i], sizeof(lbls[i]), "MCS %u", p->key);
                    items[i].label = lbls[i];
                    items[i].value = (double)p->count;
                }
                renderer_draw_bar_chart(cr, "HT MCS (802.11n)",
                                        items, n, margin, y, content_w, 200);
                y += 220;
                g_array_free(ht_arr, TRUE);
            }
            if (has_vht) {
                GArray *vht_arr = collect_uint_hash_sorted(result->vht_mcs_usage);
                int n = MIN((int)vht_arr->len, 12);
                bar_item_t items[12];
                char lbls[12][8];
                for (int i = 0; i < n; i++) {
                    uint_count_pair_t *p = &g_array_index(vht_arr, uint_count_pair_t, i);
                    snprintf(lbls[i], sizeof(lbls[i]), "MCS %u", p->key);
                    items[i].label = lbls[i];
                    items[i].value = (double)p->count;
                }
                renderer_draw_bar_chart(cr, "VHT MCS (802.11ac)",
                                        items, n, margin, y, content_w, 200);
                y += 220;
                g_array_free(vht_arr, TRUE);
            }
        }
    }
    WANN_SIDEBAR(&wann_mcs);
    WANN_PAGE_END();

    /* ==== 7. Frame Type Distribution ==== */
    WANN_NEW_PAGE("7. Frame Type Distribution");
    WANN_TAG_DEST("section7");
    {
        guint64 total = result->frame_mgmt + result->frame_control + result->frame_data;
        if (total > 0) {
            pie_item_t ftype_items[3];
            int fn = 0;
            if (result->frame_mgmt > 0) {
                ftype_items[fn].label = "Management";
                ftype_items[fn].value = (double)result->frame_mgmt;
                fn++;
            }
            if (result->frame_control > 0) {
                ftype_items[fn].label = "Control";
                ftype_items[fn].value = (double)result->frame_control;
                fn++;
            }
            if (result->frame_data > 0) {
                ftype_items[fn].label = "Data";
                ftype_items[fn].value = (double)result->frame_data;
                fn++;
            }
            renderer_draw_pie_chart(cr, "Frame Type Distribution",
                                    ftype_items, fn,
                                    margin, y, content_w, 250);
            y += 270;
        }

        GArray *subtype_arr = collect_str_hash_by_count(result->frame_subtypes);
        if (subtype_arr->len > 0) {
            int n = MIN((int)subtype_arr->len, 10);
            const char *thdrs[] = {"Message Type", "Frame Count"};
            char ***trows = (char ***)g_new0(gpointer, n);
            char row_data[10][2][64];
            for (int i = 0; i < n; i++) {
                str_count_pair_t *p = &g_array_index(subtype_arr, str_count_pair_t, i);
                guint type = 0, subtype = 0;
                if (sscanf(p->key, "%u-%u", &type, &subtype) == 2) {
                    g_strlcpy(row_data[i][0],
                              wifi_frame_type_name(type, subtype),
                              sizeof(row_data[i][0]));
                } else {
                    g_strlcpy(row_data[i][0], p->key, sizeof(row_data[i][0]));
                }
                snprintf(row_data[i][1], sizeof(row_data[i][1]),
                         "%" G_GUINT64_FORMAT, p->count);
                trows[i] = (char **)g_new0(gpointer, 2);
                trows[i][0] = row_data[i][0];
                trows[i][1] = row_data[i][1];
            }
            table_def_t tbl = { thdrs, 2, (const char ***)trows, n };
            renderer_draw_table(cr, "7.1 Top 10 802.11 Message Types",
                                &tbl, margin, y, content_w);
            for (int i = 0; i < n; i++) g_free(trows[i]);
            g_free(trows);
        }
        g_array_free(subtype_arr, TRUE);
    }
    WANN_SIDEBAR(&wann_frame_types);
    WANN_PAGE_END();

    /* ==== 8. Deauth / Disassoc Reasons ==== */
    WANN_NEW_PAGE("8. Deauth / Disassoc Reasons");
    WANN_TAG_DEST("section8");
    {
        if (result->deauth == 0 && result->disassoc == 0) {
            renderer_set_font(cr, "sans-serif", CAIRO_FONT_SLANT_ITALIC,
                              CAIRO_FONT_WEIGHT_NORMAL, 10.0);
            cairo_set_source_rgb(cr, 0.5, 0.5, 0.5);
            cairo_move_to(cr, margin, y);
            cairo_show_text(cr,
                "No deauthentication or disassociation frames detected.");
        } else {
            renderer_set_font(cr, "sans-serif", CAIRO_FONT_SLANT_ITALIC,
                              CAIRO_FONT_WEIGHT_NORMAL, 9.0);
            cairo_set_source_rgb(cr, 0.4, 0.4, 0.4);
            cairo_move_to(cr, margin, y);
            cairo_show_text(cr,
                "Deauth/disassociation frames indicate clients leaving "
                "the network. Frequent occurrences may signal issues.");
            y += 18;

            snprintf(buf, sizeof(buf),
                     "Deauthentications: %" G_GUINT64_FORMAT
                     "   Disassociations: %" G_GUINT64_FORMAT,
                     result->deauth, result->disassoc);
            renderer_set_font(cr, "sans-serif", CAIRO_FONT_SLANT_NORMAL,
                              CAIRO_FONT_WEIGHT_NORMAL, 10.0);
            cairo_set_source_rgb(cr, 0.2, 0.2, 0.2);
            cairo_move_to(cr, margin, y);
            cairo_show_text(cr, buf); y += 20;

            GArray *reason_arr = collect_uint_hash_sorted_by_count(result->reason_codes);
            if (reason_arr->len > 0) {
                int n = MIN((int)reason_arr->len, 10);
                pie_item_t pitems[10];
                char labels[10][80];
                for (int i = 0; i < n; i++) {
                    uint_count_pair_t *p = &g_array_index(reason_arr, uint_count_pair_t, i);
                    snprintf(labels[i], sizeof(labels[i]), "%u: %s",
                             p->key, wifi_reason_code_name(p->key));
                    pitems[i].label = labels[i];
                    pitems[i].value = (double)p->count;
                }
                renderer_draw_pie_chart(cr, "Deauth/Disassoc Reason Codes",
                                        pitems, n, margin, y, content_w, 280);
            }
            g_array_free(reason_arr, TRUE);
        }
    }
    WANN_SIDEBAR(&wann_deauth);
    WANN_PAGE_END();

    /* ==== 9. Retry Analysis ==== */
    WANN_NEW_PAGE("9. Retry Analysis");
    WANN_TAG_DEST("section9");
    {
        if (result->total_data_frames == 0) {
            renderer_set_font(cr, "sans-serif", CAIRO_FONT_SLANT_ITALIC,
                              CAIRO_FONT_WEIGHT_NORMAL, 10.0);
            cairo_set_source_rgb(cr, 0.5, 0.5, 0.5);
            cairo_move_to(cr, margin, y);
            cairo_show_text(cr, "No data frames detected for retry analysis.");
            y += 20;
        } else {
            renderer_set_font(cr, "sans-serif", CAIRO_FONT_SLANT_NORMAL,
                              CAIRO_FONT_WEIGHT_NORMAL, 10.0);
            cairo_set_source_rgb(cr, 0.2, 0.2, 0.2);

            snprintf(buf, sizeof(buf), "Total Data Frames: %" G_GUINT64_FORMAT,
                     result->total_data_frames);
            cairo_move_to(cr, margin, y); cairo_show_text(cr, buf); y += 16;

            snprintf(buf, sizeof(buf), "Retried Frames: %" G_GUINT64_FORMAT,
                     result->retry_count);
            cairo_move_to(cr, margin, y); cairo_show_text(cr, buf); y += 16;

            double retry_pct = 0.0;
            if (result->total_data_frames > 0)
                retry_pct = (double)result->retry_count * 100.0 /
                            (double)result->total_data_frames;
            snprintf(buf, sizeof(buf), "Retry Rate: %.1f%%", retry_pct);
            cairo_move_to(cr, margin, y); cairo_show_text(cr, buf); y += 20;

            if (result->fcs_good > 0 || result->fcs_bad > 0) {
                snprintf(buf, sizeof(buf),
                         "FCS Good: %" G_GUINT64_FORMAT "   FCS Bad: %" G_GUINT64_FORMAT,
                         result->fcs_good, result->fcs_bad);
                cairo_move_to(cr, margin, y); cairo_show_text(cr, buf); y += 16;
            }

            snprintf(buf, sizeof(buf), "EAPOL Frames: %" G_GUINT64_FORMAT,
                     result->eapol_frames);
            cairo_move_to(cr, margin, y); cairo_show_text(cr, buf); y += 20;

            snprintf(buf, sizeof(buf),
                     "Assoc Req/Resp: %" G_GUINT64_FORMAT "/%" G_GUINT64_FORMAT
                     "   Reassoc Req/Resp: %" G_GUINT64_FORMAT "/%" G_GUINT64_FORMAT,
                     result->assoc_req, result->assoc_resp,
                     result->reassoc_req, result->reassoc_resp);
            cairo_move_to(cr, margin, y); cairo_show_text(cr, buf); y += 20;
        }
    }
    WANN_SIDEBAR(&wann_retry);
    WANN_PAGE_END();

    /* ==== 10. Top Airtime Talkers ==== */
    WANN_NEW_PAGE("10. Top Airtime Talkers");
    WANN_TAG_DEST("section10");
    {
        if (result->airtime_total_us <= 0.0) {
            renderer_set_font(cr, "sans-serif", CAIRO_FONT_SLANT_ITALIC,
                              CAIRO_FONT_WEIGHT_NORMAL, 10.0);
            cairo_set_source_rgb(cr, 0.5, 0.5, 0.5);
            cairo_move_to(cr, margin, y);
            cairo_show_text(cr,
                "No airtime data (requires data rate in radiotap header).");
        } else {
            renderer_set_font(cr, "sans-serif", CAIRO_FONT_SLANT_ITALIC,
                              CAIRO_FONT_WEIGHT_NORMAL, 9.0);
            cairo_set_source_rgb(cr, 0.4, 0.4, 0.4);
            snprintf(buf, sizeof(buf),
                     "Total estimated airtime: %.1f seconds",
                     result->airtime_total_us / 1e6);
            cairo_move_to(cr, margin, y);
            cairo_show_text(cr, buf); y += 18;

            GList *top_at = wifi_top_clients_by_airtime(
                                (wifi_collection_result_t *)result, 10);
            int n = g_list_length(top_at);
            if (n > 0) {
                bar_item_t items[10];
                char labels[10][80];
                int i = 0;
                for (GList *l = top_at; l && i < 10; l = l->next, i++) {
                    wifi_client_stats_t *cs = (wifi_client_stats_t *)l->data;
                    if (cs->vendor)
                        snprintf(labels[i], sizeof(labels[i]),
                                 "%s (%s)", cs->mac, cs->vendor);
                    else
                        g_strlcpy(labels[i], cs->mac, sizeof(labels[i]));
                    items[i].label = labels[i];
                    items[i].value = cs->airtime_us / 1000.0;
                }
                renderer_draw_bar_chart(cr, "Top Airtime Talkers (ms)",
                                        items, i,
                                        margin, y, content_w, 250);
            }
            g_list_free(top_at);
        }
    }
    WANN_SIDEBAR(&wann_airtime);
    WANN_PAGE_END();

    /* ==== Summary Page ==== */
    cairo_set_source_rgb(cr, 1, 1, 1);
    cairo_paint(cr);
    y = margin;
    renderer_draw_section_header(cr, "Summary", margin, y, full_w);
    y += 50;
    WANN_TAG_DEST("section11");

    {
        char vbuf[256];

        renderer_set_font(cr, "sans-serif", CAIRO_FONT_SLANT_NORMAL,
                          CAIRO_FONT_WEIGHT_BOLD, 12.0);
        cairo_set_source_rgb(cr, 0.17, 0.48, 0.71);
        cairo_move_to(cr, margin, y);
        cairo_show_text(cr, "WiFi Capture at a Glance");
        y += 24;

        renderer_set_font(cr, "sans-serif", CAIRO_FONT_SLANT_NORMAL,
                          CAIRO_FONT_WEIGHT_NORMAL, 10.0);
        cairo_set_source_rgb(cr, 0.15, 0.15, 0.15);

        snprintf(vbuf, sizeof(vbuf),
                 "This WiFi capture contains %" G_GUINT64_FORMAT " frames totaling ",
                 result->total_packets);
        cairo_move_to(cr, margin, y);
        cairo_show_text(cr, vbuf); y += 16;

        {
            char bbuf[64];
            format_bytes_str(result->total_bytes, bbuf, sizeof(bbuf));
            char dbuf[64];
            format_duration_str(result->duration, dbuf, sizeof(dbuf));
            snprintf(vbuf, sizeof(vbuf), "%s over a duration of %s.", bbuf, dbuf);
        }
        cairo_move_to(cr, margin, y);
        cairo_show_text(cr, vbuf); y += 28;

        renderer_set_font(cr, "sans-serif", CAIRO_FONT_SLANT_NORMAL,
                          CAIRO_FONT_WEIGHT_BOLD, 12.0);
        cairo_set_source_rgb(cr, 0.17, 0.48, 0.71);
        cairo_move_to(cr, margin, y);
        cairo_show_text(cr, "Key Metrics");
        y += 20;

        #define WANN_SUM(label, fmt, ...) do { \
            renderer_set_font(cr, "sans-serif", CAIRO_FONT_SLANT_NORMAL, \
                              CAIRO_FONT_WEIGHT_BOLD, 9.0); \
            cairo_set_source_rgb(cr, 0.3, 0.3, 0.3); \
            cairo_move_to(cr, margin + 10, y); \
            cairo_show_text(cr, (label)); \
            renderer_set_font(cr, "sans-serif", CAIRO_FONT_SLANT_NORMAL, \
                              CAIRO_FONT_WEIGHT_NORMAL, 9.0); \
            cairo_set_source_rgb(cr, 0.15, 0.15, 0.15); \
            snprintf(vbuf, sizeof(vbuf), fmt, __VA_ARGS__); \
            cairo_move_to(cr, margin + 180, y); \
            cairo_show_text(cr, vbuf); \
            y += 16; \
        } while(0)

        WANN_SUM("BSSIDs Discovered:", "%u",
                 result->bssid_table ? g_hash_table_size(result->bssid_table) : 0);
        WANN_SUM("Client MACs:", "%u",
                 result->client_table ? g_hash_table_size(result->client_table) : 0);
        WANN_SUM("Management Frames:", "%" G_GUINT64_FORMAT, result->frame_mgmt);
        WANN_SUM("Control Frames:", "%" G_GUINT64_FORMAT, result->frame_control);
        WANN_SUM("Data Frames:", "%" G_GUINT64_FORMAT, result->frame_data);
        if (result->total_data_frames > 0) {
            double retry_pct = (double)result->retry_count * 100.0 /
                               (double)result->total_data_frames;
            WANN_SUM("Retry Rate:", "%.1f%%", retry_pct);
        }
        WANN_SUM("Deauthentications:", "%" G_GUINT64_FORMAT, result->deauth);
        WANN_SUM("Disassociations:", "%" G_GUINT64_FORMAT, result->disassoc);
        #undef WANN_SUM

        y += 20;
        renderer_set_font(cr, "sans-serif", CAIRO_FONT_SLANT_NORMAL,
                          CAIRO_FONT_WEIGHT_BOLD, 12.0);
        cairo_set_source_rgb(cr, 0.17, 0.48, 0.71);
        cairo_move_to(cr, margin, y);
        cairo_show_text(cr, "Reading This Report");
        y += 20;

        cairo_set_source_rgb(cr, 0.2, 0.2, 0.2);
        y = draw_wrapped_text(cr,
            "Each section of this report includes an annotation sidebar on the "
            "right side of the page. The sidebar explains where the data comes "
            "from (which Wireshark fields or radiotap headers), what data points "
            "are being measured, and how to interpret the results even if you are "
            "not a WiFi analysis expert.",
            margin, y, full_w, 9.0, 14.0);
        y += 10;

        y = draw_wrapped_text(cr,
            "Look for: weak RSSI values, low SNR, high retry rates, unexpected "
            "deauthentication frames, channel congestion, and clients stuck on "
            "low MCS indices. These are typically the most actionable findings "
            "in a WiFi capture analysis.",
            margin, y, full_w, 9.0, 14.0);
        y += 10;

        y = draw_wrapped_text(cr,
            "This report was generated by PacketReporter Pro "
            PLUGIN_VERSION_STR ". For more information visit "
            "https://github.com/netwho/PacketCirclePro",
            margin, y, full_w, 9.0, 14.0);
    }

    renderer_draw_page_footer(cr, paper, page_num);
    cairo_show_page(cr);
    page_num++;

    #undef WANN_NEW_PAGE
    #undef WANN_SIDEBAR
    #undef WANN_PAGE_END
    #undef WANN_TAG_DEST

    cairo_destroy(cr);
    cairo_surface_destroy(surface);

    ws_log(WS_LOG_DOMAIN, LOG_LEVEL_INFO,
           "WiFi annotated %s PDF (%d pages) written to %s",
           paper->name, page_num - 1, path);
    return path;
}

/* ================================================================
 * WiFi Executive Summary — single A4 page
 *
 * Key WiFi metrics tiles, channel pie chart, top-5 MAC talkers
 * bar chart.  Designed for a quick overview printout.
 * ================================================================ */

char *pdf_export_wifi_summary(const wifi_collection_result_t *result,
                              const reporter_config_t *cfg,
                              const char *out_path)
{
    const paper_size_t *paper = &PAPER_A4_SIZE;
    char *path;
    cairo_surface_t *surface;
    cairo_t *cr;
    double y;
    double margin    = 50.0;
    double content_w = paper->width_pt - 2 * margin;
    char buf[128];

    path = make_output_path(out_path, "wifi_summary");

    surface = cairo_pdf_surface_create(path,
                                       paper->width_pt, paper->height_pt);
    if (cairo_surface_status(surface) != CAIRO_STATUS_SUCCESS) {
        ws_log(WS_LOG_DOMAIN, LOG_LEVEL_WARNING,
               "Could not create WiFi summary PDF: %s", path);
        g_free(path);
        return NULL;
    }
    cr = cairo_create(surface);

    cairo_set_source_rgb(cr, 1, 1, 1);
    cairo_paint(cr);

    y = margin;

    /* Logo or title */
    if (cfg && cfg->logo_loaded && cfg->logo_surface) {
        double img_w  = (double)cfg->logo_width;
        double img_h  = (double)cfg->logo_height;
        double max_h  = 60.0;
        double scale  = max_h / img_h;

        cairo_save(cr);
        cairo_translate(cr, margin, y);
        cairo_scale(cr, scale, scale);
        cairo_set_source_surface(cr, cfg->logo_surface, 0, 0);
        cairo_paint(cr);
        cairo_restore(cr);

        y += max_h + 10;
    }

    renderer_set_font(cr, "sans-serif",
                      CAIRO_FONT_SLANT_NORMAL,
                      CAIRO_FONT_WEIGHT_BOLD, 24.0);
    cairo_set_source_rgb(cr, 0.0, 0.65, 0.79);  /* WiFi teal */
    cairo_move_to(cr, margin, y);
    cairo_show_text(cr, "WiFi Executive Summary");
    y += 16;

    if (cfg && cfg->desc_line1 && *cfg->desc_line1) {
        renderer_set_font(cr, "sans-serif",
                          CAIRO_FONT_SLANT_NORMAL,
                          CAIRO_FONT_WEIGHT_NORMAL, 11.0);
        cairo_set_source_rgb(cr, 0.3, 0.3, 0.3);
        cairo_move_to(cr, margin, y + 14);
        cairo_show_text(cr, cfg->desc_line1);
        y += 20;
    }

    /* Separator */
    y += 10;
    cairo_set_source_rgb(cr, 0.0, 0.65, 0.79);
    cairo_set_line_width(cr, 1.5);
    cairo_move_to(cr, margin, y);
    cairo_line_to(cr, margin + content_w, y);
    cairo_stroke(cr);
    y += 25;

    /* ── Key metrics tiles ── */
    {
        double tile_w = content_w / 3.0 - 10;
        double tile_h = 60;
        int col;

        struct { const char *label; char value[64]; } metrics[9];
        int n_metrics = 0;

        snprintf(metrics[n_metrics].value, 64, "%" G_GUINT64_FORMAT,
                 result->total_packets);
        metrics[n_metrics].label = "Packets";
        n_metrics++;

        {
            char bb[64];
            format_bytes_str(result->total_bytes, bb, sizeof(bb));
            snprintf(metrics[n_metrics].value, 64, "%s", bb);
        }
        metrics[n_metrics].label = "Bytes";
        n_metrics++;

        {
            char db[64];
            format_duration_str(result->duration, db, sizeof(db));
            snprintf(metrics[n_metrics].value, 64, "%s", db);
        }
        metrics[n_metrics].label = "Duration";
        n_metrics++;

        snprintf(metrics[n_metrics].value, 64, "%u",
                 result->bssid_table ? g_hash_table_size(result->bssid_table) : 0);
        metrics[n_metrics].label = "BSSIDs";
        n_metrics++;

        snprintf(metrics[n_metrics].value, 64, "%u",
                 result->client_table ? g_hash_table_size(result->client_table) : 0);
        metrics[n_metrics].label = "Clients";
        n_metrics++;

        snprintf(metrics[n_metrics].value, 64, "%u",
                 result->channel_usage ? g_hash_table_size(result->channel_usage) : 0);
        metrics[n_metrics].label = "Channels";
        n_metrics++;

        /* RSSI average */
        {
            gint64 rssi_total = 0;
            guint64 rssi_cnt = 0;
            GHashTableIter it;
            gpointer kk, vv;
            if (result->rssi_buckets) {
                g_hash_table_iter_init(&it, result->rssi_buckets);
                while (g_hash_table_iter_next(&it, &kk, &vv)) {
                    gint bucket = GPOINTER_TO_INT(kk);
                    guint64 cnt = *(guint64 *)vv;
                    rssi_total += (gint64)(bucket + 2) * (gint64)cnt;
                    rssi_cnt += cnt;
                }
            }
            if (rssi_cnt > 0) {
                snprintf(metrics[n_metrics].value, 64, "%d dBm",
                         (int)(rssi_total / (gint64)rssi_cnt));
                metrics[n_metrics].label = "Avg RSSI";
                n_metrics++;
            }
        }

        /* Retry rate */
        if (result->total_data_frames > 0) {
            double rate = 100.0 * (double)result->retry_count
                          / (double)result->total_data_frames;
            snprintf(metrics[n_metrics].value, 64, "%.1f%%", rate);
            metrics[n_metrics].label = "Retry Rate";
            n_metrics++;
        }

        /* Frame composition */
        {
            guint64 total = result->frame_mgmt + result->frame_control
                            + result->frame_data;
            if (total > 0) {
                snprintf(metrics[n_metrics].value, 64, "%.0f%% Data",
                         100.0 * (double)result->frame_data / (double)total);
                metrics[n_metrics].label = "Frame Mix";
                n_metrics++;
            }
        }

        for (col = 0; col < n_metrics; col++) {
            double tx = margin + (col % 3) * (tile_w + 10);
            double ty = y + (col / 3) * (tile_h + 8);

            cairo_set_source_rgb(cr, 0.96, 0.96, 0.96);
            cairo_rectangle(cr, tx, ty, tile_w, tile_h);
            cairo_fill(cr);

            renderer_set_font(cr, "sans-serif",
                              CAIRO_FONT_SLANT_NORMAL,
                              CAIRO_FONT_WEIGHT_BOLD, 20.0);
            cairo_set_source_rgb(cr, 0.0, 0.65, 0.79);
            cairo_move_to(cr, tx + 10, ty + 30);
            cairo_show_text(cr, metrics[col].value);

            renderer_set_font(cr, "sans-serif",
                              CAIRO_FONT_SLANT_NORMAL,
                              CAIRO_FONT_WEIGHT_NORMAL, 9.0);
            cairo_set_source_rgb(cr, 0.4, 0.4, 0.4);
            cairo_move_to(cr, tx + 10, ty + 48);
            cairo_show_text(cr, metrics[col].label);
        }

        y += ((n_metrics + 2) / 3) * (tile_h + 8) + 20;
    }

    /* ── Channel usage pie chart ── */
    {
        GArray *ch_arr = collect_uint_hash_sorted(result->channel_usage);
        int count = (int)ch_arr->len;
        if (count > 0) {
            int show = count > 8 ? 8 : count;
            pie_item_t *items = g_new0(pie_item_t, show);
            char (*ch_lbls)[16] = (char (*)[16])g_malloc0(show * 16);
            int i;
            for (i = 0; i < show; i++) {
                uint_count_pair_t *p =
                    &g_array_index(ch_arr, uint_count_pair_t, i);
                snprintf(ch_lbls[i], 16, "Ch %u", p->key);
                items[i].label = ch_lbls[i];
                items[i].value = (double)p->count;
            }
            renderer_draw_pie_chart(cr, "Channel Usage",
                                    items, show,
                                    margin, y, content_w, 200);
            g_free(items);
            g_free(ch_lbls);
            y += 215;
        }
        g_array_free(ch_arr, TRUE);
    }

    /* ── Top 5 MAC addresses bar chart ── */
    {
        GList *top_macs = wifi_top_macs_by_frames(
                              (wifi_collection_result_t *)result, 5);
        int count = (int)g_list_length(top_macs);
        if (count > 0) {
            bar_item_t *items = g_new0(bar_item_t, count);
            GList *l;
            int i;
            for (l = top_macs, i = 0; l; l = l->next, i++) {
                wifi_client_stats_t *cs = (wifi_client_stats_t *)l->data;
                items[i].label = cs->mac;
                items[i].value = (double)cs->frames;
            }
            renderer_draw_bar_chart(cr, "Top 5 Talkers (by frames)",
                                    items, count,
                                    margin, y, content_w, 200);
            g_free(items);
        }
        g_list_free(top_macs);
    }

    /* Footer */
    {
        char date_buf[64];
        time_t now = time(NULL);
        struct tm *tm_now = localtime(&now);
        if (!tm_now) {
            g_snprintf(date_buf, sizeof(date_buf), "Unknown");
        } else {
            strftime(date_buf, sizeof(date_buf), "%Y-%m-%d %H:%M:%S", tm_now);
        }
        char footer[128];
        snprintf(footer, sizeof(footer),
                 BRAND_NAME " " PLUGIN_VERSION_STR " WiFi Summary - %s", date_buf);
        renderer_set_font(cr, "sans-serif",
                          CAIRO_FONT_SLANT_NORMAL,
                          CAIRO_FONT_WEIGHT_NORMAL, 8.0);
        cairo_set_source_rgb(cr, 0.6, 0.6, 0.6);
        double fw = renderer_text_width(cr, footer);
        cairo_move_to(cr, (paper->width_pt - fw) / 2.0,
                      paper->height_pt - 30);
        cairo_show_text(cr, footer);
    }

    cairo_show_page(cr);
    cairo_destroy(cr);
    cairo_surface_destroy(surface);

    ws_log(WS_LOG_DOMAIN, LOG_LEVEL_INFO,
           "WiFi summary PDF written to %s", path);
    return path;
}

/* ================================================================
 * Executive Summary — auto-detecting WiFi vs Network capture
 *
 * If the capture has WiFi (802.11 monitor-mode) frames, the
 * executive summary shows WiFi-specific metrics.  Otherwise
 * it falls through to the standard network executive summary.
 * ================================================================ */

static gboolean wifi_capture_detected(const wifi_collection_result_t *wr)
{
    if (!wr) return FALSE;
    if (wr->frame_mgmt + wr->frame_control + wr->frame_data > 0) return TRUE;
    if (wr->bssid_table && g_hash_table_size(wr->bssid_table) > 0) return TRUE;
    return FALSE;
}

char *pdf_export_executive(const collection_result_t *net_result,
                           const wifi_collection_result_t *wifi_result,
                           const reporter_config_t *cfg,
                           const char *out_path)
{
    if (!net_result && !wifi_result) {
        ws_log(WS_LOG_DOMAIN, LOG_LEVEL_WARNING,
               "pdf_export_executive: no data available");
        return NULL;
    }
    if (wifi_capture_detected(wifi_result))
        return pdf_export_wifi_summary(wifi_result, cfg, out_path);

    return pdf_export_management(net_result, cfg, out_path);
}
