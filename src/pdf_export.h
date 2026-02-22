#ifndef PDF_EXPORT_H
#define PDF_EXPORT_H

#include <glib.h>
#include "packet_collector.h"
#include "config_reader.h"
#include "wifi_collector.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Generate a summary report PDF (single page).
 *
 * @param result    Collected packet statistics
 * @param cfg       User configuration (logo, description)
 * @param out_path  Output PDF path (if NULL, auto-generated)
 * @return Newly-allocated string with the output path, or NULL on failure.
 *         Caller must g_free().
 */
char *pdf_export_summary(const collection_result_t *result,
                         const reporter_config_t *cfg,
                         const char *out_path);

/**
 * Generate a detailed report PDF (multi-page with cover).
 *
 * @param result    Collected packet statistics
 * @param cfg       User configuration
 * @param paper     Paper size (A4 or Legal)
 * @param out_path  Output PDF path (if NULL, auto-generated)
 * @return Newly-allocated string with the output path, or NULL on failure.
 *         Caller must g_free().
 */
char *pdf_export_detailed(const collection_result_t *result,
                          const reporter_config_t *cfg,
                          const paper_size_t *paper,
                          const char *out_path);

/**
 * Generate a one-page management / executive summary PDF.
 * Large-font key metrics, protocol pie, top-5 talkers bar chart.
 *
 * @param result    Collected packet statistics
 * @param cfg       User configuration (logo, description)
 * @param out_path  Output PDF path (if NULL, auto-generated)
 * @return Newly-allocated path or NULL on failure. Caller g_free().
 */
char *pdf_export_management(const collection_result_t *result,
                            const reporter_config_t *cfg,
                            const char *out_path);

/**
 * Generate a WiFi detailed report PDF (multi-page with cover).
 * Sections: PCAP summary, Top MACs, RSSI, SNR, Channels,
 *           MCS, Frame types, Deauth/Disassoc, Retries, Airtime.
 *
 * @param result    WiFi-specific collected statistics
 * @param cfg       User configuration
 * @param paper     Paper size (A4 or Legal)
 * @param out_path  Output PDF path (if NULL, auto-generated)
 * @return Newly-allocated path or NULL on failure. Caller g_free().
 */
char *pdf_export_wifi(const wifi_collection_result_t *result,
                      const reporter_config_t *cfg,
                      const paper_size_t *paper,
                      const char *out_path);

/**
 * Generate a WiFi executive summary PDF (single page, A4).
 * Key WiFi metrics tiles, channel pie chart, top-5 talkers bar chart.
 *
 * @param result    WiFi-specific collected statistics
 * @param cfg       User configuration (logo, description)
 * @param out_path  Output PDF path (if NULL, auto-generated)
 * @return Newly-allocated path or NULL on failure. Caller g_free().
 */
char *pdf_export_wifi_summary(const wifi_collection_result_t *result,
                              const reporter_config_t *cfg,
                              const char *out_path);

/**
 * Generate an annotated report PDF (multi-page with cover).
 * Same content as the detailed report, but each section uses a 2/3 + 1/3
 * layout: charts and tables in the left 2/3, an annotation sidebar in the
 * right 1/3 explaining data sources, data points, and interpretation.
 * Ends with a summary page.
 *
 * @param result    Collected packet statistics
 * @param cfg       User configuration
 * @param paper     Paper size (A4 or Legal)
 * @param out_path  Output PDF path (if NULL, auto-generated)
 * @return Newly-allocated string with the output path, or NULL on failure.
 *         Caller must g_free().
 */
char *pdf_export_annotated(const collection_result_t *result,
                           const reporter_config_t *cfg,
                           const paper_size_t *paper,
                           const char *out_path);

/**
 * Generate a WiFi annotated report PDF (multi-page with cover).
 * Same content as the WiFi detailed report, but each section uses a
 * 60% + 40% layout: charts in the left 60%, annotation sidebar in
 * the right 40%. Ends with a summary page.
 *
 * @param result    WiFi-specific collected statistics
 * @param cfg       User configuration
 * @param paper     Paper size (A4 or Legal)
 * @param out_path  Output PDF path (if NULL, auto-generated)
 * @return Newly-allocated path or NULL on failure. Caller g_free().
 */
char *pdf_export_wifi_annotated(const wifi_collection_result_t *result,
                                const reporter_config_t *cfg,
                                const paper_size_t *paper,
                                const char *out_path);

/**
 * Generate an executive summary PDF that auto-detects the capture type.
 * For WiFi/monitor-mode captures (with 802.11 frames), shows WiFi metrics.
 * For regular captures, shows network/IP metrics.
 *
 * @param net_result  Network statistics (always collected)
 * @param wifi_result WiFi statistics (always collected; checked for WiFi data)
 * @param cfg         User configuration
 * @param out_path    Output PDF path (if NULL, auto-generated)
 * @return Newly-allocated path or NULL on failure. Caller g_free().
 */
char *pdf_export_executive(const collection_result_t *net_result,
                           const wifi_collection_result_t *wifi_result,
                           const reporter_config_t *cfg,
                           const char *out_path);

/**
 * Get the default reports output directory.
 * Creates the directory if it does not exist.
 * @return Newly-allocated path string. Caller must g_free().
 */
char *pdf_export_get_reports_dir(void);

/**
 * Open a file with the platform default application.
 */
void pdf_export_open_file(const char *path);

#ifdef __cplusplus
}
#endif

#endif /* PDF_EXPORT_H */
