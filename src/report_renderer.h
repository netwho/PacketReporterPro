#ifndef REPORT_RENDERER_H
#define REPORT_RENDERER_H

#include <cairo.h>
#include <cairo-pdf.h>
#include "packet_collector.h"
#include "config_reader.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Brand colours (matching the Lua plugin's palette) */
#define CLR_PRIMARY_R   0.173   /* #2C7BB6 */
#define CLR_PRIMARY_G   0.482
#define CLR_PRIMARY_B   0.714

/* Chart colour palette (10 entries, cycled) */
typedef struct { double r, g, b; } rgb_t;
extern const rgb_t CHART_PALETTE[10];

/* ----------------------------------------------------------------
 * Bar chart
 * ---------------------------------------------------------------- */
typedef struct {
    const char *label;
    double      value;
} bar_item_t;

void renderer_draw_bar_chart(cairo_t *cr, const char *title,
                             const bar_item_t *items, int count,
                             double x, double y,
                             double width, double height);

/**
 * Bar chart with per-bar custom colours (e.g. quality-based RSSI/SNR).
 * If colors is NULL, falls back to the standard palette.
 */
void renderer_draw_bar_chart_colored(cairo_t *cr, const char *title,
                                     const bar_item_t *items,
                                     const rgb_t *colors, int count,
                                     double x, double y,
                                     double width, double height);

/* ----------------------------------------------------------------
 * Pie chart
 * ---------------------------------------------------------------- */
typedef struct {
    const char *label;
    double      value;
} pie_item_t;

void renderer_draw_pie_chart(cairo_t *cr, const char *title,
                             const pie_item_t *items, int count,
                             double x, double y,
                             double width, double height);

/* ----------------------------------------------------------------
 * Table
 * ---------------------------------------------------------------- */
typedef struct {
    const char **headers;   /* array of column titles */
    int          n_cols;
    const char ***rows;     /* array of row arrays */
    int          n_rows;
} table_def_t;

double renderer_draw_table(cairo_t *cr, const char *title,
                           const table_def_t *tbl,
                           double x, double y, double width);

/* ----------------------------------------------------------------
 * Chord / circle diagram (communication matrix)
 * ---------------------------------------------------------------- */
void renderer_draw_chord_diagram(cairo_t *cr, const char *title,
                                 const char **node_labels, int num_nodes,
                                 const guint64 *matrix,
                                 double x, double y,
                                 double width, double height);

/* ----------------------------------------------------------------
 * Cover page
 * ---------------------------------------------------------------- */
void renderer_draw_cover_page(cairo_t *cr, const paper_size_t *paper,
                              const reporter_config_t *cfg,
                              const char **toc_titles, const int *toc_pages,
                              int toc_count);

/* ----------------------------------------------------------------
 * Section header / footer helpers
 * ---------------------------------------------------------------- */
void renderer_draw_section_header(cairo_t *cr, const char *title,
                                  double x, double y, double width);

void renderer_draw_page_footer(cairo_t *cr, const paper_size_t *paper,
                               int page_num);

/* ----------------------------------------------------------------
 * Text helpers
 * ---------------------------------------------------------------- */
void renderer_set_font(cairo_t *cr, const char *family,
                       cairo_font_slant_t slant,
                       cairo_font_weight_t weight,
                       double size);

double renderer_text_width(cairo_t *cr, const char *text);

/* Format helpers */
const char *format_bytes_str(guint64 bytes, char *buf, size_t buf_size);
const char *format_duration_str(double seconds, char *buf, size_t buf_size);

#ifdef __cplusplus
}
#endif

#endif /* REPORT_RENDERER_H */
