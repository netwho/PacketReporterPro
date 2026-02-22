#include <config.h>
#include <wireshark.h>

#include "report_renderer.h"
#include "reporter_plugin.h"

#include <cairo.h>
#include <cairo-pdf.h>
#include <math.h>
#include <string.h>
#include <stdio.h>
#include <time.h>

#ifndef MIN
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#endif

/* ----------------------------------------------------------------
 * Colour palette (matches Lua plugin)
 * ---------------------------------------------------------------- */
const rgb_t CHART_PALETTE[10] = {
    {0.173, 0.482, 0.714},   /* #2C7BB6 */
    {0.000, 0.651, 0.792},   /* #00A6CA */
    {0.000, 0.800, 0.737},   /* #00CCBC */
    {0.565, 0.933, 0.565},   /* #90EE90 */
    {1.000, 0.843, 0.000},   /* #FFD700 */
    {1.000, 0.549, 0.259},   /* #FF8C42 */
    {1.000, 0.420, 0.420},   /* #FF6B6B */
    {0.851, 0.275, 0.937},   /* #D946EF */
    {0.545, 0.361, 0.965},   /* #8B5CF6 */
    {0.024, 0.714, 0.831},   /* #06B6D4 */
};

/* ----------------------------------------------------------------
 * Text helpers
 * ---------------------------------------------------------------- */

void renderer_set_font(cairo_t *cr, const char *family,
                       cairo_font_slant_t slant,
                       cairo_font_weight_t weight,
                       double size)
{
    cairo_select_font_face(cr, family, slant, weight);
    cairo_set_font_size(cr, size);
}

double renderer_text_width(cairo_t *cr, const char *text)
{
    cairo_text_extents_t ext;
    cairo_text_extents(cr, text, &ext);
    return ext.x_advance;
}

const char *format_bytes_str(guint64 bytes, char *buf, size_t buf_size)
{
    if (bytes < 1024ULL)
        snprintf(buf, buf_size, "%" G_GUINT64_FORMAT " B", bytes);
    else if (bytes < 1024ULL * 1024)
        snprintf(buf, buf_size, "%.1f KB", (double)bytes / 1024.0);
    else if (bytes < 1024ULL * 1024 * 1024)
        snprintf(buf, buf_size, "%.1f MB", (double)bytes / (1024.0 * 1024.0));
    else
        snprintf(buf, buf_size, "%.1f GB", (double)bytes / (1024.0 * 1024.0 * 1024.0));
    return buf;
}

const char *format_duration_str(double seconds, char *buf, size_t buf_size)
{
    if (seconds < 1.0)
        snprintf(buf, buf_size, "%.3f ms", seconds * 1000.0);
    else if (seconds < 60.0)
        snprintf(buf, buf_size, "%.2f s", seconds);
    else if (seconds < 3600.0)
        snprintf(buf, buf_size, "%dm %02ds",
                 (int)(seconds / 60.0), (int)fmod(seconds, 60.0));
    else
        snprintf(buf, buf_size, "%dh %02dm %02ds",
                 (int)(seconds / 3600.0),
                 (int)(fmod(seconds, 3600.0) / 60.0),
                 (int)fmod(seconds, 60.0));
    return buf;
}

/* ----------------------------------------------------------------
 * Bar chart
 * ---------------------------------------------------------------- */

void renderer_draw_bar_chart(cairo_t *cr, const char *title,
                             const bar_item_t *items, int count,
                             double x, double y,
                             double width, double height)
{
    double max_val = 0;
    double title_h, label_zone, left_pad, bar_area_w, bar_w, chart_h, chart_top;
    int i;
    char val_buf[64];
    char label_buf[24];

    if (count <= 0) return;

    title_h    = 40;
    label_zone = 80;
    left_pad   = 25;

    /* Title — drawn inside the bounding box with clear gap below */
    renderer_set_font(cr, "sans-serif",
                      CAIRO_FONT_SLANT_NORMAL,
                      CAIRO_FONT_WEIGHT_BOLD, 11.0);
    cairo_set_source_rgb(cr, 0.067, 0.067, 0.067);
    cairo_move_to(cr, x, y + 14);
    cairo_show_text(cr, title);

    chart_top  = y + title_h;
    chart_h    = height - title_h - label_zone;
    if (chart_h < 20) chart_h = 20;
    bar_area_w = width - left_pad - 10;
    bar_w      = bar_area_w / count;

    for (i = 0; i < count; i++)
        if (items[i].value > max_val) max_val = items[i].value;
    if (max_val == 0) max_val = 1;

    for (i = 0; i < count; i++) {
        double bar_h = (items[i].value / max_val) * chart_h;
        double bx    = x + left_pad + i * bar_w;
        double by    = chart_top + chart_h - bar_h;
        const rgb_t *c = &CHART_PALETTE[i % 10];

        cairo_set_source_rgb(cr, c->r, c->g, c->b);
        cairo_rectangle(cr, bx + 2, by, bar_w - 4, bar_h);
        cairo_fill(cr);

        /* Value label above bar */
        renderer_set_font(cr, "sans-serif",
                          CAIRO_FONT_SLANT_NORMAL,
                          CAIRO_FONT_WEIGHT_NORMAL, 8.0);
        cairo_set_source_rgb(cr, 0.2, 0.2, 0.2);
        snprintf(val_buf, sizeof(val_buf), "%.0f", items[i].value);
        cairo_move_to(cr, bx + bar_w / 2.0 -
                      renderer_text_width(cr, val_buf) / 2.0, by - 4);
        cairo_show_text(cr, val_buf);

        /* X-axis label — truncate, then draw rotated below bars.
         * Positive rotation (clockwise on screen) makes text go
         * down-right into the label zone, away from the bars. */
        const char *lbl = items[i].label ? items[i].label : "";
        if (strlen(lbl) > 20) {
            snprintf(label_buf, sizeof(label_buf), "%.17s...", lbl);
            lbl = label_buf;
        }

        renderer_set_font(cr, "sans-serif",
                          CAIRO_FONT_SLANT_NORMAL,
                          CAIRO_FONT_WEIGHT_NORMAL, 7.0);
        cairo_set_source_rgb(cr, 0.3, 0.3, 0.3);

        cairo_save(cr);
        cairo_translate(cr, bx + bar_w * 0.5, chart_top + chart_h + 6);
        cairo_rotate(cr, G_PI / 4.0);
        cairo_move_to(cr, 0, 0);
        cairo_show_text(cr, lbl);
        cairo_restore(cr);
    }
}

void renderer_draw_bar_chart_colored(cairo_t *cr, const char *title,
                                     const bar_item_t *items,
                                     const rgb_t *colors, int count,
                                     double x, double y,
                                     double width, double height)
{
    double max_val = 0;
    double title_h, label_zone, left_pad, bar_area_w, bar_w, chart_h, chart_top;
    int i;
    char val_buf[64];
    char label_buf[24];

    if (count <= 0) return;

    title_h    = 40;
    label_zone = 80;
    left_pad   = 25;

    renderer_set_font(cr, "sans-serif",
                      CAIRO_FONT_SLANT_NORMAL,
                      CAIRO_FONT_WEIGHT_BOLD, 11.0);
    cairo_set_source_rgb(cr, 0.067, 0.067, 0.067);
    cairo_move_to(cr, x, y + 14);
    cairo_show_text(cr, title);

    chart_top  = y + title_h;
    chart_h    = height - title_h - label_zone;
    if (chart_h < 20) chart_h = 20;
    bar_area_w = width - left_pad - 10;
    bar_w      = bar_area_w / count;

    for (i = 0; i < count; i++)
        if (items[i].value > max_val) max_val = items[i].value;
    if (max_val == 0) max_val = 1;

    for (i = 0; i < count; i++) {
        double bar_h = (items[i].value / max_val) * chart_h;
        double bx    = x + left_pad + i * bar_w;
        double by    = chart_top + chart_h - bar_h;
        const rgb_t *c = colors ? &colors[i] : &CHART_PALETTE[i % 10];

        cairo_set_source_rgb(cr, c->r, c->g, c->b);
        cairo_rectangle(cr, bx + 2, by, bar_w - 4, bar_h);
        cairo_fill(cr);

        renderer_set_font(cr, "sans-serif",
                          CAIRO_FONT_SLANT_NORMAL,
                          CAIRO_FONT_WEIGHT_NORMAL, 8.0);
        cairo_set_source_rgb(cr, 0.2, 0.2, 0.2);
        snprintf(val_buf, sizeof(val_buf), "%.0f", items[i].value);
        cairo_move_to(cr, bx + bar_w / 2.0 -
                      renderer_text_width(cr, val_buf) / 2.0, by - 4);
        cairo_show_text(cr, val_buf);

        const char *lbl = items[i].label ? items[i].label : "";
        if (strlen(lbl) > 20) {
            snprintf(label_buf, sizeof(label_buf), "%.17s...", lbl);
            lbl = label_buf;
        }
        renderer_set_font(cr, "sans-serif",
                          CAIRO_FONT_SLANT_NORMAL,
                          CAIRO_FONT_WEIGHT_NORMAL, 7.0);
        cairo_set_source_rgb(cr, 0.3, 0.3, 0.3);
        cairo_save(cr);
        cairo_translate(cr, bx + bar_w * 0.5, chart_top + chart_h + 6);
        cairo_rotate(cr, G_PI / 4.0);
        cairo_move_to(cr, 0, 0);
        cairo_show_text(cr, lbl);
        cairo_restore(cr);
    }
}

/* ----------------------------------------------------------------
 * Chord / circle diagram (communication matrix)
 *
 * Draws a circle with up to 10 nodes evenly spaced, connected by
 * curved Bezier arcs whose width/colour represents traffic volume.
 * Mirrors the Lua plugin's Section 4 visualisation.
 * ---------------------------------------------------------------- */

static void chord_bin(guint64 packets, double *width_out,
                      double *r, double *g, double *b)
{
    if (packets >= 1001) {
        *width_out = 8.0;  *r = 1.000; *g = 0.420; *b = 0.420;  /* #FF6B6B */
    } else if (packets >= 501) {
        *width_out = 6.0;  *r = 1.000; *g = 0.549; *b = 0.259;  /* #FF8C42 */
    } else if (packets >= 101) {
        *width_out = 4.0;  *r = 0.000; *g = 0.800; *b = 0.737;  /* #00CCBC */
    } else if (packets >= 11) {
        *width_out = 2.5;  *r = 0.000; *g = 0.651; *b = 0.792;  /* #00A6CA */
    } else {
        *width_out = 1.5;  *r = 0.173; *g = 0.482; *b = 0.714;  /* #2C7BB6 */
    }
}

void renderer_draw_chord_diagram(cairo_t *cr, const char *title,
                                 const char **node_labels, int num_nodes,
                                 const guint64 *matrix,
                                 double x, double y,
                                 double width, double height)
{
    int i, j;
    double title_h = 30;
    double cx, cy, radius, label_radius;
    double *nx, *ny, *angles;

    if (num_nodes <= 0) return;

    /* Title */
    renderer_set_font(cr, "sans-serif",
                      CAIRO_FONT_SLANT_NORMAL,
                      CAIRO_FONT_WEIGHT_BOLD, 11.0);
    cairo_set_source_rgb(cr, 0.067, 0.067, 0.067);
    cairo_move_to(cr, x, y + 14);
    cairo_show_text(cr, title);

    double legend_h = 100;
    double chart_h = height - title_h - legend_h;
    double chart_w = width;
    cx = x + chart_w * 0.5;
    cy = y + title_h + chart_h * 0.5;
    radius = MIN(chart_w, chart_h) * 0.38;
    label_radius = radius + 12;

    nx     = (double *)g_malloc(num_nodes * sizeof(double));
    ny     = (double *)g_malloc(num_nodes * sizeof(double));
    angles = (double *)g_malloc(num_nodes * sizeof(double));

    for (i = 0; i < num_nodes; i++) {
        angles[i] = 2.0 * G_PI * i / num_nodes - G_PI / 2.0;
        nx[i] = cx + radius * cos(angles[i]);
        ny[i] = cy + radius * sin(angles[i]);
    }

    /* Draw connections (curved Bezier through center) */
    for (i = 0; i < num_nodes; i++) {
        for (j = i + 1; j < num_nodes; j++) {
            guint64 pkts = matrix[i * num_nodes + j] +
                           matrix[j * num_nodes + i];
            if (pkts == 0) continue;

            double lw, cr_r, cr_g, cr_b;
            chord_bin(pkts, &lw, &cr_r, &cr_g, &cr_b);

            double cp1x = nx[i] + 2.0/3.0 * (cx - nx[i]);
            double cp1y = ny[i] + 2.0/3.0 * (cy - ny[i]);
            double cp2x = nx[j] + 2.0/3.0 * (cx - nx[j]);
            double cp2y = ny[j] + 2.0/3.0 * (cy - ny[j]);

            double inset = 6.0;
            double sx = nx[i] + inset * (cx - nx[i]) / radius;
            double sy = ny[i] + inset * (cy - ny[i]) / radius;
            double ex = nx[j] + inset * (cx - nx[j]) / radius;
            double ey = ny[j] + inset * (cy - ny[j]) / radius;

            cairo_set_source_rgba(cr, cr_r, cr_g, cr_b, 0.5);
            cairo_set_line_width(cr, lw);
            cairo_move_to(cr, sx, sy);
            cairo_curve_to(cr, cp1x, cp1y, cp2x, cp2y, ex, ey);
            cairo_stroke(cr);
        }
    }

    /* Draw nodes and labels */
    renderer_set_font(cr, "sans-serif",
                      CAIRO_FONT_SLANT_NORMAL,
                      CAIRO_FONT_WEIGHT_NORMAL, 7.0);

    for (i = 0; i < num_nodes; i++) {
        /* Node circle */
        cairo_set_source_rgb(cr, 0.13, 0.13, 0.13);
        cairo_new_sub_path(cr);
        cairo_arc(cr, nx[i], ny[i], 4.0, 0, 2.0 * G_PI);
        cairo_fill(cr);

        /* Label */
        double lx = cx + label_radius * cos(angles[i]);
        double ly = cy + label_radius * sin(angles[i]);

        const char *lbl = node_labels[i] ? node_labels[i] : "";
        char trunc[24];
        if (strlen(lbl) > 18) {
            snprintf(trunc, sizeof(trunc), "%.15s...", lbl);
            lbl = trunc;
        }

        cairo_set_source_rgb(cr, 0.2, 0.2, 0.2);
        if (cos(angles[i]) < -0.1) {
            double tw = renderer_text_width(cr, lbl);
            cairo_move_to(cr, lx - tw, ly + 3);
        } else if (cos(angles[i]) > 0.1) {
            cairo_move_to(cr, lx, ly + 3);
        } else {
            double tw = renderer_text_width(cr, lbl);
            cairo_move_to(cr, lx - tw / 2.0, ly + 3);
        }
        cairo_show_text(cr, lbl);
    }

    /* Center label */
    renderer_set_font(cr, "sans-serif",
                      CAIRO_FONT_SLANT_NORMAL,
                      CAIRO_FONT_WEIGHT_BOLD, 8.0);
    cairo_set_source_rgb(cr, 0.4, 0.4, 0.4);
    {
        const char *clbl = "IP Communications";
        double tw = renderer_text_width(cr, clbl);
        cairo_move_to(cr, cx - tw / 2.0, cy + 3);
        cairo_show_text(cr, clbl);
    }

    /* Legend — placed below the circle, spread horizontally */
    {
        double ly = y + title_h + chart_h + 10;
        struct { const char *label; guint64 threshold; } bins[] = {
            {"1-10 pkts",    1},
            {"11-100",      11},
            {"101-500",    101},
            {"501-1k",     501},
            {"1001+",     1001},
        };

        renderer_set_font(cr, "sans-serif",
                          CAIRO_FONT_SLANT_NORMAL,
                          CAIRO_FONT_WEIGHT_BOLD, 8.0);
        cairo_set_source_rgb(cr, 0.2, 0.2, 0.2);
        cairo_move_to(cr, x, ly);
        cairo_show_text(cr, "Traffic Volume:");
        ly += 16;

        renderer_set_font(cr, "sans-serif",
                          CAIRO_FONT_SLANT_NORMAL,
                          CAIRO_FONT_WEIGHT_NORMAL, 7.0);

        double col_w = width / 5.0;
        for (i = 0; i < 5; i++) {
            double lw, lr, lg, lb;
            chord_bin(bins[i].threshold, &lw, &lr, &lg, &lb);
            double lx = x + i * col_w;

            cairo_set_source_rgb(cr, lr, lg, lb);
            cairo_set_line_width(cr, lw);
            cairo_move_to(cr, lx, ly);
            cairo_line_to(cr, lx + 22, ly);
            cairo_stroke(cr);

            cairo_set_source_rgb(cr, 0.3, 0.3, 0.3);
            cairo_move_to(cr, lx + 26, ly + 3);
            cairo_show_text(cr, bins[i].label);
        }
    }

    g_free(nx);
    g_free(ny);
    g_free(angles);
}

/* ----------------------------------------------------------------
 * Pie chart
 * ---------------------------------------------------------------- */

void renderer_draw_pie_chart(cairo_t *cr, const char *title,
                             const pie_item_t *items, int count,
                             double x, double y,
                             double width, double height)
{
    double total = 0;
    double title_h = 24;
    double cx, cy, radius;
    double angle;
    double legend_x, legend_y;
    double chart_h;
    int i;

    if (count <= 0) return;

    /* Title — drawn inside the bounding box */
    renderer_set_font(cr, "sans-serif",
                      CAIRO_FONT_SLANT_NORMAL,
                      CAIRO_FONT_WEIGHT_BOLD, 11.0);
    cairo_set_source_rgb(cr, 0.067, 0.067, 0.067);
    cairo_move_to(cr, x, y + 14);
    cairo_show_text(cr, title);

    for (i = 0; i < count; i++)
        total += items[i].value;
    if (total == 0) return;

    chart_h = height - title_h;
    cx     = x + width * 0.35;
    cy     = y + title_h + chart_h * 0.5;
    radius = MIN(width * 0.28, chart_h * 0.42);
    angle  = -G_PI / 2.0;

    for (i = 0; i < count; i++) {
        double slice = (items[i].value / total) * 2.0 * G_PI;
        const rgb_t *c = &CHART_PALETTE[i % 10];

        cairo_set_source_rgb(cr, c->r, c->g, c->b);
        cairo_move_to(cr, cx, cy);
        cairo_arc(cr, cx, cy, radius, angle, angle + slice);
        cairo_close_path(cr);
        cairo_fill(cr);

        angle += slice;
    }

    /* Legend */
    legend_x = x + width * 0.72;
    legend_y = y + title_h + 10;

    renderer_set_font(cr, "sans-serif",
                      CAIRO_FONT_SLANT_NORMAL,
                      CAIRO_FONT_WEIGHT_NORMAL, 8.0);

    for (i = 0; i < count; i++) {
        const rgb_t *c = &CHART_PALETTE[i % 10];
        char pct_buf[32];

        cairo_set_source_rgb(cr, c->r, c->g, c->b);
        cairo_rectangle(cr, legend_x, legend_y - 7, 10, 10);
        cairo_fill(cr);

        cairo_set_source_rgb(cr, 0.2, 0.2, 0.2);
        snprintf(pct_buf, sizeof(pct_buf), "%s (%.1f%%)",
                 items[i].label ? items[i].label : "",
                 (items[i].value / total) * 100.0);
        cairo_move_to(cr, legend_x + 14, legend_y + 2);
        cairo_show_text(cr, pct_buf);

        legend_y += 15;
    }
}

/* ----------------------------------------------------------------
 * Table
 * ---------------------------------------------------------------- */

double renderer_draw_table(cairo_t *cr, const char *title,
                           const table_def_t *tbl,
                           double x, double y, double width)
{
    double row_h   = 18.0;
    double hdr_h   = 22.0;
    double col_w;
    double cur_y;
    int r_idx, c_idx;

    if (!tbl || tbl->n_cols == 0) return y;

    col_w = width / tbl->n_cols;

    /* Title — drawn inside the bounding box */
    if (title) {
        renderer_set_font(cr, "sans-serif",
                          CAIRO_FONT_SLANT_NORMAL,
                          CAIRO_FONT_WEIGHT_BOLD, 11.0);
        cairo_set_source_rgb(cr, 0.067, 0.067, 0.067);
        cairo_move_to(cr, x, y + 14);
        cairo_show_text(cr, title);
    }

    cur_y = y + (title ? 22 : 0);

    /* Header background */
    cairo_set_source_rgb(cr, CLR_PRIMARY_R, CLR_PRIMARY_G, CLR_PRIMARY_B);
    cairo_rectangle(cr, x, cur_y, width, hdr_h);
    cairo_fill(cr);

    /* Header text */
    renderer_set_font(cr, "sans-serif",
                      CAIRO_FONT_SLANT_NORMAL,
                      CAIRO_FONT_WEIGHT_BOLD, 9.0);
    cairo_set_source_rgb(cr, 1.0, 1.0, 1.0);

    for (c_idx = 0; c_idx < tbl->n_cols; c_idx++) {
        cairo_move_to(cr, x + c_idx * col_w + 4, cur_y + 15);
        cairo_show_text(cr, tbl->headers[c_idx]);
    }

    cur_y += hdr_h;

    /* Data rows */
    renderer_set_font(cr, "sans-serif",
                      CAIRO_FONT_SLANT_NORMAL,
                      CAIRO_FONT_WEIGHT_NORMAL, 8.0);

    for (r_idx = 0; r_idx < tbl->n_rows; r_idx++) {
        /* Alternating row background */
        if (r_idx % 2 == 0) {
            cairo_set_source_rgb(cr, 0.96, 0.96, 0.96);
            cairo_rectangle(cr, x, cur_y, width, row_h);
            cairo_fill(cr);
        }

        cairo_set_source_rgb(cr, 0.13, 0.13, 0.13);
        for (c_idx = 0; c_idx < tbl->n_cols; c_idx++) {
            const char *cell = tbl->rows[r_idx][c_idx];
            cairo_move_to(cr, x + c_idx * col_w + 4, cur_y + 13);
            cairo_show_text(cr, cell ? cell : "");
        }

        cur_y += row_h;
    }

    return cur_y;
}

/* ----------------------------------------------------------------
 * Section header
 * ---------------------------------------------------------------- */

void renderer_draw_section_header(cairo_t *cr, const char *title,
                                  double x, double y, double width)
{
    /* Accent bar */
    cairo_set_source_rgb(cr, CLR_PRIMARY_R, CLR_PRIMARY_G, CLR_PRIMARY_B);
    cairo_rectangle(cr, x, y, width, 2);
    cairo_fill(cr);

    /* Title */
    renderer_set_font(cr, "sans-serif",
                      CAIRO_FONT_SLANT_NORMAL,
                      CAIRO_FONT_WEIGHT_BOLD, 14.0);
    cairo_move_to(cr, x, y + 20);
    cairo_show_text(cr, title);
}

/* ----------------------------------------------------------------
 * Page footer
 * ---------------------------------------------------------------- */

void renderer_draw_page_footer(cairo_t *cr, const paper_size_t *paper,
                               int page_num)
{
    char buf[64];

    renderer_set_font(cr, "sans-serif",
                      CAIRO_FONT_SLANT_NORMAL,
                      CAIRO_FONT_WEIGHT_NORMAL, 8.0);
    cairo_set_source_rgb(cr, 0.6, 0.6, 0.6);

    snprintf(buf, sizeof(buf), "PacketReporter Pro \xe2\x80\x94 Page %d", page_num);
    cairo_move_to(cr, paper->width_pt / 2.0 -
                  renderer_text_width(cr, buf) / 2.0,
                  paper->height_pt - 20);
    cairo_show_text(cr, buf);
}

/* ----------------------------------------------------------------
 * Cover page
 * ---------------------------------------------------------------- */

void renderer_draw_cover_page(cairo_t *cr, const paper_size_t *paper,
                              const reporter_config_t *cfg,
                              const char **toc_titles, const int *toc_pages,
                              int toc_count)
{
    double y_pos = 80;
    int i;

    /* White background */
    cairo_set_source_rgb(cr, 1, 1, 1);
    cairo_paint(cr);

    /* Logo or text fallback */
    if (cfg && cfg->logo_loaded && cfg->logo_surface) {
        double img_w  = (double)cfg->logo_width;
        double img_h  = (double)cfg->logo_height;
        double max_w  = 300.0;
        double max_h  = 150.0;
        double scale  = MIN(max_w / img_w, max_h / img_h);
        double draw_w = img_w * scale;
        double draw_h = img_h * scale;

        cairo_save(cr);
        cairo_translate(cr, (paper->width_pt - draw_w) / 2.0, y_pos);
        cairo_scale(cr, scale, scale);
        cairo_set_source_surface(cr, cfg->logo_surface, 0, 0);
        cairo_paint(cr);
        cairo_restore(cr);

        y_pos += draw_h + 40;
    } else {
        renderer_set_font(cr, "sans-serif",
                          CAIRO_FONT_SLANT_NORMAL,
                          CAIRO_FONT_WEIGHT_BOLD, 36.0);
        cairo_set_source_rgb(cr, CLR_PRIMARY_R, CLR_PRIMARY_G, CLR_PRIMARY_B);
        double tw = renderer_text_width(cr, "PacketReporter Pro");
        cairo_move_to(cr, (paper->width_pt - tw) / 2.0, y_pos);
        cairo_show_text(cr, "PacketReporter Pro");
        y_pos += 30;

        renderer_set_font(cr, "sans-serif",
                          CAIRO_FONT_SLANT_NORMAL,
                          CAIRO_FONT_WEIGHT_NORMAL, 12.0);
        cairo_set_source_rgb(cr, 0.4, 0.4, 0.4);
        tw = renderer_text_width(cr, PLUGIN_VERSION_STR);
        cairo_move_to(cr, (paper->width_pt - tw) / 2.0, y_pos);
        cairo_show_text(cr, PLUGIN_VERSION_STR);
        y_pos += 50;
    }

    /* Description lines */
    renderer_set_font(cr, "sans-serif",
                      CAIRO_FONT_SLANT_NORMAL,
                      CAIRO_FONT_WEIGHT_NORMAL, 11.0);
    cairo_set_source_rgb(cr, 0.2, 0.2, 0.2);

    if (cfg) {
        const char *lines[3] = { cfg->desc_line1, cfg->desc_line2, cfg->desc_line3 };
        for (i = 0; i < 3; i++) {
            if (lines[i] && *lines[i]) {
                cairo_move_to(cr, 72, y_pos);
                cairo_show_text(cr, lines[i]);
                y_pos += 20;
            }
        }
    }
    y_pos += 40;

    /* Separator line */
    cairo_set_source_rgb(cr, CLR_PRIMARY_R, CLR_PRIMARY_G, CLR_PRIMARY_B);
    cairo_set_line_width(cr, 1.5);
    cairo_move_to(cr, 60, y_pos);
    cairo_line_to(cr, paper->width_pt - 60, y_pos);
    cairo_stroke(cr);
    y_pos += 30;

    /* Table of Contents */
    renderer_set_font(cr, "sans-serif",
                      CAIRO_FONT_SLANT_NORMAL,
                      CAIRO_FONT_WEIGHT_BOLD, 16.0);
    cairo_set_source_rgb(cr, CLR_PRIMARY_R, CLR_PRIMARY_G, CLR_PRIMARY_B);
    cairo_move_to(cr, 72, y_pos);
    cairo_show_text(cr, "Table of Contents");
    y_pos += 50;

    renderer_set_font(cr, "sans-serif",
                      CAIRO_FONT_SLANT_NORMAL,
                      CAIRO_FONT_WEIGHT_NORMAL, 10.0);

    for (i = 0; i < toc_count; i++) {
        char page_buf[16];
        char link_attr[128];

        snprintf(link_attr, sizeof(link_attr),
                 "dest='section%d'", i + 1);
        cairo_tag_begin(cr, CAIRO_TAG_LINK, link_attr);

        cairo_set_source_rgb(cr, CLR_PRIMARY_R, CLR_PRIMARY_G,
                             CLR_PRIMARY_B);
        cairo_move_to(cr, 90, y_pos);
        cairo_show_text(cr, toc_titles[i]);

        snprintf(page_buf, sizeof(page_buf), "%d", toc_pages[i]);
        cairo_set_source_rgb(cr, 0.4, 0.4, 0.4);
        cairo_move_to(cr, paper->width_pt - 90 -
                      renderer_text_width(cr, page_buf), y_pos);
        cairo_show_text(cr, page_buf);

        cairo_tag_end(cr, CAIRO_TAG_LINK);

        y_pos += 20;
    }

    /* Footer */
    {
        char date_buf[64];
        time_t now = time(NULL);
        struct tm *tm_now = localtime(&now);
        char footer[128];

        strftime(date_buf, sizeof(date_buf), "%Y-%m-%d %H:%M:%S", tm_now);
        snprintf(footer, sizeof(footer),
                 "Generated by PacketReporter Pro %s on %s",
                 PLUGIN_VERSION_STR, date_buf);

        renderer_set_font(cr, "sans-serif",
                          CAIRO_FONT_SLANT_NORMAL,
                          CAIRO_FONT_WEIGHT_NORMAL, 8.0);
        cairo_set_source_rgb(cr, 0.6, 0.6, 0.6);
        double fw = renderer_text_width(cr, footer);
        cairo_move_to(cr, (paper->width_pt - fw) / 2.0,
                      paper->height_pt - 40);
        cairo_show_text(cr, footer);
    }
}
