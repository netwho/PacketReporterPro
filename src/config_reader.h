#ifndef CONFIG_READER_H
#define CONFIG_READER_H

#include <glib.h>
#include <cairo.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    gboolean         logo_loaded;
    cairo_surface_t *logo_surface;  /* PNG loaded via cairo; NULL if absent */
    int              logo_width;
    int              logo_height;

    char            *desc_line1;    /* First line from packet_reporter.txt */
    char            *desc_line2;
    char            *desc_line3;
} reporter_config_t;

/**
 * Read configuration from ~/.packet_reporter/
 *   - Logo.png  → loaded as cairo_surface_t
 *   - packet_reporter.txt → up to 3 lines
 *
 * @return Freshly-allocated config. Caller frees with config_reader_free().
 */
reporter_config_t *config_reader_load(void);

void config_reader_free(reporter_config_t *cfg);

/**
 * Save current config to ~/.packet_reporter/
 *   - Writes packet_reporter.txt from cfg->desc_line1..3
 *   - Copies logo_src_path → ~/.packet_reporter/Logo.png (if non-NULL)
 *
 * @param cfg        Configuration with description lines
 * @param logo_src   Path to logo image to copy, or NULL to leave unchanged
 */
void config_reader_save(const reporter_config_t *cfg,
                        const char *logo_src);

/**
 * Return the config directory path (~/.packet_reporter).
 * @return Newly-allocated string. Caller must g_free().
 */
char *config_reader_get_dir(void);

#ifdef __cplusplus
}
#endif

#endif /* CONFIG_READER_H */
