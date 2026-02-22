#include <config.h>
#include <wireshark.h>

#include "config_reader.h"
#include "reporter_plugin.h"

#include <cairo.h>
#include <wsutil/wslog.h>

#include <stdio.h>
#include <string.h>
#include <time.h>

char *config_reader_get_dir(void)
{
    const char *home;

#ifdef _WIN32
    home = g_getenv("USERPROFILE");
#else
    home = g_getenv("HOME");
#endif

    if (!home || !*home)
        home = g_get_tmp_dir();

    return g_build_filename(home, ".packet_reporter", NULL);
}

reporter_config_t *config_reader_load(void)
{
    reporter_config_t *cfg = g_new0(reporter_config_t, 1);
    char *dir  = config_reader_get_dir();
    char *logo_path = g_build_filename(dir, "Logo.png", NULL);
    char *desc_path = g_build_filename(dir, "packet_reporter.txt", NULL);

    /* Load logo PNG via Cairo */
    cfg->logo_surface = cairo_image_surface_create_from_png(logo_path);
    if (cfg->logo_surface &&
        cairo_surface_status(cfg->logo_surface) == CAIRO_STATUS_SUCCESS) {
        cfg->logo_loaded = TRUE;
        cfg->logo_width  = cairo_image_surface_get_width(cfg->logo_surface);
        cfg->logo_height = cairo_image_surface_get_height(cfg->logo_surface);
        ws_log(WS_LOG_DOMAIN, LOG_LEVEL_DEBUG,
               "Logo loaded: %dx%d from %s",
               cfg->logo_width, cfg->logo_height, logo_path);
    } else {
        if (cfg->logo_surface) {
            cairo_surface_destroy(cfg->logo_surface);
            cfg->logo_surface = NULL;
        }
        cfg->logo_loaded = FALSE;
    }

    /* Read description file (up to 3 lines) */
    {
        FILE *f = fopen(desc_path, "r");
        if (f) {
            char line[512];
            int n = 0;
            while (n < 3 && fgets(line, sizeof(line), f)) {
                /* Strip trailing newline */
                size_t len = strlen(line);
                while (len > 0 && (line[len - 1] == '\n' ||
                                    line[len - 1] == '\r'))
                    line[--len] = '\0';

                switch (n) {
                case 0: cfg->desc_line1 = g_strdup(line); break;
                case 1: cfg->desc_line2 = g_strdup(line); break;
                case 2: cfg->desc_line3 = g_strdup(line); break;
                }
                n++;
            }
            fclose(f);
        }
    }

    /* Defaults if no description loaded */
    if (!cfg->desc_line1)
        cfg->desc_line1 = g_strdup("PacketReporter Pro \xe2\x80\x94 Network Traffic Analysis Report");
    if (!cfg->desc_line2)
        cfg->desc_line2 = g_strdup("Comprehensive analysis of captured network packets");
    if (!cfg->desc_line3) {
        char ts[64];
        time_t now = time(NULL);
        struct tm *tm_now = localtime(&now);
        strftime(ts, sizeof(ts), "Generated: %Y-%m-%d %H:%M:%S", tm_now);
        cfg->desc_line3 = g_strdup(ts);
    }

    g_free(logo_path);
    g_free(desc_path);
    g_free(dir);
    return cfg;
}

void config_reader_save(const reporter_config_t *cfg,
                        const char *logo_src)
{
    char *dir = config_reader_get_dir();
    g_mkdir_with_parents(dir, 0755);

    /* Write description file */
    {
        char *path = g_build_filename(dir, "packet_reporter.txt", NULL);
        FILE *f = fopen(path, "w");
        if (f) {
            if (cfg->desc_line1) fprintf(f, "%s\n", cfg->desc_line1);
            if (cfg->desc_line2) fprintf(f, "%s\n", cfg->desc_line2);
            if (cfg->desc_line3) fprintf(f, "%s\n", cfg->desc_line3);
            fclose(f);
            ws_log(WS_LOG_DOMAIN, LOG_LEVEL_INFO,
                   "Saved description to %s", path);
        }
        g_free(path);
    }

    /* Copy logo if source path provided */
    if (logo_src && *logo_src) {
        char *dst = g_build_filename(dir, "Logo.png", NULL);
        /* Simple file copy */
        FILE *in = fopen(logo_src, "rb");
        if (in) {
            FILE *out = fopen(dst, "wb");
            if (out) {
                char buf[8192];
                size_t n;
                while ((n = fread(buf, 1, sizeof(buf), in)) > 0)
                    fwrite(buf, 1, n, out);
                fclose(out);
                ws_log(WS_LOG_DOMAIN, LOG_LEVEL_INFO,
                       "Saved logo to %s", dst);
            }
            fclose(in);
        }
        g_free(dst);
    }

    g_free(dir);
}

void config_reader_free(reporter_config_t *cfg)
{
    if (!cfg) return;

    if (cfg->logo_surface)
        cairo_surface_destroy(cfg->logo_surface);

    g_free(cfg->desc_line1);
    g_free(cfg->desc_line2);
    g_free(cfg->desc_line3);
    g_free(cfg);
}
