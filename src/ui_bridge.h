#ifndef UI_BRIDGE_H
#define UI_BRIDGE_H

#ifdef __cplusplus
extern "C" {
#endif

typedef struct _capture_file capture_file;

void reporter_pro_open_window(capture_file *cf);
void reporter_pro_close_window(void);

#ifdef __cplusplus
}
#endif

#endif /* UI_BRIDGE_H */
