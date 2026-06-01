/* mq_framebuf.c — see mq_framebuf.h. */
#include "proxy/mq_framebuf.h"

int
mq_framebuf_fill(mq_stream_t *s, mq_framebuf_t *fb, int *fin)
{
    if (!s || !fb) {
        return -1;
    }

    for (;;) {
        if (fb->len >= sizeof(fb->buf)) {
            break; /* buffer full: stop; caller decides malformed after decode */
        }
        int f = 0;
        long n = mq_stream_recv(s, fb->buf + fb->len, sizeof(fb->buf) - fb->len, &f);
        if (n < 0) {
            /* Hard error / RESET before a frame. Match the historical client
             * data-header behavior: report it without consulting fin. */
            return -1;
        }
        if (n > 0) {
            fb->len += (size_t)n;
        }
        if (f && fin) {
            *fin = 1;
        }
        if (n == 0) {
            break; /* EAGAIN: nothing more right now */
        }
    }

    return 0;
}
