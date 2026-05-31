#include "mq_log.h"
#include <stdarg.h>
#include <stdio.h>

static int g_log_level = MQ_LOG_INFO;

void
mq_log_set_level(int level)
{
    g_log_level = level;
}

void
mq_log(int level, const char *fmt, ...)
{
    if (level > g_log_level) return;

    const char *prefix;
    switch (level) {
    case MQ_LOG_ERROR: prefix = "ERROR"; break;
    case MQ_LOG_WARN: prefix = "WARN"; break;
    case MQ_LOG_INFO: prefix = "INFO"; break;
    case MQ_LOG_DEBUG: prefix = "DEBUG"; break;
    default: prefix = "UNKNOWN"; break;
    }

    fprintf(stderr, "[%s] ", prefix);

    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);

    fprintf(stderr, "\n");
}
