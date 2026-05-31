#ifndef MQ_LOG_H
#define MQ_LOG_H

/* Log level constants — higher value = more verbose */
#define MQ_LOG_ERROR 0
#define MQ_LOG_WARN  1
#define MQ_LOG_INFO  2
#define MQ_LOG_DEBUG 3

/**
 * Set the maximum log level that will be emitted.
 * Messages with level > configured level are suppressed.
 */
void mq_log_set_level(int level);

/**
 * Emit a log message at the given level.
 * Writes to stderr with a level prefix.
 * Messages with level > configured level are suppressed.
 */
void mq_log(int level, const char *fmt, ...) __attribute__((format(printf, 2, 3)));

/* Convenience macros */
#define MQ_LOGE(...) mq_log(MQ_LOG_ERROR, __VA_ARGS__)
#define MQ_LOGW(...) mq_log(MQ_LOG_WARN, __VA_ARGS__)
#define MQ_LOGI(...) mq_log(MQ_LOG_INFO, __VA_ARGS__)
#define MQ_LOGD(...) mq_log(MQ_LOG_DEBUG, __VA_ARGS__)

#endif /* MQ_LOG_H */
