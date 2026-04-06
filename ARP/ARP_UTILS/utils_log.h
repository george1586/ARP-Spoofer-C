#ifndef UTILS_LOG_H
#define UTILS_LOG_H

#include <stdarg.h>

/**
 * Initialize file logging. Pass NULL to disable file logging.
 */
void log_init(const char *filepath);

/**
 * Close the log file if open.
 */
void log_close(void);

/**
 * Printf-style logging to both stdout and the log file (if open).
 */
void log_printf(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

#endif
