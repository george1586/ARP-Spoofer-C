#include "utils_log.h"
#include <stdio.h>
#include <time.h>

static FILE *g_logfile = NULL;

void log_init(const char *filepath) {
    if (!filepath) return;
    g_logfile = fopen(filepath, "a");
    if (!g_logfile) {
        fprintf(stderr, "[!] Cannot open log file: %s\n", filepath);
        return;
    }
    time_t now = time(NULL);
    fprintf(g_logfile, "\n=== ARP Spoofer Session Started: %s===\n", ctime(&now));
    fflush(g_logfile);
}

void log_close(void) {
    if (g_logfile) {
        time_t now = time(NULL);
        fprintf(g_logfile, "=== Session Ended: %s===\n", ctime(&now));
        fclose(g_logfile);
        g_logfile = NULL;
    }
}

void log_printf(const char *fmt, ...) {
    va_list args, args2;
    va_start(args, fmt);
    va_copy(args2, args);

    vprintf(fmt, args);

    if (g_logfile) {
        vfprintf(g_logfile, fmt, args2);
        fflush(g_logfile);
    }

    va_end(args2);
    va_end(args);
}
