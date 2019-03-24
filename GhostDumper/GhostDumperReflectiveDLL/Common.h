#pragma once

#define DEBUG_PRINTS

#define INFO(fmt, ...) fprintf(stderr, "[INFO] "); fprintf(stderr, fmt, __VA_ARGS__)
#ifdef DEBUG_PRINTS
#define DEBUG(fmt, ...) fprintf(stderr, "[DEBUG] "); fprintf(stderr, fmt, __VA_ARGS__)
#else
#define DEBUG
#endif
#define PERROR(str) fprintf(stderr, "[ERROR] %s(): %d\n", str, GetLastError())