#include "logmsg.h"
#include <stdio.h>
#include <stdarg.h>

void errmsg(FILE* fp, const char* fmt, ...)
{
    va_list vl;

    va_start(vl, fmt);
    fprintf(fp, "[%s:%d] : ", __func__, __LINE__);
    vfprintf(fp, fmt, vl);
    fprintf(fp, "\n");
    fflush(fp);

    va_end(vl);
}

void std_errmsg(const char* fmt, ...)
{
    va_list vl;

    va_start(vl, fmt);
    fprintf(stderr, "[%s:%d] : ", __func__, __LINE__);
    vfprintf(stderr, fmt, vl);
    fprintf(stderr, "\n");
    fflush(stderr);

    va_end(vl);
}
