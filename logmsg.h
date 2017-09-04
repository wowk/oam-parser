#ifndef LOGMSG_H
#define LOGMSG_H

#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

void errmsg(FILE* fp, const char* fmt, ...);
void std_errmsg(const char* fmt, ...);

#ifdef __cplusplus
}
#endif

#endif // LOGMSG_H
