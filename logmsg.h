#ifndef LOGMSG_H
#define LOGMSG_H

#include <stdio.h>
#include <stdarg.h>

#define errmsg(fp, fmt, ...) do{                    \
    fprintf(fp, "[%s:%d] : ", __func__, __LINE__);  \
    fprintf(fp, fmt, ##__VA_ARGS__);                \
    fprintf(fp, "\n");                              \
    fflush(fp);                                     \
}while(0)


#define std_errmsg(fmt, ...) errmsg(stderr, fmt, ##__VA_ARGS__)

#endif // LOGMSG_H
