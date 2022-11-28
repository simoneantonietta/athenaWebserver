#include <errno.h>
#include <sys/types.h>
#include <netdb.h>
#include <time.h>
#include <sys/file.h>
#include "net.h"

#define ADDROOTDIR(x) x

typedef void (*function)(int idx, char *param);

void register_plugin(char *name, int host, function func);
void Log(int idx, char *msg);

typedef struct hostProperties{
    unsigned char hostIP[INET6_ADDRSTRLEN];      // IP address of a host
    unsigned char authorized;                    // authorization state of a host
    unsigned char isActive;                      // the host made the last request
    time_t expirationTime;                       // time until authorization will expire
}hostProperties;

typedef void * (*arbitrary)();
