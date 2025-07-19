#pragma once

#include <xtl.h>
#include "XboxTLS.h"

// Define HANDLE if not already defined
#ifndef _WINNT_
typedef void* HANDLE;
#endif

struct TLSClient {
    XboxTLSContext ctx;

    char host[64];
    char ip[64];
    char path[128];

	volatile bool reconnecting;

    HANDLE recvThread;
    HANDLE heartbeatThread;

    volatile BOOL running;
    DWORD lastActivityTick;
	DWORD heartbeatInterval;
};
