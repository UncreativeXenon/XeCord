#pragma once

/// @file SystemSocket.h
///
/// Macros to override the standard socket functions with their internal version and run
/// them with the proper process type, either title of system (`XNCALLER_TITLE` or
/// `XNCALLER_SYSAPP` respectively).

#include "Kernel.h"
#include "Xam.h"

#define accept(s, addr, addrlen) NetDll_accept((XNCALLER_TYPE)KeGetCurrentProcessType(), s, addr, addrlen)
#define bind(s, name, namelen) NetDll_bind((XNCALLER_TYPE)KeGetCurrentProcessType(), s, name, namelen)
#define closesocket(s) NetDll_closesocket((XNCALLER_TYPE)KeGetCurrentProcessType(), s)
#define connect(s, name, namelen) NetDll_connect((XNCALLER_TYPE)KeGetCurrentProcessType(), s, name, namelen)
#define getpeername(s, name, namelen) NetDll_getpeername((XNCALLER_TYPE)KeGetCurrentProcessType(), s, name, namelen)
#define getsockname(s, name, namelen) NetDll_getsockname((XNCALLER_TYPE)KeGetCurrentProcessType(), s, name, namelen)
#define getsockopt(s, level, optname, optval, optlen) NetDll_getsockopt((XNCALLER_TYPE)KeGetCurrentProcessType(), s, level, optname, optval, optlen)
#define inet_addr(cp) NetDll_inet_addr(cp)
#define ioctlsocket(s, cmd, argp) NetDll_ioctlsocket((XNCALLER_TYPE)KeGetCurrentProcessType(), s, cmd, argp)
#define listen(s, backlog) NetDll_listen((XNCALLER_TYPE)KeGetCurrentProcessType(), s, backlog)
#define recv(s, buf, len, flags) NetDll_recv((XNCALLER_TYPE)KeGetCurrentProcessType(), s, buf, len, flags)
#define recvfrom(s, buf, len, flags, from, fromlen) NetDll_recvfrom((XNCALLER_TYPE)KeGetCurrentProcessType(), s, buf, len, flags, from, fromlen)
#define select(nfds, readfds, writefds, exceptfds, timeout) NetDll_select((XNCALLER_TYPE)KeGetCurrentProcessType(), nfds, readfds, writefds, exceptfds, timeout)
#define send(s, buf, len, flags) NetDll_send((XNCALLER_TYPE)KeGetCurrentProcessType(), s, buf, len, flags)
#define sendto(s, buf, len, flags, to, tolen) NetDll_sendto((XNCALLER_TYPE)KeGetCurrentProcessType(), s, buf, len, flags, to, tolen)
#define setsockopt(s, level, optname, optval, optlen) NetDll_setsockopt((XNCALLER_TYPE)KeGetCurrentProcessType(), s, level, optname, optval, optlen)
#define shutdown(s, how) NetDll_shutdown((XNCALLER_TYPE)KeGetCurrentProcessType(), s, how)
#define socket(af, type, protocol) NetDll_socket((XNCALLER_TYPE)KeGetCurrentProcessType(), af, type, protocol)
#define WSACleanup() NetDll_WSACleanup((XNCALLER_TYPE)KeGetCurrentProcessType())
#define WSAStartup(wVersionRequested, lpWSAData) NetDll_WSAStartupEx((XNCALLER_TYPE)KeGetCurrentProcessType(), wVersionRequested, lpWSAData, 2)
#define XNetCleanup() NetDll_XNetCleanup((XNCALLER_TYPE)KeGetCurrentProcessType())
#define XNetDnsLookup(pszHost, hEvent, ppxndns) NetDll_XNetDnsLookup((XNCALLER_TYPE)KeGetCurrentProcessType(), pszHost, hEvent, ppxndns)
#define XNetDnsRelease(pxndns) NetDll_XNetDnsRelease((XNCALLER_TYPE)KeGetCurrentProcessType(), pxndns)
#define XNetStartup(pxnsp) NetDll_XNetStartup((XNCALLER_TYPE)KeGetCurrentProcessType(), pxnsp)
