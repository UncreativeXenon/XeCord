#pragma once

namespace XexUtils
{
namespace Xam
{

/// @brief The notification icon.
typedef enum _XNOTIFYQUEUEUI_TYPE
{
    XNOTIFYUI_TYPE_FRIENDONLINE = 0,
    XNOTIFYUI_TYPE_GAMEINVITE = 1,
    XNOTIFYUI_TYPE_FRIENDREQUEST = 2,
    XNOTIFYUI_TYPE_GENERIC = 3,
    XNOTIFYUI_TYPE_MULTIPENDING = 4,
    XNOTIFYUI_TYPE_PERSONALMESSAGE = 5,
    XNOTIFYUI_TYPE_SIGNEDOUT = 6,
    XNOTIFYUI_TYPE_SIGNEDIN = 7,
    XNOTIFYUI_TYPE_SIGNEDINLIVE = 8,
    XNOTIFYUI_TYPE_SIGNEDINNEEDPASS = 9,
    XNOTIFYUI_TYPE_CHATREQUEST = 10,
    XNOTIFYUI_TYPE_CONNECTIONLOST = 11,
    XNOTIFYUI_TYPE_DOWNLOADCOMPLETE = 12,
    XNOTIFYUI_TYPE_SONGPLAYING = 13,
    XNOTIFYUI_TYPE_PREFERRED_REVIEW = 14,
    XNOTIFYUI_TYPE_AVOID_REVIEW = 15,
    XNOTIFYUI_TYPE_COMPLAINT = 16,
    XNOTIFYUI_TYPE_CHATCALLBACK = 17,
    XNOTIFYUI_TYPE_REMOVEDMU = 18,
    XNOTIFYUI_TYPE_REMOVEDGAMEPAD = 19,
    XNOTIFYUI_TYPE_CHATJOIN = 20,
    XNOTIFYUI_TYPE_CHATLEAVE = 21,
    XNOTIFYUI_TYPE_GAMEINVITESENT = 22,
    XNOTIFYUI_TYPE_CANCELPERSISTENT = 23,
    XNOTIFYUI_TYPE_CHATCALLBACKSENT = 24,
    XNOTIFYUI_TYPE_MULTIFRIENDONLINE = 25,
    XNOTIFYUI_TYPE_ONEFRIENDONLINE = 26,
    XNOTIFYUI_TYPE_ACHIEVEMENT = 27,
    XNOTIFYUI_TYPE_HYBRIDDISC = 28,
    XNOTIFYUI_TYPE_MAILBOX = 29,
    XNOTIFYUI_TYPE_VIDEOCHATINVITE = 30,
    XNOTIFYUI_TYPE_DOWNLOADCOMPLETEDREADYTOPLAY = 31,
    XNOTIFYUI_TYPE_CANNOTDOWNLOAD = 32,
    XNOTIFYUI_TYPE_DOWNLOADSTOPPED = 33,
    XNOTIFYUI_TYPE_CONSOLEMESSAGE = 34,
    XNOTIFYUI_TYPE_GAMEMESSAGE = 35,
    XNOTIFYUI_TYPE_DEVICEFULL = 36,
    XNOTIFYUI_TYPE_CHATMESSAGE = 38,
    XNOTIFYUI_TYPE_MULTIACHIEVEMENTS = 39,
    XNOTIFYUI_TYPE_NUDGE = 40,
    XNOTIFYUI_TYPE_MESSENGERCONNECTIONLOST = 41,
    XNOTIFYUI_TYPE_MESSENGERSIGNINFAILED = 43,
    XNOTIFYUI_TYPE_MESSENGERCONVERSATIONMISSED = 44,
    XNOTIFYUI_TYPE_FAMILYTIMERREMAINING = 45,
    XNOTIFYUI_TYPE_CONNECTIONLOSTRECONNECT = 46,
    XNOTIFYUI_TYPE_EXCESSIVEPLAYTIME = 47,
    XNOTIFYUI_TYPE_PARTYJOINREQUEST = 49,
    XNOTIFYUI_TYPE_PARTYINVITESENT = 50,
    XNOTIFYUI_TYPE_PARTYGAMEINVITESENT = 51,
    XNOTIFYUI_TYPE_PARTYKICKED = 52,
    XNOTIFYUI_TYPE_PARTYDISCONNECTED = 53,
    XNOTIFYUI_TYPE_PARTYCANNOTCONNECT = 56,
    XNOTIFYUI_TYPE_PARTYSOMEONEJOINED = 57,
    XNOTIFYUI_TYPE_PARTYSOMEONELEFT = 58,
    XNOTIFYUI_TYPE_GAMERPICTUREUNLOCKED = 59,
    XNOTIFYUI_TYPE_AVATARAWARDUNLOCKED = 60,
    XNOTIFYUI_TYPE_PARTYJOINED = 61,
    XNOTIFYUI_TYPE_REMOVEDUSB = 62,
    XNOTIFYUI_TYPE_PLAYERMUTED = 63,
    XNOTIFYUI_TYPE_PLAYERUNMUTED = 64,
    XNOTIFYUI_TYPE_CHATMESSAGE2 = 65,
    XNOTIFYUI_TYPE_KINECTCONNECTED = 66,
    XNOTIFYUI_TYPE_KINECTBREAK = 67,
    XNOTIFYUI_TYPE_ETHERNET = 68,
    XNOTIFYUI_TYPE_KINECTPLAYERRECOGNIZED = 69,
    XNOTIFYUI_TYPE_CONSOLESHUTTINGDOWNSOONALERT = 70,
    XNOTIFYUI_TYPE_PROFILESIGNEDINELSEWHERE = 71,
    XNOTIFYUI_TYPE_LASTSIGNINELSEWHERE = 73,
    XNOTIFYUI_TYPE_KINECTDEVICEUNSUPPORTED = 74,
    XNOTIFYUI_TYPE_WIRELESSDEVICETURNOFF = 75,
    XNOTIFYUI_TYPE_UPDATING = 76,
    XNOTIFYUI_TYPE_SMARTGLASSAVAILABLE = 77,
} XNOTIFYQUEUEUI_TYPE;

/// @brief Displays a system notification.
/// @param text The text to display.
/// @param type The notification icon.
void XNotify(const std::string &text, XNOTIFYQUEUEUI_TYPE type = XNOTIFYUI_TYPE_PREFERRED_REVIEW);

/// @brief Opens a system keyboard.
///
/// This function blocks the calling thread while the keyboard is open.
///
/// @param title The title.
/// @param description The description.
/// @param defaultText The text written by default in the input.
/// @param result What was typed by the user.
/// @param maxLength The max amount of characters the user can type.
/// @param keyboardType The keyboard type (e.g. email, phone, password, etc.).
/// @return How the keyboard was closed.
uint32_t ShowKeyboard(const std::wstring &title, const std::wstring &description, const std::wstring &defaultText, std::string &result, size_t maxLength = 15, uint32_t keyboardType = VKBD_DEFAULT);

/// @brief Opens a system message box.
///
/// This function blocks the calling thread while the message box is open.
///
/// @param title The title.
/// @param text The main content.
/// @param buttonLabels A vector of label buttons.
/// @param messageBoxType The type of message box (e.g. error, info, warning).
/// @param pButtonPressedIndex A pointer to a `uint32_t` to store the index in `buttonLabels`
/// of the button that was clicked.
/// @param focusedButtonIndex Index in `buttonLabels` of the button to focus by default.
/// @return How the message box was closed.
uint32_t ShowMessageBox(const std::wstring &title, const std::wstring &text, const std::vector<std::wstring> &buttonLabels, uint32_t messageBoxType = XMB_NOICON, uint32_t *pButtonPressedIndex = nullptr, uint32_t focusedButtonIndex = 0);

}
}

/// A list of functions exported by `xam.xex` and the associated structures to use them.
/// Most of those were taken from xkelib.

#define EXPORTNUM(x)

typedef enum _XNCALLER_TYPE
{
    XNCALLER_INVALID = 0,
    XNCALLER_TITLE = 1,
    XNCALLER_SYSAPP = 2,
    XNCALLER_XBDM = 3,
    XNCALLER_PERSISTING = 3,
    XNCALLER_TEST = 4,
    NUM_XNCALLER_TYPES = 4,
} XNCALLER_TYPE;

extern "C"
{
    EXPORTNUM(14)
    SOCKET NetDll_accept(
        XNCALLER_TYPE xnCaller,
        SOCKET s,
        sockaddr *addr,
        int *addrlen
    );

    EXPORTNUM(11)
    int NetDll_bind(
        XNCALLER_TYPE xnCaller,
        SOCKET s,
        const sockaddr *name,
        int namelen
    );

    EXPORTNUM(4)
    int NetDll_closesocket(
        XNCALLER_TYPE xnCaller,
        SOCKET s
    );

    EXPORTNUM(12)
    int NetDll_connect(
        XNCALLER_TYPE xnCaller,
        SOCKET s,
        const sockaddr *name,
        int namelen
    );

    EXPORTNUM(10)
    int NetDll_getpeername(
        XNCALLER_TYPE xnc,
        SOCKET s,
        sockaddr *name,
        int *namelen
    );

    EXPORTNUM(9)
    int NetDll_getsockname(
        XNCALLER_TYPE xnCaller,
        SOCKET s,
        sockaddr *name,
        int *namelen
    );

    EXPORTNUM(8)
    int NetDll_getsockopt(
        XNCALLER_TYPE xnCaller,
        SOCKET s,
        int level,
        int optname,
        char *optval,
        int *optlen
    );

    EXPORTNUM(26)
    uint32_t NetDll_inet_addr(
        const char *cp
    );

    EXPORTNUM(6)
    int NetDll_ioctlsocket(
        XNCALLER_TYPE xnCaller,
        SOCKET s,
        int cmd,
        uint32_t *argp
    );

    EXPORTNUM(13)
    int NetDll_listen(
        XNCALLER_TYPE xnCaller,
        SOCKET s,
        int backlog
    );

    EXPORTNUM(18)
    int NetDll_recv(
        XNCALLER_TYPE xnCaller,
        SOCKET s,
        char *buf,
        int len,
        int flags
    );

    EXPORTNUM(20)
    int NetDll_recvfrom(
        XNCALLER_TYPE xnCaller,
        SOCKET s,
        const char *buf,
        int len,
        int flags,
        sockaddr *from,
        int *fromlen
    );

    EXPORTNUM(15)
    int NetDll_select(
        IN XNCALLER_TYPE xnCaller,
        int nfds,
        fd_set *readfds,
        fd_set *writefds,
        fd_set *exceptfds,
        const timeval *timeout
    );

    EXPORTNUM(22)
    int NetDll_send(
        XNCALLER_TYPE xnCaller,
        SOCKET s,
        const char *buf,
        int len,
        int flags
    );

    EXPORTNUM(24)
    int NetDll_sendto(
        XNCALLER_TYPE xnCaller,
        SOCKET s,
        const char *buf,
        int len,
        int flags,
        const sockaddr *to,
        int tolen
    );

    EXPORTNUM(7)
    int NetDll_setsockopt(
        XNCALLER_TYPE xnCaller,
        SOCKET s,
        int level,
        int optname,
        const char *optval,
        int optlen
    );

    EXPORTNUM(5)
    int NetDll_shutdown(
        XNCALLER_TYPE xnCaller,
        SOCKET s,
        int how
    );

    EXPORTNUM(3)
    SOCKET NetDll_socket(
        XNCALLER_TYPE xnCaller,
        int af,
        int type,
        int protocol
    );

    EXPORTNUM(2)
    int NetDll_WSACleanup(
        XNCALLER_TYPE xnCaller
    );

    EXPORTNUM(36)
    int NetDll_WSAStartupEx(
        XNCALLER_TYPE xnCaller,
        uint16_t versionRequested,
        WSAData *pWSAData,
        uint32_t versionReq
    );

    EXPORTNUM(52)
    int NetDll_XNetCleanup(
        XNCALLER_TYPE xnCaller
    );

    EXPORTNUM(67)
    int NetDll_XNetDnsLookup(
        XNCALLER_TYPE xnCaller,
        const char *pszHost,
        HANDLE hEvent,
        XNDNS **ppxndns
    );

    EXPORTNUM(68)
    int NetDll_XNetDnsRelease(
        XNCALLER_TYPE xnCaller,
        XNDNS *pxndns
    );

    EXPORTNUM(51)
    int NetDll_XNetStartup(
        XNCALLER_TYPE xnCaller,
        const XNetStartupParams *pxnsp
    );

    EXPORTNUM(463)
    uint32_t XamGetCurrentTitleId(
        void
    );
}
