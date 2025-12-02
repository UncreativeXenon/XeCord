#include "pch.h"
#include "Socket.h"

#include "SystemSocket.h"
#include "TlsSession.h"

namespace XexUtils
{

bool Socket::s_Initialized = false;
size_t Socket::s_ReferenceCounter = 0;

Socket::Socket()
    : m_Socket(INVALID_SOCKET), m_Port(0), m_Secure(false), m_Connected(false), m_pTlsSession(nullptr)
{
}

Socket::Socket(const std::string &domain, uint16_t port, bool secure)
    : m_Socket(INVALID_SOCKET), m_Domain(domain), m_Port(port), m_Secure(secure), m_Connected(false), m_pTlsSession(nullptr)
{
    if (m_Secure)
        m_pTlsSession = new TlsSession();
}

Socket::Socket(const Socket &other)
    : m_Socket(INVALID_SOCKET), m_Domain(other.m_Domain), m_Port(other.m_Port), m_Secure(other.m_Secure), m_Connected(false), m_pTlsSession(nullptr)
{
    if (m_Secure)
        m_pTlsSession = new TlsSession();
}

Socket::~Socket()
{
    Disconnect();

    // Cleanup the TLS session if one was created
    if (m_pTlsSession != nullptr)
        delete m_pTlsSession;
}

HRESULT Socket::Connect()
{
    // Execute the global initialization when connecting with a socket for the first time
    if (s_ReferenceCounter == 0 && s_Initialized == false)
    {
        HRESULT hr = GlobalInit();
        if (FAILED(hr))
            return hr;
    }

    // Resolve domain to IP address
    IN_ADDR ipAddress = DnsLookup();
    if (ipAddress.s_addr == INADDR_NONE)
        return E_FAIL;

    // Set up the address info of the server
    sockaddr_in addrInfo = {};
    addrInfo.sin_family = AF_INET;
    addrInfo.sin_port = htons(m_Port);
    addrInfo.sin_addr = ipAddress;

    // Create the socket
    m_Socket = socket(addrInfo.sin_family, SOCK_STREAM, IPPROTO_TCP);
    if (m_Socket == INVALID_SOCKET)
    {
        DebugPrint("[XexUtils][Socket]: Error: Failed to create socket: %d.", WSAGetLastError());
        return E_FAIL;
    }

    // Disable encryption
    BOOL yes = TRUE;
    if (setsockopt(m_Socket, SOL_SOCKET, 0x5801, reinterpret_cast<const char *>(&yes), sizeof(yes)) == SOCKET_ERROR)
    {
        DebugPrint("[XexUtils][Socket]: Error: Failed to disable encryption with setsockopt: %d.", WSAGetLastError());
        Disconnect();
        return E_FAIL;
    }

    // Connect to the server
    if (connect(m_Socket, reinterpret_cast<sockaddr *>(&addrInfo), sizeof(addrInfo)) == SOCKET_ERROR)
    {
        DebugPrint("[XexUtils][Socket]: Error: Failed to connect: %d.", WSAGetLastError());
        Disconnect();
        return E_FAIL;
    }

    // Start TLS session if requested
    if (m_Secure)
        m_pTlsSession->Start(m_Socket, m_Domain);

    m_Connected = true;

    s_ReferenceCounter++;

    return S_OK;
}

void Socket::Disconnect()
{
    // Disconnect the socket
    if (m_Socket != INVALID_SOCKET)
    {
        shutdown(m_Socket, SD_BOTH);
        closesocket(m_Socket);
    }

    m_Connected = false;

    if (s_ReferenceCounter != 0)
        s_ReferenceCounter--;

    // Once the amount of connected sockets hits 0, execute the global cleanup
    if (s_ReferenceCounter == 0 && s_Initialized == true)
        GlobalCleanup();
}

int Socket::Send(const char *buffer, size_t size)
{
    XASSERT(m_Connected == true);

    // Let the TLS session handle sending packets when in secure mode
    if (m_Secure)
        return m_pTlsSession->Send(buffer, size);

    return send(m_Socket, buffer, size, 0);
}

int Socket::Receive(char *buffer, size_t maxSize)
{
    XASSERT(m_Connected == true);

    // Let the TLS session handle receiving packets when in secure mode
    if (m_Secure)
        return m_pTlsSession->Receive(buffer, maxSize);

    return recv(m_Socket, buffer, maxSize, 0);
}

HRESULT Socket::AddECTrustAnchor(const uint8_t *dn, size_t dnSize, const uint8_t *q, size_t qSize, EllipticCurveType curveType)
{
    if (!m_Secure)
    {
        DebugPrint("[XexUtils][Socket]: Error: This socket is not in secure mode, trust anchors can't be added.");
        return E_FAIL;
    }

    m_pTlsSession->AddECTrustAnchor(dn, dnSize, q, qSize, curveType);

    return S_OK;
}

HRESULT Socket::AddRsaTrustAnchor(const uint8_t *dn, size_t dnSize, const uint8_t *n, size_t nSize, const uint8_t *e, size_t eSize)
{
    if (!m_Secure)
    {
        DebugPrint("[XexUtils][Socket]: Error: This socket is not in secure mode, trust anchors can't be added.");
        return E_FAIL;
    }

    m_pTlsSession->AddRsaTrustAnchor(dn, dnSize, n, nSize, e, eSize);

    return S_OK;
}

IN_ADDR Socket::DnsLookup()
{
    XASSERT(s_Initialized == true);
    XASSERT(m_Domain.empty() == false);

    IN_ADDR address = {};
    address.s_addr = INADDR_NONE;

    XNDNS *pXNDns = nullptr;
    HANDLE hEvent = CreateEvent(nullptr, false, false, nullptr);

    // Start the domain resolution, this task is asynchronous
    int error = XNetDnsLookup(m_Domain.c_str(), hEvent, &pXNDns);
    if (error != 0)
    {
        DebugPrint("[XexUtils][Socket]: Error: XNetDnsLookup failed with code %d.", error);
        CloseHandle(hEvent);
        return address;
    }

    // Error case
    if (pXNDns->iStatus != 0 && pXNDns->iStatus != WSAEINPROGRESS)
    {
        DebugPrint("[XexUtils][Socket]: Error: Unexpected XNDNS::iStatus value: %d.", error);
        XNetDnsRelease(pXNDns);
        CloseHandle(hEvent);
        return address;
    }

    // Wait at most 5 seconds for completion
    if (pXNDns->iStatus == WSAEINPROGRESS)
        WaitForSingleObject(hEvent, 5000);

    // Check for timeout
    if (pXNDns->iStatus != 0)
    {
        DebugPrint("[XexUtils][Socket]: Error: DNS lookup for %s timed out.", m_Domain.c_str());
        XNetDnsRelease(pXNDns);
        CloseHandle(hEvent);
        return address;
    }

    address = pXNDns->aina[0];

    // Cleanup
    XNetDnsRelease(pXNDns);
    CloseHandle(hEvent);

    return address;
}

HRESULT Socket::GlobalInit()
{
    WSADATA wsaData = {};
    XNetStartupParams xNetStartupParams = {};

    // Bypass security
    xNetStartupParams.cfgSizeOfStruct = sizeof(XNetStartupParams);
    xNetStartupParams.cfgFlags = XNET_STARTUP_BYPASS_SECURITY;

    // Initialize XNet
    int err = XNetStartup(&xNetStartupParams);
    if (err != 0)
    {
        DebugPrint("[XexUtils][Socket]: Error: XNetStartup failed with code %d.", err);
        return E_FAIL;
    }

    // Initialize Winsock
    err = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (err != 0)
    {
        DebugPrint("[XexUtils][Socket]: Error: WSAStartup failed with code %d.", err);
        return E_FAIL;
    }

    s_Initialized = true;

    return S_OK;
}

void Socket::GlobalCleanup()
{
    WSACleanup();
    XNetCleanup();
    s_Initialized = false;
}

}
