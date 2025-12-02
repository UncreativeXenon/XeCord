#include "pch.h"
#include "TlsSession.h"

#include "Kernel.h"
#include "Memory.h"
#include "SystemSocket.h"

namespace XexUtils
{

TlsSession::TlsSession()
{
    ZeroMemory(&m_SslClientContext, sizeof(m_SslClientContext));
    ZeroMemory(&m_x509Context, sizeof(m_x509Context));
    ZeroMemory(m_IoBuffer, sizeof(m_IoBuffer));
    ZeroMemory(&m_IoContext, sizeof(m_IoContext));
}

void TlsSession::Start(const SOCKET &sock, const std::string &domain)
{
    XASSERT(sock != INVALID_SOCKET);
    XASSERT(domain.empty() == false);

    br_ssl_client_init_full(&m_SslClientContext, &m_x509Context, m_TrustAnchors.data(), m_TrustAnchors.size());

    br_ssl_engine_set_buffer(&m_SslClientContext.eng, m_IoBuffer, sizeof(m_IoBuffer), 1);

    br_ssl_client_reset(&m_SslClientContext, domain.c_str(), 0);

    br_sslio_init(
        &m_IoContext,
        &m_SslClientContext.eng,
        SocketReadCallback,
        const_cast<SOCKET *>(&sock),
        SocketWriteCallback,
        const_cast<SOCKET *>(&sock)
    );
}

void TlsSession::AddECTrustAnchor(const uint8_t *dn, size_t dnSize, const uint8_t *q, size_t qSize, int curveType)
{
    XASSERT(dn != nullptr);
    XASSERT(q != nullptr);

    br_x509_trust_anchor trustAnchor = {};
    trustAnchor.dn.data = const_cast<uint8_t *>(dn);
    trustAnchor.dn.len = dnSize;
    trustAnchor.flags = BR_X509_TA_CA;
    trustAnchor.pkey.key_type = BR_KEYTYPE_EC;
    trustAnchor.pkey.key.ec.curve = curveType;
    trustAnchor.pkey.key.ec.q = const_cast<uint8_t *>(q);
    trustAnchor.pkey.key.ec.qlen = qSize;

    m_TrustAnchors.emplace_back(trustAnchor);
}

void TlsSession::AddRsaTrustAnchor(const uint8_t *dn, size_t dnSize, const uint8_t *n, size_t nSize, const uint8_t *e, size_t eSize)
{
    XASSERT(dn != nullptr);
    XASSERT(n != nullptr);
    XASSERT(e != nullptr);

    br_x509_trust_anchor trustAnchor = {};
    trustAnchor.dn.data = const_cast<uint8_t *>(dn);
    trustAnchor.dn.len = dnSize;
    trustAnchor.flags = BR_X509_TA_CA;
    trustAnchor.pkey.key_type = BR_KEYTYPE_RSA;
    trustAnchor.pkey.key.rsa.n = const_cast<uint8_t *>(n);
    trustAnchor.pkey.key.rsa.nlen = nSize;
    trustAnchor.pkey.key.rsa.e = const_cast<uint8_t *>(e);
    trustAnchor.pkey.key.rsa.elen = eSize;

    m_TrustAnchors.emplace_back(trustAnchor);
}

int TlsSession::Send(const char *buffer, size_t size)
{
    XASSERT(buffer != nullptr);

    if (br_sslio_write_all(&m_IoContext, buffer, size) != 0)
    {
        DebugPrint(
            "[XexUtils][TlsSession]: Error: SSL write error: %d",
            br_ssl_engine_last_error(&m_SslClientContext.eng)
        );
        return SOCKET_ERROR;
    }

    if (br_sslio_flush(&m_IoContext) != 0)
    {
        DebugPrint(
            "[XexUtils][TlsSession]: Error: SSL flush error: %d",
            br_ssl_engine_last_error(&m_SslClientContext.eng)
        );
        return SOCKET_ERROR;
    }

    return size;
}

int TlsSession::Receive(char *buffer, size_t maxSize)
{
    XASSERT(buffer != nullptr);

    int bytesRead = br_sslio_read(&m_IoContext, buffer, maxSize);

#ifndef NDEBUG
    int lastSslError = br_ssl_engine_last_error(&m_SslClientContext.eng);
    if (bytesRead < 0 && lastSslError != 0)
        DebugPrint("[XexUtils][Socket]: Error: SSL read error: %d", lastSslError);
#endif

    return bytesRead;
}

int TlsSession::SocketReadCallback(void *pContext, uint8_t *buffer, size_t maxSize)
{
    SOCKET socket = Memory::Read<SOCKET>(pContext);

    return recv(socket, reinterpret_cast<char *>(buffer), maxSize, 0);
}

int TlsSession::SocketWriteCallback(void *pContext, const uint8_t *buffer, size_t maxSize)
{
    SOCKET socket = Memory::Read<SOCKET>(pContext);

    return send(socket, reinterpret_cast<const char *>(buffer), maxSize, 0);
}

}

static br_hmac_drbg_context s_drbg;

// Custom enthropy function
static int CustomSeeder(const br_prng_class **ppContext)
{
    uint8_t seed[32] = {};
    XeCryptRandom(seed, sizeof(seed));
    br_hmac_drbg_init(&s_drbg, &br_sha256_vtable, seed, sizeof(seed));
    *ppContext = s_drbg.vtable;

    return 1;
}

// Replace the original br_prng_seeder_system function from BearSSL with our own because the original
// one obviously doesn't support the Xbox 360
br_prng_seeder br_prng_seeder_system(const char **name)
{
    if (name)
        *name = "XeCryptRandom";

    return &CustomSeeder;
}
