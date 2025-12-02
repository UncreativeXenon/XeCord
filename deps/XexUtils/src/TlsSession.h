#pragma once

/// @file TlsSession.h
///
/// This module is heavily insipired by XboxTLS (https://github.com/JakobRangel/XboxTLS),
/// which served as an example for integrating BearSSL on Xbox 360. Especially on how to
/// provide a custom enthropy function using the native XeCrypt* functions.
///
/// It is meant to be internal and only used by other XexUtils APIs.

#include <bearssl.h>

namespace XexUtils
{

class TlsSession
{
public:
    /// @brief Default constructor.
    TlsSession();

    /// @brief Initializes a TLS session.
    /// @param socket The socket to start the session on.
    /// @param domain The domain name to verify the certificates against.
    void Start(const SOCKET &socket, const std::string &domain);

    /// @brief Adds an Elliptic Curve trust anchor.
    /// @param dn The distinguished name.
    /// @param dnSize The amount of bytes in `dn`.
    /// @param q The public key curve point.
    /// @param qSize The amount of bytes in `q`.
    /// @param curveType The curve type.
    void AddECTrustAnchor(const uint8_t *dn, size_t dnSize, const uint8_t *q, size_t qSize, int curveType);

    /// @brief Adds an RSA trust anchor.
    /// @param dn The distinguished name.
    /// @param dnSize The amount of bytes in `dn`.
    /// @param n The public key modulus.
    /// @param nSize The amount of bytes in `n`.
    /// @param e The public key exponent.
    /// @param eSize The amount of bytes in `e`.
    /// @return `S_OK` on success, `E_FAIL` on error.
    void AddRsaTrustAnchor(const uint8_t *dn, size_t dnSize, const uint8_t *n, size_t nSize, const uint8_t *e, size_t eSize);

    /// @brief Sends `size` bytes from `buffer` into the socket associated with the TLS session.
    ///
    /// This function can fail if not all bytes could be sent.
    ///
    /// @param buffer The buffer to send data from.
    /// @param size The amount of bytes to send.
    /// @return The amount of bytes sent on success, `SOCKET_ERROR` on error.
    int Send(const char *buffer, size_t size);

    /// @brief Receives at most `maxSize` bytes from the socket associated with the TLS
    /// session and store them in `buffer`.
    /// @param buffer The buffer to store data into.
    /// @param maxSize The max amount of bytes to receive.
    /// @return The amount of bytes sent on success, `SOCKET_ERROR` on error or when no bytes
    /// were received.
    int Receive(char *buffer, size_t maxSize);

private:
    br_ssl_client_context m_SslClientContext;
    br_x509_minimal_context m_x509Context;
    uint8_t m_IoBuffer[BR_SSL_BUFSIZE_BIDI];
    br_sslio_context m_IoContext;
    std::vector<br_x509_trust_anchor> m_TrustAnchors;

    static int SocketReadCallback(void *pContext, uint8_t *buffer, size_t maxSize);

    static int SocketWriteCallback(void *pContext, const uint8_t *buffer, size_t maxSize);
};

}
