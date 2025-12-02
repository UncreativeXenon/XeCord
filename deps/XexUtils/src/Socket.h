#pragma once

namespace XexUtils
{

// `TlsSession` is forward declared so that its header doesn't need to be included in a
// public API. This is meant to abstract away BearSSL so that users don't need to configure
// their compiler to resolve its includes.
class TlsSession;

/// @brief A class representing a socket connection.
class Socket
{
public:
    /// @brief Elliptic curve identifiers used with EC trust anchors (aligned with BearSSL).
    typedef enum
    {
        Curve_sect163k1 = 1,
        Curve_sect163r1,
        Curve_sect163r2,
        Curve_sect193r1,
        Curve_sect193r2,
        Curve_sect233k1,
        Curve_sect233r1,
        Curve_sect239k1,
        Curve_sect283k1,
        Curve_sect283r1,
        Curve_sect409k1,
        Curve_sect409r1,
        Curve_sect571k1,
        Curve_sect571r1,
        Curve_secp160k1,
        Curve_secp160r1,
        Curve_secp160r2,
        Curve_secp192k1,
        Curve_secp192r1,
        Curve_secp224k1,
        Curve_secp224r1,
        Curve_secp256k1,
        Curve_secp256r1,
        Curve_secp384r1,
        Curve_secp521r1,
        Curve_brainpoolP256r1,
        Curve_brainpoolP384r1,
        Curve_brainpoolP512r1,
        Curve_curve25519,
        Curve_curve448
    } EllipticCurveType;

    /// @brief Creates an empty `Socket`.
    Socket();

    /// @brief Creates a `Socket`.
    /// @param domain The domain name to connect to.
    /// @param port The port to connect to.
    /// @param secure Wether to use TLS or not.
    Socket(const std::string &domain, uint16_t port, bool secure = true);

    /// @brief Creates a copy from an existing `Socket`.
    /// @param other The other `Socket` to copy from.
    Socket(const Socket &other);

    /// @brief Calls `Disconnect`.
    ~Socket();

    /// @brief Connects the socket to the specified domain and port.
    ///
    /// The built-in encryption, which is different from TLS, is disabled. It means the
    /// running process needs to have the insecure socket privilege.
    ///
    /// This function can fail if the DNS lookup fails (invalid name, DNS server
    /// connectivity issues), if disabling the built-in encryption fails (insufficient
    /// privilege), or if the server doesn't listen on the specified port.
    ///
    /// @return `S_OK` on success, `E_FAIL` on error.
    HRESULT Connect();

    /// @brief Shuts down and closes the socket.
    void Disconnect();

    /// @brief Sends `size` bytes from `buffer` into the socket connection.
    ///
    /// When TLS is enabled, exactly `size` bytes need to be sent for the function to
    /// succeed. When TLS is disabled, this function just calls `send` from the standard
    /// library.
    ///
    /// @param buffer The buffer to send data from.
    /// @param size The amount of bytes to send.
    /// @return The amount of bytes sent on success, `SOCKET_ERROR` on error.
    int Send(const char *buffer, size_t size);

    /// @brief Receives at most `maxSize` bytes from the socket connection and store them
    /// in `buffer`.
    ///
    /// When TLS is disabled, this function just calls `recv` from the standard library.
    ///
    /// @param buffer The buffer to store data into.
    /// @param maxSize The max amount of bytes to receive.
    /// @return The amount of bytes sent on success, `SOCKET_ERROR` on error or when no
    /// bytes were received.
    int Receive(char *buffer, size_t maxSize);

    /// @brief Adds an Elliptic Curve trust anchor.
    ///
    /// This function can fail if TLS is disabled.
    ///
    /// @param dn The distinguished name.
    /// @param dnSize The amount of bytes in `dn`.
    /// @param q The public key curve point.
    /// @param qSize The amount of bytes in `q`.
    /// @param curveType The curve type.
    /// @return `S_OK` on success, `E_FAIL` on error.
    HRESULT AddECTrustAnchor(const uint8_t *dn, size_t dnSize, const uint8_t *q, size_t qSize, EllipticCurveType curveType);

    /// @brief Adds an RSA trust anchor.
    ///
    /// This function can fail if TLS is disabled.
    ///
    /// @param dn The distinguished name.
    /// @param dnSize The amount of bytes in `dn`.
    /// @param n The public key modulus.
    /// @param nSize The amount of bytes in `n`.
    /// @param e The public key exponent.
    /// @param eSize The amount of bytes in `e`.
    /// @return `S_OK` on success, `E_FAIL` on error.
    HRESULT AddRsaTrustAnchor(const uint8_t *dn, size_t dnSize, const uint8_t *n, size_t nSize, const uint8_t *e, size_t eSize);

    SOCKET m_Socket;
    
private:
    std::string m_Domain;
    uint16_t m_Port;
    bool m_Secure;
    bool m_Connected;
    TlsSession *m_pTlsSession;

    IN_ADDR DnsLookup();

private:
    static bool s_Initialized;
    static size_t s_ReferenceCounter;

    static HRESULT GlobalInit();

    static void GlobalCleanup();
};

}
