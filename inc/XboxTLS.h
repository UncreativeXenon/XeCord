/*
 ============================================================================
  XboxTLS.h - TLS 1.2 Client API for Xbox 360 using BearSSL
 ============================================================================

  Overview:
  ---------
  XboxTLS provides a lightweight TLS 1.2 client implementation designed to run
  on modded or development Xbox 360 consoles. It is built on top of BearSSL’s 
  minimal TLS and X.509 engine, using platform-specific APIs for networking 
  (Winsock/XNet) and cryptographic randomness (XeCryptRandom).

  This header defines the full public API exposed by the XboxTLS static library.
  The API enables developers to securely connect to HTTPS endpoints directly 
  from Xbox 360 homebrew applications. It supports both RSA and Elliptic Curve
  trust anchors, along with a configurable choice of hash algorithms for 
  certificate verification.

  Features:
  ---------
    • TLS 1.2 protocol with encrypted socket communication
    • Minimal X.509 certificate validation (trust anchor only)
    • EC and RSA root certificate support (manual injection)
    • SHA-256, SHA-384, SHA-512, SHA-1, SHA-224 support
    • Works with Let’s Encrypt, Google, Cloudflare, etc.
    • Fully static, no dynamic BearSSL dependencies

  Usage Workflow:
  ---------------
    1. Initialize an XboxTLSContext using `XboxTLS_CreateContext`.
    2. Set the desired certificate hash algorithm in `ctx->hashAlgo`.
    3. Add trust anchors via `XboxTLS_AddTrustAnchor_RSA` or `_EC`.
    4. Resolve the server IP manually (via XNet DNS or hardcoded).
    5. Call `XboxTLS_Connect()` to establish a secure connection.
    6. Use `XboxTLS_Write()` and `XboxTLS_Read()` for data transfer.
    7. Call `XboxTLS_Free()` to clean up and close the connection.

  Notes:
  ------
    • This library targets Xbox 360 environments.
    • Trust anchors must be embedded manually; no system store is used.
    • Only TLS 1.2 is supported. TLS 1.3 is not implemented yet.

  Author:
    Jakob Rangel (@jakobrangel)

  License:
    MIT License (MIT) — see LICENSE file for details

 ============================================================================
*/


#pragma once
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif


// Hash algorithm options supported for certificate validation and internal PRNG
typedef enum {
    XboxTLS_Hash_SHA256,  // Recommended default
    XboxTLS_Hash_SHA384,  // Used for P-384 certificates
    XboxTLS_Hash_SHA512,  // For future-proofing or specific CA requirements
    XboxTLS_Hash_SHA1,    // Deprecated, but may be required for legacy certificates
    XboxTLS_Hash_SHA224   // Rarely used, included for completeness
} XboxTLSHash;

// Opaque context structure used to manage TLS state, buffers, and trust anchors
typedef struct {
    void* internal;          // Internal implementation-specific structure
    XboxTLSHash hashAlgo;    // Hash algorithm used for certificate validation
} XboxTLSContext;

// Public key types supported in trust anchors
typedef enum {
    XboxTLS_KeyType_RSA = 1,  // RSA public key
    XboxTLS_KeyType_EC  = 2   // Elliptic curve public key
} XboxTLSKeyType;

// Elliptic curve identifiers used with EC trust anchors (aligned with BearSSL)
typedef enum {
    XboxTLS_Curve_sect163k1        = 1,
    XboxTLS_Curve_sect163r1        = 2,
    XboxTLS_Curve_sect163r2        = 3,
    XboxTLS_Curve_sect193r1        = 4,
    XboxTLS_Curve_sect193r2        = 5,
    XboxTLS_Curve_sect233k1        = 6,
    XboxTLS_Curve_sect233r1        = 7,
    XboxTLS_Curve_sect239k1        = 8,
    XboxTLS_Curve_sect283k1        = 9,
    XboxTLS_Curve_sect283r1        = 10,
    XboxTLS_Curve_sect409k1        = 11,
    XboxTLS_Curve_sect409r1        = 12,
    XboxTLS_Curve_sect571k1        = 13,
    XboxTLS_Curve_sect571r1        = 14,
    XboxTLS_Curve_secp160k1        = 15,
    XboxTLS_Curve_secp160r1        = 16,
    XboxTLS_Curve_secp160r2        = 17,
    XboxTLS_Curve_secp192k1        = 18,
    XboxTLS_Curve_secp192r1        = 19,
    XboxTLS_Curve_secp224k1        = 20,
    XboxTLS_Curve_secp224r1        = 21,
    XboxTLS_Curve_secp256k1        = 22,
    XboxTLS_Curve_secp256r1        = 23,  // NIST P-256
    XboxTLS_Curve_secp384r1        = 24,  // NIST P-384
    XboxTLS_Curve_secp521r1        = 25,  // NIST P-521
    XboxTLS_Curve_brainpoolP256r1  = 26,
    XboxTLS_Curve_brainpoolP384r1  = 27,
    XboxTLS_Curve_brainpoolP512r1  = 28,
    XboxTLS_Curve_Curve25519       = 29,
    XboxTLS_Curve_Curve448         = 30
} XboxTLSCurve;

/**
 * @brief Initializes a new TLS context.
 *
 * Allocates internal memory and prepares the structure for use. This must be called before
 * adding trust anchors or initiating a connection.
 *
 * @param ctx Pointer to a user-allocated XboxTLSContext.
 * @param hostname Server hostname used for certificate verification and SNI.
 * @return true on success, false on error.
 */
bool XboxTLS_CreateContext(XboxTLSContext* ctx, const char* hostname);

/**
 * @brief Adds an RSA-based certificate authority to the context.
 *
 * This public key will be used to verify the server's certificate during the handshake.
 *
 * @param ctx        TLS context pointer
 * @param dn         Distinguished Name of the issuer
 * @param dn_len     Length of the DN in bytes
 * @param n          RSA modulus
 * @param n_len      Length of modulus in bytes
 * @param e          RSA public exponent
 * @param e_len      Length of exponent in bytes
 * @return true on success, false if anchor limit is reached or parameters are invalid
 */

typedef void(*XboxTLS_LogCallback)(const char* msg);
void XboxTLS_SetLogCallback(XboxTLSContext* ctx, XboxTLS_LogCallback callback);

bool XboxTLS_AddTrustAnchor_RSA(XboxTLSContext* ctx,
    const unsigned char* dn, size_t dn_len,
    const unsigned char* n, size_t n_len,
    const unsigned char* e, size_t e_len);

/**
 * @brief Adds an EC (Elliptic Curve) trust anchor to the context.
 *
 * This is used for certificate authorities with EC-based public keys.
 *
 * @param ctx        TLS context pointer
 * @param dn         Distinguished Name of the issuer
 * @param dn_len     Length of the DN in bytes
 * @param q          EC public key (uncompressed)
 * @param q_len      Length of EC key in bytes
 * @param curve_id   The elliptic curve used (e.g., NIST P-384)
 * @return true on success, false if anchor limit is reached or parameters are invalid
 */
bool XboxTLS_AddTrustAnchor_EC(XboxTLSContext* ctx,
    const unsigned char* dn, size_t dn_len,
    const unsigned char* q, size_t q_len,
    XboxTLSCurve curve_id);

/**
 * @brief Establishes a TCP connection and performs a full TLS handshake.
 *
 * After calling this, the TLS connection is ready to send/receive encrypted data.
 *
 * @param ctx        Initialized TLS context
 * @param ip         Server IP address in dotted notation (e.g., "192.168.1.1")
 * @param hostname   Hostname used for certificate validation and SNI
 * @param port       Port to connect to (typically 443)
 * @return true on success, false on failure
 */
bool XboxTLS_Connect(XboxTLSContext* ctx, const char* ip, const char* hostname, int port);

/**
 * @brief Sends encrypted data over the established TLS connection.
 *
 * This encrypts and flushes the buffer through the BearSSL I/O abstraction.
 *
 * @param ctx TLS context
 * @param buf Pointer to the plaintext data
 * @param len Number of bytes to send
 * @return Number of bytes sent on success, or -1 on error
 */
int XboxTLS_Write(XboxTLSContext* ctx, const void* buf, int len);

/**
 * @brief Reads decrypted application data from the TLS connection.
 *
 * Blocks until data is available or the connection is closed.
 *
 * @param ctx TLS context
 * @param buf Buffer to receive plaintext
 * @param len Maximum number of bytes to read
 * @return Number of bytes read on success, or -1 on error
 */
int XboxTLS_Read(XboxTLSContext* ctx, void* buf, int len);

/**
 * @brief Frees all resources and closes the TLS connection.
 *
 * Should be called once communication is complete. Cleans up internal structures
 * including trust anchors and cryptographic contexts.
 *
 * @param ctx TLS context to destroy
 */
void XboxTLS_Free(XboxTLSContext* ctx);

// Performs the WebSocket upgrade over TLS
bool XboxTLS_WebSocketUpgrade(XboxTLSContext* ctx, const char* host, const char* path, const char* origin);

// Sends a WebSocket frame (unmasked, text-only for now)
bool XboxTLS_SendWebSocketFrame(XboxTLSContext* ctx, const void* data, size_t len);

// Receives a WebSocket frame (text-only, returns null-terminated string; must free())
char* XboxTLS_ReceiveWebSocketFrame(XboxTLSContext* ctx, size_t* outLen, bool* isZlib);

int XboxTLS_LastError(XboxTLSContext* ctx);

void XboxTLS_ShutdownAndClose(XboxTLSContext* ctx);

bool XboxTLS_IsAlive(XboxTLSContext* ctx);

bool XboxTLS_HasFatalError(XboxTLSContext* ctx);

bool XboxTLS_SocketDead(XboxTLSContext* ctx);

#ifdef __cplusplus
}
#endif