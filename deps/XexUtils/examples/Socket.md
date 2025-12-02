# Socket

Connect to a server and exchange data:

> [!NOTE]
> When using sockets from a title (so not a system DLL), the title needs to have the insecure socket privilege.

```C++
void Init()
{
    HRESULT hr = S_OK;

    // Create a socket with TLS enabled (this is the default)
    uint16_t port = 443;
    bool secure = true;
    XexUtils::Socket socket("example.com", port, secure);

    // Add an Elliptic Curve trust anchor (only necessary when using a secure socket)
    const uint8_t dn[] = { 0x1, 0x2, 0x3 };
    const uint8_t q[] = { 0x1, 0x2, 0x3 };
    hr = socket.AddECTrustAnchor(dn, sizeof(dn), q, sizeof(q), XexUtils::Socket::Curve_secp384r1);
    if (FAILED(hr))
    {
        XexUtils::Log::Print("Couldn't add elliptic curve trust anchor");
        return;
    }

    // Connect to the server
    hr = socket.Connect();
    if (FAILED(hr))
    {
        XexUtils::Log::Print("Couldn't connect to server");
        return;
    }

    // Send a packet
    const char request[] =
        "GET /somepage.html HTTP/1.1\r\n"
        "Host: example.com\r\n"
        "Connection: close\r\n\r\n";
    int bytesSent = socket.Send(request, sizeof(request));
    if (bytesSent != sizeof(request))
    {
        XexUtils::Log::Print("Not all packets were sent");
        socket.Disconnect();
        return;
    }

    // Receive the response
    char buffer[4096] = {};
    int bytesReceived = socket.Receive(buffer, sizeof(buffer));
    if (bytesReceive <= 0)
    {
        XexUtils::Log::Print("Couldn't receive the server response");
        socket.Disconnect();
        return;
    }

    // Do something with what is inside buffer

    // The destructor calls Disconnect so this is optional
    socket.Disconnect();
}
```

To generate C byte arrays from a certificate, you can use the `brssl` command-line tool like so:

```
brssl ta ./cert.pem
```

The `brssl` command-line tool can be built from the [BearSSL source](https://bearssl.org/#download-and-installation). On a Linux system, simply clone the repository and run `make`. The output binary will be in `build/brssl`. The same process might work on Windows, but I never tried.
