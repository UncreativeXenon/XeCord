#include <iostream>
#include <xtl.h>
#include <xdk.h>
#include "XboxTLS.h"
#include "TLSClient.h"
#include <stdio.h>
#include <cstdint>
#include <cstdio>
#include <string>
#include <cstring>
#include "xkelib.h"
#include <io.h>       // For _access
#include <direct.h>   // For _mkdir
#include <sys/stat.h> // For S_IFDIR

#define CONFIG_PATH "hdd:\\Plugins\\PluginData\\XeCord\\config.ini"

#define RAPIDJSON_BIGENDIAN 1
#define RAPIDJSON_ENDIAN RAPIDJSON_BIGENDIAN
#define RAPIDJSON_SNPRINTF _snprintf
#define RAPIDJSON_VSNPRINTF _vsnprintf

#ifdef max
#undef max
#endif
#ifdef min
#undef min
#endif

#include "rapidjson/document.h"
#include "rapidjson/reader.h"
#include "rapidjson/encodedstream.h"
#include <rapidjson/writer.h>
#include <rapidjson/stringbuffer.h>

using namespace rapidjson;

#define MAX_CLIENTS 4

TLSClient g_Clients[MAX_CLIENTS];
int g_ClientCount = 0;
bool g_JustReconnected = false;
char g_Token[128] = {0};
int g_Dash;
const char* g_DashList[] = {
    "FFFE07D1",
    "00000166",
    "00000167"
};

uint32_t g_LastTitleId = 99999999;
uint64_t g_GameStartTimestamp = 0;

/*char sessionId[256];
int seq = -1;
char resumeGatewayURL[256];*/

static const unsigned char EC_DN[] = {
	0x30, 0x47, 0x31, 0x0B, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13,
	0x02, 0x55, 0x53, 0x31, 0x22, 0x30, 0x20, 0x06, 0x03, 0x55, 0x04, 0x0A,
	0x13, 0x19, 0x47, 0x6F, 0x6F, 0x67, 0x6C, 0x65, 0x20, 0x54, 0x72, 0x75,
	0x73, 0x74, 0x20, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x73, 0x20,
	0x4C, 0x4C, 0x43, 0x31, 0x14, 0x30, 0x12, 0x06, 0x03, 0x55, 0x04, 0x03,
	0x13, 0x0B, 0x47, 0x54, 0x53, 0x20, 0x52, 0x6F, 0x6F, 0x74, 0x20, 0x52,
	0x34
};

static const unsigned char EC_Q[] = {
	0x04, 0xF3, 0x74, 0x73, 0xA7, 0x68, 0x8B, 0x60, 0xAE, 0x43, 0xB8, 0x35,
	0xC5, 0x81, 0x30, 0x7B, 0x4B, 0x49, 0x9D, 0xFB, 0xC1, 0x61, 0xCE, 0xE6,
	0xDE, 0x46, 0xBD, 0x6B, 0xD5, 0x61, 0x18, 0x35, 0xAE, 0x40, 0xDD, 0x73,
	0xF7, 0x89, 0x91, 0x30, 0x5A, 0xEB, 0x3C, 0xEE, 0x85, 0x7C, 0xA2, 0x40,
	0x76, 0x3B, 0xA9, 0xC6, 0xB8, 0x47, 0xD8, 0x2A, 0xE7, 0x92, 0x91, 0x6A,
	0x73, 0xE9, 0xB1, 0x72, 0x39, 0x9F, 0x29, 0x9F, 0xA2, 0x98, 0xD3, 0x5F,
	0x5E, 0x58, 0x86, 0x65, 0x0F, 0xA1, 0x84, 0x65, 0x06, 0xD1, 0xDC, 0x8B,
	0xC9, 0xC7, 0x73, 0xC8, 0x8C, 0x6A, 0x2F, 0xE5, 0xC4, 0xAB, 0xD1, 0x1D,
	0x8A
};

const unsigned char RSA_DN[] = {
    0x30, 0x31, 0x31, 0x0B, 0x30, 0x09, 0x06, 0x03,
    0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31,
    0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x0A,
    0x13, 0x0A, 0x49, 0x53, 0x52, 0x47, 0x20, 0x2C,
    0x49, 0x6E, 0x63, 0x2E, 0x31, 0x13, 0x30, 0x11,
    0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x0A, 0x49,
    0x53, 0x52, 0x47, 0x20, 0x52, 0x6F, 0x6F, 0x74,
    0x20, 0x58, 0x31
};
const unsigned char RSA_N[] = {
    0x00, 0xaf, 0x2f, 0x62, 0xe9, 0xf5, 0x3d, 0x1f, 0x64, 0x2e, 0x98, 0x0f, 0x09, 0x3a, 0x65, 0x9b,
    0xf5, 0x77, 0x6f, 0x47, 0xdc, 0x96, 0xf9, 0x4e, 0x58, 0x91, 0x1f, 0x94, 0xb6, 0x1b, 0x7f, 0x7d,
    0x25, 0xa4, 0x0c, 0xc2, 0x55, 0x43, 0xd6, 0x62, 0xe3, 0xf3, 0x82, 0xc5, 0x0b, 0x12, 0x4d, 0xb0,
    0x0e, 0xb3, 0x4c, 0x4e, 0xf0, 0xac, 0x6a, 0x26, 0x4e, 0xd3, 0x93, 0xf4, 0x39, 0xd2, 0xc8, 0x2c,
    0x3b, 0xc6, 0x0a, 0xc7, 0x57, 0x18, 0x6c, 0xd1, 0x60, 0x60, 0x87, 0xd8, 0xac, 0x00, 0x11, 0x5d,
    0xb3, 0x69, 0x6a, 0x25, 0x80, 0xa5, 0x6f, 0x84, 0x2c, 0x1b, 0x33, 0x61, 0x4a, 0xe7, 0xd1, 0x8d,
    0x1f, 0xa2, 0xb0, 0x0d, 0x2d, 0xea, 0xbb, 0x0e, 0x5f, 0xe2, 0x7f, 0xa5, 0x80, 0xd2, 0x5f, 0xb7,
    0x25, 0x34, 0xb0, 0x4e, 0x76, 0x9e, 0x2c, 0x83, 0x25, 0xb2, 0x3e, 0x33, 0xe7, 0x2d, 0x5e, 0x45,
    0x93, 0xa4, 0xb2, 0x2b, 0x73, 0x1a, 0x6c, 0xf4, 0x30, 0x95, 0x28, 0x3b, 0x6b, 0xa3, 0x75, 0x4d,
    0x38, 0xbe, 0x7a, 0x11, 0x3c, 0xdf, 0x71, 0x33, 0x4f, 0x0e, 0x9e, 0x6d, 0xe5, 0xa6, 0x76, 0x7e,
    0x3e, 0xf6, 0xf4, 0x91, 0x8a, 0xbe, 0x3d, 0xf4, 0x11, 0xc4, 0x91, 0x0a, 0xe3, 0x5c, 0x2f, 0xbe,
    0x2e, 0x27, 0x3e, 0x61, 0x61, 0xb4, 0x12, 0xfa, 0xb9, 0xd4, 0x26, 0x44, 0xbd, 0x1a, 0xd3, 0x12,
    0x68, 0x96, 0xa2, 0x92, 0x7a, 0x8b, 0x86, 0x4d, 0x12, 0x29, 0xa1, 0x77, 0x53, 0x4a, 0x9a, 0x35,
    0xe2, 0xa1, 0x56, 0x45, 0xc5, 0xf3, 0xd7, 0x70, 0xd7, 0x91, 0x9f, 0x8c, 0x1b, 0xdf, 0x1c, 0x0b,
    0xb1, 0x3d, 0xa7, 0xf2, 0xbb, 0xd9, 0x6b, 0x75, 0x8d, 0x2d, 0x7b, 0xc7, 0x19, 0x5b, 0x9f, 0x32,
    0xbc, 0x3a, 0x1a, 0xd5, 0xa3, 0x93, 0xb3, 0xf9, 0x75, 0x26, 0x2e, 0x67, 0xf2, 0x77, 0x93, 0x41
};
const unsigned char RSA_E[] = { 0x01, 0x00, 0x01 };

void Notify(const wchar_t* msg) {
    typedef void (*XNOTIFYQUEUEUI)(uint32_t, uint32_t, uint64_t, const wchar_t*, void*);
    HMODULE h = GetModuleHandle("xam.xex");
    XNOTIFYQUEUEUI XNotifyQueueUI = (XNOTIFYQUEUEUI)GetProcAddress(h, (LPCSTR)656);
    if (XNotifyQueueUI) {
        XNotifyQueueUI(0, 0, XNOTIFY_SYSTEM, msg, NULL);
    }
}

void XboxTLSLogger(const char* msg) {
    wchar_t wmsg[256];
    MultiByteToWideChar(CP_UTF8, 0, msg, -1, wmsg, 256);
    //Notify(wmsg);
}

bool ResolveDNS(const char* domain, char* outIp, int size) {
    XNDNS* dns = nullptr;
    if (XNetDnsLookup(domain, nullptr, &dns) != 0) return false;
    for (int i = 0; i < 50 && dns->iStatus == WSAEINPROGRESS; ++i) Sleep(100);
    if (dns->iStatus != 0 || dns->cina == 0) { XNetDnsRelease(dns); return false; }
    XNetInAddrToString(dns->aina[0], outIp, size);
    XNetDnsRelease(dns);
    return true;
}

void ensureDirectoryExists(const char* path) {
    char temp[256];
    strncpy(temp, path, sizeof(temp));
    temp[sizeof(temp) - 1] = '\0';

    for (char* p = temp + 1; *p; ++p) {
        if (*p == '\\' || *p == '/') {
            *p = '\0';
            _mkdir(temp);  // mkdir is OK if already exists
            *p = '\\';
        }
    }
}

void createDefaultConfigIfMissing() {
    ensureDirectoryExists(CONFIG_PATH);

    if (_access(CONFIG_PATH, 0) != 0) {
        FILE* file = fopen(CONFIG_PATH, "w");
        if (file) {
            fprintf(file,
                "[Discord]\n"
                "Token=\n"
                "\n"
                "[General]\n"
                "DefaultDash=1 ; 0 = Xbox 360 Dashboard, 1 = Aurora, 2 = Freestyle 3\n"
            );
            fclose(file);
            Notify(L"Created default config.ini");
        } else {
            Notify(L"Failed to create config.ini");
        }
    }
}

bool readIniValue(const char* section, const char* key, char* outValue, size_t outSize) {
    createDefaultConfigIfMissing();  // Ensure config exists

    FILE* file = fopen(CONFIG_PATH, "r");
    if (!file) {
        Notify(L"Failed to open config.ini");
        return false;
    }

    char line[256];
    bool inTargetSection = false;

    while (fgets(line, sizeof(line), file)) {
        char* trimmed = line;
        while (*trimmed == ' ' || *trimmed == '\t') trimmed++;

        if (*trimmed == ';' || *trimmed == '#' || *trimmed == '\n' || *trimmed == '\0')
            continue;

        if (*trimmed == '[') {
            char currentSection[64];
            if (sscanf(trimmed, "[%63[^]]]", currentSection) == 1) {
                inTargetSection = (_stricmp(currentSection, section) == 0);
            }
            continue;
        }

        if (inTargetSection) {
            char foundKey[64], foundValue[192];
            if (sscanf(trimmed, "%63[^=]=%191[^\r\n]", foundKey, foundValue) == 2) {
                if (_stricmp(foundKey, key) == 0) {
                    strncpy(outValue, foundValue, outSize - 1);
                    outValue[outSize - 1] = '\0';
                    fclose(file);
                    return true;
                }
            }
        }
    }

    fclose(file);
    return false;
}

uint64_t GetEpochMilliseconds() {
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);

    ULARGE_INTEGER ull;
    ull.LowPart = ft.dwLowDateTime;
    ull.HighPart = ft.dwHighDateTime;

    // Convert from 100-nanosecond intervals since 1601 to milliseconds since 1970
    return (ull.QuadPart - 116444736000000000ULL) / 10000ULL;
}

char* GetGamertag() {
    if (XUserGetSigninState(0) != eXUserSigninState_NotSignedIn) {
		static char gamertag[16];
		if (XUserGetName(0, gamertag, 16) == ERROR_SUCCESS) {
			return gamertag;
		} else {
			return (char*)"Unknown";
		}
	} else {
		return (char*)"Signed Out";
	}
}

DWORD SwapDword(DWORD val) {
    return ((val & 0xFF000000) >> 24) |
           ((val & 0x00FF0000) >> 8)  |
           ((val & 0x0000FF00) << 8)  |
           ((val & 0x000000FF) << 24);
}

DWORD GetOriginalXboxTitleID(const char* path) {
    FILE* file = fopen(path, "rb");
    if (!file) {
        Notify(L"Failed to open XBE file");
        return 0;
    }

    BYTE headerBuf[0x190] = {0};
    fread(headerBuf, 1, sizeof(headerBuf), file);
    fclose(file);

    DWORD rawTitleId = *(DWORD*)&headerBuf[0x18C];
    DWORD titleId = SwapDword(rawTitleId);

    return titleId;
}

std::string DecodeChunkedBody(const std::string& chunked) {
    std::string decoded;
    size_t pos = 0;

    while (pos < chunked.size()) {
        size_t lineEnd = chunked.find("\r\n", pos);
        if (lineEnd == std::string::npos) break;

        std::string chunkSizeStr = chunked.substr(pos, lineEnd - pos);
        size_t chunkSize = strtoul(chunkSizeStr.c_str(), nullptr, 16);
        if (chunkSize == 0) break;

        pos = lineEnd + 2;
        if (pos + chunkSize > chunked.size()) break;

        decoded.append(chunked.substr(pos, chunkSize));
        pos += chunkSize + 2;
    }

    return decoded;
}

char* GetGameIcon(const char* token, const char titleId[16]) {
	DWORD dwordTitleId = strtoul(titleId, nullptr, 16);
	if (dwordTitleId == 0xFFFE07D1) return (char*)"mp:app-assets/1380960102609064008/1385422462862229565.png";
    if (dwordTitleId == 0x00000166) return (char*)"mp:app-assets/1380960102609064008/1387868590035701791.png";
    if (dwordTitleId == 0x00000167) return (char*)"mp:app-assets/1380960102609064008/1387868096206864537.png";

    if (g_ClientCount >= MAX_CLIENTS) return nullptr;  // Return nullptr if client count exceeds limit

    Sleep(6000);

    TLSClient* client = &g_Clients[g_ClientCount];
    memset(client, 0, sizeof(TLSClient));
    client->running = TRUE;

    const char* host = "discord.com";
    const char* path = "/api/v9/applications/1380960102609064008/external-assets";

    // Build the asset URL manually using strcat and strncpy
    char assetUrl[512];
    const char* baseUrl = "https://raw.githubusercontent.com/UncreativeXenon/XboxUnity-Scraper/refs/heads/master/Icons/";

    // Initialize the assetUrl with the base URL
    strncpy(assetUrl, baseUrl, sizeof(assetUrl) - 1);
    assetUrl[sizeof(assetUrl) - 1] = '\0';  // Ensure null termination

    // Append the titleID and ".png" to the URL
    strncat(assetUrl, titleId, sizeof(assetUrl) - strlen(assetUrl) - 1);
    strncat(assetUrl, ".png", sizeof(assetUrl) - strlen(assetUrl) - 1);

    // Print the asset URL to check if it's correct
    //printf("Asset URL: %s\n", assetUrl);

    strncpy(client->host, host, sizeof(client->host) - 1);
    strncpy(client->path, path, sizeof(client->path) - 1);

    if (!ResolveDNS(host, client->ip, sizeof(client->ip))) return nullptr;  // Return nullptr if DNS resolution fails

    XboxTLSContext* ctx = &client->ctx;
    if (!XboxTLS_CreateContext(ctx, host)) return nullptr;  // Return nullptr if TLS context creation fails
    ctx->hashAlgo = XboxTLS_Hash_SHA256;

    XboxTLS_AddTrustAnchor_EC(ctx, EC_DN, sizeof(EC_DN), EC_Q, sizeof(EC_Q), XboxTLS_Curve_secp384r1);
    XboxTLS_AddTrustAnchor_RSA(ctx, RSA_DN, sizeof(RSA_DN), RSA_N, sizeof(RSA_N), RSA_E, sizeof(RSA_E));

    bool connected = false;
    while (!connected) {
        if (XboxTLS_Connect(ctx, client->ip, host, 443)) { connected = true; break; }
        wchar_t msg[64];
        swprintf_s(msg, 64, L"Connect attempt failed, retrying.");
        Notify(msg);
    }

    char jsonBody[512];
    sprintf(jsonBody, "{\"urls\":[\"%s\"]}", assetUrl);

    char request[1024];
    sprintf(request,
        "POST %s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "Authorization: %s\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: %d\r\n"
        "Connection: close\r\n"
        "\r\n"
        "%s",
        path, host, token, (int)strlen(jsonBody), jsonBody
    );

    XboxTLS_Write(ctx, request, (int)strlen(request));

    std::string responseStr;
    char buffer[512];
    int r = 0;
    while ((r = XboxTLS_Read(ctx, buffer, sizeof(buffer) - 1)) > 0) {
        buffer[r] = '\0';
        responseStr.append(buffer, r);
    }

    XboxTLS_Free(ctx);

    size_t header_end = responseStr.find("\r\n\r\n");
    if (header_end == std::string::npos) return nullptr;  // Return nullptr if no response body found

    std::string body = responseStr.substr(header_end + 4);
    if (responseStr.find("Transfer-Encoding: chunked") != std::string::npos)
        body = DecodeChunkedBody(body);

    rapidjson::Document doc;
    doc.Parse(body.c_str());
    if (doc.HasParseError()) return nullptr;  // Return nullptr if JSON parsing fails

    if (doc.IsArray() && doc.Size() > 0) {
        const rapidjson::Value& obj = doc[0];
        if (obj.IsObject() && obj.HasMember("external_asset_path") && obj["external_asset_path"].IsString()) {
            // Allocate memory for the result
            const char* assetPath = obj["external_asset_path"].GetString();
            size_t len = strlen(assetPath) + 1;  // +1 for the null terminator

            // Dynamically allocate memory for the result
            char* result = new char[len+3];
			strcpy(result, "mp:");
            strncpy(result+3, assetPath, len);  // Copy the string to the allocated memory

            return result;
        }
    }

    g_ClientCount++;
    return nullptr;  // Return nullptr if no valid asset path found
}

bool ReadJsonFile(const char* filePath, Document& doc) {
    FILE* file = fopen(filePath, "rb");
    if (!file) {
        Notify(L"Failed to open JSON file.");
        return false;
    }

    fseek(file, 0, SEEK_END);
    long fileSize = ftell(file);
    fseek(file, 0, SEEK_SET);

    if (fileSize <= 0) {
        fclose(file);
        Notify(L"Empty JSON file.");
        return false;
    }

    char* buffer = (char*)malloc(fileSize + 1);
    if (!buffer) {
        fclose(file);
        Notify(L"Failed to allocate memory for JSON.");
        return false;
    }

    fread(buffer, 1, fileSize, file);
    buffer[fileSize] = '\0';
    fclose(file);

    doc.Parse(buffer);
    free(buffer);

    if (doc.HasParseError()) {
        Notify(L"JSON parse error.");
        return false;
    }

    return true;
}

bool GetGameInfo(const Document& doc, const char* titleId, wchar_t* outName, bool* outIcon, size_t outSize) {
    if (!doc.HasMember(titleId) || !doc[titleId].IsObject()) {
		MultiByteToWideChar(CP_UTF8, 0,"Unknown Game", -1, outName, (int)outSize);
		*outIcon = false;
		return true;
	}

    const Value& obj = doc[titleId];
    if (obj.HasMember("n") && obj["n"].IsString()) {
        MultiByteToWideChar(CP_UTF8, 0, obj["n"].GetString(), -1, outName, (int)outSize);
    }
    if (obj.HasMember("i") && obj["i"].IsBool()) {
        *outIcon = obj["i"].GetBool();
		return true;
    }
    return false;
}

bool SendWebSocketText(TLSClient* client, const char* payload) {
    return XboxTLS_SendWebSocketFrame(&client->ctx, payload, (int)strlen(payload));
}

bool SendPresenceUpdate(TLSClient* client,
                        const char* name,
						const char* largeImage,
						const char* smallImage,
						const char* titleType,
						const char* gamertag,
                        uint64_t timestamp)
{
    char presenceJson[1024];
	char smallImageData[512];
    char timestampsData[128];
	
	if (smallImage && smallImage[0] != '\0' && name != nullptr && strcmp(name, "Xbox 360 Dashboard") != 0) {
		sprintf_s(smallImageData, sizeof(smallImageData),
			",\"small_image\":\"%s\",\"small_text\":\"%s Game\"",
			smallImage, titleType
		);
	} else {
		smallImageData[0] = '\0';
	}

    if (g_JustReconnected) {
        sprintf_s(timestampsData, sizeof(timestampsData),
            ",\"timestamps\":{\"start\":\"%llu\"}",
            (unsigned long long)timestamp
        );
        g_JustReconnected = false; // Reset after use
    } else {
        timestampsData[0] = '\0';
    }

	sprintf_s(presenceJson, sizeof(presenceJson), 
		"{\"op\":3,\"d\":{\"since\":0,\"activities\":[{\"name\":\"%s\",\"type\":0,\"state\":\"%s\",\"details\":\"Xbox 360\",\"platform\":\"xbox\"%s,\"assets\":{\"large_image\":\"%s\",\"large_text\":\"XeCord\"%s}}],\"status\":\"online\",\"afk\":false}}", 
		name, gamertag, timestampsData, largeImage, smallImageData
	);

    return SendWebSocketText(client, presenceJson);
}

DWORD WINAPI MonitorTitleId(LPVOID param) {
    TLSClient* client = (TLSClient*)param;
    uint32_t currentTitleId = 99999999;

    while (client->running) {
        uint32_t newTitleId = XamGetCurrentTitleId();
        if (newTitleId != currentTitleId) {
            currentTitleId = newTitleId;
			
			if (newTitleId != g_LastTitleId) {
				g_LastTitleId = newTitleId;
				g_GameStartTimestamp = GetEpochMilliseconds();  // only reset when switching games
			}

            char titleId[16];
			sprintf(titleId, "%08X", newTitleId);

            if (client) {
				if (strcmp(titleId, "00000000") == 0) {
					strcpy(titleId, g_DashList[g_Dash]);
				};
				char* largeAssetPath;
				char* smallAssetPath;
				char* titleType;
				bool xbOriginal;
				if (strcmp(titleId, "FFFE07D2") == 0) {
					//client->running = FALSE;
					//XboxTLS_Free(&client->ctx);
					//ExCreateThread(nullptr, 0, nullptr, nullptr, ReconnectThread, client, 2);
					xbOriginal = true;
					titleType = "Xbox Original"; 
					DWORD xbeTitleId = GetOriginalXboxTitleID("game:\\default.xbe");
					if (titleId) { sprintf(titleId, "%08X", xbeTitleId); } else { sprintf(titleId, "%08X", "FFFE07D2"); }
				} else {
					xbOriginal = false;
					titleType = "Xbox 360"; 
				};
				char gameName[512];
				wchar_t gameName_t[512];
				bool gameIcon = false;
				Document gameTitles;
				/*wchar_t titlemsg[256];
				MultiByteToWideChar(CP_UTF8, 0, titleId, -1, titlemsg, 256);
				Notify(titlemsg);*/
				if (ReadJsonFile("hdd:\\Plugins\\PluginData\\XeCord\\gameTitles.json", gameTitles)) {
					GetGameInfo(gameTitles, titleId, gameName_t, &gameIcon, 512);
				}

				char* defaultPath = (char*)(xbOriginal 
					? "mp:app-assets/1380960102609064008/1385426559661248553.png" 
					: "mp:app-assets/1380960102609064008/1385422462862229565.png");

				if (gameIcon) {
					largeAssetPath = GetGameIcon(g_Token, titleId);
					smallAssetPath = defaultPath;
				} else {
					largeAssetPath = defaultPath;
					smallAssetPath = (char*)"";
				}

				WideCharToMultiByte(CP_UTF8, 0, gameName_t, -1, gameName, sizeof(gameName), NULL, NULL);
				SendPresenceUpdate(client, gameName, largeAssetPath, smallAssetPath, titleType, GetGamertag(), g_GameStartTimestamp);
            }
        }
        Sleep(500);
    }
    return 0;
}

/*void SendResume(TLSClient* client) {
	if (sessionId[0] == '\0') {
		return;
	}
    char payload[1024];
    sprintf_s(payload, sizeof(payload),
        "{\"op\":6,\"d\":{"
        "\"token\":\"%s\","
        "\"session_id\":\"%s\","
        "\"seq\":%d"
        "}}",
        token, sessionId, seq
    );

    XboxTLS_SendWebSocketFrame(&client->ctx, payload, strlen(payload));
}*/

void HandleReady(TLSClient* client) {
    // Example: show a notification per client
    wchar_t msg[64];
    swprintf_s(msg, 64, L"Client[%d] READY", g_ClientCount);
    //Notify(msg);

	ExCreateThread(nullptr, 0, nullptr, nullptr, MonitorTitleId, client, 2);

    // Here you could launch additional threads or send presence updates, etc.
}

DWORD WINAPI HeartbeatThread(LPVOID param) {
    TLSClient* client = (TLSClient*)param;
    XboxTLSContext* ctx = &client->ctx;

    while (client->running) {
        const char* heartbeat = "{\"op\":1,\"d\":null}";
        XboxTLS_SendWebSocketFrame(ctx, heartbeat, strlen(heartbeat));
		Sleep(client->heartbeatInterval); // Every 30 seconds
    }
    return 0;
}

DWORD WINAPI RecvThread(LPVOID param) {
    TLSClient* client = (TLSClient*)param;
    XboxTLSContext* ctx = &client->ctx;

    while (client->running) {
        size_t len;
        bool isZlib;
        char* frame = XboxTLS_ReceiveWebSocketFrame(ctx, &len, &isZlib);

        if (isZlib) {
            HandleReady(client);
        }

        if (!frame) continue;
		client->lastActivityTick = GetTickCount();
        if (isZlib) { free(frame); continue; }

		if (frame) {
			std::string json(frame, len);
			int wlen = MultiByteToWideChar(CP_UTF8, 0, json.c_str(), -1, NULL, 0);
			if (wlen > 0) {
				std::wstring wideStr(wlen, L'\0');
				MultiByteToWideChar(CP_UTF8, 0, json.c_str(), -1, &wideStr[0], wlen);
			}

			Document doc;
			if (doc.Parse(json.c_str()).HasParseError()) {
				free(frame);
				continue;
			}

			int op = -1;
			if (doc.HasMember("op")) {
				const rapidjson::Value& opVal = doc["op"];
				if (opVal.IsInt()) {
					op = opVal.GetInt();
				}
			} else {
				free(frame);
				continue;
			}

			if (op == 10) {
				int hbi = -1;
				if (doc.HasMember("d") && doc["d"].IsObject()) {
					const Value& d = doc["d"];
					if (d.HasMember("heartbeat_interval") && d["heartbeat_interval"].IsInt()) {
						hbi = d["heartbeat_interval"].GetInt();
						if (hbi > 0) {
							client->heartbeatInterval = hbi;
							ExCreateThread(&client->heartbeatThread, 0, nullptr, nullptr, HeartbeatThread, client, 2);
						}
					}
				}
			} else if (op == 11) {
				client->lastActivityTick = GetTickCount();
			}
			
			/*switch (op) {
				case 0: {
					// READY, PRESENCE_UPDATE, etc.
					if (doc.HasMember("t") && doc["t"].IsString()) {
						if (doc.HasMember("s") && doc["s"].IsInt()) {
							seq = doc["s"].GetInt();
							wchar_t wbuf[512];
							swprintf_s(wbuf, 512, L"seq: %d", seq);
							//Notify(wbuf);
						}
						if (doc.HasMember("d") && doc["d"].IsObject()) {
							const Value& d = doc["d"];
							/*static int readyCount = 0;
							readyCount++;
							if (d.HasMember("session_id") && d["session_id"].IsString()) {
								const char* session_id_valid = d["session_id"].GetString();
								if (session_id_valid) {
									strcpy_s(sessionId, sizeof(sessionId), session_id_valid);
									sessionId[sizeof(sessionId) - 1] = '\0';
								} else {
								}
							}
							if (d.HasMember("resume_gateway_url") && d["resume_gateway_url"].IsString()) {
								Notify(L"KAKAW");
								const char* url = d["resume_gateway_url"].GetString();
								if (url) {
									wchar_t wbu2f[512];
									swprintf_s(wbu2f, 512, L"url: %s", url);
									Notify(wbu2f);
									strcpy_s(resumeGatewayURL, sizeof(resumeGatewayURL), url);
									resumeGatewayURL[sizeof(resumeGatewayURL) - 1] = '\0';
								} else {
								}
							}
						}
					}
					break;
				}
				case 1: {
					//LOG("1");
					char heartbeat[512];
					if (seq != -1) {
						sprintf_s(heartbeat, sizeof(heartbeat), "{\"op\":1,\"d\":%d}", seq);
					} else {
						sprintf_s(heartbeat, sizeof(heartbeat), "{\"op\":1,\"d\":null}");
					}
					XboxTLS_SendWebSocketFrame(ctx, heartbeat, strlen(heartbeat));
					break;
				}
				case 10: {
					//LOG("10");
					int hbi = -1;
					if (doc.HasMember("d") && doc["d"].IsObject()) {
						const Value& d = doc["d"];
						if (d.HasMember("heartbeat_interval") && d["heartbeat_interval"].IsInt()) {
							hbi = d["heartbeat_interval"].GetInt();
							if (hbi > 0) {
								client->heartbeatInterval = hbi;
								ExCreateThread(&client->heartbeatThread, 0, nullptr, nullptr, HeartbeatThread, client, 2);
							}
						}
					}
					break;
				}
				case 11: {
					// HEARTBEAT_ACK
					client->lastActivityTick = GetTickCount();
					break;
				}
			}*/
		}
        free(frame);
    }
    return 0;
}

bool SendIdentify(TLSClient* client, const char* token) {
    char identifyJson[2048];
    // Build your identify JSON; fill in your token and any properties you need.
    sprintf_s(identifyJson, sizeof(identifyJson), 
		"{\"op\":2,\"d\":{\"token\":\"%s\",\"capabilities\":1021,\"client_state\":{\"guild_hashes\":{},\"highest_last_message_id\":\"0\",\"private_channels_version\":\"0\",\"read_state_version\":0,\"user_guild_settings_version\":-1,\"user_settings_version\":-1},\"compress\":false,\"presence\":{\"activities\":[],\"afk\":false,\"since\":0,\"status\":\"online\"},\"properties\":{\"browser\":\"Discord Client\",\"client_build_number\":152131,\"client_event_source\":null,\"client_version\":\"0.0.20\",\"os\":\"Linux\",\"os_arch\":\"x64\",\"os_version\":\"5.19.13-arch1-1\",\"release_channel\":\"stable\",\"system_locale\":\"en-GB\"}}}", 
		token
	);

    return SendWebSocketText(client, identifyJson);
}

void ResetTLSClient(TLSClient* client) {
    if (!client) return;

    client->running = FALSE;

    if (client->recvThread) {
        WaitForSingleObject(client->recvThread, INFINITE);
        CloseHandle(client->recvThread);
        client->recvThread = NULL;
    }

    if (client->heartbeatThread) {
        WaitForSingleObject(client->heartbeatThread, INFINITE);
        CloseHandle(client->heartbeatThread);
        client->heartbeatThread = NULL;
    }

    XboxTLS_Free(&client->ctx);
    memset(client, 0, sizeof(TLSClient));
}

bool StartTLSClient(const char* host, const char* path, int slot = g_ClientCount) {
	if (slot < 0 || slot >= MAX_CLIENTS) return false;

	ResetTLSClient(&g_Clients[slot]);  // already does memset and free
	TLSClient* client = &g_Clients[slot];  // get fresh pointer AFTER reset
	client->running = TRUE;
	client->recvThread = NULL;
	client->heartbeatThread = NULL;
    client->running = TRUE;

    strncpy(client->host, host, sizeof(client->host) - 1);
    strncpy(client->path, path, sizeof(client->path) - 1);

	if (!host || strlen(host) == 0) {
        Notify(L"host is null or empty!");
        return false;
    }

    if (!ResolveDNS(host, client->ip, sizeof(client->ip))) {
        Notify(L"DNS failed");
        return false;
    }

	Sleep(6000);

    XboxTLSContext* ctx = &client->ctx;

    if (!XboxTLS_CreateContext(ctx, host)) return false;
    XboxTLS_SetLogCallback(ctx, XboxTLSLogger);
    ctx->hashAlgo = XboxTLS_Hash_SHA384;

    XboxTLS_AddTrustAnchor_EC(ctx, EC_DN, sizeof(EC_DN), EC_Q, sizeof(EC_Q), XboxTLS_Curve_secp384r1);
    XboxTLS_AddTrustAnchor_RSA(ctx, RSA_DN, sizeof(RSA_DN), RSA_N, sizeof(RSA_N), RSA_E, sizeof(RSA_E));

	if (!ctx) {
		Notify(L"CTX is null before connect");
		return false;
	}
	if (strlen(client->ip) == 0) {
		Notify(L"client->ip is empty before connect");
		return false;
	}
	if (!host || strlen(host) == 0) {
		Notify(L"host is null/empty before connect");
		return false;
	}

    bool connected = false;
	while (!connected) {
		if (XboxTLS_Connect(ctx, client->ip, host, 443)) { connected = true; break; }
        wchar_t msg[64];
		swprintf_s(msg, 64, L"Connect attempt failed, retrying.");
		Notify(msg);
	}

    if (!XboxTLS_WebSocketUpgrade(ctx, host, path, "https://discord.com")) {
        Notify(L"WS upgrade failed");
        XboxTLS_Free(ctx);
        return false;
    }

	client->lastActivityTick = GetTickCount();

	SendIdentify(client, g_Token);
    /*if (sessionId[0] != '\0' && seq >= 0 && strlen(sessionId) < sizeof(sessionId)) {
		Notify(L"RE");
        SendResume(client);
    } else {
        SendIdentify(client, token);
    }*/

    ExCreateThread(&client->recvThread, 0, nullptr, nullptr, RecvThread, client, 2);
    
    if (slot >= g_ClientCount) g_ClientCount = slot + 1;
    return true;
}

void ShutdownAllClients() {
    for (int i = 0; i < MAX_CLIENTS; ++i)
        ResetTLSClient(&g_Clients[i]);

    g_ClientCount = 0;
    /*seq = -1;
    sessionId[0] = '\0';
    resumeGatewayURL[0] = '\0';*/
}

bool TLSClient_IsDead(TLSClient* client) {
    if (!client) return true;
    if (!client->running) return true;
    if (XboxTLS_HasFatalError(&client->ctx)) return true;
    if (XboxTLS_SocketDead(&client->ctx)) return true;
	DWORD now = GetTickCount();
	if (now - client->lastActivityTick > 60000) return true;
    return false;
}


DWORD WINAPI AutoReconnectWatcher(LPVOID lpParam) {
    for (;;) {
        Sleep(1000);

        TLSClient* client = &g_Clients[0];

        if (TLSClient_IsDead(client) && !client->reconnecting) {
			client->reconnecting = true;
            ResetTLSClient(client); // kill threads, free context, zero struct
            client->running = FALSE;

            const char* host = "gateway.discord.gg";
            const char* path = "/?v=9&encoding=json";
            /*const char* host = defaultHost;
            const char* path = defaultPath;

            if (resumeGatewayURL[0] != '\0') {
                const char* scheme = strstr(resumeGatewayURL, "wss://");
                const char* pathStart = strchr(resumeGatewayURL + 6, '/');

                if (scheme && pathStart) {
                    size_t hostLen = pathStart - (resumeGatewayURL + 6);
                    if (hostLen > 0 && hostLen < sizeof(client->host)) {
                        strncpy(client->host, resumeGatewayURL + 6, hostLen);
                        client->host[hostLen] = '\0';
                        strncpy(client->path, pathStart, sizeof(client->path) - 1);
                        client->path[sizeof(client->path) - 1] = '\0';

                        host = client->host;
                        path = client->path;
                    }
                }
            }*/

            XNetStartupParams xnsp = { sizeof(xnsp), XNET_STARTUP_BYPASS_SECURITY };
            XNetStartup(&xnsp);

            WSADATA wsa;
            WSAStartup(MAKEWORD(2, 2), &wsa);

            Sleep(5000);

			g_JustReconnected = true;
            StartTLSClient(host, path, 0);
			client->reconnecting = false;
        }
    }
}

DWORD WINAPI EntryPointThread(LPVOID) {
	Sleep(5000);

    XNetStartupParams xnsp = { sizeof(xnsp), XNET_STARTUP_BYPASS_SECURITY };
    DWORD result = XNetStartup(&xnsp);
    
    while (result != 0) {
        Sleep(1000);
        result = XNetStartup(&xnsp);
    }

	char tokenBuf[128] = {0};
    if (!readIniValue("Discord", "Token", tokenBuf, sizeof(tokenBuf))) {
        Notify(L"Missing [Discord] Token entry");
        return 1;
    }

	if (tokenBuf[0] == '\0') {
        Notify(L"[Discord] Token is empty in config.ini");
        return 1;
    }

	strncpy(g_Token, tokenBuf, sizeof(g_Token) - 1);

	char DashVal[8] = {0};

	if (!readIniValue("General", "DefaultDash", DashVal, sizeof(DashVal))) {
		Notify(L"Missing [General] DefaultDash entry");
		return 1;
	}

	if (DashVal[0] == '\0') {
		Notify(L"[DefaultDash] Token is empty in config.ini");
		return 1;
	}

	g_Dash = atoi(DashVal);

    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);

    Sleep(5000);

    StartTLSClient("gateway.discord.gg", "/?v=9&encoding=json");
	ExCreateThread(nullptr, 0, nullptr, nullptr, AutoReconnectWatcher, nullptr, 2);

    return 0;
}

/*DWORD WINAPI PostEntryThread(LPVOID) {
    XNetStartupParams xnsp = { sizeof(xnsp), XNET_STARTUP_BYPASS_SECURITY };
    XNetStartup(&xnsp);

    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);

    Sleep(3000);

    StartPostClient("");
    return 0;
}*/

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        //DisableThreadLibraryCalls(hModule)
		//ExCreateThread(nullptr, 0, nullptr, nullptr, GetGameTitlesThread, nullptr, 2);
		//ExCreateThread(nullptr, 0, nullptr, nullptr, PostEntryThread, nullptr, 2);
        ExCreateThread(nullptr, 0, nullptr, nullptr, EntryPointThread, nullptr, 2);
	} else if (reason == DLL_PROCESS_DETACH) {
        ShutdownAllClients();
    }
    return TRUE;
}