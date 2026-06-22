#include "GameDB.h"
#include "INIReader.h"
#include "XexUtils.h"

#include "GTA5/Hooks.h"
#include "GTA5/SessionInfo.h"

#include <cstdint>
#include <fstream>
#include <sstream>
#include <string>
#include <xtl.h>

#define CONSOLE_TYPE_XENON 0x00000000
#define CONSOLE_TYPE_ZEPHYR 0x10000000
#define CONSOLE_TYPE_FALCON 0x20000000
#define CONSOLE_TYPE_JASPER 0x30000000
#define CONSOLE_TYPE_TRINITY 0x40000000
#define CONSOLE_TYPE_CORONA 0x50000000
#define CONSOLE_TYPE_WINCHESTER 0x60000000

#define CONSOLE_TYPE_FLAGS_MASK (0xF0000000)
#define CONSOLE_TYPE_FROM_FLAGS                                                \
	(XboxHardwareInfo->Flags & CONSOLE_TYPE_FLAGS_MASK)
// #define IS_CONSOLE_TYPE_SLIM		(CONSOLE_TYPE_FROM_FLAGS >
// CONSOLE_TYPE_JASPER)

#define UNIX_TIME_START 0x019DB1DED53E8000ULL
#define TICKS_PER_MILLISECOND 10000ULL

// THANKS BYROM

// internal hard disk
#define MOUNT_HDD "Hdd:"
#define DEVICE_HARDISK0_PART1 "\\Device\\Harddisk0\\Partition1"
// usb memory stick
#define MOUNT_USB "Usb:"
#define MOUNT_USB0 "Usb0:"
#define DEVICE_USB0 "\\Device\\Mass0"
#define MOUNT_USB1 "Usb1:"
#define DEVICE_USB1 "\\Device\\Mass1"
#define MOUNT_USB2 "Usb2:"
#define DEVICE_USB2 "\\Device\\Mass2"
// internal slim trinity mu
#define MOUNT_INTMU "IntMu:"
#define DEVICE_INTMEM "\\Device\\BuiltInMuUsb\\Storage"
// CD / DVD
#define MOUNT_DVD "Dvd:"
#define DEVICE_CDROM0 "\\Device\\Cdrom0"
// Nand Flash
#define MOUNT_FLASH "Flash:"
#define DEVICE_NAND_FLASH "\\Device\\Flash"
// DEVKIT folder on Hdd
#define MOUNT_DEVKIT "DEVKIT:"
#define DEVICE_DEVKIT "\\Device\\Harddisk0\\Partition1\\DEVKIT"
// Games folder on Hdd
#define MOUNT_HDDGAMES "HddGames:"
#define DEVICE_HDDGAMES "\\Device\\Harddisk0\\Partition1\\Games"
// Apps folder on Hdd
#define MOUNT_HDDAPPS "HddApps:"
#define DEVICE_HDDAPPS "\\Device\\Harddisk0\\Partition1\\Apps"
// Network share using connectx
#define DEVICE_NETSHARE "Netshare:"
#define DEVICE_SMB "\\Network\\Smb"
// internal corona 4g mu
#define MOUNT_MMCMU "MmcMu:"
#define DEVICE_MMCMU "\\Device\\BuiltInMuMmc\\Storage"
// big block NAND mu
#define MOUNT_FLASHMU "FlashMu:"
#define DEVICE_FLASHMU "\\Device\\BuiltInMuSfc"
// memory unit
#define MOUNT_MU "Mu:"
#define DEVICE_MEMORY_UNIT0 "\\Device\\Mu0"
#define MOUNT_MU1 "Mu1:"
#define DEVICE_MEMORY_UNIT1 "\\Device\\Mu1"
// USB memory unit
#define MOUNT_USBMU0 "UsbMu0:"
#define DEVICE_USBMU0 "\\Device\\Mass0PartitionFile\\Storage"
#define MOUNT_USBMU1 "UsbMu1:"
#define DEVICE_USBMU1 "\\Device\\Mass1PartitionFile\\Storage"
#define MOUNT_USBMU2 "UsbMu2:"
#define DEVICE_USBMU2 "\\Device\\Mass2PartitionFile\\Storage"

char iniPath[MAX_PATH];
char dbPath[MAX_PATH];
char pluginPath[MAX_PATH];

static const char *g_LastDevicePrefix = NULL;
static const char *g_LastMountPoint = NULL;
std::string g_Token = "DISCORD_TOKEN";



DWORD g_BootDelay = 20000;
bool g_ShowNotifications = true;
bool g_NowPlayingNotifications = false;

char g_PlayingOn[64] = "xbox";
char g_Status[64] = "online";
bool g_ShowSmallImage = true;
bool g_ShowSmallImageOnCustomDash = false;
bool g_SwapImages = false;
bool g_ShowGameIcon = true;
bool g_AlwaysShowOGXboxIcon = true;
bool g_FallbackTo360SmallForXbox1 = false;
bool g_ShowConsole = true;
std::string g_ConsoleName = "Xbox 360";
bool g_ShowConsoleType = true;
bool g_ShowKernelVersion = true;
bool g_ShowBuildNumberOnly = false;
long g_CustomVersionNumber = 0;
bool g_ShowProfile = true;
bool g_ResetTimePerGame = true;
bool g_UseFallbackDash = true;
int g_FallbackDash = 1;

bool discordFirstConnect = true;
bool wasGameShown = false;

#define TITLE_GTA5 0x545408A7

const uint32_t g_DashList[] = {
    0xFFFE07D1, // Xbox 360 Dash
    0x00000166, // Aurora
    0x00000167, // Freestyle
};

const std::string g_ValidPlatforms[] = {"xbox", "ps4", "ps5"};

const size_t g_ValidPlatformCount =
    sizeof(g_ValidPlatforms) / sizeof(g_ValidPlatforms[0]);

const std::string g_ValidStatuses[] = {"online", "idle", "dnd", "invisible"};

const size_t g_ValidStatusCount =
    sizeof(g_ValidStatuses) / sizeof(g_ValidStatuses[0]);

volatile uint64_t g_EpochMillisecondsStart = 0;

typedef struct {
	const char *mount;
	const char *device;
} MountMapping;

static const MountMapping g_DriveMappings[] = {
    {MOUNT_DEVKIT, DEVICE_DEVKIT},      {MOUNT_HDDGAMES, DEVICE_HDDGAMES},
    {MOUNT_HDDAPPS, DEVICE_HDDAPPS},    {MOUNT_USBMU0, DEVICE_USBMU0},
    {MOUNT_USBMU1, DEVICE_USBMU1},      {MOUNT_USBMU2, DEVICE_USBMU2},
    {MOUNT_HDD, DEVICE_HARDISK0_PART1}, {MOUNT_USB0, DEVICE_USB0},
    {MOUNT_USB1, DEVICE_USB1},          {MOUNT_USB2, DEVICE_USB2},
    {MOUNT_INTMU, DEVICE_INTMEM},       {MOUNT_DVD, DEVICE_CDROM0},
    {MOUNT_FLASH, DEVICE_NAND_FLASH},   {MOUNT_MMCMU, DEVICE_MMCMU},
    {MOUNT_FLASHMU, DEVICE_FLASHMU},    {MOUNT_MU, DEVICE_MEMORY_UNIT0},
    {MOUNT_MU1, DEVICE_MEMORY_UNIT1},   {NULL, NULL}};

uint8_t EC_DN[] = {0x30, 0x47, 0x31, 0x0B, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04,
                   0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x22, 0x30, 0x20, 0x06,
                   0x03, 0x55, 0x04, 0x0A, 0x13, 0x19, 0x47, 0x6F, 0x6F, 0x67,
                   0x6C, 0x65, 0x20, 0x54, 0x72, 0x75, 0x73, 0x74, 0x20, 0x53,
                   0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x73, 0x20, 0x4C, 0x4C,
                   0x43, 0x31, 0x14, 0x30, 0x12, 0x06, 0x03, 0x55, 0x04, 0x03,
                   0x13, 0x0B, 0x47, 0x54, 0x53, 0x20, 0x52, 0x6F, 0x6F, 0x74,
                   0x20, 0x52, 0x34};

uint8_t EC_Q[] = {0x04, 0xF3, 0x74, 0x73, 0xA7, 0x68, 0x8B, 0x60, 0xAE, 0x43,
                  0xB8, 0x35, 0xC5, 0x81, 0x30, 0x7B, 0x4B, 0x49, 0x9D, 0xFB,
                  0xC1, 0x61, 0xCE, 0xE6, 0xDE, 0x46, 0xBD, 0x6B, 0xD5, 0x61,
                  0x18, 0x35, 0xAE, 0x40, 0xDD, 0x73, 0xF7, 0x89, 0x91, 0x30,
                  0x5A, 0xEB, 0x3C, 0xEE, 0x85, 0x7C, 0xA2, 0x40, 0x76, 0x3B,
                  0xA9, 0xC6, 0xB8, 0x47, 0xD8, 0x2A, 0xE7, 0x92, 0x91, 0x6A,
                  0x73, 0xE9, 0xB1, 0x72, 0x39, 0x9F, 0x29, 0x9F, 0xA2, 0x98,
                  0xD3, 0x5F, 0x5E, 0x58, 0x86, 0x65, 0x0F, 0xA1, 0x84, 0x65,
                  0x06, 0xD1, 0xDC, 0x8B, 0xC9, 0xC7, 0x73, 0xC8, 0x8C, 0x6A,
                  0x2F, 0xE5, 0xC4, 0xAB, 0xD1, 0x1D, 0x8A};

struct DiscordState {
	XexUtils::Socket *socket;
	bool isConnected;
	bool isAuthenticated;
	int lastSequence;
	int heartbeatInterval;
	unsigned long lastHeartbeatTime;

	char *recvBuffer;

	DiscordState() {
		recvBuffer = new char[8192];
		isConnected = false;
		isAuthenticated = false;
		lastSequence = -1;
	}

	~DiscordState() {
		if (recvBuffer)
			delete[] recvBuffer;
		if (socket) {
			socket->Disconnect();
			delete socket;
		}
	}
};

bool WSSend(XexUtils::Socket *socket, const char *jsonPayload);
bool PerformHandshake(DiscordState *state);
void SendIdentify(DiscordState *state);
bool SendHeartbeat(DiscordState *state);
void ProcessPacket(DiscordState *state, char *payload, int payloadLen);

bool discordAuth = false;
static uint16_t defaultInstruction = 0;
static uintptr_t patchAddress = 0x816A3158;

const char *GetSafeGamertag() {
	if (XUserGetSigninState(0) != eXUserSigninState_NotSignedIn) {
		static char gamertag[16];
		if (XUserGetName(0, gamertag, 16) == ERROR_SUCCESS)
			return gamertag;
	} else if (XUserGetSigninState(0) == eXUserSigninState_NotSignedIn) {
		return "Signed Out";
	}
	return "Unknown User";
}

static const char *BASE64_CHARS =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

void Base64Encode(const unsigned char *input, int inputLen, char *output) {
	int i = 0, j = 0;
	unsigned char char_array_3[3];
	unsigned char char_array_4[4];

	while (inputLen--) {
		char_array_3[i++] = *(input++);
		if (i == 3) {
			char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
			char_array_4[1] = ((char_array_3[0] & 0x03) << 4) +
			                  ((char_array_3[1] & 0xf0) >> 4);
			char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) +
			                  ((char_array_3[2] & 0xc0) >> 6);
			char_array_4[3] = char_array_3[2] & 0x3f;

			for (i = 0; i < 4; i++)
				output[j++] = BASE64_CHARS[char_array_4[i]];
			i = 0;
		}
	}

	if (i) {
		for (int k = i; k < 3; k++)
			char_array_3[k] = '\0';

		char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
		char_array_4[1] =
		    ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
		char_array_4[2] =
		    ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
		char_array_4[3] = char_array_3[2] & 0x3f;

		for (int k = 0; k < i + 1; k++)
			output[j++] = BASE64_CHARS[char_array_4[k]];
		while (i++ < 3)
			output[j++] = '=';
	}

	output[j] = '\0';
}

std::string GenerateWebSocketKey() {
	unsigned char randomBytes[16];
	XeCryptRandom(randomBytes, 16);

	char encoded[32];
	Base64Encode(randomBytes, 16, encoded);

	return std::string(encoded);
}

bool PerformHandshake(DiscordState *state) {
	std::string wsKey = GenerateWebSocketKey();

	char upgradeRequest[1024];
	sprintf_s(upgradeRequest, 1024,
	          "GET /?v=9&encoding=json HTTP/1.1\r\n"
	          "Host: gateway.discord.gg\r\n"
	          "Connection: Upgrade\r\n"
	          "Upgrade: websocket\r\n"
	          "Sec-WebSocket-Key: %s\r\n"
	          "Sec-WebSocket-Version: 13\r\n"
	          "Sec-WebSocket-Extensions: permessage-deflate; "
	          "client_max_window_bits\r\n"
	          "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
	          "AppleWebKit/537.36 (KHTML, like Gecko) discord/1.0.9216 "
	          "Chrome/138.0.7204.251 Electron/37.6.0 Safari/537.36\r\n"
	          "Accept-Encoding: gzip, deflate, br\r\n"
	          "Accept-Language: en-US,en;q=0.9\r\n"
	          "Origin: https://discord.com\r\n"
	          "\r\n",
	          wsKey.c_str());

	state->socket->Send(upgradeRequest, strlen(upgradeRequest));

	char buffer[1024];
	memset(buffer, 0, 1024);

	int len = state->socket->Receive(buffer, 1023);

	if (len > 0)
		buffer[len] = '\0';

	if (len <= 0 || strstr(buffer, "101 Switching Protocols") == NULL) {
		XexUtils::Log::Print("[XeCord] Error: Discord Handshake Failed.");
		return false;
	}

	XexUtils::Log::Print("[XeCord] Discord WebSocket Upgraded.");
	return true;
}

bool WSSend(XexUtils::Socket *socket, const char *jsonPayload) {
	if (!socket || !jsonPayload)
		return false;

	size_t payloadLen = strlen(jsonPayload);

	size_t headerSize = (payloadLen < 126) ? 6 : 8;
	size_t frameSize = headerSize + payloadLen;

	char *frame = new char[frameSize];

	frame[0] = (char)0x81;

	if (payloadLen > 65500) {
		XexUtils::Log::Print("[XeCord] Error: Payload too large for WSSend!");
		return false;
	} else if (payloadLen < 126) {
		frame[1] = (char)(0x80 | payloadLen);
	} else {
		frame[1] = (char)(0x80 | 126);

		frame[2] = (char)((payloadLen >> 8) & 0xFF);
		frame[3] = (char)(payloadLen & 0xFF);
	}

	char *maskKey = frame + (headerSize - 4);

	for (int i = 0; i < 4; i++)
		maskKey[i] = (char)(rand() % 255);

	char *frameData = frame + headerSize;

	for (size_t i = 0; i < payloadLen; i++) {
		frameData[i] = jsonPayload[i] ^ maskKey[i % 4];
	}

	int bytesSent = socket->Send(frame, frameSize);

	delete[] frame;

	if (bytesSent <= 0) {
		XexUtils::Log::Print("[XeCord] Error: WSSend failed. Connection dead.");
		return false;
	}

	return true;
}

std::string GenerateUUID() {
	unsigned char bytes[16];
	XeCryptRandom(bytes, 16);

	bytes[6] = (bytes[6] & 0x0F) | 0x40;

	bytes[8] = (bytes[8] & 0x3F) | 0x80;

	char buffer[37];
	sprintf_s(
	    buffer, 37,
	    "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
	    bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6],
	    bytes[7], bytes[8], bytes[9], bytes[10], bytes[11], bytes[12],
	    bytes[13], bytes[14], bytes[15]);

	return std::string(buffer);
}

std::string GenerateLaunchSignature() {
	unsigned char bytes[16];
	XeCryptRandom(bytes, 16);

	bytes[6] = (bytes[6] & 0x0F) | 0x40;
	bytes[8] = (bytes[8] & 0x3F) | 0x80;

	const unsigned char modMask[16] = {0x00, 0x80, 0x10, 0x10, 0x08, 0x10,
	                                   0x08, 0x00, 0x20, 0x81, 0x00, 0x40,
	                                   0x01, 0x00, 0x20, 0x00};

	for (int i = 0; i < 16; i++) {
		bytes[i] &= ~modMask[i];
	}

	char buffer[37];
	sprintf_s(
	    buffer, 37,
	    "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
	    bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6],
	    bytes[7], bytes[8], bytes[9], bytes[10], bytes[11], bytes[12],
	    bytes[13], bytes[14], bytes[15]);

	return std::string(buffer);
}

bool EndsWith(const char *str, const char *suffix) {
	if (!str || !suffix)
		return false;

	size_t lenstr = strlen(str);
	size_t lensuff = strlen(suffix);

	if (lensuff > lenstr)
		return false;

	return (strcmp(str + (lenstr - lensuff), suffix) == 0);
}

DWORD GetXbox1TID(const char *path) {
	DWORD titleId = 0;
	DWORD bytesRead = 0;
	HANDLE hFile = INVALID_HANDLE_VALUE;

	for (int i = 0; i < 5; i++) {
		hFile = CreateFile(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

        if (hFile != INVALID_HANDLE_VALUE) {
            break;
        }

        Sleep(500);
    }

	if (hFile == INVALID_HANDLE_VALUE) {
        return 0;
    }

	if (SetFilePointer(hFile, 0x18C, NULL, FILE_BEGIN) != INVALID_SET_FILE_POINTER) {
        ReadFile(hFile, &titleId, sizeof(uint32_t), &bytesRead, NULL);
    }

    CloseHandle(hFile);

    if (bytesRead == sizeof(uint32_t)) {
        return _byteswap_ulong(titleId);
    }

	return 0;
}

bool FetchDiscordAsset(uint32_t titleId, uint32_t secId, char *outAssetId,
                       size_t outSize) {
	bool success = false;

	Sleep(4000);

	if (XamGetCurrentTitleId() != 0xFFFE07D2) {
		if (XamGetCurrentTitleId() != titleId) {
			return false;
		}
	} else {
		if (GetXbox1TID("game:\\default.xbe") != titleId) {
			return false;
		}
	}

	XexUtils::Socket *apiSocket =
	    new XexUtils::Socket("discord.com", 443, true);

	HRESULT hr =
	    apiSocket->AddECTrustAnchor(EC_DN, sizeof(EC_DN), EC_Q, sizeof(EC_Q),
	                                XexUtils::Socket::Curve_secp384r1);

	if (FAILED(hr)) {
		XexUtils::Log::Print("[XeCord] Error: SSL Init Failed.");
		delete apiSocket;
		return false;
	}

	bool connected = false;
	for (int i = 0; i < 10; i++) {
		if (SUCCEEDED(apiSocket->Connect())) {
			connected = true;
			break;
		}
		Sleep(1000);
	}

	if (!connected) {
		XexUtils::Log::Print("[XeCord] Error: Could not connect to API.");
		delete apiSocket;
		return false;
	}

	if (XamGetCurrentTitleId() != 0xFFFE07D2) {
		if (XamGetCurrentTitleId() != titleId) {
			delete apiSocket;
			return false;
		}
	} else {
		if (GetXbox1TID("game:\\default.xbe") != titleId) {
			delete apiSocket;
			return false;
		}
	}

	char *tempBuffer = new char[1024];

	char *iconUrl = tempBuffer;
	if (secId != 0)
		sprintf_s(iconUrl, 256,
		          "https://cdn.jsdelivr.net/gh/uncreativexenon/"
		          "xboxunity-scraper@master/Icons/%08X.png",
		          secId);
	else if (titleId == 0x5841149E)
		sprintf_s(iconUrl, 256,
		          "https://cdn.jsdelivr.net/gh/uncreativexenon/"
		          "xboxunity-scraper@master/Icons/%s.png",
		          "5841149E_1");
	else
		sprintf_s(iconUrl, 256,
		          "https://cdn.jsdelivr.net/gh/uncreativexenon/"
		          "xboxunity-scraper@master/Icons/%08X.png",
		          titleId);

	char *jsonBody = tempBuffer + 256;
	sprintf_s(jsonBody, 512, "{\"urls\":[\"%s\"]}", iconUrl);

	const char *super_props =
	    "eyJvcyI6IldpbmRvd3MiLCJicm93c2VyIjoiRGlzY29yZCBDbGllbnQiLCJyZWxlYXNlX2"
	    "No"
	    "YW5uZWwiOiJzdGFibGUiLCJjbGllbnRfdmVyc2lvbiI6IjEuMC45MjE2Iiwib3NfdmVyc2"
	    "lv"
	    "biI6IjEwLjAuMjYyMDAiLCJvc19hcmNoIjoieDY0IiwiYXBwX2FyY2giOiJ4NjQiLCJzeX"
	    "N0"
	    "ZW1fbG9jYWxlIjoiZW4tVVMiLCJoYXNfY2xpZW50X21vZHMiOmZhbHNlLCJjbGllbnRfYn"
	    "Vp"
	    "bGRfbnVtYmVyIjo0NzQwMjksIm5hdGl2ZV9idWlsZF9udW1iZXIiOjcyMzg1fQ==";

	char *request = new char[2048];
	sprintf_s(request, 2048,
	          "POST /api/v9/applications/1410522131762253927/external-assets "
	          "HTTP/1.1\r\n"
	          "Host: discord.com\r\n"
	          "Accept: */*\r\n"
	          "Accept-Language: en-US,en;q=0.9\r\n"
	          "Authorization: %s\r\n"
	          "Content-Type: application/json\r\n"
	          "Content-Length: %u\r\n"
	          "Priority: u=1, i\r\n"
	          "Sec-Ch-Ua: \"Not)A;Brand\";v=\"8\", \"Chromium\";v=\"138\"\r\n"
	          "Sec-Ch-Ua-Mobile: ?0\r\n"
	          "Sec-Ch-Ua-Platform: \"Windows\"\r\n"
	          "Sec-Fetch-Dest: empty\r\n"
	          "Sec-Fetch-Mode: cors\r\n"
	          "Sec-Fetch-Site: same-origin\r\n"
	          "X-Debug-Options: bugReporterEnabled\r\n"
	          "X-Discord-Locale: en-US\r\n"
	          "X-Discord-Timezone: America/New_York\r\n"
	          "X-Super-Properties: %s\r\n"
	          "Referer: https://discord.com/channels/@me\r\n"
	          "Connection: close\r\n"
	          "\r\n"
	          "%s",
	          g_Token.c_str(), (unsigned int)strlen(jsonBody), super_props,
	          jsonBody);

	if (apiSocket->Send(request, strlen(request)) > 0) {
		char *buffer = new char[8192];
		memset(buffer, 0, 8192);

		int totalBytes = 0;
		while (totalBytes < 8192 - 1) {
			int r =
			    apiSocket->Receive(buffer + totalBytes, 8192 - totalBytes - 1);
			if (r <= 0)
				break;
			totalBytes += r;
		}
		buffer[totalBytes] = '\0';

		char *pathKey = strstr(buffer, "\"external_asset_path\"");

		if (pathKey) {
			char *valStart = pathKey + 23;

			strcpy_s(outAssetId, outSize, "mp:");

			size_t i = 0;
			size_t outIndex = 3;

			while (valStart[i] != '"' && valStart[i] != '\0' &&
			       outIndex < outSize - 1) {
				if (valStart[i] != '\\') {
					outAssetId[outIndex] = valStart[i];
					outIndex++;
				}
				i++;
			}
			outAssetId[outIndex] = '\0';

			// XexUtils::Log::Print("[XeCord] Constructed Asset: %s.",
			// outAssetId);
			success = true;
		} else {
			XexUtils::Log::Print(
			    "[XeCord] Error: 'external_asset_path' not found in response.");
		}

		delete[] buffer;
	}

	delete[] request;
	delete[] tempBuffer;
	apiSocket->Disconnect();
	delete apiSocket;

	return success;
}

const char *GetConsoleType() {
	switch (CONSOLE_TYPE_FROM_FLAGS) {
	case CONSOLE_TYPE_XENON:
		return "Xenon";
	case CONSOLE_TYPE_ZEPHYR:
		return "Zephyr";
	case CONSOLE_TYPE_FALCON:
		return "Falcon";
	case CONSOLE_TYPE_JASPER:
		return "Jasper";
	case CONSOLE_TYPE_TRINITY:
		return "Trinity";
	case CONSOLE_TYPE_CORONA:
		return "Corona";
	case CONSOLE_TYPE_WINCHESTER:
		return "Winchester";
	default:
		return "Unknown";
	}
}

unsigned long long GetEpochMilliseconds() {
	FILETIME ft;
	GetSystemTimeAsFileTime(&ft);

	ULARGE_INTEGER largeInt;
	largeInt.LowPart = ft.dwLowDateTime;
	largeInt.HighPart = ft.dwHighDateTime;

	return (largeInt.QuadPart - UNIX_TIME_START) / TICKS_PER_MILLISECOND;
}

uint64_t GetValidEpoch() {
	const uint64_t MIN_VALID_EPOCH = 1167609600000ULL; // Jan 1, 2007
	uint64_t epoch = 0;

	do {
		epoch = GetEpochMilliseconds();
		if (epoch < MIN_VALID_EPOCH) {
			Sleep(100);
		}
	} while (epoch < MIN_VALID_EPOCH);

	return epoch;
}

bool IsPlatformValid(const std::string &platform) {
	for (size_t i = 0; i < g_ValidPlatformCount; ++i) {
		if (platform == g_ValidPlatforms[i]) {
			return true;
		}
	}
	return false;
}

bool IsStatusValid(const std::string &status) {
	for (size_t i = 0; i < g_ValidStatusCount; ++i) {
		if (status == g_ValidStatuses[i]) {
			return true;
		}
	}
	return false;
}

bool ContainsStringCI(const char* haystack, const char* needle) {
    if (!haystack || !needle) return false;
    if (!*needle) return true;
    
    for (; *haystack; ++haystack) {
        if (tolower(*haystack) == tolower(*needle)) {
            const char* h = haystack;
            const char* n = needle;
            while (*h && *n && tolower(*h) == tolower(*n)) {
                h++; 
                n++;
            }
            if (!*n) return true;
        }
    }
    return false;
}

bool SendPresenceUpdate(DiscordState *state, uint32_t titleId) {
	const char* appId = "1410522131762253927";//discord app ID

	uint32_t finalTitleId = titleId;
	const char *finalGameName = "Unknown Game";
	static char gameNameBuffer[64];//for gta
	bool finalGameIconExists = false;
	const char *finalLargeImage =
	    "mp:app-assets/1410522131762253927/1417550167074406711.png";
	const char *finalSmallImage = "";
	const char *gameIcon = "";
	char dynamicAssetBuffer[256] = {0};

	if (titleId == 0x00000000) {
		if (EndsWith(ExLoadedImageName, "Aurora.xex"))
			finalTitleId = 0x00000166;
		else if (EndsWith(ExLoadedImageName, "dash.xex"))
			finalTitleId = 0xFFFE07D1;
		else if (ContainsStringCI(ExLoadedImageName, "rsdkv5") || 
			    (ContainsStringCI(ExLoadedImageName, "sonic") && ContainsStringCI(ExLoadedImageName, "mania")))
			finalTitleId = 0x4D5307E7;
		else
			if (g_UseFallbackDash) {
				finalTitleId = g_DashList[g_FallbackDash]; 
			}
			else {
				wasGameShown = false;
				return true;
			}
	} else if (titleId == 0xFFFE07D2) {
		finalTitleId = GetXbox1TID("game:\\default.xbe");
		if (finalTitleId == 0x00000000) finalTitleId = 0x01234567;
	}

	for (size_t i = 0; i < g_GameList.size(); i++) {
		const GameEntry &game = g_GameList[i];
		if (game.titleId == finalTitleId) {

			finalGameName = game.name;
			finalGameIconExists = game.iconExists;

			if (g_ShowGameIcon && game.iconExists &&
			    finalTitleId != 0x00000166 && finalTitleId != 0x00000167 &&
			    finalTitleId != 0xFFFE07D1 && finalTitleId != 0x4D5307E7) {
				if (FetchDiscordAsset(finalTitleId, game.secondaryId,
				                      dynamicAssetBuffer, 256)) {
					dynamicAssetBuffer[255] = '\0';

					finalLargeImage = dynamicAssetBuffer;
				} else {
					XexUtils::Log::Print(
					    "[XeCord] Error: Icon Fetch failed, using "
					    "default icon. Requested TID: %08X.",
					    finalTitleId);
					finalGameIconExists = false;
				}
			}

			finalLargeImage = finalGameIconExists ? finalLargeImage
			                  : (titleId == 0xFFFE07D2)
			                      ? "mp:app-assets/1410522131762253927/"
			                        "1410522692959998023.png"
			                      : "mp:app-assets/1410522131762253927/"
			                        "1417550167074406711.png";
			finalSmallImage =
			    (titleId == 0xFFFE07D2)
			        ? (finalGameIconExists
			               ? "mp:app-assets/1410522131762253927/"
			                 "1410522692959998023.png"
			               : (g_FallbackTo360SmallForXbox1
			                      ? "mp:app-assets/1410522131762253927/"
			                        "1410522692968382586.png"
			                      : ""))
			        : (finalGameIconExists
			               ? "mp:app-assets/1410522131762253927/"
			                 "1410522692968382586.png"
			               : "");

			if (finalTitleId == TITLE_GTA5) {
				//TODO: pls add the online icon asset to the offical rich presence and remove the stuff that changes app ID
				appId = "621813072641916968";

				if (GTA5SessionInfo::GetIsOnline()) {
					sprintf_s(gameNameBuffer, sizeof(gameNameBuffer), "GTA 5 - Online (%d/18 Players)", GTA5SessionInfo::GetPlayerCount());
					finalGameName = gameNameBuffer;
					finalLargeImage = "mp:app-assets/621813072641916968/1518660957985964122.png";
					finalSmallImage = "";
				}
				else {
					finalGameName = "GTA 5 - Story Mode";
					finalLargeImage = "mp:app-assets/621813072641916968/1518660898217132234.png";
					finalSmallImage = "";
				}
			}
			break;
		}
	}

	if (finalTitleId == 0x00000166) // Aurora
	{
		finalGameName = "Aurora";
		finalLargeImage =
		    "mp:app-assets/1410522131762253927/1410523603815895132.png";
		finalSmallImage =
		    g_ShowSmallImageOnCustomDash
		        ? "mp:app-assets/1410522131762253927/1410522692968382586.png"
		        : "";
	} else if (finalTitleId == 0x00000167) // Freestyle 3
	{
		finalGameName = "Freestyle 3";
		finalLargeImage =
		    "mp:app-assets/1410522131762253927/1410522692414738493.png";
		finalSmallImage =
		    g_ShowSmallImageOnCustomDash
		        ? "mp:app-assets/1410522131762253927/1410522692968382586.png"
		        : "";
	} else if (finalTitleId == 0xFFFE07D1) // Xbox 360 Dashboard
	{
		finalGameName = "Xbox 360 Dashboard";
		finalLargeImage =
		    "mp:app-assets/1410522131762253927/1417550167074406711.png";
		finalSmallImage = "";
	} else if (finalTitleId == 0x4D5307E7) // Sonic Mania (RSDKv5)
	{
		finalGameName = "Sonic Mania (RSDKv5)";
		finalLargeImage =
		    "mp:app-assets/1410522131762253927/1477624510306844829.png";
		finalSmallImage = "";
	}

	if (!g_ShowGameIcon) {
		finalLargeImage =
		    (titleId == 0xFFFE07D2)
		        ? (g_AlwaysShowOGXboxIcon ? "mp:app-assets/1410522131762253927/"
		                                    "1410522692959998023.png"
		                                  : "mp:app-assets/1410522131762253927/"
		                                    "1417550167074406711.png")
		        : "mp:app-assets/1410522131762253927/1417550167074406711.png";
		finalSmallImage = (titleId == 0xFFFE07D2)
		                      ? (g_FallbackTo360SmallForXbox1
		                             ? "mp:app-assets/1410522131762253927/"
		                               "1410522692968382586.png"
		                             : "")
		                      : "";
	}

	const int BUF_SIZE = 4096;
	char *json = new char[BUF_SIZE];

	std::stringstream profileinfos;

	if (g_ShowProfile) {
		profileinfos << "\"state\":\"Profile: " << GetSafeGamertag() << "\",";
	}

	std::string profileinfo = profileinfos.str();

	std::stringstream addinfos;

	if (g_ShowConsole) {
		addinfos << "\"details\":\"" << g_ConsoleName;

		if (g_ShowConsoleType) {
			addinfos << " " << "(" << GetConsoleType() << ")";
		}

		if (g_ShowKernelVersion) {
			if (g_ShowBuildNumberOnly) {
				addinfos << " " << "["
				         << ((g_CustomVersionNumber == 0)
				                 ? XboxKrnlVersion->Build
				                 : g_CustomVersionNumber)
				         << "]";
			} else {
				addinfos << " " << "[2.0."
				         << ((g_CustomVersionNumber == 0)
				                 ? XboxKrnlVersion->Build
				                 : g_CustomVersionNumber)
				         << ".0]";
			}
		}

		addinfos << "\",";
	}

	std::string addinfo = addinfos.str();

	std::stringstream playingons;

	if (IsPlatformValid(g_PlayingOn)) {
		playingons << "\"platform\":\"" << g_PlayingOn << "\",";
	} else {
		playingons << "\"platform\":\"desktop\",";
	}

	std::string playingon = playingons.str();

	std::stringstream smallimagedatas;

	if (g_ShowSmallImage && strlen(finalSmallImage) > 0) {
		if (g_SwapImages) {
			finalSmallImage = finalLargeImage;
			finalLargeImage = (titleId == 0xFFFE07D2)
			                      ? "mp:app-assets/1410522131762253927/"
			                        "1410522692959998023.png"
			                      : "mp:app-assets/1410522131762253927/"
			                        "1417550167074406711.png";
		}
		smallimagedatas << "\"small_image\":\"" << finalSmallImage << "\",";
	}

	std::string smallimagedata = smallimagedatas.str();

	std::stringstream epochmillisecondss;

	if (g_EpochMillisecondsStart > 0)
		epochmillisecondss << "\"timestamps\":{\"start\":"
		                   << g_EpochMillisecondsStart << "},";

	std::string epochmilliseconds = epochmillisecondss.str();

	XexUtils::Log::Print(
	    "[XeCord] Game Changed! Updating Presence to: %s (%08X).",
	    finalGameName, finalTitleId);

	sprintf_s(json, BUF_SIZE,
	          "{\"op\":3,\"d\":{"
	          "\"since\":0,"
	          "\"activities\":[{"
	          "\"application_id\":\"%s\","
	          "\"name\":\"%s\","
	          "\"type\":0,"
	          "\"metadata\":{},"
	          "%s"
	          "%s"
	          "%s"
	          "%s"
	          "\"assets\":{"
	          "\"large_image\":\"%s\","
	          "\"large_text\":\"XeCord\","
	          "%s"
	          "\"small_text\":\"%s Game\""
	          "}"
	          "}],"
	          "\"status\":\"%s\","
	          "\"afk\":false"
	          "}}",
		      appId, finalGameName, profileinfo.c_str(), addinfo.c_str(),
	          playingon.c_str(), epochmilliseconds.c_str(), finalLargeImage,
	          smallimagedata.c_str(),
	          (titleId == 0xFFFE07D2) ? "Xbox Original" : "Xbox 360",
	          IsStatusValid(g_Status) ? g_Status : "online");

	if (g_ShowNotifications && g_NowPlayingNotifications && !wasGameShown) {
		std::stringstream nowshowingtexts;
		nowshowingtexts << "XeCord - Now Showing: " << finalGameName;
		std::string nowshowingtext = nowshowingtexts.str();
		wasGameShown = true;
		XexUtils::Xam::XNotify(nowshowingtext,
		                       XexUtils::Xam::XNOTIFYUI_TYPE_FRIENDONLINE);
	}

	bool result = WSSend(state->socket, json);
	delete[] json;

	return result;
}

void SendIdentify(DiscordState *state) {
	XexUtils::Log::Print("[XeCord] Sending Discord Identify.");

	const int BUF_SIZE = 8192;
	char *json = new char[BUF_SIZE];

	std::string launchId = GenerateUUID();
	std::string launchSig = GenerateLaunchSignature();

	sprintf_s(json, BUF_SIZE,
	          "{\"op\":2,\"d\":{"
	          "\"token\":\"%s\","
	          "\"capabilities\":1734653,"
	          "\"properties\":{"
	          "\"os\":\"Windows\","
	          "\"browser\":\"Discord Client\","
	          "\"release_channel\":\"stable\","
	          "\"client_version\":\"1.0.9216\","
	          "\"os_version\":\"10.0.26200\","
	          "\"os_arch\":\"x64\","
	          "\"app_arch\":\"x64\","
	          "\"system_locale\":\"en-US\","
	          "\"has_client_mods\":false,"
	          "\"client_launch_id\":\"%s\","
	          "\"browser_user_agent\":\"Mozilla/5.0 (Windows NT 10.0; Win64; "
	          "x64) AppleWebKit/537.36 (KHTML, like Gecko) discord/1.0.9216 "
	          "Chrome/138.0.7204.251 Electron/37.6.0 Safari/537.36\","
	          "\"browser_version\":\"37.6.0\","
	          "\"os_sdk_version\":\"26200\","
	          "\"client_build_number\":474029,"
	          "\"native_build_number\":72385,"
	          "\"client_event_source\":null,"
	          "\"launch_signature\":\"%s\","
	          "\"client_app_state\":\"focused\","
	          "\"is_fast_connect\":false,"
	          "\"gateway_connect_reasons\":\"AppSkeleton\""
	          "},"
	          "\"presence\":{"
	          "\"status\":\"unknown\","
	          "\"since\":0,"
	          "\"activities\":[],"
	          "\"afk\":false"
	          "},"
	          "\"compress\":false,"
	          "\"client_state\":{"
	          "\"guild_versions\":{}"
	          "}"
	          "}}",
	          g_Token.c_str(), launchId.c_str(), launchSig.c_str());

	WSSend(state->socket, json);
	delete[] json;
}

bool SendHeartbeat(DiscordState *state) {
	unsigned long currentTime = GetTickCount();

	if (currentTime - state->lastHeartbeatTime >=
	    (unsigned long)(state->heartbeatInterval)) {
		char json[64];
		if (state->lastSequence == -1)
			sprintf_s(json, 64, "{\"op\": 1, \"d\": null}");
		else
			sprintf_s(json, 64, "{\"op\": 1, \"d\": %d}", state->lastSequence);

		if (!WSSend(state->socket, json)) {
			return false;
		}

		state->lastHeartbeatTime = currentTime;

		// XexUtils::Log::Print("[XeCord] Discord Heartbeat Sent with seq value:
		// %d!", state->lastSequence);
		return true;
	}

	return true;
}

bool ParseJSONInt(const char *fullPayload, int payloadLen, const char *key,
                  int *outValue) {
	if (!fullPayload || payloadLen <= 0 || !key)
		return false;

	const char *endPtr = fullPayload + payloadLen;
	const char *searchPtr = fullPayload;

	while (searchPtr < endPtr) {
		char *keyPtr = strstr((char *)searchPtr, key);
		if (!keyPtr)
			return false;

		if (keyPtr > fullPayload && *(keyPtr - 1) == '\\') {
			searchPtr = keyPtr + 1;
			continue;
		}

		char *valPtr = keyPtr + strlen(key);

		while (valPtr < endPtr &&
		       (*valPtr == ' ' || *valPtr == '\t' || *valPtr == '\n')) {
			valPtr++;
		}

		if (valPtr >= endPtr)
			return false;

		if (valPtr + 4 <= endPtr && strncmp(valPtr, "null", 4) == 0)
			return false;

		int result = 0;
		bool foundDigit = false;

		while (valPtr < endPtr) {
			char c = *valPtr;
			if (c >= '0' && c <= '9') {
				result = (result * 10) + (c - '0');
				foundDigit = true;
			} else if (c == ',' || c == '}' || c == ']' || c == ' ' ||
			           c == '\r' || c == '\n') {
				if (foundDigit) {
					*outValue = result;
					return true;
				}
				break;
			} else {
				break;
			}
			valPtr++;
		}

		return false;
	}

	return false;
}

/*bool JSONStringEquals(const char* payload, int payloadLen, const char* key,
const char* expectedValue)
{
    if (!payload || payloadLen <= 0 || !key || !expectedValue) return false;

    const char* endPtr = payload + payloadLen;

    char* keyPtr = strstr((char*)payload, key);
    if (!keyPtr) return false;

    char* valPtr = keyPtr + strlen(key);

    while (valPtr < endPtr && (*valPtr == ' ' || *valPtr == '\t')) {
        valPtr++;
    }

    if (valPtr >= endPtr || *valPtr != '"') return false;
    valPtr++;

    size_t expectedLen = strlen(expectedValue);

    if (valPtr + expectedLen >= endPtr) return false;

    if (strncmp(valPtr, expectedValue, expectedLen) == 0)
    {
        if (valPtr[expectedLen] == '"') {
            return true;
        }
    }

    return false;
}*/

void ProcessPacket(DiscordState *state, char *payload, int payloadLen) {
	int val = 0;

	if (ParseJSONInt(payload, payloadLen, "\"s\":", &val)) {
		if (val > state->lastSequence) {
			state->lastSequence = val;
		}
	}

	int opCode = -1;
	if (ParseJSONInt(payload, payloadLen, "\"op\":", &opCode)) {
		switch (opCode) {
		case 0:
			if (!state->isAuthenticated) {
				state->isAuthenticated = true;
				XexUtils::Log::Print("[XeCord] User Authenticated!");
			}
			/*if (JSONStringEquals(payload, payloadLen, "\"t\":", "READY")) {
			        XexUtils::Log::Print("[XeCord] Found Ready!");
			}*/
			break;

		case 1:
			state->lastHeartbeatTime = 0;
			break;

		case 10:
			if (ParseJSONInt(payload, payloadLen,
			                 "\"heartbeat_interval\":", &val)) {
				state->heartbeatInterval = val;
				XexUtils::Log::Print(
				    "[XeCord] Discord Heartbeat Interval: %d ms.", val);
			}
			break;

		case 11:
			// XexUtils::Log::Print("[XeCord] Discord Heartbeat Acknowledged.");
			break;

		default:
			break;
		}
	}
}

HRESULT MountAndNormalizePath() {
	if (!pluginPath)
		return E_POINTER;

	for (int i = 0; g_DriveMappings[i].mount != NULL; i++) {
		const char *devicePrefix = g_DriveMappings[i].device;
		const char *mountPoint = g_DriveMappings[i].mount;
		size_t devLen = strlen(devicePrefix);

		if (strncmp(pluginPath, devicePrefix, devLen) == 0) {
			if (pluginPath[devLen] == '\\' || pluginPath[devLen] == '\0') {
				HRESULT hr = XexUtils::Fs::MountPath(mountPoint, devicePrefix);

				if (FAILED(hr)) {
					XexUtils::Log::Print("[XeCord] Error: Failed to mount %s.",
					                     mountPoint);
				}

				char temp[MAX_PATH];
				const char *remainingPath = pluginPath + devLen;

				if (*remainingPath == '\\') {
					remainingPath++;
				}

				sprintf_s(temp, MAX_PATH, "%s\\%s", mountPoint, remainingPath);

				strcpy_s(pluginPath, MAX_PATH, temp);

				g_LastDevicePrefix = devicePrefix;
				g_LastMountPoint = mountPoint;

				return hr;
			}
		}
	}

	return S_OK;
}

void LoadConfig(char *iniPath) {
	INIReader reader(iniPath);

	XexUtils::Log::Print("[XeCord] Loading config from: %s.", iniPath);

	g_Token = reader.Get("Discord", "Token", "DISCORD_TOKEN");

	g_BootDelay = reader.GetInteger("General", "BootDelay", 20) * 1000;
	g_ShowNotifications =
	    reader.GetBoolean("General", "ShowNotifications", true);
	g_NowPlayingNotifications =
	    reader.GetBoolean("General", "NowPlayingNotifications", false);

	std::string playingOnStr = reader.Get("Presence", "PlayingOn", "xbox");
	strcpy_s(g_PlayingOn, 64, playingOnStr.c_str());
	std::string statusStr = reader.Get("Presence", "Status", "online");
	strcpy_s(g_Status, 64, statusStr.c_str());
	g_ShowSmallImage = reader.GetBoolean("Presence", "ShowSmallImage", true);
	g_ShowSmallImageOnCustomDash =
	    reader.GetBoolean("Presence", "ShowSmallImageOnCustomDash", false);
	g_SwapImages = reader.GetBoolean("Presence", "SwapImages", false);
	g_ShowGameIcon = reader.GetBoolean("Presence", "ShowGameIcon", true);
	g_AlwaysShowOGXboxIcon =
	    reader.GetBoolean("Presence", "AlwaysShowOGXboxIcon", true);
	g_FallbackTo360SmallForXbox1 =
	    reader.GetBoolean("Presence", "FallbackTo360SmallForXbox1", false);
	g_ShowConsole = reader.GetBoolean("Presence", "ShowConsole", true);
	g_ConsoleName = reader.Get("Presence", "ConsoleName", "Xbox 360");
	g_ShowConsoleType = reader.GetBoolean("Presence", "ShowConsoleType", true);
	g_ShowKernelVersion =
	    reader.GetBoolean("Presence", "ShowKernelVersion", false);
	g_ShowBuildNumberOnly =
	    reader.GetBoolean("Presence", "ShowBuildNumberOnly", false);
	g_CustomVersionNumber =
	    reader.GetInteger("General", "CustomVersionNumber", 0);
	g_ShowProfile = reader.GetBoolean("Presence", "ShowProfile", true);
	g_ResetTimePerGame =
	    reader.GetBoolean("Presence", "ResetTimePerGame", true);
	g_UseFallbackDash = reader.GetBoolean("General", "UseFallbackDash", false);
	g_FallbackDash = reader.GetInteger("General", "FallbackDash", 1);

	XexUtils::Log::Print("[XeCord] Loaded XeCord.ini.");
}

void GatewayThread(void *pArgs) {
	if (g_BootDelay < 6000)
		g_BootDelay = 6000;

	Sleep(g_BootDelay);

	MountAndNormalizePath();

	char tempFilename[MAX_PATH];

	char *lastSlash = strrchr(pluginPath, '\\');

	if (lastSlash) {
		strcpy_s(tempFilename, MAX_PATH, lastSlash + 1);

		*lastSlash = '\0';

		sprintf_s(iniPath, MAX_PATH, "%s\\%s", pluginPath, "XeCord.ini");
		sprintf_s(dbPath, MAX_PATH, "%s\\%s", pluginPath, "XeCordTitles.bin");

		sprintf_s(pluginPath, MAX_PATH, "%s\\%s", pluginPath, tempFilename);
	} else {
		strcpy_s(iniPath, MAX_PATH, "XeCord.ini");
		strcpy_s(dbPath, MAX_PATH, "XeCordTitles.bin");
	}

	LoadConfig(iniPath);
	LoadGameDatabase(dbPath);

	if (g_LastMountPoint && g_LastDevicePrefix) {
		char safeMount[32];
		strcpy_s(safeMount, 32, g_LastMountPoint);

		size_t len = strlen(safeMount);
		if (len > 0 && safeMount[len - 1] == '\\') {
			safeMount[len - 1] = '\0';
		}

		XexUtils::Fs::UnmountPath(safeMount);
	}

	while (true) {
		Sleep(5000);

		DiscordState *state = new DiscordState();
		state->isConnected = false;
		state->isAuthenticated = false;
		state->lastSequence = -1;
		state->heartbeatInterval = 41250;
		state->lastHeartbeatTime = GetTickCount();

		Sleep(4000);

		if (g_ShowNotifications && discordFirstConnect) {
			XexUtils::Xam::XNotify("XeCord - Connecting...",
			                       XexUtils::Xam::XNOTIFYUI_TYPE_FRIENDONLINE);
		}

		XexUtils::Socket *ds =
		    new XexUtils::Socket("gateway.discord.gg", 443, true);
		state->socket = ds;

		ds->AddECTrustAnchor(EC_DN, sizeof(EC_DN), EC_Q, sizeof(EC_Q),
		                     XexUtils::Socket::Curve_secp384r1);

		for (int i = 0; i < 10; i++) {
			if (SUCCEEDED(ds->Connect())) {
				state->isConnected = true;
				break;
			}
			Sleep(1000);
		}

		if (!state->isConnected) {
			XexUtils::Log::Print("[XeCord] Error: Failed to connect.");
			Sleep(5000);
			delete state;

			continue;
		}

		SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_HIGHEST);

		if (PerformHandshake(state)) {
			// state->socket->Receive(state->recvBuffer, 8192);

			SendIdentify(state);

			int timeoutMs = 100;
			setsockopt(ds->m_Socket, SOL_SOCKET, SO_RCVTIMEO,
			           (const char *)&timeoutMs, sizeof(timeoutMs));

			uint32_t activeTitleId = 0x01234567;

			static uint64_t lastSentTimestamp = 0;
			std::string lastSentGamertag = "";
			std::string lastLoadedImageName = "";

			XexUtils::Log::Print("[XeCord] Discord Gateway Opened.");

			if (g_ShowNotifications && discordFirstConnect) {
				XexUtils::Xam::XNotify(
				    "XeCord - Connected!",
				    XexUtils::Xam::XNOTIFYUI_TYPE_FRIENDONLINE);
				discordFirstConnect = false;
			}

			while (state->isConnected) {
				if (state->isAuthenticated) {
					uint32_t currentTitleId = XamGetCurrentTitleId();
					std::string currentGamertag = GetSafeGamertag();
					std::string currentImageName = ExLoadedImageName ? ExLoadedImageName : "";

					if (activeTitleId != currentTitleId ||
						lastSentTimestamp != g_EpochMillisecondsStart ||
						lastSentGamertag != currentGamertag ||
						lastLoadedImageName != currentImageName ||
						GTA5SessionInfo::HasDataUpdated())
					{
						activeTitleId = currentTitleId;
						lastSentTimestamp = g_EpochMillisecondsStart;
						lastSentGamertag = currentGamertag;
						lastLoadedImageName = currentImageName;
						GTA5SessionInfo::SetPresenceUpdated(true);

						if (!SendPresenceUpdate(state, activeTitleId)) {
							XexUtils::Log::Print(
							    "[XeCord] Error: Presence update failed. "
							    "Disconnecting...");
							state->isConnected = false;
							break;
						}
					}
				}

				if (!SendHeartbeat(state)) {
					XexUtils::Log::Print("[XeCord] Error: Heartbeat send "
					                     "failed. Disconnecting...");
					state->isConnected = false;
					break;
				}

				int len = state->socket->Receive(state->recvBuffer, 8191);

				if (len > 0) {
					state->recvBuffer[len] = '\0';
				}

				if (len >= 2) {
					unsigned char *uBuffer = (unsigned char *)state->recvBuffer;
					int payloadLen = uBuffer[1] & 0x7F;
					int headerSize = 2;

					if (payloadLen == 126) {
						headerSize = 4;

						if (len < 4) {
							return;
						}

						payloadLen =
						    *reinterpret_cast<unsigned short *>(&uBuffer[2]);
					}

					if ((size_t)payloadLen < 8192 - (size_t)headerSize) {
						int currentPayloadBytes = len - headerSize;

						while (currentPayloadBytes < payloadLen) {
							char *writePtr = state->recvBuffer + headerSize +
							                 currentPayloadBytes;
							int bytesNeeded = payloadLen - currentPayloadBytes;

							int r = ds->Receive(writePtr, bytesNeeded);

							if (r <= 0) {
								XexUtils::Log::Print(
								    "[XeCord] Error: Connection died while "
								    "downloading packet fragment.");
								state->isConnected = false;
								break;
							}

							currentPayloadBytes += r;
						}

						if (currentPayloadBytes >= payloadLen) {
							char *payload = state->recvBuffer + headerSize;
							payload[payloadLen] = '\0';

							ProcessPacket(state, payload, payloadLen);
						}
					}
				} else {
					if (len <= 0) {
						int err = WSAGetLastError();

						if (err == 10060) {
							continue;
							break;
						}

						XexUtils::Log::Print("[XeCord] Error: Connection "
						                     "Closed. Bytes: %d, Code: %d",
						                     len, err);
						state->isConnected = false;
						break;
					}
				}
			}
		}

		delete state;
		XexUtils::Log::Print(
		    "[XeCord] Error: Connection lost. Reconnecting in 5 seconds...");
		Sleep(5000);
	}
}

void EpochMillisecondsThread(void *pArgs) {
	Sleep(5000);

	wasGameShown = false;
	g_EpochMillisecondsStart = GetValidEpoch();
	static uint32_t lastSeenRawTitle;
	lastSeenRawTitle = XamGetCurrentTitleId();
	std::string lastSeenImageName = ExLoadedImageName ? ExLoadedImageName : "";

	while (true) {
		uint32_t currentTitle = XamGetCurrentTitleId();
		std::string currentImageName = ExLoadedImageName ? ExLoadedImageName : "";
		if (currentTitle != lastSeenRawTitle || currentImageName != lastSeenImageName) {
			wasGameShown = false;
			if (g_ResetTimePerGame) {
				g_EpochMillisecondsStart = GetValidEpoch();
			}
			lastSeenRawTitle = currentTitle;
			lastSeenImageName = currentImageName;
		}

		Sleep(1000);
	}
}

bool gta5Initialized = false;
void resetInitializedHookBooleans() {
	gta5Initialized = false;
}

void HookingThread(void* pArgs) {
	Sleep(5000);


	while (true) {
		Sleep(1000);

		DWORD titleId = XamGetCurrentTitleId();
		switch (titleId) {
		case TITLE_GTA5: {
			if (!gta5Initialized) {
				//reset initialized booleans
				resetInitializedHookBooleans();

				//setup main hook
				XexUtils::Detour& mainDetour = Hooks::GetMainDetour();
				mainDetour = XexUtils::Detour(0x82CE9F98, &Hooks::MainHook);
				mainDetour.Install();

				//mark gta initialized
				gta5Initialized = true;
			}
			break;
		}
		default: {
			resetInitializedHookBooleans();
			break;
		}
		}
	}
}

BOOL DllMain(HINSTANCE hModule, DWORD reason, void *pReserved) {
	switch (reason) {
	case DLL_PROCESS_ATTACH: {
		if (defaultInstruction == 0)
			defaultInstruction = *reinterpret_cast<uint16_t *>(patchAddress);
		*reinterpret_cast<uint16_t *>(patchAddress) = 0x4800;

		LDR_DATA_TABLE_ENTRY *pDataTable =
		    reinterpret_cast<LDR_DATA_TABLE_ENTRY *>(hModule);

		WideCharToMultiByte(CP_ACP, 0, pDataTable->FullDllName.Buffer, -1,
		                    pluginPath, MAX_PATH, nullptr, nullptr);

		XexUtils::ThreadEx(
		    reinterpret_cast<PTHREAD_START_ROUTINE>(EpochMillisecondsThread),
		    (void *)0, EXCREATETHREAD_FLAG_SYSTEM);
		XexUtils::ThreadEx(
		    reinterpret_cast<PTHREAD_START_ROUTINE>(GatewayThread), (void *)0,
		    EXCREATETHREAD_FLAG_SYSTEM);
		XexUtils::ThreadEx(
			reinterpret_cast<PTHREAD_START_ROUTINE>(HookingThread), (void*)0,
			EXCREATETHREAD_FLAG_SYSTEM);

		break;
	}
	case DLL_PROCESS_DETACH: {
		if (defaultInstruction != 0)
			*reinterpret_cast<uint16_t*>(patchAddress) = defaultInstruction;

		break;
	}
	}
	return TRUE;
}
