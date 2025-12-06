#include "GameDB.h"
#include "XexUtils.h"
#include <xtl.h> // Required for CreateFile, ReadFile

std::vector<GameEntry> g_GameList;

const char *GetGameTypeString(uint8_t type) {
	switch (type) {
	case 1:
		return "360";
	case 2:
		return "XBLA";
	case 3:
		return "Xbox1";
	case 4:
		return "HomeBrew";
	default:
		return "360";
	}
}

bool LoadGameDatabase(const char *filePath) {
	XexUtils::Log::Print("[XeCord] Loading titles from: %s.", filePath);

	HANDLE hFile = CreateFile(filePath, GENERIC_READ, FILE_SHARE_READ, NULL,
	                          OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	if (hFile == INVALID_HANDLE_VALUE) {
		XexUtils::Log::Print(
		    "[XeCord] Failed to open file. Check if XeCordTitles.bin exists.");
		return false;
	}

	LARGE_INTEGER fileSize;
	if (!GetFileSizeEx(hFile, &fileSize)) {
		CloseHandle(hFile);
		return false;
	}

	if (fileSize.QuadPart <= 0 || fileSize.QuadPart % sizeof(GameEntry) != 0) {
		XexUtils::Log::Print(
		    "[XeCord] XeCordTitles.bin is empty or has corrupt size: %d.",
		    (int)fileSize.QuadPart);
		CloseHandle(hFile);
		return false;
	}

	int count = (int)fileSize.QuadPart / sizeof(GameEntry);
	g_GameList.resize(count);

	DWORD bytesRead = 0;
	if (!ReadFile(hFile, g_GameList.data(), (DWORD)fileSize.QuadPart,
	              &bytesRead, NULL)) {
		XexUtils::Log::Print("[XeCord] Failed to read XeCordTitles.bin.");
		CloseHandle(hFile);
		return false;
	}

	CloseHandle(hFile);

	XexUtils::Log::Print("[XeCord] Loaded XeCordTitles.bin. Found %d games.",
	                     count);
	return true;
}