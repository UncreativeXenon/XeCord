#pragma once
#include <cstdint>
#include <vector>
#include <xtl.h>

#pragma pack(push, 1)
struct GameEntry {
	unsigned int titleId;
	unsigned int secondaryId;
	char name[60];
	unsigned char type;
	bool iconExists;
};
#pragma pack(pop)

extern std::vector<GameEntry> g_GameList;

bool LoadGameDatabase(const char *filePath);
const char *GetGameTypeString(unsigned char type);