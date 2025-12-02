#include <fstream>
#include "GameDB.h"
#include "XexUtils.h"

std::vector<GameEntry> g_GameList;

const char* GetGameTypeString(uint8_t type) {
    switch (type) {
        case 1: return "360";
        case 2: return "Xbox1";
        case 3: return "XBLA";
		case 4: return "Homebrew";
        default: return "360";
    }
}

bool LoadGameDatabase(const char* filePath) 
{
    XexUtils::Log::Print("[XeCord] Loading games info from: %s", filePath);

    std::ifstream file(filePath, std::ios::binary | std::ios::ate);
    
    if (!file.is_open()) 
    {
        XexUtils::Log::Print("[XeCord] Failed to open file. Check if XeCordTitles.bin exists.");
        return false;
    }

    std::streamsize fileSize = file.tellg();
    
    file.seekg(0, std::ios::beg);

    if (fileSize <= 0 || fileSize % sizeof(GameEntry) != 0) 
    {
        XexUtils::Log::Print("[XeCord] XeCordTitles.bin file empty or corrupt size: %d", (int)fileSize);
        return false;
    }

    int count = (int)fileSize / sizeof(GameEntry);
    g_GameList.resize(count);

    file.read((char*)g_GameList.data(), fileSize);

    file.close();
    
    XexUtils::Log::Print("[XeCord] Loaded XeCordTitles.bin. Found %d games.", count);
    return true;
}