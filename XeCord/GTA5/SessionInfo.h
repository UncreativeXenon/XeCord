#pragma once

struct GTA5SessionInfo {
	bool isOnline;
	int playerCount;
	bool updatePresence;
	bool updatedPresence;
	GTA5SessionInfo() : isOnline(false), playerCount(0), updatePresence(false), updatedPresence(true) {}
};

GTA5SessionInfo& GetGTA5SessionInfo();