#pragma once

struct GTA5SessionInfo {
	bool isOnline;
	int playerCount;
	GTA5SessionInfo() : isOnline(false), playerCount(0) {}
};

GTA5SessionInfo& GetGTA5SessionInfo();