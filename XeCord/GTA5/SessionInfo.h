#pragma once

struct GTA5SessionInfo {
	bool isOnline;
	int playerCount;
	bool changedSession;
	GTA5SessionInfo() : isOnline(false), playerCount(0), changedSession(false) {}
};

GTA5SessionInfo& GetGTA5SessionInfo();