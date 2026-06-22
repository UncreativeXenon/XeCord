#include "SessionInfo.h"

struct SessionInfo {
	bool isOnline;
	int playerCount;
	bool updatePresence;
	bool updatedPresence;
	SessionInfo() : isOnline(false), playerCount(0), updatePresence(false), updatedPresence(true) {}
};
SessionInfo g_SessionInfo;

void GTA5SessionInfo::SetIsOnline(bool isOnline) {
	g_SessionInfo.isOnline = isOnline;
}

bool GTA5SessionInfo::GetIsOnline() {
	return g_SessionInfo.isOnline;
}

void GTA5SessionInfo::SetPlayerCount(int playerCount) {
	g_SessionInfo.playerCount = playerCount;
}

int GTA5SessionInfo::GetPlayerCount() {
	return g_SessionInfo.playerCount;
}

void GTA5SessionInfo::SetDataUpdated(bool updated) {
	g_SessionInfo.updatePresence = updated;
}

bool GTA5SessionInfo::HasDataUpdated() {
	return g_SessionInfo.updatePresence;
}

void GTA5SessionInfo::SetPresenceUpdated(bool updated) {
	g_SessionInfo.updatedPresence = updated;
}

bool GTA5SessionInfo::HasPresenceUpdated() {
	return g_SessionInfo.updatedPresence;
}
