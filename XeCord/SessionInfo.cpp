#include "SessionInfo.h"

SessionInfo::SessionInfo() : m_isOnline(false), m_playerCount(0), m_maxPlayers(0), m_updatePresence(false), m_updatedPresence(true) {}

void SessionInfo::SetIsOnline(bool isOnline) {
	m_isOnline = isOnline;
}

void SessionInfo::SetPlayerCount(int playerCount) {
	m_playerCount = playerCount;
}

void SessionInfo::SetMaxPlayerCount(int maxPlayers) {
	m_maxPlayers = maxPlayers;
}

void SessionInfo::SetDataUpdated(bool updated) {
	m_updatePresence = updated;
}

void SessionInfo::SetPresenceUpdated(bool updated) {
	m_updatedPresence = updated;
}

bool SessionInfo::GetIsOnline() {
	return m_isOnline;
}

int SessionInfo::GetPlayerCount() {
	return m_playerCount;
}

int SessionInfo::GetMaxPlayerCount() {
	return m_maxPlayers;
}

bool SessionInfo::HasDataUpdated() {
	return m_updatePresence;
}

bool SessionInfo::HasPresenceUpdated() {
	return m_updatedPresence;
}

SessionInfo g_GTA5_SessionInfo;