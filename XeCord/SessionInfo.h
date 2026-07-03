#pragma once

class SessionInfo {
private:
	bool m_isOnline;//in a session
	int m_playerCount;//how many players
	int m_maxPlayers;//max players
	bool m_updatePresence;//RPC presence should be updated
	bool m_updatedPresence;//RPC presence has been updated and loop is safe to continue
public:
	SessionInfo();

	void SetIsOnline(bool isOnline);
	void SetPlayerCount(int playerCount);
	void SetMaxPlayerCount(int maxPlayers);
	void SetDataUpdated(bool updated);
	void SetPresenceUpdated(bool updated);

	bool GetIsOnline();
	int GetPlayerCount();
	int GetMaxPlayerCount();
	bool HasDataUpdated();
	bool HasPresenceUpdated();
};

extern SessionInfo g_GTA5_SessionInfo;