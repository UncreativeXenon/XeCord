#pragma once

namespace GTA5SessionInfo {
	void SetIsOnline(bool isOnline);
	bool GetIsOnline();
	void SetPlayerCount(int playerCount);
	int GetPlayerCount();
	void SetDataUpdated(bool updated);
	bool HasDataUpdated();
	void SetPresenceUpdated(bool updated);
	bool HasPresenceUpdated();
}