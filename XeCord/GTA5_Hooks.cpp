#include "Hooks.h"
#include "SessionInfo.h"

typedef BOOL(*t_MainHook)(Rage::Native::NativeContext*);

XexUtils::Detour& Hooks::GTA5::GetMainDetour() {
	static XexUtils::Detour g_MainDetour;
	return g_MainDetour;
}

int frameCache = 0;
BOOL Hooks::GTA5::MainHook(Rage::Native::NativeContext* Context) {
	int frameCount = Rage::Native::Invoker::Invoke<int>(0xB477A015);//get frame count
	if (frameCache < frameCount) {//avoids running more than once in the same frame
		frameCache = frameCount;

		int myPlayerId = Rage::Native::Invoker::Invoke<int>(0x8AEA886C);//get player id
		
		int playerCount = 0;
		for (int i = 0; i < 18; i++) {
			bool isMe = i == myPlayerId;//get player id
			bool isActive = Rage::Native::Invoker::Invoke<int>(0x43657B17, i) != 0;//is player active
			if (!isActive && !isMe) continue;
			playerCount++;
		}
		
		if (g_GTA5_SessionInfo.HasPresenceUpdated()) {
			bool isOnline = Rage::Native::Invoker::Invoke<int>(0x4BC4105E) != 0;//is in session
			bool lastOnlineState = g_GTA5_SessionInfo.GetIsOnline();
			int lastPlayerCount = g_GTA5_SessionInfo.GetPlayerCount();

			g_GTA5_SessionInfo.SetIsOnline(isOnline);
			g_GTA5_SessionInfo.SetPlayerCount(playerCount);
			g_GTA5_SessionInfo.SetMaxPlayerCount(18);
			//if data changed "data updated" tells the presense thread to update 
			//the presence updated bool is set to false then set back to true in the presence so this doesn't flip back before that gets chance to run
			bool dataUpdated = lastOnlineState != isOnline || lastPlayerCount != playerCount;
			g_GTA5_SessionInfo.SetDataUpdated(dataUpdated);
			if (dataUpdated) g_GTA5_SessionInfo.SetPresenceUpdated(false);
		}
	}

	XexUtils::Detour& mainDetour = GetMainDetour();
	return mainDetour.GetOriginal<t_MainHook>()(Context);
}