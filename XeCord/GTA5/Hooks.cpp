#include "Hooks.h"
#include "SessionInfo.h"

typedef BOOL(*t_MainHook)(Rage::Native::NativeContext*);

XexUtils::Detour& Hooks::GetMainDetour() {
	static XexUtils::Detour g_MainDetour;
	return g_MainDetour;
}

int frameCache = 0;
BOOL Hooks::MainHook(Rage::Native::NativeContext* Context) {
	int frameCount = Rage::Native::Invoker::Invoke<INT>(0xB477A015);//get frame count
	if (frameCache < frameCount) {//avoids running more than once in the same frame
		frameCache = frameCount;

		int myPlayerId = Rage::Native::Invoker::Invoke<INT>(0x8AEA886C);//get player id
		
		int playerCount = 0;
		for (int i = 0; i < 18; i++) {
			bool isMe = i == myPlayerId;//get player id
			bool isActive = Rage::Native::Invoker::Invoke<Any>(0x43657B17, i) != 0;//is player active
			if (isMe || isActive) playerCount++;
		}
		
		if (GTA5SessionInfo::HasPresenceUpdated()) {
			bool isOnline = Rage::Native::Invoker::Invoke<Any>(0x4BC4105E) != 0;//is in session
			bool lastOnlineState = GTA5SessionInfo::GetIsOnline();
			int lastPlayerCount = GTA5SessionInfo::GetPlayerCount();

			GTA5SessionInfo::SetIsOnline(isOnline);
			GTA5SessionInfo::SetPlayerCount(playerCount);
			//if data changed "data updated" tells the presense thread to update 
			//the presence updated bool is set to false then set back to true in the presence so this doesn't flip back before that gets chance to run
			bool dataUpdated = lastOnlineState != isOnline || lastPlayerCount != playerCount;
			GTA5SessionInfo::SetDataUpdated(dataUpdated);
			if (dataUpdated) GTA5SessionInfo::SetPresenceUpdated(false);
		}
	}

	XexUtils::Detour& mainDetour = GetMainDetour();
	return mainDetour.GetOriginal<t_MainHook>()(Context);
}