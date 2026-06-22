#include "Hooks.h"
#include "SessionInfo.h"

Hooks::t_MainHook originalMainHook;
Hooks::t_MainHook& Hooks::GetOriginalMainHook() {
	return originalMainHook;
}

int frameCache = 0;
BOOL Hooks::MainHook(Rage::Native::NativeContext* Context) {
	int frameCount = Rage::Native::Invoker::Invoke<INT>(0xB477A015);//get frame count
	if (frameCache < frameCount) {//avoids running more than once in the same frame
		frameCache = frameCount;

		int myPlayerId = Rage::Native::Invoker::Invoke<INT>(0x8AEA886C);
		
		int playerCount = 0;
		for (int i = 0; i < 18; i++) {
			bool isMe = i == myPlayerId;//get player id
			bool isActive = Rage::Native::Invoker::Invoke<INT>(0x43657B17, i) != 0;//is player active
			if (isMe || isActive) playerCount++;
		}

		GTA5SessionInfo& sessionInfo = GetGTA5SessionInfo();
		bool isOnline = Rage::Native::Invoker::Invoke<INT>(0x43657B17, myPlayerId) != 0;//is player active
		bool lastOnlineState = sessionInfo.isOnline;
		int lastPlayerCount = sessionInfo.playerCount;
		sessionInfo.isOnline = isOnline;
		sessionInfo.playerCount = playerCount;
		sessionInfo.changedSession = lastOnlineState != isOnline || lastPlayerCount != playerCount;
	}

	return originalMainHook(Context);
}