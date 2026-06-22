#include "Hooks.h"
#include "SessionInfo.h"
#include <XexUtils.h>

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
			bool isActive = Rage::Native::Invoker::Invoke<Any>(0x43657B17, i) != 0;//is player active
			if (isMe || isActive) playerCount++;
		}

		GTA5SessionInfo& sessionInfo = GetGTA5SessionInfo();
		if (sessionInfo.updatedPresence) {
			bool isOnline = Rage::Native::Invoker::Invoke<Any>(0x4BC4105E) != 0;//is in session
			bool lastOnlineState = sessionInfo.isOnline;
			int lastPlayerCount = sessionInfo.playerCount;

			sessionInfo.isOnline = isOnline;
			sessionInfo.playerCount = playerCount;
			sessionInfo.updatePresence = lastOnlineState != isOnline || lastPlayerCount != playerCount;

			if (sessionInfo.updatePresence) {
				sessionInfo.updatedPresence = false;
			}
		}
	}

	return originalMainHook(Context);
}