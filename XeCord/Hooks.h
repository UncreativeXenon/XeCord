#pragma once
#include "GTA5_Invoker.h"
#include <XexUtils.h>

namespace Hooks {
	namespace GTA5 {
		XexUtils::Detour& GetMainDetour();
		BOOL MainHook(Rage::Native::NativeContext* Context);
	}
}