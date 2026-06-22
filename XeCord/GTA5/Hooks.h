#pragma once
#include "Invoker.h"
#include <XexUtils.h>

namespace Hooks {
	XexUtils::Detour& GetMainDetour();
	BOOL MainHook(Rage::Native::NativeContext* Context);
}