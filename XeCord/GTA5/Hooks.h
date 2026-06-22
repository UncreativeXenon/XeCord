#pragma once
#include "Invoker.h"

namespace Hooks {
	typedef BOOL(*t_MainHook)(Rage::Native::NativeContext*);
	t_MainHook& GetOriginalMainHook();
	BOOL MainHook(Rage::Native::NativeContext* Context);
};