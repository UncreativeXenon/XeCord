#pragma once
#include <xtl.h>
#include <vector>

struct DetourContext {
	DWORD dwAddress;
	BYTE szAsm[0x10];
	int iWriteSize;
	DetourContext() {
		iWriteSize = 0x10;
	}
};

class Hooking {
private:
	std::vector<DetourContext> m_PatchContext;
	BYTE m_HookSection[0x1000];//TODO: fix warning
	DWORD m_HookCount;
public:
	Hooking();
	~Hooking();

	void RemoveAllPatches();
	void ClearHookContext();

	DWORD RelinkGLPR(DWORD dwSFSOffset, DWORD* dwSaveStubAddress, DWORD* dwOriginalAddress);
	void PatchInJump(DWORD* dwAddress, DWORD dwDestination, bool bLinked = false);
	void HookFunctionStart(DWORD* dwAddress, DWORD* dwSaveStub, DWORD dwDestination);

	template <typename T>
	bool HookFunction(std::string Name, DWORD dwAddress, void* pHookFunction, T* pTrampoline) {
		if (dwAddress > 0x80000000) {
			DWORD* startStub = (DWORD*)&m_HookSection[m_HookCount * 0x20];
			if (!startStub) return false;

			m_HookCount++;

			for (int i = 0; i < 7; i++) {
				startStub[i] = 0x60000000;
			}
			startStub[7] = 0x4E800020;

			HookFunctionStart((DWORD*)dwAddress, startStub, (DWORD)pHookFunction);

			if (!pTrampoline) {
				return false;
			}

			*pTrampoline = (T)startStub;

			return true;
		}

		return false;
	}

	bool HookFunctionNoLink(DWORD dwAddress, void* pHookFunction);

	template <typename T>
	bool HookVirtual(DWORD dwVTable, void* pReplacement, T* pTrampoline) {
		if (dwVTable) {
			DetourContext cxt;
			cxt.dwAddress = dwVTable;
			cxt.iWriteSize = 0x4;
			memcpy(cxt.szAsm, (void*)dwVTable, 0x4);
			m_patch_context.push_back(cxt);

			DWORD originalCall = *(DWORD*)dwVTable;
			*(DWORD*)dwVTable = (DWORD)pReplacement;
			*pTrampoline = (T)originalCall;

			return true;
		}

		return false;
	}
};