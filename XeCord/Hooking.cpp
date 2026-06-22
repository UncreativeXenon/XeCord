#include "Hooking.h"

#include "../deps/XexUtils/include/XexUtils.h"

Hooking::Hooking() : m_patch_context(), m_hook_section(), m_hook_count(0) {

}

void Hooking::RemoveAllPatches() {
	for (size_t i = 0; i < m_patch_context.size(); i++) {
		DWORD* addr = (DWORD*)m_patch_context[i].dwAddress;

		//restore original code
		memcpy(addr, m_patch_context[i].szAsm, m_patch_context[i].iWriteSize);

		//flush **all 4 instructions** (16 bytes)
		for (int i = 0; i < 4; ++i) __dcbst(0, &addr[i]);

		__sync();
		__isync();

#ifdef DEVELOPER
		logger& g_logger = get_logger();
		g_logger.log(logger_types::LOG_SUCCESS, "Unpatched: Address=0x%X", m_patch_context[i].dwAddress);
#endif
	}

	ClearHookContext();
}

void Hooking::ClearHookContext() {
	m_hook_count = 0;
	memset(m_hook_section, 0, sizeof(m_hook_section));
	m_patch_context.clear();
}

void __declspec(naked) GLPR(void) {
	__asm {
		std     r14, -0x98(sp)
		std     r15, -0x90(sp)
		std     r16, -0x88(sp)
		std     r17, -0x80(sp)
		std     r18, -0x78(sp)
		std     r19, -0x70(sp)
		std     r20, -0x68(sp)
		std     r21, -0x60(sp)
		std     r22, -0x58(sp)
		std     r23, -0x50(sp)
		std     r24, -0x48(sp)
		std     r25, -0x40(sp)
		std     r26, -0x38(sp)
		std     r27, -0x30(sp)
		std     r28, -0x28(sp)
		std     r29, -0x20(sp)
		std     r30, -0x18(sp)
		std     r31, -0x10(sp)
		stw     r12, -0x8(sp)
		lwz        r2, 0x2AC(r13)
		xor r2, r2, r12
		stw        r2, -4(r1)
		blr
	}
}
DWORD Hooking::RelinkGLPR(DWORD dwSFSOffset, DWORD* dwSaveStubAddress, DWORD* dwOriginalAddress) {
	DWORD Instruction = 0, Replacing;
	PDWORD Saver = (PDWORD)GLPR;

	if (dwSFSOffset & 0x2000000) {
		dwSFSOffset = dwSFSOffset | 0xFC000000;
	}

	Replacing = dwOriginalAddress[dwSFSOffset / 4];

	for (int i = 0; i < 20; i++) {
		if (Replacing == Saver[i]) {
			DWORD NewOffset = (DWORD)&Saver[i] - (DWORD)dwSaveStubAddress;
			Instruction = 0x48000001 | (NewOffset & 0x3FFFFFC);
		}
	}

	return Instruction;
}

void Hooking::PatchInJump(DWORD* dwAddress, DWORD dwDestination, bool bLinked) {
	DetourContext ctx;
	ctx.dwAddress = (DWORD)dwAddress;
	ctx.iWriteSize = 0x10;//we always write 4 instructions
	memcpy(ctx.szAsm, dwAddress, 0x10);//save original 16 bytes

	m_patch_context.push_back(ctx);

	//build lis/ori/mtctr/bctrl
	if (dwDestination & 0x8000)
		dwAddress[0] = 0x3D600000 + (((dwDestination >> 16) & 0xFFFF) + 1);
	else
		dwAddress[0] = 0x3D600000 + ((dwDestination >> 16) & 0xFFFF);

	dwAddress[1] = 0x396B0000 + (dwDestination & 0xFFFF);
	dwAddress[2] = 0x7D6903A6;
	dwAddress[3] = 0x4E800420 | (bLinked ? 1 : 0);

	//flush the **whole** patch
	for (int i = 0; i < 4; ++i) __dcbst(0, &dwAddress[i]);
	__sync();
	__isync();

#ifdef DEVELOPER
	logger& g_logger = get_logger();
	g_logger.log(logger_types::LOG_SUCCESS, "Patched: %X | Destination: %X", dwAddress, dwDestination);
#endif
}

void Hooking::HookFunctionStart(DWORD* dwAddress, DWORD* dwSaveStub, DWORD dwDestination) {
	if ((dwSaveStub != NULL) && (dwAddress != NULL)) {
		DWORD AddressRelocation = (DWORD)(&dwAddress[4]);

		if (AddressRelocation & 0x8000) {
			dwSaveStub[0] = 0x3D600000 + (((AddressRelocation >> 16) & 0xFFFF) + 1);
		}
		else {
			dwSaveStub[0] = 0x3D600000 + ((AddressRelocation >> 16) & 0xFFFF);
		}

		dwSaveStub[1] = 0x396B0000 + (AddressRelocation & 0xFFFF);
		dwSaveStub[2] = 0x7D6903A6;

		for (int i = 0; i < 4; i++) {
			if ((dwAddress[i] & 0x48000003) == 0x48000001) {
				dwSaveStub[i + 3] = RelinkGLPR((dwAddress[i] & ~0x48000003), &dwSaveStub[i + 3], &dwAddress[i]);
			}
			else {
				dwSaveStub[i + 3] = dwAddress[i];
			}
		}

		dwSaveStub[7] = 0x4E800420;
		__dcbst(0, dwSaveStub);
		__sync();
		__isync();

		PatchInJump(dwAddress, dwDestination);
	}
}

bool Hooking::HookFunctionNoLink(DWORD dwAddress, void* pHookFunction) {
	if (dwAddress > 0x80000000) {
		PatchInJump((DWORD*)dwAddress, (DWORD)pHookFunction);

#ifdef DEVELOPER
		logger& g_logger = get_logger();
		g_logger.log(logger_types::LOG_SUCCESS, "Hooked: Address=0x%X", dwAddress);
#endif

		return true;
	}

#ifdef DEVELOPER
	logger& g_logger = get_logger();
	g_logger.log(logger_types::LOG_ERROR, "Failed to hook: Address=0x%X", dwAddress);
#endif

	return false;
}

Hooking& GetHooking() {
	static Hooking g_Hooking;
	return g_Hooking;
}