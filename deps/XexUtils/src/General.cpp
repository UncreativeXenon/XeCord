#include "pch.h"
#include "General.h"

#include "Memory.h"

namespace XexUtils
{

void *ResolveExport(const std::string &moduleName, uint32_t ordinal)
{
    HMODULE moduleHandle = GetModuleHandle(moduleName.c_str());
    if (moduleHandle == nullptr)
    {
        DebugPrint("[XexUtils]: Error: Could find module %s. Make sure it is loaded.", moduleName.c_str());
        return nullptr;
    }

    return GetProcAddress(moduleHandle, reinterpret_cast<const char *>(ordinal));
}

HANDLE Thread(PTHREAD_START_ROUTINE pStartAddress, void *pArgs)
{
    return CreateThread(nullptr, 0, pStartAddress, pArgs, 0, nullptr);
}

HANDLE ThreadEx(PTHREAD_START_ROUTINE pStartAddress, void *pArgs, EXCREATETHREAD_FLAG creationFlags, uint32_t *pThreadId)
{
    HANDLE handle = nullptr;
    ExCreateThread(&handle, 0, pThreadId, nullptr, pStartAddress, pArgs, creationFlags);

    return handle;
}

void Reboot()
{
    HalReturnToFirmware(HalRebootRoutine);
}

bool IsDevkit()
{
    // Read a 32-bit unsigned int at 0x8E038610 and if the 16th is NOT set, the console is a devkit.
    // This bit is not set while running in Xenia so make sure that's not the case
    return !(Memory::Read<uint32_t>(0x8E038610) & (1 << 15)) && !InXenia();
}

bool InXenia()
{
    // Inspired by this
    // https://github.com/RBEnhanced/RB3Enhanced/blob/master/source/xbox360.c#L16

    void *xamFirstExport = ResolveExport("xam.xex", 1);
#ifndef NDEBUG
    if (xamFirstExport == nullptr)
        DebugPrint("[XexUtils]: Error: Could not find the first function exported by xam.xex, this should not happen.");
#endif

    // If Xam is not in the typical memory address space, we're in an emulator
    return reinterpret_cast<uintptr_t>(xamFirstExport) >> 24 != 0x81;
}

}
