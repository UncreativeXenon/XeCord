#include "pch.h"
#include "Detour.h"

#include "General.h"
#include "Kernel.h"
#include "Memory.h"

namespace XexUtils
{

#pragma section(".text")

// This will hold all the instructions for all hooks. Allocating in an executable section
// isn't mandatory on real hardware because modded consoles have page permissions disabled,
// but this is necessary on Xenia, which emulates retail hardware
__declspec(allocate(".text")) Detour::Stub Detour::s_StubSection[MAX_HOOK_COUNT];
size_t Detour::s_HookCount = 0;
CRITICAL_SECTION Detour::s_CriticalSection = {};

Detour::Detour()
    : m_pSource(nullptr), m_pDestination(nullptr), m_HookIndex(static_cast<size_t>(-1))
{
}

Detour::Detour(void *pSource, const void *pDestination)
    : m_pSource(pSource), m_pDestination(pDestination), m_HookIndex(static_cast<size_t>(-1))
{
    XASSERT(m_pSource != nullptr);
    XASSERT(m_pDestination != nullptr);
}

Detour::Detour(uintptr_t sourceAddress, const void *pDestination)
    : m_pSource(reinterpret_cast<void *>(sourceAddress)), m_pDestination(pDestination), m_HookIndex(static_cast<size_t>(-1))
{
    XASSERT(m_pSource != nullptr);
    XASSERT(m_pDestination != nullptr);
}

Detour::Detour(const std::string &moduleName, uint32_t ordinal, const void *pDestination)
    : m_pSource(ResolveExport(moduleName, ordinal)), m_pDestination(pDestination), m_HookIndex(static_cast<size_t>(-1))
{
    XASSERT(m_pSource != nullptr);
    XASSERT(m_pDestination != nullptr);
}

Detour::Detour(const std::string &moduleName, const std::string &importedModuleName, uint32_t ordinal, const void *pDestination)
    : m_pSource(GetModuleImport(moduleName, importedModuleName, ordinal)), m_pDestination(pDestination), m_HookIndex(static_cast<size_t>(-1))
{
    XASSERT(m_pSource != nullptr);
    XASSERT(m_pDestination != nullptr);
}

Detour::~Detour()
{
    Remove();
}

HRESULT Detour::Install()
{
    if (s_HookCount >= MAX_HOOK_COUNT || m_pSource == nullptr || m_pDestination == nullptr)
    {
        DebugPrint("[XexUtils][Detour]: Error");

#ifndef NDEBUG
        if (s_HookCount >= MAX_HOOK_COUNT)
            DebugPrint("\tMax hook count exceeded, current: %d, max: %d.", s_HookCount, MAX_HOOK_COUNT);
        if (m_pSource == nullptr)
            DebugPrint("\tSource address is null.");
        if (m_pDestination == nullptr)
            DebugPrint("\tDestination address is null.");
#endif

        return E_FAIL;
    }

    if (s_CriticalSection.Synchronization.RawEvent[0] == 0)
        InitializeCriticalSection(&s_CriticalSection);

    EnterCriticalSection(&s_CriticalSection);

    // Keep track of where the stub of the current instance is in s_StubSection
    m_HookIndex = s_HookCount;

    // Copy the original instructions at m_pSource before hooking to be able to
    // restore them later
    m_Original = Memory::Read<Jump>(m_pSource);

    DetourFunctionStart();

    s_HookCount++;

    LeaveCriticalSection(&s_CriticalSection);

    return S_OK;
}

void Detour::Remove()
{
    // Restore the original instructions if needed
    if (m_HookIndex != -1 && m_pSource != nullptr && MmIsAddressValid(m_pSource))
        Memory::Write<Jump>(m_pSource, m_Original);

    m_pSource = nullptr;
    m_pDestination = nullptr;
    m_HookIndex = 0;
    m_Original = Jump();
}

#define POWERPC_B 0x48
#define POWERPC_BL 0x4B

void Detour::DetourFunctionStart()
{
    POWERPC_INSTRUCTION *pSource = static_cast<POWERPC_INSTRUCTION *>(m_pSource);
    POWERPC_INSTRUCTION *pStub = reinterpret_cast<POWERPC_INSTRUCTION *>(&s_StubSection[m_HookIndex]);
    size_t instructionCount = 0;

    for (size_t i = 0; i < NUM_INSTRUCTIONS_IN_JUMP; i++)
    {
        POWERPC_INSTRUCTION instruction = pSource[i];
        POWERPC_INSTRUCTION_TYPE instructionType = Memory::Read<POWERPC_INSTRUCTION_TYPE>(&pSource[i]);

        // If the function op code is null, it's invalid
        if (instruction == 0)
        {
            DebugPrint(
                "[XexUtils][Detour]: Error: Found invalid instruction with null opcode at %p.",
                &pSource[i]
            );
            break;
        }

        // If the instruction is a branch
        if (instructionType == POWERPC_B || instructionType == POWERPC_BL)
        {
            // Get a pointer to where the branch goes
            void *pBranchDestination = ResolveBranch(instruction, &pSource[i]);
            bool linked = (instruction & 1) != 0;

            // Jump from the stub to where the branch goes
            PatchInJump(&pStub[instructionCount], pBranchDestination, linked);
            instructionCount += NUM_INSTRUCTIONS_IN_JUMP;

            // If it was a branch to a different section of the same function (b loc_),
            // we won't need to add anything else to the stub
            if (!linked)
            {
                PatchInJump(pSource, m_pDestination, false);
                return;
            }
        }
        // Otherwise, just copy the instruction to the stub
        else
        {
            pStub[instructionCount] = instruction;
            instructionCount++;
        }
    }

    // Make the stub call the original function
    PatchInJump(&pStub[instructionCount], &pSource[NUM_INSTRUCTIONS_IN_JUMP], false);

    // Make the original function call the stub
    PatchInJump(pSource, m_pDestination, false);
}

void Detour::PatchInJump(void *pSource, const void *pDestination, bool linked)
{
    Jump jump;
    uintptr_t destinationAddress = reinterpret_cast<uintptr_t>(pDestination);

    jump.Instructions[0] = 0x3C000000 + (destinationAddress >> 16);    // lis    %r0, dest>>16
    jump.Instructions[1] = 0x60000000 + (destinationAddress & 0xFFFF); // ori    %r0, %r0, dest&0xFFFF
    jump.Instructions[2] = 0x7C0903A6;                                 // mtctr  %r0
    jump.Instructions[3] = 0x4E800420 + (linked ? 1 : 0);              // bctr/bctrl

    Memory::Write<Jump>(pSource, jump);

    doSync(pSource);
}

void *Detour::ResolveBranch(POWERPC_INSTRUCTION instruction, const void *pBranch)
{
    // Taken from here
    // https://github.com/skiff/libpsutil/blob/master/libpsutil/system/memory.cpp#L90

    XASSERT(instruction != 0);
    XASSERT(pBranch != nullptr);

    uintptr_t offset = instruction & 0x3FFFFFC;

    if (offset & (1 << 25))
        offset |= 0xFC000000;

    return reinterpret_cast<void *>(reinterpret_cast<uintptr_t>(pBranch) + offset);
}

void *Detour::GetModuleImport(const std::string &baseModuleName, const std::string &importedModuleName, uint32_t ordinal)
{
    // Very inspired by this
    // https://github.com/TeaModz/XeLiveStealth-Full-Source/blob/master/XeLive/Hooking.cpp#L100

    // Usage example
    //
    // GetModuleImport("hud.xex", "xam.xex", 842);
    //
    // This would get a pointer to the 842nd function exported by xam.xex (XuiRegisterClass)
    // used by "hud.xex"

    // Get the module handle of the base module
    HMODULE moduleHandle = GetModuleHandle(baseModuleName.c_str());
    if (moduleHandle == nullptr)
    {
        DebugPrint(
            "[XexUtils][Detour]: Error: Could not get handle of module %s. Make sure it is loaded.",
            baseModuleName.c_str()
        );
        return nullptr;
    }

    // Get a pointer to the function we're looking for but from our module (so the one
    // this code is running in, not the base module)
    void *pFunc = ResolveExport(importedModuleName, ordinal);
    if (pFunc == nullptr)
    {
        DebugPrint(
            "[XexUtils][Detour]: Error: Could not resolve function number %d from module %s."
            "Make sure the module is loaded and exports at least %d functions.",
            ordinal,
            importedModuleName.c_str(),
            ordinal
        );
        return nullptr;
    }

    // Get the import descriptor of the base module
    LDR_DATA_TABLE_ENTRY *pDataTable = reinterpret_cast<LDR_DATA_TABLE_ENTRY *>(moduleHandle);
    XEX_IMPORT_DESCRIPTOR *pImportDesc = static_cast<XEX_IMPORT_DESCRIPTOR *>(
        RtlImageXexHeaderField(pDataTable->XexHeaderBase, XEX_HEADER_FIELD_IMPORT_DESCRIPTOR)
    );

    XASSERT(pImportDesc != nullptr);

    // Calculate the import table location from the import descriptor
    // The memory is laid out as such:
    //
    // ┌──────────────────────────────┐
    // │ XEX_IMPORT_DESCRIPTOR        │
    // │   uint32_t Size              │  => size: 0xC
    // │   uint32_t NameTableSize     │
    // │   uint32_t ModuleCount       │
    // ├──────────────────────────────┤
    // │ NAME_TABLE                   │  => size: NameTableSize
    // │ (unknown struct)             │
    // ├──────────────────────────────┤
    // │ XEX_IMPORT_TABLE 1           │
    // │ XEX_IMPORT_TABLE 2           │  => size: The sum of all XEX_IMPORT_TABLE TableSize fields
    // │ XEX_IMPORT_TABLE ...         │
    // │ XEX_IMPORT_TABLE ModuleCount │
    // └──────────────────────────────┘
    //
    // So the address of the first import table is
    // pImportDesc + sizeof(XEX_IMPORT_DESCRIPTOR) + pImportDesc->NameTableSize

    XEX_IMPORT_TABLE *pImportTable = reinterpret_cast<XEX_IMPORT_TABLE *>(
        reinterpret_cast<uintptr_t>(pImportDesc) + sizeof(XEX_IMPORT_DESCRIPTOR) + pImportDesc->NameTableSize
    );

    for (size_t i = 0; i < pImportDesc->ModuleCount; i++)
    {
        for (size_t j = 0; j < pImportTable->ImportCount; j++)
        {
            void *pImportStubAddress = *reinterpret_cast<void **>(pImportTable->ImportStubAddr[j]);

            if (pImportStubAddress == pFunc)
                return reinterpret_cast<void *>(pImportTable->ImportStubAddr[j + 1]);
        }

        // Set pImportTable to the address of the next import table, which is the
        // address of the current import table + the size of the current import table
        pImportTable = reinterpret_cast<XEX_IMPORT_TABLE *>(
            reinterpret_cast<uintptr_t>(pImportTable) + pImportTable->TableSize
        );
    }

    DebugPrint(
        "[XexUtils][Detour]: Error: Could not find function number %d exported by %s used in %s.",
        ordinal,
        importedModuleName.c_str(),
        baseModuleName.c_str()
    );

    return nullptr;
}

}
