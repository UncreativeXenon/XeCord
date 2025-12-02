#pragma once

#define MAX_HOOK_COUNT 100
#define NUM_INSTRUCTIONS_IN_JUMP 4

namespace XexUtils
{

/// @brief A class representing a function detour or hook.
class Detour
{
public:
    /// @brief Creates an empty `Detour`.
    Detour();

    /// @brief Creates a `Detour` from `pSource` to `pDestination`.
    /// @param pSource Where to detour.
    /// @param pDestination Where to make the detour go.
    Detour(void *pSource, const void *pDestination);

    /// @brief Creates a `Detour` from `sourceAddress` to `pDestination`.
    /// @param sourceAddress Where to detour.
    /// @param pDestination Where to make the detour go.
    Detour(uintptr_t sourceAddress, const void *pDestination);

    /// @brief Creates a `Detour` from the `ordinal`th function exported by `moduleName`
    /// to `pDestination`.
    /// @param moduleName The name of the module.
    /// @param ordinal The ordinal of the function to detour.
    /// @param pDestination Where the make the detour go.
    Detour(const std::string &moduleName, uint32_t ordinal, const void *pDestination);

    /// @brief Creates a `Detour` from the `ordinal`th function exported by
    /// `importedModuleName` used by `moduleName` to `pDestination`.
    /// @param moduleName The name of the module importing the function.
    /// @param importedModuleName The name of the module from which the function is exported.
    /// @param ordinal The ordinal of the function to detour.
    /// @param pDestination Where the make the detour go.
    Detour(const std::string &moduleName, const std::string &importedModuleName, uint32_t ordinal, const void *pDestination);

    /// @brief Calls `Remove`.
    ~Detour();

    /// @brief Sets up the detour from the source to the destination.
    ///
    /// This function can fail if the total amount of detours exceeds `MAX_HOOK_COUNT`,
    /// or if either the source or the destination are `nullptr`.
    ///
    /// @return `S_OK` on success, `E_FAIL` on error.
    HRESULT Install();

    /// @brief Restores the original behavior at the source.
    void Remove();

    /// @brief Gets a function pointer to the original function, before the detour.
    /// @tparam T The function pointer type to return.
    /// @return A function pointer of type `T`.
    template<typename T>
    inline T GetOriginal() const
    {
        return reinterpret_cast<T>(&s_StubSection[m_HookIndex]);
    }

private:
    typedef uint32_t POWERPC_INSTRUCTION;
    typedef uint8_t POWERPC_INSTRUCTION_TYPE;

    struct Stub
    {
        POWERPC_INSTRUCTION Instructions[20]; // DetourFunctionStart can copy up to 20 instructions

        Stub() { ZeroMemory(&Instructions, sizeof(Instructions)); }
    };

    struct Jump
    {
        POWERPC_INSTRUCTION Instructions[NUM_INSTRUCTIONS_IN_JUMP];

        Jump() { ZeroMemory(&Instructions, sizeof(Instructions)); }
    };

    void *m_pSource;
    const void *m_pDestination;
    size_t m_HookIndex;
    Jump m_Original;

    static Stub s_StubSection[MAX_HOOK_COUNT];
    static size_t s_HookCount;
    static CRITICAL_SECTION s_CriticalSection;

    void DetourFunctionStart();

    void PatchInJump(void *pSource, const void *pDestination, bool linked);

    void *ResolveBranch(POWERPC_INSTRUCTION instruction, const void *pBranch);

    void *GetModuleImport(const std::string &baseModuleName, const std::string &importedModuleName, uint32_t ordinal);
};

}
