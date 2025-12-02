#pragma once

#include "Kernel.h"
#include "Xam.h"

namespace XexUtils
{
namespace Memory
{

/// @brief Safely writes an instance of `T` at `pDestination` (without access violations).
/// @tparam T The type of data to write.
/// @param pDestination A pointer to where to write `data`.
/// @param data The instance of `T` to write.
template<typename T>
void Write(void *pDestination, const T &data)
{
    if (pDestination == nullptr || !MmIsAddressValid(pDestination))
    {
        DebugPrint("[XexUtils][Memory]: Error: Invalid address: %p.", pDestination);
        return;
    }

    *static_cast<T *>(pDestination) = data;
}

/// @brief Safely writes an instance of `T` at `address` (without access violations).
/// @tparam T The type of data to write.
/// @param address Where to write `data`.
/// @param data The instance of `T` to write.
template<typename T>
inline void Write(uintptr_t address, const T &data)
{
    Write<T>(reinterpret_cast<void *>(address), data);
}

/// @brief Safely reads an instance of `T` at `pSource` (without access violations).
/// @tparam T The type of data to read.
/// @param pSource A pointer to where to read.
/// @return An instance of `T` copied from `pSource`.
template<typename T>
inline T Read(void *pSource)
{
    if (pSource == nullptr || !MmIsAddressValid(pSource))
    {
        DebugPrint("[XexUtils][Memory]: Error: Invalid address: %p.", pSource);
        return T();
    }

    return *static_cast<T *>(pSource);
}

/// @brief Safely reads an instance of `T` at `address` (without access violations).
/// @tparam T The type of data to read.
/// @param address Where to read.
/// @return An instance of `T` copied from `address`.
template<typename T>
inline T Read(uintptr_t address)
{
    return Read<T>(reinterpret_cast<void *>(address));
}

}
}
