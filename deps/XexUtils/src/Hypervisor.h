#pragma once

namespace XexUtils
{
namespace Hypervisor
{

/// @brief Reads an instance of `T` at `address` in the hypervisor.
/// @tparam T The return type.
/// @param address The physical address to read at.
/// @return An instance of `T` copied from `address`.
template<typename T>
T Peek(uint64_t address)
{
    void *pData = XPhysicalAlloc(sizeof(T), MAXULONG_PTR, 0, PAGE_READWRITE);
    Peek(address, pData, sizeof(T));
    T result = *reinterpret_cast<T *>(pData);
    XPhysicalFree(pData);

    return result;
}

/// @brief Writes an instance of `T` at `address` in the hypervisor.
/// @tparam T The type to write.
/// @param address The physical address to write at.
/// @param data The instance of `T` to write.
template<typename T>
void Poke(uint64_t address, const T &data)
{
    Poke(address, &data, sizeof(data));
}

/// @brief Reads `length` bytes at `address` in the hypervisor and store them at `pDestination`.
/// @param address The physical address to read at.
/// @param pDestination A pointer to physical memory allocated using `XPhysicalAlloc`.
/// @param length The amount of bytes available at `pDestination`.
void Peek(uint64_t address, void *pDestination, size_t length);

/// @brief Writes `length` bytes from `pSource` at `address` in the hypervisor.
/// @param address The physical address to write at.
/// @param pSource A pointer to memory to read `length` bytes from.
/// @param length The amount of bytes to write.
void Poke(uint64_t address, const void *pSource, size_t length);

}
}
