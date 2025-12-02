#pragma once

#include "Kernel.h"

namespace XexUtils
{

/// @file General.h
///
/// Functions in this file are voluntarily placed directly in the `XexUtils` namespace,
/// so not inside of a sub-namespace like the other modules.

/// @brief Gets a pointer to the `ordinal`th function exported by `moduleName`.
///
/// This function can fail if no module with the name `moduleName` is currently loaded,
/// or if `ordinal` is greater than the amount of functions exported by `moduleName`.
///
/// @param moduleName The name of the module.
/// @param ordinal The ordinal number of the function.
/// @return A generic `void *` to the function on success, `nullptr` on error.
void *ResolveExport(const std::string &moduleName, uint32_t ordinal);

/// @brief Simple wrapper around `CreateThread` to only pass a function and its arguments.
/// @param pStartAddress A pointer to the function to run in a separate thread.
/// @param pArgs A pointer to the arguments to pass to the function at `pStartAddress`.
/// @return The `HANDLE` of the newly created thread.
HANDLE Thread(PTHREAD_START_ROUTINE pStartAddress, void *pArgs = nullptr);

/// @brief Simple wrapper around `ExCreateThread` to pass less arguments.
/// @param pStartAddress A pointer to the function to run in a separate thread.
/// @param pArgs A pointer to the arguments to pass to the function at `pStartAddress`.
/// @param creationFlags The thread creation flags.
/// @param pThreadId A pointer to a `uint32_t` to store the thread ID.
/// @return The `HANDLE` of the newly created thread.
HANDLE ThreadEx(PTHREAD_START_ROUTINE pStartAddress, void *pArgs, EXCREATETHREAD_FLAG creationFlags, uint32_t *pThreadId = nullptr);

/// @brief Reboots the console.
void Reboot();

/// @brief Checks wether the console is running the debug kernel or not.
/// @return `true` if the console is running the debug kernel, `false` otherwise.
bool IsDevkit();

/// @brief Checks wether the current title is running in the Xenia emulator or not.
/// @return `true` if the current title is running in the Xenia emulator, `false` otherwise.
bool InXenia();

}
