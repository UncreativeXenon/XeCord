#include "pch.h"
#include "Dashlaunch.h"

#include "General.h"

#define LAUNCH_MODULE "launch.xex"

namespace XexUtils
{
namespace Dashlaunch
{

typedef enum _DL_ORDINALS
{
    DL_ORDINALS_LDAT = 1,
    DL_ORDINALS_GETOPTVALBYNAME = 9,
    DL_ORDINALS_SETOPTVALBYNAME = 10,
} DL_ORDINALS;

LaunchData *pLaunchData = nullptr;
DLAUNCHGETOPTVALBYNAME GetOptionValueByName = nullptr;
DLAUNCHSETOPTVALBYNAME SetOptionValueByName = nullptr;

HRESULT Init()
{
    pLaunchData = static_cast<LaunchData *>(ResolveExport(LAUNCH_MODULE, DL_ORDINALS_LDAT));
    if (pLaunchData == nullptr)
    {
        DebugPrint("[XexUtils][Dashlaunch]: Error: Could not resolve the Dashlaunch data.");
        return E_FAIL;
    }

    GetOptionValueByName = static_cast<DLAUNCHGETOPTVALBYNAME>(ResolveExport(LAUNCH_MODULE, DL_ORDINALS_GETOPTVALBYNAME));
    if (GetOptionValueByName == nullptr)
    {
        DebugPrint("[XexUtils][Dashlaunch]: Error: Could not resolve the GetOptionValueByName function.");
        return E_FAIL;
    }

    SetOptionValueByName = static_cast<DLAUNCHSETOPTVALBYNAME>(ResolveExport(LAUNCH_MODULE, DL_ORDINALS_SETOPTVALBYNAME));
    if (SetOptionValueByName == nullptr)
    {
        DebugPrint("[XexUtils][Dashlaunch]: Error: Could not resolve the SetOptionValueByName function.");
        return E_FAIL;
    }

    return S_OK;
}

}
}
