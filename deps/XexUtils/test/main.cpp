#include "pch.h"

#include "Console.h"
#include "specs.h"

Console g_Console;

void __cdecl main()
{
    HRESULT hr = g_Console.Create();

    if (FAILED(hr))
        ATG::FatalError("Failed to create console: %x\n", hr);

    RunTests();

    for (;;)
    {
        g_Console.Update();

        g_Console.Render();
    }
}
