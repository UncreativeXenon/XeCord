# Dashlaunch

Access the global Dashlaunch data:

```C++
void Init()
{
    // Initialize the Dashlaunch exports
    HRESULT hr = XexUtils::Dashlaunch::Init();
    if (FAILED(hr))
    {
        XexUtils::Log::Print("Couldn't get exports from Dashlaunch");
        return;
    }

    // Get the kernel version that Dashlaunch supports
    uint16_t supportedKernelVersion = XexUtils::Dashlaunch::pLaunchData->TargetKernel;
    XexUtils::Log::Print("Dashlaunch supports kernel: %d", supportedKernelVersion);
}
```

Get and set a Dashlaunch option value by its name:

```C++
void Init()
{
    // Initialize the Dashlaunch exports
    HRESULT hr = XexUtils::Dashlaunch::Init();
    if (FAILED(hr))
    {
        XexUtils::Log::Print("Couldn't get exports from Dashlaunch");
        return;
    }

    // Force liveblock to be enabled
    uint32_t liveBlockEnabled = 0;
    BOOL result = XexUtils::Dashlaunch::GetOptionValueByName("liveblock", &liveBlockEnabled);
    if (result == FALSE)
    {
        XexUtils::Log::Print("Couldn't get the liveblock value from Dashlaunch");
        return;
    }

    if (liveBlockEnabled == 0)
    {
        uint32_t enableLiveBlock = 1;
        result = XexUtils::Dashlaunch::SetOptionValueByName("liveblock", &enableLiveBlock);
        if (result == FALSE)
        {
            XexUtils::Log::Print("Couldn't enable liveblock");
            return;
        }
    }
}
```
