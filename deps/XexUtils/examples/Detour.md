# Detouring

Detour a function:

```C++
XexUtils::Detour functionDetour(0x12345678, FunctionHook);

void FunctionHook(int param1, int param2)
{
    // Do some extra stuff...

    functionDetour.GetOriginal<decltype(&FunctionHook)>()(param1, param2);
}

void Init()
{
    HRESULT hr = functionDetour.Install();
    if (FAILED(hr))
    {
        // Something went wrong
    }
}
```

You can also detour a function imported from a module:

```C++
// Detour the 123th function exported by xboxkrnl.exe
XexUtils::Detour functionDetour("xboxkrnl.exe", 123, FunctionHook);

// Export the 123th function exported by xboxkrnl.exe used in xam.xex
XexUtils::Detour functionDetour("xam.xex", "xboxkrnl.exe", 123, FunctionHook);
```

#### Note

`Detour::GetOriginal` is a templated function that needs to be called with the function pointer type to return. This could be done automatically with templated arguments but the Xbox 360 compiler only supports C++0x, which is a draft of C++11, and templated arguments were not part of the draft yet. A templated arguments implementation would be much nicer to use:

```C++
class Detour
{
    // Rest of the class
public:
    template<typename T = void, typename... Args>
    T Original(Args... Params)
    {
        T(*OriginalFn)(Args...) = reinterpret_cast<T(*)(Args...)>(pOriginalInstructions);

        return OriginalFn(Params...);
    }
};

XexUtils::Detour functionDetour(0x12345678, FunctionHook);

void FunctionHook(int param1, int param2)
{
    // Do some extra stuff...

    functionDetour.Original(param1, param2);
}

void Init()
{
    HRESULT hr = functionDetour.Install();
    if (FAILED(hr))
    {
        // Something went wrong
    }
}
```
