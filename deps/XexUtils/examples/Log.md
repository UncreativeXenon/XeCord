# Logging

Log messages to stdout:

```C++
void Init()
{
    XexUtils::Log::Print("Address is: %#010x", 0x1234); // Print 'Address is: 0x12340000'

    std::string text = "Hello John";
    XexUtils::Log::Print(text); // Print 'Hello John'
}
```

Each log function has a corresponding wide string version:

```C++
void Init()
{
    wchar_t buffer[] = L"World";
    XexUtils::Log::Print(L"Hello %s", buffer);  // Print 'Hello World'

    std::wstring text = L"Hello John";
    XexUtils::Log::Print(text); // Print 'Hello John'
}
```

Print something only in debug builds:

```C++
void Init()
{
    DebugPrint("This will to be logged to stdout only in debug builds.");
}
```
