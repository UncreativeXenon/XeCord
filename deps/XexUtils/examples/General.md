# General

Get a function pointer from a module through its ordinal:

```C++
void Init()
{
    typedef void (*FunctionPointerType)(int param1, int param2);
    FunctionPointerType function = static_cast<FunctionPointerType>(XexUtils::ResolveExport("xam.xex", 123));

    function();
}
```

Create a thread (like you would with the accessible Win32 API):

```C++
uint32_t Worker(void *pArgs)
{
    int number = *static_cast<int *>(pArgs);

    // Do something with number

    return 0;
}

void Init()
{
    int number = 3;

    XexUtils::Thread(reinterpret_cast<PTHREAD_START_ROUTINE>(Worker), &number);
}
```

Create a thread detached from the current running title (that will keep running even when the title stops):

```C++
uint32_t Worker(void *pArgs)
{
    int number = *static_cast<int *>(pArgs);

    // Do something with number

    return 0;
}

void Init()
{
    int number = 3;

    // The flag parameter (the third one), is the one that allows you to customize the way the thread behaves
    XexUtils::ThreadEx(reinterpret_cast<PTHREAD_START_ROUTINE>(Worker), &number, EXCREATETHREAD_FLAG_SYSTEM);
}
```

Reboot the console:

```C++
void Init()
{
    XexUtils::Reboot();
}
```

Detect if the console is a devkit:

```C++
void Init()
{
    if (XexUtils::IsDevkit())
        XexUtils::Log::Print("Console is a devkit");
    else
        XexUtils::Log::Print("Console is not a devkit");
}
```

Detect if the code is running in [Xenia](https://xenia.jp/):

```C++
void Init()
{
    if (XexUtils::InXenia())
        XexUtils::Log::Print("Code is running in Xenia");
    else
        XexUtils::Log::Print("Code is not running in Xenia");
}
```
