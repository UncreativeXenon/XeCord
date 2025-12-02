# Memory

Read and write to arbitrary addresses safely with no segfault:

```C++
void Init()
{
    uintptr_t address = 0x12345678;

    // If reading fails, a message will be logged to stderr and 0 is returned
    // If writing fails, a message will be logged to stderr and nothing will be done
    int previousValue = XexUtils::Memory::Read<int>(address);
    XexUtils::Memory::Write<int>(address, 3);
    int currentValue = XexUtils::Memory::Read<int>(address);
}
```
