# Hypervisor

Read hypervisor memory:

```C++
void Init()
{
    // Reading a small data type
    uint32_t data = XexUtils::Hypervisor::Peek<uint32_t>(0x1234);

    // Reading into a buffer
    // Note: the buffer HAS to be allocated with XPhysicalAlloc and not just malloc
    // and freed with XPhysicalFree and not just free
    uint8_t *buffer = static_cast<uint8_t *>(XPhysicalAlloc(20, MAXULONG_PTR, 0, PAGE_READWRITE));
    XexUtils::Hypervisor::Peek(0x1234, buffer, 20);

    // Do something with buffer...

    XPhysicalFree(buffer);
}
```

Write hypervisor memory:

```C++
void Init()
{
    // Writing a small data type
    XexUtils::Hypervisor::Poke<uint32_t>(0x8000010400001234, 3);

    // Writing a buffer
    uint8_t buffer[] = { 1, 2, 3, 4 };
    XexUtils::Hypervisor::Poke(0x8000010400001234, buffer, sizeof(buffer));
}
```
