# Assert

Use an assertion to trigger a breakpoint when a condition is false, only in debug builds:

```C++
#define ARRAY_SIZE 3

int data[ARRAY_SIZE];

void Print(uint32_t index)
{
    XASSERT(index < ARRAY_SIZE); // Will trigger a breakpoint in debug builds if index is greater or equal to ARRAY_SIZE

    XexUtils::Log::Print("%d", data[index]);
}

void Init()
{
    Print(2);
}
```
