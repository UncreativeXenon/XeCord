# Formatting

Format a string in a `printf` style:

```C++
void Init()
{
    std::string formattedString = XexUtils::Formatter::Format("My favorite number is %i", 3);
}
```

Format a wide string in a `wprintf` style:

```C++
void Init()
{
    std::wstring formattedWideString = XexUtils::Formatter::Format(L"My favorite number is %i", 3);
}
```

Convert a narrow string to a wide string:

```C++
void Init()
{
    std::string name = "John";
    std::wstring wideName = XexUtils::Formatter::ToWide(name);
}
```

Convert a wide string to a narrow string:

```C++
void Init()
{
    std::wstring wideName = L"John";
    std::wstring name = XexUtils::Formatter::ToNarrow(wideName);
}
```
