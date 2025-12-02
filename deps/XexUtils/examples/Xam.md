# XAM (Xbox API)

Show an Xbox notification:

```C++
void Init()
{
    XexUtils::Xam::XNotify("You just unlocked an achievement!", XexUtils::Xam::XNOTIFYUI_TYPE_ACHIEVEMENT);
}
```

Open a keyboard to get a numerical value:

```C++
void Init()
{
    std::string value;
    uint32_t result = XexUtils::Xam::ShowKeyboard(L"Keyboard", L"Enter a value", L"123", value, 3, VKBD_LATIN_NUMERIC);

    if (result == ERROR_CANCELLED)
        XexUtils::Log::Print("Keyboard canceled");
    else if (result == ERROR_SUCCESS)
    {
        int number = atoi(value.c_str());

        // Do something with the number...
    }
}
```

Open a message box:

```C++
void Init()
{
    std::vector<std::wstring> buttonLabels(2);
    buttonLabels[0] = L"Yes";
    buttonLabels[1] = L"No";
    uint32_t buttonPressedIndex = 0;

    uint32_t result = XexUtils::Xam::ShowMessageBox(
        L"Sandwich",
        L"Do you want a sandwich?",
        buttonLabels,
        XMB_ALERTICON,
        &buttonPressedIndex
    );

    if (result == ERROR_CANCELLED)
        XexUtils::Log::Print("Message box canceled");
    else if (result == ERROR_SUCCESS)
        wprintf_s(L"User pressed %s\n", buttonLabels[buttonPressedIndex]);
}
```
