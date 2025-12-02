#include "pch.h"
#include "Console.h"

namespace ATG
{

extern D3DDevice *g_pd3dDevice;

}

ATG::D3DDevice *Console::s_pd3dDevice = nullptr;

D3DPRESENT_PARAMETERS Console::s_d3dpp = {
    s_DisplayWidth,                // BackBufferWidth;
    s_DisplayHeight,               // BackBufferHeight;
    D3DFMT_A8R8G8B8,               // BackBufferFormat;
    1,                             // BackBufferCount;
    D3DMULTISAMPLE_NONE,           // MultiSampleType;
    0,                             // MultiSampleQuality;
    D3DSWAPEFFECT_DISCARD,         // SwapEffect;
    NULL,                          // hDeviceWindow;
    FALSE,                         // Windowed;
    TRUE,                          // EnableAutoDepthStencil;
    D3DFMT_D24S8,                  // AutoDepthStencilFormat;
    0,                             // Flags;
    0,                             // FullScreen_RefreshRateInHz;
    D3DPRESENT_INTERVAL_IMMEDIATE, // FullScreen_PresentationInterval;
};

Console::Console()
    : m_LineHeight(0.0f), m_MaxLinesToDisplay(0), m_FirstLineIndex(0)
{
}

// Ignore warning about "unused" pD3D variable
#pragma warning(push)
#pragma warning(disable : 4189)

HRESULT Console::Create()
{
    Direct3D *pD3D = Direct3DCreate9(D3D_SDK_VERSION);
    XASSERT(pD3D != nullptr);

    HRESULT hr = pD3D->CreateDevice(0, D3DDEVTYPE_HAL, NULL, D3DCREATE_HARDWARE_VERTEXPROCESSING, &s_d3dpp, reinterpret_cast<D3DDevice **>(&s_pd3dDevice));
    XASSERT(SUCCEEDED(hr));

    // Set the global device so that other functions can use it
    ATG::g_pd3dDevice = s_pd3dDevice;

    hr = m_Font.Create("game:\\Media\\Fonts\\Arial_16.xpr");
    XASSERT(SUCCEEDED(hr));

    m_LineHeight = m_Font.GetFontHeight();
    m_MaxLinesToDisplay = static_cast<size_t>(s_SafeAreaHeight / m_LineHeight);

    return hr;
}

#pragma warning(pop)

void Console::Print(const std::wstring &text)
{
    m_Lines.emplace_back(text);

    // If the number of lines goes beyond what can be displayed, scroll down automatically
    if (m_Lines.size() > m_MaxLinesToDisplay)
        m_FirstLineIndex = m_Lines.size() - m_MaxLinesToDisplay;
}

void Console::Print(const std::string &text)
{
    Print(XexUtils::Formatter::ToWide(text));
}

void Console::Update()
{
    XexUtils::Input::Gamepad *pGamepad = XexUtils::Input::GetInput();

    XASSERT(pGamepad != nullptr);

    // No need to scroll if we have enough space to display everything
    if (m_Lines.size() <= m_MaxLinesToDisplay)
        return;

    // Scroll up and down
    if (pGamepad->PressedButtons & XINPUT_GAMEPAD_DPAD_UP)
    {
        if (m_FirstLineIndex > 0)
            m_FirstLineIndex--;
    }
    else if (pGamepad->PressedButtons & XINPUT_GAMEPAD_DPAD_DOWN)
    {
        // Stop scrolling when the last line hits the bottom of the screen
        if (m_FirstLineIndex < m_Lines.size() - m_MaxLinesToDisplay)
            m_FirstLineIndex++;
    }
}

void Console::Render()
{
    ATG::RenderBackground(D3DCOLOR_XRGB(31, 0, 95), D3DCOLOR_XRGB(31, 0, 95));

    // Calculate the offset needed to force the last line to be at the bottom of the screen,
    // this offset is 0 when the number of lines is greater than the number of lines that can be displayed
    float yOffset = std::max<int32_t>(m_MaxLinesToDisplay - m_Lines.size(), 0) * m_LineHeight;

    m_Font.Begin();

    for (size_t i = 0; i < std::min<size_t>(m_Lines.size(), m_MaxLinesToDisplay); i++)
    {
        float x = static_cast<float>(s_SafeAreaOffsetX);
        float y = static_cast<float>(s_SafeAreaOffsetY) + yOffset + m_LineHeight * i;
        m_Font.DrawText(x, y, D3DCOLOR_XRGB(255, 255, 255), m_Lines[m_FirstLineIndex + i].c_str());
    }

    m_Font.End();

    s_pd3dDevice->Present(nullptr, nullptr, nullptr, nullptr);
}
