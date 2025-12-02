#pragma once

class Console
{
public:
    Console();

    HRESULT Create();

    void Print(const std::wstring &text);

    void Print(const std::string &text);

    void Update();

    void Render();

private:
    static const uint32_t s_DisplayWidth = 1280;
    static const uint32_t s_DisplayHeight = 720;
    static const uint32_t s_SafeAreaPercentage = 90;
    static const uint32_t s_SafeAreaWidth = s_DisplayWidth * s_SafeAreaPercentage / 100;
    static const uint32_t s_SafeAreaHeight = s_DisplayHeight * s_SafeAreaPercentage / 100;
    static const uint32_t s_SafeAreaOffsetX = (s_DisplayWidth - s_SafeAreaWidth) / 2;
    static const uint32_t s_SafeAreaOffsetY = (s_DisplayHeight - s_SafeAreaHeight) / 2;

    static D3DPRESENT_PARAMETERS s_d3dpp;
    static ATG::D3DDevice *s_pd3dDevice;

    ATG::Font m_Font;

    float m_LineHeight;
    size_t m_MaxLinesToDisplay;
    uint32_t m_FirstLineIndex;
    std::vector<std::wstring> m_Lines;
};
