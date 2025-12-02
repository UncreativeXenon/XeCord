#pragma once

namespace XexUtils
{
namespace SMC
{

typedef enum _LEDColor
{
    LEDColor_Off = 0x00,
    LEDColor_Red = 0x08,
    LEDColor_Green = 0x80,
    LEDColor_Orange = 0x88,
} LEDColor;

typedef enum _PowerLEDMode
{
    PowerLED_On = 0x01,
    PowerLED_Default = 0x02,
    PowerLED_Off = 0x03,
    PowerLED_Blink = 0x10,
} PowerLEDMode;

/// @brief Sets the behavior of the power LED.
/// @param mode The behavior to set.
/// @param animate Wether to trigger the power LED animation or not.
void SetPowerLED(PowerLEDMode mode, bool animate);

/// @brief Changes the colors of the different power LED segments.
/// @param topLeft The color of the top left segment.
/// @param topRight The color of the top right segment.
/// @param bottomLeft The color of the bottom left segment.
/// @param bottomRight The color of the bottom right segment.
void SetLEDColors(LEDColor topLeft, LEDColor topRight, LEDColor bottomLeft, LEDColor bottomRight);

}
}
