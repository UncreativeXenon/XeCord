#include "pch.h"
#include "SMC.h"

#include "Kernel.h"

namespace XexUtils
{
namespace SMC
{

void SetPowerLED(PowerLEDMode mode, bool animate)
{
    uint8_t commandBuffer[16] = {};

    commandBuffer[0] = 0x8C;
    commandBuffer[1] = static_cast<uint8_t>(mode);
    commandBuffer[2] = (animate ? 0x01 : 0x00);

    HalSendSMCMessage(commandBuffer, nullptr);
}

void SetLEDColors(LEDColor topLeft, LEDColor topRight, LEDColor bottomLeft, LEDColor bottomRight)
{
    uint8_t commandBuffer[16] = {};

    commandBuffer[0] = 0x99;
    commandBuffer[1] = 0x01;

    commandBuffer[2] = static_cast<uint8_t>(topLeft) >> 3 |
                       static_cast<uint8_t>(topRight) >> 2 |
                       static_cast<uint8_t>(bottomLeft) >> 1 |
                       static_cast<uint8_t>(bottomRight);

    HalSendSMCMessage(commandBuffer, nullptr);
}

}
}
