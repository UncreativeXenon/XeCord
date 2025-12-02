#include "pch.h"
#include "Input.h"

#include "Memory.h"

namespace XexUtils
{
namespace Input
{

static Gamepad s_Gamepads[XUSER_MAX_COUNT];

Gamepad::Gamepad()
    : LastButtons(0), LastLeftTrigger(false), LastRightTrigger(false), PressedButtons(0), PressedLeftTrigger(false), PressedRightTrigger(false)
{
}

static uint16_t ButtonForVirtualKey(uint16_t virtualKey)
{
    switch (virtualKey)
    {
    case VK_PAD_A:
        return XINPUT_GAMEPAD_A;
    case VK_PAD_B:
        return XINPUT_GAMEPAD_B;
    case VK_PAD_X:
        return XINPUT_GAMEPAD_X;
    case VK_PAD_Y:
        return XINPUT_GAMEPAD_Y;
    case VK_PAD_RSHOULDER:
        return XINPUT_GAMEPAD_RIGHT_SHOULDER;
    case VK_PAD_LSHOULDER:
        return XINPUT_GAMEPAD_LEFT_SHOULDER;
    case VK_PAD_DPAD_UP:
        return XINPUT_GAMEPAD_DPAD_UP;
    case VK_PAD_DPAD_DOWN:
        return XINPUT_GAMEPAD_DPAD_DOWN;
    case VK_PAD_DPAD_LEFT:
        return XINPUT_GAMEPAD_DPAD_LEFT;
    case VK_PAD_DPAD_RIGHT:
        return XINPUT_GAMEPAD_DPAD_RIGHT;
    case VK_PAD_START:
        return XINPUT_GAMEPAD_START;
    case VK_PAD_BACK:
        return XINPUT_GAMEPAD_BACK;
    case VK_PAD_LTHUMB_PRESS:
        return XINPUT_GAMEPAD_LEFT_THUMB;
    case VK_PAD_RTHUMB_PRESS:
        return XINPUT_GAMEPAD_RIGHT_THUMB;
    default:
        return 0;
    }
}

static float ConvertThumbstickValue(int16_t thumbstickValue, int16_t deadZone)
{
    if (thumbstickValue > +deadZone)
        return (thumbstickValue - deadZone) / (32767.0f - deadZone);
    if (thumbstickValue < -deadZone)
        return (thumbstickValue + deadZone + 1.0f) / (32767.0f - deadZone);

    return 0.0f;
}

Gamepad *GetInput(uint32_t userIndex)
{
    // Get the gamepad state
    XINPUT_STATE state = {};
    uint32_t result = XInputGetState(userIndex, &state);

    XASSERT(userIndex < XUSER_MAX_COUNT);

    Gamepad &gamepad = s_Gamepads[userIndex];

    // If the first controller is not connected, just return early
    if (result != ERROR_SUCCESS)
        return &gamepad;

    // Copy the gamepad to the local structure
    Memory::Write<XINPUT_GAMEPAD>(&gamepad, state.Gamepad);

    // Save the buttons pressed at the previous frame to set the currently pressed buttons only if
    // they were not already pressed at the previous frame, we need to do this because pressing
    // then releasing a button (even done really fast) takes multiple frames.
    gamepad.PressedButtons = (gamepad.LastButtons ^ gamepad.wButtons) & gamepad.wButtons;
    gamepad.LastButtons = gamepad.wButtons;

    // Convert thumbstick values coming from XINPUT to a [-1;+1] space
    gamepad.ThumbLeftX = ConvertThumbstickValue(gamepad.sThumbLX, XINPUT_GAMEPAD_LEFT_THUMB_DEADZONE);
    gamepad.ThumbLeftY = ConvertThumbstickValue(gamepad.sThumbLY, XINPUT_GAMEPAD_LEFT_THUMB_DEADZONE);
    gamepad.ThumbRightX = ConvertThumbstickValue(gamepad.sThumbRX, XINPUT_GAMEPAD_RIGHT_THUMB_DEADZONE);
    gamepad.ThumbRightY = ConvertThumbstickValue(gamepad.sThumbRY, XINPUT_GAMEPAD_RIGHT_THUMB_DEADZONE);

    // Get the keystrokes
    XINPUT_KEYSTROKE keystroke = {};
    result = XInputGetKeystroke(userIndex, XINPUT_FLAG_GAMEPAD, &keystroke);

    // If no button is pressed, just return early
    if (result != ERROR_SUCCESS)
        return &gamepad;

    // If a key is being held, add it to the pressed buttons even if it was already pressed at the previous frame
    if (keystroke.Flags & XINPUT_KEYSTROKE_REPEAT)
        gamepad.PressedButtons |= ButtonForVirtualKey(keystroke.VirtualKey);

    // Check if the left trigger is pressed
    bool leftTriggerPressed = (gamepad.bLeftTrigger > XINPUT_GAMEPAD_TRIGGER_THRESHOLD);
    if (leftTriggerPressed)
        gamepad.PressedLeftTrigger = !gamepad.LastLeftTrigger;
    else
        gamepad.PressedLeftTrigger = false;

    // Store the left trigger state for next time
    gamepad.LastLeftTrigger = leftTriggerPressed;

    // Check if the left trigger is pressed
    bool rightTriggerPressed = (gamepad.bRightTrigger > XINPUT_GAMEPAD_TRIGGER_THRESHOLD);
    if (rightTriggerPressed)
        gamepad.PressedRightTrigger = !gamepad.LastRightTrigger;
    else
        gamepad.PressedRightTrigger = false;

    // Store the left trigger state for next time
    gamepad.LastRightTrigger = leftTriggerPressed;

    return &gamepad;
}

}
}
