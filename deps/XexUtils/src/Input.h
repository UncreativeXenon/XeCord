#pragma once

namespace XexUtils
{
namespace Input
{

/// @brief A structure representing the current state of the gamepad.
struct Gamepad : public XINPUT_GAMEPAD
{
    Gamepad();

    /// @brief The state (when last updated) of the buttons. This remains set as long as
    /// the buttons are pressed.
    uint16_t LastButtons;

    /// @brief The state (when last updated) of the left trigger. This remains set as
    /// long as the left trigger is pressed.
    bool LastLeftTrigger;

    /// @brief The state (when last updated) of the right trigger. This remains set as
    /// long as the right trigger is pressed.
    bool LastRightTrigger;

    /// @brief The buttons pressed at this frame - only set on the first frame where the
    /// buttons are pressed.
    uint16_t PressedButtons;

    /// @brief The left trigger state at this frame - only set on the first frame where
    /// the left trigger is pressed.
    bool PressedLeftTrigger;

    /// @brief The right trigger state at this frame - only set on the first frame where
    /// the right trigger is pressed.
    bool PressedRightTrigger;

    /// @brief Left thumbstick X value converted to range [-1,+1].
    float ThumbLeftX;

    /// @brief Left thumbstick Y value converted to range [-1,+1].
    float ThumbLeftY;

    /// @brief Right thumbstick X value converted to range [-1,+1].
    float ThumbRightX;

    /// @brief Right thumbstick Y value converted to range [-1,+1].
    float ThumbRightY;
};

/// @brief Gets a pointer to a `Gamepad` structure representing the current gamepad state.
///
/// This function will trigger a breakpoint in debug mode if `userIndex` is greater
/// than `XUSER_MAX_COUNT`.
///
/// @param userIndex The user index between `0` and `XUSER_MAX_COUNT`.
/// @return A `Gamepad` pointer.
Gamepad *GetInput(uint32_t userIndex = 0);

}
}
