#pragma once

#include "Vec2.h"
#include "Vec3.h"
#include "Vec4.h"

namespace XexUtils
{
namespace Math
{

/// @brief Converts `degrees` to radians.
/// @param degrees The angle in degrees.
/// @return `degrees` converted to radians.
float Radians(float degrees);

/// @brief Creates a point `distance` away from `origin` in the `viewY` direction.
/// @param origin The `point` to start from.
/// @param viewY The direction angle in radians.
/// @param distance The distance away from `origin`.
/// @return A point as a `vec3`.
vec3 ProjectForward(const vec3 &origin, float viewY, float distance);

/// @brief Gets the next `uint32_t` after `base` that is a multiple of `N`.
///
/// This function doesn't compile if `N` is `0`.
///
/// @tparam N The multiple.
/// @param base The number to start from.
/// @return A `uint32_t`.
template<uint32_t N>
uint32_t RoundToNextMultipleOf(uint32_t base)
{
    static_assert(N != 0, "Multiplier N cannot be zero.");

    uint32_t remainder = base % N;

    return base + (N - remainder);
}

}
}
