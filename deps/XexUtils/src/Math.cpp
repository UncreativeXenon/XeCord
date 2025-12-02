#include "pch.h"
#include "Math.h"

namespace XexUtils
{

float Math::Radians(float degrees)
{
    return (degrees * (XM_PI / 180.0f));
}

Math::vec3 Math::ProjectForward(const vec3 &origin, float viewY, float distance)
{
    return vec3(origin.x + distance * cos(viewY), origin.y + distance * sin(viewY), origin.z);
}

}
