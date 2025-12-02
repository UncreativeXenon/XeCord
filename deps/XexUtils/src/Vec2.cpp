#include "pch.h"
#include "Vec2.h"

namespace XexUtils
{
namespace Math
{

vec2::vec2()
    : x(0.0f), y(0.0f)
{
}

vec2::vec2(float x, float y)
    : x(x), y(y)
{
}

float vec2::magnitude() const
{
    return sqrtf(x * x + y * y);
}

vec2 vec2::normalize() const
{
    return *this / magnitude();
}

void vec2::add(const vec2 &other)
{
    x += other.x;
    y += other.y;
}

void vec2::substract(const vec2 &other)
{
    x -= other.x;
    y -= other.y;
}

void vec2::multiply(const vec2 &other)
{
    x *= other.x;
    y *= other.y;
}

void vec2::multiply(const float &multiplier)
{
    x *= multiplier;
    y *= multiplier;
}

void vec2::divide(const vec2 &other)
{
    x /= other.x;
    y /= other.y;
}

void vec2::divide(const float &divider)
{
    x /= divider;
    y /= divider;
}

bool vec2::isNull() const
{
    return x == 0.0f && y == 0.0f;
}

bool vec2::operator==(const vec2 &other) const
{
    return x == other.x && y == other.y;
}

bool vec2::operator!=(const vec2 &other) const
{
    return x != other.x || y != other.y;
}

bool vec2::operator<(const vec2 &other) const
{
    return magnitude() < other.magnitude();
}

bool vec2::operator<=(const vec2 &other) const
{
    return magnitude() <= other.magnitude();
}

bool vec2::operator>(const vec2 &other) const
{
    return magnitude() > other.magnitude();
}

bool vec2::operator>=(const vec2 &other) const
{
    return magnitude() >= other.magnitude();
}

vec2 vec2::operator+(const vec2 &other) const
{
    return vec2(x + other.x, y + other.y);
}

vec2 vec2::operator-(const vec2 &other) const
{
    return vec2(x - other.x, y - other.y);
}

vec2 vec2::operator*(const vec2 &other) const
{
    return vec2(x * other.x, y * other.y);
}

vec2 vec2::operator*(const float &multiplier) const
{
    return vec2(x * multiplier, y * multiplier);
}

vec2 vec2::operator/(const vec2 &other) const
{
    return vec2(x / other.x, y / other.y);
}

vec2 vec2::operator/(const float &divider) const
{
    return vec2(x / divider, y / divider);
}

vec2 vec2::operator-() const
{
    return vec2(-x, -y);
}

}
}
