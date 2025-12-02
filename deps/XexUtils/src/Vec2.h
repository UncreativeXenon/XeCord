#pragma once

namespace XexUtils
{
namespace Math
{

/// @brief A structure representing a two-component vector.
struct vec2
{
    /// @brief Creates an empty vector, with `x` and `y` set to `0.0f`.
    vec2();

    /// @brief Creates a vector from `x` and `y`.
    /// @param x The first component.
    /// @param y The second component.
    vec2(float x, float y);

// Disable the C4201 warning for nameless union/struct
#pragma warning(push)
#pragma warning(disable : 4201)

    union {
        struct
        {
            /// @brief The first component.
            float x;

            /// @brief The second component.
            float y;
        };

        struct
        {
            /// @brief The first component.
            float r;

            /// @brief The second component.
            float g;
        };
    };

#pragma warning(pop)

    /// @brief Calculates the magnitude of the vector.
    /// @return The magnitude.
    float magnitude() const;

    /// @brief Normalizes each component of the vector to a value between `0` and `1`.
    /// @return A new normalized vector.
    vec2 normalize() const;

    /// @brief Adds the `other` vector to the current vector.
    /// @param other The other vector.
    void add(const vec2 &other);

    /// @brief Substracts the `other` vector from the current vector.
    /// @param other The other vector.
    void substract(const vec2 &other);

    /// @brief Multiplies the current vector by the `other` vector.
    /// @param other The other vector.
    void multiply(const vec2 &other);

    /// @brief Multiplies each component of the vector by a scalar.
    /// @param multiplier The scalar.
    void multiply(const float &multiplier);

    /// @brief Divides the current vector by the `other` vector.
    /// @param other The other vector.
    void divide(const vec2 &other);

    /// @brief Divides the current vector by a scalar.
    /// @param divider The scalar.
    void divide(const float &divider);

    /// @brief Checks wether each component of the vector is equal to `0.0f` or not.
    /// @return `true` when each component of the vector is `0.0f`, `false` otherwise.
    bool isNull() const;

    /// @brief Equality operator.
    /// @param other The other vector.
    /// @return `true` if the current vector is equal to the `other` vector, `false`
    /// otherwise.
    bool operator==(const vec2 &other) const;

    /// @brief Inequality operator.
    /// @param other The other vector.
    /// @return `true` if the current vector is not equal to the `other` vector, `false`
    /// otherwise.
    bool operator!=(const vec2 &other) const;

    /// @brief Less than operator.
    /// @param other The other vector.
    /// @return `true` if the magnitude of the current vector is less than the magnitude
    /// of the `other` vector, `false` otherwise.
    bool operator<(const vec2 &other) const;

    /// @brief Less than or equal to operator.
    /// @param other The other vector.
    /// @return `true` if the magnitude of the current vector is less than or equal to the
    /// magnitude of the `other` vector, `false` otherwise.
    bool operator<=(const vec2 &other) const;

    /// @brief Greater than operator.
    /// @param other The other vector.
    /// @return `true` if the magnitude of the current vector is greater than the magnitude
    /// of the `other` vector, `false` otherwise.
    bool operator>(const vec2 &other) const;

    /// @brief Greater than or equal to operator.
    /// @param other The other vector.
    /// @return `true` if the magnitude of the current vector is greater than or equal to the
    /// magnitude of the `other` vector, `false` otherwise.
    bool operator>=(const vec2 &other) const;

    /// @brief Adds the `other` vector to the current vector and returns a new vector.
    /// @param other The other vector.
    /// @return A new vector.
    vec2 operator+(const vec2 &other) const;

    /// @brief Substracts the `other` vector from the current vector and returns a new vector.
    /// @param other The other vector.
    /// @return A new vector.
    vec2 operator-(const vec2 &other) const;

    /// @brief Multiplies the current vector by the `other` vector and returns a new vector.
    /// @param other The other vector.
    /// @return A new vector.
    vec2 operator*(const vec2 &other) const;

    /// @brief Multiplies each component of the vector by a scalar and returns a new vector.
    /// @param multiplier The scalar.
    /// @return A new vector.
    vec2 operator*(const float &multiplier) const;

    /// @brief Divides the current vector by the `other` vector and returns a new vector.
    /// @param other The other vector.
    /// @return A new vector.
    vec2 operator/(const vec2 &other) const;

    /// @brief Divides the current vector by a scalar and returns a new vector.
    /// @param divider The scalar.
    /// @return A new vector.
    vec2 operator/(const float &divider) const;

    /// @brief Unary negation operator.
    /// @return A new negated vector.
    vec2 operator-() const;
};

}
}
