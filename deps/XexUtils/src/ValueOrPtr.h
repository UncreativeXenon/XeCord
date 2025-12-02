#pragma once

namespace XexUtils
{

/// @brief A class to manipulate both a value and a pointer seemlessly.
/// @tparam T The underlying type to store a value or a pointer to.
template<typename T>
class ValueOrPtr
{
public:
    /// @brief Creates a `ValueOrPtr` from a value.
    /// @param value The value.
    ValueOrPtr(const T &value)
        : m_Value(value), m_Ptr(nullptr), m_IsPtr(false) {}

    /// @brief Creates a `ValueOrPtr` from a pointer.
    /// @param ptr The pointer.
    ValueOrPtr(T *ptr)
        : m_Value(T()), m_Ptr(ptr), m_IsPtr(true)
    {
        XASSERT(m_Ptr != nullptr);
    }

    /// @brief Dereference operator.
    /// @return The constant value or a constant copy of the value at the pointer.
    inline const T &operator*() const { return m_IsPtr ? *m_Ptr : m_Value; }

    /// @brief Dereference operator.
    /// @return The value or a copy of the value at the pointer.
    inline T &operator*() { return m_IsPtr ? *m_Ptr : m_Value; }

    /// @brief Address-of operator.
    /// @return The address of the value or the pointer.
    inline T *operator&() const { return m_IsPtr ? m_Ptr : const_cast<T *>(&m_Value); }

    /// @brief Conversion operator to type T.
    /// @return The value or the value at the pointer.
    inline operator T() const { return operator*(); }

    /// @brief Conversion operator to pointer of type T.
    /// @return The address of the value or the pointer.
    inline operator T *() const { return operator&(); }

    /// @brief Assignment operator.
    /// @param other The other `ValueOrPtr`.
    /// @return Reference to the current `ValueOrPtr`.
    inline ValueOrPtr<T> &operator=(const ValueOrPtr<T> &other)
    {
        operator*() = other;
        return *this;
    }

    /// @brief Unary minus operator.
    /// @return The negated value or the negated value at the pointer.
    inline ValueOrPtr<T> operator-() const { return -operator*(); }

    /// @brief Unary plus operator.
    /// @return The value or the value at the pointer.
    inline ValueOrPtr<T> operator+() const { return +operator*(); }

    /// @brief Bitwise NOT operator.
    /// @return The bitwise NOT of the value or the value at the pointer.
    inline ValueOrPtr<T> operator~() const { return ~operator*(); }

    /// @brief Addition assignment operator.
    /// @param value The value to add.
    /// @return Reference to the current `ValueOrPtr`.
    inline ValueOrPtr<T> &operator+=(const T &value)
    {
        operator*() += value;
        return *this;
    }

    /// @brief Subtraction assignment operator.
    /// @param value The value to subtract.
    /// @return Reference to the current `ValueOrPtr`.
    inline ValueOrPtr<T> &operator-=(const T &value)
    {
        operator*() -= value;
        return *this;
    }

    /// @brief Multiplication assignment operator.
    /// @param value The value to multiply by.
    /// @return Reference to the current `ValueOrPtr`.
    inline ValueOrPtr<T> &operator*=(const T &value)
    {
        operator*() *= value;
        return *this;
    }

    /// @brief Division assignment operator.
    /// @param value The value to divide by.
    /// @return Reference to the current `ValueOrPtr`.
    inline ValueOrPtr<T> &operator/=(const T &value)
    {
        operator*() /= value;
        return *this;
    }

    /// @brief Modulo assignment operator.
    /// @param value The value to take modulo of.
    /// @return Reference to the current `ValueOrPtr`.
    inline ValueOrPtr<T> &operator%=(const T &value)
    {
        operator*() %= value;
        return *this;
    }

    /// @brief Bitwise AND assignment operator.
    /// @param value The value to bitwise AND with.
    /// @return Reference to the current `ValueOrPtr`.
    inline ValueOrPtr<T> &operator&=(const T &value)
    {
        operator*() &= value;
        return *this;
    }

    /// @brief Bitwise OR assignment operator.
    /// @param value The value to bitwise OR with.
    /// @return Reference to the current `ValueOrPtr`.
    inline ValueOrPtr<T> &operator|=(const T &value)
    {
        operator*() |= value;
        return *this;
    }

    /// @brief Bitwise XOR assignment operator.
    /// @param value The value to bitwise XOR with.
    /// @return Reference to the current `ValueOrPtr`.
    inline ValueOrPtr<T> &operator^=(const T &value)
    {
        operator*() ^= value;
        return *this;
    }

    /// @brief Left shift assignment operator.
    /// @param value The value to left shift by.
    /// @return Reference to the current `ValueOrPtr`.
    inline ValueOrPtr<T> &operator<<=(const T &value)
    {
        operator*() <<= value;
        return *this;
    }

    /// @brief Right shift assignment operator.
    /// @param value The value to right shift by.
    /// @return Reference to the current `ValueOrPtr`.
    inline ValueOrPtr<T> &operator>>=(const T &value)
    {
        operator*() >>= value;
        return *this;
    }

    /// @brief Pre-increment operator.
    /// @return The incremented value or the incremented value at the pointer.
    inline ValueOrPtr<T> operator++() { return ++operator*(); }

    /// @brief Post-increment operator.
    /// @return The value or the value at the pointer before incrementing.
    inline ValueOrPtr<T> operator++(int) { return operator*()++; }

    /// @brief Pre-decrement operator.
    /// @return The decremented value or the decremented value at the pointer.
    inline ValueOrPtr<T> operator--() { return --operator*(); }

    /// @brief Post-decrement operator.
    /// @return The value or the value at the pointer before decrementing.
    inline ValueOrPtr<T> operator--(int) { return operator*()--; }

private:
    T m_Value;
    T *m_Ptr;
    bool m_IsPtr;
};

/// @brief Addition operator for two `ValueOrPtr` objects.
/// @tparam T The type of the values or pointers.
/// @param lhs The left-hand side `ValueOrPtr`.
/// @param rhs The right-hand side `ValueOrPtr`.
/// @return The result of the addition.
template<typename T>
inline ValueOrPtr<T> operator+(const ValueOrPtr<T> &lhs, const ValueOrPtr<T> &rhs)
{
    return *lhs + *rhs;
}

/// @brief Subtraction operator for two `ValueOrPtr` objects.
/// @tparam T The type of the values or pointers.
/// @param lhs The left-hand side `ValueOrPtr`.
/// @param rhs The right-hand side `ValueOrPtr`.
/// @return The result of the subtraction.
template<typename T>
inline ValueOrPtr<T> operator-(const ValueOrPtr<T> &lhs, const ValueOrPtr<T> &rhs)
{
    return *lhs - *rhs;
}

/// @brief Multiplication operator for two `ValueOrPtr` objects.
/// @tparam T The type of the values or pointers.
/// @param lhs The left-hand side `ValueOrPtr`.
/// @param rhs The right-hand side `ValueOrPtr`.
/// @return The result of the multiplication.
template<typename T>
inline ValueOrPtr<T> operator*(const ValueOrPtr<T> &lhs, const ValueOrPtr<T> &rhs)
{
    return *lhs * *rhs;
}

/// @brief Division operator for two `ValueOrPtr` objects.
/// @tparam T The type of the values or pointers.
/// @param lhs The left-hand side `ValueOrPtr`.
/// @param rhs The right-hand side `ValueOrPtr`.
/// @return The result of the division.
template<typename T>
inline ValueOrPtr<T> operator/(const ValueOrPtr<T> &lhs, const ValueOrPtr<T> &rhs)
{
    return *lhs / *rhs;
}

/// @brief Modulo operator for two `ValueOrPtr` objects.
/// @tparam T The type of the values or pointers.
/// @param lhs The left-hand side `ValueOrPtr`.
/// @param rhs The right-hand side `ValueOrPtr`.
/// @return The result of the modulo operation.
template<typename T>
inline ValueOrPtr<T> operator%(const ValueOrPtr<T> &lhs, const ValueOrPtr<T> &rhs)
{
    return *lhs % *rhs;
}

/// @brief Bitwise AND operator for two `ValueOrPtr` objects.
/// @tparam T The type of the values or pointers.
/// @param lhs The left-hand side `ValueOrPtr`.
/// @param rhs The right-hand side `ValueOrPtr`.
/// @return The result of the bitwise AND operation.
template<typename T>
inline ValueOrPtr<T> operator&(const ValueOrPtr<T> &lhs, const ValueOrPtr<T> &rhs)
{
    return *lhs & *rhs;
}

/// @brief Bitwise OR operator for two `ValueOrPtr` objects.
/// @tparam T The type of the values or pointers.
/// @param lhs The left-hand side `ValueOrPtr`.
/// @param rhs The right-hand side `ValueOrPtr`.
/// @return The result of the bitwise OR operation.
template<typename T>
inline ValueOrPtr<T> operator|(const ValueOrPtr<T> &lhs, const ValueOrPtr<T> &rhs)
{
    return *lhs | *rhs;
}

/// @brief Bitwise XOR operator for two `ValueOrPtr` objects.
/// @tparam T The type of the values or pointers.
/// @param lhs The left-hand side `ValueOrPtr`.
/// @param rhs The right-hand side `ValueOrPtr`.
/// @return The result of the bitwise XOR operation.
template<typename T>
inline ValueOrPtr<T> operator^(const ValueOrPtr<T> &lhs, const ValueOrPtr<T> &rhs)
{
    return *lhs ^ *rhs;
}

/// @brief Left shift operator for two `ValueOrPtr` objects.
/// @tparam T The type of the values or pointers.
/// @param lhs The left-hand side `ValueOrPtr`.
/// @param rhs The right-hand side `ValueOrPtr`.
/// @return The result of the left shift operation.
template<typename T>
inline ValueOrPtr<T> operator<<(const ValueOrPtr<T> &lhs, const ValueOrPtr<T> &rhs)
{
    return *lhs << *rhs;
}

/// @brief Right shift operator for two `ValueOrPtr` objects.
/// @tparam T The type of the values or pointers.
/// @param lhs The left-hand side `ValueOrPtr`.
/// @param rhs The right-hand side `ValueOrPtr`.
/// @return The result of the right shift operation.
template<typename T>
inline ValueOrPtr<T> operator>>(const ValueOrPtr<T> &lhs, const ValueOrPtr<T> &rhs)
{
    return *lhs >> *rhs;
}

/// @brief Equality operator for two `ValueOrPtr` objects.
/// @tparam T The type of the values or pointers.
/// @param lhs The left-hand side `ValueOrPtr`.
/// @param rhs The right-hand side `ValueOrPtr`.
/// @return `true` if the values or values at pointers are equal, `false` otherwise.
template<typename T>
inline bool operator==(const ValueOrPtr<T> &lhs, const ValueOrPtr<T> &rhs)
{
    return *lhs == *rhs;
}

/// @brief Inequality operator for two `ValueOrPtr` objects.
/// @tparam T The type of the values or pointers.
/// @param lhs The left-hand side `ValueOrPtr`.
/// @param rhs The right-hand side `ValueOrPtr`.
/// @return `true` if the values or values at pointers are not equal, `false` otherwise.
template<typename T>
inline bool operator!=(const ValueOrPtr<T> &lhs, const ValueOrPtr<T> &rhs)
{
    return *lhs != *rhs;
}

/// @brief Less than operator for two `ValueOrPtr` objects.
/// @tparam T The type of the values or pointers.
/// @param lhs The left-hand side `ValueOrPtr`.
/// @param rhs The right-hand side `ValueOrPtr`.
/// @return `true` if the left value or value at pointer is less than the right, `false`
/// otherwise.
template<typename T>
inline bool operator<(const ValueOrPtr<T> &lhs, const ValueOrPtr<T> &rhs)
{
    return *lhs < *rhs;
}

/// @brief Less than or equal to operator for two `ValueOrPtr` objects.
/// @tparam T The type of the values or pointers.
/// @param lhs The left-hand side `ValueOrPtr`.
/// @param rhs The right-hand side `ValueOrPtr`.
/// @return `true` if the left value or value at pointer is less than or equal to the
/// right, `false` otherwise.
template<typename T>
inline bool operator<=(const ValueOrPtr<T> &lhs, const ValueOrPtr<T> &rhs)
{
    return *lhs <= *rhs;
}

/// @brief Greater than operator for two `ValueOrPtr` objects.
/// @tparam T The type of the values or pointers.
/// @param lhs The left-hand side `ValueOrPtr`.
/// @param rhs The right-hand side `ValueOrPtr`.
/// @return `true` if the left value or value at pointer is greater than the right,
/// `false` otherwise.
template<typename T>
inline bool operator>(const ValueOrPtr<T> &lhs, const ValueOrPtr<T> &rhs)
{
    return *lhs > *rhs;
}

/// @brief Greater than or equal to operator for two `ValueOrPtr` objects.
/// @tparam T The type of the values or pointers.
/// @param lhs The left-hand side `ValueOrPtr`.
/// @param rhs The right-hand side `ValueOrPtr`.
/// @return `true` if the left value or value at pointer is greater than or equal to the
/// right, `false` otherwise.
template<typename T>
inline bool operator>=(const ValueOrPtr<T> &lhs, const ValueOrPtr<T> &rhs)
{
    return *lhs >= *rhs;
}

/// @brief Stream insertion operator for `ValueOrPtr` objects.
/// @tparam T The type of the values or pointers.
/// @param os The output stream.
/// @param value The `ValueOrPtr` to output.
/// @return The output stream with the `ValueOrPtr`'s value inserted.
template<typename T>
inline std::ostream &operator<<(std::ostream &os, const ValueOrPtr<T> &value)
{
    return os << *value;
}

}
