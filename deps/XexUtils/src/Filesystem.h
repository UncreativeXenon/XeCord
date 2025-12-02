#pragma once

namespace XexUtils
{
namespace Fs
{

/// @brief Allows the current process to access other storage devices or partitions.
/// @param linkName The symbolic link name (e.g. hdd:).
/// @param devicePath The full device path (e.g. \Device\Harddisk0\Partition1\).
/// @return `S_OK` on success, an `NTSTATUS` error on error.
HRESULT MountPath(const std::string &linkName, const std::string &devicePath);

/// @brief Allows the current process to access the hard drive using the `hdd:` drive name.
/// @return `S_OK` on success, an `NTSTATUS` error on error.
HRESULT MountHdd();

/// @brief Allows the current process to access the first USB stick using the `usb:` drive name.
/// @return `S_OK` on success, an `NTSTATUS` error on error.
HRESULT MountUsb();

/// @brief Removes a symbolic link previously created with `MountPath`.
/// @param linkName The symbolic link name (e.g. hdd:).
/// @return `S_OK` on success, an `NTSTATUS` error on error.
HRESULT UnmountPath(const std::string &linkName);

/// @brief Removes the `hdd:` symbolic link previously created with `MountHdd`.
/// @return `S_OK` on success, an `NTSTATUS` error on error.
HRESULT UnmountHdd();

/// @brief Removes the `usb:` symbolic link previously created with `MountUsb`.
/// @return `S_OK` on success, an `NTSTATUS` error on error.
HRESULT UnmountUsb();

/// @brief A class representing a file system path.
class Path
{
public:
    /// @brief Creates an empty `Path`.
    Path();

    /// @brief Creates a `Path` object from a given string.
    /// @param path The string representing the path.
    Path(const std::string &path);

    /// @brief Creates a `Path` object from a given string.
    /// @param path The string representing the path.
    Path(const char *path);

    /// @brief Concatenates a generic type with a `Path` object.
    /// @tparam T The type of the left operand.
    /// @param left The left operand of the concatenation.
    /// @param path The `Path` object to concatenate.
    /// @return The resulting string from the concatenation.
    template<typename T>
    inline friend Path operator+(const T &left, const Path &path)
    {
        return left + path.String();
    }

    /// @brief Concatenates a `Path` object with a generic type.
    /// @tparam T The type of the right operand.
    /// @param path The `Path` object to concatenate.
    /// @param right The right operand of the concatenation.
    /// @return The resulting string from the concatenation.
    template<typename T>
    inline friend Path operator+(const Path &path, const T &right)
    {
        return path.String() + right;
    }

    /// @brief Outputs the `Path` object to an output stream.
    /// @param stream The output stream.
    /// @param path The `Path` object to output.
    /// @return The output stream with the `Path` object's string representation.
    inline friend std::ostream &operator<<(std::ostream &stream, const Path &path)
    {
        return stream << path.String();
    }

    /// @brief Appends a `Path` to the current `Path` object.
    /// @param path The `Path` to append.
    /// @return A reference to the modified `Path` object.
    inline Path &operator/=(const Path &path)
    {
        return Append(path);
    }

    /// @brief Combines two `Path` objects.
    /// @param path The left `Path` object.
    /// @param right The right `Path` object.
    /// @return The resulting `Path` from the combination.
    friend Path operator/(const Path &path, const Path &right)
    {
        Path tmp = path;
        tmp /= right;
        return tmp;
    }

    /// @brief Compares two `Path` objects for equality.
    /// @param left The left `Path` object.
    /// @param right The right `Path` object.
    /// @return `true` if the `Path` objects are equal, `false` otherwise.
    inline friend bool operator==(const Path &left, const Path &right)
    {
        return left.Compare(right);
    }

    /// @brief Compares a generic type with a `Path` for equality.
    /// @tparam T The type of left operand.
    /// @param left The left operand of the comparison.
    /// @param right The `Path` to compare.
    /// @return `true` if the operands are equal, `false` otherwise.
    template<typename T>
    inline friend bool operator==(const T &left, const Path &right)
    {
        return left == right.String();
    }

    /// @brief Compares a `Path` with a generic type for equality.
    /// @tparam T The type of right operand.
    /// @param left The `Path` to compare.
    /// @param right The right operand of the comparison.
    /// @return `true` if the operands are equal, `false` otherwise.
    template<typename T>
    inline friend bool operator==(const Path &left, const T &right)
    {
        return left.String() == right;
    }

    /// @brief Compares two `Path` objects for inequality.
    /// @param left The left `Path` object.
    /// @param right The right `Path` object.
    /// @return `true` if the `Path` objects are not equal, `false` otherwise.
    inline friend bool operator!=(const Path &left, const Path &right)
    {
        return !(left == right);
    }

    /// @brief Compares a generic type with a `Path` for inequality.
    /// @tparam T The type of left operand.
    /// @param left The left operand of the comparison.
    /// @param right The `Path` to compare.
    /// @return `true` if the operands are not equal, `false` otherwise.
    template<typename T>
    inline friend bool operator!=(const T &left, const Path &right)
    {
        return left != right.String();
    }

    /// @brief Compares a `Path` with a generic type for inequality.
    /// @tparam T The type of right operand.
    /// @param left The `Path` to compare.
    /// @param right The right operand of the comparison.
    /// @return `true` if the operands are not equal, `false` otherwise.
    template<typename T>
    inline friend bool operator!=(const Path &left, const T &right)
    {
        return left.String() != right;
    }

    /// @brief Gets the string representation of the `Path`.
    /// @return The string representation of the `Path`.
    inline const std::string &String() const { return m_Path; }

    /// @brief Gets the drive part of the `Path`.
    /// @return The drive part of the `Path`.
    Path Drive() const;

    /// @brief Gets the basename part of the `Path`.
    /// @return The basename part of the `Path`.
    Path Basename() const;

    /// @brief Gets the extension part of the `Path`.
    /// @return The extension part of the `Path`.
    Path Extension() const;

    /// @brief Gets the filename part of the `Path`.
    /// @return The filename part of the `Path`.
    Path Filename() const;

    /// @brief Gets the parent directory part of the `Path`.
    /// @return The parent directory part of the `Path`.
    Path Parent() const;

    /// @brief Gets a `Path` that is relative to the drive. In other words, `*this`
    /// without the drive.
    /// @return A `Path` relative to the drive.
    Path RelativePath() const;

    /// @brief Appends a `Path` to the current `Path` object.
    /// @param path The `Path` to append.
    /// @return A reference to the modified `Path` object.
    Path &Append(const Path &path);

    /// @brief Compares the current `Path` object with another `Path` object.
    /// @param other The other `Path` object to compare with.
    /// @return `true` if the `Path` objects are equal, `false` otherwise.
    bool Compare(const Path &other) const;

    /// @brief Checks if the `Path` is empty.
    /// @return `true` if the `Path` is empty, `false` otherwise.
    bool IsEmpty() const;

    /// @brief Checks if the `Path` is a root path.
    /// @return `true` if the `Path` is a root path, `false` otherwise.
    bool IsRoot() const;

    /// @brief Calls `.c_str()` on the underlying `std::string`.
    /// @return The result of `.c_str()` on the underlying `std::string`.
    const char *c_str() const;

    /// @brief Returns the size of the underlying `std::string`.
    /// @return The size of the underlying `std::string`.
    size_t Size() const;

private:
    std::string m_Path;

    static const char s_Separator;
};

}
}
