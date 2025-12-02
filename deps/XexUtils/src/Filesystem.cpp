#include "pch.h"
#include "Filesystem.h"

#include "Kernel.h"

namespace XexUtils
{
namespace Fs
{

HRESULT MountPath(const std::string &linkName, const std::string &devicePath)
{
    // The system only allows executables to access the directory they live in and binds it to
    // the "game:" drive. Nothing else is accessible unless you create a symbolic link.

    STRING link = {};
    STRING device = {};
    std::string userDestinationDrive = "\\??\\" + linkName;
    std::string systemDestinationDrive = "\\System??\\" + linkName;

    // Initialize the STRING structs
    if (KeGetCurrentProcessType() == PROC_TYPE_SYSTEM)
        RtlInitAnsiString(&link, systemDestinationDrive.c_str());
    else
        RtlInitAnsiString(&link, userDestinationDrive.c_str());

    RtlInitAnsiString(&device, devicePath.c_str());

    // Bind devicePath to the linkName.
    return ObCreateSymbolicLink(&link, &device);
}

HRESULT MountHdd()
{
    return MountPath("hdd:", "\\Device\\Harddisk0\\Partition1\\");
}

HRESULT MountUsb()
{
    return MountPath("usb:", "\\Device\\Mass0\\");
}

HRESULT UnmountPath(const std::string &linkName)
{
    STRING link = {};
    std::string userDestinationDrive = "\\??\\" + linkName;
    std::string systemDestinationDrive = "\\System??\\" + linkName;

    // Initialize the STRING structs
    if (KeGetCurrentProcessType() == PROC_TYPE_SYSTEM)
        RtlInitAnsiString(&link, systemDestinationDrive.c_str());
    else
        RtlInitAnsiString(&link, userDestinationDrive.c_str());

    // Remove the symbolic link
    return ObDeleteSymbolicLink(&link);
}

HRESULT UnmountHdd()
{
    return UnmountPath("hdd:");
}

HRESULT UnmountUsb()
{
    return UnmountPath("usb:");
}

const char Path::s_Separator = '\\';

Path::Path()
{
}

Path::Path(const std::string &path)
    : m_Path(path)
{
}

Path::Path(const char *path)
    : m_Path(path)
{
}

Path Path::Drive() const
{
    size_t colonPos = m_Path.find_first_of(':');

    if (colonPos == std::string::npos)
        return Path();

    return Path(m_Path.substr(0, colonPos + 1));
}

Path Path::Basename() const
{
    size_t lastSeparatorPos = m_Path.find_last_of(s_Separator);
    size_t lastDotPos = m_Path.find_last_of('.');
    size_t colonPos = m_Path.find_first_of(':');
    size_t characterBeforeFileNamePos = lastSeparatorPos != std::string::npos ? lastSeparatorPos : colonPos;

    // Case of path only containing a drive
    if (colonPos == m_Path.size() - 1)
        return Path();

    // Case of file name starting with a dot and no extension (like .gitignore)
    if (lastDotPos == characterBeforeFileNamePos + 1)
        return Path(m_Path.substr(characterBeforeFileNamePos + 1));

    return Path(m_Path.substr(characterBeforeFileNamePos + 1, lastDotPos - characterBeforeFileNamePos - 1));
}

Path Path::Extension() const
{
    size_t lastSeparatorPos = m_Path.find_last_of(s_Separator);
    size_t lastDotPos = m_Path.find_last_of('.');
    size_t colonPos = m_Path.find_first_of(':');
    size_t characterBeforeFileNamePos = lastSeparatorPos != std::string::npos ? lastSeparatorPos : colonPos;

    // No dot or dot is the first character of the file name (like .gitignore)
    if (lastDotPos == std::string::npos || lastDotPos == characterBeforeFileNamePos + 1)
        return Path();

    return Path(m_Path.substr(lastDotPos));
}

Path Path::Filename() const
{
    return Basename().String() + Extension().String();
}

Path Path::Parent() const
{
    if (IsEmpty())
        return Path();

    if (IsRoot())
        return *this;

    // When the path is a directory (so ends with the separator), we make the offset
    // to be one character before so that lastSeparatorPos doesn't point the very last
    // separator but the one before
    size_t offset = std::string::npos;
    if (m_Path.back() == s_Separator)
        offset = m_Path.size() - 2;

    size_t lastSeparatorPos = m_Path.find_last_of(s_Separator, offset);

    // Handle absolute path case
    if (lastSeparatorPos == 0)
        return Path(std::string(1, s_Separator));

    if (lastSeparatorPos == std::string::npos)
    {
        Path drive = Drive();
        if (!drive.IsEmpty())
            return drive;

        return Path();
    }

    return Path(m_Path.substr(0, lastSeparatorPos));
}

Path Path::RelativePath() const
{
    return m_Path.substr(Drive().Size());
}

Path &Path::Append(const Path &path)
{
    const std::string &otherAsString = path.String();
    const std::string &currentWithoutFinalSeparator = !IsEmpty() && m_Path.back() == s_Separator ? m_Path.substr(0, m_Path.size() - 1) : m_Path;
    const std::string &otherWithoutFirstSeparator = !path.IsEmpty() && otherAsString.front() == s_Separator ? otherAsString.substr(1) : otherAsString;

    m_Path = currentWithoutFinalSeparator + s_Separator + otherWithoutFirstSeparator;

    return *this;
}

bool Path::Compare(const Path &other) const
{
    return String() == other.String();
}

bool Path::IsEmpty() const
{
    return m_Path.empty();
}

bool Path::IsRoot() const
{
    if (IsEmpty())
        return true;

    // If the path is a path of a file it can't be the root of drive
    if (!Filename().IsEmpty())
        return false;

    size_t lastSeparatorPos = m_Path.find_last_of(s_Separator);
    size_t colonPos = m_Path.find_first_of(':');

    return colonPos == m_Path.size() - 1 || lastSeparatorPos == colonPos + 1;
}

const char *Path::c_str() const
{
    return m_Path.c_str();
}

size_t Path::Size() const
{
    return m_Path.size();
}

}
}
