#pragma once

/// @file Kernel.h
///
/// A list of functions exported by `xboxkrnl.exe` and the associated structures to use
/// them. Most of those were taken from xkelib.
///
///
/// Notes about flag naming conventions:
///
/// A common pattern for flags is to create a `typedef` between `uint32_t` and the flag
/// type name, define an enum named like the flag but follow by an underscore (_), and then
/// the flag values are all prefixed by the enum name. For example:
/// ```
/// typedef uint32_t MY_FLAG;
/// enum MY_FLAG_
/// {
///     MY_FLAG_NONE = 0,
///     MY_FLAG_FIRST = 1 << 0,
///     MY_FLAG_SECOND = 1 << 1,
/// };
/// ```
/// The whole point of this convention is to be autocompletion friendly. If a function
/// takes a `MY_FLAG` argument, the user should be able to type `MY_FLAG_` and see all the
/// possible values. This convention is inspired by how Dear ImGui names its flags.
/// It isn't 100% applied for flags taken from Win32/NT APIs because I wanted to preserve
/// the name Microsoft gave them, so that values can also be found from the official
/// Microsoft documentation.

// Found here:
// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/596a1078-e883-4972-9bbc-49e60bebca55
typedef enum _NTSTATUS
{
    STATUS_SUCESS = 0x00000000,
    STATUS_NO_MORE_FILES = 0x80000006,
    STATUS_OBJECT_NAME_COLLISION = 0xC0000035,
    STATUS_DIRECTORY_NOT_EMPTY = 0xC0000101,
    STATUS_NO_MORE_ENTRIES = 0x8000001A,
} NTSTATUS;

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

#define EXPORTNUM(x)

// Disable the C4201 warning for nameless union/struct
#pragma warning(push)
#pragma warning(disable : 4201)

struct XBOX_HARDWARE_INFO
{
    uint32_t Flags;
    uint8_t NumberOfProcessors;
    uint8_t PCIBridgeRevisionID;
    uint8_t Reserved[6];
    uint16_t BldrMagic;
    uint16_t BldrFlags;
};

struct XBOX_KRNL_VERSION
{
    uint16_t Major;
    uint16_t Minor;
    uint16_t Build;
    uint16_t Qfe;
};

typedef uint32_t EXCREATETHREAD_FLAG;

enum EXCREATETHREAD_FLAG_
{
    EXCREATETHREAD_FLAG_SUSPENDED = 1 << 0,
    EXCREATETHREAD_FLAG_SYSTEM = 1 << 1,
    EXCREATETHREAD_FLAG_TLS_STATIC = 1 << 3,
    EXCREATETHREAD_FLAG_PRIORITY1 = 1 << 5,
    EXCREATETHREAD_FLAG_PRIORITY0 = 1 << 6,
    EXCREATETHREAD_FLAG_RETURN_KTHREAD = 1 << 7,
    EXCREATETHREAD_FLAG_TITLE_EXEC = 1 << 8,
    EXCREATETHREAD_FLAG_HIDDEN = 1 << 10,
    EXCREATETHREAD_FLAG_CORE0 = 1 << 24,
    EXCREATETHREAD_FLAG_CORE1 = 1 << 25,
    EXCREATETHREAD_FLAG_CORE2 = 1 << 26,
    EXCREATETHREAD_FLAG_CORE3 = 1 << 27,
    EXCREATETHREAD_FLAG_CORE4 = 1 << 28,
    EXCREATETHREAD_FLAG_CORE5 = 1 << 29,
};

struct STRING
{
    uint16_t Length;
    uint16_t MaxLength;
    char *Buffer;
};

struct UNICODE_STRING
{
    uint16_t Length;
    uint16_t MaxLength;
    wchar_t *Buffer;
};

struct LDR_DATA_TABLE_ENTRY
{
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InClosureOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    void *NtHeadersBase;
    void *ImageBase;
    uint32_t SizeOfNtImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    uint32_t Flags;
    uint32_t SizeOfFullImage;
    void *EntryPoint;
    uint16_t LoadCount;
    uint16_t ModuleIndex;
    void *DllBaseOriginal;
    uint32_t CheckSum;
    uint32_t ModuleLoadFlags;
    uint32_t TimeDateStamp;
    void *LoadedImports;
    void *XexHeaderBase;

    union {
        STRING LoadFileName;

        struct
        {
            void *ClosureRoot;
            void *TraversalParent;
        };
    };
};

struct XEX_IMPORT_TABLE
{
    uint32_t TableSize;
    uint8_t NextImportDigest[20];
    uint32_t ModuleNumber;
    uint32_t Version[2];
    uint8_t Unused;
    uint8_t ModuleIndex;
    uint16_t ImportCount;
    uint32_t ImportStubAddr[1];
};

struct XEX_IMPORT_DESCRIPTOR
{
    uint32_t Size;
    uint32_t NameTableSize;
    uint32_t ModuleCount;
};

#pragma pack(push, 1)

union XBOX32VER {
    struct
    {
        uint8_t Major : 4;
        uint8_t Minor : 4;
        uint16_t Build;
        uint8_t Qfe;
    };

    uint32_t AsULong;
};

#pragma pack(pop)

struct XEX_EXECUTION_ID
{
    uint32_t MediaId;
    XBOX32VER Version;
    XBOX32VER BaseVersion;

    union {
        uint32_t TitleId;

        struct
        {
            uint16_t PublisherId;
            uint16_t GameId;
        };
    };

    uint8_t Platform;
    uint8_t ExecutableType;
    uint8_t DiscNum;
    uint8_t DiscsInSet;
    uint32_t SaveGameId;
};

struct IMAGE_XEX_HEADER
{
    char Magic[4];
    uint32_t ModuleFlags;
    uint32_t SizeOfHeaders;
    uint32_t SizeOfDiscardableHeaders;
    uint32_t SecurityInfo;
    uint32_t HeaderDirectoryEntryCount;
};

struct XEX_VITAL_STATS
{
    uint32_t Checksum;
    uint32_t Timestamp;
};

typedef enum _FIRMWARE_REENTRY
{
    HalHaltRoutine,
    HalRebootRoutine,
    HalKdRebootRoutine,
    HalFatalErrorRebootRoutine,
    HalResetSMCRoutine,
    HalPowerDownRoutine,
    HalRebootQuiesceRoutine,
    HalForceShutdownRoutine,
    HalPowerCycleQuiesceRoutine,
    HalMaximumRoutine,
} FIRMWARE_REENTRY;

typedef enum _PROC_TYPE
{
    PROC_TYPE_IDLE,
    PROC_TYPE_USER,
    PROC_TYPE_SYSTEM,
} PROC_TYPE;

typedef uint32_t OBJECT_ATTRIBUTE;

enum OBJECT_ATTRIBUTE_
{
    OBJ_CASE_INSENSITIVE = 1 << 6,
};

struct OBJECT_ATTRIBUTES
{
    HANDLE RootDirectory;
    STRING *ObjectName;
    OBJECT_ATTRIBUTE Attributes;
};

typedef enum _OBJECT_TYPE
{
    OBJECT_TYPE_SYMLINK = 0x626d7953,
    OBJECT_TYPE_DIRECTORY = 0x65726944,
    OBJECT_TYPE_DEVICE = 0x69766544,
    OBJECT_TYPE_EVENT = 0x76657645,
    OBJECT_TYPE_DEBUG = 0x63706d64,
} OBJECT_TYPE;

struct OBJECT_DIRECTORY_INFORMATION
{
    STRING Name;
    OBJECT_TYPE Type;
};

struct IO_STATUS_BLOCK
{
    union {
        NTSTATUS Status;
        void *Pointer;
    };

    uintptr_t Information;
};

#define InitializeObjectAttributes(p, name, attrib, root) \
    { \
        (p)->RootDirectory = root; \
        (p)->Attributes = attrib; \
        (p)->ObjectName = name; \
    }

typedef uint32_t FILE_ATTRIBUTE;
typedef uint32_t FILE_SHARE;

typedef uint32_t CREATE_OPTION;
typedef CREATE_OPTION OPEN_OPTION;

enum CREATE_OPTION_
{
    FILE_DIRECTORY_FILE = 0x00000001,
    FILE_SYNCHRONOUS_IO_NONALERT = 0x00000020,
};

typedef enum _CREATE_DISPOSITION
{
    FILE_SUPERSEDE = 0x00000000,
    FILE_OPEN = 0x00000001,
    FILE_CREATE = 0x00000002,
    FILE_OPEN_IF = 0x00000003,
    FILE_OVERWRITE = 0x00000004,
    FILE_OVERWRITE_IF = 0x00000005,
    FILE_MAXIMUM_DISPOSITION = 0x00000005,
} CREATE_DISPOSITION;

struct FILE_FS_SIZE_INFORMATION
{
    LARGE_INTEGER TotalAllocationUnits;
    LARGE_INTEGER AvailableAllocationUnits;
    uint32_t SectorsPerAllocationUnit;
    uint32_t BytesPerSector;
};

typedef enum _FS_INFORMATION_CLASS
{
    FileFsVolumeInformation = 1,
    FileFsLabelInformation,
    FileFsSizeInformation,
    FileFsDeviceInformation,
    FileFsAttributeInformation,
    FileFsControlInformation,
    FileFsFullSizeInformation,
    FileFsObjectIdInformation,
    FileFsMaximumInformation,
} FS_INFORMATION_CLASS;

struct FILE_DIRECTORY_INFORMATION
{
    uint32_t NextEntryOffset;
    uint32_t FileIndex;
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER EndOfFile;
    LARGE_INTEGER AllocationSize;
    FILE_ATTRIBUTE FileAttributes;
    uint32_t FileNameLength;
    char FileName[1];
};

struct FILE_RENAME_INFORMATION
{
    bool ReplaceIfExists;
    HANDLE RootDirectory;
    STRING FileName;
};

struct FILE_NETWORK_OPEN_INFORMATION
{
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER AllocationSize;
    LARGE_INTEGER EndOfFile;
    FILE_ATTRIBUTE FileAttributes;
};

typedef enum _FILE_INFORMATION_CLASS
{
    FileDirectoryInformation = 1,
    FileFullDirectoryInformation,
    FileBothDirectoryInformation,
    FileBasicInformation,
    FileStandardInformation,
    FileInternalInformation,
    FileEaInformation,
    FileAccessInformation,
    FileNameInformation,
    FileRenameInformation,
    FileLinkInformation,
    FileNamesInformation,
    FileDispositionInformation,
    FilePositionInformation,
    FileFullEaInformation,
    FileModeInformation,
    FileAlignmentInformation,
    FileAllInformation,
    FileAllocationInformation,
    FileEndOfFileInformation,
    FileAlternateNameInformation,
    FileStreamInformation,
    FilePipeInformation,
    FilePipeLocalInformation,
    FilePipeRemoteInformation,
    FileMailslotQueryInformation,
    FileMailslotSetInformation,
    FileCompressionInformation,
    FileObjectIdInformation,
    FileCompletionInformation,
    FileMoveClusterInformation,
    FileQuotaInformation,
    FileReparsePointInformation,
    FileNetworkOpenInformation,
    FileAttributeTagInformation,
    FileTrackingInformation,
    FileMaximumInformation,
} FILE_INFORMATION_CLASS;

typedef enum _XEX_HEADER_FIELD
{
    XEX_HEADER_FIELD_IMPORT_DESCRIPTOR = 0x103FF,
    XEX_HEADER_FIELD_VITAL_STATS = 0x18002,
    XEX_HEADER_FIELD_EXECUTION_ID = 0x40006,
} XEX_HEADER_FIELD;

typedef uint32_t XEX_LOADING_FLAG;

enum XEX_LOADING_FLAG_
{
    XEX_LOADING_FLAG_TITLE_PROCESS = 1 << 0,
    XEX_LOADING_FLAG_TITLE_IMPORTS = 1 << 1,
    XEX_LOADING_FLAG_DEBUGGER = 1 << 2,
    XEX_LOADING_FLAG_DLL = 1 << 3,
    XEX_LOADING_FLAG_PATCH = 1 << 4,
    XEX_LOADING_FLAG_PATCH_FULL = 1 << 5,
    XEX_LOADING_FLAG_PATCH_DELTA = 1 << 6,
    XEX_LOADING_FLAG_BOUND_PATH = 1 << 30,
    XEX_LOADING_FLAG_SILENT_LOAD = 1 << 31,
    XEX_LOADING_FLAG_TITLE = XEX_LOADING_FLAG_TITLE_PROCESS,
    XEX_LOADING_FLAG_TITLE_DLL = XEX_LOADING_FLAG_TITLE_PROCESS | XEX_LOADING_FLAG_DLL,
    XEX_LOADING_FLAG_SYSTEM_APP = XEX_LOADING_FLAG_DLL,
    XEX_LOADING_FLAG_SYSTEM_DLL = XEX_LOADING_FLAG_DLL | XEX_LOADING_FLAG_TITLE_IMPORTS,
};

struct KEXCEPTION_FRAME
{
    uint32_t Status;
    uint32_t Unknown1;
    uint32_t Unknown2;
    uint32_t Unknown3;
    BOOL Continuable;
    uint32_t ExceptionInformation[32];
};

typedef BOOL (*TRAPHANDLER)(void *pUnknown, KEXCEPTION_FRAME *pExceptionFrame, CONTEXT *pContext, BOOL secondChance);

#pragma warning(pop) // Disable C4201

#define __isync() __emit(0x4C00012C)

#define doSync(addr) \
    __dcbst(0, addr); \
    __sync(); \
    __isync()

EXPORTNUM(342)
extern "C" XBOX_HARDWARE_INFO *XboxHardwareInfo;

EXPORTNUM(343)
extern "C" XBOX_KRNL_VERSION *XboxKrnlBaseVersion;

EXPORTNUM(344)
extern "C" XBOX_KRNL_VERSION *XboxKrnlVersion;

EXPORTNUM(403)
extern "C" HANDLE *XexExecutableModuleHandle;

EXPORTNUM(431)
extern "C" const char *ExLoadedImageName;

extern "C"
{
    EXPORTNUM(13)
    uint32_t ExCreateThread(
        HANDLE *pHandle,
        uint32_t stackSize,
        uint32_t *pThreadId,
        void *pApiThreadStartup,
        PTHREAD_START_ROUTINE pStartAddress,
        void *pParameter,
        EXCREATETHREAD_FLAG creationFlags
    );

    EXPORTNUM(40)
    void HalReturnToFirmware(
        FIRMWARE_REENTRY powerDownMode
    );

    EXPORTNUM(41)
    void HalSendSMCMessage(
        void *pInput,
        void *pOutput
    );

    EXPORTNUM(102)
    PROC_TYPE KeGetCurrentProcessType(
        void
    );

    EXPORTNUM(190)
    void *MmGetPhysicalAddress(
        void *pAddress
    );

    EXPORTNUM(191)
    bool MmIsAddressValid(
        const void *pAddress
    );

    EXPORTNUM(207)
    NTSTATUS NtClose(
        HANDLE Handle
    );

    EXPORTNUM(210)
    NTSTATUS NtCreateFile(
        HANDLE *pHandle,
        ACCESS_MASK desiredAccess,
        OBJECT_ATTRIBUTES *pObjectAttributes,
        IO_STATUS_BLOCK *pIoStatusBlock,
        LARGE_INTEGER *pAllocationSize,
        FILE_ATTRIBUTE fileAttributes,
        FILE_SHARE shareAccess,
        CREATE_DISPOSITION createDisposition,
        CREATE_OPTION createOptions
    );

    EXPORTNUM(216)
    NTSTATUS NtDeleteFile(
        OBJECT_ATTRIBUTES *pObjectAttributes
    );

    EXPORTNUM(222)
    NTSTATUS NtOpenDirectoryObject(
        HANDLE *pDirectoryHandle,
        OBJECT_ATTRIBUTES *pObjectAttributes
    );

    EXPORTNUM(223)
    NTSTATUS NtOpenFile(
        HANDLE *pHandle,
        ACCESS_MASK desiredAccess,
        OBJECT_ATTRIBUTES *pObjectAttributes,
        IO_STATUS_BLOCK *pIoStatusBlock,
        FILE_SHARE shareAccess,
        OPEN_OPTION openOptions
    );

    EXPORTNUM(224)
    NTSTATUS NtOpenSymbolicLinkObject(
        HANDLE *pLinkHandle,
        OBJECT_ATTRIBUTES *pObjectAttributes
    );

    EXPORTNUM(228)
    NTSTATUS NtQueryDirectoryFile(
        HANDLE handle,
        HANDLE event,
        void *pApcRoutine,
        void *pApcContext,
        IO_STATUS_BLOCK *pIoStatusBlock,
        void *pFileInformation,
        uint32_t length,
        STRING *pFileMask,
        BOOL restartScan
    );

    EXPORTNUM(229)
    NTSTATUS NtQueryDirectoryObject(
        HANDLE directoryHandle,
        void *pBuffer,
        size_t length,
        bool restartScan,
        uint32_t *pContext,
        uint32_t *pReturnLength
    );

    EXPORTNUM(231)
    NTSTATUS NtQueryFullAttributesFile(
        OBJECT_ATTRIBUTES *pObjectAttributes,
        FILE_NETWORK_OPEN_INFORMATION *pAttributes
    );

    EXPORTNUM(232)
    NTSTATUS NtQueryInformationFile(
        HANDLE handle,
        IO_STATUS_BLOCK *pIoStatusBlock,
        void *pFileInformation,
        uint32_t Length,
        FILE_INFORMATION_CLASS fileInformationClass
    );

    EXPORTNUM(236)
    NTSTATUS NtQuerySymbolicLinkObject(
        HANDLE linkHandle,
        STRING *pLinkTarget,
        uint32_t *pReturnedLength
    );

    EXPORTNUM(239)
    NTSTATUS NtQueryVolumeInformationFile(
        HANDLE handle,
        IO_STATUS_BLOCK *pIoStatusBlock,
        void *pFsInformation,
        uint32_t length,
        FS_INFORMATION_CLASS fsInformationClass
    );

    EXPORTNUM(240)
    NTSTATUS NtReadFile(
        HANDLE handle,
        HANDLE event,
        void *pApcRoutine,
        void *pApcContext,
        IO_STATUS_BLOCK *pIoStatusBlock,
        void *buffer,
        uint32_t length,
        LARGE_INTEGER *pByteOffset
    );

    EXPORTNUM(247)
    NTSTATUS NtSetInformationFile(
        HANDLE handle,
        IO_STATUS_BLOCK *pIoStatusBlock,
        void *pFileInformation,
        uint32_t length,
        FILE_INFORMATION_CLASS fileInformationClass
    );

    EXPORTNUM(255)
    NTSTATUS NtWriteFile(
        HANDLE handle,
        HANDLE event,
        void *pApcRoutine,
        void *pApcContext,
        IO_STATUS_BLOCK *pIoStatusBlock,
        void *buffer,
        uint32_t length,
        LARGE_INTEGER *pByteOffset
    );

    EXPORTNUM(259)
    NTSTATUS ObCreateSymbolicLink(
        STRING *pLinkName,
        STRING *pDevicePath
    );

    EXPORTNUM(260)
    NTSTATUS ObDeleteSymbolicLink(
        STRING *pLinkName
    );

    EXPORTNUM(299)
    void *RtlImageXexHeaderField(
        void *pXexHeaderBase,
        XEX_HEADER_FIELD imageField
    );

    EXPORTNUM(300)
    void RtlInitAnsiString(
        STRING *pDestinationString,
        const char *sourceString
    );

    EXPORTNUM(394)
    void XeCryptRandom(
        uint8_t *pBytes,
        size_t count
    );

    EXPORTNUM(409)
    NTSTATUS XexLoadImage(
        const char *imageName,
        XEX_LOADING_FLAG flags,
        uint32_t minVersion,
        HANDLE *pHandle
    );

    EXPORTNUM(417)
    NTSTATUS XexUnloadImage(
        HANDLE handle
    );
}
