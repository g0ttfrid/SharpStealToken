using System;
using System.Runtime.InteropServices;
using System.Text;

namespace SharpStealToken
{
    public static class Class1
    {

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool RevertToSelf();

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool ImpersonateLoggedOnUser(IntPtr hToken);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool CloseHandle(IntPtr handle);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern bool PrivilegeCheck(IntPtr ClientToken, ref PRIVILEGE_SET RequiredPrivileges, out bool pfResult);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, out LUID lpLuid);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool OpenProcessToken(IntPtr ProcessHandle, TOKEN_ACCESS_MASK DesiredAccess, out IntPtr TokenHandle);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges, ref TOKEN_PRIVILEGES NewState, uint BufferLength, IntPtr PreviousState, IntPtr ReturnLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr GetCurrentProcess();

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public extern static bool DuplicateTokenEx(
            IntPtr hExistingToken,
            TOKEN_ACCESS_MASK dwDesiredAccess,
            ref SECURITY_ATTRIBUTES lpTokenAttributes,
            SECURITY_IMPERSONATION_LEVEL ImpersonationLevel,
            TOKEN_TYPE TokenType,
            out IntPtr phNewToken);

        [DllImport("advapi32", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool CreateProcessWithTokenW(
            IntPtr hToken,
            UInt32 dwLogonFlags,
            string lpApplicationName,
            string lpCommandLine,
            UInt32 dwCreationFlags,
            IntPtr lpEnvironment,
            string lpCurrentDirectory,
            [In] ref STARTUPINFO lpStartupInfo,
            out PROCESS_INFORMATION lpProcessInformation);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct PROFILEINFO
        {
            public int dwSize;
            public int dwFlags;
            public string lpUserName;
            public string lpProfilePath;
            public string lpDefaultPath;
            public string lpServerName;
            public string lpPolicyPath;
            public IntPtr hProfile;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct PRIVILEGE_SET
        {
            public uint PrivilegeCount;
            public uint Control;
            public static uint PRIVILEGE_SET_ALL_NECESSARY = 1;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
            public LUID_AND_ATTRIBUTES[] Privilege;
        }

        [Flags]
        public enum TOKEN_PRIVILEGES_ATTRIBUTES : uint
        {
            SE_PRIVILEGE_ENABLED = 0x00000002,
            SE_PRIVILEGE_ENABLED_BY_DEFAULT = 0x00000001,
            SE_PRIVILEGE_REMOVED = 0x00000004,
            SE_PRIVILEGE_USED_FOR_ACCESS = 0x80000000,
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct LUID
        {
            public uint LowPart;
            public int HighPart;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct LUID_AND_ATTRIBUTES
        {
            public LUID Luid;
            public TOKEN_PRIVILEGES_ATTRIBUTES Attributes;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct TOKEN_PRIVILEGES
        {
            public uint PrivilegeCount;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
            public LUID_AND_ATTRIBUTES[] Privileges;
        }

        public struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct STARTUPINFO
        {
            public Int32 cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public Int32 dwX;
            public Int32 dwY;
            public Int32 dwXSize;
            public Int32 dwYSize;
            public Int32 dwXCountChars;
            public Int32 dwYCountChars;
            public Int32 dwFillAttribute;
            public Int32 dwFlags;
            public Int16 wShowWindow;
            public Int16 cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        public enum TOKEN_TYPE
        {
            TokenPrimary = 1,
            TokenImpersonation
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SECURITY_ATTRIBUTES
        {
            public int nLength;
            public IntPtr lpSecurityDescriptor;
            public bool bInheritHandle;
        }

        public enum SECURITY_IMPERSONATION_LEVEL
        {
            SecurityAnonymous = 0,
            SecurityIdentification = 1,
            SecurityImpersonation = 2,
            SecurityDelegation = 3
        }

        [Flags]
        public enum TOKEN_ACCESS_MASK : uint
        {
            TOKEN_DELETE = 0x00010000,
            TOKEN_READ_CONTROL = 0x00020000,
            TOKEN_WRITE_DAC = 0x00040000,
            TOKEN_WRITE_OWNER = 0x00080000,
            TOKEN_ACCESS_SYSTEM_SECURITY = 0x01000000,
            TOKEN_ASSIGN_PRIMARY = 0x00000001,
            TOKEN_DUPLICATE = 0x00000002,
            TOKEN_IMPERSONATE = 0x00000004,
            TOKEN_QUERY = 0x00000008,
            TOKEN_QUERY_SOURCE = 0x00000010,
            TOKEN_ADJUST_PRIVILEGES = 0x00000020,
            TOKEN_ADJUST_GROUPS = 0x00000040,
            TOKEN_ADJUST_DEFAULT = 0x00000080,
            TOKEN_ADJUST_SESSIONID = 0x00000100,
            TOKEN_READ = 0x00020008,
            TOKEN_WRITE = 0x000200E0,
            TOKEN_EXECUTE = 0x00020000,
            TOKEN_TRUST_CONSTRAINT_MASK = 0x00020018,
            TOKEN_ACCESS_PSEUDO_HANDLE_WIN8 = 0x00000018,
            TOKEN_ACCESS_PSEUDO_HANDLE = 0x00000018,
            TOKEN_ALL_ACCESS = 0x000F01FF,
        }

        [Flags]
        public enum PROCESS_ACCESS_RIGHTS : uint
        {
            PROCESS_TERMINATE = 0x00000001,
            PROCESS_CREATE_THREAD = 0x00000002,
            PROCESS_SET_SESSIONID = 0x00000004,
            PROCESS_VM_OPERATION = 0x00000008,
            PROCESS_VM_READ = 0x00000010,
            PROCESS_VM_WRITE = 0x00000020,
            PROCESS_DUP_HANDLE = 0x00000040,
            PROCESS_CREATE_PROCESS = 0x00000080,
            PROCESS_SET_QUOTA = 0x00000100,
            PROCESS_SET_INFORMATION = 0x00000200,
            PROCESS_QUERY_INFORMATION = 0x00000400,
            PROCESS_SUSPEND_RESUME = 0x00000800,
            PROCESS_QUERY_LIMITED_INFORMATION = 0x00001000,
            PROCESS_SET_LIMITED_INFORMATION = 0x00002000,
            PROCESS_ALL_ACCESS = 0x001FFFFF,
            PROCESS_DELETE = 0x00010000,
            PROCESS_READ_CONTROL = 0x00020000,
            PROCESS_WRITE_DAC = 0x00040000,
            PROCESS_WRITE_OWNER = 0x00080000,
            PROCESS_SYNCHRONIZE = 0x00100000,
            PROCESS_STANDARD_RIGHTS_REQUIRED = 0x000F0000,
        }

        public enum TOKEN_INFORMATION_CLASS
        {
            TokenUser = 1,
            TokenGroups = 2,
            TokenPrivileges = 3,
            TokenOwner = 4,
            TokenPrimaryGroup = 5,
            TokenDefaultDacl = 6,
            TokenSource = 7,
            TokenType = 8,
            TokenImpersonationLevel = 9,
            TokenStatistics = 10,
            TokenRestrictedSids = 11,
            TokenSessionId = 12,
            TokenGroupsAndPrivileges = 13,
            TokenSessionReference = 14,
            TokenSandBoxInert = 15,
            TokenAuditPolicy = 16,
            TokenOrigin = 17,
            TokenElevationType = 18,
            TokenLinkedToken = 19,
            TokenElevation = 20,
            TokenHasRestrictions = 21,
            TokenAccessInformation = 22,
            TokenVirtualizationAllowed = 23,
            TokenVirtualizationEnabled = 24,
            TokenIntegrityLevel = 25,
            TokenUIAccess = 26,
            TokenMandatoryPolicy = 27,
            TokenLogonSid = 28,
            TokenIsAppContainer = 29,
            TokenCapabilities = 30,
            TokenAppContainerSid = 31,
            TokenAppContainerNumber = 32,
            TokenUserClaimAttributes = 33,
            TokenDeviceClaimAttributes = 34,
            TokenRestrictedUserClaimAttributes = 35,
            TokenRestrictedDeviceClaimAttributes = 36,
            TokenDeviceGroups = 37,
            TokenRestrictedDeviceGroups = 38,
            TokenSecurityAttributes = 39,
            TokenIsRestricted = 40,
            TokenProcessTrustLevel = 41,
            TokenPrivateNameSpace = 42,
            TokenSingletonAttributes = 43,
            TokenBnoIsolation = 44,
            TokenChildProcessFlags = 45,
            TokenIsLessPrivilegedAppContainer = 46,
            TokenIsSandboxed = 47,
            TokenIsAppSilo = 48,
            MaxTokenInfoClass = 49,
        }
    }
}
