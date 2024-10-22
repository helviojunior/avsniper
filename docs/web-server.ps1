# Windows Http Server Module
# Before run the server execute this commands bellow as Administrator
#     netsh http add urlacl url=http://+:8080/ user=([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)
#     New-NetFirewallRule -DisplayName "AllowTestWebServer" -Direction Inbound -Protocol TCP -LocalPort 8080 -Action Allow

$code = @"
using System;
using System.Text;
using System.Net;
using System.Threading;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.IO;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Json;
using System.Security.Cryptography;
using System.Linq;
using System.Collections.Generic;
using System.Management;
using Microsoft.Win32;

namespace AvTester
{
    public class Tester
    {
        [DataContract]
        public class JSONRequest
        {
            [DataMember]
            public Int32 test_id;

            [DataMember]
            public string hash;

            [DataMember]
            public Boolean crashed;

            [DataMember]
            public double wait_time;

            [DataMember]
            public Boolean execute_exe;

            [DataMember]
            public string command;

            [DataMember]
            public string data;

        }

        [DataContract]
        public class OSInfo
        {
            public OSInfo()
            {
                try{
                    string HKLMWinNTCurrent = @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion";
                    this.name = Registry.GetValue(HKLMWinNTCurrent, "productName", "").ToString();
                    this.release = Registry.GetValue(HKLMWinNTCurrent, "ReleaseId", "").ToString();
                    this.version = Environment.OSVersion.Version.ToString();
                    this.type = Environment.Is64BitOperatingSystem ? "64-bit" : "32-bit";
                    this.build = Registry.GetValue(HKLMWinNTCurrent, "CurrentBuildNumber", "").ToString();
                    this.ubr = Registry.GetValue(HKLMWinNTCurrent, "UBR", "").ToString();
                }catch (Exception ex){}

                try{
                    //https://learn.microsoft.com/en-us/answers/questions/555857/windows-11-product-name-in-registry
                    var path = string.Format(@"\\{0}\root\cimv2", Environment.MachineName);
                    var searcher = new ManagementObjectSearcher(path, "SELECT * FROM Win32_OperatingSystem");
                    var name = searcher.Get().Cast<ManagementObject>()
                                            .Select(x => (string)x.GetPropertyValue("Caption"))
                                            .FirstOrDefault();
                    if (!String.IsNullOrEmpty(name))
                        this.name = name;
                }catch (Exception ex){}
            }

            [DataMember]
            public string name;

            [DataMember]
            public string release;

            [DataMember]
            public string version;

            [DataMember]
            public string type;

            [DataMember]
            public string build;

            [DataMember]
            public string ubr;
        }

        [DataContract]
        public class AVData
        {
            public AVData()
            {
                this.display_name = "Unknown";
            }

            [DataMember]
            public string display_name;

            [DataMember]
            public string instance_guid;

            [DataMember]
            public string path_to_exe;

            [DataMember]
            public UInt32 product_state;

            [DataMember]
            public string timestamp;
        }

        [DataContract]
        public class JSONResponse
        {

            public JSONResponse(AVData av_data) : this(false, false, false, false, "", "")
            {
                this.av_data = av_data;
                this.os_info = new OSInfo();
            }

            public JSONResponse(Exception ex, string message) : this(true, message, ex.Message + Environment.NewLine + ex.StackTrace)
            { }

            public JSONResponse(Exception ex) : this(true, ex.Message, ex.StackTrace)
            { }

            public JSONResponse(Boolean error, string message) : this(error, message, "")
            { }

            public JSONResponse(Boolean error, string message, string stack_trace)
            {
                this.error = error;
                this.message = message;
                this.stack_trace = stack_trace;
            }

            public JSONResponse(Boolean error, Boolean file_exists, Boolean hash, Boolean execution) : this(error, file_exists, hash, execution, "", "")
            { }

            public JSONResponse(Boolean error, Boolean file_exists, Boolean hash, Boolean execution, string message) : this(error, file_exists, hash, execution, message, "")
            { }


            public JSONResponse(Boolean error, Boolean file_exists, Boolean hash, Boolean execution, string message, string stack_trace)
            {
                this.error = error;
                this.message = message;
                this.stack_trace = stack_trace;
                this.file_exists = file_exists;
                this.hash = hash;
                this.execution = execution;
            }

            [DataMember]
            public Boolean error = false;

            [DataMember]
            public string message = "";

            [DataMember]
            public string stack_trace = "";

            [DataMember]
            public Boolean file_exists = false;

            [DataMember]
            public Boolean hash = false;

            [DataMember]
            public Boolean execution = false;

            [DataMember]
            public AVData av_data = null;

            [DataMember]
            public OSInfo os_info = null;

        }

        [StructLayout(LayoutKind.Sequential)]
        private struct PROCESS_INFORMATION
        {
            public IntPtr hProcess; public IntPtr hThread; public uint dwProcessId; public uint dwThreadId;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct STARTUPINFO
        {
            public uint cb; public string lpReserved; public string lpDesktop; public string lpTitle;
            public uint dwX; public uint dwY; public uint dwXSize; public uint dwYSize; public uint dwXCountChars;
            public uint dwYCountChars; public uint dwFillAttribute; public uint dwFlags; public short wShowWindow;
            public short cbReserved2; public IntPtr lpReserved2; public IntPtr hStdInput; public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct SECURITY_ATTRIBUTES
        {
            public int length; public IntPtr lpSecurityDescriptor; public bool bInheritHandle;
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CreateProcess(
            string lpApplicationName, string lpCommandLine, ref SECURITY_ATTRIBUTES lpProcessAttributes,
            ref SECURITY_ATTRIBUTES lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags,
            IntPtr lpEnvironment, string lpCurrentDirectory, ref STARTUPINFO lpStartupInfo,
            out PROCESS_INFORMATION lpProcessInformation);


        private static HttpListener _listener;
        private static Int32 _requests = 0;
        private static Random random = new Random();
        private static String _cmd = "";

        static void Main(string[] args)
        {
            StartServer(8080);
        }

        public static Boolean IsListening
        {
            get
            {
                if (Tester._listener == null)
                    return false;

                return Tester._listener.IsListening;
            }
        }

        public static void StartServer(Int16 port)
        {

            Thread serverThread = new Thread(new ParameterizedThreadStart(_server));
            serverThread.Start(port);

        }

        public static void StartServer(Int16 port, String checkCommand)
        {

            Thread serverThread = new Thread(new ParameterizedThreadStart(_server));
            serverThread.Start(port);
            _cmd = checkCommand;
        }

        public static void StopServer()
        {
            _listener.Stop();
        }

        private static void _server(Object port)
        {
            _listener = new HttpListener();
            _listener.Prefixes.Add("http://+:" + port+ "/");
            _listener.Start();

            Thread statusThread = new Thread(new ThreadStart(_status));
            statusThread.Start();

            while (true)
            {
                var context = _listener.GetContext();
                Thread backgroundThread = new Thread(() => HandleContext(context));
                backgroundThread.Start();
            }
        }

        private static void _status()
        {
            Int32 last_count = -1;
            Thread.Sleep(1000);
            while (true)
            {
                if (Tester._requests != last_count)
                {
                    Console.Error.Write("\r  Received requests: " + Tester._requests + "\r");
                    last_count = Tester._requests;
                }
                Thread.Sleep(300);
            }
        }

        public static string RandomString(int length)
        {
            const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
            return new string(Enumerable.Repeat(chars, length)
                .Select(s => s[random.Next(s.Length)]).ToArray());
        }

        static void HandleContext(HttpListenerContext context)
        {
            try
            {
                if (context.Request.RawUrl.IndexOf("/api/v1/ping") == 0)
                {
                    SetResponse(context, 200, new JSONResponse(false, false, false, false, "Pong!"));
                    return;
                }

                if (context.Request.RawUrl.IndexOf("/api/v1/av_name") == 0)
                {
                    var path = string.Format(@"\\{0}\root\SecurityCenter2", Environment.MachineName);
                    var searcher = new ManagementObjectSearcher(path, "SELECT * FROM AntivirusProduct");
                    var av_list = searcher.Get().Cast<ManagementObject>()
                                    .Select(x => new AVData()
                                    {
                                        display_name = (string)x.GetPropertyValue("displayName"),
                                        instance_guid = (string)x.GetPropertyValue("instanceGuid"),
                                        path_to_exe = (string)x.GetPropertyValue("pathToSignedReportingExe"),
                                        product_state = (UInt32)x.GetPropertyValue("productState"),
                                        timestamp = (string)x.GetPropertyValue("timestamp")
                                    });

                    var data = new List<AVData>()
                        .Concat(av_list.Where(x => x.display_name.ToLower().IndexOf("windows defender") == -1))
                        .Concat(av_list.Where(x => x.display_name.ToLower().IndexOf("windows defender") != -1))
                        .FirstOrDefault();

                    SetResponse(context, 200, new JSONResponse(data));
                    return;
                }

                //(Get - CimInstance - Namespace root / SecurityCenter2 -ClassName AntivirusProduct).displayName

                Tester._requests++;
                if (context.Request.HttpMethod == "POST" && context.Request.RawUrl.IndexOf("/api/v1/check_file/") == 0)
                {
                    String jsonString = "";
                    using (StreamReader stm = new StreamReader(context.Request.InputStream))
                        jsonString = stm.ReadToEnd();

                    JSONRequest jRequest = Deserialize<JSONRequest>(jsonString);
                    if (String.IsNullOrEmpty(jRequest.command) && !String.IsNullOrEmpty(_cmd))
                    {
                        jRequest.command = _cmd;
                    }

                    Byte[] bData = Convert.FromBase64String(jRequest.data);

                    for (Int32 i = 0; i < bData.Length; i++)
                    {
                        bData[i] = (byte)(bData[i] ^ 0x4d);
                    }

                    bData = Convert.FromBase64String(Encoding.BigEndianUnicode.GetString(bData));

                    String fileName = Path.Combine(Path.GetTempPath(), "srv-" + jRequest.test_id + "-" + RandomString(10)  + ".exe");
                    try
                    {
                        try
                        {
                            File.WriteAllBytes(fileName, bData);
                        }
                        catch (Exception ex)
                        {
                            SetResponse(context, 400, new JSONResponse(ex, "Exception creating file at disk"));
                            return;
                        }

                        if (!File.Exists(fileName))
                        {
                            SetResponse(context, 400, new JSONResponse(true, false, false, false, "File not found"));
                            return;
                        }

                        String hash = "";

                        try
                        {
                            hash = CalculateMD5(fileName);
                        }
                        catch (Exception ex)
                        {
                            SetResponse(context, 400, new JSONResponse(true, true, false, false, "Exception calculating hash of the file", ex.Message + Environment.NewLine + ex.StackTrace));
                            return;
                        }

                        if (hash != jRequest.hash)
                        {
                            SetResponse(context, 400, new JSONResponse(true, true, false, false, "Hash is not equal"));
                            return;
                        }

                        if (!String.IsNullOrEmpty(jRequest.command))
                        {
                            if (!ExecuteCommand(jRequest.command.Replace("{exe}", fileName)))
                            {
                                SetResponse(context, 400, new JSONResponse(true, true, true, false, "Fail executing custom command"));
                                return;
                            }

                            if (!File.Exists(fileName))
                            {
                                SetResponse(context, 400, new JSONResponse(true, false, false, false, "File not found after custom command execution"));
                                return;
                            }

                        }

                        if (jRequest.execute_exe)
                        {
                            if (!Execute(fileName) && !jRequest.crashed)
                            {
                                SetResponse(context, 400, new JSONResponse(true, true, true, false, "Fail executing file"));
                                return;
                            }

                            if (!File.Exists(fileName))
                            {
                                SetResponse(context, 400, new JSONResponse(true, false, false, false, "File not found after execution"));
                                return;
                            }

                            //Wait some time before check againg
                            Thread.Sleep((Int32)(jRequest.wait_time * 1000));

                            //Check Hash again
                            try
                            {
                                hash = CalculateMD5(fileName);
                            }
                            catch (Exception ex)
                            {
                                SetResponse(context, 400, new JSONResponse(true, true, false, true, "Exception calculating hash of the file", ex.Message + Environment.NewLine + ex.StackTrace));
                                return;
                            }

                            if (hash != jRequest.hash)
                            {
                                SetResponse(context, 400, new JSONResponse(true, true, false, true, "Hash is not equal after execution"));
                                return;
                            }
                        }

                        SetResponse(context, 200, new JSONResponse(false, true, true, true, "File ok"));
                    }
                    catch (Exception ex)
                    {
                        SetResponse(context, 500, new JSONResponse(ex));
                    }
                    finally
                    {
                        try
                        {
                            File.Delete(fileName);
                        }
                        catch { }
                    }
                }
                else
                {
                    SetResponse(context, 404, new JSONResponse(true, "Route not found: " + context.Request.RawUrl));
                }

            }
            catch (Exception ex)
            {
                SetResponse(context, 500, new JSONResponse(ex));
            }
        }

        private static Boolean ExecuteCommand(String command)
        {
            string[] cP = command.Split(" ".ToCharArray(), 2);
            ProcessStartInfo startInfo = new ProcessStartInfo();
            startInfo.FileName = cP[0];
            startInfo.Arguments = cP.Length > 1 ? cP[1] : "";
            startInfo.UseShellExecute = false;
            startInfo.CreateNoWindow = true;
            Process process = new Process();
            process.StartInfo = startInfo;
            process.Start();

            process.WaitForExit();
            return process.ExitCode == 0;
        }

        private static void SetResponse(HttpListenerContext context, Int32 StatusCode, JSONResponse response)
        {
            String jRet = Serialize<JSONResponse>(response);

            // resposed to the request
            context.Response.ContentType = "application/json";
            context.Response.ContentEncoding = Encoding.UTF8;
            context.Response.KeepAlive = false;
            context.Response.StatusCode = StatusCode;

            byte[] buffer = Encoding.UTF8.GetBytes(jRet);
            context.Response.ContentLength64 = buffer.Length;
            context.Response.OutputStream.Write(buffer, 0, buffer.Length);
            context.Response.OutputStream.Close();

        }

        private static T Deserialize<T>(String jsonText)
        {
            DataContractJsonSerializer ser = new DataContractJsonSerializer(typeof(T));
            using (MemoryStream ms = new MemoryStream(Encoding.UTF8.GetBytes(jsonText)))
                return (T)ser.ReadObject(ms);
        }

        public static String Serialize<T>(T obj)
        {
            String ret = "";

            DataContractJsonSerializer ser = new DataContractJsonSerializer(typeof(T));

            using (MemoryStream ms = new MemoryStream())
            {
                ser.WriteObject(ms, obj);
                ms.Flush();
                ret = Encoding.UTF8.GetString(ms.ToArray());
            }

            return ret;
        }

        private static string CalculateMD5(string filename)
        {
            using (var md5 = MD5.Create())
            {
                using (var stream = File.OpenRead(filename))
                {
                    var hash = md5.ComputeHash(stream);
                    return BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
                }
            }
        }

        private static Boolean Execute(string filename)
        {

            STARTUPINFO sinfo = new STARTUPINFO();
            sinfo.cb = (UInt32)Marshal.SizeOf(sinfo);
            sinfo.dwFlags = 0x00000010 | 0x00000004;
            sinfo.wShowWindow = 0x0000;

            PROCESS_INFORMATION pinfo = new PROCESS_INFORMATION();

            SECURITY_ATTRIBUTES sec = new SECURITY_ATTRIBUTES();
            sec.length = Marshal.SizeOf(sec);


            if (CreateProcess(null, filename, ref sec, ref sec, false, 0x00000010 | 0x00000004, IntPtr.Zero, null, ref sinfo, out pinfo))
            {
                Thread.Sleep(500);
                try
                {
                    Process.GetProcessById((Int32)pinfo.dwProcessId).Kill();
                }
                catch { }
                return true;
            }
            else
            {
                return false;
            }

        }

    }
}
"@

Add-Type -IgnoreWarnings -TypeDefinition $code -Language CSharp -ReferencedAssemblies System.Xml,System.Runtime.Serialization,System.Management


[AvTester.Tester]::StartServer(8080);

Write-Host "Listening..."
Write-Host "Press Ctrl+C to terminate"

[console]::TreatControlCAsInput = $true

# Wait for it all to complete
while ([AvTester.Tester]::IsListening)
{
     if ([console]::KeyAvailable) {
        $key = [system.console]::readkey($true)
        if (($key.modifiers -band [consolemodifiers]"control") -and ($key.key -eq "C"))
        {
            Write-Host "Terminating..."
            [AvTester.Tester]::StopServer();
            break
        }
    }

    Start-Sleep -s 1
}