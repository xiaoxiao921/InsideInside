using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;

namespace InsideInside
{
    internal static class StringExtensions
    {
        public static string Format(this string fmt, Dictionary<string, Func<string>> vars)
        {
            return vars.Aggregate(fmt, (str, kv) => str.Replace($"{{{kv.Key}}}", kv.Value()));
        }

        public static byte?[] ParseHexBytes(this string str)
        {
            static bool IsHexChar(char lowerC) => '0' <= lowerC && lowerC <= '9' || 'a' <= lowerC && lowerC <= 'f';
            var result = new List<byte?>();

            var sr = new StringReader(str);
            while (sr.Peek() > 0)
            {
                var c = char.ToLower((char)sr.Read());

                if (char.IsWhiteSpace(c))
                    continue;
                if (c == ';')
                {
                    sr.ReadLine();
                }
                else if (c == '?')
                {
                    result.Add(null);
                    sr.Read();
                }
                else if (IsHexChar(c) && sr.Peek() > 0)
                {
                    var other = char.ToLower((char)sr.Peek());
                    if (!IsHexChar(other)) continue;
                    sr.Read();
                    result.Add(byte.Parse($"{c}{other}", NumberStyles.HexNumber));
                }
            }

            return result.ToArray();
        }
    }

    internal class BytePattern
    {
        private readonly byte?[] pattern;

        public BytePattern(string bytes)
        {
            pattern = bytes.ParseHexBytes();
        }

        public BytePattern(byte[] bytes)
        {
            pattern = bytes.Cast<byte?>().ToArray();
        }

        public int Length => pattern.Length;

        public bool IsE8 => pattern[0] == 0xE8;

        public static implicit operator BytePattern(string pattern)
        {
            return new BytePattern(pattern);
        }

        public static implicit operator BytePattern(byte[] pattern)
        {
            return new BytePattern(pattern);
        }

        public unsafe List<long> Match(IntPtr targetArrayStart, long targetArraySize)
        {
            var results = new List<long>();

            var targetArrayStartPtr = (byte*)targetArrayStart.ToPointer();

            for (long targetArrayCursor = 0; targetArrayCursor < targetArraySize; targetArrayCursor++)
            {
                bool isMatch = true;

                for (int patternCursor = 0; patternCursor < Length; patternCursor++)
                {
                    if (targetArrayStartPtr[targetArrayCursor + patternCursor] != pattern[patternCursor])
                    {
                        isMatch = false;
                        break;
                    }
                }

                if (isMatch)
                {
                    results.Add(targetArrayCursor);
                }
            }

            return results;
        }
    }

    class MemoryScanner
    {
        [Flags]
        private enum MemoryProtection : uint
        {
            PAGE_NOACCESS = 0x01,
            PAGE_READONLY = 0x02,
            PAGE_READWRITE = 0x04,
            PAGE_WRITECOPY = 0x08,
            PAGE_EXECUTE = 0x10,
            PAGE_EXECUTE_READ = 0x20,
            PAGE_EXECUTE_READWRITE = 0x40,
            PAGE_EXECUTE_WRITECOPY = 0x80,
            PAGE_GUARD = 0x100,
            PAGE_NOCACHE = 0x200,
            PAGE_WRITECOMBINE = 0x400
        }

        [Flags]
        private enum MemoryState : uint
        {
            MEM_COMMIT = 0x1000,
            MEM_FREE = 0x10000,
            MEM_RESERVE = 0x2000
        }

        [Flags]
        private enum MemoryType : uint
        {
            MEM_IMAGE = 0x1000000,
            MEM_MAPPED = 0x40000,
            MEM_PRIVATE = 0x20000
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct MEMORY_BASIC_INFORMATION
        {
            public IntPtr BaseAddress;
            public IntPtr AllocationBase;
            public MemoryProtection AllocationProtect;
            public IntPtr RegionSize;
            public MemoryState State;
            public MemoryProtection Protect;
            public MemoryType Type;
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenProcess(int processAccess, bool bInheritHandle, int processId);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out uint lpNumberOfBytesRead);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern int VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr GetCurrentProcess();

        private const int PROCESS_QUERY_INFORMATION = 0x0400;
        private const int PROCESS_VM_READ = 0x0010;

        public static int assCount = 0;

        public static void ScanAndDumpPEFilesFromProcessMemory(string outputDumpFolderPath)
        {
            IntPtr processHandle = GetCurrentProcess();

            if (processHandle == IntPtr.Zero)
            {
                Core.Logger.Msg("Failed to open process. Error: " + Marshal.GetLastWin32Error());
                return;
            }

            IntPtr address = IntPtr.Zero;
            MEMORY_BASIC_INFORMATION memoryInfo;
            uint memoryInfoSize = (uint)Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION));
            byte[] buffer = new byte[10024 * 1024];

            while (VirtualQueryEx(processHandle, address, out memoryInfo, memoryInfoSize) != 0)
            {
                if (memoryInfo.State == MemoryState.MEM_COMMIT &&
                    (memoryInfo.Protect == MemoryProtection.PAGE_READWRITE ||
                     memoryInfo.Protect == MemoryProtection.PAGE_READONLY ||
                     memoryInfo.Protect == MemoryProtection.PAGE_EXECUTE_READ ||
                     memoryInfo.Protect == MemoryProtection.PAGE_EXECUTE_READWRITE))
                {
                    uint bytesRead;
                    IntPtr regionSize = memoryInfo.RegionSize;

                    for (IntPtr offset = IntPtr.Zero; offset.ToInt64() < regionSize.ToInt64();)
                    {
                        IntPtr readAddress = (IntPtr)(memoryInfo.BaseAddress.ToInt64() + offset.ToInt32());
                        uint bytesToRead = (uint)Math.Min(buffer.Length, regionSize.ToInt64() - offset.ToInt64());

                        if (ReadProcessMemory(processHandle, readAddress, buffer, bytesToRead, out bytesRead))
                        {
                            //Core.Logger.Msg($"Read {bytesRead} bytes from address: 0x{readAddress.ToString("X")}");
                            const string MzPattern = "4D 5A 90 00 03";
                            var patternScanResult = new BytePattern(MzPattern).Match(readAddress, bytesRead);
                            if (patternScanResult.Count > 0)
                            {
                                var offsetActualStartOfMzFile = patternScanResult[0];

                                Core.Logger.Msg($"Read {bytesRead} bytes from address: 0x{readAddress.ToString("X")}, found {patternScanResult.Count}, {offsetActualStartOfMzFile}");

                                byte[] fileBuffer = new byte[bytesRead - offsetActualStartOfMzFile];
                                Array.Copy(buffer, offsetActualStartOfMzFile, fileBuffer, 0, bytesRead - offsetActualStartOfMzFile);
                                File.WriteAllBytes($"{outputDumpFolderPath}/Ass{assCount++}.dll", fileBuffer);
                            }
                        }

                        offset = (IntPtr)(offset.ToInt64() + buffer.Length);
                    }
                }

                // Move to the next region.

                address = (IntPtr)(memoryInfo.BaseAddress.ToInt64() + memoryInfo.RegionSize.ToInt64());
            }

            CloseHandle(processHandle);
        }
    }
}