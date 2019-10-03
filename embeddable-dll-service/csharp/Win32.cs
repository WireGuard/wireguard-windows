/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

using System;
using System.Runtime.InteropServices;

namespace Tunnel
{
    static class Win32
    {
        [Flags]
        public enum ScmAccessRights
        {
            Connect = 0x0001,
            CreateService = 0x0002,
            EnumerateService = 0x0004,
            Lock = 0x0008,
            QueryLockStatus = 0x0010,
            ModifyBootConfig = 0x0020,
            StandardRightsRequired = 0xF0000,
            AllAccess = (StandardRightsRequired | Connect | CreateService | EnumerateService | Lock | QueryLockStatus | ModifyBootConfig)
        }

        [Flags]
        public enum ServiceAccessRights
        {
            QueryConfig = 0x1,
            ChangeConfig = 0x2,
            QueryStatus = 0x4,
            EnumerateDependants = 0x8,
            Start = 0x10,
            Stop = 0x20,
            PauseContinue = 0x40,
            Interrogate = 0x80,
            UserDefinedControl = 0x100,
            Delete = 0x00010000,
            StandardRightsRequired = 0xF0000,
            AllAccess = (StandardRightsRequired | QueryConfig | ChangeConfig | QueryStatus | EnumerateDependants | Start | Stop | PauseContinue | Interrogate | UserDefinedControl)
        }

        [Flags]
        public enum ServiceStartType
        {
            Boot = 0x00000000,
            System = 0x00000001,
            Auto = 0x00000002,
            Demand = 0x00000003,
            Disabled = 0x00000004
        }

        [Flags]
        public enum ServiceControl
        {
            Stop = 0x00000001,
            Pause = 0x00000002,
            Continue = 0x00000003,
            Interrogate = 0x00000004,
            Shutdown = 0x00000005,
            ParamChange = 0x00000006,
            NetBindAdd = 0x00000007,
            NetBindRemove = 0x00000008,
            NetBindEnable = 0x00000009,
            NetBindDisable = 0x0000000A
        }

        [Flags]
        public enum ServiceError
        {
            Ignore = 0x00000000,
            Normal = 0x00000001,
            Severe = 0x00000002,
            Critical = 0x00000003
        }

        [Flags]
        public enum ServiceSidType
        {
            None = 0x00000000,
            Unrestricted = 0x00000001,
            Restricted = 0x00000003
        }

        [Flags]
        public enum ServiceType
        {
            KernelDriver = 0x00000001,
            FileSystemDriver = 0x00000002,
            Win32OwnProcess = 0x00000010,
            Win32ShareProcess = 0x00000020,
            InteractiveProcess = 0x00000100
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode, Size = 8192), ComVisible(false)]
        public struct ServiceSidInfo
        {
            public ServiceSidType serviceSidType;
        };

        public enum ServiceState
        {
            Unknown = -1,
            NotFound = 0,
            Stopped = 1,
            StartPending = 2,
            StopPending = 3,
            Running = 4,
            ContinuePending = 5,
            PausePending = 6,
            Paused = 7
        }

        [StructLayout(LayoutKind.Sequential)]
        public class ServiceStatus
        {
            public int dwServiceType = 0;
            public ServiceState dwCurrentState = 0;
            public int dwControlsAccepted = 0;
            public int dwWin32ExitCode = 0;
            public int dwServiceSpecificExitCode = 0;
            public int dwCheckPoint = 0;
            public int dwWaitHint = 0;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode, Size = 8192), ComVisible(false)]
        public struct ServiceDescription
        {
            public String lpDescription;
        };

        public enum ServiceConfigType
        {
            Description = 1,
            SidInfo = 5
        }

        [DllImport("advapi32.dll", EntryPoint = "OpenSCManagerW", ExactSpelling = true, CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern IntPtr OpenSCManager(string machineName, string databaseName, ScmAccessRights dwDesiredAccess);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern IntPtr OpenService(IntPtr hSCManager, string lpServiceName, ServiceAccessRights dwDesiredAccess);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CloseServiceHandle(IntPtr hSCObject);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool StartService(IntPtr hService, int dwNumServiceArgs, string[] lpServiceArgVectors);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern IntPtr CreateService(IntPtr hSCManager, string lpServiceName, string lpDisplayName, ServiceAccessRights dwDesiredAccess, ServiceType dwServiceType, ServiceStartType dwStartType, ServiceError dwErrorControl, string lpBinaryPathName, string lpLoadOrderGroup, IntPtr lpdwTagId, string lpDependencies, string lp, string lpPassword);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool DeleteService(IntPtr hService);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool ControlService(IntPtr hService, ServiceControl dwControl, ServiceStatus lpServiceStatus);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool QueryServiceStatus(IntPtr hService, ServiceStatus lpServiceStatus);

        [DllImport("advapi32.dll", EntryPoint = "ChangeServiceConfig2", CharSet = CharSet.Unicode, SetLastError = true, CallingConvention = CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool ChangeServiceConfig2(IntPtr hService, ServiceConfigType dwInfoLevel, ref ServiceSidType lpInfo);

        [DllImport("advapi32.dll", EntryPoint = "ChangeServiceConfig2", CharSet = CharSet.Unicode, SetLastError = true, CallingConvention = CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool ChangeServiceConfig2(IntPtr hService, ServiceConfigType dwInfoLevel, ref ServiceDescription lpInfo);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
        public class KeyBlob
        {
            BCRYPT_ECCKEY_BLOB Header;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
            public byte[] Public;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
            public byte[] Unused;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
            public byte[] Private;
        }

        public const string BCRYPT_ECC_CURVE_NAME = "ECCCurveName";
        public const string BCRYPT_ECDH_ALGORITHM = "ECDH";
        public const string BCRYPT_ECC_CURVE_25519 = "curve25519";
        public const string BCRYPT_ECCPRIVATE_BLOB = "ECCPRIVATEBLOB";

        [DllImport("bcrypt.dll", SetLastError = true, ExactSpelling = true, CharSet = CharSet.Unicode)]
        public static extern uint BCryptSetProperty(IntPtr hObject, string property, string input, int inputSize, uint Flags = 0);

        [DllImport("bcrypt.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern uint BCryptOpenAlgorithmProvider(ref IntPtr hAlgorithm, string AlgId, string Implementation, uint Flags);

        [DllImport("bcrypt.dll", SetLastError = true)]
        public static extern uint BCryptGenerateKeyPair(IntPtr hObject, ref IntPtr hKey, uint length, uint Flags);

        [DllImport("bcrypt.dll", SetLastError = true)]
        public static extern uint BCryptFinalizeKeyPair(IntPtr hKey, uint Flags);

        [DllImport("bcrypt.dll", SetLastError = true, ExactSpelling = true, CharSet = CharSet.Unicode)]
        public static extern uint BCryptExportKey(IntPtr hKey, IntPtr hExportKey, [MarshalAs(UnmanagedType.LPWStr)] string pszBlobType, [Out] KeyBlob pbOutput, int cbOutput, out int pcbResult, uint Flags = 0);

        [DllImport("bcrypt.dll", SetLastError = true)]
        public static extern uint BCryptDestroyKey(IntPtr hKey);

        [DllImport("bcrypt.dll", SetLastError = true)]
        public static extern uint BCryptCloseAlgorithmProvider(IntPtr hAlgorithm, uint Flags);

        [DllImport("bcrypt.dll", SetLastError = true)]
        public static extern uint BCryptDestroySecret(IntPtr hSecretAgreement);

        [DllImport("bcrypt.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern uint BCryptImportKeyPair(IntPtr hAlgorithm, IntPtr hImportKey, string BlobType, ref IntPtr hPublicKey, byte[] Input, uint InputByteLength, uint Flags);

        [DllImport("bcrypt.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern uint BCryptSecretAgreement(IntPtr hPrivKey, IntPtr hPublicKey, ref IntPtr phSecret, uint Flags);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        public class BCryptBufferDesc
        {
            public uint ulVersion;
            public uint cBuffers;
            public IntPtr pBuffers;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        public class BCryptBuffer
        {
            public uint cbBuffer;
            public uint bufferType;
            public IntPtr pvBuffer;
        }

        [StructLayout(LayoutKind.Sequential)]
        public class BCRYPT_ECCKEY_BLOB
        {
            uint magic;
            uint cbKey;
        }
    }
}
