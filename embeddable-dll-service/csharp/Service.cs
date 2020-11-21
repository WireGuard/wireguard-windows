/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2020 WireGuard LLC. All Rights Reserved.
 */

using System;
using System.IO;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.ComponentModel;
using System.Diagnostics;
using System.Security.Principal;
using System.Threading;

namespace Tunnel
{
    public class Service
    {
        private const string LongName = "Example WireGuard Tunnel Client";
        private const string Description = "A WireGuard tunnel created by example code.";

        [DllImport("tunnel.dll", EntryPoint = "WireGuardTunnelService", CallingConvention = CallingConvention.Cdecl)]
        public static extern bool Run([MarshalAs(UnmanagedType.LPWStr)] string configFile);

        public static NamedPipeClientStream GetPipe(string configFile)
        {
            var pipepath = "ProtectedPrefix\\Administrators\\WireGuard\\" + Path.GetFileNameWithoutExtension(configFile);
            return new NamedPipeClientStream(pipepath);
        }

        public static void Add(string configFile)
        {
            var tunnelName = Path.GetFileNameWithoutExtension(configFile);
            var shortName = String.Format("WireGuardTunnel${0}", tunnelName);
            var longName = String.Format("{0}: {1}", LongName, tunnelName);
            var exeName = Process.GetCurrentProcess().MainModule.FileName;
            var pathAndArgs = String.Format("\"{0}\" /service \"{1}\"", exeName, configFile); //TODO: This is not the proper way to escape file args.

            var accessControl = File.GetAccessControl(configFile); //TODO: TOCTOU!
            accessControl.SetOwner(new NTAccount(Environment.UserDomainName, Environment.UserName));
            File.SetAccessControl(configFile, accessControl);

            var scm = Win32.OpenSCManager(null, null, Win32.ScmAccessRights.AllAccess);
            if (scm == IntPtr.Zero)
                throw new Win32Exception(Marshal.GetLastWin32Error());
            try
            {
                var service = Win32.OpenService(scm, shortName, Win32.ServiceAccessRights.AllAccess);
                if (service != IntPtr.Zero)
                {
                    Win32.CloseServiceHandle(service);
                    Remove(configFile);
                }
                service = Win32.CreateService(scm, shortName, longName, Win32.ServiceAccessRights.AllAccess, Win32.ServiceType.Win32OwnProcess, Win32.ServiceStartType.Demand, Win32.ServiceError.Normal, pathAndArgs, null, IntPtr.Zero, "Nsi", null, null);
                if (service == IntPtr.Zero)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                try
                {
                    var sidType = Win32.ServiceSidType.Unrestricted;
                    if (!Win32.ChangeServiceConfig2(service, Win32.ServiceConfigType.SidInfo, ref sidType))
                        throw new Win32Exception(Marshal.GetLastWin32Error());

                    var description = new Win32.ServiceDescription { lpDescription = Description };
                    if (!Win32.ChangeServiceConfig2(service, Win32.ServiceConfigType.Description, ref description))
                        throw new Win32Exception(Marshal.GetLastWin32Error());

                    if (!Win32.StartService(service, 0, null))
                        throw new Win32Exception(Marshal.GetLastWin32Error());
                }
                finally
                {
                    Win32.CloseServiceHandle(service);
                }
            }
            finally
            {
                Win32.CloseServiceHandle(scm);
            }
        }

        public static void Remove(string configFile)
        {
            var tunnelName = Path.GetFileNameWithoutExtension(configFile);
            var shortName = String.Format("WireGuardTunnel${0}", tunnelName);

            var scm = Win32.OpenSCManager(null, null, Win32.ScmAccessRights.AllAccess);
            if (scm == IntPtr.Zero)
                throw new Win32Exception(Marshal.GetLastWin32Error());
            try
            {
                var service = Win32.OpenService(scm, shortName, Win32.ServiceAccessRights.AllAccess);
                if (service == IntPtr.Zero)
                {
                    Win32.CloseServiceHandle(service);
                    return;
                }
                try
                {
                    var serviceStatus = new Win32.ServiceStatus();
                    Win32.ControlService(service, Win32.ServiceControl.Stop, serviceStatus);

                    for (int i = 0; i < 180 && Win32.QueryServiceStatus(service, serviceStatus) && serviceStatus.dwCurrentState != Win32.ServiceState.Stopped; ++i)
                        Thread.Sleep(1000);

                    if (!Win32.DeleteService(service))
                        throw new Win32Exception(Marshal.GetLastWin32Error());
                }
                finally
                {
                    Win32.CloseServiceHandle(service);
                }
            }
            finally
            {
                Win32.CloseServiceHandle(scm);
            }
        }
    }
}
