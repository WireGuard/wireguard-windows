/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2022 WireGuard LLC. All Rights Reserved.
 */

using System;
using System.Threading;
using System.Diagnostics;
using System.Windows.Forms;

namespace DemoUI
{
    static class Program
    {
        [STAThread]
        static void Main(string[] args)
        {
            if (args.Length == 3 && args[0] == "/service")
            {
                var t = new Thread(() =>
                {
                    try
                    {
                        var currentProcess = Process.GetCurrentProcess();
                        var uiProcess = Process.GetProcessById(int.Parse(args[2]));
                        if (uiProcess.MainModule.FileName != currentProcess.MainModule.FileName)
                            return;
                        uiProcess.WaitForExit();
                        Tunnel.Service.Remove(args[1], false);
                    }
                    catch { }
                });
                t.Start();
                Tunnel.Service.Run(args[1]);
                t.Interrupt();
                return;
            }
            Application.SetHighDpiMode(HighDpiMode.SystemAware);
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new MainWindow());
        }
    }
}
