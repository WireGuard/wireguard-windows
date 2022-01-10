﻿/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2022 WireGuard LLC. All Rights Reserved.
 */

using System;
using System.Text;
using System.Threading.Tasks;
using System.IO;
using System.Windows.Forms;
using System.Threading;
using System.IO.Pipes;
using System.Diagnostics;
using System.Net.Sockets;
using System.Security.AccessControl;

namespace DemoUI
{
    public partial class MainWindow : Form
    {
        private static readonly string userDirectory = Path.Combine(Path.GetDirectoryName(Process.GetCurrentProcess().MainModule.FileName), "Config"); //TODO: put in Program Files in real code.
        private static readonly string configFile = Path.Combine(userDirectory, "demobox.conf");
        private static readonly string logFile = Path.Combine(userDirectory, "log.bin");

        private Tunnel.Ringlogger log;
        private Thread logPrintingThread, transferUpdateThread;
        private volatile bool threadsRunning;
        private bool connected;

        public MainWindow()
        {
            makeConfigDirectory();
            InitializeComponent();
            Application.ApplicationExit += Application_ApplicationExit;
            try { File.Delete(logFile); } catch { }
            log = new Tunnel.Ringlogger(logFile, "GUI");
            logPrintingThread = new Thread(new ThreadStart(tailLog));
            transferUpdateThread = new Thread(new ThreadStart(tailTransfer));
        }

        private void makeConfigDirectory()
        {
            var ds = new DirectorySecurity();
            ds.SetSecurityDescriptorSddlForm("O:BAG:BAD:PAI(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)");
            FileSystemAclExtensions.CreateDirectory(ds, userDirectory);
        }

        private void tailLog()
        {
            var cursor = Tunnel.Ringlogger.CursorAll;
            while (threadsRunning)
            {
                var lines = log.FollowFromCursor(ref cursor);
                foreach (var line in lines)
                    logBox.Invoke(new Action<string>(logBox.AppendText), new object[] { line + "\r\n" });
                try
                {
                    Thread.Sleep(300);
                }
                catch
                {
                    break;
                }
            }
        }

        private void tailTransfer()
        {
            Tunnel.Driver.Adapter adapter = null;
            while (threadsRunning)
            {
                if (adapter == null)
                {
                    while (threadsRunning)
                    {
                        try
                        {
                            adapter = Tunnel.Service.GetAdapter(configFile);
                            break;
                        }
                        catch
                        {
                            try
                            {
                                Thread.Sleep(1000);
                            }
                            catch { }
                        }
                    }
                }
                if (adapter == null)
                    continue;
                try
                {
                    ulong rx = 0, tx = 0;
                    var config = adapter.GetConfiguration();
                    foreach (var peer in config.Peers)
                    {
                        rx += peer.RxBytes;
                        tx += peer.TxBytes;
                    }
                    Invoke(new Action<ulong, ulong>(updateTransferTitle), new object[] { rx, tx });
                    Thread.Sleep(1000);
                }
                catch { adapter = null; }
            }
        }

        private void Application_ApplicationExit(object sender, EventArgs e)
        {
            Tunnel.Service.Remove(configFile, true);
            try { File.Delete(logFile); } catch { }
            try { File.Delete(configFile); } catch { }
        }

        private void MainWindow_Load(object sender, EventArgs e)
        {
            threadsRunning = true;
            logPrintingThread.Start();
            transferUpdateThread.Start();
        }

        private void MainWindow_FormClosing(object sender, FormClosingEventArgs e)
        {
            threadsRunning = false;
            logPrintingThread.Interrupt();
            transferUpdateThread.Interrupt();
            try { logPrintingThread.Join(); } catch { }
            try { transferUpdateThread.Join(); } catch { }
        }

        private static string formatBytes(ulong bytes)
        {
            decimal d = bytes;
            string selectedUnit = null;
            foreach (string unit in new string[] { "B", "KiB", "MiB", "GiB", "TiB" })
            {
                selectedUnit = unit;
                if (d < 1024)
                    break;
                d /= 1024;
            }
            return string.Format("{0:0.##} {1}", d, selectedUnit);
        }

        private void updateTransferTitle(ulong rx, ulong tx)
        {
            var titleBase = Text;
            var idx = titleBase.IndexOf(" - ");
            if (idx != -1)
                titleBase = titleBase.Substring(0, idx);
            if (rx == 0 && tx == 0)
                Text = titleBase;
            else
                Text = string.Format("{0} - rx: {1}, tx: {2}", titleBase, formatBytes(rx), formatBytes(tx));
        }

        private async Task<string> generateNewConfig()
        {
            log.Write("Generating keys");
            var keys = Tunnel.Keypair.Generate();
            log.Write("Exchanging keys with demo server");
            var client = new TcpClient();
            await client.ConnectAsync("demo.wireguard.com", 42912);
            var stream = client.GetStream();
            var reader = new StreamReader(stream, Encoding.UTF8);
            var pubKeyBytes = Encoding.UTF8.GetBytes(keys.Public + "\n");
            await stream.WriteAsync(pubKeyBytes, 0, pubKeyBytes.Length);
            await stream.FlushAsync();
            var ret = (await reader.ReadLineAsync()).Split(':');
            client.Close();
            var status = ret.Length >= 1 ? ret[0] : "";
            var serverPubkey = ret.Length >= 2 ? ret[1] : "";
            var serverPort = ret.Length >= 3 ? ret[2] : "";
            var internalIP = ret.Length >= 4 ? ret[3] : "";
            if (status != "OK")
                throw new InvalidOperationException(string.Format("Server status is {0}", status));
            return string.Format("[Interface]\nPrivateKey = {0}\nAddress = {1}/24\nDNS = 8.8.8.8, 8.8.4.4\n\n[Peer]\nPublicKey = {2}\nEndpoint = demo.wireguard.com:{3}\nAllowedIPs = 0.0.0.0/0\n", keys.Private, internalIP, serverPubkey, serverPort);
        }

        private async void connectButton_Click(object sender, EventArgs e)
        {
            if (connected)
            {
                connectButton.Enabled = false;
                await Task.Run(() =>
                {
                    Tunnel.Service.Remove(configFile, true);
                    try { File.Delete(configFile); } catch { }
                });
                updateTransferTitle(0, 0);
                connectButton.Text = "&Connect";
                connectButton.Enabled = true;
                connected = false;
                return;
            }

            connectButton.Enabled = false;
            try
            {
                var config = await generateNewConfig();
                await File.WriteAllBytesAsync(configFile, Encoding.UTF8.GetBytes(config));
                await Task.Run(() => Tunnel.Service.Add(configFile, true));
                connected = true;
                connectButton.Text = "&Disconnect";
            }
            catch (Exception ex)
            {
                log.Write(ex.Message);
                try { File.Delete(configFile); } catch { }
            }
            connectButton.Enabled = true;
        }
    }
}
