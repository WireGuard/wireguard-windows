/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

using System;
using System.Net.Sockets;
using System.IO;
using System.Text;
using System.Diagnostics;
using System.Threading;
using System.Runtime.InteropServices;

namespace Tunnel
{
    class Program
    {

        [DllImport("kernel32.dll")]
        private static extern bool SetConsoleCtrlHandler(SetConsoleCtrlEventHandler handler, bool add);
        private delegate bool SetConsoleCtrlEventHandler(UInt32 signal);

        public static void Main(string[] args)
        {
            if (args.Length == 2 && args[0] == "/service")
            {
                Service.Run(args[1]);
                return;
            }

            var baseDirectory = Path.GetDirectoryName(Process.GetCurrentProcess().MainModule.FileName);
            var configFile = Path.Combine(baseDirectory, "demobox.conf");
            var logFile = Path.Combine(baseDirectory, "log.bin");

            try { File.Delete(logFile); } catch { }
            Ringlogger log = new Ringlogger(logFile, "GUI");

            var logPrintingThread = new Thread(() =>
            {
                var cursor = Ringlogger.CursorAll;
                while (Thread.CurrentThread.IsAlive)
                {
                    var lines = log.FollowFromCursor(ref cursor);
                    foreach (var line in lines)
                        Console.WriteLine(line);
                    Thread.Sleep(300);
                }
            });
            logPrintingThread.Start();

            log.Write("Generating keys");
            var keys = Keypair.Generate();
            log.Write("Exchanging keys with demo server");
            var client = new TcpClient("demo.wireguard.com", 42912);
            var stream = client.GetStream();
            var reader = new StreamReader(stream, Encoding.UTF8);
            var pubKeyBytes = Encoding.UTF8.GetBytes(keys.Public + "\n");
            stream.Write(pubKeyBytes, 0, pubKeyBytes.Length);
            stream.Flush();
            var ret = reader.ReadLine().Split(':');
            client.Close();
            var status = ret.Length >= 1 ? ret[0] : "";
            var serverPubkey = ret.Length >= 2 ? ret[1] : "";
            var serverPort = ret.Length >= 3 ? ret[2] : "";
            var internalIP = ret.Length >= 4 ? ret[3] : "";

            if (status != "OK")
                throw new InvalidOperationException(String.Format("Server status is {0}", status));

            SetConsoleCtrlHandler(delegate
            {
                Service.Remove(configFile);
                Environment.Exit(0);
                return true;
            }, true);

            log.Write("Writing config file to disk");
            var configFileContents = String.Format("[Interface]\nPrivateKey = {0}\nAddress = {1}/24\nDNS = 8.8.8.8, 8.8.4.4\n\n[Peer]\nPublicKey = {2}\nEndpoint = demo.wireguard.com:{3}\nAllowedIPs = 0.0.0.0/0\n", keys.Private, internalIP, serverPubkey, serverPort);
            File.WriteAllText(configFile, configFileContents);

            try
            {
                Service.Add(configFile);
                logPrintingThread.Join();
            }
            finally
            {
                Service.Remove(configFile);
            }
        }
    }
}
