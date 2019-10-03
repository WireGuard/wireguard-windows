/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

using System;
using System.Net.Sockets;
using System.IO;
using System.Text;
using System.Diagnostics;

namespace Tunnel
{
    class Program
    {
        static void Main(string[] args)
        {
            if (args.Length == 2 && args[0] == "/service")
            {
                Service.Run(args[1]);
                return;
            }
            var keys = Keypair.Generate();
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

            var configFileContents = String.Format("[Interface]\nPrivateKey = {0}\nAddress = {1}/24\nDNS = 8.8.8.8, 8.8.4.4\n\n[Peer]\nPublicKey = {2}\nEndpoint = demo.wireguard.com:{3}\nAllowedIPs = 0.0.0.0/0\n", keys.Private, internalIP, serverPubkey, serverPort);
            var configFile = Path.Combine(Path.GetDirectoryName(Process.GetCurrentProcess().MainModule.FileName), "demobox.conf");
            File.WriteAllText(configFile, configFileContents);

            try
            {
                Service.Add(configFile);
                Console.WriteLine("=== Press enter to exit ===");
                Console.ReadLine();
            }
            finally
            {
                Service.Remove(configFile);
            }
        }
    }
}
