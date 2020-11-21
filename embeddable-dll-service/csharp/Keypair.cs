/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2020 WireGuard LLC. All Rights Reserved.
 */

using System;
using System.Runtime.InteropServices;

namespace Tunnel
{
    public class Keypair
    {
        public readonly string Public;
        public readonly string Private;

        private Keypair(string pub, string priv)
        {
            Public = pub;
            Private = priv;
        }

        [DllImport("tunnel.dll", EntryPoint = "WireGuardGenerateKeypair", CallingConvention = CallingConvention.Cdecl)]
        private static extern bool WireGuardGenerateKeypair(byte[] publicKey, byte[] privateKey);

        public static Keypair Generate()
        {
            var publicKey = new byte[32];
            var privateKey = new byte[32];
            WireGuardGenerateKeypair(publicKey, privateKey);
            return new Keypair(Convert.ToBase64String(publicKey), Convert.ToBase64String(privateKey));
        }
    }
}
