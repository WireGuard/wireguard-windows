/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

using System;
using System.ComponentModel;
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

        public static Keypair Generate()
        {
            var algoHandle = new IntPtr();
            var statusCode = Win32.BCryptOpenAlgorithmProvider(ref algoHandle, Win32.BCRYPT_ECDH_ALGORITHM, null, 0);
            if (statusCode > 0)
                throw new Win32Exception((int)statusCode);

            try
            {
                var curveType = Win32.BCRYPT_ECC_CURVE_25519 + Char.MinValue;
                statusCode = Win32.BCryptSetProperty(algoHandle, Win32.BCRYPT_ECC_CURVE_NAME, curveType, curveType.Length * sizeof(char), 0);
                if (statusCode > 0)
                    throw new Win32Exception((int)statusCode);
                var key = new IntPtr();
                statusCode = Win32.BCryptGenerateKeyPair(algoHandle, ref key, 255, 0);
                if (statusCode > 0)
                    throw new Win32Exception((int)statusCode);
                try
                {
                    statusCode = Win32.BCryptFinalizeKeyPair(key, 0);
                    if (statusCode > 0)
                        throw new Win32Exception((int)statusCode);

                    var keyBlob = new Win32.KeyBlob();
                    int exportedKeySize = 0;
                    statusCode = Win32.BCryptExportKey(key, IntPtr.Zero, Win32.BCRYPT_ECCPRIVATE_BLOB, keyBlob, Marshal.SizeOf(typeof(Win32.KeyBlob)), out exportedKeySize);
                    if (statusCode > 0)
                        throw new Win32Exception((int)statusCode);

                    return new Keypair(Convert.ToBase64String(keyBlob.Public), Convert.ToBase64String(keyBlob.Private));
                }
                finally
                {
                    Win32.BCryptDestroyKey(key);
                }
            }
            finally
            {
                Win32.BCryptCloseAlgorithmProvider(algoHandle, 0);
            }
        }
    }
}
