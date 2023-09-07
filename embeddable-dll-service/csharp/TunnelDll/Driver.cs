/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2022 WireGuard LLC. All Rights Reserved.
 */

using System;
using System.ComponentModel;
using System.Net;
using System.Runtime.InteropServices;

namespace Tunnel
{
    public class Driver
    {
        [DllImport("wireguard.dll", EntryPoint = "WireGuardOpenAdapter", CallingConvention = CallingConvention.StdCall, SetLastError = true)]
        private static extern IntPtr openAdapter([MarshalAs(UnmanagedType.LPWStr)] string name);
        [DllImport("wireguard.dll", EntryPoint = "WireGuardCloseAdapter", CallingConvention = CallingConvention.StdCall)]
        private static extern void freeAdapter(IntPtr adapter);
        [DllImport("wireguard.dll", EntryPoint = "WireGuardGetConfiguration", CallingConvention = CallingConvention.StdCall, SetLastError = true)]
        private static extern bool getConfiguration(IntPtr adapter, byte[] iface, ref UInt32 bytes);

        public class Adapter
        {
            private IntPtr _handle;
            private UInt32 _lastGetGuess;
            public Adapter(string name)
            {
                _lastGetGuess = 1024;
                _handle = openAdapter(name);
                if (_handle == IntPtr.Zero)
                    throw new Win32Exception();
            }
            ~Adapter()
            {
                freeAdapter(_handle);
            }
            public unsafe Interface GetConfiguration()
            {
                var iface = new Interface();
                byte[] bytes;
                for (; ; )
                {
                    bytes = new byte[_lastGetGuess];
                    if (getConfiguration(_handle, bytes, ref _lastGetGuess))
                        break;
                    if (Marshal.GetLastWin32Error() != 234 /* ERROR_MORE_DATA */)
                        throw new Win32Exception();
                }
                fixed (void* start = bytes)
                {
                    var ioctlIface = (IoctlInterface*)start;
                    if ((ioctlIface->Flags & IoctlInterfaceFlags.HasPublicKey) != 0)
                        iface.PublicKey = new Key(ioctlIface->PublicKey);
                    if ((ioctlIface->Flags & IoctlInterfaceFlags.HasPrivateKey) != 0)
                        iface.PrivateKey = new Key(ioctlIface->PrivateKey);
                    if ((ioctlIface->Flags & IoctlInterfaceFlags.HasListenPort) != 0)
                        iface.ListenPort = ioctlIface->ListenPort;
                    var peers = new Peer[ioctlIface->PeersCount];
                    var ioctlPeer = (IoctlPeer*)((byte*)ioctlIface + sizeof(IoctlInterface));
                    for (UInt32 i = 0; i < peers.Length; ++i)
                    {
                        var peer = new Peer();
                        if ((ioctlPeer->Flags & IoctlPeerFlags.HasPublicKey) != 0)
                            peer.PublicKey = new Key(ioctlPeer->PublicKey);
                        if ((ioctlPeer->Flags & IoctlPeerFlags.HasPresharedKey) != 0)
                            peer.PresharedKey = new Key(ioctlPeer->PresharedKey);
                        if ((ioctlPeer->Flags & IoctlPeerFlags.HasPersistentKeepalive) != 0)
                            peer.PersistentKeepalive = ioctlPeer->PersistentKeepalive;
                        if ((ioctlPeer->Flags & IoctlPeerFlags.HasEndpoint) != 0)
                        {
                            if (ioctlPeer->Endpoint.si_family == Win32.ADDRESS_FAMILY.AF_INET)
                            {
                                var ip = new byte[4];
                                Marshal.Copy((IntPtr)ioctlPeer->Endpoint.Ipv4.sin_addr.bytes, ip, 0, 4);
                                peer.Endpoint = new IPEndPoint(new IPAddress(ip), (ushort)IPAddress.NetworkToHostOrder((short)ioctlPeer->Endpoint.Ipv4.sin_port));
                            }
                            else if (ioctlPeer->Endpoint.si_family == Win32.ADDRESS_FAMILY.AF_INET6)
                            {
                                var ip = new byte[16];
                                Marshal.Copy((IntPtr)ioctlPeer->Endpoint.Ipv6.sin6_addr.bytes, ip, 0, 16);
                                peer.Endpoint = new IPEndPoint(new IPAddress(ip), (ushort)IPAddress.NetworkToHostOrder((short)ioctlPeer->Endpoint.Ipv6.sin6_port));
                            }
                        }
                        peer.TxBytes = ioctlPeer->TxBytes;
                        peer.RxBytes = ioctlPeer->RxBytes;
                        if (ioctlPeer->LastHandshake != 0)
                            peer.LastHandshake = DateTime.FromFileTimeUtc((long)ioctlPeer->LastHandshake);
                        var allowedIPs = new AllowedIP[ioctlPeer->AllowedIPsCount];
                        var ioctlAllowedIP = (IoctlAllowedIP*)((byte*)ioctlPeer + sizeof(IoctlPeer));
                        for (UInt32 j = 0; j < allowedIPs.Length; ++j)
                        {
                            var allowedIP = new AllowedIP();
                            if (ioctlAllowedIP->AddressFamily == Win32.ADDRESS_FAMILY.AF_INET)
                            {
                                var ip = new byte[4];
                                Marshal.Copy((IntPtr)ioctlAllowedIP->V4.bytes, ip, 0, 4);
                                allowedIP.Address = new IPAddress(ip);
                            }
                            else if (ioctlAllowedIP->AddressFamily == Win32.ADDRESS_FAMILY.AF_INET6)
                            {
                                var ip = new byte[16];
                                Marshal.Copy((IntPtr)ioctlAllowedIP->V6.bytes, ip, 0, 16);
                                allowedIP.Address = new IPAddress(ip);
                            }
                            allowedIP.Cidr = ioctlAllowedIP->Cidr;
                            allowedIPs[j] = allowedIP;
                            ioctlAllowedIP = (IoctlAllowedIP*)((byte*)ioctlAllowedIP + sizeof(IoctlAllowedIP));
                        }
                        peer.AllowedIPs = allowedIPs;
                        peers[i] = peer;
                        ioctlPeer = (IoctlPeer*)ioctlAllowedIP;
                    }
                    iface.Peers = peers;
                }
                return iface;
            }

            public class Key
            {
                private byte[] _bytes;
                public byte[] Bytes
                {
                    get
                    {
                        return _bytes;
                    }
                    set
                    {
                        if (value == null || value.Length != 32)
                            throw new ArgumentException("Keys must be 32 bytes");
                        _bytes = value;
                    }
                }
                public Key(byte[] bytes)
                {
                    Bytes = bytes;
                }
                public unsafe Key(byte* bytes)
                {
                    _bytes = new byte[32];
                    Marshal.Copy((IntPtr)bytes, _bytes, 0, 32);
                }
                public override String ToString()
                {
                    return Convert.ToBase64String(_bytes);
                }
            }

            public class Interface
            {
                public UInt16 ListenPort { get; set; }
                public Key PrivateKey { get; set; }
                public Key PublicKey { get; set; }
                public Peer[] Peers { get; set; }
            }

            public class Peer
            {
                public Key PublicKey { get; set; }
                public Key PresharedKey { get; set; }
                public UInt16 PersistentKeepalive { get; set; }
                public IPEndPoint Endpoint { get; set; }
                public UInt64 TxBytes { get; set; }
                public UInt64 RxBytes { get; set; }
                public DateTime LastHandshake { get; set; }
                public AllowedIP[] AllowedIPs { get; set; }
            }

            public class AllowedIP
            {
                public IPAddress Address { get; set; }
                public byte Cidr { get; set; }
            }

            private enum IoctlInterfaceFlags : UInt32
            {
                HasPublicKey = 1 << 0,
                HasPrivateKey = 1 << 1,
                HasListenPort = 1 << 2,
                ReplacePeers = 1 << 3
            };

            [StructLayout(LayoutKind.Sequential, Pack = 8, Size = 80)]
            private unsafe struct IoctlInterface
            {
                public IoctlInterfaceFlags Flags;
                public UInt16 ListenPort;
                public fixed byte PrivateKey[32];
                public fixed byte PublicKey[32];
                public UInt32 PeersCount;
            };

            private enum IoctlPeerFlags : UInt32
            {
                HasPublicKey = 1 << 0,
                HasPresharedKey = 1 << 1,
                HasPersistentKeepalive = 1 << 2,
                HasEndpoint = 1 << 3,
                ReplaceAllowedIPs = 1 << 5,
                Remove = 1 << 6,
                UpdateOnly = 1 << 7
            };

            [StructLayout(LayoutKind.Sequential, Pack = 8, Size = 136)]
            private unsafe struct IoctlPeer
            {
                public IoctlPeerFlags Flags;
                public UInt32 Reserved;
                public fixed byte PublicKey[32];
                public fixed byte PresharedKey[32];
                public UInt16 PersistentKeepalive;
                public Win32.SOCKADDR_INET Endpoint;
                public UInt64 TxBytes, RxBytes;
                public UInt64 LastHandshake;
                public UInt32 AllowedIPsCount;
            };

            [StructLayout(LayoutKind.Explicit, Pack = 8, Size = 24)]
            private unsafe struct IoctlAllowedIP
            {
                [FieldOffset(0)]
                [MarshalAs(UnmanagedType.Struct)]
                public Win32.IN_ADDR V4;
                [FieldOffset(0)]
                [MarshalAs(UnmanagedType.Struct)]
                public Win32.IN6_ADDR V6;
                [FieldOffset(16)]
                public Win32.ADDRESS_FAMILY AddressFamily;
                [FieldOffset(18)]
                public byte Cidr;
            }
        }
    }
}
