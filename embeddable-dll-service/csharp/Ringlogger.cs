/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

using System;
using System.IO;
using System.IO.MemoryMappedFiles;
using System.Text;

namespace Tunnel
{
    public class Ringlogger
    {
        private readonly MemoryMappedViewAccessor _viewAccessor;

        public Ringlogger(string filename)
        {
            var file = File.Open(filename, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            var mmap = MemoryMappedFile.CreateFromFile(file, null, 0, MemoryMappedFileAccess.Read, HandleInheritability.None, false);
            _viewAccessor = mmap.CreateViewAccessor(0, 8 + 2048 * (512 + 8), MemoryMappedFileAccess.Read);
            if (_viewAccessor.ReadUInt32(0) != 0xbadbabe)
                throw new InvalidDataException("The provided file is missing the magic number.");
        }

        public void WriteTo(TextWriter writer)
        {
            var start = _viewAccessor.ReadUInt32(4);
            for (var i = 0; i < 2048; ++i)
            {
                var lineOffset = 8 + (8 + 512) * ((i + start) % 2048);
                var timeNs = _viewAccessor.ReadInt64(lineOffset);
                if (timeNs == 0)
                    continue;
                var textBytes = new byte[512];
                _viewAccessor.ReadArray<byte>(lineOffset + 8, textBytes, 0, textBytes.Length);
                var nullByte = Array.IndexOf<byte>(textBytes, 0);
                if (nullByte <= 0)
                    continue;
                var text = Encoding.UTF8.GetString(textBytes, 0, nullByte);
                var time = DateTimeOffset.FromUnixTimeMilliseconds(timeNs / 1000000).ToString("yyyy'-'MM'-'dd HH':'mm':'ss'.'ffffff");
                writer.WriteLine(String.Format("{0}: {1}", time, text));
            }
        }
    }
}
