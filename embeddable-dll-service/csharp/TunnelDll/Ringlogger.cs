/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2021 WireGuard LLC. All Rights Reserved.
 */

using System;
using System.IO;
using System.IO.MemoryMappedFiles;
using System.Text;
using System.Collections.Generic;
using System.Threading;
using System.Runtime.CompilerServices;

namespace Tunnel
{
    public class Ringlogger
    {
        private struct UnixTimestamp
        {
            private Int64 _ns;
            public UnixTimestamp(Int64 ns) => _ns = ns;
            public bool IsEmpty => _ns == 0;
            public static UnixTimestamp Empty => new UnixTimestamp(0);
            public static UnixTimestamp Now
            {
                get
                {
                    var now = DateTimeOffset.UtcNow;
                    var ns = (now.Subtract(DateTimeOffset.FromUnixTimeSeconds(0)).Ticks * 100) % 1000000000;
                    return new UnixTimestamp(now.ToUnixTimeSeconds() * 1000000000 + ns);
                }
            }
            public Int64 Nanoseconds => _ns;
            public override string ToString()
            {
                return DateTimeOffset.FromUnixTimeSeconds(_ns / 1000000000).LocalDateTime.ToString("yyyy'-'MM'-'dd HH':'mm':'ss'.'") + ((_ns % 1000000000).ToString() + "00000").Substring(0, 6);
            }
        }
        private struct Line
        {
            private const int maxLineLength = 512;
            private const int offsetTimeNs = 0;
            private const int offsetLine = 8;

            private readonly MemoryMappedViewAccessor _view;
            private readonly int _start;
            public Line(MemoryMappedViewAccessor view, UInt32 index) => (_view, _start) = (view, (int)(Log.HeaderBytes + index * Bytes));

            public static int Bytes => maxLineLength + offsetLine;

            public UnixTimestamp Timestamp
            {
                get => new UnixTimestamp(_view.ReadInt64(_start + offsetTimeNs));
                set => _view.Write(_start + offsetTimeNs, value.Nanoseconds);
            }

            public string Text
            {
                get
                {
                    var textBytes = new byte[maxLineLength];
                    _view.ReadArray(_start + offsetLine, textBytes, 0, textBytes.Length);
                    var nullByte = Array.IndexOf<byte>(textBytes, 0);
                    if (nullByte <= 0)
                        return null;
                    return Encoding.UTF8.GetString(textBytes, 0, nullByte);
                }
                set
                {
                    if (value == null)
                    {
                        _view.WriteArray(_start + offsetLine, new byte[maxLineLength], 0, maxLineLength);
                        return;
                    }
                    var textBytes = Encoding.UTF8.GetBytes(value);
                    var bytesToWrite = Math.Min(maxLineLength - 1, textBytes.Length);
                    _view.Write(_start + offsetLine + bytesToWrite, (byte)0);
                    _view.WriteArray(_start + offsetLine, textBytes, 0, bytesToWrite);
                }
            }

            public override string ToString()
            {
                var time = Timestamp;
                if (time.IsEmpty)
                    return null;
                var text = Text;
                if (text == null)
                    return null;
                return string.Format("{0}: {1}", time, text);
            }
        }
        private struct Log
        {
            private const UInt32 maxLines = 2048;
            private const UInt32 magic = 0xbadbabe;
            private const int offsetMagic = 0;
            private const int offsetNextIndex = 4;
            private const int offsetLines = 8;

            private readonly MemoryMappedViewAccessor _view;
            public Log(MemoryMappedViewAccessor view) => _view = view;

            public static int HeaderBytes => offsetLines;
            public static int Bytes => (int)(HeaderBytes + Line.Bytes * maxLines);

            public UInt32 ExpectedMagic => magic;
            public UInt32 Magic
            {
                get => _view.ReadUInt32(offsetMagic);
                set => _view.Write(offsetMagic, value);
            }

            public UInt32 NextIndex
            {
                get => _view.ReadUInt32(offsetNextIndex);
                set => _view.Write(offsetNextIndex, value);
            }
            public unsafe UInt32 InsertNextIndex()
            {
                byte* pointer = null;
                _view.SafeMemoryMappedViewHandle.AcquirePointer(ref pointer);
                var ret = (UInt32)Interlocked.Increment(ref Unsafe.AsRef<Int32>(pointer + offsetNextIndex));
                _view.SafeMemoryMappedViewHandle.ReleasePointer();
                return ret;
            }

            public UInt32 LineCount => maxLines;
            public Line this[UInt32 i] => new Line(_view, i % maxLines);

            public void Clear() => _view.WriteArray(0, new byte[Bytes], 0, Bytes);
        }

        private readonly Log _log;
        private readonly string _tag;

        public Ringlogger(string filename, string tag)
        {
            var file = File.Open(filename, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.ReadWrite | FileShare.Delete);
            file.SetLength(Log.Bytes);
            var mmap = MemoryMappedFile.CreateFromFile(file, null, 0, MemoryMappedFileAccess.ReadWrite, HandleInheritability.None, false);
            var view = mmap.CreateViewAccessor(0, Log.Bytes, MemoryMappedFileAccess.ReadWrite);
            _log = new Log(view);
            if (_log.Magic != _log.ExpectedMagic)
            {
                _log.Clear();
                _log.Magic = _log.ExpectedMagic;
            }
            _tag = tag;
        }

        public void Write(string line)
        {
            var time = UnixTimestamp.Now;
            var entry = _log[_log.InsertNextIndex() - 1];
            entry.Timestamp = UnixTimestamp.Empty;
            entry.Text = null;
            entry.Text = string.Format("[{0}] {1}", _tag, line.Trim());
            entry.Timestamp = time;
        }

        public void WriteTo(TextWriter writer)
        {
            var start = _log.NextIndex;
            for (UInt32 i = 0; i < _log.LineCount; ++i)
            {
                var entry = _log[i + start];
                if (entry.Timestamp.IsEmpty)
                    continue;
                var text = entry.ToString();
                if (text == null)
                    continue;
                writer.WriteLine(text);
            }
        }

        public static readonly UInt32 CursorAll = UInt32.MaxValue;
        public List<string> FollowFromCursor(ref UInt32 cursor)
        {
            var lines = new List<string>((int)_log.LineCount);
            var i = cursor;
            var all = cursor == CursorAll;
            if (all)
                i = _log.NextIndex;
            for (UInt32 l = 0; l < _log.LineCount; ++l, ++i)
            {
                if (!all && i % _log.LineCount == _log.NextIndex % _log.LineCount)
                    break;
                var entry = _log[i];
                if (entry.Timestamp.IsEmpty)
                {
                    if (all)
                        continue;
                    break;
                }
                cursor = (i + 1) % _log.LineCount;
                var text = entry.ToString();
                if (text == null)
                    continue;
                lines.Add(text);
            }
            return lines;
        }
    }
}
