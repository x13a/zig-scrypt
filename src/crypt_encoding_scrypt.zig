// SPDX-License-Identifier: MIT
// Copyright (c) 2015-2021 Zig Contributors
// This file is part of [zig](https://ziglang.org/), which is MIT licensed.
// The MIT license requires this copyright notice to be included in all copies
// and substantial portions of the software.

// Modular crypt(3) format for scrypt
// https://en.wikipedia.org/wiki/Crypt_(C)
// https://gitlab.com/jas/scrypt-unix-crypt/blob/master/unix-scrypt.txt

const std = @import("std");
const io = std.io;
const math = std.math;
const mem = std.mem;
const meta = std.meta;

pub const Error = std.crypto.errors.Error || error{NoSpaceLeft};

/// Standard type for a set of scrypt parameters, with the salt and hash.
pub fn HashResult(comptime max_hash_len: usize) type {
    return struct {
        ln: u6,
        r: u30,
        p: u30,
        salt: []const u8,
        hash: BinValue(max_hash_len),
    };
}

/// scrypt parameters only - no salt nor hash.
pub const HashParameters = struct {
    ln: u6,
    r: u30,
    p: u30,
};

/// A wrapped binary value whose maximum size is `max_len`.
///
/// This type must be used whenever a binary value is encoded in a PHC-formatted string.
/// This includes `salt`, `hash`, and any other binary parameters such as keys.
///
/// Once initialized, the actual value can be read with the `unwrap()` function.
pub fn BinValue(comptime max_len: usize) type {
    return struct {
        const Self = @This();
        const capacity = max_len;
        const max_encoded_length = Codec.encodedLen(max_len);

        buf: [max_len]u8 = undefined,
        len: usize = 0,

        /// Wrap an existing byte slice
        pub fn fromSlice(slice: []const u8) Error!Self {
            if (slice.len > capacity) return Error.NoSpaceLeft;
            var bin_value: Self = undefined;
            mem.copy(u8, &bin_value.buf, slice);
            bin_value.len = slice.len;
            return bin_value;
        }

        /// Return the slice containing the actual value.
        pub fn unwrap(self: Self) []const u8 {
            return self.buf[0..self.len];
        }

        fn fromB64(self: *Self, str: []const u8) !void {
            const len = Codec.decodedLen(str.len);
            if (len > self.buf.len) return Error.NoSpaceLeft;
            try Codec.decode(self.buf[0..len], str);
            self.len = len;
        }

        fn toB64(self: Self, buf: []u8) ![]const u8 {
            const value = self.unwrap();
            const len = Codec.encodedLen(value.len);
            if (len > buf.len) return Error.NoSpaceLeft;
            var encoded = buf[0..len];
            Codec.encode(encoded, value);
            return encoded;
        }
    };
}

/// Expand binary data into a salt for the modular crypt format.
pub fn saltFromBin(comptime len: usize, salt: [len]u8) [Codec.encodedLen(len)]u8 {
    var buf: [Codec.encodedLen(len)]u8 = undefined;
    Codec.encode(&buf, &salt);
    return buf;
}

const Codec = CustomB64Codec("./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz".*);

/// String prefix for scrypt
pub const prefix = "$7$";

/// Deserialize a string into a structure `T` (matching `HashResult`).
pub fn deserialize(comptime T: type, str: []const u8) Error!T {
    var out: T = undefined;

    if (str.len < 16) return Error.InvalidEncoding;
    if (!mem.eql(u8, prefix, str[0..3])) return Error.InvalidEncoding;
    out.ln = try Codec.intDecode(u6, str[3..4]);
    out.r = try Codec.intDecode(u30, str[4..9]);
    out.p = try Codec.intDecode(u30, str[9..14]);

    var it = mem.split(str[14..], "$");

    const salt = it.next() orelse return Error.InvalidEncoding;
    if (@hasField(T, "salt")) out.salt = salt;

    const hash_str = it.next() orelse return Error.InvalidEncoding;
    if (@hasField(T, "hash")) try out.hash.fromB64(hash_str);

    return out;
}

/// Serialize parameters into a string in modular crypt format.
pub fn serialize(params: anytype, str: []u8) Error![]const u8 {
    var buf = io.fixedBufferStream(str);
    try serializeTo(params, buf.writer());
    return buf.getWritten();
}

/// Compute the number of bytes required to serialize `params`
pub fn calcSize(params: anytype) usize {
    var buf = io.countingWriter(io.null_writer);
    serializeTo(params, buf.writer()) catch unreachable;
    return @intCast(usize, buf.bytes_written);
}

fn serializeTo(params: anytype, out: anytype) !void {
    var header: [14]u8 = undefined;
    mem.copy(u8, header[0..3], prefix);
    Codec.intEncode(header[3..4], params.ln);
    Codec.intEncode(header[4..9], params.r);
    Codec.intEncode(header[9..14], params.p);
    try out.writeAll(&header);
    try out.writeAll(params.salt);
    try out.writeAll("$");
    var buf: [@TypeOf(params.hash).max_encoded_length]u8 = undefined;
    const hash_str = try params.hash.toB64(&buf);
    try out.writeAll(hash_str);
}

/// Custom codec that maps 6 bits into 8 like regular Base64, but uses its own alphabet, 
/// encodes bits in little-endian, and can also encode integers.
fn CustomB64Codec(comptime map: [64]u8) type {
    return struct {
        const map64 = map;

        fn encodedLen(len: usize) usize {
            return (len * 4 + 2) / 3;
        }

        fn decodedLen(len: usize) usize {
            return len / 4 * 3 + (len % 4) * 3 / 4;
        }

        fn intEncode(dst: []u8, src: anytype) void {
            var n = src;
            for (dst) |*x, i| {
                x.* = map64[@truncate(u6, n)];
                n = math.shr(@TypeOf(src), n, 6);
            }
        }

        fn intDecode(comptime T: type, src: *const [(meta.bitCount(T) + 5) / 6]u8) !T {
            var v: T = 0;
            for (src) |x, i| {
                const vi = mem.indexOfScalar(u8, &map64, x) orelse return Error.InvalidEncoding;
                v |= @intCast(T, vi) << @intCast(math.Log2Int(T), i * 6);
            }
            return v;
        }

        fn decode(dst: []u8, src: []const u8) !void {
            std.debug.assert(dst.len == decodedLen(src.len));
            var i: usize = 0;
            while (i < src.len / 4) : (i += 1) {
                mem.writeIntSliceLittle(u24, dst[i * 3 ..], try intDecode(u24, src[i * 4 ..][0..4]));
            }
            const leftover = src[i * 4 ..];
            var v: u24 = 0;
            for (leftover) |_, j| {
                v |= @as(u24, try intDecode(u6, leftover[j..][0..1])) << @intCast(u5, j * 6);
            }
            for (dst[i * 3 ..]) |*x, j| {
                x.* = @truncate(u8, v >> @intCast(u5, j * 8));
            }
        }

        fn encode(dst: []u8, src: []const u8) void {
            std.debug.assert(dst.len == encodedLen(src.len));
            var i: usize = 0;
            while (i < src.len / 3) : (i += 1) {
                intEncode(dst[i * 4 ..][0..4], mem.readIntSliceLittle(u24, src[i * 3 ..]));
            }
            const leftover = src[i * 3 ..];
            var v: u24 = 0;
            for (leftover) |x, j| {
                v |= @as(u24, x) << @intCast(u5, j * 8);
            }
            intEncode(dst[i * 4 ..], v);
        }
    };
}

test "scrypt crypt format" {
    const str = "$7$C6..../....SodiumChloride$kBGj9fHznVYFQMEn/qDCfrDevf9YDtcDdKvEqHJLV8D";
    const params = try deserialize(HashResult(32), str);
    var buf: [str.len]u8 = undefined;
    const s1 = try serialize(params, &buf);
    try std.testing.expectEqualStrings(s1, str);
}
