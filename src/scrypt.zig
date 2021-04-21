// SPDX-License-Identifier: MIT
// Copyright (c) 2015-2021 Zig Contributors
// This file is part of [zig](https://ziglang.org/), which is MIT licensed.
// The MIT license requires this copyright notice to be included in all copies
// and substantial portions of the software.

// https://tools.ietf.org/html/rfc7914
// https://github.com/golang/crypto/blob/master/scrypt/scrypt.go

const std = @import("std");
const crypto = std.crypto;
const fmt = std.fmt;
const math = std.math;
const mem = std.mem;

const phc_format = @import("phc_encoding.zig");
const crypt_format = @import("crypt_encoding_scrypt.zig");
const pwhash = @import("pwhash.zig");

const HmacSha256 = crypto.auth.hmac.sha2.HmacSha256;

pub const KdfError = crypto.Error || mem.Allocator.Error;
pub const Error = KdfError || phc_format.Error || crypt_format.Error;

const max_size = math.maxInt(usize);
const max_int = max_size >> 1;
const default_salt_len = 32;
const default_hash_len = 32;
const max_salt_len = 64;
const max_hash_len = 64;

fn blockCopy(dst: []align(16) u32, src: []align(16) const u32, n: usize) void {
    mem.copy(u32, dst, src[0 .. n * 16]);
}

fn blockXor(dst: []align(16) u32, src: []align(16) const u32, n: usize) void {
    for (src[0 .. n * 16]) |v, i| {
        dst[i] ^= v;
    }
}

const QuarterRound = struct { a: usize, b: usize, c: usize, d: u6 };

fn Rp(a: usize, b: usize, c: usize, d: u6) QuarterRound {
    return QuarterRound{ .a = a, .b = b, .c = c, .d = d };
}

fn salsa8core(b: *align(16) [16]u32) void {
    const arx_steps = comptime [_]QuarterRound{
        Rp(4, 0, 12, 7),   Rp(8, 4, 0, 9),    Rp(12, 8, 4, 13),   Rp(0, 12, 8, 18),
        Rp(9, 5, 1, 7),    Rp(13, 9, 5, 9),   Rp(1, 13, 9, 13),   Rp(5, 1, 13, 18),
        Rp(14, 10, 6, 7),  Rp(2, 14, 10, 9),  Rp(6, 2, 14, 13),   Rp(10, 6, 2, 18),
        Rp(3, 15, 11, 7),  Rp(7, 3, 15, 9),   Rp(11, 7, 3, 13),   Rp(15, 11, 7, 18),
        Rp(1, 0, 3, 7),    Rp(2, 1, 0, 9),    Rp(3, 2, 1, 13),    Rp(0, 3, 2, 18),
        Rp(6, 5, 4, 7),    Rp(7, 6, 5, 9),    Rp(4, 7, 6, 13),    Rp(5, 4, 7, 18),
        Rp(11, 10, 9, 7),  Rp(8, 11, 10, 9),  Rp(9, 8, 11, 13),   Rp(10, 9, 8, 18),
        Rp(12, 15, 14, 7), Rp(13, 12, 15, 9), Rp(14, 13, 12, 13), Rp(15, 14, 13, 18),
    };
    var x = b.*;
    var j: usize = 0;
    while (j < 8) : (j += 2) {
        inline for (arx_steps) |r| {
            x[r.a] ^= math.rotl(u32, x[r.b] +% x[r.c], r.d);
        }
    }
    j = 0;
    while (j < 16) : (j += 1) {
        b[j] +%= x[j];
    }
}

fn salsaXor(tmp: *align(16) [16]u32, in: []align(16) const u32, out: []align(16) u32) void {
    blockXor(tmp, in, 1);
    salsa8core(tmp);
    blockCopy(out, tmp, 1);
}

fn blockMix(tmp: *align(16) [16]u32, in: []align(16) const u32, out: []align(16) u32, r: u30) void {
    blockCopy(tmp, in[(2 * r - 1) * 16 ..], 1);
    var i: usize = 0;
    while (i < 2 * r) : (i += 2) {
        salsaXor(tmp, in[i * 16 ..], out[i * 8 ..]);
        salsaXor(tmp, in[i * 16 + 16 ..], out[i * 8 + r * 16 ..]);
    }
}

fn integerify(b: []align(16) const u32, r: u30) u64 {
    const j = (2 * r - 1) * 16;
    return @as(u64, b[j]) | @as(u64, b[j + 1]) << 32;
}

fn smix(b: []align(16) u8, r: u30, n: usize, v: []align(16) u32, xy: []align(16) u32) void {
    var x = xy[0 .. 32 * r];
    var y = xy[32 * r ..];

    for (x) |*v1, j| {
        v1.* = mem.readIntSliceLittle(u32, b[4 * j ..]);
    }

    var tmp: [16]u32 align(16) = undefined;
    var i: usize = 0;
    while (i < n) : (i += 2) {
        blockCopy(v[i * (32 * r) ..], x, 2 * r);
        blockMix(&tmp, x, y, r);

        blockCopy(v[(i + 1) * (32 * r) ..], y, 2 * r);
        blockMix(&tmp, y, x, r);
    }

    i = 0;
    while (i < n) : (i += 2) {
        // 32bit downcast
        var j = @intCast(usize, integerify(x, r) & (n - 1));
        blockXor(x, v[j * (32 * r) ..], 2 * r);
        blockMix(&tmp, x, y, r);

        // 32bit downcast
        j = @intCast(usize, integerify(y, r) & (n - 1));
        blockXor(y, v[j * (32 * r) ..], 2 * r);
        blockMix(&tmp, y, x, r);
    }

    for (x) |v1, j| {
        mem.writeIntLittle(u32, b[4 * j ..][0..4], v1);
    }
}

pub const Params = struct {
    const Self = @This();

    ln: u6,
    r: u30,
    p: u30,

    /// Baseline parameters for interactive logins
    pub const interactive = Self.fromLimits(524288, 16777216);

    /// Baseline parameters for offline usage
    pub const sensitive = Self.fromLimits(33554432, 1073741824);

    /// Create parameters from ops and mem limits
    pub fn fromLimits(ops_limit: u64, mem_limit: usize) Self {
        const ops = math.max(32768, ops_limit);
        const r: u30 = 8;
        if (ops < mem_limit / 32) {
            const max_n = ops / (r * 4);
            return Self{ .r = r, .p = 1, .ln = @intCast(u6, math.log2(max_n)) };
        } else {
            const max_n = mem_limit / (@intCast(usize, r) * 128);
            const ln = @intCast(u6, math.log2(max_n));
            const max_rp = math.min(0x3fffffff, (ops / 4) / (@as(u64, 1) << ln));
            return Self{ .r = r, .p = @intCast(u30, max_rp / @as(u64, r)), .ln = ln };
        }
    }
};

/// Apply scrypt to generate a key from a password.
///
/// scrypt is defined in RFC 7914.
///
/// allocator: *mem.Allocator.
///
/// derived_key: Slice of appropriate size for generated key. Generally 16 or 32 bytes in length.
///              May be uninitialized. All bytes will be overwritten.
///              Maximum size is `derived_key.len / 32 == 0xffff_ffff`.
///
/// password: Arbitrary sequence of bytes of any length.
///
/// salt: Arbitrary sequence of bytes of any length.
///
/// params: Params.
pub fn kdf(
    allocator: *mem.Allocator,
    derived_key: []u8,
    password: []const u8,
    salt: []const u8,
    params: Params,
) KdfError!void {
    if (derived_key.len == 0 or derived_key.len / 32 > 0xffff_ffff) {
        return KdfError.OutputTooLong;
    }
    if (params.ln == 0 or params.r == 0 or params.p == 0) {
        return KdfError.WeakParameters;
    }

    const n64 = @as(u64, 1) << params.ln;
    if (n64 > max_size) {
        return KdfError.WeakParameters;
    }
    const n = @intCast(usize, n64);
    if (@as(u64, params.r) * @as(u64, params.p) >= 1 << 30 or
        params.r > max_int / 128 / @as(u64, params.p) or
        params.r > max_int / 256 or
        n > max_int / 128 / @as(u64, params.r))
    {
        return KdfError.WeakParameters;
    }

    var xy = try allocator.alignedAlloc(u32, 16, 64 * params.r);
    defer allocator.free(xy);
    var v = try allocator.alignedAlloc(u32, 16, 32 * n * params.r);
    defer allocator.free(v);
    var dk = try allocator.alignedAlloc(u8, 16, params.p * 128 * params.r);
    defer allocator.free(dk);

    try crypto.pwhash.pbkdf2(dk, password, salt, 1, HmacSha256);
    var i: u32 = 0;
    while (i < params.p) : (i += 1) {
        smix(dk[i * 128 * params.r ..], params.r, n, v, xy);
    }
    try crypto.pwhash.pbkdf2(derived_key, password, dk, 1, HmacSha256);
}

/// Hash and verify passwords using the PHC format.
const PhcFormatHasher = struct {
    const BinValue = phc_format.BinValue;

    const HashResult = struct {
        alg_id: []const u8,
        ln: u6,
        r: u30,
        p: u30,
        salt: BinValue(max_salt_len),
        hash: BinValue(max_hash_len),
    };

    /// Return a non-deterministic hash of the password encoded as a PHC-format string
    pub fn create(allocator: *mem.Allocator, password: []const u8, params: Params, buf: []u8) (phc_format.Error || KdfError)![]const u8 {
        var salt: [default_salt_len]u8 = undefined;
        crypto.random.bytes(&salt);

        var hash: [default_hash_len]u8 = undefined;
        try kdf(allocator, &hash, password, &salt, params);

        return phc_format.serialize(HashResult{
            .alg_id = "scrypt",
            .ln = params.ln,
            .r = params.r,
            .p = params.p,
            .salt = try BinValue(max_salt_len).fromSlice(&salt),
            .hash = try BinValue(max_hash_len).fromSlice(&hash),
        }, buf);
    }

    /// Verify a password against a PHC-format encoded string
    pub fn verify(
        allocator: *mem.Allocator,
        str: []const u8,
        password: []const u8,
    ) (phc_format.Error || KdfError)!void {
        const hash_result = try phc_format.deserialize(HashResult, str);
        if (!mem.eql(u8, hash_result.alg_id, "scrypt")) return Error.PasswordVerificationFailed;
        const params = Params{ .ln = hash_result.ln, .r = hash_result.r, .p = hash_result.p };
        const expected_hash = hash_result.hash.unwrap();
        var hash_buf: [max_hash_len]u8 = undefined;
        if (expected_hash.len > hash_buf.len) return Error.InvalidEncoding;
        var hash = hash_buf[0..expected_hash.len];
        try kdf(allocator, hash, password, hash_result.salt.unwrap(), params);
        if (!mem.eql(u8, hash, expected_hash)) return Error.PasswordVerificationFailed;
    }
};

/// Hash and verify passwords using the modular crypt format.
const CryptFormatHasher = struct {
    const BinValue = crypt_format.BinValue;
    const HashResult = crypt_format.HashResult(max_hash_len);

    /// Length of a string returned by the create() function
    pub const pwhash_str_length: usize = 101;

    /// Return a non-deterministic hash of the password encoded into the modular crypt format
    pub fn create(allocator: *mem.Allocator, password: []const u8, params: Params, buf: []u8) (crypt_format.Error || KdfError)![]const u8 {
        var salt_bin: [default_salt_len]u8 = undefined;
        crypto.random.bytes(&salt_bin);
        const salt = crypt_format.saltFromBin(salt_bin.len, salt_bin);

        var hash: [default_hash_len]u8 = undefined;
        try kdf(allocator, &hash, password, &salt, params);

        return crypt_format.serialize(HashResult{
            .ln = params.ln,
            .r = params.r,
            .p = params.p,
            .salt = &salt,
            .hash = try BinValue(max_hash_len).fromSlice(&hash),
        }, buf);
    }

    /// Verify a password against a string in modular crypt format
    pub fn verify(
        allocator: *mem.Allocator,
        str: []const u8,
        password: []const u8,
    ) (crypt_format.Error || KdfError)!void {
        const hash_result = try crypt_format.deserialize(HashResult, str);
        const params = Params{ .ln = hash_result.ln, .r = hash_result.r, .p = hash_result.p };
        const expected_hash = hash_result.hash.unwrap();
        var hash_buf: [max_hash_len]u8 = undefined;
        if (expected_hash.len > hash_buf.len) return Error.InvalidEncoding;
        var hash = hash_buf[0..expected_hash.len];
        try kdf(allocator, hash, password, hash_result.salt, params);
        if (!mem.eql(u8, hash, expected_hash)) return Error.PasswordVerificationFailed;
    }
};

/// Options for hashing a password.
pub const HashOptions = struct {
    kdf_params: Params,
    encoding: pwhash.Encoding,
};

/// Compute a hash of a password using the scrypt key derivation function.
/// The function returns a string that includes all the parameters required for verification.
pub fn strHash(
    allocator: *mem.Allocator,
    password: []const u8,
    options: HashOptions,
    out: []u8,
) ![]const u8 {
    switch (options.encoding) {
        .phc => return PhcFormatHasher.create(allocator, password, options.kdf_params, out),
        .crypt => return CryptFormatHasher.create(allocator, password, options.kdf_params, out),
    }
}

/// Options for hash verification.
pub const VerifyOptions = struct {};

/// Verify that a previously computed hash is valid for a given password.
pub fn strVerify(
    allocator: *mem.Allocator,
    str: []const u8,
    password: []const u8,
    options: VerifyOptions,
) !void {
    if (mem.startsWith(u8, str, crypt_format.prefix)) {
        return CryptFormatHasher.verify(allocator, str, password);
    } else {
        return PhcFormatHasher.verify(allocator, str, password);
    }
}

test "kdf" {
    const password = "testpass";
    const salt = "saltsalt";

    var dk: [32]u8 = undefined;
    try kdf(std.testing.allocator, &dk, password, salt, .{ .ln = 15, .r = 8, .p = 1 });

    const hex = "1e0f97c3f6609024022fbe698da29c2fe53ef1087a8e396dc6d5d2a041e886de";
    var bytes: [hex.len / 2]u8 = undefined;
    _ = try fmt.hexToBytes(&bytes, hex);

    std.testing.expectEqualSlices(u8, &bytes, &dk);
}

test "kdf rfc 1" {
    const password = "";
    const salt = "";

    var dk: [64]u8 = undefined;
    try kdf(std.testing.allocator, &dk, password, salt, .{ .ln = 4, .r = 1, .p = 1 });

    const hex = "77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442fcd0069ded0948f8326a753a0fc81f17e8d3e0fb2e0d3628cf35e20c38d18906";
    var bytes: [hex.len / 2]u8 = undefined;
    _ = try fmt.hexToBytes(&bytes, hex);

    std.testing.expectEqualSlices(u8, &bytes, &dk);
}

test "kdf rfc 2" {
    const password = "password";
    const salt = "NaCl";

    var dk: [64]u8 = undefined;
    try kdf(std.testing.allocator, &dk, password, salt, .{ .ln = 10, .r = 8, .p = 16 });

    const hex = "fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b3731622eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640";
    var bytes: [hex.len / 2]u8 = undefined;
    _ = try fmt.hexToBytes(&bytes, hex);

    std.testing.expectEqualSlices(u8, &bytes, &dk);
}

test "kdf rfc 3" {
    const password = "pleaseletmein";
    const salt = "SodiumChloride";

    var dk: [64]u8 = undefined;
    try kdf(std.testing.allocator, &dk, password, salt, .{ .ln = 14, .r = 8, .p = 1 });

    const hex = "7023bdcb3afd7348461c06cd81fd38ebfda8fbba904f8e3ea9b543f6545da1f2d5432955613f0fcf62d49705242a9af9e61e85dc0d651e40dfcf017b45575887";
    var bytes: [hex.len / 2]u8 = undefined;
    _ = try fmt.hexToBytes(&bytes, hex);

    std.testing.expectEqualSlices(u8, &bytes, &dk);
}

test "kdf rfc 4" {
    // skip slow test
    if (true) {
        return error.SkipZigTest;
    }

    const password = "pleaseletmein";
    const salt = "SodiumChloride";

    var dk: [64]u8 = undefined;
    try kdf(std.testing.allocator, &dk, password, salt, .{ .ln = 20, .r = 8, .p = 1 });

    const hex = "2101cb9b6a511aaeaddbbe09cf70f881ec568d574a2ffd4dabe5ee9820adaa478e56fd8f4ba5d09ffa1c6d927c40f4c337304049e8a952fbcbf45c6fa77a41a4";
    var bytes: [hex.len / 2]u8 = undefined;
    _ = try fmt.hexToBytes(&bytes, hex);

    std.testing.expectEqualSlices(u8, &bytes, &dk);
}

test "password hashing (crypt format)" {
    const str = "$7$A6....1....TrXs5Zk6s8sWHpQgWDIXTR8kUU3s6Jc3s.DtdS8M2i4$a4ik5hGDN7foMuHOW.cp.CtX01UyCeO0.JAG.AHPpx5";
    const password = "Y0!?iQa9M%5ekffW(`";
    try CryptFormatHasher.verify(std.testing.allocator, str, password);

    const params = Params.interactive;
    var buf: [CryptFormatHasher.pwhash_str_length]u8 = undefined;
    const str2 = try CryptFormatHasher.create(std.testing.allocator, password, params, &buf);
    try CryptFormatHasher.verify(std.testing.allocator, str2, password);
}

test "strHash and strVerify" {
    const alloc = std.testing.allocator;

    const password = "testpass";
    const verify_options = VerifyOptions{};
    var buf: [128]u8 = undefined;

    const s = try strHash(
        alloc,
        password,
        HashOptions{ .kdf_params = Params.interactive, .encoding = .crypt },
        &buf,
    );
    try strVerify(alloc, s, password, verify_options);

    const s1 = try strHash(
        alloc,
        password,
        HashOptions{ .kdf_params = Params.interactive, .encoding = .phc },
        &buf,
    );
    try strVerify(alloc, s1, password, verify_options);
}

test "unix-scrypt" {
    // https://gitlab.com/jas/scrypt-unix-crypt/blob/master/unix-scrypt.txt
    {
        const str = "$7$C6..../....SodiumChloride$kBGj9fHznVYFQMEn/qDCfrDevf9YDtcDdKvEqHJLV8D";
        const password = "pleaseletmein";
        try strVerify(std.testing.allocator, str, password, .{});
    }
    // one of the libsodium test vectors
    {
        const str = "$7$B6....1....75gBMAGwfFWZqBdyF3WdTQnWdUsuTiWjG1fF9c1jiSD$tc8RoB3.Em3/zNgMLWo2u00oGIoTyJv4fl3Fl8Tix72";
        const password = "^T5H$JYt39n%K*j:W]!1s?vg!:jGi]Ax?..l7[p0v:1jHTpla9;]bUN;?bWyCbtqg nrDFal+Jxl3,2`#^tFSu%v_+7iYse8-cCkNf!tD=KrW)";
        try strVerify(std.testing.allocator, str, password, .{});
    }
}
