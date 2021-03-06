// https://tools.ietf.org/html/rfc7914
// https://github.com/golang/crypto/blob/master/scrypt/scrypt.go

const std = @import("std");
const crypto = std.crypto;
const math = std.math;
const mem = std.mem;

const max_int = math.maxInt(u64) >> 1;

fn blockCopy(dst: []u32, src: []u32, n: usize) void {
    std.mem.copy(u32, dst, src[0..n]);
}

fn blockXOR(dst: []u32, src: []u32, n: usize) void {
    for (src[0..n]) | v, i | {
        dst[i] ^= v;
    }
}

fn salsaXOR(tmp: *[16]u32, in: []u32, out: []u32) void {
    const w0 = tmp[0] ^ in[0];
    const w1 = tmp[1] ^ in[1];
    const w2 = tmp[2] ^ in[2];
    const w3 = tmp[3] ^ in[3];
    const w4 = tmp[4] ^ in[4];
    const w5 = tmp[5] ^ in[5];
    const w6 = tmp[6] ^ in[6];
    const w7 = tmp[7] ^ in[7];
    const w8 = tmp[8] ^ in[8];
    const w9 = tmp[9] ^ in[9];
    const w10 = tmp[10] ^ in[10];
    const w11 = tmp[11] ^ in[11];
    const w12 = tmp[12] ^ in[12];
    const w13 = tmp[13] ^ in[13];
    const w14 = tmp[14] ^ in[14];
    const w15 = tmp[15] ^ in[15];

    var x0 = w0;
    var x1 = w1;
    var x2 = w2;
    var x3 = w3;
    var x4 = w4;
    var x5 = w5;
    var x6 = w6;
    var x7 = w7;
    var x8 = w8;
    var x9 = w9;
    var x10 = w10;
    var x11 = w11;
    var x12 = w12;
    var x13 = w13;
    var x14 = w14;
    var x15 = w15;

    var i: i32 = 0;
    while (i < 8) : (i += 2) {
        x4 ^= math.rotl(u32, x0 +% x12, 7);
        x8 ^= math.rotl(u32, x4 +% x0, 9);
        x12 ^= math.rotl(u32, x8 +% x4, 13);
        x0 ^= math.rotl(u32, x12 +% x8, 18);

        x9 ^= math.rotl(u32, x5 +% x1, 7);
        x13 ^= math.rotl(u32, x9 +% x5, 9);
        x1 ^= math.rotl(u32, x13 +% x9, 13);
        x5 ^= math.rotl(u32, x1 +% x13, 18);

        x14 ^= math.rotl(u32, x10 +% x6, 7);
        x2 ^= math.rotl(u32, x14 +% x10, 9);
        x6 ^= math.rotl(u32, x2 +% x14, 13);
        x10 ^= math.rotl(u32, x6 +% x2, 18);

        x3 ^= math.rotl(u32, x15 +% x11, 7);
        x7 ^= math.rotl(u32, x3 +% x15, 9);
        x11 ^= math.rotl(u32, x7 +% x3, 13);
        x15 ^= math.rotl(u32, x11 +% x7, 18);

        x1 ^= math.rotl(u32, x0 +% x3, 7);
        x2 ^= math.rotl(u32, x1 +% x0, 9);
        x3 ^= math.rotl(u32, x2 +% x1, 13);
        x0 ^= math.rotl(u32, x3 +% x2, 18);

        x6 ^= math.rotl(u32, x5 +% x4, 7);
        x7 ^= math.rotl(u32, x6 +% x5, 9);
        x4 ^= math.rotl(u32, x7 +% x6, 13);
        x5 ^= math.rotl(u32, x4 +% x7, 18);

        x11 ^= math.rotl(u32, x10 +% x9, 7);
        x8 ^= math.rotl(u32, x11 +% x10, 9);
        x9 ^= math.rotl(u32, x8 +% x11, 13);
        x10 ^= math.rotl(u32, x9 +% x8, 18);

        x12 ^= math.rotl(u32, x15 +% x14, 7);
        x13 ^= math.rotl(u32, x12 +% x15, 9);
        x14 ^= math.rotl(u32, x13 +% x12, 13);
        x15 ^= math.rotl(u32, x14 +% x13, 18);
    }

    x0 +%= w0;
    x1 +%= w1;
    x2 +%= w2;
    x3 +%= w3;
    x4 +%= w4;
    x5 +%= w5;
    x6 +%= w6;
    x7 +%= w7;
    x8 +%= w8;
    x9 +%= w9;
    x10 +%= w10;
    x11 +%= w11;
    x12 +%= w12;
    x13 +%= w13;
    x14 +%= w14;
    x15 +%= w15;

    out[0] = x0;
    out[1] = x1;
    out[2] = x2;
    out[3] = x3;
    out[4] = x4;
    out[5] = x5;
    out[6] = x6;
    out[7] = x7;
    out[8] = x8;
    out[9] = x9;
    out[10] = x10;
    out[11] = x11;
    out[12] = x12;
    out[13] = x13;
    out[14] = x14;
    out[15] = x15;

    tmp[0] = x0;
    tmp[1] = x1;
    tmp[2] = x2;
    tmp[3] = x3;
    tmp[4] = x4;
    tmp[5] = x5;
    tmp[6] = x6;
    tmp[7] = x7;
    tmp[8] = x8;
    tmp[9] = x9;
    tmp[10] = x10;
    tmp[11] = x11;
    tmp[12] = x12;
    tmp[13] = x13;
    tmp[14] = x14;
    tmp[15] = x15;
}

fn blockMix(tmp: *[16]u32, in: []u32, out: []u32, r: u32) void {
    blockCopy(tmp, in[(2*r-1)*16..], 16);
    var i: u64 = 0;
    while (i < 2*r) : (i += 2) {
        salsaXOR(tmp, in[i*16..], out[i*8..]);
        salsaXOR(tmp, in[i*16+16..], out[i*8+r*16..]);
    }
}

fn integer(b: []u32, r: u32) u64 {
    const j = (2*r - 1) * 16;
    return @as(u64, b[j]) | @as(u64, b[j + 1]) << 32;
}

fn smix(b: []u8, r: u32, n: usize, v: []u32, xy: []u32) void {
    var tmp: [16]u32 = undefined;
    var x = xy;
    var y = xy[32*r..];
    
    var i: usize = 0;
    var j: usize = 0;
    while (i < 32*r) : (i += 1) {
        x[i] = (
            @as(u32, b[j])
            | @as(u32, b[j + 1]) << 8
            | @as(u32, b[j + 2]) << 16
            | @as(u32, b[j + 3]) << 24
        );
        j += 4;
    }

    i = 0;
    while (i < n) : (i += 2) {
        blockCopy(v[i*(32*r)..], x, 32*r);
        blockMix(&tmp, x, y, r);

        blockCopy(v[(i+1)*(32*r)..], y, 32*r);
        blockMix(&tmp, y, x, r);
    }

    i = 0;
    while (i < n) : (i += 2) {
        j = integer(x, r) & (n-1);
        blockXOR(x, v[j*(32*r)..], 32*r);
        blockMix(&tmp, x, y, r);

        j = integer(y, r) & (n-1);
        blockXOR(y, v[j*(32*r)..], 32*r);
        blockMix(&tmp, y, x, r);
    }

    j = 0;
    for (x[0..32*r]) | v1 | {
        b[j + 0] = @truncate(u8, v1 >> 0);
        b[j + 1] = @truncate(u8, v1 >> 8);
        b[j + 2] = @truncate(u8, v1 >> 16);
        b[j + 3] = @truncate(u8, v1 >> 24);
        j += 4;
    }
}

const Error = error {
    InvalidParams,
    InvalidDerivedKeyLen,
};

// +Pbkdf2Error
pub const ScriptError = Error || mem.Allocator.Error;

pub const ScriptParams = struct {
    const Self = @This();

    log_n: u6 = 15,
    r: u32 = 8,
    p: u32 = 1,

    pub fn init(log_n: u6, r: u32, p: u32) Self {
        return Self {
            .log_n = log_n,
            .r = r,
            .p = p,
        };
    }
};

pub fn scrypt(
    allocator: *mem.Allocator,
    derived_key: []u8,
    password: []const u8, 
    salt: []const u8, 
    params: ?ScriptParams,
) !void {
    if (derived_key.len == 0 or derived_key.len / 32 > 0xffff_ffff) {
        return ScriptError.InvalidDerivedKeyLen;
    }
    const param = params orelse ScriptParams {};
    const n = @as(usize, 1) << param.log_n;
    if (n <= 1 or n&(n-1) != 0) {
        return ScriptError.InvalidParams;
    }
    if (
        @as(u64, param.r) * @as(u64, param.p) >= 1<<30 
        or param.r > max_int/128/@as(u64, param.p)
        or param.r > max_int/256 
        or n > max_int/128/@as(u64, param.r)
    ) {
        return ScriptError.InvalidParams;
    }

    var xy = try allocator.alloc(u32, 64*param.r);
    defer allocator.free(xy);
    var v = try allocator.alloc(u32, 32*n*param.r);
    defer allocator.free(v);
    var dk = try allocator.alloc(u8, param.p*128*param.r);
    defer allocator.free(dk);

    try crypto.pwhash.pbkdf2(
        dk[0..], 
        password, 
        salt, 
        1, 
        crypto.auth.hmac.sha2.HmacSha256,
    );
    var i: u32 = 0;
    while (i < param.p) : (i += 1) {
        smix(
            dk[i*128*param.r..], 
            param.r, 
            n, 
            v[0..], 
            xy[0..],
        );
    }
    try crypto.pwhash.pbkdf2(
        derived_key[0..], 
        password, 
        dk[0..], 
        1, 
        crypto.auth.hmac.sha2.HmacSha256,
    );
}

test "scrypt" {
    const password = "testpass";
    const salt = "saltsalt";

    var v: [32]u8 = undefined;
    try scrypt(std.testing.allocator, v[0..], password, salt, null);

    const hex = "1e0f97c3f6609024022fbe698da29c2fe53ef1087a8e396dc6d5d2a041e886de";
    var bytes: [hex.len/2]u8 = undefined;
    try std.fmt.hexToBytes(bytes[0..], hex);
    std.testing.expectEqualSlices(u8, bytes[0..], v[0..]);
}
