const std = @import("std");
const crypto = std.crypto;
const math = std.math;

const maxInt = math.maxInt(u64) >> 1;

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

fn blockMix(tmp: *[16]u32, in: []u32, out: []u32, r: usize) void {
    blockCopy(tmp, in[(2*r-1)*16..], 16);
    var i: usize = 0;
    while (i < 2*r) : (i += 2) {
        salsaXOR(tmp, in[i*16..], out[i*8..]);
        salsaXOR(tmp, in[i*16+16..], out[i*8+r*16..]);
    }
}

fn integer(b: []u32, r: usize) usize {
    const j = (2*r - 1) * 16;
    return @as(usize, b[j]) | @as(usize, b[j + 1]) << 32;
}

fn smix(b: []u8, r: usize, N: usize, v: []u32, xy: []u32) void {
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
    while (i < N) : (i += 2) {
        blockCopy(v[i*(32*r)..], x, 32*r);
        blockMix(&tmp, x, y, r);

        blockCopy(v[(i+1)*(32*r)..], y, 32*r);
        blockMix(&tmp, y, x, r);
    }

    i = 0;
    while (i < N) : (i += 2) {
        j = integer(x, r) & (N-1);
        blockXOR(x, v[j*(32*r)..], 32*r);
        blockMix(&tmp, x, y, r);

        j = integer(y, r) & (N-1);
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

pub const ScriptError = error {
    InvalidParams,
};

pub fn scrypt(
    derivedKey: []u8,
    password: []const u8, 
    salt: []const u8, 
    comptime N: i32, 
    comptime r: i32, 
    comptime p: i32, 
) !void {
    if (N <= 1 or N&(N-1) != 0) {
        return ScryptError.InvalidParams;
    }
    if (
        @intCast(u64, r) * @intCast(u64, p) >= 1<<30 
        or r > maxInt/128/@intCast(u64, p)
        or r > maxInt/256 
        or N > maxInt/128/@intCast(u64, r)
    ) {
        return ScryptError.InvalidParams;
    }
    var xy: [@intCast(usize, 64*r)]u32 = undefined;
    var v: [@intCast(usize, 32*N*r)]u32 = undefined;
    var derived_key: [@intCast(usize, p*128*r)]u8 = undefined;
    try crypto.pwhash.pbkdf2(
        derived_key[0..], 
        password, 
        salt, 
        1, 
        crypto.auth.hmac.sha2.HmacSha256,
    );
    var i: i32 = 0;
    while (i < p) : (i += 1) {
        smix(
            derived_key[@intCast(usize, i*128*r)..], 
            @intCast(usize, r), 
            @intCast(usize, N), 
            v[0..], 
            xy[0..],
        );
    }
    try crypto.pwhash.pbkdf2(
        derivedKey[0..], 
        password, 
        derived_key[0..], 
        1, 
        crypto.auth.hmac.sha2.HmacSha256,
    );
}

test "scrypt" {
    const password = "testpass";
    const salt = "saltsalt";
    const N = 32768;
    const r = 8;
    const p = 1;

    var v: [32]u8 = undefined;
    try scrypt(v[0..], password, salt, N, r, p);

    const hex = "1e0f97c3f6609024022fbe698da29c2fe53ef1087a8e396dc6d5d2a041e886de";
    var bytes: [hex.len/2]u8 = undefined;
    for (bytes) | *r1, i | {
        r1.* = std.fmt.parseInt(u8, hex[2*i..2*i+2], 16) catch unreachable;
    }
    std.testing.expectEqualSlices(u8, bytes[0..], v[0..]);
}
