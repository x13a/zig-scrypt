// SPDX-License-Identifier: MIT
// Copyright (c) 2015-2021 Zig Contributors
// This file is part of [zig](https://ziglang.org/), which is MIT licensed.
// The MIT license requires this copyright notice to be included in all copies
// and substantial portions of the software.

// https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md
// https://github.com/P-H-C/phc-string-format/pull/4

const std = @import("std");
const base64 = std.base64;
const crypto = std.crypto;
const fmt = std.fmt;
const mem = std.mem;

const b64enc = base64.standard_encoder;
const b64dec = base64.standard_decoder;

const fields_delimiter = "$";
const version_prefix = "v=";
pub const params_delimiter = ",";
pub const kv_delimiter = "=";

const PhcEncodingError = error{
    ParseError,
    InvalidAlgorithm,
    VerificationError,
    NullSalt,
};

// TODO add base64 error to Error
// TODO PhcEncoding.fromString should return Error!Self
pub const Error = PhcEncodingError || mem.Allocator.Error || fmt.ParseIntError;

pub fn PhcEncoding(comptime T: type) type {
    return struct {
        const Self = @This();

        allocator: *mem.Allocator,
        alg_id: []const u8,
        version: ?u32 = null,
        params: ?T = null,
        salt: ?[]u8 = null,
        derived_key: ?[]u8 = null,

        pub fn fromString(allocator: *mem.Allocator, s: []const u8) !Self {
            var it = mem.split(s, fields_delimiter);
            _ = it.next();
            const alg_id = it.next() orelse return Error.ParseError;
            if (alg_id.len == 0 or alg_id.len > 32) {
                return Error.ParseError;
            }
            var res = Self{ .allocator = allocator, .alg_id = alg_id };
            var s1 = it.next() orelse return res;
            if (mem.startsWith(u8, s1, version_prefix) and
                mem.indexOf(u8, s1, params_delimiter) == null)
            {
                res.version = try fmt.parseInt(u32, s1[version_prefix.len..], 10);
                s1 = it.next() orelse return res;
            }
            if (mem.indexOf(u8, s1, kv_delimiter) != null) {
                res.params = try T.fromPhcString(s1);
                s1 = it.next() orelse return res;
            }
            const salt = try b64decode(allocator, s1);
            errdefer allocator.free(salt);
            const derived_key = try b64decode(
                allocator,
                it.next() orelse {
                    res.salt = salt;
                    return res;
                },
            );
            errdefer allocator.free(derived_key);
            if (it.next() != null) {
                return Error.ParseError;
            }
            res.salt = salt;
            res.derived_key = derived_key;
            return res;
        }

        pub fn check_id(self: *Self, alg_id: []const u8) Error!void {
            if (!mem.eql(u8, self.alg_id, alg_id)) {
                return error.InvalidAlgorithm;
            }
        }

        pub fn verify(allocator: *mem.Allocator, str: []const u8, derived_key: []const u8) !void {
            var self = try Self.fromString(allocator, str);
            defer self.deinit();
            var dk = self.derived_key orelse return error.VerificationError;
            defer crypto.utils.secureZero(u8, dk);
            // TODO use crypto.utils.timingSafeEql
            if (!mem.eql(u8, dk, derived_key)) {
                return error.VerificationError;
            }
        }

        pub fn deinit(self: *Self) void {
            if (self.salt) |v| {
                self.allocator.free(v);
                self.salt = null;
            }
            if (self.derived_key) |v| {
                self.allocator.free(v);
                self.derived_key = null;
            }
        }

        pub fn toString(self: *Self) Error![]const u8 {
            var i: usize = self.alg_id.len + fields_delimiter.len;
            var versionLen: usize = 0;
            if (self.version) |v| {
                versionLen = fmt.count("{s}{s}{d}", .{ fields_delimiter, version_prefix, v });
                i += versionLen;
            }
            var params: ?[]const u8 = null;
            if (self.params) |v| {
                const s = try v.toPhcString(self.allocator);
                i += s.len + fields_delimiter.len;
                params = s;
            }
            defer {
                if (params) |v| {
                    self.allocator.free(v);
                }
            }
            var salt: ?[]const u8 = null;
            if (self.salt) |v| {
                const s = try b64encode(self.allocator, v);
                i += s.len + fields_delimiter.len;
                salt = s;
            }
            defer {
                if (salt) |v| {
                    self.allocator.free(v);
                }
            }
            var derived_key: ?[]const u8 = null;
            if (self.derived_key) |v| {
                if (salt == null) {
                    return error.NullSalt;
                }
                const s = try b64encode(self.allocator, v);
                i += s.len + fields_delimiter.len;
                derived_key = s;
            }
            defer {
                if (derived_key) |v| {
                    self.allocator.free(v);
                }
            }
            var buf = try self.allocator.alloc(u8, i);
            i = write(buf, self.alg_id);
            if (self.version) |v| {
                _ = fmt.bufPrint(
                    buf[i..],
                    "{s}{s}{d}",
                    .{ fields_delimiter, version_prefix, v },
                ) catch unreachable;
                i += versionLen;
            }
            i += write(buf[i..], params);
            i += write(buf[i..], salt);
            _ = write(buf[i..], derived_key);
            return buf;
        }
    };
}

fn write(buf: []u8, v: ?[]const u8) usize {
    var value = v orelse return 0;
    mem.copy(u8, buf, fields_delimiter);
    mem.copy(u8, buf[fields_delimiter.len..], value);
    return fields_delimiter.len + value.len;
}

fn b64encode(allocator: *mem.Allocator, v: []const u8) mem.Allocator.Error![]u8 {
    // TODO use base64 encode without padding
    var buf = try allocator.alloc(u8, base64.Base64Encoder.calcSize(v.len));
    _ = b64enc.encode(buf, v);
    var i: usize = buf.len;
    while (i > 0) : (i -= 1) {
        if (buf[i - 1] != '=') {
            break;
        }
    }
    if (i != buf.len) {
        errdefer allocator.free(buf);
        return allocator.realloc(buf, i);
    }
    return buf;
}

// TODO b64decode should return Error![]u8
fn b64decode(allocator: *mem.Allocator, s: []const u8) ![]u8 {
    if (s.len == 0) {
        return Error.ParseError;
    }
    var buf: []u8 = undefined;
    // TODO use base64 decode without padding
    if (s.len % 4 != 0) {
        var s1 = try allocator.alloc(u8, s.len + (4 - (s.len % 4)));
        defer allocator.free(s1);
        mem.copy(u8, s1, s);
        mem.set(u8, s1[s.len..], '=');
        buf = try allocator.alloc(u8, try b64dec.calcSize(s1));
        errdefer allocator.free(buf);
        try b64dec.decode(buf, s1);
    } else {
        buf = try allocator.alloc(u8, try b64dec.calcSize(s));
        errdefer allocator.free(buf);
        try b64dec.decode(buf, s);
    }
    return buf;
}

pub const Param = struct {
    const Self = @This();

    key: []const u8,
    value: []const u8,

    pub fn decimal(self: Self, comptime T: type) fmt.ParseIntError!T {
        return fmt.parseInt(T, self.value, 10);
    }
};

pub const ParamsIterator = struct {
    const Self = @This();

    it: mem.SplitIterator,
    limit: usize,
    pos: usize = 0,

    pub fn new(s: []const u8, limit: usize) Self {
        return Self{ .it = mem.split(s, params_delimiter), .limit = limit };
    }

    pub fn next(self: *Self) Error!?Param {
        const s = self.it.next() orelse return null;
        if (self.pos == self.limit) {
            return error.ParseError;
        }
        var it = mem.split(s, kv_delimiter);
        const key = it.next() orelse return error.ParseError;
        if (key.len == 0 or key.len > 32) {
            return error.ParseError;
        }
        const value = it.next() orelse return error.ParseError;
        if (it.next() != null) {
            return error.ParseError;
        }
        self.pos += 1;
        return Param{ .key = key, .value = value };
    }
};

test "conv" {
    const scrypt = @import("scrypt.zig");
    const alloc = std.testing.allocator;

    const phc = PhcEncoding(scrypt.Params);
    const s = "$scrypt$v=1$ln=15,r=8,p=1$c2FsdHNhbHQ$dGVzdHBhc3M";

    var v = try phc.fromString(alloc, s);
    defer v.deinit();

    const s1 = try v.toString();
    defer alloc.free(s1);

    std.testing.expectEqualSlices(u8, s, s1);
}

test "verify" {
    const scrypt = @import("scrypt.zig");

    const phc = PhcEncoding(scrypt.Params);
    const s = "$scrypt$v=1$ln=15,r=8,p=1$c2FsdHNhbHQ$dGVzdHBhc3M";

    try phc.verify(std.testing.allocator, s, "testpass");
}

test "check_id" {
    const scrypt = @import("scrypt.zig");
    const alloc = std.testing.allocator;

    const phc = PhcEncoding(scrypt.Params);
    const s = "$scrypt$v=1$ln=15,r=8,p=1$c2FsdHNhbHQ$dGVzdHBhc3M";

    var v = try phc.fromString(alloc, s);
    defer v.deinit();

    try v.check_id("scrypt");
}

test "conv only id" {
    const scrypt = @import("scrypt.zig");
    const alloc = std.testing.allocator;

    const phc = PhcEncoding(scrypt.Params);
    const s = "$scrypt";

    var v = try phc.fromString(alloc, s);
    defer v.deinit();

    const s1 = try v.toString();
    defer alloc.free(s1);

    std.testing.expectEqualSlices(u8, s, s1);
}

test "conv only version" {
    const scrypt = @import("scrypt.zig");
    const alloc = std.testing.allocator;

    const phc = PhcEncoding(scrypt.Params);
    const s = "$scrypt$v=1";

    var v = try phc.fromString(alloc, s);
    defer v.deinit();

    const s1 = try v.toString();
    defer alloc.free(s1);

    std.testing.expectEqualSlices(u8, s, s1);
}

test "conv only params" {
    const scrypt = @import("scrypt.zig");
    const alloc = std.testing.allocator;

    const phc = PhcEncoding(scrypt.Params);
    const s = "$scrypt$ln=15,r=8,p=1";

    var v = try phc.fromString(alloc, s);
    defer v.deinit();

    const s1 = try v.toString();
    defer alloc.free(s1);

    std.testing.expectEqualSlices(u8, s, s1);
}

test "conv only salt" {
    const scrypt = @import("scrypt.zig");
    const alloc = std.testing.allocator;

    const phc = PhcEncoding(scrypt.Params);
    const s = "$scrypt$c2FsdHNhbHQ";

    var v = try phc.fromString(alloc, s);
    defer v.deinit();

    const s1 = try v.toString();
    defer alloc.free(s1);

    std.testing.expectEqualSlices(u8, s, s1);
}

test "conv without derived_key" {
    const scrypt = @import("scrypt.zig");
    const alloc = std.testing.allocator;

    const phc = PhcEncoding(scrypt.Params);
    const s = "$scrypt$v=1$ln=15,r=8,p=1$c2FsdHNhbHQ";

    var v = try phc.fromString(alloc, s);
    defer v.deinit();

    const s1 = try v.toString();
    defer alloc.free(s1);

    std.testing.expectEqualSlices(u8, s, s1);
}

test "conv without salt" {
    const scrypt = @import("scrypt.zig");
    const alloc = std.testing.allocator;

    const phc = PhcEncoding(scrypt.Params);
    const s = "$scrypt$v=1$ln=15,r=8,p=1";

    var v = try phc.fromString(alloc, s);
    defer v.deinit();

    const s1 = try v.toString();
    defer alloc.free(s1);

    std.testing.expectEqualSlices(u8, s, s1);
}

test "conv without params" {
    const scrypt = @import("scrypt.zig");
    const alloc = std.testing.allocator;

    const phc = PhcEncoding(scrypt.Params);
    const s = "$scrypt$v=1$c2FsdHNhbHQ$dGVzdHBhc3M";

    var v = try phc.fromString(alloc, s);
    defer v.deinit();

    const s1 = try v.toString();
    defer alloc.free(s1);

    std.testing.expectEqualSlices(u8, s, s1);
}

test "conv without version" {
    const scrypt = @import("scrypt.zig");
    const alloc = std.testing.allocator;

    const phc = PhcEncoding(scrypt.Params);
    const s = "$scrypt$ln=15,r=8,p=1$c2FsdHNhbHQ$dGVzdHBhc3M";

    var v = try phc.fromString(alloc, s);
    defer v.deinit();

    const s1 = try v.toString();
    defer alloc.free(s1);

    std.testing.expectEqualSlices(u8, s, s1);
}

test "conv without params and derived_key" {
    const scrypt = @import("scrypt.zig");
    const alloc = std.testing.allocator;

    const phc = PhcEncoding(scrypt.Params);
    const s = "$scrypt$v=1$c2FsdHNhbHQ";

    var v = try phc.fromString(alloc, s);
    defer v.deinit();

    const s1 = try v.toString();
    defer alloc.free(s1);

    std.testing.expectEqualSlices(u8, s, s1);
}

test "conv without version and params" {
    const scrypt = @import("scrypt.zig");
    const alloc = std.testing.allocator;

    const phc = PhcEncoding(scrypt.Params);
    const s = "$scrypt$c2FsdHNhbHQ$dGVzdHBhc3M";

    var v = try phc.fromString(alloc, s);
    defer v.deinit();

    const s1 = try v.toString();
    defer alloc.free(s1);

    std.testing.expectEqualSlices(u8, s, s1);
}
