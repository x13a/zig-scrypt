// https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md

const std = @import("std");
const base64 = std.base64;
const fmt = std.fmt;
const mem = std.mem;

const b64enc = base64.standard_encoder;
const b64dec = base64.standard_decoder;

const fields_delimiter = "$";
const params_delimiter = ",";
const kv_delimiter = "=";

const Error = error{
    ParseError,
    InvalidAlgorithm,
};

// TODO base64 doesn't have one error set
pub const PHCStringError = Error || mem.Allocator.Error || fmt.ParseIntError;

pub fn PHCString(comptime T: type) type {
    return struct {
        const Self = @This();

        allocator: *mem.Allocator,
        alg_id: []const u8,
        params: ?T = null,
        salt: ?[]u8 = null,
        key: ?[]u8 = null,

        pub fn fromString(
            allocator: *mem.Allocator,
            s: []const u8,
        ) !Self {
            var it = mem.split(s, fields_delimiter);
            _ = it.next();
            const alg_id = it.next() orelse return error.ParseError;
            if (alg_id.len == 0 or alg_id.len > 32) {
                return error.ParseError;
            }
            var res = Self{
                .allocator = allocator,
                .alg_id = alg_id,
            };
            var s1 = it.next() orelse return res;
            if (mem.indexOf(u8, s1, "=")) |_| {
                res.params = try T.fromString(s1);
            }
            const salt = try b64decode(
                allocator,
                it.next() orelse return res,
            );
            errdefer allocator.free(salt);
            const key = try b64decode(
                allocator,
                it.next() orelse {
                    res.salt = salt;
                    return res;
                },
            );
            errdefer allocator.free(key);
            if (it.next()) |_| {
                return error.ParseError;
            }
            res.salt = salt;
            res.key = key;
            return res;
        }

        pub fn check_id(self: *Self, alg_id: []const u8) PHCStringError!void {
            if (!mem.eql(u8, self.alg_id, alg_id)) {
                return error.InvalidAlgorithm;
            }
        }

        pub fn deinit(self: *Self) void {
            if (self.salt) |v| {
                self.allocator.free(v);
                self.salt = null;
            }
            if (self.key) |v| {
                self.allocator.free(v);
                self.key = null;
            }
        }

        pub fn toString(self: *Self) ![]const u8 {
            var i: usize = 1 + self.alg_id.len;
            var params: []const u8 = undefined;
            if (self.params) |v| {
                params = try v.toString(self.allocator);
                i += params.len + 1;
            }
            errdefer self.allocator.free(params);
            var salt: []u8 = undefined;
            if (self.salt) |v| {
                salt = try b64encode(self.allocator, v);
                i += salt.len + 1;
            }
            errdefer self.allocator.free(salt);
            var key: []u8 = undefined;
            if (self.key) |v| {
                key = try b64encode(self.allocator, v);
                i += key.len + 1;
            }
            errdefer self.allocator.free(key);
            var buf = try self.allocator.alloc(u8, i);
            write(self.allocator, buf, 0, self.alg_id, false);
            write(self.allocator, buf, 1 + self.alg_id.len, params, true);
            write(
                self.allocator,
                buf,
                2 + self.alg_id.len + params.len,
                salt,
                true,
            );
            write(
                self.allocator,
                buf,
                3 + self.alg_id.len + params.len + salt.len,
                key,
                true,
            );
            return buf;
        }
    };
}

fn write(
    allocator: *mem.Allocator,
    buf: []u8,
    pos: usize,
    v: []const u8,
    free: bool,
) void {
    if (v.len == 0) {
        return;
    }
    mem.copy(u8, buf[pos..], fields_delimiter);
    mem.copy(u8, buf[pos + fields_delimiter.len ..], v);
    if (free) {
        allocator.free(v);
    }
}

fn b64encode(allocator: *mem.Allocator, v: []u8) ![]u8 {
    // TODO bug in calcSize?
    // v0.7.1
    // error: expected 1 argument(s), found 2
    // var buf = try self.allocator.alloc(u8, b64enc.calcSize(v.len));
    var buf = try allocator.alloc(u8, @divTrunc(v.len + 2, 3) * 4);
    b64enc.encode(buf, v);
    // TODO base64 encoding without padding
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

fn b64decode(allocator: *mem.Allocator, s: []const u8) ![]u8 {
    if (s.len == 0) {
        return error.ParseError;
    }
    // TODO std base64 decoder not working without padding
    var buf: []u8 = undefined;
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

    pub fn init(s: []const u8) Self {
        return Self{ .it = mem.split(s, params_delimiter) };
    }

    pub fn next(self: *Self) PHCStringError!?Param {
        const s = self.it.next() orelse return null;
        var it = mem.split(s, kv_delimiter);
        const key = it.next() orelse return error.ParseError;
        if (key.len == 0 or key.len > 32) {
            return error.ParseError;
        }
        const value = it.next() orelse return error.ParseError;
        if (value.len == 0) {
            return error.ParseError;
        }
        if (it.next()) |_| {
            return error.ParseError;
        }
        return Param{
            .key = key,
            .value = value,
        };
    }
};

test "phc string" {
    const scrypt = @import("scrypt.zig");
    const phc = PHCString(scrypt.ScryptParams);
    const alloc = std.testing.allocator;
    const s = "$scrypt$ln=15,r=8,p=1$c2FsdHNhbHQ$dGVzdHBhc3M";
    var v = try phc.fromString(alloc, s);
    defer v.deinit();
    const s1 = try v.toString();
    defer alloc.free(s1);
    std.testing.expectEqualSlices(u8, s, s1);
}
