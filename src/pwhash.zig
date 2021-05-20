const std = @import("std");

pub const Encoding = enum {
    phc,
    crypt,
};

pub const KdfError = std.crypto.errors.Error || std.mem.Allocator.Error;
