arena: Allocator,
data: []const u8,
path: []const u8,
opts: @import("main.zig").Options,

objects: std.ArrayListUnmanaged(Object) = .{},
strtab: []const u8 = &[0]u8{},

pub fn isArchive(path: []const u8) !bool {
    const file = try std.fs.cwd().openFile(path, .{});
    defer file.close();
    const reader = file.reader();
    const magic = reader.readBytesNoEof(SARMAG) catch return false;
    if (!mem.eql(u8, &magic, ARMAG)) return false;
    return true;
}

pub fn parse(self: *Archive) !void {
    var stream = std.io.fixedBufferStream(self.data);
    const reader = stream.reader();
    _ = try reader.readBytesNoEof(SARMAG);

    while (true) {
        if (stream.pos >= self.data.len) break;

        if (stream.pos % 2 != 0) {
            stream.pos += 1;
        }

        const hdr = try reader.readStruct(ar_hdr);

        if (!mem.eql(u8, &hdr.ar_fmag, ARFMAG)) return error.InvalidHeaderDelimiter;

        const size = try hdr.size();
        defer {
            _ = stream.seekBy(size) catch {};
        }

        if (hdr.isSymtab()) continue;
        if (hdr.isStrtab()) {
            self.strtab = self.data[stream.pos..][0..size];
            continue;
        }

        const name = ar_hdr.getValue(&hdr.ar_name);

        if (mem.eql(u8, name, "__.SYMDEF") or mem.eql(u8, name, "__.SYMDEF SORTED")) continue;

        const object_name = blk: {
            if (name[0] == '/') {
                const off = try std.fmt.parseInt(u32, name[1..], 10);
                break :blk self.getString(off);
            }
            break :blk name;
        };

        const object = try self.objects.addOne(self.arena);
        object.* = Object{
            .arena = self.arena,
            .path = object_name[0 .. object_name.len - 1], // To account for trailing '/'
            .data = self.data[stream.pos..][0..size],
            .opts = self.opts,
        };
        try object.parse();
    }
}

fn getString(self: Archive, off: u32) []const u8 {
    assert(off < self.strtab.len);
    return mem.sliceTo(@as([*:'\n']const u8, @ptrCast(self.strtab.ptr + off)), 0);
}

const ar_hdr = extern struct {
    /// Member file name, sometimes / terminated.
    ar_name: [16]u8,

    /// File date, decimal seconds since Epoch.
    ar_date: [12]u8,

    /// User ID, in ASCII format.
    ar_uid: [6]u8,

    /// Group ID, in ASCII format.
    ar_gid: [6]u8,

    /// File mode, in ASCII octal.
    ar_mode: [8]u8,

    /// File size, in ASCII decimal.
    ar_size: [10]u8,

    /// Always contains ARFMAG.
    ar_fmag: [2]u8,

    fn date(self: ar_hdr) !u64 {
        const value = getValue(&self.ar_date);
        return std.fmt.parseInt(u64, value, 10);
    }

    fn size(self: ar_hdr) !u32 {
        const value = getValue(&self.ar_size);
        return std.fmt.parseInt(u32, value, 10);
    }

    fn getValue(raw: []const u8) []const u8 {
        return mem.trimRight(u8, raw, &[_]u8{@as(u8, 0x20)});
    }

    fn isStrtab(self: ar_hdr) bool {
        return mem.eql(u8, getValue(&self.ar_name), "//");
    }

    fn isSymtab(self: ar_hdr) bool {
        return mem.eql(u8, getValue(&self.ar_name), "/");
    }
};

const ARMAG: *const [SARMAG:0]u8 = "!<arch>\n";
const SARMAG: u4 = 8;
const ARFMAG: *const [2:0]u8 = "`\n";
const SYMNAME: *const [1:0]u8 = "/";
const STRNAME: *const [2:0]u8 = "//";
const SYM64NAME: *const [7:0]u8 = "/SYM64/";

const assert = std.debug.assert;
const mem = std.mem;
const std = @import("std");

const Allocator = mem.Allocator;
const Archive = @This();
const Object = @import("Object.zig");
