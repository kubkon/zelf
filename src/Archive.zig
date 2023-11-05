arena: Allocator,
data: []const u8,
path: []const u8,
opts: @import("main.zig").Options,

objects: std.ArrayListUnmanaged(Object) = .{},
symtab: Symtab = .{},
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
        if (!mem.isAligned(stream.pos, 2)) stream.pos += 1;

        const hdr = try reader.readStruct(ar_hdr);

        if (!mem.eql(u8, &hdr.ar_fmag, ARFMAG)) return error.InvalidHeaderDelimiter;

        const size = try hdr.size();
        defer {
            _ = stream.seekBy(size) catch {};
        }

        if (hdr.isSymtab() or hdr.isSymtab64()) {
            self.symtab.format = if (hdr.isSymtab64()) .p64 else .p32;
            try self.symtab.parse(self.arena, self.data[stream.pos..][0..size]);
            continue;
        }
        if (hdr.isStrtab()) {
            self.strtab = self.data[stream.pos..][0..size];
            continue;
        }

        const name = ar_hdr.getValue(&hdr.ar_name);

        if (mem.eql(u8, name, "__.SYMDEF") or mem.eql(u8, name, "__.SYMDEF SORTED")) continue;

        const object_name = blk: {
            if (name[0] == '/') {
                const off = try std.fmt.parseInt(u32, name[1..], 10);
                const object_name = self.getString(off);
                break :blk object_name[0 .. object_name.len - 1]; // To account for trailing '/'
            }
            break :blk try self.arena.dupe(u8, name);
        };

        const object = try self.objects.addOne(self.arena);
        object.* = Object{
            .arena = self.arena,
            .path = object_name,
            .data = self.data[stream.pos..][0..size],
            .opts = self.opts,
        };
        try object.parse();
    }
}

pub fn printSymtab(self: Archive, writer: anytype) !void {
    if (self.symtab.entries.items.len == 0) {
        return writer.writeAll("no index found in archive\n");
    }

    var size_in_symtab: usize = 0;
    for (self.symtab.entries.items) |entry| {
        size_in_symtab += entry.name.len + 1;
    }
    try writer.print("Index of archive {s}: ({d} entries, 0x{x} bytes in the symbol table)\n", .{
        self.path,
        self.symtab.entries.items.len,
        size_in_symtab,
    });

    // Sort by file
    var by_file = std.AutoArrayHashMap(u64, std.ArrayList(usize)).init(self.arena);
    for (self.symtab.entries.items, 0..) |entry, i| {
        const gop = try by_file.getOrPut(entry.file);
        if (!gop.found_existing) {
            gop.value_ptr.* = std.ArrayList(usize).init(self.arena);
        }
        try gop.value_ptr.append(i);
    }

    for (by_file.keys(), by_file.values()) |file, indexes| {
        try writer.print("Contents of binary {s} at offset 0x{x}\n", .{ "TODO", file });
        for (indexes.items) |index| {
            try writer.print("      {s}\n", .{self.symtab.entries.items[index].name});
        }
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
        return mem.eql(u8, getValue(&self.ar_name), STRNAME);
    }

    fn isSymtab(self: ar_hdr) bool {
        return mem.eql(u8, getValue(&self.ar_name), SYMNAME);
    }

    fn isSymtab64(self: ar_hdr) bool {
        return mem.eql(u8, getValue(&self.ar_name), SYM64NAME);
    }

    pub fn format(
        self: ar_hdr,
        comptime unused_fmt_string: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = unused_fmt_string;
        _ = options;
        try writer.print("ar_name: {s} ({x})\n", .{
            std.fmt.fmtSliceEscapeLower(&self.ar_name),
            std.fmt.fmtSliceHexLower(&self.ar_name),
        });
        try writer.print("ar_date: {s} ({x})\n", .{
            std.fmt.fmtSliceEscapeLower(&self.ar_date),
            std.fmt.fmtSliceHexLower(&self.ar_date),
        });
        try writer.print("ar_uid:  {s} ({x})\n", .{
            std.fmt.fmtSliceEscapeLower(&self.ar_uid),
            std.fmt.fmtSliceHexLower(&self.ar_uid),
        });
        try writer.print("ar_gid:  {s} ({x})\n", .{
            std.fmt.fmtSliceEscapeLower(&self.ar_gid),
            std.fmt.fmtSliceHexLower(&self.ar_gid),
        });
        try writer.print("ar_mode: {s} ({x})\n", .{
            std.fmt.fmtSliceEscapeLower(&self.ar_mode),
            std.fmt.fmtSliceHexLower(&self.ar_mode),
        });
        try writer.print("ar_size: {s} ({x})\n", .{
            std.fmt.fmtSliceEscapeLower(&self.ar_size),
            std.fmt.fmtSliceHexLower(&self.ar_size),
        });
        try writer.print("ar_fmag: {s} ({x})\n", .{
            std.fmt.fmtSliceEscapeLower(&self.ar_fmag),
            std.fmt.fmtSliceHexLower(&self.ar_fmag),
        });
    }
};

const Symtab = struct {
    entries: std.ArrayListUnmanaged(Entry) = .{},
    format: enum { p32, p64 } = .p32,

    fn ptrWidth(ar: Symtab) usize {
        return switch (ar.format) {
            .p32 => @as(usize, 4),
            .p64 => 8,
        };
    }

    fn parse(ar: *Symtab, arena: Allocator, data: []const u8) !void {
        var stream = std.io.fixedBufferStream(data);
        const reader = stream.reader();

        const num = try ar.readInt(reader);
        try ar.entries.ensureTotalCapacityPrecise(arena, num);

        for (0..num) |_| {
            const file = try ar.readInt(reader);
            ar.entries.appendAssumeCapacity(.{ .name = undefined, .file = file });
        }

        const strtab_off = (num + 1) * ar.ptrWidth();
        const strtab_len = data.len - strtab_off;
        const strtab = data[strtab_off..];

        var next: usize = 0;
        var i: usize = 0;
        while (i < strtab_len) : (next += 1) {
            const name = mem.sliceTo(@as([*:0]const u8, @ptrCast(strtab.ptr + i)), 0);
            ar.entries.items[next].name = name;
            i += name.len + 1;
        }
    }

    fn readInt(ar: Symtab, reader: anytype) !u64 {
        return switch (ar.format) {
            .p32 => @as(u64, @intCast(try reader.readInt(u32, .big))),
            .p64 => try reader.readInt(u64, .big),
        };
    }

    const Entry = struct {
        /// Symbol name
        name: [:0]const u8,
        /// Offset of the object file.
        file: u64,
    };
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
