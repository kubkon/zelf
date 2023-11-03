pub fn isArchive(path: []const u8) !bool {
    const file = try std.fs.cwd().openFile(path, .{});
    defer file.close();
    const reader = file.reader();
    const magic = reader.readBytesNoEof(SARMAG) catch return false;
    if (!mem.eql(u8, &magic, ARMAG)) return false;
    return true;
}

const ARMAG: *const [SARMAG:0]u8 = "!<arch>\n";
const SARMAG: u4 = 8;

const mem = std.mem;
const std = @import("std");
