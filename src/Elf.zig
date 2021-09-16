const Elf = @This();

const std = @import("std");
const elf = std.elf;
const fs = std.fs;
const log = std.log.scoped(.elf);
const mem = std.mem;

const Allocator = mem.Allocator;

allocator: *Allocator,
file: fs.File,

header: ?elf.Header = null,

pub fn init(allocator: *Allocator, file: fs.File) Elf {
    return .{
        .allocator = allocator,
        .file = file,
    };
}

pub fn deinit(self: *Elf) void {}

pub fn parseMetadata(self: *Elf) !void {
    self.header = try elf.Header.read(self.file);
}

pub fn printHeader(self: Elf, writer: anytype) !void {
    const header = self.header orelse unreachable;
    try writer.print("ELF Header:\n", .{});
    try writer.print("  Endianness: {s}\n", .{header.endian});
    try writer.print("  Machine: {s}\n", .{(&switch (header.machine) {
        ._NONE => "none",
        ._M32 => "AT&T WE 32100",
        ._AARCH64 => "ARM Aarch64",
        ._X86_64 => "AMD x86-64 architecture",
        else => "unknown",
    }).*});
    try writer.print("  Class: {s}\n", .{(&if (header.is_64) "ELF64" else "ELF32").*});
    try writer.print("  Entry point address: 0x{x}\n", .{header.entry});
    try writer.print("  Start of program headers: {d} (bytes into file)\n", .{header.phoff});
    try writer.print("  Start of section headers: {d} (bytes into file)\n", .{header.shoff});
    try writer.print("  Size of program headers: {d} (bytes)\n", .{header.phentsize});
    try writer.print("  Number of program headers: {d}\n", .{header.phnum});
    try writer.print("  Size of section headers: {d} (bytes)\n", .{header.shentsize});
    try writer.print("  Number of section headers: {d}\n", .{header.shnum});
    try writer.print("  Section header string table index: {d}\n", .{header.shstrndx});
}
