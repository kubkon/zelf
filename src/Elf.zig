const Elf = @This();

const std = @import("std");
const assert = std.debug.assert;
const elf = std.elf;
const fmt = std.fmt;
const fs = std.fs;
const log = std.log.scoped(.zelf);
const mem = std.mem;

const Allocator = mem.Allocator;

// TODO add these to upstream Zig
const SHN_UNDEF = 0;
const SHN_LORESERVE = 0xff00;
const SHN_LOPROC = 0xff00;
const SHN_HIPROC = 0xff1f;
const SHN_LIVEPATCH = 0xff20;
const SHN_ABS = 0xfff1;
const SHN_COMMON = 0xfff2;
const SHN_HIRESERVE = 0xffff;

allocator: *Allocator,
file: fs.File,

header: elf.Header = undefined,
shdrs: std.ArrayListUnmanaged(elf.Elf64_Shdr) = .{},
shstrtab: std.ArrayListUnmanaged(u8) = .{},

symtab_shdr_index: ?u16 = null,
strtab_shdr_index: ?u16 = null,

symtab: std.ArrayListUnmanaged(elf.Elf64_Sym) = .{},
strtab: std.ArrayListUnmanaged(u8) = .{},

pub fn init(allocator: *Allocator, file: fs.File) Elf {
    return .{
        .allocator = allocator,
        .file = file,
    };
}

pub fn deinit(self: *Elf) void {
    self.shdrs.deinit(self.allocator);
    self.shstrtab.deinit(self.allocator);
    self.symtab.deinit(self.allocator);
    self.strtab.deinit(self.allocator);
}

pub fn parseMetadata(self: *Elf) !void {
    self.header = try elf.Header.read(self.file);

    // Parse section headers
    {
        try self.shdrs.ensureTotalCapacity(self.allocator, self.header.shnum);
        var it = self.header.section_header_iterator(self.file);
        var index: u16 = 0;
        while (try it.next()) |shdr| {
            self.shdrs.appendAssumeCapacity(shdr);

            if (shdr.sh_type == elf.SHT_SYMTAB) {
                self.symtab_shdr_index = index;
            } else if (shdr.sh_type == elf.SHT_STRTAB and index != self.header.shstrndx) {
                self.strtab_shdr_index = index;
            }

            index += 1;
        }
    }

    // Parse section header string table
    {
        var buffer = try self.readShdrContents(self.header.shstrndx);
        defer self.allocator.free(buffer);
        try self.shstrtab.appendSlice(self.allocator, buffer);
    }

    // Parse symbol table
    if (self.symtab_shdr_index) |symtab_index| {
        var buffer = try self.readShdrContents(symtab_index);
        defer self.allocator.free(buffer);

        if (self.header.is_64) {
            // TODO non-native endianness
            const syms = @alignCast(@alignOf(elf.Elf64_Sym), mem.bytesAsSlice(elf.Elf64_Sym, buffer));
            try self.symtab.appendSlice(self.allocator, syms);
        } else {
            // TODO non-native endianness
            const syms = @alignCast(@alignOf(elf.Elf32_Sym), mem.bytesAsSlice(elf.Elf32_Sym, buffer));
            try self.symtab.ensureTotalCapacity(self.allocator, syms.len);
            for (syms) |sym| {
                self.symtab.appendAssumeCapacity(.{
                    .st_name = sym.st_name,
                    .st_info = sym.st_info,
                    .st_other = sym.st_other,
                    .st_shndx = sym.st_shndx,
                    .st_value = sym.st_value,
                    .st_size = sym.st_size,
                });
            }
        }
    }

    // Parse string table
    if (self.strtab_shdr_index) |strtab_index| {
        var buffer = try self.readShdrContents(strtab_index);
        defer self.allocator.free(buffer);
        try self.strtab.appendSlice(self.allocator, buffer);
    }
}

pub fn printHeader(self: Elf, writer: anytype) !void {
    try writer.print("ELF Header:\n", .{});
    try writer.print("  Endianness: {s}\n", .{self.header.endian});
    try writer.print("  Machine: {s}\n", .{(&switch (self.header.machine) {
        ._NONE => "none",
        ._M32 => "AT&T WE 32100",
        ._AARCH64 => "ARM Aarch64",
        ._X86_64 => "AMD x86-64 architecture",
        else => "unknown",
    }).*});
    try writer.print("  Class: {s}\n", .{(&if (self.header.is_64) "ELF64" else "ELF32").*});
    try writer.print("  Entry point address: 0x{x}\n", .{self.header.entry});
    try writer.print("  Start of program headers: {d} (bytes into file)\n", .{self.header.phoff});
    try writer.print("  Start of section headers: {d} (bytes into file)\n", .{self.header.shoff});
    try writer.print("  Size of program headers: {d} (bytes)\n", .{self.header.phentsize});
    try writer.print("  Number of program headers: {d}\n", .{self.header.phnum});
    try writer.print("  Size of section headers: {d} (bytes)\n", .{self.header.shentsize});
    try writer.print("  Number of section headers: {d}\n", .{self.header.shnum});
    try writer.print("  Section header string table index: {d}\n", .{self.header.shstrndx});
}

pub fn printShdrs(self: Elf, writer: anytype) !void {
    try writer.print("There are {d} section headers, starting at offset 0x{x}:\n\n", .{
        self.header.shnum,
        self.header.shoff,
    });
    try writer.print("Section Headers:\n", .{});
    try writer.print("  [Nr]  Name{s: <14}Type{s: <14}Address{s: <11}Offset\n", .{ "", "", "" });
    try writer.print("        Size{s: <14}EntSize{s: <11}Flags  Link  Info  Align\n", .{ "", "" });
    for (self.shdrs.items) |shdr, i| {
        const sh_name = self.getShString(shdr.sh_name);
        const sh_type = blk: {
            if (elf.SHT_LOOS <= shdr.sh_type and shdr.sh_type < elf.SHT_HIOS) {
                break :blk try fmt.allocPrint(self.allocator, "LOOS+0x{x}", .{shdr.sh_type - elf.SHT_LOOS});
            }
            if (elf.SHT_LOPROC <= shdr.sh_type and shdr.sh_type < elf.SHT_HIPROC) {
                break :blk try fmt.allocPrint(self.allocator, "LOPROC+0x{x}", .{shdr.sh_type - elf.SHT_LOPROC});
            }
            if (elf.SHT_LOUSER <= shdr.sh_type and shdr.sh_type < elf.SHT_HIUSER) {
                break :blk try fmt.allocPrint(self.allocator, "LOUSER+0x{x}", .{shdr.sh_type - elf.SHT_LOUSER});
            }
            const sh_type = &switch (shdr.sh_type) {
                elf.SHT_NULL => "NULL",
                elf.SHT_PROGBITS => "PROGBITS",
                elf.SHT_SYMTAB => "SYMTAB",
                elf.SHT_STRTAB => "STRTAB",
                elf.SHT_RELA => "RELA",
                elf.SHT_HASH => "HASH",
                elf.SHT_DYNAMIC => "DYNAMIC",
                elf.SHT_NOTE => "NOTE",
                elf.SHT_NOBITS => "NOBITS",
                elf.SHT_REL => "REL",
                elf.SHT_SHLIB => "SHLIB",
                elf.SHT_DYNSYM => "DYNSYM",
                elf.SHT_INIT_ARRAY => "INIT_ARRAY",
                elf.SHT_FINI_ARRAY => "FINI_ARRAY",
                elf.SHT_PREINIT_ARRAY => "PREINIT_ARRAY",
                elf.SHT_GROUP => "GROUP",
                elf.SHT_SYMTAB_SHNDX => "SYMTAB_SHNDX",
                else => unreachable,
            };
            break :blk try self.allocator.dupe(u8, sh_type.*);
        };
        defer self.allocator.free(sh_type);
        const flags = blk: {
            var flags = std.ArrayList(u8).init(self.allocator);
            defer flags.deinit();
            if (elf.SHF_WRITE & shdr.sh_flags != 0) {
                try flags.append('W');
            }
            if (elf.SHF_ALLOC & shdr.sh_flags != 0) {
                try flags.append('A');
            }
            if (elf.SHF_EXECINSTR & shdr.sh_flags != 0) {
                try flags.append('X');
            }
            if (elf.SHF_MERGE & shdr.sh_flags != 0) {
                try flags.append('M');
            }
            if (elf.SHF_STRINGS & shdr.sh_flags != 0) {
                try flags.append('S');
            }
            if (elf.SHF_INFO_LINK & shdr.sh_flags != 0) {
                try flags.append('I');
            }
            if (elf.SHF_LINK_ORDER & shdr.sh_flags != 0) {
                try flags.append('L');
            }
            if (elf.SHF_EXCLUDE & shdr.sh_flags != 0) {
                try flags.append('E');
            }
            // TODO parse more flags
            break :blk flags.toOwnedSlice();
        };
        defer self.allocator.free(flags);
        try writer.print("  [{d: >2}]  {s: <16}  {s: <16}  {x:0>16}  {x:0>16}\n", .{
            i,
            sh_name,
            sh_type,
            shdr.sh_addr,
            shdr.sh_offset,
        });
        try writer.print("        {x:0>16}  {x:0>16}  {s: <5}  {d: >4}  {d: >4}  {d: >4}\n", .{
            shdr.sh_size,
            shdr.sh_entsize,
            flags,
            shdr.sh_link,
            shdr.sh_info,
            shdr.sh_addralign,
        });
    }
}

pub fn printSymtab(self: Elf, writer: anytype) !void {
    if (self.symtab_shdr_index == null) {
        try writer.print("There is no symbol table in this file.", .{});
        return;
    }

    const shdr = self.shdrs.items[self.symtab_shdr_index.?];
    try writer.print("Symbol table '{s}' contains {d} entries:\n", .{
        self.getShString(shdr.sh_name),
        self.symtab.items.len,
    });
    try writer.print("  Num:{s: <12}Value{s: <2}Size Type{s: <3} Bind{s: <2} Vis{s: <5} Ndx{s: <2} Name\n", .{
        "",
        "",
        "",
        "",
        "",
        "",
    });

    for (self.symtab.items) |sym, i| {
        const sym_name = self.getString(sym.st_name);
        const sym_type = blk: {
            const tt = sym.st_info & 0xf;
            if (elf.STT_LOPROC <= tt and tt < elf.STT_HIPROC) {
                break :blk try fmt.allocPrint(self.allocator, "LOPROC+{d}", .{tt - elf.STT_LOPROC});
            }
            if (elf.STT_LOOS <= tt and tt < elf.STT_HIOS) {
                break :blk try fmt.allocPrint(self.allocator, "LOOS+{d}", .{tt - elf.STT_LOOS});
            }
            const sym_type = &switch (tt) {
                elf.STT_NOTYPE => "NOTYPE",
                elf.STT_OBJECT => "OBJECT",
                elf.STT_FUNC => "FUNC",
                elf.STT_SECTION => "SECTION",
                elf.STT_FILE => "FILE",
                elf.STT_COMMON => "COMMON",
                elf.STT_TLS => "TLS",
                elf.STT_NUM => "NUM",
                else => unreachable,
            };
            break :blk try self.allocator.dupe(u8, sym_type.*);
        };
        defer self.allocator.free(sym_type);
        const sym_bind = blk: {
            const bind = sym.st_info >> 4;
            if (elf.STB_LOPROC <= bind and bind < elf.STB_HIPROC) {
                break :blk try fmt.allocPrint(self.allocator, "LOPROC+{d}", .{bind - elf.STB_LOPROC});
            }
            if (elf.STB_LOOS <= bind and bind < elf.STB_HIOS) {
                break :blk try fmt.allocPrint(self.allocator, "LOOS+{d}", .{bind - elf.STB_LOOS});
            }
            const sym_bind = &switch (bind) {
                elf.STB_LOCAL => "LOCAL",
                elf.STB_GLOBAL => "GLOBAL",
                elf.STB_WEAK => "WEAK",
                elf.STB_NUM => "NUM",
                else => unreachable,
            };
            break :blk try self.allocator.dupe(u8, sym_bind.*);
        };
        defer self.allocator.free(sym_bind);
        const sym_vis = (&if (sym.st_other == 0) "DEFAULT" else "UNKNOWN").*;
        const sym_ndx = blk: {
            if (SHN_LORESERVE <= sym.st_shndx and sym.st_shndx < SHN_HIRESERVE) {
                if (SHN_LOPROC <= sym.st_shndx and sym.st_shndx < SHN_HIPROC) {
                    break :blk try fmt.allocPrint(self.allocator, "LO+{d}", .{sym.st_shndx - SHN_LOPROC});
                }

                const sym_ndx = &switch (sym.st_shndx) {
                    SHN_ABS => "ABS",
                    SHN_COMMON => "COM",
                    SHN_LIVEPATCH => "LIV",
                    else => unreachable,
                };
                break :blk try self.allocator.dupe(u8, sym_ndx.*);
            } else if (sym.st_shndx == SHN_UNDEF) {
                break :blk try self.allocator.dupe(u8, "UND");
            }
            break :blk try fmt.allocPrint(self.allocator, "{d}", .{sym.st_shndx});
        };
        defer self.allocator.free(sym_ndx);
        try writer.print("  {d: >3}: {x:0<16} {d: >5} {s: <7} {s: <6} {s: <8} {s: <5} {s}\n", .{
            i,
            sym.st_value,
            sym.st_size,
            sym_type,
            sym_bind,
            sym_vis,
            sym_ndx,
            sym_name,
        });
    }
}

fn getShString(self: Elf, off: u32) []const u8 {
    assert(off < self.shstrtab.items.len);
    return mem.spanZ(@ptrCast([*:0]const u8, self.shstrtab.items.ptr + off));
}

fn getString(self: Elf, off: u32) []const u8 {
    assert(off < self.strtab.items.len);
    return mem.spanZ(@ptrCast([*:0]const u8, self.strtab.items.ptr + off));
}

fn readShdrContents(self: Elf, shdr_index: u16) ![]u8 {
    const shdr = self.shdrs.items[shdr_index];
    var buffer = try self.allocator.alloc(u8, shdr.sh_size);
    const amt = try self.file.preadAll(buffer, shdr.sh_offset);
    assert(amt == buffer.len);
    return buffer;
}
