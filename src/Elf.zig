const Elf = @This();

const std = @import("std");
const bits = @import("bits.zig");
const assert = std.debug.assert;
const elf = std.elf;
const fmt = std.fmt;
const fs = std.fs;
const log = std.log.scoped(.zelf);
const mem = std.mem;

const Allocator = mem.Allocator;

allocator: *Allocator,
file: fs.File,

header: elf.Header = undefined,
shdrs: std.ArrayListUnmanaged(elf.Elf64_Shdr) = .{},
phds: std.ArrayListUnmanaged(elf.Elf64_Phdr) = .{},

symtab: std.ArrayListUnmanaged(elf.Elf64_Sym) = .{},
strtab: std.ArrayListUnmanaged(u8) = .{},
symtab_offsets: std.AutoHashMapUnmanaged(u16, u32) = .{},
strtab_offsets: std.AutoHashMapUnmanaged(u16, u32) = .{},

pub fn init(allocator: *Allocator, file: fs.File) Elf {
    return .{
        .allocator = allocator,
        .file = file,
    };
}

pub fn deinit(self: *Elf) void {
    self.shdrs.deinit(self.allocator);
    self.symtab.deinit(self.allocator);
    self.strtab.deinit(self.allocator);
    self.symtab_offsets.deinit(self.allocator);
    self.strtab_offsets.deinit(self.allocator);
}

pub fn parseMetadata(self: *Elf) !void {
    self.header = try elf.Header.read(self.file);

    // Parse section headers
    {
        try self.shdrs.ensureTotalCapacity(self.allocator, self.header.shnum);
        var it = self.header.section_header_iterator(self.file);
        while (try it.next()) |shdr| {
            self.shdrs.appendAssumeCapacity(shdr);
        }
    }

    // Parse symtabs and strtabs
    for (self.shdrs.items) |shdr, i| {
        if (shdr.sh_type != elf.SHT_SYMTAB and shdr.sh_type != elf.SHT_STRTAB) continue;

        const ndx = @intCast(u16, i);
        var buffer = try self.readShdrContents(@intCast(u16, ndx));
        defer self.allocator.free(buffer);

        if (shdr.sh_type == elf.SHT_SYMTAB) {
            const nsyms = @divExact(shdr.sh_size, shdr.sh_entsize);
            const off = @intCast(u32, self.symtab.items.len);

            if (self.header.is_64) {
                // TODO non-native endianness
                const syms = @alignCast(@alignOf(elf.Elf64_Sym), mem.bytesAsSlice(elf.Elf64_Sym, buffer));
                try self.symtab.appendSlice(self.allocator, syms);
            } else {
                try self.symtab.ensureUnusedCapacity(self.allocator, nsyms);
                // TODO non-native endianness
                const syms = @alignCast(@alignOf(elf.Elf32_Sym), mem.bytesAsSlice(elf.Elf32_Sym, buffer));
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

            try self.symtab_offsets.putNoClobber(self.allocator, ndx, off);
        } else {
            const off = @intCast(u32, self.strtab.items.len);
            try self.strtab.appendSlice(self.allocator, buffer);
            try self.strtab_offsets.putNoClobber(self.allocator, ndx, off);
        }
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
        const sh_name = self.getString(self.header.shstrndx, shdr.sh_name);
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
                else => "UNKNOWN",
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

pub fn printRelocs(self: Elf, writer: anytype) !void {
    var has_relocs = false;
    for (self.shdrs.items) |shdr, i| {
        switch (shdr.sh_type) {
            elf.SHT_REL, elf.SHT_RELA => {},
            else => continue,
        }

        has_relocs = true;
        const symtab_shdr = self.shdrs.items[shdr.sh_link];
        const symtab = self.getSymtab(@intCast(u16, shdr.sh_link));

        var buffer = try self.readShdrContents(@intCast(u16, i));
        defer self.allocator.free(buffer);

        const nrelocs = @divExact(shdr.sh_size, shdr.sh_entsize);
        var relocs = try self.allocator.alloc(elf.Elf64_Rela, nrelocs);
        defer self.allocator.free(relocs);

        if (self.header.is_64) {
            // TODO non-native endianness
            if (shdr.sh_type == elf.SHT_REL) {
                const slice = @alignCast(
                    @alignOf(elf.Elf64_Rel),
                    mem.bytesAsSlice(elf.Elf64_Rel, buffer),
                );
            } else {
                const slice = @alignCast(
                    @alignOf(elf.Elf64_Rela),
                    mem.bytesAsSlice(elf.Elf64_Rela, buffer),
                );
                mem.copy(elf.Elf64_Rela, relocs, slice);
            }
        } else {
            // TODO non-native endianness
            if (shdr.sh_type == elf.SHT_REL) {
                const slice = @alignCast(
                    @alignOf(elf.Elf32_Rel),
                    mem.bytesAsSlice(elf.Elf32_Rel, buffer),
                );
            } else {
                const slice = @alignCast(
                    @alignOf(elf.Elf32_Rela),
                    mem.bytesAsSlice(elf.Elf32_Rela, buffer),
                );
            }
        }

        try writer.print("Relocation section '{s}' at offset 0x{x} contains {d} entries:\n", .{
            self.getString(self.header.shstrndx, shdr.sh_name),
            shdr.sh_offset,
            nrelocs,
        });
        try writer.print(
            "  Offset{s: <8}Info{s: <12}Type{s: <20}Sym. Value{s: <2}Sym. Name + Addend\n",
            .{ "", "", "", "" },
        );

        for (relocs) |reloc| {
            const r_sym = reloc.r_info >> 32;
            const sym = symtab[r_sym];
            const sym_name = self.getString(@intCast(u16, symtab_shdr.sh_link), sym.st_name);
            const r_type = @truncate(u32, reloc.r_info);
            const rel_type = &switch (r_type) {
                bits.R_X86_64_NONE => "R_X86_64_NONE",
                bits.R_X86_64_64 => "R_X86_64_64",
                bits.R_X86_64_PC32 => "R_X86_64_PC32",
                bits.R_X86_64_GOT32 => "R_X86_64_GOT32",
                bits.R_X86_64_PLT32 => "R_X86_64_PLT32",
                bits.R_X86_64_COPY => "R_X86_64_COPY",
                bits.R_X86_64_GLOB_DAT => "R_X86_64_GLOB_DAT",
                bits.R_X86_64_JUMP_SLOT => "R_X86_64_JUMP_SLOT",
                bits.R_X86_64_RELATIVE => "R_X86_64_RELATIVE",
                bits.R_X86_64_GOTPCREL => "R_X86_64_GOTPCREL",
                bits.R_X86_64_32 => "R_X86_64_32",
                bits.R_X86_64_32S => "R_X86_64_32S",
                bits.R_X86_64_16 => "R_X86_64_16",
                bits.R_X86_64_PC16 => "R_X86_64_PC16",
                bits.R_X86_64_8 => "R_X86_64_8",
                bits.R_X86_64_PC8 => "R_X86_64_PC8",
                bits.R_X86_64_DTPMOD64 => "R_X86_64_DTPMOD64",
                bits.R_X86_64_DTPOFF64 => "R_X86_64_DTPOFF64",
                bits.R_X86_64_TPOFF64 => "R_X86_64_TPOFF64",
                bits.R_X86_64_TLSGD => "R_X86_64_TLSGD",
                bits.R_X86_64_TLSLD => "R_X86_64_TLSLD",
                bits.R_X86_64_DTPOFF32 => "R_X86_64_DTPOFF32",
                bits.R_X86_64_GOTTPOFF => "R_X86_64_GOTTPOFF",
                bits.R_X86_64_TPOFF32 => "R_X86_64_TPOFF32",
                bits.R_X86_64_PC64 => "R_X86_64_PC64",
                bits.R_X86_64_GOTOFF64 => "R_X86_64_GOTOFF64",
                bits.R_X86_64_GOTPC32 => "R_X86_64_GOTPC32",
                bits.R_X86_64_GOT64 => "R_X86_64_GOT64",
                bits.R_X86_64_GOTPCREL64 => "R_X86_64_GOTPCREL64",
                bits.R_X86_64_GOTPC64 => "R_X86_64_GOTPC64",
                bits.R_X86_64_GOTPLT64 => "R_X86_64_GOTPLT64",
                bits.R_X86_64_PLTOFF64 => "R_X86_64_PLTOFF64",
                bits.R_X86_64_SIZE32 => "R_X86_64_SIZE32",
                bits.R_X86_64_SIZE64 => "R_X86_64_SIZE64",
                bits.R_X86_64_GOTPC32_TLSDESC => "R_X86_64_GOTPC32_TLSDESC",
                bits.R_X86_64_TLSDESC_CALL => "R_X86_64_TLSDESC_CALL",
                bits.R_X86_64_TLSDESC => "R_X86_64_TLSDESC",
                bits.R_X86_64_IRELATIVE => "R_X86_64_IRELATIVE",
                bits.R_X86_64_RELATIVE64 => "R_X86_64_RELATIVE64",
                bits.R_X86_64_GOTPCRELX => "R_X86_64_GOTPCRELX",
                bits.R_X86_64_REX_GOTPCRELX => "R_X86_64_REX_GOTPCRELX",
                bits.R_X86_64_NUM => "R_X86_64_NUM",
                else => "UNKNOWN",
            };
            try writer.print("{x:0>12} {x:0>12} {s: <24} {x:0>16} {s} {d}\n", .{
                reloc.r_offset,
                reloc.r_info,
                rel_type.*,
                sym.st_value,
                sym_name,
                reloc.r_addend,
            });
        }
    }

    if (!has_relocs) {
        try writer.print("There is no relocation info in this file.", .{});
    }
}

pub fn printSymtabs(self: Elf, writer: anytype) !void {
    var has_symtab = false;
    for (self.shdrs.items) |shdr, ndx| {
        if (shdr.sh_type != elf.SHT_SYMTAB) continue;

        has_symtab = true;
        const symtab = self.getSymtab(@intCast(u16, ndx));

        try writer.print("Symbol table '{s}' contains {d} entries:\n", .{
            self.getString(self.header.shstrndx, shdr.sh_name),
            symtab.len,
        });
        try writer.print(
            "  Num:{s: <12}Value{s: <2}Size Type{s: <3} Bind{s: <2} Vis{s: <5} Ndx{s: <2} Name\n",
            .{ "", "", "", "", "", "" },
        );

        for (symtab) |sym, i| {
            const sym_name = self.getString(@intCast(u16, shdr.sh_link), sym.st_name);
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
                    else => "UNKNOWN",
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
                    else => "UNKNOWN",
                };
                break :blk try self.allocator.dupe(u8, sym_bind.*);
            };
            defer self.allocator.free(sym_bind);
            const sym_vis = (&if (sym.st_other == 0) "DEFAULT" else "UNKNOWN").*;
            const sym_ndx = blk: {
                if (bits.SHN_LORESERVE <= sym.st_shndx and sym.st_shndx < bits.SHN_HIRESERVE) {
                    if (bits.SHN_LOPROC <= sym.st_shndx and sym.st_shndx < bits.SHN_HIPROC) {
                        break :blk try fmt.allocPrint(self.allocator, "LO+{d}", .{sym.st_shndx - bits.SHN_LOPROC});
                    }

                    const sym_ndx = &switch (sym.st_shndx) {
                        bits.SHN_ABS => "ABS",
                        bits.SHN_COMMON => "COM",
                        bits.SHN_LIVEPATCH => "LIV",
                        else => "UNK",
                    };
                    break :blk try self.allocator.dupe(u8, sym_ndx.*);
                } else if (sym.st_shndx == bits.SHN_UNDEF) {
                    break :blk try self.allocator.dupe(u8, "UND");
                }
                break :blk try fmt.allocPrint(self.allocator, "{d}", .{sym.st_shndx});
            };
            defer self.allocator.free(sym_ndx);
            try writer.print(
                "  {d: >3}: {x:0<16} {d: >5} {s: <7} {s: <6} {s: <8} {s: <5} {s}\n",
                .{ i, sym.st_value, sym.st_size, sym_type, sym_bind, sym_vis, sym_ndx, sym_name },
            );
        }
    }

    if (!has_symtab) {
        try writer.print("There is no symbol table in this file.", .{});
    }
}

fn getString(self: Elf, shdr_ndx: u16, off: u32) []const u8 {
    const actual_off = self.strtab_offsets.get(shdr_ndx).? + off;
    assert(actual_off < self.strtab.items.len);
    return mem.spanZ(@ptrCast([*:0]const u8, self.strtab.items.ptr + actual_off));
}

fn getSymtab(self: Elf, shdr_ndx: u16) []const elf.Elf64_Sym {
    const shdr = self.shdrs.items[shdr_ndx];
    const nsyms = @divExact(shdr.sh_size, shdr.sh_entsize);
    const start_ndx = self.symtab_offsets.get(shdr_ndx).?;
    assert(start_ndx < self.symtab.items.len);
    return self.symtab.items[start_ndx..][0..nsyms];
}

fn readShdrContents(self: Elf, shdr_index: u16) ![]u8 {
    const shdr = self.shdrs.items[shdr_index];
    var buffer = try self.allocator.alloc(u8, shdr.sh_size);
    const amt = try self.file.preadAll(buffer, shdr.sh_offset);
    assert(amt == buffer.len);
    return buffer;
}
