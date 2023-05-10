const Elf = @This();

const std = @import("std");
const assert = std.debug.assert;
const elf = std.elf;
const fmt = std.fmt;
const fs = std.fs;
const mem = std.mem;

const Allocator = mem.Allocator;

arena: Allocator,
data: []const u8,

header: elf.Elf64_Ehdr = undefined,
shdrs: []align(1) const elf.Elf64_Shdr = &[0]elf.Elf64_Shdr{},
phdrs: []align(1) const elf.Elf64_Phdr = &[0]elf.Elf64_Phdr{},
shstrtab: []const u8 = &[0]u8{},

symtab_index: ?u32 = null,
symtab: []align(1) const elf.Elf64_Sym = &[0]elf.Elf64_Sym{},
strtab: []const u8 = &[0]u8{},

dynsymtab_index: ?u32 = null,
dynsymtab: []align(1) const elf.Elf64_Sym = &[0]elf.Elf64_Sym{},
dynstrtab: []const u8 = &[0]u8{},

pub fn parse(self: *Elf) !void {
    var stream = std.io.fixedBufferStream(self.data);
    const reader = stream.reader();

    self.header = try reader.readStruct(elf.Elf64_Ehdr);

    if (!mem.eql(u8, self.header.e_ident[0..4], "\x7fELF")) return error.InvalidMagic;

    self.shdrs = @ptrCast([*]align(1) const elf.Elf64_Shdr, self.data.ptr + self.header.e_shoff)[0..self.header.e_shnum];
    self.phdrs = @ptrCast([*]align(1) const elf.Elf64_Phdr, self.data.ptr + self.header.e_phoff)[0..self.header.e_phnum];
    self.shstrtab = self.getSectionContentsByIndex(self.header.e_shstrndx);

    for (self.shdrs, 0..) |shdr, i| switch (shdr.sh_type) {
        elf.SHT_SYMTAB, elf.SHT_DYNSYM => {
            const raw = self.getSectionContents(shdr);
            const nsyms = @divExact(raw.len, @sizeOf(elf.Elf64_Sym));
            const symtab = @ptrCast([*]align(1) const elf.Elf64_Sym, raw.ptr)[0..nsyms];
            const strtab = self.getSectionContentsByIndex(shdr.sh_link);

            switch (shdr.sh_type) {
                elf.SHT_SYMTAB => {
                    self.symtab_index = @intCast(u32, i);
                    self.symtab = symtab;
                    self.strtab = strtab;
                },
                elf.SHT_DYNSYM => {
                    self.dynsymtab_index = @intCast(u32, i);
                    self.dynsymtab = symtab;
                    self.dynstrtab = strtab;
                },
                else => unreachable,
            }
        },
        else => {},
    };
}

pub fn printHeader(self: Elf, writer: anytype) !void {
    try writer.print("ELF Header:\n", .{});

    try writer.writeAll("  Magic:  ");
    for (self.header.e_ident) |byte| {
        try writer.print(" {x:0>2}", .{byte});
    }
    try writer.writeByte('\n');

    try writer.print("  {s: <34} {s}\n", .{ "Class:", switch (self.header.e_ident[elf.EI_CLASS]) {
        elf.ELFCLASS32 => "ELF32",
        elf.ELFCLASS64 => "ELF64",
        else => "Unknown",
    } });
    try writer.print("  {s: <34} 2's complement, {s} endian\n", .{ "Data:", switch (self.header.e_ident[elf.EI_DATA]) {
        elf.ELFDATA2LSB => "little",
        elf.ELFDATA2MSB => "big",
        else => "unknown",
    } });
    try writer.print("  {s: <34} {d} ({s})\n", .{
        "Version:",
        self.header.e_ident[elf.EI_VERSION],
        if (self.header.e_ident[elf.EI_VERSION] == 1) "current" else "unknown",
    });
    try writer.print("  {s: <34} {s}\n", .{ "OS/ABI:", switch (self.header.e_ident[EI_OSABI]) {
        ELFOSABI_SYSV => "UNIX - System V",
        ELFOSABI_HPUX => "HP UNIX",
        ELFOSABI_NETBSD => "NetBSD",
        ELFOSABI_LINUX => "Linux GNU",
        ELFOSABI_SOLARIS => "Solaris UNIX",
        ELFOSABI_AIX => "AIX",
        ELFOSABI_IRIX => "IRIX",
        ELFOSABI_FREEBSD => "FreeBSD",
        ELFOSABI_TRU64 => "TRU64",
        ELFOSABI_MODESTO => "Modesto",
        ELFOSABI_OPENBSD => "OpenBSD",
        ELFOSABI_ARM => "ARM",
        ELFOSABI_STANDALONE => "Standalone",
        else => "Unknown",
    } });
    try writer.print("  {s: <34} {d}\n", .{ "ABI Version:", self.header.e_ident[EI_ABIVERSION] });
    if (elf.ET.LOPROC <= @enumToInt(self.header.e_type) and @enumToInt(self.header.e_type) < elf.ET.HIPROC) {
        try writer.print("  {s: <34} {s}+{x} (Processor-specific)\n", .{
            "Type:",
            "LOPROC",
            @enumToInt(self.header.e_type),
        });
    } else {
        try writer.print("  {s: <34} {s} ({s})\n", .{ "Type:", @tagName(self.header.e_type), switch (self.header.e_type) {
            .NONE => "No file type",
            .REL => "Relocatable file",
            .EXEC => "Executable file",
            .DYN => "Shared object file",
            .CORE => "Core file",
        } });
    }
    try writer.print("  {s: <34} {s}\n", .{ "Machine:", switch (self.header.e_machine) {
        .NONE => "None",
        .X86_64 => "Advanced Micro Devices X86-64",
        else => "Unknown",
    } });
    try writer.print("  {s: <34} 0x{x}\n", .{ "Version:", self.header.e_version });
    try writer.print("  {s: <34} 0x{x}\n", .{ "Entry point address:", self.header.e_entry });
    try writer.print("  {s: <34} {d} (bytes into file)\n", .{ "Start of program headers:", self.header.e_phoff });
    try writer.print("  {s: <34} {d} (bytes into file)\n", .{ "Start of section headers:", self.header.e_shoff });
    try writer.print("  {s: <34} 0x{x}\n", .{ "Flags:", self.header.e_flags });
    try writer.print("  {s: <34} {d} (bytes)\n", .{ "Size of this header:", self.header.e_ehsize });
    try writer.print("  {s: <34} {d} (bytes)\n", .{ "Size of program headers:", self.header.e_phentsize });
    try writer.print("  {s: <34} {d}\n", .{ "Number of program headers:", self.header.e_phnum });
    try writer.print("  {s: <34} {d} (bytes)\n", .{ "Size of section headers:", self.header.e_shentsize });
    try writer.print("  {s: <34} {d}\n", .{ "Number of section headers:", self.header.e_shnum });
    try writer.print("  {s: <34} {d}\n", .{ "Section header string table index:", self.header.e_shstrndx });
}

const EI_OSABI = 7;
const ELFOSABI_NONE = 0;
const ELFOSABI_SYSV = 0;
const ELFOSABI_HPUX = 1;
const ELFOSABI_NETBSD = 2;
const ELFOSABI_LINUX = 3;
const ELFOSABI_GNU = 3;
const ELFOSABI_SOLARIS = 6;
const ELFOSABI_AIX = 7;
const ELFOSABI_IRIX = 8;
const ELFOSABI_FREEBSD = 9;
const ELFOSABI_TRU64 = 10;
const ELFOSABI_MODESTO = 11;
const ELFOSABI_OPENBSD = 12;
const ELFOSABI_ARM = 97;
const ELFOSABI_STANDALONE = 255;

const EI_ABIVERSION = 8;

pub fn printShdrs(self: Elf, writer: anytype) !void {
    const legend =
        \\Key to Flags:
        \\  W (write), A (alloc), X (execute), M (merge), S (strings), I (info),
        \\  L (link order), O (extra OS processing required), G (group), T (TLS),
        \\  C (compressed), x (unknown), o (OS specific), E (exclude),
        \\  D (mbind), l (large), p (processor specific)
        \\
    ;

    try writer.print("There are {d} section headers, starting at offset 0x{x}:\n\n", .{
        self.header.e_shnum,
        self.header.e_shoff,
    });
    try writer.print("Section Headers:\n", .{});
    try writer.print("  [Nr]  Name{s: <14}Type{s: <14}Address{s: <11}Offset\n", .{ "", "", "" });
    try writer.print("        Size{s: <14}EntSize{s: <11}Flags  Link  Info  Align\n", .{ "", "" });

    var sh_name_fmt = FormatName(16){};

    for (self.shdrs, 0..) |shdr, i| {
        const sh_flags = shdr.sh_flags;
        const sh_name = self.getShString(shdr.sh_name);
        const sh_type = switch (shdr.sh_type) {
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
            elf.SHT_X86_64_UNWIND => "X86_64_UNWIND",
            elf.SHT_LLVM_ADDRSIG => "LLVM_ADDRSIG",
            else => |sht| blk: {
                if (elf.SHT_LOOS <= sht and sht < elf.SHT_HIOS) {
                    break :blk try fmt.allocPrint(self.arena, "LOOS+0x{x}", .{sht - elf.SHT_LOOS});
                }
                if (elf.SHT_LOPROC <= sht and sht < elf.SHT_HIPROC) {
                    break :blk try fmt.allocPrint(self.arena, "LOPROC+0x{x}", .{sht - elf.SHT_LOPROC});
                }
                if (elf.SHT_LOUSER <= sht and sht < elf.SHT_HIUSER) {
                    break :blk try fmt.allocPrint(self.arena, "LOUSER+0x{x}", .{sht - elf.SHT_LOUSER});
                }
                break :blk "UNKNOWN";
            },
        };
        const flags = blk: {
            var flags = std.ArrayList(u8).init(self.arena);
            if (elf.SHF_WRITE & sh_flags != 0) {
                try flags.append('W');
            }
            if (elf.SHF_ALLOC & sh_flags != 0) {
                try flags.append('A');
            }
            if (elf.SHF_EXECINSTR & sh_flags != 0) {
                try flags.append('X');
            }
            if (elf.SHF_MERGE & sh_flags != 0) {
                try flags.append('M');
            }
            if (elf.SHF_STRINGS & sh_flags != 0) {
                try flags.append('S');
            }
            if (elf.SHF_INFO_LINK & sh_flags != 0) {
                try flags.append('I');
            }
            if (elf.SHF_LINK_ORDER & sh_flags != 0) {
                try flags.append('L');
            }
            if (elf.SHF_EXCLUDE & sh_flags != 0) {
                try flags.append('E');
            }
            if (elf.SHF_COMPRESSED & sh_flags != 0) {
                try flags.append('C');
            }
            if (elf.SHF_GROUP & sh_flags != 0) {
                try flags.append('G');
            }
            if (elf.SHF_OS_NONCONFORMING & sh_flags != 0) {
                try flags.append('O');
            }
            if (elf.SHF_TLS & sh_flags != 0) {
                try flags.append('T');
            }
            if (elf.SHF_X86_64_LARGE & sh_flags != 0) {
                try flags.append('l');
            }
            if (elf.SHF_MIPS_ADDR & sh_flags != 0 or elf.SHF_ARM_PURECODE & sh_flags != 0) {
                try flags.append('p');
            }
            // TODO parse more flags
            break :blk try flags.toOwnedSlice();
        };
        try writer.print("  [{d: >2}]  {s: <16}  {s: <16}  {x:0>16}  {x:0>16}\n", .{
            i,
            sh_name_fmt.fmt(sh_name),
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

    try writer.writeAll(legend);
}

pub fn printPhdrs(self: Elf, writer: anytype) !void {
    if (self.phdrs.len == 0) return writer.print("There are no program headers in this file.\n", .{});

    try writer.print("Entry point 0x{x}\n", .{self.header.e_entry});
    try writer.print("There are {d} program headers, starting at offset {d}\n\n", .{
        self.phdrs.len,
        self.header.e_phoff,
    });
    try writer.print("Program Headers:\n", .{});
    try writer.print("  Type{s: <12} Offset{s: <10} VirtAddr{s: <8} PhysAddr{s: <8}\n", .{ "", "", "", "" });
    try writer.print("  {s: <16} FileSiz{s: <9} MemSiz{s: <10} Flags  Align\n", .{ "", "", "" });

    var section_to_segment = try self.arena.alloc(std.ArrayList(usize), self.phdrs.len);
    for (self.phdrs, 0..) |_, i| {
        section_to_segment[i] = std.ArrayList(usize).init(self.arena);
    }

    for (self.phdrs, 0..) |phdr, i| {
        const p_type = switch (phdr.p_type) {
            elf.PT_NULL => "NULL",
            elf.PT_LOAD => "LOAD",
            elf.PT_DYNAMIC => "DYNAMIC",
            elf.PT_INTERP => "INTERP",
            elf.PT_NOTE => "NOTE",
            elf.PT_SHLIB => "SHLIB",
            elf.PT_PHDR => "PHDR",
            elf.PT_TLS => "TLS",
            elf.PT_NUM => "NUM",
            elf.PT_GNU_EH_FRAME => "GNU_EH_FRAME",
            elf.PT_GNU_STACK => "GNU_STACK",
            elf.PT_GNU_RELRO => "GNU_RELRO",
            else => |pt| blk: {
                if (elf.PT_LOOS <= pt and pt < elf.PT_HIOS) {
                    break :blk try fmt.allocPrint(self.arena, "LOOS+0x{x}", .{pt - elf.PT_LOOS});
                }
                if (elf.PT_LOPROC <= pt and pt < elf.PT_HIPROC) {
                    break :blk try fmt.allocPrint(self.arena, "LOPROC+0x{x}", .{pt - elf.PT_LOPROC});
                }
                break :blk "UNKNOWN";
            },
        };
        const p_flags = blk: {
            var p_flags = std.ArrayList(u8).init(self.arena);
            if (phdr.p_flags & elf.PF_R != 0) {
                try p_flags.append('R');
            }
            if (phdr.p_flags & elf.PF_W != 0) {
                try p_flags.append('W');
            }
            if (phdr.p_flags & elf.PF_X != 0) {
                try p_flags.append('E');
            }
            if (phdr.p_flags & elf.PF_MASKOS != 0) {
                try p_flags.appendSlice("OS");
            }
            if (phdr.p_flags & elf.PF_MASKPROC != 0) {
                try p_flags.appendSlice("PROC");
            }
            break :blk try p_flags.toOwnedSlice();
        };
        try writer.print("  {s: <16} {x:0>16} {x:0>16} {x:0>16}\n", .{
            p_type,
            phdr.p_offset,
            phdr.p_vaddr,
            phdr.p_paddr,
        });
        try writer.print("  {s: >16} {x:0>16} {x:0>16} {s: <6} {x:0>6}\n", .{
            "",
            phdr.p_filesz,
            phdr.p_memsz,
            p_flags,
            phdr.p_align,
        });

        const start_addr = phdr.p_vaddr;
        const end_addr = start_addr + phdr.p_memsz;
        for (self.shdrs, 0..) |shdr, j| {
            if (start_addr <= shdr.sh_addr and shdr.sh_addr < end_addr) {
                try section_to_segment[i].append(j);
            }
        }
    }

    try writer.writeAll("\n");
    try writer.print(" Section to Segment mapping:\n", .{});
    try writer.print("  Segment Sections...\n", .{});

    for (section_to_segment, 0..) |ss, i| {
        try writer.print("   {d:0>2}     ", .{i});

        for (ss.items, 0..) |shdr_ndx, x| {
            const shdr = self.shdrs[shdr_ndx];
            const shdr_name = self.getShString(shdr.sh_name);
            try writer.print("{s}", .{shdr_name});
            if (x < ss.items.len - 1) {
                try writer.writeAll(" ");
            }
        }

        try writer.writeAll("\n");
    }
}

pub fn printRelocs(self: Elf, writer: anytype) !void {
    const has_relocs = for (self.shdrs) |shdr| switch (shdr.sh_type) {
        elf.SHT_RELA => break true,
        else => {},
    } else false;
    if (!has_relocs) return writer.print("There is no relocation info in this file.\n", .{});

    var last_shndx: usize = 0;
    for (self.shdrs, 0..) |shdr, i| switch (shdr.sh_type) {
        elf.SHT_RELA => last_shndx = i,
        else => {},
    };

    for (self.shdrs, 0..) |shdr, i| {
        switch (shdr.sh_type) {
            elf.SHT_RELA => {},
            else => continue,
        }

        const raw = self.getSectionContents(shdr);
        const nrelocs = @divExact(shdr.sh_size, shdr.sh_entsize);
        const relocs = @ptrCast([*]align(1) const elf.Elf64_Rela, raw.ptr)[0..nrelocs];

        try writer.print("Relocation section '{s}' at offset 0x{x} contains {d} entries:\n", .{
            self.getShString(shdr.sh_name),
            shdr.sh_offset,
            nrelocs,
        });
        try writer.print(
            "  Offset{s: <8}Info{s: <12}Type{s: <20}Sym. Value{s: <2}Sym. Name + Addend\n",
            .{ "", "", "", "" },
        );

        for (relocs) |reloc| {
            var sym: elf.Elf64_Sym = undefined;
            var sym_name: []const u8 = undefined;
            if (self.symtab_index != null and shdr.sh_link == self.symtab_index.?) {
                sym = self.symtab[reloc.r_sym()];
                sym_name = blk: {
                    if (sym.st_name == 0 and sym.st_type() == elf.STT_SECTION) {
                        const target_shdr = self.shdrs[sym.st_shndx];
                        break :blk self.getShString(target_shdr.sh_name);
                    }
                    break :blk getString(self.strtab, sym.st_name);
                };
            } else if (self.dynsymtab_index != null and shdr.sh_link == self.dynsymtab_index.?) {
                sym = self.dynsymtab[reloc.r_sym()];
                sym_name = getString(self.dynstrtab, sym.st_name);
            } else unreachable;
            try writer.print("{x:0>12} {x:0>12} {s: <24} {x:0>16} {s} ", .{
                reloc.r_offset,
                reloc.r_info,
                fmtRelocType(reloc.r_type()),
                sym.st_value,
                sym_name,
            });
            if (reloc.r_addend >= 0) {
                try writer.print("+ {x}", .{reloc.r_addend});
            } else {
                try writer.print("- {x}", .{try std.math.absInt(reloc.r_addend)});
            }
            try writer.writeByte('\n');
        }

        if (i != last_shndx) try writer.writeByte('\n');
    }
}

fn fmtRelocType(r_type: u32) std.fmt.Formatter(formatRelocType) {
    return .{ .data = r_type };
}

fn formatRelocType(
    r_type: u32,
    comptime unused_fmt_string: []const u8,
    options: std.fmt.FormatOptions,
    writer: anytype,
) !void {
    _ = unused_fmt_string;
    const str = switch (r_type) {
        elf.R_X86_64_NONE => "R_X86_64_NONE",
        elf.R_X86_64_64 => "R_X86_64_64",
        elf.R_X86_64_PC32 => "R_X86_64_PC32",
        elf.R_X86_64_GOT32 => "R_X86_64_GOT32",
        elf.R_X86_64_PLT32 => "R_X86_64_PLT32",
        elf.R_X86_64_COPY => "R_X86_64_COPY",
        elf.R_X86_64_GLOB_DAT => "R_X86_64_GLOB_DAT",
        elf.R_X86_64_JUMP_SLOT => "R_X86_64_JUMP_SLOT",
        elf.R_X86_64_RELATIVE => "R_X86_64_RELATIVE",
        elf.R_X86_64_GOTPCREL => "R_X86_64_GOTPCREL",
        elf.R_X86_64_32 => "R_X86_64_32",
        elf.R_X86_64_32S => "R_X86_64_32S",
        elf.R_X86_64_16 => "R_X86_64_16",
        elf.R_X86_64_PC16 => "R_X86_64_PC16",
        elf.R_X86_64_8 => "R_X86_64_8",
        elf.R_X86_64_PC8 => "R_X86_64_PC8",
        elf.R_X86_64_DTPMOD64 => "R_X86_64_DTPMOD64",
        elf.R_X86_64_DTPOFF64 => "R_X86_64_DTPOFF64",
        elf.R_X86_64_TPOFF64 => "R_X86_64_TPOFF64",
        elf.R_X86_64_TLSGD => "R_X86_64_TLSGD",
        elf.R_X86_64_TLSLD => "R_X86_64_TLSLD",
        elf.R_X86_64_DTPOFF32 => "R_X86_64_DTPOFF32",
        elf.R_X86_64_GOTTPOFF => "R_X86_64_GOTTPOFF",
        elf.R_X86_64_TPOFF32 => "R_X86_64_TPOFF32",
        elf.R_X86_64_PC64 => "R_X86_64_PC64",
        elf.R_X86_64_GOTOFF64 => "R_X86_64_GOTOFF64",
        elf.R_X86_64_GOTPC32 => "R_X86_64_GOTPC32",
        elf.R_X86_64_GOT64 => "R_X86_64_GOT64",
        elf.R_X86_64_GOTPCREL64 => "R_X86_64_GOTPCREL64",
        elf.R_X86_64_GOTPC64 => "R_X86_64_GOTPC64",
        elf.R_X86_64_GOTPLT64 => "R_X86_64_GOTPLT64",
        elf.R_X86_64_PLTOFF64 => "R_X86_64_PLTOFF64",
        elf.R_X86_64_SIZE32 => "R_X86_64_SIZE32",
        elf.R_X86_64_SIZE64 => "R_X86_64_SIZE64",
        elf.R_X86_64_GOTPC32_TLSDESC => "R_X86_64_GOTPC32_TLSDESC",
        elf.R_X86_64_TLSDESC_CALL => "R_X86_64_TLSDESC_CALL",
        elf.R_X86_64_TLSDESC => "R_X86_64_TLSDESC",
        elf.R_X86_64_IRELATIVE => "R_X86_64_IRELATIVE",
        elf.R_X86_64_RELATIVE64 => "R_X86_64_RELATIVE64",
        elf.R_X86_64_GOTPCRELX => "R_X86_64_GOTPCRELX",
        elf.R_X86_64_REX_GOTPCRELX => "R_X86_64_REX_GOTPCRELX",
        elf.R_X86_64_NUM => "R_X86_64_NUM",
        else => "R_X86_64_UNKNOWN",
    };
    try writer.print("{s}", .{str});
    if (options.width) |width| {
        if (str.len > width) return error.NoSpaceLeft; // TODO how should we actually handle this here?
        const fill = width - str.len;
        if (fill > 0) try writer.writeByteNTimes(options.fill, fill);
    }
}

pub fn printSymtabs(self: Elf, writer: anytype) !void {
    if (self.symtab_index == null and self.dynsymtab_index == null) {
        try writer.print("There is no symbol table in this file.", .{});
        return;
    }
    if (self.symtab_index) |ndx| {
        try self.printSymtab(ndx, self.symtab, self.strtab, writer);
    }
    if (self.dynsymtab_index) |ndx| {
        try self.printSymtab(ndx, self.dynsymtab, self.dynstrtab, writer);
    }
}

fn printSymtab(
    self: Elf,
    shdr_ndx: u32,
    symtab: []align(1) const elf.Elf64_Sym,
    strtab: []align(1) const u8,
    writer: anytype,
) !void {
    const shdr = self.shdrs[shdr_ndx];

    try writer.print("Symbol table '{s}' contains {d} entries:\n", .{
        self.getShString(shdr.sh_name),
        symtab.len,
    });
    try writer.print(
        "  Num:{s: <12}Value{s: <2}Size Type{s: <3} Bind{s: <2} Vis{s: <5} Ndx{s: <2} Name\n",
        .{ "", "", "", "", "", "" },
    );

    var sym_name_fmt = FormatName(32){};

    for (symtab, 0..) |sym, i| {
        const sym_name = getString(strtab, sym.st_name);
        const sym_type = switch (sym.st_type()) {
            elf.STT_NOTYPE => "NOTYPE",
            elf.STT_OBJECT => "OBJECT",
            elf.STT_FUNC => "FUNC",
            elf.STT_SECTION => "SECTION",
            elf.STT_FILE => "FILE",
            elf.STT_COMMON => "COMMON",
            elf.STT_TLS => "TLS",
            elf.STT_NUM => "NUM",
            else => |tt| blk: {
                if (elf.STT_LOPROC <= tt and tt < elf.STT_HIPROC) {
                    break :blk try fmt.allocPrint(self.arena, "LOPROC+{d}", .{tt - elf.STT_LOPROC});
                }
                if (elf.STT_LOOS <= tt and tt < elf.STT_HIOS) {
                    break :blk try fmt.allocPrint(self.arena, "LOOS+{d}", .{tt - elf.STT_LOOS});
                }
                break :blk "UNK";
            },
        };
        const sym_bind = switch (sym.st_bind()) {
            elf.STB_LOCAL => "LOCAL",
            elf.STB_GLOBAL => "GLOBAL",
            elf.STB_WEAK => "WEAK",
            elf.STB_NUM => "NUM",
            else => |bind| blk: {
                if (elf.STB_LOPROC <= bind and bind < elf.STB_HIPROC) {
                    break :blk try fmt.allocPrint(self.arena, "LOPROC+{d}", .{bind - elf.STB_LOPROC});
                }
                if (elf.STB_LOOS <= bind and bind < elf.STB_HIOS) {
                    break :blk try fmt.allocPrint(self.arena, "LOOS+{d}", .{bind - elf.STB_LOOS});
                }
                break :blk "UNKNOWN";
            },
        };
        const sym_vis = (&if (sym.st_other == 0) "DEFAULT" else "UNKNOWN").*;
        const sym_ndx = blk: {
            if (elf.SHN_LORESERVE <= sym.st_shndx and sym.st_shndx < elf.SHN_HIRESERVE) {
                if (elf.SHN_LOPROC <= sym.st_shndx and sym.st_shndx < elf.SHN_HIPROC) {
                    break :blk try fmt.allocPrint(self.arena, "LO+{d}", .{sym.st_shndx - elf.SHN_LOPROC});
                }

                const sym_ndx = &switch (sym.st_shndx) {
                    elf.SHN_ABS => "ABS",
                    elf.SHN_COMMON => "COM",
                    elf.SHN_LIVEPATCH => "LIV",
                    else => "UNK",
                };
                break :blk sym_ndx.*;
            } else if (sym.st_shndx == elf.SHN_UNDEF) {
                break :blk "UND";
            }
            break :blk try fmt.allocPrint(self.arena, "{d}", .{sym.st_shndx});
        };
        try writer.print(
            "  {d: >3}: {x:0>16} {d: >5} {s: <7} {s: <6} {s: <8} {s: <5} {s}\n",
            .{ i, sym.st_value, sym.st_size, sym_type, sym_bind, sym_vis, sym_ndx, sym_name_fmt.fmt(sym_name) },
        );
    }
}

fn getShString(self: Elf, off: u32) []const u8 {
    if (self.shstrtab.len == 0) return "<no-strings>";
    assert(off < self.shstrtab.len);
    return mem.sliceTo(@ptrCast([*:0]const u8, self.shstrtab.ptr + off), 0);
}

fn getString(strtab: []const u8, off: u32) []const u8 {
    if (strtab.len == 0) return "<no-strings>";
    assert(off < strtab.len);
    return mem.sliceTo(@ptrCast([*:0]const u8, strtab.ptr + off), 0);
}

inline fn getSectionContents(self: Elf, shdr: elf.Elf64_Shdr) []const u8 {
    return self.data[shdr.sh_offset..][0..shdr.sh_size];
}

fn getSectionContentsByIndex(self: Elf, shdr_index: u32) []const u8 {
    if (self.shdrs.len == 0) return &[0]u8{};
    assert(shdr_index < self.shdrs.len);
    const shdr = self.shdrs[shdr_index];
    return self.getSectionContents(shdr);
}

fn FormatName(comptime max_len: comptime_int) type {
    return struct {
        buffer: [max_len]u8 = undefined,

        fn fmt(this: *@This(), name: []const u8) []const u8 {
            if (name.len <= max_len) return name;
            @memcpy(this.buffer[0 .. max_len - 4], name[0 .. max_len - 4]);
            @memcpy(this.buffer[max_len - 4 ..], "[..]");
            return &this.buffer;
        }
    };
}
