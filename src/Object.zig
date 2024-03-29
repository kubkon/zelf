arena: Allocator,
data: []const u8,
path: []const u8,
opts: @import("main.zig").Options,

header: elf.Elf64_Ehdr = undefined,
shdrs: []align(1) const elf.Elf64_Shdr = &[0]elf.Elf64_Shdr{},
phdrs: []align(1) const elf.Elf64_Phdr = &[0]elf.Elf64_Phdr{},
shstrtab: []const u8 = &[0]u8{},

symtab_index: ?u32 = null,
symtab: []align(1) const elf.Elf64_Sym = &[0]elf.Elf64_Sym{},
strtab: []const u8 = &[0]u8{},

dynamic_index: ?u32 = null,

dynsymtab_index: ?u32 = null,
dynsymtab: []align(1) const elf.Elf64_Sym = &[0]elf.Elf64_Sym{},
dynstrtab: []const u8 = &[0]u8{},

versymtab_index: ?u32 = null,
versymtab: []align(1) const elf.Elf64_Versym = &[0]elf.Elf64_Versym{},

verdef_index: ?u32 = null,
verdefsyms: std.ArrayListUnmanaged(VersionSym(elf.Elf64_Verdef)) = .{},
/// Lookup to verdefsyms.
verdefsyms_lookup: std.AutoHashMapUnmanaged(u32, u32) = .{},
verdefaux: std.ArrayListUnmanaged(VersionSymAux(elf.Elf64_Verdaux)) = .{},

verneed_index: ?u32 = null,
verneedsyms: std.ArrayListUnmanaged(VersionSym(elf.Elf64_Verneed)) = .{},
/// Lookup to verneedaux.
verneedsyms_lookup: std.AutoHashMapUnmanaged(u32, u32) = .{},
verneedaux: std.ArrayListUnmanaged(VersionSymAux(elf.Elf64_Vernaux)) = .{},

pub fn parse(self: *Object) !void {
    var stream = std.io.fixedBufferStream(self.data);
    const reader = stream.reader();

    self.header = try reader.readStruct(elf.Elf64_Ehdr);

    if (!mem.eql(u8, self.header.e_ident[0..4], "\x7fELF")) return error.InvalidMagic;

    self.shdrs = @as([*]align(1) const elf.Elf64_Shdr, @ptrCast(self.data.ptr + self.header.e_shoff))[0..self.header.e_shnum];
    self.phdrs = @as([*]align(1) const elf.Elf64_Phdr, @ptrCast(self.data.ptr + self.header.e_phoff))[0..self.header.e_phnum];
    self.shstrtab = self.getSectionContentsByIndex(self.header.e_shstrndx);

    for (self.shdrs, 0..) |shdr, i| switch (shdr.sh_type) {
        elf.SHT_SYMTAB, elf.SHT_DYNSYM => {
            const raw = self.getSectionContents(shdr);
            const nsyms = @divExact(raw.len, @sizeOf(elf.Elf64_Sym));
            const symtab = @as([*]align(1) const elf.Elf64_Sym, @ptrCast(raw.ptr))[0..nsyms];
            const strtab = self.getSectionContentsByIndex(shdr.sh_link);

            switch (shdr.sh_type) {
                elf.SHT_SYMTAB => {
                    self.symtab_index = @as(u32, @intCast(i));
                    self.symtab = symtab;
                    self.strtab = strtab;
                },
                elf.SHT_DYNSYM => {
                    self.dynsymtab_index = @as(u32, @intCast(i));
                    self.dynsymtab = symtab;
                    self.dynstrtab = strtab;
                },
                else => unreachable,
            }
        },

        elf.SHT_DYNAMIC => {
            self.dynamic_index = @as(u32, @intCast(i));
        },

        elf.SHT_GNU_VERDEF => {
            self.verdef_index = @as(u32, @intCast(i));
        },

        elf.SHT_GNU_VERNEED => {
            self.verneed_index = @as(u32, @intCast(i));
        },

        elf.SHT_GNU_VERSYM => {
            self.versymtab_index = @as(u32, @intCast(i));
            const raw = self.getSectionContents(shdr);
            const nsyms = @divExact(raw.len, @sizeOf(elf.Elf64_Versym));
            self.versymtab = @as([*]align(1) const elf.Elf64_Versym, @ptrCast(raw.ptr))[0..nsyms];
        },

        else => {},
    };

    if (self.verdef_index) |shndx| {
        const shdr = self.shdrs[shndx];
        const raw = self.getSectionContents(shdr);
        const nsyms = @as(u32, @intCast(self.getVerdefNum()));
        try self.verdefsyms.ensureTotalCapacityPrecise(self.arena, nsyms);
        try self.verdefsyms_lookup.ensureTotalCapacity(self.arena, nsyms);

        {
            var i: u32 = 0;
            var offset: u32 = 0;
            while (i < nsyms) : (i += 1) {
                const verdefsym = @as(*align(1) const elf.Elf64_Verdef, @ptrCast(raw.ptr + offset)).*;
                self.verdefsyms.appendAssumeCapacity(.{
                    .sym = verdefsym,
                    .off = offset,
                    .aux = undefined,
                });
                offset += verdefsym.vd_next;
            }
        }

        for (self.verdefsyms.items, 0..) |*verdefsym, i| {
            const aux = @as(u32, @intCast(self.verdefaux.items.len));
            verdefsym.aux = aux;

            self.verdefsyms_lookup.putAssumeCapacityNoClobber(verdefsym.sym.vd_ndx, @as(u32, @intCast(i)));
            try self.verdefaux.ensureUnusedCapacity(self.arena, verdefsym.sym.vd_cnt);

            var j: u32 = 0;
            var offset: u32 = verdefsym.off + verdefsym.sym.vd_aux;
            while (j < verdefsym.sym.vd_cnt) : (j += 1) {
                const verdefaux = @as(*align(1) const elf.Elf64_Verdaux, @ptrCast(raw.ptr + offset)).*;
                self.verdefaux.appendAssumeCapacity(.{ .off = offset, .sym = verdefaux });
                offset += verdefaux.vda_next;
            }
        }
    }

    if (self.verneed_index) |shndx| {
        const shdr = self.shdrs[shndx];
        const raw = self.getSectionContents(shdr);
        const nsyms = @as(u32, @intCast(self.getVerneedNum()));
        try self.verneedsyms.ensureTotalCapacityPrecise(self.arena, nsyms);

        {
            var i: u32 = 0;
            var offset: u32 = 0;
            while (i < nsyms) : (i += 1) {
                const verneedsym = @as(*align(1) const elf.Elf64_Verneed, @ptrCast(raw.ptr + offset)).*;
                self.verneedsyms.appendAssumeCapacity(.{
                    .sym = verneedsym,
                    .off = offset,
                    .aux = undefined,
                });
                offset += verneedsym.vn_next;
            }
        }

        for (self.verneedsyms.items) |*verneedsym| {
            const aux = @as(u32, @intCast(self.verneedaux.items.len));
            verneedsym.aux = aux;

            try self.verneedaux.ensureUnusedCapacity(self.arena, verneedsym.sym.vn_cnt);
            try self.verneedsyms_lookup.ensureUnusedCapacity(self.arena, verneedsym.sym.vn_cnt);

            var i: u32 = 0;
            var offset: u32 = verneedsym.off + verneedsym.sym.vn_aux;
            while (i < verneedsym.sym.vn_cnt) : (i += 1) {
                const verneedaux = @as(*align(1) const elf.Elf64_Vernaux, @ptrCast(raw.ptr + offset)).*;
                self.verneedaux.appendAssumeCapacity(.{ .off = offset, .sym = verneedaux });
                offset += verneedaux.vna_next;
                self.verneedsyms_lookup.putAssumeCapacityNoClobber(verneedaux.vna_other, aux + i);
            }
        }
    }
}

pub fn printHeader(self: Object, writer: anytype) !void {
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
    if (elf.ET.LOPROC <= @intFromEnum(self.header.e_type) and @intFromEnum(self.header.e_type) < elf.ET.HIPROC) {
        try writer.print("  {s: <34} {s}+{x} (Processor-specific)\n", .{
            "Type:",
            "LOPROC",
            @intFromEnum(self.header.e_type),
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
        .AARCH64 => "Aarch64",
        .RISCV => "RISC-V",
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

pub fn printShdrs(self: Object, writer: anytype) !void {
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

    var sh_name_fmt = FormatName(max_name_len){ .wide = self.opts.wide };

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
            0x6ffffff6 => "GNU_HASH", // SHT_GNU_HASH
            0x6ffffffd => "VERDEF", // SHT_GNU_verdef
            0x6ffffffe => "VERNEED", // SHT_GNU_verneed
            0x6fffffff => "VERSYM", // SHT_GNU_versym
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

pub fn printPhdrs(self: Object, writer: anytype) !void {
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

pub fn printRelocs(self: Object, writer: anytype) !void {
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
        const relocs = @as([*]align(1) const elf.Elf64_Rela, @ptrCast(raw.ptr))[0..nrelocs];

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
                fmtRelocType(reloc.r_type(), self),
                sym.st_value,
                sym_name,
            });
            if (reloc.r_addend >= 0) {
                try writer.print("+ {x}", .{reloc.r_addend});
            } else {
                try writer.print("- {x}", .{@abs(reloc.r_addend)});
            }
            try writer.writeByte('\n');
        }

        if (i != last_shndx) try writer.writeByte('\n');
    }
}

const FmtRelocTypeCtx = struct {
    r_type: u32,
    object: Object,
};

fn fmtRelocType(r_type: u32, object: Object) std.fmt.Formatter(formatRelocType) {
    return .{ .data = .{
        .r_type = r_type,
        .object = object,
    } };
}

fn formatRelocType(
    ctx: FmtRelocTypeCtx,
    comptime unused_fmt_string: []const u8,
    options: std.fmt.FormatOptions,
    writer: anytype,
) !void {
    _ = unused_fmt_string;
    const r_type = ctx.r_type;
    const object = ctx.object;
    const prefix = switch (object.header.e_machine) {
        .X86_64 => "R_X86_64_",
        .AARCH64 => "R_AARCH64_",
        .RISCV => "R_RISCV_",
        else => unreachable,
    };
    const suffix = switch (object.header.e_machine) {
        .X86_64 => @tagName(@as(elf.R_X86_64, @enumFromInt(r_type))),
        .AARCH64 => @tagName(@as(elf.R_AARCH64, @enumFromInt(r_type))),
        .RISCV => @tagName(@as(elf.R_RISCV, @enumFromInt(r_type))),
        else => unreachable,
    };
    const width = options.width orelse return writer.print("{s}{s}", .{ prefix, suffix });
    if (object.opts.wide) {
        return writer.print("{s}{s}", .{ prefix, suffix });
    }
    const total_len = prefix.len + suffix.len;
    if (total_len > width) {
        try writer.print("{s}{s}", .{ prefix, suffix[0 .. width - prefix.len] });
    } else {
        try writer.print("{s}{s}", .{ prefix, suffix });
        const padding = width - total_len;
        if (padding > 0) {
            // TODO I have no idea what I'm doing here!
            var fill_buffer: [4]u8 = undefined;
            const fill = if (std.unicode.utf8Encode(options.fill, &fill_buffer)) |l|
                fill_buffer[0..l]
            else |_|
                @panic("impossible to apply fmt fill!");
            try writer.writeBytesNTimes(fill, padding);
        }
    }
}

pub fn printSymbolTable(self: Object, writer: anytype) !void {
    const ndx = self.symtab_index orelse
        return writer.print("There is no symbol table in this file.", .{});
    try self.printSymtab(ndx, self.symtab, self.strtab, writer);
}

pub fn printDynamicSymbolTable(self: Object, writer: anytype) !void {
    const ndx = self.dynsymtab_index orelse
        return writer.print("There is no dynamic symbol table in this file.", .{});
    try self.printSymtab(ndx, self.dynsymtab, self.dynstrtab, writer);
}

fn printSymtab(
    self: Object,
    shdr_ndx: u32,
    symtab: []align(1) const elf.Elf64_Sym,
    strtab: []align(1) const u8,
    writer: anytype,
) !void {
    const shdr = self.shdrs[shdr_ndx];
    const is_dynsym = shdr.sh_type == elf.SHT_DYNSYM;

    try writer.print("Symbol table '{s}' contains {d} entries:\n", .{
        self.getShString(shdr.sh_name),
        symtab.len,
    });
    try writer.print(
        "  Num:{s: <12}Value{s: <2}Size Type{s: <3} Bind{s: <2} Vis{s: <5} Ndx{s: <2} Name\n",
        .{ "", "", "", "", "", "" },
    );

    var sym_name_fmt = FormatName(max_name_len){ .wide = self.opts.wide };

    for (symtab, 0..) |sym, i| {
        const sym_name = blk: {
            switch (sym.st_type()) {
                elf.STT_SECTION => {
                    const sym_shdr = self.shdrs[sym.st_shndx];
                    break :blk self.getShString(sym_shdr.sh_name);
                },
                else => {
                    const base_name = getString(strtab, sym.st_name);
                    if (is_dynsym and self.versymtab_index != null) {
                        const versym = self.versymtab[@as(u32, @intCast(i))] & elf.VERSYM_VERSION;
                        if (self.verdefsyms_lookup.get(versym)) |verdef_index| {
                            const verdef = self.verdefsyms.items[verdef_index];
                            const verdaux = self.verdefaux.items[verdef.aux];
                            break :blk try std.fmt.allocPrint(self.arena, "{s}@{s} ({d})", .{
                                base_name,
                                getString(strtab, verdaux.sym.vda_name),
                                versym,
                            });
                        }
                        if (self.verneedsyms_lookup.get(versym)) |verneed_index| {
                            const vernaux = self.verneedaux.items[verneed_index];
                            break :blk try std.fmt.allocPrint(self.arena, "{s}@{s} ({d})", .{
                                base_name,
                                getString(strtab, vernaux.sym.vna_name),
                                versym,
                            });
                        }
                    }
                    break :blk base_name;
                },
            }
        };
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
        const sym_vis = @as(elf.STV, @enumFromInt(sym.st_other));
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
            .{ i, sym.st_value, sym.st_size, sym_type, sym_bind, @tagName(sym_vis), sym_ndx, sym_name_fmt.fmt(sym_name) },
        );
    }
}

pub fn printDynamicSection(self: Object, writer: anytype) !void {
    const shdr = self.getShdrByType(elf.SHT_DYNAMIC) orelse
        return writer.writeAll("There is no dynamic section in this file.");
    const data = self.getSectionContents(shdr);
    const nentries = @divExact(data.len, @sizeOf(elf.Elf64_Dyn));
    const entries = @as([*]align(1) const elf.Elf64_Dyn, @ptrCast(data.ptr))[0..nentries];

    try writer.print(" {s:<18} {s:<24} {s}\n", .{ "Tag", "Type", "Name/Value" });

    for (entries) |entry| {
        const key = @as(u64, @bitCast(entry.d_tag));
        const value = entry.d_val;

        try writer.print("0x{x:0>16} {s:<22}", .{ key, fmtDynamicSectionType(key) });

        switch (key) {
            elf.DT_NEEDED,
            elf.DT_SONAME,
            elf.DT_RPATH,
            elf.DT_RUNPATH,
            => {
                const name = getString(self.dynstrtab, @as(u32, @intCast(value)));
                switch (key) {
                    elf.DT_NEEDED => try writer.writeAll(" Shared library: "),
                    elf.DT_SONAME => try writer.writeAll(" Library soname: "),
                    elf.DT_RPATH => try writer.writeAll(" Library rpath: "),
                    elf.DT_RUNPATH => try writer.writeAll(" Library runpath: "),
                    else => unreachable,
                }
                try writer.print("[{s}]", .{name});
            },

            elf.DT_INIT_ARRAY,
            elf.DT_FINI_ARRAY,
            elf.DT_HASH,
            elf.DT_GNU_HASH,
            elf.DT_STRTAB,
            elf.DT_SYMTAB,
            elf.DT_PLTGOT,
            elf.DT_JMPREL,
            elf.DT_RELA,
            elf.DT_VERDEF,
            elf.DT_VERNEED,
            elf.DT_VERSYM,
            elf.DT_INIT,
            elf.DT_FINI,
            elf.DT_NULL,
            => try writer.print(" 0x{x}", .{value}),

            elf.DT_INIT_ARRAYSZ,
            elf.DT_FINI_ARRAYSZ,
            elf.DT_STRSZ,
            elf.DT_SYMENT,
            elf.DT_PLTRELSZ,
            elf.DT_RELASZ,
            elf.DT_RELAENT,
            => try writer.print(" {d} (bytes)", .{value}),

            elf.DT_PLTREL => try writer.print(" {s}", .{fmtDynamicSectionType(value)}),

            elf.DT_FLAGS => if (value > 0) {
                if (value & elf.DF_ORIGIN != 0) try writer.writeAll(" ORIGIN");
                if (value & elf.DF_SYMBOLIC != 0) try writer.writeAll(" SYMBOLIC");
                if (value & elf.DF_TEXTREL != 0) try writer.writeAll(" TEXTREL");
                if (value & elf.DF_BIND_NOW != 0) try writer.writeAll(" BIND_NOW");
                if (value & elf.DF_STATIC_TLS != 0) try writer.writeAll(" STATIC_TLS");
            } else try writer.print(" {x}", .{value}),

            elf.DT_FLAGS_1 => if (value > 0) {
                try writer.writeAll(" Flags:");
                if (value & elf.DF_1_NOW != 0) try writer.writeAll(" NOW");
                if (value & elf.DF_1_GLOBAL != 0) try writer.writeAll(" GLOBAL");
                if (value & elf.DF_1_GROUP != 0) try writer.writeAll(" GROUP");
                if (value & elf.DF_1_NODELETE != 0) try writer.writeAll(" NODELETE");
                if (value & elf.DF_1_LOADFLTR != 0) try writer.writeAll(" LOADFLTR");
                if (value & elf.DF_1_INITFIRST != 0) try writer.writeAll(" INITFIRST");
                if (value & elf.DF_1_NOOPEN != 0) try writer.writeAll(" NOOPEN");
                if (value & elf.DF_1_ORIGIN != 0) try writer.writeAll(" ORIGIN");
                if (value & elf.DF_1_DIRECT != 0) try writer.writeAll(" DIRECT");
                if (value & elf.DF_1_TRANS != 0) try writer.writeAll(" TRANS");
                if (value & elf.DF_1_INTERPOSE != 0) try writer.writeAll(" INTERPOSE");
                if (value & elf.DF_1_NODEFLIB != 0) try writer.writeAll(" NODEFLIB");
                if (value & elf.DF_1_NODUMP != 0) try writer.writeAll(" NODUMP");
                if (value & elf.DF_1_CONFALT != 0) try writer.writeAll(" CONFALT");
                if (value & elf.DF_1_ENDFILTEE != 0) try writer.writeAll(" ENDFILTEE");
                if (value & elf.DF_1_DISPRELDNE != 0) try writer.writeAll(" DISPRELDNE");
                if (value & elf.DF_1_DISPRELPND != 0) try writer.writeAll(" DISPRELPND");
                if (value & elf.DF_1_NODIRECT != 0) try writer.writeAll(" NODIRECT");
                if (value & elf.DF_1_IGNMULDEF != 0) try writer.writeAll(" IGNMULDEF");
                if (value & elf.DF_1_NOKSYMS != 0) try writer.writeAll(" NOKSYMS");
                if (value & elf.DF_1_NOHDR != 0) try writer.writeAll(" NOHDR");
                if (value & elf.DF_1_EDITED != 0) try writer.writeAll(" EDITED");
                if (value & elf.DF_1_NORELOC != 0) try writer.writeAll(" NORELOC");
                if (value & elf.DF_1_SYMINTPOSE != 0) try writer.writeAll(" SYMINTPOSE");
                if (value & elf.DF_1_GLOBAUDIT != 0) try writer.writeAll(" GLOBAUDIT");
                if (value & elf.DF_1_SINGLETON != 0) try writer.writeAll(" SINGLETON");
                if (value & elf.DF_1_STUB != 0) try writer.writeAll(" STUB");
                if (value & elf.DF_1_PIE != 0) try writer.writeAll(" PIE");
            } else try writer.print(" {x}", .{value}),

            elf.DT_RELACOUNT => try writer.print(" {d}", .{value}),

            else => try writer.print(" {x}", .{value}),
        }

        try writer.writeByte('\n');
    }
}

fn fmtDynamicSectionType(@"type": u64) std.fmt.Formatter(formatDynamicSectionType) {
    return .{ .data = @"type" };
}

fn formatDynamicSectionType(
    @"type": u64,
    comptime unused_fmt_string: []const u8,
    options: std.fmt.FormatOptions,
    writer: anytype,
) !void {
    _ = unused_fmt_string;
    const str = switch (@"type") {
        elf.DT_NEEDED => "NEEDED",
        elf.DT_SONAME => "SONAME",
        elf.DT_INIT_ARRAY => "INIT_ARRAY",
        elf.DT_INIT_ARRAYSZ => "INIT_ARRAYSZ",
        elf.DT_FINI_ARRAY => "FINI_ARRAY",
        elf.DT_FINI_ARRAYSZ => "FINI_ARRAYSZ",
        elf.DT_HASH => "HASH",
        elf.DT_GNU_HASH => "GNU_HASH",
        elf.DT_STRTAB => "STRTAB",
        elf.DT_SYMTAB => "SYMTAB",
        elf.DT_STRSZ => "STRSZ",
        elf.DT_SYMENT => "SYMENT",
        elf.DT_PLTGOT => "PLTGOT",
        elf.DT_PLTRELSZ => "PLTRELSZ",
        elf.DT_PLTREL => "PLTREL",
        elf.DT_JMPREL => "JMPREL",
        elf.DT_RELA => "RELA",
        elf.DT_RELASZ => "RELASZ",
        elf.DT_RELAENT => "RELAENT",
        elf.DT_VERDEF => "VERDEF",
        elf.DT_VERDEFNUM => "VERDEFNUM",
        elf.DT_FLAGS => "FLAGS",
        elf.DT_FLAGS_1 => "FLAGS_1",
        elf.DT_VERNEED => "VERNEED",
        elf.DT_VERNEEDNUM => "VERNEEDNUM",
        elf.DT_VERSYM => "VERSYM",
        elf.DT_RELACOUNT => "RELACOUNT",
        elf.DT_RPATH => "RPATH",
        elf.DT_RUNPATH => "RUNPATH",
        elf.DT_INIT => "INIT",
        elf.DT_FINI => "FINI",
        elf.DT_NULL => "NULL",
        else => "UNKNOWN",
    };
    try writer.print("{s}", .{str});
    if (options.width) |width| {
        if (str.len > width) return error.NoSpaceLeft; // TODO how should we actually handle this here?
        const padding = width - str.len;
        if (padding > 0) {
            // TODO I have no idea what I'm doing here!
            var fill_buffer: [4]u8 = undefined;
            const fill = if (std.unicode.utf8Encode(options.fill, &fill_buffer)) |l|
                fill_buffer[0..l]
            else |_|
                @panic("impossible to apply fmt fill!");
            try writer.writeBytesNTimes(fill, padding);
        }
    }
}

pub fn printInitializers(self: Object, writer: anytype) !void {
    var no_inits = true;
    for (self.shdrs) |shdr| switch (shdr.sh_type) {
        elf.SHT_INIT_ARRAY, elf.SHT_FINI_ARRAY, elf.SHT_PREINIT_ARRAY => {
            try writer.print("{s}:\n", .{self.getShString(shdr.sh_name)});
            const entry_size = shdr.sh_entsize;
            const entries = self.getSectionContents(shdr);
            const nentries = @divExact(shdr.sh_size, entry_size);
            var ientry: usize = 0;
            while (ientry < nentries) : (ientry += 1) {
                const off = ientry * entry_size;
                const entry = entries[off..][0..entry_size];
                const value = switch (entry_size) {
                    4 => mem.readInt(u32, entry[0..4], .little),
                    8 => mem.readInt(u64, entry[0..8], .little),
                    else => unreachable,
                };
                const sym_index = self.findSymbolByAddress(value).?;
                const name = getString(self.strtab, self.symtab[sym_index].st_name);
                try writer.print("  {x:0>16}: {x:0>16}    {s}\n", .{ shdr.sh_addr + off, value, name });
            }
            no_inits = false;
        },
        else => {},
    };

    if (no_inits) {
        try writer.writeAll("There is no .init_array, .fini_array or .preinit_array section in this file.");
    }
}

pub fn printVersionSections(self: Object, writer: anytype) !void {
    if (self.versymtab_index == null) {
        return writer.writeAll("There are no version sections in this file.");
    }

    if (self.versymtab_index) |shndx| {
        const shdr = self.shdrs[shndx];
        try writer.print("Version symbols section '{s}' contains {d} entries:\n", .{
            self.getShString(shdr.sh_name),
            self.versymtab.len,
        });
        try writer.print(" Addr: 0x{x:0>16}  Offset: 0x{x:0>8}  Link: {d} ({s})\n", .{
            shdr.sh_addr,
            shdr.sh_offset,
            shdr.sh_link,
            self.getShString(self.shdrs[shdr.sh_link].sh_name),
        });

        var count: usize = 0;
        while (count < self.versymtab.len) : (count += 4) {
            const remaining = self.versymtab[count..];
            const num = @min(remaining.len, 4);

            try writer.print("  {x:0>4}", .{count});

            for (remaining[0..num]) |versym| {
                const actual_versym = versym & elf.VERSYM_VERSION;
                const name = switch (actual_versym) {
                    elf.VER_NDX_LOCAL => "*local*",
                    elf.VER_NDX_GLOBAL => "*global*",
                    else => blk: {
                        if (self.verdefsyms_lookup.get(actual_versym)) |verdef_index| {
                            const verdef = self.verdefsyms.items[verdef_index];
                            const verauxs = self.verdefaux.items[verdef.aux..][0..verdef.sym.vd_cnt];
                            break :blk getString(self.dynstrtab, verauxs[0].sym.vda_name);
                        }
                        if (self.verneedsyms_lookup.get(actual_versym)) |vernaux_index| {
                            const vernaux = self.verneedaux.items[vernaux_index];
                            break :blk getString(self.dynstrtab, vernaux.sym.vna_name);
                        }
                        break :blk try std.fmt.allocPrint(self.arena, "unknown({d})", .{actual_versym});
                    },
                };
                const hidden = versym & elf.VERSYM_HIDDEN != 0;
                try writer.print(" {d: >4}{s}({s})", .{ actual_versym, if (hidden) "h" else " ", name });
            }

            try writer.writeByte('\n');
        }
        try writer.writeByte('\n');
    }

    if (self.verdef_index) |shndx| {
        const shdr = self.shdrs[shndx];
        try writer.print("Version definition section '{s}' contains {d} entries:\n", .{
            self.getShString(shdr.sh_name),
            self.verdefsyms.items.len,
        });
        try writer.print(" Addr: 0x{x:0>16}  Offset: 0x{x:0>8}  Link: {d} ({s})\n", .{
            shdr.sh_addr,
            shdr.sh_offset,
            shdr.sh_link,
            self.getShString(self.shdrs[shdr.sh_link].sh_name),
        });

        for (self.verdefsyms.items) |verdef| {
            const verauxs = self.verdefaux.items[verdef.aux..][0..verdef.sym.vd_cnt];
            try writer.print("  0x{x:0>8}: Rev: {d}  Flags: {s}  Index: {d: >2}  Cnt: {d: >2}  Name: {s}\n", .{
                verdef.off,
                verdef.sym.vd_version,
                switch (verdef.sym.vd_flags) {
                    0 => "none",
                    elf.VER_FLG_BASE => "BASE",
                    elf.VER_FLG_WEAK => "WEAK",
                    else => "unknown",
                },
                verdef.sym.vd_ndx,
                verdef.sym.vd_cnt,
                getString(self.dynstrtab, verauxs[0].sym.vda_name),
            });

            for (verauxs[1..], 1..) |veraux, i| {
                try writer.print("  0x{x:0>8}: Parent {d}: {s}\n", .{
                    veraux.off,
                    i,
                    getString(self.dynstrtab, veraux.sym.vda_name),
                });
            }
        }

        try writer.writeByte('\n');
    }

    if (self.verneed_index) |shndx| {
        const shdr = self.shdrs[shndx];
        try writer.print("Version needs section '{s}' contains {d} entries:\n", .{
            self.getShString(shdr.sh_name),
            self.verneedsyms.items.len,
        });
        try writer.print(" Addr: 0x{x:0>16}  Offset: 0x{x:0>8}  Link: {d} ({s})\n", .{
            shdr.sh_addr,
            shdr.sh_offset,
            shdr.sh_link,
            self.getShString(self.shdrs[shdr.sh_link].sh_name),
        });

        for (self.verneedsyms.items) |verneed| {
            const verauxs = self.verneedaux.items[verneed.aux..][0..verneed.sym.vn_cnt];
            try writer.print("  0x{x:0>8}: Version: {d}  File: {s}  Cnt: {d}\n", .{
                verneed.off,
                verneed.sym.vn_version,
                getString(self.dynstrtab, verneed.sym.vn_file),
                verneed.sym.vn_cnt,
            });

            for (verauxs) |veraux| {
                try writer.print("  0x{x:0>8}:   Name: {s}  Flags: {s}  Version: {d}\n", .{
                    veraux.off,
                    getString(self.dynstrtab, veraux.sym.vna_name),
                    switch (veraux.sym.vna_flags) {
                        0 => "none",
                        elf.VER_FLG_BASE => "BASE",
                        elf.VER_FLG_WEAK => "WEAK",
                        else => "unknown",
                    },
                    veraux.sym.vna_other,
                });
            }
        }
    }
}

fn getDynamicTable(self: Object) []align(1) const elf.Elf64_Dyn {
    const shndx = self.dynamic_index orelse return &[0]elf.Elf64_Dyn{};
    const raw = self.getSectionContentsByIndex(shndx);
    const num = @divExact(raw.len, @sizeOf(elf.Elf64_Dyn));
    return @as([*]align(1) const elf.Elf64_Dyn, @ptrCast(raw.ptr))[0..num];
}

fn getVerdefNum(self: Object) u64 {
    const dynamic = self.getDynamicTable();
    for (dynamic) |entry| switch (entry.d_tag) {
        elf.DT_VERDEFNUM => return entry.d_val,
        else => {},
    };
    return 0;
}

fn getVerneedNum(self: Object) u64 {
    const dynamic = self.getDynamicTable();
    for (dynamic) |entry| switch (entry.d_tag) {
        elf.DT_VERNEEDNUM => return entry.d_val,
        else => {},
    };
    return 0;
}

fn findSymbolByAddress(self: Object, addr: u64) ?u32 {
    for (self.symtab, 0..) |sym, idx| {
        if (sym.st_value <= addr and addr < sym.st_value + sym.st_size) return @as(u32, @intCast(idx));
    }
    return null;
}

fn getShdrByType(self: Object, sh_type: u32) ?elf.Elf64_Shdr {
    for (self.shdrs) |shdr| if (shdr.sh_type == sh_type) {
        return shdr;
    };
    return null;
}

fn getShString(self: Object, off: u32) []const u8 {
    if (self.shstrtab.len == 0) return "<no-strings>";
    assert(off < self.shstrtab.len);
    return mem.sliceTo(@as([*:0]const u8, @ptrCast(self.shstrtab.ptr + off)), 0);
}

fn getString(strtab: []const u8, off: u32) []const u8 {
    if (strtab.len == 0) return "<no-strings>";
    assert(off < strtab.len);
    return mem.sliceTo(@as([*:0]const u8, @ptrCast(strtab.ptr + off)), 0);
}

inline fn getSectionContents(self: Object, shdr: elf.Elf64_Shdr) []const u8 {
    return self.data[shdr.sh_offset..][0..shdr.sh_size];
}

fn getSectionContentsByIndex(self: Object, shdr_index: u32) []const u8 {
    if (self.shdrs.len == 0) return &[0]u8{};
    assert(shdr_index < self.shdrs.len);
    const shdr = self.shdrs[shdr_index];
    return self.getSectionContents(shdr);
}

const max_name_len = 16;

fn FormatName(comptime max_len: comptime_int) type {
    return struct {
        buffer: [max_len]u8 = undefined,
        wide: bool = false,

        fn fmt(this: *@This(), name: []const u8) []const u8 {
            if (this.wide) return name;
            if (name.len <= max_len) return name;
            @memcpy(this.buffer[0 .. max_len - 4], name[0 .. max_len - 4]);
            @memcpy(this.buffer[max_len - 4 ..], "[..]");
            return &this.buffer;
        }
    };
}

fn VersionSym(comptime Inner: type) type {
    return struct {
        sym: Inner,
        off: u32,
        aux: u32,
    };
}

fn VersionSymAux(comptime Inner: type) type {
    return struct {
        sym: Inner,
        off: u32,
    };
}

const Object = @This();

const std = @import("std");
const assert = std.debug.assert;
const elf = std.elf;
const fmt = std.fmt;
const fs = std.fs;
const mem = std.mem;

const Allocator = mem.Allocator;
