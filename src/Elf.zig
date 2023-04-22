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

gpa: Allocator,
file: fs.File,

header: elf.Header = undefined,
shdrs: std.ArrayListUnmanaged(elf.Elf64_Shdr) = .{},
phdrs: std.ArrayListUnmanaged(elf.Elf64_Phdr) = .{},
shstrtab: std.ArrayListUnmanaged(u8) = .{},

symtab: std.ArrayListUnmanaged(elf.Elf64_Sym) = .{},
strtab: std.ArrayListUnmanaged(u8) = .{},

dynsymtab: std.ArrayListUnmanaged(elf.Elf64_Sym) = .{},
dynstrtab: std.ArrayListUnmanaged(u8) = .{},

symtab_index: ?u16 = null,
strtab_index: ?u16 = null,
dynsymtab_index: ?u16 = null,
dynstrtab_index: ?u16 = null,

pub fn init(gpa: Allocator, file: fs.File) Elf {
    return .{
        .gpa = gpa,
        .file = file,
    };
}

pub fn deinit(self: *Elf) void {
    self.shdrs.deinit(self.gpa);
    self.phdrs.deinit(self.gpa);
    self.shstrtab.deinit(self.gpa);
    self.symtab.deinit(self.gpa);
    self.strtab.deinit(self.gpa);
    self.dynsymtab.deinit(self.gpa);
    self.dynstrtab.deinit(self.gpa);
}

pub fn parseMetadata(self: *Elf) !void {
    self.header = try elf.Header.read(self.file);

    // Parse section headers
    {
        try self.shdrs.ensureTotalCapacity(self.gpa, self.header.shnum);
        var it = self.header.section_header_iterator(self.file);
        var ndx: u16 = 0;
        while (try it.next()) |shdr| {
            switch (shdr.sh_type) {
                elf.SHT_SYMTAB => {
                    if (self.symtab_index != null) {
                        // According to the UNIX System V release 4, there can only be one symtab per ELF file.
                        log.err("Two symtabs detected in one file", .{});
                        return error.MultipleSymtabs;
                    }
                    self.symtab_index = ndx;
                },
                elf.SHT_DYNSYM => {
                    if (self.dynsymtab_index != null) {
                        // According to the UNIX System V release 4, there can only be one dynsym per ELF file.
                        log.err("Two dynsyms detected in one file", .{});
                        return error.MultipleDynsyms;
                    }
                    self.dynsymtab_index = ndx;
                },
                else => {},
            }
            self.shdrs.appendAssumeCapacity(shdr);
            ndx += 1;
        }
    }

    // Parse program headers
    {
        try self.phdrs.ensureTotalCapacity(self.gpa, self.header.phnum);
        var it = self.header.program_header_iterator(self.file);
        while (try it.next()) |phdr| {
            self.phdrs.appendAssumeCapacity(phdr);
        }
    }

    // Parse shstrtab
    {
        var buffer = try self.readShdrContents(self.header.shstrndx);
        defer self.gpa.free(buffer);
        try self.shstrtab.appendSlice(self.gpa, buffer);
    }

    // Parse symtab and matching strtab
    if (self.symtab_index) |ndx| {
        const shdr = self.shdrs.items[ndx];

        var raw_symtab = try self.readShdrContents(ndx);
        defer self.gpa.free(raw_symtab);

        // TODO non-native endianness
        if (self.header.is_64) {
            const syms = @alignCast(@alignOf(elf.Elf64_Sym), mem.bytesAsSlice(elf.Elf64_Sym, raw_symtab));
            try self.symtab.appendSlice(self.gpa, syms);
        } else {
            const nsyms = @divExact(shdr.sh_size, shdr.sh_entsize);
            try self.symtab.ensureUnusedCapacity(self.gpa, nsyms);
            const syms = @alignCast(@alignOf(elf.Elf32_Sym), mem.bytesAsSlice(elf.Elf32_Sym, raw_symtab));
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

        self.strtab_index = @intCast(u16, shdr.sh_link);
        var raw_strtab = try self.readShdrContents(shdr.sh_link);
        defer self.gpa.free(raw_strtab);
        try self.strtab.appendSlice(self.gpa, raw_strtab);
    }

    // Parse dynsymtab and matching dynstrtab
    if (self.dynsymtab_index) |ndx| {
        const shdr = self.shdrs.items[ndx];

        var raw_dynsym = try self.readShdrContents(ndx);
        defer self.gpa.free(raw_dynsym);

        // TODO non-native endianness
        if (self.header.is_64) {
            const syms = @alignCast(@alignOf(elf.Elf64_Sym), mem.bytesAsSlice(elf.Elf64_Sym, raw_dynsym));
            try self.dynsymtab.appendSlice(self.gpa, syms);
        } else {
            const nsyms = @divExact(shdr.sh_size, shdr.sh_entsize);
            try self.dynsymtab.ensureUnusedCapacity(self.gpa, nsyms);
            const syms = @alignCast(@alignOf(elf.Elf32_Sym), mem.bytesAsSlice(elf.Elf32_Sym, raw_dynsym));
            for (syms) |sym| {
                self.dynsymtab.appendAssumeCapacity(.{
                    .st_name = sym.st_name,
                    .st_info = sym.st_info,
                    .st_other = sym.st_other,
                    .st_shndx = sym.st_shndx,
                    .st_value = sym.st_value,
                    .st_size = sym.st_size,
                });
            }
        }

        self.dynstrtab_index = @intCast(u16, shdr.sh_link);
        var raw_strtab = try self.readShdrContents(shdr.sh_link);
        defer self.gpa.free(raw_strtab);
        try self.dynstrtab.appendSlice(self.gpa, raw_strtab);
    }
}

pub fn printHeader(self: Elf, writer: anytype) !void {
    try writer.print("ELF Header:\n", .{});
    try writer.print("  Endianness: {s}\n", .{@tagName(self.header.endian)});
    try writer.print("  Machine: {s}\n", .{switch (self.header.machine) {
        .NONE => "none",
        .M32 => "AT&T WE 32100",
        .AARCH64 => "ARM Aarch64",
        .X86_64 => "AMD x86-64 architecture",
        else => "unknown",
    }});
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

    var arena_allocator = std.heap.ArenaAllocator.init(self.gpa);
    defer arena_allocator.deinit();
    const arena = arena_allocator.allocator();

    for (self.shdrs.items, 0..) |shdr, i| {
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
            else => |sht| blk: {
                if (elf.SHT_LOOS <= sht and sht < elf.SHT_HIOS) {
                    break :blk try fmt.allocPrint(arena, "LOOS+0x{x}", .{sht - elf.SHT_LOOS});
                }
                if (elf.SHT_LOPROC <= sht and sht < elf.SHT_HIPROC) {
                    break :blk try fmt.allocPrint(arena, "LOPROC+0x{x}", .{sht - elf.SHT_LOPROC});
                }
                if (elf.SHT_LOUSER <= sht and sht < elf.SHT_HIUSER) {
                    break :blk try fmt.allocPrint(arena, "LOUSER+0x{x}", .{sht - elf.SHT_LOUSER});
                }
                break :blk "UNKNOWN";
            },
        };
        const flags = blk: {
            var flags = std.ArrayList(u8).init(arena);
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
            break :blk try flags.toOwnedSlice();
        };
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

pub fn printPhdrs(self: Elf, writer: anytype) !void {
    if (self.phdrs.items.len == 0) {
        try writer.print("There are no program headers in this file.\n", .{});
        return;
    }

    try writer.print("Entry point 0x{x}\n", .{self.header.entry});
    try writer.print("There are {d} program headers, starting at offset {d}\n\n", .{
        self.phdrs.items.len,
        self.header.phoff,
    });
    try writer.print("Program Headers:\n", .{});
    try writer.print("  Type{s: <12} Offset{s: <10} VirtAddr{s: <8} PhysAddr{s: <8}\n", .{ "", "", "", "" });
    try writer.print("  {s: <16} FileSiz{s: <9} MemSiz{s: <10} Flags  Align\n", .{ "", "", "" });

    var arena_allocator = std.heap.ArenaAllocator.init(self.gpa);
    defer arena_allocator.deinit();
    const arena = arena_allocator.allocator();

    var section_to_segment = try arena.alloc(std.ArrayList(usize), self.phdrs.items.len);
    for (self.phdrs.items, 0..) |_, i| {
        section_to_segment[i] = std.ArrayList(usize).init(arena);
    }

    for (self.phdrs.items, 0..) |phdr, i| {
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
                    break :blk try fmt.allocPrint(arena, "LOOS+0x{x}", .{pt - elf.PT_LOOS});
                }
                if (elf.PT_LOPROC <= pt and pt < elf.PT_HIPROC) {
                    break :blk try fmt.allocPrint(arena, "LOPROC+0x{x}", .{pt - elf.PT_LOPROC});
                }
                break :blk "UNKNOWN";
            },
        };
        const p_flags = blk: {
            var p_flags = std.ArrayList(u8).init(arena);
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
        for (self.shdrs.items, 0..) |shdr, j| {
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
            const shdr = self.shdrs.items[shdr_ndx];
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
    var has_relocs = false;
    for (self.shdrs.items, 0..) |shdr, i| {
        switch (shdr.sh_type) {
            elf.SHT_REL, elf.SHT_RELA => {},
            else => continue,
        }

        has_relocs = true;

        var buffer = try self.readShdrContents(@intCast(u16, i));
        defer self.gpa.free(buffer);

        const nrelocs = @divExact(shdr.sh_size, shdr.sh_entsize);
        var relocs = try self.gpa.alloc(elf.Elf64_Rela, nrelocs);
        defer self.gpa.free(relocs);

        if (self.header.is_64) {
            // TODO non-native endianness
            if (shdr.sh_type == elf.SHT_REL) {
                var code = try self.readShdrContents(shdr.sh_info);
                defer self.gpa.free(code);

                const slice = @alignCast(@alignOf(elf.Elf64_Rel), mem.bytesAsSlice(elf.Elf64_Rel, buffer));
                // Parse relocs addend from inst and convert into Elf64_Rela
                for (slice, 0..) |rel, rel_i| {
                    var out_rel = elf.Elf64_Rela{
                        .r_offset = rel.r_offset,
                        .r_info = rel.r_info,
                        .r_addend = 0,
                    };
                    const r_addend: i64 = addend: {
                        switch (out_rel.r_type()) {
                            elf.R_X86_64_64 => {
                                const in_inst = code[out_rel.r_offset..][0..8];
                                break :addend mem.readIntSliceLittle(i64, in_inst);
                            },
                            elf.R_X86_64_32 => {
                                const in_inst = code[out_rel.r_offset..][0..4];
                                break :addend mem.readIntSliceLittle(i32, in_inst);
                            },
                            else => break :addend 0, // TODO
                        }
                    };
                    out_rel.r_addend = r_addend;
                    relocs[rel_i] = out_rel;
                }
            } else {
                const slice = @alignCast(@alignOf(elf.Elf64_Rela), mem.bytesAsSlice(elf.Elf64_Rela, buffer));
                mem.copy(elf.Elf64_Rela, relocs, slice);
            }
        } else {
            // TODO non-native endianness
            if (shdr.sh_type == elf.SHT_REL) {
                _ = @alignCast(@alignOf(elf.Elf32_Rel), mem.bytesAsSlice(elf.Elf32_Rel, buffer));
            } else {
                _ = @alignCast(@alignOf(elf.Elf32_Rela), mem.bytesAsSlice(elf.Elf32_Rela, buffer));
            }
        }

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
            const r_sym = reloc.r_info >> 32;
            var sym: elf.Elf64_Sym = undefined;
            var sym_name: []const u8 = undefined;
            if (self.symtab_index != null and shdr.sh_link == self.symtab_index.?) {
                sym = self.symtab.items[r_sym];
                sym_name = getString(self.strtab.items, sym.st_name);
            } else if (self.dynsymtab_index != null and shdr.sh_link == self.dynsymtab_index.?) {
                sym = self.dynsymtab.items[r_sym];
                sym_name = getString(self.dynstrtab.items, sym.st_name);
            } else unreachable;
            const r_type = @truncate(u32, reloc.r_info);
            const rel_type = switch (r_type) {
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
                rel_type,
                sym.st_value,
                sym_name,
                reloc.r_addend,
            });
        }
        try writer.print("\n", .{});
    }

    if (!has_relocs) {
        try writer.print("There is no relocation info in this file.\n", .{});
    }
}

pub fn printSymtabs(self: Elf, writer: anytype) !void {
    if (self.symtab_index == null and self.dynsymtab_index == null) {
        try writer.print("There is no symbol table in this file.", .{});
        return;
    }
    if (self.symtab_index) |ndx| {
        try self.printSymtab(ndx, self.symtab.items, self.strtab.items, writer);
        try writer.print("\n", .{});
    }
    if (self.dynsymtab_index) |ndx| {
        try self.printSymtab(ndx, self.dynsymtab.items, self.dynstrtab.items, writer);
        try writer.print("\n", .{});
    }
}

fn printSymtab(self: Elf, shdr_ndx: u16, symtab: []const elf.Elf64_Sym, strtab: []const u8, writer: anytype) !void {
    const shdr = self.shdrs.items[shdr_ndx];

    try writer.print("Symbol table '{s}' contains {d} entries:\n", .{
        self.getShString(shdr.sh_name),
        symtab.len,
    });
    try writer.print(
        "  Num:{s: <12}Value{s: <2}Size Type{s: <3} Bind{s: <2} Vis{s: <5} Ndx{s: <2} Name\n",
        .{ "", "", "", "", "", "" },
    );

    var arena_allocator = std.heap.ArenaAllocator.init(self.gpa);
    defer arena_allocator.deinit();
    const arena = arena_allocator.allocator();

    for (symtab, 0..) |sym, i| {
        const sym_name = getString(strtab, sym.st_name);
        const sym_type = switch (sym.st_info & 0xf) {
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
                    break :blk try fmt.allocPrint(arena, "LOPROC+{d}", .{tt - elf.STT_LOPROC});
                }
                if (elf.STT_LOOS <= tt and tt < elf.STT_HIOS) {
                    break :blk try fmt.allocPrint(arena, "LOOS+{d}", .{tt - elf.STT_LOOS});
                }
                break :blk "UNK";
            },
        };
        const sym_bind = switch (sym.st_info >> 4) {
            elf.STB_LOCAL => "LOCAL",
            elf.STB_GLOBAL => "GLOBAL",
            elf.STB_WEAK => "WEAK",
            elf.STB_NUM => "NUM",
            else => |bind| blk: {
                if (elf.STB_LOPROC <= bind and bind < elf.STB_HIPROC) {
                    break :blk try fmt.allocPrint(arena, "LOPROC+{d}", .{bind - elf.STB_LOPROC});
                }
                if (elf.STB_LOOS <= bind and bind < elf.STB_HIOS) {
                    break :blk try fmt.allocPrint(arena, "LOOS+{d}", .{bind - elf.STB_LOOS});
                }
                break :blk "UNKNOWN";
            },
        };
        const sym_vis = (&if (sym.st_other == 0) "DEFAULT" else "UNKNOWN").*;
        const sym_ndx = blk: {
            if (bits.SHN_LORESERVE <= sym.st_shndx and sym.st_shndx < bits.SHN_HIRESERVE) {
                if (bits.SHN_LOPROC <= sym.st_shndx and sym.st_shndx < bits.SHN_HIPROC) {
                    break :blk try fmt.allocPrint(arena, "LO+{d}", .{sym.st_shndx - bits.SHN_LOPROC});
                }

                const sym_ndx = &switch (sym.st_shndx) {
                    bits.SHN_ABS => "ABS",
                    bits.SHN_COMMON => "COM",
                    bits.SHN_LIVEPATCH => "LIV",
                    else => "UNK",
                };
                break :blk sym_ndx.*;
            } else if (sym.st_shndx == bits.SHN_UNDEF) {
                break :blk "UND";
            }
            break :blk try fmt.allocPrint(arena, "{d}", .{sym.st_shndx});
        };
        try writer.print(
            "  {d: >3}: {x:0>16} {d: >5} {s: <7} {s: <6} {s: <8} {s: <5} {s}\n",
            .{ i, sym.st_value, sym.st_size, sym_type, sym_bind, sym_vis, sym_ndx, sym_name },
        );
    }
}

fn getShString(self: Elf, off: u32) []const u8 {
    assert(off < self.shstrtab.items.len);
    return mem.sliceTo(@ptrCast([*:0]const u8, self.shstrtab.items.ptr + off), 0);
}

fn getString(strtab: []const u8, off: u32) []const u8 {
    assert(off < strtab.len);
    return mem.sliceTo(@ptrCast([*:0]const u8, strtab.ptr + off), 0);
}

fn readShdrContents(self: Elf, shdr_index: u32) ![]u8 {
    const shdr = self.shdrs.items[shdr_index];
    var buffer = try self.gpa.alloc(u8, shdr.sh_size);
    const amt = try self.file.preadAll(buffer, shdr.sh_offset);
    assert(amt == buffer.len);
    return buffer;
}
