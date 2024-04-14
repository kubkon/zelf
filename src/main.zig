const std = @import("std");
const fs = std.fs;

const Archive = @import("Archive.zig");
const Object = @import("Object.zig");

var global_alloc = std.heap.GeneralPurposeAllocator(.{}){};
const gpa = global_alloc.allocator();

const usage =
    \\Usage: zelf [options] file
    \\
    \\General Options:
    \\-a, --all                        Equivalent of having all flags on
    \\-h, --file-header                Display ELF file header
    \\-l, --program-headers            Display program headers (if present)
    \\-S, --section-headers            Display section headers
    \\-s, --symbols                    Display symbol table
    \\    --dyn-syms                   Display the dynamic symbol table
    \\-r, --relocs                     Display relocations (if present)
    \\-d, --dynamic                    Display the dynamic section (if present)
    \\--initializers                   Display table(s) of initializers/finalizers (if present)
    \\-p, --string-dump=<number|name>  Dump the contents of section <number|name> as strings
    \\-V, --version-info               Display the version sections (if present)
    \\-W, --wide                       Do not shorten the names if too wide
    \\-x, --hex-dump=<number|name>     Dump the contents of section <number|name> as bytes
    \\--help                           Display this help and exit
    \\
;

fn fatal(comptime format: []const u8, args: anytype) noreturn {
    ret: {
        const msg = std.fmt.allocPrint(gpa, format ++ "\n", args) catch break :ret;
        std.io.getStdErr().writeAll(msg) catch {};
    }
    std.process.exit(1);
}

const ArgsIterator = struct {
    args: []const []const u8,
    i: usize = 0,

    fn next(it: *@This()) ?[]const u8 {
        if (it.i >= it.args.len) {
            return null;
        }
        defer it.i += 1;
        return it.args[it.i];
    }

    fn nextOrFatal(it: *@This()) []const u8 {
        return it.next() orelse fatal("expected parameter after {s}", .{it.args[it.i - 1]});
    }

    pub fn peek(it: *@This()) ?[]const u8 {
        const arg = it.next();
        defer if (it.i > 0) {
            it.i -= 1;
        };
        return arg;
    }
};

const ArgsParser = struct {
    next_arg: []const u8 = undefined,
    it: *ArgsIterator,

    pub fn hasMore(p: *ArgsParser) bool {
        p.next_arg = p.it.next() orelse return false;
        return true;
    }

    pub fn flag1(p: *ArgsParser, comptime pat: []const u8) bool {
        return p.flagPrefix(pat, "-");
    }

    pub fn flag2(p: *ArgsParser, comptime pat: []const u8) bool {
        return p.flagPrefix(pat, "--");
    }

    fn flagPrefix(p: *ArgsParser, comptime pat: []const u8, comptime prefix: []const u8) bool {
        if (std.mem.startsWith(u8, p.next_arg, prefix)) {
            const actual_arg = p.next_arg[prefix.len..];
            if (std.mem.eql(u8, actual_arg, pat)) {
                return true;
            }
        }
        return false;
    }

    pub fn arg1(p: *ArgsParser, comptime pat: []const u8) ?[]const u8 {
        return p.argPrefix(pat, "-");
    }

    pub fn arg2(p: *ArgsParser, comptime pat: []const u8) ?[]const u8 {
        return p.argPrefix(pat, "--");
    }

    fn argPrefix(p: *ArgsParser, comptime pat: []const u8, comptime prefix: []const u8) ?[]const u8 {
        if (std.mem.startsWith(u8, p.next_arg, prefix)) {
            const actual_arg = p.next_arg[prefix.len..];
            if (std.mem.eql(u8, actual_arg, pat)) {
                if (p.it.peek()) |next| {
                    if (std.mem.startsWith(u8, next, "-")) return null;
                }
                return p.it.nextOrFatal();
            }
            if (std.mem.startsWith(u8, actual_arg, pat)) {
                return actual_arg[pat.len..];
            }
        }
        return null;
    }
};

pub fn main() anyerror!void {
    var arena_allocator = std.heap.ArenaAllocator.init(gpa);
    defer arena_allocator.deinit();
    const arena = arena_allocator.allocator();

    const all_args = try std.process.argsAlloc(arena);
    const args = all_args[1..];

    if (args.len == 0) fatal(usage, .{});

    var filename: ?[]const u8 = null;
    var opts: Options = .{};

    var print_matrix: PrintMatrix = .{};
    var arg_data: ArgData = .{};

    var it = ArgsIterator{ .args = args };
    var p = ArgsParser{ .it = &it };
    while (p.hasMore()) {
        if (std.mem.startsWith(u8, p.next_arg, "-")) blk: {
            var i: usize = 1;
            var tmp = PrintMatrix{};
            while (i < p.next_arg.len) : (i += 1) switch (p.next_arg[i]) {
                '-' => break :blk,
                'a' => tmp = PrintMatrix.enableAll(),
                'c' => tmp.archive_index = true,
                'h' => tmp.header = true,
                'l' => tmp.phdrs = true,
                'S' => tmp.shdrs = true,
                's' => {
                    tmp.dynamic_symbols = true;
                    tmp.symbols = true;
                },
                'r' => tmp.relocs = true,
                'd' => tmp.dynamic_section = true,
                'V' => tmp.version_sections = true,
                'W' => opts.wide = true,
                else => break :blk,
            };
            print_matrix.add(tmp);
            continue;
        }

        if (p.flag2("help")) {
            fatal(usage, .{});
        } else if (p.flag2("all")) {
            print_matrix = PrintMatrix.enableAll();
        } else if (p.flag2("file-header")) {
            print_matrix.header = true;
        } else if (p.flag2("program-headers")) {
            print_matrix.phdrs = true;
        } else if (p.flag2("section-headers")) {
            print_matrix.shdrs = true;
        } else if (p.flag2("symbols")) {
            print_matrix.dynamic_symbols = true;
            print_matrix.symbols = true;
        } else if (p.flag2("dyn-syms")) {
            print_matrix.dynamic_symbols = true;
        } else if (p.flag2("relocs")) {
            print_matrix.relocs = true;
        } else if (p.flag2("dynamic")) {
            print_matrix.dynamic_section = true;
        } else if (p.flag2("initializers")) {
            print_matrix.initializers = true;
        } else if (p.flag2("version-info")) {
            print_matrix.version_sections = true;
        } else if (p.flag2("archive-index")) {
            print_matrix.archive_index = true;
        } else if (p.flag2("wide")) {
            opts.wide = true;
        } else if (p.arg1("x")) |value| {
            if (std.fmt.parseUnsigned(u32, value, 0)) |num| {
                print_matrix.hex_dump_num = true;
                arg_data.hex_dump_num = num;
            } else |_| {
                print_matrix.hex_dump_str = true;
                arg_data.hex_dump_str = value;
            }
        } else if (p.arg2("hex-dump=")) |value| {
            if (std.fmt.parseUnsigned(u32, value, 0)) |num| {
                print_matrix.hex_dump_num = true;
                arg_data.hex_dump_num = num;
            } else |_| {
                print_matrix.hex_dump_str = true;
                arg_data.hex_dump_str = value;
            }
        } else if (p.arg1("p")) |value| {
            if (std.fmt.parseUnsigned(u32, value, 0)) |num| {
                print_matrix.str_dump_num = true;
                arg_data.str_dump_num = num;
            } else |_| {
                print_matrix.str_dump_str = true;
                arg_data.str_dump_str = value;
            }
        } else if (p.arg2("string-dump=")) |value| {
            if (std.fmt.parseUnsigned(u32, value, 0)) |num| {
                print_matrix.str_dump_num = true;
                arg_data.str_dump_num = num;
            } else |_| {
                print_matrix.str_dump_str = true;
                arg_data.str_dump_str = value;
            }
        } else {
            if (filename != null) fatal("too many positional arguments specified", .{});
            filename = p.next_arg;
        }
    }

    const fname = filename orelse fatal("no input file specified", .{});
    const file = try fs.cwd().openFile(fname, .{});
    defer file.close();
    const data = try file.readToEndAlloc(arena, std.math.maxInt(u32));

    const stdout = std.io.getStdOut().writer();
    if (print_matrix.isUnset()) fatal("no option specified", .{});

    if (try Archive.isArchive(fname)) {
        var archive = Archive{ .arena = arena, .data = data, .path = fname, .opts = opts };
        try archive.parse();
        if (print_matrix.archive_index) {
            try archive.printSymtab(stdout);
            try stdout.writeAll("\n");
        }
        print_matrix.archive_index = false;
        if (!print_matrix.isUnset()) for (archive.objects.values()) |object| {
            try stdout.print("File: {s}({s})\n", .{ archive.path, object.path });
            try printObject(object, print_matrix, arg_data, stdout);
        };
    } else {
        var object = Object{ .arena = arena, .data = data, .path = fname, .opts = opts };
        object.parse() catch |err| switch (err) {
            error.InvalidMagic => fatal("not an ELF file - invalid magic bytes", .{}),
            else => |e| return e,
        };
        try printObject(object, print_matrix, arg_data, stdout);
    }
}

fn printObject(object: Object, print_matrix: PrintMatrix, arg_data: ArgData, stdout: anytype) !void {
    if (print_matrix.header) {
        try object.printHeader(stdout);
        try stdout.writeAll("\n");
    }
    if (print_matrix.shdrs) {
        try object.printShdrs(stdout);
        try stdout.writeAll("\n");
    }
    if (print_matrix.phdrs) {
        try object.printPhdrs(stdout);
        try stdout.writeAll("\n");
    }
    if (print_matrix.relocs) {
        try object.printRelocs(stdout);
        try stdout.writeAll("\n");
    }
    if (print_matrix.symbols) {
        try object.printSymbolTable(stdout);
        try stdout.writeAll("\n");
    }
    if (print_matrix.dynamic_symbols) {
        try object.printDynamicSymbolTable(stdout);
        try stdout.writeAll("\n");
    }
    if (print_matrix.dynamic_section) {
        try object.printDynamicSection(stdout);
        try stdout.writeAll("\n");
    }
    if (print_matrix.initializers) {
        try object.printInitializers(stdout);
        try stdout.writeAll("\n");
    }
    if (print_matrix.version_sections) {
        try object.printVersionSections(stdout);
        try stdout.writeAll("\n");
    }
    if (print_matrix.hex_dump_num) {
        try object.dumpSectionHex(arg_data.hex_dump_num, stdout);
        try stdout.writeAll("\n");
    }
    if (print_matrix.hex_dump_str) {
        const shndx = object.getSectionByName(arg_data.hex_dump_str) orelse
            fatal("section '{s}' not found", .{arg_data.hex_dump_str});
        try object.dumpSectionHex(shndx, stdout);
        try stdout.writeAll("\n");
    }
    if (print_matrix.str_dump_num) {
        try object.dumpSectionStr(arg_data.str_dump_num, stdout);
        try stdout.writeAll("\n");
    }
    if (print_matrix.str_dump_str) {
        const shndx = object.getSectionByName(arg_data.str_dump_str) orelse
            fatal("section '{s}' not found", .{arg_data.str_dump_str});
        try object.dumpSectionStr(shndx, stdout);
        try stdout.writeAll("\n");
    }
}

pub const Options = struct {
    wide: bool = false,
};

const PrintMatrix = packed struct {
    header: bool = false,
    archive_index: bool = false,
    phdrs: bool = false,
    shdrs: bool = false,
    symbols: bool = false,
    dynamic_symbols: bool = false,
    dynamic_section: bool = false,
    relocs: bool = false,
    initializers: bool = false,
    version_sections: bool = false,
    hex_dump_num: bool = false,
    hex_dump_str: bool = false,
    str_dump_num: bool = false,
    str_dump_str: bool = false,

    const Int = blk: {
        const bits = @typeInfo(@This()).Struct.fields.len;
        break :blk @Type(.{
            .Int = .{
                .signedness = .unsigned,
                .bits = bits,
            },
        });
    };

    fn enableAll() @This() {
        return .{
            .header = true,
            .archive_index = true,
            .phdrs = true,
            .shdrs = true,
            .symbols = true,
            .dynamic_symbols = true,
            .dynamic_section = true,
            .relocs = true,
            .initializers = true,
            .version_sections = true,
        };
    }

    fn isUnset(pm: @This()) bool {
        return @as(Int, @bitCast(pm)) == 0;
    }

    fn add(pm: *@This(), other: @This()) void {
        pm.* = @as(@This(), @bitCast(@as(Int, @bitCast(pm.*)) | @as(Int, @bitCast(other))));
    }
};

const ArgData = struct {
    hex_dump_num: u32 = 0,
    hex_dump_str: []const u8 = &[0]u8{},
    str_dump_num: u32 = 0,
    str_dump_str: []const u8 = &[0]u8{},
};
