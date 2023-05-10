const std = @import("std");
const fs = std.fs;

const Elf = @import("Elf.zig");

var global_alloc = std.heap.GeneralPurposeAllocator(.{}){};
const gpa = global_alloc.allocator();

const usage =
    \\Usage: zelf [options] file
    \\
    \\General Options:
    \\-a, --all                Equivalent of having all flags on
    \\-h, --file-header        Display ELF file header
    \\-l, --program-headers    Display program headers (if any)
    \\-S, --section-headers    Display section headers
    \\-s, --symbols            Display symbol table
    \\-r, --relocs             Display relocations (if any)
    \\--help                   Display this help and exit
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
};

pub fn main() anyerror!void {
    var arena_allocator = std.heap.ArenaAllocator.init(gpa);
    defer arena_allocator.deinit();
    const arena = arena_allocator.allocator();

    const all_args = try std.process.argsAlloc(arena);
    const args = all_args[1..];

    if (args.len == 0) fatal(usage, .{});

    var filename: ?[]const u8 = null;

    const PrintMatrix = packed struct {
        header: u1 = 0,
        phdrs: u1 = 0,
        shdrs: u1 = 0,
        symbols: u1 = 0,
        relocs: u1 = 0,
    };
    var print_matrix: PrintMatrix = .{};

    var it = ArgsIterator{ .args = args };
    while (it.next()) |arg| {
        if (std.mem.eql(u8, arg, "--help")) {
            fatal(usage, .{});
        } else if (std.mem.eql(u8, arg, "-a") or std.mem.eql(u8, arg, "--all")) {
            print_matrix = @bitCast(PrintMatrix, ~@as(u5, 0));
        } else if (std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--file-header")) {
            print_matrix.header = 1;
        } else if (std.mem.eql(u8, arg, "-l") or std.mem.eql(u8, arg, "--program-headers")) {
            print_matrix.phdrs = 1;
        } else if (std.mem.eql(u8, arg, "-S") or std.mem.eql(u8, arg, "--section-headers")) {
            print_matrix.shdrs = 1;
        } else if (std.mem.eql(u8, arg, "-s") or std.mem.eql(u8, arg, "--symbols")) {
            print_matrix.symbols = 1;
        } else if (std.mem.eql(u8, arg, "-r") or std.mem.eql(u8, arg, "--relocs")) {
            print_matrix.relocs = 1;
        } else {
            if (filename != null) fatal("too many positional arguments specified", .{});
            filename = arg;
        }
    }

    const fname = filename orelse fatal("no input file specified", .{});
    const file = try fs.cwd().openFile(fname, .{});
    defer file.close();
    const data = try file.readToEndAlloc(arena, std.math.maxInt(u32));

    var elf = Elf{ .arena = arena, .data = data };
    elf.parse() catch |err| switch (err) {
        error.InvalidMagic => fatal("not an ELF file - invalid magic bytes", .{}),
        else => |e| return e,
    };

    const stdout = std.io.getStdOut().writer();

    if (@bitCast(u5, print_matrix) == 0) fatal("no option specified", .{});

    if (print_matrix.header == 1) {
        try elf.printHeader(stdout);
        try stdout.writeAll("\n");
    }
    if (print_matrix.shdrs == 1) {
        try elf.printShdrs(stdout);
        try stdout.writeAll("\n");
    }
    if (print_matrix.phdrs == 1) {
        try elf.printPhdrs(stdout);
        try stdout.writeAll("\n");
    }
    if (print_matrix.relocs == 1) {
        try elf.printRelocs(stdout);
        try stdout.writeAll("\n");
    }
    if (print_matrix.symbols == 1) {
        try elf.printSymtabs(stdout);
        try stdout.writeAll("\n");
    }
}
