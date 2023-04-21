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
    const all_args = try std.process.argsAlloc(gpa);
    defer std.process.argsFree(gpa, all_args);
    const args = all_args[1..];

    if (args.len == 0) fatal(usage, .{});

    var filename: ?[]const u8 = null;
    var print_all = false;
    var print_header = false;
    var print_phdrs = false;
    var print_shdrs = false;
    var print_symtab = false;
    var print_relocs = false;

    var args_iter = ArgsIterator{ .args = args };

    while (args_iter.next()) |arg| {
        if (std.mem.eql(u8, arg, "--help")) {
            fatal(usage, .{});
        } else if (std.mem.eql(u8, arg, "-a") or std.mem.eql(u8, arg, "--all")) {
            print_all = true;
        } else if (std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--file-header")) {
            print_header = true;
        } else if (std.mem.eql(u8, arg, "-l") or std.mem.eql(u8, arg, "--program-headers")) {
            print_phdrs = true;
        } else if (std.mem.eql(u8, arg, "-S") or std.mem.eql(u8, arg, "--section-headers")) {
            print_shdrs = true;
        } else if (std.mem.eql(u8, arg, "-s") or std.mem.eql(u8, arg, "--symbols")) {
            print_symtab = true;
        } else if (std.mem.eql(u8, arg, "-r") or std.mem.eql(u8, arg, "--relocs")) {
            print_relocs = true;
        } else {
            if (filename != null) fatal("too many positional arguments specified", .{});
            filename = arg;
        }
    }

    const fname = filename orelse fatal("no input file specified", .{});
    const file = try fs.cwd().openFile(fname, .{});
    defer file.close();

    var elf = Elf.init(gpa, file);
    defer elf.deinit();
    try elf.parseMetadata();

    const stdout = std.io.getStdOut().writer();

    if (print_all) {
        try elf.printHeader(stdout);
        try stdout.writeAll("\n");
        try elf.printShdrs(stdout);
        try stdout.writeAll("\n");
        try elf.printPhdrs(stdout);
        try stdout.writeAll("\n");
        try elf.printRelocs(stdout);
        try stdout.writeAll("\n");
        try elf.printSymtabs(stdout);
    } else if (print_header) {
        try elf.printHeader(stdout);
    } else if (print_shdrs) {
        try elf.printShdrs(stdout);
    } else if (print_phdrs) {
        try elf.printPhdrs(stdout);
    } else if (print_relocs) {
        try elf.printRelocs(stdout);
    } else if (print_symtab) {
        try elf.printSymtabs(stdout);
    } else fatal("no option specified", .{});
}
