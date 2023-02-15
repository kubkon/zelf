const std = @import("std");
const clap = @import("clap");
const fs = std.fs;

const Elf = @import("Elf.zig");

var global_alloc = std.heap.GeneralPurposeAllocator(.{}){};
const gpa = global_alloc.allocator();

pub fn main() anyerror!void {
    const stderr = std.io.getStdErr().writer();
    const stdout = std.io.getStdOut().writer();

    const params = comptime [_]clap.Param(clap.Help){
        clap.parseParam("--help                  Display this help and exit") catch unreachable,
        clap.parseParam("-a, --all               Equivalent to having all flags on") catch unreachable,
        clap.parseParam("-h, --file-header       Display the ELF file header") catch unreachable,
        clap.parseParam("-l, --program-headers   Display the programs' headers") catch unreachable,
        clap.parseParam("-S, --section-headers   Display the sections' header") catch unreachable,
        clap.parseParam("-s, --symbols           Display the symbol table") catch unreachable,
        clap.parseParam("-r, --relocs            Display the relocations (if present)") catch unreachable,
        clap.parseParam("<FILE>") catch unreachable,
    };

    const parsers = comptime .{
        .FILE = clap.parsers.string,
    };

    var res = try clap.parse(clap.Help, &params, parsers, .{
        .allocator = gpa,
        .diagnostic = null,
    });
    defer res.deinit();

    if (res.args.help) {
        return printUsageWithHelp(&params, stderr);
    }

    if (res.positionals.len == 0) {
        return stderr.print("missing positional argument <FILE>...\n", .{});
    }

    const filename = res.positionals[0];
    const file = try fs.cwd().openFile(filename, .{});
    defer file.close();

    var elf = Elf.init(gpa, file);
    defer elf.deinit();
    try elf.parseMetadata();

    if (res.args.all) {
        try elf.printHeader(stdout);
        try stdout.writeAll("\n");
        try elf.printShdrs(stdout);
        try stdout.writeAll("\n");
        try elf.printPhdrs(stdout);
        try stdout.writeAll("\n");
        try elf.printRelocs(stdout);
        try stdout.writeAll("\n");
        try elf.printSymtabs(stdout);
    } else if (res.args.@"file-header") {
        try elf.printHeader(stdout);
    } else if (res.args.@"section-headers") {
        try elf.printShdrs(stdout);
    } else if (res.args.@"program-headers") {
        try elf.printPhdrs(stdout);
    } else if (res.args.relocs) {
        try elf.printRelocs(stdout);
    } else if (res.args.symbols) {
        try elf.printSymtabs(stdout);
    } else {
        return printUsageWithHelp(&params, stderr);
    }
}

fn printUsageWithHelp(comptime params: []const clap.Param(clap.Help), writer: anytype) !void {
    try writer.print("zelf ", .{});
    try clap.usage(writer, clap.Help, params);
    try writer.print("\n", .{});
    try clap.help(writer, clap.Help, params, .{});
}
