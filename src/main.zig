const std = @import("std");
const clap = @import("clap");
const fs = std.fs;

const Elf = @import("Elf.zig");

var global_alloc = std.heap.GeneralPurposeAllocator(.{}){};
const gpa = &global_alloc.allocator;

pub fn main() anyerror!void {
    const stderr = std.io.getStdErr().writer();
    const stdout = std.io.getStdOut().writer();

    const params = comptime [_]clap.Param(clap.Help){
        clap.parseParam("--help                  Display this help and exit") catch unreachable,
        clap.parseParam("-a, --all               Equivalent to having all flags on") catch unreachable,
        clap.parseParam("-h, --file-header       Display the ELF file header") catch unreachable,
        clap.parseParam("-S, --section-headers   Display the sections' header") catch unreachable,
        clap.parseParam("<FILE>") catch unreachable,
    };

    var args = try clap.parse(clap.Help, &params, .{});
    defer args.deinit();

    if (args.flag("--help")) {
        return printUsageWithHelp(&params, stderr);
    }

    const positionals = args.positionals();
    if (positionals.len == 0) {
        return stderr.print("missing positional argument <FILE>...\n", .{});
    }

    const filename = positionals[0];
    const file = try fs.cwd().openFile(filename, .{});
    defer file.close();

    var elf = Elf.init(gpa, file);
    defer elf.deinit();
    try elf.parseMetadata();

    const print_header = args.flag("--all") or args.flag("--file-header");
    const print_shdrs = args.flag("--all") or args.flag("--section-headers");

    if (!print_header and !print_shdrs) {
        return printUsageWithHelp(&params, stderr);
    }
    if (print_header) {
        try elf.printHeader(stdout);
    }
    if (print_shdrs) {
        try elf.printShdrs(stdout);
    }
}

fn printUsageWithHelp(comptime params: []const clap.Param(clap.Help), writer: anytype) !void {
    try writer.print("zelf ", .{});
    try clap.usage(writer, params);
    try writer.print("\n", .{});
    try clap.help(writer, params);
}
