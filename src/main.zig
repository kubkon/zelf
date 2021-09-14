const std = @import("std");
const clap = @import("clap");
const fs = std.fs;

var global_alloc = std.heap.GeneralPurposeAllocator(.{}){};
const gpa = &global_alloc.allocator;

pub fn main() anyerror!void {
    const stderr = std.io.getStdErr().writer();
    const stdout = std.io.getStdOut().writer();

    const params = comptime [_]clap.Param(clap.Help){
        clap.parseParam("--help              Display this help and exit") catch unreachable,
        clap.parseParam("-h, --file-header   Display the ELF file header") catch unreachable,
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

    std.log.info("All your codebase are belong to us.", .{});
}

fn printUsageWithHelp(comptime params: []const clap.Param(clap.Help), writer: anytype) !void {
    try writer.print("zelf ", .{});
    try clap.usage(writer, params);
    try writer.print("\n", .{});
    try clap.help(writer, params);
}
