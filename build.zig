const builtin = @import("builtin");
const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const mode = b.standardOptimizeOption(.{});

    const use_llvm = b.option(bool, "use-llvm", "Whether to use LLVM") orelse true;
    const use_lld = if (builtin.target.os.tag.isDarwin()) false else use_llvm;

    const exe = b.addExecutable(.{
        .name = "zelf",
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = mode,
        .use_llvm = use_llvm,
        .use_lld = use_lld,
    });
    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);
}
