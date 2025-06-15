{
  description = "Zelf: readelf-like tool written in Zig";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-24.11";
    flake-utils.url = "github:numtide/flake-utils";
    zig.url = "github:mitchellh/zig-overlay";
    zls.url = "github:zigtools/zls";

    # Used for shell.nix
    flake-compat = {
      url = "github:edolstra/flake-compat";
      flake = false;
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      flake-utils,
      ...
    }@inputs:
    let
      overlays = [
        # Other overlays
        (final: prev: {
          zigpkgs = inputs.zig.packages.${prev.system};
          zlspkgs = inputs.zls.packages.${prev.system};
        })
      ];

      # Our supported systems are the same supported systems as the Zig binaries
      systems = builtins.attrNames inputs.zig.packages;
    in
    flake-utils.lib.eachSystem systems (
      system:
      let
        pkgs = import nixpkgs { inherit overlays system; };
      in
      rec {
        buildInputs = with pkgs; [ zigpkgs."0.14.0" ];

        packages.default = packages.zelf;
        packages.zelf = pkgs.stdenv.mkDerivation {
          name = "zelf";
          version = "master";
          src = ./.;
          nativeBuildInputs = buildInputs;
          dontConfigure = true;
          dontInstall = true;
          doCheck = false;
          buildPhase = ''
            mkdir -p .cache
            zig build install -Doptimize=ReleaseSafe --prefix $out --cache-dir $(pwd)/.zig-cache --global-cache-dir $(pwd)/.cache 
          '';
        };

        devShells.default = pkgs.mkShell {
          buildInputs = buildInputs ++ (with pkgs; [ zlspkgs.default ]);
        };

        # For compatibility with older versions of the `nix` binary
        devShell = self.devShells.${system}.default;
      }
    );
}
