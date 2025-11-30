{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-parts.url = "github:hercules-ci/flake-parts";
  };

  outputs =
    inputs@{ flake-parts, ... }:
    flake-parts.lib.mkFlake { inherit inputs; } {
      systems = [ "x86_64-linux" ];
      perSystem =
        { pkgs, ... }:
        {
          devShells.default = pkgs.mkShell {
            buildInputs = with pkgs; [
              (python3.withPackages (
                ps: with ps; [
                  pip
                  angr
                  pwntools
                  pycryptodome
                  z3-solver
                  requests
                  pillow
                  opencv4
                  evtx
                  lxml
                  fickling
                  tqdm
                ]
              ))

              radare2
              binwalk
              john
              hashcat
              nmap
              wireshark
              wget
              xxd
              unzip
              sleuthkit
              yara
              cmake
              gnumake
              llvm
              gdb
              libseccomp
              pwntools
            ];
          };
        };
    };
}
