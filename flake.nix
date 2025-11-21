{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
  };

  outputs =
    { nixpkgs, ... }:
    let
      system = "x86_64-linux";
      pkgs = import nixpkgs { inherit system; };

      ctf-packages = with pkgs; [
        python3
        gdb
      ];

      python-ctf = pkgs.python3.withPackages (p: [
        p.angr
        p.pwntools
        p.pycryptodome
        p.z3-solver
        p.pip
      ]);
    in
    {
      devShells.${system}.default = pkgs.mkShell {
        buildInputs = ctf-packages ++ [ python-ctf ];
      };
    };
}
