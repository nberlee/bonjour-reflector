{
  description = "bonjour-reflector";

  inputs.nixpkgs.url = "github:nixos/nixpkgs/nixos-23.05";
  inputs.flake-utils.url = "github:numtide/flake-utils";
  inputs.treefmt-nix.url = "github:numtide/treefmt-nix";
  inputs.treefmt-nix.inputs.nixpkgs.follows = "nixpkgs";

  outputs = { self, nixpkgs, flake-utils, treefmt-nix }:
    flake-utils.lib.eachDefaultSystem (system: {
      formatter = treefmt-nix.lib.mkWrapper nixpkgs.legacyPackages.${system}
        {
          projectRootFile = "flake.nix";
          programs.nixpkgs-fmt.enable = true;
          programs.gofmt.enable = true;
        };

      defaultPackage = self.packages.${system}.default;

      packages = {
        default = self.packages.${system}.bonjour-reflector;

        bonjour-reflector = nixpkgs.legacyPackages.${system}.callPackage self {
          src = self;
          version = "master";
        };
      };

      nixosModules = {
        bonjour-reflector = import ./module.nix;
        default =  self.nixosModules.bonjour-reflector;
      };

      devShells = {
        default = nixpkgs.legacyPackages.${system}.mkShell {
          buildInputs = with nixpkgs.legacyPackages.${system}; [ go gopls go-tools gotools libpcap ];
        };
      };
    });
}
