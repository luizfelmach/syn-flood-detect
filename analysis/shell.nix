# Python plotting environment, including the native PNG viewer.
{ pkgs ? import <nixpkgs> {} }:
pkgs.mkShell {
  packages = [ (pkgs.python312.withPackages (ps: [ ps.matplotlib ps.tkinter ])) ];
}
