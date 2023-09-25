{ pkgs ? import <nixpkgs> { }
, src ? ./.
, buildGoModule
, fetchFromGithub
, version
,
}:

buildGoModule rec {
  name = "bonjour-reflector";
  inherit src;
  inherit version;

  vendorSha256 = "sha256-WDzJlOnh+cVSMgX5yuzcxkbYRckKNGG83yQDtNfh5/4=";

  buildInputs = [
    pkgs.libpcap # for github.com/google/gopacket
  ];

  meta = {
    description = "A reflector that forwards mdns packets between VLANs - like avahi-reflector but with fine-grained control !";
    homepage = "https://github.com/nberlee/bonjour-reflector";
  };
}
