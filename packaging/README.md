# Packaging

- We use [nFPM](https://nfpm.goreleaser.com/) for making `.deb` packages (configured in `.goreleaser.yml` and `packaging/deb/`).
- We use [nFPM](https://nfpm.goreleaser.com/) for making `.rpm` packages (configured in `packaging/rpm/nfpm.yaml`, `packaging/rpm/`, and `.github/workflows/release-rpm.yml`).
- We use Arch Linux `PKGBUILD` and `makepkg` (in `packaging/arch/` and `.github/workflows/release-arch.yml`) for Arch Linux `.pkg.tar.zst` packages.

This folder contains files we need to package with these releases.
