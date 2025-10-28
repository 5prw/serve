# Release Management

This document explains how to create releases for the Serve project.

## Automated Releases with GitHub Actions

To enable automated releases, you need to manually create the GitHub Actions workflow file, as it cannot be pushed via automated tools due to GitHub security restrictions.

### Setting Up the Workflow

1. Go to your GitHub repository
2. Click on "Actions" tab
3. Click "New workflow"
4. Click "set up a workflow yourself"
5. Name the file: `.github/workflows/release.yml`
6. Paste the following content:

```yaml
name: Release

on:
  push:
    tags:
      - 'v*'

permissions:
  contents: write

jobs:
  release:
    name: Create Release
    runs-on: ubuntu-latest

    strategy:
      matrix:
        include:
          - goos: linux
            goarch: amd64
            output: serve-linux-amd64
          - goos: linux
            goarch: arm64
            output: serve-linux-arm64
          - goos: darwin
            goarch: amd64
            output: serve-darwin-amd64
          - goos: darwin
            goarch: arm64
            output: serve-darwin-arm64
          - goos: windows
            goarch: amd64
            output: serve-windows-amd64.exe
          - goos: windows
            goarch: arm64
            output: serve-windows-arm64.exe

    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Set up Go
        uses: actions/setup-go@v5
        with:
          go-version: '1.21'

      - name: Build binary
        env:
          GOOS: ${{ matrix.goos }}
          GOARCH: ${{ matrix.goarch }}
          CGO_ENABLED: 0
        run: |
          go build -ldflags="-s -w -X main.version=${{ github.ref_name }}" -o ${{ matrix.output }}

      - name: Create archive (Unix)
        if: matrix.goos != 'windows'
        run: |
          tar -czf ${{ matrix.output }}.tar.gz ${{ matrix.output }} README.md LICENSE config.example.json
          sha256sum ${{ matrix.output }}.tar.gz > ${{ matrix.output }}.tar.gz.sha256

      - name: Create archive (Windows)
        if: matrix.goos == 'windows'
        run: |
          zip ${{ matrix.output }}.zip ${{ matrix.output }} README.md LICENSE config.example.json
          sha256sum ${{ matrix.output }}.zip > ${{ matrix.output }}.zip.sha256

      - name: Upload Release Asset (Unix)
        if: matrix.goos != 'windows'
        uses: softprops/action-gh-release@v1
        with:
          files: |
            ${{ matrix.output }}.tar.gz
            ${{ matrix.output }}.tar.gz.sha256
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}

      - name: Upload Release Asset (Windows)
        if: matrix.goos == 'windows'
        uses: softprops/action-gh-release@v1
        with:
          files: |
            ${{ matrix.output }}.zip
            ${{ matrix.output }}.zip.sha256
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

7. Commit the file

### Creating a Release

Once the workflow is set up, create a release by pushing a tag:

```bash
# Create a tag
git tag -a v1.0.0 -m "Release v1.0.0"

# Push the tag
git push origin v1.0.0
```

The GitHub Action will automatically:
- Build binaries for all platforms (Linux, macOS, Windows on amd64 and arm64)
- Create `.tar.gz` archives for Unix systems
- Create `.zip` archives for Windows
- Generate SHA256 checksums
- Upload all files to the GitHub Release

## Manual Releases

If you prefer to create releases manually, use the Makefile:

### Build All Platforms

```bash
make build-all
```

This creates binaries in `./dist/`:
- `serve-linux-amd64`
- `serve-linux-arm64`
- `serve-darwin-amd64`
- `serve-darwin-arm64`
- `serve-windows-amd64.exe`
- `serve-windows-arm64.exe`

### Create Release Archives

```bash
make release-local
```

This creates archives in `./dist/archives/`:
- `serve-linux-amd64.tar.gz`
- `serve-linux-arm64.tar.gz`
- `serve-darwin-amd64.tar.gz`
- `serve-darwin-arm64.tar.gz`
- `serve-windows-amd64.zip`
- `serve-windows-arm64.zip`

### Upload to GitHub

1. Go to your repository on GitHub
2. Click "Releases"
3. Click "Draft a new release"
4. Create a new tag (e.g., `v1.0.0`)
5. Set the release title (e.g., `Release v1.0.0`)
6. Add release notes (copy from CHANGELOG.md)
7. Upload the archive files from `./dist/archives/`
8. Publish the release

## Platforms Supported

- **Linux** (amd64, arm64)
- **macOS** (amd64 - Intel, arm64 - Apple Silicon)
- **Windows** (amd64, arm64)

## Binary Sizes

Optimized binaries (with `-ldflags="-s -w"`):
- Approximately 7-8 MB per binary
- No external dependencies required
- Stripped symbols and debug info

## Versioning

This project follows [Semantic Versioning](https://semver.org/):

- **MAJOR**: Incompatible API changes
- **MINOR**: Backwards-compatible functionality additions
- **PATCH**: Backwards-compatible bug fixes

## Pre-release Tags

For pre-releases, use:
- `v1.0.0-alpha.1` - Alpha releases
- `v1.0.0-beta.1` - Beta releases
- `v1.0.0-rc.1` - Release candidates

## Release Checklist

Before creating a release:

- [ ] Update CHANGELOG.md with changes
- [ ] Update version in relevant documentation
- [ ] Run tests (when available)
- [ ] Build and test locally: `make build-all`
- [ ] Verify all features work
- [ ] Update README.md if needed
- [ ] Create git tag
- [ ] Push tag to trigger release
- [ ] Verify release artifacts on GitHub
- [ ] Test download and installation
- [ ] Announce release (if applicable)

## Troubleshooting

### Release Build Fails

Check that:
- Go 1.21+ is installed
- All dependencies are available
- No syntax errors in code

### Archives Missing Files

Ensure these files exist:
- `README.md`
- `LICENSE`
- `config.example.json`

### GitHub Action Not Triggering

Verify:
- Workflow file is in `.github/workflows/`
- Tag starts with `v` (e.g., `v1.0.0`)
- Repository has Actions enabled
- Workflow has `contents: write` permission
