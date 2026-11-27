# Verifying a release

## Native Windows application

Identify the commit or tag you intend to use. The native application builds from the C++ source and the bundled indicator files. Build a separate Release copy and run its synthetic tests from the repository root.

```powershell
python "1. build.py" --candidate --tests --no-pause
```

The candidate executable is `out/candidate/Release/XASpy.exe`. Its build receipt records the source and output identities for that build. To compare a downloaded executable with a published SHA-256 checksum, run the following against your local copy. Obtain the expected checksum through a trusted channel.

```powershell
Get-FileHash -Algorithm SHA256 -LiteralPath .\XASpy.exe
```

## Signed artifacts

When a publisher provides a detached signature, verify the full signing-key fingerprint through an independent trusted channel before importing the public key. Use the actual filenames supplied with the release. A valid signature ties the manifest to the signing key. Compare each downloaded artifact with its entry in the verified manifest.

```sh
gpg --show-keys --with-fingerprint release-signing-key.asc
gpg --import release-signing-key.asc
gpg --verify SHA256SUMS.txt.asc SHA256SUMS.txt
sha256sum -c SHA256SUMS.txt
```

## Retained Python toolkit

The legacy packaging helper prepares the Python distribution. It accepts `--no-sign` for a checksum-only build and `--key FINGERPRINT` for a signed build using the maintainer’s local GPG keyring. Historical upstream releases must be verified using the key and checksums published for those releases.
