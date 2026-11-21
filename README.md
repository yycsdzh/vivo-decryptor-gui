# VivoDecryptor

A simple Windows program that decrypts **new-format vivo Suite backups** (made by vivo's Suite / backup app). You need the backup password.

## Requirements
- Windows 10 or 11
- Nothing else. No Python needed.

## Running
1. Download `VivoDecryptor.exe` from the Releases page.
2. Double-click it.

### SmartScreen warning
Windows may say "Windows protected your PC" because the file is not code-signed. To continue:
1. Click **More info**.
2. Click **Run anyway**.

### Verify the download (SHA256)
Compare the hash of your file with the one in `SHA256SUMS` on the release page. In Command Prompt:

    certutil -hashfile VivoDecryptor.exe SHA256

The two values must match. If they don't, don't run the file.

## Usage
1. Pick the **backup folder** (the vivo Suite backup).
2. Pick an **output folder**.
3. Enter the backup **password**.
4. Choose the **container** in the backup.
5. Click to **list files**.
6. **Select** the files you want.
7. Click **Start**.

## Notes
- Large backups take a long time. Let it finish.
- The output folder needs enough free disk space (about the size of the decrypted files).
- Your password is never saved and never sent anywhere. Everything runs on your PC.
- Only the new vivo Suite format is supported.

## Building from source
Install Python 3.12 and run `build.bat`. The exe appears in `dist\`.

## Credits
Based on [awakaze/vivo-backup-decryptor](https://github.com/awakaze/vivo-backup-decryptor), released under the MIT License. This GUI and packaging are distributed under the same license.
