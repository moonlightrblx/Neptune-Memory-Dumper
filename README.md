# Neptune Dumper (Usermode + Kernel Driver)

[![Repo Views](https://komarev.com/ghpvc/?username=p-neptunememdump&label=Repo%20views&color=0e75b6&style=flat)](https://github.com/paysonism/Neptune-Memory-Dumper)
[![GitHub Stars](https://img.shields.io/github/stars/paysonism/Neptune-Memory-Dumper?style=flat&color=yellow)](https://github.com/paysonism/Neptune-Memory-Dumper/stargazers)

Dump processes directly from memory to get decrypted information to help you Reverse Engineer applications and games.

Please star the repo to support me!

## What it does
- Uses my v2 IOCTL driver to read memory and get base address.
- Usermode app (`UM/Payson Dumper/Neptune.cpp`) talks to that driver to:
  - Find a target process by name.
  - Grab its base address (driver first, WinAPI as fallback).
  - Read headers and all sections out of the target.
  - Rebuild a disk‑style PE with proper raw offsets.
  - Clean up the relocation table so IDA doesn’t complain.
  - Save the result as `MemoryDump.exe` in the same path as the dumper exe.

## How it works
1) Driver creates `\\.\{PaysonMemoryDumper}` with two codes:
   - `PaysonRead`: page‑walk + physical read for arbitrary virtual addresses.
   - `PaysonBase`: returns the image base of the target process.
2) Usermode finds the PID, opens the process, and uses the driver to read:
   - Headers (`SizeOfHeaders` worth).
   - Each section (virtual size or raw size, whichever is bigger).
3) It builds a new buffer with file alignment, updates `PointerToRawData`/`SizeOfRawData`, and drops cleaned relocations back in place (or zeros the reloc dir if nothing valid remains).
4) Writes that buffer to `MemoryDump.exe`.

## Usage
1) Load the driver (use Neptune Mapper).
2) Run the usermode exe.
3) It asks if you want verbose debug logging (creates `DumperLog.txt` when yes).
4) Enter the target name (e.g., `TestEncrypt.exe`).
5) Hit Enter when you’re ready to dump (added in case the target decrypts itself at runtime).
6) Check for `MemoryDump.exe` in the working folder.

## Notes
- The driver uses page table walking; if a page isn’t present, you’ll get zeroes/partials (usermode will warn you)
- Relocs are cleaned to avoid IDA popups. If you don’t need rebasing, you can also zero the reloc directory.
- Imports/IAT are not rebuilt. This is not mean to be run after dumping. Only for reverse engineering.
- Verbose logging is off by default; turn it on at startup when you need details if you are having problems or need support.

## Main Files
- `UM/Payson Dumper/Neptune.cpp` — usermode dumper logic.
- `UM/Payson Dumper/driver.hpp` — usermode driver wrapper + helpers.
- `KM/Payson IOCTL/IOCTL.cpp` — kernel driver (IOCTL handler, CR3/translation, physical reads).

## Quick build hints
- Kernel: build as a Windows kernel driver. MUST HAVE THE SDK AND WDK INSTALLED!
- Usermode: standard Win32 console app; link against `psapi` if your toolchain needs it.

## Credits

Made By [Payson](https://github.com/paysonism)
Updated by [Ellii](https://github.com/moonlightrblx)

Contact me on Discord: [@payson_.](https://discord.com/users/1214355385457188926)
Join my server: [discord.gg/getneptune](https://discord.gg/getneptune)