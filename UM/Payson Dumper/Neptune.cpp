#define NOMINMAX
#include <windows.h>
#include <psapi.h>
#include <winnt.h>
#include <iostream>
#include <string>
#include <vector>
#include <fstream>
#include <iomanip>
#include <algorithm>
#include <cstdint>
#include <cstring>

#include "driver.hpp"

#define CLR_RESET 7
#define CLR_GOOD 10
#define CLR_NOTE 14
#define CLR_BAD 12
#define CLR_INPUT 13

bool g_verbose_debug = false;

void set_color(HANDLE con, int color) {
    SetConsoleTextAttribute(con, color);
}

void log_to_file(const std::string& message) {
    if (!g_verbose_debug) {
        return;
    }
    std::ofstream logfile("DumperLog.txt", std::ios::app);
    if (logfile.is_open()) {
        logfile << "[DEBUG] " << message << std::endl;
        logfile.close();
    }
}

DWORD grab_pid(const std::string& proc_name) {
    log_to_file("Entering grab_pid function.");
    int size_needed = MultiByteToWideChar(CP_UTF8, 0, proc_name.c_str(), -1, NULL, 0);
    std::wstring w_proc_name(size_needed, 0);
    MultiByteToWideChar(CP_UTF8, 0, proc_name.c_str(), -1, &w_proc_name[0], size_needed);
    DWORD pid = PaysonDRV::FindProcessID(w_proc_name.c_str());
    log_to_file("FindProcessID returned PID: " + std::to_string(pid));
    if (pid == 0) {
        log_to_file("Process not found: " + proc_name);
        return 0;
    }
    log_to_file("Process found, PID set to: " + std::to_string(pid));
    return pid;
}

bool snag_mem(HANDLE hProc, ULONG64 addr, ULONG sz, std::vector<char>& out) {
    log_to_file("Attempting memory read at address: 0x" + std::to_string(addr) + ", size: " + std::to_string(sz));
    out.assign(sz, 0);

    const ULONG chunk = 0x1000;
    ULONG total_read = 0;
    HANDLE con = GetStdHandle(STD_OUTPUT_HANDLE);

    while (total_read < sz) {
        ULONG to_read = std::min(chunk, sz - total_read);
        DWORD bytes_read = 0;
        ULONG64 cur_addr = addr + total_read;

        bool ok = PaysonDRV::ReadPhysical((PVOID)cur_addr, out.data() + total_read, to_read, &bytes_read);

        if (ok && bytes_read == to_read) {
            total_read += bytes_read;
            continue;
        }

        // Driver gave partial or failed. try user-mode ReadProcessMemory as a fallback
        SIZE_T user_read = 0;
        if (ReadProcessMemory(hProc, reinterpret_cast<LPCVOID>(cur_addr), out.data() + total_read, to_read, &user_read) && user_read > 0) {
            total_read += static_cast<ULONG>(user_read);
        }
        else {
            if (!ok) {
                log_to_file("ReadPhysical failed at address: 0x" + std::to_string(cur_addr) + ", requested: " + std::to_string(to_read));
            }
            else {
                log_to_file("Partial read at address: 0x" + std::to_string(cur_addr) + ", driver bytes: " + std::to_string(bytes_read));
            }
            if (user_read == 0) {
                log_to_file("ReadProcessMemory also failed at address: 0x" + std::to_string(cur_addr));
                set_color(con, CLR_BAD);
                std::cout << "[!] Unmapped/blank page at 0x" << std::hex << cur_addr << std::dec << std::endl;
                set_color(con, CLR_RESET);
                break;
            }
        }
    }

    if (total_read == 0) {
        log_to_file("snag_mem failed to read any bytes at address: 0x" + std::to_string(addr));
        return false;
    }

    if (total_read < sz) {
        log_to_file("Partial read: requested " + std::to_string(sz) + " got " + std::to_string(total_read));
    } else {
        log_to_file("ReadPhysical succeeded for size: " + std::to_string(sz));
    }
    return true;
}

void patch_pe(std::vector<char>& dump) {
    log_to_file("Patching PE headers for dump.");
    if (dump.empty()) {
        log_to_file("Dump is empty, cannot patch PE.");
        return;
    }
    // Ensure dump has at least enough data for DOS and NT headers
    if (dump.size() < sizeof(IMAGE_DOS_HEADER) + sizeof(IMAGE_NT_HEADERS64)) {
        log_to_file("Dump size too small for PE headers. Size: " + std::to_string(dump.size()));
        return;
    }
    // Access DOS header safely
    PIMAGE_DOS_HEADER dos_hdr = reinterpret_cast<PIMAGE_DOS_HEADER>(dump.data());
    if (dos_hdr->e_magic != IMAGE_DOS_SIGNATURE) {
        log_to_file("Invalid DOS signature in dump: 0x" + std::to_string(dos_hdr->e_magic));
        return;
    }
    // Calculate offset to NT headers
    size_t nt_offset = dos_hdr->e_lfanew;
    if (nt_offset + sizeof(IMAGE_NT_HEADERS64) > dump.size()) {
        log_to_file("NT headers offset exceeds dump size. Offset: " + std::to_string(nt_offset) + ", Dump size: " + std::to_string(dump.size()));
        return;
    }
    PIMAGE_NT_HEADERS64 nt_hdr = reinterpret_cast<PIMAGE_NT_HEADERS64>(dump.data() + nt_offset);
    if (nt_hdr->Signature != IMAGE_NT_SIGNATURE) {
        log_to_file("Invalid NT signature in dump: 0x" + std::to_string(nt_hdr->Signature));
        return;
    }
    log_to_file("Patching PE with " + std::to_string(nt_hdr->FileHeader.NumberOfSections) + " sections.");
    // Minimal patching for now to avoid crashes (add specific fixes here if needed)
    log_to_file("PE headers validated, minimal patching applied to avoid crashes.");
}

int main() {
    HANDLE con = GetStdHandle(STD_OUTPUT_HANDLE);
    set_color(con, CLR_RESET);

    set_color(con, CLR_INPUT);
    std::cout << "[?] Enable verbose debugging? (y/n): ";
    std::string dbg_choice;
    std::getline(std::cin, dbg_choice);
    if (!dbg_choice.empty() && (dbg_choice[0] == 'y' || dbg_choice[0] == 'Y')) {
        g_verbose_debug = true;
        log_to_file("Verbose debugging enabled.");
    }
    else {
        g_verbose_debug = false;
    }

    log_to_file("Starting Neptune Memory Dumper.");

    set_color(con, CLR_NOTE);
    std::cout << "[*] Initializing driver..." << std::endl;
    log_to_file("Initializing driver connection.");
    if (!PaysonDRV::Init()) {
        set_color(con, CLR_BAD);
        std::cerr << "[!] Driver init failed!" << std::endl;
        log_to_file("Driver initialization failed.");
        set_color(con, CLR_RESET);
        return 1;
    }
    set_color(con, CLR_GOOD);
    std::cout << "[+] Driver Loaded!" << std::endl;
    std::cout << std::endl;
    log_to_file("Driver connection successful.");

    // Get process name input
    set_color(con, CLR_INPUT);
    std::cout << "[>] Enter exe name (with .exe): ";
    std::string proc_name;
    std::getline(std::cin, proc_name);
    log_to_file("User input received: " + proc_name);

    // Get PID
    DWORD pid = grab_pid(proc_name);
    if (pid == 0) {
        set_color(con, CLR_BAD);
        std::cerr << "[!] Process not found: " << proc_name << std::endl;
        set_color(con, CLR_RESET);
        return 1;
    }
    set_color(con, CLR_GOOD);
    std::cout << "[+] PID: " << pid << std::endl;
    std::cout << std::endl;

    // Open process handle
    set_color(con, CLR_NOTE);
    std::cout << "[*] Opening process..." << std::endl;
    log_to_file("Opening process with PID: " + std::to_string(pid));
    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (hProc == NULL) {
        set_color(con, CLR_BAD);
        std::cerr << "[!] Open process failed: " << GetLastError() << std::endl;
        log_to_file("Failed to open process, error: " + std::to_string(GetLastError()));
        set_color(con, CLR_RESET);
        return 1;
    }
    set_color(con, CLR_GOOD);
    std::cout << "[+] Handle acquired!" << std::endl;
    std::cout << std::endl;
    log_to_file("Process opened successfully.");

    // Grab base address via driver or fallback
    set_color(con, CLR_NOTE);
    std::cout << "[*] Getting base addr..." << std::endl;
    log_to_file("Fetching base address via driver for PID: " + std::to_string(pid));
    ULONG64 base_addr = PaysonDRV::GetBaseAddress();
    log_to_file("GetBaseAddress returned: 0x" + std::to_string(base_addr));
    if (!base_addr) {
        set_color(con, CLR_BAD);
        std::cerr << "[!] Base addr fetch failed via driver. Attempting fallback method..." << std::endl;
        log_to_file("Failed to get base address via driver. Falling back to user-mode API.");
        HMODULE hMods[1024];
        DWORD cbNeeded;
        base_addr = 0;
        if (EnumProcessModules(hProc, hMods, sizeof(hMods), &cbNeeded)) {
            base_addr = (ULONG64)hMods[0];
            log_to_file("Fallback successful: Base address via EnumProcessModules: 0x" + std::to_string(base_addr));
            set_color(con, CLR_NOTE);
            std::cout << "[*] Fallback success: Base at 0x" << std::hex << base_addr << std::endl;
        }
        else {
            set_color(con, CLR_BAD);
            std::cerr << "[!] Fallback failed: Unable to get base address: " << GetLastError() << std::endl;
            log_to_file("Fallback failed, EnumProcessModules error: " + std::to_string(GetLastError()));
            set_color(con, CLR_RESET);
            CloseHandle(hProc);
            return 1;
        }
    }
    set_color(con, CLR_GOOD);
    std::cout << "[+] Base at 0x" << std::hex << base_addr << std::endl;
    std::cout << std::endl;
    log_to_file("Base address retrieved: 0x" + std::to_string(base_addr));

    // Pause for runtime decryption if needed
    set_color(con, CLR_NOTE);
    std::cout << "[*] Waiting for runtime decryption (if any). Press Enter to continue dumping..." << std::endl;
    log_to_file("Waiting for user confirmation to allow runtime decryption.");
    std::cin.get();
    log_to_file("User confirmed, proceeding with dump.");

    // Enumerate and dump PE sections
    set_color(con, CLR_NOTE);
    std::cout << "[*] Enumerating PE sections for comprehensive dump..." << std::endl;
    log_to_file("Starting PE section enumeration for PID: " + std::to_string(pid));

    // Read PE headers to get section info
    std::vector<char> pe_header;
    ULONG header_read_size = 0x1000;
    if (!snag_mem(hProc, base_addr, header_read_size, pe_header)) {
        set_color(con, CLR_BAD);
        std::cerr << "[!] Failed to read PE headers for section info." << std::endl;
        log_to_file("Failed to read PE headers at base: 0x" + std::to_string(base_addr));
        CloseHandle(hProc);
        return 1;
    }

    // Parse PE headers to get section table (simplified, assumes 64-bit PE)
    PIMAGE_DOS_HEADER dos_hdr = reinterpret_cast<PIMAGE_DOS_HEADER>(pe_header.data());
    if (dos_hdr->e_magic != IMAGE_DOS_SIGNATURE) {
        set_color(con, CLR_BAD);
        std::cerr << "[!] Invalid DOS signature in PE header." << std::endl;
        log_to_file("Invalid DOS signature in PE header: 0x" + std::to_string(dos_hdr->e_magic));
        CloseHandle(hProc);
        return 1;
    }
    PIMAGE_NT_HEADERS64 nt_hdr = reinterpret_cast<PIMAGE_NT_HEADERS64>(pe_header.data() + dos_hdr->e_lfanew);
    if (nt_hdr->Signature != IMAGE_NT_SIGNATURE) {
        set_color(con, CLR_BAD);
        std::cerr << "[!] Invalid NT signature in PE header." << std::endl;
        log_to_file("Invalid NT signature in PE header: 0x" + std::to_string(nt_hdr->Signature));
        CloseHandle(hProc);
        return 1;
    }

    // If headers are larger than what we read, fetch the full header region
    if (nt_hdr->OptionalHeader.SizeOfHeaders > pe_header.size()) {
        header_read_size = nt_hdr->OptionalHeader.SizeOfHeaders;
        if (!snag_mem(hProc, base_addr, header_read_size, pe_header)) {
            set_color(con, CLR_BAD);
            std::cerr << "[!] Failed to read full PE headers." << std::endl;
            log_to_file("Failed to read extended PE headers. Size requested: " + std::to_string(header_read_size));
            CloseHandle(hProc);
            return 1;
        }
        dos_hdr = reinterpret_cast<PIMAGE_DOS_HEADER>(pe_header.data());
        nt_hdr = reinterpret_cast<PIMAGE_NT_HEADERS64>(pe_header.data() + dos_hdr->e_lfanew);
    }

    auto align_up = [](ULONG value, ULONG align) -> ULONG {
        if (align == 0) return value;
        return (value + align - 1) / align * align;
    };

    PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(nt_hdr);
    log_to_file("Found " + std::to_string(nt_hdr->FileHeader.NumberOfSections) + " sections.");

    // Dump memory for each section
    ULONG file_align = nt_hdr->OptionalHeader.FileAlignment ? nt_hdr->OptionalHeader.FileAlignment : 0x200;

    struct SectionDump {
        IMAGE_SECTION_HEADER header;
        std::vector<char> data;
    };
    std::vector<SectionDump> section_dumps;
    section_dumps.reserve(nt_hdr->FileHeader.NumberOfSections);

    for (int i = 0; i < nt_hdr->FileHeader.NumberOfSections; ++i) {
        PIMAGE_SECTION_HEADER sec = &sections[i];
        ULONG64 sec_addr = base_addr + sec->VirtualAddress;
        ULONG sec_size = std::max(sec->Misc.VirtualSize, sec->SizeOfRawData);
        std::string sec_name(reinterpret_cast<char*>(sec->Name), 8);
        log_to_file("Dumping section " + sec_name + " at 0x" + std::to_string(sec_addr) + ", size: " + std::to_string(sec_size));
        std::vector<char> sec_data;
        if (!snag_mem(hProc, sec_addr, sec_size, sec_data)) {
            log_to_file("Failed to dump section " + sec_name);
            set_color(con, CLR_BAD);
            std::cerr << "[!] Failed to dump section: " << sec_name << std::endl;
        }
        else {
            SectionDump dump_entry{};
            dump_entry.header = *sec;
            dump_entry.data = std::move(sec_data);
            section_dumps.push_back(std::move(dump_entry));
        }
    }

    // Build on-disk image with raw section layout
    ULONG headers_aligned = align_up(nt_hdr->OptionalHeader.SizeOfHeaders, file_align);
    std::vector<char> full_dump(headers_aligned, 0);
    std::copy_n(pe_header.begin(), std::min(pe_header.size(), full_dump.size()), full_dump.begin());

    PIMAGE_DOS_HEADER file_dos = reinterpret_cast<PIMAGE_DOS_HEADER>(full_dump.data());
    PIMAGE_NT_HEADERS64 file_nt = reinterpret_cast<PIMAGE_NT_HEADERS64>(full_dump.data() + file_dos->e_lfanew);
    PIMAGE_SECTION_HEADER file_sections = IMAGE_FIRST_SECTION(file_nt);

    ULONG current_raw = headers_aligned;
    for (size_t i = 0; i < section_dumps.size(); ++i) {
        IMAGE_SECTION_HEADER sec_hdr = section_dumps[i].header;
        ULONG raw_size = align_up(std::max(sec_hdr.SizeOfRawData, sec_hdr.Misc.VirtualSize), file_align);
        ULONG raw_offset = align_up(current_raw, file_align);
        if (raw_offset + raw_size > full_dump.size()) {
            full_dump.resize(raw_offset + raw_size, 0);
        }

        size_t copy_sz = std::min(static_cast<size_t>(raw_size), section_dumps[i].data.size());
        std::copy_n(section_dumps[i].data.begin(), copy_sz, full_dump.begin() + raw_offset);

        sec_hdr.PointerToRawData = raw_offset;
        sec_hdr.SizeOfRawData = raw_size;
        file_sections[i] = sec_hdr;

        current_raw = raw_offset + raw_size;
    }

    file_nt->OptionalHeader.SizeOfHeaders = headers_aligned;

    // Clean relocation directory to avoid bogus fixups
    IMAGE_DATA_DIRECTORY& reloc_dir = file_nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (reloc_dir.VirtualAddress != 0 && reloc_dir.Size != 0) {
        // Find section containing relocations
        PIMAGE_SECTION_HEADER reloc_sec = nullptr;
        for (int i = 0; i < file_nt->FileHeader.NumberOfSections; ++i) {
            ULONG sec_va = file_sections[i].VirtualAddress;
            ULONG sec_vs = std::max(file_sections[i].Misc.VirtualSize, file_sections[i].SizeOfRawData);
            if (reloc_dir.VirtualAddress >= sec_va && reloc_dir.VirtualAddress < sec_va + sec_vs) {
                reloc_sec = &file_sections[i];
                break;
            }
        }

        if (reloc_sec) {
            ULONG sec_offset = reloc_sec->PointerToRawData;
            ULONG reloc_offset = sec_offset + (reloc_dir.VirtualAddress - reloc_sec->VirtualAddress);
            ULONG reloc_end = std::min<ULONG>(static_cast<ULONG>(full_dump.size()), reloc_offset + reloc_dir.Size);

            struct RelocBlock {
                DWORD PageRVA;
                DWORD BlockSize;
            };

            std::vector<uint8_t> cleaned;
            size_t cursor = reloc_offset;
            while (cursor + sizeof(RelocBlock) <= reloc_end) {
                auto* blk = reinterpret_cast<RelocBlock*>(full_dump.data() + cursor);
                if (blk->BlockSize < sizeof(RelocBlock) || cursor + blk->BlockSize > reloc_end)
                    break;

                size_t entry_count = (blk->BlockSize - sizeof(RelocBlock)) / sizeof(WORD);
                std::vector<WORD> entries;
                entries.reserve(entry_count);

                WORD* entry_ptr = reinterpret_cast<WORD*>(full_dump.data() + cursor + sizeof(RelocBlock));
                for (size_t e = 0; e < entry_count; ++e) {
                    WORD entry = entry_ptr[e];
                    WORD type = entry >> 12;
                    if (type == IMAGE_REL_BASED_ABSOLUTE || type == IMAGE_REL_BASED_HIGHLOW || type == IMAGE_REL_BASED_DIR64) {
                        entries.push_back(entry);
                    }
                }

                if (!entries.empty()) {
                    RelocBlock new_blk{};
                    new_blk.PageRVA = blk->PageRVA;
                    new_blk.BlockSize = static_cast<DWORD>(sizeof(RelocBlock) + entries.size() * sizeof(WORD));
                    size_t start = cleaned.size();
                    cleaned.resize(cleaned.size() + new_blk.BlockSize);
                    memcpy(cleaned.data() + start, &new_blk, sizeof(new_blk));
                    memcpy(cleaned.data() + start + sizeof(new_blk), entries.data(), entries.size() * sizeof(WORD));
                }

                cursor += blk->BlockSize;
            }

            if (cleaned.empty()) {
                reloc_dir.VirtualAddress = 0;
                reloc_dir.Size = 0;
            }
            else {
                if (reloc_offset + cleaned.size() > full_dump.size()) {
                    full_dump.resize(reloc_offset + cleaned.size(), 0);
                }
                memcpy(full_dump.data() + reloc_offset, cleaned.data(), cleaned.size());
                reloc_dir.Size = static_cast<DWORD>(cleaned.size());
                reloc_sec->SizeOfRawData = std::max(reloc_sec->SizeOfRawData, reloc_dir.Size);
                reloc_sec->Misc.VirtualSize = std::max(reloc_sec->Misc.VirtualSize, reloc_dir.Size);
            }
        }
        else {
            reloc_dir.VirtualAddress = 0;
            reloc_dir.Size = 0;
        }
    }

    // Proceed with writing full_dump to file
    set_color(con, CLR_GOOD);
    std::cout << "[+] Sections dumped, proceeding..." << std::endl;

    // Patch PE headers if needed
    set_color(con, CLR_NOTE);
    std::cout << "[*] Patching PE..." << std::endl;
    patch_pe(full_dump);

    // Write dump to file
    set_color(con, CLR_NOTE);
    std::cout << "[*] Writing dump..." << std::endl;
    log_to_file("Writing memory dump to file.");
    std::ofstream outfile("MemoryDump.exe", std::ios::binary);
    if (!outfile) {
        set_color(con, CLR_BAD);
        std::cerr << "[!] Failed to open output file!" << std::endl;
        log_to_file("Failed to create output file: MemoryDump.exe");
        CloseHandle(hProc);
        return 1;
    }
    outfile.write(full_dump.data(), full_dump.size());
    outfile.close();
    set_color(con, CLR_GOOD);
    std::cout << "[+] Dump saved as MemoryDump.exe!" << std::endl;
    std::cout << std::endl;
    log_to_file("Memory dump saved as MemoryDump.exe, size: " + std::to_string(full_dump.size()) + " bytes.");

    // Cleanup
    set_color(con, CLR_NOTE);
    std::cout << "[*] Wrapping up..." << std::endl;
    log_to_file("Cleaning up resources.");
    CloseHandle(hProc);
    set_color(con, CLR_GOOD);
    std::cout << "[+] All done, enjoy!" << std::endl;
    std::cout << std::endl;
    log_to_file("Dumper execution completed.");
    set_color(con, CLR_RESET);
    log_to_file("");
    log_to_file("Thanks for using Neptune Mem Dumper!");
    log_to_file("Made By Payson - github.com/paysonism");
    system("pause"); // Pause to prevent console from closing
    return 0;
}
