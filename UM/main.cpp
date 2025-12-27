#define NOMINMAX
#include <windows.h>
#include <psapi.h>
#include <winnt.h>
#include <iostream>
#include <string>
#include <vector>
#include <fstream>
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
HANDLE con;

void set_color(HANDLE handle, int color) {
    SetConsoleTextAttribute(handle, color);
}

void log_to_file(const std::string& message) {
    if (!g_verbose_debug)
        return;

    std::ofstream logfile("log.txt", std::ios::app);
    if (logfile)
        logfile << "[DEBUG] " << message << std::endl;
}

DWORD grab_pid(const std::string& proc_name) {
    int size_needed = MultiByteToWideChar(CP_UTF8, 0, proc_name.c_str(), -1, nullptr, 0);
    std::wstring wname(size_needed, 0);
    MultiByteToWideChar(CP_UTF8, 0, proc_name.c_str(), -1, &wname[0], size_needed);

    return PaysonDRV::FindProcessID(wname.c_str());
}

bool snag_mem(HANDLE hproc, ULONG64 addr, ULONG size, std::vector<char>& out) {
    out.assign(size, 0);

    const ULONG chunk = 0x1000;
    ULONG total = 0;

    while (total < size) {
        ULONG to_read = std::min(chunk, size - total);
        DWORD bytes_read = 0;
        ULONG64 cur = addr + total;

        if (PaysonDRV::ReadPhysical((PVOID)cur, out.data() + total, to_read, &bytes_read) && bytes_read == to_read) {
            total += bytes_read;
            continue;
        }

        DWORD user_read = 0; 
        if (PaysonDRV::ReadPhysical((PVOID)cur, out.data() + total, to_read, &user_read) && user_read) {
            total += static_cast<ULONG>(user_read);
        }
        else {
            set_color(con, CLR_BAD);
            std::cout << "[!] unmapped page at 0x" << std::hex << cur << std::dec << std::endl;
            set_color(con, CLR_RESET);
            break;
        }
    }

    return total != 0;
}

void patch_pe(std::vector<char>& dump) {
    if (dump.size() < sizeof(IMAGE_DOS_HEADER) + sizeof(IMAGE_NT_HEADERS64))
        return;

    auto dos = reinterpret_cast<PIMAGE_DOS_HEADER>(dump.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
        return;

    auto nt = reinterpret_cast<PIMAGE_NT_HEADERS64>(dump.data() + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE)
        return;
}

int main() {
    con = GetStdHandle(STD_OUTPUT_HANDLE);
    set_color(con, CLR_RESET);

    set_color(con, CLR_INPUT);
    std::cout << "[?] enable verbose debugging? (y/n): ";
    std::string dbg;
    std::getline(std::cin, dbg);
    g_verbose_debug = !dbg.empty() && (dbg[0] == 'y' || dbg[0] == 'Y');

    set_color(con, CLR_NOTE);
    std::cout << "[*] initializing driver..." << std::endl;
    if (!PaysonDRV::Init()) {
        set_color(con, CLR_BAD);
        std::cerr << "[!] driver init failed" << std::endl;
        return 1;
    }

    set_color(con, CLR_GOOD);
    std::cout << "[+] driver loaded" << std::endl << std::endl;

    set_color(con, CLR_INPUT);
    std::cout << "[>] enter exe name: ";
    std::string proc;
    std::getline(std::cin, proc);

    DWORD pid = grab_pid(proc);
    if (!pid) {
        set_color(con, CLR_BAD);
        std::cerr << "[!] process not found" << std::endl;
        return 1;
    }

    HANDLE hproc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hproc) {
        set_color(con, CLR_BAD);
        std::cerr << "[!] OpenProcess failed" << std::endl;
        return 1;
    }

    ULONG64 base = PaysonDRV::GetBaseAddress();
    if (!base) {
        HMODULE mods[1024];
        DWORD needed;
        if (EnumProcessModules(hproc, mods, sizeof(mods), &needed))
            base = reinterpret_cast<ULONG64>(mods[0]);
        else
            return 1;
    }

    set_color(con, CLR_NOTE);
    std::cout << "[*] press enter to dump..." << std::endl;
    std::cin.get();

    std::vector<char> pe;
    if (!snag_mem(hproc, base, 0x1000, pe))
        return 1;

    auto dos = reinterpret_cast<PIMAGE_DOS_HEADER>(pe.data());
    auto nt = reinterpret_cast<PIMAGE_NT_HEADERS64>(pe.data() + dos->e_lfanew);

    auto align_up = [](ULONG v, ULONG a) {
        return a ? (v + a - 1) / a * a : v;
        };

    struct section_dump {
        IMAGE_SECTION_HEADER header;
        std::vector<char> data;
    };

    std::vector<section_dump> dumps;
    auto sections = IMAGE_FIRST_SECTION(nt);

    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        auto& s = sections[i];
        ULONG size = std::max(s.Misc.VirtualSize, s.SizeOfRawData);
        std::vector<char> data;
        if (snag_mem(hproc, base + s.VirtualAddress, size, data))
            dumps.push_back({ s, std::move(data) });
    }

    ULONG headers = align_up(nt->OptionalHeader.SizeOfHeaders, nt->OptionalHeader.FileAlignment);
    std::vector<char> full(headers, 0);
    std::copy(pe.begin(), pe.end(), full.begin());

    auto file_nt = reinterpret_cast<PIMAGE_NT_HEADERS64>(full.data() + dos->e_lfanew);
    auto file_sec = IMAGE_FIRST_SECTION(file_nt);

    ULONG cur = headers;
    for (size_t i = 0; i < dumps.size(); i++) {
        auto& d = dumps[i];
        ULONG raw = align_up(std::max(d.header.SizeOfRawData, d.header.Misc.VirtualSize), file_nt->OptionalHeader.FileAlignment);
        ULONG off = align_up(cur, file_nt->OptionalHeader.FileAlignment);

        full.resize(off + raw);
        memcpy(full.data() + off, d.data.data(), std::min<size_t>(raw, d.data.size()));

        d.header.PointerToRawData = off;
        d.header.SizeOfRawData = raw;
        file_sec[i] = d.header;
        cur = off + raw;
    }

    patch_pe(full);

    std::ofstream out("MemoryDump.exe", std::ios::binary);
    out.write(full.data(), full.size());
    out.close();

    set_color(con, CLR_GOOD);
    std::cout << "[+] dump saved as MemoryDump.exe" << std::endl;

    CloseHandle(hproc);
    set_color(con, CLR_RESET);
    std::cin.get();
}
