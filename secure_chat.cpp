/*
  Secure Chat - Manual DES Implementation over TCP (CBC Mode)
  Tugas Keamanan Informasi - Simulasi Transmisi Ciphertext 2 Arah
  Platform: Windows & Linux (C++11)

  Kompilasi:
    Windows (MinGW): g++ secure_chat.cpp -o secure_chat.exe -lws2_32 -std=c++11
    Linux/GCC:       g++ secure_chat.cpp -o secure_chat -pthread -std=c++11

  Cara pakai:
    Server: secure_chat server <port>
    Client: secure_chat client <ip> <port>
*/

#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <cstring>
#include <cstdint>
#include <cstdio>
#include <chrono>
#include <random>

#ifdef _WIN32
  #ifndef WIN32_LEAN_AND_MEAN
  #define WIN32_LEAN_AND_MEAN
  #endif
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #pragma comment(lib, "ws2_32.lib")
  typedef int socklen_t;
#else
  #include <sys/socket.h>
  #include <netinet/in.h>
  #include <arpa/inet.h>
  #include <unistd.h>
  #include <netdb.h>
  typedef int SOCKET;
  #define INVALID_SOCKET -1
  #define SOCKET_ERROR -1
  #define closesocket close
#endif

using u8  = uint8_t;
using u16 = uint16_t;
using u32 = uint32_t;
using u64 = uint64_t;

// ============================================================================
// MANUAL DES IMPLEMENTATION (No external crypto libraries)
// ============================================================================

// DES Tables (1-based indexes in literature; handled by bit extractor)
static const u8 IP_TBL[64] = {
    58,50,42,34,26,18,10,2,
    60,52,44,36,28,20,12,4,
    62,54,46,38,30,22,14,6,
    64,56,48,40,32,24,16,8,
    57,49,41,33,25,17,9,1,
    59,51,43,35,27,19,11,3,
    61,53,45,37,29,21,13,5,
    63,55,47,39,31,23,15,7
};

static const u8 FP_TBL[64] = {
    40,8,48,16,56,24,64,32,
    39,7,47,15,55,23,63,31,
    38,6,46,14,54,22,62,30,
    37,5,45,13,53,21,61,29,
    36,4,44,12,52,20,60,28,
    35,3,43,11,51,19,59,27,
    34,2,42,10,50,18,58,26,
    33,1,41,9,49,17,57,25
};

static const u8 E_TBL[48] = {
    32,1,2,3,4,5,
    4,5,6,7,8,9,
    8,9,10,11,12,13,
    12,13,14,15,16,17,
    16,17,18,19,20,21,
    20,21,22,23,24,25,
    24,25,26,27,28,29,
    28,29,30,31,32,1
};

static const u8 P_TBL[32] = {
    16,7,20,21,29,12,28,17,
    1,15,23,26,5,18,31,10,
    2,8,24,14,32,27,3,9,
    19,13,30,6,22,11,4,25
};

static const u8 PC1_TBL[56] = {
    57,49,41,33,25,17,9,
    1,58,50,42,34,26,18,
    10,2,59,51,43,35,27,
    19,11,3,60,52,44,36,
    63,55,47,39,31,23,15,
    7,62,54,46,38,30,22,
    14,6,61,53,45,37,29,
    21,13,5,28,20,12,4
};

static const u8 PC2_TBL[48] = {
    14,17,11,24,1,5,
    3,28,15,6,21,10,
    23,19,12,4,26,8,
    16,7,27,20,13,2,
    41,52,31,37,47,55,
    30,40,51,45,33,48,
    44,49,39,56,34,53,
    46,42,50,36,29,32
};

static const u8 SHIFT_TBL[16] = {
    1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1
};

static const u8 SBOX[8][64] = {
    { // S1
      14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7,
      0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8,
      4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0,
      15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13
    },
    { // S2
      15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10,
      3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5,
      0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15,
      13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9
    },
    { // S3
      10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8,
      13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1,
      13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7,
      1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12
    },
    { // S4
      7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15,
      13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9,
      10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4,
      3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14
    },
    { // S5
      2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9,
      14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6,
      4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14,
      11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3
    },
    { // S6
      12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11,
      10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8,
      9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6,
      4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13
    },
    { // S7
      4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1,
      13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6,
      1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2,
      6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12
    },
    { // S8
      13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7,
      1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2,
      7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8,
      2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11
    }
};

// Permute 'in' (u64, DES bit 1 at bit 63) using table of length n
// Output is right-aligned in lower n bits of returned u64.
static u64 permute(u64 in, const u8* tbl, int n) {
    u64 out = 0;
    for (int i = 0; i < n; ++i) {
        int src = tbl[i];                 // 1-indexed DES bit position in input
        u64 bit = (in >> (64 - src)) & 1ULL;
        out |= (bit << (n - 1 - i));
    }
    return out;
}

static u32 rotateLeft28(u32 val, int n) {
    return ((val << n) | (val >> (28 - n))) & 0x0FFFFFFFu;
}

// DES F-function: R (32-bit), K (48-bit)
static u32 des_f(u32 R, u64 K48) {
    // Expansion E: place R into high 32 bits of u64 for permute()
    u64 r64 = (static_cast<u64>(R) << 32);
    u64 e48 = permute(r64, E_TBL, 48);
    u64 x = e48 ^ K48;

    // S-Box substitution
    u32 sout = 0;
    for (int i = 0; i < 8; ++i) {
        u8 six = static_cast<u8>((x >> (42 - 6 * i)) & 0x3FULL);
        int row = ((six >> 5) & 1) * 2 + (six & 1);
        int col = (six >> 1) & 0x0F;
        u8 val = SBOX[i][row * 16 + col];
        sout |= (static_cast<u32>(val) << (28 - 4 * i));
    }

    // Permutation P
    u64 sout64 = (static_cast<u64>(sout) << 32);
    return static_cast<u32>(permute(sout64, P_TBL, 32));
}

// Generate 16 round keys (48-bit each) from 64-bit master key
static void des_key_schedule(const u8 master[8], u64 rk[16]) {
    u64 key64 = 0;
    for (int i = 0; i < 8; ++i)
        key64 = (key64 << 8) | static_cast<u64>(master[i]);

    u64 pc1 = permute(key64, PC1_TBL, 56);
    u32 C = static_cast<u32>((pc1 >> 28) & 0x0FFFFFFFu);
    u32 D = static_cast<u32>(pc1 & 0x0FFFFFFFu);

    for (int i = 0; i < 16; ++i) {
        int s = SHIFT_TBL[i];
        C = rotateLeft28(C, s);
        D = rotateLeft28(D, s);
        u64 cd = (static_cast<u64>(C) << 28) | static_cast<u64>(D);
        rk[i] = permute(cd << 8, PC2_TBL, 48);
    }
}

// Single DES block: encrypt if decrypt==false, decrypt if true
static void des_block(const u8 in[8], const u64 rk[16], bool decrypt, u8 out[8]) {
    u64 block = 0;
    for (int i = 0; i < 8; ++i)
        block = (block << 8) | static_cast<u64>(in[i]);

    u64 ip = permute(block, IP_TBL, 64);
    u32 L = static_cast<u32>(ip >> 32);
    u32 R = static_cast<u32>(ip & 0xFFFFFFFFu);

    for (int r = 0; r < 16; ++r) {
        int ki = decrypt ? (15 - r) : r;
        u32 newR = L ^ des_f(R, rk[ki]);
        L = R;
        R = newR;
    }

    // Final swap
    u64 preout = (static_cast<u64>(R) << 32) | static_cast<u64>(L);
    u64 fp = permute(preout, FP_TBL, 64);

    for (int i = 0; i < 8; ++i)
        out[i] = static_cast<u8>(fp >> (56 - i * 8));
}

// ============================================================================
// CBC MODE using manual DES
// ============================================================================

static void des_cbc_encrypt(const std::vector<u8>& plain, const u64 rk[16],
                            const u8 iv[8], std::vector<u8>& cipher) {
    cipher.clear();
    cipher.reserve(plain.size());
    u8 prev[8];
    std::memcpy(prev, iv, 8);
    size_t blocks = plain.size() / 8;
    for (size_t i = 0; i < blocks; ++i) {
        u8 in[8], out[8];
        for (int j = 0; j < 8; ++j)
            in[j] = plain[i * 8 + j] ^ prev[j];
        des_block(in, rk, false, out);
        std::memcpy(prev, out, 8);
        cipher.insert(cipher.end(), out, out + 8);
    }
}

static void des_cbc_decrypt(std::vector<u8>& plain, const u64 rk[16],
                            const u8 iv[8], const std::vector<u8>& cipher) {
    plain.clear();
    plain.reserve(cipher.size());
    u8 prev[8];
    std::memcpy(prev, iv, 8);
    size_t blocks = cipher.size() / 8;
    for (size_t i = 0; i < blocks; ++i) {
        u8 tmp[8], out[8];
        for (int j = 0; j < 8; ++j)
            tmp[j] = cipher[i * 8 + j];
        des_block(tmp, rk, true, out);
        for (int j = 0; j < 8; ++j)
            out[j] ^= prev[j];
        std::memcpy(prev, tmp, 8);
        plain.insert(plain.end(), out, out + 8);
    }
}

// ============================================================================
// NETWORK UTILITIES
// ============================================================================

static bool initSockets() {
#ifdef _WIN32
    WSADATA wsa;
    return WSAStartup(MAKEWORD(2, 2), &wsa) == 0;
#else
    return true;
#endif
}

static void cleanupSockets() {
#ifdef _WIN32
    WSACleanup();
#endif
}

static bool sendAll(SOCKET s, const u8* buf, int len) {
    int total = 0;
    while (total < len) {
        int sent = send(s, reinterpret_cast<const char*>(buf) + total, len - total, 0);
        if (sent == SOCKET_ERROR) return false;
        total += sent;
    }
    return true;
}

static bool recvAll(SOCKET s, u8* buf, int len) {
    int total = 0;
    while (total < len) {
        int r = recv(s, reinterpret_cast<char*>(buf) + total, len - total, 0);
        if (r <= 0) return false;
        total += r;
    }
    return true;
}

// ============================================================================
// PACKET FORMAT: [IV:8][numBlocks:4][ciphertext:N]
// ============================================================================

static std::vector<u8> packPlaintext(const std::string& msg) {
    u32 len = static_cast<u32>(msg.size());
    std::vector<u8> v(4 + len);
    v[0] = static_cast<u8>( len        & 0xFF);
    v[1] = static_cast<u8>((len >> 8)  & 0xFF);
    v[2] = static_cast<u8>((len >> 16) & 0xFF);
    v[3] = static_cast<u8>((len >> 24) & 0xFF);
    std::memcpy(v.data() + 4, msg.data(), len);
    while (v.size() % 8 != 0) v.push_back(0);
    return v;
}

static std::string unpackPlaintext(const std::vector<u8>& v) {
    if (v.size() < 4) return "";
    u32 len = (static_cast<u32>(v[0]))        |
              (static_cast<u32>(v[1]) << 8)  |
              (static_cast<u32>(v[2]) << 16) |
              (static_cast<u32>(v[3]) << 24);
    if (len + 4 > v.size()) return "";
    return std::string(reinterpret_cast<const char*>(v.data()) + 4, len);
}

// ============================================================================
// SHARED KEY (pre-shared / hardcoded; NEVER sent over network)
// ============================================================================
static const char* MASTER_KEY_STR = "KELOMPOK1";  // shared secret

static void deriveMasterKey(const char* str, u8 out[8]) {
    std::memset(out, 0, 8);
    size_t n = std::strlen(str);
    for (size_t i = 0; i < n; ++i)
        out[i % 8] ^= static_cast<u8>(str[i]);
}

// ============================================================================
// APPLICATION LOGIC
// ============================================================================
static std::mutex g_printMutex;

static void senderLoop(SOCKET peer) {
    u8 key[8];
    deriveMasterKey(MASTER_KEY_STR, key);
    u64 rk[16];
    des_key_schedule(key, rk);

    std::string line;
    while (true) {
        std::cout << "[You]> ";
        std::getline(std::cin, line);
        if (line == "exit") break;

        std::vector<u8> plain = packPlaintext(line);

        // Random IV per message
        u8 iv[8];
        std::mt19937 rng(static_cast<unsigned>(
            std::chrono::steady_clock::now().time_since_epoch().count()));
        for (int i = 0; i < 8; ++i)
            iv[i] = static_cast<u8>(rng());

        std::vector<u8> cipher;
        des_cbc_encrypt(plain, rk, iv, cipher);
        u32 numBlocks = static_cast<u32>(cipher.size() / 8);

        {
            std::lock_guard<std::mutex> lock(g_printMutex);
            std::cout << "[TX] Ciphertext (hex): ";
            size_t limit = cipher.size() > 40 ? 40 : cipher.size();
            for (size_t i = 0; i < limit; ++i)
                printf("%02X", cipher[i]);
            if (cipher.size() > limit) std::cout << "...";
            std::cout << " (" << numBlocks << " blocks)\n";
        }

        u8 hdr[12];
        std::memcpy(hdr, iv, 8);
        hdr[8]  = static_cast<u8>( numBlocks        & 0xFF);
        hdr[9]  = static_cast<u8>((numBlocks >> 8)  & 0xFF);
        hdr[10] = static_cast<u8>((numBlocks >> 16) & 0xFF);
        hdr[11] = static_cast<u8>((numBlocks >> 24) & 0xFF);

        if (!sendAll(peer, hdr, 12)) break;
        if (!sendAll(peer, cipher.data(), static_cast<int>(cipher.size()))) break;
    }
}

static void receiverLoop(SOCKET peer) {
    u8 key[8];
    deriveMasterKey(MASTER_KEY_STR, key);
    u64 rk[16];
    des_key_schedule(key, rk);

    while (true) {
        u8 hdr[12];
        if (!recvAll(peer, hdr, 12)) break;

        u8 iv[8];
        std::memcpy(iv, hdr, 8);
        u32 numBlocks = (static_cast<u32>(hdr[8]))         |
                        (static_cast<u32>(hdr[9])  << 8)  |
                        (static_cast<u32>(hdr[10]) << 16) |
                        (static_cast<u32>(hdr[11]) << 24);
        if (numBlocks == 0 || numBlocks > 65536) break;

        std::vector<u8> cipher(static_cast<size_t>(numBlocks) * 8);
        if (!recvAll(peer, cipher.data(), static_cast<int>(cipher.size()))) break;

        std::vector<u8> plain;
        des_cbc_decrypt(plain, rk, iv, cipher);
        std::string msg = unpackPlaintext(plain);

        std::lock_guard<std::mutex> lock(g_printMutex);
        std::cout << "\n[Peer]> " << msg << "\n[You]> " << std::flush;
    }
}

static SOCKET createListener(int port) {
    SOCKET s = socket(AF_INET, SOCK_STREAM, 0);
    if (s == INVALID_SOCKET) return INVALID_SOCKET;
    int opt = 1;
#ifdef _WIN32
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR,
               reinterpret_cast<const char*>(&opt), sizeof(opt));
#else
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
#endif
    sockaddr_in addr;
    std::memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(static_cast<u16>(port));
    if (bind(s, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == SOCKET_ERROR) {
        closesocket(s);
        return INVALID_SOCKET;
    }
    if (listen(s, 1) == SOCKET_ERROR) {
        closesocket(s);
        return INVALID_SOCKET;
    }
    return s;
}

static SOCKET connectTo(const char* ip, int port) {
    SOCKET s = socket(AF_INET, SOCK_STREAM, 0);
    if (s == INVALID_SOCKET) return INVALID_SOCKET;
    sockaddr_in addr;
    std::memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(static_cast<u16>(port));
    addr.sin_addr.s_addr = inet_addr(ip);
    if (connect(s, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == SOCKET_ERROR) {
        closesocket(s);
        return INVALID_SOCKET;
    }
    return s;
}

// ============================================================================
// MAIN
// ============================================================================

int main(int argc, char** argv) {
    if (argc < 3) {
        std::cerr << "Usage:\n"
                  << "  Server: " << argv[0] << " server <port>\n"
                  << "  Client: " << argv[0] << " client <ip> <port>\n";
        return 1;
    }

    if (!initSockets()) {
        std::cerr << "Failed to initialize sockets\n";
        return 1;
    }

    std::string mode = argv[1];
    SOCKET peer = INVALID_SOCKET;

    if (mode == "server") {
        int port = std::atoi(argv[2]);
        SOCKET listener = createListener(port);
        if (listener == INVALID_SOCKET) {
            std::cerr << "Failed to create listener (port " << port << ")\n";
            cleanupSockets();
            return 1;
        }
        std::cout << "[*] Listening on 0.0.0.0:" << port << " ...\n";
        sockaddr_in clientAddr;
        socklen_t addrlen = sizeof(clientAddr);
        peer = accept(listener, reinterpret_cast<sockaddr*>(&clientAddr), &addrlen);
        closesocket(listener);
        if (peer == INVALID_SOCKET) {
            std::cerr << "Accept failed\n";
            cleanupSockets();
            return 1;
        }
        std::cout << "[*] Peer connected. Start chatting! (type 'exit' to quit)\n";
    } else {
        if (argc < 4) {
            std::cerr << "Usage: " << argv[0] << " client <ip> <port>\n";
            cleanupSockets();
            return 1;
        }
        const char* ip = argv[2];
        int port = std::atoi(argv[3]);
        peer = connectTo(ip, port);
        if (peer == INVALID_SOCKET) {
            std::cerr << "Failed to connect to " << ip << ":" << port << "\n";
            cleanupSockets();
            return 1;
        }
        std::cout << "[*] Connected to " << ip << ":" << port
                  << ". Start chatting! (type 'exit' to quit)\n";
    }

    std::thread rx(receiverLoop, peer);
    senderLoop(peer);

#ifdef _WIN32
    shutdown(peer, SD_BOTH);
#else
    shutdown(peer, SHUT_RDWR);
#endif
    closesocket(peer);
    rx.join();

    cleanupSockets();
    return 0;
}
