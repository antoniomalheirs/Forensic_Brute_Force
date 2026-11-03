#ifndef CRC32_H
#define CRC32_H

#include <cstdint>
#include <string>

// IEEE 802.3 CRC32 Checksum (Standard Ethernet / ZIP / PNG)
inline std::string crc32(const std::string &input) {
    static const uint32_t table[16] = {
        0x00000000, 0x1DB71064, 0x3B6E20C8, 0x26D930AC,
        0x76DC4190, 0x6B6B51F4, 0x4DB26158, 0x5005713C,
        0xEDB88320, 0xF00F9344, 0xD6D6A3E8, 0xCB61B38C,
        0x9B64C2B0, 0x86D3D2D4, 0xA00AE278, 0xBDBDF21C
    };

    uint32_t crc = ~0u;
    for (unsigned char c : input) {
        crc = (crc >> 4) ^ table[(crc ^ c) & 0x0F];
        crc = (crc >> 4) ^ table[(crc ^ (c >> 4)) & 0x0F];
    }
    crc = ~crc;

    static const char hexChars[] = "0123456789abcdef";
    char buf[9];
    for (int i = 0; i < 4; i++) {
        uint8_t byte = (crc >> (24 - i * 8)) & 0xFF;
        buf[i * 2]     = hexChars[(byte >> 4) & 0x0F];
        buf[i * 2 + 1] = hexChars[byte & 0x0F];
    }
    buf[8] = '\0';
    return std::string(buf, 8);
}

#endif // CRC32_H
