# socks5-lite

**매우 가벼운, 의존성 0짜리 SOCKS5 + HTTP 프록시.** Node.js 표준 모듈만 쓴다(npm 설치 없음).
**한 포트에서 SOCKS5·HTTP 를 자동 감지**해 둘 다 서빙한다(첫 바이트: SOCKS5=0x05, HTTP=메서드).

프록시를 거친 트래픽은 **이 프록시가 도는 호스트의 네트워크로 나간다**(egress = 그 호스트의 IP).
접근 제어는 **신뢰 CIDR(무인증) · IP 화이트리스트 · 토큰 인증 · fail2ban** 을 조합해서 건다.

```
[클라이언트] --(SOCKS5 또는 HTTP)--> [socks5-lite :1080] --호스트 네트워크--> 인터넷
```

- SOCKS5(CONNECT) + HTTP(CONNECT/평문) + **원격 DNS**
- 토큰 인증 — SOCKS5는 user/pass(RFC 1929), HTTP는 `Proxy-Authorization: Basic`
- IP 화이트리스트(와일드카드/CIDR/정확) · fail2ban · 핫리로드
- 설정 없으면 **신뢰 CIDR 전용 + 무인증 + fail2ban on** 으로 동작

> **브라우저 + 토큰**: Chromium 은 SOCKS 인증을 못 하지만 **HTTP 프록시 인증은 된다.**
> 그래서 신뢰대역 밖의 자동화 기기는 **HTTP + 토큰**으로 붙는 게 가장 간단하다
> (Playwright `proxy:{ server:'http://host:port', username, password }` 가 407 을 자동 처리).

---

## 구성 파일

| 파일 | 역할 |
|------|------|
| `socks5.js` | 프록시 본체 |
| `start.cmd` | 죽으면 3초 후 자동 재시작하는 무한 루프 래퍼 (Windows) |
| `config.example.json` | 설정 템플릿. `config.json` 으로 복사해 사용(git 제외됨) |

환경변수: `PROXY_HOST`, `PROXY_PORT`, `PROXY_TOKEN`(auth 비번), `PROXY_CONFIG`(설정 파일 경로).

---

## 실행

```bash
node socks5.js          # 기본 0.0.0.0:1080
```

- 상시 실행이 필요하면 프로세스 매니저(systemd / pm2 / Windows 작업 스케줄러 등)로 띄운다.
- Windows: `start.cmd`(자동 재시작 래퍼)를 작업 스케줄러에 `AtStartup` 으로 등록하면 부팅 시
  자동 시작 + 크래시 자동 복구. 방화벽에서 필요한 소스에만 포트를 열어라.

---

## 접근 제어 (`config.json`)

`socks5.js` 옆의 `config.json` 을 읽고 **핫리로드**한다(3초 폴링 — 껐다 켤 필요 없이 반영).
**파일이 없으면 기본값**으로 동작(신뢰 CIDR 전용 + 무인증).

적용 순서: **① ban 체크 → ② 신뢰 CIDR(무인증) → ③ 화이트리스트 → ④ 토큰 인증**

```jsonc
{
  "host": "0.0.0.0",
  "port": 1080,
  "trusted": {                          // 이 대역에서 오는 연결은 무인증 통과
    "allow": true,
    "cidrs": ["100.64.0.0/10"]          // 사설/오버레이 대역 등. 필요에 맞게 교체
  },
  "auth": {                             // 신뢰 대역 밖 소스에 SOCKS5 user/pass 요구
    "enabled": true,
    "username": "user",
    "password": ""                      // 비우고 PROXY_TOKEN 환경변수로 주입 권장(유출 방지)
  },
  "whitelist": {                        // 켜면 목록 IP만 접속 가능(신뢰 대역 밖). off면 무시.
    "enabled": true,
    "entries": ["10.10.10.*", "203.0.113.5", "198.51.100.0/24"]  // 와일드카드 / 정확IP / CIDR
  },
  "fail2ban": {                         // 토큰 실패 누적 IP 차단
    "enabled": true,
    "maxFails": 5,
    "windowSec": 600,
    "banSec": 3600
  }
}
```

- **신뢰 CIDR** 은 `auth`/`whitelist` 를 켜도 **무인증으로 통과**한다(내부/신뢰 기기용).
  전부 인증 걸려면 `"trusted": { "allow": false }`.
- **화이트리스트 항목**: `10.10.10.*`(와일드카드) · `203.0.113.5`(정확) · `198.51.100.0/24`(CIDR).
- **토큰 인증**: `socks5://user:pass@host:port` (curl 은 `--socks5-hostname user:pass@host:port`,
  Playwright 는 `proxy: { server, username, password }`).

---

## 클라이언트 사용

```bash
# SOCKS5
curl --socks5-hostname <host>:1080 https://api.ipify.org             # 무인증(신뢰 대역)
curl --socks5-hostname user:token@<host>:1080 https://api.ipify.org  # 토큰 인증

# HTTP (같은 포트)
curl -x http://<host>:1080 https://api.ipify.org                     # 무인증(신뢰 대역)
curl -x http://user:token@<host>:1080 https://api.ipify.org          # 토큰 인증
```

Playwright/patchright:
```js
// 신뢰 대역(무인증) — SOCKS/HTTP 아무거나
chromium.launch({ proxy: { server: 'socks5://<host>:1080' } })
// 신뢰 대역 밖(토큰) — HTTP 로 (SOCKS 인증은 Chromium 미지원)
chromium.launch({ proxy: { server: 'http://<host>:1080', username: 'user', password: '<token>' } })
```

---

## 보안

- 무인증은 **신뢰 대역/방화벽으로 접근이 이미 제한된 환경**에서만 안전하다.
- 공인망에 포트를 열 때는 **강한 랜덤 토큰 + (가능하면) 화이트리스트 + 비표준 포트**를 함께 쓰고,
  fail2ban 을 켜 둘 것. 무인증 프록시를 공인망에 그대로 노출하면 오픈 프록시로 악용된다.
