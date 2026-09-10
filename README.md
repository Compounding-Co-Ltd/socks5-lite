# office-proxy

사무실 회선(고정 공인 IP)으로 나가는 **의존성 0짜리 SOCKS5 프록시**.
브라우저 자동화(예: 네이버 블로그 발행)를 이 프록시에 태우면, 상대 서버에는
사무실 IP 로 찍힌다. 접근은 **Tailscale tailnet + Windows 방화벽**으로 이중 제한한다.

```
[클라이언트(Mac 등)] --Tailscale--> [윈도우 office-socks :1080] --사무실 회선--> 인터넷
                                                                    (egress = 사무실 공인 IP)
```

- **무인증** SOCKS5 (tailnet 이 사설망이라 인증 대신 망 + 방화벽으로 차단)
- **원격 DNS**(socks5h) — DNS 까지 프록시 경유
- Node.js 표준 모듈만 사용 (npm 의존성 없음). `3proxy` 는 Windows Defender 가 오탐 차단해서 회피.

---

## 구성 파일

| 파일 | 역할 |
|------|------|
| `office-socks.js` | SOCKS5(CONNECT) 프록시 본체. 기본 `0.0.0.0:1080`, tailnet(100.64.0.0/10)+localhost 만 허용 |
| `start.cmd` | 죽으면 3초 후 자동 재시작하는 무한 루프 래퍼 (Windows) |

환경변수: `PROXY_HOST`(기본 `0.0.0.0`), `PROXY_PORT`(기본 `1080`).

---

## 서버 설치 (Windows)

1. Node.js 설치 (LTS 이상).
2. 이 저장소를 `C:\office-proxy\` 에 둔다 (`office-socks.js`, `start.cmd`).
3. `start.cmd` 안의 node 경로를 실제 경로로 맞춘다 (기본 `C:\Program Files\nodejs\node.exe`).
4. **방화벽 — 1080 인바운드를 tailnet 에서만 허용**:
   ```powershell
   New-NetFirewallRule -DisplayName 'Office SOCKS Proxy (tailnet)' -Direction Inbound `
     -Action Allow -Protocol TCP -LocalPort 1080 -RemoteAddress 100.64.0.0/10
   ```
5. **부팅 시 자동 시작 + 상시 실행 (SYSTEM 스케줄 작업)**:
   ```powershell
   $a = New-ScheduledTaskAction -Execute 'C:\office-proxy\start.cmd'
   $t = New-ScheduledTaskTrigger -AtStartup
   $p = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
   $s = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
        -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) `
        -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew
   Register-ScheduledTask -TaskName 'OfficeSocksProxy' -Action $a -Trigger $t -Principal $p -Settings $s -Force
   Start-ScheduledTask -TaskName 'OfficeSocksProxy'
   ```
6. Tailscale 설치 후 로그인 → 이 머신의 tailnet IP(`100.x.x.x`)가 접속 주소가 된다.

로그는 `C:\office-proxy\proxy.log`. 재시작/리스닝 상태가 남는다.

---

## 클라이언트 사용 (Mac 등)

1. Tailscale 로 같은 tailnet 에 합류(헤드리스 서버면 `tailscaled` 시스템 데몬 권장,
   `tailscale up --accept-dns=false` 로 DNS 는 안 건드림).
2. 자동화가 프록시를 가리키게:
   - Playwright/patchright: `launch({ proxy: { server: 'socks5://<tailscale-ip>:1080' } })`
   - Chrome 직접: `--proxy-server="socks5://<tailscale-ip>:1080"`
   - curl 검증: `curl --socks5-hostname <tailscale-ip>:1080 https://api.ipify.org` → 사무실 공인 IP 가 나오면 성공

---

## 운영 메모

- **fail-closed 권장**: 클라이언트 쪽에서 프록시가 죽었으면 직접 IP 로 폴백하지 말고
  **중단**할 것. (Chromium 은 프록시 불가 시 DIRECT 폴백을 하지 않고 `ERR_PROXY_CONNECTION_FAILED`
  를 낸다 — 새지 않음.)
- **한 IP 다계정 주의**: 같은 프록시 IP 로 여러 계정을 동시에 굴리면 탐지 위험. 계정별로
  IP 를 분리하거나, 같은 IP 에 묶인 계정은 **동시 로그인·작업을 직렬화**할 것.
- **재시작**:
  ```powershell
  Stop-ScheduledTask OfficeSocksProxy; Start-ScheduledTask OfficeSocksProxy
  ```

## 보안

- 무인증이지만 `0.0.0.0` 바인딩 + tailnet 소스 필터(스크립트) + 방화벽(tailnet only)로 삼중 차단.
- 공인망에 이 포트를 직접 노출하지 말 것. 노출이 필요하면 인증을 붙일 것.
