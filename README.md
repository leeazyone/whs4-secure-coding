# Tiny Second-hand Shopping Platform

WhiteHat School 4기 · 시큐어 코딩 과제

유효곤 강사님이 제공한 베이스 코드([ugonfor/secure-coding](https://github.com/ugonfor/secure-coding))를
감사하여 보안 약점을 식별·수정하고, 과제 요구사항에 맞춰 기능을 확장한 중고거래 플랫폼입니다.

---

## 환경 설정

### 요구 사항

- Linux (Ubuntu 22.04에서 개발·검증) 또는 WSL2
- Python 3.10 이상

> **참고 — conda 대신 venv를 사용합니다.**
> 강의 슬라이드는 miniconda를 안내하지만, 최신 conda는 Anaconda 기본 채널의
> 이용약관 동의를 요구합니다. 파이썬 표준 도구인 `venv`는 그런 제약이 없고
> 설정도 단순해 이쪽을 택했습니다.

### 설치

```bash
# 1. 저장소 클론
git clone https://github.com/<사용자명>/secure-coding.git
cd secure-coding

# 2. 가상환경 생성 및 활성화
python3 -m venv .venv
source .venv/bin/activate

# 3. 의존성 설치
pip install -r requirements.txt

# 4. 환경변수 설정
cp .env.example .env
```

### `.env` 설정 (필수)

`SECRET_KEY`를 반드시 채워야 합니다. 비어 있으면 앱이 기동을 거부합니다.

```bash
# 키 생성
python -c "import secrets; print(secrets.token_hex(32))"
```

출력된 값을 `.env`의 `SECRET_KEY=` 뒤에 붙여넣으세요.

| 변수 | 필수 | 기본값 | 설명 |
|---|---|---|---|
| `SECRET_KEY` | **O** | 없음 | 세션 쿠키 서명 키. 미설정 시 기동 거부 |
| `DATABASE` | X | `market.db` | SQLite 파일 경로 |
| `ADMIN_USERNAME` | X | `admin` | 관리자 계정명 |
| `ADMIN_PASSWORD` | X | 임의 생성 | 비워두면 최초 실행 시 생성되어 콘솔에 1회 출력 |
| `FLASK_DEBUG` | X | `0` | `1`이면 디버그 모드. **운영에서 절대 금지** |
| `HTTPS_ONLY` | X | `0` | `1`이면 세션 쿠키에 `Secure` 플래그 적용 |
| `HOST` / `PORT` | X | `127.0.0.1` / `5000` | 바인딩 주소 |
| `ALLOWED_ORIGINS` | X | localhost | Socket.IO 허용 출처 (쉼표 구분) |

> `.env`는 `.gitignore`에 등록되어 있습니다. **절대 커밋하지 마세요.**

---

## 실행

```bash
source .venv/bin/activate
python app.py
```

브라우저에서 <http://127.0.0.1:5000> 접속.

### 최초 실행 시 관리자 계정

`ADMIN_PASSWORD`를 설정하지 않았다면 콘솔에 다음과 같이 **한 번만** 출력됩니다.

```
================================================================
  관리자 계정이 생성되었습니다. 이 비밀번호는 다시 표시되지 않습니다.
    아이디   : admin
    비밀번호 : VeAY0HpBhDbh5trdKpnpgg
================================================================
```

반드시 기록해두세요. 놓쳤다면 `market.db`를 삭제하고 다시 실행하면 됩니다.

### 외부 접속 (ngrok)

```bash
ngrok http 5000
```

발급된 주소를 `.env`의 `ALLOWED_ORIGINS`에 추가하고 `HTTPS_ONLY=1`로 설정하세요.

---

## 테스트

서버를 띄운 상태에서 별도 터미널에서 실행합니다.

```bash
source .venv/bin/activate
pip install requests

# 보안 요구사항 검증 (36개 항목)
python tests/test_security.py

# 송금 경쟁 조건(TOCTOU) 방어 검증
python tests/test_race_condition.py
```

### 대조 실험: 취약한 구현은 어떻게 뚫리는가

`BEGIN IMMEDIATE` 트랜잭션이 왜 필요한지 직접 확인할 수 있습니다.
아래는 본 프로젝트 코드가 아니라, 방어가 없을 때 무슨 일이 벌어지는지
재현하기 위한 독립 데모입니다.

```bash
python tests/demo_vulnerable_transfer.py
```

```
잔액 10,000원 계정에서 10,000원 송금을 동시에 12건 요청

[취약한 구현]                    [본 프로젝트]
성공 12건 / 거부 0건             성공 1건 / 거부 11건
공격자 잔액 -110,000원           공격자 잔액 0원
피해자 수령 120,000원            피해자 수령 10,000원
→ 잔액 1만원으로 12만원 송금      → 정상
```

---

## 구현 기능

### 요구사항 대응

| 요구사항 | 구현 |
|---|---|
| 플랫폼 가입 | 회원가입 / 로그인 / 로그아웃 / 마이페이지 |
| 상품 등록·조회 | 등록 / 목록 / 상세 / 수정 / 삭제 / 내 상품 관리 |
| 사용자 간 소통 | 전체 실시간 채팅 / 1:1 채팅 / 사용자 목록·프로필 |
| 악성 유저·상품 차단 | 신고 / 신고 누적 자동 차단(상품)·휴면 전환(유저) |
| **송금** | 잔액 관리 / 사용자 간 송금 / 거래 내역 / 충전(학습용) |
| **검색** | 상품명·설명 키워드 검색 |
| **관리자** | 통계 / 사용자 관리 / 상품 관리 / 신고 조회 / 감사 로그 |

### 프로젝트 구조

```
secure-coding/
├── app.py                          # 라우트, 설정, Socket.IO 이벤트
├── db.py                           # DB 연결, 트랜잭션, 감사 로그
├── security.py                     # 인증·인가 가드, 입력 검증
├── schema.sql                      # 스키마 (CHECK 제약 포함)
├── requirements.txt
├── .env.example
├── secure_coding_checklist.csv     # 보안 체크리스트 (54개 항목)
├── templates/                      # Jinja2 템플릿
│   └── admin/
├── static/
│   ├── css/style.css
│   └── js/
│       ├── chat.js                 # 채팅 (인라인 스크립트 없음)
│       └── socket.io.min.js        # 로컬 호스팅 (CDN 미사용)
├── tests/
│   ├── test_security.py            # 보안 요구사항 검증
│   ├── test_race_condition.py      # TOCTOU 방어 검증
│   └── demo_vulnerable_transfer.py # 대조군 (취약 구현 재현)
└── docs/
    └── security-log.md             # 취약점 발견·수정 기록 (before/after)
```

---

## 기술 스택

| 구분 | 선택 | 이유 |
|---|---|---|
| 웹 프레임워크 | Flask 3.1 | 베이스 코드 유지 |
| 실시간 통신 | Flask-SocketIO + **gevent** | eventlet은 deprecated 경고. 의존성 관리 체크리스트와 충돌 |
| DB | SQLite (raw `sqlite3`) | ORM 대신 파라미터 바인딩. 송금의 명시적 트랜잭션 제어에 유리 |
| 비밀번호 해싱 | bcrypt | 사용자별 자동 salt |
| CSRF | Flask-WTF | |
| Rate Limiting | Flask-Limiter | |

---

## 보안 요약

베이스 코드 감사에서 **14개 취약점**을 식별하고 전부 수정했습니다.
상세 내역과 before/after 코드는 [`docs/security-log.md`](docs/security-log.md)를 참고하세요.

주요 항목:

| 취약점 | 수정 |
|---|---|
| `SECRET_KEY = 'secret!'` 하드코딩 | 환경변수 분리, 미설정 시 기동 거부 |
| `debug=True` (Werkzeug 디버거 RCE) | 기본 `False`, 환경변수 제어 |
| 비밀번호 평문 저장 | bcrypt 해싱 |
| CSRF 토큰 전무 | Flask-WTF 전역 적용 |
| Socket.IO 인증 없음 | 세션 검증 후 미인증 연결 거부 |
| **채팅 신원을 클라이언트가 전송** | 서버가 세션에서 판단 (관리자 사칭 차단) |
| 로그인 무제한 시도 | 5회 실패 시 15분 잠금 + rate limit |
| `price TEXT` (음수 가격 저장) | `INTEGER` + 범위 검증 + DB CHECK |
| 신고 대상 무검증 | 존재 확인 + 중복 신고 UNIQUE 차단 |
| 외부 CDN 의존 | 로컬 호스팅 + CSP `script-src 'self'` |

이미 안전했던 부분: SQL 인젝션(파라미터 바인딩), XSS(Jinja2 autoescape).
새 기능을 추가할 때 이 습관을 유지하는 것이 핵심이었습니다.

---

## 알려진 제약

학습용 로컬 환경 기준이라 다음은 미적용입니다. 운영 배포 시 필요합니다.

- **HTTPS/WSS** — 리버스 프록시(nginx) + TLS 종단 처리 필요
- **Rate Limiter 저장소** — 현재 메모리 기반. 다중 프로세스 환경에서는 Redis 등 공유 저장소 필요
- **DB 사용자 권한** — SQLite는 파일 기반이라 권한 개념이 없음. PostgreSQL 등 전환 시 최소 권한 적용
- **송금 결제 연동** — PG사 연동 대신 학습용 충전 기능으로 대체
