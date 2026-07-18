# Tiny Second-hand Shopping Platform

WhiteHat School 4기 · 시큐어 코딩 과제

---

## 환경 설정

### 요구 사항

- Linux (Ubuntu 22.04에서 개발·검증) 또는 WSL2
- Python 3.10 이상

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

### `.env` 설정

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

