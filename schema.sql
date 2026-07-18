-- Tiny Second-hand Shopping Platform - 데이터베이스 스키마
--
-- 설계 원칙: 애플리케이션 계층의 입력 검증과 별개로, DB 계층에도
-- CHECK 제약을 걸어 이중 방어(defense in depth)를 구성한다.
-- 애플리케이션 검증에 구멍이 생겨도 DB가 마지막 방어선이 된다.

PRAGMA foreign_keys = ON;

-- ─────────────────────────────────────────────────────────────
-- 사용자
-- ─────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS user (
    id                 TEXT PRIMARY KEY,
    username           TEXT UNIQUE NOT NULL,
    -- [보안] 평문 password 컬럼을 password_hash로 교체 (bcrypt)
    password_hash      TEXT NOT NULL,
    bio                TEXT NOT NULL DEFAULT '',

    -- [송금] 잔액은 정수(원 단위)로만. 실수 사용 시 반올림 오차로 금액이 새어나감.
    --        음수 잔액은 DB 차원에서 거부한다.
    balance            INTEGER NOT NULL DEFAULT 0 CHECK (balance >= 0),

    -- [관리자] 권한은 문자열이 아니라 제한된 집합으로 강제
    role               TEXT NOT NULL DEFAULT 'user'
                       CHECK (role IN ('user', 'admin')),

    -- [차단] active=정상, dormant=신고 누적 휴면, blocked=관리자 차단
    status             TEXT NOT NULL DEFAULT 'active'
                       CHECK (status IN ('active', 'dormant', 'blocked')),

    -- [무차별 대입 방어] 실패 횟수 누적 및 잠금 해제 시각
    failed_login_count INTEGER NOT NULL DEFAULT 0,
    locked_until       TEXT,

    report_count       INTEGER NOT NULL DEFAULT 0,
    created_at         TEXT NOT NULL DEFAULT (datetime('now'))
);

-- ─────────────────────────────────────────────────────────────
-- 상품
-- ─────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS product (
    id           TEXT PRIMARY KEY,
    title        TEXT NOT NULL,
    description  TEXT NOT NULL,

    -- [보안] 베이스 코드는 price가 TEXT였다. 송금 기능이 붙는 순간
    --        음수 가격 상품으로 잔액을 늘리는 공격이 가능해진다.
    --        INTEGER + 범위 CHECK로 봉쇄.
    price        INTEGER NOT NULL CHECK (price > 0 AND price <= 100000000),

    seller_id    TEXT NOT NULL REFERENCES user(id),
    image_path   TEXT,

    status       TEXT NOT NULL DEFAULT 'active'
                 CHECK (status IN ('active', 'blocked', 'sold')),

    report_count INTEGER NOT NULL DEFAULT 0,
    created_at   TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_product_seller ON product(seller_id);
CREATE INDEX IF NOT EXISTS idx_product_status ON product(status);

-- ─────────────────────────────────────────────────────────────
-- 신고
-- ─────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS report (
    id          TEXT PRIMARY KEY,
    reporter_id TEXT NOT NULL REFERENCES user(id),

    -- [보안] 베이스 코드는 target_id만 있어 유저/상품 구분이 없었다.
    --        UUID가 우연히 겹치지 않더라도 의미가 모호해 처리 로직이 성립하지 않는다.
    target_type TEXT NOT NULL CHECK (target_type IN ('user', 'product')),
    target_id   TEXT NOT NULL,

    reason      TEXT NOT NULL,
    created_at  TEXT NOT NULL DEFAULT (datetime('now')),

    -- [신고 남용 방지] 같은 사람이 같은 대상을 반복 신고해 차단시키는 공격 봉쇄.
    --                  DB 유니크 제약이라 앱 로직이 뚫려도 막힌다.
    UNIQUE (reporter_id, target_type, target_id)
);

CREATE INDEX IF NOT EXISTS idx_report_target ON report(target_type, target_id);

-- ─────────────────────────────────────────────────────────────
-- 메시지 (receiver_id IS NULL => 전체 채팅, 지정 => 1:1 채팅)
-- ─────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS message (
    id          TEXT PRIMARY KEY,
    sender_id   TEXT NOT NULL REFERENCES user(id),
    receiver_id TEXT REFERENCES user(id),
    content     TEXT NOT NULL,
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_message_dm ON message(sender_id, receiver_id, created_at);

-- ─────────────────────────────────────────────────────────────
-- 송금 원장
-- ─────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS transfer (
    id          TEXT PRIMARY KEY,
    sender_id   TEXT NOT NULL REFERENCES user(id),
    receiver_id TEXT NOT NULL REFERENCES user(id),

    -- [송금] 0원/음수 송금 차단. 음수를 허용하면 "상대에게 -1000원 송금"이
    --        곧 "상대에게서 1000원 갈취"가 된다.
    amount      INTEGER NOT NULL CHECK (amount > 0),

    product_id  TEXT REFERENCES product(id),
    created_at  TEXT NOT NULL DEFAULT (datetime('now')),

    -- [송금] 자기 자신에게 송금 차단
    CHECK (sender_id <> receiver_id)
);

CREATE INDEX IF NOT EXISTS idx_transfer_sender ON transfer(sender_id, created_at);
CREATE INDEX IF NOT EXISTS idx_transfer_receiver ON transfer(receiver_id, created_at);

-- ─────────────────────────────────────────────────────────────
-- 감사 로그 (체크리스트: "신고 활동이 감사 로그로 기록되는지")
-- ─────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS audit_log (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    actor_id   TEXT,
    action     TEXT NOT NULL,
    target     TEXT,
    detail     TEXT,
    ip         TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_audit_actor ON audit_log(actor_id, created_at);
