"""데이터베이스 연결 및 트랜잭션 관리."""

import sqlite3
from contextlib import contextmanager
from pathlib import Path

from flask import current_app, g

SCHEMA_PATH = Path(__file__).parent / "schema.sql"


def get_db() -> sqlite3.Connection:
    """요청 단위 DB 연결. 요청이 끝나면 close_db가 정리한다."""
    db = getattr(g, "_database", None)
    if db is None:
        db = g._database = sqlite3.connect(
            current_app.config["DATABASE"],
            # isolation_level=None => 파이썬의 암묵적 트랜잭션 관리를 끄고
            # BEGIN 시점을 코드가 직접 통제한다. 송금의 원자성 보장에 필요.
            isolation_level=None,
            timeout=10,
        )
        db.row_factory = sqlite3.Row
        # [보안] 외래키 제약은 SQLite에서 연결마다 켜야 한다. 끄면 스키마의
        #        REFERENCES가 전부 장식이 되어 고아 레코드가 생긴다.
        db.execute("PRAGMA foreign_keys = ON")
        # 동시 읽기/쓰기 처리 개선 (송금 시 잠금 경합 완화)
        db.execute("PRAGMA journal_mode = WAL")
    return db


def close_db(exception=None) -> None:
    db = getattr(g, "_database", None)
    if db is not None:
        db.close()
        g._database = None


@contextmanager
def write_transaction():
    """쓰기 트랜잭션. 예외 시 자동 롤백.

    [보안 - 경쟁 조건 방어]
    BEGIN IMMEDIATE는 트랜잭션 시작 즉시 쓰기 잠금을 획득한다.
    송금처럼 "잔액을 읽고 → 검사하고 → 차감"하는 흐름에서, 기본
    DEFERRED 모드를 쓰면 두 요청이 같은 잔액을 동시에 읽어
    각자 통과시켜 버린다(TOCTOU). IMMEDIATE는 두 번째 요청을
    첫 번째가 끝날 때까지 대기시켜 이를 봉쇄한다.
    """
    db = get_db()
    db.execute("BEGIN IMMEDIATE")
    try:
        yield db
    except Exception:
        db.execute("ROLLBACK")
        raise
    else:
        db.execute("COMMIT")


def init_db(app) -> None:
    """스키마 적용 및 관리자 계정 보장."""
    with app.app_context():
        db = get_db()
        db.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))
        close_db()


def write_audit(actor_id, action, target=None, detail=None, ip=None) -> None:
    """감사 로그 기록.

    [보안] 관리자 행위와 신고 접수는 사후 추적이 가능해야 한다.
           로그에는 식별자만 남기고 비밀번호/토큰 등 민감값은 절대 넣지 않는다.
    """
    db = get_db()
    db.execute(
        "INSERT INTO audit_log (actor_id, action, target, detail, ip) "
        "VALUES (?, ?, ?, ?, ?)",
        (actor_id, action, target, detail, ip),
    )
