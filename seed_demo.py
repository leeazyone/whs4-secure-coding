"""데모 데이터 시드 스크립트 (선택 사항).

스크린샷·시연을 위해 샘플 사용자와 상품을 생성한다.
보안 검증에는 필요 없으며, 실제 앱 로직(create_app)을 그대로 사용해
비밀번호 해싱 등이 정상 경로로 처리된다.

사용법:  python seed_demo.py
"""

import os
import uuid

os.environ.setdefault("SECRET_KEY", "seed-only-not-for-production-" + "x" * 16)

from app import create_app, ensure_admin  # noqa: E402
from db import get_db, init_db  # noqa: E402
from security import hash_password  # noqa: E402

DEMO_USERS = [
    ("alice", "Password123", 50000, "안녕하세요, 앨리스입니다. 책과 전자기기를 팝니다."),
    ("bob", "Password123", 30000, "밥의 중고 상점. 운동용품 위주로 있어요."),
    ("charlie", "Password123", 10000, ""),
]

DEMO_PRODUCTS = [
    ("alice", "파이썬 프로그래밍 책", "거의 새 책입니다. 밑줄 없음.", 15000),
    ("alice", "기계식 키보드", "적축, 3개월 사용. 정상 작동합니다.", 45000),
    ("bob", "요가 매트", "6mm 두께, TPE 소재. 세척 완료.", 12000),
    ("bob", "덤벨 5kg 2개", "한 쌍입니다. 코팅 벗겨짐 약간.", 20000),
    ("charlie", "USB-C 충전기", "65W PD 지원. 박스 있음.", 18000),
]


def main():
    app, _ = create_app()
    init_db(app)
    ensure_admin(app)

    with app.app_context():
        db = get_db()
        name_to_id = {}

        for username, password, balance, bio in DEMO_USERS:
            if db.execute("SELECT 1 FROM user WHERE username = ?",
                          (username,)).fetchone():
                row = db.execute("SELECT id FROM user WHERE username = ?",
                                 (username,)).fetchone()
                name_to_id[username] = row["id"]
                continue
            uid = str(uuid.uuid4())
            db.execute(
                "INSERT INTO user (id, username, password_hash, bio, balance) "
                "VALUES (?, ?, ?, ?, ?)",
                (uid, username, hash_password(password), bio, balance),
            )
            name_to_id[username] = uid
            print(f"[+] 사용자 생성: {username} / {password} (잔액 {balance:,}원)")

        for seller, title, desc, price in DEMO_PRODUCTS:
            seller_id = name_to_id[seller]
            exists = db.execute(
                "SELECT 1 FROM product WHERE title = ? AND seller_id = ?",
                (title, seller_id),
            ).fetchone()
            if exists:
                continue
            db.execute(
                "INSERT INTO product (id, title, description, price, seller_id) "
                "VALUES (?, ?, ?, ?, ?)",
                (str(uuid.uuid4()), title, desc, price, seller_id),
            )
            print(f"[+] 상품 생성: {title} ({price:,}원, 판매자 {seller})")

    print("\n데모 데이터 준비 완료. 다음 계정으로 로그인해보세요:")
    print("  alice / Password123  (잔액 50,000원 - 송금 테스트용)")
    print("  bob   / Password123")
    print("  관리자는 app.py 최초 실행 시 콘솔에 출력된 계정을 사용하세요.")


if __name__ == "__main__":
    main()
