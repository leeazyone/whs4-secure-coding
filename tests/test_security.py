"""보안 요구사항 검증 테스트.

체크리스트 항목이 실제로 코드에서 지켜지는지 HTTP 레벨에서 확인한다.
서버를 띄운 뒤 실행:  python tests/test_security.py
"""

import re
import sys
import uuid

import requests

BASE = "http://127.0.0.1:5000"

passed = 0
failed = 0


def check(name, condition, detail=""):
    global passed, failed
    if condition:
        passed += 1
        print(f"  [PASS] {name}")
    else:
        failed += 1
        print(f"  [FAIL] {name}  {detail}")


def csrf(sess, path):
    """페이지에서 CSRF 토큰을 추출한다."""
    html = sess.get(BASE + path).text
    m = re.search(r'name="csrf_token" value="([^"]+)"', html)
    return m.group(1) if m else None


def new_user(name=None):
    """새 사용자 등록 후 로그인된 세션을 반환한다."""
    name = name or ("u" + uuid.uuid4().hex[:10])
    s = requests.Session()
    s.post(BASE + "/register", data={
        "csrf_token": csrf(s, "/register"),
        "username": name, "password": "password123",
    })
    s.post(BASE + "/login", data={
        "csrf_token": csrf(s, "/login"),
        "username": name, "password": "password123",
    })
    return s, name


def main():
    print("\n─── 1. 인증 및 세션 ───")

    s = requests.Session()
    r = s.get(BASE + "/dashboard", allow_redirects=False)
    check("미로그인 시 대시보드 접근 차단", r.status_code == 302)

    alice, alice_name = new_user()
    r = alice.get(BASE + "/dashboard")
    check("로그인 후 대시보드 접근 가능", r.status_code == 200)

    cookie = alice.cookies.get_dict()
    r = alice.get(BASE + "/login")
    set_cookie = r.headers.get("Set-Cookie", "")
    check("세션 쿠키 HttpOnly", "HttpOnly" in set_cookie, set_cookie[:80])
    check("세션 쿠키 SameSite", "SameSite" in set_cookie, set_cookie[:80])

    print("\n─── 2. CSRF 보호 ───")

    r = requests.post(BASE + "/register",
                      data={"username": "csrftest", "password": "password123"})
    check("CSRF 토큰 없는 회원가입 차단", r.status_code == 400, f"got {r.status_code}")

    r = alice.post(BASE + "/transfer",
                   data={"to_username": "someone", "amount": "100"})
    check("CSRF 토큰 없는 송금 차단", r.status_code == 400, f"got {r.status_code}")

    print("\n─── 3. 입력 검증 ───")

    r = requests.Session()
    s2 = requests.Session()
    r = s2.post(BASE + "/register", data={
        "csrf_token": csrf(s2, "/register"),
        "username": "ab", "password": "password123",
    }, allow_redirects=True)
    check("짧은 사용자명 거부", "3~20자" in r.text)

    s3 = requests.Session()
    r = s3.post(BASE + "/register", data={
        "csrf_token": csrf(s3, "/register"),
        "username": "validname", "password": "short",
    }, allow_redirects=True)
    check("짧은 비밀번호 거부", "최소 8자" in r.text)

    s4 = requests.Session()
    r = s4.post(BASE + "/register", data={
        "csrf_token": csrf(s4, "/register"),
        "username": "bad<script>", "password": "password123",
    }, allow_redirects=True)
    check("특수문자 사용자명 거부", "영문/숫자/밑줄" in r.text)

    print("\n─── 4. 상품: 가격 검증 (베이스 코드 price TEXT 문제) ───")

    r = alice.post(BASE + "/product/new", data={
        "csrf_token": csrf(alice, "/product/new"),
        "title": "음수가격", "description": "test", "price": "-10000",
    }, allow_redirects=True)
    check("음수 가격 거부", "1 이상" in r.text)

    r = alice.post(BASE + "/product/new", data={
        "csrf_token": csrf(alice, "/product/new"),
        "title": "문자가격", "description": "test", "price": "abc",
    }, allow_redirects=True)
    check("문자열 가격 거부", "숫자여야" in r.text)

    r = alice.post(BASE + "/product/new", data={
        "csrf_token": csrf(alice, "/product/new"),
        "title": "초과가격", "description": "test", "price": "999999999999",
    }, allow_redirects=True)
    check("범위 초과 가격 거부", "허용 범위" in r.text)

    r = alice.post(BASE + "/product/new", data={
        "csrf_token": csrf(alice, "/product/new"),
        "title": "정상상품", "description": "설명입니다", "price": "50000",
    }, allow_redirects=True)
    check("정상 상품 등록", "등록되었습니다" in r.text)

    m = re.search(r"/product/([0-9a-f-]{36})", r.url + r.text)
    alice_product = m.group(1) if m else None
    check("상품 ID 확보", alice_product is not None)

    print("\n─── 5. XSS 방어 ───")

    payload = "<script>alert(1)</script>"
    alice.post(BASE + "/product/new", data={
        "csrf_token": csrf(alice, "/product/new"),
        "title": "XSS테스트", "description": payload, "price": "1000",
    })
    r = alice.get(BASE + "/dashboard")
    check("스크립트 태그가 이스케이프됨",
          "<script>alert(1)</script>" not in r.text)

    print("\n─── 6. 인가: IDOR ───")

    bob, bob_name = new_user()
    r = bob.get(BASE + f"/product/{alice_product}/edit", allow_redirects=False)
    check("남의 상품 수정 페이지 차단(403)", r.status_code == 403,
          f"got {r.status_code}")

    r = bob.post(BASE + f"/product/{alice_product}/delete", data={
        "csrf_token": csrf(bob, "/dashboard") or "x",
    }, allow_redirects=False)
    check("남의 상품 삭제 차단", r.status_code in (400, 403),
          f"got {r.status_code}")

    print("\n─── 7. 인가: 관리자 ───")

    r = alice.get(BASE + "/admin", allow_redirects=False)
    check("일반 사용자의 관리자 페이지 접근 시 404", r.status_code == 404,
          f"got {r.status_code}")

    r = alice.get(BASE + "/admin/users", allow_redirects=False)
    check("일반 사용자의 사용자 관리 접근 시 404", r.status_code == 404,
          f"got {r.status_code}")

    print("\n─── 8. 송금 ───")

    alice.post(BASE + "/charge", data={
        "csrf_token": csrf(alice, "/transfer"), "amount": "10000",
    })
    r = alice.get(BASE + "/transfer")
    check("충전 반영", "10,000원" in r.text)

    r = alice.post(BASE + "/transfer", data={
        "csrf_token": csrf(alice, "/transfer"),
        "to_username": alice_name, "amount": "1000",
    }, allow_redirects=True)
    check("자기 자신에게 송금 거부", "자기 자신" in r.text)

    r = alice.post(BASE + "/transfer", data={
        "csrf_token": csrf(alice, "/transfer"),
        "to_username": bob_name, "amount": "-5000",
    }, allow_redirects=True)
    check("음수 송금 거부", "1 이상" in r.text)

    r = alice.post(BASE + "/transfer", data={
        "csrf_token": csrf(alice, "/transfer"),
        "to_username": bob_name, "amount": "999999",
    }, allow_redirects=True)
    check("잔액 초과 송금 거부", "잔액이 부족" in r.text)

    r = alice.post(BASE + "/transfer", data={
        "csrf_token": csrf(alice, "/transfer"),
        "to_username": "nonexistentuser", "amount": "1000",
    }, allow_redirects=True)
    check("없는 사용자에게 송금 거부", "찾을 수 없습니다" in r.text)

    r = alice.post(BASE + "/transfer", data={
        "csrf_token": csrf(alice, "/transfer"),
        "to_username": bob_name, "amount": "3000",
    }, allow_redirects=True)
    check("정상 송금 성공", "송금했습니다" in r.text)
    check("송금 후 잔액 차감", "7,000원" in r.text)

    r = bob.get(BASE + "/transfer")
    check("수신자 잔액 증가", "3,000원" in r.text)

    print("\n─── 9. 검색 ───")

    r = alice.get(BASE + "/search", params={"q": "정상상품"})
    check("검색 동작", "정상상품" in r.text)

    r = alice.get(BASE + "/search", params={"q": "' OR '1'='1"})
    check("SQL 인젝션 시도 시 결과 없음", "검색 결과가 없습니다" in r.text)

    r = alice.get(BASE + "/search", params={"q": "%"})
    check("LIKE 와일드카드 이스케이프", "검색 결과가 없습니다" in r.text)

    print("\n─── 10. 신고 ───")

    r = alice.post(BASE + "/report", data={
        "csrf_token": csrf(alice, "/report"),
        "target_type": "user", "target_id": alice.cookies.get("session", "x"),
        "reason": "test",
    }, allow_redirects=True)
    check("존재하지 않는 대상 신고 거부", "찾을 수 없습니다" in r.text)

    r = alice.post(BASE + "/report", data={
        "csrf_token": csrf(alice, "/report"),
        "target_type": "invalid", "target_id": "x", "reason": "test",
    }, allow_redirects=True)
    check("잘못된 대상 종류 거부", "잘못된 신고 대상" in r.text)

    carol, _ = new_user()
    r = carol.post(BASE + "/report", data={
        "csrf_token": csrf(carol, "/report"),
        "target_type": "product", "target_id": alice_product,
        "reason": "허위 매물입니다",
    }, allow_redirects=True)
    check("정상 신고 접수", "접수되었습니다" in r.text)

    r = carol.post(BASE + "/report", data={
        "csrf_token": csrf(carol, "/report"),
        "target_type": "product", "target_id": alice_product,
        "reason": "또 신고",
    }, allow_redirects=True)
    check("중복 신고 차단", "이미 신고한 대상" in r.text)

    print("\n─── 11. 에러 처리 ───")

    r = alice.get(BASE + "/product/nonexistent-id-12345")
    check("없는 상품 404", r.status_code == 404, f"got {r.status_code}")
    check("스택 트레이스 미노출", "Traceback" not in r.text)

    print("\n" + "=" * 50)
    print(f"  통과 {passed} / 실패 {failed}")
    print("=" * 50)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
