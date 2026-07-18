"""송금 경쟁 조건(TOCTOU) 검증.

잔액 10,000원인 계정에서 10,000원 송금을 동시에 여러 번 요청한다.
올바르게 구현되었다면 정확히 1건만 성공하고 잔액은 0원이 되어야 한다.

취약한 구현(잔액 확인과 차감이 별도 트랜잭션)이라면 여러 요청이 각자
"잔액 10000 >= 10000, 통과"를 읽고 모두 차감해 잔액이 음수가 되거나,
받는 쪽에 없던 돈이 생긴다.

사용법:
    python tests/test_race_condition.py            # 현재 구현 검증
    python tests/test_race_condition.py --unsafe   # 취약 구현 재현 (비교용)
"""

import re
import sys
import threading
import uuid

import requests

BASE = "http://127.0.0.1:5000"
CONCURRENCY = 12
AMOUNT = 10000


def csrf(sess, path):
    html = sess.get(BASE + path).text
    m = re.search(r'name="csrf_token" value="([^"]+)"', html)
    return m.group(1) if m else None


def new_user():
    name = "u" + uuid.uuid4().hex[:10]
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


def balance(sess):
    html = sess.get(BASE + "/transfer").text
    m = re.search(r'<div class="amount">([\d,]+)원</div>', html)
    return int(m.group(1).replace(",", "")) if m else None


def main():
    attacker, attacker_name = new_user()
    victim, victim_name = new_user()

    # 공격자에게 정확히 AMOUNT 만큼만 충전
    attacker.post(BASE + "/charge", data={
        "csrf_token": csrf(attacker, "/transfer"), "amount": str(AMOUNT),
    })

    start_balance = balance(attacker)
    print(f"공격자 초기 잔액 : {start_balance:,}원")
    print(f"동시 송금 요청   : {CONCURRENCY}건 x {AMOUNT:,}원")
    print(f"기대 결과        : 1건만 성공, 최종 잔액 0원\n")

    # requests.Session은 스레드 안전하지 않으므로, 같은 세션 쿠키를 복사한
    # 독립 Session을 스레드마다 하나씩 만든다. 서버 입장에서는 동일 사용자의
    # 동시 요청 12건이다.
    session_cookie = attacker.cookies.get("session")
    workers = []
    for _ in range(CONCURRENCY):
        s = requests.Session()
        s.cookies.set("session", session_cookie, domain="127.0.0.1")
        # CSRF 토큰은 세션에서 파생되므로 이 쿠키로 발급받은 토큰이 유효하다.
        workers.append((s, csrf(s, "/transfer")))

    barrier = threading.Barrier(CONCURRENCY)
    results = []
    lock = threading.Lock()

    def attack(sess, token):
        barrier.wait()  # 모든 스레드가 동시에 출발
        try:
            r = sess.post(BASE + "/transfer", data={
                "csrf_token": token,
                "to_username": victim_name,
                "amount": str(AMOUNT),
            }, allow_redirects=True, timeout=20)
            ok = "송금했습니다" in r.text
        except Exception as e:
            with lock:
                results.append(("error", str(e)[:40]))
            return
        with lock:
            results.append(("success" if ok else "rejected", ""))

    threads = [threading.Thread(target=attack, args=(s, t)) for s, t in workers]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    succeeded = sum(1 for r, _ in results if r == "success")
    rejected = sum(1 for r, _ in results if r == "rejected")
    errored = sum(1 for r, _ in results if r == "error")

    end_attacker = balance(attacker)
    end_victim = balance(victim)

    print(f"성공 {succeeded}건 / 거부 {rejected}건 / 오류 {errored}건")
    print(f"공격자 최종 잔액 : {end_attacker:,}원")
    print(f"피해자 최종 잔액 : {end_victim:,}원")
    print(f"총액 보존        : {start_balance:,} -> "
          f"{end_attacker + end_victim:,}")

    print()
    ok = True
    if succeeded != 1:
        print(f"  [FAIL] 송금이 {succeeded}건 성공했습니다. 1건이어야 합니다.")
        ok = False
    else:
        print("  [PASS] 정확히 1건만 성공")

    if end_attacker != 0:
        print(f"  [FAIL] 공격자 잔액이 {end_attacker}원입니다. 0원이어야 합니다.")
        ok = False
    else:
        print("  [PASS] 공격자 잔액 0원")

    if end_victim != AMOUNT:
        print(f"  [FAIL] 피해자 잔액이 {end_victim}원입니다. "
              f"{AMOUNT}원이어야 합니다.")
        ok = False
    else:
        print("  [PASS] 피해자 잔액 정확")

    if end_attacker + end_victim != start_balance:
        print("  [FAIL] 총액이 보존되지 않았습니다. 돈이 복제/증발했습니다.")
        ok = False
    else:
        print("  [PASS] 총액 보존 (돈이 복제되지 않음)")

    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
