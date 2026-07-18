"""[대조군] 취약한 송금 구현 재현 — 보고서 증거용.

본 프로젝트의 송금이 왜 트랜잭션으로 묶여야 하는지 보이기 위해,
"AI에게 송금 기능을 만들어달라고 하면 흔히 나오는" 순진한 구현을
그대로 재현하고 같은 공격을 가한다.

이 파일은 실제 서비스 코드가 아니다. tests/ 안에만 존재하며
app.py는 이 파일을 import하지 않는다.

실행:
    python tests/demo_vulnerable_transfer.py
"""

import re
import sqlite3
import threading
import time
import uuid

import requests
from flask import Flask, Response, request

DB = "/tmp/vuln_demo.db"
PORT = 5099
BASE = f"http://127.0.0.1:{PORT}"
CONCURRENCY = 12
AMOUNT = 10000

app = Flask(__name__)


def db():
    conn = sqlite3.connect(DB, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn


@app.route("/transfer", methods=["POST"])
def vulnerable_transfer():
    """전형적인 취약 구현.

    문제: 잔액을 읽고 → 검사하고 → 차감하는 세 단계가 각각 독립적이다.
    두 요청이 동시에 들어오면 둘 다 "잔액 충분"을 읽고 통과한 뒤
    각자 차감한다. 잔액 확인은 이미 지나간 과거의 사실이 된다.
    (Time Of Check To Time Of Use)
    """
    sender = request.form["sender"]
    receiver = request.form["receiver"]
    amount = int(request.form["amount"])

    conn = db()

    # 1) 잔액 확인
    row = conn.execute("SELECT balance FROM acct WHERE name = ?",
                       (sender,)).fetchone()
    if row["balance"] < amount:
        conn.close()
        return Response("잔액 부족", status=400)

    # 2) 실제 서비스의 처리 지연을 흉내낸다. 이 틈이 없어도 경쟁은
    #    발생하지만, 재현을 안정적으로 만들기 위해 넣는다.
    time.sleep(0.05)

    # 3) 차감 및 입금
    conn.execute("UPDATE acct SET balance = balance - ? WHERE name = ?",
                 (amount, sender))
    conn.execute("UPDATE acct SET balance = balance + ? WHERE name = ?",
                 (amount, receiver))
    conn.commit()
    conn.close()
    return Response("송금 완료", status=200)


@app.route("/balance/<name>")
def get_balance(name):
    conn = db()
    row = conn.execute("SELECT balance FROM acct WHERE name = ?",
                       (name,)).fetchone()
    conn.close()
    return str(row["balance"])


def setup():
    import os
    if os.path.exists(DB):
        os.remove(DB)
    conn = db()
    conn.execute("CREATE TABLE acct (name TEXT PRIMARY KEY, balance INTEGER)")
    conn.execute("INSERT INTO acct VALUES ('attacker', ?)", (AMOUNT,))
    conn.execute("INSERT INTO acct VALUES ('victim', 0)")
    conn.commit()
    conn.close()


def attack():
    time.sleep(1.5)

    start = int(requests.get(f"{BASE}/balance/attacker").text)
    print(f"공격자 초기 잔액 : {start:,}원")
    print(f"동시 송금 요청   : {CONCURRENCY}건 x {AMOUNT:,}원")
    print(f"정상이라면       : 1건만 성공, 최종 잔액 0원\n")

    barrier = threading.Barrier(CONCURRENCY)
    results = []
    lock = threading.Lock()

    def worker():
        barrier.wait()
        try:
            r = requests.post(f"{BASE}/transfer", data={
                "sender": "attacker", "receiver": "victim",
                "amount": str(AMOUNT),
            }, timeout=20)
            ok = r.status_code == 200
        except Exception:
            ok = False
        with lock:
            results.append(ok)

    threads = [threading.Thread(target=worker) for _ in range(CONCURRENCY)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    succeeded = sum(1 for r in results if r)
    end_a = int(requests.get(f"{BASE}/balance/attacker").text)
    end_v = int(requests.get(f"{BASE}/balance/victim").text)

    print(f"성공 {succeeded}건 / 거부 {CONCURRENCY - succeeded}건")
    print(f"공격자 최종 잔액 : {end_a:,}원")
    print(f"피해자 최종 잔액 : {end_v:,}원")
    print(f"총액             : {start:,} -> {end_a + end_v:,}")
    print()

    if succeeded > 1 or end_a < 0 or (end_a + end_v) != start:
        print("  >>> 취약점 재현 성공 <<<")
        print(f"  잔액 {start:,}원뿐인 계정에서 {succeeded * AMOUNT:,}원이 나갔습니다.")
        if (end_a + end_v) != start:
            diff = (end_a + end_v) - start
            print(f"  총액이 {diff:+,}원 변했습니다. 없던 돈이 생겼습니다.")
        print()
        print("  => 이것이 app.py의 write_transaction()(BEGIN IMMEDIATE)이")
        print("     막고 있는 공격입니다.")
    else:
        print("  경쟁이 재현되지 않았습니다. CONCURRENCY를 늘려 다시 시도하세요.")

    # os._exit()는 stdout 버퍼를 비우지 않고 프로세스를 끝낸다.
    # 명시적으로 flush하지 않으면 위 출력이 전부 사라진다.
    import os
    import sys
    sys.stdout.flush()
    os._exit(0)


if __name__ == "__main__":
    setup()
    threading.Thread(target=attack, daemon=True).start()
    app.run(host="127.0.0.1", port=PORT, threaded=True, debug=False)
