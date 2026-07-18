"""인증·인가 가드와 서버측 입력 검증.

보안 판단을 이 파일 한 곳에 모아둔다. 라우트 코드에 검증 로직이
흩어지면 새 기능을 추가할 때 빠뜨리기 쉽고, 리뷰 시 무엇이 검증되는지
한눈에 확인할 수 없다.
"""

import functools
import re

import bcrypt
from flask import abort, flash, g, redirect, request, session, url_for

from db import get_db

# ─────────────────────────────────────────────────────────────
# 비밀번호 해싱
# ─────────────────────────────────────────────────────────────

# bcrypt는 72바이트를 넘는 입력을 잘라내거나(구버전) 거부한다(5.x).
# 조용히 잘리면 "앞 72바이트만 같으면 로그인 성공"이 되므로, 검증 단계에서
# 길이를 강제해 그런 상황 자체를 만들지 않는다.
PASSWORD_MAX_BYTES = 72
PASSWORD_MIN_LENGTH = 8

# 로그인 실패 시 어떤 사용자명으로도 동일한 시간이 걸리도록, 존재하지 않는
# 계정에 대해서도 검증을 수행할 더미 해시.
_DUMMY_HASH = bcrypt.hashpw(b"dummy-password-for-timing", bcrypt.gensalt())


def hash_password(password: str) -> str:
    """[보안] 평문 저장 금지. bcrypt는 사용자마다 고유 salt를 자동 생성하므로
    같은 비밀번호라도 해시가 달라져 레인보우 테이블 공격이 무력화된다."""
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("ascii")


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("ascii"))
    except (ValueError, TypeError):
        return False


def dummy_verify() -> None:
    """[보안] 사용자 열거(enumeration) 방어.

    계정이 없을 때 즉시 실패를 반환하면, 존재하는 계정(bcrypt 검증 ~100ms)과
    없는 계정(~0ms)의 응답 시간이 달라 공격자가 유효한 사용자명 목록을
    수집할 수 있다. 없는 계정에도 동일한 비용을 지불시킨다.
    """
    bcrypt.checkpw(b"dummy-password-for-timing", _DUMMY_HASH)


# ─────────────────────────────────────────────────────────────
# 현재 사용자
# ─────────────────────────────────────────────────────────────

def get_current_user():
    """세션의 user_id로 DB에서 사용자를 조회한다.

    [보안] 신원은 세션에 담긴 id로 매번 DB에서 다시 읽는다. 사용자명·권한·
           잔액 같은 값을 세션에 캐싱하면, 관리자가 계정을 차단해도 기존
           세션이 살아있는 한 계속 통과하게 된다.
    """
    if "user_id" not in session:
        return None
    user = getattr(g, "_current_user", None)
    if user is None:
        db = get_db()
        user = db.execute(
            "SELECT * FROM user WHERE id = ?", (session["user_id"],)
        ).fetchone()
        g._current_user = user
    return user


# ─────────────────────────────────────────────────────────────
# 접근 제어 데코레이터
# ─────────────────────────────────────────────────────────────

def login_required(view):
    """로그인 + 계정 상태 확인.

    [보안] 차단/휴면 계정의 세션을 즉시 무효화한다. 로그인 시점에만
           상태를 확인하면, 차단당하기 전에 로그인해 둔 세션으로
           계속 활동할 수 있다.
    """
    @functools.wraps(view)
    def wrapped(*args, **kwargs):
        user = get_current_user()
        if user is None:
            flash("로그인이 필요합니다.")
            return redirect(url_for("login"))
        if user["status"] == "blocked":
            session.clear()
            flash("차단된 계정입니다. 관리자에게 문의하세요.")
            return redirect(url_for("login"))
        if user["status"] == "dormant":
            session.clear()
            flash("신고 누적으로 휴면 전환된 계정입니다.")
            return redirect(url_for("login"))
        return view(*args, **kwargs)

    return wrapped


def admin_required(view):
    """[보안] 관리자 전용. role은 세션이 아니라 DB에서 확인한다.

    세션에 is_admin 같은 값을 넣어두면 SECRET_KEY가 유출되는 순간
    권한 상승으로 직결된다. 세션은 "누구인가"만 담고, "무엇을 할 수
    있는가"는 항상 서버가 DB를 보고 판단한다.
    """
    @functools.wraps(view)
    @login_required
    def wrapped(*args, **kwargs):
        user = get_current_user()
        if user["role"] != "admin":
            # 404를 반환해 관리자 경로의 존재 자체를 노출하지 않는다.
            abort(404)
        return view(*args, **kwargs)

    return wrapped


def owner_required_product(view):
    """[보안] 소유자 확인 (IDOR 방어).

    로그인만 확인하고 소유권을 확인하지 않으면, 로그인한 아무나
    URL의 product_id만 바꿔서 남의 상품을 수정·삭제할 수 있다.
    관리자는 예외로 통과시킨다.
    """
    @functools.wraps(view)
    @login_required
    def wrapped(product_id, *args, **kwargs):
        user = get_current_user()
        db = get_db()
        product = db.execute(
            "SELECT * FROM product WHERE id = ?", (product_id,)
        ).fetchone()
        if product is None:
            abort(404)
        if product["seller_id"] != user["id"] and user["role"] != "admin":
            abort(403)
        return view(product_id, *args, **kwargs)

    return wrapped


# ─────────────────────────────────────────────────────────────
# 서버측 입력 검증
#
# 클라이언트측 검증(HTML maxlength, JS)은 사용자 편의를 위한 것이지
# 보안 장치가 아니다. curl 한 줄이면 전부 우회된다. 아래 함수들이
# 실제 방어선이다.
# ─────────────────────────────────────────────────────────────

USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{3,20}$")

BIO_MAX = 500
TITLE_MAX = 100
DESCRIPTION_MAX = 2000
REASON_MAX = 500
MESSAGE_MAX = 1000
PRICE_MAX = 100_000_000
AMOUNT_MAX = 100_000_000


class ValidationError(Exception):
    """사용자에게 그대로 보여줘도 안전한 검증 실패 메시지."""


def validate_username(raw: str) -> str:
    username = (raw or "").strip()
    if not USERNAME_RE.match(username):
        # 허용 문자를 화이트리스트로 제한한다. 블랙리스트(위험 문자 제거)는
        # 항상 빠뜨리는 케이스가 생긴다.
        raise ValidationError("사용자명은 영문/숫자/밑줄 3~20자여야 합니다.")
    return username


def validate_password(raw: str) -> str:
    password = raw or ""
    if len(password) < PASSWORD_MIN_LENGTH:
        raise ValidationError(f"비밀번호는 최소 {PASSWORD_MIN_LENGTH}자 이상이어야 합니다.")
    if len(password.encode("utf-8")) > PASSWORD_MAX_BYTES:
        raise ValidationError("비밀번호가 너무 깁니다. (최대 72바이트)")
    return password


def validate_text(raw: str, field: str, max_len: int, required: bool = True) -> str:
    """길이 제한 + 필수 여부 검증.

    [보안] XSS는 여기서 HTML을 제거해 막지 않는다. Jinja2의 자동
           이스케이프가 출력 시점에 처리한다. 입력 단계에서 태그를
           지우려 하면(sanitize) 우회 기법이 끝없이 나오고, 정상적인
           '<' 문자까지 손상시킨다. 저장은 원문 그대로, 방어는 출력에서.
    """
    text = (raw or "").strip()
    if required and not text:
        raise ValidationError(f"{field}은(는) 필수 항목입니다.")
    if len(text) > max_len:
        raise ValidationError(f"{field}은(는) {max_len}자를 넘을 수 없습니다.")
    return text


def validate_positive_int(raw, field: str, max_value: int) -> int:
    """[보안] 금액·가격 검증.

    int()는 '007', ' 12 ', '+5' 같은 입력도 통과시키고 음수도 받는다.
    실수(float)를 쓰면 0.1+0.2 문제로 금액이 어긋난다. 정수로만 다루고
    범위를 양쪽 다 막는다. 상한이 없으면 2**63 근처 값으로 오버플로우를
    노리는 입력이 들어온다.
    """
    if raw is None or str(raw).strip() == "":
        raise ValidationError(f"{field}을(를) 입력해주세요.")
    try:
        value = int(str(raw).strip())
    except (ValueError, TypeError):
        raise ValidationError(f"{field}은(는) 숫자여야 합니다.")
    if value <= 0:
        raise ValidationError(f"{field}은(는) 1 이상이어야 합니다.")
    if value > max_value:
        raise ValidationError(f"{field}이(가) 허용 범위를 넘습니다.")
    return value


def client_ip() -> str:
    """감사 로그용 IP. 프록시 뒤가 아니면 remote_addr가 신뢰 가능한 값이다.

    [보안] X-Forwarded-For를 무조건 신뢰하면 안 된다. 클라이언트가
           마음대로 넣을 수 있어 로그 위조와 Rate Limit 우회에 쓰인다.
           신뢰할 수 있는 리버스 프록시 뒤에 둘 때만 ProxyFix로 처리한다.
    """
    return request.remote_addr or "unknown"
