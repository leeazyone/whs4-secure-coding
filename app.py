"""Tiny Second-hand Shopping Platform.

WhiteHat School 4기 - 시큐어 코딩 과제
유효곤 강사 제공 베이스 코드(github.com/ugonfor/secure-coding)를 감사하여
식별한 보안 약점을 수정하고, 요구사항에 맞춰 기능을 확장한 결과물.
"""

import os
import secrets
import sqlite3
import time
import uuid
from datetime import datetime, timedelta, timezone

from dotenv import load_dotenv
from flask import (
    Flask, abort, flash, redirect, render_template, request, session, url_for
)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_socketio import SocketIO, emit, join_room
from flask_wtf.csrf import CSRFProtect

from db import close_db, get_db, init_db, write_audit, write_transaction
from security import (
    AMOUNT_MAX, BIO_MAX, DESCRIPTION_MAX, MESSAGE_MAX, PRICE_MAX, REASON_MAX,
    TITLE_MAX, ValidationError, admin_required, client_ip, dummy_verify,
    get_current_user, hash_password, login_required, owner_required_product,
    validate_password, validate_positive_int, validate_text, validate_username,
    verify_password,
)

load_dotenv()

# 신고 임계치: 이 횟수 이상 신고되면 자동 차단/휴면
REPORT_THRESHOLD = 3

# 로그인 실패 잠금 정책
MAX_FAILED_LOGINS = 5
LOCKOUT_MINUTES = 15

# 소켓 메시지 rate limit
MSG_PER_10SEC = 5


def create_app():
    app = Flask(__name__)

    # ─────────────────────────────────────────────────────────
    # [보안 수정 #1] SECRET_KEY 하드코딩 제거
    #
    # 베이스 코드: app.config['SECRET_KEY'] = 'secret!'  (공개 레포에 노출)
    # 이 키로 Flask는 세션 쿠키에 서명한다. 키를 아는 사람은 임의의
    # user_id를 담은 쿠키를 직접 서명해 아무 계정으로든 로그인할 수 있다.
    # 환경변수에서 읽고, 없으면 기동을 거부한다. (기본값을 두면 아무도
    # 설정하지 않아 결국 하드코딩과 같아진다.)
    # ─────────────────────────────────────────────────────────
    secret_key = os.environ.get("SECRET_KEY")
    if not secret_key:
        raise RuntimeError(
            "SECRET_KEY 환경변수가 설정되지 않았습니다.\n"
            '  python -c "import secrets; print(secrets.token_hex(32))"\n'
            "위 명령으로 생성한 값을 .env 파일에 SECRET_KEY=... 로 저장하세요."
        )
    app.config["SECRET_KEY"] = secret_key
    app.config["DATABASE"] = os.environ.get("DATABASE", "market.db")

    # ─────────────────────────────────────────────────────────
    # [보안 수정 #11] 세션 쿠키 강화
    #
    # 베이스 코드는 아무 설정이 없어 HttpOnly(Flask 기본값)만 걸려 있었다.
    # 실측: Set-Cookie: session=...; HttpOnly; Path=/   ← SameSite/Secure 없음
    # ─────────────────────────────────────────────────────────
    app.config.update(
        # JS에서 document.cookie로 세션을 읽지 못하게 한다 (XSS 피해 완화)
        SESSION_COOKIE_HTTPONLY=True,
        # 크로스 사이트 요청에 쿠키가 실려나가지 않게 한다 (CSRF 2차 방어)
        SESSION_COOKIE_SAMESITE="Lax",
        # HTTPS 배포 시 True. 로컬 HTTP 개발에서 True면 쿠키가 아예 안 붙어
        # 로그인이 불가능하므로 환경변수로 제어한다.
        SESSION_COOKIE_SECURE=os.environ.get("HTTPS_ONLY", "0") == "1",
        # 세션 만료. 무기한 세션은 탈취된 쿠키가 영원히 유효하다는 뜻이다.
        PERMANENT_SESSION_LIFETIME=timedelta(hours=2),
        # 요청 본문 크기 상한 (DoS 방어)
        MAX_CONTENT_LENGTH=2 * 1024 * 1024,
    )

    # ─────────────────────────────────────────────────────────
    # [보안 수정 #4] CSRF 보호
    #
    # 베이스 코드의 모든 POST 폼에 토큰이 없었다. 공격자 페이지에
    # <form action="http://victim/transfer" method="POST"> 를 심어두면
    # 피해자가 방문하는 것만으로 피해자 세션으로 강제 송금이 실행된다.
    # CSRFProtect는 앱 전체 POST/PUT/DELETE에 토큰 검증을 강제한다.
    # ─────────────────────────────────────────────────────────
    CSRFProtect(app)

    # ─────────────────────────────────────────────────────────
    # [보안 수정 #7] Rate Limiting
    #
    # 베이스 코드엔 아무 제한이 없어 초당 수백 번 로그인을 시도해도
    # 막히지 않았다. 계정 잠금(login 참고)과 함께 이중으로 건다.
    # 학습용이라 메모리 저장소를 쓴다. 운영에서는 프로세스가 여러 개라
    # Redis 등 공유 저장소가 필요하다.
    # ─────────────────────────────────────────────────────────
    limiter = Limiter(
        get_remote_address,
        app=app,
        default_limits=["300 per hour"],
        storage_uri="memory://",
    )

    app.teardown_appcontext(close_db)

    # ─────────────────────────────────────────────────────────
    # [보안 수정 #13] 보안 헤더
    # ─────────────────────────────────────────────────────────
    @app.after_request
    def set_security_headers(response):
        # MIME 스니핑 차단: 브라우저가 응답을 멋대로 HTML로 해석해 실행하는 것을 막는다.
        response.headers["X-Content-Type-Options"] = "nosniff"
        # 클릭재킹 차단: 우리 페이지가 공격자 사이트의 iframe에 실리는 것을 막는다.
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "same-origin"
        # CSP: XSS가 발생하더라도 스크립트 실행 경로를 좁힌다.
        #
        # script-src에 'self'만 두고 'unsafe-inline'을 뺐다. 이러면 공격자가
        # 페이지에 <script>를 주입하는 데 성공하더라도 브라우저가 실행을 거부한다.
        # 이를 위해 모든 JS를 static/js/*.js 외부 파일로 분리했다.
        #
        # 베이스 코드는 socket.io를 cdnjs에서 불러왔다. 외부 CDN은 공급망
        # 공격 표면이다(CDN이 침해되면 우리 사이트에 악성 코드가 주입된다).
        # 로컬로 내려받아 직접 서빙하고 CSP를 'self'로 제한한다.
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self'; "
            "img-src 'self' data:; "
            "connect-src 'self' ws: wss:; "
            "base-uri 'none'; "
            "form-action 'self'; "
            "frame-ancestors 'none'"
        )
        return response

    # ─────────────────────────────────────────────────────────
    # [보안 수정 #2 관련] 에러 처리
    #
    # debug=True를 끄면 예외 시 스택 트레이스 대신 이 페이지들이 나간다.
    # 내부 정보(파일 경로, DB 구조, 코드 일부)를 사용자에게 노출하지 않는다.
    # ─────────────────────────────────────────────────────────
    @app.errorhandler(400)
    def bad_request(err):
        return render_template("error.html", code=400,
                               message="잘못된 요청입니다."), 400

    @app.errorhandler(403)
    def forbidden(err):
        return render_template("error.html", code=403,
                               message="접근 권한이 없습니다."), 403

    @app.errorhandler(404)
    def not_found(err):
        return render_template("error.html", code=404,
                               message="페이지를 찾을 수 없습니다."), 404

    @app.errorhandler(413)
    def too_large(err):
        return render_template("error.html", code=413,
                               message="요청 크기가 너무 큽니다."), 413

    @app.errorhandler(429)
    def rate_limited(err):
        return render_template("error.html", code=429,
                               message="요청이 너무 많습니다. 잠시 후 다시 시도해주세요."), 429

    @app.errorhandler(500)
    def server_error(err):
        # 상세 내용은 서버 로그에만 남기고, 사용자에게는 일반 메시지만 보낸다.
        app.logger.exception("Unhandled error")
        return render_template("error.html", code=500,
                               message="서버 오류가 발생했습니다."), 500

    @app.context_processor
    def inject_globals():
        return {
            "current_user": get_current_user(),
            "report_threshold": REPORT_THRESHOLD,
        }

    # ═════════════════════════════════════════════════════════
    # 기본
    # ═════════════════════════════════════════════════════════

    @app.route("/")
    def index():
        if get_current_user():
            return redirect(url_for("dashboard"))
        return render_template("index.html")

    # ═════════════════════════════════════════════════════════
    # 인증
    # ═════════════════════════════════════════════════════════

    @app.route("/register", methods=["GET", "POST"])
    @limiter.limit("10 per hour", methods=["POST"])
    def register():
        if request.method == "POST":
            try:
                username = validate_username(request.form.get("username"))
                password = validate_password(request.form.get("password"))
            except ValidationError as err:
                flash(str(err))
                return redirect(url_for("register"))

            db = get_db()
            if db.execute("SELECT 1 FROM user WHERE username = ?",
                          (username,)).fetchone():
                flash("이미 존재하는 사용자명입니다.")
                return redirect(url_for("register"))

            user_id = str(uuid.uuid4())
            db.execute(
                # [보안 수정 #3] 평문 저장 → bcrypt 해시
                "INSERT INTO user (id, username, password_hash) VALUES (?, ?, ?)",
                (user_id, username, hash_password(password)),
            )
            write_audit(user_id, "register", target=username, ip=client_ip())
            flash("회원가입이 완료되었습니다. 로그인 해주세요.")
            return redirect(url_for("login"))
        return render_template("register.html")

    @app.route("/login", methods=["GET", "POST"])
    @limiter.limit("10 per minute", methods=["POST"])
    def login():
        if request.method == "POST":
            username = (request.form.get("username") or "").strip()
            password = request.form.get("password") or ""

            db = get_db()
            user = db.execute("SELECT * FROM user WHERE username = ?",
                              (username,)).fetchone()

            # [보안 수정 #3] 베이스 코드는 SQL에서 평문 비밀번호를 직접 비교했다:
            #   SELECT * FROM user WHERE username = ? AND password = ?
            # 해시를 쓰면 이 쿼리는 성립하지 않는다. 사용자명으로 조회한 뒤
            # bcrypt로 검증하는 구조로 바꾼다.
            if user is None:
                # [보안] 계정이 없어도 동일한 시간을 소비해 사용자 열거를 막는다.
                dummy_verify()
                flash("아이디 또는 비밀번호가 올바르지 않습니다.")
                return redirect(url_for("login"))

            # [보안 수정 #7] 계정 잠금 확인
            if user["locked_until"]:
                locked_until = datetime.fromisoformat(user["locked_until"])
                if locked_until > datetime.now(timezone.utc):
                    flash("로그인 시도가 너무 많습니다. 잠시 후 다시 시도해주세요.")
                    return redirect(url_for("login"))

            if not verify_password(password, user["password_hash"]):
                failed = user["failed_login_count"] + 1
                locked_until = None
                if failed >= MAX_FAILED_LOGINS:
                    locked_until = (
                        datetime.now(timezone.utc) + timedelta(minutes=LOCKOUT_MINUTES)
                    ).isoformat()
                    failed = 0
                    write_audit(user["id"], "account_locked", ip=client_ip())
                db.execute(
                    "UPDATE user SET failed_login_count = ?, locked_until = ? "
                    "WHERE id = ?",
                    (failed, locked_until, user["id"]),
                )
                # [보안] "비밀번호가 틀렸습니다"와 "없는 아이디입니다"를 구분하면
                #        어떤 아이디가 존재하는지 알려주게 된다. 메시지를 통일한다.
                flash("아이디 또는 비밀번호가 올바르지 않습니다.")
                return redirect(url_for("login"))

            if user["status"] == "blocked":
                flash("차단된 계정입니다. 관리자에게 문의하세요.")
                return redirect(url_for("login"))
            if user["status"] == "dormant":
                flash("신고 누적으로 휴면 전환된 계정입니다.")
                return redirect(url_for("login"))

            db.execute(
                "UPDATE user SET failed_login_count = 0, locked_until = NULL "
                "WHERE id = ?",
                (user["id"],),
            )

            # [보안] 세션 고정(session fixation) 방어.
            # 로그인 전 세션을 그대로 승격시키면, 공격자가 미리 심어둔
            # 세션 값이 인증된 세션으로 바뀐다. 기존 세션을 비우고 새로 만든다.
            session.clear()
            session["user_id"] = user["id"]
            session.permanent = True

            write_audit(user["id"], "login", ip=client_ip())
            flash("로그인 성공!")
            return redirect(url_for("dashboard"))
        return render_template("login.html")

    @app.route("/logout")
    @login_required
    def logout():
        session.clear()
        flash("로그아웃되었습니다.")
        return redirect(url_for("index"))

    # ═════════════════════════════════════════════════════════
    # 대시보드 · 검색
    # ═════════════════════════════════════════════════════════

    @app.route("/dashboard")
    @login_required
    def dashboard():
        db = get_db()
        # [차단] 차단된 상품은 목록에서 제외한다.
        products = db.execute(
            "SELECT p.*, u.username AS seller_name FROM product p "
            "JOIN user u ON u.id = p.seller_id "
            "WHERE p.status = 'active' ORDER BY p.created_at DESC LIMIT 50"
        ).fetchall()
        recent = db.execute(
            "SELECT m.content, m.created_at, u.username FROM message m "
            "JOIN user u ON u.id = m.sender_id "
            "WHERE m.receiver_id IS NULL ORDER BY m.created_at DESC LIMIT 30"
        ).fetchall()
        return render_template("dashboard.html", products=products,
                               recent_messages=list(reversed(recent)))

    @app.route("/search")
    @login_required
    def search():
        keyword = (request.args.get("q") or "").strip()[:100]
        db = get_db()
        if not keyword:
            products = []
        else:
            # [보안] SQL 인젝션 방어: 검색어를 문자열로 이어붙이지 않고
            #        파라미터 바인딩한다. 추가로 LIKE의 와일드카드(% _)를
            #        이스케이프해야 사용자가 '%'만 입력해 전체를 긁어가거나
            #        의도치 않은 패턴 매칭을 유발하는 것을 막는다.
            escaped = (keyword.replace("\\", "\\\\")
                              .replace("%", "\\%")
                              .replace("_", "\\_"))
            pattern = f"%{escaped}%"
            products = db.execute(
                "SELECT p.*, u.username AS seller_name FROM product p "
                "JOIN user u ON u.id = p.seller_id "
                "WHERE p.status = 'active' "
                "  AND (p.title LIKE ? ESCAPE '\\' "
                "       OR p.description LIKE ? ESCAPE '\\') "
                "ORDER BY p.created_at DESC LIMIT 50",
                (pattern, pattern),
            ).fetchall()
        return render_template("search.html", products=products, keyword=keyword)

    # ═════════════════════════════════════════════════════════
    # 프로필
    # ═════════════════════════════════════════════════════════

    @app.route("/profile", methods=["GET", "POST"])
    @login_required
    def profile():
        user = get_current_user()
        db = get_db()
        if request.method == "POST":
            try:
                bio = validate_text(request.form.get("bio"), "소개글",
                                    BIO_MAX, required=False)
            except ValidationError as err:
                flash(str(err))
                return redirect(url_for("profile"))
            db.execute("UPDATE user SET bio = ? WHERE id = ?", (bio, user["id"]))
            flash("프로필이 업데이트되었습니다.")
            return redirect(url_for("profile"))
        return render_template("profile.html", user=user)

    @app.route("/profile/password", methods=["POST"])
    @login_required
    def change_password():
        user = get_current_user()
        current = request.form.get("current_password") or ""

        # [보안] 민감 작업 재인증.
        # 현재 비밀번호를 묻지 않으면, 잠깐 자리를 비운 사이 남이 브라우저를
        # 만지거나 세션이 탈취됐을 때 곧바로 계정을 빼앗긴다.
        if not verify_password(current, user["password_hash"]):
            flash("현재 비밀번호가 올바르지 않습니다.")
            return redirect(url_for("profile"))

        try:
            new_password = validate_password(request.form.get("new_password"))
        except ValidationError as err:
            flash(str(err))
            return redirect(url_for("profile"))

        db = get_db()
        db.execute("UPDATE user SET password_hash = ? WHERE id = ?",
                   (hash_password(new_password), user["id"]))
        write_audit(user["id"], "password_change", ip=client_ip())
        flash("비밀번호가 변경되었습니다.")
        return redirect(url_for("profile"))

    @app.route("/user/<user_id>")
    @login_required
    def view_user(user_id):
        db = get_db()
        target = db.execute("SELECT * FROM user WHERE id = ?", (user_id,)).fetchone()
        if target is None:
            abort(404)
        products = db.execute(
            "SELECT * FROM product WHERE seller_id = ? AND status = 'active' "
            "ORDER BY created_at DESC LIMIT 50",
            (user_id,),
        ).fetchall()
        return render_template("user.html", target=target, products=products)

    @app.route("/chat/<user_id>")
    @login_required
    def direct_chat(user_id):
        """1:1 채팅 페이지."""
        user = get_current_user()
        if user_id == user["id"]:
            flash("자기 자신과는 채팅할 수 없습니다.")
            return redirect(url_for("user_list"))

        db = get_db()
        partner = db.execute(
            "SELECT id, username FROM user WHERE id = ? AND status = 'active'",
            (user_id,),
        ).fetchone()
        if partner is None:
            abort(404)

        # [보안] 대화 내역은 본인이 참여한 것만 조회한다. 조건을 빠뜨리면
        #        URL의 user_id만 바꿔 남의 대화를 훔쳐볼 수 있다(IDOR).
        history = db.execute(
            "SELECT m.content, m.created_at, m.sender_id, u.username "
            "FROM message m JOIN user u ON u.id = m.sender_id "
            "WHERE (m.sender_id = ? AND m.receiver_id = ?) "
            "   OR (m.sender_id = ? AND m.receiver_id = ?) "
            "ORDER BY m.created_at ASC LIMIT 100",
            (user["id"], partner["id"], partner["id"], user["id"]),
        ).fetchall()
        return render_template("chat.html", partner=partner, history=history)

    @app.route("/users")
    @login_required
    def user_list():
        db = get_db()
        users = db.execute(
            "SELECT id, username, bio, status FROM user "
            "WHERE status = 'active' ORDER BY created_at DESC LIMIT 100"
        ).fetchall()
        return render_template("users.html", users=users)

    # ═════════════════════════════════════════════════════════
    # 상품
    # ═════════════════════════════════════════════════════════

    @app.route("/product/new", methods=["GET", "POST"])
    @login_required
    @limiter.limit("30 per hour", methods=["POST"])
    def new_product():
        if request.method == "POST":
            try:
                title = validate_text(request.form.get("title"), "상품명", TITLE_MAX)
                description = validate_text(request.form.get("description"),
                                            "상품 설명", DESCRIPTION_MAX)
                # [보안 수정 #8] price가 TEXT라 음수/문자열이 그대로 저장됐다.
                #                정수 + 범위 검증으로 봉쇄.
                price = validate_positive_int(request.form.get("price"),
                                              "가격", PRICE_MAX)
            except ValidationError as err:
                flash(str(err))
                return redirect(url_for("new_product"))

            user = get_current_user()
            product_id = str(uuid.uuid4())
            db = get_db()
            db.execute(
                "INSERT INTO product (id, title, description, price, seller_id) "
                "VALUES (?, ?, ?, ?, ?)",
                (product_id, title, description, price, user["id"]),
            )
            write_audit(user["id"], "product_create", target=product_id,
                        ip=client_ip())
            flash("상품이 등록되었습니다.")
            return redirect(url_for("view_product", product_id=product_id))
        return render_template("new_product.html")

    @app.route("/product/<product_id>")
    @login_required
    def view_product(product_id):
        db = get_db()
        product = db.execute("SELECT * FROM product WHERE id = ?",
                             (product_id,)).fetchone()
        if product is None:
            abort(404)

        user = get_current_user()
        # [차단] 차단된 상품은 소유자와 관리자만 볼 수 있다.
        if (product["status"] == "blocked"
                and product["seller_id"] != user["id"]
                and user["role"] != "admin"):
            abort(404)

        seller = db.execute("SELECT * FROM user WHERE id = ?",
                            (product["seller_id"],)).fetchone()
        return render_template("view_product.html", product=product, seller=seller)

    @app.route("/product/<product_id>/edit", methods=["GET", "POST"])
    @owner_required_product
    def edit_product(product_id):
        db = get_db()
        if request.method == "POST":
            try:
                title = validate_text(request.form.get("title"), "상품명", TITLE_MAX)
                description = validate_text(request.form.get("description"),
                                            "상품 설명", DESCRIPTION_MAX)
                price = validate_positive_int(request.form.get("price"),
                                              "가격", PRICE_MAX)
            except ValidationError as err:
                flash(str(err))
                return redirect(url_for("edit_product", product_id=product_id))

            db.execute(
                "UPDATE product SET title = ?, description = ?, price = ? "
                "WHERE id = ?",
                (title, description, price, product_id),
            )
            write_audit(get_current_user()["id"], "product_edit",
                        target=product_id, ip=client_ip())
            flash("상품이 수정되었습니다.")
            return redirect(url_for("view_product", product_id=product_id))

        product = db.execute("SELECT * FROM product WHERE id = ?",
                             (product_id,)).fetchone()
        return render_template("edit_product.html", product=product)

    @app.route("/product/<product_id>/delete", methods=["POST"])
    @owner_required_product
    def delete_product(product_id):
        db = get_db()
        db.execute("DELETE FROM product WHERE id = ?", (product_id,))
        write_audit(get_current_user()["id"], "product_delete",
                    target=product_id, ip=client_ip())
        flash("상품이 삭제되었습니다.")
        return redirect(url_for("my_products"))

    @app.route("/my/products")
    @login_required
    def my_products():
        user = get_current_user()
        db = get_db()
        products = db.execute(
            "SELECT * FROM product WHERE seller_id = ? ORDER BY created_at DESC",
            (user["id"],),
        ).fetchall()
        return render_template("my_products.html", products=products)

    # ═════════════════════════════════════════════════════════
    # 송금
    # ═════════════════════════════════════════════════════════

    @app.route("/transfer", methods=["GET", "POST"])
    @login_required
    @limiter.limit("20 per hour", methods=["POST"])
    def transfer():
        user = get_current_user()
        if request.method == "POST":
            try:
                to_username = validate_username(request.form.get("to_username"))
                amount = validate_positive_int(request.form.get("amount"),
                                               "송금액", AMOUNT_MAX)
            except ValidationError as err:
                flash(str(err))
                return redirect(url_for("transfer"))

            try:
                # ─────────────────────────────────────────────
                # [보안 핵심] 송금은 반드시 하나의 트랜잭션 안에서.
                #
                # 잔액 확인과 차감이 분리되면 TOCTOU 경쟁 조건이 생긴다.
                # 잔액 1000원인 계정에서 1000원 송금 요청을 동시에 두 번 보내면,
                # 두 요청이 각자 "잔액 1000 >= 1000, 통과"를 읽고 각각 차감해
                # 2000원이 나간다. write_transaction()의 BEGIN IMMEDIATE가
                # 두 번째 요청을 첫 번째가 끝날 때까지 대기시켜 이를 막는다.
                # ─────────────────────────────────────────────
                with write_transaction() as db:
                    sender = db.execute("SELECT * FROM user WHERE id = ?",
                                        (user["id"],)).fetchone()
                    receiver = db.execute("SELECT * FROM user WHERE username = ?",
                                          (to_username,)).fetchone()

                    if receiver is None:
                        raise ValidationError("받는 사용자를 찾을 수 없습니다.")
                    if receiver["id"] == sender["id"]:
                        raise ValidationError("자기 자신에게는 송금할 수 없습니다.")
                    if receiver["status"] != "active":
                        raise ValidationError("해당 계정은 현재 송금을 받을 수 없습니다.")
                    if sender["balance"] < amount:
                        raise ValidationError("잔액이 부족합니다.")

                    db.execute("UPDATE user SET balance = balance - ? WHERE id = ?",
                               (amount, sender["id"]))
                    db.execute("UPDATE user SET balance = balance + ? WHERE id = ?",
                               (amount, receiver["id"]))
                    db.execute(
                        "INSERT INTO transfer (id, sender_id, receiver_id, amount) "
                        "VALUES (?, ?, ?, ?)",
                        (str(uuid.uuid4()), sender["id"], receiver["id"], amount),
                    )
                    write_audit(sender["id"], "transfer", target=receiver["id"],
                                detail=str(amount), ip=client_ip())
            except ValidationError as err:
                flash(str(err))
                return redirect(url_for("transfer"))

            flash(f"{to_username}님에게 {amount:,}원을 송금했습니다.")
            return redirect(url_for("transfer"))

        db = get_db()
        history = db.execute(
            "SELECT t.*, s.username AS sender_name, r.username AS receiver_name "
            "FROM transfer t "
            "JOIN user s ON s.id = t.sender_id "
            "JOIN user r ON r.id = t.receiver_id "
            "WHERE t.sender_id = ? OR t.receiver_id = ? "
            "ORDER BY t.created_at DESC LIMIT 30",
            (user["id"], user["id"]),
        ).fetchall()
        return render_template("transfer.html", user=user, history=history)

    @app.route("/charge", methods=["POST"])
    @login_required
    @limiter.limit("10 per hour")
    def charge():
        """학습용 잔액 충전. 실제 결제 연동(PG) 대신 테스트 편의를 위해 둔다."""
        user = get_current_user()
        try:
            amount = validate_positive_int(request.form.get("amount"),
                                           "충전액", 1_000_000)
        except ValidationError as err:
            flash(str(err))
            return redirect(url_for("transfer"))
        db = get_db()
        db.execute("UPDATE user SET balance = balance + ? WHERE id = ?",
                   (amount, user["id"]))
        write_audit(user["id"], "charge", detail=str(amount), ip=client_ip())
        flash(f"{amount:,}원이 충전되었습니다.")
        return redirect(url_for("transfer"))

    # ═════════════════════════════════════════════════════════
    # 신고
    # ═════════════════════════════════════════════════════════

    @app.route("/report", methods=["GET", "POST"])
    @login_required
    @limiter.limit("20 per hour", methods=["POST"])
    def report():
        user = get_current_user()
        if request.method == "POST":
            target_type = request.form.get("target_type")
            target_id = (request.form.get("target_id") or "").strip()

            try:
                reason = validate_text(request.form.get("reason"),
                                       "신고 사유", REASON_MAX)
            except ValidationError as err:
                flash(str(err))
                return redirect(url_for("report"))

            # [보안 수정 #9] 베이스 코드는 target_id를 아무 검증 없이 저장했다.
            #                존재하지 않는 대상, 자기 자신, 중복 신고가 전부 통과했다.
            if target_type not in ("user", "product"):
                flash("잘못된 신고 대상입니다.")
                return redirect(url_for("report"))

            db = get_db()
            # target_type은 바로 위 화이트리스트를 통과한 두 리터럴 중 하나뿐이라
            # 사용자 입력이 SQL 문자열에 직접 들어가지 않는다. target_id는 바인딩된다.
            table = "user" if target_type == "user" else "product"

            target = db.execute(
                f"SELECT id FROM {table} WHERE id = ?", (target_id,)
            ).fetchone()
            if target is None:
                flash("신고 대상을 찾을 수 없습니다.")
                return redirect(url_for("report"))

            if target_type == "user" and target_id == user["id"]:
                flash("자기 자신은 신고할 수 없습니다.")
                return redirect(url_for("report"))

            try:
                db.execute(
                    "INSERT INTO report "
                    "(id, reporter_id, target_type, target_id, reason) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (str(uuid.uuid4()), user["id"], target_type, target_id, reason),
                )
            except sqlite3.IntegrityError:
                # UNIQUE(reporter_id, target_type, target_id) 위반.
                # [신고 남용 방지] 같은 대상을 반복 신고해 차단시키는 공격 차단.
                flash("이미 신고한 대상입니다.")
                return redirect(url_for("report"))

            count = db.execute(
                "SELECT COUNT(*) AS c FROM report "
                "WHERE target_type = ? AND target_id = ?",
                (target_type, target_id),
            ).fetchone()["c"]
            db.execute(f"UPDATE {table} SET report_count = ? WHERE id = ?",
                       (count, target_id))

            # [차단] 임계치 초과 시 자동 조치
            if count >= REPORT_THRESHOLD:
                if target_type == "product":
                    db.execute("UPDATE product SET status = 'blocked' WHERE id = ?",
                               (target_id,))
                else:
                    # 관리자는 자동 휴면 대상에서 제외한다. 악의적 사용자들이
                    # 담합해 관리자를 신고하면 플랫폼 운영이 마비된다.
                    db.execute(
                        "UPDATE user SET status = 'dormant' "
                        "WHERE id = ? AND role != 'admin'",
                        (target_id,),
                    )
                write_audit(None, f"auto_block_{target_type}", target=target_id,
                            detail=f"reports={count}")

            write_audit(user["id"], "report", target=target_id,
                        detail=target_type, ip=client_ip())
            flash("신고가 접수되었습니다.")
            return redirect(url_for("dashboard"))

        return render_template(
            "report.html",
            target_type=request.args.get("target_type", ""),
            target_id=request.args.get("target_id", ""),
        )

    # ═════════════════════════════════════════════════════════
    # 관리자
    # ═════════════════════════════════════════════════════════

    @app.route("/admin")
    @admin_required
    def admin_dashboard():
        db = get_db()
        stats = {
            "users": db.execute("SELECT COUNT(*) AS c FROM user").fetchone()["c"],
            "products": db.execute(
                "SELECT COUNT(*) AS c FROM product").fetchone()["c"],
            "reports": db.execute("SELECT COUNT(*) AS c FROM report").fetchone()["c"],
            "transfers": db.execute(
                "SELECT COUNT(*) AS c FROM transfer").fetchone()["c"],
        }
        reports = db.execute(
            "SELECT r.*, u.username AS reporter_name FROM report r "
            "JOIN user u ON u.id = r.reporter_id "
            "ORDER BY r.created_at DESC LIMIT 50"
        ).fetchall()
        return render_template("admin/dashboard.html", stats=stats, reports=reports)

    @app.route("/admin/users")
    @admin_required
    def admin_users():
        db = get_db()
        users = db.execute(
            "SELECT * FROM user ORDER BY report_count DESC, created_at DESC"
        ).fetchall()
        return render_template("admin/users.html", users=users)

    @app.route("/admin/users/<user_id>/status", methods=["POST"])
    @admin_required
    def admin_set_user_status(user_id):
        new_status = request.form.get("status")
        if new_status not in ("active", "dormant", "blocked"):
            abort(400)

        admin = get_current_user()
        # [보안] 관리자가 자기 자신을 차단해 시스템에서 잠기는 것을 막는다.
        if user_id == admin["id"]:
            flash("자기 자신의 상태는 변경할 수 없습니다.")
            return redirect(url_for("admin_users"))

        db = get_db()
        db.execute("UPDATE user SET status = ? WHERE id = ?", (new_status, user_id))
        write_audit(admin["id"], "admin_set_user_status", target=user_id,
                    detail=new_status, ip=client_ip())
        flash(f"사용자 상태를 {new_status}(으)로 변경했습니다.")
        return redirect(url_for("admin_users"))

    @app.route("/admin/products")
    @admin_required
    def admin_products():
        db = get_db()
        products = db.execute(
            "SELECT p.*, u.username AS seller_name FROM product p "
            "JOIN user u ON u.id = p.seller_id "
            "ORDER BY p.report_count DESC, p.created_at DESC"
        ).fetchall()
        return render_template("admin/products.html", products=products)

    @app.route("/admin/products/<product_id>/status", methods=["POST"])
    @admin_required
    def admin_set_product_status(product_id):
        new_status = request.form.get("status")
        if new_status not in ("active", "blocked", "sold"):
            abort(400)
        db = get_db()
        db.execute("UPDATE product SET status = ? WHERE id = ?",
                   (new_status, product_id))
        write_audit(get_current_user()["id"], "admin_set_product_status",
                    target=product_id, detail=new_status, ip=client_ip())
        flash(f"상품 상태를 {new_status}(으)로 변경했습니다.")
        return redirect(url_for("admin_products"))

    @app.route("/admin/logs")
    @admin_required
    def admin_logs():
        db = get_db()
        logs = db.execute(
            "SELECT a.*, u.username AS actor_name FROM audit_log a "
            "LEFT JOIN user u ON u.id = a.actor_id "
            "ORDER BY a.id DESC LIMIT 200"
        ).fetchall()
        return render_template("admin/logs.html", logs=logs)

    # ═════════════════════════════════════════════════════════
    # 실시간 채팅 (Socket.IO)
    # ═════════════════════════════════════════════════════════

    socketio = SocketIO(
        app,
        async_mode="gevent",
        # [보안] Socket.IO는 기본적으로 모든 출처의 연결을 허용한다.
        #        공격자 사이트가 피해자 브라우저를 통해 우리 소켓에 붙는 것을 막는다.
        cors_allowed_origins=os.environ.get(
            "ALLOWED_ORIGINS", "http://127.0.0.1:5000,http://localhost:5000"
        ).split(","),
    )

    # 소켓 메시지 rate limit: {user_id: [timestamp, ...]}
    msg_times: dict = {}

    def socket_user():
        """[보안 수정 #5] Socket.IO 이벤트에서도 세션 인증을 확인한다.

        베이스 코드는 인증 검사가 전혀 없어, 로그인하지 않은 사람도
        소켓에 붙어 전체 브로드캐스트를 할 수 있었다.
        """
        if "user_id" not in session:
            return None
        db = get_db()
        return db.execute(
            "SELECT * FROM user WHERE id = ? AND status = 'active'",
            (session["user_id"],),
        ).fetchone()

    @socketio.on("connect")
    def on_connect():
        user = socket_user()
        if user is None:
            return False  # 연결 거부
        join_room(f"user:{user['id']}")
        return True

    @socketio.on("send_message")
    def on_send_message(data):
        user = socket_user()
        if user is None:
            return

        # ─────────────────────────────────────────────────────
        # [보안 수정 #6] 신원은 클라이언트에게 묻지 않는다.
        #
        # 베이스 코드(dashboard.html):
        #   socket.emit('send_message', {username: "{{ user.username }}", ...})
        # 베이스 코드(app.py):
        #   send(data, broadcast=True)   ← 클라이언트가 보낸 username을 그대로 신뢰
        #
        # 브라우저 콘솔에서 username을 'admin'으로 바꿔 emit하면 관리자
        # 사칭이 성립했다. 클라이언트가 보낸 username은 완전히 무시하고,
        # 세션에서 서버가 조회한 값만 사용한다.
        # ─────────────────────────────────────────────────────
        if not isinstance(data, dict):
            return

        # [보안 수정 #12] 메시지 길이 제한.
        # 베이스 코드는 클라이언트가 보낸 dict를 그대로 브로드캐스트해
        # 거대한 메시지로 전체 사용자 브라우저를 마비시킬 수 있었다.
        try:
            content = validate_text(data.get("message"), "메시지", MESSAGE_MAX)
        except ValidationError:
            return

        # [보안] 소켓 레벨 rate limit (스팸 방지).
        # HTTP 라우트의 Flask-Limiter는 소켓 이벤트에 적용되지 않는다.
        now = time.time()
        times = [t for t in msg_times.get(user["id"], []) if now - t < 10]
        if len(times) >= MSG_PER_10SEC:
            return
        times.append(now)
        msg_times[user["id"]] = times

        receiver_id = data.get("receiver_id") or None
        db = get_db()

        if receiver_id:
            receiver = db.execute(
                "SELECT id FROM user WHERE id = ? AND status = 'active'",
                (receiver_id,),
            ).fetchone()
            if receiver is None:
                return

        db.execute(
            "INSERT INTO message (id, sender_id, receiver_id, content) "
            "VALUES (?, ?, ?, ?)",
            (str(uuid.uuid4()), user["id"], receiver_id, content),
        )

        payload = {
            "username": user["username"],   # ← 서버가 세션에서 조회한 값
            "user_id": user["id"],
            "message": content,
            "scope": "dm" if receiver_id else "global",
        }

        if receiver_id:
            emit("message", payload, room=f"user:{receiver_id}")
            emit("message", payload, room=f"user:{user['id']}")
        else:
            emit("message", payload, broadcast=True)

    return app, socketio


def ensure_admin(app) -> None:
    """관리자 계정 보장.

    [보안] 비밀번호를 코드에 박지 않는다. 환경변수가 없으면 임의 생성해
           콘솔에 1회 출력한다. 'admin/admin' 같은 기본 계정은 공개 배포
           즉시 탈취된다.
    """
    with app.app_context():
        db = get_db()
        if db.execute("SELECT 1 FROM user WHERE role = 'admin' LIMIT 1").fetchone():
            return

        username = os.environ.get("ADMIN_USERNAME", "admin")
        password = os.environ.get("ADMIN_PASSWORD")
        generated = False
        if not password:
            password = secrets.token_urlsafe(16)
            generated = True

        db.execute(
            "INSERT INTO user (id, username, password_hash, role) "
            "VALUES (?, ?, ?, 'admin')",
            (str(uuid.uuid4()), username, hash_password(password)),
        )
        close_db()

        # flush=True: stdout이 파일이나 파이프로 연결되면 파이썬이 출력을
        # 버퍼링한다. 이 비밀번호는 한 번만 표시되므로, 버퍼에 남은 채
        # 프로세스가 죽으면 영영 잃어버린다.
        if generated:
            print("=" * 64, flush=True)
            print("  관리자 계정이 생성되었습니다. 이 비밀번호는 다시 표시되지 않습니다.",
                  flush=True)
            print(f"    아이디   : {username}", flush=True)
            print(f"    비밀번호 : {password}", flush=True)
            print("=" * 64, flush=True)
        else:
            print(f"[init] 관리자 계정 '{username}' 생성됨 (ADMIN_PASSWORD 사용)",
                  flush=True)


if __name__ == "__main__":
    application, sio = create_app()
    init_db(application)
    ensure_admin(application)

    # ─────────────────────────────────────────────────────────
    # [보안 수정 #2] debug=True 제거
    #
    # 베이스 코드: socketio.run(app, debug=True)
    # Werkzeug 디버거가 켜지면 예외 페이지에서 임의 파이썬 코드를 실행할 수
    # 있다(RCE). 스택 트레이스로 파일 경로와 DB 구조도 노출된다.
    # 기본값을 False로 두고, 개발 중에만 환경변수로 켠다.
    # ─────────────────────────────────────────────────────────
    debug_mode = os.environ.get("FLASK_DEBUG", "0") == "1"
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "5000"))

    sio.run(application, host=host, port=port, debug=debug_mode)
