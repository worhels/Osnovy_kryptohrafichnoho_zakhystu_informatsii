from __future__ import annotations

import logging
import os
import re
import secrets
import time
from collections import defaultdict, deque
from datetime import timedelta
from functools import wraps
from pathlib import Path
from typing import Any, Callable

from flask import Flask, flash, redirect, render_template, request, session, url_for

from benchmark import read_results, run_benchmark
from database import create_user, get_all_users, get_user_by_username, init_db
from password_hashing import (
    DEFAULT_ALGORITHM,
    SUPPORTED_ALGORITHMS,
    format_algorithm_name,
    get_algorithm_choices,
    hash_password,
    verify_password,
)


BASE_DIR = Path(__file__).resolve().parent
LOG_PATH = BASE_DIR / "app.log"
USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")
LOGIN_RATE_LIMIT = 5
LOGIN_RATE_WINDOW_SECONDS = 60
LOGIN_ATTEMPTS: dict[str, deque[float]] = defaultdict(deque)


app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.getenv("SECRET_KEY") or secrets.token_hex(32),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
)


def configure_logging() -> None:
    if any(
        isinstance(handler, logging.FileHandler)
        and getattr(handler, "baseFilename", "") == str(LOG_PATH)
        for handler in app.logger.handlers
    ):
        return

    file_handler = logging.FileHandler(LOG_PATH, encoding="utf-8")
    file_handler.setLevel(logging.INFO)
    file_handler.setFormatter(
        logging.Formatter("%(asctime)s | %(levelname)s | %(message)s")
    )

    app.logger.setLevel(logging.INFO)
    app.logger.addHandler(file_handler)
    app.logger.propagate = False


configure_logging()


def login_required(view: Callable[..., Any]) -> Callable[..., Any]:
    @wraps(view)
    def wrapped_view(*args: Any, **kwargs: Any) -> Any:
        if "username" not in session:
            flash("Увійдіть у систему, щоб переглянути цю сторінку.", "warning")
            return redirect(url_for("login"))
        return view(*args, **kwargs)

    return wrapped_view


def get_form_value(name: str, default: str = "") -> str:
    value = request.form.get(name, default)
    return value if isinstance(value, str) else default


def get_client_ip() -> str:
    forwarded_for = request.headers.get("X-Forwarded-For", "")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    return request.remote_addr or "unknown"


def get_csrf_token() -> str:
    token = session.get("_csrf_token")
    if not isinstance(token, str) or not token:
        token = secrets.token_urlsafe(32)
        session["_csrf_token"] = token
    return token


def validate_csrf_token() -> bool:
    token_from_form = get_form_value("csrf_token")
    token_from_session = session.get("_csrf_token")

    if not isinstance(token_from_session, str) or not token_from_form:
        return False

    is_valid = secrets.compare_digest(token_from_form, token_from_session)
    if is_valid:
        session["_csrf_token"] = secrets.token_urlsafe(32)
    return is_valid


def validate_username(username: str) -> str | None:
    if not USERNAME_PATTERN.fullmatch(username):
        return (
            "Логін повинен містити 3-32 символи та складатися з латинських літер, "
            "цифр, крапки, дефіса або underscore."
        )
    return None


def validate_password(password: str, confirm_password: str | None = None) -> str | None:
    if not password:
        return "Пароль не може бути порожнім."
    if len(password) < 8 or len(password) > 128:
        return "Пароль повинен містити від 8 до 128 символів."
    if confirm_password is not None and password != confirm_password:
        return "Підтвердження пароля не збігається."
    return None


def prune_login_attempts(ip_address: str) -> deque[float]:
    attempts = LOGIN_ATTEMPTS[ip_address]
    current_time = time.monotonic()
    while attempts and current_time - attempts[0] > LOGIN_RATE_WINDOW_SECONDS:
        attempts.popleft()
    return attempts


def is_login_rate_limited(ip_address: str) -> bool:
    return len(prune_login_attempts(ip_address)) >= LOGIN_RATE_LIMIT


def record_login_attempt(ip_address: str) -> None:
    attempts = prune_login_attempts(ip_address)
    attempts.append(time.monotonic())


def clear_login_attempts(ip_address: str) -> None:
    LOGIN_ATTEMPTS.pop(ip_address, None)


def normalize_benchmark_rows(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    normalized_rows: list[dict[str, Any]] = []

    for row in results:
        try:
            hash_ms = float(row["avg_hash_ms"])
            verify_ms = float(row["avg_verify_ms"])
            rounds = int(row["rounds"])
            password_length = int(row["password_length"])
        except (KeyError, TypeError, ValueError):
            continue

        algorithm = str(row.get("algorithm", ""))
        normalized_rows.append(
            {
                "algorithm": algorithm,
                "algorithm_display": format_algorithm_name(algorithm),
                "parameters": str(row.get("parameters", "")),
                "rounds": rounds,
                "avg_hash_ms": f"{hash_ms:.3f}",
                "avg_hash_ms_value": hash_ms,
                "avg_verify_ms": f"{verify_ms:.3f}",
                "avg_verify_ms_value": verify_ms,
                "correct_password": str(row.get("correct_password", "")),
                "wrong_password": str(row.get("wrong_password", "")),
                "password_length": password_length,
            }
        )

    if not normalized_rows:
        return []

    max_hash = max(row["avg_hash_ms_value"] for row in normalized_rows) or 1
    max_verify = max(row["avg_verify_ms_value"] for row in normalized_rows) or 1

    for row in normalized_rows:
        row["hash_bar_pct"] = max(10.0, (row["avg_hash_ms_value"] / max_hash) * 100)
        row["verify_bar_pct"] = max(
            10.0,
            (row["avg_verify_ms_value"] / max_verify) * 100,
        )

    return normalized_rows


def build_benchmark_summary(rows: list[dict[str, Any]]) -> dict[str, str]:
    if not rows:
        return {
            "fastest": "Ще не обчислено",
            "strongest": "Argon2id",
            "recommended": "Argon2id",
        }

    fastest_row = min(rows, key=lambda row: row["avg_hash_ms_value"])
    return {
        "fastest": (
            f"{fastest_row['algorithm_display']} "
            f"({fastest_row['parameters']})"
        ),
        "strongest": "Argon2id (m=65536, t=3, p=4)",
        "recommended": "Argon2id",
    }


@app.context_processor
def inject_template_helpers() -> dict[str, Any]:
    return {
        "csrf_token": get_csrf_token,
        "default_algorithm_label": format_algorithm_name(DEFAULT_ALGORITHM),
    }


@app.before_request
def startup() -> None:
    init_db()


@app.after_request
def apply_security_headers(response: Any) -> Any:
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "style-src 'self' 'unsafe-inline'; "
        "script-src 'self' 'unsafe-inline';"
    )
    return response


@app.route("/")
def index() -> str:
    return render_template(
        "index.html",
        current_user=session.get("username"),
    )


@app.route("/register", methods=["GET", "POST"])
def register() -> Any:
    selected_algorithm = DEFAULT_ALGORITHM
    form_username = ""

    if request.method == "POST":
        if not validate_csrf_token():
            flash("Сеанс форми недійсний. Спробуйте ще раз.", "danger")
            return redirect(url_for("register"))

        ip_address = get_client_ip()
        form_username = get_form_value("username").strip()
        password = get_form_value("password")
        confirm_password = get_form_value("confirm_password")
        selected_algorithm = get_form_value("algorithm", DEFAULT_ALGORITHM)

        username_error = validate_username(form_username)
        password_error = validate_password(password, confirm_password)

        if username_error:
            flash(username_error, "danger")
        elif password_error:
            flash(password_error, "danger")
        elif selected_algorithm not in SUPPORTED_ALGORITHMS:
            flash("Оберіть підтримуваний алгоритм хешування.", "danger")
        elif get_user_by_username(form_username):
            flash("Користувач з таким логіном уже існує.", "danger")
        else:
            stored_hash = hash_password(password, selected_algorithm)
            create_user(form_username, stored_hash, selected_algorithm)
            app.logger.info(
                "registration_success username=%s algorithm=%s ip=%s",
                form_username,
                selected_algorithm,
                ip_address,
            )
            flash("Реєстрацію завершено. Тепер можна увійти.", "success")
            return redirect(url_for("login"))

    return render_template(
        "register.html",
        algorithms=get_algorithm_choices(),
        selected_algorithm=selected_algorithm,
        form_username=form_username,
    )


@app.route("/login", methods=["GET", "POST"])
def login() -> Any:
    form_username = ""

    if request.method == "POST":
        if not validate_csrf_token():
            flash("Сеанс форми недійсний. Спробуйте ще раз.", "danger")
            return redirect(url_for("login"))

        ip_address = get_client_ip()
        form_username = get_form_value("username").strip()
        password = get_form_value("password")

        if is_login_rate_limited(ip_address):
            app.logger.warning(
                "login_rate_limited username=%s ip=%s",
                form_username or "empty",
                ip_address,
            )
            flash("Забагато спроб входу. Спробуйте ще раз пізніше.", "danger")
            return render_template("login.html", form_username=form_username)

        user = get_user_by_username(form_username) if form_username else None

        if user and verify_password(password, str(user["password_hash"])):
            clear_login_attempts(ip_address)
            session.clear()
            session.permanent = True
            session["user_id"] = int(user["id"])
            session["username"] = str(user["username"])
            app.logger.info(
                "login_success username=%s ip=%s",
                session["username"],
                ip_address,
            )
            flash("Вхід виконано успішно.", "success")
            return redirect(url_for("users"))

        record_login_attempt(ip_address)
        app.logger.warning(
            "login_failed username=%s ip=%s",
            form_username or "empty",
            ip_address,
        )
        flash("Невірний логін або пароль.", "danger")

    return render_template("login.html", form_username=form_username)


@app.route("/logout")
def logout() -> Any:
    session.clear()
    flash("Сеанс завершено.", "info")
    return redirect(url_for("index"))


@app.route("/users")
@login_required
def users() -> str:
    user_rows = get_all_users()
    return render_template(
        "users.html",
        users=user_rows,
        current_user=session.get("username"),
        user_count=len(user_rows),
        recommended_algorithm="Argon2id",
    )


@app.route("/benchmark", methods=["GET", "POST"])
@login_required
def benchmark() -> Any:
    raw_results: list[dict[str, Any]] = read_results()

    if request.method == "POST":
        if not validate_csrf_token():
            flash("Сеанс форми недійсний. Спробуйте ще раз.", "danger")
            return redirect(url_for("benchmark"))

        rounds_raw = get_form_value("rounds", "5").strip()

        try:
            rounds = max(1, min(int(rounds_raw), 20))
        except ValueError:
            rounds = 5

        raw_results = run_benchmark(rounds=rounds)
        app.logger.info(
            "benchmark_run username=%s rounds=%s ip=%s",
            session.get("username", "unknown"),
            rounds,
            get_client_ip(),
        )
        flash("Бенчмарк виконано успішно.", "success")

    benchmark_rows = normalize_benchmark_rows(raw_results)
    benchmark_summary = build_benchmark_summary(benchmark_rows)

    return render_template(
        "benchmark.html",
        results=benchmark_rows,
        benchmark_summary=benchmark_summary,
        current_user=session.get("username"),
    )


if __name__ == "__main__":
    init_db()
    app.run(debug=False)
