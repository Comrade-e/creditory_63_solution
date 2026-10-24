import hashlib
import hmac
import os
from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

import jwt
from fastapi import Cookie, FastAPI, Header, HTTPException, Query, Response
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.responses import JSONResponse
from jwt import InvalidTokenError
from pydantic import BaseModel, EmailStr, Field
from pwdlib import PasswordHash
from psycopg.errors import UniqueViolation

from backend.src.db import get_connection


password_hash = PasswordHash.recommended()

JWT_SECRET_KEY = os.environ["JWT_SECRET_KEY"]
JWT_ALGORITHM = "HS256"

ACCESS_TOKEN_MINUTES = 30
REFRESH_TOKEN_DAYS = 30
REFRESH_COOKIE_NAME = "refreshToken"
REFRESH_COOKIE_PATH = "/api/v1/auth"

# For local HTTP development this can be false.
# In production, use HTTPS and set REFRESH_COOKIE_SECURE=true.
REFRESH_COOKIE_SECURE = os.getenv("REFRESH_COOKIE_SECURE", "false").lower() == "true"
REFRESH_COOKIE_SAMESITE = os.getenv("REFRESH_COOKIE_SAMESITE", "lax").lower()

app = FastAPI()


# All API errors use the same response envelope:
# {"error": {"code": "...", "message": "...", "fields": {...}}}
STATUS_ERROR_CODES = {
    400: "VALIDATION_ERROR",
    401: "UNAUTHORIZED",
    403: "FORBIDDEN",
    404: "NOT_FOUND",
    409: "CONFLICT",
    413: "FILE_TOO_LARGE",
    415: "UNSUPPORTED_MEDIA_TYPE",
    422: "VALIDATION_ERROR",
}


def _field_name(location: tuple) -> str | None:
    """Convert a Pydantic error location into a client-facing field path."""
    parts = [str(part) for part in location if part not in ("body", "query", "path", "header")]
    if not parts:
        return None

    # Keep the first segment in camelCase and support nested objects/arrays.
    def camel_case(value: str) -> str:
        chunks = value.split("_")
        return chunks[0] + "".join(chunk[:1].upper() + chunk[1:] for chunk in chunks[1:])

    parts[0] = camel_case(parts[0])
    return ".".join(parts)


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request, exc: RequestValidationError):
    fields = {}
    for error in exc.errors():
        name = _field_name(tuple(error.get("loc", ())))
        if name:
            fields[name] = error.get("msg", "Некорректное значение")

    return JSONResponse(
        status_code=422,
        content={
            "error": {
                "code": "VALIDATION_ERROR",
                "message": "Проверьте обязательные поля",
                "fields": fields,
            }
        },
    )


@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request, exc: StarletteHTTPException):
    status_code = exc.status_code
    code = STATUS_ERROR_CODES.get(status_code, "HTTP_ERROR")
    detail = exc.detail

    default_messages = {
        400: "Проверьте переданные данные",
        401: "Сессия истекла или недействительна",
        403: "Недостаточно прав для выполнения операции",
        404: "Ресурс не найден или недоступен",
        409: "Операция конфликтует с текущим состоянием ресурса",
        413: "Файл превышает допустимый размер",
        415: "Неподдерживаемый тип файла",
        422: "Проверьте обязательные поля",
    }
    message = detail if isinstance(detail, str) else default_messages.get(status_code, "Ошибка запроса")

    # For custom validation errors, keep the same envelope and allow field-level details.
    fields = {}
    if isinstance(detail, dict):
        message = detail.get("message", default_messages.get(status_code, "Ошибка запроса"))
        fields = detail.get("fields", {})
        code = detail.get("code", code)

    return JSONResponse(
        status_code=status_code,
        content={
            "error": {
                "code": code,
                "message": message,
                "fields": fields,
            }
        },
        headers=exc.headers,
    )


@app.exception_handler(Exception)
async def unhandled_exception_handler(request, exc: Exception):
    # Do not expose database errors, stack traces, or secrets to API clients.
    return JSONResponse(
        status_code=500,
        content={
            "error": {
                "code": "INTERNAL_SERVER_ERROR",
                "message": "Внутренняя ошибка сервера",
                "fields": {},
            }
        },
    )


class RegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)
    passwordConfirmation: str


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


def hash_refresh_token(token: str) -> str:
    """Store only a SHA-256 hash of the refresh token in the database."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def create_access_token(user_id: str, role: str, session_id: str) -> str:
    now = datetime.now(timezone.utc)
    return jwt.encode(
        {
            "sub": str(user_id),
            "role": role,
            "sid": str(session_id),
            "type": "access",
            "iat": now,
            "exp": now + timedelta(minutes=ACCESS_TOKEN_MINUTES),
        },
        JWT_SECRET_KEY,
        algorithm=JWT_ALGORITHM,
    )


def create_refresh_token(
    user_id: str, role: str, session_id: str
) -> tuple[str, datetime]:
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(days=REFRESH_TOKEN_DAYS)

    token = jwt.encode(
        {
            "sub": str(user_id),
            "role": role,
            "sid": str(session_id),
            "type": "refresh",
            "iat": now,
            "exp": expires_at,
        },
        JWT_SECRET_KEY,
        algorithm=JWT_ALGORITHM,
    )
    return token, expires_at


def set_refresh_cookie(response: Response, token: str, expires_at: datetime) -> None:
    max_age = max(
        0,
        int((expires_at - datetime.now(timezone.utc)).total_seconds()),
    )
    response.set_cookie(
        key=REFRESH_COOKIE_NAME,
        value=token,
        httponly=True,
        secure=REFRESH_COOKIE_SECURE,
        samesite=REFRESH_COOKIE_SAMESITE,
        path=REFRESH_COOKIE_PATH,
        max_age=max_age,
        expires=expires_at,
    )


def clear_refresh_cookie(response: Response) -> None:
    response.delete_cookie(
        key=REFRESH_COOKIE_NAME,
        path=REFRESH_COOKIE_PATH,
        httponly=True,
        secure=REFRESH_COOKIE_SECURE,
        samesite=REFRESH_COOKIE_SAMESITE,
    )


@app.get("/")
async def root():
    return {"message": "Hello World"}


@app.post("/api/v1/auth/register", status_code=201)
def register(data: RegisterRequest):
    if data.password != data.passwordConfirmation:
        raise HTTPException(
            status_code=400,
            detail="Passwords do not match",
        )

    hashed_password = password_hash.hash(data.password)

    try:
        with get_connection() as conn, conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO users (email, password_hash)
                VALUES (%s, %s)
                RETURNING id, email, role, created_at;
                """,
                (str(data.email), hashed_password),
            )
            user = cur.fetchone()

        return {
            "id": str(user[0]),
            "email": user[1],
            "role": user[2],
            "createdAt": user[3],
        }

    except UniqueViolation:
        raise HTTPException(
            status_code=409,
            detail="Email already registered",
        )


@app.post("/api/v1/auth/login")
def login(data: LoginRequest, response: Response):
    with get_connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            SELECT id, email, password_hash, role
            FROM users
            WHERE email = %s
            """,
            (str(data.email),),
        )
        user = cur.fetchone()

    if user is None or not password_hash.verify(data.password, user[2]):
        raise HTTPException(
            status_code=401,
            detail="Invalid email or password",
        )

    user_id = str(user[0])
    role = user[3]
    session_id = str(uuid4())

    access_token = create_access_token(user_id, role, session_id)
    refresh_token, refresh_expires_at = create_refresh_token(
        user_id, role, session_id
    )

    with get_connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO auth_sessions (
                id, user_id, refresh_token_hash, expires_at
            )
            VALUES (%s, %s, %s, %s)
            """,
            (
                session_id,
                user_id,
                hash_refresh_token(refresh_token),
                refresh_expires_at,
            ),
        )

    set_refresh_cookie(response, refresh_token, refresh_expires_at)

    # Refresh token is intentionally NOT returned in JSON.
    return {
        "accessToken": access_token,
        "tokenType": "bearer",
        "expiresIn": ACCESS_TOKEN_MINUTES * 60,
    }


@app.post("/api/v1/auth/refresh")
def refresh(
    response: Response,
    refresh_token: str | None = Cookie(default=None, alias=REFRESH_COOKIE_NAME),
):
    if not refresh_token:
        raise HTTPException(status_code=401, detail="Refresh cookie is missing")

    try:
        payload = jwt.decode(
            refresh_token,
            JWT_SECRET_KEY,
            algorithms=[JWT_ALGORITHM],
        )
    except InvalidTokenError:
        clear_refresh_cookie(response)
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired refresh token",
        )

    if payload.get("type") != "refresh":
        clear_refresh_cookie(response)
        raise HTTPException(status_code=401, detail="Refresh token required")

    user_id = payload.get("sub")
    session_id = payload.get("sid")
    if not user_id or not session_id:
        clear_refresh_cookie(response)
        raise HTTPException(status_code=401, detail="Invalid refresh token")

    try:
        user_uuid = UUID(user_id)
        session_uuid = UUID(session_id)
    except (ValueError, TypeError):
        clear_refresh_cookie(response)
        raise HTTPException(status_code=401, detail="Invalid refresh token")

    now = datetime.now(timezone.utc)

    # Lock the session row while checking and rotating the token. This prevents
    # two simultaneous refresh requests from both successfully using the same token.
    with get_connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            SELECT s.refresh_token_hash, s.expires_at, s.revoked_at, u.role
            FROM auth_sessions AS s
            JOIN users AS u ON u.id = s.user_id
            WHERE s.id = %s AND s.user_id = %s
            FOR UPDATE OF s
            """,
            (session_uuid, user_uuid),
        )
        session = cur.fetchone()

        if (
            session is None
            or session[2] is not None
            or session[1] <= now
            or not hmac.compare_digest(
                session[0], hash_refresh_token(refresh_token)
            )
        ):
            clear_refresh_cookie(response)
            raise HTTPException(
                status_code=401,
                detail="Refresh session is invalid or has been revoked",
            )

        role = session[3]
        new_refresh_token, new_refresh_expires_at = create_refresh_token(
            str(user_uuid), role, str(session_uuid)
        )
        cur.execute(
            """
            UPDATE auth_sessions
            SET refresh_token_hash = %s, expires_at = %s
            WHERE id = %s
            """,
            (
                hash_refresh_token(new_refresh_token),
                new_refresh_expires_at,
                session_uuid,
            ),
        )

    new_access_token = create_access_token(
        str(user_uuid), role, str(session_uuid)
    )
    set_refresh_cookie(response, new_refresh_token, new_refresh_expires_at)

    return {
        "accessToken": new_access_token,
        "tokenType": "bearer",
        "expiresIn": ACCESS_TOKEN_MINUTES * 60,
    }


@app.get("/api/v1/auth/me")
def get_me(authorization: str | None = Header(default=None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=401,
            detail="Bearer access token required",
        )

    token = authorization.removeprefix("Bearer ")

    try:
        payload = jwt.decode(
            token,
            JWT_SECRET_KEY,
            algorithms=[JWT_ALGORITHM],
        )
    except InvalidTokenError:
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired access token",
        )

    if payload.get("type") != "access":
        raise HTTPException(status_code=401, detail="Access token required")

    user_id = payload.get("sub")
    session_id = payload.get("sid")
    if not user_id or not session_id:
        raise HTTPException(status_code=401, detail="Invalid access token")

    try:
        session_uuid = UUID(session_id)
        user_uuid = UUID(user_id)
    except (ValueError, TypeError):
        raise HTTPException(status_code=401, detail="Invalid access token")

    with get_connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            SELECT u.id, u.email, u.role
            FROM users AS u
            JOIN auth_sessions AS s ON s.user_id = u.id
            WHERE u.id = %s
              AND s.id = %s
              AND s.revoked_at IS NULL
            """,
            (user_uuid, session_uuid),
        )
        user = cur.fetchone()

    if user is None:
        raise HTTPException(status_code=401, detail="Session is no longer active")

    return {
        "id": str(user[0]),
        "email": user[1],
        "role": user[2],
    }


@app.post("/api/v1/auth/logout", status_code=204)
def logout(
    response: Response,
    refresh_token: str | None = Cookie(default=None, alias=REFRESH_COOKIE_NAME),
):
    # Logout should succeed even if the cookie is already absent or expired.
    # Verify signature but allow an expired token so its session can still be revoked.
    if refresh_token:
        try:
            payload = jwt.decode(
                refresh_token,
                JWT_SECRET_KEY,
                algorithms=[JWT_ALGORITHM],
                options={"verify_exp": False},
            )
            if payload.get("type") == "refresh":
                user_id = payload.get("sub")
                session_id = payload.get("sid")
                if user_id and session_id:
                    try:
                        user_uuid = UUID(user_id)
                        session_uuid = UUID(session_id)
                    except (ValueError, TypeError):
                        pass
                    else:
                        with get_connection() as conn, conn.cursor() as cur:
                            cur.execute(
                                """
                                UPDATE auth_sessions
                                SET revoked_at = NOW()
                                WHERE id = %s
                                  AND user_id = %s
                                  AND revoked_at IS NULL
                                """,
                                (session_uuid, user_uuid),
                            )
        except InvalidTokenError:
            # Invalid cookies are still cleared; there is no valid session to revoke.
            pass

    clear_refresh_cookie(response)
    return response


@app.get("/api/v1/companies/lookup")
def lookup_company(inn: str = Query(min_length=10, max_length=12)):
    if not inn.isdigit() or len(inn) not in (10, 12):
        raise HTTPException(
            status_code=422,
            detail="INN must contain 10 or 12 digits",
        )

    with get_connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            SELECT inn, company_name, ogrn, address, okved
            FROM mock_companies
            WHERE inn = %s
            """,
            (inn,),
        )
        company = cur.fetchone()

    if company is None:
        raise HTTPException(status_code=404, detail="Company not found")

    return {
        "inn": company[0],
        "companyName": company[1],
        "ogrn": company[2],
        "address": company[3],
        "okved": company[4],
    }


@app.get("/api/v1/applications")
def get_applications():
    # Temporary placeholder. Replace with user_id from the validated access token.
    user_id = "test-user"

    try:
        with get_connection() as conn, conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, status, company_data, financial_data, created_at
                FROM applications
                WHERE user_id = %s
                ORDER BY created_at DESC
                """,
                (user_id,),
            )
            rows = cur.fetchall()

        return [
            {
                "id": str(row[0]),
                "status": row[1],
                "companyData": row[2],
                "financialData": row[3],
                "createdAt": row[4].isoformat(),
            }
            for row in rows
        ]

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail="Не удалось получить заявки",
        ) from exc


@app.get("/api/v1/applications/{id}")
def get_application(id: UUID):
    # Temporary placeholder. Replace with user_id from the validated access token.
    user_id = "test-user"

    with get_connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            SELECT id, status, company_data, financial_data, created_at
            FROM applications
            WHERE id = %s AND user_id = %s
            """,
            (id, user_id),
        )
        row = cur.fetchone()

    if row is None:
        raise HTTPException(status_code=404, detail="Заявка не найдена")

    return {
        "id": str(row[0]),
        "status": row[1],
        "companyData": row[2],
        "financialData": row[3],
        "createdAt": row[4].isoformat(),
    }
