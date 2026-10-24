import hashlib
from email.header import Header

from jwt import InvalidTokenError

from uuid import UUID, uuid4

from backend.src.db import *
from fastapi import FastAPI, HTTPException, Query, Response
from pydantic import BaseModel, EmailStr, Field
from pwdlib import PasswordHash
from psycopg.errors import UniqueViolation

import os
import jwt

from datetime import datetime, timedelta, timezone
from fastapi import HTTPException, Header
from pydantic import BaseModel, EmailStr
from pwdlib import PasswordHash


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


class RegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)
    passwordConfirmation: str


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class RefreshRequest(BaseModel):
    refreshToken: str

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



@app.get("/api/v1/auth/me")
def get_me(authorization: str = Header()):
    if not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=401,
            detail="Invalid authorization header",
        )

    token = authorization.removeprefix("Bearer ")

    try:
        payload = jwt.decode(
            token,
            JWT_SECRET_KEY,
            algorithms=[JWT_ALGORITHM],
        )
        user_id = payload.get("sub")

        if not user_id:
            raise HTTPException(
                status_code=401,
                detail="Invalid token",
            )

    except InvalidTokenError:
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired token",
        )

    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, email, role, created_at
                FROM users
                WHERE id = %s
                """,
                (user_id,),
            )
            user = cur.fetchone()

    if user is None:
        raise HTTPException(
            status_code=401,
            detail="User not found",
        )

    return {
        "id": str(user[0]),
        "email": user[1],
        "role": user[2],
        "createdAt": user[3],
    }

@app.get("/api/v1/companies/lookup")
def lookup_company(inn: str = Query(min_length=10, max_length=12)):
    if not inn.isdigit() or len(inn) not in (10, 12):
        raise HTTPException(
            status_code=422,
            detail="INN must contain 10 or 12 digits",
        )

    with get_connection() as conn:
        with conn.cursor() as cur:
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
        raise HTTPException(
            status_code=404,
            detail="Company not found",
        )

    return {
        "inn": company[0],
        "companyName": company[1],
        "ogrn": company[2],
        "address": company[3],
        "okved": company[4],
    }



@app.get("/api/v1/applications")
def get_applications():
    # Временно. Позже заменить на user_id из проверенного accessToken.
    user_id = "test-user"

    try:
        with get_connection() as conn, conn.cursor() as cur:
            cur.execute(
                """
                SELECT
                    id,
                    status,
                    company_data,
                    financial_data,
                    created_at
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
    user_id = "test-user"  # Временно, до подключения авторизации

    with get_connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            SELECT
                id,
                status,
                company_data,
                financial_data,
                created_at
            FROM applications
            WHERE id = %s AND user_id = %s
            """,
            (id, user_id),
        )

        row = cur.fetchone()

    if row is None:
        raise HTTPException(
            status_code=404,
            detail="Заявка не найдена",
        )

    return {
        "id": str(row[0]),
        "status": row[1],
        "companyData": row[2],
        "financialData": row[3],
        "createdAt": row[4].isoformat(),
    }