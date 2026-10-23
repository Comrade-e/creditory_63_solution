from email.header import Header

from jwt import InvalidTokenError

from backend.src.db import *
from fastapi import FastAPI, HTTPException, Query
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


app = FastAPI()


class RegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)
    passwordConfirmation: str


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


@app.get("/")
async def root():
    return {"message": "Hello World"}

@app.post("/api/v1/applications")
def create_application():
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO applications (user_id)
                VALUES (%s)
                RETURNING id, status
            """, ("test-user",))

            application = cur.fetchone()

    return {
        "id": str(application[0]),
        "status": application[1],
    }

@app.post("/auth/register", status_code=201)
def register(data: RegisterRequest):
    if data.password != data.passwordConfirmation:
        raise HTTPException(
            status_code=400,
            detail="Passwords do not match",
        )

    hashed_password = password_hash.hash(data.password)

    try:
        with get_connection() as conn:
            with conn.cursor() as cur:
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
            "created_at": user[3],
        }

    except UniqueViolation:
        raise HTTPException(
            status_code=409,
            detail="Email already registered",
        )


@app.post("/auth/login")
def login(data: LoginRequest):
    with get_connection() as conn:
        with conn.cursor() as cur:
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

    now = datetime.now(timezone.utc)

    access_token = jwt.encode(
        {
            "sub": str(user[0]),
            "role": user[3],
            "iat": now,
            "exp": now + timedelta(minutes=30),
        },
        JWT_SECRET_KEY,
        algorithm=JWT_ALGORITHM,
    )

    return {
        "accessToken": access_token,
        "tokenType": "bearer",
        "expiresIn": 1800,
    }



@app.get("/auth/me")
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

@app.get("/companies/lookup")
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