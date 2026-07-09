"""Authentication router with JWT and RBAC."""

from datetime import datetime, timedelta, timezone
from typing import Annotated
from uuid import UUID

import jwt
from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jwt import PyJWTError
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.config import settings
from backend.app.hashing import hash_secret, verify_secret
from backend.app.lockout import clear_failures, is_locked_out, record_failure
from backend.app.models.user import User, Role
from backend.app.ratelimit import auth_limit, limiter, register_limit
from backend.app.services.database import get_db

router = APIRouter()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/token")


class UserCreate(BaseModel):
    username: str = Field(min_length=3, max_length=100)
    email: EmailStr
    # Enforce a minimum password length at the edge. Argon2id has no practical
    # input cap; bound the max to avoid abusive payloads.
    password: str = Field(min_length=12, max_length=128)
    # NOTE: role is intentionally NOT accepted from the client. Privileged roles
    # are assigned by an administrator via /users/{id}/role. Allowing the client
    # to choose its own role was a privilege-escalation vulnerability.


class RoleUpdate(BaseModel):
    role: Role


class UserResponse(BaseModel):
    id: UUID
    username: str
    email: str
    role: Role
    is_active: bool

    class Config:
        from_attributes = True


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int


class TokenData(BaseModel):
    user_id: str | None = None
    role: str | None = None


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return verify_secret(hashed_password, plain_password)


def get_password_hash(password: str) -> str:
    return hash_secret(password)


def create_access_token(data: dict, expires_delta: timedelta | None = None) -> str:
    to_encode = data.copy()
    now = datetime.now(timezone.utc)
    expire = now + (expires_delta or timedelta(minutes=settings.jwt_expire_minutes))
    to_encode.update({"exp": expire, "iat": now})
    return jwt.encode(to_encode, settings.secret_key, algorithm=settings.jwt_algorithm)


async def get_current_user(
    token: Annotated[str, Depends(oauth2_scheme)],
    db: Annotated[AsyncSession, Depends(get_db)]
) -> User:
    """Get current authenticated user from JWT token."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        payload = jwt.decode(token, settings.secret_key, algorithms=[settings.jwt_algorithm])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise credentials_exception
    except PyJWTError:
        raise credentials_exception

    # The JWT subject is a stringified UUID; cast it back so the comparison is
    # database-agnostic (a raw string fails against a UUID column on some DBs).
    try:
        user_uuid = UUID(user_id)
    except (ValueError, TypeError):
        raise credentials_exception

    result = await db.execute(select(User).where(User.id == user_uuid))
    user = result.scalar_one_or_none()

    if user is None or not user.is_active:
        raise credentials_exception

    return user


def require_role(allowed_roles: list[Role]):
    """Dependency to require specific roles."""
    async def role_checker(user: Annotated[User, Depends(get_current_user)]) -> User:
        if user.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions"
            )
        return user
    return role_checker


@router.post("/register", response_model=UserResponse)
@limiter.limit(register_limit)
async def register(
    request: Request,
    user_data: UserCreate,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Register a new user."""
    # Check if username exists
    result = await db.execute(select(User).where(User.username == user_data.username))
    if result.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="Username already registered")

    # Check if email exists
    result = await db.execute(select(User).where(User.email == user_data.email))
    if result.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="Email already registered")

    # First user to register bootstraps the ADMIN account. Everyone else gets
    # the least-privileged role and must be promoted by an administrator.
    total_users = await db.execute(select(func.count()).select_from(User))
    is_first_user = (total_users.scalar() or 0) == 0
    assigned_role = Role.ADMIN if is_first_user else Role.OPERATOR

    user = User(
        username=user_data.username,
        email=user_data.email,
        password_hash=get_password_hash(user_data.password),
        role=assigned_role,
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)

    return user


@router.patch("/users/{user_id}/role", response_model=UserResponse)
async def update_user_role(
    user_id: UUID,
    payload: RoleUpdate,
    db: Annotated[AsyncSession, Depends(get_db)],
    admin: Annotated[User, Depends(require_role([Role.ADMIN]))],
):
    """Assign a role to a user. Administrators only."""
    result = await db.execute(select(User).where(User.id == user_id))
    target = result.scalar_one_or_none()
    if target is None:
        raise HTTPException(status_code=404, detail="User not found")

    target.role = payload.role
    await db.commit()
    await db.refresh(target)
    return target


@router.post("/token", response_model=Token)
@limiter.limit(auth_limit)
async def login(
    request: Request,
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
    db: Annotated[AsyncSession, Depends(get_db)]
):
    """Login and get access token."""
    redis = getattr(request.app.state, "redis", None)

    # Defense-in-depth beyond rate limiting: temporarily lock an account after
    # too many failed attempts (keyed by username). No-op when Redis is absent.
    if await is_locked_out(redis, form_data.username):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Account temporarily locked due to failed login attempts. Try again later.",
        )

    result = await db.execute(select(User).where(User.username == form_data.username))
    user = result.scalar_one_or_none()

    if not user or not verify_password(form_data.password, user.password_hash):
        await record_failure(redis, form_data.username)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        raise HTTPException(status_code=400, detail="User account is disabled")

    # Successful auth clears the failure counter.
    await clear_failures(redis, form_data.username)

    # Update last login
    user.last_login = datetime.utcnow()
    await db.commit()

    access_token = create_access_token(
        data={"sub": str(user.id), "role": user.role.value}
    )

    return Token(
        access_token=access_token,
        expires_in=settings.jwt_expire_minutes * 60
    )


@router.get("/me", response_model=UserResponse)
async def get_me(user: Annotated[User, Depends(get_current_user)]):
    """Get current user information."""
    return user
