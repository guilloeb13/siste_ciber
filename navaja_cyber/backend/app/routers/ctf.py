"""CTF module router for training challenges."""

import hashlib
import secrets
from datetime import datetime
from typing import Annotated
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.config import settings
from backend.app.models.ctf import (
    Challenge, Team, Submission, CTFEvent,
    ChallengeCategory, ChallengeStatus
)
from backend.app.models.user import User, Role
from backend.app.routers.auth import get_current_user, require_role
from backend.app.services.database import get_db

router = APIRouter()


class EventCreate(BaseModel):
    name: str
    description: str | None = None
    start_time: datetime | None = None
    end_time: datetime | None = None


class ChallengeCreate(BaseModel):
    event_id: UUID | None = None
    name: str
    description: str
    category: ChallengeCategory
    points: int
    flag: str
    docker_image: str | None = None
    docker_config: dict = {}
    hints: list[str] = []
    files: list[str] = []


class TeamCreate(BaseModel):
    event_id: UUID | None = None
    name: str
    members: list[str] = []


class FlagSubmit(BaseModel):
    team_token: str
    challenge_id: UUID
    flag: str


class ChallengeResponse(BaseModel):
    id: UUID
    name: str
    description: str
    category: ChallengeCategory
    points: int
    solves: int
    hints: list[str]
    files: list[str]

    class Config:
        from_attributes = True


class TeamResponse(BaseModel):
    id: UUID
    name: str
    score: int
    members: list
    is_active: bool

    class Config:
        from_attributes = True


class ScoreboardEntry(BaseModel):
    rank: int
    team_name: str
    score: int
    solves: int
    last_solve: datetime | None


@router.post("/events", response_model=dict)
async def create_event(
    event_data: EventCreate,
    db: Annotated[AsyncSession, Depends(get_db)],
    user: Annotated[User, Depends(require_role([Role.ADMIN, Role.TRAINER]))],
):
    """Create a new CTF event."""
    event = CTFEvent(
        name=event_data.name,
        description=event_data.description,
        start_time=event_data.start_time,
        end_time=event_data.end_time,
    )

    db.add(event)
    await db.commit()
    await db.refresh(event)

    return {
        "event_id": str(event.id),
        "name": event.name,
        "message": "Event created successfully",
    }


@router.post("/challenges", response_model=dict)
async def create_challenge(
    challenge_data: ChallengeCreate,
    db: Annotated[AsyncSession, Depends(get_db)],
    user: Annotated[User, Depends(require_role([Role.ADMIN, Role.TRAINER]))],
):
    """
    Create a new CTF challenge.

    The flag is hashed before storage - the original flag is never stored.
    """
    # Hash the flag
    flag_hash = hashlib.sha256(
        (settings.ctf_flag_prefix + challenge_data.flag + settings.ctf_flag_suffix).encode()
    ).hexdigest()

    challenge = Challenge(
        event_id=challenge_data.event_id,
        name=challenge_data.name,
        description=challenge_data.description,
        category=challenge_data.category,
        points=challenge_data.points,
        flag_hash=flag_hash,
        docker_image=challenge_data.docker_image,
        docker_config=challenge_data.docker_config,
        hints=challenge_data.hints,
        files=challenge_data.files,
        status=ChallengeStatus.DRAFT,
    )

    db.add(challenge)
    await db.commit()
    await db.refresh(challenge)

    return {
        "challenge_id": str(challenge.id),
        "name": challenge.name,
        "category": challenge.category.value,
        "message": "Challenge created successfully",
    }


@router.get("/challenges", response_model=list[ChallengeResponse])
async def list_challenges(
    db: Annotated[AsyncSession, Depends(get_db)],
    user: Annotated[User, Depends(get_current_user)],
    event_id: UUID | None = None,
    category: ChallengeCategory | None = None,
):
    """List active challenges."""
    query = select(Challenge).where(Challenge.status == ChallengeStatus.ACTIVE)

    if event_id:
        query = query.where(Challenge.event_id == event_id)
    if category:
        query = query.where(Challenge.category == category)

    query = query.order_by(Challenge.points)

    result = await db.execute(query)
    return result.scalars().all()


@router.post("/challenges/{challenge_id}/activate")
async def activate_challenge(
    challenge_id: UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    user: Annotated[User, Depends(require_role([Role.ADMIN, Role.TRAINER]))],
):
    """Activate a challenge to make it available to teams."""
    result = await db.execute(select(Challenge).where(Challenge.id == challenge_id))
    challenge = result.scalar_one_or_none()

    if not challenge:
        raise HTTPException(status_code=404, detail="Challenge not found")

    challenge.status = ChallengeStatus.ACTIVE
    await db.commit()

    # Start Docker container if configured
    if challenge.docker_image:
        try:
            import docker
            client = docker.from_env()

            # Pull image if needed
            client.images.pull(challenge.docker_image)

            # Start container with configured options
            container = client.containers.run(
                challenge.docker_image,
                detach=True,
                network=settings.ctf_docker_network,
                name=f"ctf_{challenge_id}",
                **challenge.docker_config,
            )

            return {
                "status": "activated",
                "challenge_id": str(challenge_id),
                "container_id": container.short_id,
            }

        except Exception as e:
            return {
                "status": "activated_no_container",
                "challenge_id": str(challenge_id),
                "error": str(e),
            }

    return {
        "status": "activated",
        "challenge_id": str(challenge_id),
    }


@router.post("/teams", response_model=dict)
async def create_team(
    team_data: TeamCreate,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Create a new team and get authentication token."""
    # Generate team token
    token = secrets.token_urlsafe(16)

    team = Team(
        event_id=team_data.event_id,
        name=team_data.name,
        token=token,
        members=team_data.members,
    )

    db.add(team)
    await db.commit()
    await db.refresh(team)

    return {
        "team_id": str(team.id),
        "name": team.name,
        "token": token,
        "message": "Team created. Save this token - it's used to submit flags.",
    }


@router.get("/teams", response_model=list[TeamResponse])
async def list_teams(
    db: Annotated[AsyncSession, Depends(get_db)],
    user: Annotated[User, Depends(get_current_user)],
    event_id: UUID | None = None,
):
    """List teams."""
    query = select(Team).where(Team.is_active == True)

    if event_id:
        query = query.where(Team.event_id == event_id)

    query = query.order_by(Team.score.desc())

    result = await db.execute(query)
    return result.scalars().all()


@router.post("/submit", response_model=dict)
async def submit_flag(
    submission: FlagSubmit,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """
    Submit a flag for a challenge.

    Returns:
    - correct: Whether the flag was correct
    - points: Points awarded (if correct and first solve)
    - message: Status message
    """
    # Find team by token
    result = await db.execute(select(Team).where(Team.token == submission.team_token))
    team = result.scalar_one_or_none()

    if not team:
        raise HTTPException(status_code=401, detail="Invalid team token")

    if not team.is_active:
        raise HTTPException(status_code=403, detail="Team is not active")

    # Find challenge
    result = await db.execute(select(Challenge).where(Challenge.id == submission.challenge_id))
    challenge = result.scalar_one_or_none()

    if not challenge:
        raise HTTPException(status_code=404, detail="Challenge not found")

    if challenge.status != ChallengeStatus.ACTIVE:
        raise HTTPException(status_code=400, detail="Challenge is not active")

    # Check if already solved
    result = await db.execute(
        select(Submission).where(
            Submission.team_id == team.id,
            Submission.challenge_id == challenge.id,
            Submission.is_correct == True,
        )
    )
    if result.scalar_one_or_none():
        return {
            "correct": False,
            "points": 0,
            "message": "Challenge already solved by your team",
        }

    # Verify flag
    submitted_hash = hashlib.sha256(
        (settings.ctf_flag_prefix + submission.flag + settings.ctf_flag_suffix).encode()
    ).hexdigest()

    is_correct = submitted_hash == challenge.flag_hash
    points = challenge.points if is_correct else 0

    # Record submission
    sub = Submission(
        team_id=team.id,
        challenge_id=challenge.id,
        flag_submitted=submission.flag,
        is_correct=is_correct,
        points_awarded=points,
    )
    db.add(sub)

    if is_correct:
        # Update team score
        team.score += points

        # Update challenge solves
        challenge.solves += 1

    await db.commit()

    return {
        "correct": is_correct,
        "points": points,
        "message": "Correct! Points awarded." if is_correct else "Incorrect flag.",
        "new_score": team.score if is_correct else None,
    }


@router.get("/scoreboard", response_model=list[ScoreboardEntry])
async def get_scoreboard(
    db: Annotated[AsyncSession, Depends(get_db)],
    event_id: UUID | None = None,
    limit: int = 100,
):
    """Get CTF scoreboard."""
    query = select(Team).where(Team.is_active == True)

    if event_id:
        query = query.where(Team.event_id == event_id)

    query = query.order_by(Team.score.desc()).limit(limit)

    result = await db.execute(query)
    teams = result.scalars().all()

    scoreboard = []
    for rank, team in enumerate(teams, 1):
        # Get last solve time
        last_result = await db.execute(
            select(Submission)
            .where(Submission.team_id == team.id, Submission.is_correct == True)
            .order_by(Submission.submitted_at.desc())
            .limit(1)
        )
        last_sub = last_result.scalar_one_or_none()

        # Count solves
        solve_result = await db.execute(
            select(Submission)
            .where(Submission.team_id == team.id, Submission.is_correct == True)
        )
        solves = len(solve_result.scalars().all())

        scoreboard.append(ScoreboardEntry(
            rank=rank,
            team_name=team.name,
            score=team.score,
            solves=solves,
            last_solve=last_sub.submitted_at if last_sub else None,
        ))

    return scoreboard
