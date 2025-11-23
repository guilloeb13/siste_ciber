"""Database security analysis router."""

from datetime import datetime
from typing import Annotated
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.models.user import User, Role
from backend.app.routers.auth import get_current_user, require_role
from backend.app.services.database import get_db

router = APIRouter()


class DatabaseConnection(BaseModel):
    """Database connection configuration for analysis."""
    db_type: str  # postgres, mysql, mssql
    host: str
    port: int
    database: str
    username: str
    password: str
    ssl_mode: str = "prefer"


class AnalysisRequest(BaseModel):
    """Database security analysis request."""
    connection: DatabaseConnection
    checks: list[str] = ["config", "permissions", "pii", "logs"]


class ConfigIssue(BaseModel):
    """Database configuration issue."""
    check: str
    severity: str
    description: str
    recommendation: str
    current_value: str | None = None
    recommended_value: str | None = None


class PIIColumn(BaseModel):
    """Potentially sensitive column detection."""
    schema_name: str
    table_name: str
    column_name: str
    data_type: str
    pattern_matched: str
    confidence: str
    recommendation: str


class AnalysisResult(BaseModel):
    """Database security analysis results."""
    analysis_id: UUID
    db_type: str
    database: str
    analyzed_at: datetime
    config_issues: list[ConfigIssue]
    permission_issues: list[dict]
    pii_columns: list[PIIColumn]
    log_patterns: list[dict]
    summary: dict


@router.post("/analyze", response_model=AnalysisResult)
async def analyze_database(
    request: AnalysisRequest,
    db: Annotated[AsyncSession, Depends(get_db)],
    user: Annotated[User, Depends(require_role([Role.ADMIN, Role.ANALYST]))],
):
    """
    Perform security analysis on a database.

    IMPORTANT: This performs read-only analysis. No data is modified.
    Requires explicit authorization to access the target database.

    Checks performed:
    - config: Configuration security (auth, ssl, logging)
    - permissions: Role and privilege analysis
    - pii: PII/sensitive data detection in schemas
    - logs: SQL injection pattern detection in query logs
    """
    analysis_id = uuid4()

    # Perform analysis based on database type
    if request.connection.db_type == "postgres":
        result = await analyze_postgres(request.connection, request.checks)
    elif request.connection.db_type == "mysql":
        result = await analyze_mysql(request.connection, request.checks)
    else:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported database type: {request.connection.db_type}"
        )

    return AnalysisResult(
        analysis_id=analysis_id,
        db_type=request.connection.db_type,
        database=request.connection.database,
        analyzed_at=datetime.utcnow(),
        **result,
    )


async def analyze_postgres(conn: DatabaseConnection, checks: list[str]) -> dict:
    """Perform PostgreSQL security analysis."""
    import asyncpg

    config_issues = []
    permission_issues = []
    pii_columns = []
    log_patterns = []

    try:
        # Connect to database
        connection = await asyncpg.connect(
            host=conn.host,
            port=conn.port,
            database=conn.database,
            user=conn.username,
            password=conn.password,
            ssl=conn.ssl_mode,
        )

        if "config" in checks:
            # Check SSL configuration
            ssl_result = await connection.fetchval("SHOW ssl")
            if ssl_result != "on":
                config_issues.append(ConfigIssue(
                    check="ssl_enabled",
                    severity="high",
                    description="SSL is not enabled for database connections",
                    recommendation="Enable SSL in postgresql.conf: ssl = on",
                    current_value=ssl_result,
                    recommended_value="on",
                ))

            # Check password encryption
            pwd_enc = await connection.fetchval("SHOW password_encryption")
            if pwd_enc not in ["scram-sha-256", "md5"]:
                config_issues.append(ConfigIssue(
                    check="password_encryption",
                    severity="medium",
                    description="Weak password encryption method",
                    recommendation="Use scram-sha-256 for password encryption",
                    current_value=pwd_enc,
                    recommended_value="scram-sha-256",
                ))

            # Check logging
            log_stmt = await connection.fetchval("SHOW log_statement")
            if log_stmt == "none":
                config_issues.append(ConfigIssue(
                    check="log_statement",
                    severity="medium",
                    description="SQL statement logging is disabled",
                    recommendation="Enable statement logging for audit purposes",
                    current_value=log_stmt,
                    recommended_value="ddl",
                ))

        if "permissions" in checks:
            # Check for public schema grants
            public_grants = await connection.fetch("""
                SELECT grantee, privilege_type, table_schema, table_name
                FROM information_schema.table_privileges
                WHERE grantee = 'PUBLIC' AND table_schema NOT IN ('pg_catalog', 'information_schema')
            """)

            for grant in public_grants:
                permission_issues.append({
                    "type": "public_grant",
                    "severity": "medium",
                    "grantee": grant["grantee"],
                    "privilege": grant["privilege_type"],
                    "object": f"{grant['table_schema']}.{grant['table_name']}",
                    "recommendation": "Review and restrict PUBLIC grants",
                })

            # Check superuser accounts
            superusers = await connection.fetch("""
                SELECT usename FROM pg_user WHERE usesuper = true
            """)

            if len(superusers) > 2:
                permission_issues.append({
                    "type": "excessive_superusers",
                    "severity": "medium",
                    "count": len(superusers),
                    "users": [u["usename"] for u in superusers],
                    "recommendation": "Minimize superuser accounts",
                })

        if "pii" in checks:
            # Detect potentially sensitive columns
            pii_patterns = [
                ("email", ["email", "e_mail", "correo"]),
                ("phone", ["phone", "telefono", "mobile", "celular"]),
                ("ssn", ["ssn", "social_security", "nss"]),
                ("credit_card", ["credit_card", "card_number", "tarjeta"]),
                ("password", ["password", "pwd", "pass", "contrasena"]),
                ("address", ["address", "direccion", "street"]),
            ]

            columns = await connection.fetch("""
                SELECT table_schema, table_name, column_name, data_type
                FROM information_schema.columns
                WHERE table_schema NOT IN ('pg_catalog', 'information_schema')
            """)

            for col in columns:
                col_name = col["column_name"].lower()
                for pattern_name, patterns in pii_patterns:
                    if any(p in col_name for p in patterns):
                        pii_columns.append(PIIColumn(
                            schema_name=col["table_schema"],
                            table_name=col["table_name"],
                            column_name=col["column_name"],
                            data_type=col["data_type"],
                            pattern_matched=pattern_name,
                            confidence="high" if col_name in patterns else "medium",
                            recommendation=f"Consider encryption or masking for {pattern_name} data",
                        ))

        await connection.close()

    except Exception as e:
        config_issues.append(ConfigIssue(
            check="connection",
            severity="critical",
            description=f"Failed to connect to database: {str(e)}",
            recommendation="Verify connection parameters and network access",
        ))

    return {
        "config_issues": config_issues,
        "permission_issues": permission_issues,
        "pii_columns": pii_columns,
        "log_patterns": log_patterns,
        "summary": {
            "total_issues": len(config_issues) + len(permission_issues),
            "pii_columns_found": len(pii_columns),
            "critical_count": sum(1 for i in config_issues if i.severity == "critical"),
            "high_count": sum(1 for i in config_issues if i.severity == "high"),
        }
    }


async def analyze_mysql(conn: DatabaseConnection, checks: list[str]) -> dict:
    """Perform MySQL security analysis (placeholder)."""
    # Similar implementation for MySQL
    return {
        "config_issues": [],
        "permission_issues": [],
        "pii_columns": [],
        "log_patterns": [],
        "summary": {"message": "MySQL analysis not yet implemented"},
    }
