"""Forensic module router for evidence collection and analysis."""

import hashlib
import json
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Annotated
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Query
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.config import settings
from backend.app.models.user import User, Role
from backend.app.routers.auth import get_current_user, require_role
from backend.app.services.database import get_db

router = APIRouter()


class EvidenceMetadata(BaseModel):
    """Evidence metadata for chain of custody."""
    case_id: str
    source: str
    description: str
    collected_by: str
    collection_method: str
    tags: list[str] = []


class EvidenceRecord(BaseModel):
    """Evidence record with integrity information."""
    evidence_id: UUID
    case_id: str
    filename: str
    file_size: int
    sha256_hash: str
    md5_hash: str
    mime_type: str
    collected_at: datetime
    collected_by: str
    storage_path: str
    metadata: dict


class IOCSearchRequest(BaseModel):
    """IOC (Indicator of Compromise) search request."""
    ioc_type: str  # ip, domain, hash, email
    values: list[str]
    case_id: str | None = None


class TimelineEvent(BaseModel):
    """Timeline event for forensic analysis."""
    timestamp: datetime
    event_type: str
    source: str
    description: str
    artifacts: list[str] = []
    metadata: dict = {}


@router.post("/collect", response_model=EvidenceRecord)
async def collect_evidence(
    metadata: EvidenceMetadata,
    db: Annotated[AsyncSession, Depends(get_db)],
    user: Annotated[User, Depends(require_role([Role.ADMIN, Role.ANALYST]))],
    file: UploadFile = File(...),
):
    """
    Upload and catalog forensic evidence.

    Computes cryptographic hashes for integrity verification
    and stores in secure storage with chain of custody metadata.
    """
    evidence_id = uuid4()

    # Read file content
    content = await file.read()
    file_size = len(content)

    # Compute hashes for integrity
    sha256_hash = hashlib.sha256(content).hexdigest()
    md5_hash = hashlib.md5(content).hexdigest()

    # Determine MIME type
    import magic
    mime_type = magic.from_buffer(content, mime=True)

    # Generate storage path
    timestamp = datetime.utcnow().strftime("%Y/%m/%d")
    storage_path = f"{metadata.case_id}/{timestamp}/{evidence_id}/{file.filename}"

    # Upload to MinIO/S3
    try:
        from minio import Minio

        client = Minio(
            settings.minio_endpoint,
            access_key=settings.minio_access_key,
            secret_key=settings.minio_secret_key,
            secure=settings.minio_secure,
        )

        # Ensure bucket exists
        if not client.bucket_exists(settings.minio_bucket_evidence):
            client.make_bucket(settings.minio_bucket_evidence)

        # Upload with metadata
        from io import BytesIO
        client.put_object(
            settings.minio_bucket_evidence,
            storage_path,
            BytesIO(content),
            file_size,
            content_type=mime_type,
            metadata={
                "case_id": metadata.case_id,
                "sha256": sha256_hash,
                "collected_by": metadata.collected_by,
            }
        )

    except Exception as e:
        # Fallback to local storage in simulation mode
        if settings.simulation_mode:
            local_path = Path(tempfile.gettempdir()) / "navaja_evidence" / storage_path
            local_path.parent.mkdir(parents=True, exist_ok=True)
            local_path.write_bytes(content)
        else:
            raise HTTPException(status_code=500, detail=f"Storage error: {str(e)}")

    return EvidenceRecord(
        evidence_id=evidence_id,
        case_id=metadata.case_id,
        filename=file.filename,
        file_size=file_size,
        sha256_hash=sha256_hash,
        md5_hash=md5_hash,
        mime_type=mime_type,
        collected_at=datetime.utcnow(),
        collected_by=metadata.collected_by,
        storage_path=storage_path,
        metadata={
            "source": metadata.source,
            "description": metadata.description,
            "collection_method": metadata.collection_method,
            "tags": metadata.tags,
        }
    )


@router.post("/ioc/search", response_model=dict)
async def search_ioc(
    request: IOCSearchRequest,
    db: Annotated[AsyncSession, Depends(get_db)],
    user: Annotated[User, Depends(get_current_user)],
):
    """
    Search for Indicators of Compromise across collected evidence.

    Supported IOC types:
    - ip: IP addresses
    - domain: Domain names
    - hash: File hashes (MD5, SHA1, SHA256)
    - email: Email addresses
    """
    results = {
        "ioc_type": request.ioc_type,
        "searched": len(request.values),
        "matches": [],
        "searched_at": datetime.utcnow().isoformat(),
    }

    # In a real implementation, this would search Elasticsearch
    # or other indexed storage for IOC matches

    for ioc_value in request.values:
        # Placeholder for actual search logic
        match = {
            "ioc": ioc_value,
            "found": False,
            "sources": [],
        }
        results["matches"].append(match)

    return results


@router.post("/timeline/generate", response_model=list[TimelineEvent])
async def generate_timeline(
    case_id: str,
    db: Annotated[AsyncSession, Depends(get_db)],
    user: Annotated[User, Depends(get_current_user)],
    start_time: datetime | None = None,
    end_time: datetime | None = None,
):
    """
    Generate a forensic timeline from collected evidence.

    Aggregates events from:
    - System logs
    - Network captures
    - File system artifacts
    - Application logs
    """
    events = []

    # This would aggregate events from various sources
    # For now, return example timeline structure

    events.append(TimelineEvent(
        timestamp=datetime.utcnow(),
        event_type="analysis_started",
        source="navaja_forensic",
        description=f"Timeline generation started for case {case_id}",
        artifacts=[],
        metadata={"case_id": case_id},
    ))

    return events


@router.get("/export/{case_id}")
async def export_case(
    case_id: str,
    db: Annotated[AsyncSession, Depends(get_db)],
    user: Annotated[User, Depends(require_role([Role.ADMIN, Role.ANALYST, Role.AUDITOR]))],
    format: str = Query(default="zip", enum=["zip", "json"]),
):
    """
    Export case evidence and metadata.

    Creates a ZIP archive with:
    - All evidence files
    - manifest.json with hashes and metadata
    - Chain of custody documentation
    - Timeline if generated
    """
    # Generate export manifest
    manifest = {
        "case_id": case_id,
        "exported_at": datetime.utcnow().isoformat(),
        "exported_by": str(user.id),
        "format_version": "1.0",
        "evidence_files": [],
        "chain_of_custody": [],
        "integrity": {
            "algorithm": settings.forensic_hash_algorithm,
        }
    }

    if format == "json":
        return manifest

    # For ZIP export, would create archive with files
    # This is a placeholder response
    return {
        "status": "export_queued",
        "case_id": case_id,
        "format": format,
        "download_url": f"/api/forensic/download/{case_id}",
    }


@router.post("/pcap/analyze")
async def analyze_pcap(
    db: Annotated[AsyncSession, Depends(get_db)],
    user: Annotated[User, Depends(require_role([Role.ADMIN, Role.ANALYST]))],
    file: UploadFile = File(...),
    extract_files: bool = False,
):
    """
    Analyze a PCAP network capture file.

    Extracts:
    - Connection summary
    - Protocol statistics
    - DNS queries
    - HTTP requests
    - Potential IOCs

    Note: Requires authorization to capture network traffic.
    """
    content = await file.read()

    # Save to temp file for analysis
    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tmp:
        tmp.write(content)
        tmp_path = tmp.name

    try:
        # Use scapy for analysis
        from scapy.all import rdpcap, IP, TCP, UDP, DNS

        packets = rdpcap(tmp_path)

        analysis = {
            "filename": file.filename,
            "total_packets": len(packets),
            "protocols": {},
            "connections": [],
            "dns_queries": [],
            "potential_iocs": [],
        }

        # Analyze packets
        for pkt in packets[:1000]:  # Limit analysis
            if IP in pkt:
                src = pkt[IP].src
                dst = pkt[IP].dst

                if TCP in pkt:
                    proto = "TCP"
                elif UDP in pkt:
                    proto = "UDP"
                else:
                    proto = "OTHER"

                analysis["protocols"][proto] = analysis["protocols"].get(proto, 0) + 1

                if DNS in pkt and pkt[DNS].qd:
                    query = pkt[DNS].qd.qname.decode()
                    analysis["dns_queries"].append(query)

        # Remove duplicates
        analysis["dns_queries"] = list(set(analysis["dns_queries"]))

        return analysis

    finally:
        Path(tmp_path).unlink(missing_ok=True)
