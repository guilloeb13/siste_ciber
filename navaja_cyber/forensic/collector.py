"""
Forensic Evidence Collector

Collects system artifacts, logs, and network data for forensic analysis.

USO AUTORIZADO ÚNICAMENTE. La recolección de evidencia requiere autorización
explícita. Solo debe usarse en sistemas propios o con permiso documentado.
"""

import asyncio
import hashlib
import json
import os
import platform
import tempfile
import zipfile
from datetime import datetime
from pathlib import Path
from uuid import uuid4

import structlog

logger = structlog.get_logger(__name__)


class ForensicCollector:
    """Collect forensic artifacts from a system."""

    def __init__(self, case_id: str, output_dir: str | None = None):
        self.case_id = case_id
        self.collection_id = str(uuid4())
        self.output_dir = Path(output_dir) if output_dir else Path(tempfile.mkdtemp(prefix="navaja_forensic_"))
        self.manifest = {
            "case_id": case_id,
            "collection_id": self.collection_id,
            "collected_at": datetime.utcnow().isoformat(),
            "collector_version": "0.1.0",
            "system_info": self._get_system_info(),
            "artifacts": [],
        }

    def _get_system_info(self) -> dict:
        """Get system information."""
        return {
            "hostname": platform.node(),
            "platform": platform.system(),
            "platform_version": platform.version(),
            "architecture": platform.machine(),
            "processor": platform.processor(),
        }

    def _compute_hash(self, filepath: Path) -> dict:
        """Compute multiple hashes for a file."""
        content = filepath.read_bytes()
        return {
            "md5": hashlib.md5(content).hexdigest(),
            "sha1": hashlib.sha1(content).hexdigest(),
            "sha256": hashlib.sha256(content).hexdigest(),
        }

    async def collect_file(self, filepath: str, artifact_type: str = "file") -> dict | None:
        """
        Collect a single file as evidence.

        Copies the file and computes integrity hashes.
        """
        source = Path(filepath)

        if not source.exists():
            logger.warning("file_not_found", path=filepath)
            return None

        try:
            # Create artifact directory
            artifact_dir = self.output_dir / "artifacts" / artifact_type
            artifact_dir.mkdir(parents=True, exist_ok=True)

            # Copy file
            dest = artifact_dir / source.name
            dest.write_bytes(source.read_bytes())

            # Compute hashes
            hashes = self._compute_hash(dest)

            artifact = {
                "id": str(uuid4()),
                "type": artifact_type,
                "source_path": str(source.absolute()),
                "collected_path": str(dest.relative_to(self.output_dir)),
                "size_bytes": source.stat().st_size,
                "modified_time": datetime.fromtimestamp(source.stat().st_mtime).isoformat(),
                "hashes": hashes,
                "collected_at": datetime.utcnow().isoformat(),
            }

            self.manifest["artifacts"].append(artifact)
            logger.info("artifact_collected", path=filepath, type=artifact_type)

            return artifact

        except Exception as e:
            logger.error("collection_error", path=filepath, error=str(e))
            return None

    async def collect_logs_linux(self) -> list[dict]:
        """Collect common Linux log files."""
        log_paths = [
            "/var/log/syslog",
            "/var/log/auth.log",
            "/var/log/secure",
            "/var/log/messages",
            "/var/log/kern.log",
            "/var/log/dmesg",
            "/var/log/apache2/access.log",
            "/var/log/apache2/error.log",
            "/var/log/nginx/access.log",
            "/var/log/nginx/error.log",
        ]

        artifacts = []
        for log_path in log_paths:
            artifact = await self.collect_file(log_path, "log")
            if artifact:
                artifacts.append(artifact)

        return artifacts

    async def collect_logs_windows(self) -> list[dict]:
        """
        Collect Windows Event Logs.

        Requires python-evtx for parsing: pip install python-evtx
        """
        artifacts = []

        # Windows event log locations
        evtx_paths = [
            r"C:\Windows\System32\winevt\Logs\System.evtx",
            r"C:\Windows\System32\winevt\Logs\Security.evtx",
            r"C:\Windows\System32\winevt\Logs\Application.evtx",
        ]

        for evtx_path in evtx_paths:
            artifact = await self.collect_file(evtx_path, "evtx")
            if artifact:
                artifacts.append(artifact)

        return artifacts

    async def collect_process_list(self) -> dict:
        """Collect current process list."""
        import psutil

        processes = []
        for proc in psutil.process_iter(['pid', 'name', 'username', 'cmdline', 'create_time']):
            try:
                pinfo = proc.info
                processes.append({
                    "pid": pinfo['pid'],
                    "name": pinfo['name'],
                    "username": pinfo['username'],
                    "cmdline": pinfo.get('cmdline', []),
                    "create_time": datetime.fromtimestamp(pinfo['create_time']).isoformat() if pinfo.get('create_time') else None,
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        # Save to file
        output_file = self.output_dir / "artifacts" / "system" / "processes.json"
        output_file.parent.mkdir(parents=True, exist_ok=True)
        output_file.write_text(json.dumps(processes, indent=2))

        hashes = self._compute_hash(output_file)

        artifact = {
            "id": str(uuid4()),
            "type": "process_list",
            "collected_path": str(output_file.relative_to(self.output_dir)),
            "process_count": len(processes),
            "hashes": hashes,
            "collected_at": datetime.utcnow().isoformat(),
        }

        self.manifest["artifacts"].append(artifact)
        logger.info("processes_collected", count=len(processes))

        return artifact

    async def collect_network_connections(self) -> dict:
        """Collect active network connections."""
        import psutil

        connections = []
        for conn in psutil.net_connections(kind='inet'):
            connections.append({
                "fd": conn.fd,
                "family": str(conn.family),
                "type": str(conn.type),
                "local_address": f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None,
                "remote_address": f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
                "status": conn.status,
                "pid": conn.pid,
            })

        # Save to file
        output_file = self.output_dir / "artifacts" / "network" / "connections.json"
        output_file.parent.mkdir(parents=True, exist_ok=True)
        output_file.write_text(json.dumps(connections, indent=2))

        hashes = self._compute_hash(output_file)

        artifact = {
            "id": str(uuid4()),
            "type": "network_connections",
            "collected_path": str(output_file.relative_to(self.output_dir)),
            "connection_count": len(connections),
            "hashes": hashes,
            "collected_at": datetime.utcnow().isoformat(),
        }

        self.manifest["artifacts"].append(artifact)
        logger.info("connections_collected", count=len(connections))

        return artifact

    async def collect_filesystem_hashes(self, directories: list[str], extensions: list[str] | None = None) -> dict:
        """
        Compute hashes for files in specified directories.

        Useful for detecting file changes/tampering.
        """
        file_hashes = []
        extensions = extensions or [".exe", ".dll", ".sys", ".py", ".sh", ".conf"]

        for directory in directories:
            dir_path = Path(directory)
            if not dir_path.exists():
                continue

            for file_path in dir_path.rglob("*"):
                if not file_path.is_file():
                    continue
                if extensions and file_path.suffix not in extensions:
                    continue
                if file_path.stat().st_size > 100_000_000:  # Skip files > 100MB
                    continue

                try:
                    hashes = self._compute_hash(file_path)
                    file_hashes.append({
                        "path": str(file_path),
                        "size": file_path.stat().st_size,
                        "modified": datetime.fromtimestamp(file_path.stat().st_mtime).isoformat(),
                        "hashes": hashes,
                    })
                except (PermissionError, OSError):
                    continue

        # Save to file
        output_file = self.output_dir / "artifacts" / "filesystem" / "file_hashes.json"
        output_file.parent.mkdir(parents=True, exist_ok=True)
        output_file.write_text(json.dumps(file_hashes, indent=2))

        hashes = self._compute_hash(output_file)

        artifact = {
            "id": str(uuid4()),
            "type": "filesystem_hashes",
            "collected_path": str(output_file.relative_to(self.output_dir)),
            "file_count": len(file_hashes),
            "hashes": hashes,
            "collected_at": datetime.utcnow().isoformat(),
        }

        self.manifest["artifacts"].append(artifact)
        logger.info("filesystem_hashes_collected", files=len(file_hashes))

        return artifact

    async def collect_all(self) -> dict:
        """Run full system collection."""
        logger.info("starting_full_collection", case_id=self.case_id)

        # Determine OS
        if platform.system() == "Linux":
            await self.collect_logs_linux()
        elif platform.system() == "Windows":
            await self.collect_logs_windows()

        # Common collections
        await self.collect_process_list()
        await self.collect_network_connections()

        # System directories for hash collection
        if platform.system() == "Linux":
            await self.collect_filesystem_hashes(["/etc", "/usr/bin", "/usr/sbin"])
        elif platform.system() == "Windows":
            await self.collect_filesystem_hashes([r"C:\Windows\System32"])

        logger.info("collection_complete", artifacts=len(self.manifest["artifacts"]))

        return self.manifest

    def save_manifest(self) -> Path:
        """Save the collection manifest."""
        manifest_path = self.output_dir / "manifest.json"
        manifest_path.write_text(json.dumps(self.manifest, indent=2))
        return manifest_path

    def create_archive(self, sign: bool = False) -> Path:
        """
        Create a ZIP archive of all collected artifacts.

        Includes manifest for chain of custody.
        """
        # Save manifest
        self.save_manifest()

        # Create archive
        archive_name = f"{self.case_id}_{self.collection_id}.zip"
        archive_path = self.output_dir.parent / archive_name

        with zipfile.ZipFile(archive_path, 'w', zipfile.ZIP_DEFLATED) as zf:
            for file_path in self.output_dir.rglob("*"):
                if file_path.is_file():
                    arcname = file_path.relative_to(self.output_dir)
                    zf.write(file_path, arcname)

        # Compute archive hash
        archive_hash = hashlib.sha256(archive_path.read_bytes()).hexdigest()

        # Write hash file
        hash_file = archive_path.with_suffix('.sha256')
        hash_file.write_text(f"{archive_hash}  {archive_name}\n")

        logger.info("archive_created", path=str(archive_path), hash=archive_hash)

        return archive_path


async def upload_to_minio(archive_path: Path, settings: dict) -> str:
    """Upload archive to MinIO/S3 storage."""
    from minio import Minio
    from io import BytesIO

    client = Minio(
        settings["endpoint"],
        access_key=settings["access_key"],
        secret_key=settings["secret_key"],
        secure=settings.get("secure", False),
    )

    bucket = settings.get("bucket", "navaja-evidence")

    # Ensure bucket exists
    if not client.bucket_exists(bucket):
        client.make_bucket(bucket)

    # Upload
    object_name = f"collections/{archive_path.name}"
    content = archive_path.read_bytes()

    client.put_object(
        bucket,
        object_name,
        BytesIO(content),
        len(content),
        content_type="application/zip",
    )

    logger.info("uploaded_to_minio", bucket=bucket, object=object_name)

    return f"{bucket}/{object_name}"


# CLI interface
if __name__ == "__main__":
    import sys
    import argparse

    parser = argparse.ArgumentParser(description="NavajaCyber Forensic Collector")
    parser.add_argument("--case-id", required=True, help="Case identifier")
    parser.add_argument("--output", help="Output directory")
    parser.add_argument("--archive", action="store_true", help="Create ZIP archive")

    args = parser.parse_args()

    async def main():
        collector = ForensicCollector(args.case_id, args.output)

        print(f"Starting collection for case: {args.case_id}")
        print(f"Collection ID: {collector.collection_id}")
        print(f"Output directory: {collector.output_dir}")
        print("-" * 50)

        manifest = await collector.collect_all()

        print(f"\nCollected {len(manifest['artifacts'])} artifacts")

        if args.archive:
            archive = collector.create_archive()
            print(f"Archive created: {archive}")

        collector.save_manifest()
        print(f"Manifest saved: {collector.output_dir / 'manifest.json'}")

    asyncio.run(main())
