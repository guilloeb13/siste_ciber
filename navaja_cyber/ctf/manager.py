"""
CTF Challenge Manager

Manages Docker-based CTF challenges for security training.

USO AUTORIZADO ÚNICAMENTE. Los retos CTF están diseñados para entrenamiento
en entornos aislados y controlados.
"""

import asyncio
import hashlib
import secrets
from datetime import datetime
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

import docker
import structlog
import yaml

logger = structlog.get_logger(__name__)


class ChallengeManager:
    """Manage CTF challenges using Docker containers."""

    def __init__(self, network_name: str = "navaja-ctf-net"):
        self.docker_client = docker.from_env()
        self.network_name = network_name
        self._ensure_network()

    def _ensure_network(self):
        """Ensure the CTF network exists."""
        try:
            self.docker_client.networks.get(self.network_name)
        except docker.errors.NotFound:
            self.docker_client.networks.create(
                self.network_name,
                driver="bridge",
                internal=True,  # Isolated from host network
            )
            logger.info("created_ctf_network", network=self.network_name)

    def generate_flag(self, prefix: str = "NAVAJA{", suffix: str = "}") -> str:
        """Generate a random flag."""
        flag_content = secrets.token_hex(16)
        return f"{prefix}{flag_content}{suffix}"

    def hash_flag(self, flag: str) -> str:
        """Hash a flag for secure storage."""
        return hashlib.sha256(flag.encode()).hexdigest()

    async def create_challenge(
        self,
        name: str,
        category: str,
        description: str,
        docker_image: str,
        points: int,
        flag: str | None = None,
        ports: dict | None = None,
        environment: dict | None = None,
        files: list[str] | None = None,
        hints: list[str] | None = None,
    ) -> dict:
        """
        Create a new CTF challenge.

        Args:
            name: Challenge name
            category: Category (web, forensic, crypto, etc.)
            description: Challenge description
            docker_image: Docker image to use
            points: Points for solving
            flag: Flag string (generated if not provided)
            ports: Port mappings {container_port: host_port}
            environment: Environment variables
            files: Files to provide to participants
            hints: Hints for the challenge

        Returns:
            Challenge configuration dict
        """
        challenge_id = uuid4()

        # Generate flag if not provided
        if not flag:
            flag = self.generate_flag()

        flag_hash = self.hash_flag(flag)

        challenge = {
            "id": str(challenge_id),
            "name": name,
            "category": category,
            "description": description,
            "points": points,
            "docker_image": docker_image,
            "flag_hash": flag_hash,
            "ports": ports or {},
            "environment": environment or {},
            "files": files or [],
            "hints": hints or [],
            "status": "created",
            "created_at": datetime.utcnow().isoformat(),
        }

        logger.info("challenge_created", challenge_id=str(challenge_id), name=name)

        # Return flag separately (should be stored securely)
        return {
            "challenge": challenge,
            "flag": flag,  # Only returned during creation
        }

    async def deploy_challenge(self, challenge: dict) -> dict:
        """
        Deploy a challenge by starting its Docker container.

        Returns container information.
        """
        challenge_id = challenge["id"]
        image = challenge["docker_image"]

        try:
            # Pull image if needed
            try:
                self.docker_client.images.get(image)
            except docker.errors.ImageNotFound:
                logger.info("pulling_image", image=image)
                self.docker_client.images.pull(image)

            # Prepare port bindings
            ports = {}
            for container_port, host_port in challenge.get("ports", {}).items():
                ports[f"{container_port}/tcp"] = host_port

            # Create and start container
            container = self.docker_client.containers.run(
                image,
                name=f"ctf_{challenge_id}",
                detach=True,
                network=self.network_name,
                ports=ports,
                environment=challenge.get("environment", {}),
                mem_limit="512m",
                cpu_quota=50000,  # 50% CPU
                auto_remove=False,
            )

            logger.info("challenge_deployed", challenge_id=challenge_id, container_id=container.short_id)

            return {
                "challenge_id": challenge_id,
                "container_id": container.id,
                "container_name": container.name,
                "status": "running",
                "ports": ports,
            }

        except Exception as e:
            logger.error("deployment_error", challenge_id=challenge_id, error=str(e))
            raise

    async def stop_challenge(self, challenge_id: str) -> bool:
        """Stop and remove a challenge container."""
        container_name = f"ctf_{challenge_id}"

        try:
            container = self.docker_client.containers.get(container_name)
            container.stop(timeout=10)
            container.remove()
            logger.info("challenge_stopped", challenge_id=challenge_id)
            return True

        except docker.errors.NotFound:
            logger.warning("container_not_found", challenge_id=challenge_id)
            return False
        except Exception as e:
            logger.error("stop_error", challenge_id=challenge_id, error=str(e))
            return False

    async def get_challenge_status(self, challenge_id: str) -> dict:
        """Get the status of a challenge container."""
        container_name = f"ctf_{challenge_id}"

        try:
            container = self.docker_client.containers.get(container_name)
            return {
                "challenge_id": challenge_id,
                "container_id": container.id,
                "status": container.status,
                "ports": container.ports,
                "created": container.attrs["Created"],
            }
        except docker.errors.NotFound:
            return {
                "challenge_id": challenge_id,
                "status": "not_found",
            }

    def validate_flag(self, submitted_flag: str, flag_hash: str) -> bool:
        """Validate a submitted flag against the stored hash."""
        submitted_hash = self.hash_flag(submitted_flag)
        return submitted_hash == flag_hash

    async def list_running_challenges(self) -> list[dict]:
        """List all running challenge containers."""
        containers = self.docker_client.containers.list(
            filters={"name": "ctf_"}
        )

        challenges = []
        for container in containers:
            challenges.append({
                "container_id": container.short_id,
                "name": container.name,
                "status": container.status,
                "image": container.image.tags[0] if container.image.tags else "unknown",
            })

        return challenges

    async def cleanup_all(self) -> int:
        """Stop and remove all challenge containers."""
        containers = self.docker_client.containers.list(
            all=True,
            filters={"name": "ctf_"}
        )

        count = 0
        for container in containers:
            try:
                container.stop(timeout=5)
                container.remove()
                count += 1
            except Exception as e:
                logger.error("cleanup_error", container=container.name, error=str(e))

        logger.info("cleanup_complete", removed=count)
        return count


class ChallengeTemplates:
    """Pre-built challenge templates for common scenarios."""

    @staticmethod
    def web_challenge(
        name: str,
        description: str,
        vulnerability_type: str,
        points: int = 100,
    ) -> dict:
        """Create a web vulnerability challenge template."""
        # These are educational challenges with intentional vulnerabilities
        # for training purposes only

        templates = {
            "sqli_basic": {
                "image": "navaja/ctf-web-sqli:basic",
                "description": f"{description}\n\nThis challenge contains an intentional SQL injection vulnerability for educational purposes.",
                "ports": {"80": None},  # Random host port
                "hints": [
                    "Try testing the login form with special characters",
                    "SQL uses single quotes for string literals",
                ],
            },
            "xss_reflected": {
                "image": "navaja/ctf-web-xss:reflected",
                "description": f"{description}\n\nFind and exploit the XSS vulnerability.",
                "ports": {"80": None},
                "hints": [
                    "Check how user input is reflected in the page",
                    "Try using script tags",
                ],
            },
            "auth_bypass": {
                "image": "navaja/ctf-web-auth:bypass",
                "description": f"{description}\n\nBypass the authentication to find the flag.",
                "ports": {"80": None},
                "hints": [
                    "Check how sessions are managed",
                    "Look at the cookies",
                ],
            },
        }

        template = templates.get(vulnerability_type, {
            "image": "nginx:alpine",
            "description": description,
            "ports": {"80": None},
            "hints": [],
        })

        return {
            "name": name,
            "category": "web",
            "description": template["description"],
            "docker_image": template["image"],
            "points": points,
            "ports": template["ports"],
            "hints": template["hints"],
        }

    @staticmethod
    def forensic_challenge(
        name: str,
        description: str,
        artifact_type: str,
        points: int = 150,
    ) -> dict:
        """Create a forensic analysis challenge template."""
        return {
            "name": name,
            "category": "forensic",
            "description": description,
            "docker_image": "navaja/ctf-forensic:base",
            "points": points,
            "hints": [
                f"The flag is hidden in a {artifact_type} artifact",
                "Use standard forensic tools for analysis",
            ],
            "files": [f"{artifact_type}_evidence.zip"],
        }

    @staticmethod
    def config_challenge(
        name: str,
        description: str,
        service_type: str,
        points: int = 100,
    ) -> dict:
        """Create a misconfiguration challenge template."""
        return {
            "name": name,
            "category": "configuration",
            "description": description,
            "docker_image": f"navaja/ctf-config:{service_type}",
            "points": points,
            "hints": [
                "Look for default credentials or misconfigurations",
                "Check the service configuration files",
            ],
        }


# CLI interface
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="NavajaCyber CTF Manager")
    parser.add_argument("command", choices=["create", "deploy", "stop", "list", "cleanup"])
    parser.add_argument("--name", help="Challenge name")
    parser.add_argument("--id", help="Challenge ID")

    args = parser.parse_args()

    async def main():
        manager = ChallengeManager()

        if args.command == "list":
            challenges = await manager.list_running_challenges()
            print(f"Running challenges: {len(challenges)}")
            for ch in challenges:
                print(f"  - {ch['name']}: {ch['status']}")

        elif args.command == "cleanup":
            count = await manager.cleanup_all()
            print(f"Removed {count} containers")

        elif args.command == "create":
            result = await manager.create_challenge(
                name=args.name or "Test Challenge",
                category="misc",
                description="A test challenge",
                docker_image="nginx:alpine",
                points=100,
            )
            print(f"Challenge created: {result['challenge']['id']}")
            print(f"Flag: {result['flag']}")

    asyncio.run(main())
