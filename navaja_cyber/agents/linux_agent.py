#!/usr/bin/env python3
"""
NavajaCyber Linux Monitoring Agent

A lightweight agent that collects system metrics and sends them to the central server.

USO AUTORIZADO ÚNICAMENTE. Este software está diseñado para defensa y monitoreo.
Solo debe ser instalado en sistemas autorizados de la organización.

Usage:
    python linux_agent.py --register --backend http://localhost:8000
    python linux_agent.py --config /etc/navaja/agent.conf
"""

import argparse
import asyncio
import hashlib
import json
import logging
import os
import platform
import signal
import socket
import ssl
import sys
from datetime import datetime
from pathlib import Path

import httpx
import psutil
import yaml

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("/var/log/navaja-agent.log") if os.path.exists("/var/log") else logging.NullHandler(),
    ]
)
logger = logging.getLogger("navaja-agent")


class MetricCollector:
    """Collect system metrics."""

    @staticmethod
    def get_cpu_metrics() -> list[dict]:
        """Collect CPU usage metrics."""
        cpu_percent = psutil.cpu_percent(interval=1)
        cpu_freq = psutil.cpu_freq()
        cpu_count = psutil.cpu_count()

        metrics = [
            {
                "metric_type": "cpu",
                "name": "cpu_usage_percent",
                "value": cpu_percent,
                "unit": "percent",
                "labels": {"core": "all"},
            }
        ]

        if cpu_freq:
            metrics.append({
                "metric_type": "cpu",
                "name": "cpu_frequency_mhz",
                "value": cpu_freq.current,
                "unit": "MHz",
                "labels": {},
            })

        # Per-core usage
        per_cpu = psutil.cpu_percent(percpu=True)
        for i, usage in enumerate(per_cpu):
            metrics.append({
                "metric_type": "cpu",
                "name": "cpu_core_usage",
                "value": usage,
                "unit": "percent",
                "labels": {"core": str(i)},
            })

        return metrics

    @staticmethod
    def get_memory_metrics() -> list[dict]:
        """Collect memory usage metrics."""
        mem = psutil.virtual_memory()
        swap = psutil.swap_memory()

        return [
            {
                "metric_type": "memory",
                "name": "memory_usage_percent",
                "value": mem.percent,
                "unit": "percent",
                "labels": {},
            },
            {
                "metric_type": "memory",
                "name": "memory_used_bytes",
                "value": mem.used,
                "unit": "bytes",
                "labels": {},
            },
            {
                "metric_type": "memory",
                "name": "memory_available_bytes",
                "value": mem.available,
                "unit": "bytes",
                "labels": {},
            },
            {
                "metric_type": "memory",
                "name": "swap_usage_percent",
                "value": swap.percent,
                "unit": "percent",
                "labels": {},
            },
        ]

    @staticmethod
    def get_disk_metrics() -> list[dict]:
        """Collect disk usage metrics."""
        metrics = []

        for partition in psutil.disk_partitions():
            try:
                usage = psutil.disk_usage(partition.mountpoint)
                metrics.extend([
                    {
                        "metric_type": "disk",
                        "name": "disk_usage_percent",
                        "value": usage.percent,
                        "unit": "percent",
                        "labels": {"mountpoint": partition.mountpoint, "device": partition.device},
                    },
                    {
                        "metric_type": "disk",
                        "name": "disk_used_bytes",
                        "value": usage.used,
                        "unit": "bytes",
                        "labels": {"mountpoint": partition.mountpoint},
                    },
                ])
            except PermissionError:
                continue

        return metrics

    @staticmethod
    def get_network_metrics() -> list[dict]:
        """Collect network metrics."""
        net_io = psutil.net_io_counters()
        metrics = [
            {
                "metric_type": "network",
                "name": "network_bytes_sent",
                "value": net_io.bytes_sent,
                "unit": "bytes",
                "labels": {},
            },
            {
                "metric_type": "network",
                "name": "network_bytes_recv",
                "value": net_io.bytes_recv,
                "unit": "bytes",
                "labels": {},
            },
            {
                "metric_type": "network",
                "name": "network_packets_sent",
                "value": net_io.packets_sent,
                "unit": "count",
                "labels": {},
            },
            {
                "metric_type": "network",
                "name": "network_packets_recv",
                "value": net_io.packets_recv,
                "unit": "count",
                "labels": {},
            },
        ]

        return metrics

    @staticmethod
    def get_process_metrics(process_names: list[str]) -> list[dict]:
        """Check if critical processes are running."""
        metrics = []

        for proc_name in process_names:
            running = False
            for proc in psutil.process_iter(['name']):
                if proc.info['name'] == proc_name:
                    running = True
                    break

            metrics.append({
                "metric_type": "process",
                "name": "process_running",
                "value": 1.0 if running else 0.0,
                "unit": "boolean",
                "labels": {"process": proc_name},
            })

        return metrics

    @staticmethod
    def check_service_http(url: str, timeout: int = 5) -> dict:
        """Check HTTP service availability."""
        import httpx

        try:
            start = datetime.now()
            response = httpx.get(url, timeout=timeout, follow_redirects=True)
            latency = (datetime.now() - start).total_seconds() * 1000

            return {
                "metric_type": "service",
                "name": "service_http_latency",
                "value": latency,
                "unit": "ms",
                "labels": {
                    "url": url,
                    "status_code": str(response.status_code),
                    "healthy": str(response.status_code < 400).lower(),
                },
            }
        except Exception as e:
            return {
                "metric_type": "service",
                "name": "service_http_latency",
                "value": -1,
                "unit": "ms",
                "labels": {
                    "url": url,
                    "error": str(e),
                    "healthy": "false",
                },
            }

    @staticmethod
    def check_certificate(host: str, port: int = 443) -> dict:
        """Check TLS certificate expiration."""
        import ssl
        import socket
        from datetime import datetime

        try:
            context = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    expires = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    days_left = (expires - datetime.utcnow()).days

                    return {
                        "metric_type": "certificate",
                        "name": "certificate_days_remaining",
                        "value": days_left,
                        "unit": "days",
                        "labels": {
                            "host": host,
                            "port": str(port),
                            "expires": expires.isoformat(),
                        },
                    }
        except Exception as e:
            return {
                "metric_type": "certificate",
                "name": "certificate_days_remaining",
                "value": -1,
                "unit": "days",
                "labels": {
                    "host": host,
                    "error": str(e),
                },
            }

    @staticmethod
    def check_file_integrity(files: list[str]) -> list[dict]:
        """Check file integrity via SHA256 hashes."""
        metrics = []

        for filepath in files:
            path = Path(filepath)
            if path.exists():
                file_hash = hashlib.sha256(path.read_bytes()).hexdigest()
                metrics.append({
                    "metric_type": "file_integrity",
                    "name": "file_hash",
                    "value": 1.0,  # File exists
                    "unit": "status",
                    "labels": {
                        "path": filepath,
                        "sha256": file_hash,
                        "size": str(path.stat().st_size),
                    },
                })
            else:
                metrics.append({
                    "metric_type": "file_integrity",
                    "name": "file_hash",
                    "value": 0.0,  # File missing
                    "unit": "status",
                    "labels": {
                        "path": filepath,
                        "error": "file_not_found",
                    },
                })

        return metrics


class NavajaCyberAgent:
    """Main agent class that coordinates metric collection and reporting."""

    def __init__(self, config: dict):
        self.config = config
        self.agent_id = config.get("agent_id")
        self.agent_token = config.get("agent_token")
        self.backend_url = config.get("backend_url", "http://localhost:8000")
        self.interval = config.get("metric_interval", 30)
        self.collector = MetricCollector()
        self.running = False

    async def register(self) -> bool:
        """Register agent with the central server."""
        hostname = socket.gethostname()
        ip_address = socket.gethostbyname(hostname)

        registration_data = {
            "name": self.config.get("agent_name", f"agent-{hostname}"),
            "hostname": hostname,
            "ip_address": ip_address,
            "os_type": platform.system().lower(),
            "os_version": platform.release(),
            "agent_version": "0.1.0",
            "tags": self.config.get("tags", []),
        }

        async with httpx.AsyncClient() as client:
            try:
                response = await client.post(
                    f"{self.backend_url}/api/agents/register",
                    json=registration_data,
                    timeout=10,
                )

                if response.status_code == 200:
                    data = response.json()
                    self.agent_id = data["id"]
                    self.agent_token = data["token"]

                    logger.info(f"Agent registered successfully: {self.agent_id}")
                    logger.info("Save the following token securely:")
                    logger.info(f"  AGENT_TOKEN={self.agent_token}")

                    return True
                else:
                    logger.error(f"Registration failed: {response.text}")
                    return False

            except Exception as e:
                logger.error(f"Registration error: {e}")
                return False

    async def send_heartbeat(self):
        """Send heartbeat to server."""
        if not self.agent_id:
            return

        async with httpx.AsyncClient() as client:
            try:
                await client.post(
                    f"{self.backend_url}/api/agents/{self.agent_id}/heartbeat",
                    json={"status": "active"},
                    timeout=5,
                )
            except Exception as e:
                logger.warning(f"Heartbeat failed: {e}")

    async def send_metrics(self, metrics: list[dict]):
        """Send collected metrics to the central server."""
        if not self.agent_id:
            logger.error("Agent not registered")
            return

        # Add agent_id to all metrics
        for metric in metrics:
            metric["agent_id"] = self.agent_id
            metric["timestamp"] = datetime.utcnow().isoformat()

        async with httpx.AsyncClient() as client:
            try:
                response = await client.post(
                    f"{self.backend_url}/api/metrics/batch",
                    json={"metrics": metrics},
                    timeout=10,
                )

                if response.status_code == 200:
                    logger.debug(f"Sent {len(metrics)} metrics")
                else:
                    logger.warning(f"Failed to send metrics: {response.status_code}")

            except Exception as e:
                logger.error(f"Error sending metrics: {e}")

    def collect_all_metrics(self) -> list[dict]:
        """Collect all configured metrics."""
        metrics = []

        # System metrics
        metrics.extend(self.collector.get_cpu_metrics())
        metrics.extend(self.collector.get_memory_metrics())
        metrics.extend(self.collector.get_disk_metrics())
        metrics.extend(self.collector.get_network_metrics())

        # Process monitoring
        if "processes" in self.config:
            metrics.extend(self.collector.get_process_metrics(self.config["processes"]))

        # Service checks
        if "services" in self.config:
            for service in self.config["services"]:
                metrics.append(self.collector.check_service_http(service["url"]))

        # Certificate checks
        if "certificates" in self.config:
            for cert in self.config["certificates"]:
                metrics.append(self.collector.check_certificate(cert["host"], cert.get("port", 443)))

        # File integrity
        if "file_integrity" in self.config:
            metrics.extend(self.collector.check_file_integrity(self.config["file_integrity"]))

        return metrics

    async def run(self):
        """Main agent loop."""
        self.running = True
        logger.info(f"Starting NavajaCyber Agent (interval: {self.interval}s)")

        while self.running:
            try:
                # Collect metrics
                metrics = self.collect_all_metrics()

                # Send to server
                await self.send_metrics(metrics)

                # Send heartbeat
                await self.send_heartbeat()

                # Wait for next interval
                await asyncio.sleep(self.interval)

            except Exception as e:
                logger.error(f"Agent error: {e}")
                await asyncio.sleep(5)

    def stop(self):
        """Stop the agent."""
        self.running = False
        logger.info("Agent stopping...")


def load_config(config_path: str | None) -> dict:
    """Load configuration from file or environment."""
    config = {
        "backend_url": os.getenv("BACKEND_URL", "http://localhost:8000"),
        "agent_id": os.getenv("AGENT_ID"),
        "agent_token": os.getenv("AGENT_TOKEN"),
        "metric_interval": int(os.getenv("METRIC_INTERVAL", "30")),
        "tags": [],
        "processes": [],
        "services": [],
        "certificates": [],
        "file_integrity": [],
    }

    if config_path and Path(config_path).exists():
        with open(config_path) as f:
            if config_path.endswith(".yaml") or config_path.endswith(".yml"):
                file_config = yaml.safe_load(f)
            else:
                file_config = json.load(f)
            config.update(file_config)

    return config


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="NavajaCyber Monitoring Agent",
        epilog="USO AUTORIZADO ÚNICAMENTE"
    )
    parser.add_argument("--register", action="store_true", help="Register agent with server")
    parser.add_argument("--backend", type=str, help="Backend server URL")
    parser.add_argument("--config", type=str, help="Path to configuration file")
    parser.add_argument("--name", type=str, help="Agent name")
    parser.add_argument("--interval", type=int, help="Metric collection interval (seconds)")

    args = parser.parse_args()

    # Load configuration
    config = load_config(args.config)

    if args.backend:
        config["backend_url"] = args.backend
    if args.name:
        config["agent_name"] = args.name
    if args.interval:
        config["metric_interval"] = args.interval

    # Create agent
    agent = NavajaCyberAgent(config)

    # Handle signals
    def signal_handler(sig, frame):
        agent.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Run agent
    if args.register:
        success = asyncio.run(agent.register())
        if not success:
            sys.exit(1)
    else:
        if not config.get("agent_id"):
            logger.error("Agent not registered. Run with --register first.")
            sys.exit(1)
        asyncio.run(agent.run())


if __name__ == "__main__":
    main()
