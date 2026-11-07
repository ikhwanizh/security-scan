import ipaddress
import socket

import httpx
import requests


async def execute(connection, plain_password):
    # ruleid: kscan-ssrf-unvalidated-host
    db_client = DatabaseClient(
        db_type=connection["db_type"],
        host=connection["host"],
        port=connection["port"],
        password=plain_password,
    )
    return db_client


def fetch(webhook_url):
    # ruleid: kscan-ssrf-unvalidated-host
    return requests.post(webhook_url, json={})


def fetch_validated(target_url, host):
    ip = ipaddress.ip_address(socket.gethostbyname(host))
    if ip.is_private or ip.is_loopback:
        raise ValueError("blocked")
    # ok: kscan-ssrf-unvalidated-host
    return httpx.get(target_url)


def local_only():
    # ok: kscan-ssrf-unvalidated-host
    c = DatabaseClient(host="localhost", port=5432)
    # ok: kscan-ssrf-unvalidated-host
    r = requests.get("https://api.example.com/health")
    return c, r


def validated_helper(conn):
    validate_host(conn.host)
    # ok: kscan-ssrf-unvalidated-host
    return MongoClient(host=conn.host)


class EmbeddingClient:
    def __init__(self, settings):
        self.base_url = settings.OLLAMA_BASE_URL
        # ok: kscan-ssrf-unvalidated-host
        self.ollama = ollama.Client(host=settings.OLLAMA_BASE_URL)

    def health(self, client):
        # ok: kscan-ssrf-unvalidated-host
        return client.get(f"{self.base_url}/health")


def save(user_id, request):
    # ok: kscan-ssrf-unvalidated-host
    return DatabaseConnection(user_id=user_id, host=request.host)


async def test_route(request):
    # ruleid: kscan-ssrf-unvalidated-host
    return await ConnectionService.test_connection_credentials(db_type=request.db_type, host=request.host)


def call_mcp(client, mcp_url):
    # ruleid: kscan-ssrf-unvalidated-host
    return client.post(mcp_url, json={})
