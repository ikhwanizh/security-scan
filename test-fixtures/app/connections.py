import ipaddress
import socket

import httpx
import requests


async def execute(connection, plain_password):
    db_client = DatabaseClient(
        db_type=connection["db_type"],
        host=connection["host"],
        port=connection["port"],
        password=plain_password,
    )
    return db_client


def fetch(webhook_url):
    return requests.post(webhook_url, json={})


def fetch_validated(target_url, host):
    ip = ipaddress.ip_address(socket.gethostbyname(host))
    if ip.is_private or ip.is_loopback:
        raise ValueError("blocked")
    return httpx.get(target_url)


def local_only():
    c = DatabaseClient(host="localhost", port=5432)
    r = requests.get("https://api.example.com/health")
    return c, r


def validated_helper(conn):
    validate_host(conn.host)
    return MongoClient(host=conn.host)
