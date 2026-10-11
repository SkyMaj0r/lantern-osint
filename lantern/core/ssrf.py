from __future__ import annotations

import asyncio
import ipaddress
import socket
from typing import Union

import httpx

IPAddress = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]

# Hard rule: block private/loopback/link-local ranges on every outbound request,
# since the tool fetches URLs derived from user input.
_BLOCKED_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]

_ALLOWED_SCHEMES = {"http", "https"}


class SSRFError(Exception):
    pass


def is_blocked_ip(ip: IPAddress) -> bool:
    # IPv4-mapped IPv6 (::ffff:10.0.0.1) must be unwrapped before checking,
    # otherwise it sails through the IPv6 ranges above.
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return any(ip in net for net in _BLOCKED_NETWORKS)


async def resolve_host(host: str) -> list[IPAddress]:
    try:
        return [ipaddress.ip_address(host)]
    except ValueError:
        pass

    loop = asyncio.get_running_loop()
    try:
        infos = await loop.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise SSRFError(f"DNS resolution failed for {host!r}: {exc}") from exc

    addresses = {ipaddress.ip_address(info[4][0]) for info in infos}
    if not addresses:
        raise SSRFError(f"no addresses resolved for {host!r}")
    return list(addresses)


async def resolve_safe(host: str) -> IPAddress:
    """Resolve `host` and return one address that is confirmed not blocked.

    Raises SSRFError if the host has no safe address.
    """
    addresses = await resolve_host(host)
    for ip in addresses:
        if not is_blocked_ip(ip):
            return ip
    raise SSRFError(f"{host!r} resolves only to blocked addresses: {addresses}")


class SSRFGuardTransport(httpx.AsyncHTTPTransport):
    """An httpx transport that resolves the target host itself, rejects
    private/loopback/link-local addresses, and pins the connection to the
    exact validated IP (rewriting the request's host and setting the
    original hostname as the Host header + TLS SNI). Pinning closes the
    DNS-rebinding TOCTOU window a plain pre-request check would leave open.
    """

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        if request.url.scheme not in _ALLOWED_SCHEMES:
            raise SSRFError(f"scheme not allowed: {request.url.scheme!r}")

        original_host = request.url.host
        ip = await resolve_safe(original_host)

        request.url = request.url.copy_with(host=str(ip))
        request.headers["host"] = original_host
        request.extensions["sni_hostname"] = original_host

        return await super().handle_async_request(request)


def build_guarded_client(**kwargs) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=SSRFGuardTransport(), **kwargs)
