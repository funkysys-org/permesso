"""Target parsing and URL derivation."""
from __future__ import annotations

from dataclasses import dataclass

DEFAULT_PORTS = (80, 443)


@dataclass
class TargetSpec:
    host: str
    ports: list[int]

    @classmethod
    def parse(cls, host: str, ports: str | None = None) -> "TargetSpec":
        if host.startswith(("http://", "https://")):
            raise ValueError("pass a bare host or IP, not a URL")
        host = host.strip().rstrip(".")
        if not host or any(c.isspace() for c in host) or "/" in host:
            raise ValueError(f"invalid target host: {host!r}")
        if ports:
            parsed = sorted({int(p) for p in ports.split(",") if p.strip()})
        else:
            parsed = list(DEFAULT_PORTS)
        for p in parsed:
            if not 1 <= p <= 65535:
                raise ValueError(f"invalid port {p}")
        return cls(host=host.lower(), ports=parsed)

    def base_urls(self) -> list[str]:
        urls = []
        for p in self.ports:
            if p == 443:
                urls.append(f"https://{self.host}")
            elif p == 80:
                urls.append(f"http://{self.host}")
            else:
                urls.append(f"http://{self.host}:{p}")
                urls.append(f"https://{self.host}:{p}")
        return urls
