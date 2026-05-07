from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Protocol
import socket
import ssl
import xml.etree.ElementTree as ET


REQUIRED_KEY_ALGORITHM = "RSA"
REQUIRED_KEY_SIZE_BITS = 4096
RECV_BUFFER_SIZE = 4096


@dataclass(frozen=True)
class EppMtlsConfig:
    host: str
    client_cert_file: Path
    client_key_file: Path
    ca_cert_file: Path | None = None
    port: int = 700
    timeout_seconds: int = 30
    key_algorithm: str = REQUIRED_KEY_ALGORITHM
    key_size_bits: int = REQUIRED_KEY_SIZE_BITS

    def __post_init__(self) -> None:
        if self.key_algorithm.upper() != REQUIRED_KEY_ALGORITHM:
            raise ValueError(
                f"ICANN 2026 EPP mTLS profile requires RSA client keys, got: {self.key_algorithm}"
            )
        if self.key_size_bits != REQUIRED_KEY_SIZE_BITS:
            raise ValueError(
                f"ICANN 2026 EPP mTLS profile requires 4096-bit client keys, got: {self.key_size_bits} bits"
            )


class EppTransport(Protocol):
    def send(
        self,
        *,
        xml_command: str,
        ssl_context: ssl.SSLContext,
        host: str,
        port: int,
        timeout_seconds: int,
    ) -> str: ...


class SocketEppTransport:
    def send(
        self,
        *,
        xml_command: str,
        ssl_context: ssl.SSLContext,
        host: str,
        port: int,
        timeout_seconds: int,
    ) -> str:
        with socket.create_connection((host, port), timeout=timeout_seconds) as sock:
            with ssl_context.wrap_socket(sock, server_hostname=host) as tls_sock:
                tls_sock.sendall(xml_command.encode("utf-8"))
                chunks: list[bytes] = []
                while True:
                    chunk = tls_sock.recv(RECV_BUFFER_SIZE)
                    if not chunk:
                        break
                    chunks.append(chunk)
        return b"".join(chunks).decode("utf-8")


class EppClient:
    def __init__(
        self,
        config: EppMtlsConfig,
        transport: EppTransport | None = None,
        ssl_context: ssl.SSLContext | None = None,
    ) -> None:
        self.config = config
        self.transport = transport or SocketEppTransport()
        self.ssl_context = ssl_context or self._build_ssl_context()

    def _build_ssl_context(self) -> ssl.SSLContext:
        context = ssl.create_default_context(
            purpose=ssl.Purpose.SERVER_AUTH,
            cafile=str(self.config.ca_cert_file) if self.config.ca_cert_file else None,
        )
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.load_cert_chain(
            certfile=str(self.config.client_cert_file),
            keyfile=str(self.config.client_key_file),
        )
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        return context

    def send_command(self, xml_command: str) -> str:
        return self.transport.send(
            xml_command=xml_command,
            ssl_context=self.ssl_context,
            host=self.config.host,
            port=self.config.port,
            timeout_seconds=self.config.timeout_seconds,
        )

    @staticmethod
    def result_code(response_xml: str) -> int:
        root = ET.fromstring(response_xml)
        result = root.find(".//{*}result")
        if result is None:
            result = root.find(".//result")
        if result is None or "code" not in result.attrib:
            raise ValueError("EPP response missing result code")
        return int(result.attrib["code"])

    @classmethod
    def is_success(cls, response_xml: str) -> bool:
        return 1000 <= cls.result_code(response_xml) < 2000
