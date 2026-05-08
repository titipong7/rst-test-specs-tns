from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Protocol
import struct
import socket
import ssl
import xml.etree.ElementTree as ET


REQUIRED_RSA_KEY_ALGORITHM = "RSA"
REQUIRED_RSA_KEY_SIZE_BITS = 4096
REQUIRED_ECDSA_KEY_ALGORITHM = "ECDSA"
REQUIRED_ECDSA_KEY_SIZE_BITS = 256
RECV_BUFFER_SIZE = 4096


class EppTlsHandshakeError(RuntimeError):
    """Raised when EPP mTLS handshake fails with SSL-specific causes."""


@dataclass(frozen=True)
class EppMtlsConfig:
    host: str
    client_cert_file: Path
    client_key_file: Path
    ca_cert_file: Path | None = None
    port: int = 700
    timeout_seconds: int = 30
    key_algorithm: str = REQUIRED_RSA_KEY_ALGORITHM
    key_size_bits: int = REQUIRED_RSA_KEY_SIZE_BITS

    def __post_init__(self) -> None:
        key_profile = (self.key_algorithm.upper(), self.key_size_bits)
        valid_profiles = {
            (REQUIRED_RSA_KEY_ALGORITHM, REQUIRED_RSA_KEY_SIZE_BITS),
            (REQUIRED_ECDSA_KEY_ALGORITHM, REQUIRED_ECDSA_KEY_SIZE_BITS),
        }
        if key_profile not in valid_profiles:
            raise ValueError(
                "ICANN 2026 EPP mTLS profile requires either RSA 4096-bit or ECDSA P-256 client keys, "
                f"got: {self.key_algorithm} {self.key_size_bits}-bit"
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
    @staticmethod
    def _recv_exact(sock: ssl.SSLSocket, expected_bytes: int) -> bytes:
        chunks: list[bytes] = []
        remaining = expected_bytes
        while remaining > 0:
            chunk = sock.recv(min(RECV_BUFFER_SIZE, remaining))
            if not chunk:
                raise ConnectionError("Connection closed before full EPP frame was received")
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)

    def send(
        self,
        *,
        xml_command: str,
        ssl_context: ssl.SSLContext,
        host: str,
        port: int,
        timeout_seconds: int,
    ) -> str:
        xml_payload = xml_command.encode("utf-8")
        framed_payload = struct.pack("!I", len(xml_payload) + 4) + xml_payload

        try:
            with socket.create_connection((host, port), timeout=timeout_seconds) as sock:
                with ssl_context.wrap_socket(sock, server_hostname=host) as tls_sock:
                    tls_sock.sendall(framed_payload)
                    header = self._recv_exact(tls_sock, 4)
                    body_length = struct.unpack("!I", header)[0] - 4
                    if body_length < 0:
                        raise ValueError("Received invalid EPP frame length")
                    body = self._recv_exact(tls_sock, body_length)
                    return body.decode("utf-8")
        except ssl.SSLCertVerificationError as exc:
            raise EppTlsHandshakeError(f"mTLS handshake failed: server certificate verification error ({exc})") from exc
        except ssl.SSLZeroReturnError as exc:
            raise EppTlsHandshakeError(
                "mTLS handshake failed: TLS session closed unexpectedly (possible cipher suite mismatch)"
            ) from exc


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
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.maximum_version = ssl.TLSVersion.TLSv1_3
        context.options |= ssl.OP_NO_SSLv3
        context.options |= ssl.OP_NO_TLSv1
        context.options |= ssl.OP_NO_TLSv1_1
        context.load_cert_chain(
            certfile=str(self.config.client_cert_file),
            keyfile=str(self.config.client_key_file),
        )
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        return context

    def send_epp_command(self, xml_content: str) -> str:
        return self.transport.send(
            xml_command=xml_content,
            ssl_context=self.ssl_context,
            host=self.config.host,
            port=self.config.port,
            timeout_seconds=self.config.timeout_seconds,
        )

    def send_command(self, xml_command: str) -> str:
        return self.send_epp_command(xml_command)

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

    def run_login_and_check(self, *, login_xml: str, check_xml: str) -> list["EppCommandCheckResult"]:
        login_response = self.send_epp_command(login_xml)
        check_response = self.send_epp_command(check_xml)
        return [
            assess_epp_command(command_name="login", response_xml=login_response),
            assess_epp_command(command_name="check", response_xml=check_response),
        ]


@dataclass(frozen=True)
class EppCommandCheckResult:
    command_name: str
    response_code: int
    status: str
    reason: str


def assess_epp_command(*, command_name: str, response_xml: str) -> EppCommandCheckResult:
    code = EppClient.result_code(response_xml)
    if 1000 <= code < 2000:
        return EppCommandCheckResult(
            command_name=command_name,
            response_code=code,
            status="pass",
            reason=f"{command_name} command accepted",
        )
    if code == 2306:
        return EppCommandCheckResult(
            command_name=command_name,
            response_code=code,
            status="fail",
            reason=f"{command_name} command rejected by Narrow Glue Policy",
        )
    return EppCommandCheckResult(
        command_name=command_name,
        response_code=code,
        status="fail",
        reason=f"{command_name} command failed with EPP result code {code}",
    )
