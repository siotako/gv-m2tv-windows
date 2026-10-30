# SPDX-License-Identifier: MIT
"""GV-M2TV certificate authentication and B-CAS initialization.

Ported from wanimochi-tv SecureAuth.swift and BCASManager.swift.
Copyright (c) 2026 sh1ma. Licensed under the MIT License; see
LICENSE. The upstream implementations attribute their
protocol to gvm2tv-init.c and gvm2tv-stream.c.

No device is accessed on import. Callers must serialize access to the client's
command/interrupt endpoints. Keys and card responses are deliberately not logged.

The upstream B-CAS encoder swaps words multiple times, and its intermediate
encLen * 2 loops exceed its fixed buffer for long APDUs. The equivalent wire
encoding below avoids those loops. Upstream response decoding also skips command
ID/status/length checks; this port fails on malformed replies instead.
"""

from __future__ import annotations

import hashlib
import struct
import time
from typing import Protocol

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


class SecureProtocolError(RuntimeError):
    """A device response was incomplete, unsuccessful, or inconsistent."""

    def __init__(self, message: str, *, status: int | None = None):
        super().__init__(message)
        self.status = status


class Client(Protocol):
    def reg_write(self, reg: int, data: bytes, addr: int = 0) -> None: ...
    def reg_read(self, reg: int, length: int, addr: int = 0) -> bytes: ...
    def api_command(self, command: bytes) -> None: ...
    def get_ack(self, timeout_ms: int) -> bytes: ...
    def secure_reg_write(self, base: int, data: bytes) -> None: ...
    def secure_reg_read(self, base: int, length: int) -> bytes: ...
    def bcas_reg_write(self, reg: int, data: bytes) -> None: ...
    def bcas_reg_read(self, reg: int, length: int) -> bytes: ...


def _swap16(data: bytes) -> bytes:
    if len(data) % 2:
        raise ValueError("word-swap input must have an even length")
    out = bytearray(data)
    out[0::2], out[1::2] = data[1::2], data[0::2]
    return bytes(out)


def _swap32(data: bytes) -> bytes:
    if len(data) % 4:
        raise ValueError("dword-swap input must be aligned to four bytes")
    return b"".join(data[i:i + 4][::-1] for i in range(0, len(data), 4))


def _aes_cbc(key: bytes, data: bytes, *, decrypt: bool = False) -> bytes:
    if len(key) != 16 or not data or len(data) % 16:
        raise ValueError("AES-128 CBC requires a 16-byte key and aligned data")
    cipher = Cipher(algorithms.AES(key), modes.CBC(bytes(16)))
    operation = cipher.decryptor() if decrypt else cipher.encryptor()
    return operation.update(data) + operation.finalize()


def _wire_dword(data: bytes, offset: int) -> int:
    low, high = struct.unpack_from("<HH", data, offset)
    return (low << 16) | high


def _split_dword(value: int) -> bytes:
    if not 0 <= value <= 0xFFFFFFFF:
        raise ValueError("secure command field exceeds 32 bits")
    return struct.pack("<HH", value >> 16, value & 0xFFFF)


def _require_length(data: bytes, length: int, label: str) -> bytes:
    data = bytes(data)
    if len(data) != length:
        raise SecureProtocolError(f"{label}: expected {length} bytes, received {len(data)}")
    return data


class SecureAuth:
    """Device certificate authentication; call authenticate after IDLE FW boots."""

    def __init__(self, client: Client):
        self.client = client
        self.aes_key: bytes | None = None
        self._rtc_counter: int | None = None

    @staticmethod
    def build_command(command_id: int, parameter_count: int, parameters: bytes) -> bytes:
        parameters = bytes(parameters)
        if not 0 <= parameter_count <= 124:
            raise ValueError("secure command parameter count exceeds packet capacity")
        if len(parameters) != parameter_count * 4:
            raise ValueError("secure command parameter bytes do not match count")
        packet = bytearray(512)
        packet[0:4] = _split_dword(command_id)
        packet[8:12] = _split_dword(parameter_count)
        packet[12:16] = b"\xff" * 4
        packet[16:16 + len(parameters)] = parameters
        return bytes(packet)

    @staticmethod
    def decode_response(response: bytes, expected_command: int) -> bytes:
        """Decode the post-swap reply to status LE32 + parameter LE32 values."""
        response = _require_length(response, 512, "secure response")
        if _wire_dword(response, 0) != expected_command:
            raise SecureProtocolError("secure response command ID does not match request")
        status = _wire_dword(response, 4)
        if status != 0:
            raise SecureProtocolError(f"secure command failed with status 0x{status:08x}", status=status)
        count = _wire_dword(response, 8)
        if count > 124:
            raise SecureProtocolError("secure response parameter count exceeds packet capacity")
        return struct.pack("<I", status) + b"".join(
            struct.pack("<I", _wire_dword(response, 16 + i * 4)) for i in range(count)
        )

    def exchange(self, command_id: int, packet: bytes) -> bytes:
        packet = _require_length(packet, 512, "secure command")
        if _wire_dword(packet, 0) != command_id:
            raise ValueError("secure packet command ID does not match request")
        output = bytearray(packet)
        encrypt_request = bool(command_id & 0x400)
        decrypt_response = bool(command_id & 0x200)
        if (encrypt_request or decrypt_response) and self.aes_key is None:
            raise SecureProtocolError("device certificate authentication is required")
        if encrypt_request:
            if self.aes_key is None:
                raise SecureProtocolError("device certificate authentication is required")
            ciphertext = _aes_cbc(self.aes_key, packet[12:508])
            output[12:508] = _swap16(ciphertext)
            output[:508] = _swap16(output[:508])
        else:
            output[:12] = _swap16(output[:12])

        self.client.secure_reg_write(0x83000, bytes(output))
        self.client.api_command(bytes([0, 0, 0x08, 0, 0, 0]))
        acknowledged = False
        for _ in range(20):
            try:
                acknowledged = bool(self.client.get_ack(500))
            except TimeoutError:
                continue
            if acknowledged:
                break
        if not acknowledged:
            raise TimeoutError("secure command did not acknowledge within 10 seconds")

        response = bytearray(_require_length(
            self.client.secure_reg_read(0x83000, 512), 512, "secure response"
        ))
        response[:508] = _swap16(response[:508])
        if decrypt_response:
            ciphertext = _swap16(response[12:508])
            response[12:508] = _aes_cbc(self.aes_key, ciphertext, decrypt=True)
        result = bytes(response)
        # Validate all replies, including CER_RES_SEND and retainSecureEP, which
        # upstream accepted without checking their status or echoed command ID.
        self.decode_response(result, command_id)
        return result

    def authenticate(self) -> bytes:
        self.aes_key = None
        self._rtc_counter = None
        self.client.reg_write(0x90078, bytes([0x08, 0x04]))
        first_id = 0x01010000
        first = self.exchange(first_id, self.build_command(first_id, 8, _DRIVER_VERSION))
        decoded = self.decode_response(first, first_id)
        if len(decoded) < 40:
            raise SecureProtocolError("certificate challenge response is too short")
        index = hashlib.sha1(_MAGIC + bytes([decoded[0x27], 0x0B])).digest()[19] & 0x0F
        password = _swap32(_DRIVER_PASSWORDS[index])
        challenge_hash = hashlib.sha1(_swap32(decoded[4:36]) + password).digest()

        second_id = 0x01020000
        self.exchange(second_id, self.build_command(second_id, 5, challenge_hash))
        digest = hashlib.sha1(challenge_hash + password).digest()
        key = digest[16:20] + digest[6:10] + digest[11:15] + digest[0:4]
        self.aes_key = key
        # Original certificate() at 0x1000ae31e starts RTC verification at one.
        self._rtc_counter = 1
        return key

    def real_time_certificate(self) -> None:
        """Refresh device verification; caller schedules this every 20 seconds.

        Call once during setup, then periodically while the authenticated device
        remains in use. The caller must serialize this complete two-command
        transaction against other control/interrupt operations.
        """
        if self.aes_key is None or self._rtc_counter is None:
            raise SecureProtocolError("device certificate authentication is required")
        start_id = 0x02010200
        response = self.exchange(start_id, self.build_command(start_id, 0, b""))
        if _wire_dword(response, 8) < 8:
            raise SecureProtocolError("realtime certificate challenge response is too short")
        # The original decoder's word assembly followed by MemCpyLongToByte
        # cancels its extra post-AES swap. This port retains raw AES plaintext,
        # so the 32 challenge bytes are already in the hash's required order.
        challenge = response[16:48]
        # Original startup at 0x1000a3e50 unmasks _m_magic_number with
        # alternating A5/5A XOR bytes, yielding the existing _MAGIC constant.
        # Hashing the obfuscated bytes from the executable fails verification.
        digest = hashlib.sha1(challenge + _MAGIC + self._rtc_counter.to_bytes(4, "big")).digest()
        answer_id = 0x02020400
        self.exchange(answer_id, self.build_command(answer_id, 5, digest))
        self._rtc_counter = (self._rtc_counter + 1) & 0xFFFFFFFF

    keepalive = real_time_certificate

    def release_secure_ep(self, *, missing_ok: bool = True) -> bool:
        """Release the device stream key after streaming has stopped.

        Original releaseSecureEP at 0x1000aa8d0 uses command 0x07030400 with
        parameters [0x03000000, 0]. A prior process can leave this resource
        retained even after sleep/wake and a fresh certificate authentication.
        Only the explicit "not used" status is optionally ignored.
        """
        command_id = 0x07030400
        parameters = bytes([0, 0, 0, 3]) + bytes(4)
        try:
            self.exchange(command_id, self.build_command(command_id, 2, parameters))
        except SecureProtocolError as error:
            if missing_ok and error.status == 0x00020018:
                return False
            raise
        return True


class BCAS:
    """Initialize the inserted B-CAS card and retrieve the device contents key.

    The device must already have entered IDLE after SecureAuth.authenticate().
    Card identity is neither retained nor emitted by this implementation.
    """

    def __init__(self, client: Client, auth: SecureAuth):
        self.client = client
        self.auth = auth
        self.contents_key: bytes | None = None
        self._last_marker: bytes | None = None

    def _key(self) -> bytes:
        if self.auth.aes_key is None:
            raise SecureProtocolError("device certificate authentication is required")
        return self.auth.aes_key

    def _wait_ready(self, attempts: int = 30) -> bytes:
        for _ in range(attempts):
            status = _require_length(self.client.bcas_reg_read(0x822AC, 2), 2, "B-CAS status")
            state = status[0] >> 4
            if state == 3:
                return status
            if state != 2:
                raise SecureProtocolError(f"unexpected B-CAS reader state 0x{state:x}")
            time.sleep(0.02)
        raise TimeoutError("B-CAS reader did not become ready")

    def _api_with_ack(self, command: bytes, timeout_ms: int) -> None:
        self.client.api_command(command)
        if not self.client.get_ack(timeout_ms):
            raise TimeoutError("B-CAS command did not acknowledge")

    def _send_apdu(self, apdu: bytes) -> None:
        apdu = bytes(apdu)
        if not apdu or len(apdu) > 260:
            raise ValueError("B-CAS APDU length is outside supported buffer capacity")
        # Original m2TV sendBcasCommandBytes:length: at 0x1000abc3c writes
        # APDU length + 4 into the API command before padding the register data.
        # Swift rounds this field up to an even length; keep the original value.
        command_size = len(apdu) + 4
        padded_size = (command_size + 1) & ~1
        encrypted_size = (padded_size + 15) & ~15
        # The original word-swap chain simplifies to this plaintext and direct
        # ciphertext write. Keep the device's four-byte request wrapper exactly.
        plaintext = (b"\x00\xff\x00\xff" + apdu).ljust(encrypted_size, b"\x00")
        self.client.bcas_reg_write(0x8219C, _aes_cbc(self._key(), plaintext))
        self._api_with_ack(bytes([0, 0, 0x0A, 0x10,
                                  command_size >> 8, command_size & 0xFF]), 3000)

    def _response(self, minimum_length: int = 2) -> bytes:
        # Original lengthOfBCASResponse at 0x1000ace40 checks the low nibble as
        # response status and uses byte 1 alone as the length. Swift mistakenly
        # combines them into a 12-bit length. The first four plaintext bytes are
        # a changing marker, not a fixed header (original random_ comparison at
        # 0x1000acff0). getBcasResponse skips them unconditionally.
        for _ in range(30):
            status = _require_length(self.client.bcas_reg_read(0x822AC, 2), 2, "B-CAS status")
            state = status[0] >> 4
            length = status[1]
            if state in (2, 3) and length == 0:
                time.sleep(0.02)
                continue
            if state != 3:
                raise SecureProtocolError(f"unexpected B-CAS reader state 0x{state:x}")
            if status[0] & 0x0F:
                raise SecureProtocolError("B-CAS reader returned an unsuccessful response status")
            if length < 4 + minimum_length:
                raise SecureProtocolError("B-CAS response is too short for marker and payload")
            encrypted_length = (length + 15) & ~15
            raw = _require_length(self.client.bcas_reg_read(0x822AE, encrypted_length),
                                  encrypted_length, "B-CAS response")
            decrypted = _aes_cbc(self._key(), raw, decrypt=True)[:length]
            marker, plain = decrypted[:4], decrypted[4:]
            if marker == self._last_marker:
                time.sleep(0.25)
                continue
            if len(plain) < minimum_length or not any(plain):
                raise SecureProtocolError("B-CAS decrypted response is empty or truncated")
            # The card's status trailer is preserved after removing its marker.
            if len(plain) >= 2 and plain[-2] in (0x60, 0x61, 0x62, 0x63, 0x64,
                                                0x65, 0x67, 0x68, 0x69, 0x6A,
                                                0x6B, 0x6C, 0x6D, 0x6E, 0x6F):
                raise SecureProtocolError("B-CAS APDU returned an unsuccessful status")
            self._last_marker = marker
            return plain
        raise TimeoutError("B-CAS response remained empty or stale")

    def initialize(self) -> bytes:
        self._key()
        self.contents_key = None
        self._last_marker = None
        self._api_with_ack(bytes([0, 0, 0x0A, 0, 0, 1]), 2000)
        self._api_with_ack(bytes([0, 0, 0x0A, 1, 0, 1]), 2000)
        self._wait_ready(20)

        self._send_apdu(bytes([0x90, 0x30, 0, 0, 0]))
        time.sleep(0.05)
        self._response(minimum_length=50)
        self._send_apdu(bytes([0x90, 0x32, 0, 0, 0]))
        time.sleep(0.05)
        self._response()

        command_id = 0x07010600
        parameters = bytes([0, 0, 0, 3]) + bytes(8)
        packet = self.auth.build_command(command_id, 3, parameters)
        try:
            result = self.auth.exchange(command_id, packet)
        except SecureProtocolError as error:
            if error.status != 0x00020019:
                raise
            # The exclusive device connection and fresh authentication belong to
            # this process. Release the previous process's retained playback EP
            # only when firmware explicitly reports it is already in use.
            self.auth.release_secure_ep()
            result = self.auth.exchange(command_id, packet)
        if _wire_dword(result, 8) < 4:
            raise SecureProtocolError("retainSecureEP response does not contain a complete contents key")
        # Preserve upstream extraction from the decrypted wire response. This
        # field is already in AES byte order, unlike decode_response's LE dwords.
        key = result[16:32]
        if key in (bytes(16), b"\xff" * 16):
            raise SecureProtocolError("retainSecureEP returned an invalid contents key")
        self.contents_key = key
        return key


_DRIVER_VERSION = bytes.fromhex(
    "150095f8c50843a5a945f25b63733e0b364263094a1d4e9e9a3395f8c508a252"
)
_MAGIC = bytes.fromhex("c294a1bd41a9e38ef35ba1836b93da6cd95a1f248ba93d6b39d2a36b")
_DRIVER_PASSWORDS = tuple(bytes.fromhex(value) for value in (
    "2559d429c2fbbfd2309301712f8901ed8e94b0f34e1fb82783d91be2b898a0d1",
    "9e4ed37251033c64d6b11ac886f7c8aa4b3edda50e875ac06cc23dd10553e104",
    "7dde0ce5a0351b3b159217e1b460c346598dd54cf91047b059949cd0fca59560",
    "f6be41e66ca120367045d2e0074b3d540813471dda183f8eb44bd797e5898b0d",
    "f55b712682a0ec534d34772e34da1e592edaa5cab8f1d51042f2255608874546",
    "5c30f9f5b3d91c268fc03b559e79b6059786473b6fa3e17c7ed5cd0da1502fe3",
    "7ded569cf8c2829f49211dd0e30a8b0993c96d1bfe0d14667f2b01743fbfcb7c",
    "7dbad7a20c58bfb75e488fb024ea073390d57f69add59f28f822a77b79c502de",
    "9bdb72b26d241f5ca8d6a807db46186b7aa52f45c0aa23c0d601a5b00b752564",
    "472844e02187c01b4d962440776fe3f1c3bcad062db2c5655f54dd114a2d08e4",
    "790c4f021e59d4f9073dd893c02691bf06cdd37f21b367e350c258694316ad50",
    "2e1c828edd2fb59c83b75c3e2a4b08f609690f8280d29d242abda375a73f6d11",
    "b7b6e63571ea21ae8bc3d97c23cca6558aef340e5fec490c38b558b87ea87ee4",
    "e169bf62fea7ee5ff99cb682789d5d0372f8f3d69ac86567c019f7e7a91e924c",
    "f92d710c78d4cff1f44bf29eb47d3843dd5d1bbbc35c812d9b7bfde1549b4ca2",
    "8f9dd2b4c13732c699b5563537d2830f34592de031a273707b755c49ca596480",
))
