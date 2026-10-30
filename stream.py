# SPDX-License-Identifier: MIT
"""GV-M2TV transcoder and MPEG-TS reception over the supplied USB client.

Adapted from wanimochi-tv StreamingEngine.swift, Copyright (c) 2026 sh1ma.
MIT License: permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files (the "Software"), to
deal in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
of the Software, and to permit persons to whom the Software is furnished to do so,
subject to the following conditions: The above copyright notice and this
permission notice shall be included in all copies or substantial portions of the
Software. THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

The upstream comments and code disagree about whether the device sets TS
scrambling flags. ``auto`` uses those flags plus PES start-code evidence;
``sc`` follows only flags, and ``pmt`` decrypts every audio/video PID from PMTs.
This module never performs software MULTI2 descrambling: the physical B-CAS card
and tuner firmware handle broadcast conditional access.
"""

from __future__ import annotations

import logging
import threading
import time
from pathlib import Path

from Crypto.Cipher import AES
from tuner import Tuner

LOG = logging.getLogger(__name__)
TS_IV = bytes.fromhex("ec8f4b6ad92a36892bdfb618fc255efc")
TRC_PARAMS = (
    (0x1002, 0x84, 0x04), (0x1004, 0x01, 0x84), (0x100A, 0x00, 0x20),
    (0x100C, 0x00, 0x10), (0x101A, 0xB3, 0x00), (0x101C, 0x02, 0x0F),
    (0x104C, 0x9F, 0xC8), (0x1050, 0x80, 0x10), (0x1052, 0x80, 0x11),
    (0x1054, 0x80, 0x12), (0x1056, 0x80, 0x14), (0x1058, 0x80, 0x24),
    (0x105A, 0x80, 0x27), (0x105C, 0x80, 0x29), (0x105E, 0x81, 0x00),
    (0x1060, 0x81, 0x10), (0x1062, 0x81, 0xF0), (0x1102, 0x00, 0x02),
    (0x1104, 0x61, 0xA8), (0x1136, 0x01, 0x41), (0x113A, 0x02, 0x0F),
)
AV_STREAM_TYPES = {0x01, 0x02, 0x03, 0x04, 0x0F, 0x10, 0x11, 0x1B, 0x24, 0x42}


class StreamProtocolError(RuntimeError):
    """The device rejected streaming or did not complete its command protocol."""


def payload_offset(packet: bytes) -> int | None:
    """Return a validated payload offset, or None for invalid/no-payload TS."""
    if len(packet) != 188 or packet[0] != 0x47 or packet[1] & 0x80:
        return None
    adaptation = (packet[3] >> 4) & 3
    if adaptation in (0, 2):
        return None
    offset = 5 + packet[4] if adaptation == 3 else 4
    return offset if offset < 188 else None


def decrypt_payload(payload: bytes, key: bytes) -> bytes:
    """Device AES-CBC with a truncated OFB tail, resetting IV per TS packet."""
    aligned = len(payload) & ~15
    result = AES.new(key, AES.MODE_CBC, TS_IV).decrypt(payload[:aligned]) if aligned else b""
    if aligned != len(payload):
        last_cipher = payload[aligned - 16:aligned] if aligned else TS_IV
        tail_key = AES.new(key, AES.MODE_ECB).encrypt(last_cipher)
        result += bytes(a ^ b for a, b in zip(payload[aligned:], tail_key))
    return result


def _mpeg_crc(data: bytes) -> int:
    crc = 0xFFFFFFFF
    for value in data:
        crc ^= value << 24
        for _ in range(8):
            crc = ((crc << 1) ^ 0x04C11DB7) & 0xFFFFFFFF if crc & 0x80000000 else (crc << 1) & 0xFFFFFFFF
    return crc


class _PhaseOneDrainer:
    """Keep the single EP1 read active while phase-one STOP flushes the DSP."""

    def __init__(self, client):
        self.client = client
        self.finished = threading.Event()
        self.started = threading.Event()
        self.error = None
        self.bytes_read = 0
        self.thread = threading.Thread(target=self._read, name="GV-M2TV STOP EP1 drain", daemon=True)

    def _read(self):
        self.started.set()
        while not self.finished.is_set():
            try:
                data = bytes(self.client.bulk_read(4096, timeout_ms=200))
                self.bytes_read += len(data)
                if not data:
                    self.finished.wait(0.001)
            except OSError as error:
                if isinstance(error, TimeoutError) or getattr(error, "winerror", None) == 121:
                    self.finished.wait(0.001)
                    continue
                self.error = error
                return
            except Exception as error:
                self.error = error
                return

    def start(self):
        self.thread.start()
        if not self.started.wait(1):
            self.close()
            raise RuntimeError("EP1 STOP drainer did not start")

    def close(self):
        self.finished.set()
        self.thread.join(1)
        if self.thread.is_alive():
            # Do not let the caller start a second EP1 reader while this one
            # might still own a pending USB read. Normal reads time out in200ms.
            raise RuntimeError("EP1 STOP drainer did not finish; refusing another bulk reader")


class _StopSequence:
    """Device stop handshake, usable after a previous process left TRC active."""

    def __init__(self, client):
        self.client = client

    def state(self):
        value = bytes(self.client.reg_read(0x82008, 2))
        if len(value) != 2:
            raise RuntimeError("Short device-state register read during STOP")
        return int.from_bytes(value, "big")

    def clear_irq(self):
        self.client.reg_write(0x90074, b"\x07\xfc")

    def ack(self, timeout_ms):
        try:
            return bytes(self.client.get_ack(timeout_ms))
        except OSError as error:
            if isinstance(error, TimeoutError) or getattr(error, "winerror", None) == 121:
                return b""
            raise

    def flush_interrupts(self):
        self.clear_irq()
        for _ in range(5):
            ack = self.ack(100)
            if not ack:
                return
            if ack[0] == 0x20:
                self.clear_irq()

    def wait_state_change(self):
        for _ in range(5):
            ack = self.ack(2000)
            if ack and ack[0] == 0x20:
                self.clear_irq()
                return True
        return False

    def wait_command_ack(self):
        """Match original m2TV's GPIO-command ACK before awaiting state change."""
        for _ in range(20):
            ack = self.ack(500)
            if len(ack) >= 6 and ack[0] == 0x10 and ack[4] == 0x05 and ack[5] != 0x80:
                return True
            # A state-change left by an earlier command is not this command's
            # acceptance ACK. Clear it, then continue to the matching 0x10 ACK.
            if ack and ack[0] == 0x20:
                self.clear_irq()
        return False

    def stop_phase(self, subcommand):
        self.client.api_command(bytes((0, 0, 5, 0, 0, subcommand)))
        if not self.wait_command_ack():
            raise TimeoutError(f"STOP phase {subcommand:02x} did not receive matching command ACK")
        if not self.wait_state_change():
            raise TimeoutError(f"STOP phase {subcommand:02x} did not receive state-change notification")
        LOG.info("STOP phase %02x completed; device state=%04x", subcommand, self.state())

    def run(self, state=None):
        state = self.state() if state is None else state
        if state in (1, 0x11):
            return state
        if state not in (2, 4):
            raise RuntimeError(f"Cannot recover TRC STOP from state {state:04x}")
        try:
            self.client.clear_halt(0x81)
        except OSError:
            LOG.debug("EP1 halt clear failed before STOP; continuing handshake")
        self.flush_interrupts()
        # Original m2TV _StopTunerTSTera_MJ111 disables TS with two writes only;
        # full tuner/demodulator sleep in the Swift port changes this handshake.
        Tuner(self.client).stop_ts()
        drain_error = None
        if state == 2:
            # The DSP may need the host to accept its final EP1 data before it
            # can emit phase one's state-change interrupt. Interrupt and bulk
            # endpoints can operate concurrently, but only this thread reads
            # EP1 until it has been stopped/joined below.
            phase_one_drainer = _PhaseOneDrainer(self.client)
            phase_one_drainer.start()
            try:
                self.stop_phase(4)
            finally:
                phase_one_drainer.close()
            drain_error = phase_one_drainer.error
            LOG.info("STOP phase-one reader drained %d USB bytes", phase_one_drainer.bytes_read)
            # Original EP1_StopStream aborts its async reader and clears the
            # pipe stall after phase04's state change, before its final drain.
            # Joining above replaces aborting the reader; reset the pipe only
            # after it can no longer own an outstanding EP1 request.
            self.client.clear_halt(0x81)
        # START reaches 0002 (active reception). Phase04 must run before the
        # drain/phase01 handshake. Only 0004 can resume at the drain phase.
        self.flush_interrupts()
        deadline = time.monotonic() + 5
        drained = 0
        try:
            for _ in range(500):
                if time.monotonic() >= deadline:
                    break
                data = bytes(self.client.bulk_read(4096, timeout_ms=200))
                if not data:
                    break
                drained += len(data)
                # Original m2TV tests the START of one complete 4096-byte USB
                # read for this exact marker. A null packet elsewhere in TS
                # payload/data must not prematurely terminate the drain.
                if len(data) == 4096 and data.startswith(b"\x47\x1f\xff\x10\xff"):
                    break
        except Exception as error:
            if not isinstance(error, TimeoutError) and getattr(error, "winerror", None) != 121:
                drain_error = error
        LOG.info("STOP drained %d buffered USB bytes", drained)
        # Always attempt phase two after a drain failure; leaving firmware in
        # state 0004 prevents the next normal authentication/tune lifecycle.
        self.flush_interrupts()
        self.stop_phase(1)
        time.sleep(0.5)
        for _ in range(10):
            state = self.state()
            if state in (1, 0x11):
                if drain_error is not None:
                    raise drain_error
                LOG.info("STOP completed in firmware state %04x", state)
                return state
            self.ack(100)
            self.clear_irq()
            time.sleep(0.5)
        raise RuntimeError(f"STOP did not reach TRC standby or IDLE (state={state:04x})")


class _PSIAssembler:
    """Assemble bounded PSI sections, respecting pointer and continuity fields."""

    def __init__(self):
        self.buffer = bytearray()
        self.continuity = None

    def _extract(self) -> list[bytes]:
        sections = []
        while len(self.buffer) >= 3:
            if self.buffer[0] == 0xFF:
                self.buffer.clear()
                break
            length = ((self.buffer[1] & 15) << 8) | self.buffer[2]
            if length < 4 or length > 1021:
                self.buffer.clear()
                break
            size = length + 3
            if len(self.buffer) < size:
                break
            section = bytes(self.buffer[:size])
            del self.buffer[:size]
            if _mpeg_crc(section) == 0:
                sections.append(section)
        return sections

    def feed(self, packet: bytes) -> list[bytes]:
        offset = payload_offset(packet)
        if offset is None or packet[3] & 0xC0:
            return []
        cc = packet[3] & 15
        discontinuity = ((packet[3] >> 4) & 3) == 3 and packet[4] > 0 and packet[5] & 0x80
        if discontinuity:
            self.buffer.clear()
            self.continuity = None
        if self.continuity == cc:
            return []  # duplicated payload packet
        if self.continuity is not None and cc != (self.continuity + 1) & 15:
            self.buffer.clear()
        self.continuity = cc
        payload = packet[offset:]
        sections = []
        if packet[1] & 0x40:
            pointer = payload[0]
            if pointer + 1 > len(payload):
                self.buffer.clear()
                return []
            if self.buffer:
                self.buffer.extend(payload[1:1 + pointer])
                sections.extend(self._extract())
            self.buffer.clear()
            payload = payload[1 + pointer:]
        elif not self.buffer:
            return []
        self.buffer.extend(payload)
        sections.extend(self._extract())
        return sections


class StreamEngine:
    def __init__(self, client, contents_key: bytes, decrypt_mode: str = "auto"):
        if len(contents_key) != 16:
            raise ValueError("GV-M2TV contents key must be 16 bytes")
        if decrypt_mode not in {"auto", "sc", "pmt", "none"}:
            raise ValueError("decrypt_mode must be auto, sc, pmt, or none")
        self.client = client
        self.contents_key = bytes(contents_key)
        self.decrypt_mode = decrypt_mode
        self.running = False
        self.firmware_loaded = False
        self._reset_stream()

    def _reset_stream(self):
        self.raw_bytes = 0
        self.total_bytes = 0
        self.total_packets = 0
        self.decrypted_packets = 0
        self.scrambled_packets = 0
        self.sync_losses = 0
        self.programs = {}
        self.pmt_pids = set()
        self.encrypted_pids = set()
        self._program_es = {}
        self._psi = {0: _PSIAssembler()}
        self._buffer = bytearray()
        self._synced = False
        self._pid_modes = {}

    @property
    def stats(self) -> dict:
        return {
            "raw_bytes": self.raw_bytes, "total_bytes": self.total_bytes,
            "total_packets": self.total_packets, "decrypted_packets": self.decrypted_packets,
            "scrambled_packets": self.scrambled_packets, "sync_losses": self.sync_losses,
            "programs": dict(self.programs), "pmt_pids": sorted(self.pmt_pids),
            "encrypted_pids": sorted(self.encrypted_pids), "decrypt_mode": self.decrypt_mode,
        }

    def _ack(self, timeout_ms=1000) -> bytes:
        try:
            return bytes(self.client.get_ack(timeout_ms))
        except OSError as error:
            if isinstance(error, TimeoutError) or getattr(error, "winerror", None) == 121:
                return b""
            raise

    def _state(self) -> int:
        value = bytes(self.client.reg_read(0x82008, 2))
        if len(value) != 2:
            raise RuntimeError("Short device-state register read")
        return int.from_bytes(value, "big")

    def load_firmware(self, path):
        data = Path(path).read_bytes() if isinstance(path, (str, Path)) else bytes(path)
        if not data.startswith(b"MB8AC018"):
            raise ValueError("Invalid TRC firmware header")
        if self.running:
            raise RuntimeError("Stop reception before loading TRC firmware")
        LOG.info("Clearing TRC parameters and uploading %d bytes", len(data))
        for reg in range(0x1000, 0x1500, 2):
            self.client.reg_write(reg, b"\0\0")
        for reg, high, low in TRC_PARAMS:
            self.client.reg_write(reg, bytes((high, low)))
        self.client.api_command(bytes((0, 0, 4, 0, 0, 0)))
        self._ack()
        self.client.upload_firmware(data)
        time.sleep(0.001)
        self.client.api_command(bytes((0, 0, 4, 0x20, 0, 0)))
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            self._ack(500)
            state = self._state()
            if state == 1:
                self.firmware_loaded = True
                LOG.info("TRC firmware active")
                return
        raise RuntimeError(f"TRC activation did not reach state 0001 (state={state:04x})")

    def _state_description(self):
        try:
            return f"{self._state():04x}"
        except Exception as error:
            return f"unavailable ({error})"

    def _start_error(self, reason):
        return StreamProtocolError(f"{reason}; device state={self._state_description()}")

    def _wait_start_message(self, *, acceptance, timeout_ms):
        deadline = time.monotonic() + timeout_ms / 1000
        # Original GetAckMsg polls up to50 times at15ms intervals. A20ms
        # endpoint timeout gives a comparable finite budget on Windows.
        for _ in range(50):
            remaining_ms = int((deadline - time.monotonic()) * 1000)
            if remaining_ms <= 0:
                break
            ack = self._ack(min(20, remaining_ms))
            if len(ack) >= 6 and ack[0] == 0x10 and ack[4] == 0x05:
                if ack[5] == 0x80:
                    raise self._start_error("START rejected by device (command05 ACK status=0x80)")
                if acceptance:
                    return
            if ack and ack[0] == 0x20:
                self.client.reg_write(0x90074, b"\x07\xfc")
                if not acceptance:
                    return
        stage = "matching command05 acceptance ACK" if acceptance else "separate state-change notification0x20"
        raise self._start_error(f"START did not receive {stage} within {timeout_ms}ms")

    def start(self, timeout_ms=1000):
        if self.running:
            return
        if not isinstance(timeout_ms, int) or isinstance(timeout_ms, bool) or timeout_ms <= 0:
            raise ValueError("START timeout must be a positive integer in milliseconds")
        self.client.clear_halt(0x81)
        self.client.api_command(bytes((0, 0, 5, 0, 0, 2)))
        # Original GVTunerService.start (VA0x1000A70D0) verifies command05
        # acceptance and a subsequent, separate state-change message before
        # starting EP1 reads. RF/PAT waits must not hide a rejected START.
        self._wait_start_message(acceptance=True, timeout_ms=timeout_ms)
        self._wait_start_message(acceptance=False, timeout_ms=timeout_ms)
        LOG.info("START command accepted; device state=%s", self._state_description())
        self._reset_stream()
        self.running = True

    def _parse_tables(self, packet):
        pid = ((packet[1] & 31) << 8) | packet[2]
        assembler = self._psi.get(pid)
        if assembler is None:
            return
        for section in assembler.feed(packet):
            if not section[5] & 1:
                continue  # next table, not current table
            if pid == 0 and section[0] == 0 and len(section) >= 12:
                for i in range(8, len(section) - 4, 4):
                    if i + 4 > len(section) - 4:
                        break
                    program = int.from_bytes(section[i:i + 2], "big")
                    pmt_pid = ((section[i + 2] & 31) << 8) | section[i + 3]
                    if program:
                        self.programs[program] = pmt_pid
                        self.pmt_pids.add(pmt_pid)
                        self._psi.setdefault(pmt_pid, _PSIAssembler())
            elif pid in self.pmt_pids and section[0] == 2 and len(section) >= 16:
                program = int.from_bytes(section[3:5], "big")
                info_length = ((section[10] & 15) << 8) | section[11]
                offset = 12 + info_length
                streams = set()
                valid = offset <= len(section) - 4
                while valid and offset + 5 <= len(section) - 4:
                    kind = section[offset]
                    es_pid = ((section[offset + 1] & 31) << 8) | section[offset + 2]
                    es_length = ((section[offset + 3] & 15) << 8) | section[offset + 4]
                    if offset + 5 + es_length > len(section) - 4:
                        valid = False
                        break
                    if kind in AV_STREAM_TYPES:
                        streams.add(es_pid)
                    offset += 5 + es_length
                if valid:
                    self._program_es[program] = streams
                    self.encrypted_pids = set().union(*self._program_es.values())

    def _decrypt_packet(self, packet: bytes) -> bytes:
        offset = payload_offset(packet)
        sc = (packet[3] >> 6) & 3
        if sc:
            self.scrambled_packets += 1
        pid = ((packet[1] & 31) << 8) | packet[2]
        if offset is None or pid not in self.encrypted_pids or self.decrypt_mode == "none":
            return packet
        payload = packet[offset:]
        should_decrypt = bool(sc) or self.decrypt_mode == "pmt"
        decrypted = None
        if self.decrypt_mode == "auto" and not sc:
            if packet[1] & 0x40:
                if payload.startswith(b"\0\0\1"):
                    self._pid_modes[pid] = False
                else:
                    candidate = decrypt_payload(payload, self.contents_key)
                    if candidate.startswith(b"\0\0\1"):
                        self._pid_modes[pid] = True
                        decrypted = candidate
            should_decrypt = self._pid_modes.get(pid, False)
        if not should_decrypt:
            return packet
        if decrypted is None:
            decrypted = decrypt_payload(payload, self.contents_key)
        result = bytearray(packet[:offset] + decrypted)
        result[3] &= 0x3F
        self.decrypted_packets += 1
        return bytes(result)

    def feed(self, raw: bytes) -> bytes:
        """Synchronize, parse and decrypt bytes received from USB."""
        self.raw_bytes += len(raw)
        self._buffer.extend(raw)
        output = bytearray()
        offset = 0
        size = len(self._buffer)
        while size - offset >= 188:
            if self._buffer[offset] != 0x47:
                offset += 1
                self.sync_losses += 1
                self._synced = False
                continue
            if not self._synced:
                if size - offset < 189:
                    break
                if self._buffer[offset + 188] != 0x47:
                    offset += 1
                    self.sync_losses += 1
                    continue
                self._synced = True
            packet = bytes(self._buffer[offset:offset + 188])
            self._parse_tables(packet)
            output.extend(self._decrypt_packet(packet))
            self.total_packets += 1
            offset += 188
        if offset:
            del self._buffer[:offset]
        self.total_bytes += len(output)
        return bytes(output)

    def read_packets(self) -> bytes:
        if not self.running:
            raise RuntimeError("Stream has not been started")
        return self.feed(bytes(self.client.bulk_read(4096, timeout_ms=3000)))

    @classmethod
    def recover(cls, client, state=None):
        """Finish TRC STOP; return standby0001 or IDLE0011 after the handshake.

        Raw0001 is TRC standby, 0002 is active reception and 0004 is the
        intermediate STOP state. Standby requires no repeated STOP commands.
        """
        return _StopSequence(client).run(state)

    def stop(self, force=False, state=None):
        """Deactivate streaming into TRC standby/IDLE with bounded drains."""
        if not force and not self.running and not self.firmware_loaded:
            return
        self.running = False
        result = self.recover(self.client, state)
        self.firmware_loaded = False
        return result
