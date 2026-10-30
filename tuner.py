# SPDX-License-Identifier: MIT
"""MJ111 ISDB-T control ported from wanimochi-tv's TunerController.swift.

Original software Copyright (c) 2026 sh1ma, MIT License.
Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:
The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""

import logging
import time

LOG = logging.getLogger(__name__)

TUNER_SW_RESET = ((0xFE, 0xC0, 0xFF),)
DEMOD_INIT = (
    (0x03, 0x80), (0x09, 0x10), (0x11, 0x26), (0x12, 0x0C),
    (0x13, 0x2B), (0x14, 0x40), (0x16, 0x00), (0x1C, 0x2A),
    (0x1D, 0xA0), (0x1E, 0xA8), (0x1F, 0xA8), (0x30, 0x00),
    (0x31, 0x0D), (0x32, 0x79), (0x34, 0x0F), (0x38, 0x00),
    (0x39, 0x94), (0x3A, 0x20), (0x3B, 0x21), (0x3C, 0x3F),
    (0x71, 0x00), (0x75, 0x28), (0x76, 0x0C), (0x77, 0x01),
    (0x7D, 0x80), (0xEF, 0x01),
)
TUNER_INIT = (
    (0xFE, 0xC0, 0x00, 0x3F, 0x02, 0x00, 0x03, 0x48,
     0x04, 0x00, 0x05, 0x04, 0x06, 0x10, 0x2E, 0x15,
     0x30, 0x10, 0x45, 0x58, 0x48, 0x19, 0x52, 0x03,
     0x53, 0x44, 0x6A, 0x4B, 0x76, 0x00, 0x78, 0x18,
     0x7A, 0x17, 0x85, 0x06),
    (0xFE, 0xC0, 0x01, 0x01),
)
DEMOD_WAKEUP = ((0x03, 0x80), (0x1C, 0x2A))
TUNER_WAKEUP = ((0xFE, 0xC0, 0x01, 0x01),)
AGC_STOP = ((0x25, 0x00), (0x23, 0x4D))
SEQUENCER_STOP = ((0xFE, 0xC0, 0x0F, 0x00),)
BANDWIDTH = ((0xFE, 0xC0, 0x0C, 0x15),)
DEFAULT_SETTING_1 = ((0xFE, 0xC0, 0x1F, 0x87, 0x20, 0x1F,
                      0x21, 0x87, 0x22, 0x1F),)
SEQUENCER_START = ((0xFE, 0xC0, 0x0F, 0x01),)
SYNC_SEQUENCER_START = ((0x01, 0x40),)
AGC_START = ((0x23, 0x4C),)
TS_ENABLE = ((0x1E, 0x80), (0x1F, 0x08))
TS_DISABLE = ((0x1E, 0xA8), (0x1F, 0xA8))
TUNER_SLEEP = ((0xFE, 0xC0, 0x0F, 0x00, 0x01, 0x00),)
DEMOD_SLEEP = ((0x1E, 0xA8), (0x1F, 0xA8), (0x1C, 0xAA), (0x03, 0xF0))

SIGNAL_TABLE = (
    22, 23, 24, 25, 26, 27, 28, 29, 31, 32, 33, 35, 36, 38, 40, 42,
    44, 46, 48, 50, 53, 56, 59, 62, 65, 69, 72, 77, 81, 86, 91, 97,
    103, 109, 116, 124, 132, 142, 152, 163, 175, 188, 203, 219, 237,
    257, 280, 305, 333, 364, 400, 440, 486, 539, 599, 668, 748, 840,
    949, 1076, 1226, 1404, 1616, 1871, 2179, 2553, 3010, 3572, 4268,
    5133, 6215, 7574, 9288, 11456, 14205, 17697, 22134, 27774, 34938,
    44027, 55546, 70126, 88557, 111834, 141220, 178318, 225192, 284517,
    359803, 455723, 578602, 737185, 943867, 1216799, 1583680, 2089200,
    2811329, 3903296, 5735416, 9778432,
)


class Tuner:
    """Control an MJ111 through a client's I2C proxy methods."""

    def __init__(self, client):
        self.client = client
        self.last_channel = None
        self.last_lock_registers = None

    def _write_table(self, table):
        for entry in table:
            self.client.i2c_write(bytes(entry))

    def initialize(self):
        self._write_table(TUNER_SW_RESET)
        time.sleep(0.05)
        self._write_table(DEMOD_INIT)
        value = self.client.i2c_read(0x03, 1)[0]
        LOG.info("MJ111 register 03=%02x (expected 80)", value)
        if value != 0x80:
            LOG.warning("MJ111 I2C readback mismatch: register 03=%02x", value)
        self._write_table(TUNER_INIT)

    def tune(self, channel):
        if isinstance(channel, bool) or not isinstance(channel, int) or not 13 <= channel <= 62:
            raise ValueError("Physical channel must be an integer from 13 to 62")
        freq_khz = channel * 6000 + 395143
        divider = (freq_khz * 64 + 500) // 1000
        LOG.info("Tuning physical CH%d: %d kHz, PLL=%04x", channel, freq_khz, divider)
        self._write_table(DEMOD_WAKEUP)
        self._write_table(TUNER_WAKEUP)
        self.client.api_command(bytes((0, 0, 0x05, 0, 0, 0)))
        self.client.get_ack(500)
        self._write_table(AGC_STOP)
        self._write_table(SEQUENCER_STOP)
        self._write_table(BANDWIDTH)
        self.client.i2c_write(bytes((0xFE, 0xC0, 0x0D, divider & 0xFF,
                                     0x0E, (divider >> 8) & 0xFF)))
        self._write_table(DEFAULT_SETTING_1)
        threshold = 0x01 if freq_khz < 333000 else 0x41
        self.client.i2c_write(bytes((0xFE, 0xC0, 0x80, threshold)))
        self._write_table(SEQUENCER_START)
        self._write_table(SYNC_SEQUENCER_START)
        self._write_table(AGC_START)
        locked = False
        for attempt in range(20):
            time.sleep(0.1)
            if self.check_lock() == 0:
                locked = True
                LOG.info("CH%d locked after %d ms", channel, (attempt + 1) * 100)
                break
        self.last_channel = channel
        LOG.info("CH%d locked=%s strength=%d/100 registers=%s", channel, locked,
                 self.signal_strength(), self.last_lock_registers)
        self._write_table(TS_ENABLE)
        return locked

    def check_lock(self):
        """Return the original driver's status: 0=lock, 1=unlock, 2=pending/error.

        Recovered from m2TV 1.30 x86_64 _GetSignalLockStateTera_MJ111,
        VA 0x1000AE440. The Swift port accidentally treated bit 7 of register
        80 as a lock while the original returns 1 for that branch. Only the
        final register-96 test can return 0. This matters for absent channels,
        which report e.g. 80=af,b0=a0,96=00.
        """
        self.last_lock_registers = {"80": None, "b0": None, "96": None}

        def read(reg):
            response = self.client.i2c_read(reg, 1)
            if len(response) != 1:
                raise OSError(f"Short MJ111 register {reg:02x} read")
            value = response[0]
            self.last_lock_registers[f"{reg:02x}"] = value
            return value

        try:
            r80 = read(0x80)
            rb0 = read(0xB0)
        except OSError as error:
            self.last_lock_registers["error"] = str(error)
            LOG.debug("MJ111 lock-status read failed: %s", error)
            return 2

        if (r80 & 0x28) or (rb0 & 0x0F) <= 7:
            # Register 96 is not needed on this branch in the original driver.
            # Read it for scan diagnostics without changing the original result
            # if this optional read fails.
            result = 1 if r80 & 0x80 else 2
            try:
                read(0x96)
            except OSError as error:
                self.last_lock_registers["diagnostic_error"] = str(error)
            return result

        try:
            r96 = read(0x96)
        except OSError as error:
            self.last_lock_registers["error"] = str(error)
            LOG.debug("MJ111 lock-status read failed: %s", error)
            return 2
        return 0 if r96 & 0xE0 else 2

    def signal_strength(self):
        raw = ((self.client.i2c_read(0x8B, 1)[0] << 16)
               | (self.client.i2c_read(0x8C, 1)[0] << 8)
               | self.client.i2c_read(0x8D, 1)[0])
        if raw == 0:
            return 0
        for index, threshold in enumerate(SIGNAL_TABLE):
            if raw < threshold:
                return 100 - index
        return 0

    def stop_ts(self):
        """Disable only TS output, as original m2TV's STOP handshake requires.

        _StopTunerTSTera_MJ111 (VA0x1000AE400) sends only the two entries of
        table0x1004ADAC0. Sleeping the RF tuner/demodulator here changes the
        original STOP lifecycle and can prevent the next channel receiving TS.
        """
        self._write_table(TS_DISABLE)

    def sleep(self):
        self._write_table(TS_DISABLE)
        self._write_table(TUNER_SLEEP)
        self._write_table(DEMOD_SLEEP)
