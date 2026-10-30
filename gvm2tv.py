# SPDX-License-Identifier: MIT
"""Minimal Windows GV-M2TV channel scanner and binary TS receiver."""
import argparse
import json
import logging
import math
import os
from pathlib import Path
import sys
import time

from winusb import Client
from secure import SecureAuth, BCAS
from tuner import Tuner
from stream import StreamEngine

LOG = logging.getLogger('gvm2tv')
FW = Path(os.environ.get('GVM2TV_FIRMWARE_DIR', str(Path(__file__).resolve().parent / 'firmware'))).expanduser()

def enter_idle(client):
    """Original shutdown's separate TRC-standby -> IDLE transition."""
    client.api_command(bytes([0, 0, 1, 0, 0, 0]))
    accepted = changed = False
    for _ in range(20):
        ack = client.get_ack(500)
        if len(ack) >= 6 and ack[0] == 0x10 and ack[4] == 1:
            if ack[5] == 0x80:
                raise RuntimeError('Device rejected transition to IDLE')
            accepted = True
        elif ack and ack[0] == 0x20 and accepted:
            changed = True
            break
    if not accepted or not changed:
        raise TimeoutError('Device did not acknowledge transition to IDLE')
    client.reg_write(0x90074, b'\x00\x04')
    for _ in range(10):
        state = client.read_state()
        if state == 0x11:
            return state
        time.sleep(.1)
    raise RuntimeError(f'Device did not enter IDLE: {state:04x}')

def initialize(client, firmware, bcas=True):
    state = client.read_state()
    LOG.info('Device state: %04x', state)
    if state == 0xFFFF:
        # Original m2TV bootup uses forceResetX only for this error state.
        # Unlike command 0f this keeps USB configured and restores SECURE.
        LOG.info('Recovering expired device authentication with original command 03')
        client.api_command(bytes([0, 0, 3, 0, 0, 0]))
        accepted = changed = False
        for _ in range(10):
            ack = client.get_ack(500)
            if not ack:
                continue
            if ack[0] == 0x20:
                changed = True
            if len(ack) >= 6 and ack[0] == 0x10 and ack[4] == 3:
                if ack[5] == 0x80:
                    raise RuntimeError('Device rejected authentication recovery')
                accepted = True
            if accepted and changed:
                break
        if not accepted or not changed:
            raise TimeoutError('Device did not acknowledge authentication recovery')
        time.sleep(.01)
        state = client.read_state()
        LOG.info('Recovered device state: %04x', state)
    if state == 1:
        state = enter_idle(client)
    elif state in (2, 4):
        state = StreamEngine.recover(client, state)
        if state == 1:
            state = enter_idle(client)
    if state == 0x11:
        LOG.info('Sleeping previous firmware session before fresh authentication')
        client.api_command(bytes([0, 0, 2, 1, 0, 0]))
        for _ in range(20):
            client.get_ack(500)
            state = client.read_state()
            if state == 0x12:
                break
        if state != 0x12:
            raise RuntimeError(f'Device sleep did not reach 0012: {state:04x}')
        time.sleep(.05)
    if state == 0x12:
        LOG.info('Waking device into SECURE state')
        client.api_command(bytes([0, 0, 2, 0, 0, 0]))
        for _ in range(20):
            client.get_ack(500)
            state = client.read_state()
            if state == 0x10:
                break
        if state != 0x10:
            raise RuntimeError(f'Device wake did not reach 0010: {state:04x}')
    if state == 0:
        state = client.boot((firmware / 'mb86h57_h58_aac_idle.bin').read_bytes())
        LOG.info('Firmware boot state: %04x', state)
    if state not in (0x10, 0x11):
        raise RuntimeError(f'Unexpected state {state:04x}; disconnect/reconnect tuner USB before retrying')
    auth = SecureAuth(client)
    auth.authenticate()
    client.secure_auth = auth
    LOG.info('Device authentication completed')
    client.api_command(bytes([0, 0, 1, 0, 0, 0]))
    for _ in range(30):
        ack = client.get_ack(500)
        if ack and ack[0] == 0x20:
            break
    client.reg_write(0x90074, b'\x00\x04')
    for _ in range(10):
        state = client.read_state()
        if state == 0x11:
            break
        time.sleep(.2)
    if state != 0x11:
        raise RuntimeError(f'IDLE command did not reach state 0011: {state:04x}')
    LOG.info('Device reached IDLE')
    if not bcas:
        return None
    contents_key = BCAS(client, auth).initialize()
    LOG.info('Inserted B-CAS initialized; device stream key obtained')
    return contents_key

def init_tuner(client):
    client.reg_write(0x90014, b'\x02\xf4')
    client.reg_write(0x90018, b'\x03\xff')
    tuner = Tuner(client)
    tuner.initialize()
    return tuner


def channel_number(value):
    try:
        number = int(value)
        if 13 <= number <= 52:
            return number
    except ValueError:
        pass
    raise argparse.ArgumentTypeError('Physical channel must be 13-52')


def channel_list(value):
    channels = []
    for part in value.split(','):
        bounds = part.strip().split('-')
        if len(bounds) == 1:
            channels.append(channel_number(bounds[0]))
        elif len(bounds) == 2:
            first, last = map(channel_number, bounds)
            if first > last:
                raise argparse.ArgumentTypeError('Channel range must be ascending')
            channels.extend(range(first, last + 1))
        else:
            raise argparse.ArgumentTypeError('Use 13-52 or 21,24,25')
    return list(dict.fromkeys(channels))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='action', required=True)
    scan = commands.add_parser('scan', help='Scan physical channels; JSON lines to stdout')
    scan.add_argument('--channels', type=channel_list, default='13-52')
    receive = commands.add_parser('stream', help='Receive binary MPEG-TS to a file or stdout')
    receive.add_argument('--channel', type=channel_number, required=True)
    receive.add_argument('--output', default='-', help='TS file path, or - for binary stdout (default)')
    receive.add_argument('--seconds', type=float, default=0, help='Duration; 0 runs until Ctrl+C')
    for command in (scan, receive):
        command.add_argument('--firmware', type=Path, default=FW, help='Directory containing the firmware files')
    args = parser.parse_args()
    if args.action == 'stream' and (not math.isfinite(args.seconds) or args.seconds < 0):
        parser.error('--seconds must be a finite non-negative number')
    names = ['mb86h57_h58_aac_idle.bin']
    if args.action == 'stream':
        names.append('mb86h57_h58_aac_trc.bin')
    for name in names:
        if not (args.firmware / name).is_file():
            parser.error(f'Missing firmware: {args.firmware / name}; see README.md')

    # stdout belongs exclusively to scan JSON or binary TS.
    logging.basicConfig(level=logging.INFO, format='%(levelname)s %(message)s', stream=sys.stderr)
    client = Client()
    engine = output = None
    result = 1
    try:
        client.connect()
        contents_key = initialize(client, args.firmware, bcas=args.action == 'stream')
        auth = client.secure_auth
        auth.keepalive()
        last_certificate = time.monotonic()

        def keepalive():
            nonlocal last_certificate
            if time.monotonic() - last_certificate >= 15:
                auth.keepalive()
                last_certificate = time.monotonic()

        tuner = init_tuner(client)
        if args.action == 'scan':
            found = False
            for channel in args.channels:
                keepalive()
                locked = tuner.tune(channel)
                found |= locked
                print(json.dumps({'channel': channel, 'locked': locked,
                                  'strength': tuner.signal_strength()}), flush=True)
            result = 0 if found else 2
        else:
            if not tuner.tune(args.channel):
                raise RuntimeError(f'No signal lock on physical CH{args.channel}')
            engine = StreamEngine(client, contents_key)
            engine.load_firmware(args.firmware / names[1])
            engine.start()
            if args.output == '-':
                import msvcrt
                msvcrt.setmode(sys.stdout.fileno(), os.O_BINARY)
                # A separate unbuffered descriptor leaves no buffered TS to
                # flush again if a downstream process closes its pipe.
                output = os.fdopen(os.dup(sys.stdout.fileno()), 'wb', buffering=0)
            else:
                output = open(args.output, 'wb')
            started = time.monotonic()
            while not args.seconds or time.monotonic() - started < args.seconds:
                keepalive()
                try:
                    data = engine.read_packets()
                except OSError as error:
                    if getattr(error, 'winerror', None) != 121:
                        raise
                    LOG.warning('Waiting for reception')
                    continue
                if data:
                    output.write(data)
            result = 0 if engine.programs and engine.total_packets else 2
            if result:
                LOG.error('No program information (PAT) received')
    except KeyboardInterrupt:
        result = 130
    except BrokenPipeError:
        result = 0
    except Exception as error:
        LOG.error('%s', error)
    finally:
        if output is not None:
            try:
                output.close()
            except OSError as error:
                LOG.error('Output close failed: %s', error)
                result = 1
        if engine is not None:
            try:
                engine.stop()
            except Exception as error:
                LOG.error('STOP failed: %s', error)
                result = 1
        auth = getattr(client, 'secure_auth', None)
        if auth is not None:
            try:
                state = client.read_state()
                if state in (2, 4):
                    state = StreamEngine.recover(client, state)
                if state == 1:
                    enter_idle(client)
                if args.action == 'stream':
                    auth.release_secure_ep(missing_ok=True)
            except Exception as error:
                LOG.error('Session cleanup failed: %s', error)
                result = 1
        client.close()
    return result


if __name__ == '__main__':
    sys.exit(main())
