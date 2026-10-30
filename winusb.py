# SPDX-License-Identifier: MIT
"""GV-M2TV userspace USB transport using Microsoft's inbox winusb.dll.

Protocol ported from wanimochi-tv (MIT; see LICENSE).
"""
import ctypes as C
from ctypes import wintypes as W
import threading
import time
import uuid
import winreg

DEVICE_KEY = r'SYSTEM\CurrentControlSet\Enum\USB\VID_04BB&PID_053A'
DEFAULT_GUID = '{08B4C4A8-1254-4C5A-99F3-EE2D0E660D48}'

class GUID(C.Structure):
    _fields_ = [('data', C.c_ubyte * 16)]
    def __init__(self, value):
        super().__init__()
        self.data[:] = uuid.UUID(value).bytes_le

class InterfaceData(C.Structure):
    _fields_ = [('cbSize', W.DWORD), ('InterfaceClassGuid', GUID), ('Flags', W.DWORD), ('Reserved', C.c_void_p)]

class SetupPacket(C.Structure):
    _pack_ = 1
    _fields_ = [('RequestType', C.c_ubyte), ('Request', C.c_ubyte), ('Value', W.WORD), ('Index', W.WORD), ('Length', W.WORD)]

class PipeInfo(C.Structure):
    _fields_ = [('PipeType', C.c_int), ('PipeId', C.c_ubyte), ('MaximumPacketSize', W.WORD), ('Interval', C.c_ubyte)]

api = C.WinDLL('setupapi', use_last_error=True)
usb = C.WinDLL('winusb', use_last_error=True)
kernel = C.WinDLL('kernel32', use_last_error=True)
api.SetupDiGetClassDevsW.argtypes = [C.POINTER(GUID), W.LPCWSTR, C.c_void_p, W.DWORD]
api.SetupDiGetClassDevsW.restype = C.c_void_p
api.SetupDiEnumDeviceInterfaces.argtypes = [C.c_void_p, C.c_void_p, C.POINTER(GUID), W.DWORD, C.POINTER(InterfaceData)]
api.SetupDiGetDeviceInterfaceDetailW.argtypes = [C.c_void_p, C.POINTER(InterfaceData), C.c_void_p, W.DWORD, C.POINTER(W.DWORD), C.c_void_p]
api.SetupDiDestroyDeviceInfoList.argtypes = [C.c_void_p]
kernel.CreateFileW.argtypes = [W.LPCWSTR, W.DWORD, W.DWORD, C.c_void_p, W.DWORD, W.DWORD, C.c_void_p]
kernel.CreateFileW.restype = C.c_void_p
kernel.CloseHandle.argtypes = [C.c_void_p]
usb.WinUsb_Initialize.argtypes = [C.c_void_p, C.POINTER(C.c_void_p)]
usb.WinUsb_Free.argtypes = [C.c_void_p]
usb.WinUsb_ControlTransfer.argtypes = [C.c_void_p, SetupPacket, C.c_void_p, W.DWORD, C.POINTER(W.DWORD), C.c_void_p]
usb.WinUsb_ReadPipe.argtypes = [C.c_void_p, C.c_ubyte, C.c_void_p, W.DWORD, C.POINTER(W.DWORD), C.c_void_p]
usb.WinUsb_WritePipe.argtypes = usb.WinUsb_ReadPipe.argtypes
usb.WinUsb_SetPipePolicy.argtypes = [C.c_void_p, C.c_ubyte, W.DWORD, W.DWORD, C.c_void_p]
usb.WinUsb_ResetPipe.argtypes = [C.c_void_p, C.c_ubyte]
usb.WinUsb_QueryPipe.argtypes = [C.c_void_p, C.c_ubyte, C.c_ubyte, C.POINTER(PipeInfo)]

def check(ok):
    if not ok:
        raise C.WinError(C.get_last_error())

def interface_guids():
    result = {DEFAULT_GUID}
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, DEVICE_KEY) as root:
            for i in range(winreg.QueryInfoKey(root)[0]):
                try:
                    with winreg.OpenKey(root, winreg.EnumKey(root, i) + '\\Device Parameters') as key:
                        value = winreg.QueryValueEx(key, 'DeviceInterfaceGUIDs')[0]
                        result.update(value if isinstance(value, list) else [value])
                except FileNotFoundError:
                    continue
    except FileNotFoundError:
        pass
    return result

def device_paths():
    result = set()
    for value in interface_guids():
        guid = GUID(value)
        handle = api.SetupDiGetClassDevsW(C.byref(guid), None, None, 0x12)
        if handle == C.c_void_p(-1).value:
            continue
        try:
            for index in range(100):
                info = InterfaceData()
                info.cbSize = C.sizeof(info)
                if not api.SetupDiEnumDeviceInterfaces(handle, None, C.byref(guid), index, C.byref(info)):
                    if C.get_last_error() == 259:
                        break
                    raise C.WinError(C.get_last_error())
                size = W.DWORD()
                api.SetupDiGetDeviceInterfaceDetailW(handle, C.byref(info), None, 0, C.byref(size), None)
                buffer = C.create_string_buffer(size.value)
                C.cast(buffer, C.POINTER(W.DWORD))[0] = 8 if C.sizeof(C.c_void_p) == 8 else 6
                check(api.SetupDiGetDeviceInterfaceDetailW(handle, C.byref(info), buffer, size, None, None))
                path = C.wstring_at(C.addressof(buffer) + 4)
                if 'vid_04bb&pid_053a' in path.casefold():
                    result.add(path)
        finally:
            api.SetupDiDestroyDeviceInfoList(handle)
    return sorted(result)

class Client:
    def __init__(self):
        self.file = None
        self.handle = C.c_void_p()
        self.seq = 0
        self.lock = threading.RLock()

    def connect(self):
        paths = device_paths()
        if not paths:
            raise RuntimeError('GV-M2TV WinUSB interface not found; run install_winusb.py --install as administrator')
        self.file = kernel.CreateFileW(paths[0], 0xC0000000, 3, None, 3, 0x40000000, None)
        if self.file == C.c_void_p(-1).value:
            self.file = None
            raise C.WinError(C.get_last_error())
        try:
            check(usb.WinUsb_Initialize(self.file, C.byref(self.handle)))
            for ep in [0x00] + [int(info['address'], 16) for info in self.endpoints()]:
                self.set_timeout(ep, 3000)
        except Exception:
            self.close()
            raise
        return self

    def endpoints(self):
        result = []
        for index in range(16):
            info = PipeInfo()
            if not usb.WinUsb_QueryPipe(self.handle, 0, index, C.byref(info)):
                break
            result.append({'address': hex(info.PipeId), 'type': info.PipeType, 'max_packet': info.MaximumPacketSize})
        return result

    def close(self):
        if self.handle.value:
            usb.WinUsb_Free(self.handle)
            self.handle = C.c_void_p()
        if self.file:
            kernel.CloseHandle(self.file)
            self.file = None

    def set_timeout(self, endpoint, timeout_ms):
        value = W.DWORD(timeout_ms)
        check(usb.WinUsb_SetPipePolicy(self.handle, endpoint, 3, C.sizeof(value), C.byref(value)))

    def control(self, request_type, request, value, index, data_or_length):
        reading = bool(request_type & 0x80)
        length = data_or_length if reading else len(data_or_length)
        buffer = C.create_string_buffer(length)
        if not reading:
            buffer.raw = bytes(data_or_length)
        transferred = W.DWORD()
        with self.lock:
            check(usb.WinUsb_ControlTransfer(self.handle, SetupPacket(request_type, request, value, index, length), buffer, length, C.byref(transferred), None))
        if transferred.value != length:
            raise IOError(f'Short USB control transfer {transferred.value}/{length}')
        return buffer.raw[:transferred.value]

    def reg_write(self, reg, data, addr=0):
        self.control(0x40, 0xBC, (addr & 255) | ((reg >> 8) & 0xF00), reg & 0xFFFF, bytes(data))

    def reg_read(self, reg, length, addr=0):
        return self.control(0xC0, 0xBC, (addr & 255) | ((reg >> 8) & 0xF00), reg & 0xFFFF, length)

    def api_command(self, command):
        command = bytearray(command)
        if len(command) != 6:
            raise ValueError('API command must contain six bytes')
        with self.lock:
            command[1] = self.seq
            self.seq = (self.seq + 1) % 0x3F
            self.control(0x40, 0xB8, 0, 0, command)

    def get_ack(self, timeout_ms=3000):
        try:
            return self.bulk_read(64, timeout_ms, endpoint=0x83)
        except OSError as error:
            if error.winerror == 121:
                return b''
            raise

    def i2c_write(self, data):
        with self.lock:
            self.control(0x40, 0xBD, 0, 0x1800, bytes(data))
            self.control(0xC0, 0xBD, 15, 0x1800, 2)

    def i2c_read(self, reg, length):
        with self.lock:
            self.i2c_write(bytes([reg]))
            result = self.control(0xC0, 0xBD, 0, 0x1800, length)
            self.control(0xC0, 0xBD, 15, 0x1800, 2)
            return result

    def bulk_write(self, data):
        data = bytes(data)
        buffer = C.create_string_buffer(data, len(data))
        transferred = W.DWORD()
        check(usb.WinUsb_WritePipe(self.handle, 0x02, buffer, len(data), C.byref(transferred), None))
        if transferred.value != len(data):
            raise IOError('Short bulk write')

    def bulk_read(self, length, timeout_ms=3000, endpoint=0x81):
        self.set_timeout(endpoint, timeout_ms)
        buffer = C.create_string_buffer(length)
        transferred = W.DWORD()
        check(usb.WinUsb_ReadPipe(self.handle, endpoint, buffer, length, C.byref(transferred), None))
        return buffer.raw[:transferred.value]

    def clear_halt(self, endpoint):
        check(usb.WinUsb_ResetPipe(self.handle, endpoint))

    def upload_firmware(self, data):
        if not data.startswith(b'MB8AC018'):
            raise ValueError('Invalid GV-M2TV firmware header')
        self.clear_halt(0x02)
        for offset in range(0, len(data), 512):
            self.bulk_write(data[offset:offset + 512])

    def secure_reg_write(self, base, data):
        for offset in range(0, len(data), 64):
            self.reg_write(base + offset, data[offset:offset + 64])

    def secure_reg_read(self, base, length):
        return b''.join(self.reg_read(base + offset, min(64, length - offset)) for offset in range(0, length, 64))

    bcas_reg_write = secure_reg_write
    bcas_reg_read = secure_reg_read

    def read_state(self):
        return int.from_bytes(self.reg_read(0x82008, 2), 'big')

    def boot(self, data):
        for _ in range(50):
            if self.reg_read(0x90074, 2)[1] & 4:
                break
            time.sleep(0.02)
        else:
            raise TimeoutError('Firmware IRQ was not ready')
        self.reg_write(0x90074, b'\x00\x04')
        self.upload_firmware(data)
        self.reg_write(0x90070, b'\x00\x04')
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            ack = self.get_ack(500)
            if ack and ack[0] == 0x20:
                break
        else:
            raise TimeoutError('Firmware did not send a state-change notification')
        time.sleep(.01)
        return self.read_state()
