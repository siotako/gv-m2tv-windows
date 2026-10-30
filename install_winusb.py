# SPDX-License-Identifier: MIT
"""Assign the Microsoft inbox WinUSB driver to ONLY the attached GV-M2TV.

No downloaded driver, custom certificate, or signature enforcement changes.
Default mode only lists the available driver. --install requires elevation.
Based on Microsoft's WinUSB installation and SetupAPI documentation.
"""
import argparse
import ctypes as C
from ctypes import wintypes as W
import json
from pathlib import Path
import subprocess
import sys
import winreg
import os

USB_KEY = r'SYSTEM\CurrentControlSet\Enum\USB\VID_04BB&PID_053A'
INTERFACE_GUID = '{08B4C4A8-1254-4C5A-99F3-EE2D0E660D48}'

class GUID(C.Structure):
    _fields_ = [('a', W.DWORD), ('b', W.WORD), ('c', W.WORD), ('d', C.c_ubyte * 8)]

class DeviceInfo(C.Structure):
    _fields_ = [('cbSize', W.DWORD), ('ClassGuid', GUID), ('DevInst', W.DWORD), ('Reserved', C.c_void_p)]

class InstallParams(C.Structure):
    _fields_ = [('cbSize', W.DWORD), ('Flags', W.DWORD), ('FlagsEx', W.DWORD),
                ('hwndParent', C.c_void_p), ('InstallMsgHandler', C.c_void_p),
                ('InstallMsgHandlerContext', C.c_void_p), ('FileQueue', C.c_void_p),
                ('ClassInstallReserved', C.c_void_p), ('Reserved', W.DWORD), ('DriverPath', W.WCHAR * 260)]

class DriverInfo(C.Structure):
    _fields_ = [('cbSize', W.DWORD), ('DriverType', W.DWORD), ('Reserved', C.c_void_p),
                ('Description', W.WCHAR * 256), ('MfgName', W.WCHAR * 256),
                ('ProviderName', W.WCHAR * 256), ('DriverDate', W.FILETIME), ('DriverVersion', C.c_uint64)]

api = C.WinDLL('setupapi', use_last_error=True)
newdev = C.WinDLL('newdev', use_last_error=True)
api.SetupDiCreateDeviceInfoList.argtypes = [C.c_void_p, C.c_void_p]
api.SetupDiCreateDeviceInfoList.restype = C.c_void_p
api.SetupDiOpenDeviceInfoW.argtypes = [C.c_void_p, W.LPCWSTR, C.c_void_p, W.DWORD, C.POINTER(DeviceInfo)]
api.SetupDiGetDeviceInstallParamsW.argtypes = [C.c_void_p, C.POINTER(DeviceInfo), C.POINTER(InstallParams)]
api.SetupDiSetDeviceInstallParamsW.argtypes = [C.c_void_p, C.POINTER(DeviceInfo), C.POINTER(InstallParams)]
api.SetupDiBuildDriverInfoList.argtypes = [C.c_void_p, C.POINTER(DeviceInfo), W.DWORD]
api.SetupDiEnumDriverInfoW.argtypes = [C.c_void_p, C.POINTER(DeviceInfo), W.DWORD, W.DWORD, C.POINTER(DriverInfo)]
api.SetupDiDestroyDeviceInfoList.argtypes = [C.c_void_p]
newdev.DiInstallDevice.argtypes = [C.c_void_p, C.c_void_p, C.POINTER(DeviceInfo), C.POINTER(DriverInfo), W.DWORD, C.POINTER(W.BOOL)]
cfg = C.WinDLL('cfgmgr32')
cfg.CM_Get_DevNode_Status.argtypes = [C.POINTER(W.DWORD), C.POINTER(W.DWORD), W.DWORD, W.DWORD]

def check(ok, operation):
    if not ok:
        raise C.WinError(C.get_last_error(), operation)

def instances():
    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, USB_KEY) as key:
        for i in range(winreg.QueryInfoKey(key)[0]):
            yield winreg.EnumKey(key, i)

def run(install=False):
    found = []
    for suffix in instances():
        instance = 'USB\\VID_04BB&PID_053A\\' + suffix
        dev = DeviceInfo(cbSize=C.sizeof(DeviceInfo))
        handle = api.SetupDiCreateDeviceInfoList(None, None)
        if handle == C.c_void_p(-1).value:
            raise C.WinError(C.get_last_error())
        try:
            if not api.SetupDiOpenDeviceInfoW(handle, instance, None, 0, C.byref(dev)):
                continue
            status, problem = W.DWORD(), W.DWORD()
            if cfg.CM_Get_DevNode_Status(C.byref(status), C.byref(problem), dev.DevInst, 0) != 0:
                continue  # Ignore disconnected historical device instances.
            # Only a present device can be installed by DiInstallDevice.
            params = InstallParams(cbSize=C.sizeof(InstallParams))
            check(api.SetupDiGetDeviceInstallParamsW(handle, C.byref(dev), C.byref(params)), 'Get install params')
            params.Flags |= 0x00010000 | 0x00800000  # DI_ENUMSINGLEINF | DI_QUIETINSTALL
            params.FlagsEx |= 0x00000800  # DI_FLAGSEX_ALLOWEXCLUDEDDRVS
            params.DriverPath = str(Path(os.environ['SystemRoot']) / 'INF' / 'winusb.inf')
            check(api.SetupDiSetDeviceInstallParamsW(handle, C.byref(dev), C.byref(params)), 'Set install params')
            check(api.SetupDiBuildDriverInfoList(handle, C.byref(dev), 1), 'Build class driver list')
            selected = None
            for index in range(20):
                info = DriverInfo(cbSize=C.sizeof(DriverInfo))
                if not api.SetupDiEnumDriverInfoW(handle, C.byref(dev), 1, index, C.byref(info)):
                    if C.get_last_error() == 259:
                        break
                    raise C.WinError(C.get_last_error())
                print(json.dumps({'instance': instance, 'driver': info.Description, 'provider': info.ProviderName}))
                if info.Description.casefold() == 'winusb device':
                    selected = info
            if selected is None:
                raise RuntimeError('Microsoft inbox WinUsb Device model was not found')
            found.append(instance)
            if not install:
                continue
            if not C.windll.shell32.IsUserAnAdmin():
                raise PermissionError('Driver assignment requires an administrator process')
            keypath = USB_KEY + '\\' + suffix
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, keypath) as key:
                try:
                    service = winreg.QueryValueEx(key, 'Service')[0]
                except FileNotFoundError:
                    service = ''
            if service and service.casefold() != 'winusb':
                raise RuntimeError('Refusing to replace an existing driver: ' + service)
            with winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE, keypath + '\\Device Parameters', 0, winreg.KEY_READ | winreg.KEY_WRITE) as key:
                try:
                    guids = winreg.QueryValueEx(key, 'DeviceInterfaceGUIDs')[0]
                except FileNotFoundError:
                    guids = []
                if not isinstance(guids, list):
                    guids = [guids]
                if INTERFACE_GUID.casefold() not in [g.casefold() for g in guids]:
                    winreg.SetValueEx(key, 'DeviceInterfaceGUIDs', 0, winreg.REG_MULTI_SZ, guids + [INTERFACE_GUID])
            reboot = W.BOOL()
            check(newdev.DiInstallDevice(None, handle, C.byref(dev), C.byref(selected), 0, C.byref(reboot)), 'DiInstallDevice WinUSB')
            print(json.dumps({'installed': instance, 'reboot_required': bool(reboot.value), 'interface_guid': INTERFACE_GUID}))
            subprocess.run(['pnputil.exe', '/restart-device', instance], check=True)
        finally:
            api.SetupDiDestroyDeviceInfoList(handle)
    if not found:
        raise RuntimeError('GV-M2TV was not found')

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--install', action='store_true')
    args = parser.parse_args()
    try:
        run(args.install)
    except Exception as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)
