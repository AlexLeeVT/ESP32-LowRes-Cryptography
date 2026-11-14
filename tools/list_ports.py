#!/usr/bin/env python3
import os
import subprocess
from pathlib import Path

from serial.tools import list_ports

if __name__ == "__main__":
    # get available ports
    for port in list_ports.comports():
        if (port.vid == 0x303A) or ("espressif" in (port.manufacturer or "").lower()):
            print(port.device)