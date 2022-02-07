# xyrella

`xyrella` is a simple XLL builder without any remote injection functionality (it can unhook NTDLL, though). I sincerely believe that it makes things easier when you separate your intial access method and your injection/EDR bypass technique.

The approach is briefly discussed in https://tishina.in/initial-access/xll-delivery

`xyrella` currently **only builds on Windows.**

# dependencies

`nim` should be reachable from $PATH. 
```
> nimble install nimcrypto ptr_math winim
> pip install pycryptodome
```

# usage
From the execution standpoint, `xyrella` is just [nim-fibers](https://tishina.in/execution/nim-fibers), compiled to a DLL. The usage is pretty straightforward:
```

                        _ _
                       | | |
 _   _ _   _  ____ ____| | | ____
( \ / ) | | |/ ___) _  ) | |/ _  |
 ) X (| |_| | |  ( (/ /| | ( ( | |
(_/ \_)\__  |_|   \____)_|_|\_||_|
      (____/       Nim XLL builder PoC v0.2.1

usage: build.py [-h] [-u STAGEURL] [-e] [-n] [-w] [-d DECOY] [-v] [-o OUTPUT] -s SHELLCODE

optional arguments:
  -h, --help            show this help message and exit

staging arguments:
  -u STAGEURL, --stageurl STAGEURL
                        URL to stage from (if staged, optional)

stageless arguments:
  -e, --encrypt         encrypt shellcode (aes128-cbc)

compilation arguments:
  -n, --skip-unhook     do not do NTDLL unhooking
  -w, --hidewindow      hide excel window during execution
  -d DECOY, --decoy DECOY
                        path to the decoy file to open on startup (optional)
  -v, --verbose         increase output verbosity
  -o OUTPUT, --output OUTPUT
                        path to store the resulting .XLL file (optional)

required arguments:
  -s SHELLCODE, --shellcode SHELLCODE
                        path to shellcode .bin (required)

```

