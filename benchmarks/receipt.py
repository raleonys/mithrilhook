# SPDX-License-Identifier: GPL-3.0-only
import hashlib,json,sys
from pathlib import Path
exe,source,inputs,compiler,bits=sys.argv[1:]
p=Path(exe)
p.with_suffix('.receipt.json').write_text(json.dumps({'schema':'mithrilhook.benchmark-build.v1','exe_sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'source_digest':source,'input_digest':inputs,'compiler':compiler,'bits':int(bits),'configuration':'Release','optimization':'/O2 /Ob2; LTO off; /MT'},indent=2)+'\n')
