#!/usr/bin/env python3
"""Deterministically package reviewed source. No npm install, scripts, or network."""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import shutil

ROOT = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser()
parser.add_argument('--out', type=Path, required=True)
parser.add_argument('--fixture', action='store_true')
args = parser.parse_args()
source = ROOT / 'hardened'
out = args.out.resolve()
if out == source or source in out.parents:
    raise SystemExit('Output must be outside hardened source')
if out.exists():
    raise SystemExit('Output already exists; choose a fresh build directory')
out.mkdir(parents=True)
files = ['background.js','domains.js','policy.js','native.js','popup.html','popup.css','popup.js','SECURITY.md','vendor/nacl-fast.js','vendor/LICENSE','vendor/PROVENANCE.json','vendor/public_suffix_list.dat','vendor/public-suffix-rules.js','vendor/PSL-LICENSE','vendor/PSL-PROVENANCE.json']
for name in files:
    destination = out / name
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source / name, destination)
shutil.copyfile(ROOT / 'LICENSE.md', out / 'LICENSE.md')
key = (source / 'keys' / ('fixture.der' if args.fixture else 'production.der')).read_bytes()
extension_id = ''.join(chr(97 + int(nibble,16)) for nibble in hashlib.sha256(key).hexdigest()[:32])
manifest = {
    'manifest_version':3,
    'name':'Strongbox Login TEST — synthetic only' if args.fixture else 'Strongbox Login',
    'version':'0.2.1',
    'description':'Explicit click-to-fill for Strongbox. No automatic filling or page-message bridge.',
    'key':base64.b64encode(key).decode(),
    'minimum_chrome_version':'106',
    'permissions':['activeTab','scripting','nativeMessaging'],
    'action':{'default_title':'Strongbox Login TEST' if args.fixture else 'Strongbox Login','default_popup':'popup.html'},
    'background':{'service_worker':'background.js','type':'module'},
    'content_security_policy':{'extension_pages':"script-src 'self'; object-src 'none'; base-uri 'none'; connect-src 'none'"}
}
(out / 'manifest.json').write_text(json.dumps(manifest,sort_keys=True,indent=2)+'\n')
host = 'com.averagechris.strongbox_test' if args.fixture else 'com.markmcguill.strongbox'
(out / 'config.js').write_text(f'export const NATIVE_HOST = {json.dumps(host)};\nexport const ALLOW_LOOPBACK = {str(args.fixture).lower()};\n')
hashes = {str(p.relative_to(out)):hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(out.rglob('*')) if p.is_file()}
(out / 'SHA256SUMS.json').write_text(json.dumps(hashes,sort_keys=True,indent=2)+'\n')
print(json.dumps({'directory':str(out),'extensionId':extension_id,'fixture':args.fixture,'files':len(hashes)},indent=2))
