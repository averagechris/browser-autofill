#!/usr/bin/env python3
"""Register a single reviewed extension in Helium's standard native-host path."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import base64

p=argparse.ArgumentParser()
p.add_argument('--extension',type=Path,required=True)
p.add_argument('--fixture-launcher',type=Path)
p.add_argument('--helium-data',type=Path,default=Path.home()/'Library/Application Support/net.imput.helium')
args=p.parse_args()
m=json.loads((args.extension/'manifest.json').read_text())
key=base64.b64decode(m['key'],validate=True)
extension_id=''.join(chr(97+int(x,16)) for x in hashlib.sha256(key).hexdigest()[:32])
if args.fixture_launcher:
    if m['name']!='Strongbox Login TEST — synthetic only':raise SystemExit('Not the synthetic build')
    name='com.averagechris.strongbox_test';executable=args.fixture_launcher.resolve()
else:
    if m['name']!='Strongbox Login':raise SystemExit('Not the production build')
    name='com.markmcguill.strongbox';executable=Path('/Applications/Strongbox.app/Contents/MacOS/afproxy')
    subprocess.run(['/usr/bin/codesign','--verify','--strict',str(executable)],check=True,capture_output=True)
    info=subprocess.run(['/usr/bin/codesign','-dvv',str(executable)],check=True,capture_output=True,text=True)
    if 'TeamIdentifier=4326J8XDF2' not in info.stderr:raise SystemExit('Unexpected Strongbox signing team')
    st=executable.stat()
    if st.st_uid!=0 or st.st_mode&0o022:raise SystemExit('Strongbox helper must be root-owned and not group/world writable')
if not executable.is_file():raise SystemExit('Missing host executable')
manifest={'name':name,'description':'Taro Fill synthetic fixture' if args.fixture_launcher else 'Strongbox for reviewed Taro Fill','path':str(executable),'type':'stdio','allowed_origins':['chrome-extension://'+extension_id+'/']}
directory=args.helium_data/'NativeMessagingHosts'
directory.mkdir(mode=0o700,parents=True,exist_ok=True)
dest=directory/(name+'.json')
if dest.exists() and json.loads(dest.read_text())!=manifest:raise SystemExit('Existing native-host registration differs; refusing to overwrite '+str(dest))
dest.write_text(json.dumps(manifest,indent=2)+'\n');dest.chmod(0o600)
print(json.dumps({'manifest':str(dest),'extensionId':extension_id,'host':name},indent=2))
