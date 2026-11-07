import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
globalThis.self = globalThis;
const { NativeClient } = await import('../hardened/native.js');
const { selectCredentials } = await import('../hardened/policy.js');

function transport(_host, request) {
  return new Promise((resolve,reject) => {
    const child = spawn(process.execPath, [fileURLToPath(new URL('./fixtures/native-host.mjs',import.meta.url))], {stdio:['pipe','pipe','pipe']});
    const chunks=[];let size=0,settled=false;
    const timeout=setTimeout(()=>finish(new Error('Fixture timeout')),3000);
    function finish(error,value) {
      if(settled)return;settled=true;clearTimeout(timeout);child.kill();
      if(error)reject(error);else resolve(value);
    }
    child.on('error',error=>finish(error));
    child.stdout.on('data',chunk=>{
      chunks.push(chunk);size+=chunk.length;
      if(size>1048576)return finish(new Error('Oversize fixture'));
      const bytes=Buffer.concat(chunks);
      if(bytes.length>=4&&bytes.length>=bytes.readUInt32LE(0)+4){
        try{finish(null,JSON.parse(bytes.subarray(4,bytes.readUInt32LE(0)+4).toString('utf8')));}catch(error){finish(error);}
      }
    });
    child.on('exit',code=>{if(!settled)finish(new Error(`Fixture exited ${code}`));});
    const body=Buffer.from(JSON.stringify(request));const header=Buffer.alloc(4);header.writeUInt32LE(body.length);
    child.stdin.end(Buffer.concat([header,body]));
  });
}

test('native adapter exchanges real framed/encrypted messages with a separate synthetic host process',async()=>{
  const client=new NativeClient(transport);
  assert.equal((await client.status()).serverVersionInfo,'Synthetic fixture 1');
  const result=await client.credentialsForUrl('http://127.0.0.1:57839');
  assert.equal(result.results.length,1);
  assert.equal(result.results[0].password,'SYNTHETIC-TEST-PASSWORD');
  assert.equal('totp' in result.results[0],false);
  assert.equal('notes' in result.results[0],false);
  assert.equal('customFields' in result.results[0],false);
  const google = await client.credentialsForUrl('https://accounts.google.com');
  assert.equal(google.results[0].url, 'https://google.com');
  assert.equal(selectCredentials(google, {origin:'https://accounts.google.com'}).length, 1);
  const search = await client.search('Archive');
  assert.equal(search.results[0].title, 'Archive Portal');
  assert.equal(search.results[0].url, 'https://old.example.invalid');
  client.clear();
});
