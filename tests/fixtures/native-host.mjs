// Synthetic native messaging fixture. Never contacts Strongbox or a vault.
globalThis.self = globalThis;
await import('../../hardened/vendor/nacl-fast.js');
const nacl = globalThis.nacl;
const pair = nacl.box.keyPair.fromSecretKey(new Uint8Array(32).fill(7));
const encode = bytes => Buffer.from(bytes).toString('base64');
const decode = text => new Uint8Array(Buffer.from(text, 'base64'));
const ORIGIN = 'http://127.0.0.1:57839';
let pending = Buffer.alloc(0);
process.stdin.on('data', chunk => {
  pending = Buffer.concat([pending,chunk]);
  if (pending.length < 4) return;
  const length = pending.readUInt32LE(0);
  if (length > 65536) process.exit(1);
  if (pending.length < length + 4) return;
  try {
    const request = JSON.parse(pending.subarray(4,4+length).toString('utf8'));
    const publicKey = decode(request.clientPublicKey);
    if (publicKey.length !== 32) throw Error('key');
    let payload;
    if (request.messageType === 0) {
      payload = {serverVersionInfo:'Synthetic fixture 1',databases:[{uuid:'synthetic',nickName:'Synthetic only',locked:false,autoFillEnabled:true}],serverSettings:{}};
    } else if ([1, 2].includes(request.messageType)) {
      const nonce = decode(request.nonce);
      if (nonce.length !== 24) throw Error('nonce');
      const bytes = nacl.box.open(decode(request.message),nonce,publicKey,pair.secretKey);
      if (!bytes) throw Error('ciphertext');
      const query = JSON.parse(new TextDecoder().decode(bytes));
      if (request.messageType === 1) {
        if (typeof query.query !== 'string' || query.take !== 24 || ![0,24,48,72].includes(query.skip)) throw Error('search');
        payload = { results: query.skip === 0 && (!query.query || query.query.toLowerCase().includes('archive')) ? [{
          uuid: 'other-entry', databaseId: 'synthetic', title: 'Archive Portal',
          username: 'archive@example.invalid', password: 'SYNTHETIC-ARCHIVE', url: 'https://old.example.invalid',
        }] : [] };
      } else {
        const origin = new URL(query.url).origin;
        if (![ORIGIN, 'https://accounts.google.com'].includes(origin) || query.skip !== 0 || !Number.isInteger(query.take) || query.take < 1 || query.take > 100) throw Error('query');
        payload = {unlockedDatabaseCount:1,results:[{uuid:'synthetic-entry',databaseId:'synthetic',title:'Synthetic account',username:'synthetic@example.invalid',password:'SYNTHETIC-TEST-PASSWORD',url:origin === ORIGIN ? ORIGIN+'/login' : 'https://google.com',totp:'otpauth://totp/Synthetic?secret=JBSWY3DPEHPK3PXP',notes:'DO-NOT-DELIVER-NOTES',customFields:{recovery:'DO-NOT-DELIVER-RECOVERY'}}]};
      }
    } else throw Error('unsupported');
    const nonce = nacl.randomBytes(24);
    const message = nacl.box(new TextEncoder().encode(JSON.stringify(payload)),nonce,publicKey,pair.secretKey);
    const body = Buffer.from(JSON.stringify({success:true,serverPublicKey:encode(pair.publicKey),nonce:encode(nonce),message:encode(message)}));
    const header = Buffer.alloc(4); header.writeUInt32LE(body.length);
    process.stdout.write(Buffer.concat([header,body]));
  } catch { process.exitCode = 1; }
});
