# Post Secret

One-time secret sharing with client-side AES-256-GCM encryption, delete-on-read storage, and an IPFS-hosted frontend you can verify by CID.

## How it works

1. You enter a secret — it's encrypted in your browser using AES-256-GCM (`WebCrypto` API)
2. Only the ciphertext is sent to the server, which stores it and returns an ID
3. The server deletes the ciphertext on first read
4. The decryption key never touches the server — it travels via a separate channel or sits in the URL `#fragment` (browsers never include the fragment in HTTP requests)

## Security properties

- **Server never sees plaintext** — encryption happens client-side before any network request
- **Delete on read** — ciphertext is gone after the recipient fetches it
- **Key isolation** — in two-channel mode the key and link travel separately; in combined mode the key is in the `#fragment`, invisible to servers
- **Verifiable frontend** — the app is a single static file hosted on IPFS; its CID is a cryptographic hash of the exact code you're running. Verify it yourself: `ipfs add --only-hash index.html`
- **Zero dependencies** — one HTML file + 70-line Node.js server using only built-in modules

## Sharing modes

**Two-channel (more secure):** send the link via one app (e.g. Telegram) and the key via another (e.g. SMS). Neither channel alone can reveal the secret.

**Combined link (convenient):** a single URL with `#id|key` in the fragment. Anyone with the link can decrypt. The key is never sent to any server.

## Self-hosting

```bash
node server.js          # default port 3000
PORT=8080 node server.js
```

Docker:

```bash
docker build -t post-secret .
docker run -p 3000:3000 post-secret
```

## CLI usage

Encrypt from the command line (requires Node.js):

```bash
SECRET='your-secret-here' API='https://send-secret.fly.dev' BASE='https://your-ipfs-url/' node -e "(async()=>{const c=require('crypto'),k=c.randomBytes(32),iv=c.randomBytes(12),ci=c.createCipheriv('aes-256-gcm',k,iv),ct=Buffer.concat([ci.update(process.env.SECRET,'utf8'),ci.final()]),payload=Buffer.concat([iv,ct,ci.getAuthTag()]).toString('base64url'),key=k.toString('base64url'),{id}=await(await fetch(process.env.API+'/create',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({ciphertext:payload})})).json();console.log('Link:     '+process.env.BASE+'#'+id+'\nKey:      '+key+'\nCombined: '+process.env.BASE+'#'+id+'|'+key);})()"
```

## API

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/create` | Body: `{ ciphertext, ttl? }`. Returns `{ id }`. TTL default 24h, max 7d. |
| `GET` | `/secret/:id` | Returns `{ ciphertext }` and immediately deletes. 404 on second access. |
