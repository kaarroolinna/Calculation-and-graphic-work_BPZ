const net = require('net');
const crypto = require('crypto');
const fs = require('fs');
const readline = require('readline');

const PORT = 8000;
const HOST = '127.0.0.1';

function deriveSessionKey(premaster, clientRandom, serverRandom) {
    const hmac = crypto.createHmac('sha256', premaster);
    hmac.update(clientRandom);
    hmac.update(serverRandom);
    return hmac.digest().slice(0, 32);
}

function encryptAESGCM(key, plaintext) {
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    const enc = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
    const tag = cipher.getAuthTag();
    return Buffer.concat([iv, tag, enc]).toString('base64');
}

function decryptAESGCM(key, dataB64) {
    const buf = Buffer.from(dataB64, 'base64');
    const iv = buf.slice(0, 12);
    const tag = buf.slice(12, 28);
    const ct = buf.slice(28);
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(tag);
    const out = Buffer.concat([decipher.update(ct), decipher.final()]);
    return out.toString('utf8');
}

const clientRandom = crypto.randomBytes(32).toString('hex');
let serverPublicPem = null;
let serverRandom = null;
let premaster = crypto.randomBytes(48);
let sessionKey = null;
let handshakeComplete = false;

const socket = net.createConnection(PORT, HOST, () => {
    console.log('Connected to server.');
    const clientHello = { type: 'CLIENT_HELLO', clientRandom };
    socket.write(JSON.stringify(clientHello));
    console.log('[1] CLIENT_HELLO sent.');
});

socket.on('data', (data) => {
    try {
        const msg = JSON.parse(data.toString());
        if (msg.type === 'SERVER_HELLO') {
            serverRandom = msg.serverRandom;
            serverPublicPem = msg.serverPublicPem;
            console.log('[2] SERVER_HELLO received. serverRandom:', serverRandom.slice(0,16), '...');

            const encryptedPremaster = crypto.publicEncrypt(
                {
                    key: serverPublicPem,
                    padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
                    oaepHash: 'sha256'
                },
                premaster
            );
            const b64 = encryptedPremaster.toString('base64');
            socket.write(JSON.stringify({ type: 'CLIENT_KEY_EXCHANGE', encryptedPremaster: b64 }));
            console.log('[4] CLIENT_KEY_EXCHANGE sent (premaster encrypted).');

            sessionKey = deriveSessionKey(premaster, clientRandom, serverRandom);
            console.log('[5] sessionKey derived (client).');

            const readyEnc = encryptAESGCM(sessionKey, 'CLIENT_READY');
            socket.write(JSON.stringify({ type: 'CLIENT_FINISHED', data: readyEnc }));
            console.log('[6] CLIENT_FINISHED sent (encrypted).');
        } else if (msg.type === 'SERVER_FINISHED') {
            const dec = decryptAESGCM(sessionKey, msg.data);
            console.log('[6] SERVER_FINISHED decrypted:', dec);
            if (dec === 'SERVER_READY') {
                handshakeComplete = true;
                console.log('Handshake complete (client). Secure channel ready.');
                startInteractive();
            } else {
                console.warn('Unexpected SERVER_FINISHED content.');
            }
        } else if (msg.type === 'SECURE_MSG' && handshakeComplete) {
            const payload = decryptAESGCM(sessionKey, msg.data);
            try {
                const parsed = JSON.parse(payload);
                if (parsed.filename && parsed.contentB64) {
                    const outPath = './received_' + parsed.filename;
                    fs.writeFileSync(outPath, Buffer.from(parsed.contentB64, 'base64'));
                    console.log(`Received file saved as ${outPath}`);
                } else {
                    console.log('Secure message:', payload);
                }
            } catch (e) {
                console.log('Secure message:', payload);
            }
        } else {
            console.warn('Unknown message type or handshake incomplete.');
        }
    } catch (e) {
        console.error('Error processing server data:', e);
    }
});

socket.on('close', () => {
    console.log('Connection closed.');
});

socket.on('error', (err) => {
    console.error('Socket error:', err.message);
});

const rl = readline.createInterface({ input: process.stdin, output: process.stdout });

function startInteractive() {
    console.log('\n=== Secure channel ready. Введіть текст для відправки серверу.');
    console.log('Команди: SEND_FILE:<шлях_до_файлу> | exit\n');
    rl.on('line', (line) => {
        if (!handshakeComplete) {
            console.log('Handshake not complete yet.');
            return;
        }
        if (line === 'exit') {
            socket.end();
            rl.close();
            return;
        }
        if (line.startsWith('SEND_FILE:')) {
            const path = line.split(':')[1];
            const enc = encryptAESGCM(sessionKey, line);
            socket.write(JSON.stringify({ type: 'SECURE_MSG', data: enc }));
        } else {
            const enc = encryptAESGCM(sessionKey, line);
            socket.write(JSON.stringify({ type: 'SECURE_MSG', data: enc }));
        }
    });
}
