const net = require('net');
const crypto = require('crypto');
const fs = require('fs');

const PORT = 8000;

const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
});

const serverPublicPem = publicKey.export({ type: 'pkcs1', format: 'pem' });
const serverPrivatePem = privateKey.export({ type: 'pkcs1', format: 'pem' });

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

const server = net.createServer((socket) => {
    console.log('Client connected:', socket.remoteAddress, socket.remotePort);
    let clientRandom = null;
    let serverRandom = crypto.randomBytes(32).toString('hex');
    let premaster = null;
    let sessionKey = null;
    let handshakeComplete = false;

    socket.on('data', (data) => {
        try {
            const msg = JSON.parse(data.toString());
            if (msg.type === 'CLIENT_HELLO') {
                clientRandom = msg.clientRandom;
                console.log('[1] CLIENT_HELLO received. clientRandom:', clientRandom.slice(0,16), '...');
                const serverHello = {
                    type: 'SERVER_HELLO',
                    serverRandom,
                    serverPublicPem
                };
                socket.write(JSON.stringify(serverHello));
                console.log('[2] SERVER_HELLO sent with serverPublicPem.');
            } else if (msg.type === 'CLIENT_KEY_EXCHANGE') {
                const encryptedPremasterB64 = msg.encryptedPremaster;
                const encryptedBuf = Buffer.from(encryptedPremasterB64, 'base64');

                premaster = crypto.privateDecrypt(
                    {
                        key: serverPrivatePem,
                        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
                        oaepHash: 'sha256'
                    },
                    encryptedBuf
                );
                console.log('[4] premaster decrypted.');

                sessionKey = deriveSessionKey(premaster, clientRandom, serverRandom);
                console.log('[5] sessionKey derived.');

                const readyEncrypted = encryptAESGCM(sessionKey, 'SERVER_READY');
                socket.write(JSON.stringify({ type: 'SERVER_FINISHED', data: readyEncrypted }));
                console.log('[6] SERVER_FINISHED sent (encrypted).');
            } else if (msg.type === 'CLIENT_FINISHED') {
                const decrypted = decryptAESGCM(sessionKey, msg.data);
                console.log('[6] CLIENT_FINISHED decrypted:', decrypted);
                if (decrypted === 'CLIENT_READY') {
                    handshakeComplete = true;
                    console.log('Handshake complete. Secure channel established.');
                } else {
                    console.warn('CLIENT_FINISHED content unexpected.');
                }
            } else if (msg.type === 'SECURE_MSG' && handshakeComplete) {
                const plaintext = decryptAESGCM(sessionKey, msg.data);
                console.log('Secure message from client:', plaintext);

                if (plaintext.startsWith('SEND_FILE:')) {
                    const filepath = plaintext.split(':')[1];
                    if (fs.existsSync(filepath)) {
                        const fileBuf = fs.readFileSync(filepath);
                        const payload = JSON.stringify({ filename: require('path').basename(filepath), contentB64: fileBuf.toString('base64') });
                        const enc = encryptAESGCM(sessionKey, payload);
                        socket.write(JSON.stringify({ type: 'SECURE_MSG', data: enc }));
                        console.log('Sent encrypted file content.');
                    } else {
                        const enc = encryptAESGCM(sessionKey, 'ERROR: file not found');
                        socket.write(JSON.stringify({ type: 'SECURE_MSG', data: enc }));
                    }
                } else {
                    const resp = 'Server echo: ' + plaintext;
                    const encResp = encryptAESGCM(sessionKey, resp);
                    socket.write(JSON.stringify({ type: 'SECURE_MSG', data: encResp }));
                }
            } else {
                console.warn('Unknown message type or handshake not complete.');
            }
        } catch (e) {
            console.error('Error handling data:', e);
        }
    });

    socket.on('close', () => {
        console.log('Client disconnected.');
    });

    socket.on('error', (err) => {
        console.error('Socket error:', err.message);
    });
});

server.listen(PORT, () => {
    console.log(`Server listening on port ${PORT}`);
});
