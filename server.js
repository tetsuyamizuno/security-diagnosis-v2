const express = require('express');
const path = require('path');
const https = require('https');
const http = require('http');
const { URL } = require('url');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.static(path.join(__dirname, 'public')));
app.use(express.json());

// ルートへのアクセスは明示的にindex.htmlを返す
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ===== サイト取得エンドポイント =====
app.get('/api/fetch-site', async (req, res) => {
  const targetUrl = req.query.url;
  if (!targetUrl) return res.status(400).json({ error: 'URLが必要です' });

  try {
    new URL(targetUrl); // URL形式チェック
  } catch {
    return res.status(400).json({ error: '無効なURL形式です' });
  }

  try {
    const result = await fetchWithRedirect(targetUrl, 5);
    res.json({
      url: targetUrl,
      finalUrl: result.finalUrl,
      statusCode: result.statusCode,
      headers: result.headers,
      html: result.html,
    });
  } catch (err) {
    res.status(500).json({ error: err.message || 'サイトの取得に失敗しました' });
  }
});

// ===== リダイレクト追跡付きフェッチ =====
function fetchWithRedirect(url, maxRedirects) {
  return new Promise((resolve, reject) => {
    if (maxRedirects < 0) return reject(new Error('リダイレクト上限を超えました'));

    let parsed;
    try { parsed = new URL(url); } catch { return reject(new Error('無効なURL: ' + url)); }

    const proto = parsed.protocol === 'https:' ? https : http;
    const port = parsed.port
      ? parseInt(parsed.port)
      : parsed.protocol === 'https:' ? 443 : 80;

    const options = {
      hostname: parsed.hostname,
      port,
      path: (parsed.pathname || '/') + (parsed.search || ''),
      method: 'GET',
      timeout: 20000,
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'ja,en-US;q=0.9,en;q=0.8',
        'Accept-Encoding': 'identity',
        'Connection': 'close',
      },
    };

    const req = proto.request(options, (response) => {
      const loc = response.headers['location'];
      if ([301, 302, 303, 307, 308].includes(response.statusCode) && loc) {
        const nextUrl = new URL(loc, url).toString();
        response.resume();
        return fetchWithRedirect(nextUrl, maxRedirects - 1).then(resolve).catch(reject);
      }

      const chunks = [];
      let totalBytes = 0;
      const MAX_BYTES = 150 * 1024; // 150KB

      response.on('data', (chunk) => {
        totalBytes += chunk.length;
        if (totalBytes <= MAX_BYTES) chunks.push(chunk);
      });

      response.on('end', () => {
        const html = Buffer.concat(chunks).toString('utf8');
        resolve({
          finalUrl: url,
          statusCode: response.statusCode,
          headers: response.headers,
          html,
        });
      });

      response.on('error', reject);
    });

    req.on('timeout', () => { req.destroy(); reject(new Error('タイムアウト（20秒）')); });
    req.on('error', reject);
    req.end();
  });
}

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
