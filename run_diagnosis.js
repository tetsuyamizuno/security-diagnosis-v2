#!/usr/bin/env node
/**
 * run_diagnosis.js
 * セキュリティ脆弱性診断スクリプト（Claude Code連携版）
 *
 * 使い方：
 *   Claude Codeで「diagnosis-config.jsonの設定でrun_diagnosis.jsを実行して、
 *   レポートをreport.htmlに保存して」と指示する
 *
 * 必要なもの：
 *   - Node.js 18以上
 *   - 環境変数 ANTHROPIC_API_KEY が設定済みであること
 *   - diagnosis-config.json（input.htmlで生成）
 *   - security-diagnosis-prompt.md（プロンプトファイル）
 */

const fs   = require('fs');
const path = require('path');
const https= require('https');
const http = require('http');
const { execSync } = require('child_process');

// ──────────────────────────────────────────
// 設定読み込み
// ──────────────────────────────────────────
const configPath = path.join(__dirname, 'diagnosis-config.json');
const promptPath = path.join(__dirname, 'security-diagnosis-prompt.md');

if (!fs.existsSync(configPath)) {
  console.error('❌ diagnosis-config.json が見つかりません。input.html で設定を保存してください。');
  process.exit(1);
}
if (!fs.existsSync(promptPath)) {
  console.error('❌ security-diagnosis-prompt.md が見つかりません。同じフォルダに置いてください。');
  process.exit(1);
}

const config = JSON.parse(fs.readFileSync(configPath, 'utf8'));
const promptMd = fs.readFileSync(promptPath, 'utf8');
const apiKey = process.env.ANTHROPIC_API_KEY;

if (!apiKey) {
  console.error('❌ 環境変数 ANTHROPIC_API_KEY が設定されていません。');
  console.error('   export ANTHROPIC_API_KEY="sk-ant-..." を実行してください。');
  process.exit(1);
}

console.log('');
console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
console.log('  セキュリティ脆弱性診断【レポート作成】');
console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
console.log(`  対象URL    : ${config.url}`);
console.log(`  所有区分   : ${config.ownershipLabel}`);
console.log(`  モデル     : ${config.model}`);
console.log(`  Web検索    : ${config.useSearch ? 'オン（最新情報を取得）' : 'オフ（AI知識ベース）'}`);
console.log(`  動作モード : ${config.mode === 'prod' ? '本番' : 'テスト'}`);
console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
console.log('');

// ──────────────────────────────────────────
// STEP 1: 対象URLのHTMLを取得
// ──────────────────────────────────────────
async function fetchPage(url) {
  return new Promise((resolve) => {
    try {
      console.log(`📥 ページを取得中: ${url}`);
      const client = url.startsWith('https') ? https : http;
      const req = client.get(url, {
        headers: {
          'User-Agent': 'Mozilla/5.0 (compatible; SecurityReviewBot/1.0)',
          'Accept': 'text/html,application/xhtml+xml'
        },
        timeout: 15000
      }, (res) => {
        let data = '';
        res.on('data', chunk => data += chunk);
        res.on('end', () => {
          console.log(`   ステータス: ${res.statusCode}`);
          resolve({ html: data.slice(0, 30000), status: res.statusCode });
        });
      });
      req.on('error', (e) => {
        console.log(`   ⚠ 取得エラー（${e.message}）- 推測ベースで続行します`);
        resolve({ html: '', status: 0 });
      });
      req.on('timeout', () => {
        req.destroy();
        console.log('   ⚠ タイムアウト - 推測ベースで続行します');
        resolve({ html: '', status: 0 });
      });
    } catch(e) {
      resolve({ html: '', status: 0 });
    }
  });
}

// ──────────────────────────────────────────
// STEP 2: HTTPヘッダーをcurlで取得
// ──────────────────────────────────────────
function fetchHeaders(url) {
  try {
    console.log(`📋 HTTPヘッダーを確認中...`);
    const result = execSync(
      `curl -s -I -L --max-time 10 --user-agent "Mozilla/5.0" "${url}" 2>&1`,
      { encoding: 'utf8', timeout: 15000 }
    );
    console.log('   ヘッダー取得完了');
    return result.slice(0, 5000);
  } catch(e) {
    console.log('   ⚠ ヘッダー取得エラー - 推測ベースで続行します');
    return '';
  }
}

// ──────────────────────────────────────────
// STEP 3: Anthropic APIを呼び出してレポート生成
// ──────────────────────────────────────────
async function callAnthropicAPI(userMessage, useSearch, model) {
  return new Promise((resolve, reject) => {
    const tools = useSearch ? [{
      type: 'web_search_20250305',
      name: 'web_search',
      max_uses: 8
    }] : [];

    const body = JSON.stringify({
      model,
      max_tokens: 8000,
      system: buildSystemPrompt(promptMd),
      messages: [{ role: 'user', content: userMessage }],
      ...(tools.length > 0 ? { tools } : {})
    });

    const options = {
      hostname: 'api.anthropic.com',
      path: '/v1/messages',
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': apiKey,
        'anthropic-version': '2023-06-01',
        'Content-Length': Buffer.byteLength(body)
      }
    };

    console.log(`🤖 Claudeがレポートを作成中...${useSearch ? '（Web検索あり・数分かかります）' : ''}`);

    const req = https.request(options, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
          const parsed = JSON.parse(data);
          if (parsed.error) {
            reject(new Error(`API エラー: ${parsed.error.message}`));
            return;
          }
          const text = (parsed.content || [])
            .filter(b => b.type === 'text')
            .map(b => b.text)
            .join('\n');
          resolve(text);
        } catch(e) {
          reject(new Error(`レスポンスのパースに失敗: ${e.message}`));
        }
      });
    });

    req.on('error', reject);
    req.write(body);
    req.end();
  });
}

// ──────────────────────────────────────────
// システムプロンプトをmdから構築
// ──────────────────────────────────────────
function buildSystemPrompt(md) {
  // mdファイルのプロンプト本文部分（```で囲まれた部分）を抽出
  const match = md.match(/```\n([\s\S]+?)\n```/);
  if (match) return match[1];
  // 見つからない場合はmd全体を使う
  return md;
}

// ──────────────────────────────────────────
// Markdown → freeeトンマナHTML変換
// ──────────────────────────────────────────
function buildReportHtml(md, config) {
  const today = new Date().toLocaleDateString('ja-JP',{year:'numeric',month:'long',day:'numeric'});
  const esc = s => (s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');

  function inlineParse(s) {
    return esc(s)
      .replace(/\*\*(.+?)\*\*/g,'<strong>$1</strong>')
      .replace(/`(.+?)`/g,'<code>$1</code>');
  }

  const lines = md.split('\n');
  let bodyHtml = '';
  let i = 0;

  while(i < lines.length) {
    const line = lines[i];
    if(/^# /.test(line)){i++;continue;}
    if(/^## /.test(line)){
      bodyHtml+=`<div class="rp-sn">/ SECTION</div><h2>${inlineParse(line.replace(/^## /,''))}</h2>`;i++;continue;
    }
    if(/^### /.test(line)){
      const title=line.replace(/^### /,'');
      const rc=/高リスク/i.test(title)?'h':/中リスク/i.test(title)?'m':'l';
      bodyHtml+=`<div class="rp-risk"><div class="rp-card"><div class="rp-ch"><span class="rp-ct">${inlineParse(title)}</span><span class="rp-badge ${rc}">${rc==='h'?'高リスク':rc==='m'?'中リスク':'低リスク'}</span></div><div class="rp-cb">`;
      i++;
      let cardBody='';
      while(i<lines.length&&!/^##/.test(lines[i])){
        const cl=lines[i];
        if(/^[-*] /.test(cl))cardBody+=`<li>${inlineParse(cl.replace(/^[-*] /,''))}</li>`;
        else if(/^\d+\. /.test(cl))cardBody+=`<li>${inlineParse(cl.replace(/^\d+\. /,''))}</li>`;
        else if(/^> /.test(cl))cardBody+=`<div class="rp-note">${inlineParse(cl.replace(/^> /,''))}</div>`;
        else if(cl.trim())cardBody+=`<p style="font-size:14px;line-height:1.9;margin:0 0 12px;color:#152230;">${inlineParse(cl)}</p>`;
        i++;
      }
      cardBody=cardBody.replace(/(<li>.*?<\/li>)+/gs,m=>`<ul>${m}</ul>`);
      bodyHtml+=cardBody+'</div></div></div>';
      continue;
    }
    if(/^\|/.test(line)){
      const tableLines=[];
      while(i<lines.length&&/^\|/.test(lines[i])){tableLines.push(lines[i]);i++;}
      const rows=tableLines.filter(r=>!/^\|[-:| ]+\|$/.test(r.trim()));
      if(rows.length>0){
        bodyHtml+=`<table class="rp-table"><thead><tr>`;
        rows[0].split('|').filter(c=>c.trim()!=='').forEach(h=>bodyHtml+=`<th>${inlineParse(h.trim())}</th>`);
        bodyHtml+=`</tr></thead><tbody>`;
        rows.slice(1).forEach(row=>{
          bodyHtml+=`<tr>`;
          row.split('|').filter(c=>c.trim()!=='').forEach(c=>{
            const cls=/最優先|高$/.test(c.trim())?'ph':/^中$/.test(c.trim())?'pm':/^低$/.test(c.trim())?'pl':'';
            bodyHtml+=`<td class="${cls}">${inlineParse(c.trim())}</td>`;
          });
          bodyHtml+=`</tr>`;
        });
        bodyHtml+=`</tbody></table>`;
      }
      continue;
    }
    if(/^> /.test(line)){bodyHtml+=`<div class="rp-note">${inlineParse(line.replace(/^> /,''))}</div>`;i++;continue;}
    if(/^[-*] /.test(line)){bodyHtml+=`<ul><li>${inlineParse(line.replace(/^[-*] /,''))}</li></ul>`;i++;continue;}
    if(/^\d+\. /.test(line)){bodyHtml+=`<ol><li>${inlineParse(line.replace(/^\d+\. /,''))}</li></ol>`;i++;continue;}
    if(line.trim()===''){i++;continue;}
    bodyHtml+=`<p style="font-size:14px;line-height:1.95;margin:0 0 14px;color:#152230;">${inlineParse(line)}</p>`;
    i++;
  }

  const highCount=(md.match(/高リスク/g)||[]).length;
  const midCount=(md.match(/中リスク/g)||[]).length;
  const lowCount=(md.match(/低リスク/g)||[]).length;

  return `<!DOCTYPE html>
<html lang="ja">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>セキュリティ脆弱性診断レポート — ${esc(config.url)}</title>
<link href="https://fonts.googleapis.com/css2?family=Zen+Kaku+Gothic+New:wght@300;400;500;700&family=Zen+Antique&family=JetBrains+Mono:wght@400;700&display=swap" rel="stylesheet">
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0;}
body{font-family:'Zen Kaku Gothic New',sans-serif;font-weight:300;background:#f4f6f9;-webkit-font-smoothing:antialiased;}
.wrap{max-width:960px;margin:0 auto;padding:40px 24px 80px;}
.rp-cover{background:linear-gradient(160deg,#0d1b2a,#13263a);color:#f6f7f4;padding:48px 56px;position:relative;overflow:hidden;border-radius:16px 16px 0 0;}
.rp-cover::before{content:"";position:absolute;inset:0;background-image:radial-gradient(circle at 80% 15%,rgba(42,161,152,.18),transparent 45%);}
.rp-cover-top{display:flex;justify-content:space-between;border-bottom:1px solid rgba(255,255,255,.15);padding-bottom:16px;margin-bottom:32px;position:relative;z-index:2;}
.rp-mono{font-family:'JetBrains Mono',monospace;font-size:10px;letter-spacing:.16em;text-transform:uppercase;color:rgba(246,247,244,.5);}
.rp-kick{font-family:'JetBrains Mono',monospace;font-size:11px;letter-spacing:.28em;color:#2aa198;text-transform:uppercase;margin-bottom:20px;position:relative;z-index:2;}
.rp-title{font-family:'Zen Antique',serif;font-size:clamp(24px,4vw,46px);line-height:1.25;position:relative;z-index:2;}
.rp-title b{display:block;}
.rp-dom{font-family:'JetBrains Mono',monospace;font-size:clamp(13px,2vw,18px);color:#2aa198;margin-top:12px;position:relative;z-index:2;}
.rp-sub{margin-top:18px;max-width:560px;color:rgba(246,247,244,.6);line-height:1.88;font-size:14px;position:relative;z-index:2;}
.rp-meta{border-top:1px solid rgba(255,255,255,.15);padding-top:20px;display:flex;flex-wrap:wrap;gap:32px;position:relative;z-index:2;margin-top:28px;}
.rp-meta div{display:flex;flex-direction:column;gap:4px;}
.rp-meta dt{font-family:'JetBrains Mono',monospace;font-size:9.5px;letter-spacing:.13em;text-transform:uppercase;color:rgba(246,247,244,.4);}
.rp-meta dd{font-size:13px;color:rgba(246,247,244,.88);font-weight:500;}
.rp-scores{background:#13263a;display:flex;border-top:1px solid rgba(255,255,255,.07);}
.rp-score{flex:1;padding:18px 26px;display:flex;align-items:center;gap:12px;border-right:1px solid rgba(255,255,255,.07);}
.rp-score:last-child{border-right:none;}
.rp-dot{width:10px;height:10px;border-radius:50%;flex:none;}
.rp-dot.h{background:#cf4036;box-shadow:0 0 9px #cf4036;}
.rp-dot.m{background:#c08327;box-shadow:0 0 9px #c08327;}
.rp-dot.l{background:#2f8a5b;box-shadow:0 0 9px #2f8a5b;}
.rp-score .rp-lab{font-size:12px;color:rgba(246,247,244,.55);}
.rp-score .rp-num{font-family:'JetBrains Mono',monospace;font-size:22px;font-weight:700;margin-left:auto;}
.rp-body{background:#f6f7f4;padding:52px 48px 72px;border-radius:0 0 16px 16px;}
.rp-note{border-left:3px solid #1f7a8c;background:rgba(31,122,140,.07);padding:20px 26px;margin-bottom:22px;font-size:13.5px;color:#52606d;line-height:1.85;}
.rp-note b{color:#152230;font-weight:700;}
.rp-sn{font-family:'JetBrains Mono',monospace;font-size:10px;letter-spacing:.22em;color:#52606d;text-transform:uppercase;margin-bottom:8px;}
.rp-body h2{font-family:'Zen Antique',serif;font-weight:400;font-size:23px;padding-bottom:13px;border-bottom:2px solid #152230;margin-bottom:28px;color:#152230;}
.rp-risk{margin-bottom:72px;}
.rp-card{border:1px solid #d3d8cf;background:#eceee7;}
.rp-ch{display:flex;justify-content:space-between;align-items:flex-start;gap:16px;padding:20px 28px;border-bottom:1px solid #d3d8cf;background:#f6f7f4;}
.rp-ct{font-family:'Zen Kaku Gothic New',sans-serif;font-weight:700;font-size:16px;line-height:1.45;color:#152230;}
.rp-badge{font-family:'JetBrains Mono',monospace;font-size:11px;font-weight:700;padding:5px 12px;border-radius:2px;white-space:nowrap;text-transform:uppercase;flex:none;}
.rp-badge.h{background:rgba(207,64,54,.1);color:#cf4036;border:1px solid rgba(207,64,54,.32);}
.rp-badge.m{background:rgba(192,131,39,.12);color:#c08327;border:1px solid rgba(192,131,39,.32);}
.rp-badge.l{background:rgba(47,138,91,.12);color:#2f8a5b;border:1px solid rgba(47,138,91,.32);}
.rp-cb{padding:28px;}
.rp-body ul{list-style:none;display:flex;flex-direction:column;gap:8px;margin-bottom:14px;}
.rp-body ul li{font-size:13px;line-height:1.78;padding-left:18px;position:relative;color:#152230;}
.rp-body ul li::before{content:"—";position:absolute;left:0;color:#52606d;font-family:'JetBrains Mono',monospace;}
.rp-body ol{list-style:none;counter-reset:r;display:flex;flex-direction:column;gap:9px;margin-bottom:14px;}
.rp-body ol li{counter-increment:r;font-size:13px;line-height:1.78;padding-left:32px;position:relative;color:#152230;}
.rp-body ol li::before{content:counter(r,decimal-leading-zero);position:absolute;left:0;font-family:'JetBrains Mono',monospace;font-size:11px;font-weight:700;color:#1f7a8c;}
.rp-body code{font-family:'JetBrains Mono',monospace;font-size:12px;background:#e2e5dc;padding:1px 5px;border-radius:2px;}
.rp-table{width:100%;border-collapse:collapse;font-size:13px;background:#f6f7f4;border:1px solid #d3d8cf;margin:14px 0;}
.rp-table thead th{text-align:left;padding:11px 14px;font-family:'JetBrains Mono',monospace;font-size:9.5px;letter-spacing:.1em;text-transform:uppercase;color:#52606d;border-bottom:2px solid #152230;}
.rp-table tbody td{padding:11px 14px;border-bottom:1px solid #d3d8cf;color:#152230;}
.rp-table .ph{font-weight:700;color:#cf4036;}.rp-table .pm{font-weight:600;color:#c08327;}.rp-table .pl{color:#2f8a5b;}
.rp-footer-bar{background:linear-gradient(160deg,#0d1b2a,#13263a);color:rgba(246,247,244,.4);padding:24px 48px;display:flex;justify-content:space-between;flex-wrap:wrap;gap:10px;font-family:'JetBrains Mono',monospace;font-size:10.5px;border-radius:0 0 16px 16px;}
.pdf-bar{text-align:center;margin:24px 0;display:flex;gap:12px;justify-content:center;}
.pdf-bar button{background:linear-gradient(135deg,#1f9b92,#2f74c0);color:#fff;border:none;border-radius:10px;padding:13px 28px;font-size:14px;font-weight:700;font-family:inherit;cursor:pointer;}
.pdf-bar button:hover{opacity:.9;}
@media print{.pdf-bar{display:none;}}
</style>
</head>
<body>
<div class="wrap">
  <div class="pdf-bar">
    <button onclick="window.print()">PDFとして保存（ブラウザの印刷→PDFを選択）</button>
    <button onclick="window.close()">閉じる</button>
  </div>

  <div class="rp-cover">
    <div class="rp-cover-top">
      <span class="rp-mono">セキュリティ脆弱性診断 / 非侵襲レビュー / Claude Code版</span>
      <span class="rp-mono">OWASP Top 10 準拠</span>
    </div>
    <div class="rp-kick">Security Vulnerability Assessment</div>
    <h1 class="rp-title">セキュリティ脆弱性診断<b>リスク・レビューレポート</b></h1>
    <div class="rp-dom">${esc(config.url)}</div>
    <p class="rp-sub">公開情報に基づく非侵襲的な机上レビューです。実際の攻撃・スキャン・侵入テストは行っていません。</p>
    <dl class="rp-meta">
      <div><dt>診断対象</dt><dd>${esc(config.url)}</dd></div>
      <div><dt>所有区分</dt><dd>${config.ownership==='self'?'自社':'他社'}</dd></div>
      <div><dt>作成日</dt><dd>${today}</dd></div>
      <div><dt>補足</dt><dd>${esc(config.notes)}</dd></div>
      <div><dt>モデル</dt><dd>${esc(config.model)}</dd></div>
      <div><dt>Web検索</dt><dd>${config.useSearch?'あり（最新情報取得）':'なし'}</dd></div>
    </dl>
  </div>
  <div class="rp-scores">
    <div class="rp-score"><span class="rp-dot h"></span><span class="rp-lab">高リスク</span><span class="rp-num" style="color:#ff9a92">${highCount}</span></div>
    <div class="rp-score"><span class="rp-dot m"></span><span class="rp-lab">中リスク</span><span class="rp-num" style="color:#f0c474">${midCount}</span></div>
    <div class="rp-score"><span class="rp-dot l"></span><span class="rp-lab">低リスク</span><span class="rp-num" style="color:#8ad6a9">${lowCount}</span></div>
  </div>
  <div class="rp-body">
    ${bodyHtml}
  </div>
  <div class="rp-footer-bar">
    <span>セキュリティ脆弱性診断【レポート作成】Claude Code版</span>
    <span>${today} / 非侵襲・公開情報のみ / OWASP Top 10 準拠</span>
  </div>

  <div class="pdf-bar" style="margin-top:24px;">
    <button onclick="window.print()">PDFとして保存（ブラウザの印刷→PDFを選択）</button>
  </div>
</div>
</body>
</html>`;
}

// ──────────────────────────────────────────
// メイン処理
// ──────────────────────────────────────────
async function main() {
  // STEP 1: ページ取得
  const { html: pageHtml } = await fetchPage(config.url);

  // STEP 2: HTTPヘッダー取得
  const headers = fetchHeaders(config.url);

  // STEP 3: ユーザーメッセージ組み立て
  const userMessage = `
以下のURLについて、セキュリティ脆弱性診断レポートを作成してください。

【診断対象URL】
${config.url}

【所有区分】
${config.ownershipLabel}

【補足メモ】
${config.notes}

【取得したHTMLソース（先頭30,000文字）】
${pageHtml ? pageHtml : '（取得できませんでした。URLから推測して診断してください）'}

【取得したHTTPレスポンスヘッダー】
${headers ? headers : '（取得できませんでした。一般的なリスクで診断してください）'}

━━━━━━━━━━━━━━━━━━━━━━
【診断手順】以下の①〜⑦を必ずこの順番で実行してください
━━━━━━━━━━━━━━━━━━━━━━

① 上記のHTMLソースとHTTPヘッダーから技術スタックを特定してください。
  GTMのコンテナID、外部スクリプトの読み込み元、metaタグ情報も確認。

② HTTPヘッダーの設定状況（CSP・X-Frame-Options・HSTS等）を一つずつ確認・記録。

③ 特定した技術スタックに応じて、最新CVEと攻撃事例をWeb検索（検索が使える場合）。

④ 調査中に気になった点は、指示リストにない内容でも自律的に追加確認。

⑤ 実在する攻撃事例と公的統計（IBM・警察庁・IPA等）で損害額を裏取り。

⑥ このサイトの性質（扱うデータ・機能・規模）を踏まえてリスク優先度を補正。

⑦ 「推測」と「確認済み」が混在していないか確認してからレポートを作成。

━━━━━━━━━━━━━━━━━━━━━━
【レポート形式（Markdown）】
━━━━━━━━━━━━━━━━━━━━━━

# 冒頭注記（非侵襲／OWASP準拠の意味／金額は推計）
# 対象サマリー（技術スタック一覧・ヘッダー設定状況）
# リスク一覧（高→中→低。各リスクに①説明・②事例3つ・③損害額・④原因・⑤対応策・OWASP項目）
# 優先対応ロードマップ（表）
# 免責事項

専門用語の初出には必ず（）で注釈。非専門家にも分かる言葉で書いてください。
`.trim();

  // STEP 4: API呼び出し
  let reportMd;
  try {
    reportMd = await callAnthropicAPI(userMessage, config.useSearch, config.model);
  } catch(e) {
    console.error(`❌ API呼び出しエラー: ${e.message}`);
    process.exit(1);
  }

  // STEP 5: HTMLレポート生成・保存
  const reportHtml = buildReportHtml(reportMd, config);
  const outputPath = path.join(__dirname, 'report.html');
  fs.writeFileSync(outputPath, reportHtml, 'utf8');

  // Markdownも保存
  const mdPath = path.join(__dirname, 'report.md');
  fs.writeFileSync(mdPath, reportMd, 'utf8');

  console.log('');
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log('  ✅ レポート生成完了！');
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log(`  📄 HTML レポート : ${outputPath}`);
  console.log(`  📝 Markdown      : ${mdPath}`);
  console.log('');
  console.log('  ブラウザで report.html を開いてください。');
  console.log('  PDFは「印刷→PDFで保存」でダウンロードできます。');
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
}

main().catch(e => {
  console.error(`❌ 予期しないエラー: ${e.message}`);
  process.exit(1);
});
