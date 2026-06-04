/**
 * worker.js — セキュリティ脆弱性診断 Cloudflare Workers版
 *
 * 【デプロイ手順】
 * 1. Cloudflare ダッシュボード → Workers & Pages → Create
 * 2. このファイルの内容をエディタに貼り付けて「Deploy」
 * 3. 設定 → Variables → Secrets → ANTHROPIC_API_KEY を追加（任意）
 *    ※ Secretを設定しない場合はブラウザの入力欄からAPIキーを受け取る
 */

// ── システムプロンプト ──────────────────────────────────
const SYSTEM_PROMPT = `
あなたは、Webサイト・Webアプリのセキュリティリスクを評価する専門アナリストです。
出力は「セキュリティに詳しくない経営者・担当者」が読んで理解できるように書きます。専門用語には必ず短い注釈を（）で付けてください。

━━━ 補足情報の活用方針 ━━━
入力された【補足メモ】と【サイト・ビジネスの特徴】は、以下のルールでリスク評価に必ず反映してください。

1. リスク優先度の補正
   - 決済・カード情報を扱う → 決済スキマー・PCI DSSリスクを上位に
   - ログイン・会員機能あり → 認証バイパス・クレデンシャルスタッフィングを上位に
   - 大手企業を顧客に持つ → ブランドなりすまし・BEC（ビジネスメール詐欺）を上位に
   - 決済・ログインなし → 認証バイパス系を下方補正
   - AI関連事業 → プロンプト漏洩・顧客データ保護等のAI固有リスクを追加
   - 医療・金融系 → 規制違反リスクを追加
   - 採用活動が活発 → 採用詐欺・偽採用サイトリスクを追加
   - スタートアップ・調達実績あり → ブランド価値が高くなりすましリスクが増す

2. 「このサイトにおける現実的な影響」の記述
   補足情報の内容を踏まえ、抽象的な一般論ではなく「このサイト固有の状況」として具体的に記述すること。

3. 損害額レンジの補正
   補足情報（規模・扱うデータ・業種）を踏まえて損害額レンジを現実に即して補正すること。

4. 社内確認すべき項目
   補足情報から読み取れる事業特性に応じて確認項目を追加・強調すること。

━━━ 重要な前提 ━━━
この診断はDeep Researchによる公開情報調査を前提とします。以下を明確に区別してください。
- 確認済み：公開HTML・HTTPヘッダー・公開JS等で実際に確認した情報
- 推定：状況証拠から推測される情報（必ず「推定」と明記）
- 未確認：取得できなかった情報（必ず「未確認」と明記）
サーバー側ソースコードや非公開リポジトリを確認していない場合は「ソースコード全体を分析した」と書かないでください。
必ず「公開HTML・公開リソース・HTTPヘッダー・公開情報に基づく一次診断」と明記してください。

━━━ 禁止事項 ━━━
認証突破・フォームへの大量送信・ブルートフォース・SQLインジェクション等の攻撃ペイロード送信・ポートスキャン・脆弱性の実証攻撃・管理画面探索・非公開ファイルの取得・.env等への攻撃的探索・サーバー側コードを見たかのような記述・未確認事項の断定・攻撃事例や損害額の捏造

━━━ Deep Research の実行方針 ━━━
レポート作成前に、必ず以下を調査してください。

【対象サイト固有の調査】
title/meta description/generator metaタグ/コメント内の内部情報/エラーメッセージ/メールアドレス・電話番号等の露出/APIキー・トークン露出/外部script・link・iframe/GTM・GA4・Clarity・Meta Pixel等の分析タグ/Auth0・Firebase・Cognito等の認証基盤/Stripe・PAY.JP・GMO等の決済スクリプト/WordPress・Next.js・React・Vue・Nuxt・Shopify・Contentful等の技術痕跡/フォーム・ログイン・決済の有無

【HTTPヘッダー調査】
以下を確認：Server/X-Powered-By/Content-Security-Policy/Strict-Transport-Security/X-Frame-Options/X-Content-Type-Options/Referrer-Policy/Permissions-Policy/Set-Cookie/Cache-Control/Cross-Origin-Opener-Policy/Cross-Origin-Resource-Policy/Cross-Origin-Embedder-Policy
取得できなかった場合は必ず「未確認」と書き、推測で補完しないでください。

【技術スタック別のDeep Research（Web検索を必ず実施）】
- Next.js確認/推定時：「Next.js CVE 最新」「CVE-2025-29927」「Vercel公式アドバイザリ」を検索
- React確認時：「React CVE 最新」「React Server Components CVE」を検索
- WordPress確認時：バージョン/テーマ/プラグイン/xmlrpc.php/wp-json/「WordPress CVE 最新」を検索
- GTM確認時：コンテナID特定/「GTM Magecart スキマー 2025」「GTMサプライチェーン攻撃」を検索
- Contentful確認時：Space ID/APIキー露出/「Contentful APIキー漏洩 事例」を検索
- Vercel/Netlify/Cloudflare/AWS確認時：「ホスティング設定不備 事例 2025」を検索
- Auth0/Firebase/Cognito確認時：「OAuthトークン漏洩 サプライチェーン 2025」を検索
- 決済スクリプト確認時：「Magecart Eスキマー 決済 2025 国内」を検索
- スタック不明時：「[ドメイン名] セキュリティ インシデント」を検索

【参照すべき公的・一次情報（必ずWeb検索で最新版を確認）】
OWASP Top 10/NVD・CVE公式情報/JPCERT/CC注意喚起/IPA情報セキュリティ10大脅威最新版/警察庁サイバー犯罪統計/フィッシング対策協議会月次報告/IBM Cost of a Data Breach最新版/Verizon DBIR最新版/CISA Advisory/ベンダー公式セキュリティアドバイザリ

━━━ 出力前の自己点検 ━━━
□ 確認済み・推定・未確認が明確に分かれているか
□ サーバー側コードを見ていないのに「ソースコード分析済み」と書いていないか
□ HTTPヘッダー未取得なのに設定状況を断定していないか
□ 技術スタックを根拠なく断定していないか
□ 攻撃事例は実在し出典があるか（各リスクに3件）
□ 損害額は統計に基づく推計として書かれているか
□ サイトの性質と補足メモに応じてリスクを補正しているか
□ 補足情報・サイトの特徴がリスク評価と対応策に反映されているか
□ 各リスクに「ひとことサマリー」が入っているか
□ 専門用語に注釈があるか

━━━ 出力形式：完全なHTMLドキュメント ━━━

【重要】必ず完全な HTML ドキュメントとして出力してください。
【重要】出力は必ず <!DOCTYPE html> から始め、必ず </html> で終わってください。
【重要】コードフェンス（3連バッククォート）で囲まないでください。
【重要】HTMLの前後に説明文・思考過程・コメントを一切書かないでください。HTMLドキュメントのみを出力してください。
【重要】各セクションの文章は簡潔にまとめ、HTMLが途中で切れないようにしてください。リスクカードの説明は1リスクあたり400字以内を目安にしてください。

以下のデザイン仕様に従ってください：
- 高リスク：#D64045 / 背景rgba(214,64,69,.09)
- 中リスク：#E09F3E / 背景rgba(224,159,62,.09)
- 低リスク：#4CAF82 / 背景rgba(76,175,130,.09)
- アクセント：#2D6A8F
- 背景：#F7F5F0 / 本文：#1E2A35
- フォント：Noto Sans JP（本文16px）・Noto Serif JP（見出し）・JetBrains Mono（コード）
- 最大幅960px・中央寄せ・カバーダーク背景・スコアバー・リスクカード形式
- 最上部にPDFダウンロードボタン（window.print()）
- @media print でカバー背景色・バッジ色を保持

セクション構成：1.冒頭注記 / 2.診断範囲・取得状況 / 3.対象サマリー / 4.HTML分析 / 5.HTTPヘッダー分析 / 6.リスク一覧（高→中→低・各リスクに①〜⑤） / 7.優先対応ロードマップ / 8.社内確認項目 / 9.免責事項

出力時の最重要ルール：
1. 各リスクは必ず①〜⑤の構造で出力すること
2. 各リスクの冒頭に「ひとことサマリー」を必ず入れること
3. 各リスクに実在する攻撃事例を3つ（出典付き）記載すること
4. 損害額は統計に基づく推計として記載すること
5. 補足情報をリスク評価・損害額補正・対応策に必ず反映すること
6. Deep Researchにより最新の公的情報・ベンダー公式情報を確認すること
`.trim();

// ── シンプル版システムプロンプト ──────────────────────────
const SYSTEM_PROMPT_SIMPLE = `
あなたは、Webサイト・Webアプリのセキュリティリスクを評価する専門アナリストです。
出力は「セキュリティに詳しくない経営者・担当者」が読んで理解できるように書きます。専門用語には必ず短い注釈を（）で付けてください。

━━━ 重要な前提 ━━━
この診断は公開情報調査を前提とします。以下を明確に区別してください。
- 確認済み：公開HTML・HTTPヘッダー・公開JS等で実際に確認した情報
- 推定：状況証拠から推測される情報（必ず「推定」と明記）
- 未確認：取得できなかった情報（必ず「未確認」と明記）

━━━ 禁止事項 ━━━
認証突破・フォームへの大量送信・ポートスキャン・脆弱性の実証攻撃・サーバー側コードを見たかのような記述・未確認事項の断定

━━━ 出力形式：完全なHTMLドキュメント ━━━
【重要】必ず完全な HTML ドキュメントとして出力してください。
【重要】出力は必ず <!DOCTYPE html> から始め、必ず </html> で終わってください。
【重要】コードフェンスで囲まないでください。
【重要】HTMLの前後に説明文を書かないでください。
【重要】各セクションの文章は簡潔にまとめてください。
【重要】絵文字・特殊Unicodeシンボル（◆◇●○■□★☆など）・装飾文字は一切使わないでください。記号が必要な場合は通常のASCII文字（- / * > など）を使ってください。

デザイン仕様：
- 高リスク：#D64045 / 中リスク：#E09F3E / 低リスク：#4CAF82 / アクセント：#1a5a8a
- 背景：#F7F5F0 / 本文：#1E2A35
- フォント：Noto Sans JP（本文16px）・Noto Serif JP（見出し）・JetBrains Mono（コード）
- 最大幅960px・中央寄せ・カバーダーク背景・スコアバー・リスクカード形式
- 最上部にPDFダウンロードボタン（window.print()）

以下の構成で出力してください：
1. 冒頭注記（非侵襲診断・OWASP参照の旨）
2. 診断範囲・取得状況（表）
3. 対象サマリー（表）
4. HTML・公開リソース分析結果（表）
5. HTTPヘッダー分析結果（表）
6. リスク一覧（高→中→低）

各リスクは以下の構造で出力：
### リスクN：[リスク名]（[高/中/低]リスク）
**ひとことサマリー**（1〜2行・非専門家向け）
**① リスクの説明と評価**（評価・理由・OWASP該当項目・現実的な影響）
**② 原因**（技術的・運用上・設定上の原因を平易に）
**③ 対応策**（優先順位付き：最優先・短期・中期・継続）

7. 優先対応ロードマップ（表）
8. 免責事項

出力時の最重要ルール：
1. 各リスクは必ず①〜③の構造で出力すること
2. 攻撃事例・損害額は記載しないこと
3. 確認済み・推定・未確認を明確に分けること
4. 専門用語には短い注釈を付けること
`.trim();

// ── ページ取得 ──────────────────────────────────────
async function fetchPage(targetUrl) {
  try {
    const res = await fetch(targetUrl, {
      headers: { 'User-Agent': 'Mozilla/5.0 (compatible; SecurityReviewBot/1.0)', 'Accept': 'text/html' },
      signal: AbortSignal.timeout(15000),
    });
    const text = await res.text();
    return { html: text.slice(0, 10000), status: res.status };
  } catch (e) {
    return { html: '', status: 0 };
  }
}

// ── HTTPヘッダー取得 ────────────────────────────────
async function fetchHeaders(targetUrl) {
  try {
    const res = await fetch(targetUrl, {
      method: 'HEAD',
      headers: { 'User-Agent': 'Mozilla/5.0' },
      signal: AbortSignal.timeout(10000),
      redirect: 'follow',
    });
    let headers = `HTTP/1.1 ${res.status} ${res.statusText}\r\n`;
    res.headers.forEach((value, key) => {
      headers += `${key}: ${value}\r\n`;
    });
    return headers;
  } catch (e) {
    return '';
  }
}

// ── Anthropic API呼び出し ──────────────────────────
async function callClaude(userMessage, model, apiKey, simpleMode = false) {
  const tools = [{ type: 'web_search_20250305', name: 'web_search', max_uses: 3 }];
  const body = JSON.stringify({
    model,
    max_tokens: 32000,
    system: simpleMode ? SYSTEM_PROMPT_SIMPLE : SYSTEM_PROMPT,
    messages: [{ role: 'user', content: userMessage }],
    tools,
  });

  const res = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-api-key': apiKey,
      'anthropic-version': '2023-06-01',
    },
    body,
    signal: AbortSignal.timeout(300000), // 5分タイムアウト
  });

  const data = await res.json();
  if (data.error) throw new Error(`API エラー: ${data.error.message}`);
  return (data.content || []).filter(b => b.type === 'text').map(b => b.text).join('\n');
}

// ── ユーザーメッセージ組み立て ────────────────────
function buildUserMessage(config, pageHtml, headers) {
  return `
以下の診断対象について、システム指示に従いDeep Researchを実施し、完全な脆弱性診断レポートを出力してください。

【診断対象URL】
${config.url}

【所有区分】
${config.ownershipLabel}

【補足メモ（リスク評価・損害額補正・対応策に必ず反映してください）】
${config.notes || '（なし）'}

【取得した公開HTMLソース（先頭20,000文字）】
${pageHtml || '（取得できませんでした。URLから推定できる範囲で診断し、必ず「推定」と明記してください）'}

【取得したHTTPレスポンスヘッダー】
${headers || '（取得できませんでした。各ヘッダー項目は「未確認」と記載してください）'}

━━━ 実行手順 ━━━
① 上記HTMLとヘッダーから技術スタックを特定
② 各ヘッダーの設定状況を一つずつ確認・記録
③ 技術スタック別にWeb検索で最新CVE・攻撃事例を調査
④ 気になった点は自律的に追加調査
⑤ OWASP・NVD・JPCERT/CC・IPA・IBM等の公的統計で事例と損害額を裏取り
⑥ 補足メモ「${config.notes || 'なし'}」の内容を踏まえてリスク優先度と損害額レンジを補正
⑦ 「確認済み」「推定」「未確認」の区別を確認してからレポートを出力

必ずシステム指示のレポート形式（セクション1〜9）に従って出力してください。
専門用語の初出には必ず（）で注釈を付け、非専門家にも理解できる言葉で書いてください。
`.trim();
}

// ── HTMLを応答から抽出 ──────────────────────────────
function extractHtml(report) {
  const doctypeIdx = report.search(/<!DOCTYPE/i);
  const htmlTagIdx = report.search(/<html[\s>]/i);
  const startIdx   = doctypeIdx >= 0 ? doctypeIdx : htmlTagIdx >= 0 ? htmlTagIdx : -1;

  if (startIdx < 0) return { html: report, isHtml: false };

  let html = report.slice(startIdx).trim().replace(/\s*```\s*$/, '');
  if (!/\/html>/i.test(html)) html += '\n</body>\n</html>';

  return { html, isHtml: true };
}

// ── Workers ハンドラー ──────────────────────────────
export default {
  async fetch(request, env) {
    const corsHeaders = {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
    };

    // CORS プリフライト
    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: corsHeaders });
    }

    const url = new URL(request.url);

    // ── /diagnose エンドポイント ──
    if (request.method === 'POST' && url.pathname === '/diagnose') {
      try {
        const config = await request.json();

        // APIキー：リクエスト本文 → Workers Secret の順で取得
        const apiKey = config.apiKey || env.ANTHROPIC_API_KEY;
        if (!apiKey) {
          return new Response(
            JSON.stringify({ error: 'APIキーが設定されていません。入力欄に入力するか、WorkersのSecretに ANTHROPIC_API_KEY を設定してください。' }),
            { status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json; charset=utf-8' } }
          );
        }

        // ページ取得
        const { html: pageHtml } = await fetchPage(config.url);

        // HTTPヘッダー取得
        const headersStr = await fetchHeaders(config.url);

        // Claude API呼び出し
        const rawReport = await callClaude(
          buildUserMessage(config, pageHtml, headersStr),
          config.model || 'claude-sonnet-4-6',
          apiKey,
          config.simpleMode || false
        );

        // HTMLを抽出
        const { html: finalReport, isHtml } = extractHtml(rawReport);

        return new Response(
          JSON.stringify({ report: finalReport, isHtml }),
          { headers: { ...corsHeaders, 'Content-Type': 'application/json; charset=utf-8' } }
        );

      } catch (e) {
        return new Response(
          JSON.stringify({ error: e.message }),
          { status: 500, headers: { ...corsHeaders, 'Content-Type': 'application/json; charset=utf-8' } }
        );
      }
    }

    // ルート：動作確認用
    if (url.pathname === '/') {
      return new Response('セキュリティ脆弱性診断サーバー稼働中 ✅', {
        headers: { 'Content-Type': 'text/plain; charset=utf-8' },
      });
    }

    return new Response('Not Found', { status: 404, headers: corsHeaders });
  },
};
