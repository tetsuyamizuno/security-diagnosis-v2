#!/usr/bin/env node
/**
 * server.js — セキュリティ脆弱性診断サーバー（構成C）
 *
 * 【起動方法】
 *   node server.js
 *
 * 【停止方法】
 *   node server.js stop
 *
 * 【ポート】
 *   デフォルト: 3001（常に同じポートを使用）
 */

const http    = require('http');
const https   = require('https');
const fs      = require('fs');
const path    = require('path');
const url     = require('url');
const { execSync } = require('child_process');

const PORT     = process.env.PORT || 3001;
const API_KEY  = process.env.ANTHROPIC_API_KEY;
const PROMPT_PATH = path.join(__dirname, 'security-diagnosis-prompt.md');
const PID_FILE = path.join(__dirname, 'server.pid');

// ── stop コマンド ──────────────────────────────────────
if (process.argv[2] === 'stop') {
  if (!fs.existsSync(PID_FILE)) {
    console.log('ℹ  サーバーは起動していません（server.pid が見つかりません）');
    process.exit(0);
  }
  const pid = parseInt(fs.readFileSync(PID_FILE, 'utf8').trim(), 10);
  try {
    process.kill(pid, 'SIGTERM');
    fs.unlinkSync(PID_FILE);
    console.log(`✅ サーバーを停止しました（PID: ${pid}）`);
  } catch (e) {
    console.log(`ℹ  プロセス（PID: ${pid}）はすでに終了しています`);
    fs.unlinkSync(PID_FILE);
  }
  process.exit(0);
}

// ── 起動前に前回のサーバーを自動停止 ──────────────────
if (fs.existsSync(PID_FILE)) {
  const oldPid = parseInt(fs.readFileSync(PID_FILE, 'utf8').trim(), 10);
  try {
    process.kill(oldPid, 'SIGTERM');
    console.log(`🔄 前回のサーバー（PID: ${oldPid}）を停止しました`);
    // 少し待ってからポートが解放されるのを待つ
    const sleep = ms => new Promise(r => setTimeout(r, ms));
    const startWithDelay = async () => {
      await sleep(500);
      startServer();
    };
    startWithDelay();
  } catch (e) {
    // すでに終了していた場合はそのまま起動
    fs.unlinkSync(PID_FILE);
    startServer();
  }
} else {
  startServer();
}

// ── 起動チェック ──────────────────────────────────────
function checkRequirements() {
  if (!fs.existsSync(PROMPT_PATH)) {
    console.error('❌ security-diagnosis-prompt.md が見つかりません。同じフォルダに置いてください。');
    process.exit(1);
  }
  if (!API_KEY) {
    console.log('ℹ  ANTHROPIC_API_KEY 未設定 — ブラウザの入力欄からAPIキーを受け取ります。');
  }
}

function startServer() {
  checkRequirements();

// ── システムプロンプト（改訂版・Deep Research対応）────────────
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
curl -sSI -L で以下を確認：Server/X-Powered-By/Content-Security-Policy/Strict-Transport-Security/X-Frame-Options/X-Content-Type-Options/Referrer-Policy/Permissions-Policy/Set-Cookie/Cache-Control/Cross-Origin-Opener-Policy/Cross-Origin-Resource-Policy/Cross-Origin-Embedder-Policy
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
□ 「このサイトにおける現実的な影響」が補足情報を踏まえた具体的な記述になっているか
□ 各リスクに「ひとことサマリー」が入っているか
□ 対応策は実行可能な具体策になっているか
□ 専門用語に注釈があるか
□ レポートは非専門家（経営者・担当者）が読んで理解できる構成か

━━━ 出力形式：完全なHTMLドキュメント ━━━

【重要】必ず完全な HTML ドキュメントとして出力してください。
【重要】出力は必ず <!DOCTYPE html> から始め、必ず </html> で終わってください。
【重要】コードフェンス（3連バッククォート）で囲まないでください。
【重要】HTMLの前後に説明文・思考過程・コメントを一切書かないでください。HTMLドキュメントのみを出力してください。
【重要】各セクションの文章は簡潔にまとめ、HTMLが途中で切れないようにしてください。リスクカードの説明は1リスクあたり400字以内を目安にしてください。
【文字使用規則】テキストに使用できる文字は、常用漢字・ひらがな・カタカナ・英数字・基本的なASCII記号（- . , : ; ! ? ( ) [ ] / % @ # &）のみです。Geometric Shapes（幾何学図形）・Miscellaneous Symbols（装飾記号）などのUnicode記号ブロックの文字は一切使用禁止です。強調には必ず&lt;strong&gt;タグを使用してください。
【重要】必ずセクション9（免責事項）と </html> まで出力を完了してください。途中で切れないようにしてください。各リスクの説明は簡潔にまとめ、出力が完結するよう優先してください。

以下のデザイン仕様に従ってください：

【カラー設計】
- 高リスク：#D64045（赤系）/ 背景rgba(214,64,69,.09)
- 中リスク：#E09F3E（アンバー系）/ 背景rgba(224,159,62,.09)
- 低リスク：#4CAF82（緑系）/ 背景rgba(76,175,130,.09)
- アクセント：#2D6A8F（ティール・ネイビー系）
- 背景：#F7F5F0（オフホワイト）
- 本文：#1E2A35（ダークネイビー）

【フォント】
@import url('https://fonts.googleapis.com/css2?family=Noto+Sans+JP:wght@300;400;500;700&family=Noto+Serif+JP:wght@400;600;700&family=JetBrains+Mono:wght@400;600;700&display=swap');
- 見出し：Noto Serif JP
- 本文：Noto Sans JP（font-size:16px・line-height:1.95）
- コード・ラベル：JetBrains Mono

【レイアウト】
- 最大幅960px・中央寄せ
- カバーページ：ダーク背景（linear-gradient(155deg,#0F1923,#162436)）に白文字
- スコアバー：高/中/低リスク件数を光るドット付きで表示
- 各リスクはカード形式（border-radius:12px・box-shadow付き）
- リスク評価バッジ：色付きで目立つように（font-family:JetBrains Mono）
- 表：全項目罫線あり・ヘッダー行を濃色（#1E2A35）で
- セクション番号：JetBrains Monoで小さく表示

【必須要素】
- 最上部にPDFダウンロードボタン（onclick="window.print()"）
- 確認済み／推定／未確認バッジ（色分けされたspanタグ）
- 各リスクカードの冒頭に「ひとことサマリー」（左ボーダー色付き）
- 攻撃事例は左ボーダー付きカードで視覚的に区別
- 損害額は金額を右揃えのグリッドで表示
- @media print でカバー背景色・バッジ色を保持

【HTML構造】
<!DOCTYPE html>
<html lang="ja">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>セキュリティ脆弱性診断レポート — [ドメイン名]</title>
  <style>/* 上記デザイン仕様のCSS全文 */</style>
</head>
<body>
  <!-- PDFボタン -->
  <!-- カバー（ダーク背景） -->
  <!-- スコアバー -->
  <!-- メインコンテンツ（max-width:960px・中央寄せ） -->
    <!-- セクション1〜9 -->
  <!-- フッター -->
</body>
</html>

━━━ レポート出力形式（HTML セクション構成） ━━━

## 1. 冒頭注記
- 本診断は非侵襲診断である旨
- 公開HTML・HTTPヘッダー・公開JavaScript/CSS・公開情報に基づく診断である旨
- サーバー側ソースコード等は確認していない旨（該当する場合）
- OWASP Top 10は分類枠組みとして参照している旨
- 損害額は公的統計に基づく推計である旨
- 他社サイトの場合は「公開情報に基づく教育・防御目的の整理」を**太字**で

## 2. 診断範囲・取得状況（表）
| 項目 | 実施状況 | 結果 | 備考 |
で以下を出力：公開HTML取得/HTTPヘッダー取得/公開JS・CSS確認/外部script確認/外部link確認/iframe確認/サーバー側コード確認（未実施・対象外）/認証・フォーム送信テスト（未実施・対象外）/ポートスキャン（未実施・対象外）

## 3. 対象サマリー（表）
URL/所有区分/入力された補足情報（補足メモの内容を記載）/補足情報がリスク評価に与えた影響（どのリスクをどう補正したかを簡潔に）/サイト種別/主な機能/フォーム有無/ログイン有無/決済有無/採用ページ有無/確認された技術スタック/推定される技術スタック/未確認項目

## 4. HTML・公開リソース分析結果（表）
title/meta description/generator meta/HTMLコメント内情報/エラーメッセージ/メールアドレス露出/APIキー・トークンらしき文字列/Framework/CMS/GTM/Analytics/Auth/Payment/External Scripts/External Links/iframe
各項目に「確認済み／推定／未確認」を明記

## 5. HTTPヘッダー分析結果（表）
全ヘッダーについて「あり／なし／未確認」を明記。取得できなかった場合は必ず「未確認」と記載。

## 6. リスク一覧（高→中→低の順）

各リスクは必ず以下の構造で出力すること：

### リスクN：[リスク名]（[高/中/低]リスク）

**ひとことサマリー**
（1〜2行で「何が起きうるか」を非専門家向けに平易に書く。専門用語は使わない）

**① リスクの説明と評価**
- 評価：高／中／低
- 理由：
- OWASP該当項目：A0X: [項目名]
- このサイトにおける現実的な影響：（補足メモの内容を反映して具体的に）

**② 実際にあった攻撃事例**（実在する事例のみ・出典必須・確認できない事例は書かない）
1. [事例名]
   - 発生時期：
   - 概要：
   - このリスクとの関連：
   - 出典：
2. [事例名]（同上）
3. [事例名]（同上）

**③ 想定される損害額**
- 参考統計：
- 統計上の参考額：
- このサイトへの補正：（補足メモの内容を反映）
- 想定損害額レンジ：
- 注意書き：（推計である旨）

**④ 原因**
技術的な原因／運用上の原因／設定上の原因を、非専門家向けに説明。専門用語には注釈。

**⑤ 対応策**（優先順位付き）
1. 最優先対応：期限・実施内容・担当候補
2. 短期対応：期限・実施内容・担当候補
3. 中期対応：期限・実施内容・担当候補
4. 継続対応：頻度・実施内容・担当候補

## 7. 優先対応ロードマップ（表）
| 優先度 | リスク名 | 評価 | 推奨対応期限 | 中核となる対策 | 担当候補 |

## 8. 社内で追加確認すべき項目
自社サイトの場合、以下のカテゴリで確認項目を提示。補足情報・サイトの特徴を踏まえて特に重要な項目を強調すること。

【リポジトリ】package.json・lockfile・フレームワークバージョン・Dependabot/Renovate設定・Secrets混入チェック
【インフラ】ホスティング・CDN・WAF・DNS・TLS証明書・HTTPセキュリティヘッダー・ログ保存設定
【フォーム】送信先・保存先・通知先・アクセス権限・保存期間・スパム対策・個人情報の暗号化
【認証】管理画面・MFA・権限管理・退職者アカウント・OAuth設定・セッション管理
【メール】SPF・DKIM・DMARC・類似ドメイン監視・フィッシング報告窓口
【監視】アクセスログ・エラーログ・WAFログ・改ざん検知・外形監視・アラート通知先
【外部サービス】GTM・Analytics・CRM・MAツール・採用管理ツール・CDN・ホスティング・SaaS管理者一覧

【補足情報に応じた追加確認項目（該当する場合は必ず追記・強調）】

AI関連企業の場合：
- 顧客データの保存場所・プロンプトの保存有無・学習データへの利用有無
- 外部AI APIへの送信範囲・PoCデータの取り扱い・顧客別データ分離
- ログのマスキング・AI利用規程・顧客契約との整合性・従業員の外部AIツール利用ルール

医療・ヘルスケア系の場合：
- 個人情報保護法・医療法・HIPAA等の規制対応
- 患者データの匿名化・暗号化・アクセスログの医療特有要件

金融・決済系の場合：
- PCI DSS準拠状況・金融庁・財務局への報告義務・不正検知システムの有無

採用活動が活発な場合：
- 応募者の個人情報管理・保存期間・採用管理ツールのアクセス権限
- 採用詐欺・偽採用サイトの監視

## 9. 免責事項
本レポートは公開情報および非侵襲的な確認に基づく一次診断であり、実際の脆弱性の存在を断定するものではありません。サーバー側ソースコード・非公開リポジトリ・環境変数・クラウド設定等を確認していない場合それらは診断対象外です。最終的な判断には管理者権限を持つ担当者による設定確認・ソースコードレビュー・必要に応じた許可済みペネトレーションテストが必要です。

━━━ 出力時の最重要ルール ━━━
1. 各リスクは必ず①〜⑤の構造で出力すること
2. 各リスクの冒頭に「ひとことサマリー」を必ず入れること（1〜2行・非専門家向け・平易な言葉）
3. 各リスクに実在する攻撃事例を3つ記載すること
4. 各攻撃事例には出典を付けること
5. 出典が確認できない事例は書かないこと
6. 損害額は統計に基づく推計として記載すること
7. 補足情報・サイトの特徴をリスク評価・損害額補正・対応策・確認項目に必ず反映すること
8. 「このサイトにおける現実的な影響」は補足情報を踏まえた具体的な内容にすること（抽象的な一般論にしない）
9. 確認済み・推定・未確認を明確に分けること
10. サーバー側コードを見ていないのにソースコード全体を分析したと書かないこと
11. HTTPヘッダー未取得の場合は未確認と書くこと
12. 技術スタックを根拠なく断定しないこと
13. 専門用語には短い注釈を付けること
14. Deep Researchにより最新の公的情報・一次情報・ベンダー公式情報を確認すること
15. 古い情報を使う場合は古い情報であることを明記すること
16. レポートは非専門家（経営者・担当者）が読んで理解できる構成にすること
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
【文字使用規則】テキストに使用できる文字は、常用漢字・ひらがな・カタカナ・英数字・基本的なASCII記号のみです。Geometric Shapes・Miscellaneous SymbolsなどのUnicode記号ブロックの文字は一切使用禁止です。強調には&lt;strong&gt;タグを使用してください。

デザイン仕様：
- 高リスク：#D64045 / 中リスク：#E09F3E / 低リスク：#4CAF82 / アクセント：#2D6A8F
- 背景：#F7F5F0 / 本文：#1E2A35
- フォント：Noto Sans JP（本文16px）・Noto Serif JP（見出し）・JetBrains Mono（コード）
- 最大幅960px・中央寄せ・カバーダーク背景・スコアバー・リスクカード形式
- 最上部にPDFダウンロードボタン（window.print()）

以下の構成で出力してください：

## 1. 冒頭注記
本診断は非侵襲診断であること、公開情報に基づく一次診断であること、OWASP Top 10は分類枠組みとして参照していること

## 2. 診断範囲・取得状況（表）

## 3. 対象サマリー（表）
URL/所有区分/サイト種別/主な機能/フォーム有無/ログイン有無/決済有無/確認された技術スタック/推定される技術スタック/未確認項目

## 4. HTML・公開リソース分析結果（表）

## 5. HTTPヘッダー分析結果（表）

## 6. リスク一覧（高→中→低の順）

各リスクは以下の構造で出力すること：

### リスクN：[リスク名]（[高/中/低]リスク）

**ひとことサマリー**（1〜2行・非専門家向け）

**① リスクの説明と評価**
- 評価・理由・OWASP該当項目・このサイトにおける現実的な影響

**② 原因**
技術的・運用上・設定上の原因を平易に説明。専門用語には注釈。

**③ 対応策**（優先順位付き）
1. 最優先対応：期限・実施内容・担当候補
2. 短期対応：期限・実施内容・担当候補
3. 中期対応：期限・実施内容・担当候補
4. 継続対応：頻度・実施内容・担当候補

## 7. 優先対応ロードマップ（表）
| 優先度 | リスク名 | 評価 | 推奨対応期限 | 中核となる対策 | 担当候補 |

## 8. 免責事項

出力時の最重要ルール：
1. 各リスクは必ず①〜③の構造で出力すること
2. 各リスクの冒頭に「ひとことサマリー」を必ず入れること
3. 攻撃事例・損害額は記載しないこと
4. 確認済み・推定・未確認を明確に分けること
5. 専門用語には短い注釈を付けること
6. レポートは非専門家が読んで理解できる構成にすること
`.trim();

// ── ページ取得 ────────────────────────────────────────
async function fetchPage(targetUrl) {
  return new Promise(resolve => {
    try {
      const client = targetUrl.startsWith('https') ? https : http;
      const req = client.get(targetUrl, {
        headers: { 'User-Agent': 'Mozilla/5.0 (compatible; SecurityReviewBot/1.0)', 'Accept': 'text/html' },
        timeout: 15000
      }, res => {
        let data = '';
        res.on('data', chunk => data += chunk);
        res.on('end', () => resolve({ html: data.slice(0, 10000), status: res.statusCode }));
      });
      req.on('error', e => { console.log(`  ⚠ ページ取得エラー: ${e.message}`); resolve({ html: '', status: 0 }); });
      req.on('timeout', () => { req.destroy(); resolve({ html: '', status: 0 }); });
    } catch(e) { resolve({ html: '', status: 0 }); }
  });
}

// ── HTTPヘッダー取得（Node.js標準モジュール使用・curl不要）──
async function fetchHeaders(targetUrl) {
  return new Promise(resolve => {
    try {
      const client = targetUrl.startsWith('https') ? https : http;
      const req = client.request(targetUrl, {
        method: 'HEAD',
        headers: { 'User-Agent': 'Mozilla/5.0 (compatible; SecurityReviewBot/1.0)' },
        timeout: 10000
      }, res => {
        let result = `HTTP/${res.httpVersion} ${res.statusCode} ${res.statusMessage}\r\n`;
        Object.entries(res.headers).forEach(([k, v]) => {
          result += `${k}: ${Array.isArray(v) ? v.join(', ') : v}\r\n`;
        });
        resolve(result.slice(0, 5000));
      });
      req.on('error', e => { console.log(`  ⚠ ヘッダー取得エラー: ${e.message}`); resolve(''); });
      req.on('timeout', () => { req.destroy(); resolve(''); });
      req.end();
    } catch(e) {
      console.log('  ⚠ ヘッダー取得エラー');
      resolve('');
    }
  });
}

// ── Gemini API呼び出し ──────────────────────────────
async function callClaude(userMessage, model, apiKey, simpleMode = false) {
  return new Promise((resolve, reject) => {
    const resolvedKey = apiKey || API_KEY;
    if (!resolvedKey) { reject(new Error('APIキーが設定されていません。入力欄にGemini APIキーを入力してください。')); return; }

    // 標準版・シンプル版ともにGoogle Search grounding（Web検索1回相当）
    const bodyObj = {
      contents: [{ role: 'user', parts: [{ text: userMessage }] }],
      systemInstruction: { parts: [{ text: simpleMode ? SYSTEM_PROMPT_SIMPLE : SYSTEM_PROMPT }] },
      generationConfig: { maxOutputTokens: 24000, temperature: 0.7 },
      tools: [{ googleSearch: {} }]
    };
    const bodyStr = JSON.stringify(bodyObj);
    const modelName = model || 'gemini-2.0-flash';
    const options = {
      hostname: 'generativelanguage.googleapis.com',
      path: `/v1beta/models/${modelName}:generateContent?key=${resolvedKey}`,
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(bodyStr)
      }
    };
    const req = https.request(options, res => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
          const parsed = JSON.parse(data);
          if (parsed.error) { reject(new Error(`API エラー: ${parsed.error.message}`)); return; }
          const text = (parsed.candidates?.[0]?.content?.parts || [])
            .filter(p => p.text).map(p => p.text).join('\n');
          resolve(text);
        } catch(e) { reject(new Error(`レスポンスのパースに失敗: ${e.message}`)); }
      });
    });
    req.on('error', reject);
    req.write(bodyStr);
    req.end();
  });
}

// ── ユーザーメッセージ組み立て ──────────────────────
function buildUserMessage(config, pageHtml, headers) {
  return `
以下の診断対象について、システム指示に従いDeep Researchを実施し、完全な脆弱性診断レポートを出力してください。

【診断対象URL】
${config.url}

【所有区分】
${config.ownershipLabel}

【補足メモ（リスク評価・損害額補正・対応策に必ず反映してください）】
${config.notes || '（なし）'}

【取得した公開HTMLソース（先頭40,000文字）】
${pageHtml || '（取得できませんでした。URLから推定できる範囲で診断し、必ず「推定」と明記してください）'}

【取得したHTTPレスポンスヘッダー】
${headers || '（取得できませんでした。各ヘッダー項目は「未確認」と記載してください）'}

━━━ 実行手順 ━━━
① 上記HTMLとヘッダーから技術スタックを特定（GTMコンテナID・外部スクリプト読み込み元・metaタグ等）
② 各ヘッダーの設定状況を一つずつ確認・記録
③ 特定した技術スタック別にWeb検索で最新CVE・攻撃事例を調査（システム指示の技術スタック別Deep Research方針に従う）
④ 気になった点は指示リストにない内容でも自律的に追加調査
⑤ OWASP・NVD・JPCERT/CC・IPA・IBM・Verizon DBIR等の公的統計で事例と損害額を裏取り
⑥ 補足メモ「${config.notes || 'なし'}」の内容を踏まえてリスク優先度と損害額レンジを補正
⑦ 「確認済み」「推定」「未確認」の区別を確認してからレポートを出力

必ずシステム指示のレポート形式（セクション1〜9）に従って出力してください。
専門用語の初出には必ず（）で注釈を付け、非専門家にも理解できる言葉で書いてください。
`.trim();
}

// ── HTTPサーバー ─────────────────────────────────────
const server = http.createServer(async (req, res) => { // eslint-disable-line

  // CORS設定（input.htmlからのリクエストを許可）
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') { res.writeHead(204); res.end(); return; }

  const parsedUrl = url.parse(req.url);

  // ── /diagnose エンドポイント ──
  if (req.method === 'POST' && parsedUrl.pathname === '/diagnose') {
    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', async () => {
      try {
        const config = JSON.parse(body);
        console.log('');
        console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
        console.log('  診断開始');
        console.log(`  URL    : ${config.url}`);
        console.log(`  区分   : ${config.ownershipLabel}`);
        console.log(`  モデル : ${config.model}`);
        console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');

        // STEP1: ページ取得
        console.log('📥 ページを取得中...');
        const { html: pageHtml } = await fetchPage(config.url);
        console.log(`   取得完了（${pageHtml.length}文字）`);

        // STEP2: ヘッダー取得
        console.log('📋 HTTPヘッダーを確認中...');
        const headers = await fetchHeaders(config.url);
        console.log('   取得完了');

        // STEP3: Claude API呼び出し（常時 Deep Research）
        console.log('🔍 Deep Research + レポート作成中…（数分かかります）');
        const userMessage = buildUserMessage(config, pageHtml, headers);
        const report = await callClaude(userMessage, config.model, config.apiKey, config.simpleMode);
        console.log('✅ レポート生成完了');

        // HTMLドキュメントを応答テキストから抽出
        // 前後の説明文・コードフェンスを除去し、<!DOCTYPE または <html から始まる部分を取り出す
        let finalReport = report;

        const doctypeIdx = report.search(/<!DOCTYPE/i);
        const htmlTagIdx = report.search(/<html[\s>]/i);
        const startIdx   = doctypeIdx >= 0 ? doctypeIdx
                         : htmlTagIdx  >= 0 ? htmlTagIdx
                         : -1;

        if (startIdx >= 0) {
          finalReport = report.slice(startIdx).trim();
          // コードフェンスの閉じ ``` が末尾に残っている場合は除去
          finalReport = finalReport.replace(/\s*```\s*$/, '');
          // </html> がない（切れた）場合は補完
          if (!/\/html>/i.test(finalReport)) {
            finalReport += '\n</body>\n</html>';
            console.log('  ⚠ HTMLが途中で切れていたため </html> を補完しました');
          }
          if (startIdx > 0) {
            console.log(`  ℹ 先頭${startIdx}文字の説明文を除去してHTMLを抽出しました`);
          }
        }

        // HTMLドキュメントかどうか判定
        const trimmed = finalReport.trimStart();
        const isHtml = trimmed.startsWith('<!DOCTYPE') || trimmed.startsWith('<html');
        res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
        res.end(JSON.stringify({ report: finalReport, isHtml }));

      } catch(e) {
        console.error(`❌ エラー: ${e.message}`);
        res.writeHead(500, { 'Content-Type': 'application/json; charset=utf-8' });
        res.end(JSON.stringify({ error: e.message }));
      }
    });
    return;
  }

  // ── 静的ファイル配信 ──
  const staticFiles = {
    '/':                  { file: 'input.html',        type: 'text/html; charset=utf-8' },
    '/input.html':        { file: 'input.html',        type: 'text/html; charset=utf-8' },
    '/input-simple.html': { file: 'input-simple.html', type: 'text/html; charset=utf-8' },
  };
  if (req.method === 'GET' && staticFiles[parsedUrl.pathname]) {
    const { file, type } = staticFiles[parsedUrl.pathname];
    const filePath = path.join(__dirname, file);
    if (fs.existsSync(filePath)) {
      res.writeHead(200, { 'Content-Type': type });
      res.end(fs.readFileSync(filePath));
    } else {
      res.writeHead(404);
      res.end('File not found');
    }
    return;
  }

  // ── その他のリクエスト ──
  res.writeHead(404);
  res.end('Not Found');
});

  server.listen(PORT, () => {
    // PIDファイルに自分のPIDを保存
    fs.writeFileSync(PID_FILE, process.pid.toString(), 'utf8');

    console.log('');
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    console.log('  セキュリティ脆弱性診断サーバー 起動完了');
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    console.log(`  ポート  : ${PORT}`);
    console.log(`  PID     : ${process.pid}`);
    console.log(`  プロンプト: ${PROMPT_PATH}`);
    console.log('');
    console.log('  停止するには: node server.js stop');
    console.log('  1. input.html をブラウザで開く');
    console.log('  2. URLと条件を入力して「レポートを生成する」を押す');
    console.log('  3. 新しいタブでレポートが表示されたら「PDFで保存」を押す');
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  });

  server.on('error', err => {
    if (err.code === 'EADDRINUSE') {
      console.error(`❌ ポート ${PORT} はまだ使用中です。数秒待ってから再度お試しください。`);
    } else {
      console.error(`❌ サーバーエラー: ${err.message}`);
    }
    process.exit(1);
  });

  // ── 終了時にPIDファイルを削除 ──────────────────────────
  const cleanup = () => {
    try { fs.unlinkSync(PID_FILE); } catch (e) { /* 既に削除済み */ }
    process.exit(0);
  };
  process.on('SIGTERM', cleanup);
  process.on('SIGINT',  cleanup);  // Ctrl+C

} // startServer() の閉じ括弧
