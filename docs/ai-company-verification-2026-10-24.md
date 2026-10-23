# AIカンパニー接続状況・検証チェック（2026-10-24）

## 状態の区別
- GitHubにコードがある: 実装あり（デプロイ済みとは限らない）
- 過去のInstagram実投稿: 2026-10-21運用記録に投稿成功の報告あり（現在の認証有効性とは別）
- Instagram 5枚投稿UI: index.html に生成・申請・承認・公開・状態照会の処理あり
- 通常AI社員承認→直接公開: 連結していると断言しない。明示的な投稿専用承認と最終確認が必要
- Etsy: AI社員APIからのOAuth状態やショップ接続は確認不可。出品メモはEtsyへの反映ではない
- 分析自動化: 売上・広告・投稿実績の実データを取得する仕組みの稼働は未検証

## 次の検証（すべて本番公開なし）
1. AI社員の「サク」にInstagram APIの現状を報告させ、「過去の実投稿」「現時点の有効性」「通常フロー」を混同しないか確認
2. ヨウの出力の【INSTAGRAM_POST】を投稿下書きへ引き継げるか確認
3. 保存済み5枚カルーセルの画像数・画像URL検査と承認状態を確認
4. サーバーの投稿状態を照会し、公開操作を実施せず過去のMeta IDと照合
5. Etsy OAuthと店舗情報は正式な接続確認後にのみ「接続済み」と表示する

## リリース注意
- 本変更はAI社員プロンプトのステータス誤案内修正。Supabase Edge Functionのデプロイは別作業。
- EtsyまたはInstagramへの公開処理はこの変更に含めない。
- 本番確認の前に機密情報（APIトークン・認証キー）をGitHubへ書き込まない。

## 本番差分の追加調査（2026-10-24）
- Supabase project: Kunogi AI Company (lkynzlittlxhbpvnuajw), ACTIVE_HEALTHY。
- Edge Functions: company-ai v17、instagram-carousel v3、instagram-publish v12、instagram-publish-guard v7、instagram-image-upload v4、instagram-image-check v4 がACTIVE。
- Supabase 本番 company-ai のコードと GitHub main の company-ai/index.ts の文章が一致しない。GitHub に保存した修正をそのままデプロイしてはいけない。本番の変更を取り込んだ後で修正を適用すること。
- GitHub PR #50 はドラフトかつ mergeable=false。本番や main への反映は保留。
- 公開なしで検証するまでは「完全連携完成」と呼ばない。
