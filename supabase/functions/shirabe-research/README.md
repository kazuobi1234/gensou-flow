# シラベ：Firebase認証付きSupabase接続（準備中）

このブランチは**本番へ未反映**。Supabase上の既存の動作中Functionも変更していません。

## 安全な導入手順
1. Firebase Authenticationのユーザー一覧から**自分のUID**を確認する。IDトークン・APIキーは共有しない。
2. Supabase → Edge Functions → Secretsで `ALLOWED_FIREBASE_UID` にそのUIDを設定する。既存の `GEMINI_API_KEY` は維持する。
3. Supabase `shirabe-research` のコードをこの `index.ts` に置き換えてデプロイする。
4. Function Settingsの「Verify JWT with legacy secret」を**OFF**にする。これはFirebase IDトークンをSupabaseのJWTとして検証できないため。**Function内部で署名・発行者・対象プロジェクト・有効期限・UIDを検証**する実装がデプロイ済みであることを確認してからOFFにする。
5. 未ログイン時の401、別UIDの401、本人のFirebase IDトークンで200を確認する。認証トークンをチャットやGitHubに貼らない。
6. その後、幻想フローの調査ボタンをつなぐ（別PR）。

## 注意
- 認証済み本人のみ呼び出せる設計だが、短時間の連打制限・費用監視は別途必要。
- このFunctionはライブWeb検索を行わず、AIの推定を返す。
- Firebaseの公開設定（apiKey）とGeminiの秘密鍵は別物。Geminiの秘密鍵はSupabase Secretsだけに保存する。
- Etsyへの公開・Instagram投稿はこのFunctionでは行わない。
