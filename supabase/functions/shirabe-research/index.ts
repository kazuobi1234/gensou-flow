// Supabase Edge Function: shirabe-research
// Firebase ID token is verified server-side. Never put Gemini keys in the browser.
import { decodeProtectedHeader, importX509, jwtVerify } from "npm:jose@5.9.6";

const PROJECT_ID = "gensou-flow";
const CERT_URL = "https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com";
const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};
const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { ...corsHeaders, "Content-Type": "application/json; charset=utf-8" },
  });

async function verifyFirebaseUser(request: Request): Promise<boolean> {
  const allowedUid = Deno.env.get("ALLOWED_FIREBASE_UID");
  if (!allowedUid) throw new Error("ALLOWED_FIREBASE_UID is not configured");
  const match = /^Bearer (\S+)$/.exec(request.headers.get("Authorization") || "");
  if (!match) return false;
  const token = match[1];
  const header = decodeProtectedHeader(token);
  if (header.alg !== "RS256" || typeof header.kid !== "string") return false;
  const certResponse = await fetch(CERT_URL);
  if (!certResponse.ok) throw new Error("Firebase public certificates unavailable");
  const certificates = await certResponse.json() as Record<string, string>;
  const certificate = certificates[header.kid];
  if (!certificate) return false;
  const key = await importX509(certificate, "RS256");
  const { payload } = await jwtVerify(token, key, {
    algorithms: ["RS256"],
    audience: PROJECT_ID,
    issuer: `https://securetoken.google.com/${PROJECT_ID}`,
  });
  const now = Math.floor(Date.now() / 1000);
  return payload.sub === allowedUid &&
    typeof payload.iat === "number" && payload.iat <= now &&
    typeof payload.auth_time === "number" && payload.auth_time <= now;
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  if (req.method !== "POST") return json({ error: "Method not allowed" }, 405);
  try {
    if (!await verifyFirebaseUser(req)) return json({ error: "ログイン認証に失敗しました" }, 401);
  } catch (error) {
    console.error("Authentication failed:", error instanceof Error ? error.message : "unknown");
    return json({ error: "ログイン認証に失敗しました" }, 401);
  }

  const apiKey = Deno.env.get("GEMINI_API_KEY");
  if (!apiKey) return json({ error: "Gemini API key is not configured" }, 503);
  let body: Record<string, unknown>;
  try {
    body = await req.json();
  } catch {
    return json({ error: "JSON形式で送信してください" }, 400);
  }
  const productName = typeof body.productName === "string" ? body.productName.trim() : "";
  const request = typeof body.request === "string" ? body.request.trim() : "";
  if (!productName || !request || productName.length > 150 || request.length > 2000) {
    return json({ error: "商品名（150文字以内）と調査依頼（2000文字以内）が必要です" }, 400);
  }

  const prompt = `あなたは「幻想 AIカンパニー」の市場調査担当「シラベ」です。
社長は九軒（くのぎ）。主にEtsy向けのデジタル商品を検討しています。
商品名: ${productName}
依頼: ${request}
次の項目を日本語で簡潔に回答してください。
■ 調査結果 ■ 想定顧客 ■ 需要の見込み ■ 競合について ■ 価格について
■ 商品化する場合の強み ■ 注意点 ■ シラベから社長への提案
実際のWeb検索は実行していません。市場データや競合価格を確認済みと偽らず、推測は推測と明記してください。`;

  try {
    const response = await fetch(
      `https://generativelanguage.googleapis.com/v1beta/models/gemini-3.1-flash-lite:generateContent?key=${encodeURIComponent(apiKey)}`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          contents: [{ parts: [{ text: prompt }] }],
          generationConfig: { maxOutputTokens: 1800 },
        }),
      },
    );
    const data = await response.json();
    if (!response.ok) {
      console.error("Gemini API status:", response.status);
      return json({ error: "Gemini APIの呼び出しに失敗しました", status: response.status }, 502);
    }
    const result = (data?.candidates?.[0]?.content?.parts || [])
      .map((part: { text?: string }) => part.text || "").join("\n").trim();
    if (!result) return json({ error: "シラベの回答が空でした" }, 502);
    return json({ employee: "シラベ", productName, result });
  } catch (error) {
    console.error("Research request failed:", error instanceof Error ? error.message : "unknown");
    return json({ error: "調査処理に失敗しました" }, 502);
  }
});
