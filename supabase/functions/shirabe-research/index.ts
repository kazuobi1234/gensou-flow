import { decodeProtectedHeader, importX509, jwtVerify } from "npm:jose@5.9.6";

const PROJECT_ID = "gensou-flow";
const CERT_URL =
  "https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), {
    status,
    headers: {
      ...corsHeaders,
      "Content-Type": "application/json; charset=utf-8",
    },
  });

async function verifyFirebaseUser(request: Request): Promise<boolean> {
  const allowedUid = Deno.env.get("ALLOWED_FIREBASE_UID");

  if (!allowedUid) {
    throw new Error("ALLOWED_FIREBASE_UID is not configured");
  }

  const match = /^Bearer (\S+)$/.exec(
    request.headers.get("Authorization") || "",
  );

  if (!match) return false;

  const token = match[1];
  const header = decodeProtectedHeader(token);

  if (header.alg !== "RS256" || typeof header.kid !== "string") {
    return false;
  }

  const certResponse = await fetch(CERT_URL);

  if (!certResponse.ok) {
    throw new Error("Firebase public certificates unavailable");
  }

  const certificates =
    (await certResponse.json()) as Record<string, string>;

  const certificate = certificates[header.kid];

  if (!certificate) return false;

  const key = await importX509(certificate, "RS256");

  const { payload } = await jwtVerify(token, key, {
    algorithms: ["RS256"],
    audience: PROJECT_ID,
    issuer: `https://securetoken.google.com/${PROJECT_ID}`,
  });

  const now = Math.floor(Date.now() / 1000);

  return (
    payload.sub === allowedUid &&
    typeof payload.iat === "number" &&
    payload.iat <= now &&
    typeof payload.auth_time === "number" &&
    payload.auth_time <= now
  );
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }

  if (req.method !== "POST") {
    return json({ error: "Method not allowed" }, 405);
  }

  try {
    if (!(await verifyFirebaseUser(req))) {
      return json({ error: "ログイン認証に失敗しました" }, 401);
    }
  } catch (error) {
    console.error(
      "Authentication failed:",
      error instanceof Error ? error.message : "unknown",
    );

    return json({ error: "ログイン認証に失敗しました" }, 401);
  }

  const apiKey = Deno.env.get("GEMINI_API_KEY");

  if (!apiKey) {
    return json({ error: "Gemini API key is not configured" }, 503);
  }

  let body: Record<string, unknown>;

  try {
    body = await req.json();
  } catch {
    return json({ error: "JSON形式で送信してください" }, 400);
  }

  const productName =
    typeof body.productName === "string" ? body.productName.trim() : "";

  const request =
    typeof body.request === "string" ? body.request.trim() : "";

  if (
    !productName ||
    !request ||
    productName.length > 150 ||
    request.length > 2000
  ) {
    return json(
      {
        error:
          "商品名（150文字以内）と調査依頼（2000文字以内）が必要です",
      },
      400,
    );
  }

  const today = new Date().toISOString().slice(0, 10);
  // Explicit server-side opt-in only: search grounding can incur usage charges.
  const webEnabled = Deno.env.get("SHIRABE_ENABLE_GROUNDING") === "true";
  // Public YouTube metadata only. Two short searches max; no pagination.
  const youtubeKey = Deno.env.get("SHIRABE_YOUTUBE_API_KEY");
  const youtubeQueries = /彼岸|鳥居|狐月|神社|幻想|幽境|spider lily|shrine|torii/i.test(productName + " " + request)
    ? ["red spider lily torii", "Japanese shrine fantasy"]
    : [productName.slice(0, 55)];
  let youtubeFindings: Array<{title:string;url:string;publishedAt:string;channel:string;query:string}> = [];
  let youtubeStatus = youtubeKey ? "未実施" : "未接続（APIキー未設定）";
  if (youtubeKey) {
    const failures: string[] = [];
    for (const query of youtubeQueries) {
      try {
        const u = new URL("https://www.googleapis.com/youtube/v3/search");
        u.searchParams.set("part","snippet");
        u.searchParams.set("type","video");
        u.searchParams.set("maxResults","5");
        u.searchParams.set("q",query);
        u.searchParams.set("key",youtubeKey);
        const yt = await fetch(u,{signal:AbortSignal.timeout(8000)});
        if (!yt.ok) { failures.push("HTTP "+yt.status); continue; }
        const payload = await yt.json();
        for (const v of (Array.isArray(payload.items)?payload.items:[])) {
          if (typeof v?.id?.videoId !== "string") continue;
          const url="https://www.youtube.com/watch?v="+v.id.videoId;
          if (youtubeFindings.some(x=>x.url===url)) continue;
          youtubeFindings.push({title:String(v.snippet?.title||"").slice(0,180),url,publishedAt:String(v.snippet?.publishedAt||""),channel:String(v.snippet?.channelTitle||"").slice(0,100),query});
        }
      } catch { failures.push("通信エラー／タイムアウト"); }
    }
    youtubeStatus = failures.length ? "検索失敗あり："+failures.join(", ")+"／取得 "+youtubeFindings.length+"件" : youtubeFindings.length ? "公開動画メタデータ "+youtubeFindings.length+"件取得済み" : "検索成功・該当動画なし";
  }
  const youtubeEvidence = youtubeFindings.map((v,i)=>(i+1)+". "+v.title+" / "+v.channel+" / "+v.publishedAt+" / "+v.url+" / 検索語: "+v.query).join("\\n");
  // v14: the model cannot author the verified facts or the final verdict.
  // Only hypothesis text is generated. All evidence/status sections are assembled by code.
  const prompt = `
あなたはAIカンパニーの企画担当シラベです。現在日: ${today}。
商品名: ${productName}
依頼: ${request}
以下のYouTube公開動画メタデータは参考情報に限ります。再生数・人気・需要・Etsy売上は確認していません。
${youtubeEvidence || "取得なし"}
出力は企画案だけです。次の4つの見出しだけをこの順に書いてください。
④ 仮説・企画提案（未検証）
⑤ 推奨商品形式（暫定案・未検証）
⑥ 独自性ある制作案3案＋暫定推奨1案（未検証）
⑦ 次工程候補1〜3個＋完了基準（未検証）
各項目はアイデア・仮説として記述。市場規模・販売実績・需要・人気・競合数・価格相場・文化的意味など、今回検証していない事項を断定しない。
出典URLを生成しない。①②③の見出しや調査完了宣言を書かない。出品・公開・画像生成は実行しない。
`;

  try {
    const response = await fetch(
      `https://generativelanguage.googleapis.com/v1beta/models/gemini-3.1-flash-lite:generateContent?key=${encodeURIComponent(apiKey)}`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          contents: [
            {
              parts: [{ text: prompt }],
            },
          ],
          ...(webEnabled ? { tools: [{ google_search: {} }] } : {}),
          generationConfig: {
            maxOutputTokens: 2500,
          },
        }),
      },
    );

    const data = await response.json();

    if (!response.ok) {
      console.error("Gemini API status:", response.status);

      return json(
        {
          error: "Gemini APIの呼び出しに失敗しました",
          status: response.status,
        },
        502,
      );
    }

    const result =
      (data?.candidates?.[0]?.content?.parts || [])
        .map((part: { text?: string }) => part.text || "")
        .join("\n")
        .trim();

    if (!result) {
      return json({ error: "シラベの回答が空でした" }, 502);
    }

    const metadata = data?.candidates?.[0]?.groundingMetadata;
    const sources = webEnabled && Array.isArray(metadata?.groundingChunks)
      ? metadata.groundingChunks
          .map((chunk: { web?: { uri?: string; title?: string } }) => ({
            title: chunk.web?.title || "",
            url: chunk.web?.uri || "",
          }))
          .filter((source: { url: string }) => /^https:\/\//.test(source.url))
          .slice(0, 20)
      : [];
    const grounded = sources.length > 0;
    // Deterministic evidence boundary: AI text never appears in sections ①–③.
    const evidenceLines = youtubeFindings.map((v, i) =>
      (i + 1) + ". YouTube公開動画メタデータ: " + v.title +
      " / " + v.channel + " / " + v.publishedAt + " / " + v.url
    );
    const safeHypotheses = result.replace(/^[\\s\\S]*?(?=④\\s|④仮説)/, "").trim();
    const hypothesisText = /^④/.test(safeHypotheses)
      ? safeHypotheses
      : "④ 仮説・企画提案（未検証）\\n" + result;
    const report =
      "【調査モード：YouTube公開メタデータのみ／Etsy実売・一般Web未確認】\n" +
      "【YouTube API状況：" + youtubeStatus + "】\n" +
      "【調査日：" + today + "】\n\n" +
      "① 結論\n本調査未完了：制作判断は保留。Etsyの競合販売実績・需要は確認できません。\n\n" +
      "② 外部情報として実際に確認できた事実\n" +
      (evidenceLines.length ? evidenceLines.join("\n") : "取得なし") +
      "\n※動画の存在と公開メタデータだけを確認。人気・再生数・需要・実売は未確認。\n\n" +
      "③ Web確認が必要な未確認事項\nEtsyの類似商品の価格・販売実績・レビュー・需要、一般Webの動向、規約の最新内容。\n\n" +
      "【以下はAIの未検証の企画案であり、調査で確認された事実ではありません】\n" +
      hypothesisText +
      "\n\n【Google検索の参照元】\nなし（有料検索機能は使用していません）";
    return json({
      employee: "シラベ",
      productName,
      result: report,
      researchMode: "youtube_metadata_only",
      sources,
      youtubeStatus,
      youtubeFindings,
      searchedQueries: grounded ? (metadata?.webSearchQueries || []) : [],
    });
  } catch (error) {
    console.error(
      "Research request failed:",
      error instanceof Error ? error.message : "unknown",
    );

    return json({ error: "調査処理に失敗しました" }, 502);
  }
});