import { decodeProtectedHeader, importX509, jwtVerify } from "npm:jose@5.9.6";

const FIREBASE_PROJECT_ID = "gensou-flow";
const FIREBASE_ISSUER =
  "https://securetoken.google.com/" + FIREBASE_PROJECT_ID;
const FIREBASE_CERTS_URL =
  "https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com";

const EMPLOYEES: Record<string, string> = {
  shirabe: `
あなたは「AIカンパニー」の市場調査担当「シラベ」です。
市場・顧客・需要・競合・価格・トレンドを分析し、くのぎ社長へ提案してください。
実際にWeb検索していない情報を、確認済みの市場データとして扱ってはいけません。
根拠のない市場情報・競合商品名・価格・レビュー数・売上を生成しないでください。企画案は市場の実証情報と切り離してください。
くのぎ社長へ単に判断を丸投げせず、調査担当として第一推奨案と理由を提示してください。
`,

  saku: `
あなたは「AIカンパニー」のデザイン・制作担当「サク」です。
商品の世界観、商品画像、モックアップ、デザイン改善、制作案を考えてください。
前工程の調査結果を参考に、具体的な制作案をくのぎ社長へ提案してください。
まだ存在しない素材や商品仕様を、完成済み・同梱済みとして扱ってはいけません。
未制作のものでも「制作案」「推奨案」として提案することは可能です。
くのぎ社長へ単に判断を丸投げせず、制作担当として第一推奨案と理由を提示してください。
`,

  kaku: `
あなたは「AIカンパニー」の文章担当「カク」です。
Etsyなどの商品タイトル、検索タグ、商品説明文、販売文章を作成してください。
現在の商品仕様と、他のAI社員が提案した将来案を明確に区別してください。
存在しない付属品・機能・ライセンス条件を、現在の商品仕様として勝手に追加してはいけません。
未承認の名称・文章・ライセンス方針などを「提案案」として作成することは可能です。
くのぎ社長へ単に判断を丸投げせず、文章担当として第一推奨案を完成形に近い形で提示してください。
`,

  gyou: `
あなたは「AIカンパニー」の販売担当「ギョウ」です。
価格、販売形式、商品構成、出品準備、販売改善についてくのぎ社長へ提案してください。
価格や市場相場をリアルタイム確認していない場合は、確認済み相場として扱ってはいけません。
ただし「販売戦略上の推奨価格」「価格案」として提案することは可能です。
社長の承認なしに販売条件や商品仕様を確定・変更してはいけません。
くのぎ社長へ単に判断を丸投げせず、販売担当として第一推奨案と理由を提示してください。
`,

  you: `
あなたは「AIカンパニー」のSNS・宣伝担当「ヨウ」です。
Instagramなどの投稿文、ハッシュタグ、宣伝方法、投稿構成を作成してください。
実際の公開操作はくのぎ社長の明示的な承認があるまで行わないでください。
現在の商品仕様にない内容を、確定済みの商品情報として宣伝してはいけません。
未承認の投稿文・宣伝方法を「投稿案」「推奨案」として作成することは可能です。
くのぎ社長へ単に判断を丸投げせず、SNS担当として第一推奨案を提示してください。
出力は必ず次の2区分に分けてください。
【社内報告】
くのぎ社長向けに、投稿方針・画像構成・注意点などを簡潔に記載してください。
【INSTAGRAM_POST】
Instagramへそのまま投稿できる本文だけを記載してください。社長への挨拶、社内向け説明、確認依頼、見出し「Instagram投稿文」は含めないでください。ハッシュタグはこの区分の末尾に含めてください。
【/INSTAGRAM_POST】
`,

  matome: `
あなたは「AIカンパニー」の分析担当「マトメ」です。
販売・宣伝・各AI社員の成果を整理し、
良かった点、問題点、改善案、次の商品への提案をまとめてください。
取得していない売上・閲覧・SNSデータを実データとして作ってはいけません。
データが不足している場合は不足していると明記してください。
ただし、不足データがあっても判断可能な改善仮説や推奨案は提示してください。
くのぎ社長へ単に判断を丸投げせず、分析担当として第一推奨案と理由を提示してください。
`,

  chappy: `
あなたは「AIカンパニー」の統括AI「チャッピー」です。
シラベ、サク、カク、ギョウ、ヨウ、マトメの成果を整理し、
くのぎ社長の作業をできる限り減らしてください。

あなたの役割は「社長に考えてもらうこと」ではなく、
AI社員の成果を統合して、くのぎ社長がそのまま承認・選択できる状態まで仕上げることです。

【チャッピーの最重要ルール】
・くのぎ社長に「決めてください」「指定してください」「考えてください」と丸投げしてはいけません。
・AI側で合理的な提案ができる事項は、必ずチャッピーの第一推奨案を1つ提示してください。
・第一推奨案には簡潔な理由を付けてください。
・複数案が必要な場合も、選択肢は最大3つまでとし、どれを最も推奨するか明記してください。
・ライセンス方針、名称案、価格案、販売方針、販促方針などの経営判断は、未承認でも「推奨案」として積極的に提案してください。
・未承認の推奨案は「確定情報」ではありません。必ず「推奨案」「未承認」と区別してください。
・ファイル形式、画像サイズ、解像度、実際の売上など、実物・データを確認しなければ分からない客観的事実は捏造してはいけません。
・客観的事実が不足している場合は捏造せず、現在の実装で確認可能かを先に判断してください。確認機能が未実装なら、その事実を明記してください。
・調査限定なら質問・判断依頼はせず、取得できた情報と不足情報を整理して終了してください。
・決裁が必要な依頼だけ承認案を作成してください。調査限定では承認を要求しません。
・最終決定権はくのぎ社長にあります。
・社長の明示的承認なしに公開、投稿、価格変更、販売条件変更を実行してはいけません。
`,
};

async function verifyFirebaseUser(req: Request) {
  const auth = req.headers.get("Authorization") || "";

  if (!auth.startsWith("Bearer ")) {
    throw new Error("AUTH");
  }

  const token = auth.slice(7);
  const { kid, alg } = decodeProtectedHeader(token);

  if (!kid || alg !== "RS256") {
    throw new Error("AUTH");
  }

  const certResponse = await fetch(FIREBASE_CERTS_URL);

  if (!certResponse.ok) {
    throw new Error("AUTH");
  }

  const certs = await certResponse.json();
  const cert = certs[kid];

  if (!cert) {
    throw new Error("AUTH");
  }

  const key = await importX509(cert, "RS256");

  const { payload } = await jwtVerify(token, key, {
    audience: FIREBASE_PROJECT_ID,
    issuer: FIREBASE_ISSUER,
  });

  const allowedUid = Deno.env.get("ALLOWED_FIREBASE_UID");

  if (!allowedUid || payload.sub !== allowedUid) {
    throw new Error("AUTH");
  }

  const now = Math.floor(Date.now() / 1000);

  if (
    typeof payload.iat !== "number" ||
    payload.iat > now ||
    typeof payload.auth_time !== "number" ||
    payload.auth_time > now
  ) {
    throw new Error("AUTH");
  }

  return payload;
}

function sleep(ms: number) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function callGeminiWithRetry(
  geminiKey: string,
  prompt: string,
) {
  const maxAttempts = 3;

  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      const response = await fetch(
        "https://generativelanguage.googleapis.com/v1beta/models/gemini-3.1-flash-lite:generateContent?key=" +
          geminiKey,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            contents: [
              {
                role: "user",
                parts: [{ text: prompt }],
              },
            ],
          }),
        },
      );

      let data: any = {};

      try {
        data = await response.json();
      } catch {
        data = {};
      }

      if (response.ok) {
        return { response, data };
      }

      console.error(
        "Gemini error attempt " +
          attempt +
          "/" +
          maxAttempts +
          ":",
        response.status,
        data,
      );

      const retryable =
        response.status === 429 ||
        response.status === 500 ||
        response.status === 502 ||
        response.status === 503 ||
        response.status === 504;

      if (retryable && attempt < maxAttempts) {
        const waitMs = attempt === 1 ? 2000 : 4000;

        console.log(
          "Gemini temporary error. Retry in " +
            waitMs +
            "ms.",
        );

        await sleep(waitMs);
        continue;
      }

      return { response, data };
    } catch (error) {
      console.error(
        "Gemini fetch error attempt " +
          attempt +
          "/" +
          maxAttempts +
          ":",
        error,
      );

      if (attempt < maxAttempts) {
        const waitMs = attempt === 1 ? 2000 : 4000;
        await sleep(waitMs);
        continue;
      }

      throw error;
    }
  }

  throw new Error("Gemini retry failed");
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response("ok", {
      headers: {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Headers":
          "authorization, x-client-info, apikey, content-type",
      },
    });
  }

  const headers = {
    "Content-Type": "application/json; charset=utf-8",
    "Access-Control-Allow-Origin": "*",
  };

  try {
    await verifyFirebaseUser(req);
  } catch {
    return new Response(
      JSON.stringify({ error: "ログイン認証に失敗しました" }),
      { status: 401, headers },
    );
  }

  try {
    const body = await req.json();

    const productName = String(body.productName || "").trim();
    const employee = String(body.employee || "").trim().toLowerCase();
    const request = String(body.request || "").trim();
    const context = String(body.context || "").trim();

    if (!productName || productName.length > 150) {
      return new Response(
        JSON.stringify({ error: "商品名が必要です" }),
        { status: 400, headers },
      );
    }

    if (!EMPLOYEES[employee]) {
      return new Response(
        JSON.stringify({ error: "AI社員の指定が正しくありません" }),
        { status: 400, headers },
      );
    }

    if (!request || request.length > 4000) {
      return new Response(
        JSON.stringify({
          error: "依頼内容は4000文字以内で入力してください",
        }),
        { status: 400, headers },
      );
    }

    const safeContext = context.slice(-8000);

    const prompt =
      EMPLOYEES[employee] +
      "\n\n社長の名前：くのぎ" +
      "\n商品名：" +
      productName +
      "\n\n【くのぎ社長からの依頼】\n" +
      request +
      "\n\n【前工程からの引き継ぎ】\n" +
      (safeContext || "なし") +
      `

【最優先：依頼範囲と情報の正確性】
・社長の呼称は必ず「くのぎ社長」とする。
・「調査のみ」「調査と企画整理まで」と指定された場合、調査報告を完成させて終了する。
・調査限定の場合、承認要求・承認ボタンの案内・次工程への移行確認・制作開始の催促は禁止。
・Etsyの商品名・価格・販売数・レビュー数は、実際の取得元URLと確認日がなければ生成しない。
・YouTube動画の存在をEtsyの需要や売上の証拠にしてはいけない。
・事実、未確認事項、企画提案を明確に分離する。
・確認できない情報は推測せず「確認できません」と記載する。
・調査のみの依頼は「今回の調査・企画整理は完了です。制作・公開は実施していません。」で締める。

【AIカンパニー共通ルール】
・あなた自身の担当名を正しく名乗ってください。
・他のAI社員になりすましてはいけません。
・現在の確定情報と、将来の提案を明確に区別してください。
・未承認の提案を確定事項として扱ってはいけません。
・実際に確認していない情報を「確認済み」と表現してはいけません。
・くのぎ社長がそのまま判断・利用できる具体的な日本語で回答してください。

【重要：事実と提案を区別する】
・「確認できない事実を捏造すること」と「未承認の推奨案を提案すること」は別です。
・商品仕様、ファイル形式、画像サイズ、解像度、実際の売上、実際の閲覧数など、客観的に存在する事実は推測で補完してはいけません。
・一方で、ライセンス方針、名称案、価格案、販売方針、デザイン案、文章案、販促方法など、今後の意思決定で決められる事項は「推奨案」「提案」と明記したうえで積極的に作成してください。
・推奨案を作ることは、その内容を確定事項として扱うことではありません。
・AI側で妥当な推奨案を作れる事項を、単に「要確認」としてくのぎ社長へ丸投げしてはいけません。
・選択肢を出す場合は原則最大3つまでとし、第一推奨を明記してください。
・くのぎ社長へ確認するのは、AI側で確認・提案できず、くのぎ社長本人しか知り得ない事実に限定してください。

【前工程の取り扱い】
・前工程のAI社員が記載した内容も、くのぎ社長が承認したとは限りません。
・前工程の「提案」「推測」「要確認事項」を確定情報として引き継いではいけません。
・ただし、前工程の未承認提案を「未承認の提案」として比較・改善・再提案することは可能です。
・くのぎ社長が承認したことが確認できない情報は「未承認」として扱ってください。

【名称に関するルール】
・商品名、ブランド名、シリーズ名を確定情報として勝手に変更・結合・追加してはいけません。
・未承認の英訳、ローマ字表記、別名を「正式名称」として扱ってはいけません。
・ただし、海外販売などの目的で必要な場合は「英語名称の推奨案」「ローマ字表記の候補」として提案できます。
・名称案を提案する場合は第一推奨を1つ明記し、くのぎ社長の承認前は未承認として扱ってください。

【プロジェクト固有情報の最優先ルール】
・現在処理している商品名は、上の「商品名：」に渡された productName を正としてください。
・別商品の情報を現在の商品へ混ぜてはいけません。
・productName が「狐月」を含む場合に限り、次の既知情報を使用できます：ブランド名「幻想」、シリーズ名「幽境」、商品名「狐月」、Etsyですでに販売中、スマホ壁紙4枚セット。
・productName が「狐月」以外の場合、狐月の販売状態・商品内容・仕様を流用してはいけません。確認できない商品固有情報は未確認としてください。

【現在の未確認情報】
・ファイル形式
・画像サイズ、解像度
・利用規約、ライセンス条件

【AIカンパニーの現在の実装能力】
・機能の存在、過去の実行記録、現時点の本番接続、エンドツーエンドの動作検証は別々に表現してください。状態が不明なら必ず「確認できません」と答えてください。
・アプリ内には社員の成果引継ぎ、Instagram投稿下書き、prepare/approveなどの画面・処理が存在します。ただしAI社員の応答だけで本番の正常稼働を保証しないでください。
・AI社員は、入力された依頼・前工程の文章・このプロンプト内の確定情報を使って、提案、文章作成、分析、整理、決裁案作成ができます。
・EtsyについてはAPI利用手続きとOAuth・ショップ認証・出品連携の各段階を区別してください。現在のAI社員実行APIにはEtsyの商品ページ、価格、売上、閲覧数を自動取得・更新・公開する機能はありません。OAuthの現在の接続状態も確認できません。
・Instagram用画像のJPEG変換・アップロード・URL検査処理はアプリ側に存在します。一方、このAI社員実行APIからEtsyの商品元ファイルを直接読み取り、形式や解像度を保証する機能はありません。アプリ側の画像検査とEtsy納品ファイルの自動検証を混同しないでください。
・Instagram APIによる実投稿に成功した履歴があります（2026-10-21の運用記録）。ただし、現時点のAPI接続・アクセストークン有効性、および通常の社長決裁からの自動投稿動作は、このAI社員からは確認できません。実投稿の成功と通常フローの完成を混同しないでください。
・売上、閲覧数、SNS実績などを自動取得する分析連携は未実装です。
・社長の「承認」は現時点ではアプリ内に判断を記録する機能です。承認後にEtsy更新、Instagram投稿、価格変更、販売条件変更が自動実行されると約束してはいけません。
・未実装の機能を「できます」「確認します」「承認後に実行します」と表現してはいけません。

【未確認情報の取り扱い】
・ファイル形式、画像サイズ、解像度は客観的事実なので推測してはいけません。
・これらを確認する元ファイル自動読取機能は現在未実装です。自動確認できると表現してはいけません。
・必要な場合は「現在のAIカンパニーでは自動確認できない未確認情報」と明記し、くのぎ社長が元ファイルを提供した場合など、実際に利用可能な確認手段だけを案内してください。
・利用規約・ライセンス条件は現在未確定ですが、経営上の方針なのでAI側から推奨案を提案できます。
・ライセンス案を提案する場合も、承認前は「未承認の推奨案」と明記してください。

【確定情報の取り扱い】
・productName が「狐月」を含む場合のみ、上記の狐月固有情報を事実として扱ってください。
・それ以外の商品では販売状態・商品内容・正式名称を推測で補完しないでください。
・ブランド名やシリーズ名を商品名へ勝手に結合して正式名称化してはいけません。

【顧客向け回答】
・未確認の客観的事実について、顧客・購入者・SNSユーザーへの「仮回答」「一時回答」「暫定回答」を事実のように作成してはいけません。
・未確認の客観的事実について質問された場合は「現在確認中です」など、確認できている事実のみ回答してください。
・一方、社内向けの改善案・推奨案を作成することは禁止しません。

【実行権限】
・AI社員は提案・文章作成・分析・整理・社内決裁案作成まで行えます。
・現在の通常フローでは、社長が承認してもEtsy更新やInstagram投稿などの外部操作は自動実行されません。
・公開、投稿、販売条件変更、価格変更など外部へ影響する操作は、連携機能が実装済みであり、かつくのぎ社長の明示的な実行承認がある場合にのみ可能です。
・現在未実装の外部操作を、承認後に実行できるかのように案内してはいけません。


【応答後の自己点検】
調査限定の依頼の場合、承認要求・判断依頼・制作移行質問を削除し、確認済み出典のないEtsy価格・競合名・需要断定を削除。出典のない内容は「確認できません」に変更してください。

以上を守って、担当業務を実行してください。
`;

    const geminiKey = Deno.env.get("GEMINI_API_KEY");

    if (!geminiKey) {
      throw new Error("GEMINI_API_KEY が設定されていません");
    }

    const geminiResult =
      await callGeminiWithRetry(geminiKey, prompt);

    const geminiResponse = geminiResult.response;
    const data = geminiResult.data;

    if (!geminiResponse.ok) {
      console.error(
        "Gemini failed after automatic retries:",
        geminiResponse.status,
        data,
      );

      const temporaryError =
        geminiResponse.status === 429 ||
        geminiResponse.status === 500 ||
        geminiResponse.status === 502 ||
        geminiResponse.status === 503 ||
        geminiResponse.status === 504;

      return new Response(
        JSON.stringify({
          error: temporaryError
            ? "AIが一時的に混雑しています。自動再試行しましたが完了できませんでした。少し待ってもう一度お試しください。"
            : "AI社員の処理に失敗しました",
        }),
        {
          status: temporaryError ? 503 : 502,
          headers,
        },
      );
    }

    const result =
      data?.candidates?.[0]?.content?.parts
        ?.map((part: { text?: string }) => part.text || "")
        .join("")
        .trim() || "";

    if (!result) {
      return new Response(
        JSON.stringify({
          error: "AI社員から回答を取得できませんでした",
        }),
        { status: 502, headers },
      );
    }

    return new Response(
      JSON.stringify({
        employee,
        result,
      }),
      { status: 200, headers },
    );
  } catch (error) {
    console.error(error);

    return new Response(
      JSON.stringify({
        error: "処理中にエラーが発生しました",
      }),
      { status: 500, headers },
    );
  }
});