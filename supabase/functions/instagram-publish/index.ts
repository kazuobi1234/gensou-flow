const INSTAGRAM_USER_ID = Deno.env.get("INSTAGRAM_USER_ID");
const ACCESS_TOKEN = Deno.env.get("INSTAGRAM_ACCESS_TOKEN");
const POSTING_SECRET = Deno.env.get("POSTING_SECRET");

Deno.serve(async (req) => {
  try {
    // 葉専用の合言葉を確認
    const suppliedSecret = req.headers.get("x-posting-secret");

    if (!POSTING_SECRET || suppliedSecret !== POSTING_SECRET) {
      return Response.json(
        {
          ok: false,
          error: "Unauthorized",
        },
        { status: 401 }
      );
    }

    if (!INSTAGRAM_USER_ID || !ACCESS_TOKEN) {
      throw new Error(
        "Instagram ID またはアクセストークンが設定されていません"
      );
    }

    const {
      image_url,
      caption = "",
      publish = false,
    } = await req.json();

    if (!image_url) {
      return Response.json(
        {
          ok: false,
          error: "image_url is required",
        },
        { status: 400 }
      );
    }

    // ① 投稿コンテナを作成
    const createParams = new URLSearchParams({
      image_url,
      caption,
      access_token: ACCESS_TOKEN,
    });

    const createResponse = await fetch(
      `https://graph.instagram.com/v26.0/${INSTAGRAM_USER_ID}/media`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
        },
        body: createParams,
      }
    );

    const createResult = await createResponse.json();

    if (!createResponse.ok || !createResult.id) {
      return Response.json(
        {
          ok: false,
          stage: "create_container",
          meta: createResult,
        },
        { status: createResponse.status }
      );
    }

    // publish:falseなら公開せず終了
    if (!publish) {
      return Response.json({
        ok: true,
        published: false,
        note: "投稿コンテナを作成しました。Instagramには公開していません。",
        creation_id: createResult.id,
      });
    }

    // ② Instagramへ公開
    const publishParams = new URLSearchParams({
      creation_id: createResult.id,
      access_token: ACCESS_TOKEN,
    });

    const publishResponse = await fetch(
      `https://graph.instagram.com/v26.0/${INSTAGRAM_USER_ID}/media_publish`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
        },
        body: publishParams,
      }
    );

    const publishResult = await publishResponse.json();

    if (!publishResponse.ok) {
      return Response.json(
        {
          ok: false,
          stage: "publish",
          meta: publishResult,
        },
        { status: publishResponse.status }
      );
    }

    return Response.json({
      ok: true,
      published: true,
      note: "Instagramへの公開に成功しました。",
      media_id: publishResult.id,
    });
  } catch (error) {
    return Response.json(
      {
        ok: false,
        error: error instanceof Error
          ? error.message
          : String(error),
      },
      { status: 500 }
    );
  }
});