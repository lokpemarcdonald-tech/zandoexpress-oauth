import express from "express";
import axios from "axios";
import crypto from "crypto";
import bodyParser from "body-parser";
import "dotenv/config";

const app = express();

/* ---------- Autoriser l’embed dans l’Admin Shopify ---------- */
app.use((req, res, next) => {
  res.setHeader(
    "Content-Security-Policy",
    "frame-ancestors https://admin.shopify.com https://*.myshopify.com;"
  );
  res.removeHeader("X-Frame-Options");
  next();
});

/* ---------------- Helpers ---------------- */
function storeFromHost(hostB64) {
  try {
    const decoded = Buffer.from(String(hostB64), "base64").toString("utf8");
    const url = decoded.startsWith("http") ? decoded : `https://${decoded}`;
    const u = new URL(url);
    const parts = u.pathname.split("/").filter(Boolean); // ["store","<slug>"]
    const i = parts.indexOf("store");
    if (i >= 0 && parts[i + 1]) return parts[i + 1];
  } catch (_) {}
  return null;
}

function verifyHmac(query) {
  const { hmac, ...rest } = query;
  const sorted = Object.keys(rest).sort().map(k => `${k}=${rest[k]}`).join("&");
  const digest = crypto
    .createHmac("sha256", process.env.SHOPIFY_API_SECRET)
    .update(sorted)
    .digest("hex");
  return digest === hmac;
}

/* ---------------- Health ---------------- */
app.get("/", (_req, res) => {
  res.status(200).send("ZandoExpress OAuth backend is running ✔");
});

/* ---------------- App URL (UI embed) ----------------
   IMPORTANT :
   - embedded=1  => on REND la page (pas de redirection vers admin.shopify.com)
   - shop+host+hmac => install auto => /app/grant
   - shop+host (non embedded) => top-level redirect vers /app/grant
----------------------------------------------------- */
app.get("/app", (req, res) => {
  const { shop, host, embedded } = req.query;
  const handle = process.env.APP_HANDLE || "zandoexpress";

  // Slug depuis host (base64) sinon fallback avec shop
  const slugFromHost = host ? storeFromHost(host) : null;
  const slug = slugFromHost || (shop ? String(shop).replace(".myshopify.com", "") : null);

  // 1) PAS encore embarqué (pas embedded=1) ET on a shop+host => on demande le top-level grant
  //    (c'est nécessaire pour que Shopify pose ses cookies, puis il reviendra avec embedded=1)
  if (slug && shop && host && embedded !== "1") {
    const target = `https://admin.shopify.com/store/${slug}/app/grant?shop=${encodeURIComponent(shop)}&host=${encodeURIComponent(host)}`;
    return res.redirect(target);
  }

  // 2) DÉJÀ embarqué (embedded=1) => on REND la page (NE PAS rediriger vers admin.shopify.com)
  if (embedded === "1") {
    return res.type("html").send(`
<!doctype html>
<html>
  <head>
    <meta charset="utf-8" />
    <title>ZandoExpress</title>
    <meta name="viewport" content="width=device-width,initial-scale=1" />
  </head>
  <body style="font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial; padding:24px">
    <h1>ZandoExpress</h1>
    <p>Bienvenue dans l'application embarquée dans l'Admin Shopify.</p>
    <p>(Vous pourrez intégrer ici votre UI réelle, App Bridge, liens Softr, etc.)</p>
  </body>
</html>
    `);
  }

  // 3) Cas normal (on a shop, éventuellement sans host) => aller sur la HOMEPAGE de l’app (ce que l’audit attend)
  if (slug && shop) {
    const target = `https://admin.shopify.com/store/${slug}/apps/${handle}${host ? `?host=${encodeURIComponent(host)}` : ""}`;
    return res.redirect(target);
  }

  // 4) Fallback si /app sans paramètres
  res.status(200).send("ZandoExpress App is installed ✔");
});

/* -------------- OAuth callback -----------
   Après échange du code, on renvoie l’admin ouvrir l’UI de l’app.
------------------------------------------ */
app.get("/auth/callback", async (req, res) => {
  try {
    const { shop, code, hmac, host } = req.query;
    if (!shop || !code || !hmac) return res.status(400).send("Missing required OAuth params");
    if (!verifyHmac(req.query)) return res.status(401).send("HMAC invalid");

    const tokenResp = await axios.post(
      `https://${shop}/admin/oauth/access_token`,
      {
        client_id: process.env.SHOPIFY_API_KEY,
        client_secret: process.env.SHOPIFY_API_SECRET,
        code
      },
      { headers: { "Content-Type": "application/json" } }
    );
    const access_token = tokenResp.data?.access_token;
    if (!access_token) return res.status(500).send("Failed to obtain access_token");

    // (Optionnel) envoyer shop + token à Make/Airtable ici.

    // Après OAuth -> ouvre l'app dans l'Admin (l'Admin se chargera d'embarquer ensuite)
    const handle = process.env.APP_HANDLE || "zandoexpress";
    const slugFromHost = host ? storeFromHost(host) : null;
    const slug = slugFromHost || String(shop).replace(".myshopify.com", "");
    const target = `https://admin.shopify.com/store/${slug}/apps/${handle}${host ? `?host=${encodeURIComponent(host)}` : ""}`;
    return res.redirect(target);
  } catch (err) {
    const out = err?.response?.data || err?.message || "OAuth error";
    console.error("OAuth callback error:", out);
    return res.status(500).send("OAuth error");
  }
});

/* --------- Webhooks de conformité + HMAC --------- */
app.use("/webhooks", bodyParser.raw({ type: "*/*" }));

function verifyWebhookHmac(req, res, next) {
  try {
    const sig = req.get("X-Shopify-Hmac-Sha256");
    const digest = crypto
      .createHmac("sha256", process.env.SHOPIFY_API_SECRET)
      .update(req.body)
      .digest("base64");
    if (digest !== sig) return res.status(401).send("Invalid webhook HMAC");
    next();
  } catch {
    return res.status(401).send("Invalid webhook");
  }
}

app.post("/webhooks/customers/data_request", verifyWebhookHmac, (_req, res) => res.sendStatus(200));
app.post("/webhooks/customers/redact", verifyWebhookHmac, (_req, res) => res.sendStatus(200));
app.post("/webhooks/shop/redact", verifyWebhookHmac, (_req, res) => res.sendStatus(200));

/* ---------------- Listen ---------------- */
const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`ZandoExpress OAuth listening on :${port}`));
