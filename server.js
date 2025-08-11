import express from "express";
import axios from "axios";
import crypto from "crypto";
import bodyParser from "body-parser";
import "dotenv/config";

const app = express();

/* ---------------- Health ---------------- */
app.get("/", (_req, res) => {
  res.status(200).send("ZandoExpress OAuth backend is running ✔");
});

/* ------------- Utils / helpers ---------- */
// Extrait le slug du store (ex: uvszh1-m5) à partir de `host` encodé b64
function storeFromHost(hostB64) {
  try {
    const decoded = Buffer.from(String(hostB64), "base64").toString("utf8");
    const url = decoded.startsWith("http") ? decoded : `https://${decoded}`;
    const u = new URL(url);
    const parts = u.pathname.split("/").filter(Boolean); // ["store", "<slug>"]
    const i = parts.indexOf("store");
    if (i >= 0 && parts[i + 1]) return parts[i + 1];
  } catch (_) {}
  return null;
}

// Vérif HMAC (OAuth query)
function verifyHmac(query) {
  const { hmac, ...rest } = query;
  const sorted = Object.keys(rest)
    .sort()
    .map((k) => `${k}=${rest[k]}`)
    .join("&");
  const digest = crypto
    .createHmac("sha256", process.env.SHOPIFY_API_SECRET)
    .update(sorted)
    .digest("hex");
  return digest === hmac;
}

/* ---------------- App URL ----------------
   Après l’install, Shopify veut l’UI de l’app :
   https://admin.shopify.com/store/<slug>/apps/<APP_HANDLE>
------------------------------------------ */
app.get("/app", (req, res) => {
  const { shop, host } = req.query;
  const handle = process.env.APP_HANDLE || "zandoexpress";
  const slugFromHost = host ? storeFromHost(host) : null;
  const slug = slugFromHost || (shop ? String(shop).replace(".myshopify.com", "") : null);

  if (slug && shop) {
    const target =
      `https://admin.shopify.com/store/${slug}/apps/${handle}` +
      (host ? `?host=${encodeURIComponent(String(host))}` : "");
    return res.redirect(target);
  }
  // Fallback si /app sans params
  res.status(200).send("ZandoExpress App is installed ✔");
});

/* -------------- OAuth callback -----------
   Reçoit shop+code+hmac, vérifie HMAC, échange le code,
   puis redirige vers /app/grant (attendu par la vérification).
------------------------------------------ */
app.get("/auth/callback", async (req, res) => {
  try {
    const { shop, code, hmac, host } = req.query;
    if (!shop || !code || !hmac) return res.status(400).send("Missing required OAuth params");
    if (!verifyHmac(req.query)) return res.status(401).send("HMAC invalid");

    // Échange code -> access_token
    const tokenUrl = `https://${shop}/admin/oauth/access_token`;
    const tokenResp = await axios.post(
      tokenUrl,
      {
        client_id: process.env.SHOPIFY_API_KEY,
        client_secret: process.env.SHOPIFY_API_SECRET,
        code
      },
      { headers: { "Content-Type": "application/json" } }
    );
    const access_token = tokenResp.data?.access_token;
    if (!access_token) return res.status(500).send("Failed to obtain access_token");

    // TODO: envoyer shop + token vers Make/Airtable ici si besoin
    // await axios.post("https://hook.us2.make.com/TON_WEBHOOK_MAKE", { shop, access_token });

    // Redirection attendue par Shopify : /app/grant
    const slugFromHost = host ? storeFromHost(host) : null;
    const slug = slugFromHost || String(shop).replace(".myshopify.com", "");
    const target =
      `https://admin.shopify.com/store/${slug}/app/grant` +
      `?shop=${encodeURIComponent(String(shop))}` +
      (host ? `&host=${encodeURIComponent(String(host))}` : "");
    return res.redirect(target);
  } catch (err) {
    const out = err?.response?.data || err?.message || "OAuth error";
    console.error("OAuth callback error:", out);
    return res.status(500).send("OAuth error");
  }
});

/* --------- Webhooks de conformité + HMAC ---------
   On utilise bodyParser.raw UNIQUEMENT pour /webhooks
   afin de calculer l’HMAC sur le RAW body.
--------------------------------------------------- */
app.use("/webhooks", bodyParser.raw({ type: "*/*" }));

function verifyWebhookHmac(req, res, next) {
  try {
    const sig = req.get("X-Shopify-Hmac-Sha256");
    const digest = crypto
      .createHmac("sha256", process.env.SHOPIFY_API_SECRET)
      .update(req.body) // RAW body
      .digest("base64");
    if (digest !== sig) return res.status(401).send("Invalid webhook HMAC");
    next();
  } catch {
    return res.status(401).send("Invalid webhook");
  }
}

// Webhooks RGPD/CCPA obligatoires
app.post("/webhooks/customers/data_request", verifyWebhookHmac, (_req, res) => res.sendStatus(200));
app.post("/webhooks/customers/redact", verifyWebhookHmac, (_req, res) => res.sendStatus(200));
app.post("/webhooks/shop/redact", verifyWebhookHmac, (_req, res) => res.sendStatus(200));

/* ---------------- Listen ---------------- */
const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`ZandoExpress OAuth listening on :${port}`));
