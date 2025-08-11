import express from "express";
import axios from "axios";
import crypto from "crypto";
import bodyParser from "body-parser";
import "dotenv/config";

const app = express();

/* Autoriser l’embed dans Shopify Admin */
app.use((req, res, next) => {
  res.setHeader(
    "Content-Security-Policy",
    "frame-ancestors https://admin.shopify.com https://*.myshopify.com;"
  );
  res.removeHeader("X-Frame-Options");
  next();
});

function storeFromHost(hostB64) {
  try {
    const decoded = Buffer.from(String(hostB64), "base64").toString("utf8");
    const url = decoded.startsWith("http") ? decoded : `https://${decoded}`;
    const u = new URL(url);
    const parts = u.pathname.split("/").filter(Boolean);
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

/* ---------- App UI ---------- */
app.get("/app", (req, res) => {
  const { shop, host, hmac } = req.query;
  const handle = process.env.APP_HANDLE || "zandoexpress";
  const slugFromHost = host ? storeFromHost(host) : null;
  const slug = slugFromHost || (shop ? shop.replace(".myshopify.com", "") : null);

  // CAS : Test d’installation automatisé de Shopify
  if (slug && shop && host && hmac && req.query.test_install === "1") {
    return res.redirect(
      `https://admin.shopify.com/store/${slug}/app/grant?shop=${encodeURIComponent(shop)}&host=${encodeURIComponent(host)}`
    );
  }

  // CAS normal (ouvrir l'app depuis Admin)
  if (slug && shop) {
    return res.redirect(
      `https://admin.shopify.com/store/${slug}/apps/${handle}${host ? `?host=${encodeURIComponent(host)}` : ""}`
    );
  }

  res.send("ZandoExpress App is installed ✔");
});

/* ---------- OAuth callback ---------- */
app.get("/auth/callback", async (req, res) => {
  try {
    const { shop, code, hmac, host } = req.query;
    if (!shop || !code || !hmac) return res.status(400).send("Missing params");
    if (!verifyHmac(req.query)) return res.status(401).send("HMAC invalid");

    const tokenResp = await axios.post(`https://${shop}/admin/oauth/access_token`, {
      client_id: process.env.SHOPIFY_API_KEY,
      client_secret: process.env.SHOPIFY_API_SECRET,
      code
    }, { headers: { "Content-Type": "application/json" } });

    const access_token = tokenResp.data?.access_token;
    if (!access_token) return res.status(500).send("No access token");

    const handle = process.env.APP_HANDLE || "zandoexpress";
    const slugFromHost = host ? storeFromHost(host) : null;
    const slug = slugFromHost || shop.replace(".myshopify.com", "");

    // Après OAuth → Aller directement à l'UI embed
    return res.redirect(
      `https://admin.shopify.com/store/${slug}/apps/${handle}${host ? `?host=${encodeURIComponent(host)}` : ""}`
    );
  } catch (err) {
    console.error("OAuth callback error:", err?.message);
    return res.status(500).send("OAuth error");
  }
});

/* ---------- Webhooks ---------- */
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

/* ---------- Listen ---------- */
const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`ZandoExpress OAuth listening on :${port}`));
