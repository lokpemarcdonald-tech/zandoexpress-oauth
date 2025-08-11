import express from "express";
import axios from "axios";
import crypto from "crypto";
import "dotenv/config";

const app = express();

// Health & landing
app.get("/", (_req, res) => {
  res.status(200).send("ZandoExpress OAuth backend is running ✔");
});

// App URL (set this in Shopify 'App URL')
app.get("/app", (_req, res) => {
  res.status(200).send("ZandoExpress App is installed ✔");
});

// Helper to extract store slug from 'host' (base64-encoded 'admin.shopify.com/store/<slug>')
function storeFromHost(hostB64) {
  try {
    const decoded = Buffer.from(hostB64, "base64").toString("utf8");
    // ensure we have a full URL to parse
    const url = decoded.startsWith("http") ? decoded : `https://${decoded}`;
    const u = new URL(url);
    const parts = u.pathname.split("/").filter(Boolean);
    const idx = parts.indexOf("store");
    if (idx !== -1 && parts[idx+1]) return parts[idx+1];
  } catch (e) {}
  return null;
}

// OAuth callback (set this in Shopify 'Allowed redirection URL(s)')
app.get("/auth/callback", async (req, res) => {
  try {
    const { shop, code, hmac, host, state } = req.query;
    if (!shop || !code || !hmac) return res.status(400).send("Missing required OAuth params");

    // Verify HMAC (recommended by Shopify)
    const params = { ...req.query };
    delete params.hmac;
    const message = new URLSearchParams(params).toString();
    const computed = crypto.createHmac("sha256", process.env.SHOPIFY_API_SECRET).update(message).digest("hex");
    if (computed !== hmac) return res.status(401).send("HMAC invalid");

    // Exchange code for access_token
    const tokenUrl = `https://${shop}/admin/oauth/access_token`;
    const tokenResp = await axios.post(tokenUrl, {
      client_id: process.env.SHOPIFY_API_KEY,
      client_secret: process.env.SHOPIFY_API_SECRET,
      code
    }, { headers: { "Content-Type": "application/json" } });

    const access_token = tokenResp.data?.access_token;
    if (!access_token) return res.status(500).send("Failed to obtain access_token");

    // TODO: store shop + token in your DB/Airtable here if desired

    // Redirect to Shopify Admin app URL (what Shopify's automated checks expect)
    const handle = process.env.APP_HANDLE || "zandoexpress";
    let storeSlug = null;
    if (host) storeSlug = storeFromHost(host);
    if (!storeSlug) storeSlug = shop.replace(".myshopify.com", "");

    const target = `https://admin.shopify.com/store/${storeSlug}/apps/${handle}`;
    return res.redirect(target);
  } catch (err) {
    const out = err?.response?.data || err?.message || "OAuth error";
    console.error("OAuth callback error:", out);
    return res.status(500).send("OAuth error");
  }
});

const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`ZandoExpress OAuth listening on :${port}`));
