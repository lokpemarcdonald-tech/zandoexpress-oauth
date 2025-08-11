import express from "express";
import axios from "axios";
import crypto from "crypto";
import "dotenv/config";

const app = express();

// Health check
app.get("/", (_req, res) => {
  res.status(200).send("ZandoExpress OAuth backend is running ✔");
});

// App URL (Shopify > App URL)
// Après installation, Shopify veut atteindre la page de l'app,
// donc on redirige vers /apps/<handle>.
app.get("/app", (req, res) => {
  const { shop, host } = req.query;
  const handle = process.env.APP_HANDLE || "zandoexpress";
  const storeSlug = shop ? String(shop).replace(".myshopify.com", "") : "";

  // Si on a shop/host, on les passe pour un chargement propre de l’UI
  if (storeSlug) {
    const target = `https://admin.shopify.com/store/${storeSlug}/apps/${handle}${
      host ? `?host=${encodeURIComponent(String(host))}` : ""
    }`;
    return res.redirect(target);
  }

  // Fallback si appelé sans params
  res.status(200).send("ZandoExpress App is installed ✔");
});


/**
 * Vérification HMAC selon la doc Shopify :
 * - enlever hmac
 * - trier les clés ascendantes
 * - concaténer sous forme "k=v&k2=v2..."
 * - HMAC SHA256 avec SHOPIFY_API_SECRET
 */
function verifyHmac(query) {
  const { hmac, ...rest } = query;
  const sorted = Object.keys(rest)
    .sort()
    .map((key) => `${key}=${rest[key]}`)
    .join("&");

  const digest = crypto
    .createHmac("sha256", process.env.SHOPIFY_API_SECRET)
    .update(sorted)
    .digest("hex");

  return digest === hmac;
}

/**
 * /auth/callback — URL de redirection OAuth (Shopify > Allowed redirection URL(s))
 * Reçoit shop + code + hmac, vérifie HMAC, échange le code contre access_token,
 * puis redirige vers /app/grant (URL attendue par la vérification Shopify).
 */
app.get("/auth/callback", async (req, res) => {
  try {
    const { shop, code, hmac, host } = req.query;
    if (!shop || !code || !hmac) return res.status(400).send("Missing required OAuth params");

    // 1) Vérif HMAC
    if (!verifyHmac(req.query)) return res.status(401).send("HMAC invalid");

    // 2) Échange code -> access_token
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

    // (Optionnel) Envoyer shop + token vers Make/Airtable ici
    // await axios.post("https://hook.us2.make.com/TON_WEBHOOK_MAKE", { shop, access_token });

    // 3) Redirection attendue par Shopify : /app/grant
    const storeSlug = String(shop).replace(".myshopify.com", "");
    const target = `https://admin.shopify.com/store/${storeSlug}/app/grant?shop=${encodeURIComponent(
      shop
    )}${host ? `&host=${encodeURIComponent(host)}` : ""}`;
    return res.redirect(target);
  } catch (err) {
    const out = err?.response?.data || err?.message || "OAuth error";
    console.error("OAuth callback error:", out);
    return res.status(500).send("OAuth error");
  }
});

const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`ZandoExpress OAuth listening on :${port}`));
