# ZandoExpress – Shopify OAuth Minimal Backend

This tiny backend fixes Shopify's "unexpected URL" install error by handling OAuth and redirecting to the expected Admin URL.

## Deploy (Render.com – easiest)

1. **Download this project** and push it to a new GitHub repo.
2. Create an account at https://render.com → New → Web Service → Connect your repo.
3. Set:
   - **Build Command**: `npm install`
   - **Start Command**: `node server.js`
4. **Environment Variables** (Render → Settings → Environment):
   - `SHOPIFY_API_KEY` = your Shopify app client id
   - `SHOPIFY_API_SECRET` = your Shopify app client secret
   - `APP_HANDLE` = your app handle (slug as shown in Shopify admin)
   - (Optional) `PORT` = 3000 (Render sets PORT automatically; keep default if unsure)
5. Deploy. Note your public URL, e.g. `https://zandoexpress-oauth.onrender.com`.

## Configure in Shopify Partners

- **App URL**: `https://<your-render-url>/app`
- **Allowed redirection URL(s)**: `https://<your-render-url>/auth/callback`

## Test Install

Use (replace placeholders):
```
https://{shop}.myshopify.com/admin/oauth/authorize?client_id=SHOPIFY_API_KEY&scope=read_orders,read_products,read_customers&redirect_uri=https://<your-render-url>/auth/callback&state=install123
```

After accepting, the backend exchanges the code for an access token and redirects to:
`https://admin.shopify.com/store/{store}/apps/{APP_HANDLE}`

## Notes
- The code verifies HMAC and handles the "host" param.
- Store the token where you prefer (DB/Airtable) inside `/auth/callback` (marked TODO).
- Keep your secrets safe; never commit `.env`.
