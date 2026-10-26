# Alkaline Online — backend starter

Contains `server.js`, `package.json`, `.env.example`, and the existing demo `index.html`.

## Render deployment
1. Unzip and upload the four files to the root of your GitHub repository.
2. In Render create or configure a **Web Service** connected to that repository.
3. Runtime: Node; Build Command: `npm install`; Start Command: `npm start`.
4. Open `/api/health` on your Render URL to check the backend.

## Important
The storefront still uses its demonstration checkout. `/api/orders` validates a sample basket and returns a preview only. It does **not** accept payment, persist orders, send emails, or handle customer details. Connect a payment provider and persistent storage before real customer orders. Prices in `server.js` are example values in pence.
