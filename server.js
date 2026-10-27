const Stripe = require('stripe');
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const PORT = Number(process.env.PORT || 3000);
const ALLOWED_ORIGIN = "https://alkaline-online.onrender.com";

// Supabase is accessed only from the Render backend; never expose its secret key.
const DB_URL = (process.env.SUPABASE_URL || '').replace(/\/$/, '');
const DB_KEY = process.env.SUPABASE_SECRET_KEY || '';
async function db(resource, options = {}) {
  if (!DB_URL || !DB_KEY) throw Error('Supabase is not configured');
  const response = await fetch(`${DB_URL}/rest/v1/${resource}`, {
    ...options,
    headers: {
      apikey: DB_KEY,
      Authorization: `Bearer ${DB_KEY}`,
      Accept: 'application/json',
      ...(options.headers || {})
    },
    signal: AbortSignal.timeout(10000)
  });
  if (!response.ok) {
    console.error('Supabase request failed:', response.status);
    throw Error('Database request failed');
  }
  if (response.status === 204) return null;
  return response.json();
}
async function productsFromDb(all = false) {
  const where = all ? '' : '&is_active=eq.true';
  return db('products?select=id,name,description,category,price_pence,stock_quantity,is_active,image_url&order=id.asc' + where);
}
function validateProduct(p, partial = false) {
  if (!p || typeof p !== 'object' || Array.isArray(p)) throw Error('Invalid product');
  const allowed = ['name','description','category','price_pence','stock_quantity','is_active','image_url'];
  const keys = Object.keys(p);
  if (!keys.length || keys.some(k => !allowed.includes(k))) throw Error('Invalid product fields');
  if (!partial && (!keys.includes('name') || !keys.includes('price_pence') || !keys.includes('stock_quantity'))) throw Error('Missing product fields');
  if ('name' in p && (typeof p.name !== 'string' || !p.name.trim() || p.name.length > 120)) throw Error('Invalid name');
  if ('description' in p && (typeof p.description !== 'string' || p.description.length > 1500)) throw Error('Invalid description');
  if ('category' in p && (typeof p.category !== 'string' || !p.category.trim() || p.category.length > 80)) throw Error('Invalid category');
  if ('price_pence' in p && (!Number.isSafeInteger(p.price_pence) || p.price_pence < 1 || p.price_pence > 10000000)) throw Error('Invalid price');
  if ('stock_quantity' in p && (!Number.isSafeInteger(p.stock_quantity) || p.stock_quantity < 0 || p.stock_quantity > 1000000)) throw Error('Invalid stock quantity');
  if ('is_active' in p && typeof p.is_active !== 'boolean') throw Error('Invalid availability');
  if ('image_url' in p && p.image_url !== null && (typeof p.image_url !== 'string' || p.image_url.length > 1000 || (p.image_url && !/^https:\/\//.test(p.image_url)))) throw Error('Invalid image URL');
  return Object.fromEntries(keys.map(k => [k, typeof p[k] === 'string' ? p[k].trim() : p[k]]));
}

// Admin access uses a password stored ONLY in Render (ADMIN_PASSWORD).
// Sessions are signed, HttpOnly, Secure cookies and expire after 8 hours.
const ADMIN_COOKIE = 'alkaline_admin';
const ADMIN_MAX_AGE = 8 * 60 * 60;
const loginAttempts = new Map();
const adminSecret = process.env.ADMIN_SESSION_SECRET || '';
const adminPassword = process.env.ADMIN_PASSWORD || '';
function safeEqual(a, b) {
  const aa = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  return aa.length === bb.length && crypto.timingSafeEqual(aa, bb);
}
function signedToken() {
  const expiry = Date.now() + ADMIN_MAX_AGE * 1000;
  const nonce = crypto.randomBytes(16).toString('hex');
  const value = `${expiry}.${nonce}`;
  const signature = crypto.createHmac('sha256', adminSecret).update(value).digest('hex');
  return `${value}.${signature}`;
}
function adminAuthorized(req) {
  if (!adminSecret || !adminPassword) return false;
  const cookie = (req.headers.cookie || '').split(';').map(s => s.trim()).find(s => s.startsWith(ADMIN_COOKIE + '='));
  if (!cookie) return false;
  const token = cookie.slice(ADMIN_COOKIE.length + 1);
  const parts = token.split('.');
  if (parts.length !== 3) return false;
  const [expiry, nonce, signature] = parts;
  if (!/^\d{13}$/.test(expiry) || !/^[a-f0-9]{32}$/.test(nonce) || !/^[a-f0-9]{64}$/.test(signature) || Number(expiry) < Date.now()) return false;
  const expected = crypto.createHmac('sha256', adminSecret).update(`${expiry}.${nonce}`).digest('hex');
  return safeEqual(signature, expected);
}
function adminHeaders(res) {
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('X-Frame-Options', 'DENY');
}
async function jsonBody(req, max = 2048) {
  const chunks = []; let bytes = 0;
  for await (const chunk of req) { bytes += chunk.length; if (bytes > max) throw new Error('Request too large'); chunks.push(chunk); }
  return JSON.parse(Buffer.concat(chunks).toString('utf8'));
}
function cookieHeader(token, maxAge) {
  return `${ADMIN_COOKIE}=${token}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=${maxAge}`;
}
function sameOrigin(req) {
  return req.headers.origin === 'https://alkaline-online-backend.onrender.com';
}
const send=(res,status,obj)=>{res.writeHead(status,{'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store'});res.end(JSON.stringify(obj));};
http.createServer(async (req,res)=>{
res.setHeader("Access-Control-Allow-Origin", ALLOWED_ORIGIN);
res.setHeader("Vary", "Origin");
res.setHeader("Access-Control-Allow-Methods", "GET, POST, PATCH, OPTIONS");
res.setHeader("Access-Control-Allow-Headers", "Content-Type");

if (req.method === "OPTIONS") {
  if (req.url.startsWith('/api/admin/')) return send(res,403,{error:'Not allowed'});
  res.writeHead(204);
  return res.end();
}
 const url = new URL(req.url,'http://localhost');
 // Admin pages are served from the backend domain, not the public storefront.
 if (url.pathname === '/admin' || url.pathname === '/admin/') {
   if (req.method !== 'GET') return send(res,405,{error:'Method not allowed'});
   adminHeaders(res);
   res.setHeader('Content-Type','text/html; charset=utf-8');
   return fs.createReadStream(path.join(__dirname,'admin.html')).pipe(res);
 }
 if (url.pathname.startsWith('/api/admin/')) {
   adminHeaders(res);
   // Do not allow public storefront CORS on private administration endpoints.
   res.removeHeader('Access-Control-Allow-Origin');
   res.removeHeader('Access-Control-Allow-Methods');
   res.removeHeader('Access-Control-Allow-Headers');
   if (url.pathname === '/api/admin/session' && req.method === 'GET')
     return send(res,200,{authenticated:adminAuthorized(req),configured:!!(adminPassword && adminSecret)});
   if (url.pathname === '/api/admin/login' && req.method === 'POST') {
     if (!sameOrigin(req)) return send(res,403,{error:'Invalid origin'});
     if (!adminPassword || !adminSecret) return send(res,503,{error:'Admin login is not configured'});
     const ip = String(req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();
     const now = Date.now();
     for (const [key,val] of loginAttempts) if (now-val.first > 15*60*1000) loginAttempts.delete(key);
     const state = loginAttempts.get(ip) || {first:now,count:0};
     if (state.count >= 8) return send(res,429,{error:'Too many attempts. Try again later.'});
     let input;
     try { input = await jsonBody(req); } catch { return send(res,400,{error:'Invalid request'}); }
     if (typeof input.password !== 'string' || !safeEqual(input.password,adminPassword)) {
       state.count++;loginAttempts.set(ip,state);
       return send(res,401,{error:'Incorrect password'});
     }
     loginAttempts.delete(ip);
     res.setHeader('Set-Cookie',cookieHeader(signedToken(),ADMIN_MAX_AGE));
     return send(res,200,{authenticated:true});
   }
   if (url.pathname === '/api/admin/logout' && req.method === 'POST') {
     if (!sameOrigin(req)) return send(res,403,{error:'Invalid origin'});
     res.setHeader('Set-Cookie',cookieHeader('',0));
     return send(res,200,{authenticated:false});
   }
   if (!adminAuthorized(req)) return send(res,401,{error:'Login required'});
   if (url.pathname === '/api/admin/orders' && req.method === 'GET') {
     try {
       // Stripe is the durable source for historical Checkout payments; no ephemeral Render disk.
       const page = await stripe.checkout.sessions.list({limit:50});
       const sessions = page.data.filter(s=>s.mode==='payment');
       const orders = await Promise.all(sessions.map(async s => {
         let items=[];
         try {
           const result = await stripe.checkout.sessions.listLineItems(s.id,{limit:100});
           items = result.data.map(i=>({description:i.description,quantity:i.quantity,amount_total:i.amount_total}));
         } catch(e) { console.error('Admin line items unavailable:',e.message); }
         return {
           id:s.id,created:s.created,amount_total:s.amount_total,currency:s.currency,
           payment_status:s.payment_status,status:s.status,
           customer_name:s.customer_details?.name || null,
           customer_email:s.customer_details?.email || s.customer_email || null,
           shipping_name:s.shipping_details?.name || s.collected_information?.shipping_details?.name || null,
           shipping_address:s.shipping_details?.address || s.collected_information?.shipping_details?.address || null,
           items,
           fulfilment_status: s.metadata?.fulfilment_status || (s.payment_status === 'paid' ? 'Preparing' : null)
         };
       }));
       return send(res,200,{orders,has_more:page.has_more,source:'stripe'});
     } catch(e) {
       console.error('Admin Stripe lookup failed:',e.message);
       return send(res,502,{error:'Could not retrieve Stripe orders. Check Checkout Sessions API permissions.'});
     }
   }
   if (url.pathname === '/api/admin/order-status' && req.method === 'POST') {
     if (!sameOrigin(req)) return send(res,403,{error:'Invalid origin'});
     let body;
     try { body = await jsonBody(req,1024); }
     catch { return send(res,400,{error:'Invalid request'}); }
     const allowed = ['Preparing','Ready for dispatch','Dispatched','Delivered'];
     if (typeof body.id !== 'string' || !/^cs_(live|test)_[a-zA-Z0-9]+$/.test(body.id) || !allowed.includes(body.status))
       return send(res,400,{error:'Invalid order or status'});
     try {
       const session = await stripe.checkout.sessions.retrieve(body.id);
       if (session.mode !== 'payment' || session.payment_status !== 'paid')
         return send(res,400,{error:'Only paid orders can be updated'});
       // Stripe Checkout Session metadata persists across Render restarts.
       const updated = await stripe.checkout.sessions.update(session.id, {
         metadata: {...(session.metadata || {}), fulfilment_status: body.status}
       });
       return send(res,200,{id:updated.id,status:updated.metadata.fulfilment_status});
     } catch(e) {
       console.error('Admin status update failed:',e.message);
       return send(res,502,{error:'Could not save order status to Stripe'});
     }
   }
       if (url.pathname === '/api/admin/products' && req.method === 'GET') {
      try { return send(res,200,{products:await productsFromDb(true)}); }
      catch { return send(res,503,{error:'Could not load products from Supabase'}); }
    }
    if (url.pathname === '/api/admin/products' && req.method === 'POST') {
      if (!sameOrigin(req)) return send(res,403,{error:'Invalid origin'});
      try {
        const product = validateProduct(await jsonBody(req,8192));
        const saved = await db('products?select=*',{method:'POST',headers:{'Content-Type':'application/json','Prefer':'return=representation'},body:JSON.stringify(product)});
        return send(res,201,{product:saved[0]});
      } catch(e) { return send(res,400,{error:e.message}); }
    }
    const productMatch = url.pathname.match(/^\/api\/admin\/products\/(\d+)$/);
    if (productMatch && req.method === 'PATCH') {
      if (!sameOrigin(req)) return send(res,403,{error:'Invalid origin'});
      try {
        const id=Number(productMatch[1]);
        if (!Number.isSafeInteger(id) || id < 1) throw Error('Invalid product ID');
        const product=validateProduct(await jsonBody(req,8192),true);
        const saved=await db(`products?id=eq.${id}&select=*`,{method:'PATCH',headers:{'Content-Type':'application/json','Prefer':'return=representation'},body:JSON.stringify(product)});
        if (!saved.length) return send(res,404,{error:'Product not found'});
        return send(res,200,{product:saved[0]});
      } catch(e) { return send(res,400,{error:e.message}); }
    }
return send(res,404,{error:'Not found'});
 }
 if (req.method === 'POST' && url.pathname === '/api/webhook') {
  try {
    if (!process.env.STRIPE_WEBHOOK_SECRET) {
      return send(res, 503, { error: 'Webhook not configured' });
    }

    const chunks = [];
    let size = 0;

    for await (const chunk of req) {
      size += chunk.length;
      if (size > 1024 * 1024) {
        return send(res, 413, { error: 'Payload too large' });
      }
      chunks.push(chunk);
    }

    const payload = Buffer.concat(chunks);
    const signature = req.headers['stripe-signature'];

    if (!signature) {
      return send(res, 400, { error: 'Missing Stripe signature' });
    }

    const event = stripe.webhooks.constructEvent(
      payload,
      signature,
      process.env.STRIPE_WEBHOOK_SECRET
    );

    if (event.type === 'checkout.session.completed') {
      const session = event.data.object;

      if (session.payment_status === 'paid') {
        console.log('Verified Stripe payment:', session.id);
        // TODO: Save the paid order in persistent storage.
        // Do not fulfil orders based on this log alone.
      }
    }

    return send(res, 200, { received: true });
  } catch (error) {
    console.error('Stripe webhook verification failed:', error.message);
    return send(res, 400, { error: 'Invalid webhook' });
  }
} 
 if(req.method==='GET' && url.pathname==='/api/health') return send(res,200,{status:'ok',service:'alkaline-online'});
   if(req.method==='GET' && url.pathname==='/api/products') {
    try { return send(res,200,{products:await productsFromDb()}); }
    catch { return send(res,503,{error:'Product catalogue temporarily unavailable'}); }
  }
  if(req.method==='POST' && url.pathname==='/api/orders')
    return send(res,410,{error:'Order previews are no longer available; use secure checkout.'});
if (req.method === 'POST' && url.pathname === '/api/checkout') {
  try {
    if (!process.env.STRIPE_SECRET_KEY) {
      return send(res, 503, { error: 'Payments are not configured' });
    }

    let raw = '';
    for await (const chunk of req) {
      raw += chunk;
      if (raw.length > 12000) throw Error('Request too large');
    }

    const body = JSON.parse(raw);
    const items = body.items;

    if (!Array.isArray(items) || !items.length || items.length > 50) {
      throw Error('Invalid basket');
    }

    const available = await productsFromDb();
    const line_items = items.map(item => {
      if (!Number.isSafeInteger(item.id) || !Number.isInteger(item.quantity) || item.quantity < 1 || item.quantity > 100) throw Error('Invalid item');
      const product = available.find(p => p.id === item.id);
      if (!product || product.stock_quantity < item.quantity) throw Error('Product unavailable or insufficient stock');
      return {
        price_data: {currency:'gbp',product_data:{name:product.name},unit_amount:product.price_pence},
        quantity:item.quantity
      };
    });

    const session = await stripe.checkout.sessions.create({
      mode: 'payment',
      line_items,
      success_url: ALLOWED_ORIGIN + '/?payment=success&session_id={CHECKOUT_SESSION_ID}',
      cancel_url: ALLOWED_ORIGIN + '/?payment=cancelled',
      billing_address_collection: 'required',
      shipping_address_collection: {
        allowed_countries: ['GB']
      }
    });

    return send(res, 200, { url: session.url });
  } catch (error) {
    console.error('Checkout error:', error.message);
    return send(res, 400, { error: error.message === 'Product unavailable or insufficient stock' ? error.message : 'Unable to create checkout session' });
  }
}
  
  if(req.method==='GET' && (url.pathname==='/'||url.pathname==='/index.html')){res.writeHead(200,{'Content-Type':'text/html; charset=utf-8'});return fs.createReadStream(path.join(__dirname,'index.html')).pipe(res);}
 return send(res,404,{error:'Not found'});
}).listen(PORT,'0.0.0.0',()=>console.log(`Alkaline Online listening on ${PORT}`));
