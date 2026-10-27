const Stripe = require('stripe');
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const PORT = Number(process.env.PORT || 3000);
const ALLOWED_ORIGIN = "https://alkaline-online.onrender.com";
const catalog = [{id:1,price:650},{id:2,price:495},{id:3,price:575},{id:4,price:725},{id:5,price:695},{id:6,price:525},{id:7,price:395},{id:8,price:450}];
const send=(res,status,obj)=>{res.writeHead(status,{'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store'});res.end(JSON.stringify(obj));};
http.createServer(async (req,res)=>{
res.setHeader("Access-Control-Allow-Origin", ALLOWED_ORIGIN);
res.setHeader("Vary", "Origin");
res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
res.setHeader("Access-Control-Allow-Headers", "Content-Type");

if (req.method === "OPTIONS") {
  res.writeHead(204);
  return res.end();
}
 const url = new URL(req.url,'http://localhost');
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
 if(req.method==='GET' && url.pathname==='/api/products') return send(res,200,{products:catalog});
 if(req.method==='POST' && url.pathname==='/api/orders') {
  let raw='';try{for await(const chunk of req){raw+=chunk;if(raw.length>12000)throw Error('Request too large');}const body=JSON.parse(raw);
   const items=body.items;if(!Array.isArray(items)||!items.length||items.length>50)throw Error('Invalid basket');
   let total=0;for(const item of items){const p=catalog.find(p=>p.id===item.id);if(!p||!Number.isInteger(item.quantity)||item.quantity<1||item.quantity>100)throw Error('Invalid item');total+=p.price*item.quantity;}
   return send(res,200,{reference:crypto.randomUUID(),totalPence:total,status:'demo_only',message:'Order preview only. No payment taken or order saved.'});
  }catch(e){return send(res,400,{error:e.message});}
 }
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

    const names = [
      'Organic Chamomile Tea',
      'Dried Peppermint Leaves',
      'Organic Turmeric Powder',
      'Organic Chia Seeds',
      'Hibiscus Flower Tea',
      'Organic Ceylon Cinnamon',
      'Dried Rosemary',
      'Organic Rolled Oats'
    ];

    const line_items = items.map(item => {
      const product = catalog.find(p => p.id === item.id);

      if (!product || !Number.isInteger(item.quantity) ||
          item.quantity < 1 || item.quantity > 100) {
        throw Error('Invalid item');
      }

      return {
        price_data: {
          currency: 'gbp',
          product_data: { name: names[product.id - 1] },
          unit_amount: product.price
        },
        quantity: item.quantity
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
    console.error('Checkout error:', error);
    return send(res, 400, { error: 'Unable to create checkout session' });
  }
}
  
  if(req.method==='GET' && (url.pathname==='/'||url.pathname==='/index.html')){res.writeHead(200,{'Content-Type':'text/html; charset=utf-8'});return fs.createReadStream(path.join(__dirname,'index.html')).pipe(res);}
 return send(res,404,{error:'Not found'});
}).listen(PORT,'0.0.0.0',()=>console.log(`Alkaline Online listening on ${PORT}`));
