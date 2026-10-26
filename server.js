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
 if(req.method==='GET' && url.pathname==='/api/health') return send(res,200,{status:'ok',service:'alkaline-online'});
 if(req.method==='GET' && url.pathname==='/api/products') return send(res,200,{products:catalog});
 if(req.method==='POST' && url.pathname==='/api/orders') {
  let raw='';try{for await(const chunk of req){raw+=chunk;if(raw.length>12000)throw Error('Request too large');}const body=JSON.parse(raw);
   const items=body.items;if(!Array.isArray(items)||!items.length||items.length>50)throw Error('Invalid basket');
   let total=0;for(const item of items){const p=catalog.find(p=>p.id===item.id);if(!p||!Number.isInteger(item.quantity)||item.quantity<1||item.quantity>100)throw Error('Invalid item');total+=p.price*item.quantity;}
   return send(res,200,{reference:crypto.randomUUID(),totalPence:total,status:'demo_only',message:'Order preview only. No payment taken or order saved.'});
  }catch(e){return send(res,400,{error:e.message});}
 }
 if(req.method==='GET' && (url.pathname==='/'||url.pathname==='/index.html')){res.writeHead(200,{'Content-Type':'text/html; charset=utf-8'});return fs.createReadStream(path.join(__dirname,'index.html')).pipe(res);}
 return send(res,404,{error:'Not found'});
}).listen(PORT,'0.0.0.0',()=>console.log(`Alkaline Online listening on ${PORT}`));
