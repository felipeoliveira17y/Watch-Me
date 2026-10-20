const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { DatabaseSync } = require('node:sqlite');

const ROOT = __dirname;
const DATA_DIR = path.resolve(process.env.RESQ_DATA_DIR || path.join(ROOT, 'data'));
fs.mkdirSync(DATA_DIR, { recursive: true });
const db = new DatabaseSync(path.join(DATA_DIR, 'resq.sqlite'));
db.exec('PRAGMA foreign_keys=ON; CREATE TABLE IF NOT EXISTS schema_migrations(version INTEGER PRIMARY KEY,applied_at TEXT NOT NULL);');
const migrationsPath=path.join(ROOT,'migrations');
for(const file of fs.readdirSync(migrationsPath).filter(name=>/^\d+_.+\.sql$/.test(name)).sort()){
  const version=Number(file.match(/^\d+/)[0]);
  if(db.prepare('SELECT version FROM schema_migrations WHERE version=?').get(version))continue;
  db.exec('BEGIN IMMEDIATE');
  try{db.exec(fs.readFileSync(path.join(migrationsPath,file),'utf8'));db.prepare('INSERT INTO schema_migrations(version,applied_at) VALUES(?,?)').run(version,new Date().toISOString());db.exec('COMMIT');}
  catch(error){db.exec('ROLLBACK');throw error;}
}

const now = () => new Date().toISOString();
const uuid = () => crypto.randomUUID();
const hash = value => crypto.createHash('sha256').update(value).digest('hex');
const randomToken = () => crypto.randomBytes(32).toString('base64url');
const roomSecret = process.env.RESQ_ROOM_SECRET || '';
const eventRoomToken = (deviceId,eventKey) => crypto.createHmac('sha256',roomSecret).update(`${deviceId}:${eventKey}`).digest('base64url');
const adminPassword = process.env.RESQ_ADMIN_PASSWORD || '';
const isProduction = process.env.NODE_ENV === 'production';
const rateBuckets = new Map();
const official = [
  { position: 1, name: 'Polícia Militar', phone: '190', category: 'official', is_official: 1 },
  { position: 2, name: 'Polícia Civil', phone: '197', category: 'official', is_official: 1 }
];
const mime = { '.html':'text/html; charset=utf-8','.css':'text/css; charset=utf-8','.js':'text/javascript; charset=utf-8','.svg':'image/svg+xml','.png':'image/png','.ico':'image/x-icon' };

function audit(action, type, id, metadata = null) {
  db.prepare('INSERT INTO audit_logs(id,actor,action,resource_type,resource_id,created_at,metadata) VALUES(?,?,?,?,?,?,?)').run(uuid(), 'admin-session', action, type, id, now(), metadata ? JSON.stringify(metadata) : null);
}
function cookie(req, name) {
  const raw = req.headers.cookie || '';
  const item = raw.split(';').map(x => x.trim()).find(x => x.startsWith(`${name}=`));
  return item ? decodeURIComponent(item.slice(name.length + 1)) : '';
}
function authorized(req) {
  const token = cookie(req, 'resq_session');
  if (!token) return false;
  const row = db.prepare('SELECT expires_at FROM sessions WHERE token_hash=?').get(hash(token));
  return !!row && row.expires_at > now();
}
function send(res, status, data, headers = {}) {
  res.writeHead(status, { 'content-type':'application/json; charset=utf-8', 'cache-control':'no-store', 'x-content-type-options':'nosniff', ...headers });
  res.end(JSON.stringify(data));
}
function fail(res, status, message) { send(res, status, { error: message }); }
async function body(req) {
  let value = '';
  for await (const chunk of req) { value += chunk; if (value.length > 200_000) throw new Error('Payload demasiado grande'); }
  try { return value ? JSON.parse(value) : {}; } catch { throw new Error('JSON inválido'); }
}
function phoneValid(value) { return /^\+[1-9]\d{7,14}$/.test(String(value || '')); }
function validCoords(lat, lng) { return Number.isFinite(lat) && Number.isFinite(lng) && lat >= -90 && lat <= 90 && lng >= -180 && lng <= 180; }
function rateAllowed(key,limit,windowMs){const t=Date.now();let bucket=rateBuckets.get(key);if(!bucket||t-bucket.start>=windowMs){bucket={start:t,count:0};rateBuckets.set(key,bucket);}bucket.count++;if(rateBuckets.size>1000)for(const [k,v] of rateBuckets)if(t-v.start>windowMs)rateBuckets.delete(k);return bucket.count<=limit;}
function publicEvent(row) { return { id:row.id, deviceId:row.device_id, eventType:row.event_type, source:row.source, status:row.status, receivedAt:row.received_at, occurredAt:row.occurred_at, latitude:row.latitude, longitude:row.longitude, accuracy:row.accuracy, simulated:!!row.is_simulated }; }

async function api(req, res, url) {
  const route = url.pathname;
  if (route === '/api/health' && req.method === 'GET') return send(res, 200, { ok:true, mode:adminPassword ? 'configured' : 'demo-only', database:'sqlite', hardware:'not connected' });
  if (route === '/api/session' && req.method === 'GET') return send(res, 200, { authenticated: authorized(req), adminConfigured:!!adminPassword });
  if (route === '/api/session' && req.method === 'POST') {
    if (!adminPassword) return fail(res, 503, 'Administração indisponível: configure RESQ_ADMIN_PASSWORD. O simulador continua disponível.');
    const input = await body(req);
    const a = Buffer.from(String(input.password || ''));
    const b = Buffer.from(adminPassword);
    if (a.length !== b.length || !crypto.timingSafeEqual(a,b)) return fail(res, 401, 'Palavra-passe inválida.');
    const session = randomToken();
    db.prepare('INSERT INTO sessions(token_hash,expires_at,created_at) VALUES(?,?,?)').run(hash(session), new Date(Date.now()+8*60*60*1000).toISOString(), now());
    return send(res,200,{authenticated:true},{'set-cookie':`resq_session=${encodeURIComponent(session)}; HttpOnly; SameSite=Strict; Path=/; Max-Age=28800${isProduction?'; Secure':''}`});
  }
  if (route === '/api/session' && req.method === 'DELETE') {
    const session = cookie(req,'resq_session'); if (session) db.prepare('DELETE FROM sessions WHERE token_hash=?').run(hash(session));
    return send(res,200,{authenticated:false},{'set-cookie':'resq_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0'});
  }
  if (route === '/api/demo/events' && req.method === 'POST') {
    const input = await body(req);
    const allowed = ['sos_manual','possible_fall','test','system'];
    if (!allowed.includes(input.type)) return fail(res,400,'Tipo de demonstração inválido.');
    let lat = null, lng = null;
    if (input.coordinates === true) { lat = -23.5505 + (Math.random()-.5)*.02; lng = -46.6333 + (Math.random()-.5)*.02; }
    const id=uuid(), token=randomToken(), stamp=now(), state='open';
    db.prepare('INSERT INTO events(id,event_type,source,status,received_at,occurred_at,latitude,longitude,is_simulated,updated_at) VALUES(?,?,?,?,?,?,?,?,1,?)').run(id,input.type,'simulator',state,stamp,stamp,lat,lng,stamp);
    db.prepare('INSERT INTO rooms(id,event_id,token_hash,expires_at,created_at) VALUES(?,?,?,?,?)').run(uuid(),id,hash(token),new Date(Date.now()+24*60*60*1000).toISOString(),stamp);
    db.prepare('INSERT INTO event_updates(id,event_id,update_type,payload,created_at) VALUES(?,?,?,?,?)').run(uuid(),id,'created',JSON.stringify({source:'simulator'}),stamp);
    audit('demo_event_created','event',id,{eventType:input.type,simulated:true});
    return send(res,201,{event:publicEvent(db.prepare('SELECT * FROM events WHERE id=?').get(id)),roomUrl:`/room/${token}`,simulated:true,notification:'not_sent'});
  }
  if (route === '/api/dashboard' && req.method === 'GET') {
    if (!authorized(req)) {
      const list=db.prepare('SELECT * FROM events WHERE is_simulated=1 ORDER BY received_at DESC LIMIT 6').all();
      return send(res,200,{mode:'demo',devices:null,openEvents:list.filter(e=>!['resolved','cancelled','closed'].includes(e.status)).length,recentEvents:list.map(publicEvent),connection:'Desconhecido'});
    }
    const list=db.prepare('SELECT * FROM events ORDER BY received_at DESC LIMIT 8').all();
    return send(res,200,{mode:'admin',devices:db.prepare("SELECT COUNT(*) n FROM devices WHERE status='active'").get().n,openEvents:db.prepare("SELECT COUNT(*) n FROM events WHERE status IN ('received','open','monitoring')").get().n,recentEvents:list.map(publicEvent),connection:'Sem dados'});
  }
  if (route.startsWith('/api/') && !route.startsWith('/api/device/') && !authorized(req)) return fail(res,401,'Autenticação necessária.');
  if (route === '/api/devices' && req.method === 'GET') {
    const rows=db.prepare('SELECT id,name,hardware_id,firmware,status,created_at,last_seen_at FROM devices ORDER BY created_at DESC').all(); return send(res,200,{devices:rows});
  }
  if (route === '/api/devices' && req.method === 'POST') {
    const input=await body(req); const name=String(input.name||'').trim();
    if(name.length<2||name.length>80) return fail(res,400,'Indique um nome entre 2 e 80 caracteres.');
    const id=uuid(), rawToken=randomToken(), stamp=now();
    try { db.prepare('INSERT INTO devices(id,name,hardware_id,firmware,status,token_hash,created_at) VALUES(?,?,?,?,?,?,?)').run(id,name,input.hardwareId||null,input.firmware||null,'active',hash(rawToken),stamp); }
    catch { return fail(res,409,'O identificador de hardware já está registado.'); }
    for(const item of official) db.prepare('INSERT INTO contacts(id,device_id,position,name,phone,category,is_official,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)').run(uuid(),id,item.position,item.name,item.phone,item.category,1,stamp,stamp);
    audit('device_created','device',id);
    return send(res,201,{device:{id,name,status:'active',created_at:stamp},deviceToken:rawToken,tokenNotice:'Guarde este segredo agora. Não voltará a ser mostrado.'});
  }
  const rotateMatch=route.match(/^\/api\/devices\/([^/]+)\/rotate-token$/);
  if(rotateMatch && req.method==='POST') {
    const token=randomToken(),result=db.prepare("UPDATE devices SET token_hash=? WHERE id=? AND status='active'").run(hash(token),rotateMatch[1]);
    if(!result.changes)return fail(res,404,'Dispositivo ativo não encontrado.');audit('device_token_rotated','device',rotateMatch[1]);return send(res,200,{deviceToken:token,tokenNotice:'Credencial anterior revogada. Guarde a nova credencial agora.'});
  }
  const deviceStatusMatch=route.match(/^\/api\/devices\/([^/]+)\/status$/);
  if(deviceStatusMatch && req.method==='PATCH') {
    const {status}=await body(req);if(!['active','revoked'].includes(status))return fail(res,400,'Estado administrativo inválido.');
    const result=db.prepare(`UPDATE devices SET status=?,token_hash=CASE WHEN ?='revoked' THEN NULL ELSE token_hash END WHERE id=?`).run(status,status,deviceStatusMatch[1]);
    if(!result.changes)return fail(res,404,'Dispositivo não encontrado.');audit(status==='revoked'?'device_revoked':'device_activated','device',deviceStatusMatch[1]);return send(res,200,{id:deviceStatusMatch[1],status});
  }
  const roomRevokeMatch=route.match(/^\/api\/events\/([^/]+)\/room$/);
  if(roomRevokeMatch && req.method==='DELETE') {
    const stamp=now(),result=db.prepare('UPDATE rooms SET revoked_at=? WHERE event_id=? AND revoked_at IS NULL').run(stamp,roomRevokeMatch[1]);
    if(!result.changes)return fail(res,404,'Sala não encontrada ou já revogada.');audit('room_revoked','room',roomRevokeMatch[1]);return send(res,200,{revoked:true});
  }
  const deviceMatch=route.match(/^\/api\/devices\/([^/]+)\/contacts$/);
  if(deviceMatch && req.method==='GET') return send(res,200,{contacts:db.prepare('SELECT position,name,phone,category,is_official,active FROM contacts WHERE device_id=? ORDER BY position').all(deviceMatch[1])});
  if(deviceMatch && req.method==='PUT') {
    const input=await body(req), deviceId=deviceMatch[1], personal=Array.isArray(input.contacts)?input.contacts:[];
    if(!db.prepare('SELECT id FROM devices WHERE id=?').get(deviceId)) return fail(res,404,'Dispositivo não encontrado.');
    if(personal.length>3) return fail(res,400,'São permitidos até três contactos pessoais.');
    const seen=new Set();
    for(let i=0;i<personal.length;i++){const c=personal[i],pos=i+3,phone=String(c.phone||'').trim(); if(!String(c.name||'').trim()||!phoneValid(phone)) return fail(res,400,'Preencha nome e telefone internacional válido (+DDI...).'); if(seen.has(phone)) return fail(res,400,'Remova contactos duplicados.'); seen.add(phone);}
    const stamp=now();
    const tx=db; tx.exec('BEGIN IMMEDIATE');
    try { tx.prepare('DELETE FROM contacts WHERE device_id=? AND position BETWEEN 3 AND 5').run(deviceId); for(let i=0;i<personal.length;i++){const c=personal[i];tx.prepare('INSERT INTO contacts(id,device_id,position,name,phone,category,is_official,active,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)').run(uuid(),deviceId,i+3,String(c.name).trim(),String(c.phone).trim(),'personal',0,c.active===false?0:1,stamp,stamp);} tx.exec('COMMIT'); }
    catch(e){tx.exec('ROLLBACK'); return fail(res,500,'Não foi possível guardar os contactos.');}
    audit('personal_contacts_updated','device',deviceId,{count:personal.length}); return send(res,200,{contacts:db.prepare('SELECT position,name,phone,category,is_official,active FROM contacts WHERE device_id=? ORDER BY position').all(deviceId)});
  }
  if(route==='/api/device/configuration' && req.method==='GET') {
    const deviceToken=(req.headers.authorization||'').replace(/^Bearer\s+/i,'');const device=db.prepare("SELECT id,name,firmware FROM devices WHERE token_hash=? AND status='active'").get(hash(deviceToken));
    if(!device)return fail(res,401,'Dispositivo não autorizado.');
    const contacts=db.prepare('SELECT position,name,phone,category,is_official,active FROM contacts WHERE device_id=? ORDER BY position').all(device.id);const stamp=now();
    db.prepare('UPDATE devices SET last_seen_at=? WHERE id=?').run(stamp,device.id);return send(res,200,{device:{id:device.id,name:device.name,firmware:device.firmware},contacts,serverTime:stamp,notifications:{enabled:false}});
  }
  if(route==='/api/events' && req.method==='GET') return send(res,200,{events:db.prepare('SELECT * FROM events ORDER BY received_at DESC LIMIT 100').all().map(publicEvent)});
  const statusMatch=route.match(/^\/api\/events\/([^/]+)\/status$/);
  if(statusMatch && req.method==='PATCH') {
    const {status}=await body(req), valid={received:['open','cancelled'],open:['monitoring','resolved','cancelled','closed'],monitoring:['resolved','cancelled','closed'],resolved:['closed'],cancelled:['closed'],closed:[]};
    const row=db.prepare('SELECT * FROM events WHERE id=?').get(statusMatch[1]); if(!row)return fail(res,404,'Ocorrência não encontrada.'); if(!valid[row.status]?.includes(status))return fail(res,409,'Transição de estado inválida.');
    const stamp=now();db.prepare('UPDATE events SET status=?,updated_at=? WHERE id=?').run(status,stamp,row.id);db.prepare('INSERT INTO event_updates(id,event_id,update_type,payload,created_at) VALUES(?,?,?,?,?)').run(uuid(),row.id,'status',JSON.stringify({from:row.status,to:status}),stamp);audit('event_status_changed','event',row.id,{from:row.status,to:status});return send(res,200,{event:publicEvent(db.prepare('SELECT * FROM events WHERE id=?').get(row.id))});
  }
  if(route==='/api/device/events' && req.method==='POST') {
    if(roomSecret.length<32)return fail(res,503,'Integração indisponível: configure RESQ_ROOM_SECRET com pelo menos 32 caracteres aleatórios.');
    const deviceToken=(req.headers.authorization||'').replace(/^Bearer\s+/i,''); if(!deviceToken)return fail(res,401,'Credencial do dispositivo em falta.');
    const device=db.prepare("SELECT id FROM devices WHERE token_hash=? AND status='active'").get(hash(deviceToken)); if(!device)return fail(res,401,'Dispositivo não autorizado.');
    const input=await body(req), allowed=['sos_manual','possible_fall','fall_confirmed','test','system'];
    if(!allowed.includes(input.type))return fail(res,400,'Tipo de evento inválido.');
    const eventKey=String(input.eventId||'');if(eventKey.length<8||eventKey.length>120)return fail(res,400,'eventId de idempotência obrigatório (8–120 caracteres).');
    const existing=db.prepare('SELECT * FROM events WHERE device_id=? AND event_key=?').get(device.id,eventKey);
    if(existing)return send(res,200,{event:publicEvent(existing),duplicate:true,roomUrl:`/room/${eventRoomToken(device.id,eventKey)}`,notification:'not_sent'});
    let lat=null,lng=null;if(input.latitude!==undefined||input.longitude!==undefined){if(!validCoords(input.latitude,input.longitude))return fail(res,400,'Coordenadas inválidas.');lat=input.latitude;lng=input.longitude;}
    const id=uuid(),token=eventRoomToken(device.id,eventKey),stamp=now(),occurred=input.occurredAt&&Number.isFinite(Date.parse(input.occurredAt))?new Date(input.occurredAt).toISOString():null;
    db.prepare('INSERT INTO events(id,device_id,event_key,event_type,source,status,received_at,occurred_at,latitude,longitude,accuracy,is_simulated,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,0,?)').run(id,device.id,eventKey,input.type,'device','received',stamp,occurred,lat,lng,Number.isFinite(input.accuracy)?input.accuracy:null,stamp);
    db.prepare('UPDATE devices SET last_seen_at=? WHERE id=?').run(stamp,device.id);
    db.prepare('INSERT INTO rooms(id,event_id,token_hash,expires_at,created_at) VALUES(?,?,?,?,?)').run(uuid(),id,hash(token),new Date(Date.now()+24*60*60*1000).toISOString(),stamp);
    db.prepare('INSERT INTO event_updates(id,event_id,update_type,payload,created_at) VALUES(?,?,?,?,?)').run(uuid(),id,'created',JSON.stringify({source:'device'}),stamp);
    audit('device_event_received','event',id,{eventType:input.type});
    return send(res,201,{event:publicEvent(db.prepare('SELECT * FROM events WHERE id=?').get(id)),roomUrl:`/room/${token}`,notification:'not_sent',delivery:'unknown'});
  }
  const locMatch=route.match(/^\/api\/device\/events\/([^/]+)\/location$/);
  if(locMatch && req.method==='POST') {
    const deviceToken=(req.headers.authorization||'').replace(/^Bearer\s+/i,''); if(!deviceToken)return fail(res,401,'Credencial do dispositivo em falta.');
    const device=db.prepare("SELECT id FROM devices WHERE token_hash=? AND status='active'").get(hash(deviceToken)); if(!device)return fail(res,401,'Dispositivo não autorizado.');
    const event=db.prepare('SELECT * FROM events WHERE id=? AND device_id=?').get(locMatch[1],device.id);if(!event)return fail(res,404,'Ocorrência não encontrada.'); const input=await body(req);if(!validCoords(input.latitude,input.longitude))return fail(res,400,'Coordenadas inválidas.');
    const stamp=now();db.prepare('UPDATE events SET latitude=?,longitude=?,accuracy=?,updated_at=? WHERE id=?').run(input.latitude,input.longitude,Number.isFinite(input.accuracy)?input.accuracy:null,stamp,event.id);db.prepare('INSERT INTO event_updates(id,event_id,update_type,payload,created_at) VALUES(?,?,?,?,?)').run(uuid(),event.id,'location',JSON.stringify({latitude:input.latitude,longitude:input.longitude,accuracy:input.accuracy||null}),stamp);return send(res,200,{accepted:true,receivedAt:stamp});
  }
  return fail(res,404,'Rota não encontrada.');
}

async function room(req,res,token) {
  const r=db.prepare('SELECT r.event_id AS room_event_id,r.expires_at AS room_expires_at,r.revoked_at,e.* FROM rooms r JOIN events e ON e.id=r.event_id WHERE r.token_hash=?').get(hash(token));
  if(!r || r.revoked_at || r.room_expires_at<now()) return send(res,404,{error:'Esta sala expirou, foi revogada ou não existe.'});
  const updates=db.prepare('SELECT update_type,payload,created_at FROM event_updates WHERE event_id=? ORDER BY created_at').all(r.room_event_id).map(x=>({...x,payload:JSON.parse(x.payload)}));
  return send(res,200,{event:publicEvent(r),updates,simulated:!!r.is_simulated,roomExpiresAt:r.room_expires_at,warning:r.is_simulated?'Demonstração fictícia; não contactar serviços de emergência com estes dados.':'Sala privada acessível a quem possuir este link. Confirme os canais locais adequados.'});
}

const server=http.createServer(async(req,res)=>{
  res.setHeader('content-security-policy',"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com data:; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'");
  res.setHeader('referrer-policy','no-referrer'); res.setHeader('x-frame-options','DENY'); res.setHeader('permissions-policy','geolocation=(),camera=(),microphone=()');
  const url=new URL(req.url,'http://localhost');
  try {
    if(url.pathname==='/api/session'&&req.method==='POST'&&!rateAllowed(`login:${req.socket.remoteAddress}`,10,15*60_000))return fail(res,429,'Muitas tentativas. Aguarde antes de tentar novamente.');
    if(url.pathname.startsWith('/api/device/')&&!rateAllowed(`device:${req.socket.remoteAddress}`,120,60_000))return fail(res,429,'Limite temporário de pedidos atingido.');
    if(url.pathname==='/api/demo/events'&&req.method==='POST'&&!rateAllowed(`demo:${req.socket.remoteAddress}`,40,60_000))return fail(res,429,'Limite de demonstrações atingido.');
    if(url.pathname.startsWith('/api/')) return await api(req,res,url);
    if(url.pathname.startsWith('/room/')) {
      if((req.headers.accept||'').includes('text/html')) { const html=fs.readFileSync(path.join(ROOT,'public','index.html')); res.writeHead(200,{'content-type':'text/html; charset=utf-8','cache-control':'no-store','x-robots-tag':'noindex, nofollow, noarchive'}); return res.end(html); }
      return await room(req,res,decodeURIComponent(url.pathname.slice(6)));
    }
    const requested=url.pathname==='/'?'/index.html':decodeURIComponent(url.pathname); const file=path.resolve(ROOT,'public',`.${requested}`);
    if(!file.startsWith(path.resolve(ROOT,'public')+path.sep)) return fail(res,400,'Caminho inválido.');
    fs.readFile(file,(err,data)=>{if(err){res.writeHead(404,{'content-type':'text/plain'});res.end('Não encontrado');return;}res.writeHead(200,{'content-type':mime[path.extname(file)]||'application/octet-stream','cache-control':'no-cache'});res.end(data);});
  } catch(e) { fail(res,e.message==='Payload demasiado grande'?413:400,e.message||'Pedido inválido.'); }
});

const port=Number(process.env.PORT)||3000;
server.listen(port,'127.0.0.1',()=>console.log(`ResQ Wear local em http://127.0.0.1:${port} (${adminPassword?'admin configurado':'modo demonstração'})`));
