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
  { position: 1, name: 'Pol√≠cia Militar', phone: '190', category: 'official', is_official: 1 },
  { position: 2, name: 'Pol√≠cia Civil', phone: '197', category: 'official', is_official: 1 }
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
  try { return value ? JSON.parse(value) : {}; } catch { throw new Error('JSON inv√°lido'); }
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
    if (!adminPassword) return fail(res, 503, 'Administra√ß√£o indispon√≠vel: configure RESQ_ADMIN_PASSWORD. O simulador continua dispon√≠vel.');
    const input = await body(req);
    const a = Buffer.from(String(input.password || ''));
    const b = Buffer.from(adminPassword);
    if (a.length !== b.length || !crypto.timingSafeEqual(a,b)) return fail(res, 401, 'Palavra-passe inv√°lida.');
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
    if (!allowed.includes(input.type)) return fail(res,400,'Tipo de demonstra√ß√£o inv√°lido.');
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
  if (route.startsWith('/api/') && !route.startsWith('/api/device/') && !authorized(req)) return fail(res,401,'Autentica√ß√£o necess√°ria.');
  if (route === '/api/devices' && req.method === 'GET') {
    const rows=db.prepare('SELECT id,name,hardware_id,firmware,status,created_at,last_seen_at FROM devices ORDER BY created_at DESC').all(); return send(res,200,{devices:rows});
  }
  if (route === '/api/devices' && req.method === 'POST') {
    const input=await body(req); const name=String(input.name||'').trim();
    if(name.length<2||name.length>80) return fail(res,400,'Indique um nome entre 2 e 80 caracteres.');
    const id=uuid(), rawToken=randomToken(), stamp=now();
    try { db.prepare('INSERT INTO devices(id,name,hardware_id,firmware,status,token_hash,created_at) VALUES(?,?,?,?,?,?,?)').run(id,name,input.hardwareId||null,input.firmware||null,'active',hash(rawToken),stamp); }
    catch { return fail(res,409,'O identificador de hardware j√° est√° registado.'); }
    for(const item of official) db.prepare('INSERT INTO contacts(id,device_id,position,name,phone,category,is_official,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)').run(uuid(),id,item.position,item.name,item.phone,item.category,1,stamp,stamp);
    audit('device_created','device',id);
    return send(res,201,{device:{id,name,status:'active',created_at:stamp},deviceToken:rawToken,tokenNotice:'Guarde este segredo agora. N√£o voltar√° a ser mostrado.'});
  }
  const rotateMatch=route.match(/^\/api\/devices\/([^/]+)\/rotate-token$/);
  if(rotateMatch && req.method==='POST') {
    const token=randomToken(),result=db.prepare("UPDATE devices SET token_hash=? WHERE id=? AND status='active'").run(hash(token),rotateMatch[1]);
    if(!result.changes)return fail(res,404,'Dispositivo ativo n√£o encontrado.');audit('device_token_rotated','device',rotateMatch[1]);return send(res,200,{deviceToken:token,tokenNotice:'Credencial anterior revogada. Guarde a nova credencial agora.'});
  }
  const deviceStatusMatch=route.match(/^\/api\/devices\/([^/]+)\/status$/);
  if(deviceStatusMatch && req.method==='PATCH') {
    const {status}=await body(req);if(!['active','revoked'].includes(status))return fail(res,400,'Estado administrativo inv√°lido.');
    const result=db.prepare(`UPDATE devices SET status=?,token_hash=CASE WHEN ?='revoked' THEN NULL ELSE token_hash END WHERE id=?`).run(status,status,deviceStatusMatch[1]);
    if(!result.changes)return fail(res,404,'Dispositivo n√£o encontrado.');audit(status==='revoked'?'device_revoked':'device_activated','device',deviceStatusMatch[1]);return send(res,200,{id:deviceStatusMatch[1],status});
  }
  const roomRevokeMatch=route.match(/^\/api\/events\/([^/]+)\/room$/);
  if(roomRevokeMatch && req.method==='DELETE') {
    const stamp=now(),result=db.prepare('UPDATE rooms SET revoked_at=? WHERE event_id=? AND revoked_at IS NULL').run(stamp,roomRevokeMatch[1]);
    if(!result.changes)return fail(res,404,'Sala n√£o encontrada ou j√° revogada.');audit('room_revoked','room',roomRevokeMatch[1]);return send(res,200,{revoked:true});
  }
  const deviceMatch=route.match(/^\/api\/devices\/([^/]+)\/contacts$/);
  if(deviceMatch && req.method==='GET') return send(res,200,{contacts:db.prepare('SELECT position,name,phone,category,is_official,active FROM contacts WHERE device_id=? ORDER BY position').all(deviceMatch[1])});
  if(deviceMatch && req.method==='PUT') {
    const input=await body(req), deviceId=deviceMatch[1], personal=Array.isArray(input.contacts)?input.contacts:[];
    if(!db.prepare('SELECT id FROM devices WHERE id=?').get(deviceId)) return fail(res,404,'Dispositivo n√£o encontrado.');
    if(personal.length>3) return fail(res,400,'S√£o permitidos at√© tr√™s contactos pessoais.');
    const seen=new Set();
    for(let i=0;i<personal.length;i++){const c=personal[i],pos=i+3,phone=String(c.phone||'').trim(); if(!String(c.name||'').trim()||!phoneValid(phone)) return fail(res,400,'Preencha nome e telefone internacional v√°lido (+DDI...).'); if(seen.has(phone)) return fail(res,400,'Remova conwm|ÎãhëÈÏ∂ªßq´^uXY[ô»èè]èèèí[ùô[ù0Ë\ö[œ⁄èèíY[ùYöXÿY‹ô\»H\›Y»YZ[ö\›ò]]õœ‹èŸ]èè‹[à€\‹œHò€›[ùXòYŸHàYHô]öXŸKX€›[ùèå\‹‹⁄]]õ‹œ‹‹[èèŸ]èè]àYHô]öXŸ\À[\›èèŸ]èèŸ]èè‹ŸX›[€èÇÇèŸX›[€à€\‹œHùöY]»àYHùöY]ÀX€€ùX›»èè]à€\‹œHúYŸKZXY[ô»èè]èè€\‹œHô^YXúõ›»èê„Tê’S»HT“Sœ‹èOê€€ùX›‹œ⁄Oèë⁄\»Ÿ\ùöpÈ€‹»ŸöX⁄XZ\»õ›Y⁄Y‹»H]0ÍH∞Íú»€€ùX›‹»\‹€ÿZ\»‹à\‹‹⁄]]õÀè‹èŸ]èèù]€à€\‹œHòù]€àö[X\ûHàYHúÿ]ôKX€€ùX›»èë›X\ô\à[\òpÈÌY\œÿù]€èèŸ]èè]à€\‹œHò€€ùX›[^[›]èè\⁄YH€\‹œHú[ô[]öXŸK\X⁄Ÿ\àèèèîŸ[X⁄[€ò\à\‹‹⁄]]õœ⁄èèì‹»€€ùX›‹»\ù[òŸ[HH[H\‹‹⁄]]õ»ôY⁄\›YÀè‹èŸ[X›YHò€€ùX›Y]öXŸHèè‹[€àò[YOHàèë\ÿ€€H[H\‹‹⁄]]õœ€‹[€èè‹Ÿ[X›è]à€\‹œHõŸôöX⁄X[Z[ôõ»èè‹[èàO‹‹[èèì‹»€€ùX›‹»ŸöX⁄XZ\»Ë€»ôYô\∞Íõò⁄X\»[öX⁄XZ\»\òH»úò\⁄[à€€ôö\õYH‹»Ÿ\ùöpÈ€‹»H∞ÓõY\õ‹»\òHHôY⁄pË€»[ù\»H]X[]Y\à][^òpÈË€»ôX[è‹èŸ]èèÿ\⁄YOè]à€\‹œHú[ô[€€ùX›À\[ô[èè]àYHò€€ùX›ÀX€€ù[ùèè]à€\‹œHô[\K\›]Hèè‹[à€\‹œHô[\K\ﬁ[Xõ€è∏•„è‹‹[èèèîŸ[X⁄[€ôH[H\‹‹⁄]]õœÿèè€X[îôY⁄\›H[H\‹‹⁄]]õ»\òHŸ\ö\à\»‹⁄pÈÌY\»H€€ùX›Àè‹€X[èù]€à€\‹œHòù]€àŸX€€ô\ûHà]KY€›œHô]öXŸ\»èïô\à\‹‹⁄]]õ‹œÿù]€èèŸ]èèŸ]èèŸ]èèŸ]èè‹ŸX›[€èÇÇèŸX›[€à€\‹œHùöY]»àYHùöY]ÀY]ô[ù»èè]à€\‹œHúYŸKZXY[ô»èè]èè€\‹œHô^YXúõ›»èê—Sïì»HëT‘‘’O‹èOìÿ€‹ú∞Íõò⁄X\œ⁄Oèë]ô[ù‹»ôXŸXöY‹»[»òX⁄Ÿ[ô›HŸ\òY‹»õ»⁄[][Y‹ãè‹èŸ]èèù]€à€\‹œHòù]€àö[X\ûHà]KY€›œHú⁄[][]‹àèªÔ"»‹[èìõ›òH⁄[][pÈË€œ‹‹[èèÿù]€èèŸ]èè]à€\‹œHú[ô[XõK\[ô[èè]à€\‹œHú[ô[ZXY[ô»èè]èèèí\›0Ï‹öX€œ⁄èèë]ô[ù‹»ôXZ\»H⁄[][Y‹»Ë€»Y[ùYöXÿY‹»Ÿ\\òY[Y[ùKè‹èŸ]èè‹[à€\‹œHò€›[ùXòYŸHàYHô]ô[ùX€›[ùèåÿ€‹ú∞Íõò⁄X\œ‹‹[èèŸ]èè]àYHô]ô[ùÀ[\›èèŸ]èèŸ]èè‹ŸX›[€èÇÇèŸX›[€à€\‹œHùöY]»àYHùöY]À\⁄[][]‹àèè]à€\‹œHúYŸKZXY[ô»èè]èè€\‹œHô^YXúõ›»èêSPíQSïHT””Q»0≠»—SHTë–TëO‹èOî⁄[][Y‹è⁄Oèë^‹ôH»\ò›\ú€»H[H]ô[ù»Ÿ[H€€ùX›\àö[ô›pÍ[Kè‹èŸ]èè‹[à€\‹œHô[[À\[èèOè⁄OàQ‘»íP’0„P“S‘œ‹‹[èèŸ]èè]à€\‹œHú⁄[KY‹öYèè]à€\‹œHú[ô[⁄[KYõ‹õHèè]à€\‹œHú[ô[ZXY[ô»èè]èèèëŸ\ò\à]ô[ùœ⁄èèê‹öXH[XHÿ€‹ú∞Íõò⁄XHH[XHÿ[Hö]òYH[\‹∞Ë\öXKè‹èŸ]èèŸ]èèXô[€\‹œHôöY[[Xô[àõ‹èHô]ô[ù]\HèïT»HUëSïœ€Xô[èŸ[X›YHô]ô[ù]\Hèè‹[€àò[YOHú€‹◊€X[ùX[èî”‘»X[ùX[
⁄[][Y O€‹[€èè‹[€àò[YOHú‹‹⁄XõWŸò[èî‹‹Î]ô[]YYH
⁄[][YJO€‹[€èè‹[€àò[YOHù\›èï\›HH[ùY‹òpÈË€œ€‹[€èè‹[€àò[YOHúﬁ\›[Hèë]ô[ù»H⁄\›[XO€‹[€èè‹Ÿ[X›èXô[€\‹œHùŸŸ€K\õ›»èè[ú]\OHò⁄X⁄ÿõﬁàYHôòZŸK[ÿÿ][€àà⁄X⁄ŸYè‹[à€\‹œHùŸŸ€Hèè‹‹[èè‹[èèèí[ò€Z\àÿÿ[^òpÈË€»öX›0ÎX⁄XOÿèè€X[ê€€‹ô[òY\»\õﬁ[XY\»HË€»][ÀŸ\òY\»[X]‹öX[Y[ùKè‹€X[è‹‹[èè€Xô[èù]€à€\‹œHòù]€àö[X\ûHù[àYHò‹ôX]KY]ô[ùèëŸ\ò\à⁄[][pÈË€»‹[è∏°§è‹‹[èèÿù]€èè€\‹œHõZX‹õÀ[õ›Hèì∞Ë€»[ùöXH”TÀ∞Ë€»[öX⁄XH⁄[XY\»H∞Ë€»ô\ô\Ÿ[ùH[XHÿ€‹ú∞Íõò⁄XHôX[è‹èŸ]èè]à€\‹œHú[ô[⁄[][]‹ã\ô\›[àYHú⁄[K\ô\›[èè]à€\‹œHúô\›[\XŸZ€\àèè‹[à€\‹œHúô\›[[‹òö]è∏ß,œ‹‹[èèèêH⁄[][pÈË€»\\ôXŸ\∞ËH\]ZOÿèè€X[ëŸ\ôH[H]ô[ù»\òH‹öX\à[XHÿ[HHX€€\[ö\à‹»ô\‹]]õ‹»\›Y‹Àè‹€X[èŸ]èèŸ]èèŸ]èè]à€\‹œHú⁄[K]ÿ\õö[ô»èèèì[Z]\»H[[€ú›òpÈË€œÿèè‹[èì‹»]ô[ù‹»öXÿ[HX\òÿY‹»€€[»⁄[][Y‹»òHò\ŸHHY‹»Hõ»\›0Ï‹öX€Àà\›H[Ÿ»∞Ë€»ŸH[ùöX\àõ›YöXÿpÈÌY\»\òH€€ùX›‹»ôXZ\Àè‹‹[èèŸ]èè‹ŸX›[€èÇÇèŸX›[€à€\‹œHùöY]»àYHùöY]À\õ€€Hèè]àYHúõ€€KX€€ù[ùèèŸ]èè‹ŸX›[€èÇèŸ]èèõ€›\à€\‹œHôõ€›\àèè‹[èîô\‘HŸX\àè∞≠œÿèà–U“QHçè‹‹[èè‹[èëô\úò[Y[ùHH\⁄[Àà∞Ë€»›Xú›]ZHŸ\ùöpÈ€‹»H[Y\ôÍõò⁄XKè‹‹[èè‹[èîíUêP“QQH‘àQ∞‡”œ‹‹[èèŸõ€›\èè€XZ[èÇèX[Ÿ»YHõŸ⁄[ãYX[Ÿ»èèõ‹õHY]ŸHôX[Ÿ»à€\‹œHôX[ŸÀXÿ\ôàYHõŸ⁄[ãYõ‹õHèèù]€à€\‹œHôX[ŸÀX€‹ŸHàò[YOHòÿ[òŸ[à\öXK[Xô[HëôX⁄\àè∞Âœÿù]€èè‹[à€\‹œHôX[ŸÀ\ﬁ[Xõ€è∏£$O‹‹[èè€\‹œHô^YXúõ›»è∞‡TëPHQRSíT’êUUêO‹èèë[ùò\àòHŸ\›0Ë€œ⁄èèêHYZ[ö\›òpÈË€»Ï»öXÿH]]òH\0Ï‹»€€ôöY›\ò\à[XH[]úòK\\‹ŸHÿÿ[õ»Ÿ\ùöY‹ãè‹èXô[õ‹èHòYZ[ã\\‹›€‹ôèî[]úòK\\‹ŸHYZ[ö\›ò]]òO€Xô[è[ú]YHòYZ[ã\\‹›€‹ôà\OHú\‹›€‹ôà]]ÿ€€\]OHò›\úô[ù\\‹›€‹ôàô\]Z\ôYè]à€\‹œHôõ‹õKY\úõ‹ààYHõŸ⁄[ãY\úõ‹àèèŸ]èèù]€à€\‹œHòù]€àö[X\ûHù[àò[YOHôYò][èí[öX⁄X\àŸ\‹Ë€œÿù]€èèŸõ‹õOèŸX[ŸœèX[Ÿ»YHô]öXŸKYX[Ÿ»èèõ‹õHY]ŸHôX[Ÿ»à€\‹œHôX[ŸÀXÿ\ôàYHô]öXŸKYõ‹õHèèù]€à€\‹œHôX[ŸÀX€‹ŸHàò[YOHòÿ[òŸ[à\öXK[Xô[HëôX⁄\àè∞Âœÿù]€èè‹[à€\‹œHôX[ŸÀ\ﬁ[Xõ€è∏£&è‹‹[èè€\‹œHô^YXúõ›»èìì’ì»T‘‘“UUìœ‹èèîôY⁄\›\à\‹‹⁄]]õœ⁄èèXô[õ‹èHô]öXŸK[ò[YHèìõ€YH»\‹‹⁄]]õœ€Xô[è[ú]YHô]öXŸK[ò[YHàô\]Z\ôYZ[õ[ô›HåààX^[ô›HéàXŸZ€\èHë^éàõ›0Ï›\»çà8†%ò[òÿYHèèXô[õ‹èHö\ôÿ\ôKZYèíY[ùYöXÿY‹àH\ôÿ\ôH‹[èõ‹⁄[€ò[‹‹[èè€Xô[è[ú]YHö\ôÿ\ôKZYàX^[ô›HåLàXŸZ€\èHíY[ùYöXÿY‹à∞Ë€»ŸX‹ô]»èèXô[õ‹èHôö\õ]ÿ\ôK]ô\ú⁄[€àèëö\õ]ÿ\ôH‹[èõ‹⁄[€ò[‹‹[èè€Xô[è[ú]YHôö\õ]ÿ\ôK]ô\ú⁄[€ààX^[ô›HçåàXŸZ€\èHïô\úË€ÀŸH€€öX⁄YHèè]à€\‹œHôõ‹õKY\úõ‹ààYHô]öXŸKY\úõ‹àèèŸ]èèù]€à€\‹œHòù]€àö[X\ûHù[àò[YOHôYò][èîôY⁄\›\èÿù]€èèŸõ‹õOèŸX[ŸœèX[Ÿ»YHö[ôõÀYX[Ÿ»èè]à€\‹œHôX[ŸÀXÿ\ôèèù]€à€\‹œHôX[ŸÀX€‹ŸHàYHö[ôõÀX€‹ŸHà\öXK[Xô[HëôX⁄\àè∞Âœÿù]€èè‹[à€\‹œHôX[ŸÀ\ﬁ[Xõ€è∏ß,œ‹‹[èè€\‹œHô^YXúõ›»èîíUêP“QQHHSRUTœ‹èèï[XH]Yõ‹õXHH\⁄[œ⁄èèë\›Hô\úË€»0ÍH[XHò\ŸHÿÿ[\òHŸ\›0Ë€»H[[€ú›òpÈË€Àà»\‹‹⁄]]õ»ôX[Z[ôH∞Ë€»\›0ËHYÿYÀ”T»∞Ë€»Ë€»[ùöXY‹»HH[ùôYÿHHõ›YöXÿpÈÌY\»∞Ë€»0ÍH€€ôö\õXYKè‹èîÿ[\»\ÿ[H[ö‹»ŸX‹ô]‹»[\‹∞Ë\ö[‹Àà]Y[H‹‹›Z\à»[ö»ŸHXúöK[Œ»∞Ë€»0ÍH[XHô\öYöXÿpÈË€»HY[ùYYKàÿ[\»ôXZ\»∞Ë€»Ë€»^‹›\»ô\›Hô\úË€»[öX⁄X[è‹èì‹»∞ÓõY\õ‹»NLHNM»Ë€»ôYô\∞Íõò⁄X\»úò\⁄[Z\ò\»]YH]ô[HŸ\à€€ôö\õXY\»ÿÿ[Y[ùKàH\XÿpÈË€»∞Ë€»›Xú›]ZH‹»Ÿ\ùöpÈ€‹»ŸöX⁄XZ\»H[Y\ôÍõò⁄XKè‹èŸ]èèŸX[ŸœèÿõŸOè⁄[Ç