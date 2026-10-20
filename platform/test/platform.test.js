const test = require('node:test');
const assert = require('node:assert/strict');
const { spawn } = require('node:child_process');
const net = require('node:net');
const os = require('node:os');
const path = require('node:path');
const fs = require('node:fs');

let child, base, temp;
async function availablePort(){return await new Promise((resolve,reject)=>{const s=net.createServer();s.once('error',reject);s.listen(0,'127.0.0.1',()=>{const p=s.address().port;s.close(()=>resolve(p));});});}
async function untilReady(){for(let i=0;i<80;i++){if(child.exitCode!==null)throw new Error('Server exited before becoming ready');try{const r=await fetch(`${base}/api/health`);if(r.ok)return;}catch{}await new Promise(r=>setTimeout(r,100));}throw new Error('Server did not become ready');}
async function json(url,options={}){const r=await fetch(`${base}${url}`,{...options,headers:{'content-type':'application/json',...(options.headers||{})}});return {status:r.status,data:await r.json(),response:r};}

test('platform API enforces device, contact, event and room rules',async t=>{
  const port=await availablePort();base=`http://127.0.0.1:${port}`;temp=fs.mkdtempSync(path.join(os.tmpdir(),'resq-wear-'));
  child=spawn(process.execPath,['--disable-warning=ExperimentalWarning','server.js'],{cwd:path.resolve(__dirname,'..'),env:{...process.env,PORT:String(port),RESQ_ADMIN_PASSWORD:'test-only-password',RESQ_ROOM_SECRET:'test-room-secret-with-32-characters-minimum',RESQ_DATA_DIR:temp,NODE_ENV:'test'},stdio:'ignore'});
  t.after(async()=>{if(child.exitCode===null){child.kill();await new Promise(resolve=>child.once('exit',resolve));}fs.rmSync(temp,{recursive:true,force:true});});
  await untilReady();
  assert.equal((await json('/api/devices')).status,401);
  const login=await json('/api/session',{method:'POST',body:JSON.stringify({password:'test-only-password'})});assert.equal(login.status,200);
  const cookie=login.response.headers.get('set-cookie').split(';')[0];const auth={cookie};
  const noAccess=await json('/api/devices',{headers:{cookie:'resq_session=invalid'}});assert.equal(noAccess.status,401);
  const created=await json('/api/devices',{method:'POST',headers:auth,body:JSON.stringify({name:'Protótipo de bancada'})});assert.equal(created.status,201);assert.equal(created.data.deviceToken.length>30,true);
  const deviceId=created.data.device.id, token=created.data.deviceToken;
  const configuration=await json('/api/device/configuration',{headers:{authorization:`Bearer ${token}`}});assert.equal(configuration.status,200);assert.equal(configuration.data.contacts.length,2);assert.equal(configuration.data.notifications.enabled,false);
  const initial=await json(`/api/devices/${deviceId}/contacts`,{headers:auth});assert.equal(initial.status,200);assert.deepEqual(initial.data.contacts.slice(0,2).map(c=>[c.name,c.phone,c.is_official]),[['Polícia Militar','190',1],['Polícia Civil','197',1]]);
  const four=await json(`/api/devices/${deviceId}/contacts`,{method:'PUT',headers:auth,body:JSON.stringify({contacts:[1,2,3,4].map(i=>({name:`Contacto ${i}`,phone:`+55119999999${i}`}))})});assert.equal(four.status,400);
  const badPhone=await json(`/api/devices/${deviceId}/contacts`,{method:'PUT',headers:auth,body:JSON.stringify({contacts:[{name:'Inválido',phone:'190'}]})});assert.equal(badPhone.status,400);
  const saved=await json(`/api/devices/${deviceId}/contacts`,{method:'PUT',headers:auth,body:JSON.stringify({contacts:[{name:'Pessoa de teste',phone:'+5511999999999'}]})});assert.equal(saved.status,200);assert.equal(saved.data.contacts.length,3);assert.equal(saved.data.contacts[0].phone,'190');
  const unauthorized=await json('/api/device/events',{method:'POST',body:JSON.stringify({eventId:'test-event-0001',type:'sos_manual'})});assert.equal(unauthorized.status,401);
  const eventPayload={eventId:'test-event-0001',type:'sos_manual',latitude:-23.5,longitude:-46.6};
  const event=await json('/api/device/events',{method:'POST',headers:{authorization:`Bearer ${token}`},body:JSON.stringify(eventPayload)});assert.equal(event.status,201);assert.equal(event.data.event.simulated,false);assert.equal(event.data.notification,'not_sent');
  const duplicate=await json('/api/device/events',{method:'POST',headers:{authorization:`Bearer ${token}`},body:JSON.stringify(eventPayload)});assert.equal(duplicate.status,200);assert.equal(duplicate.data.duplicate,true);assert.equal(duplicate.data.roomUrl,event.data.roomUrl);
  const privateRoom=await json(event.data.roomUrl);assert.equal(privateRoom.status,200);assert.equal(privateRoom.data.event.id,event.data.event.id);assert.equal(privateRoom.data.simulated,false);
  const invalidTransition=await json(`/api/events/${event.data.event.id}/status`,{method:'PATCH',headers:auth,body:JSON.stringify({status:'closed'})});assert.equal(invalidTransition.status,409);
  const accepted=await json(`/api/events/${event.data.event.id}/status`,{method:'PATCH',headers:auth,body:JSON.stringify({status:'open'})});assert.equal(accepted.status,200);
  const demo=await json('/api/demo/events',{method:'POST',body:JSON.stringify({type:'possible_fall',coordinates:true})});assert.equal(demo.status,201);assert.equal(demo.data.event.simulated,true);assert.equal(demo.data.notification,'not_sent');
  const demoRoom=await json(demo.data.roomUrl);assert.equal(demoRoom.status,200);assert.equal(demoRoom.data.simulated,true);
  const revoked=await json(`/api/events/${event.data.event.id}/room`,{method:'DELETE',headers:auth});assert.equal(revoked.status,200);
  assert.equal((await json(event.data.roomUrl)).status,404);
  const rotated=await json(`/api/devices/${deviceId}/rotate-token`,{method:'POST',headers:auth});assert.equal(rotated.status,200);assert.notEqual(rotated.data.deviceToken,token);assert.equal((await json('/api/device/configuration',{headers:{authorization:`Bearer ${token}`}})).status,401);assert.equal((await json('/api/device/configuration',{headers:{authorization:`Bearer ${rotated.data.deviceToken}`}})).status,200);
  const staticPage=await fetch(base);const staticHtml=await staticPage.text();assert.equal(staticPage.status,200);assert.match(staticHtml,/ResQ Wear/);assert.match(staticHtml,/theme\.css/);
  const theme=await fetch(`${base}/theme.css`);assert.equal(theme.status,200);assert.match(await theme.text(),/#8a4cc2/);assert.match(theme.headers.get('content-security-policy')||'',/fonts\.googleapis\.com/);
});
