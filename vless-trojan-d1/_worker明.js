import{connect as ba}from"cloudflare:sockets";var C="direct",he="reject",rt="socks5",at="http",st="vless",ot=["raw","ws","grpc","httpupgrade","h2"],it="ws";var lt="ws",ct="geosite:",ut="geoip:",Le="geo:version",Q="vtd_admin";var dt="/ws";var pt=["qq.com","taobao.com","tmall.com","jd.com","baidu.com","bilibili.com","douyin.com","weibo.com","zhihu.com","163.com","126.com","aliyun.com","tencent.com","weixin.qq.com","alipay.com","bankofchina.com","icbc.com.cn","ccb.com","abcchina.com","cmbchina.com","boc.cn","12306.cn","gov.cn","cn","com.cn","net.cn","org.cn"],ft=["speedtest.net","fast.com","ookla.com"],ht=["google.com","googleapis.com","gstatic.com","googleusercontent.com","ggpht.com","google.cn","google.com.hk","gvt1.com","gvt2.com","gvt3.com"],_e=[];for(let t=0;t<=255;++t){let e=t.toString(16).padStart(2,"0");_e.push(e)}var $e=1e5;function Ue(t){return Array.from(new Uint8Array(t)).map(e=>e.toString(16).padStart(2,"0")).join("")}function In(){let t=new Uint8Array(16);return crypto.getRandomValues(t),Ue(t)}async function mt(t,e,n){let a=await crypto.subtle.importKey("raw",new TextEncoder().encode(t),"PBKDF2",!1,["deriveBits"]),r=await crypto.subtle.deriveBits({name:"PBKDF2",salt:new TextEncoder().encode(e),iterations:n,hash:"SHA-256"},a,256);return Ue(r)}async function gt(t){let e=In(),n=await mt(t,e,$e);return`${e}:${$e}:${n}`}async function wt(t,e){if(!e||!t)return!1;let n=String(e).split(":");if(n.length!==3)return!1;let[a,r,s]=n,o=parseInt(r,10)||$e;return await mt(t,a,o)===s}async function yt(t,e){let n=await crypto.subtle.importKey("raw",new TextEncoder().encode(t),{name:"HMAC",hash:"SHA-256"},!1,["sign"]),a=await crypto.subtle.sign("HMAC",n,new TextEncoder().encode(e));return Ue(a)}async function bt(t){let n=`admin.${Math.floor(Date.now()/1e3)+604800}`,a=await yt(t,n);return`${n}.${a}`}async function vt(t,e){if(!t||!e)return!1;let n=String(t).split(".");if(n.length!==3)return!1;let[a,r,s]=n;if(a!=="admin")return!1;let o=Number(r);if(!Number.isFinite(o)||o<Date.now()/1e3)return!1;let c=await yt(e,`${a}.${r}`);if(c.length!==s.length)return!1;let l=0;for(let i=0;i<c.length;i++)l|=c.charCodeAt(i)^s.charCodeAt(i);return l===0}function xt(t){let e={};if(!t)return e;for(let n of t.split(";")){let a=n.indexOf("=");if(a<0)continue;let r=n.slice(0,a).trim(),s=n.slice(a+1).trim();e[r]=decodeURIComponent(s)}return e}var Hn=3e4,te={settings:{p:null,ts:0},vlessUsers:{p:null,ts:0},trojanUsers:{p:null,ts:0},outbounds:{p:null,ts:0},routingRules:{p:null,ts:0}};function ee(t,e){let n=te[t],a=Date.now();if(n.p&&a-n.ts<Hn)return n.p;let r=Promise.resolve().then(e).catch(()=>null);return n.p=r,n.ts=a,r}function W(t){if(t==="all"){for(let n of Object.keys(te))te[n].p=null,te[n].ts=0;return}let e=te[t];e&&(e.p=null,e.ts=0)}async function Fn(t){try{let{results:e}=await t.prepare("SELECT key, value FROM settings").all(),n={};for(let a of e||[])n[a.key]=a.value;return n}catch{return{}}}async function zn(t){try{let{results:e}=await t.prepare("SELECT id, uuid, remark, up, down, path, expire_at, traffic_limit, traffic_reset_at FROM vless_users WHERE enable = 1 ORDER BY id").all();return e||[]}catch{try{let{results:n}=await t.prepare("SELECT id, uuid, remark, up, down FROM vless_users WHERE enable = 1 ORDER BY id").all();return(n||[]).map(a=>({path:"",expire_at:0,traffic_limit:0,traffic_reset_at:0,...a}))}catch{return[]}}}async function Bn(t){try{let{results:e}=await t.prepare("SELECT id, password, remark, up, down, path, expire_at, traffic_limit, traffic_reset_at FROM trojan_users WHERE enable = 1 ORDER BY id").all();return e||[]}catch{try{let{results:n}=await t.prepare("SELECT id, password, remark, up, down FROM trojan_users WHERE enable = 1 ORDER BY id").all();return(n||[]).map(a=>({path:"",expire_at:0,traffic_limit:0,traffic_reset_at:0,...a}))}catch{return[]}}}function jn(t){let e=String(t||"").trim();if(!e)return"";for(e.startsWith("/")||(e="/"+e);e.length>1&&e.endsWith("/");)e=e.slice(0,-1);return e}async function Tt(t,e,n){let a=Math.floor(Date.now()/1e3);for(let r of e)if(r.traffic_reset_at>0&&r.traffic_reset_at<=a)try{await t.prepare(`UPDATE ${n} SET up = 0, down = 0, traffic_reset_at = 0 WHERE id = ?`).bind(r.id).run(),r.up=0,r.down=0,r.traffic_reset_at=0}catch{}}function Gn(t,e,n){let a=new Map,r=(s,o)=>{let c=jn(s);if(!c)return;a.has(c)||a.set(c,[]),a.get(c).push(o);let l=`${c}/Tun`;a.has(l)||a.set(l,[]),a.get(l).push(o)};r(t,{kind:"all"});for(let s of e)s.path&&r(s.path,{kind:"vless",credential:s.uuid.toLowerCase()});for(let s of n)s.path&&r(s.path,{kind:"trojan",credential:s.password});return a}async function Wn(t){try{let{results:e}=await t.prepare("SELECT * FROM outbounds WHERE enable = 1 ORDER BY sort ASC, id ASC").all();return e||[]}catch{return[]}}async function Vn(t){try{let{results:e}=await t.prepare("SELECT * FROM routing_rules WHERE enable = 1 ORDER BY sort ASC, id ASC").all();return e||[]}catch{return[]}}async function Kn(t){try{let a=await t.prepare("SELECT value FROM settings WHERE key = ?").bind("admin_password_hash").first();if(a&&a.value)return{hash:a.value,tempPassword:null}}catch{}let e=Yn().replace(/-/g,"").slice(0,12),n=await gt(e);try{await t.prepare("INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at").bind("admin_password_hash",n,Date.now()).run(),W("settings")}catch{}return{hash:n,tempPassword:e}}async function De(t,e,n={}){let{DB:a}=e,r=await ee("settings",()=>Fn(a)),s=r.ws_path||dt,o=r.entry_transport||lt,c=r.default_outbound||C,l=r.admin_password_hash||"",i=null;if(!l&&n.ensureAdmin){let v=await Kn(a);l=v.hash,i=v.tempPassword}let u=r.proxyip||"",d="",f=443;if(u){let v=u.lastIndexOf(":");v>0&&!u.includes("]")&&/^\d+$/.test(u.slice(v+1))?(d=u.slice(0,v),f=Number(u.slice(v+1))||443):d=u}let p=r.udp_outbound||"",w=r.entry_host||"",m=r.entry_port||"",y=r.entry_sni||"",h=r.entry_ws_host||"",g=await ee("vlessUsers",()=>zn(a)),b=await ee("trojanUsers",()=>Bn(a)),E=await ee("outbounds",()=>Wn(a)),T=await ee("routingRules",()=>Vn(a));await Promise.all([Tt(a,g,"vless_users"),Tt(a,b,"trojan_users")]);let L=Gn(s,g,b),$={};for(let v of g)$[v.uuid]=v;let x={};for(let v of b)x[v.password]=v;return{env:e,settings:r,wsPath:s,entryTransport:o,defaultOutbound:c,adminPasswordHash:l,adminTempPassword:i,proxyipHost:d,proxyipPort:f,proxyipDisabled:c!==C,udpOutbound:p,entryHost:w,entryPort:m,entrySni:y,entryWsHost:h,vlessUsers:g,trojanUsers:b,outbounds:E,routingRules:T,vlessIndex:$,trojanIndex:x,uuidSet:new Set(g.map(v=>v.uuid.toLowerCase())),passwordSet:new Set(b.map(v=>v.password)),outboundByName:E.reduce((v,_)=>(v[_.name]=_,v),{}),inboundPathMap:L}}function Yn(){return globalThis.crypto&&typeof globalThis.crypto.randomUUID=="function"?globalThis.crypto.randomUUID():"xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(/[xy]/g,t=>{let e=Math.random()*16|0;return(t==="x"?e:e&3|8).toString(16)})}function qn(t){let e=n=>_e[t[n]];return`${e(0)}${e(1)}${e(2)}${e(3)}-${e(4)}${e(5)}-${e(6)}${e(7)}-${e(8)}${e(9)}-${e(10)}${e(11)}${e(12)}${e(13)}${e(14)}${e(15)}`.toLowerCase()}function Et(t,e){if(t.byteLength<24)return{hasError:!0,message:"invalid data"};let n=t instanceof Uint8Array?new DataView(t.buffer,t.byteOffset,t.byteLength):new DataView(t),a=n.getUint8(0),r=qn(new Uint8Array(t.slice(1,17)));if(!e.has(r))return{hasError:!0,message:"invalid user"};let o=18+n.getUint8(17);if(t.byteLength<o+4)return{hasError:!0,message:"invalid data"};let c=n.getUint8(o);if(c!==1&&c!==2)return{hasError:!0,message:`command ${c} is not supported`};let l=o+1,i=n.getUint16(l),u=n.getUint8(l+2),d,f,p;switch(u){case 1:f=4,p=l+3,d=Array.from(new Uint8Array(t.slice(p,p+f))).join(".");break;case 2:if(t.byteLength<l+4)return{hasError:!0,message:"invalid data"};f=n.getUint8(l+3),p=l+4,d=new TextDecoder().decode(t.slice(p,p+f));break;case 3:f=16,p=l+3,d=Array.from({length:8},(w,m)=>n.getUint16(p+m*2).toString(16)).join(":");break;default:return{hasError:!0,message:`invalid addressType: ${u}`}}return d?{hasError:!1,userUuid:r,addressRemote:d,addressType:u,portRemote:i,rawDataIndex:p+f,protocolVersion:new Uint8Array([a]),isUDP:c===2}:{hasError:!0,message:"addressValue is empty"}}function kt(t,e,n,a,r){let s,o,c=[];switch(e){case 1:s=4,c=n.split(".").map(Number);break;case 2:o=new TextEncoder().encode(n),s=o.length+1;break;case 3:s=16,c=Jn(n).split(":").map(u=>[parseInt(u.slice(0,2),16),parseInt(u.slice(2),16)]).flat();break;default:throw new Error(`Unknown address type: ${e}`)}let l=r.replace(/-/g,""),i=new Uint8Array(22+s);i[0]=0;for(let u=0;u<l.length;u+=2)i[1+u/2]=parseInt(l.substr(u,2),16);return i[17]=0,i[18]=t,i[19]=a>>8,i[20]=a&255,i[21]=e,e===2?(i[22]=o.length,i.set(o,23)):i.set(c,22),i}function Jn(t){if(t=t.replace(/^\[|\]$/g,""),t.includes("::")){let e=t.split("::"),n=e[0]?e[0].split(":"):[],a=e[1]?e[1].split(":"):[],r=8-n.length-a.length,s=Array(Math.max(0,r)).fill("0");return[...n,...s,...a].map(o=>o.padStart(4,"0")).join(":")}return t.split(":").map(e=>e.padStart(4,"0")).join(":")}async function Zn(t){let e=new TextEncoder().encode(t),n=await crypto.subtle.digest({name:"SHA-224"},e);return Array.from(new Uint8Array(n)).map(a=>a.toString(16).padStart(2,"0")).join("")}var Oe=new Map;function Xn(t){if(Oe.has(t))return Oe.get(t);let e=Zn(t);return Oe.set(t,e),e}function St(t){if(t.byteLength<60)return!1;let e=new Uint8Array(t);return e[0]===0?!1:e[56]===13&&e[57]===10}async function At(t,e){if(t.byteLength<60)return{hasError:!0,message:"Invalid Trojan data: too short"};let n=new Uint8Array(t),a=t instanceof Uint8Array?new DataView(t.buffer,t.byteOffset,t.byteLength):new DataView(t);if(n[56]!==13||n[57]!==10)return{hasError:!0,message:"Invalid Trojan header: missing CRLF"};let r=new TextDecoder().decode(n.slice(0,56)),s=null;for(let w of e)try{if(await Xn(w)===r){s=w;break}}catch{}if(!s)return{hasError:!0,message:"Invalid Trojan password"};let o=n[58];if(o!==1&&o!==3)return{hasError:!0,message:`Unsupported Trojan command: ${o}`};let c=n[59],l,i,u;switch(c){case 1:if(i=4,u=60,t.byteLength<u+i+2)return{hasError:!0,message:"Invalid Trojan header: IPv4 truncated"};l=Array.from(n.slice(u,u+i)).join(".");break;case 3:if(i=n[60],u=61,t.byteLength<u+i+2)return{hasError:!0,message:"Invalid Trojan header: domain truncated"};l=new TextDecoder().decode(n.slice(u,u+i));break;case 4:if(i=16,u=60,t.byteLength<u+i+2)return{hasError:!0,message:"Invalid Trojan header: IPv6 truncated"};l=Array.from({length:8},(w,m)=>a.getUint16(u+m*2).toString(16)).join(":");break;default:return{hasError:!0,message:`Invalid Trojan address type: ${c}`}}let d=u+i;if(t.byteLength<d+2)return{hasError:!0,message:"Invalid Trojan header: port truncated"};let f=a.getUint16(d),p=d+2;return t.byteLength<p+2?{hasError:!0,message:"Invalid Trojan header: missing final CRLF"}:n[p]!==13||n[p+1]!==10?{hasError:!0,message:"Invalid Trojan header: invalid final CRLF"}:{hasError:!1,userPassword:s,addressRemote:l,addressType:c===3?2:c,portRemote:f,rawDataIndex:p+2,isUDP:o===3}}function Lt(t){if(!t)return{earlyData:null,error:null};try{let e=t.replace(/-/g,"+").replace(/_/g,"/"),n=atob(e),a=new ArrayBuffer(n.length),r=new Uint8Array(a);for(let s=0;s<n.length;s++)r[s]=n.charCodeAt(s);return{earlyData:a,error:null}}catch(e){return{earlyData:null,error:e}}}function N(t){try{t&&t.readyState===1&&t.close()}catch{}}async function _t(t,e){let n=t.sni&&t.sni!==""?t.sni:t.address,a=Number(t.port),r;try{r=globalThis.connect?globalThis.connect({hostname:n,port:a,secureTransport:t.tls?"on":"off"}):void 0}catch(i){return e(`[VLESS/raw] connect error: ${i.message}`),null}if(!r)return e("[VLESS/raw] connect unavailable"),null;let s=r.readable.getReader(),o,c=new Promise(i=>{o=i});return(r.closed||Promise.resolve()).then(o,o),{readable:new ReadableStream({start(i){(async()=>{try{for(;;){let{done:u,value:d}=await s.read();if(u)break;d&&d.byteLength>0&&i.enqueue(d)}try{i.close()}catch{}}catch(u){try{i.error(u)}catch{}}})()},cancel(){try{s.cancel()}catch{}}}),writable:r.writable,closed:c,send:async i=>{let u=r.writable.getWriter();try{await u.write(i)}finally{try{u.releaseLock()}catch{}}}}}function Qn(t,e){let n=new Uint8Array(t.length+e.length);return n.set(t,0),n.set(e,t.length),n}function er(t){for(let e=0;e+3<t.length;e++)if(t[e]===13&&t[e+1]===10&&t[e+2]===13&&t[e+3]===10)return e;return-1}function tr(t){for(let e=0;e+1<t.length;e++)if(t[e]===13&&t[e+1]===10)return new TextDecoder().decode(t.slice(0,e));return""}async function $t(t,e){let n=t.sni&&t.sni!==""?t.sni:t.address,a=Number(t.port),r;try{r=globalThis.connect?globalThis.connect({hostname:n,port:a,secureTransport:t.tls?"on":"off"}):void 0}catch(w){return e(`[VLESS/httpupgrade] connect error: ${w.message}`),null}if(!r)return e("[VLESS/httpupgrade] connect unavailable"),null;let o=`GET ${t.path&&t.path.startsWith("/")?t.path:`/${t.path||""}`} HTTP/1.1\r
Host: ${n}:${a}\r
Connection: Upgrade\r
Upgrade: websocket\r
\r
`,c=r.readable.getReader(),l,i=new Promise(w=>{l=w});(r.closed||Promise.resolve()).then(l,l);let u=new Uint8Array(0),d=new Uint8Array(0);try{await Promise.race([(async()=>{let w=r.writable.getWriter();try{await w.write(new TextEncoder().encode(o))}finally{try{w.releaseLock()}catch{}}for(;;){let{done:m,value:y}=await c.read();if(m)break;if(y&&y.byteLength>0){u=Qn(u,y);let h=er(u);if(h>=0){d=u.slice(h+4);return}}}throw new Error("connection closed during handshake")})(),new Promise((w,m)=>setTimeout(()=>m(new Error("Handshake timeout")),1e4))])}catch(w){e(`[VLESS/httpupgrade] handshake failed: ${w.message}`);try{r.close()}catch{}return null}let f=tr(u);if(!/^HTTP\/1\.1 101/.test(f)){e(`[VLESS/httpupgrade] upgrade rejected: ${f}`);try{r.close()}catch{}return null}return{readable:new ReadableStream({start(w){d.byteLength>0&&w.enqueue(d),(async()=>{try{for(;;){let{done:m,value:y}=await c.read();if(m)break;y&&y.byteLength>0&&w.enqueue(y)}try{w.close()}catch{}}catch(m){try{w.error(m)}catch{}}})()},cancel(){try{c.cancel()}catch{}}}),writable:r.writable,closed:i,send:async w=>{let m=r.writable.getWriter();try{await m.write(w)}finally{try{m.releaseLock()}catch{}}}}}var nr=`PRI * HTTP/2.0\r
\r
SM\r
\r
`;var Re=new TextEncoder;function rr(t,e){let n=Re.encode(t),a=Re.encode(e),r=new Uint8Array(2+n.length+1+a.length);return r[0]=0,r[1]=n.length,r.set(n,2),r[2+n.length]=a.length,r.set(a,3+n.length),r}function ar(t){let e=new Uint8Array(0);for(let[n,a]of t)e=ne(e,rr(n,a));return e}function H(t,e,n,a){let r=a.length,s=new Uint8Array(9+r);return s[0]=r>>16&255,s[1]=r>>8&255,s[2]=r&255,s[3]=t,s[4]=e,s[5]=n>>24&127,s[6]=n>>16&255,s[7]=n>>8&255,s[8]=n&255,s.set(a,9),s}function Ut(t){let e=new Uint8Array(5+t.length);return e[0]=0,new DataView(e.buffer,e.byteOffset,5).setUint32(1,t.length,!1),e.set(t,5),e}function Dt(t){let e=new Uint8Array(4);return new DataView(e.buffer).setUint32(0,t>>>0,!1),e}function ne(t,e){let n=new Uint8Array(t.length+e.length);return n.set(t,0),n.set(e,t.length),n}async function Ot(t,e){let n=[],a=0;for(;a<e;){let{done:s,value:o}=await t.read();if(s)return null;!o||o.byteLength===0||(n.push(o),a+=o.byteLength)}let r;if(n.length===1)r=n[0];else{r=ne(n[0],n[1]);for(let s=2;s<n.length;s++)r=ne(r,n[s])}return r.byteLength>e?{data:r.slice(0,e),extra:r.slice(e)}:{data:r,extra:null}}async function Rt(t,e){let n=t.sni&&t.sni!==""?t.sni:t.address,a=Number(t.port),r;try{r=globalThis.connect?globalThis.connect({hostname:n,port:a,secureTransport:t.tls?"on":"off"}):void 0}catch(m){return e(`[VLESS/grpc] connect error: ${m.message}`),null}if(!r)return e("[VLESS/grpc] connect unavailable"),null;let s=r.writable.getWriter();async function o(m){await s.write(m)}let c,l=new Promise(m=>{c=m});(r.closed||Promise.resolve()).then(c,c);try{await o(Re.encode(nr)),await o(H(4,0,0,new Uint8Array(0)));let m=t.tls?"https":"http",y=(t.path||"").replace(/^\/+/,"").replace(/\/+$/,""),h=y?`/${y}/Tun`:"/Tun",g=ar([[":method","POST"],[":scheme",m],[":path",h],[":authority",`${n}:${a}`],["content-type","application/grpc"],["te","trailers"],["user-agent","grpc-go/1.68.0"]]);await o(H(1,4,1,g))}catch(m){e(`[VLESS/grpc] handshake failed: ${m.message}`);try{r.close()}catch{}return null}let i=r.readable.getReader(),u={needLen:5,buf:new Uint8Array(0),msgLen:0,controller:null,extra:null};function d(m,y){let h=m;for(;h.byteLength>0;)if(u.needLen>0){let g=Math.min(u.needLen,h.byteLength);u.buf=ne(u.buf,h.slice(0,g)),h=h.slice(g),u.needLen-=g,u.needLen===0&&(u.buf.byteLength===5?(u.msgLen=new DataView(u.buf.buffer,u.buf.byteOffset,5).getUint32(1,!1),u.buf=new Uint8Array(0),u.needLen=u.msgLen,u.msgLen===0&&(u.needLen=5)):(u.buf=new Uint8Array(0),u.needLen=5))}else{let g=Math.min(u.msgLen,h.byteLength);if(u.buf=ne(u.buf,h.slice(0,g)),h=h.slice(g),u.msgLen-=g,u.msgLen===0){if(u.buf.byteLength>0)try{y.enqueue(u.buf)}catch{}u.buf=new Uint8Array(0),u.needLen=5}}}let f=new ReadableStream({start(m){u.controller=m,(async()=>{try{for(;;){let y;if(u.extra)y=u.extra,u.extra=null;else{let h=await Ot(i,9);if(!h)break;let g=h.data[0]<<16|h.data[1]<<8|h.data[2],b=h.data[3],E=h.data[4],T=(h.data[5]&127)<<24|h.data[6]<<16|h.data[7]<<8|h.data[8];if(g===0)y=new Uint8Array(0);else{let L=await Ot(i,g);if(!L)break;y=L.data,u.extra=L.extra}if(b===0&&T===1){d(y,m),await o(H(8,0,1,Dt(y.byteLength))),await o(H(8,0,0,Dt(y.byteLength)));continue}if(b===4){E&1||await o(H(4,1,0,new Uint8Array(0)));continue}if(b===6){E&1||await o(H(6,1,T,y));continue}if(b===7||b===3)break}}try{m.close()}catch{}}catch(y){e(`[VLESS/grpc] read loop error: ${y.message}`);try{m.error(y)}catch{}}finally{try{c()}catch{}}})()},cancel(){try{i.cancel()}catch{}}});function p(m){let y=[],h=0,g=!0;for(;h<m.byteLength;){let b=Math.min(16384,m.byteLength-h);y.push(H(0,0,1,m.slice(h,h+b))),h+=b,g=!1}return y}let w=new WritableStream({write(m){let y=m instanceof Uint8Array?m:new Uint8Array(m),h=Ut(y),g=p(h);return(async()=>{for(let b of g)await o(b)})()},close(){try{r.close()}catch{}},abort(){try{r.close()}catch{}}});return{readable:f,writable:w,closed:l,send:async m=>{let y=Ut(m);for(let h of p(y))await o(h)}}}var sr=`PRI * HTTP/2.0\r
\r
SM\r
\r
`;var Ce=new TextEncoder;function or(t,e){let n=Ce.encode(t),a=Ce.encode(e),r=new Uint8Array(2+n.length+1+a.length);return r[0]=0,r[1]=n.length,r.set(n,2),r[2+n.length]=a.length,r.set(a,3+n.length),r}function ir(t){let e=new Uint8Array(0);for(let[n,a]of t)e=Pe(e,or(n,a));return e}function F(t,e,n,a){let r=a.length,s=new Uint8Array(9+r);return s[0]=r>>16&255,s[1]=r>>8&255,s[2]=r&255,s[3]=t,s[4]=e,s[5]=n>>24&127,s[6]=n>>16&255,s[7]=n>>8&255,s[8]=n&255,s.set(a,9),s}function Ct(t){let e=new Uint8Array(4);return new DataView(e.buffer).setUint32(0,t>>>0,!1),e}function Pe(t,e){let n=new Uint8Array(t.length+e.length);return n.set(t,0),n.set(e,t.length),n}async function Pt(t,e){let n=[],a=0;for(;a<e;){let{done:s,value:o}=await t.read();if(s)return null;!o||o.byteLength===0||(n.push(o),a+=o.byteLength)}let r;if(n.length===1)r=n[0];else{r=Pe(n[0],n[1]);for(let s=2;s<n.length;s++)r=Pe(r,n[s])}return r.byteLength>e?{data:r.slice(0,e),extra:r.slice(e)}:{data:r,extra:null}}async function Mt(t,e){let n=t.sni&&t.sni!==""?t.sni:t.address,a=Number(t.port),r;try{r=globalThis.connect?globalThis.connect({hostname:n,port:a,secureTransport:t.tls?"on":"off"}):void 0}catch(p){return e(`[VLESS/h2] connect error: ${p.message}`),null}if(!r)return e("[VLESS/h2] connect unavailable"),null;let s=r.writable.getWriter();async function o(p){await s.write(p)}let c,l=new Promise(p=>{c=p});(r.closed||Promise.resolve()).then(c,c);try{await o(Ce.encode(sr)),await o(F(4,0,0,new Uint8Array(0)));let p=t.tls?"https":"http",w=t.path&&t.path.startsWith("/")?t.path:`/${t.path||""}`,m=ir([[":method","POST"],[":scheme",p],[":path",w],[":authority",`${n}:${a}`],["content-length","0"],["user-agent","vless-h2/1.0.0"]]);await o(F(1,4,1,m))}catch(p){e(`[VLESS/h2] handshake failed: ${p.message}`);try{r.close()}catch{}return null}let i=r.readable.getReader(),u=new ReadableStream({start(p){(async()=>{let w=null;try{for(;;){let m;if(w)m=w,w=null;else{let y=await Pt(i,9);if(!y)break;let h=y.data[0]<<16|y.data[1]<<8|y.data[2],g=y.data[3],b=y.data[4],E=(y.data[5]&127)<<24|y.data[6]<<16|y.data[7]<<8|y.data[8];if(h===0)m=new Uint8Array(0);else{let T=await Pt(i,h);if(!T)break;m=T.data,w=T.extra}if(g===0&&E===1){if(m.byteLength>0)try{p.enqueue(m)}catch{}await o(F(8,0,1,Ct(m.byteLength))),await o(F(8,0,0,Ct(m.byteLength)));continue}if(g===4){b&1||await o(F(4,1,0,new Uint8Array(0)));continue}if(g===6){b&1||await o(F(6,1,E,m));continue}if(g===7||g===3)break}}try{p.close()}catch{}}catch(m){e(`[VLESS/h2] read loop error: ${m.message}`);try{p.error(m)}catch{}}finally{try{c()}catch{}}})()},cancel(){try{i.cancel()}catch{}}});function d(p){let w=[],m=0;for(;m<p.byteLength;){let y=Math.min(16384,p.byteLength-m);w.push(F(0,0,1,p.slice(m,m+y))),m+=y}return w}let f=new WritableStream({write(p){let w=p instanceof Uint8Array?p:new Uint8Array(p);return(async()=>{for(let m of d(w))await o(m)})()},close(){try{r.close()}catch{}},abort(){try{r.close()}catch{}}});return{readable:u,writable:f,closed:l,send:async p=>{for(let w of d(p))await o(w)}}}var lr=1e4;async function V(t,e,n,a,r,s,o){let c=t.transport||it;if(!ot.includes(c))return o(`[VLESS] unsupported transport: ${c}`),null;let l=null;try{c==="ws"?l=await cr(t,o):c==="raw"?l=await _t(t,o):c==="httpupgrade"?l=await $t(t,o):c==="grpc"?l=await Rt(t,o):c==="h2"&&(l=await Mt(t,o))}catch(f){return o(`[VLESS/${c}] connect failed: ${f.message}`),null}if(!l)return null;let i=kt(e,n,a,r,t.uuid),u=s instanceof Uint8Array?s:new Uint8Array(s||0),d=new Uint8Array(i.length+u.length);d.set(i,0),d.set(u,i.length);try{await l.send(d)}catch(f){o(`[VLESS/${c}] send header failed: ${f.message}`);try{l.close&&await l.close()}catch{}return null}return{readable:l.readable,writable:l.writable,closed:l.closed}}async function cr(t,e){let n=t.tls?"wss":"ws",a=t.path&&t.path.startsWith("/")?t.path:`/${t.path||""}`,r=t.sni&&t.sni!==""?t.sni:t.address,s=`${n}://${r}:${t.port}${a}`,o;try{o=new WebSocket(s),"binaryType"in o&&(o.binaryType="arraybuffer")}catch(f){return e(`[VLESS/ws] create ws failed: ${f.message}`),null}let c,l=new Promise(f=>{c=f});try{await new Promise((f,p)=>{let w=setTimeout(()=>p(new Error("Connection timeout")),lr);o.addEventListener("open",()=>{clearTimeout(w),f()}),o.addEventListener("close",m=>{clearTimeout(w),p(new Error(`closed ${m.code}`))}),o.addEventListener("error",()=>{clearTimeout(w),p(new Error("ws error"))})})}catch(f){e(`[VLESS/ws] connect failed: ${f.message}`);try{o.close()}catch{}return c(),null}o.addEventListener("close",()=>c()),o.addEventListener("error",()=>{});let i=new WritableStream({write(f){o.readyState===1&&o.send(f)},close(){N(o)},abort(){N(o)}}),u=!1;return{readable:new ReadableStream({start(f){o.addEventListener("message",p=>{let w;try{p.data instanceof ArrayBuffer?w=new Uint8Array(p.data):ArrayBuffer.isView(p.data)?w=new Uint8Array(p.data.buffer,p.data.byteOffset,p.data.byteLength):typeof p.data=="string"?w=new TextEncoder().encode(p.data):w=null}catch{w=null}if(w){if(!u&&(u=!0,w.length>=2&&w[0]===0)){let m=w[1];if(w.length>2+m)w=w.slice(2+m);else return}if(w.length>0)try{f.enqueue(w)}catch{}}}),o.addEventListener("close",()=>{try{f.close()}catch{}}),o.addEventListener("error",p=>{try{f.error(p)}catch{}})},cancel(){N(o)}}),writable:i,closed:l,send:async f=>{if(o.readyState!==1)throw new Error(`ws not open (state=${o.readyState})`);o.send(f)}}}async function re(t,e,n){for(;e.buf.length<n;){let{done:r,value:s}=await t.read();if(r)return null;if(!s||s.byteLength===0)continue;let o=new Uint8Array(e.buf.length+s.byteLength);o.set(e.buf,0),o.set(s,e.buf.length),e.buf=o}let a=e.buf.slice(0,n);return e.buf=e.buf.slice(n),a}async function Nt(t,e,n,a,r,s){let{username:o,password:c,hostname:l,port:i}=r,u=s({hostname:l,port:i}),d=u.writable.getWriter(),f=u.readable.getReader(),p=new TextEncoder,w={buf:new Uint8Array(0)};try{await d.write(new Uint8Array([5,2,0,2]));let m=await re(f,w,2);if(!m||m[0]!==5){a("socks version error");return}if(m[1]===255){a("no acceptable methods");return}if(m[1]===2){if(!o||!c){a("socks server requires auth but no credentials");return}let T=new Uint8Array([1,o.length,...p.encode(o),c.length,...p.encode(c)]);if(await d.write(T),m=await re(f,w,2),!m||m[0]!==1||m[1]!==0){a("socks auth failed");return}}let y;switch(t){case 1:y=new Uint8Array([1,...e.split(".").map(Number)]);break;case 2:y=new Uint8Array([3,e.length,...p.encode(e)]);break;case 3:y=new Uint8Array([4,...e.split(":").flatMap(T=>[parseInt(T.slice(0,2),16),parseInt(T.slice(2),16)])]);break;default:a(`invalid addressType ${t}`);return}let h=new Uint8Array([5,1,0,...y,n>>8,n&255]);await d.write(h);let g=await re(f,w,4);if(!g||g[0]!==5){a("socks version error");return}if(g[1]!==0){a(`socks connect failed rep=${g[1]}`);return}let b=0;switch(g[3]){case 1:b=6;break;case 3:b=3;break;case 4:b=18;break;default:a(`socks invalid ATYP ${g[3]}`);return}if(g[3]===3){let T=await re(f,w,1);if(!T)return;b+=T[0]}if(!await re(f,w,b))return;if(d.releaseLock(),w.buf.length>0){let T=w.buf.slice();return{readable:new ReadableStream({pull($){if(T.length>0){let x=T;T=new Uint8Array(0),$.enqueue(x);return}return f.read().then(({done:x,value:v})=>{x?$.close():v&&v.byteLength>0&&$.enqueue(v)})},cancel(){try{f.cancel()}catch{}}}),writable:u.writable,closed:u.closed||Promise.resolve()}}return f.releaseLock(),u}catch(m){a(`socks5 error: ${m.message}`);try{d.releaseLock()}catch{}try{f.releaseLock()}catch{}try{u.close()}catch{}return}}function It(t,e={}){let n=String(t||"").trim().replace(/^socks5?:\/\//i,""),[a,r]=n.split("@").reverse(),s,o,c,l;if(r){let u=r.split(":");if(u.length!==2)throw new Error("Invalid SOCKS address format");[s,o]=u}let i=a.split(":");if(l=Number(i[i.length-1]),isNaN(l))if(e&&e.port!==void 0&&e.port!==null&&e.port!=="")l=Number(e.port),c=a;else throw new Error("Invalid SOCKS address format");else c=i.slice(0,-1).join(":");if(isNaN(l)||!c)throw new Error("Invalid SOCKS address format");return e&&e.username!==void 0&&e.username!==null&&e.username!==""&&(s=e.username),e&&e.password!==void 0&&e.password!==null&&e.password!==""&&(o=e.password),{username:s,password:o,hostname:c,port:l}}async function Ht(t,e,n,a,r,s,o=new Uint8Array(0)){let{username:c,password:l,hostname:i,port:u}=r,d=s({hostname:i,port:u}),f=d.writable.getWriter(),p=d.readable.getReader();try{let w=c&&l?`Proxy-Authorization: Basic ${btoa(`${c}:${l}`)}\r
`:"",m=`CONNECT ${e}:${n} HTTP/1.1\r
Host: ${e}:${n}\r
${w}User-Agent: Mozilla/5.0\r
Connection: keep-alive\r
\r
`;await f.write(new TextEncoder().encode(m));let y=new Uint8Array(0),h=-1,g=0;for(;h===-1&&g<8192;){let{done:L,value:$}=await p.read();if(L)throw new Error("Connection closed before HTTP response");let x=new Uint8Array(y.length+$.length);x.set(y,0),x.set($,y.length),y=x,g=y.length;for(let v=0;v<y.length-3;v++)if(y[v]===13&&y[v+1]===10&&y[v+2]===13&&y[v+3]===10){h=v+4;break}}if(h===-1)throw new Error("Invalid HTTP response");let E=new TextDecoder().decode(y.slice(0,h)).split(`\r
`)[0].match(/HTTP\/\d\.\d\s+(\d+)/);if(!E)throw new Error("Invalid HTTP response format");let T=parseInt(E[1]);if(T<200||T>=300)throw new Error(`HTTP CONNECT failed: HTTP ${T}`);return o.length>0&&await f.write(o),f.releaseLock(),p.releaseLock(),d}catch(w){a(`http connect error: ${w.message}`);try{f.releaseLock()}catch{}try{p.releaseLock()}catch{}try{d.close()}catch{}return}}function Ft(t,e={}){let[n,a]=String(t||"").trim().split("@").reverse(),r,s,o,c;if(a){let i=a.split(":");if(i.length!==2)throw new Error("Invalid HTTP address format");[r,s]=i}let l=n.split(":");if(c=Number(l[l.length-1]),isNaN(c))if(e&&e.port!==void 0&&e.port!==null&&e.port!=="")c=Number(e.port),o=n;else throw new Error("Invalid HTTP address format");else o=l.slice(0,-1).join(":");if(isNaN(c)||!o)throw new Error("Invalid HTTP address format");return e&&e.username!==void 0&&e.username!==null&&e.username!==""&&(r=e.username),e&&e.password!==void 0&&e.password!==null&&e.password!==""&&(s=e.password),{username:r,password:s,hostname:o,port:c}}var ur=3e5,zt=new Map;async function dr(t,e){let n=zt.get(t);if(n&&Date.now()-n.ts<ur)return e(`doh cache ${t} -> ${n.ip}`),n.ip;let a=["https://8.8.8.8/resolve","https://8.8.4.4/resolve"],r=null;for(let s of a){let o=new AbortController,c=setTimeout(()=>o.abort(),3e3);try{let l=`${s}?name=${encodeURIComponent(t)}&type=A`,i=await fetch(l,{headers:{accept:"application/dns-json"},signal:o.signal});if(i.ok){let u=await i.json(),f=(Array.isArray(u.Answer)?u.Answer:[]).find(p=>p.type===1&&/^\d{1,3}(\.\d{1,3}){3}$/.test(p.data))?.data;if(f){clearTimeout(c),r=f,e(`doh resolved ${t} -> ${f}`);break}}}catch{}finally{clearTimeout(c)}}return r?zt.set(t,{ip:r,ts:Date.now()}):e(`doh resolve failed: ${t}`),r}var pr=["173.245.48.0/20","103.21.244.0/22","103.22.200.0/22","103.31.4.0/22","141.101.64.0/18","108.162.192.0/18","190.93.240.0/20","188.114.96.0/20","197.234.240.0/22","198.41.128.0/17","162.158.0.0/15","104.16.0.0/13","104.24.0.0/14","172.64.0.0/13","131.0.72.0/22","1.0.0.0/24","1.1.1.0/24"].map(t=>{let[e,n]=t.split("/"),a=Number(n),r=a===0?0:4294967295<<32-a>>>0,s=e.split(".");return[(+s[0]<<24)+(+s[1]<<16)+(+s[2]<<8)+ +s[3]>>>0&r,r]});function fr(t){let e=t.split(".");return(+e[0]<<24)+(+e[1]<<16)+(+e[2]<<8)+ +e[3]>>>0}function hr(t){if(!/^\d{1,3}(\.\d{1,3}){3}$/.test(t))return!1;let e=fr(t);return pr.some(([n,a])=>(e&a)===n)}var mr=[".cloudflare.com",".cloudflare.net",".jsdelivr.net",".workers.dev",".pages.dev",".trycloudflare.com",".cf-ipfs.com",".cloudflareinsights.com"];function gr(t){let e=t.toLowerCase();return mr.some(n=>e===n.slice(1)||e.endsWith(n))}var wr=6e4,z={state:"unknown",downAt:0},B=new WeakMap;function se(t){z.state!=="down"&&(z.state="down",z.downAt=Date.now(),t("proxyip marked down (no response), degrade to direct for 60s"))}function yr(t){z.state==="down"&&Date.now()-z.downAt>=wr&&(z.state="unknown",t("proxyip health reset to unknown, will retry proxyip"))}async function Gt(t,e,n,a,r){let s=t.proxyipHost,o=Number(t.proxyipPort||443);if(!s)return null;r(`direct ${e}:${n} -> retry via proxyip ${s}:${o}`);let c=await ae(s,o,r);if(!c)return se(r),null;let l=await Me(c,a,r);return l?(B.set(l,{usedProxyIp:!0}),l):(se(r),null)}async function Bt(t,e,n,a,r,s,o){let c=await br(e,n,a,r,o);if(!c)return o(`connect unavailable (${e}:${n})`),null;let l=await Me(c,s,o);return l&&B.set(l,{usedProxyIp:!1}),l}async function ae(t,e,n){let a;try{a=globalThis.connect?globalThis.connect({hostname:t,port:e}):void 0,a&&typeof a.then=="function"&&(a=await a)}catch(r){return n(`direct connect error: ${r.message}`),null}return a||null}async function br(t,e,n,a,r){if(!n&&!a){r(`direct ${t}:${e} -> native dns ${t}:${e}`);let s=await ae(t,e,r);if(s)return s;let o=await dr(t,r);return o&&(r(`direct ${t}:${e} -> doh fallback ${o}:${e}`),s=await ae(o,e,r),s)?s:null}return ae(t,e,r)}async function Me(t,e,n){if(e&&e.length>0){let a=t.writable.getWriter();try{await a.write(e)}catch(r){n(`direct initial write error: ${r.message}`)}finally{try{a.releaseLock()}catch{}}}return t}async function jt(t,e,n,a,r){let s=t.proxyipHost&&!t.proxyipDisabled,o=/^\d{1,3}(\.\d{1,3}){3}$/.test(e)||e.includes(":");yr(r);let c=s&&z.state==="down",l=!o&&gr(e),i=o&&!e.includes(":")&&hr(e);if(s&&!c&&(l||i)){let u=t.proxyipHost,d=Number(t.proxyipPort||443);r(`direct ${e}:${n} -> proxyip ${u}:${d}`);let f=await ae(u,d,r);if(!f)return se(r),r(`proxyip ${u}:${d} connect failed; degrade to direct ${e}:${n}`),Bt(t,e,n,o,l,a,r);let p=await Me(f,a,r);return p&&B.set(p,{usedProxyIp:!0}),p}return Bt(t,e,n,o,l,a,r)}async function K(t){let{config:e,outbound:n,addressType:a,addressRemote:r,portRemote:s,rawClientData:o,log:c,isUDP:l}=t,i=n;if(!i||i===C)return jt(e,r,s,o,c);if(i===he)return c("rejected by routing rule"),null;switch(i.type){case C:return jt(e,r,s,o,c);case rt:{let u;try{u=It(i.address,{username:i.username,password:i.password,port:i.port})}catch(f){return c(`bad socks5 address: ${f.message}`),null}let d=await Nt(a,r,s,c,u,globalThis.connect);if(!d)return null;if(o&&o.length>0){let f=d.writable.getWriter();try{await f.write(o)}catch(p){c(`socks5 write error: ${p.message}`)}finally{try{f.releaseLock()}catch{}}}return d}case at:{let u;try{u=Ft(i.address,{username:i.username,password:i.password,port:i.port})}catch(f){return c(`bad http address: ${f.message}`),null}return await Ht(a,r,s,c,u,globalThis.connect,o||new Uint8Array(0))}case st:return V({address:i.address,port:Number(i.port),uuid:i.uuid,path:i.path,tls:!!i.tls,sni:i.sni||"",transport:i.transport},l?2:1,a,r,s,o||new Uint8Array(0),c);default:return c(`unknown outbound type: ${i.type}`),null}}function oe(t,e){return!e||e===C?C:e===he?he:t.outboundByName[e]||C}var vr=60*60*1e3,Ne=new Map;async function Ie(t,e,n){let a=`${e}:${n}`,r=Ne.get(a);if(r&&Date.now()-r.ts<vr)return r.data;let s=null;try{let o=e==="geosite"?ct:ut,c=await t.GEO_KV.get(o+n);if(c){let l=JSON.parse(c);Array.isArray(l)&&(s=l)}}catch{}return s||(s=xr(e,n)),Ne.set(a,{data:s,ts:Date.now()}),s}function xr(t,e){if(t==="geosite")switch(e){case"cn":return pt;case"speedtest":return ft;case"google":return ht;default:return[]}return[]}function Wt(){Ne.clear()}function Tr(t){if(!t)return null;let e=String(t).trim();if(!e)return null;let n=e.match(/^geosite:(.+)$/i);if(n){let i=n[1].split(",").map(u=>u.trim()).filter(Boolean);return i.length===0?null:{type:"geosite",categories:i}}let a=e.match(/^geoip:(.+)$/i);if(a){let i=a[1].split(",").map(u=>u.trim()).filter(Boolean);return i.length===0?null:{type:"geoip",categories:i}}let r=e.match(/^domain:(.+)$/i);if(r)return{type:"domain",value:r[1].trim()};let s=e.match(/^full:(.+)$/i);if(s)return{type:"full",value:s[1].trim()};let o=e.match(/^keyword:(.+)$/i);if(o)return{type:"keyword",value:o[1].trim()};let c=e.match(/^ip-cidr:(.+)$/i);if(c)return{type:"ip-cidr",value:c[1].trim()};let l=e.match(/^regexp:(.+)$/i);return l?{type:"regexp",value:l[1].trim()}:{type:"domain",value:e}}function Vt(t){let e=t.split(".");if(e.length!==4)return null;let n=0;for(let a of e){let r=Number(a);if(isNaN(r)||r<0||r>255)return null;n=n<<8|r}return n>>>0}function Kt(t,e){let[n,a]=e.split("/"),r=a!==void 0?Number(a):32,s=Vt(t);if(s===null)return!1;let o=Vt(n);if(o===null)return!1;let c=r<=0?0:4294967295<<32-r>>>0;return(s&c)===(o&c)}function Yt(t,e){let n=t.toLowerCase(),a=e.toLowerCase();return n===a?!0:n.endsWith("."+a)||n.endsWith(a)}var qt=new Map;function Er(t){let e=qt.get(t);if(!e){try{e=new RegExp(t)}catch{e=null}qt.set(t,e)}return e}async function kr(t,e,n,a){switch(t.type){case"domain":return n?!1:Yt(e,t.value);case"full":return n?!1:e.toLowerCase()===t.value.toLowerCase();case"keyword":return n?!1:e.toLowerCase().includes(t.value.toLowerCase());case"regexp":{if(n)return!1;let r=Er(t.value);return r?r.test(e):!1}case"ip-cidr":return n?Kt(e,t.value):!1;case"geosite":{if(n)return!1;for(let r of t.categories){let s=await Ie(a,"geosite",r);for(let o of s)if(Yt(e,o))return!0}return!1}case"geoip":{if(!n)return!1;for(let r of t.categories){let s=await Ie(a,"geoip",r);for(let o of s)if(Kt(e,o))return!0}return!1}default:return!1}}async function ge(t,e,n){let a=e===1||e===3;for(let r of t.routingRules){let s=Tr(r.rule);if(!s)continue;if(await kr(s,n,a,t.env))return{outbound:r.outbound||"direct",rule:r}}return{outbound:t.defaultOutbound||"direct",rule:null}}async function ie(t,e,n,a){let r;try{r=await a.read()}catch(h){n(`read first packet error: ${h.message}`);try{await a.close()}catch{}return}if(!r){try{await a.close()}catch{}return}let s,o=null,c="vless",l=t._inboundScope||null,i=l&&!l.all?l.vless:t.uuidSet,u=l&&!l.all?l.trojan:t.passwordSet;if(St(r)){if(s=await At(r,u),s.hasError){n(`trojan header error: ${s.message}`);try{await a.close()}catch{}return}c="trojan",o=t.trojanIndex[s.userPassword]||null}else{if(s=Et(r,i),s.hasError){n(`vless header error: ${s.message}`);try{await a.close()}catch{}return}try{await a.write(new Uint8Array([0,0]))}catch{}o=t.vlessIndex[s.userUuid]||null}if(o){let h=Math.floor(Date.now()/1e3);if(o.expire_at>0&&o.expire_at<h){n(`${c} user '${o.remark||o.uuid||o.password}' expired`);try{await a.close()}catch{}return}if(o.traffic_limit>0&&Number(o.up)+Number(o.down)>=Number(o.traffic_limit)){n(`${c} user '${o.remark||o.uuid||o.password}' traffic limit reached`);try{await a.close()}catch{}return}}let{addressType:d,addressRemote:f,portRemote:p,isUDP:w}=s,m=new Uint8Array(r.slice(s.rawDataIndex)),y;try{y=await ge(t,d,f)}catch(h){n(`route error: ${h.message}`);try{await a.close()}catch{}return}w?await Ar(a,t,d,f,p,m,o,c,y,n):await Sr(a,t,d,f,p,m,o,c,y,n)}async function Sr(t,e,n,a,r,s,o,c,l,i){let u=oe(e,l.outbound),d=s&&s.length>0?s:new Uint8Array(0),f=[u];u!=="direct"&&u!=="reject"&&f.push("direct");let p=null,w=null;for(let x of f){try{p=await K({config:e,outbound:x,addressType:n,addressRemote:a,portRemote:r,rawClientData:d,log:i})}catch(v){w=v,p=null}if(p)break}if(!p){i(`tcp connect failed: ${w?w.message:"no outbound available"}`);try{await t.close()}catch{}return}let m=0,y=0,h=!1,g=5e3,b=B.get(p)||null,E=!1,T=p.writable.getWriter(),L=async()=>{if(E)return null;E=!0;let x=!!e.proxyipHost&&!e.proxyipDisabled;try{await p.close()}catch{}if(b&&b.usedProxyIp){se(i),i(`proxyip ${a}:${r} no first packet, degrade to direct retry`);try{return await K({config:e,outbound:"direct",addressType:n,addressRemote:a,portRemote:r,rawClientData:d,log:i})||null}catch(v){return i(`direct retry error: ${v.message}`),null}}if(!x||r!==443)return null;i(`direct ${a}:${r} no first packet, retry via proxyip`);try{return await Gt(e,a,r,d,i)}catch(v){return i(`proxyip retry error: ${v.message}`),null}},$=(async()=>{try{for(;;){let x=await t.read();if(x==null)break;x.byteLength!==0&&(m+=x.byteLength,await T.write(x))}}catch(x){i(`upstream read error: ${x.message}`)}})();try{let x=p.readable.getReader(),v=!1;for(;;){let _;if(!v&&!E){let A=null,R=x.read().then(Z=>({tag:"read",...Z})),Ee=new Promise(Z=>{A=setTimeout(()=>Z({tag:"timeout"}),g)});_=await Promise.race([R,Ee]),clearTimeout(A)}else _={tag:"read",...await x.read()};if(_.tag==="timeout"){i(`no first packet in ${g}ms (${a}:${r})`);let A=await L();if(!A)break;try{T.releaseLock()}catch{}p=A,T=p.writable.getWriter(),b=B.get(p)||null,x=p.readable.getReader(),v=!1;continue}if(_.done)break;_.value&&_.value.byteLength>0&&(v=!0,y+=_.value.byteLength,await t.write(_.value))}}catch(x){if(!E&&y===0){i(`tcp remote read error before first packet: ${x.message||x}`);let v=await L();if(v){try{T.releaseLock()}catch{}p=v,T=p.writable.getWriter(),b=B.get(p)||null,E=!0;let _=p.readable.getReader();try{for(;;){let{done:A,value:R}=await _.read();if(A)break;R&&R.byteLength>0&&(y+=R.byteLength,await t.write(R))}}catch(A){i(`fallback remote read error: ${A.message||A}`)}}}else i(`tcp remote read error: ${x.message||x}`)}h=!0;try{T.releaseLock()}catch{}try{await p.writable.close()}catch{}try{await t.close()}catch{}await $.catch(()=>{}),Jt(e,o,c,m,y,i)}async function Ar(t,e,n,a,r,s,o,c,l,i){let u=null,d=(e.udpOutbound||"").trim();if(d){let g=e.outboundByName[d];if(g&&g.type==="vless")u=g;else{i(`udp outbound '${d}' not found or not vless (only vless supports udp)`);try{await t.close()}catch{}return}}else{if(l.outbound&&l.outbound!=="direct"&&l.outbound!=="reject"){let g=oe(e,l.outbound);g!=="direct"&&g!=="reject"&&g.type==="vless"&&(u=g)}u||(u=e.outbounds.find(g=>g.type==="vless"))}if(!u){i("udp requires a vless outbound, none configured");try{await t.close()}catch{}return}let f=s&&s.length>0?s:new Uint8Array([0,0]),p=await V({address:u.address,port:Number(u.port),uuid:u.uuid,path:u.path,tls:!!u.tls,sni:u.sni||"",transport:u.transport||"ws"},2,n,a,r,f,i);if(!p){i("udp vless outbound connect failed");try{await t.close()}catch{}return}let w=0,m=0,y=p.writable.getWriter(),h=(async()=>{try{for(;;){let g=await t.read();if(g==null)break;g.byteLength!==0&&(w+=g.byteLength,await y.write(g))}}catch(g){i(`udp upstream read error: ${g.message}`)}})();try{let g=p.readable.getReader();for(;;){let{done:b,value:E}=await g.read();if(b)break;E&&E.byteLength>0&&(m+=E.byteLength,await t.write(E))}}catch(g){i(`udp read error: ${g.message}`)}try{y.releaseLock()}catch{}try{await p.writable.close()}catch{}try{await t.close()}catch{}await h.catch(()=>{}),Jt(e,o,c,w,m,i)}async function Jt(t,e,n,a,r,s){if(!e)return;let o=n==="vless"?"vless_users":"trojan_users";try{await t.env.DB.prepare(`UPDATE ${o} SET up = up + ?, down = down + ? WHERE id = ?`).bind(a,r,e.id).run()}catch(c){s(`record traffic error: ${c.message}`)}}function Lr(t){return t instanceof ArrayBuffer?new Uint8Array(t):ArrayBuffer.isView(t)?new Uint8Array(t.buffer,t.byteOffset,t.byteLength):typeof t=="string"?new TextEncoder().encode(t):Object.prototype.toString.call(t)==="[object ArrayBuffer]"?new Uint8Array(t):null}function _r(t,e){let n=new URL(t.url).searchParams.get("ed"),a=t.headers.get("sec-websocket-protocol")||"";if(a){a.startsWith("base64,")&&(a=a.slice(7));let{earlyData:r,error:s}=Lt(a);if(s)return e(`early data decode error: ${s.message||s}`),null;if(r&&r.byteLength>0)return e(`early data injected: ${r.byteLength} B (ed=${n||"n/a"})`),new Uint8Array(r)}return n&&e(`ed=${n} declared but no sec-websocket-protocol payload`),null}async function Zt(t,e,n){let a=t.headers.get("Upgrade");if(!a||a.toLowerCase()!=="websocket")return new Response("Expected WebSocket",{status:400});let[r,s]=Object.values(new WebSocketPair);s.accept();let o=(...l)=>console.log("[ws]",...l),c=_r(t,o);return ie(e,n,o,$r(s,o,c)).catch(l=>{o(`ws handler error: ${l.message||l}`),N(s)}),new Response(null,{status:101,webSocket:r})}function $r(t,e,n=null){let a=[],r=[],s=!1;n&&n.byteLength>0?a.push(n):setTimeout(()=>{!s&&a.length===0&&r.length>0&&(e("first packet timeout: no ws message within 6s"),N(t))},6e3);let o=async i=>{let u=i.data;typeof Blob<"u"&&u instanceof Blob&&(u=await u.arrayBuffer());let d=Lr(u);if(!d||d.byteLength===0){e(`message dropped: type=${Object.prototype.toString.call(i.data)} len=${u&&u.byteLength!=null?u.byteLength:u&&u.length!=null?u.length:"n/a"}`);return}let f=r.shift();f?f(d):a.push(d)},c=()=>{if(!s)for(s=!0;r.length;)r.shift()(null)},l=()=>c();return t.addEventListener("message",o),t.addEventListener("close",c),t.addEventListener("error",l),{read(){return a.length?Promise.resolve(a.shift()):s?Promise.resolve(null):new Promise(i=>r.push(i))},write(i){if(t.readyState===1)try{t.send(i)}catch{}},close(){N(t)}}}function He(t,e){let n=new Uint8Array(t.length+e.length);return n.set(t,0),n.set(e,t.length),n}function Ur(t){let e=new Uint8Array(5);return e[0]=0,e[1]=t>>>24&255,e[2]=t>>>16&255,e[3]=t>>>8&255,e[4]=t&255,e}function Dr(t){return He(Ur(t.byteLength),t)}async function Xt(t,e,n){let a=(...i)=>console.log("[h2-in]",...i);if(!t.body)return new Response("Bad Request",{status:400});let r=t.body.getReader(),{readable:s,writable:o}=new TransformStream,c=o.getWriter();return ie(e,n,a,{read:async()=>{let i=new Uint8Array(0);for(;;){let{done:u,value:d}=await r.read();if(u)return i.byteLength>0?i:null;if(i=He(i,d instanceof Uint8Array?d:new Uint8Array(d)),i.byteLength>=60)return i}},write:i=>c.write(i),close:async()=>{try{await r.cancel()}catch{}try{await c.close()}catch{}}}).catch(i=>{a(`h2 handler error: ${i.message||i}`),r.cancel().catch(()=>{}),c.close().catch(()=>{})}),new Response(s,{status:200,headers:{"Content-Type":"application/octet-stream","Cache-Control":"no-store"}})}async function Qt(t,e,n){let a=(...u)=>console.log("[grpc-in]",...u);if(!t.body)return new Response("Bad Request",{status:400});let r=t.body.getReader(),{readable:s,writable:o}=new TransformStream,c=o.getWriter(),l=new Uint8Array(0);return ie(e,n,a,{read:async()=>{for(;;){if(l.byteLength>=5){let f=l[1]<<24|l[2]<<16|l[3]<<8|l[4];if(l.byteLength>=5+f){let p=l.slice(5,5+f);return l=l.slice(5+f),p}}let{done:u,value:d}=await r.read();if(u){if(l.byteLength===0)return null;let f=l;return l=new Uint8Array(0),f}l=He(l,d instanceof Uint8Array?d:new Uint8Array(d))}},write:u=>c.write(Dr(u instanceof Uint8Array?u:new Uint8Array(u))),close:async()=>{try{await r.cancel()}catch{}try{await c.close()}catch{}}}).catch(u=>{a(`grpc handler error: ${u.message||u}`),r.cancel().catch(()=>{}),c.close().catch(()=>{})}),new Response(s,{status:200,headers:{"Content-Type":"application/grpc","Cache-Control":"no-store"}})}var en="ed=2560",le="random";function we(t){let e=t.startsWith("/")?t:`/${t}`;return/\?/.test(e)?`${e}&${en}`:`${e}?${en}`}function ye(t){return(t.startsWith("/")?t:`/${t}`).replace(/\/+$/,"").replace(/^\//,"")}function ce(t){let e=t.transport||"ws",n=t.wsHost||t.host,a=t.sni||(t.tls?n:""),r=new URLSearchParams({encryption:"none",type:e,host:n,security:t.tls?"tls":"none"});e==="grpc"?r.set("serviceName",`/${ye(t.wsPath)}`):e==="h2"?r.set("path",t.wsPath.startsWith("/")?t.wsPath:`/${t.wsPath}`):r.set("path",we(t.wsPath)),t.tls&&a&&r.set("sni",a),t.tls&&r.set("fp",t.fp||le);let s=encodeURIComponent(t.remark||`${t.host}:${t.port}`);return`vless://${t.uuid}@${t.host}:${t.port}?${r.toString()}#${s}`}function ue(t){let e=t.transport||"ws",n=t.wsHost||t.host,a=t.sni||(t.tls?n:""),r=new URLSearchParams({type:e,host:n,security:t.tls?"tls":"none"});e==="grpc"?r.set("serviceName",`/${ye(t.wsPath)}`):e==="h2"?r.set("path",t.wsPath.startsWith("/")?t.wsPath:`/${t.wsPath}`):r.set("path",we(t.wsPath)),t.tls&&a&&r.set("sni",a),t.tls&&r.set("fp",t.fp||le);let s=encodeURIComponent(t.remark||`${t.host}:${t.port}`);return`trojan://${encodeURIComponent(t.password)}@${t.host}:${t.port}?${r.toString()}#${s}`}function tn(t){let e=t.headers.get("Host");return e?e.split(":")[0]:"example.com"}var I=["ws","grpc","h2"];function Or(t,e){let n=[],a=e.port||(e.tls?443:80);for(let r of t.vlessUsers){let s=r.path||t.wsPath;for(let o of I)n.push(ce({uuid:r.uuid,host:e.host,port:a,wsPath:s,tls:e.tls,wsHost:e.wsHost,sni:e.sni,transport:o,remark:`vless-${r.remark||r.uuid.slice(0,8)}-${o}`}))}for(let r of t.trojanUsers){let s=r.path||t.wsPath;for(let o of I)n.push(ue({password:r.password,host:e.host,port:a,wsPath:s,tls:e.tls,wsHost:e.wsHost,sni:e.sni,transport:o,remark:`trojan-${r.remark||r.password.slice(0,8)}-${o}`}))}return n}function Fe(t,e){return Or(t,e).join(`
`)+`
`}function nn(t,e){return btoa(Fe(t,e))}function rn(t,e){let n=e.port||443,a=e.tls!==!1,r=e.wsHost||e.host,s=e.sni||(a?r:""),o=[],c=(i,u,d,f,p,w)=>{let m={name:i,type:u,server:e.host,port:n,[d]:f,network:w,tls:a,servername:s||void 0,"client-fingerprint":a?le:void 0,udp:!0};return w==="grpc"?m["grpc-opts"]={"grpc-service-name":`/${ye(p)}`}:w==="h2"?m["h2-opts"]={path:p.startsWith("/")?p:`/${p}`,host:[r]}:m["ws-opts"]={path:we(p),headers:{Host:r}},m};t.vlessUsers.forEach((i,u)=>{for(let d of I)o.push(c(`vless-${i.remark||u+1}-${d}`,"vless","uuid",i.uuid,i.path||t.wsPath,d))}),t.trojanUsers.forEach((i,u)=>{for(let d of I)o.push(c(`trojan-${i.remark||u+1}-${d}`,"trojan","password",i.password,i.path||t.wsPath,d))});let l=["proxies:"];for(let i of o)l.push(`  - name: "${i.name}"`),l.push(`    type: ${i.type}`),l.push(`    server: ${i.server}`),l.push(`    port: ${i.port}`),i.uuid&&l.push(`    uuid: ${i.uuid}`),i.password&&l.push(`    password: "${i.password}"`),l.push(`    network: ${i.network}`),l.push(`    tls: ${i.tls}`),i.servername&&l.push(`    servername: ${i.servername}`),i["client-fingerprint"]&&l.push(`    client-fingerprint: ${i["client-fingerprint"]}`),l.push("    udp: true"),i.network==="grpc"?(l.push("    grpc-opts:"),l.push(`      grpc-service-name: ${i["grpc-opts"]["grpc-service-name"]}`)):i.network==="h2"?(l.push("    h2-opts:"),l.push(`      path: ${i["h2-opts"].path}`),l.push("      host:"),l.push(`        - ${r}`)):(l.push("    ws-opts:"),l.push(`      path: ${i["ws-opts"].path}`),l.push("      headers:"),l.push(`        Host: ${r}`));return l.push(""),l.push("rules:"),l.push("  - MATCH,DIRECT"),l.join(`
`)}function an(t,e){let n=e.port||443,a=e.wsHost||e.host,r=e.sni||(e.tls?a:""),s=[],o=(c,l)=>l==="grpc"?{type:"grpc",service_name:`/${ye(c)}`}:l==="h2"?{type:"http",host:[a],path:c.startsWith("/")?c:`/${c}`}:{type:"ws",path:we(c),headers:{Host:a}};for(let c of t.vlessUsers)for(let l of I)s.push({type:"vless",tag:`vless-${c.remark||c.uuid.slice(0,8)}-${l}`,server:e.host,server_port:n,uuid:c.uuid,transport:o(c.path||t.wsPath,l),tls:e.tls?{enabled:!0,server_name:r,fingerprint:le}:null});for(let c of t.trojanUsers)for(let l of I)s.push({type:"trojan",tag:`trojan-${c.remark||c.password.slice(0,8)}-${l}`,server:e.host,server_port:n,password:c.password,transport:o(c.path||t.wsPath,l),tls:e.tls?{enabled:!0,server_name:r,fingerprint:le}:null});return JSON.stringify({outbounds:s,log:{level:"info"}},null,2)}function ze(t,e){let n=e.host,a=e.port||(e.tls?443:80),s=`/${(e.path||t.wsPath||"/ws").replace(/^\//,"")}`,o={host:n,port:a,wsPath:s,tls:e.tls,wsHost:e.wsHost,sni:e.sni},c=(f,p)=>e.kind==="vless"?ce({...o,uuid:e.credential,transport:f,remark:`vless-${p}`}):ue({...o,password:e.credential,transport:f,remark:`trojan-${p}`}),l=[{name:"WebSocket (ws)",link:c("ws","ws")},{name:"gRPC",link:c("grpc","grpc")},{name:"HTTP/2 (h2)",link:c("h2","h2")}],i=e.kind==="vless"?"VLESS":"Trojan",u=l.map((f,p)=>`
  <div class="row">
    <label>${f.name}</label>
    <div class="linkbox">
      <input type="text" readonly value="${f.link}" id="link${p}">
      <button onclick="copyLink(${p})">\u590D\u5236</button>
    </div>
  </div>`).join("");return`<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>${i} \u8282\u70B9\u914D\u7F6E</title>
<style>
  body { font-family: -apple-system, system-ui, sans-serif; background: #f5f5f7; color: #1d1d1f; display: flex; justify-content: center; padding: 48px 16px; margin: 0; }
  .card { background: #fff; border-radius: 16px; padding: 32px; max-width: 640px; width: 100%; box-shadow: 0 2px 12px rgba(0,0,0,.08); }
  h1 { font-size: 22px; margin: 0 0 8px; }
  p.desc { color: #6e6e73; font-size: 14px; margin: 0 0 24px; }
  .row { margin-bottom: 16px; }
  .row label { display: block; font-size: 13px; color: #6e6e73; margin-bottom: 6px; }
  .linkbox { display: flex; gap: 8px; align-items: center; }
  input[type=text] { flex: 1; padding: 10px 12px; border: 1px solid #d2d2d7; border-radius: 8px; font-size: 13px; color: #1d1d1f; background: #fafafa; }
  button { padding: 10px 16px; border: 0; border-radius: 8px; background: #0071e3; color: #fff; font-size: 14px; cursor: pointer; }
  button:hover { background: #0077ed; }
  .badge { display: inline-block; padding: 2px 10px; border-radius: 20px; background: #e8f0fe; color: #0071e3; font-size: 12px; font-weight: 600; }
</style>
</head>
<body>
<div class="card">
  <h1>${i} \u8282\u70B9 <span class="badge">${n}</span></h1>
  <p class="desc">\u5165\u7AD9\u8DEF\u5F84\uFF1A<b>${s}</b>\uFF08\u670D\u52A1\u7AEF\u5DF2\u81EA\u52A8\u517C\u5BB9 ws / grpc / h2\uFF0C\u590D\u5236\u4EFB\u4E00\u94FE\u63A5\u5BFC\u5165\u5BA2\u6237\u7AEF\uFF09</p>
  ${u}
</div>
<script>
function copyLink(i){ const el=document.getElementById('link'+i); el.select(); document.execCommand('copy'); el.style.borderColor='#34c759'; setTimeout(()=>el.style.borderColor='#d2d2d7',800); }
<\/script>
</body>
</html>`}function sn(t){let e=t.disguise_title||"AList",n=t.disguise_subtitle||"\u4E00\u4E2A\u652F\u6301\u591A\u5B58\u50A8\u7684\u6587\u4EF6\u5217\u8868\u7A0B\u5E8F";return`<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>${e}</title>
<style>
  :root { --bg:#fafafa; --card:#fff; --text:#1d1d1f; --muted:#86868b; --accent:#3b82f6; --border:#e5e5ea; }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family:-apple-system,BlinkMacSystemFont,"Segoe UI","PingFang SC","Microsoft YaHei",sans-serif; background:var(--bg); color:var(--text); min-height:100vh; }
  .navbar { background:var(--card); border-bottom:1px solid var(--border); padding:0 20px; height:56px; display:flex; align-items:center; justify-content:space-between; position:sticky; top:0; z-index:10; }
  .logo { font-size:18px; font-weight:700; display:flex; align-items:center; gap:8px; }
  .logo span { color:var(--accent); }
  .nav-right { display:flex; gap:16px; align-items:center; }
  .nav-right a { color:var(--muted); text-decoration:none; font-size:14px; }
  .nav-right a:hover { color:var(--accent); }
  .container { max-width:960px; margin:0 auto; padding:24px 20px 60px; }
  .breadcrumb { font-size:14px; color:var(--muted); padding:16px 0; }
  .breadcrumb b { color:var(--text); font-weight:600; }
  .searchbar { display:flex; gap:8px; margin-bottom:20px; }
  .searchbar input { flex:1; padding:10px 14px; border:1px solid var(--border); border-radius:8px; font-size:14px; background:var(--card); }
  .searchbar button { padding:10px 20px; border:0; border-radius:8px; background:var(--accent); color:#fff; font-size:14px; cursor:pointer; }
  .table { background:var(--card); border:1px solid var(--border); border-radius:12px; overflow:hidden; }
  .thead { display:flex; padding:12px 20px; font-size:12px; color:var(--muted); border-bottom:1px solid var(--border); }
  .thead > span:nth-child(1){ flex:2; } .thead > span:nth-child(2){ flex:1; } .thead > span:nth-child(3){ flex:1; }
  .file-row { display:flex; padding:14px 20px; border-bottom:1px solid var(--border); align-items:center; cursor:pointer; }
  .file-row:last-child { border-bottom:0; }
  .file-row:hover { background:#f5f5f7; }
  .file-row > span:nth-child(1){ flex:2; display:flex; align-items:center; gap:10px; }
  .file-row > span:nth-child(2){ flex:1; } .file-row > span:nth-child(3){ flex:1; }
  .icon { width:20px; text-align:center; }
  .name { font-size:14px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
  .meta { font-size:12px; color:var(--muted); }
  .footer { text-align:center; color:var(--muted); font-size:12px; padding:24px; }
</style>
</head>
<body>
<div class="navbar">
  <div class="logo"><span>\u25A4</span> ${e}</div>
  <div class="nav-right"><a href="#">\u9996\u9875</a><a href="#">\u66F4\u591A</a><a href="#">\u767B\u5F55</a></div>
</div>
<div class="container">
  <div class="breadcrumb">\u{1F4C1} <b>\u6839\u76EE\u5F55</b></div>
  <div class="searchbar">
    <input type="text" placeholder="\u641C\u7D22\u6587\u4EF6...">
    <button>\u641C\u7D22</button>
  </div>
  <div class="table">
    <div class="thead"><span>\u540D\u79F0</span><span>\u5927\u5C0F</span><span>\u4FEE\u6539\u65F6\u95F4</span></div>
    <div class="file-row"><span><span class="icon">\u{1F4C4}</span><span class="name">README.md</span></span><span class="meta">2.1 KB</span><span class="meta">2026-09-20 14:32</span></div>
    <div class="file-row"><span><span class="icon">\u{1F4C4}</span><span class="name">index.html</span></span><span class="meta">8.6 KB</span><span class="meta">2026-09-19 09:15</span></div>
    <div class="file-row"><span><span class="icon">\u{1F4C2}</span><span class="name">docs</span></span><span class="meta">-</span><span class="meta">2026-09-18 22:01</span></div>
    <div class="file-row"><span><span class="icon">\u{1F4C2}</span><span class="name">assets</span></span><span class="meta">-</span><span class="meta">2026-09-15 11:47</span></div>
    <div class="file-row"><span><span class="icon">\u{1F4C4}</span><span class="name">package.json</span></span><span class="meta">1.2 KB</span><span class="meta">2026-09-12 18:30</span></div>
    <div class="file-row"><span><span class="icon">\u{1F5BC}\uFE0F</span><span class="name">cover.png</span></span><span class="meta">456 KB</span><span class="meta">2026-09-10 08:20</span></div>
  </div>
</div>
<div class="footer">Powered by ${e} \xB7 ${n}</div>
</body>
</html>`}function Be(t,e=200){return new Response(t,{status:e,headers:{"Content-Type":"text/html; charset=utf-8","Cache-Control":"no-store"}})}function Y(t,e="text/plain; charset=utf-8"){return new Response(t,{headers:{"Content-Type":e,"Cache-Control":"no-store"}})}function Rr(t,e,n){let r=(new URL(t.url).searchParams.get("format")||"base64").toLowerCase(),s={host:n.host,port:n.port,tls:n.tls,wsHost:n.wsHost,sni:n.sni};switch(r){case"plain":return Y(Fe(e,s));case"clash":case"yaml":return Y(rn(e,s),"text/yaml; charset=utf-8");case"singbox":case"sing-box":case"json":return Y(an(e,s),"application/json; charset=utf-8");case"base64":default:return Y(nn(e,s))}}function Cr(t,e,n,a){let r=new URL(t.url),s=null;if(e.uuidSet.has(n)?s={kind:"vless",user:e.vlessIndex[n]}:e.passwordSet.has(n)&&(s={kind:"trojan",user:e.trojanIndex[n]}),!s)return new Response("Not Found",{status:404});let o=(r.searchParams.get("format")||"base64").toLowerCase(),c=a.host,l=a.port,i=s.user.path||e.wsPath,u=[];for(let f of I)s.kind==="vless"?u.push(ce({uuid:s.user.uuid,host:c,port:l,wsPath:i,tls:a.tls,wsHost:a.wsHost,sni:a.sni,transport:f,remark:`vless-${s.user.remark||"node"}-${f}`})):u.push(ue({password:s.user.password,host:c,port:l,wsPath:i,tls:a.tls,wsHost:a.wsHost,sni:a.sni,transport:f,remark:`trojan-${s.user.remark||"node"}-${f}`}));let d=u.join(`
`)+`
`;return Y(o==="plain"?d:btoa(d))}async function on(t,e,n){let a=new URL(t.url),r=a.pathname,s=tn(t),o=a.protocol==="https:",c=Number(a.port)||(o?443:80),l=(e.entryHost||"").trim(),i=l?{host:l,port:Number(e.entryPort)||443,tls:!0,wsHost:(e.entryWsHost||"").trim()||l,sni:(e.entrySni||"").trim()||l}:{host:s,port:c,tls:o,wsHost:s,sni:s};if(r==="/subscribe")return Rr(t,e,i);let u=r.match(/^\/([^/]+)\/subscribe$/);if(u)return Cr(t,e,decodeURIComponent(u[1]),i);let d=r.match(/^\/([^/]+)$/);if(d){let f=decodeURIComponent(d[1]);if(e.uuidSet.has(f)){let p=e.vlessIndex[f];return Be(ze(e,{host:i.host,port:i.port,tls:i.tls,wsHost:i.wsHost,sni:i.sni,credential:f,kind:"vless",path:p&&p.path||e.wsPath}))}if(e.passwordSet.has(f)){let p=e.trojanIndex[f];return Be(ze(e,{host:i.host,port:i.port,tls:i.tls,wsHost:i.wsHost,sni:i.sni,credential:f,kind:"trojan",path:p&&p.path||e.wsPath}))}}return Be(sn(e.settings))}var ln="1.0.8-20260925-0027";function Pr(t){if(t.length<2)return{frame:null,remaining:t,needMore:!0};let e=t[0]<<8|t[1];return e===0?{frame:new Uint8Array(0),remaining:t.slice(2),needMore:!1}:t.length<2+e?{frame:null,remaining:t,needMore:!0}:{frame:t.slice(2,2+e),remaining:t.slice(2+e),needMore:!1}}function cn(t){let e=new Uint8Array(2+t.length);return e[0]=t.length>>8,e[1]=t.length&255,e.set(t,2),e}async function un(t,e,n){let a=t.getReader(),r=new Uint8Array(0);try{for(;;){let{done:s,value:o}=await a.read();if(s)break;if(!o||o.byteLength===0)continue;let c=new Uint8Array(r.length+o.byteLength);for(c.set(r,0),c.set(o,r.length),r=c;;){let{frame:l,remaining:i,needMore:u}=Pr(r);if(u){r=i;break}if(r=i,l&&l.length>0)try{await e(l)}catch(d){n(`udp frame handler error: ${d.message}`)}if(r.length<2)break}}}catch(s){n(`readUdpFrames error: ${s.message}`)}finally{try{a.releaseLock()}catch{}}}var dn=[{name:"\u5B57\u8282\u8DF3\u52A8",host:"www.bytedance.com",port:80,region:"cn",icon:"\u{1F3B5}",color:"#325AB4"},{name:"Bilibili",host:"www.bilibili.com",port:80,region:"cn",icon:"\u{1F4FA}",color:"#FB7299"},{name:"\u5FAE\u4FE1",host:"weixin.qq.com",port:80,region:"cn",icon:"\u{1F4AC}",color:"#07C160"},{name:"\u6DD8\u5B9D",host:"www.taobao.com",port:80,region:"cn",icon:"\u{1F6D2}",color:"#FF5000"},{name:"GitHub",host:"github.com",port:80,region:"intl",icon:"\u{1F419}",color:"#24292F"},{name:"jsDelivr",host:"cdn.jsdelivr.net",port:80,region:"intl",icon:"\u{1F4E6}",color:"#E84D0E"},{name:"Cloudflare",host:"www.cloudflare.com",port:80,region:"intl",icon:"\u2601\uFE0F",color:"#F6821F"},{name:"Google",host:"www.google.com",port:80,region:"intl",icon:"\u{1F50D}",color:"#4285F4"},{name:"YouTube",host:"www.youtube.com",port:80,region:"intl",icon:"\u25B6\uFE0F",color:"#FF0000"}],pn=16,hn=3e3,fn=4;var Mr=5e3,Nr=5e3;function je(t,e,n="/"){return new TextEncoder().encode(`GET ${n} HTTP/1.1\r
Host: ${t}\r
User-Agent: Mozilla/5.0 (netprobe)\r
Connection: close\r
\r
`)}function Ir(t,e){let n=new Uint8Array(t.length+e.length);return n.set(t,0),n.set(e,t.length),n}function Hr(t){for(let e=0;e<t.length-3;e++)if(t[e]===13&&t[e+1]===10&&t[e+2]===13&&t[e+3]===10)return e+4;return-1}function mn(t){try{typeof t.close=="function"?t.close():t.writable&&typeof t.writable.close=="function"&&t.writable.close().catch(()=>{})}catch{}}function Ge(t,e){return new Promise(n=>{let a=new Uint8Array(0),r=!1,s=c=>{r||(r=!0,clearTimeout(o),n(c))},o=setTimeout(()=>s(null),e);(async()=>{let c=t.readable.getReader();try{for(;!r;){let{done:l,value:i}=await c.read();if(l)break;if(!(!i||i.byteLength===0)){if(a=Ir(a,i),Hr(a)>=0){s(Date.now());break}if(a.length>65536){s(null);break}}}}catch{}s(null);try{c.releaseLock()}catch{}})()})}async function Fr(t,e,n,a,r){let s=Date.now(),o;try{let l=await ge(t,2,e),i=oe(t,l.outbound);o=await K({config:t,outbound:i,addressType:2,addressRemote:e,portRemote:n,rawClientData:a,log:r})}catch{return null}if(!o)return null;let c=await Ge(o,hn);return mn(o),c===null?null:c-s}async function zr(t,e,n){let a=[];for(let i=0;i<pn;i+=fn){let u=[],d=Math.min(i+fn,pn);for(let p=i;p<d;p++)u.push(Fr(t,e.host,e.port,je(e.host,e.port),n));let f=await Promise.all(u);for(let p of f)a.push(p)}let r=a.filter(i=>i!==null),s=r.length>0?Math.round(r.reduce((i,u)=>i+u,0)/r.length):null,o=r.length>0?Math.min(...r):null,c=r.length>0?Math.max(...r):null,l=a.length>0?Math.round((a.length-r.length)/a.length*100):100;return{...e,samples:a,latency:s,min:o,max:c,loss:l,success:r.length,total:a.length}}async function gn(t,e){let n=await Promise.allSettled(dn.map(a=>zr(t,a,e)));return{ok:!0,ts:Date.now(),targets:n.map((a,r)=>a.status==="fulfilled"?a.value:{...dn[r],samples:[],latency:null,success:0,total:0,error:a.reason&&a.reason.message||"error"})}}async function wn(t,e){if(!t.proxyipHost)return{ok:!1,error:"\u672A\u914D\u7F6E proxyip\uFF0C\u8BF7\u5148\u5728\u7CFB\u7EDF\u8BBE\u7F6E\u4E2D\u586B\u5199"};let n="www.cloudflare.com",a=443,r=Date.now(),s=null;try{if(s=globalThis.connect?globalThis.connect({hostname:t.proxyipHost,port:Number(t.proxyipPort||443)}):null,!s)return{ok:!1,error:"connect \u4E0D\u53EF\u7528"};let c=s.writable.getWriter();await c.write(je(n,a)),c.releaseLock()}catch(c){try{s&&s.close()}catch{}return{ok:!1,error:`\u8FDE\u63A5\u5931\u8D25: ${c.message}`}}let o=await Ge(s,hn);try{s.close()}catch{}return o===null?{ok:!1,error:"\u8FDE\u63A5\u8D85\u65F6\u6216\u65E0\u54CD\u5E94"}:{ok:!0,latency:o-r,endpoint:`${t.proxyipHost}:${t.proxyipPort||443}`}}function Br(t){let n=[18,52];n.push(1,0),n.push(0,1),n.push(0,0,0,0,0,0);for(let a of String(t).split(".")){n.push(a.length);for(let r=0;r<a.length;r++)n.push(a.charCodeAt(r))}return n.push(0),n.push(0,1),n.push(0,1),new Uint8Array(n)}async function yn(t,e){let n=null,a=(t.udpOutbound||"").trim();if(a){let i=t.outboundByName[a];if(i&&i.type==="vless")n=i;else return{ok:!1,error:`UDP \u51FA\u7AD9 '${a}' \u4E0D\u5B58\u5728\u6216\u975E vless\uFF08\u4EC5 vless \u652F\u6301 UDP\uFF09`}}else if(n=t.outbounds.find(i=>i.type==="vless"),!n)return{ok:!1,error:"\u672A\u914D\u7F6E vless \u51FA\u7AD9\uFF0C\u65E0\u6CD5\u6D4B\u8BD5 UDP"};let r=Br("example.com"),s=cn(r),o=Date.now(),c;try{c=await V({address:n.address,port:Number(n.port),uuid:n.uuid,path:n.path,tls:!!n.tls,sni:n.sni||"",transport:n.transport},2,1,"8.8.8.8",53,s,e)}catch(i){return{ok:!1,error:`UDP \u51FA\u7AD9\u8FDE\u63A5\u5931\u8D25: ${i.message}`}}if(!c)return{ok:!1,error:"UDP \u51FA\u7AD9\u8FDE\u63A5\u5931\u8D25"};let l=await new Promise(i=>{let u=setTimeout(()=>i({ok:!1,error:"UDP \u54CD\u5E94\u8D85\u65F6"}),Mr);un(c.readable,d=>{d.length>=12&&d[0]===18&&d[1]===52&&d[2]&128&&(clearTimeout(u),i({ok:!0,latency:Date.now()-o,bytes:d.length}))},e)});try{c.writable.close().catch(()=>{})}catch{}return l}async function bn(t,e,n){let a="www.gstatic.com",s=Date.now(),o;try{o=await K({config:t,outbound:e,addressType:2,addressRemote:a,portRemote:80,rawClientData:je(a,80,"/generate_204"),log:n})}catch(l){return{ok:!1,error:l.message}}if(!o)return{ok:!1,error:"\u96A7\u9053\u5EFA\u7ACB\u5931\u8D25"};let c=await Ge(o,Nr);return mn(o),c===null?{ok:!1,error:"\u8FDE\u63A5\u8D85\u65F6\u6216\u65E0\u54CD\u5E94"}:{ok:!0,latency:c-s}}var U=Uint8Array,q=Uint16Array,jr=Int32Array,vn=new U([0,0,0,0,0,0,0,0,1,1,1,1,2,2,2,2,3,3,3,3,4,4,4,4,5,5,5,5,0,0,0,0]),xn=new U([0,0,0,0,1,1,2,2,3,3,4,4,5,5,6,6,7,7,8,8,9,9,10,10,11,11,12,12,13,13,0,0]),Gr=new U([16,17,18,0,8,7,9,6,10,5,11,4,12,3,13,2,14,1,15]),Tn=function(t,e){for(var n=new q(31),a=0;a<31;++a)n[a]=e+=1<<t[a-1];for(var r=new jr(n[30]),a=1;a<30;++a)for(var s=n[a];s<n[a+1];++s)r[s]=s-n[a]<<5|a;return{b:n,r}},En=Tn(vn,2),kn=En.b,Wr=En.r;kn[28]=258,Wr[258]=28;var Sn=Tn(xn,0),Vr=Sn.b,$s=Sn.r,Ke=new q(32768);for(S=0;S<32768;++S)P=(S&43690)>>1|(S&21845)<<1,P=(P&52428)>>2|(P&13107)<<2,P=(P&61680)>>4|(P&3855)<<4,Ke[S]=((P&65280)>>8|(P&255)<<8)>>1;var P,S,de=function(t,e,n){for(var a=t.length,r=0,s=new q(e);r<a;++r)t[r]&&++s[t[r]-1];var o=new q(e);for(r=1;r<e;++r)o[r]=o[r-1]+s[r-1]<<1;var c;if(n){c=new q(1<<e);var l=15-e;for(r=0;r<a;++r)if(t[r])for(var i=r<<4|t[r],u=e-t[r],d=o[t[r]-1]++<<u,f=d|(1<<u)-1;d<=f;++d)c[Ke[d]>>l]=i}else for(c=new q(a),r=0;r<a;++r)t[r]&&(c[r]=Ke[o[t[r]-1]++]>>15-t[r]);return c},pe=new U(288);for(S=0;S<144;++S)pe[S]=8;var S;for(S=144;S<256;++S)pe[S]=9;var S;for(S=256;S<280;++S)pe[S]=7;var S;for(S=280;S<288;++S)pe[S]=8;var S,An=new U(32);for(S=0;S<32;++S)An[S]=5;var S;var Kr=de(pe,9,1);var Yr=de(An,5,1),We=function(t){for(var e=t[0],n=1;n<t.length;++n)t[n]>e&&(e=t[n]);return e},D=function(t,e,n){var a=e/8|0;return(t[a]|t[a+1]<<8)>>(e&7)&n},Ve=function(t,e){var n=e/8|0;return(t[n]|t[n+1]<<8|t[n+2]<<16)>>(e&7)},qr=function(t){return(t+7)/8|0},Jr=function(t,e,n){return(e==null||e<0)&&(e=0),(n==null||n>t.length)&&(n=t.length),new U(t.subarray(e,n))};var Zr=["unexpected EOF","invalid block type","invalid length/literal","invalid distance","stream finished","no stream handler",,"no callback","invalid UTF-8 data","extra field too long","date not in range 1980-2099","filename too long","stream finishing","invalid zip data"],O=function(t,e,n){var a=new Error(e||Zr[t]);if(a.code=t,Error.captureStackTrace&&Error.captureStackTrace(a,O),!n)throw a;return a},Xr=function(t,e,n,a){var r=t.length,s=a?a.length:0;if(!r||e.f&&!e.l)return n||new U(0);var o=!n,c=o||e.i!=2,l=e.i;o&&(n=new U(r*3));var i=function(et){var tt=n.length;if(et>tt){var nt=new U(Math.max(tt*2,et));nt.set(n),n=nt}},u=e.f||0,d=e.p||0,f=e.b||0,p=e.l,w=e.d,m=e.m,y=e.n,h=r*8;do{if(!p){u=D(t,d,1);var g=D(t,d+1,3);if(d+=3,g)if(g==1)p=Kr,w=Yr,m=9,y=5;else if(g==2){var L=D(t,d,31)+257,$=D(t,d+10,15)+4,x=L+D(t,d+5,31)+1;d+=14;for(var v=new U(x),_=new U(19),A=0;A<$;++A)_[Gr[A]]=D(t,d+A*3,7);d+=$*3;for(var R=We(_),Ee=(1<<R)-1,Z=de(_,R,1),A=0;A<x;){var qe=Z[D(t,d,Ee)];d+=qe&15;var b=qe>>4;if(b<16)v[A++]=b;else{var j=0,fe=0;for(b==16?(fe=3+D(t,d,3),d+=2,j=v[A-1]):b==17?(fe=3+D(t,d,7),d+=3):b==18&&(fe=11+D(t,d,127),d+=7);fe--;)v[A++]=j}}var Je=v.subarray(0,L),M=v.subarray(L);m=We(Je),y=We(M),p=de(Je,m,1),w=de(M,y,1)}else O(1);else{var b=qr(d)+4,E=t[b-4]|t[b-3]<<8,T=b+E;if(T>r){l&&O(0);break}c&&i(f+E),n.set(t.subarray(b,T),f),e.b=f+=E,e.p=d=T*8,e.f=u;continue}if(d>h){l&&O(0);break}}c&&i(f+131072);for(var Cn=(1<<m)-1,Pn=(1<<y)-1,ke=d;;ke=d){var j=p[Ve(t,d)&Cn],G=j>>4;if(d+=j&15,d>h){l&&O(0);break}if(j||O(2),G<256)n[f++]=G;else if(G==256){ke=d,p=null;break}else{var Ze=G-254;if(G>264){var A=G-257,X=vn[A];Ze=D(t,d,(1<<X)-1)+kn[A],d+=X}var Se=w[Ve(t,d)&Pn],Ae=Se>>4;Se||O(3),d+=Se&15;var M=Vr[Ae];if(Ae>3){var X=xn[Ae];M+=Ve(t,d)&(1<<X)-1,d+=X}if(d>h){l&&O(0);break}c&&i(f+131072);var Xe=f+Ze;if(f<M){var Qe=s-M,Mn=Math.min(M,Xe);for(Qe+f<0&&O(3);f<Mn;++f)n[f]=a[Qe+f]}for(;f<Xe;++f)n[f]=n[f-M]}}e.l=p,e.p=ke,e.b=f,e.f=u,p&&(u=1,e.m=m,e.d=w,e.n=y)}while(!u);return f!=n.length&&o?Jr(n,0,f):n.subarray(0,f)};var Qr=new U(0);var ea=function(t,e){return((t[0]&15)!=8||t[0]>>4>7||(t[0]<<8|t[1])%31)&&O(6,"invalid zlib data"),(t[1]>>5&1)==+!e&&O(6,"invalid zlib data: "+(t[1]&32?"need":"unexpected")+" dictionary"),(t[1]>>3&4)+2};function Ln(t,e){return Xr(t.subarray(ea(t,e&&e.dictionary),-4),{i:2},e&&e.out,e&&e.dictionary)}var ta=typeof TextDecoder<"u"&&new TextDecoder,na=0;try{ta.decode(Qr,{stream:!0}),na=1}catch{}var Ye={"Content-Type":"application/json; charset=utf-8"};function k(t,e=200){return new Response(JSON.stringify(t),{status:e,headers:Ye})}async function ve(t){try{return await t.json()}catch{return null}}function ra(t){return t.admin_cookie_secret||t.admin_password_hash||"vtd-insecure-secret"}async function $n(t,e,n){let s=new URL(t.url).pathname.split("/").filter(Boolean),o=s[2]||"",c=s[3]||null,l=t.method,{DB:i,GEO_KV:u}=e.env,d=e.settings,f=ra(d);if(o==="login"&&l==="POST"){let h=await ve(t);if(!h||!h.password)return k({error:"password required"},400);if(!await wt(h.password,e.adminPasswordHash))return k({error:"invalid password"},401);let b=await bt(f);return new Response(JSON.stringify({ok:!0}),{status:200,headers:{...Ye,"Set-Cookie":`${Q}=${b}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${7*86400}`}})}let p=xt(t.headers.get("Cookie"));if(!await vt(p[Q],f))return k({error:"unauthorized"},401);if(o==="logout"&&l==="POST")return new Response(JSON.stringify({ok:!0}),{status:200,headers:{...Ye,"Set-Cookie":`${Q}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0`}});if(o==="version"&&l==="GET")return k({ok:!0,version:ln});if(await ya(i),o==="settings"){if(l==="GET"){let{results:h}=await i.prepare("SELECT key, value FROM settings").all();return k((h||[]).reduce((g,b)=>(g[b.key]=b.value,g),{}))}if(l==="PUT"){let h=await ve(t);if(!h)return k({error:"bad body"},400);let g=new Set(["ws_path","default_outbound","proxyip","udp_outbound","disguise_title","disguise_subtitle","entry_host","entry_port","entry_sni","entry_ws_host","admin_password_hash","admin_cookie_secret"]);for(let[b,E]of Object.entries(h))typeof E=="string"&&g.has(b)&&await i.prepare("INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at").bind(b,E,Date.now()).run();return W("settings"),k({ok:!0})}return k({error:"method not allowed"},405)}let y={"vless-users":{table:"vless_users",cacheKey:"vlessUsers",cols:["uuid","remark","enable","path","expire_at","traffic_limit","traffic_reset_at"]},"trojan-users":{table:"trojan_users",cacheKey:"trojanUsers",cols:["password","remark","enable","path","expire_at","traffic_limit","traffic_reset_at"]},outbounds:{table:"outbounds",cacheKey:"outbounds",cols:["type","name","address","port","uuid","path","tls","udp","enable","sort","username","password","sni","transport"],validate(h){if(h.type!==void 0&&!["socks5","http","vless"].includes(h.type))return"invalid outbound type";if(h.port!==void 0&&(!Number.isInteger(Number(h.port))||Number(h.port)<=0||Number(h.port)>65535))return"invalid port";if((h.type==="socks5"||h.type==="http")&&!h.address)return"address required";if(h.type==="vless"){if(!h.uuid)return"vless requires uuid";if(h.transport!==void 0&&!["raw","ws","grpc","httpupgrade","h2"].includes(h.transport))return"invalid vless transport"}return h.username&&!h.password||!h.username&&h.password?"username and password must be set together":((h.type==="socks5"||h.type==="http")&&(h.udp=0),h.type!=="vless"&&(h.transport="ws"),null)}},"routing-rules":{table:"routing_rules",cacheKey:"routingRules",cols:["rule","outbound","enable","sort"]}}[o];if(y)return aa(l,c,y,i,t);if(o==="stats"&&l==="GET"){let[h,g]=await Promise.all([i.prepare("SELECT remark, uuid, up, down, path, expire_at, traffic_limit, traffic_reset_at FROM vless_users ORDER BY (up + down) DESC").all(),i.prepare("SELECT remark, password, up, down, path, expire_at, traffic_limit, traffic_reset_at FROM trojan_users ORDER BY (up + down) DESC").all()]),b=Math.floor(Date.now()/1e3),E=T=>(T||[]).map(L=>{let $=Number(L.up||0),x=Number(L.down||0),v=Number(L.traffic_limit||0),_=$+x;return{...L,used:_,remaining:v>0?Math.max(0,v-_):null,expired:L.expire_at>0&&L.expire_at<b,limitReached:v>0&&_>=v}});return k({vless:E(h.results),trojan:E(g.results)})}if(o==="geo"&&s[3]==="update"&&l==="POST")try{if(await u.get("geo:updating")==="1")return k({ok:!0,started:!1,updating:!0});if(await u.put("geo:updating","1",{expirationTtl:600}),e.env&&e.env.GEO_QUEUE&&typeof e.env.GEO_QUEUE.send=="function")return await e.env.GEO_QUEUE.send({kind:"geo-update"}),await u.put("geo:update_status",JSON.stringify({startedAt:Date.now(),state:"updating",step:0,total:0,updated:0,failed:[],current:"",message:"\u5DF2\u5165\u961F\uFF0C\u7B49\u5F85\u6D88\u8D39\u8005\u6267\u884C\u2026"})).catch(()=>{}),k({ok:!0,started:!0,queued:!0,updating:!0});if(n&&typeof n.waitUntil=="function")return n.waitUntil(xe(i,u)),k({ok:!0,started:!0,updating:!0});let g=await xe(i,u);return k({ok:!0,started:!1,updated:g.updated,total:g.total,failed:g.failed})}catch(h){return await u.put("geo:updating","0").catch(()=>{}),k({error:h.message},500)}if(o==="geo"&&s[3]==="status"&&l==="GET"){let[h,g,b]=await Promise.all([u.get("geo:updating"),u.get("geo:update_status"),u.get(Le)]),E=null;if(g)try{E=JSON.parse(g)}catch{}return k({ok:!0,updating:h==="1",version:b||null,status:E})}if(o==="netstatus"&&s[3]==="test"&&l==="POST")try{return k(await gn(e,h=>console.log(h)))}catch(h){return k({ok:!1,error:h.message},500)}if(o==="test"){if(s[3]==="proxyip"&&l==="POST")try{return k(await wn(e,h=>console.log(h)))}catch(h){return k({ok:!1,error:h.message},500)}if(s[3]==="udp"&&l==="POST")try{return k(await yn(e,h=>console.log(h)))}catch(h){return k({ok:!1,error:h.message},500)}if(s[3]==="outbound"&&s[4]&&l==="POST"){let h=await i.prepare("SELECT * FROM outbounds WHERE id = ?").bind(Number(s[4])).first();if(!h)return k({ok:!1,error:"outbound not found"},404);try{return k(await bn(e,h,g=>console.log(g)))}catch(g){return k({ok:!1,error:g.message},500)}}}return k({error:"not found"},404)}async function _n(t){try{let{results:e}=await t.prepare("SELECT name FROM pragma_table_info('outbounds')").all();if((e||[]).some(n=>n.name==="transport"))return;await t.prepare("ALTER TABLE outbounds ADD COLUMN transport TEXT DEFAULT 'ws'").run(),console.log("[admin] outbounds.transport column added (migration)")}catch(e){console.log("[admin] outbounds transport migration skipped: "+e.message)}}async function aa(t,e,n,a,r){let{table:s,cols:o}=n,c="id";if(t==="GET"){let{results:l}=await a.prepare(`SELECT * FROM ${s} ORDER BY id`).all();return k(l||[])}if(t==="POST"){let l=await ve(r);if(!l)return k({error:"bad body"},400);if(n.validate){let p=n.validate(l);if(p)return k({error:p},400)}s==="outbounds"&&await _n(a);let i=o.filter(p=>l[p]!==void 0);if(i.length===0)return k({error:"no fields"},400);let u=i.map(()=>"?").join(","),d=i.map(p=>l[p]),{meta:f}=await a.prepare(`INSERT INTO ${s} (${i.join(",")}) VALUES (${u})`).bind(...d).run();return n.cacheKey&&W(n.cacheKey),k({ok:!0,id:f.last_row_id})}if(t==="PUT"&&e){let l=await ve(r);if(!l)return k({error:"bad body"},400);if(n.validate){let f=n.validate(l);if(f)return k({error:f},400)}s==="outbounds"&&await _n(a);let i=o.filter(f=>l[f]!==void 0);if(i.length===0)return k({error:"no fields"},400);let u=i.map(f=>`${f} = ?`).join(","),d=i.map(f=>l[f]);return await a.prepare(`UPDATE ${s} SET ${u} WHERE ${c} = ?`).bind(...d,Number(e)).run(),n.cacheKey&&W(n.cacheKey),k({ok:!0})}return t==="DELETE"&&e?(await a.prepare(`DELETE FROM ${s} WHERE ${c} = ?`).bind(Number(e)).run(),n.cacheKey&&W(n.cacheKey),k({ok:!0})):k({error:"method not allowed"},405)}var be={geosite:["cn","apple","google","microsoft","facebook","twitter","telegram","github","netflix","youtube","spotify","discord","tiktok","paypal","steam","cloudflare","openai","amazon","whatsapp","instagram","linkedin","mozilla","adobe","speedtest","oracle","digitalocean","vultr","jetbrains","gitee","baidu","aliyun","tencent","jd","bilibili","douyin","zhihu","iqiyi","youku","xiaomi","huawei"],geoip:["cn","hk","mo","tw","jp","kr","sg","my","th","vn","id","ph","us","ca","gb","de","fr","nl","se","au","nz","ru","in","br","ar","mx","za","tr","ae","sa","il","es","it","ch","at","be","dk","fi","no","pl","pt","ie","cz","hu","ro","ua","kz"]};async function Te(t,e,n){let a={geosite:new Set(be.geosite),geoip:new Set(be.geoip)},r=be.geosite.length+be.geoip.length,s=l=>{if(typeof n=="function")try{n(l)}catch{}},o={updated:0,total:0,failed:[]},c=0;for(let l of["geosite","geoip"])for(let i of a[l]){o.total++,c++,s({state:"updating",step:c,total:r,current:`${l}:${i}`,updated:o.updated,failed:o.failed,message:`\u62C9\u53D6 ${l}:${i}`});try{let u=await sa(l,i);u&&u.length>0?(await e.put(`${l}:${i}`,JSON.stringify(u)),o.updated++):o.failed.push(`${l}:${i} (empty rules)`)}catch(u){o.failed.push(`${l}:${i} (${u.message||u})`)}}return await e.put(Le,new Date().toISOString()),Wt(),o}async function xe(t,e){let n=Date.now(),a=r=>e.put("geo:update_status",JSON.stringify({startedAt:n,...r})).catch(()=>{});try{await a({state:"updating",step:0,total:0,updated:0,failed:[],current:"",message:"\u5F00\u59CB\u66F4\u65B0"});let r=await Te(t,e,s=>a({...s}));return await a({state:"done",step:r.total,total:r.total,updated:r.updated,failed:r.failed,current:"",message:"\u66F4\u65B0\u5B8C\u6210"}),await e.put("geo:updating","0").catch(()=>{}),r}catch(r){throw await a({state:"error",message:r.message||String(r),failed:[]}).catch(()=>{}),r}}async function sa(t,e){if(t==="geosite"){let r=await Un(e,new Set);if(r.length===0)throw new Error("empty geosite rules");return r}let n=await pa(e),a=[];for(let[r,s]of n)if(r.length===4?a.push(...ma(r,s)):a.push(...ga(r,s)),a.length>=3e4)break;if(a.length===0)throw new Error("empty geoip cidrs");return a}var oa="https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/",ia="https://cdn.jsdelivr.net/gh/v2fly/domain-list-community@master/data/",la=2e4;async function Un(t,e){if(e.has(t))return[];e.add(t);let n=encodeURIComponent(t),a=[oa+n,ia+n],r=null;for(let s of a)try{let o=await fetch(s,{cf:{cacheTtl:86400}});if(!o.ok){r=new Error(`HTTP ${o.status}`);continue}let c=await o.text(),l=[];for(let i of c.split(`
`)){if(i=i.trim(),!i||i.startsWith("#"))continue;if(i.startsWith("include:")){let f=i.slice(8).trim().split(/\s+/)[0];f&&l.push(...await Un(f,e));continue}let u=i;if(u.startsWith("full:"))u=u.slice(5);else if(u.startsWith("domain:"))u=u.slice(7);else if(u.startsWith("keyword:")||u.startsWith("regexp:"))continue;u=u.replace(/\s+@[^\s#]+/g,"");let d=u.indexOf("#");d>=0&&(u=u.slice(0,d)),u=u.trim().toLowerCase().replace(/^\.+/,""),u&&l.length<la&&l.push(u)}return l}catch(o){r=o}throw r||new Error("v2fly geosite fetch failed")}var ca="https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/",ua="https://cdn.jsdelivr.net/gh/SagerNet/sing-geoip@rule-set/",da=3e4;async function pa(t){let e=encodeURIComponent(t),n=[ca+"geoip-"+e+".srs",ua+"geoip-"+e+".srs"],a=null;for(let r of n)try{let s=await fetch(r,{cf:{cacheTtl:86400}});if(!s.ok){a=new Error(`HTTP ${s.status}`);continue}let o=new Uint8Array(await s.arrayBuffer());if(o.length<5||o[0]!==83||o[1]!==82||o[2]!==83){a=new Error("bad srs magic");continue}if(o[3]>1){a=new Error(`unsupported srs version ${o[3]}`);continue}let c;try{c=Ln(o.subarray(4))}catch{a=new Error("zlib inflate failed");continue}return fa(c)}catch(s){a=s}throw a||new Error("sing-geoip srs fetch failed")}function fa(t){let e=0,n=J(t,e);e=n.p;let a=[];for(let r=0;r<n.v;r++){let s=t[e++];if(s!==0)throw new Error(`geoip logical rule unsupported (type ${s})`);for(;;){let o=t[e++];if(o===255)break;if(o===5||o===6){if(t[e++]!==1)throw new Error("bad ipset version");let c=ha(t,e);e+=8;for(let l=0;l<c&&a.length<da*2;l++){let i=J(t,e);e=i.p;let u=t.subarray(e,e+i.v);e+=i.v,i=J(t,e),e=i.p;let d=t.subarray(e,e+i.v);if(e+=i.v,u.length!==d.length||u.length!==4&&u.length!==16)throw new Error("bad ipset addr");a.push([u,d])}}else if(o===0||o===7||o===9){let c=J(t,e);e=c.p,e+=c.v*2}else if(o===1||o===3||o===4||o===8||o===10||o===11||o===12||o===13||o===14||o===15||o===17||o===18||o===19||o===20||o===21||o===22||o===23){let c=J(t,e);e=c.p;for(let l=0;l<c.v;l++){let i=J(t,e);e=i.p,e+=i.v}}else throw new Error(`geoip unsupported item type ${o}`)}}return a}function J(t,e){let n=0,a=0;for(;;){let r=t[e++];if(n|=(r&127)<<a,!(r&128))break;if(a+=7,a>63)throw new Error("uvarint overflow")}return{v:n,p:e}}function ha(t,e){let n=0;for(let a=0;a<8;a++)n=n*256+t[e+a];return n}function ma(t,e){let n=(t[0]<<24>>>0)+(t[1]<<16)+(t[2]<<8)+t[3],a=(e[0]<<24>>>0)+(e[1]<<16)+(e[2]<<8)+e[3],r=[];for(;n<=a;){let s=0;for(;;){let o=1<<s+1;if(n&o-1||n+o-1>a)break;s++}r.push(`${n>>>24}.${n>>>16&255}.${n>>>8&255}.${n&255}/${32-s}`),n+=1<<s}return r}function ga(t,e){let n=0n,a=0n;for(let s of t)n=n<<8n|BigInt(s);for(let s of e)a=a<<8n|BigInt(s);let r=[];for(;n<=a;){let s=0n;for(;;){let o=1n<<s+1n;if((n&o-1n)!==0n||n+o-1n>a)break;s++}r.push(`${wa(n)}/${128-Number(s)}`),n+=1n<<s}return r}function wa(t){let e=[];for(let c=7;c>=0;c--)e.push(Number(t>>BigInt(c*16)&0xffffn));let n=-1,a=0,r=-1,s=0;for(let c=0;c<8;c++)e[c]===0?(r<0&&(r=c),s++,s>a&&(a=s,n=r)):(r=-1,s=0);let o="";for(let c=0;c<8;c++)c===n&&a>=2?(o+=(o.length>0&&!o.endsWith(":"),"::"),c+=a-1):(o.length>0&&!o.endsWith(":")&&(o+=":"),o+=e[c].toString(16));return o}async function ya(t){let e=[["path","TEXT DEFAULT ''"],["expire_at","INTEGER DEFAULT 0"],["traffic_limit","INTEGER DEFAULT 0"],["traffic_reset_at","INTEGER DEFAULT 0"]];for(let n of["vless_users","trojan_users"])try{let{results:a}=await t.prepare(`SELECT name FROM pragma_table_info('${n}')`).all(),r=new Set((a||[]).map(s=>s.name));for(let[s,o]of e)r.has(s)||(await t.prepare(`ALTER TABLE ${n} ADD COLUMN ${s} ${o}`).run(),console.log(`[admin] ${n}.${s} column added (migration)`))}catch(a){console.log(`[admin] ${n} migration skipped: ${a.message}`)}}function Dn(t){return`<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>\u8282\u70B9\u7BA1\u7406\u540E\u53F0</title>
<style>
  :root { --bg:#f2f2f7; --card:#fff; --text:#1c1c1e; --muted:#8e8e93; --accent:#0a84ff; --danger:#ff3b30; --border:rgba(60,60,67,.12); }
  * { box-sizing:border-box; margin:0; padding:0; }
  body { font-family:-apple-system,BlinkMacSystemFont,"SF Pro Text","PingFang SC","Microsoft YaHei",sans-serif; background:var(--bg); color:var(--text); }
  .login-wrap { min-height:100vh; display:flex; align-items:center; justify-content:center; }
  .login-card { background:var(--card); border-radius:24px; padding:40px; width:340px; box-shadow:0 4px 24px rgba(0,0,0,.08); text-align:center; }
  .login-card h1 { font-size:24px; font-weight:700; margin-bottom:8px; }
  .login-card p { color:var(--muted); font-size:14px; margin-bottom:24px; }
  .login-card input { width:100%; padding:12px 16px; border:1px solid var(--border); border-radius:12px; font-size:15px; margin-bottom:16px; background:#fafafa; }
  .btn { background:var(--accent); color:#fff; border:0; border-radius:12px; padding:12px; font-size:15px; font-weight:600; cursor:pointer; width:100%; }
  .btn:disabled { opacity:.5; }
  .btn.danger { background:var(--danger); }
  .btn.small { width:auto; padding:6px 12px; font-size:13px; border-radius:8px; }
  .sidebar { position:fixed; top:0; left:0; bottom:0; width:220px; background:var(--card); border-right:1px solid var(--border); padding:20px 12px; }
  .sidebar h2 { font-size:17px; font-weight:700; padding:0 12px 16px; }
  .nav-item { padding:10px 12px; border-radius:10px; font-size:14px; cursor:pointer; color:var(--text); margin-bottom:4px; }
  .nav-item:hover { background:var(--bg); }
  .nav-item.active { background:var(--accent); color:#fff; }
  .main { margin-left:220px; padding:28px 32px; max-width:1080px; }
  .page-title { font-size:26px; font-weight:700; margin-bottom:20px; }
  .card { background:var(--card); border-radius:16px; padding:20px; margin-bottom:16px; box-shadow:0 1px 4px rgba(0,0,0,.04); }
  table { width:100%; border-collapse:collapse; font-size:14px; }
  th { text-align:left; color:var(--muted); font-weight:600; font-size:12px; padding:8px 10px; border-bottom:1px solid var(--border); }
  td { padding:10px; border-bottom:1px solid var(--border); vertical-align:middle; }
  tr:last-child td { border-bottom:0; }
  .badge { display:inline-block; padding:2px 10px; border-radius:20px; font-size:12px; background:#e9f5ff; color:var(--accent); }
  .badge.off { background:#f2f2f7; color:var(--muted); }
  .badge.on { background:#e8f8ef; color:#34c759; }
  .toolbar { display:flex; gap:8px; margin-bottom:16px; }
  .toolbar .btn { width:auto; padding:8px 16px; }
  .modal-mask { position:fixed; inset:0; background:rgba(0,0,0,.4); display:none; align-items:center; justify-content:center; z-index:50; }
  .modal-mask.show { display:flex; }
  .modal { background:var(--card); border-radius:20px; padding:24px; width:480px; max-width:92vw; max-height:80vh; overflow:auto; }
  .modal h3 { font-size:18px; margin-bottom:16px; }
  .modal label { display:block; font-size:13px; color:var(--muted); margin:12px 0 6px; }
  .modal input, .modal select, .modal textarea { width:100%; padding:10px 12px; border:1px solid var(--border); border-radius:10px; font-size:14px; background:#fafafa; }
  .modal textarea { min-height:60px; font-family:ui-monospace,Menlo,monospace; }
  .modal .actions { display:flex; gap:8px; margin-top:20px; justify-content:flex-end; }
  .modal .actions .btn { width:auto; padding:10px 20px; }
  .stat-grid { display:grid; grid-template-columns:repeat(auto-fill,minmax(220px,1fr)); gap:12px; }
  .stat-item { background:var(--card); border-radius:14px; padding:16px; box-shadow:0 1px 4px rgba(0,0,0,.04); }
  .stat-item .num { font-size:22px; font-weight:700; }
  .stat-item .lbl { font-size:12px; color:var(--muted); margin-top:4px; }
  .mono { font-family:ui-monospace,Menlo,monospace; font-size:12px; word-break:break-all; }
  .toast { position:fixed; bottom:24px; left:50%; transform:translateX(-50%); background:#1c1c1e; color:#fff; padding:10px 20px; border-radius:12px; font-size:14px; opacity:0; transition:opacity .3s; z-index:100; }
  .toast.show { opacity:1; }
  .net-grid { display:grid; grid-template-columns:repeat(auto-fill,minmax(250px,1fr)); gap:12px; }
  .net-card { background:var(--card); border-radius:16px; padding:16px 18px; box-shadow:0 1px 4px rgba(0,0,0,.04); }
  .net-head { display:flex; align-items:center; gap:8px; margin-bottom:12px; }
  .net-icon { font-size:22px; line-height:1; }
  .net-name { font-size:15px; font-weight:600; flex:1; }
  .net-latency { font-size:30px; font-weight:700; letter-spacing:-.5px; margin-bottom:12px; }
  .net-latency .unit { font-size:13px; color:var(--muted); font-weight:400; margin-left:3px; }
  .net-latency.fail { font-size:16px; color:var(--muted); line-height:30px; }
  .net-dots { display:flex; gap:4px; flex-wrap:nowrap; }
  .net-dot { width:12px; height:12px; border-radius:50%; background:#d1d1d6; flex:none; }
  .net-dot.ok { background:#34c759; }
  .net-dot.warn { background:#ffcc00; }
  .net-dot.bad { background:#ff9500; }
  .net-foot { display:flex; justify-content:space-between; align-items:center; margin-top:10px; font-size:12px; color:var(--muted); }
  /* ---- Geo \u66F4\u65B0\u8FDB\u5EA6\u5F39\u6846 ---- */
  .geo-modal { position:fixed; inset:0; background:rgba(0,0,0,.45); display:none; align-items:center; justify-content:center; z-index:60; }
  .geo-modal.show { display:flex; }
  .geo-box { background:var(--card); border-radius:20px; padding:24px 26px; width:430px; max-width:92vw; box-shadow:0 8px 32px rgba(0,0,0,.18); }
  .geo-box h3 { font-size:17px; margin-bottom:6px; }
  .geo-sub { font-size:12px; color:var(--muted); margin-bottom:14px; }
  .geo-bar { height:8px; border-radius:4px; background:var(--bg); overflow:hidden; margin-bottom:12px; }
  .geo-bar > div { height:100%; width:0; background:linear-gradient(90deg,#0a84ff,#34c759); border-radius:4px; transition:width .4s ease; }
  .geo-line { font-size:13px; color:var(--text); margin-bottom:6px; line-height:1.6; word-break:break-all; }
  .geo-line .dim { color:var(--muted); }
  .geo-actions { display:flex; gap:8px; margin-top:16px; justify-content:flex-end; }
  .geo-actions .btn { width:auto; padding:8px 16px; }
  .geo-done { display:block; font-size:13px; padding:8px 12px; border-radius:10px; margin-bottom:8px; }
  .geo-done.ok { background:#e8f8ef; color:#1d7a3f; }
  .geo-done.err { background:#ffeceb; color:#d70015; }
  /* ---- \u7F51\u7EDC\u72B6\u6001\uFF1Aip.skk.moe \u98CE\u683C\u52A8\u6001\u63A2\u6D4B ---- */
  .net-toolbar { display:flex; gap:12px; align-items:center; flex-wrap:wrap; margin-bottom:14px; }
  .net-toolbar .auto-refresh { display:flex; align-items:center; gap:6px; font-size:13px; color:var(--muted); cursor:pointer; user-select:none; }
  .net-toolbar .net-update-time { font-size:12px; color:var(--muted); margin-left:auto; }
  .net-grid { display:grid; grid-template-columns:repeat(auto-fill,minmax(280px,1fr)); gap:14px; }
  .net-card { background:var(--card); border-radius:18px; padding:16px 18px; box-shadow:0 1px 4px rgba(0,0,0,.04); position:relative; overflow:hidden; animation:netIn .5s ease both; }
  .net-card::before { content:''; position:absolute; left:0; top:0; bottom:0; width:4px; background:var(--nc,#34c759); opacity:.85; }
  .net-card.warn-state::before { background:#ffcc00; }
  .net-card.bad-state::before { background:#ff3b30; }
  @keyframes netIn { from { opacity:0; transform:translateY(10px) scale(.98); } to { opacity:1; transform:none; } }
  .net-head { display:flex; align-items:center; gap:10px; margin-bottom:10px; }
  .net-logo { width:34px; height:34px; border-radius:9px; display:flex; align-items:center; justify-content:center; font-size:18px; background:#e9e9ee; color:#fff; flex:none; box-shadow:0 2px 6px rgba(0,0,0,.14); }
  .net-name { font-size:15px; font-weight:700; flex:1; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }
  .net-status-line { display:flex; align-items:center; gap:10px; margin-bottom:4px; }
  .net-pulse { width:10px; height:10px; border-radius:50%; background:#9aa0a6; flex:none; }
  .net-pulse.good { background:#34c759; animation:pulse 2s ease infinite; }
  .net-pulse.slow { background:#ffcc00; animation:pulse 2.6s ease infinite; }
  .net-pulse.fail { background:#ff3b30; animation:pulse 1.4s ease infinite; }
  @keyframes pulse { 0% { box-shadow:0 0 0 0 rgba(52,199,89,.5); } 70% { box-shadow:0 0 0 8px rgba(52,199,89,0); } 100% { box-shadow:0 0 0 0 rgba(52,199,89,0); } }
  .net-latency { font-size:30px; font-weight:800; letter-spacing:-.5px; line-height:1.1; }
  .net-latency .unit { font-size:13px; color:var(--muted); font-weight:400; margin-left:3px; }
  .net-latency.fail { font-size:15px; color:var(--muted); line-height:30px; }
  .net-meta { display:flex; gap:14px; font-size:12px; color:var(--muted); margin:8px 0 10px; }
  .net-meta b { color:var(--text); font-weight:600; }
  .net-dots { display:flex; gap:4px; flex-wrap:nowrap; }
  .net-dot { width:12px; height:12px; border-radius:50%; background:#e3e3e8; flex:none; transition:background .3s; }
  .net-dot.ok { background:#34c759; }
  .net-dot.warn { background:#ffcc00; }
  .net-dot.bad { background:#ff9500; }
  /* \u63A2\u6D4B\u4E2D\u52A8\u6548\uFF1A\u9AA8\u67B6\u626B\u63CF */
  .net-latency.scan, .net-meta.scan { background:linear-gradient(90deg,#f2f2f7 25%,#e4e4ea 37%,#f2f2f7 63%); background-size:400% 100%; animation:scanMove 1.2s ease infinite; border-radius:6px; }
  .net-latency.scan { width:55%; height:30px; }
  .net-meta.scan { width:70%; height:14px; }
  @keyframes scanMove { 0% { background-position:100% 0; } 100% { background-position:-100% 0; } }
  .net-dot.scan-dot { background:#ececf1; animation:dotBlink 1.4s ease infinite; }
  .net-dot.scan-dot:nth-child(3n) { animation-delay:.2s; }
  .net-dot.scan-dot:nth-child(5n) { animation-delay:.4s; }
  @keyframes dotBlink { 0%,100% { opacity:.25; } 50% { opacity:1; } }
  /* ---- Apple style refinements ---- */
  body { -webkit-font-smoothing:antialiased; text-rendering:optimizeLegibility; }
  .card { transition:transform .15s ease, box-shadow .15s ease; }
  .nav-item { transition:background .15s ease, color .15s ease; }
  .btn { transition:opacity .15s ease, transform .1s ease; }
  .btn:active { transform:scale(.97); }
  .table-wrap { overflow-x:auto; -webkit-overflow-scrolling:touch; }
  /* ---- Responsive: iPad ---- */
  @media (max-width:1024px){
    .sidebar { width:180px; }
    .main { margin-left:180px; padding:24px; }
    .page-title { font-size:24px; }
  }
  /* ---- Responsive: Phone ---- */
  @media (max-width:768px){
    .login-card { width:calc(100% - 40px); border-radius:20px; padding:32px 24px; }
    .sidebar { position:fixed; top:auto; left:0; right:0; bottom:0; width:100%; height:58px; display:flex; align-items:center; justify-content:flex-start; overflow-x:auto; overflow-y:hidden; -webkit-overflow-scrolling:touch; scrollbar-width:none; border-top:1px solid var(--border); border-right:0; padding:4px 4px calc(4px + env(safe-area-inset-bottom)); background:rgba(255,255,255,.9); backdrop-filter:saturate(180%) blur(20px); -webkit-backdrop-filter:saturate(180%) blur(20px); z-index:40; }
    .sidebar::-webkit-scrollbar { display:none; }
    .sidebar h2 { display:none; }
    .nav-item { padding:6px 10px; font-size:10px; text-align:center; border-radius:8px; margin:0 2px; white-space:nowrap; flex:0 0 auto; min-width:60px; }
    .nav-item.active { background:var(--accent); }
    .nav-item#logoutBtn { margin-top:0; }
    .main { margin-left:0; padding:16px 12px 84px; }
    .page-title { font-size:20px; margin-bottom:14px; }
    .card { padding:14px; border-radius:14px; }
    .toolbar { flex-wrap:wrap; }
    .modal { width:100%; max-width:100%; max-height:86vh; border-radius:16px 16px 0 0; padding:20px 16px calc(20px + env(safe-area-inset-bottom)); }
    .modal-mask { align-items:flex-end; }
    .stat-grid { grid-template-columns:repeat(auto-fill,minmax(140px,1fr)); gap:10px; }
    table { min-width:620px; }
    .net-grid { grid-template-columns:1fr; }
  }
</style>
</head>
<body>
<div class="login-wrap" id="loginWrap">
  <div class="login-card">
    <h1>\u8282\u70B9\u7BA1\u7406</h1>
    <p>\u8BF7\u8F93\u5165\u7BA1\u7406\u5BC6\u7801</p>
    ${t?`<p style="margin:-8px 0 16px;padding:10px 12px;background:#e8f8ef;color:#1d7a3f;border-radius:10px;font-size:13px">\u9996\u6B21\u90E8\u7F72\u521D\u59CB\u5BC6\u7801\uFF1A<b>${t}</b><br>\u767B\u5F55\u540E\u8BF7\u53CA\u65F6\u4FEE\u6539</p>`:""}
    <input type="password" id="loginPwd" placeholder="\u7BA1\u7406\u5BC6\u7801" autocomplete="current-password">
    <button class="btn" id="loginBtn">\u767B \u5F55</button>
  </div>
</div>

<div id="app" style="display:none">
  <aside class="sidebar">
    <h2>\u2699\uFE0F \u8282\u70B9\u7BA1\u7406</h2>
    <div class="nav-item active" data-tab="stats">\u{1F4CA} \u6D41\u91CF\u7EDF\u8BA1</div>
    <div class="nav-item" data-tab="netstatus">\u{1F4E1} \u7F51\u7EDC\u72B6\u6001</div>
    <div class="nav-item" data-tab="vless">\u{1F511} VLESS \u7528\u6237</div>
    <div class="nav-item" data-tab="trojan">\u{1F6E1}\uFE0F Trojan \u7528\u6237</div>
    <div class="nav-item" data-tab="outbounds">\u{1F310} \u51FA\u7AD9\u4EE3\u7406</div>
    <div class="nav-item" data-tab="entry">\u{1F6AA} \u5165\u53E3\u8BBE\u7F6E</div>
    <div class="nav-item" data-tab="rules">\u{1F9ED} \u5206\u6D41\u89C4\u5219</div>
    <div class="nav-item" data-tab="settings">\u2699\uFE0F \u7CFB\u7EDF\u8BBE\u7F6E</div>
    <div class="nav-item" id="logoutBtn" style="margin-top:20px;color:var(--danger)">\u21A9 \u9000\u51FA\u767B\u5F55</div>
  </aside>
  <main class="main" id="mainContent"></main>
</div>

<div class="modal-mask" id="modalMask">
  <div class="modal">
    <h3 id="modalTitle"></h3>
    <div id="modalBody"></div>
    <div class="actions">
      <button class="btn small danger" onclick="closeModal()">\u53D6\u6D88</button>
      <button class="btn small" onclick="saveModal()">\u4FDD\u5B58</button>
    </div>
  </div>
</div>

<div class="geo-modal" id="geoModal">
  <div class="geo-box">
    <h3>\u{1F30F} \u66F4\u65B0 Geo \u89C4\u5219\u5E93</h3>
    <div class="geo-sub" id="geoSub">\u6B63\u5728\u51C6\u5907\u2026</div>
    <div class="geo-bar"><div id="geoBarFill"></div></div>
    <div class="geo-line" id="geoLine1">\u521D\u59CB\u5316\u2026</div>
    <div class="geo-line" id="geoLine2"></div>
    <div class="geo-line" id="geoLine3"></div>
    <div class="geo-actions">
      <button class="btn small" onclick="closeGeoModal()">\u5173\u95ED</button>
    </div>
  </div>
</div>

<div class="toast" id="toast"></div>

<script>
const $ = (s) => document.querySelector(s);
const state = { tab:'stats', editing:null, schema:null, records:[] };
const TAB_DEFS = {
  vless:   { title:'VLESS \u7528\u6237', api:'vless-users', fields:[
    {k:'uuid',label:'UUID'},
    {k:'remark',label:'\u5907\u6CE8'},
    {k:'path',label:'\u5165\u7AD9\u8DEF\u5F84',placeholder:'\u7559\u7A7A\u4F7F\u7528\u5168\u5C40\u5165\u7AD9\u8DEF\u5F84\uFF08\u5982 /ws\uFF09'},
    {k:'expire_at',label:'\u5230\u671F\u65F6\u95F4',type:'datetime-local'},
    {k:'traffic_limit',label:'\u6D41\u91CF\u9650\u5236(GB)',type:'number',placeholder:'0=\u4E0D\u9650'},
    {k:'traffic_reset_at',label:'\u6D41\u91CF\u91CD\u7F6E\u65F6\u95F4',type:'datetime-local',placeholder:'\u5230\u6B64\u540E\u81EA\u52A8\u6E05\u96F6\u5DF2\u7528\u6D41\u91CF'},
    {k:'enable',label:'\u542F\u7528',type:'checkbox'},
    {k:'status',label:'\u72B6\u6001',type:'status'}
  ]},
  trojan:  { title:'Trojan \u7528\u6237', api:'trojan-users', fields:[
    {k:'password',label:'\u5BC6\u7801'},
    {k:'remark',label:'\u5907\u6CE8'},
    {k:'path',label:'\u5165\u7AD9\u8DEF\u5F84',placeholder:'\u7559\u7A7A\u4F7F\u7528\u5168\u5C40\u5165\u7AD9\u8DEF\u5F84\uFF08\u5982 /ws\uFF09'},
    {k:'expire_at',label:'\u5230\u671F\u65F6\u95F4',type:'datetime-local'},
    {k:'traffic_limit',label:'\u6D41\u91CF\u9650\u5236(GB)',type:'number',placeholder:'0=\u4E0D\u9650'},
    {k:'traffic_reset_at',label:'\u6D41\u91CF\u91CD\u7F6E\u65F6\u95F4',type:'datetime-local',placeholder:'\u5230\u6B64\u540E\u81EA\u52A8\u6E05\u96F6\u5DF2\u7528\u6D41\u91CF'},
    {k:'enable',label:'\u542F\u7528',type:'checkbox'},
    {k:'status',label:'\u72B6\u6001',type:'status'}
  ]},
  outbounds:{ title:'\u51FA\u7AD9\u4EE3\u7406', api:'outbounds', fields:[{k:'type',label:'\u7C7B\u578B',type:'select',opts:['socks5','http','vless']},{k:'name',label:'\u540D\u79F0'},{k:'address',label:'\u5730\u5740'},{k:'port',label:'\u7AEF\u53E3',type:'number'},{k:'username',label:'\u7528\u6237\u540D(\u4EC5socks5/http)'},{k:'password',label:'\u5BC6\u7801(\u4EC5socks5/http)'},{k:'uuid',label:'UUID(\u4EC5vless)'},{k:'transport',label:'\u4F20\u8F93(\u4EC5vless)',type:'select',opts:['raw','ws','grpc','httpupgrade','h2']},{k:'path',label:'Path(\u4EC5vless; grpc \u4E3A serviceName)',placeholder:'ws/httpupgrade/h2 \u586B\u8DEF\u5F84; grpc \u586B serviceName(\u7559\u7A7A\u4E3A /Tun)'},{k:'tls',label:'TLS',type:'checkbox'},{k:'sni',label:'SNI(\u4EC5vless)',placeholder:'\u7559\u7A7A\u5219\u4F7F\u7528\u5730\u5740\u4F5C\u4E3A\u8FDE\u63A5\u4E3B\u673A\u4E0ESNI'},{k:'udp',label:'UDP',type:'checkbox'},{k:'enable',label:'\u542F\u7528',type:'checkbox'},{k:'sort',label:'\u6392\u5E8F',type:'number'}] },
  rules:   { title:'\u5206\u6D41\u89C4\u5219', api:'routing-rules', fields:[{k:'rule',label:'\u89C4\u5219(geosite:cn / geoip:cn / domain: / full: / keyword: / ip-cidr: / regexp:)'},{k:'outbound',label:'\u51FA\u7AD9(direct / reject / \u51FA\u7AD9\u540D)'},{k:'enable',label:'\u542F\u7528',type:'checkbox'},{k:'sort',label:'\u6392\u5E8F',type:'number'}] }
};

let token = null;

function toast(msg){ const t=$('#toast'); t.textContent=msg; t.classList.add('show'); setTimeout(()=>t.classList.remove('show'),2200); }
async function api(path, opts={}){
  const res = await fetch(path, Object.assign({}, opts, { headers:Object.assign({'Content-Type':'application/json'}, opts.headers||{}) }));
  if (res.status===401){ showLogin(); throw new Error('unauthorized'); }
  const data = await res.json().catch(()=>({}));
  if (!res.ok) throw new Error(data.error || res.statusText);
  return data;
}

function showLogin(){ $('#app').style.display='none'; $('#loginWrap').style.display='flex'; }
function showApp(){ $('#loginWrap').style.display='none'; $('#app').style.display='block'; switchTab('stats'); }

async function doLogin(){
  const pwd = $('#loginPwd').value;
  if(!pwd) return;
  const btn = $('#loginBtn'); btn.disabled = true;
  try { await api('/admin/api/login',{method:'POST',body:JSON.stringify({password:pwd})}); showApp(); toast('\u767B\u5F55\u6210\u529F'); }
  catch(e){ toast(e.message); }
  btn.disabled = false;
}

async function doLogout(){ try{ await api('/admin/api/logout',{method:'POST'}); }catch(e){} showLogin(); }

document.querySelectorAll('.nav-item[data-tab]').forEach(el=>el.onclick=()=>switchTab(el.dataset.tab));
$('#loginBtn').onclick = doLogin;
$('#loginPwd').addEventListener('keydown', e=>{ if(e.key==='Enter') doLogin(); });
$('#logoutBtn').onclick = doLogout;

async function switchTab(tab){
  state.tab = tab;
  document.querySelectorAll('.nav-item[data-tab]').forEach(el=>el.classList.toggle('active', el.dataset.tab===tab));
  const mc = $('#mainContent');
  if (tab==='stats'){ mc.innerHTML = '<div class="page-title">\u6D41\u91CF\u7EDF\u8BA1</div><div class="card">\u52A0\u8F7D\u4E2D...</div>'; await loadStats(); return; }
  if (tab==='netstatus'){ clearNetAuto(); mc.innerHTML = '<div class="page-title">\u7F51\u7EDC\u72B6\u6001</div><div class="card" style="padding:12px 16px;font-size:13px;color:var(--muted)">\u68C0\u6D4B\u6309\u9879\u76EE\u7F51\u7EDC\u8BBE\u7F6E\u53D1\u8D77\uFF08\u5206\u6D41\u89C4\u5219 + \u9ED8\u8BA4\u51FA\u7AD9 + proxyip + \u51FA\u7AD9\u96A7\u9053\uFF09\uFF0C\u5168\u90E8\u63A2\u6D4B\u5728 Worker \u5185\u5B8C\u6210\uFF0C\u591A\u76EE\u6807\u5E76\u884C\u3001\u6BCF\u76EE\u6807 16 \u6B21\u91C7\u6837\uFF0C\u7EA6 10-15 \u79D2\u5B8C\u6210\u3002\u7EFF=\u6B63\u5E38\uFF0C\u9EC4=\u9AD8\u5EF6\u8FDF\uFF0C\u7EA2/\u7070=\u5931\u8D25\u3002</div><div class="net-toolbar"><button class="btn small" onclick="runNetstatus()">\u5F00\u59CB\u68C0\u6D4B</button><label class="auto-refresh"><input type="checkbox" id="netAuto" checked onchange="scheduleNetAuto()"> \u81EA\u52A8\u5237\u65B0</label><span class="net-update-time" id="netUpdateTime"></span></div><div class="net-grid" id="netGrid"></div>'; runNetstatus(); return; }
  if (tab==='settings'){ mc.innerHTML = '<div class="page-title">\u7CFB\u7EDF\u8BBE\u7F6E</div><div class="card">\u52A0\u8F7D\u4E2D...</div>'; await loadSettings(); return; }
  if (tab==='entry'){ mc.innerHTML = '<div class="page-title">\u5165\u53E3\u8BBE\u7F6E</div><div class="card">\u52A0\u8F7D\u4E2D...</div>'; await loadEntry(); return; }
  const def = TAB_DEFS[tab];
  mc.innerHTML = '<div class="page-title">'+def.title+'</div><div class="toolbar"><button class="btn small" onclick="openNew()">\uFF0B \u65B0\u589E</button></div><div class="card"><div class="table-wrap"><table><thead><tr>'+def.fields.map(f=>'<th>'+f.label+'</th>').join('')+'<th>\u64CD\u4F5C</th></tr></thead><tbody id="tbody"></tbody></table></div></div>';
  state.schema = def;
  await loadList();
}

async function loadList(){
  const def = state.schema;
  const rows = await api('/admin/api/'+def.api);
  state.records = rows;
  const tbody = $('#tbody');
  tbody.innerHTML = rows.map((r,idx)=>{
    const tds = def.fields.map(f=>{
      if (f.type==='checkbox') return '<td>'+(r[f.k]? '<span class="badge on">\u5F00</span>':'<span class="badge off">\u5173</span>')+'</td>';
      if (f.type==='status') return statusCell(r);
      if (f.k==='uuid'||f.k==='password') return '<td class="mono">'+esc(r[f.k])+'</td>';
      return '<td>'+esc(r[f.k])+'</td>';
    }).join('');
    const testBtn = def.api==='outbounds' ? '<button class="btn small" onclick="testOutbound('+idx+', event)">\u6D4B\u8BD5</button> ' : '';
    return '<tr>'+tds+'<td>'+testBtn+'<button class="btn small" onclick="openEdit('+idx+')">\u7F16\u8F91</button> <button class="btn small danger" onclick="delRow('+idx+')">\u5220\u9664</button></td></tr>';
  }).join('') || '<tr><td colspan="99" style="text-align:center;color:var(--muted)">\u6682\u65E0\u6570\u636E</td></tr>';
}

function statusCell(r){
  const used = Number(r.up||0) + Number(r.down||0);
  const limit = Number(r.traffic_limit||0);
  const exp = Number(r.expire_at||0);
  const now = Math.floor(Date.now()/1000);
  let badge = '<span class="badge on">\u6B63\u5E38</span>';
  if (exp>0 && exp<now) badge = '<span class="badge off">\u5DF2\u5230\u671F</span>';
  else if (limit>0 && used>=limit) badge = '<span class="badge off">\u5DF2\u8D85\u9650</span>';
  const quota = limit>0 ? (fmtBytes(limit)) : '\u221E';
  return '<td>'+badge+'<div style="font-size:11px;color:var(--muted);margin-top:2px">\u5DF2\u7528 '+fmtBytes(used)+' / '+quota+'</div></td>';
}

function esc(s){ return String(s==null?'':s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }

function openNew(){ state.editing=null; openModal({}); }
function openEdit(idx){ state.editing = state.records[idx]; openModal(state.editing); }

// \u51FA\u7AD9\u8868\u5355\u6309\u7C7B\u578B\u663E\u793A\u7684\u5B57\u6BB5\u96C6\u5408\uFF08socks5/http \u663E\u793A\u8BA4\u8BC1\uFF0C\u9690\u85CF uuid/path/tls/sni/udp\uFF1Bvless \u53CD\u4E4B\uFF09
const OUTBOUND_TYPE_FIELDS = {
  socks5: ['type','name','address','port','username','password','enable','sort'],
  http:   ['type','name','address','port','username','password','enable','sort'],
  vless:  ['type','name','address','port','uuid','transport','path','tls','sni','udp','enable','sort'],
};

function openModal(record){
  const def = state.schema;
  state.draft = Object.assign({}, record);
  $('#modalTitle').textContent = state.editing ? '\u7F16\u8F91' : '\u65B0\u589E';
  renderModalBody();
  $('#modalMask').classList.add('show');
}

function renderModalBody(){
  const def = state.schema;
  let fields = def.fields;
  if (def.api === 'outbounds') {
    const t = state.draft.type || 'socks5';
    const allowed = OUTBOUND_TYPE_FIELDS[t] || OUTBOUND_TYPE_FIELDS.socks5;
    fields = def.fields.filter((f) => allowed.indexOf(f.k) !== -1);
  }
  $('#modalBody').innerHTML = fields.map(f=>{
    const val = state.draft[f.k];
    if (f.type==='status') return '';
    if (f.type==='checkbox') return '<label><input type="checkbox" id="f_'+f.k+'" '+(val?'checked':'')+' onchange="collectDraft()"> '+f.label+'</label>';
    if (f.type==='select') return '<label>'+f.label+'</label><select id="f_'+f.k+'" onchange="collectDraft();renderModalBody()">'+f.opts.map(o=>'<option '+(o===val?'selected':'')+'>'+o+'</option>').join('')+'</select>';
    const inputType = f.type==='datetime-local' ? 'datetime-local' : (f.type||'text');
    const showVal = f.type==='datetime-local' ? toLocalInput(val) : val;
    return '<label>'+f.label+'</label><input type="'+inputType+'" id="f_'+f.k+'" value="'+esc(showVal)+'" oninput="collectDraft()"'+(f.placeholder?' placeholder="'+esc(f.placeholder)+'"':'')+'>';
  }).join('');
}

function toLocalInput(sec){
  if (!sec) return '';
  const d = new Date(Number(sec) * 1000);
  const p = (n)=>String(n).padStart(2,'0');
  return d.getFullYear()+'-'+p(d.getMonth()+1)+'-'+p(d.getDate())+'T'+p(d.getHours())+':'+p(d.getMinutes());
}
function fromLocalInput(v){
  if (!v) return 0;
  const t = Date.parse(v);
  return t ? Math.floor(t/1000) : 0;
}

function collectDraft(){
  const def = state.schema;
  const draft = Object.assign({}, state.draft);
  for (const f of def.fields){
    const el = $('#f_'+f.k);
    if (!el) continue;
    if (f.type==='checkbox') draft[f.k] = el.checked ? 1 : 0;
    else if (f.type==='number') draft[f.k] = Number(el.value);
    else if (f.type==='datetime-local') draft[f.k] = fromLocalInput(el.value);
    else draft[f.k] = el.value;
  }
  state.draft = draft;
}

async function saveModal(){
  collectDraft();
  const def = state.schema;
  const body = {};
  for (const f of def.fields){
    if (state.draft[f.k] !== undefined) body[f.k] = state.draft[f.k];
  }
  // \u51FA\u7AD9\uFF1A\u4EC5\u53D1\u9001\u5F53\u524D\u7C7B\u578B\u53EF\u89C1\u5B57\u6BB5\uFF1Bsocks5/http \u4E0D\u652F\u6301 UDP\uFF0C\u5F3A\u5236 udp=0
  if (def.api === 'outbounds'){
    const t = state.draft.type || 'socks5';
    const allowed = OUTBOUND_TYPE_FIELDS[t] || OUTBOUND_TYPE_FIELDS.socks5;
    for (const k of Object.keys(body)) if (allowed.indexOf(k) === -1) delete body[k];
    if (t === 'socks5' || t === 'http') body.udp = 0;
  }
  try {
    if (state.editing) await api('/admin/api/'+def.api+'/'+state.editing.id,{method:'PUT',body:JSON.stringify(body)});
    else await api('/admin/api/'+def.api,{method:'POST',body:JSON.stringify(body)});
    closeModal(); await loadList(); toast('\u5DF2\u4FDD\u5B58');
  } catch(e){ toast(e.message); }
}

async function delRow(idx){
  const def = state.schema; const r = state.records[idx];
  if (!confirm('\u786E\u8BA4\u5220\u9664\u8BE5\u8BB0\u5F55\uFF1F')) return;
  try { await api('/admin/api/'+def.api+'/'+r.id,{method:'DELETE'}); await loadList(); toast('\u5DF2\u5220\u9664'); }
  catch(e){ toast(e.message); }
}

function closeModal(){ $('#modalMask').classList.remove('show'); }

async function loadStats(){
  const mc = $('#mainContent');
  try {
    const d = await api('/admin/api/stats');
    mc.innerHTML = '<div class="page-title">\u6D41\u91CF\u7EDF\u8BA1</div>'+
      statBlock('VLESS \u7528\u6237', d.vless) + statBlock('Trojan \u7528\u6237', d.trojan);
  } catch(e){ mc.innerHTML = '<div class="page-title">\u6D41\u91CF\u7EDF\u8BA1</div><div class="card">\u52A0\u8F7D\u5931\u8D25: '+esc(e.message)+'</div>'; }
}
function statBlock(title, rows){
  const items = rows.map(r=>{
    const used = Number(r.used || 0);
    const remaining = r.remaining;
    const limit = Number(r.traffic_limit||0);
    let badge = '<span class="badge">\u4E0D\u9650\u6D41\u91CF</span>';
    if (r.expired) badge = '<span class="badge off">\u5DF2\u5230\u671F</span>';
    else if (r.limitReached) badge = '<span class="badge off">\u5DF2\u8D85\u9650</span>';
    else if (remaining!==null) badge = '<span class="badge on">\u5269\u4F59 '+fmtBytes(remaining)+'</span>';
    const expTxt = r.expire_at ? fmtDate(r.expire_at) : '\u6C38\u4E45';
    const quotaTxt = limit>0 ? (' / '+fmtBytes(limit)) : '';
    return '<div class="stat-item"><div class="num">'+fmtBytes(used)+'</div><div class="lbl">'+esc(r.remark||r.uuid||r.password)+'</div>'+
      '<div class="lbl" style="font-size:11px">\u2191 '+fmtBytes(r.up||0)+' \u2193 '+fmtBytes(r.down||0)+quotaTxt+'</div>'+
      '<div style="margin-top:6px">'+badge+'</div>'+
      '<div class="lbl" style="font-size:11px;margin-top:2px">\u5230\u671F '+expTxt+(r.traffic_reset_at? ' \xB7 \u91CD\u7F6E '+fmtDate(r.traffic_reset_at):'')+'</div></div>';
  }).join('');
  return '<h3 style="margin:16px 0 12px;font-size:18px">'+title+'</h3><div class="stat-grid">'+(items||'<div class="card">\u6682\u65E0\u6570\u636E</div>')+'</div>';
}
function fmtBytes(n){
  if (n < 1024) return n+' B';
  const units=['KB','MB','GB','TB'];
  let v=n, i=-1;
  do { v/=1024; i++; } while (v>=1024 && i<units.length-1);
  return v.toFixed(1)+' '+units[i];
}
function fmtDate(sec){
  if (!sec) return '';
  const d = new Date(Number(sec) * 1000);
  const p = (n)=>String(n).padStart(2,'0');
  return d.getFullYear()+'-'+p(d.getMonth()+1)+'-'+p(d.getDate())+' '+p(d.getHours())+':'+p(d.getMinutes());
}

async function loadSettings(){
  const mc = $('#mainContent');
  try {
    const [s, ver] = await Promise.all([
      api('/admin/api/settings'),
      api('/admin/api/version').catch(()=>({ version:'' }))
    ]);
    const fields = [
      ['ws_path','\u5165\u7AD9\u8DEF\u5F84\uFF08ws / grpc / h2 \u5171\u4EAB\uFF1B\u7528\u6237\u672A\u81EA\u5B9A\u4E49\u8DEF\u5F84\u65F6\u56DE\u9000\u5230\u6B64\u503C\uFF09'],
      ['default_outbound','\u9ED8\u8BA4\u51FA\u7AD9 (direct / \u51FA\u7AD9\u540D)'],
      ['proxyip','proxyip\uFF08\u4EE3\u7406 IP \u6216\u57DF\u540D[:\u7AEF\u53E3]\uFF0C\u8BBF\u95EE Cloudflare \u53CA\u5F00 CF CDN \u7F51\u7AD9\u4F7F\u7528\uFF1B\u4EC5\u9ED8\u8BA4\u51FA\u7AD9\u4E3A direct \u65F6\u751F\u6548\uFF09'],
      ['udp_outbound','UDP \u51FA\u7AD9\u4EE3\u7406\uFF08\u51FA\u7AD9\u540D\uFF0C\u4EC5 vless \u652F\u6301 UDP\uFF09'],
      ['disguise_title','\u4F2A\u88C5\u9875\u6807\u9898'],
      ['disguise_subtitle','\u4F2A\u88C5\u9875\u526F\u6807\u9898'],
    ];
    mc.innerHTML = '<div class="page-title">\u7CFB\u7EDF\u8BBE\u7F6E</div>'+
      '<div class="card" style="display:flex;align-items:center;justify-content:space-between;background:#f0f4ff;color:#2b5db3;font-size:13px;border-radius:10px;padding:10px 16px;margin-bottom:16px">'+
        '<span>\u7CFB\u7EDF\u7248\u672C</span><b id="sysVersion">'+(ver.version?esc(ver.version):'\u672A\u77E5')+'</b>'+
      '</div>'+
      '<div class="card" style="background:#e8f8ef;color:#1d7a3f;font-size:13px;border-radius:10px;padding:12px 16px;margin-bottom:16px">\u5165\u7AD9\u5DF2\u81EA\u52A8\u517C\u5BB9 ws / grpc / h2 \u4E09\u79CD\u4F20\u8F93\u7C7B\u578B\uFF08\u540C\u4E00\u51ED\u636E\u540C\u65F6\u53EF\u7528\uFF09\u3002\u6B64\u5904\u4EC5\u9700\u8BBE\u7F6E\u5171\u4EAB\u5165\u7AD9\u8DEF\u5F84\uFF1B\u5355\u4E2A\u7528\u6237\u53EF\u5728\u300CVLESS \u7528\u6237 / Trojan \u7528\u6237\u300D\u4E2D\u81EA\u5B9A\u4E49\u8DEF\u5F84\uFF0C\u7559\u7A7A\u5219\u4F7F\u7528\u672C\u5168\u5C40\u8DEF\u5F84\u3002</div>'+
      '<div class="card">'+
      fields.map(([k,label])=>'<label style="display:block;font-size:13px;color:var(--muted);margin:10px 0 4px">'+label+'</label><input id="s_'+k+'" value="'+esc(s[k]||'')+'" style="width:100%;padding:8px 12px;border:1px solid var(--border);border-radius:8px">').join('')+
      '<div style="margin-top:16px"><button class="btn small" onclick="saveSettings()">\u4FDD\u5B58\u8BBE\u7F6E</button> <button class="btn small" onclick="updateGeo()">\u66F4\u65B0 Geo \u89C4\u5219\u5E93</button> <button class="btn small" onclick="testProxyIp()">proxyip \u6D4B\u8BD5</button> <button class="btn small" onclick="testUdp()">UDP \u6D4B\u8BD5</button></div>'+
      '<div id="testResult" style="margin-top:12px;font-size:13px;line-height:1.8"></div></div>';
    state.settings = s;
  } catch(e){ mc.innerHTML = '<div class="page-title">\u7CFB\u7EDF\u8BBE\u7F6E</div><div class="card">\u52A0\u8F7D\u5931\u8D25: '+esc(e.message)+'</div>'; }
}

async function saveSettings(){
  const body = {};
  document.querySelectorAll('#mainContent input[id^=s_]').forEach(el=>{ body[el.id.slice(2)] = el.value; });
  try { await api('/admin/api/settings',{method:'PUT',body:JSON.stringify(body)}); toast('\u8BBE\u7F6E\u5DF2\u4FDD\u5B58'); }
  catch(e){ toast(e.message); }
}

async function loadEntry(){
  const mc = $('#mainContent');
  try {
    const s = await api('/admin/api/settings');
    const fields = [
      ['entry_host','\u5165\u53E3 IP / \u57DF\u540D'],
      ['entry_port','\u5165\u53E3\u7AEF\u53E3\uFF08\u9ED8\u8BA4 443\uFF09'],
      ['entry_sni','\u5165\u53E3 SNI'],
      ['entry_ws_host','\u5165\u53E3 Host\uFF08Host \u5934\uFF09'],
    ];
    mc.innerHTML = '<div class="page-title">\u5165\u53E3\u8BBE\u7F6E</div>'+
      '<div class="card" style="background:#e8f8ef;color:#1d7a3f;font-size:13px;border-radius:10px;padding:12px 16px;margin-bottom:16px">\u5165\u7AD9\u5DF2\u81EA\u52A8\u652F\u6301 ws / grpc / h2 \u5168\u7C7B\u578B\u4F20\u8F93\uFF08\u540C\u4E00\u51ED\u636E\u81EA\u52A8\u5206\u53D1\uFF09\uFF0C\u65E0\u9700\u518D\u9009\u62E9\u4F20\u8F93\u6A21\u5F0F\u3002\u8BBE\u7F6E\u5165\u53E3\u540E\uFF0C\u8282\u70B9/\u8BA2\u9605\u5C06\u4F7F\u7528\u5165\u53E3 IP/\u57DF\u540D\u3001\u7AEF\u53E3\u3001SNI\u3001Host \u751F\u6210\u914D\u7F6E\uFF08\u4E0D\u518D\u4F7F\u7528\u5F53\u524D\u57DF\u540D\uFF09\uFF1B\u672A\u8BBE\u7F6E\u5219\u4F7F\u7528\u5F53\u524D\u57DF\u540D\u3002</div>'+
      '<div class="card">'+
      fields.map(([k,label])=>{
        return '<label style="display:block;font-size:13px;color:var(--muted);margin:10px 0 4px">'+label+'</label><input id="s_'+k+'" value="'+esc(s[k]||'')+'" style="width:100%;padding:8px 12px;border:1px solid var(--border);border-radius:8px" placeholder="'+(k==='entry_port'?'443':'')+'">';
      }).join('')+
      '<div style="margin-top:16px"><button class="btn small" onclick="saveEntry()">\u4FDD\u5B58\u5165\u53E3\u8BBE\u7F6E</button></div></div>';
  } catch(e){ mc.innerHTML = '<div class="page-title">\u5165\u53E3\u8BBE\u7F6E</div><div class="card">\u52A0\u8F7D\u5931\u8D25: '+esc(e.message)+'</div>'; }
}

async function saveEntry(){
  const body = {};
  document.querySelectorAll('#mainContent input[id^=s_], #mainContent select[id^=s_]').forEach(el=>{ body[el.id.slice(2)] = el.value; });
  try { await api('/admin/api/settings',{method:'PUT',body:JSON.stringify(body)}); toast('\u5165\u53E3\u8BBE\u7F6E\u5DF2\u4FDD\u5B58'); }
  catch(e){ toast(e.message); }
}

async function updateGeo(){
  const m = $('#geoModal'); if (!m) return;
  m.classList.add('show');
  const fill = $('#geoBarFill'), line1 = $('#geoLine1'), line2 = $('#geoLine2'), line3 = $('#geoLine3'), sub = $('#geoSub');
  fill.style.width = '0%';
  sub.textContent = '\u6B63\u5728\u51C6\u5907\u2026';
  line1.innerHTML = '\u63D0\u4EA4\u66F4\u65B0\u8BF7\u6C42\u2026'; line2.innerHTML = ''; line3.innerHTML = '';
  try {
    const d = await api('/admin/api/geo/update',{method:'POST',body:'{}'});
    if (d && d.updating) {
      line1.innerHTML = '\u66F4\u65B0\u5DF2\u542F\u52A8\uFF0C\u6B63\u5728\u62C9\u53D6\u89C4\u5219\u5E93\uFF08\u7EA6 1-3 \u5206\u949F\uFF09\u2026';
      pollGeoStatus();
    } else if (d && (d.updated!==undefined)) {
      finishGeo({ state:'done', updated:d.updated, total:d.total, failed:d.failed||[] });
    } else {
      line1.innerHTML = '\u670D\u52A1\u8FD4\u56DE\u5F02\u5E38\uFF0C\u8BF7\u7A0D\u540E\u91CD\u8BD5';
    }
  } catch(e){ failGeo({ message: e.message }); }
}
function closeGeoModal(){ const m = $('#geoModal'); if (m) m.classList.remove('show'); }
function finishGeo(p){
  const line1 = $('#geoLine1'), line2 = $('#geoLine2'), line3 = $('#geoLine3'), sub = $('#geoSub'), fill = $('#geoBarFill');
  fill.style.width = '100%';
  line1.innerHTML = ''; line2.innerHTML = '';
  line3.innerHTML = '<span class="geo-done ok">\u66F4\u65B0\u5B8C\u6210\uFF1A\u6210\u529F '+p.updated+' / '+p.total+' \u4E2A\u5206\u7C7B'+(p.failed && p.failed.length ? '\uFF0C\u5931\u8D25 '+p.failed.length+' \u4E2A' : '')+'</span>';
  if (p.failed && p.failed.length) line3.innerHTML += '<div class="dim" style="font-size:12px">\u5931\u8D25\u9879\uFF1A'+esc(p.failed.slice(0,8).join('\u3001'))+'</div>';
  sub.textContent = '\u7248\u672C\u65F6\u95F4\uFF1A'+new Date().toLocaleString();
}
function failGeo(p){
  const line1 = $('#geoLine1'), line2 = $('#geoLine2'), line3 = $('#geoLine3'), fill = $('#geoBarFill');
  fill.style.width = '100%';
  line1.innerHTML = '<span class="geo-done err">\u66F4\u65B0\u5931\u8D25\uFF1A'+esc(p.message||'\u672A\u77E5\u9519\u8BEF')+'</span>';
  line2.innerHTML = ''; line3.innerHTML = '';
}
async function pollGeoStatus(){
  const line1 = $('#geoLine1'), line2 = $('#geoLine2'), line3 = $('#geoLine3'), fill = $('#geoBarFill');
  const started = Date.now();
  let idleStart = null;
  while (Date.now() - started < 360000) {
    let st = null;
    try { st = await api('/admin/api/geo/status'); } catch(e){ /* \u7EE7\u7EED\u8F6E\u8BE2 */ }
    if (st) {
      const p = st.status || {};
      if (st.updating) {
        const step = p.step || 0, total = p.total || 0;
        const pct = total > 0 ? Math.min(100, Math.round(step/total*100)) : 2;
        fill.style.width = pct + '%';
        line1.innerHTML = esc(p.message || '\u66F4\u65B0\u4E2D\u2026');
        line2.innerHTML = '\u8FDB\u5EA6\uFF1A<b>'+step+'</b> / '+total+'\uFF08\u6210\u529F '+(p.updated||0)+'\uFF0C\u5931\u8D25 '+((p.failed||[]).length)+'\uFF09';
        line3.innerHTML = p.current ? '\u5F53\u524D\uFF1A<span class="dim">'+esc(p.current)+'</span>' : '';
        // \u5DF2\u5165\u961F\u4F46\u957F\u65F6\u95F4\u65E0\u8FDB\u5C55\uFF1A\u63D0\u793A\u6D88\u8D39\u8005\u53EF\u80FD\u672A\u751F\u6548\uFF08\u961F\u5217\u672A\u521B\u5EFA / consumer \u672A\u7ED1\u5B9A / \u7C98\u8D34\u90E8\u7F72\u65E0\u961F\u5217\uFF09
        if (step === 0 && p.message === '\u5DF2\u5165\u961F\uFF0C\u7B49\u5F85\u6D88\u8D39\u8005\u6267\u884C\u2026') {
          if (idleStart === null) idleStart = Date.now();
          if (Date.now() - idleStart > 30000) {
            line3.innerHTML = '<span class="geo-done err">\u961F\u5217\u6D88\u8D39\u8005\u672A\u751F\u6548\uFF1A\u8BF7\u786E\u8BA4\u5DF2\u521B\u5EFA\u961F\u5217\uFF08wrangler queue create cf-vless-trojan-d1-geo-update / -dlq\uFF09\u4E14 wrangler.toml \u5DF2\u914D\u7F6E producer/consumer\uFF1B\u63A7\u5236\u53F0\u7C98\u8D34\u90E8\u7F72\u4E0D\u652F\u6301\u961F\u5217\uFF0C\u8BF7\u6539\u7528 wrangler deploy</span>';
          }
        } else {
          idleStart = null;
        }
      } else if (p.state==='done') {
        finishGeo(p);
        return;
      } else if (p.state==='error') {
        failGeo(p);
        return;
      } else if (!st.updating && st.version) {
        finishGeo({ state:'done', updated:p.updated||0, total:p.total||0, failed:p.failed||[] });
        return;
      }
    }
    await new Promise(r=>setTimeout(r,1500));
  }
  line1.innerHTML = '\u8F6E\u8BE2\u8D85\u65F6\uFF0C\u8BF7\u7A0D\u540E\u5237\u65B0\u9875\u9762\u67E5\u770B geo:version \u662F\u5426\u66F4\u65B0';
}

// ---- \u7F51\u7EDC\u72B6\u6001\uFF1AWorker \u63A2\u6D4B + \u524D\u7AEF\u6E32\u67D3\uFF08ip.skk.moe \u98CE\u683C\uFF09 ----
const SCAN_TARGETS = [
  {name:'\u5B57\u8282\u8DF3\u52A8',icon:'\u{1F3B5}',color:'#325AB4'},{name:'Bilibili',icon:'\u{1F4FA}',color:'#FB7299'},
  {name:'\u5FAE\u4FE1',icon:'\u{1F4AC}',color:'#07C160'},{name:'\u6DD8\u5B9D',icon:'\u{1F6D2}',color:'#FF5000'},
  {name:'GitHub',icon:'\u{1F419}',color:'#24292F'},{name:'jsDelivr',icon:'\u{1F4E6}',color:'#E84D0E'},
  {name:'Cloudflare',icon:'\u2601\uFE0F',color:'#F6821F'},{name:'Google',icon:'\u{1F50D}',color:'#4285F4'},
  {name:'YouTube',icon:'\u25B6\uFE0F',color:'#FF0000'}
];
let netTimer = null;
function setNetTimer(){ netTimer = setTimeout(scheduleNetAuto, 60000); }
function clearNetAuto(){ if (netTimer){ clearTimeout(netTimer); netTimer = null; } }
function scheduleNetAuto(){
  clearNetAuto();
  const cb = $('#netAuto'); if (!cb) return;
  if (cb.checked) setNetTimer();
}
async function runNetstatus(){
  const grid = $('#netGrid');
  if (!grid) return;
  renderScanCards(grid);
  try {
    const d = await api('/admin/api/netstatus/test',{method:'POST',body:'{}'});
    renderNetCards(grid, d.targets || []);
    const t = $('#netUpdateTime'); if (t) t.textContent = '\u66F4\u65B0\u4E8E ' + new Date(d.ts||Date.now()).toLocaleTimeString();
  } catch(e){ grid.innerHTML = '<div class="card" style="grid-column:1/-1">\u68C0\u6D4B\u5931\u8D25: '+esc(e.message)+'</div>'; }
  scheduleNetAuto();
}
function renderScanCards(grid){
  grid.innerHTML = SCAN_TARGETS.map(t=>{
    const dots = Array(16).fill('<span class="net-dot scan-dot"></span>').join('');
    return '<div class="net-card"><div class="net-head"><span class="net-logo" style="background:'+esc(t.color)+'">'+esc(t.icon)+'</span><span class="net-name">'+esc(t.name)+'</span></div><div class="net-status-line"><span class="net-pulse"></span><div class="net-latency scan"></div></div><div class="net-meta scan"></div><div class="net-dots">'+dots+'</div></div>';
  }).join('');
}
function renderNetCards(grid, targets){
  grid.innerHTML = targets.map(t=>{
    const region = t.region==='cn' ? '<span class="badge">\u56FD\u5185</span>' : '<span class="badge on">\u56FD\u9645</span>';
    const color = t.color || '#34c759';
    const okN = t.success||0, tot = t.total||0;
    const loss = (t.loss===null || t.loss===undefined) ? (tot>0 ? Math.round((tot-okN)/tot*100) : 100) : t.loss;
    const cls = loss>50 ? 'bad-state' : (loss>10 ? 'warn-state' : '');
    let statusHtml;
    if (t.latency===null || t.latency===undefined){
      statusHtml = '<div class="net-status-line"><span class="net-pulse fail"></span><div class="net-latency fail">\u8D85\u65F6 / \u5931\u8D25</div></div>';
    } else if (t.latency>=1500){
      statusHtml = '<div class="net-status-line"><span class="net-pulse slow"></span><div class="net-latency">'+t.latency+'<span class="unit">ms</span></div></div>';
    } else {
      statusHtml = '<div class="net-status-line"><span class="net-pulse good"></span><div class="net-latency">'+t.latency+'<span class="unit">ms</span></div></div>';
    }
    const minV = (t.min===null || t.min===undefined) ? '\u2014' : t.min;
    const maxV = (t.max===null || t.max===undefined) ? '\u2014' : t.max;
    const dots = (t.samples||[]).map(s=>dotCls(s)).join('');
    return '<div class="net-card '+cls+'" style="--nc:'+color+'"><div class="net-head"><span class="net-logo" style="background:'+color+'">'+esc(t.icon||'')+'</span><span class="net-name">'+esc(t.name||t.host||'')+'</span>'+region+'</div>'+statusHtml+'<div class="net-meta"><span>\u4E22\u5305 <b>'+loss+'%</b></span><span>min <b>'+minV+'</b></span><span>max <b>'+maxV+'</b></span></div><div class="net-dots">'+dots+'</div><div class="net-foot"><span>'+(t.success||0)+'/'+(t.total||0)+' \u6210\u529F</span><span class="mono">'+esc(t.host||'')+'</span></div></div>';
  }).join('');
}
function dotCls(ms){
  if (ms===null || ms===undefined) return '<span class="net-dot"></span>';
  if (ms < 200) return '<span class="net-dot ok"></span>';
  if (ms < 500) return '<span class="net-dot warn"></span>';
  return '<span class="net-dot bad"></span>';
}

// ---- \u7CFB\u7EDF\u8BBE\u7F6E\uFF1Aproxyip / UDP \u6D4B\u8BD5 ----
async function testProxyIp(){
  const el = $('#testResult'); if (!el) return;
  el.innerHTML = 'proxyip \u6D4B\u8BD5\u4E2D\u2026\uFF08\u8FDE\u63A5 proxyip \u88F8 TCP \u63A2\u6D4B Cloudflare \u7AD9\u70B9\uFF09';
  try {
    const r = await api('/admin/api/test/proxyip',{method:'POST',body:'{}'});
    el.innerHTML = r.ok
      ? '<span style="color:#34c759">proxyip \u53EF\u7528\uFF0C\u5EF6\u8FDF '+r.latency+' ms</span>\uFF08'+esc(r.endpoint||'')+'\uFF09'
      : '<span style="color:var(--danger)">proxyip \u4E0D\u53EF\u7528\uFF1A'+esc(r.error||'')+'</span>';
  } catch(e){ el.innerHTML = '<span style="color:var(--danger)">proxyip \u6D4B\u8BD5\u5931\u8D25\uFF1A'+esc(e.message)+'</span>'; }
}
async function testUdp(){
  const el = $('#testResult'); if (!el) return;
  el.innerHTML = 'UDP \u6D4B\u8BD5\u4E2D\u2026\uFF08\u7ECF UDP \u51FA\u7AD9\u5411 8.8.8.8:53 \u53D1\u8D77 DNS \u67E5\u8BE2\uFF09';
  try {
    const r = await api('/admin/api/test/udp',{method:'POST',body:'{}'});
    el.innerHTML = r.ok
      ? '<span style="color:#34c759">UDP \u53EF\u7528\uFF0C\u5EF6\u8FDF '+r.latency+' ms</span>'
      : '<span style="color:var(--danger)">UDP \u4E0D\u53EF\u7528\uFF1A'+esc(r.error||'')+'</span>';
  } catch(e){ el.innerHTML = '<span style="color:var(--danger)">UDP \u6D4B\u8BD5\u5931\u8D25\uFF1A'+esc(e.message)+'</span>'; }
}

// ---- \u51FA\u7AD9\u4EE3\u7406\u6D4B\u8BD5 ----
async function testOutbound(idx, ev){
  const r = state.records[idx];
  const btn = ev && ev.target;
  if (btn){ btn.disabled = true; btn.textContent = '\u6D4B\u8BD5\u4E2D\u2026'; }
  try {
    const res = await api('/admin/api/test/outbound/'+r.id,{method:'POST',body:'{}'});
    toast(res.ok ? ('\u51FA\u7AD9\u53EF\u7528\uFF0C\u5EF6\u8FDF '+res.latency+' ms') : ('\u51FA\u7AD9\u4E0D\u53EF\u7528\uFF1A'+(res.error||'\u672A\u77E5\u9519\u8BEF')));
  } catch(e){ toast('\u51FA\u7AD9\u6D4B\u8BD5\u5931\u8D25\uFF1A'+e.message); }
  if (btn){ btn.disabled = false; btn.textContent = '\u6D4B\u8BD5'; }
}

// \u521D\u59CB\uFF1A\u68C0\u67E5\u767B\u5F55\u6001
(async function init(){
  try { await api('/admin/api/settings'); showApp(); }
  catch(e){ showLogin(); }
})();
<\/script>
</body>
</html>`}async function On(t,e){let n=new URL(t.url);if(t.method==="POST"||t.method==="GET")try{let{DB:a,GEO_KV:r}=e,s=await Te(a,r);return new Response(JSON.stringify({ok:!0,updated:s.updated,total:s.total,failed:s.failed}),{status:200,headers:{"Content-Type":"application/json; charset=utf-8"}})}catch(a){return new Response(JSON.stringify({ok:!1,error:a.message}),{status:500,headers:{"Content-Type":"application/json; charset=utf-8"}})}return new Response("Not Found",{status:404})}async function Rn(t,e,n){try{let a=await Te(e.DB,e.GEO_KV);console.log(`[cron] geo update done: ${a.updated}/${a.total} categories${a.failed.length?", failed: "+a.failed.join("; "):""}`)}catch(a){console.log(`[cron] geo update failed: ${a.message}`)}}globalThis.connect=ba;function va(t){let e=new Set,n=new Set;for(let a of t){if(a.kind==="all")return{all:!0,vless:e,trojan:n};a.kind==="vless"&&a.credential&&e.add(a.credential),a.kind==="trojan"&&a.credential&&n.add(a.credential)}return{all:!1,vless:e,trojan:n}}var Zs={async fetch(t,e,n){let r=new URL(t.url).pathname;try{if(r.startsWith("/admin")){let c=await De(t,e,{ensureAdmin:!0});return r.startsWith("/admin/api/")?await $n(t,c,n):new Response(Dn(c.adminTempPassword),{headers:{"Content-Type":"text/html; charset=utf-8","Cache-Control":"no-store"}})}if(r==="/geo-update-cron")return await On(t,e);let s=await De(t,e),o=s.inboundPathMap.get(r);if(o&&o.length>0){s._inboundScope=va(o);let c=String(t.headers.get("Upgrade")||"").toLowerCase(),l=String(t.headers.get("Content-Type")||"").toLowerCase(),i=r.endsWith("/Tun")||l.includes("application/grpc");if(c==="websocket"&&!i)return await Zt(t,s,e);if(i)return await Qt(t,s,e);if(t.method==="POST")return await Xt(t,s,e)}return await on(t,s,e)}catch(s){return console.log(`[index] error: ${s.message||s}`),new Response(JSON.stringify({error:"internal error"}),{status:500,headers:{"Content-Type":"application/json; charset=utf-8"}})}},async scheduled(t,e,n){return Rn(t,e,n)},async queue(t,e,n){for(let a of t.messages)try{let r=await xe(e.DB,e.GEO_KV);console.log(`[queue] geo update done: ${r.updated}/${r.total} categories${r.failed.length?", failed: "+r.failed.join("; "):""}`),a.ack()}catch(r){throw console.log(`[queue] geo update failed (will retry): ${r.message||r}`),r}}};export{Zs as default};
