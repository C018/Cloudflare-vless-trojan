import{connect as nr}from"cloudflare:sockets";var _="direct",I="reject",se="socks5",ae="http",oe="vless",ie=["raw","ws","grpc","httpupgrade"],ce="ws",le="geosite:",de="geoip:";var D="vtd_admin";var ue="/ws";var pe=["qq.com","taobao.com","tmall.com","jd.com","baidu.com","bilibili.com","douyin.com","weibo.com","zhihu.com","163.com","126.com","aliyun.com","tencent.com","weixin.qq.com","alipay.com","bankofchina.com","icbc.com.cn","ccb.com","abcchina.com","cmbchina.com","boc.cn","12306.cn","gov.cn","cn","com.cn","net.cn","org.cn"],fe=["speedtest.net","fast.com","ookla.com"],he=["google.com","googleapis.com","gstatic.com","googleusercontent.com","ggpht.com","google.cn","google.com.hk","gvt1.com","gvt2.com","gvt3.com"],G=[];for(let e=0;e<=255;++e){let t=e.toString(16).padStart(2,"0");G.push(t)}var z=1e5;function K(e){return Array.from(new Uint8Array(e)).map(t=>t.toString(16).padStart(2,"0")).join("")}function ht(){let e=new Uint8Array(16);return crypto.getRandomValues(e),K(e)}async function me(e,t,r){let s=await crypto.subtle.importKey("raw",new TextEncoder().encode(e),"PBKDF2",!1,["deriveBits"]),n=await crypto.subtle.deriveBits({name:"PBKDF2",salt:new TextEncoder().encode(t),iterations:r,hash:"SHA-256"},s,256);return K(n)}async function be(e){let t=ht(),r=await me(e,t,z);return`${t}:${z}:${r}`}async function we(e,t){if(!t||!e)return!1;let r=String(t).split(":");if(r.length!==3)return!1;let[s,n,a]=r,o=parseInt(n,10)||z;return await me(e,s,o)===a}async function ye(e,t){let r=await crypto.subtle.importKey("raw",new TextEncoder().encode(e),{name:"HMAC",hash:"SHA-256"},!1,["sign"]),s=await crypto.subtle.sign("HMAC",r,new TextEncoder().encode(t));return K(s)}async function ge(e){let r=`admin.${Math.floor(Date.now()/1e3)+604800}`,s=await ye(e,r);return`${r}.${s}`}async function xe(e,t){if(!e||!t)return!1;let r=String(e).split(".");if(r.length!==3)return!1;let[s,n,a]=r;if(s!=="admin")return!1;let o=Number(n);if(!Number.isFinite(o)||o<Date.now()/1e3)return!1;let i=await ye(t,`${s}.${n}`);if(i.length!==a.length)return!1;let d=0;for(let c=0;c<i.length;c++)d|=i.charCodeAt(c)^a.charCodeAt(c);return d===0}function ve(e){let t={};if(!e)return t;for(let r of e.split(";")){let s=r.indexOf("=");if(s<0)continue;let n=r.slice(0,s).trim(),a=r.slice(s+1).trim();t[n]=decodeURIComponent(a)}return t}async function mt(e){try{let{results:t}=await e.prepare("SELECT key, value FROM settings").all(),r={};for(let s of t||[])r[s.key]=s.value;return r}catch{return{}}}async function bt(e){try{let{results:t}=await e.prepare("SELECT id, uuid, remark, up, down FROM vless_users WHERE enable = 1 ORDER BY id").all();return t||[]}catch{return[]}}async function wt(e){try{let{results:t}=await e.prepare("SELECT id, password, remark, up, down FROM trojan_users WHERE enable = 1 ORDER BY id").all();return t||[]}catch{return[]}}async function yt(e){try{let{results:t}=await e.prepare("SELECT * FROM outbounds WHERE enable = 1 ORDER BY sort ASC, id ASC").all();return t||[]}catch{return[]}}async function gt(e){try{let{results:t}=await e.prepare("SELECT * FROM routing_rules WHERE enable = 1 ORDER BY sort ASC, id ASC").all();return t||[]}catch{return[]}}async function xt(e){try{let s=await e.prepare("SELECT value FROM settings WHERE key = ?").bind("admin_password_hash").first();if(s&&s.value)return{hash:s.value,tempPassword:null}}catch{}let t=vt().replace(/-/g,"").slice(0,12),r=await be(t);try{await e.prepare("INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at").bind("admin_password_hash",r,Date.now()).run()}catch{}return{hash:r,tempPassword:t}}async function Y(e,t,r={}){let{DB:s}=t,n=await mt(s),a=n.ws_path||ue,o=n.default_outbound||_,i=n.admin_password_hash||"",d=null;if(!i&&r.ensureAdmin){let E=await xt(s);i=E.hash,d=E.tempPassword}let c=n.proxyip||"",l="",p=443;if(c){let E=c.lastIndexOf(":");E>0&&!c.includes("]")&&/^\d+$/.test(c.slice(E+1))?(l=c.slice(0,E),p=Number(c.slice(E+1))||443):l=c}let f=n.udp_outbound||"",b=n.entry_host||"",m=n.entry_port||"",h=n.entry_sni||"",u=n.entry_ws_host||"",w=await bt(s),g=await wt(s),y=await yt(s),v=await gt(s),T={};for(let E of w)T[E.uuid]=E;let S={};for(let E of g)S[E.password]=E;return{env:t,settings:n,wsPath:a,defaultOutbound:o,adminPasswordHash:i,adminTempPassword:d,proxyipHost:l,proxyipPort:p,proxyipDisabled:o!==_,udpOutbound:f,entryHost:b,entryPort:m,entrySni:h,entryWsHost:u,vlessUsers:w,trojanUsers:g,outbounds:y,routingRules:v,vlessIndex:T,trojanIndex:S,uuidSet:new Set(w.map(E=>E.uuid)),passwordSet:new Set(g.map(E=>E.password)),outboundByName:y.reduce((E,U)=>(E[U.name]=U,E),{})}}function vt(){return globalThis.crypto&&typeof globalThis.crypto.randomUUID=="function"?globalThis.crypto.randomUUID():"xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(/[xy]/g,e=>{let t=Math.random()*16|0;return(e==="x"?t:t&3|8).toString(16)})}function Tt(e){let t=r=>G[e[r]];return`${t(0)}${t(1)}${t(2)}${t(3)}-${t(4)}${t(5)}-${t(6)}${t(7)}-${t(8)}${t(9)}-${t(10)}${t(11)}${t(12)}${t(13)}${t(14)}${t(15)}`.toLowerCase()}function Te(e,t){if(e.byteLength<24)return{hasError:!0,message:"invalid data"};let r=new DataView(e),s=r.getUint8(0),n=Tt(new Uint8Array(e.slice(1,17)));if(!t.has(n))return{hasError:!0,message:"invalid user"};let o=18+r.getUint8(17);if(e.byteLength<o+4)return{hasError:!0,message:"invalid data"};let i=r.getUint8(o);if(i!==1&&i!==2)return{hasError:!0,message:`command ${i} is not supported`};let d=o+1,c=r.getUint16(d),l=r.getUint8(d+2),p,f,b;switch(l){case 1:f=4,b=d+3,p=Array.from(new Uint8Array(e.slice(b,b+f))).join(".");break;case 2:if(e.byteLength<d+4)return{hasError:!0,message:"invalid data"};f=r.getUint8(d+3),b=d+4,p=new TextDecoder().decode(e.slice(b,b+f));break;case 3:f=16,b=d+3,p=Array.from({length:8},(m,h)=>r.getUint16(b+h*2).toString(16)).join(":");break;default:return{hasError:!0,message:`invalid addressType: ${l}`}}return p?{hasError:!1,userUuid:n,addressRemote:p,addressType:l,portRemote:c,rawDataIndex:b+f,protocolVersion:new Uint8Array([s]),isUDP:i===2}:{hasError:!0,message:"addressValue is empty"}}function Ee(e,t,r,s,n){let a,o,i=[];switch(t){case 1:a=4,i=r.split(".").map(Number);break;case 2:o=new TextEncoder().encode(r),a=o.length+1;break;case 3:a=16,i=Et(r).split(":").map(l=>[parseInt(l.slice(0,2),16),parseInt(l.slice(2),16)]).flat();break;default:throw new Error(`Unknown address type: ${t}`)}let d=n.replace(/-/g,""),c=new Uint8Array(22+a);c[0]=0;for(let l=0;l<d.length;l+=2)c[1+l/2]=parseInt(d.substr(l,2),16);return c[17]=0,c[18]=e,c[19]=s>>8,c[20]=s&255,c[21]=t,t===2?(c[22]=o.length,c.set(o,23)):c.set(i,22),c}function Et(e){if(e=e.replace(/^\[|\]$/g,""),e.includes("::")){let t=e.split("::"),r=t[0]?t[0].split(":"):[],s=t[1]?t[1].split(":"):[],n=8-r.length-s.length,a=Array(Math.max(0,n)).fill("0");return[...r,...a,...s].map(o=>o.padStart(4,"0")).join(":")}return e.split(":").map(t=>t.padStart(4,"0")).join(":")}async function kt(e){let t=new TextEncoder().encode(e),r=await crypto.subtle.digest({name:"SHA-224"},t);return Array.from(new Uint8Array(r)).map(s=>s.toString(16).padStart(2,"0")).join("")}function ke(e){if(e.byteLength<60)return!1;let t=new Uint8Array(e);return t[56]===13&&t[57]===10}async function Se(e,t){if(e.byteLength<60)return{hasError:!0,message:"Invalid Trojan data: too short"};let r=new Uint8Array(e),s=new DataView(e);if(r[56]!==13||r[57]!==10)return{hasError:!0,message:"Invalid Trojan header: missing CRLF"};let n=new TextDecoder().decode(r.slice(0,56)),a=null;for(let m of t)try{if(await kt(m)===n){a=m;break}}catch{}if(!a)return{hasError:!0,message:"Invalid Trojan password"};let o=r[58];if(o!==1&&o!==3)return{hasError:!0,message:`Unsupported Trojan command: ${o}`};let i=r[59],d,c,l;switch(i){case 1:if(c=4,l=60,e.byteLength<l+c+2)return{hasError:!0,message:"Invalid Trojan header: IPv4 truncated"};d=Array.from(r.slice(l,l+c)).join(".");break;case 3:if(c=r[60],l=61,e.byteLength<l+c+2)return{hasError:!0,message:"Invalid Trojan header: domain truncated"};d=new TextDecoder().decode(r.slice(l,l+c));break;case 4:if(c=16,l=60,e.byteLength<l+c+2)return{hasError:!0,message:"Invalid Trojan header: IPv6 truncated"};d=Array.from({length:8},(m,h)=>s.getUint16(l+h*2).toString(16)).join(":");break;default:return{hasError:!0,message:`Invalid Trojan address type: ${i}`}}let p=l+c;if(e.byteLength<p+2)return{hasError:!0,message:"Invalid Trojan header: port truncated"};let f=s.getUint16(p),b=p+2;return e.byteLength<b+2?{hasError:!0,message:"Invalid Trojan header: missing final CRLF"}:r[b]!==13||r[b+1]!==10?{hasError:!0,message:"Invalid Trojan header: invalid final CRLF"}:{hasError:!1,userPassword:a,addressRemote:d,addressType:i===3?2:i,portRemote:f,rawDataIndex:b+2,isUDP:o===3}}function k(e){try{e&&e.readyState===1&&e.close()}catch{}}async function _e(e,t){let r=e.sni&&e.sni!==""?e.sni:e.address,s=Number(e.port),n;try{n=globalThis.connect?globalThis.connect({hostname:r,port:s,secureTransport:e.tls?"on":"off"}):void 0}catch(c){return t(`[VLESS/raw] connect error: ${c.message}`),null}if(!n)return t("[VLESS/raw] connect unavailable"),null;let a=n.readable.getReader(),o,i=new Promise(c=>{o=c});return(n.closed||Promise.resolve()).then(o,o),{readable:new ReadableStream({start(c){(async()=>{try{for(;;){let{done:l,value:p}=await a.read();if(l)break;p&&p.byteLength>0&&c.enqueue(p)}try{c.close()}catch{}}catch(l){try{c.error(l)}catch{}}})()},cancel(){try{a.cancel()}catch{}}}),writable:n.writable,closed:i,send:async c=>{let l=n.writable.getWriter();try{await l.write(c)}finally{try{l.releaseLock()}catch{}}}}}function St(e,t){let r=new Uint8Array(e.length+t.length);return r.set(e,0),r.set(t,e.length),r}function _t(e){for(let t=0;t+3<e.length;t++)if(e[t]===13&&e[t+1]===10&&e[t+2]===13&&e[t+3]===10)return t;return-1}function Lt(e){for(let t=0;t+1<e.length;t++)if(e[t]===13&&e[t+1]===10)return new TextDecoder().decode(e.slice(0,t));return""}async function Le(e,t){let r=e.sni&&e.sni!==""?e.sni:e.address,s=Number(e.port),n;try{n=globalThis.connect?globalThis.connect({hostname:r,port:s,secureTransport:e.tls?"on":"off"}):void 0}catch(m){return t(`[VLESS/httpupgrade] connect error: ${m.message}`),null}if(!n)return t("[VLESS/httpupgrade] connect unavailable"),null;let o=`GET ${e.path&&e.path.startsWith("/")?e.path:`/${e.path||""}`} HTTP/1.1\r
Host: ${r}:${s}\r
Connection: Upgrade\r
Upgrade: websocket\r
\r
`,i=n.readable.getReader(),d,c=new Promise(m=>{d=m});(n.closed||Promise.resolve()).then(d,d);let l=new Uint8Array(0),p=new Uint8Array(0);try{await Promise.race([(async()=>{let m=n.writable.getWriter();try{await m.write(new TextEncoder().encode(o))}finally{try{m.releaseLock()}catch{}}for(;;){let{done:h,value:u}=await i.read();if(h)break;if(u&&u.byteLength>0){l=St(l,u);let w=_t(l);if(w>=0){p=l.slice(w+4);return}}}throw new Error("connection closed during handshake")})(),new Promise((m,h)=>setTimeout(()=>h(new Error("Handshake timeout")),1e4))])}catch(m){t(`[VLESS/httpupgrade] handshake failed: ${m.message}`);try{n.close()}catch{}return null}let f=Lt(l);if(!/^HTTP\/1\.1 101/.test(f)){t(`[VLESS/httpupgrade] upgrade rejected: ${f}`);try{n.close()}catch{}return null}return{readable:new ReadableStream({start(m){p.byteLength>0&&m.enqueue(p),(async()=>{try{for(;;){let{done:h,value:u}=await i.read();if(h)break;u&&u.byteLength>0&&m.enqueue(u)}try{m.close()}catch{}}catch(h){try{m.error(h)}catch{}}})()},cancel(){try{i.cancel()}catch{}}}),writable:n.writable,closed:c,send:async m=>{let h=n.writable.getWriter();try{await h.write(m)}finally{try{h.releaseLock()}catch{}}}}}var At=`PRI * HTTP/2.0\r
\r
SM\r
\r
`;var J=new TextEncoder;function Ut(e,t){let r=J.encode(e),s=J.encode(t),n=new Uint8Array(2+r.length+1+s.length);return n[0]=0,n[1]=r.length,n.set(r,2),n[2+r.length]=s.length,n.set(s,3+r.length),n}function Ot(e){let t=new Uint8Array(0);for(let[r,s]of e)t=R(t,Ut(r,s));return t}function A(e,t,r,s){let n=s.length,a=new Uint8Array(9+n);return a[0]=n>>16&255,a[1]=n>>8&255,a[2]=n&255,a[3]=e,a[4]=t,a[5]=r>>24&127,a[6]=r>>16&255,a[7]=r>>8&255,a[8]=r&255,a.set(s,9),a}function Ae(e){let t=new Uint8Array(5+e.length);return t[0]=0,new DataView(t.buffer,t.byteOffset,5).setUint32(1,e.length,!1),t.set(e,5),t}function Ue(e){let t=new Uint8Array(4);return new DataView(t.buffer).setUint32(0,e>>>0,!1),t}function R(e,t){let r=new Uint8Array(e.length+t.length);return r.set(e,0),r.set(t,e.length),r}async function Oe(e,t){let r=[],s=0;for(;s<t;){let{done:a,value:o}=await e.read();if(a)return null;!o||o.byteLength===0||(r.push(o),s+=o.byteLength)}let n;if(r.length===1)n=r[0];else{n=R(r[0],r[1]);for(let a=2;a<r.length;a++)n=R(n,r[a])}return n.byteLength>t?{data:n.slice(0,t),extra:n.slice(t)}:{data:n,extra:null}}async function Pe(e,t){let r=e.sni&&e.sni!==""?e.sni:e.address,s=Number(e.port),n;try{n=globalThis.connect?globalThis.connect({hostname:r,port:s,secureTransport:e.tls?"on":"off"}):void 0}catch(h){return t(`[VLESS/grpc] connect error: ${h.message}`),null}if(!n)return t("[VLESS/grpc] connect unavailable"),null;let a=n.writable.getWriter();async function o(h){await a.write(h)}let i,d=new Promise(h=>{i=h});(n.closed||Promise.resolve()).then(i,i);try{await o(J.encode(At)),await o(A(4,0,0,new Uint8Array(0)));let h=e.tls?"https":"http",u=(e.path||"").replace(/^\/+/,"").replace(/\/+$/,""),w=u?`/${u}/Tun`:"/Tun",g=Ot([[":method","POST"],[":scheme",h],[":path",w],[":authority",`${r}:${s}`],["content-type","application/grpc"],["te","trailers"],["user-agent","grpc-go/1.68.0"]]);await o(A(1,4,1,g))}catch(h){t(`[VLESS/grpc] handshake failed: ${h.message}`);try{n.close()}catch{}return null}let c=n.readable.getReader(),l={needLen:5,buf:new Uint8Array(0),msgLen:0,controller:null,extra:null};function p(h,u){let w=h;for(;w.byteLength>0;)if(l.needLen>0){let g=Math.min(l.needLen,w.byteLength);l.buf=R(l.buf,w.slice(0,g)),w=w.slice(g),l.needLen-=g,l.needLen===0&&(l.buf.byteLength===5?(l.msgLen=new DataView(l.buf.buffer,l.buf.byteOffset,5).getUint32(1,!1),l.buf=new Uint8Array(0),l.needLen=l.msgLen,l.msgLen===0&&(l.needLen=5)):(l.buf=new Uint8Array(0),l.needLen=5))}else{let g=Math.min(l.msgLen,w.byteLength);if(l.buf=R(l.buf,w.slice(0,g)),w=w.slice(g),l.msgLen-=g,l.msgLen===0){if(l.buf.byteLength>0)try{u.enqueue(l.buf)}catch{}l.buf=new Uint8Array(0),l.needLen=5}}}let f=new ReadableStream({start(h){l.controller=h,(async()=>{try{for(;;){let u;if(l.extra)u=l.extra,l.extra=null;else{let w=await Oe(c,9);if(!w)break;let g=w.data[0]<<16|w.data[1]<<8|w.data[2],y=w.data[3],v=w.data[4],T=(w.data[5]&127)<<24|w.data[6]<<16|w.data[7]<<8|w.data[8];if(g===0)u=new Uint8Array(0);else{let S=await Oe(c,g);if(!S)break;u=S.data,l.extra=S.extra}if(y===0&&T===1){p(u,h),await o(A(8,0,1,Ue(u.byteLength))),await o(A(8,0,0,Ue(u.byteLength)));continue}if(y===4){v&1||await o(A(4,1,0,new Uint8Array(0)));continue}if(y===6){v&1||await o(A(6,1,T,u));continue}if(y===7||y===3)break}}try{h.close()}catch{}}catch(u){t(`[VLESS/grpc] read loop error: ${u.message}`);try{h.error(u)}catch{}}finally{try{i()}catch{}}})()},cancel(){try{c.cancel()}catch{}}});function b(h){let u=[],w=0,g=!0;for(;w<h.byteLength;){let y=Math.min(16384,h.byteLength-w);u.push(A(0,0,1,h.slice(w,w+y))),w+=y,g=!1}return u}let m=new WritableStream({write(h){let u=h instanceof Uint8Array?h:new Uint8Array(h),w=Ae(u),g=b(w);return(async()=>{for(let y of g)await o(y)})()},close(){try{n.close()}catch{}},abort(){try{n.close()}catch{}}});return{readable:f,writable:m,closed:d,send:async h=>{let u=Ae(h);for(let w of b(u))await o(w)}}}var Pt=1e4;async function O(e,t,r,s,n,a,o){let i=e.transport||ce;if(!ie.includes(i))return o(`[VLESS] unsupported transport: ${i}`),null;let d=null;try{i==="ws"?d=await $t(e,o):i==="raw"?d=await _e(e,o):i==="httpupgrade"?d=await Le(e,o):i==="grpc"&&(d=await Pe(e,o))}catch(f){return o(`[VLESS/${i}] connect failed: ${f.message}`),null}if(!d)return null;let c=Ee(t,r,s,n,e.uuid),l=a instanceof Uint8Array?a:new Uint8Array(a||0),p=new Uint8Array(c.length+l.length);p.set(c,0),p.set(l,c.length);try{await d.send(p)}catch(f){o(`[VLESS/${i}] send header failed: ${f.message}`);try{d.close&&await d.close()}catch{}return null}return{readable:d.readable,writable:d.writable,closed:d.closed}}async function $t(e,t){let r=e.tls?"wss":"ws",s=e.path&&e.path.startsWith("/")?e.path:`/${e.path||""}`,n=e.sni&&e.sni!==""?e.sni:e.address,a=`${r}://${n}:${e.port}${s}`,o;try{o=new WebSocket(a)}catch(f){return t(`[VLESS/ws] create ws failed: ${f.message}`),null}let i,d=new Promise(f=>{i=f});try{await new Promise((f,b)=>{let m=setTimeout(()=>b(new Error("Connection timeout")),Pt);o.addEventListener("open",()=>{clearTimeout(m),f()}),o.addEventListener("close",h=>{clearTimeout(m),b(new Error(`closed ${h.code}`))}),o.addEventListener("error",()=>{clearTimeout(m),b(new Error("ws error"))})})}catch(f){t(`[VLESS/ws] connect failed: ${f.message}`);try{o.close()}catch{}return i(),null}o.addEventListener("close",()=>i()),o.addEventListener("error",()=>{});let c=new WritableStream({write(f){o.readyState===1&&o.send(f)},close(){k(o)},abort(){k(o)}}),l=!1;return{readable:new ReadableStream({start(f){o.addEventListener("message",b=>{let m;try{b.data instanceof ArrayBuffer?m=new Uint8Array(b.data):ArrayBuffer.isView(b.data)?m=new Uint8Array(b.data.buffer,b.data.byteOffset,b.data.byteLength):typeof b.data=="string"?m=new TextEncoder().encode(b.data):m=null}catch{m=null}if(m){if(!l&&(l=!0,m.length>=2)){let h=m[1];if(m.length>2+h)m=m.slice(2+h);else return}if(m.length>0)try{f.enqueue(m)}catch{}}}),o.addEventListener("close",()=>{try{f.close()}catch{}}),o.addEventListener("error",b=>{try{f.error(b)}catch{}})},cancel(){k(o)}}),writable:c,closed:d,send:async f=>{if(o.readyState!==1)throw new Error(`ws not open (state=${o.readyState})`);o.send(f)}}}async function $e(e,t,r,s,n,a){let{username:o,password:i,hostname:d,port:c}=n,l=a({hostname:d,port:c}),p=l.writable.getWriter(),f=l.readable.getReader(),b=new TextEncoder;try{await p.write(new Uint8Array([5,2,0,2]));let m=(await f.read()).value;if(!m||m[0]!==5){s("socks version error");return}if(m[1]===255){s("no acceptable methods");return}if(m[1]===2){if(!o||!i){s("socks server requires auth but no credentials");return}let w=new Uint8Array([1,o.length,...b.encode(o),i.length,...b.encode(i)]);if(await p.write(w),m=(await f.read()).value,!m||m[0]!==1||m[1]!==0){s("socks auth failed");return}}let h;switch(e){case 1:h=new Uint8Array([1,...t.split(".").map(Number)]);break;case 2:h=new Uint8Array([3,t.length,...b.encode(t)]);break;case 3:h=new Uint8Array([4,...t.split(":").flatMap(w=>[parseInt(w.slice(0,2),16),parseInt(w.slice(2),16)])]);break;default:s(`invalid addressType ${e}`);return}let u=new Uint8Array([5,1,0,...h,r>>8,r&255]);if(await p.write(u),m=(await f.read()).value,!m||m[1]!==0){s(`socks connect failed rep=${m?m[1]:"none"}`);return}return p.releaseLock(),f.releaseLock(),l}catch(m){s(`socks5 error: ${m.message}`);try{p.releaseLock()}catch{}try{f.releaseLock()}catch{}try{l.close()}catch{}return}}function De(e,t={}){let[r,s]=e.split("@").reverse(),n,a,o,i;if(s){let c=s.split(":");if(c.length!==2)throw new Error("Invalid SOCKS address format");[n,a]=c}let d=r.split(":");if(i=Number(d.pop()),isNaN(i))throw new Error("Invalid SOCKS address format");return o=d.join(":"),t&&t.username!==void 0&&t.username!==null&&t.username!==""&&(n=t.username),t&&t.password!==void 0&&t.password!==null&&t.password!==""&&(a=t.password),{username:n,password:a,hostname:o,port:i}}async function Re(e,t,r,s,n,a,o=new Uint8Array(0)){let{username:i,password:d,hostname:c,port:l}=n,p=a({hostname:c,port:l}),f=p.writable.getWriter(),b=p.readable.getReader();try{let m=i&&d?`Proxy-Authorization: Basic ${btoa(`${i}:${d}`)}\r
`:"",h=`CONNECT ${t}:${r} HTTP/1.1\r
Host: ${t}:${r}\r
${m}User-Agent: Mozilla/5.0\r
Connection: keep-alive\r
\r
`;await f.write(new TextEncoder().encode(h));let u=new Uint8Array(0),w=-1,g=0;for(;w===-1&&g<8192;){let{done:S,value:E}=await b.read();if(S)throw new Error("Connection closed before HTTP response");let U=new Uint8Array(u.length+E.length);U.set(u,0),U.set(E,u.length),u=U,g=u.length;for(let L=0;L<u.length-3;L++)if(u[L]===13&&u[L+1]===10&&u[L+2]===13&&u[L+3]===10){w=L+4;break}}if(w===-1)throw new Error("Invalid HTTP response");let v=new TextDecoder().decode(u.slice(0,w)).split(`\r
`)[0].match(/HTTP\/\d\.\d\s+(\d+)/);if(!v)throw new Error("Invalid HTTP response format");let T=parseInt(v[1]);if(T<200||T>=300)throw new Error(`HTTP CONNECT failed: HTTP ${T}`);return o.length>0&&await f.write(o),f.releaseLock(),b.releaseLock(),p}catch(m){s(`http connect error: ${m.message}`);try{f.releaseLock()}catch{}try{b.releaseLock()}catch{}try{p.close()}catch{}return}}function Ce(e,t={}){let[r,s]=e.split("@").reverse(),n,a,o,i;if(s){let c=s.split(":");if(c.length!==2)throw new Error("Invalid HTTP address format");[n,a]=c}let d=r.split(":");if(i=Number(d.pop()),isNaN(i))throw new Error("Invalid HTTP address format");return o=d.join(":"),t&&t.username!==void 0&&t.username!==null&&t.username!==""&&(n=t.username),t&&t.password!==void 0&&t.password!==null&&t.password!==""&&(a=t.password),{username:n,password:a,hostname:o,port:i}}function Ne(e,t,r,s,n){let a=e.proxyipHost&&!e.proxyipDisabled,o=a?e.proxyipHost:t,i=a?Number(e.proxyipPort||443):r,d=globalThis.connect?globalThis.connect({hostname:o,port:i}):void 0;if(!d)return n("connect unavailable"),null;if(s&&s.length>0){let c=d.writable.getWriter();c.write(s).then(()=>c.releaseLock()).catch(l=>n(`direct initial write error: ${l.message}`))}return d}async function C(e){let{config:t,outbound:r,addressType:s,addressRemote:n,portRemote:a,rawClientData:o,log:i,isUDP:d}=e,c=r;if(!c||c===_)return Ne(t,n,a,o,i);if(c===I)return i("rejected by routing rule"),null;switch(c.type){case _:return Ne(t,n,a,o,i);case se:{let l;try{l=De(c.address,{username:c.username,password:c.password})}catch(f){return i(`bad socks5 address: ${f.message}`),null}let p=await $e(s,n,a,i,l,globalThis.connect);if(!p)return null;if(o&&o.length>0){let f=p.writable.getWriter();f.write(o).then(()=>f.releaseLock()).catch(b=>i(`socks5 write error: ${b.message}`))}return p}case ae:{let l;try{l=Ce(c.address,{username:c.username,password:c.password})}catch(f){return i(`bad http address: ${f.message}`),null}return await Re(s,n,a,i,l,globalThis.connect,o||new Uint8Array(0))}case oe:return O({address:c.address,port:Number(c.port),uuid:c.uuid,path:c.path,tls:!!c.tls,sni:c.sni||"",transport:c.transport},d?2:1,s,n,a,o||new Uint8Array(0),i);default:return i(`unknown outbound type: ${c.type}`),null}}function N(e,t){return!t||t===_?_:t===I?I:e.outboundByName[t]||_}var Dt=60*60*1e3,q=new Map;async function X(e,t,r){let s=`${t}:${r}`,n=q.get(s);if(n&&Date.now()-n.ts<Dt)return n.data;let a=null;try{let o=t==="geosite"?le:de,i=await e.GEO_KV.get(o+r);if(i){let d=JSON.parse(i);Array.isArray(d)&&(a=d)}}catch{}return a||(a=Rt(t,r)),q.set(s,{data:a,ts:Date.now()}),a}function Rt(e,t){if(e==="geosite")switch(t){case"cn":return pe;case"speedtest":return fe;case"google":return he;default:return[]}return[]}function Me(){q.clear()}function Ct(e){if(!e)return null;let t=String(e).trim();if(!t)return null;let r=t.match(/^geosite:(.+)$/i);if(r){let c=r[1].split(",").map(l=>l.trim()).filter(Boolean);return c.length===0?null:{type:"geosite",categories:c}}let s=t.match(/^geoip:(.+)$/i);if(s){let c=s[1].split(",").map(l=>l.trim()).filter(Boolean);return c.length===0?null:{type:"geoip",categories:c}}let n=t.match(/^domain:(.+)$/i);if(n)return{type:"domain",value:n[1].trim()};let a=t.match(/^full:(.+)$/i);if(a)return{type:"full",value:a[1].trim()};let o=t.match(/^keyword:(.+)$/i);if(o)return{type:"keyword",value:o[1].trim()};let i=t.match(/^ip-cidr:(.+)$/i);if(i)return{type:"ip-cidr",value:i[1].trim()};let d=t.match(/^regexp:(.+)$/i);return d?{type:"regexp",value:d[1].trim()}:{type:"domain",value:t}}function He(e){let t=e.split(".");if(t.length!==4)return null;let r=0;for(let s of t){let n=Number(s);if(isNaN(n)||n<0||n>255)return null;r=r<<8|n}return r>>>0}function Ie(e,t){let[r,s]=t.split("/"),n=s!==void 0?Number(s):32,a=He(e);if(a===null)return!1;let o=He(r);if(o===null)return!1;let i=n<=0?0:4294967295<<32-n>>>0;return(a&i)===(o&i)}function je(e,t){let r=e.toLowerCase(),s=t.toLowerCase();return r===s?!0:r.endsWith("."+s)||r.endsWith(s)}var Be=new Map;function Nt(e){let t=Be.get(e);if(!t){try{t=new RegExp(e)}catch{t=null}Be.set(e,t)}return t}async function Mt(e,t,r,s){switch(e.type){case"domain":return r?!1:je(t,e.value);case"full":return r?!1:t.toLowerCase()===e.value.toLowerCase();case"keyword":return r?!1:t.toLowerCase().includes(e.value.toLowerCase());case"regexp":{if(r)return!1;let n=Nt(e.value);return n?n.test(t):!1}case"ip-cidr":return r?Ie(t,e.value):!1;case"geosite":{if(r)return!1;for(let n of e.categories){let a=await X(s,"geosite",n);for(let o of a)if(je(t,o))return!0}return!1}case"geoip":{if(!r)return!1;for(let n of e.categories){let a=await X(s,"geoip",n);for(let o of a)if(Ie(t,o))return!0}return!1}default:return!1}}async function B(e,t,r){let s=t===1||t===3;for(let n of e.routingRules){let a=Ct(n.rule);if(!a)continue;if(await Mt(a,r,s,e.env))return{outbound:n.outbound||"direct",rule:n}}return{outbound:e.defaultOutbound||"direct",rule:null}}function Ht(e){return e instanceof ArrayBuffer?e:ArrayBuffer.isView(e)?e.buffer.slice(e.byteOffset,e.byteOffset+e.byteLength):typeof e=="string"?new TextEncoder().encode(e).buffer:null}function Fe(e){return e instanceof ArrayBuffer?new Uint8Array(e):ArrayBuffer.isView(e)?new Uint8Array(e.buffer,e.byteOffset,e.byteLength):typeof e=="string"?new TextEncoder().encode(e):null}async function Ve(e,t,r){let s=e.headers.get("Upgrade");if(!s||s.toLowerCase()!=="websocket")return new Response("Expected WebSocket",{status:400});let[n,a]=Object.values(new WebSocketPair);a.accept();let o=(...i)=>console.log("[ws]",...i);return It(a,t,r,o).catch(i=>{o(`ws handler error: ${i.message||i}`),k(a)}),new Response(null,{status:101,webSocket:n})}async function It(e,t,r,s){let n;try{n=await jt(e,s)}catch(m){s(`read first packet error: ${m.message}`),k(e);return}if(!n){k(e);return}let a,o=null,i="vless";if(ke(n)){if(a=await Se(n,t.passwordSet),a.hasError){s(`trojan header error: ${a.message}`),k(e);return}i="trojan",o=t.trojanIndex[a.userPassword]||null}else{if(a=Te(n,t.uuidSet),a.hasError){s(`vless header error: ${a.message}`),k(e);return}o=t.vlessIndex[a.userUuid]||null}let{addressType:d,addressRemote:c,portRemote:l,isUDP:p}=a,f=new Uint8Array(n.slice(a.rawDataIndex)),b;try{b=await B(t,d,c)}catch(m){s(`route error: ${m.message}`),k(e);return}p?await Ft(e,t,d,c,l,f,o,i,b,s):await Bt(e,t,d,c,l,f,o,i,b,s)}function jt(e,t){return new Promise((r,s)=>{let n=!1,a=()=>{e.removeEventListener("message",o),e.removeEventListener("close",i),e.removeEventListener("error",d)},o=c=>{n||(n=!0,a(),r(Ht(c.data)))},i=()=>{n||(n=!0,a(),r(null))},d=c=>{n||(n=!0,a(),s(c))};e.addEventListener("message",o),e.addEventListener("close",i),e.addEventListener("error",d),setTimeout(()=>{n||(n=!0,a(),r(null))},15e3)})}async function Bt(e,t,r,s,n,a,o,i,d,c){let l=N(t,d.outbound),p=a&&a.length>0?a:new Uint8Array(0),f=[l];l!=="direct"&&l!=="reject"&&f.push("direct");let b=null,m=null;for(let v of f){try{b=await C({config:t,outbound:v,addressType:r,addressRemote:s,portRemote:n,rawClientData:p,log:c})}catch(T){m=T,b=null}if(b)break}if(!b){c(`tcp connect failed: ${m?m.message:"no outbound available"}`),k(e);return}let h=0,u=0,w=!1,g=b.writable.getWriter(),y=v=>{if(w)return;let T=Fe(v.data);if(!(!T||T.length===0)){h+=T.byteLength;try{g.write(T).catch(()=>{})}catch{}}};e.addEventListener("message",y);try{let v=b.readable.getReader();for(;;){let{done:T,value:S}=await v.read();if(T)break;S&&S.byteLength>0&&(u+=S.byteLength,e.readyState===1&&e.send(S))}}catch(v){c(`tcp remote read error: ${v.message}`)}w=!0,e.removeEventListener("message",y);try{g.releaseLock()}catch{}try{await b.writable.close()}catch{}try{e.close()}catch{}await We(t,o,i,h,u,c)}async function Ft(e,t,r,s,n,a,o,i,d,c){let l=null,p=(t.udpOutbound||"").trim();if(p){let y=t.outboundByName[p];if(y&&y.type==="vless")l=y;else{c(`udp outbound '${p}' not found or not vless (only vless supports udp)`),k(e);return}}else{if(d.outbound&&d.outbound!=="direct"&&d.outbound!=="reject"){let y=N(t,d.outbound);y!=="direct"&&y!=="reject"&&y.type==="vless"&&(l=y)}l||(l=t.outbounds.find(y=>y.type==="vless"))}if(!l){c("udp requires a vless outbound, none configured"),k(e);return}let f=a&&a.length>0?a:new Uint8Array([0,0]),b=await O({address:l.address,port:Number(l.port),uuid:l.uuid,path:l.path,tls:!!l.tls,sni:l.sni||""},2,r,s,n,f,c);if(!b){c("udp vless outbound connect failed"),k(e);return}let m=0,h=0,u=!1,w=b.writable.getWriter(),g=y=>{if(u)return;let v=Fe(y.data);if(!(!v||v.length===0)){m+=v.byteLength;try{w.write(v).catch(()=>{})}catch{}}};e.addEventListener("message",g);try{let y=b.readable.getReader();for(;;){let{done:v,value:T}=await y.read();if(v)break;T&&T.byteLength>0&&(h+=T.byteLength,e.readyState===1&&e.send(T))}}catch(y){c(`udp read error: ${y.message}`)}u=!0,e.removeEventListener("message",g);try{w.releaseLock()}catch{}try{await b.writable.close()}catch{}k(e),await We(t,o,i,m,h,c)}async function We(e,t,r,s,n,a){if(!t)return;let o=r==="vless"?"vless_users":"trojan_users";try{await e.env.DB.prepare(`UPDATE ${o} SET up = up + ?, down = down + ? WHERE id = ?`).bind(s,n,t.id).run()}catch(i){a(`record traffic error: ${i.message}`)}}var Ge="ed=2560",P="random";function F(e){let t=e.startsWith("/")?e:`/${e}`;return/\?/.test(t)?`${t}&${Ge}`:`${t}?${Ge}`}function M(e){let t=F(e.wsPath),r=e.wsHost||e.host,s=e.sni||(e.tls?r:""),n=new URLSearchParams({encryption:"none",type:"ws",path:t,host:r,security:e.tls?"tls":"none"});e.tls&&s&&n.set("sni",s),e.tls&&n.set("fp",e.fp||P);let a=encodeURIComponent(e.remark||`${e.host}:${e.port}`);return`vless://${e.uuid}@${e.host}:${e.port}?${n.toString()}#${a}`}function H(e){let t=F(e.wsPath),r=e.wsHost||e.host,s=e.sni||(e.tls?r:""),n=new URLSearchParams({type:"ws",path:t,host:r,security:e.tls?"tls":"none"});e.tls&&s&&n.set("sni",s),e.tls&&n.set("fp",e.fp||P);let a=encodeURIComponent(e.remark||`${e.host}:${e.port}`);return`trojan://${encodeURIComponent(e.password)}@${e.host}:${e.port}?${n.toString()}#${a}`}function ze(e){let t=e.headers.get("Host");return t?t.split(":")[0]:"example.com"}function Vt(e,t){let r=[],s=t.port||(t.tls?443:80);for(let n of e.vlessUsers)r.push(M({uuid:n.uuid,host:t.host,port:s,wsPath:e.wsPath,tls:t.tls,wsHost:t.wsHost,sni:t.sni,remark:`vless-${n.remark||n.uuid.slice(0,8)}`}));for(let n of e.trojanUsers)r.push(H({password:n.password,host:t.host,port:s,wsPath:e.wsPath,tls:t.tls,wsHost:t.wsHost,sni:t.sni,remark:`trojan-${n.remark||n.password.slice(0,8)}`}));return r}function Q(e,t){return Vt(e,t).join(`
`)+`
`}function Ke(e,t){return btoa(Q(e,t))}function Ye(e,t){let r=t.port||443,s=t.tls!==!1,n=F(e.wsPath),a=t.wsHost||t.host,o=t.sni||(s?a:""),i=[],d=e.vlessUsers.map((p,f)=>({name:`vless-${p.remark||f+1}`,type:"vless",server:t.host,port:r,uuid:p.uuid,network:"ws",tls:s,servername:o||void 0,"client-fingerprint":s?P:void 0,"ws-opts":{path:n,headers:{Host:a}},udp:!0})),c=e.trojanUsers.map((p,f)=>({name:`trojan-${p.remark||f+1}`,type:"trojan",server:t.host,port:r,password:p.password,network:"ws",tls:s,servername:o||void 0,"client-fingerprint":s?P:void 0,"ws-opts":{path:n,headers:{Host:a}},udp:!0}));i.push(...d,...c);let l=["proxies:"];for(let p of i)l.push(`  - name: "${p.name}"`),l.push(`    type: ${p.type}`),l.push(`    server: ${p.server}`),l.push(`    port: ${p.port}`),p.uuid&&l.push(`    uuid: ${p.uuid}`),p.password&&l.push(`    password: "${p.password}"`),l.push("    network: ws"),l.push(`    tls: ${p.tls}`),p.servername&&l.push(`    servername: ${p.servername}`),p["client-fingerprint"]&&l.push(`    client-fingerprint: ${p["client-fingerprint"]}`),l.push("    udp: true"),l.push("    ws-opts:"),l.push(`      path: ${p["ws-opts"].path}`),l.push("      headers:"),l.push(`        Host: ${a}`);return l.push(""),l.push("rules:"),l.push("  - MATCH,DIRECT"),l.join(`
`)}function Je(e,t){let r=t.port||443,s=F(e.wsPath),n=t.wsHost||t.host,a=t.sni||(t.tls?n:""),o=[];for(let i of e.vlessUsers)o.push({type:"vless",tag:`vless-${i.remark||i.uuid.slice(0,8)}`,server:t.host,server_port:r,uuid:i.uuid,transport:{type:"ws",path:s,headers:{Host:n}},tls:t.tls?{enabled:!0,server_name:a,fingerprint:P}:null});for(let i of e.trojanUsers)o.push({type:"trojan",tag:`trojan-${i.remark||i.password.slice(0,8)}`,server:t.host,server_port:r,password:i.password,transport:{type:"ws",path:s,headers:{Host:n}},tls:t.tls?{enabled:!0,server_name:a,fingerprint:P}:null});return JSON.stringify({outbounds:o,log:{level:"info"}},null,2)}function Z(e,t){let r=t.host,s=t.port||(t.tls?443:80),n=e.wsPath.startsWith("/")?e.wsPath:`/${e.wsPath}`,a="",o="";return t.kind==="vless"?(a=M({uuid:t.credential,host:r,port:s,wsPath:n,tls:t.tls,wsHost:t.wsHost,sni:t.sni,remark:"vless-node"}),o="VLESS"):t.kind==="trojan"&&(a=H({password:t.credential,host:r,port:s,wsPath:n,tls:t.tls,wsHost:t.wsHost,sni:t.sni,remark:"trojan-node"}),o="Trojan"),`<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>${o} \u8282\u70B9\u914D\u7F6E</title>
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
  <h1>${o} \u8282\u70B9 <span class="badge">${r}</span></h1>
  <p class="desc">\u590D\u5236\u4E0B\u65B9\u94FE\u63A5\u5230 v2rayN / sing-box / Clash \u5BA2\u6237\u7AEF\u5BFC\u5165\u8282\u70B9</p>
  <div class="row">
    <label>\u8282\u70B9\u5206\u4EAB\u94FE\u63A5</label>
    <div class="linkbox">
      <input type="text" readonly value="${a}" id="link">
      <button onclick="copyLink()">\u590D\u5236</button>
    </div>
  </div>
</div>
<script>
function copyLink(){ const el=document.getElementById('link'); el.select(); document.execCommand('copy'); el.style.borderColor='#34c759'; setTimeout(()=>el.style.borderColor='#d2d2d7',800); }
<\/script>
</body>
</html>`}function qe(e){let t=e.disguise_title||"AList",r=e.disguise_subtitle||"\u4E00\u4E2A\u652F\u6301\u591A\u5B58\u50A8\u7684\u6587\u4EF6\u5217\u8868\u7A0B\u5E8F";return`<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>${t}</title>
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
  <div class="logo"><span>\u25A4</span> ${t}</div>
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
<div class="footer">Powered by ${t} \xB7 ${r}</div>
</body>
</html>`}function ee(e,t=200){return new Response(e,{status:t,headers:{"Content-Type":"text/html; charset=utf-8","Cache-Control":"no-store"}})}function $(e,t="text/plain; charset=utf-8"){return new Response(e,{headers:{"Content-Type":t,"Cache-Control":"no-store"}})}function Wt(e,t,r){let n=(new URL(e.url).searchParams.get("format")||"base64").toLowerCase(),a={host:r.host,port:r.port,tls:r.tls,wsHost:r.wsHost,sni:r.sni};switch(n){case"plain":return $(Q(t,a));case"clash":case"yaml":return $(Ye(t,a),"text/yaml; charset=utf-8");case"singbox":case"sing-box":case"json":return $(Je(t,a),"application/json; charset=utf-8");case"base64":default:return $(Ke(t,a))}}function Gt(e,t,r,s){let n=new URL(e.url),a=null;if(t.uuidSet.has(r)?a={kind:"vless",user:t.vlessIndex[r]}:t.passwordSet.has(r)&&(a={kind:"trojan",user:t.trojanIndex[r]}),!a)return new Response("Not Found",{status:404});let o=(n.searchParams.get("format")||"base64").toLowerCase(),i=s.host,d=s.port,c=t.wsPath,l;return a.kind==="vless"?l=M({uuid:a.user.uuid,host:i,port:d,wsPath:t.wsPath,tls:s.tls,wsHost:s.wsHost,sni:s.sni,remark:`vless-${a.user.remark||"node"}`}):l=H({password:a.user.password,host:i,port:d,wsPath:t.wsPath,tls:s.tls,wsHost:s.wsHost,sni:s.sni,remark:`trojan-${a.user.remark||"node"}`}),$(o==="plain"?l+`
`:btoa(l+`
`))}async function Xe(e,t,r){let s=new URL(e.url),n=s.pathname,a=ze(e),o=s.protocol==="https:",i=Number(s.port)||(o?443:80),d=(t.entryHost||"").trim(),c=d?{host:d,port:Number(t.entryPort)||443,tls:!0,wsHost:(t.entryWsHost||"").trim()||d,sni:(t.entrySni||"").trim()||d}:{host:a,port:i,tls:o,wsHost:a,sni:a};if(n==="/subscribe")return Wt(e,t,c);let l=n.match(/^\/([^/]+)\/subscribe$/);if(l)return Gt(e,t,decodeURIComponent(l[1]),c);let p=n.match(/^\/([^/]+)$/);if(p){let f=decodeURIComponent(p[1]);if(t.uuidSet.has(f))return ee(Z(t,{host:c.host,port:c.port,tls:c.tls,wsHost:c.wsHost,sni:c.sni,credential:f,kind:"vless"}));if(t.passwordSet.has(f))return ee(Z(t,{host:c.host,port:c.port,tls:c.tls,wsHost:c.wsHost,sni:c.sni,credential:f,kind:"trojan"}))}return ee(qe(t.settings))}function zt(e){if(e.length<2)return{frame:null,remaining:e,needMore:!0};let t=e[0]<<8|e[1];return t===0?{frame:new Uint8Array(0),remaining:e.slice(2),needMore:!1}:e.length<2+t?{frame:null,remaining:e,needMore:!0}:{frame:e.slice(2,2+t),remaining:e.slice(2+t),needMore:!1}}function Qe(e){let t=new Uint8Array(2+e.length);return t[0]=e.length>>8,t[1]=e.length&255,t.set(e,2),t}async function Ze(e,t,r){let s=e.getReader(),n=new Uint8Array(0);try{for(;;){let{done:a,value:o}=await s.read();if(a)break;if(!o||o.byteLength===0)continue;let i=new Uint8Array(n.length+o.byteLength);for(i.set(n,0),i.set(o,n.length),n=i;;){let{frame:d,remaining:c,needMore:l}=zt(n);if(l){n=c;break}if(n=c,d&&d.length>0)try{await t(d)}catch(p){r(`udp frame handler error: ${p.message}`)}if(n.length<2)break}}}catch(a){r(`readUdpFrames error: ${a.message}`)}finally{try{s.releaseLock()}catch{}}}var et=[{name:"\u5B57\u8282\u8DF3\u52A8",host:"www.bytedance.com",port:80,region:"cn",icon:"\u{1F3B5}"},{name:"Bilibili",host:"www.bilibili.com",port:80,region:"cn",icon:"\u{1F4FA}"},{name:"\u5FAE\u4FE1",host:"weixin.qq.com",port:80,region:"cn",icon:"\u{1F4AC}"},{name:"\u6DD8\u5B9D",host:"www.taobao.com",port:80,region:"cn",icon:"\u{1F6D2}"},{name:"GitHub",host:"github.com",port:80,region:"intl",icon:"\u{1F419}"},{name:"jsDelivr",host:"cdn.jsdelivr.net",port:80,region:"intl",icon:"\u{1F4E6}"},{name:"Cloudflare",host:"www.cloudflare.com",port:80,region:"intl",icon:"\u2601\uFE0F"},{name:"YouTube",host:"www.youtube.com",port:80,region:"intl",icon:"\u25B6\uFE0F"}],tt=16,nt=3e3,rt=4;var Kt=5e3,Yt=5e3;function te(e,t,r="/"){return new TextEncoder().encode(`GET ${r} HTTP/1.1\r
Host: ${e}\r
User-Agent: Mozilla/5.0 (netprobe)\r
Connection: close\r
\r
`)}function Jt(e,t){let r=new Uint8Array(e.length+t.length);return r.set(e,0),r.set(t,e.length),r}function qt(e){for(let t=0;t<e.length-3;t++)if(e[t]===13&&e[t+1]===10&&e[t+2]===13&&e[t+3]===10)return t+4;return-1}function st(e){try{typeof e.close=="function"?e.close():e.writable&&typeof e.writable.close=="function"&&e.writable.close().catch(()=>{})}catch{}}function re(e,t){return new Promise(r=>{let s=new Uint8Array(0),n=!1,a=i=>{n||(n=!0,clearTimeout(o),r(i))},o=setTimeout(()=>a(null),t);(async()=>{let i=e.readable.getReader();try{for(;!n;){let{done:d,value:c}=await i.read();if(d)break;if(!(!c||c.byteLength===0)){if(s=Jt(s,c),qt(s)>=0){a(Date.now());break}if(s.length>65536){a(null);break}}}}catch{}a(null);try{i.releaseLock()}catch{}})()})}async function Xt(e,t,r,s,n){let a=Date.now(),o;try{let d=await B(e,2,t),c=N(e,d.outbound);o=await C({config:e,outbound:c,addressType:2,addressRemote:t,portRemote:r,rawClientData:s,log:n})}catch{return null}if(!o)return null;let i=await re(o,nt);return st(o),i===null?null:i-a}async function Qt(e,t,r){let s=[];for(let o=0;o<tt;o+=rt){let i=[],d=Math.min(o+rt,tt);for(let l=o;l<d;l++)i.push(Xt(e,t.host,t.port,te(t.host,t.port),r));let c=await Promise.all(i);for(let l of c)s.push(l)}let n=s.filter(o=>o!==null),a=n.length>0?Math.round(n.reduce((o,i)=>o+i,0)/n.length):null;return{...t,samples:s,latency:a,success:n.length,total:s.length}}async function at(e,t){let r=await Promise.allSettled(et.map(s=>Qt(e,s,t)));return{ok:!0,ts:Date.now(),targets:r.map((s,n)=>s.status==="fulfilled"?s.value:{...et[n],samples:[],latency:null,success:0,total:0,error:s.reason&&s.reason.message||"error"})}}async function ot(e,t){if(!e.proxyipHost)return{ok:!1,error:"\u672A\u914D\u7F6E proxyip\uFF0C\u8BF7\u5148\u5728\u7CFB\u7EDF\u8BBE\u7F6E\u4E2D\u586B\u5199"};let r="www.cloudflare.com",s=443,n=Date.now(),a=null;try{if(a=globalThis.connect?globalThis.connect({hostname:e.proxyipHost,port:Number(e.proxyipPort||443)}):null,!a)return{ok:!1,error:"connect \u4E0D\u53EF\u7528"};let i=a.writable.getWriter();await i.write(te(r,s)),i.releaseLock()}catch(i){try{a&&a.close()}catch{}return{ok:!1,error:`\u8FDE\u63A5\u5931\u8D25: ${i.message}`}}let o=await re(a,nt);try{a.close()}catch{}return o===null?{ok:!1,error:"\u8FDE\u63A5\u8D85\u65F6\u6216\u65E0\u54CD\u5E94"}:{ok:!0,latency:o-n,endpoint:`${e.proxyipHost}:${e.proxyipPort||443}`}}function Zt(e){let r=[18,52];r.push(1,0),r.push(0,1),r.push(0,0,0,0,0,0);for(let s of String(e).split(".")){r.push(s.length);for(let n=0;n<s.length;n++)r.push(s.charCodeAt(n))}return r.push(0),r.push(0,1),r.push(0,1),new Uint8Array(r)}async function it(e,t){let r=null,s=(e.udpOutbound||"").trim();if(s){let c=e.outboundByName[s];if(c&&c.type==="vless")r=c;else return{ok:!1,error:`UDP \u51FA\u7AD9 '${s}' \u4E0D\u5B58\u5728\u6216\u975E vless\uFF08\u4EC5 vless \u652F\u6301 UDP\uFF09`}}else if(r=e.outbounds.find(c=>c.type==="vless"),!r)return{ok:!1,error:"\u672A\u914D\u7F6E vless \u51FA\u7AD9\uFF0C\u65E0\u6CD5\u6D4B\u8BD5 UDP"};let n=Zt("example.com"),a=Qe(n),o=Date.now(),i;try{i=await O({address:r.address,port:Number(r.port),uuid:r.uuid,path:r.path,tls:!!r.tls,sni:r.sni||"",transport:r.transport},2,1,"1.1.1.1",53,a,t)}catch(c){return{ok:!1,error:`UDP \u51FA\u7AD9\u8FDE\u63A5\u5931\u8D25: ${c.message}`}}if(!i)return{ok:!1,error:"UDP \u51FA\u7AD9\u8FDE\u63A5\u5931\u8D25"};let d=await new Promise(c=>{let l=setTimeout(()=>c({ok:!1,error:"UDP \u54CD\u5E94\u8D85\u65F6"}),Kt);Ze(i.readable,p=>{p.length>=12&&p[0]===18&&p[1]===52&&p[2]&128&&(clearTimeout(l),c({ok:!0,latency:Date.now()-o,bytes:p.length}))},t)});try{i.writable.close().catch(()=>{})}catch{}return d}async function ct(e,t,r){let s="www.gstatic.com",a=Date.now(),o;try{o=await C({config:e,outbound:t,addressType:2,addressRemote:s,portRemote:80,rawClientData:te(s,80,"/generate_204"),log:r})}catch(d){return{ok:!1,error:d.message}}if(!o)return{ok:!1,error:"\u96A7\u9053\u5EFA\u7ACB\u5931\u8D25"};let i=await re(o,Yt);return st(o),i===null?{ok:!1,error:"\u8FDE\u63A5\u8D85\u65F6\u6216\u65E0\u54CD\u5E94"}:{ok:!0,latency:i-a}}var ne={"Content-Type":"application/json; charset=utf-8"};function x(e,t=200){return new Response(JSON.stringify(e),{status:t,headers:ne})}async function V(e){try{return await e.json()}catch{return null}}function er(e){return e.admin_cookie_secret||e.admin_password_hash||"vtd-insecure-secret"}async function lt(e,t){let n=new URL(e.url).pathname.split("/").filter(Boolean),a=n[2]||"",o=n[3]||null,i=e.method,{DB:d,GEO_KV:c}=t.env,l=t.settings,p=er(l);if(a==="login"&&i==="POST"){let u=await V(e);if(!u||!u.password)return x({error:"password required"},400);if(!await we(u.password,t.adminPasswordHash))return x({error:"invalid password"},401);let g=await ge(p);return new Response(JSON.stringify({ok:!0}),{status:200,headers:{...ne,"Set-Cookie":`${D}=${g}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${7*86400}`}})}let f=ve(e.headers.get("Cookie"));if(!await xe(f[D],p))return x({error:"unauthorized"},401);if(a==="logout"&&i==="POST")return new Response(JSON.stringify({ok:!0}),{status:200,headers:{...ne,"Set-Cookie":`${D}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0`}});if(a==="settings"){if(i==="GET"){let{results:u}=await d.prepare("SELECT key, value FROM settings").all();return x((u||[]).reduce((w,g)=>(w[g.key]=g.value,w),{}))}if(i==="PUT"){let u=await V(e);if(!u)return x({error:"bad body"},400);let w=new Set(["ws_path","default_outbound","proxyip","udp_outbound","disguise_title","disguise_subtitle","entry_host","entry_port","entry_sni","entry_ws_host","admin_password_hash","admin_cookie_secret"]);for(let[g,y]of Object.entries(u))typeof y=="string"&&w.has(g)&&await d.prepare("INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at").bind(g,y,Date.now()).run();return x({ok:!0})}return x({error:"method not allowed"},405)}let h={"vless-users":{table:"vless_users",cols:["uuid","remark","enable"]},"trojan-users":{table:"trojan_users",cols:["password","remark","enable"]},outbounds:{table:"outbounds",cols:["type","name","address","port","uuid","path","tls","udp","enable","sort","username","password","sni","transport"],validate(u){if(u.type!==void 0&&!["socks5","http","vless"].includes(u.type))return"invalid outbound type";if(u.port!==void 0&&(!Number.isInteger(Number(u.port))||Number(u.port)<=0||Number(u.port)>65535))return"invalid port";if((u.type==="socks5"||u.type==="http")&&!u.address)return"address required";if(u.type==="vless"){if(!u.uuid)return"vless requires uuid";if(u.transport!==void 0&&!["raw","ws","grpc","httpupgrade"].includes(u.transport))return"invalid vless transport"}return u.username&&!u.password||!u.username&&u.password?"username and password must be set together":((u.type==="socks5"||u.type==="http")&&(u.udp=0),u.type!=="vless"&&(u.transport="ws"),null)}},"routing-rules":{table:"routing_rules",cols:["rule","outbound","enable","sort"]}}[a];if(h)return tr(i,o,h,d,e);if(a==="stats"&&i==="GET"){let[u,w]=await Promise.all([d.prepare("SELECT remark, uuid, up, down FROM vless_users ORDER BY (up + down) DESC").all(),d.prepare("SELECT remark, password, up, down FROM trojan_users ORDER BY (up + down) DESC").all()]);return x({vless:u.results||[],trojan:w.results||[]})}if(a==="geo"&&n[3]==="update"&&i==="POST")try{let u=await W(d,c);return x({ok:!0,updated:u})}catch(u){return x({error:u.message},500)}if(a==="netstatus"&&n[3]==="test"&&i==="POST")try{return x(await at(t,u=>console.log(u)))}catch(u){return x({ok:!1,error:u.message},500)}if(a==="test"){if(n[3]==="proxyip"&&i==="POST")try{return x(await ot(t,u=>console.log(u)))}catch(u){return x({ok:!1,error:u.message},500)}if(n[3]==="udp"&&i==="POST")try{return x(await it(t,u=>console.log(u)))}catch(u){return x({ok:!1,error:u.message},500)}if(n[3]==="outbound"&&n[4]&&i==="POST"){let u=await d.prepare("SELECT * FROM outbounds WHERE id = ?").bind(Number(n[4])).first();if(!u)return x({ok:!1,error:"outbound not found"},404);try{return x(await ct(t,u,w=>console.log(w)))}catch(w){return x({ok:!1,error:w.message},500)}}}return x({error:"not found"},404)}async function tr(e,t,r,s,n){let{table:a,cols:o}=r,i="id";if(e==="GET"){let{results:d}=await s.prepare(`SELECT * FROM ${a} ORDER BY id`).all();return x(d||[])}if(e==="POST"){let d=await V(n);if(!d)return x({error:"bad body"},400);if(r.validate){let b=r.validate(d);if(b)return x({error:b},400)}let c=o.filter(b=>d[b]!==void 0);if(c.length===0)return x({error:"no fields"},400);let l=c.map(()=>"?").join(","),p=c.map(b=>d[b]),{meta:f}=await s.prepare(`INSERT INTO ${a} (${c.join(",")}) VALUES (${l})`).bind(...p).run();return x({ok:!0,id:f.last_row_id})}if(e==="PUT"&&t){let d=await V(n);if(!d)return x({error:"bad body"},400);if(r.validate){let f=r.validate(d);if(f)return x({error:f},400)}let c=o.filter(f=>d[f]!==void 0);if(c.length===0)return x({error:"no fields"},400);let l=c.map(f=>`${f} = ?`).join(","),p=c.map(f=>d[f]);return await s.prepare(`UPDATE ${a} SET ${l} WHERE ${i} = ?`).bind(...p,Number(t)).run(),x({ok:!0})}return e==="DELETE"&&t?(await s.prepare(`DELETE FROM ${a} WHERE ${i} = ?`).bind(Number(t)).run(),x({ok:!0})):x({error:"method not allowed"},405)}async function W(e,t){let{results:r}=await e.prepare("SELECT rule FROM routing_rules").all(),s={geosite:new Set,geoip:new Set};for(let a of r||[]){let o=String(a.rule||"").trim(),i=o.match(/^geosite:(.+)$/i);i&&i[1].split(",").forEach(d=>s.geosite.add(d.trim())),i=o.match(/^geoip:(.+)$/i),i&&i[1].split(",").forEach(d=>s.geoip.add(d.trim()))}let n=0;for(let a of["geosite","geoip"])for(let o of s[a])try{let i=await rr(a,o);i&&i.length>0&&(await t.put(`${a}:${o}`,JSON.stringify(i)),n++)}catch{}return await t.put("geo:version",new Date().toISOString()),Me(),n}async function rr(e,t){let s=`https://raw.githubusercontent.com/${e==="geosite"?"MetaCubeX/sing-geosite":"MetaCubeX/sing-geoip"}/rule-set/${t}.json`,n=await fetch(s,{cf:{cacheTtl:86400}});if(!n.ok)return null;let a=await n.text(),o;try{o=JSON.parse(a)}catch{return null}let i=[],d=c=>{typeof c=="string"&&c&&i.length<2e4&&i.push(c)};for(let c of o.rules||[])if(e==="geosite"){for(let l of c.domain||[])d(l);for(let l of c.domain_suffix||[])d(String(l).replace(/^\.+/,""))}else for(let l of c.ip_cidr||[])d(l);return i}function dt(e){return`<!DOCTYPE html>
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
</style>
</head>
<body>
<div class="login-wrap" id="loginWrap">
  <div class="login-card">
    <h1>\u8282\u70B9\u7BA1\u7406</h1>
    <p>\u8BF7\u8F93\u5165\u7BA1\u7406\u5BC6\u7801</p>
    ${e?`<p style="margin:-8px 0 16px;padding:10px 12px;background:#e8f8ef;color:#1d7a3f;border-radius:10px;font-size:13px">\u9996\u6B21\u90E8\u7F72\u521D\u59CB\u5BC6\u7801\uFF1A<b>${e}</b><br>\u767B\u5F55\u540E\u8BF7\u53CA\u65F6\u4FEE\u6539</p>`:""}
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

<div class="toast" id="toast"></div>

<script>
const $ = (s) => document.querySelector(s);
const state = { tab:'stats', editing:null, schema:null, records:[] };
const TAB_DEFS = {
  vless:   { title:'VLESS \u7528\u6237', api:'vless-users', fields:[{k:'uuid',label:'UUID'},{k:'remark',label:'\u5907\u6CE8'},{k:'enable',label:'\u542F\u7528',type:'checkbox'}] },
  trojan:  { title:'Trojan \u7528\u6237', api:'trojan-users', fields:[{k:'password',label:'\u5BC6\u7801'},{k:'remark',label:'\u5907\u6CE8'},{k:'enable',label:'\u542F\u7528',type:'checkbox'}] },
  outbounds:{ title:'\u51FA\u7AD9\u4EE3\u7406', api:'outbounds', fields:[{k:'type',label:'\u7C7B\u578B',type:'select',opts:['socks5','http','vless']},{k:'name',label:'\u540D\u79F0'},{k:'address',label:'\u5730\u5740'},{k:'port',label:'\u7AEF\u53E3',type:'number'},{k:'username',label:'\u7528\u6237\u540D(\u4EC5socks5/http)'},{k:'password',label:'\u5BC6\u7801(\u4EC5socks5/http)'},{k:'uuid',label:'UUID(\u4EC5vless)'},{k:'transport',label:'\u4F20\u8F93(\u4EC5vless)',type:'select',opts:['raw','ws','grpc','httpupgrade']},{k:'path',label:'Path(\u4EC5vless; grpc \u4E3A serviceName)',placeholder:'ws/httpupgrade \u586B\u8DEF\u5F84; grpc \u586B serviceName(\u7559\u7A7A\u4E3A /Tun)'},{k:'tls',label:'TLS',type:'checkbox'},{k:'sni',label:'SNI(\u4EC5vless)',placeholder:'\u7559\u7A7A\u5219\u4F7F\u7528\u5730\u5740\u4F5C\u4E3A\u8FDE\u63A5\u4E3B\u673A\u4E0ESNI'},{k:'udp',label:'UDP',type:'checkbox'},{k:'enable',label:'\u542F\u7528',type:'checkbox'},{k:'sort',label:'\u6392\u5E8F',type:'number'}] },
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
  if (tab==='netstatus'){ mc.innerHTML = '<div class="page-title">\u7F51\u7EDC\u72B6\u6001</div><div class="card" style="padding:12px 16px;font-size:13px;color:var(--muted)">\u68C0\u6D4B\u6309\u9879\u76EE\u7F51\u7EDC\u8BBE\u7F6E\u53D1\u8D77\uFF08\u5206\u6D41\u89C4\u5219 + \u9ED8\u8BA4\u51FA\u7AD9 + proxyip + \u51FA\u7AD9\u96A7\u9053\uFF09\uFF0C\u591A\u76EE\u6807\u5E76\u884C\u3001\u6BCF\u76EE\u6807 16 \u6B21\u91C7\u6837\uFF0C\u7EA6 10-15 \u79D2\u5B8C\u6210\u3002\u7EFF\u8272=\u6B63\u5E38\uFF0C\u9EC4\u8272/\u6A59\u8272=\u9AD8\u5EF6\u8FDF\uFF0C\u7070\u8272=\u8D85\u65F6/\u5931\u8D25\u3002</div><div class="toolbar"><button class="btn small" onclick="runNetstatus()">\u5F00\u59CB\u68C0\u6D4B</button></div><div class="net-grid" id="netGrid"></div>'; runNetstatus(); return; }
  if (tab==='settings'){ mc.innerHTML = '<div class="page-title">\u7CFB\u7EDF\u8BBE\u7F6E</div><div class="card">\u52A0\u8F7D\u4E2D...</div>'; await loadSettings(); return; }
  if (tab==='entry'){ mc.innerHTML = '<div class="page-title">\u5165\u53E3\u8BBE\u7F6E</div><div class="card">\u52A0\u8F7D\u4E2D...</div>'; await loadEntry(); return; }
  const def = TAB_DEFS[tab];
  mc.innerHTML = '<div class="page-title">'+def.title+'</div><div class="toolbar"><button class="btn small" onclick="openNew()">\uFF0B \u65B0\u589E</button></div><div class="card"><table><thead><tr>'+def.fields.map(f=>'<th>'+f.label+'</th>').join('')+'<th>\u64CD\u4F5C</th></tr></thead><tbody id="tbody"></tbody></table></div>';
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
      if (f.k==='uuid'||f.k==='password') return '<td class="mono">'+esc(r[f.k])+'</td>';
      return '<td>'+esc(r[f.k])+'</td>';
    }).join('');
    const testBtn = def.api==='outbounds' ? '<button class="btn small" onclick="testOutbound('+idx+', event)">\u6D4B\u8BD5</button> ' : '';
    return '<tr>'+tds+'<td>'+testBtn+'<button class="btn small" onclick="openEdit('+idx+')">\u7F16\u8F91</button> <button class="btn small danger" onclick="delRow('+idx+')">\u5220\u9664</button></td></tr>';
  }).join('') || '<tr><td colspan="99" style="text-align:center;color:var(--muted)">\u6682\u65E0\u6570\u636E</td></tr>';
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
    if (f.type==='checkbox') return '<label><input type="checkbox" id="f_'+f.k+'" '+(val?'checked':'')+' onchange="collectDraft()"> '+f.label+'</label>';
    if (f.type==='select') return '<label>'+f.label+'</label><select id="f_'+f.k+'" onchange="collectDraft();renderModalBody()">'+f.opts.map(o=>'<option '+(o===val?'selected':'')+'>'+o+'</option>').join('')+'</select>';
    return '<label>'+f.label+'</label><input type="'+ (f.type||'text') +'" id="f_'+f.k+'" value="'+esc(val)+'" oninput="collectDraft()"'+(f.placeholder?' placeholder="'+esc(f.placeholder)+'"':'')+'>';
  }).join('');
}

function collectDraft(){
  const def = state.schema;
  const draft = Object.assign({}, state.draft);
  for (const f of def.fields){
    const el = $('#f_'+f.k);
    if (!el) continue;
    if (f.type==='checkbox') draft[f.k] = el.checked ? 1 : 0;
    else if (f.type==='number') draft[f.k] = Number(el.value);
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
  const items = rows.map(r=>'<div class="stat-item"><div class="num">'+fmtBytes((r.up||0)+(r.down||0))+'</div><div class="lbl">'+esc(r.remark||r.uuid||r.password)+'</div><div class="lbl" style="font-size:11px">\u2191 '+fmtBytes(r.up||0)+' \u2193 '+fmtBytes(r.down||0)+'</div></div>').join('');
  return '<h3 style="margin:16px 0 12px;font-size:18px">'+title+'</h3><div class="stat-grid">'+(items||'<div class="card">\u6682\u65E0\u6570\u636E</div>')+'</div>';
}
function fmtBytes(n){
  if (n < 1024) return n+' B';
  const units=['KB','MB','GB','TB'];
  let v=n, i=-1;
  do { v/=1024; i++; } while (v>=1024 && i<units.length-1);
  return v.toFixed(1)+' '+units[i];
}

async function loadSettings(){
  const mc = $('#mainContent');
  try {
    const s = await api('/admin/api/settings');
    const fields = [
      ['ws_path','WebSocket \u8DEF\u5F84'],
      ['default_outbound','\u9ED8\u8BA4\u51FA\u7AD9 (direct / \u51FA\u7AD9\u540D)'],
      ['proxyip','proxyip\uFF08\u4EE3\u7406 IP \u6216\u57DF\u540D[:\u7AEF\u53E3]\uFF0C\u8BBF\u95EE Cloudflare \u53CA\u5F00 CF CDN \u7F51\u7AD9\u4F7F\u7528\uFF1B\u4EC5\u9ED8\u8BA4\u51FA\u7AD9\u4E3A direct \u65F6\u751F\u6548\uFF09'],
      ['udp_outbound','UDP \u51FA\u7AD9\u4EE3\u7406\uFF08\u51FA\u7AD9\u540D\uFF0C\u4EC5 vless \u652F\u6301 UDP\uFF09'],
      ['disguise_title','\u4F2A\u88C5\u9875\u6807\u9898'],
      ['disguise_subtitle','\u4F2A\u88C5\u9875\u526F\u6807\u9898'],
    ];
    mc.innerHTML = '<div class="page-title">\u7CFB\u7EDF\u8BBE\u7F6E</div><div class="card">'+
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
      ['entry_ws_host','\u5165\u53E3 Host\uFF08WebSocket Host \u5934\uFF09'],
    ];
    mc.innerHTML = '<div class="page-title">\u5165\u53E3\u8BBE\u7F6E</div>'+
      '<div class="card" style="background:#e8f8ef;color:#1d7a3f;font-size:13px;border-radius:10px;padding:12px 16px;margin-bottom:16px">\u8BBE\u7F6E\u5165\u53E3\u540E\uFF0C\u8282\u70B9/\u8BA2\u9605\u5C06\u4F7F\u7528\u5165\u53E3 IP/\u57DF\u540D\u3001\u7AEF\u53E3\u3001SNI\u3001Host \u751F\u6210\u914D\u7F6E\uFF08\u4E0D\u518D\u4F7F\u7528\u5F53\u524D\u57DF\u540D\uFF09\uFF1B\u672A\u8BBE\u7F6E\u5219\u4F7F\u7528\u5F53\u524D\u57DF\u540D\u3002</div>'+
      '<div class="card">'+
      fields.map(([k,label])=>'<label style="display:block;font-size:13px;color:var(--muted);margin:10px 0 4px">'+label+'</label><input id="s_'+k+'" value="'+esc(s[k]||'')+'" style="width:100%;padding:8px 12px;border:1px solid var(--border);border-radius:8px" placeholder="'+(k==='entry_port'?'443':'')+'">').join('')+
      '<div style="margin-top:16px"><button class="btn small" onclick="saveEntry()">\u4FDD\u5B58\u5165\u53E3\u8BBE\u7F6E</button></div></div>';
  } catch(e){ mc.innerHTML = '<div class="page-title">\u5165\u53E3\u8BBE\u7F6E</div><div class="card">\u52A0\u8F7D\u5931\u8D25: '+esc(e.message)+'</div>'; }
}

async function saveEntry(){
  const body = {};
  document.querySelectorAll('#mainContent input[id^=s_]').forEach(el=>{ body[el.id.slice(2)] = el.value; });
  try { await api('/admin/api/settings',{method:'PUT',body:JSON.stringify(body)}); toast('\u5165\u53E3\u8BBE\u7F6E\u5DF2\u4FDD\u5B58'); }
  catch(e){ toast(e.message); }
}

async function updateGeo(){
  try { const d = await api('/admin/api/geo/update',{method:'POST',body:'{}'}); toast('\u5DF2\u66F4\u65B0 '+d.updated+' \u4E2A\u5206\u7C7B'); }
  catch(e){ toast('\u66F4\u65B0\u5931\u8D25: '+e.message); }
}

// ---- \u7F51\u7EDC\u72B6\u6001 ----
async function runNetstatus(){
  const grid = $('#netGrid');
  if (!grid) return;
  grid.innerHTML = '<div class="card" style="grid-column:1/-1">\u68C0\u6D4B\u4E2D\uFF0C\u8BF7\u7A0D\u5019\u2026\uFF08\u591A\u76EE\u6807\u5E76\u884C\u91C7\u6837\uFF0C\u7EA6 10-15 \u79D2\uFF09</div>';
  try {
    const d = await api('/admin/api/netstatus/test',{method:'POST',body:'{}'});
    renderNetCards(grid, d.targets || []);
  } catch(e){ grid.innerHTML = '<div class="card" style="grid-column:1/-1">\u68C0\u6D4B\u5931\u8D25: '+esc(e.message)+'</div>'; }
}
function renderNetCards(grid, targets){
  grid.innerHTML = targets.map(t=>{
    const region = t.region==='cn' ? '<span class="badge">\u56FD\u5185</span>' : '<span class="badge on">\u56FD\u9645</span>';
    const lat = (t.latency===null || t.latency===undefined)
      ? '<div class="net-latency fail">\u8D85\u65F6 / \u5931\u8D25</div>'
      : '<div class="net-latency">'+t.latency+'<span class="unit">ms</span></div>';
    const dots = (t.samples||[]).map(s=>dotCls(s)).join('');
    return '<div class="net-card"><div class="net-head"><span class="net-icon">'+esc(t.icon||'')+'</span><span class="net-name">'+esc(t.name||t.host||'')+'</span>'+region+'</div>'+lat+'<div class="net-dots">'+dots+'</div><div class="net-foot"><span>'+(t.success||0)+'/'+(t.total||0)+' \u6210\u529F</span><span class="mono">'+esc(t.host||'')+'</span></div></div>';
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
  el.innerHTML = 'UDP \u6D4B\u8BD5\u4E2D\u2026\uFF08\u7ECF UDP \u51FA\u7AD9\u5411 1.1.1.1:53 \u53D1\u8D77 DNS \u67E5\u8BE2\uFF09';
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
</html>`}async function ut(e,t){let r=new URL(e.url);if(e.method==="POST"||e.method==="GET")try{let{DB:s,GEO_KV:n}=t,a=await W(s,n);return new Response(JSON.stringify({ok:!0,updated:a}),{status:200,headers:{"Content-Type":"application/json; charset=utf-8"}})}catch(s){return new Response(JSON.stringify({ok:!1,error:s.message}),{status:500,headers:{"Content-Type":"application/json; charset=utf-8"}})}return new Response("Not Found",{status:404})}async function pt(e,t,r){try{let s=await W(t.DB,t.GEO_KV);console.log(`[cron] geo update done: ${s} categories`)}catch(s){console.log(`[cron] geo update failed: ${s.message}`)}}globalThis.connect=nr;var vn={async fetch(e,t,r){let n=new URL(e.url).pathname;try{if(n.startsWith("/admin")){let o=await Y(e,t,{ensureAdmin:!0});return n.startsWith("/admin/api/")?await lt(e,o):new Response(dt(o.adminTempPassword),{headers:{"Content-Type":"text/html; charset=utf-8","Cache-Control":"no-store"}})}if(n==="/geo-update-cron")return await ut(e,t);let a=await Y(e,t);return n===a.wsPath?await Ve(e,a,t):await Xe(e,a,t)}catch(a){return console.log(`[index] error: ${a.message||a}`),new Response(JSON.stringify({error:"internal error"}),{status:500,headers:{"Content-Type":"application/json; charset=utf-8"}})}},async scheduled(e,t,r){return pt(e,t,r)}};export{vn as default};
