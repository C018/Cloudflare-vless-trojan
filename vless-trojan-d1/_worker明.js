import{connect as Lr}from"cloudflare:sockets";var A="direct",W="reject",he="socks5",me="http",be="vless",we=["raw","ws","grpc","httpupgrade","h2"],ge="ws";var ye="ws",xe="geosite:",ve="geoip:";var C="vtd_admin";var Te="/ws";var Ee=["qq.com","taobao.com","tmall.com","jd.com","baidu.com","bilibili.com","douyin.com","weibo.com","zhihu.com","163.com","126.com","aliyun.com","tencent.com","weixin.qq.com","alipay.com","bankofchina.com","icbc.com.cn","ccb.com","abcchina.com","cmbchina.com","boc.cn","12306.cn","gov.cn","cn","com.cn","net.cn","org.cn"],ke=["speedtest.net","fast.com","ookla.com"],Se=["google.com","googleapis.com","gstatic.com","googleusercontent.com","ggpht.com","google.cn","google.com.hk","gvt1.com","gvt2.com","gvt3.com"],X=[];for(let e=0;e<=255;++e){let t=e.toString(16).padStart(2,"0");X.push(t)}var q=1e5;function Z(e){return Array.from(new Uint8Array(e)).map(t=>t.toString(16).padStart(2,"0")).join("")}function $t(){let e=new Uint8Array(16);return crypto.getRandomValues(e),Z(e)}async function _e(e,t,r){let a=await crypto.subtle.importKey("raw",new TextEncoder().encode(e),"PBKDF2",!1,["deriveBits"]),n=await crypto.subtle.deriveBits({name:"PBKDF2",salt:new TextEncoder().encode(t),iterations:r,hash:"SHA-256"},a,256);return Z(n)}async function Ae(e){let t=$t(),r=await _e(e,t,q);return`${t}:${q}:${r}`}async function Le(e,t){if(!t||!e)return!1;let r=String(t).split(":");if(r.length!==3)return!1;let[a,n,s]=r,o=parseInt(n,10)||q;return await _e(e,a,o)===s}async function Ue(e,t){let r=await crypto.subtle.importKey("raw",new TextEncoder().encode(e),{name:"HMAC",hash:"SHA-256"},!1,["sign"]),a=await crypto.subtle.sign("HMAC",r,new TextEncoder().encode(t));return Z(a)}async function Re(e){let r=`admin.${Math.floor(Date.now()/1e3)+604800}`,a=await Ue(e,r);return`${r}.${a}`}async function $e(e,t){if(!e||!t)return!1;let r=String(e).split(".");if(r.length!==3)return!1;let[a,n,s]=r;if(a!=="admin")return!1;let o=Number(n);if(!Number.isFinite(o)||o<Date.now()/1e3)return!1;let c=await Ue(t,`${a}.${n}`);if(c.length!==s.length)return!1;let l=0;for(let i=0;i<c.length;i++)l|=c.charCodeAt(i)^s.charCodeAt(i);return l===0}function Oe(e){let t={};if(!e)return t;for(let r of e.split(";")){let a=r.indexOf("=");if(a<0)continue;let n=r.slice(0,a).trim(),s=r.slice(a+1).trim();t[n]=decodeURIComponent(s)}return t}async function Ot(e){try{let{results:t}=await e.prepare("SELECT key, value FROM settings").all(),r={};for(let a of t||[])r[a.key]=a.value;return r}catch{return{}}}async function Dt(e){try{let{results:t}=await e.prepare("SELECT id, uuid, remark, up, down, path, expire_at, traffic_limit, traffic_reset_at FROM vless_users WHERE enable = 1 ORDER BY id").all();return t||[]}catch{try{let{results:r}=await e.prepare("SELECT id, uuid, remark, up, down FROM vless_users WHERE enable = 1 ORDER BY id").all();return(r||[]).map(a=>({path:"",expire_at:0,traffic_limit:0,traffic_reset_at:0,...a}))}catch{return[]}}}async function Pt(e){try{let{results:t}=await e.prepare("SELECT id, password, remark, up, down, path, expire_at, traffic_limit, traffic_reset_at FROM trojan_users WHERE enable = 1 ORDER BY id").all();return t||[]}catch{try{let{results:r}=await e.prepare("SELECT id, password, remark, up, down FROM trojan_users WHERE enable = 1 ORDER BY id").all();return(r||[]).map(a=>({path:"",expire_at:0,traffic_limit:0,traffic_reset_at:0,...a}))}catch{return[]}}}function Ct(e){let t=String(e||"").trim();if(!t)return"";for(t.startsWith("/")||(t="/"+t);t.length>1&&t.endsWith("/");)t=t.slice(0,-1);return t}async function De(e,t,r){let a=Math.floor(Date.now()/1e3);for(let n of t)if(n.traffic_reset_at>0&&n.traffic_reset_at<=a)try{await e.prepare(`UPDATE ${r} SET up = 0, down = 0, traffic_reset_at = 0 WHERE id = ?`).bind(n.id).run(),n.up=0,n.down=0,n.traffic_reset_at=0}catch{}}function Nt(e,t,r){let a=new Map,n=(s,o)=>{let c=Ct(s);if(!c)return;a.has(c)||a.set(c,[]),a.get(c).push(o);let l=`${c}/Tun`;a.has(l)||a.set(l,[]),a.get(l).push(o)};n(e,{kind:"all"});for(let s of t)s.path&&n(s.path,{kind:"vless",credential:s.uuid.toLowerCase()});for(let s of r)s.path&&n(s.path,{kind:"trojan",credential:s.password});return a}async function Mt(e){try{let{results:t}=await e.prepare("SELECT * FROM outbounds WHERE enable = 1 ORDER BY sort ASC, id ASC").all();return t||[]}catch{return[]}}async function It(e){try{let{results:t}=await e.prepare("SELECT * FROM routing_rules WHERE enable = 1 ORDER BY sort ASC, id ASC").all();return t||[]}catch{return[]}}async function Ht(e){try{let a=await e.prepare("SELECT value FROM settings WHERE key = ?").bind("admin_password_hash").first();if(a&&a.value)return{hash:a.value,tempPassword:null}}catch{}let t=Ft().replace(/-/g,"").slice(0,12),r=await Ae(t);try{await e.prepare("INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at").bind("admin_password_hash",r,Date.now()).run()}catch{}return{hash:r,tempPassword:t}}async function Q(e,t,r={}){let{DB:a}=t,n=await Ot(a),s=n.ws_path||Te,o=n.entry_transport||ye,c=n.default_outbound||A,l=n.admin_password_hash||"",i=null;if(!l&&r.ensureAdmin){let T=await Ht(a);l=T.hash,i=T.tempPassword}let d=n.proxyip||"",m="",f=443;if(d){let T=d.lastIndexOf(":");T>0&&!d.includes("]")&&/^\d+$/.test(d.slice(T+1))?(m=d.slice(0,T),f=Number(d.slice(T+1))||443):m=d}let p=n.udp_outbound||"",b=n.entry_host||"",h=n.entry_port||"",u=n.entry_sni||"",g=n.entry_ws_host||"",w=await Dt(a),y=await Pt(a),x=await Mt(a),v=await It(a);await Promise.all([De(a,w,"vless_users"),De(a,y,"trojan_users")]);let k=Nt(s,w,y),_={};for(let T of w)_[T.uuid]=T;let S={};for(let T of y)S[T.password]=T;return{env:t,settings:n,wsPath:s,entryTransport:o,defaultOutbound:c,adminPasswordHash:l,adminTempPassword:i,proxyipHost:m,proxyipPort:f,proxyipDisabled:c!==A,udpOutbound:p,entryHost:b,entryPort:h,entrySni:u,entryWsHost:g,vlessUsers:w,trojanUsers:y,outbounds:x,routingRules:v,vlessIndex:_,trojanIndex:S,uuidSet:new Set(w.map(T=>T.uuid.toLowerCase())),passwordSet:new Set(y.map(T=>T.password)),outboundByName:x.reduce((T,fe)=>(T[fe.name]=fe,T),{}),inboundPathMap:k}}function Ft(){return globalThis.crypto&&typeof globalThis.crypto.randomUUID=="function"?globalThis.crypto.randomUUID():"xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(/[xy]/g,e=>{let t=Math.random()*16|0;return(e==="x"?t:t&3|8).toString(16)})}function jt(e){let t=r=>X[e[r]];return`${t(0)}${t(1)}${t(2)}${t(3)}-${t(4)}${t(5)}-${t(6)}${t(7)}-${t(8)}${t(9)}-${t(10)}${t(11)}${t(12)}${t(13)}${t(14)}${t(15)}`.toLowerCase()}function Pe(e,t){if(e.byteLength<24)return{hasError:!0,message:"invalid data"};let r=e instanceof Uint8Array?new DataView(e.buffer,e.byteOffset,e.byteLength):new DataView(e),a=r.getUint8(0),n=jt(new Uint8Array(e.slice(1,17)));if(!t.has(n))return{hasError:!0,message:"invalid user"};let o=18+r.getUint8(17);if(e.byteLength<o+4)return{hasError:!0,message:"invalid data"};let c=r.getUint8(o);if(c!==1&&c!==2)return{hasError:!0,message:`command ${c} is not supported`};let l=o+1,i=r.getUint16(l),d=r.getUint8(l+2),m,f,p;switch(d){case 1:f=4,p=l+3,m=Array.from(new Uint8Array(e.slice(p,p+f))).join(".");break;case 2:if(e.byteLength<l+4)return{hasError:!0,message:"invalid data"};f=r.getUint8(l+3),p=l+4,m=new TextDecoder().decode(e.slice(p,p+f));break;case 3:f=16,p=l+3,m=Array.from({length:8},(b,h)=>r.getUint16(p+h*2).toString(16)).join(":");break;default:return{hasError:!0,message:`invalid addressType: ${d}`}}return m?{hasError:!1,userUuid:n,addressRemote:m,addressType:d,portRemote:i,rawDataIndex:p+f,protocolVersion:new Uint8Array([a]),isUDP:c===2}:{hasError:!0,message:"addressValue is empty"}}function Ce(e,t,r,a,n){let s,o,c=[];switch(t){case 1:s=4,c=r.split(".").map(Number);break;case 2:o=new TextEncoder().encode(r),s=o.length+1;break;case 3:s=16,c=Bt(r).split(":").map(d=>[parseInt(d.slice(0,2),16),parseInt(d.slice(2),16)]).flat();break;default:throw new Error(`Unknown address type: ${t}`)}let l=n.replace(/-/g,""),i=new Uint8Array(22+s);i[0]=0;for(let d=0;d<l.length;d+=2)i[1+d/2]=parseInt(l.substr(d,2),16);return i[17]=0,i[18]=e,i[19]=a>>8,i[20]=a&255,i[21]=t,t===2?(i[22]=o.length,i.set(o,23)):i.set(c,22),i}function Bt(e){if(e=e.replace(/^\[|\]$/g,""),e.includes("::")){let t=e.split("::"),r=t[0]?t[0].split(":"):[],a=t[1]?t[1].split(":"):[],n=8-r.length-a.length,s=Array(Math.max(0,n)).fill("0");return[...r,...s,...a].map(o=>o.padStart(4,"0")).join(":")}return e.split(":").map(t=>t.padStart(4,"0")).join(":")}async function Gt(e){let t=new TextEncoder().encode(e),r=await crypto.subtle.digest({name:"SHA-224"},t);return Array.from(new Uint8Array(r)).map(a=>a.toString(16).padStart(2,"0")).join("")}var ee=new Map;function Wt(e){if(ee.has(e))return ee.get(e);let t=Gt(e);return ee.set(e,t),t}function Ne(e){if(e.byteLength<60)return!1;let t=new Uint8Array(e);return t[0]===0?!1:t[56]===13&&t[57]===10}async function Me(e,t){if(e.byteLength<60)return{hasError:!0,message:"Invalid Trojan data: too short"};let r=new Uint8Array(e),a=e instanceof Uint8Array?new DataView(e.buffer,e.byteOffset,e.byteLength):new DataView(e);if(r[56]!==13||r[57]!==10)return{hasError:!0,message:"Invalid Trojan header: missing CRLF"};let n=new TextDecoder().decode(r.slice(0,56)),s=null;for(let b of t)try{if(await Wt(b)===n){s=b;break}}catch{}if(!s)return{hasError:!0,message:"Invalid Trojan password"};let o=r[58];if(o!==1&&o!==3)return{hasError:!0,message:`Unsupported Trojan command: ${o}`};let c=r[59],l,i,d;switch(c){case 1:if(i=4,d=60,e.byteLength<d+i+2)return{hasError:!0,message:"Invalid Trojan header: IPv4 truncated"};l=Array.from(r.slice(d,d+i)).join(".");break;case 3:if(i=r[60],d=61,e.byteLength<d+i+2)return{hasError:!0,message:"Invalid Trojan header: domain truncated"};l=new TextDecoder().decode(r.slice(d,d+i));break;case 4:if(i=16,d=60,e.byteLength<d+i+2)return{hasError:!0,message:"Invalid Trojan header: IPv6 truncated"};l=Array.from({length:8},(b,h)=>a.getUint16(d+h*2).toString(16)).join(":");break;default:return{hasError:!0,message:`Invalid Trojan address type: ${c}`}}let m=d+i;if(e.byteLength<m+2)return{hasError:!0,message:"Invalid Trojan header: port truncated"};let f=a.getUint16(m),p=m+2;return e.byteLength<p+2?{hasError:!0,message:"Invalid Trojan header: missing final CRLF"}:r[p]!==13||r[p+1]!==10?{hasError:!0,message:"Invalid Trojan header: invalid final CRLF"}:{hasError:!1,userPassword:s,addressRemote:l,addressType:c===3?2:c,portRemote:f,rawDataIndex:p+2,isUDP:o===3}}function U(e){try{e&&e.readyState===1&&e.close()}catch{}}async function Ie(e,t){let r=e.sni&&e.sni!==""?e.sni:e.address,a=Number(e.port),n;try{n=globalThis.connect?globalThis.connect({hostname:r,port:a,secureTransport:e.tls?"on":"off"}):void 0}catch(i){return t(`[VLESS/raw] connect error: ${i.message}`),null}if(!n)return t("[VLESS/raw] connect unavailable"),null;let s=n.readable.getReader(),o,c=new Promise(i=>{o=i});return(n.closed||Promise.resolve()).then(o,o),{readable:new ReadableStream({start(i){(async()=>{try{for(;;){let{done:d,value:m}=await s.read();if(d)break;m&&m.byteLength>0&&i.enqueue(m)}try{i.close()}catch{}}catch(d){try{i.error(d)}catch{}}})()},cancel(){try{s.cancel()}catch{}}}),writable:n.writable,closed:c,send:async i=>{let d=n.writable.getWriter();try{await d.write(i)}finally{try{d.releaseLock()}catch{}}}}}function Vt(e,t){let r=new Uint8Array(e.length+t.length);return r.set(e,0),r.set(t,e.length),r}function zt(e){for(let t=0;t+3<e.length;t++)if(e[t]===13&&e[t+1]===10&&e[t+2]===13&&e[t+3]===10)return t;return-1}function Kt(e){for(let t=0;t+1<e.length;t++)if(e[t]===13&&e[t+1]===10)return new TextDecoder().decode(e.slice(0,t));return""}async function He(e,t){let r=e.sni&&e.sni!==""?e.sni:e.address,a=Number(e.port),n;try{n=globalThis.connect?globalThis.connect({hostname:r,port:a,secureTransport:e.tls?"on":"off"}):void 0}catch(b){return t(`[VLESS/httpupgrade] connect error: ${b.message}`),null}if(!n)return t("[VLESS/httpupgrade] connect unavailable"),null;let o=`GET ${e.path&&e.path.startsWith("/")?e.path:`/${e.path||""}`} HTTP/1.1\r
Host: ${r}:${a}\r
Connection: Upgrade\r
Upgrade: websocket\r
\r
`,c=n.readable.getReader(),l,i=new Promise(b=>{l=b});(n.closed||Promise.resolve()).then(l,l);let d=new Uint8Array(0),m=new Uint8Array(0);try{await Promise.race([(async()=>{let b=n.writable.getWriter();try{await b.write(new TextEncoder().encode(o))}finally{try{b.releaseLock()}catch{}}for(;;){let{done:h,value:u}=await c.read();if(h)break;if(u&&u.byteLength>0){d=Vt(d,u);let g=zt(d);if(g>=0){m=d.slice(g+4);return}}}throw new Error("connection closed during handshake")})(),new Promise((b,h)=>setTimeout(()=>h(new Error("Handshake timeout")),1e4))])}catch(b){t(`[VLESS/httpupgrade] handshake failed: ${b.message}`);try{n.close()}catch{}return null}let f=Kt(d);if(!/^HTTP\/1\.1 101/.test(f)){t(`[VLESS/httpupgrade] upgrade rejected: ${f}`);try{n.close()}catch{}return null}return{readable:new ReadableStream({start(b){m.byteLength>0&&b.enqueue(m),(async()=>{try{for(;;){let{done:h,value:u}=await c.read();if(h)break;u&&u.byteLength>0&&b.enqueue(u)}try{b.close()}catch{}}catch(h){try{b.error(h)}catch{}}})()},cancel(){try{c.cancel()}catch{}}}),writable:n.writable,closed:i,send:async b=>{let h=n.writable.getWriter();try{await h.write(b)}finally{try{h.releaseLock()}catch{}}}}}var Yt=`PRI * HTTP/2.0\r
\r
SM\r
\r
`;var te=new TextEncoder;function Jt(e,t){let r=te.encode(e),a=te.encode(t),n=new Uint8Array(2+r.length+1+a.length);return n[0]=0,n[1]=r.length,n.set(r,2),n[2+r.length]=a.length,n.set(a,3+r.length),n}function Xt(e){let t=new Uint8Array(0);for(let[r,a]of e)t=N(t,Jt(r,a));return t}function R(e,t,r,a){let n=a.length,s=new Uint8Array(9+n);return s[0]=n>>16&255,s[1]=n>>8&255,s[2]=n&255,s[3]=e,s[4]=t,s[5]=r>>24&127,s[6]=r>>16&255,s[7]=r>>8&255,s[8]=r&255,s.set(a,9),s}function Fe(e){let t=new Uint8Array(5+e.length);return t[0]=0,new DataView(t.buffer,t.byteOffset,5).setUint32(1,e.length,!1),t.set(e,5),t}function je(e){let t=new Uint8Array(4);return new DataView(t.buffer).setUint32(0,e>>>0,!1),t}function N(e,t){let r=new Uint8Array(e.length+t.length);return r.set(e,0),r.set(t,e.length),r}async function Be(e,t){let r=[],a=0;for(;a<t;){let{done:s,value:o}=await e.read();if(s)return null;!o||o.byteLength===0||(r.push(o),a+=o.byteLength)}let n;if(r.length===1)n=r[0];else{n=N(r[0],r[1]);for(let s=2;s<r.length;s++)n=N(n,r[s])}return n.byteLength>t?{data:n.slice(0,t),extra:n.slice(t)}:{data:n,extra:null}}async function Ge(e,t){let r=e.sni&&e.sni!==""?e.sni:e.address,a=Number(e.port),n;try{n=globalThis.connect?globalThis.connect({hostname:r,port:a,secureTransport:e.tls?"on":"off"}):void 0}catch(h){return t(`[VLESS/grpc] connect error: ${h.message}`),null}if(!n)return t("[VLESS/grpc] connect unavailable"),null;let s=n.writable.getWriter();async function o(h){await s.write(h)}let c,l=new Promise(h=>{c=h});(n.closed||Promise.resolve()).then(c,c);try{await o(te.encode(Yt)),await o(R(4,0,0,new Uint8Array(0)));let h=e.tls?"https":"http",u=(e.path||"").replace(/^\/+/,"").replace(/\/+$/,""),g=u?`/${u}/Tun`:"/Tun",w=Xt([[":method","POST"],[":scheme",h],[":path",g],[":authority",`${r}:${a}`],["content-type","application/grpc"],["te","trailers"],["user-agent","grpc-go/1.68.0"]]);await o(R(1,4,1,w))}catch(h){t(`[VLESS/grpc] handshake failed: ${h.message}`);try{n.close()}catch{}return null}let i=n.readable.getReader(),d={needLen:5,buf:new Uint8Array(0),msgLen:0,controller:null,extra:null};function m(h,u){let g=h;for(;g.byteLength>0;)if(d.needLen>0){let w=Math.min(d.needLen,g.byteLength);d.buf=N(d.buf,g.slice(0,w)),g=g.slice(w),d.needLen-=w,d.needLen===0&&(d.buf.byteLength===5?(d.msgLen=new DataView(d.buf.buffer,d.buf.byteOffset,5).getUint32(1,!1),d.buf=new Uint8Array(0),d.needLen=d.msgLen,d.msgLen===0&&(d.needLen=5)):(d.buf=new Uint8Array(0),d.needLen=5))}else{let w=Math.min(d.msgLen,g.byteLength);if(d.buf=N(d.buf,g.slice(0,w)),g=g.slice(w),d.msgLen-=w,d.msgLen===0){if(d.buf.byteLength>0)try{u.enqueue(d.buf)}catch{}d.buf=new Uint8Array(0),d.needLen=5}}}let f=new ReadableStream({start(h){d.controller=h,(async()=>{try{for(;;){let u;if(d.extra)u=d.extra,d.extra=null;else{let g=await Be(i,9);if(!g)break;let w=g.data[0]<<16|g.data[1]<<8|g.data[2],y=g.data[3],x=g.data[4],v=(g.data[5]&127)<<24|g.data[6]<<16|g.data[7]<<8|g.data[8];if(w===0)u=new Uint8Array(0);else{let k=await Be(i,w);if(!k)break;u=k.data,d.extra=k.extra}if(y===0&&v===1){m(u,h),await o(R(8,0,1,je(u.byteLength))),await o(R(8,0,0,je(u.byteLength)));continue}if(y===4){x&1||await o(R(4,1,0,new Uint8Array(0)));continue}if(y===6){x&1||await o(R(6,1,v,u));continue}if(y===7||y===3)break}}try{h.close()}catch{}}catch(u){t(`[VLESS/grpc] read loop error: ${u.message}`);try{h.error(u)}catch{}}finally{try{c()}catch{}}})()},cancel(){try{i.cancel()}catch{}}});function p(h){let u=[],g=0,w=!0;for(;g<h.byteLength;){let y=Math.min(16384,h.byteLength-g);u.push(R(0,0,1,h.slice(g,g+y))),g+=y,w=!1}return u}let b=new WritableStream({write(h){let u=h instanceof Uint8Array?h:new Uint8Array(h),g=Fe(u),w=p(g);return(async()=>{for(let y of w)await o(y)})()},close(){try{n.close()}catch{}},abort(){try{n.close()}catch{}}});return{readable:f,writable:b,closed:l,send:async h=>{let u=Fe(h);for(let g of p(u))await o(g)}}}var qt=`PRI * HTTP/2.0\r
\r
SM\r
\r
`;var re=new TextEncoder;function Zt(e,t){let r=re.encode(e),a=re.encode(t),n=new Uint8Array(2+r.length+1+a.length);return n[0]=0,n[1]=r.length,n.set(r,2),n[2+r.length]=a.length,n.set(a,3+r.length),n}function Qt(e){let t=new Uint8Array(0);for(let[r,a]of e)t=ne(t,Zt(r,a));return t}function $(e,t,r,a){let n=a.length,s=new Uint8Array(9+n);return s[0]=n>>16&255,s[1]=n>>8&255,s[2]=n&255,s[3]=e,s[4]=t,s[5]=r>>24&127,s[6]=r>>16&255,s[7]=r>>8&255,s[8]=r&255,s.set(a,9),s}function We(e){let t=new Uint8Array(4);return new DataView(t.buffer).setUint32(0,e>>>0,!1),t}function ne(e,t){let r=new Uint8Array(e.length+t.length);return r.set(e,0),r.set(t,e.length),r}async function Ve(e,t){let r=[],a=0;for(;a<t;){let{done:s,value:o}=await e.read();if(s)return null;!o||o.byteLength===0||(r.push(o),a+=o.byteLength)}let n;if(r.length===1)n=r[0];else{n=ne(r[0],r[1]);for(let s=2;s<r.length;s++)n=ne(n,r[s])}return n.byteLength>t?{data:n.slice(0,t),extra:n.slice(t)}:{data:n,extra:null}}async function ze(e,t){let r=e.sni&&e.sni!==""?e.sni:e.address,a=Number(e.port),n;try{n=globalThis.connect?globalThis.connect({hostname:r,port:a,secureTransport:e.tls?"on":"off"}):void 0}catch(p){return t(`[VLESS/h2] connect error: ${p.message}`),null}if(!n)return t("[VLESS/h2] connect unavailable"),null;let s=n.writable.getWriter();async function o(p){await s.write(p)}let c,l=new Promise(p=>{c=p});(n.closed||Promise.resolve()).then(c,c);try{await o(re.encode(qt)),await o($(4,0,0,new Uint8Array(0)));let p=e.tls?"https":"http",b=e.path&&e.path.startsWith("/")?e.path:`/${e.path||""}`,h=Qt([[":method","POST"],[":scheme",p],[":path",b],[":authority",`${r}:${a}`],["content-length","0"],["user-agent","vless-h2/1.0.0"]]);await o($(1,4,1,h))}catch(p){t(`[VLESS/h2] handshake failed: ${p.message}`);try{n.close()}catch{}return null}let i=n.readable.getReader(),d=new ReadableStream({start(p){(async()=>{let b=null;try{for(;;){let h;if(b)h=b,b=null;else{let u=await Ve(i,9);if(!u)break;let g=u.data[0]<<16|u.data[1]<<8|u.data[2],w=u.data[3],y=u.data[4],x=(u.data[5]&127)<<24|u.data[6]<<16|u.data[7]<<8|u.data[8];if(g===0)h=new Uint8Array(0);else{let v=await Ve(i,g);if(!v)break;h=v.data,b=v.extra}if(w===0&&x===1){if(h.byteLength>0)try{p.enqueue(h)}catch{}await o($(8,0,1,We(h.byteLength))),await o($(8,0,0,We(h.byteLength)));continue}if(w===4){y&1||await o($(4,1,0,new Uint8Array(0)));continue}if(w===6){y&1||await o($(6,1,x,h));continue}if(w===7||w===3)break}}try{p.close()}catch{}}catch(h){t(`[VLESS/h2] read loop error: ${h.message}`);try{p.error(h)}catch{}}finally{try{c()}catch{}}})()},cancel(){try{i.cancel()}catch{}}});function m(p){let b=[],h=0;for(;h<p.byteLength;){let u=Math.min(16384,p.byteLength-h);b.push($(0,0,1,p.slice(h,h+u))),h+=u}return b}let f=new WritableStream({write(p){let b=p instanceof Uint8Array?p:new Uint8Array(p);return(async()=>{for(let h of m(b))await o(h)})()},close(){try{n.close()}catch{}},abort(){try{n.close()}catch{}}});return{readable:d,writable:f,closed:l,send:async p=>{for(let b of m(p))await o(b)}}}var er=1e4;async function O(e,t,r,a,n,s,o){let c=e.transport||ge;if(!we.includes(c))return o(`[VLESS] unsupported transport: ${c}`),null;let l=null;try{c==="ws"?l=await tr(e,o):c==="raw"?l=await Ie(e,o):c==="httpupgrade"?l=await He(e,o):c==="grpc"?l=await Ge(e,o):c==="h2"&&(l=await ze(e,o))}catch(f){return o(`[VLESS/${c}] connect failed: ${f.message}`),null}if(!l)return null;let i=Ce(t,r,a,n,e.uuid),d=s instanceof Uint8Array?s:new Uint8Array(s||0),m=new Uint8Array(i.length+d.length);m.set(i,0),m.set(d,i.length);try{await l.send(m)}catch(f){o(`[VLESS/${c}] send header failed: ${f.message}`);try{l.close&&await l.close()}catch{}return null}return{readable:l.readable,writable:l.writable,closed:l.closed}}async function tr(e,t){let r=e.tls?"wss":"ws",a=e.path&&e.path.startsWith("/")?e.path:`/${e.path||""}`,n=e.sni&&e.sni!==""?e.sni:e.address,s=`${r}://${n}:${e.port}${a}`,o;try{o=new WebSocket(s),"binaryType"in o&&(o.binaryType="arraybuffer")}catch(f){return t(`[VLESS/ws] create ws failed: ${f.message}`),null}let c,l=new Promise(f=>{c=f});try{await new Promise((f,p)=>{let b=setTimeout(()=>p(new Error("Connection timeout")),er);o.addEventListener("open",()=>{clearTimeout(b),f()}),o.addEventListener("close",h=>{clearTimeout(b),p(new Error(`closed ${h.code}`))}),o.addEventListener("error",()=>{clearTimeout(b),p(new Error("ws error"))})})}catch(f){t(`[VLESS/ws] connect failed: ${f.message}`);try{o.close()}catch{}return c(),null}o.addEventListener("close",()=>c()),o.addEventListener("error",()=>{});let i=new WritableStream({write(f){o.readyState===1&&o.send(f)},close(){U(o)},abort(){U(o)}}),d=!1;return{readable:new ReadableStream({start(f){o.addEventListener("message",p=>{let b;try{p.data instanceof ArrayBuffer?b=new Uint8Array(p.data):ArrayBuffer.isView(p.data)?b=new Uint8Array(p.data.buffer,p.data.byteOffset,p.data.byteLength):typeof p.data=="string"?b=new TextEncoder().encode(p.data):b=null}catch{b=null}if(b){if(!d&&(d=!0,b.length>=2&&b[0]===0)){let h=b[1];if(b.length>2+h)b=b.slice(2+h);else return}if(b.length>0)try{f.enqueue(b)}catch{}}}),o.addEventListener("close",()=>{try{f.close()}catch{}}),o.addEventListener("error",p=>{try{f.error(p)}catch{}})},cancel(){U(o)}}),writable:i,closed:l,send:async f=>{if(o.readyState!==1)throw new Error(`ws not open (state=${o.readyState})`);o.send(f)}}}async function M(e,t,r){for(;t.buf.length<r;){let{done:n,value:s}=await e.read();if(n)return null;if(!s||s.byteLength===0)continue;let o=new Uint8Array(t.buf.length+s.byteLength);o.set(t.buf,0),o.set(s,t.buf.length),t.buf=o}let a=t.buf.slice(0,r);return t.buf=t.buf.slice(r),a}async function Ke(e,t,r,a,n,s){let{username:o,password:c,hostname:l,port:i}=n,d=s({hostname:l,port:i}),m=d.writable.getWriter(),f=d.readable.getReader(),p=new TextEncoder,b={buf:new Uint8Array(0)};try{await m.write(new Uint8Array([5,2,0,2]));let h=await M(f,b,2);if(!h||h[0]!==5){a("socks version error");return}if(h[1]===255){a("no acceptable methods");return}if(h[1]===2){if(!o||!c){a("socks server requires auth but no credentials");return}let v=new Uint8Array([1,o.length,...p.encode(o),c.length,...p.encode(c)]);if(await m.write(v),h=await M(f,b,2),!h||h[0]!==1||h[1]!==0){a("socks auth failed");return}}let u;switch(e){case 1:u=new Uint8Array([1,...t.split(".").map(Number)]);break;case 2:u=new Uint8Array([3,t.length,...p.encode(t)]);break;case 3:u=new Uint8Array([4,...t.split(":").flatMap(v=>[parseInt(v.slice(0,2),16),parseInt(v.slice(2),16)])]);break;default:a(`invalid addressType ${e}`);return}let g=new Uint8Array([5,1,0,...u,r>>8,r&255]);await m.write(g);let w=await M(f,b,4);if(!w||w[0]!==5){a("socks version error");return}if(w[1]!==0){a(`socks connect failed rep=${w[1]}`);return}let y=0;switch(w[3]){case 1:y=6;break;case 3:y=3;break;case 4:y=18;break;default:a(`socks invalid ATYP ${w[3]}`);return}if(w[3]===3){let v=await M(f,b,1);if(!v)return;y+=v[0]}if(!await M(f,b,y))return;if(m.releaseLock(),b.buf.length>0){let v=b.buf.slice();return{readable:new ReadableStream({pull(_){if(v.length>0){let S=v;v=new Uint8Array(0),_.enqueue(S);return}return f.read().then(({done:S,value:T})=>{S?_.close():T&&T.byteLength>0&&_.enqueue(T)})},cancel(){try{f.cancel()}catch{}}}),writable:d.writable,closed:d.closed||Promise.resolve()}}return f.releaseLock(),d}catch(h){a(`socks5 error: ${h.message}`);try{m.releaseLock()}catch{}try{f.releaseLock()}catch{}try{d.close()}catch{}return}}function Ye(e,t={}){let r=String(e||"").trim().replace(/^socks5?:\/\//i,""),[a,n]=r.split("@").reverse(),s,o,c,l;if(n){let d=n.split(":");if(d.length!==2)throw new Error("Invalid SOCKS address format");[s,o]=d}let i=a.split(":");if(l=Number(i[i.length-1]),isNaN(l))if(t&&t.port!==void 0&&t.port!==null&&t.port!=="")l=Number(t.port),c=a;else throw new Error("Invalid SOCKS address format");else c=i.slice(0,-1).join(":");if(isNaN(l)||!c)throw new Error("Invalid SOCKS address format");return t&&t.username!==void 0&&t.username!==null&&t.username!==""&&(s=t.username),t&&t.password!==void 0&&t.password!==null&&t.password!==""&&(o=t.password),{username:s,password:o,hostname:c,port:l}}async function Je(e,t,r,a,n,s,o=new Uint8Array(0)){let{username:c,password:l,hostname:i,port:d}=n,m=s({hostname:i,port:d}),f=m.writable.getWriter(),p=m.readable.getReader();try{let b=c&&l?`Proxy-Authorization: Basic ${btoa(`${c}:${l}`)}\r
`:"",h=`CONNECT ${t}:${r} HTTP/1.1\r
Host: ${t}:${r}\r
${b}User-Agent: Mozilla/5.0\r
Connection: keep-alive\r
\r
`;await f.write(new TextEncoder().encode(h));let u=new Uint8Array(0),g=-1,w=0;for(;g===-1&&w<8192;){let{done:k,value:_}=await p.read();if(k)throw new Error("Connection closed before HTTP response");let S=new Uint8Array(u.length+_.length);S.set(u,0),S.set(_,u.length),u=S,w=u.length;for(let T=0;T<u.length-3;T++)if(u[T]===13&&u[T+1]===10&&u[T+2]===13&&u[T+3]===10){g=T+4;break}}if(g===-1)throw new Error("Invalid HTTP response");let x=new TextDecoder().decode(u.slice(0,g)).split(`\r
`)[0].match(/HTTP\/\d\.\d\s+(\d+)/);if(!x)throw new Error("Invalid HTTP response format");let v=parseInt(x[1]);if(v<200||v>=300)throw new Error(`HTTP CONNECT failed: HTTP ${v}`);return o.length>0&&await f.write(o),f.releaseLock(),p.releaseLock(),m}catch(b){a(`http connect error: ${b.message}`);try{f.releaseLock()}catch{}try{p.releaseLock()}catch{}try{m.close()}catch{}return}}function Xe(e,t={}){let[r,a]=String(e||"").trim().split("@").reverse(),n,s,o,c;if(a){let i=a.split(":");if(i.length!==2)throw new Error("Invalid HTTP address format");[n,s]=i}let l=r.split(":");if(c=Number(l[l.length-1]),isNaN(c))if(t&&t.port!==void 0&&t.port!==null&&t.port!=="")c=Number(t.port),o=r;else throw new Error("Invalid HTTP address format");else o=l.slice(0,-1).join(":");if(isNaN(c)||!o)throw new Error("Invalid HTTP address format");return t&&t.username!==void 0&&t.username!==null&&t.username!==""&&(n=t.username),t&&t.password!==void 0&&t.password!==null&&t.password!==""&&(s=t.password),{username:n,password:s,hostname:o,port:c}}async function qe(e,t,r,a,n){let s=e.proxyipHost&&!e.proxyipDisabled,o=s?e.proxyipHost:t,c=s?Number(e.proxyipPort||443):r,l=globalThis.connect?globalThis.connect({hostname:o,port:c}):void 0;if(!l)return n("connect unavailable"),null;if(a&&a.length>0){let i=l.writable.getWriter();try{await i.write(a)}catch(d){n(`direct initial write error: ${d.message}`)}finally{try{i.releaseLock()}catch{}}}return l}async function I(e){let{config:t,outbound:r,addressType:a,addressRemote:n,portRemote:s,rawClientData:o,log:c,isUDP:l}=e,i=r;if(!i||i===A)return qe(t,n,s,o,c);if(i===W)return c("rejected by routing rule"),null;switch(i.type){case A:return qe(t,n,s,o,c);case he:{let d;try{d=Ye(i.address,{username:i.username,password:i.password,port:i.port})}catch(f){return c(`bad socks5 address: ${f.message}`),null}let m=await Ke(a,n,s,c,d,globalThis.connect);if(!m)return null;if(o&&o.length>0){let f=m.writable.getWriter();try{await f.write(o)}catch(p){c(`socks5 write error: ${p.message}`)}finally{try{f.releaseLock()}catch{}}}return m}case me:{let d;try{d=Xe(i.address,{username:i.username,password:i.password,port:i.port})}catch(f){return c(`bad http address: ${f.message}`),null}return await Je(a,n,s,c,d,globalThis.connect,o||new Uint8Array(0))}case be:return O({address:i.address,port:Number(i.port),uuid:i.uuid,path:i.path,tls:!!i.tls,sni:i.sni||"",transport:i.transport},l?2:1,a,n,s,o||new Uint8Array(0),c);default:return c(`unknown outbound type: ${i.type}`),null}}function H(e,t){return!t||t===A?A:t===W?W:e.outboundByName[t]||A}var rr=60*60*1e3,ae=new Map;async function se(e,t,r){let a=`${t}:${r}`,n=ae.get(a);if(n&&Date.now()-n.ts<rr)return n.data;let s=null;try{let o=t==="geosite"?xe:ve,c=await e.GEO_KV.get(o+r);if(c){let l=JSON.parse(c);Array.isArray(l)&&(s=l)}}catch{}return s||(s=nr(t,r)),ae.set(a,{data:s,ts:Date.now()}),s}function nr(e,t){if(e==="geosite")switch(t){case"cn":return Ee;case"speedtest":return ke;case"google":return Se;default:return[]}return[]}function Ze(){ae.clear()}function ar(e){if(!e)return null;let t=String(e).trim();if(!t)return null;let r=t.match(/^geosite:(.+)$/i);if(r){let i=r[1].split(",").map(d=>d.trim()).filter(Boolean);return i.length===0?null:{type:"geosite",categories:i}}let a=t.match(/^geoip:(.+)$/i);if(a){let i=a[1].split(",").map(d=>d.trim()).filter(Boolean);return i.length===0?null:{type:"geoip",categories:i}}let n=t.match(/^domain:(.+)$/i);if(n)return{type:"domain",value:n[1].trim()};let s=t.match(/^full:(.+)$/i);if(s)return{type:"full",value:s[1].trim()};let o=t.match(/^keyword:(.+)$/i);if(o)return{type:"keyword",value:o[1].trim()};let c=t.match(/^ip-cidr:(.+)$/i);if(c)return{type:"ip-cidr",value:c[1].trim()};let l=t.match(/^regexp:(.+)$/i);return l?{type:"regexp",value:l[1].trim()}:{type:"domain",value:t}}function Qe(e){let t=e.split(".");if(t.length!==4)return null;let r=0;for(let a of t){let n=Number(a);if(isNaN(n)||n<0||n>255)return null;r=r<<8|n}return r>>>0}function et(e,t){let[r,a]=t.split("/"),n=a!==void 0?Number(a):32,s=Qe(e);if(s===null)return!1;let o=Qe(r);if(o===null)return!1;let c=n<=0?0:4294967295<<32-n>>>0;return(s&c)===(o&c)}function tt(e,t){let r=e.toLowerCase(),a=t.toLowerCase();return r===a?!0:r.endsWith("."+a)||r.endsWith(a)}var rt=new Map;function sr(e){let t=rt.get(e);if(!t){try{t=new RegExp(e)}catch{t=null}rt.set(e,t)}return t}async function or(e,t,r,a){switch(e.type){case"domain":return r?!1:tt(t,e.value);case"full":return r?!1:t.toLowerCase()===e.value.toLowerCase();case"keyword":return r?!1:t.toLowerCase().includes(e.value.toLowerCase());case"regexp":{if(r)return!1;let n=sr(e.value);return n?n.test(t):!1}case"ip-cidr":return r?et(t,e.value):!1;case"geosite":{if(r)return!1;for(let n of e.categories){let s=await se(a,"geosite",n);for(let o of s)if(tt(t,o))return!0}return!1}case"geoip":{if(!r)return!1;for(let n of e.categories){let s=await se(a,"geoip",n);for(let o of s)if(et(t,o))return!0}return!1}default:return!1}}async function z(e,t,r){let a=t===1||t===3;for(let n of e.routingRules){let s=ar(n.rule);if(!s)continue;if(await or(s,r,a,e.env))return{outbound:n.outbound||"direct",rule:n}}return{outbound:e.defaultOutbound||"direct",rule:null}}async function F(e,t,r,a){let n;try{n=await a.read()}catch(g){r(`read first packet error: ${g.message}`);try{await a.close()}catch{}return}if(!n){try{await a.close()}catch{}return}let s,o=null,c="vless",l=e._inboundScope||null,i=l&&!l.all?l.vless:e.uuidSet,d=l&&!l.all?l.trojan:e.passwordSet;if(Ne(n)){if(s=await Me(n,d),s.hasError){r(`trojan header error: ${s.message}`);try{await a.close()}catch{}return}c="trojan",o=e.trojanIndex[s.userPassword]||null}else{if(s=Pe(n,i),s.hasError){r(`vless header error: ${s.message}`);try{await a.close()}catch{}return}try{await a.write(new Uint8Array([0,0]))}catch{}o=e.vlessIndex[s.userUuid]||null}if(o){let g=Math.floor(Date.now()/1e3);if(o.expire_at>0&&o.expire_at<g){r(`${c} user '${o.remark||o.uuid||o.password}' expired`);try{await a.close()}catch{}return}if(o.traffic_limit>0&&Number(o.up)+Number(o.down)>=Number(o.traffic_limit)){r(`${c} user '${o.remark||o.uuid||o.password}' traffic limit reached`);try{await a.close()}catch{}return}}let{addressType:m,addressRemote:f,portRemote:p,isUDP:b}=s,h=new Uint8Array(n.slice(s.rawDataIndex)),u;try{u=await z(e,m,f)}catch(g){r(`route error: ${g.message}`);try{await a.close()}catch{}return}b?await cr(a,e,m,f,p,h,o,c,u,r):await ir(a,e,m,f,p,h,o,c,u,r)}async function ir(e,t,r,a,n,s,o,c,l,i){let d=H(t,l.outbound),m=s&&s.length>0?s:new Uint8Array(0),f=[d];d!=="direct"&&d!=="reject"&&f.push("direct");let p=null,b=null;for(let x of f){try{p=await I({config:t,outbound:x,addressType:r,addressRemote:a,portRemote:n,rawClientData:m,log:i})}catch(v){b=v,p=null}if(p)break}if(!p){i(`tcp connect failed: ${b?b.message:"no outbound available"}`);try{await e.close()}catch{}return}let h=0,u=0,g=!1,w=p.writable.getWriter(),y=(async()=>{try{for(;;){let x=await e.read();if(x==null)break;x.byteLength!==0&&(h+=x.byteLength,await w.write(x))}}catch(x){i(`upstream read error: ${x.message}`)}})();try{let x=p.readable.getReader();for(;;){let{done:v,value:k}=await x.read();if(v)break;k&&k.byteLength>0&&(u+=k.byteLength,await e.write(k))}}catch(x){i(`tcp remote read error: ${x.message}`)}g=!0;try{w.releaseLock()}catch{}try{await p.writable.close()}catch{}try{await e.close()}catch{}await y.catch(()=>{}),await nt(t,o,c,h,u,i)}async function cr(e,t,r,a,n,s,o,c,l,i){let d=null,m=(t.udpOutbound||"").trim();if(m){let w=t.outboundByName[m];if(w&&w.type==="vless")d=w;else{i(`udp outbound '${m}' not found or not vless (only vless supports udp)`);try{await e.close()}catch{}return}}else{if(l.outbound&&l.outbound!=="direct"&&l.outbound!=="reject"){let w=H(t,l.outbound);w!=="direct"&&w!=="reject"&&w.type==="vless"&&(d=w)}d||(d=t.outbounds.find(w=>w.type==="vless"))}if(!d){i("udp requires a vless outbound, none configured");try{await e.close()}catch{}return}let f=s&&s.length>0?s:new Uint8Array([0,0]),p=await O({address:d.address,port:Number(d.port),uuid:d.uuid,path:d.path,tls:!!d.tls,sni:d.sni||"",transport:d.transport||"ws"},2,r,a,n,f,i);if(!p){i("udp vless outbound connect failed");try{await e.close()}catch{}return}let b=0,h=0,u=p.writable.getWriter(),g=(async()=>{try{for(;;){let w=await e.read();if(w==null)break;w.byteLength!==0&&(b+=w.byteLength,await u.write(w))}}catch(w){i(`udp upstream read error: ${w.message}`)}})();try{let w=p.readable.getReader();for(;;){let{done:y,value:x}=await w.read();if(y)break;x&&x.byteLength>0&&(h+=x.byteLength,await e.write(x))}}catch(w){i(`udp read error: ${w.message}`)}try{u.releaseLock()}catch{}try{await p.writable.close()}catch{}try{await e.close()}catch{}await g.catch(()=>{}),await nt(t,o,c,b,h,i)}async function nt(e,t,r,a,n,s){if(!t)return;let o=r==="vless"?"vless_users":"trojan_users";try{await e.env.DB.prepare(`UPDATE ${o} SET up = up + ?, down = down + ? WHERE id = ?`).bind(a,n,t.id).run()}catch(c){s(`record traffic error: ${c.message}`)}}function lr(e){return e instanceof ArrayBuffer?new Uint8Array(e):ArrayBuffer.isView(e)?new Uint8Array(e.buffer,e.byteOffset,e.byteLength):typeof e=="string"?new TextEncoder().encode(e):null}async function at(e,t,r){let a=e.headers.get("Upgrade");if(!a||a.toLowerCase()!=="websocket")return new Response("Expected WebSocket",{status:400});let[n,s]=Object.values(new WebSocketPair);s.accept();let o=(...c)=>console.log("[ws]",...c);return F(t,r,o,dr(s,o)).catch(c=>{o(`ws handler error: ${c.message||c}`),U(s)}),new Response(null,{status:101,webSocket:n})}function dr(e,t){let r=[],a=[],n=!1,s=l=>{let i=lr(l.data);if(!i||i.byteLength===0)return;let d=a.shift();d?d(i):r.push(i)},o=()=>{if(!n)for(n=!0;a.length;)a.shift()(null)},c=()=>o();return e.addEventListener("message",s),e.addEventListener("close",o),e.addEventListener("error",c),{read(){return r.length?Promise.resolve(r.shift()):n?Promise.resolve(null):new Promise(l=>a.push(l))},write(l){if(e.readyState===1)try{e.send(l)}catch{}},close(){U(e)}}}function oe(e,t){let r=new Uint8Array(e.length+t.length);return r.set(e,0),r.set(t,e.length),r}function ur(e){let t=new Uint8Array(5);return t[0]=0,t[1]=e>>>24&255,t[2]=e>>>16&255,t[3]=e>>>8&255,t[4]=e&255,t}function pr(e){return oe(ur(e.byteLength),e)}async function st(e,t,r){let a=(...i)=>console.log("[h2-in]",...i);if(!e.body)return new Response("Bad Request",{status:400});let n=e.body.getReader(),{readable:s,writable:o}=new TransformStream,c=o.getWriter();return F(t,r,a,{read:async()=>{let i=new Uint8Array(0);for(;;){let{done:d,value:m}=await n.read();if(d)return i.byteLength>0?i:null;if(i=oe(i,m instanceof Uint8Array?m:new Uint8Array(m)),i.byteLength>=60)return i}},write:i=>c.write(i),close:async()=>{try{await n.cancel()}catch{}try{await c.close()}catch{}}}).catch(i=>{a(`h2 handler error: ${i.message||i}`),n.cancel().catch(()=>{}),c.close().catch(()=>{})}),new Response(s,{status:200,headers:{"Content-Type":"application/octet-stream","Cache-Control":"no-store"}})}async function ot(e,t,r){let a=(...d)=>console.log("[grpc-in]",...d);if(!e.body)return new Response("Bad Request",{status:400});let n=e.body.getReader(),{readable:s,writable:o}=new TransformStream,c=o.getWriter(),l=new Uint8Array(0);return F(t,r,a,{read:async()=>{for(;;){if(l.byteLength>=5){let f=l[1]<<24|l[2]<<16|l[3]<<8|l[4];if(l.byteLength>=5+f){let p=l.slice(5,5+f);return l=l.slice(5+f),p}}let{done:d,value:m}=await n.read();if(d){if(l.byteLength===0)return null;let f=l;return l=new Uint8Array(0),f}l=oe(l,m instanceof Uint8Array?m:new Uint8Array(m))}},write:d=>c.write(pr(d instanceof Uint8Array?d:new Uint8Array(d))),close:async()=>{try{await n.cancel()}catch{}try{await c.close()}catch{}}}).catch(d=>{a(`grpc handler error: ${d.message||d}`),n.cancel().catch(()=>{}),c.close().catch(()=>{})}),new Response(s,{status:200,headers:{"Content-Type":"application/grpc","Cache-Control":"no-store"}})}var it="ed=2560",j="random";function D(e){let t=e.startsWith("/")?e:`/${e}`;return/\?/.test(t)?`${t}&${it}`:`${t}?${it}`}function K(e){return(e.startsWith("/")?e:`/${e}`).replace(/\/+$/,"").replace(/^\//,"")}function B(e){let t=e.transport||"ws",r=e.wsHost||e.host,a=e.sni||(e.tls?r:""),n=new URLSearchParams({encryption:"none",type:t,host:r,security:e.tls?"tls":"none"});t==="grpc"?n.set("serviceName",`/${K(e.wsPath)}`):n.set("path",D(e.wsPath)),e.tls&&a&&n.set("sni",a),e.tls&&n.set("fp",e.fp||j);let s=encodeURIComponent(e.remark||`${e.host}:${e.port}`);return`vless://${e.uuid}@${e.host}:${e.port}?${n.toString()}#${s}`}function G(e){let t=e.transport||"ws",r=e.wsHost||e.host,a=e.sni||(e.tls?r:""),n=new URLSearchParams({type:t,host:r,security:e.tls?"tls":"none"});t==="grpc"?n.set("serviceName",`/${K(e.wsPath)}`):n.set("path",D(e.wsPath)),e.tls&&a&&n.set("sni",a),e.tls&&n.set("fp",e.fp||j);let s=encodeURIComponent(e.remark||`${e.host}:${e.port}`);return`trojan://${encodeURIComponent(e.password)}@${e.host}:${e.port}?${n.toString()}#${s}`}function ct(e){let t=e.headers.get("Host");return t?t.split(":")[0]:"example.com"}var L=["ws","grpc","h2"];function fr(e,t){let r=[],a=t.port||(t.tls?443:80);for(let n of e.vlessUsers){let s=n.path||e.wsPath;for(let o of L)r.push(B({uuid:n.uuid,host:t.host,port:a,wsPath:s,tls:t.tls,wsHost:t.wsHost,sni:t.sni,transport:o,remark:`vless-${n.remark||n.uuid.slice(0,8)}-${o}`}))}for(let n of e.trojanUsers){let s=n.path||e.wsPath;for(let o of L)r.push(G({password:n.password,host:t.host,port:a,wsPath:s,tls:t.tls,wsHost:t.wsHost,sni:t.sni,transport:o,remark:`trojan-${n.remark||n.password.slice(0,8)}-${o}`}))}return r}function ie(e,t){return fr(e,t).join(`
`)+`
`}function lt(e,t){return btoa(ie(e,t))}function dt(e,t){let r=t.port||443,a=t.tls!==!1,n=t.wsHost||t.host,s=t.sni||(a?n:""),o=[],c=(i,d,m,f,p,b)=>{let h={name:i,type:d,server:t.host,port:r,[m]:f,network:b,tls:a,servername:s||void 0,"client-fingerprint":a?j:void 0,udp:!0};return b==="grpc"?h["grpc-opts"]={"grpc-service-name":`/${K(p)}`}:b==="h2"?h["h2-opts"]={path:D(p),host:[n]}:h["ws-opts"]={path:D(p),headers:{Host:n}},h};e.vlessUsers.forEach((i,d)=>{for(let m of L)o.push(c(`vless-${i.remark||d+1}-${m}`,"vless","uuid",i.uuid,i.path||e.wsPath,m))}),e.trojanUsers.forEach((i,d)=>{for(let m of L)o.push(c(`trojan-${i.remark||d+1}-${m}`,"trojan","password",i.password,i.path||e.wsPath,m))});let l=["proxies:"];for(let i of o)l.push(`  - name: "${i.name}"`),l.push(`    type: ${i.type}`),l.push(`    server: ${i.server}`),l.push(`    port: ${i.port}`),i.uuid&&l.push(`    uuid: ${i.uuid}`),i.password&&l.push(`    password: "${i.password}"`),l.push(`    network: ${i.network}`),l.push(`    tls: ${i.tls}`),i.servername&&l.push(`    servername: ${i.servername}`),i["client-fingerprint"]&&l.push(`    client-fingerprint: ${i["client-fingerprint"]}`),l.push("    udp: true"),i.network==="grpc"?(l.push("    grpc-opts:"),l.push(`      grpc-service-name: ${i["grpc-opts"]["grpc-service-name"]}`)):i.network==="h2"?(l.push("    h2-opts:"),l.push(`      path: ${i["h2-opts"].path}`),l.push("      host:"),l.push(`        - ${n}`)):(l.push("    ws-opts:"),l.push(`      path: ${i["ws-opts"].path}`),l.push("      headers:"),l.push(`        Host: ${n}`));return l.push(""),l.push("rules:"),l.push("  - MATCH,DIRECT"),l.join(`
`)}function ut(e,t){let r=t.port||443,a=t.wsHost||t.host,n=t.sni||(t.tls?a:""),s=[],o=(c,l)=>l==="grpc"?{type:"grpc",service_name:`/${K(c)}`}:l==="h2"?{type:"http",host:[a],path:D(c)}:{type:"ws",path:D(c),headers:{Host:a}};for(let c of e.vlessUsers)for(let l of L)s.push({type:"vless",tag:`vless-${c.remark||c.uuid.slice(0,8)}-${l}`,server:t.host,server_port:r,uuid:c.uuid,transport:o(c.path||e.wsPath,l),tls:t.tls?{enabled:!0,server_name:n,fingerprint:j}:null});for(let c of e.trojanUsers)for(let l of L)s.push({type:"trojan",tag:`trojan-${c.remark||c.password.slice(0,8)}-${l}`,server:t.host,server_port:r,password:c.password,transport:o(c.path||e.wsPath,l),tls:t.tls?{enabled:!0,server_name:n,fingerprint:j}:null});return JSON.stringify({outbounds:s,log:{level:"info"}},null,2)}function ce(e,t){let r=t.host,a=t.port||(t.tls?443:80),s=`/${(t.path||e.wsPath||"/ws").replace(/^\//,"")}`,o={host:r,port:a,wsPath:s,tls:t.tls,wsHost:t.wsHost,sni:t.sni},c=(f,p)=>t.kind==="vless"?B({...o,uuid:t.credential,transport:f,remark:`vless-${p}`}):G({...o,password:t.credential,transport:f,remark:`trojan-${p}`}),l=[{name:"WebSocket (ws)",link:c("ws","ws")},{name:"gRPC",link:c("grpc","grpc")},{name:"HTTP/2 (h2)",link:c("h2","h2")}],i=t.kind==="vless"?"VLESS":"Trojan",d=l.map((f,p)=>`
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
  <h1>${i} \u8282\u70B9 <span class="badge">${r}</span></h1>
  <p class="desc">\u5165\u7AD9\u8DEF\u5F84\uFF1A<b>${s}</b>\uFF08\u670D\u52A1\u7AEF\u5DF2\u81EA\u52A8\u517C\u5BB9 ws / grpc / h2\uFF0C\u590D\u5236\u4EFB\u4E00\u94FE\u63A5\u5BFC\u5165\u5BA2\u6237\u7AEF\uFF09</p>
  ${d}
</div>
<script>
function copyLink(i){ const el=document.getElementById('link'+i); el.select(); document.execCommand('copy'); el.style.borderColor='#34c759'; setTimeout(()=>el.style.borderColor='#d2d2d7',800); }
<\/script>
</body>
</html>`}function pt(e){let t=e.disguise_title||"AList",r=e.disguise_subtitle||"\u4E00\u4E2A\u652F\u6301\u591A\u5B58\u50A8\u7684\u6587\u4EF6\u5217\u8868\u7A0B\u5E8F";return`<!DOCTYPE html>
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
</html>`}function le(e,t=200){return new Response(e,{status:t,headers:{"Content-Type":"text/html; charset=utf-8","Cache-Control":"no-store"}})}function P(e,t="text/plain; charset=utf-8"){return new Response(e,{headers:{"Content-Type":t,"Cache-Control":"no-store"}})}function hr(e,t,r){let n=(new URL(e.url).searchParams.get("format")||"base64").toLowerCase(),s={host:r.host,port:r.port,tls:r.tls,wsHost:r.wsHost,sni:r.sni};switch(n){case"plain":return P(ie(t,s));case"clash":case"yaml":return P(dt(t,s),"text/yaml; charset=utf-8");case"singbox":case"sing-box":case"json":return P(ut(t,s),"application/json; charset=utf-8");case"base64":default:return P(lt(t,s))}}function mr(e,t,r,a){let n=new URL(e.url),s=null;if(t.uuidSet.has(r)?s={kind:"vless",user:t.vlessIndex[r]}:t.passwordSet.has(r)&&(s={kind:"trojan",user:t.trojanIndex[r]}),!s)return new Response("Not Found",{status:404});let o=(n.searchParams.get("format")||"base64").toLowerCase(),c=a.host,l=a.port,i=s.user.path||t.wsPath,d=[];for(let f of L)s.kind==="vless"?d.push(B({uuid:s.user.uuid,host:c,port:l,wsPath:i,tls:a.tls,wsHost:a.wsHost,sni:a.sni,transport:f,remark:`vless-${s.user.remark||"node"}-${f}`})):d.push(G({password:s.user.password,host:c,port:l,wsPath:i,tls:a.tls,wsHost:a.wsHost,sni:a.sni,transport:f,remark:`trojan-${s.user.remark||"node"}-${f}`}));let m=d.join(`
`)+`
`;return P(o==="plain"?m:btoa(m))}async function ft(e,t,r){let a=new URL(e.url),n=a.pathname,s=ct(e),o=a.protocol==="https:",c=Number(a.port)||(o?443:80),l=(t.entryHost||"").trim(),i=l?{host:l,port:Number(t.entryPort)||443,tls:!0,wsHost:(t.entryWsHost||"").trim()||l,sni:(t.entrySni||"").trim()||l}:{host:s,port:c,tls:o,wsHost:s,sni:s};if(n==="/subscribe")return hr(e,t,i);let d=n.match(/^\/([^/]+)\/subscribe$/);if(d)return mr(e,t,decodeURIComponent(d[1]),i);let m=n.match(/^\/([^/]+)$/);if(m){let f=decodeURIComponent(m[1]);if(t.uuidSet.has(f)){let p=t.vlessIndex[f];return le(ce(t,{host:i.host,port:i.port,tls:i.tls,wsHost:i.wsHost,sni:i.sni,credential:f,kind:"vless",path:p&&p.path||t.wsPath}))}if(t.passwordSet.has(f)){let p=t.trojanIndex[f];return le(ce(t,{host:i.host,port:i.port,tls:i.tls,wsHost:i.wsHost,sni:i.sni,credential:f,kind:"trojan",path:p&&p.path||t.wsPath}))}}return le(pt(t.settings))}function br(e){if(e.length<2)return{frame:null,remaining:e,needMore:!0};let t=e[0]<<8|e[1];return t===0?{frame:new Uint8Array(0),remaining:e.slice(2),needMore:!1}:e.length<2+t?{frame:null,remaining:e,needMore:!0}:{frame:e.slice(2,2+t),remaining:e.slice(2+t),needMore:!1}}function ht(e){let t=new Uint8Array(2+e.length);return t[0]=e.length>>8,t[1]=e.length&255,t.set(e,2),t}async function mt(e,t,r){let a=e.getReader(),n=new Uint8Array(0);try{for(;;){let{done:s,value:o}=await a.read();if(s)break;if(!o||o.byteLength===0)continue;let c=new Uint8Array(n.length+o.byteLength);for(c.set(n,0),c.set(o,n.length),n=c;;){let{frame:l,remaining:i,needMore:d}=br(n);if(d){n=i;break}if(n=i,l&&l.length>0)try{await t(l)}catch(m){r(`udp frame handler error: ${m.message}`)}if(n.length<2)break}}}catch(s){r(`readUdpFrames error: ${s.message}`)}finally{try{a.releaseLock()}catch{}}}var bt=[{name:"\u5B57\u8282\u8DF3\u52A8",host:"www.bytedance.com",port:80,region:"cn",icon:"\u{1F3B5}"},{name:"Bilibili",host:"www.bilibili.com",port:80,region:"cn",icon:"\u{1F4FA}"},{name:"\u5FAE\u4FE1",host:"weixin.qq.com",port:80,region:"cn",icon:"\u{1F4AC}"},{name:"\u6DD8\u5B9D",host:"www.taobao.com",port:80,region:"cn",icon:"\u{1F6D2}"},{name:"GitHub",host:"github.com",port:80,region:"intl",icon:"\u{1F419}"},{name:"jsDelivr",host:"cdn.jsdelivr.net",port:80,region:"intl",icon:"\u{1F4E6}"},{name:"Cloudflare",host:"www.cloudflare.com",port:80,region:"intl",icon:"\u2601\uFE0F"},{name:"YouTube",host:"www.youtube.com",port:80,region:"intl",icon:"\u25B6\uFE0F"}],wt=16,yt=3e3,gt=4;var wr=5e3,gr=5e3;function de(e,t,r="/"){return new TextEncoder().encode(`GET ${r} HTTP/1.1\r
Host: ${e}\r
User-Agent: Mozilla/5.0 (netprobe)\r
Connection: close\r
\r
`)}function yr(e,t){let r=new Uint8Array(e.length+t.length);return r.set(e,0),r.set(t,e.length),r}function xr(e){for(let t=0;t<e.length-3;t++)if(e[t]===13&&e[t+1]===10&&e[t+2]===13&&e[t+3]===10)return t+4;return-1}function xt(e){try{typeof e.close=="function"?e.close():e.writable&&typeof e.writable.close=="function"&&e.writable.close().catch(()=>{})}catch{}}function ue(e,t){return new Promise(r=>{let a=new Uint8Array(0),n=!1,s=c=>{n||(n=!0,clearTimeout(o),r(c))},o=setTimeout(()=>s(null),t);(async()=>{let c=e.readable.getReader();try{for(;!n;){let{done:l,value:i}=await c.read();if(l)break;if(!(!i||i.byteLength===0)){if(a=yr(a,i),xr(a)>=0){s(Date.now());break}if(a.length>65536){s(null);break}}}}catch{}s(null);try{c.releaseLock()}catch{}})()})}async function vr(e,t,r,a,n){let s=Date.now(),o;try{let l=await z(e,2,t),i=H(e,l.outbound);o=await I({config:e,outbound:i,addressType:2,addressRemote:t,portRemote:r,rawClientData:a,log:n})}catch{return null}if(!o)return null;let c=await ue(o,yt);return xt(o),c===null?null:c-s}async function Tr(e,t,r){let a=[];for(let o=0;o<wt;o+=gt){let c=[],l=Math.min(o+gt,wt);for(let d=o;d<l;d++)c.push(vr(e,t.host,t.port,de(t.host,t.port),r));let i=await Promise.all(c);for(let d of i)a.push(d)}let n=a.filter(o=>o!==null),s=n.length>0?Math.round(n.reduce((o,c)=>o+c,0)/n.length):null;return{...t,samples:a,latency:s,success:n.length,total:a.length}}async function vt(e,t){let r=await Promise.allSettled(bt.map(a=>Tr(e,a,t)));return{ok:!0,ts:Date.now(),targets:r.map((a,n)=>a.status==="fulfilled"?a.value:{...bt[n],samples:[],latency:null,success:0,total:0,error:a.reason&&a.reason.message||"error"})}}async function Tt(e,t){if(!e.proxyipHost)return{ok:!1,error:"\u672A\u914D\u7F6E proxyip\uFF0C\u8BF7\u5148\u5728\u7CFB\u7EDF\u8BBE\u7F6E\u4E2D\u586B\u5199"};let r="www.cloudflare.com",a=443,n=Date.now(),s=null;try{if(s=globalThis.connect?globalThis.connect({hostname:e.proxyipHost,port:Number(e.proxyipPort||443)}):null,!s)return{ok:!1,error:"connect \u4E0D\u53EF\u7528"};let c=s.writable.getWriter();await c.write(de(r,a)),c.releaseLock()}catch(c){try{s&&s.close()}catch{}return{ok:!1,error:`\u8FDE\u63A5\u5931\u8D25: ${c.message}`}}let o=await ue(s,yt);try{s.close()}catch{}return o===null?{ok:!1,error:"\u8FDE\u63A5\u8D85\u65F6\u6216\u65E0\u54CD\u5E94"}:{ok:!0,latency:o-n,endpoint:`${e.proxyipHost}:${e.proxyipPort||443}`}}function Er(e){let r=[18,52];r.push(1,0),r.push(0,1),r.push(0,0,0,0,0,0);for(let a of String(e).split(".")){r.push(a.length);for(let n=0;n<a.length;n++)r.push(a.charCodeAt(n))}return r.push(0),r.push(0,1),r.push(0,1),new Uint8Array(r)}async function Et(e,t){let r=null,a=(e.udpOutbound||"").trim();if(a){let i=e.outboundByName[a];if(i&&i.type==="vless")r=i;else return{ok:!1,error:`UDP \u51FA\u7AD9 '${a}' \u4E0D\u5B58\u5728\u6216\u975E vless\uFF08\u4EC5 vless \u652F\u6301 UDP\uFF09`}}else if(r=e.outbounds.find(i=>i.type==="vless"),!r)return{ok:!1,error:"\u672A\u914D\u7F6E vless \u51FA\u7AD9\uFF0C\u65E0\u6CD5\u6D4B\u8BD5 UDP"};let n=Er("example.com"),s=ht(n),o=Date.now(),c;try{c=await O({address:r.address,port:Number(r.port),uuid:r.uuid,path:r.path,tls:!!r.tls,sni:r.sni||"",transport:r.transport},2,1,"1.1.1.1",53,s,t)}catch(i){return{ok:!1,error:`UDP \u51FA\u7AD9\u8FDE\u63A5\u5931\u8D25: ${i.message}`}}if(!c)return{ok:!1,error:"UDP \u51FA\u7AD9\u8FDE\u63A5\u5931\u8D25"};let l=await new Promise(i=>{let d=setTimeout(()=>i({ok:!1,error:"UDP \u54CD\u5E94\u8D85\u65F6"}),wr);mt(c.readable,m=>{m.length>=12&&m[0]===18&&m[1]===52&&m[2]&128&&(clearTimeout(d),i({ok:!0,latency:Date.now()-o,bytes:m.length}))},t)});try{c.writable.close().catch(()=>{})}catch{}return l}async function kt(e,t,r){let a="www.gstatic.com",s=Date.now(),o;try{o=await I({config:e,outbound:t,addressType:2,addressRemote:a,portRemote:80,rawClientData:de(a,80,"/generate_204"),log:r})}catch(l){return{ok:!1,error:l.message}}if(!o)return{ok:!1,error:"\u96A7\u9053\u5EFA\u7ACB\u5931\u8D25"};let c=await ue(o,gr);return xt(o),c===null?{ok:!1,error:"\u8FDE\u63A5\u8D85\u65F6\u6216\u65E0\u54CD\u5E94"}:{ok:!0,latency:c-s}}var pe={"Content-Type":"application/json; charset=utf-8"};function E(e,t=200){return new Response(JSON.stringify(e),{status:t,headers:pe})}async function Y(e){try{return await e.json()}catch{return null}}function kr(e){return e.admin_cookie_secret||e.admin_password_hash||"vtd-insecure-secret"}async function _t(e,t){let n=new URL(e.url).pathname.split("/").filter(Boolean),s=n[2]||"",o=n[3]||null,c=e.method,{DB:l,GEO_KV:i}=t.env,d=t.settings,m=kr(d);if(s==="login"&&c==="POST"){let u=await Y(e);if(!u||!u.password)return E({error:"password required"},400);if(!await Le(u.password,t.adminPasswordHash))return E({error:"invalid password"},401);let w=await Re(m);return new Response(JSON.stringify({ok:!0}),{status:200,headers:{...pe,"Set-Cookie":`${C}=${w}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${7*86400}`}})}let f=Oe(e.headers.get("Cookie"));if(!await $e(f[C],m))return E({error:"unauthorized"},401);if(s==="logout"&&c==="POST")return new Response(JSON.stringify({ok:!0}),{status:200,headers:{...pe,"Set-Cookie":`${C}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0`}});if(await Ar(l),s==="settings"){if(c==="GET"){let{results:u}=await l.prepare("SELECT key, value FROM settings").all();return E((u||[]).reduce((g,w)=>(g[w.key]=w.value,g),{}))}if(c==="PUT"){let u=await Y(e);if(!u)return E({error:"bad body"},400);let g=new Set(["ws_path","default_outbound","proxyip","udp_outbound","disguise_title","disguise_subtitle","entry_host","entry_port","entry_sni","entry_ws_host","admin_password_hash","admin_cookie_secret"]);for(let[w,y]of Object.entries(u))typeof y=="string"&&g.has(w)&&await l.prepare("INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at").bind(w,y,Date.now()).run();return E({ok:!0})}return E({error:"method not allowed"},405)}let h={"vless-users":{table:"vless_users",cols:["uuid","remark","enable","path","expire_at","traffic_limit","traffic_reset_at"]},"trojan-users":{table:"trojan_users",cols:["password","remark","enable","path","expire_at","traffic_limit","traffic_reset_at"]},outbounds:{table:"outbounds",cols:["type","name","address","port","uuid","path","tls","udp","enable","sort","username","password","sni","transport"],validate(u){if(u.type!==void 0&&!["socks5","http","vless"].includes(u.type))return"invalid outbound type";if(u.port!==void 0&&(!Number.isInteger(Number(u.port))||Number(u.port)<=0||Number(u.port)>65535))return"invalid port";if((u.type==="socks5"||u.type==="http")&&!u.address)return"address required";if(u.type==="vless"){if(!u.uuid)return"vless requires uuid";if(u.transport!==void 0&&!["raw","ws","grpc","httpupgrade","h2"].includes(u.transport))return"invalid vless transport"}return u.username&&!u.password||!u.username&&u.password?"username and password must be set together":((u.type==="socks5"||u.type==="http")&&(u.udp=0),u.type!=="vless"&&(u.transport="ws"),null)}},"routing-rules":{table:"routing_rules",cols:["rule","outbound","enable","sort"]}}[s];if(h)return Sr(c,o,h,l,e);if(s==="stats"&&c==="GET"){let[u,g]=await Promise.all([l.prepare("SELECT remark, uuid, up, down, path, expire_at, traffic_limit, traffic_reset_at FROM vless_users ORDER BY (up + down) DESC").all(),l.prepare("SELECT remark, password, up, down, path, expire_at, traffic_limit, traffic_reset_at FROM trojan_users ORDER BY (up + down) DESC").all()]),w=Math.floor(Date.now()/1e3),y=x=>(x||[]).map(v=>{let k=Number(v.up||0),_=Number(v.down||0),S=Number(v.traffic_limit||0),T=k+_;return{...v,used:T,remaining:S>0?Math.max(0,S-T):null,expired:v.expire_at>0&&v.expire_at<w,limitReached:S>0&&T>=S}});return E({vless:y(u.results),trojan:y(g.results)})}if(s==="geo"&&n[3]==="update"&&c==="POST")try{let u=await J(l,i);return E({ok:!0,updated:u.updated,total:u.total,failed:u.failed})}catch(u){return E({error:u.message},500)}if(s==="netstatus"&&n[3]==="test"&&c==="POST")try{return E(await vt(t,u=>console.log(u)))}catch(u){return E({ok:!1,error:u.message},500)}if(s==="test"){if(n[3]==="proxyip"&&c==="POST")try{return E(await Tt(t,u=>console.log(u)))}catch(u){return E({ok:!1,error:u.message},500)}if(n[3]==="udp"&&c==="POST")try{return E(await Et(t,u=>console.log(u)))}catch(u){return E({ok:!1,error:u.message},500)}if(n[3]==="outbound"&&n[4]&&c==="POST"){let u=await l.prepare("SELECT * FROM outbounds WHERE id = ?").bind(Number(n[4])).first();if(!u)return E({ok:!1,error:"outbound not found"},404);try{return E(await kt(t,u,g=>console.log(g)))}catch(g){return E({ok:!1,error:g.message},500)}}}return E({error:"not found"},404)}async function St(e){try{let{results:t}=await e.prepare("SELECT name FROM pragma_table_info('outbounds')").all();if((t||[]).some(r=>r.name==="transport"))return;await e.prepare("ALTER TABLE outbounds ADD COLUMN transport TEXT DEFAULT 'ws'").run(),console.log("[admin] outbounds.transport column added (migration)")}catch(t){console.log("[admin] outbounds transport migration skipped: "+t.message)}}async function Sr(e,t,r,a,n){let{table:s,cols:o}=r,c="id";if(e==="GET"){let{results:l}=await a.prepare(`SELECT * FROM ${s} ORDER BY id`).all();return E(l||[])}if(e==="POST"){let l=await Y(n);if(!l)return E({error:"bad body"},400);if(r.validate){let p=r.validate(l);if(p)return E({error:p},400)}s==="outbounds"&&await St(a);let i=o.filter(p=>l[p]!==void 0);if(i.length===0)return E({error:"no fields"},400);let d=i.map(()=>"?").join(","),m=i.map(p=>l[p]),{meta:f}=await a.prepare(`INSERT INTO ${s} (${i.join(",")}) VALUES (${d})`).bind(...m).run();return E({ok:!0,id:f.last_row_id})}if(e==="PUT"&&t){let l=await Y(n);if(!l)return E({error:"bad body"},400);if(r.validate){let f=r.validate(l);if(f)return E({error:f},400)}s==="outbounds"&&await St(a);let i=o.filter(f=>l[f]!==void 0);if(i.length===0)return E({error:"no fields"},400);let d=i.map(f=>`${f} = ?`).join(","),m=i.map(f=>l[f]);return await a.prepare(`UPDATE ${s} SET ${d} WHERE ${c} = ?`).bind(...m,Number(t)).run(),E({ok:!0})}return e==="DELETE"&&t?(await a.prepare(`DELETE FROM ${s} WHERE ${c} = ?`).bind(Number(t)).run(),E({ok:!0})):E({error:"method not allowed"},405)}async function J(e,t){let{results:r}=await e.prepare("SELECT rule FROM routing_rules").all(),a={geosite:new Set,geoip:new Set};for(let s of r||[]){let o=String(s.rule||"").trim(),c=o.match(/^geosite:(.+)$/i);c&&c[1].split(",").forEach(l=>a.geosite.add(l.trim())),c=o.match(/^geoip:(.+)$/i),c&&c[1].split(",").forEach(l=>a.geoip.add(l.trim()))}let n={updated:0,total:0,failed:[]};for(let s of["geosite","geoip"])for(let o of a[s]){n.total++;try{let c=await _r(s,o);c&&c.length>0?(await t.put(`${s}:${o}`,JSON.stringify(c)),n.updated++):n.failed.push(`${s}:${o} (empty rules)`)}catch(c){n.failed.push(`${s}:${o} (${c.message||c})`)}}return await t.put("geo:version",new Date().toISOString()),Ze(),n}async function _r(e,t){let r=(o,c)=>`https://raw.githubusercontent.com/${o}/rule-set/${c}`,a=(o,c)=>`https://cdn.jsdelivr.net/gh/${o}@rule-set/${c}`,n=e==="geosite"?[r("MetaCubeX/sing-geosite",`${t}-geosite.json`),r("MetaCubeX/sing-geosite",`${t}.json`),a("MetaCubeX/sing-geosite",`${t}-geosite.json`)]:[r("MetaCubeX/sing-geoip",`${t}.json`),r("MetaCubeX/sing-geoip",`${t}-geoip.json`),a("MetaCubeX/sing-geoip",`${t}.json`)],s=null;for(let o of n)try{let c=await fetch(o,{cf:{cacheTtl:86400}});if(!c.ok){s=new Error(`HTTP ${c.status}`);continue}let l=await c.text(),i;try{i=JSON.parse(l)}catch{s=new Error("invalid json");continue}let d=[],m=f=>{typeof f=="string"&&f&&d.length<2e4&&d.push(f)};for(let f of i.rules||[])if(e==="geosite"){for(let p of f.domain||[])m(p);for(let p of f.domain_suffix||[])m(String(p).replace(/^\.+/,""));for(let p of f.domain_keyword||[])m(String(p))}else for(let p of f.ip_cidr||[])m(p);if(d.length>0)return d;s=new Error("empty rules")}catch(c){s=c}throw s||new Error("fetch failed")}async function Ar(e){let t=[["path","TEXT DEFAULT ''"],["expire_at","INTEGER DEFAULT 0"],["traffic_limit","INTEGER DEFAULT 0"],["traffic_reset_at","INTEGER DEFAULT 0"]];for(let r of["vless_users","trojan_users"])try{let{results:a}=await e.prepare(`SELECT name FROM pragma_table_info('${r}')`).all(),n=new Set((a||[]).map(s=>s.name));for(let[s,o]of t)n.has(s)||(await e.prepare(`ALTER TABLE ${r} ADD COLUMN ${s} ${o}`).run(),console.log(`[admin] ${r}.${s} column added (migration)`))}catch(a){console.log(`[admin] ${r} migration skipped: ${a.message}`)}}function At(e){return`<!DOCTYPE html>
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
    .sidebar { position:fixed; top:auto; left:0; right:0; bottom:0; width:100%; height:58px; display:flex; align-items:center; justify-content:space-around; border-top:1px solid var(--border); border-right:0; padding:4px 4px calc(4px + env(safe-area-inset-bottom)); background:rgba(255,255,255,.9); backdrop-filter:saturate(180%) blur(20px); -webkit-backdrop-filter:saturate(180%) blur(20px); z-index:40; }
    .sidebar h2 { display:none; }
    .nav-item { padding:6px 2px; font-size:10px; text-align:center; border-radius:8px; margin:0; white-space:nowrap; flex:1; }
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
  if (tab==='netstatus'){ mc.innerHTML = '<div class="page-title">\u7F51\u7EDC\u72B6\u6001</div><div class="card" style="padding:12px 16px;font-size:13px;color:var(--muted)">\u68C0\u6D4B\u6309\u9879\u76EE\u7F51\u7EDC\u8BBE\u7F6E\u53D1\u8D77\uFF08\u5206\u6D41\u89C4\u5219 + \u9ED8\u8BA4\u51FA\u7AD9 + proxyip + \u51FA\u7AD9\u96A7\u9053\uFF09\uFF0C\u591A\u76EE\u6807\u5E76\u884C\u3001\u6BCF\u76EE\u6807 16 \u6B21\u91C7\u6837\uFF0C\u7EA6 10-15 \u79D2\u5B8C\u6210\u3002\u7EFF\u8272=\u6B63\u5E38\uFF0C\u9EC4\u8272/\u6A59\u8272=\u9AD8\u5EF6\u8FDF\uFF0C\u7070\u8272=\u8D85\u65F6/\u5931\u8D25\u3002</div><div class="toolbar"><button class="btn small" onclick="runNetstatus()">\u5F00\u59CB\u68C0\u6D4B</button></div><div class="net-grid" id="netGrid"></div>'; runNetstatus(); return; }
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
    const s = await api('/admin/api/settings');
    const fields = [
      ['ws_path','\u5165\u7AD9\u8DEF\u5F84\uFF08ws / grpc / h2 \u5171\u4EAB\uFF1B\u7528\u6237\u672A\u81EA\u5B9A\u4E49\u8DEF\u5F84\u65F6\u56DE\u9000\u5230\u6B64\u503C\uFF09'],
      ['default_outbound','\u9ED8\u8BA4\u51FA\u7AD9 (direct / \u51FA\u7AD9\u540D)'],
      ['proxyip','proxyip\uFF08\u4EE3\u7406 IP \u6216\u57DF\u540D[:\u7AEF\u53E3]\uFF0C\u8BBF\u95EE Cloudflare \u53CA\u5F00 CF CDN \u7F51\u7AD9\u4F7F\u7528\uFF1B\u4EC5\u9ED8\u8BA4\u51FA\u7AD9\u4E3A direct \u65F6\u751F\u6548\uFF09'],
      ['udp_outbound','UDP \u51FA\u7AD9\u4EE3\u7406\uFF08\u51FA\u7AD9\u540D\uFF0C\u4EC5 vless \u652F\u6301 UDP\uFF09'],
      ['disguise_title','\u4F2A\u88C5\u9875\u6807\u9898'],
      ['disguise_subtitle','\u4F2A\u88C5\u9875\u526F\u6807\u9898'],
    ];
    mc.innerHTML = '<div class="page-title">\u7CFB\u7EDF\u8BBE\u7F6E</div>'+
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
  try {
    const d = await api('/admin/api/geo/update',{method:'POST',body:'{}'});
    const msg = '\u5DF2\u66F4\u65B0 '+d.updated+' / '+d.total+' \u4E2A\u5206\u7C7B' + ((d.failed && d.failed.length) ? ('\uFF1B\u5931\u8D25: '+d.failed.join(', ')) : '');
    toast(msg);
  }
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
</html>`}async function Lt(e,t){let r=new URL(e.url);if(e.method==="POST"||e.method==="GET")try{let{DB:a,GEO_KV:n}=t,s=await J(a,n);return new Response(JSON.stringify({ok:!0,updated:s.updated,total:s.total,failed:s.failed}),{status:200,headers:{"Content-Type":"application/json; charset=utf-8"}})}catch(a){return new Response(JSON.stringify({ok:!1,error:a.message}),{status:500,headers:{"Content-Type":"application/json; charset=utf-8"}})}return new Response("Not Found",{status:404})}async function Ut(e,t,r){try{let a=await J(t.DB,t.GEO_KV);console.log(`[cron] geo update done: ${a.updated}/${a.total} categories${a.failed.length?", failed: "+a.failed.join("; "):""}`)}catch(a){console.log(`[cron] geo update failed: ${a.message}`)}}globalThis.connect=Lr;function Ur(e){let t=new Set,r=new Set;for(let a of e){if(a.kind==="all")return{all:!0,vless:t,trojan:r};a.kind==="vless"&&a.credential&&t.add(a.credential),a.kind==="trojan"&&a.credential&&r.add(a.credential)}return{all:!1,vless:t,trojan:r}}var ea={async fetch(e,t,r){let n=new URL(e.url).pathname;try{if(n.startsWith("/admin")){let c=await Q(e,t,{ensureAdmin:!0});return n.startsWith("/admin/api/")?await _t(e,c):new Response(At(c.adminTempPassword),{headers:{"Content-Type":"text/html; charset=utf-8","Cache-Control":"no-store"}})}if(n==="/geo-update-cron")return await Lt(e,t);let s=await Q(e,t),o=s.inboundPathMap.get(n);if(o&&o.length>0){s._inboundScope=Ur(o);let c=String(e.headers.get("Upgrade")||"").toLowerCase(),l=String(e.headers.get("Content-Type")||"").toLowerCase(),i=n.endsWith("/Tun")||l.includes("application/grpc");if(c==="websocket"&&!i)return await at(e,s,t);if(i)return await ot(e,s,t);if(e.method==="POST")return await st(e,s,t)}return await ft(e,s,t)}catch(s){return console.log(`[index] error: ${s.message||s}`),new Response(JSON.stringify({error:"internal error"}),{status:500,headers:{"Content-Type":"application/json; charset=utf-8"}})}},async scheduled(e,t,r){return Ut(e,t,r)}};export{ea as default};
