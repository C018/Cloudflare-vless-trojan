import{connect as Ca}from"cloudflare:sockets";var I="direct",Z="reject",Pt="socks5",Mt="http",It="vless",xe=["raw","ws","grpc","httpupgrade","h2"];var ve="geosite:",Te="geoip:",Nt="geo:version",ot="vtd_admin";var ke=["qq.com","taobao.com","tmall.com","jd.com","baidu.com","bilibili.com","douyin.com","weibo.com","zhihu.com","163.com","126.com","aliyun.com","tencent.com","weixin.qq.com","alipay.com","bankofchina.com","icbc.com.cn","ccb.com","abcchina.com","cmbchina.com","boc.cn","12306.cn","gov.cn","cn","com.cn","net.cn","org.cn"],Ee=["speedtest.net","fast.com","ookla.com"],Se=["google.com","googleapis.com","gstatic.com","googleusercontent.com","ggpht.com","google.cn","google.com.hk","gvt1.com","gvt2.com","gvt3.com"],Ht=[];for(let e=0;e<=255;++e){let t=e.toString(16).padStart(2,"0");Ht.push(t)}var Ft=1e5;function zt(e){return Array.from(new Uint8Array(e)).map(t=>t.toString(16).padStart(2,"0")).join("")}function Xr(){let e=new Uint8Array(16);return crypto.getRandomValues(e),zt(e)}async function Ae(e,t,r){let a=await crypto.subtle.importKey("raw",new TextEncoder().encode(e),"PBKDF2",!1,["deriveBits"]),n=await crypto.subtle.deriveBits({name:"PBKDF2",salt:new TextEncoder().encode(t),iterations:r,hash:"SHA-256"},a,256);return zt(n)}async function _e(e){let t=Xr(),r=await Ae(e,t,Ft);return`${t}:${Ft}:${r}`}async function Le(e,t){if(!t||!e)return!1;let r=String(t).split(":");if(r.length!==3)return!1;let[a,n,s]=r,o=parseInt(n,10)||Ft;return await Ae(e,a,o)===s}async function $e(e,t){let r=await crypto.subtle.importKey("raw",new TextEncoder().encode(e),{name:"HMAC",hash:"SHA-256"},!1,["sign"]),a=await crypto.subtle.sign("HMAC",r,new TextEncoder().encode(t));return zt(a)}async function Ue(e){let r=`admin.${Math.floor(Date.now()/1e3)+604800}`,a=await $e(e,r);return`${r}.${a}`}async function Oe(e,t){if(!e||!t)return!1;let r=String(e).split(".");if(r.length!==3)return!1;let[a,n,s]=r;if(a!=="admin")return!1;let o=Number(n);if(!Number.isFinite(o)||o<Date.now()/1e3)return!1;let c=await $e(t,`${a}.${n}`);if(c.length!==s.length)return!1;let u=0;for(let i=0;i<c.length;i++)u|=c.charCodeAt(i)^s.charCodeAt(i);return u===0}function De(e){let t={};if(!e)return t;for(let r of e.split(";")){let a=r.indexOf("=");if(a<0)continue;let n=r.slice(0,a).trim(),s=r.slice(a+1).trim();t[n]=decodeURIComponent(s)}return t}var tn=3e4,lt={settings:{p:null,ts:0},vlessUsers:{p:null,ts:0},trojanUsers:{p:null,ts:0},outbounds:{p:null,ts:0},routingRules:{p:null,ts:0}};function it(e,t){let r=lt[e],a=Date.now();if(r.p&&a-r.ts<tn)return r.p;let n=Promise.resolve().then(t).catch(()=>null);return r.p=n,r.ts=a,n}function Q(e){if(e==="all"){for(let r of Object.keys(lt))lt[r].p=null,lt[r].ts=0;return}let t=lt[e];t&&(t.p=null,t.ts=0)}async function en(e){try{let{results:t}=await e.prepare("SELECT key, value FROM settings").all(),r={};for(let a of t||[])r[a.key]=a.value;return r}catch{return{}}}async function rn(e){try{let{results:t}=await e.prepare("SELECT id, uuid, remark, up, down, path, expire_at, traffic_limit, traffic_reset_at FROM vless_users WHERE enable = 1 ORDER BY id").all();return t||[]}catch{try{let{results:r}=await e.prepare("SELECT id, uuid, remark, up, down FROM vless_users WHERE enable = 1 ORDER BY id").all();return(r||[]).map(a=>({path:"",expire_at:0,traffic_limit:0,traffic_reset_at:0,...a}))}catch{return[]}}}async function nn(e){try{let{results:t}=await e.prepare("SELECT id, password, remark, up, down, path, expire_at, traffic_limit, traffic_reset_at FROM trojan_users WHERE enable = 1 ORDER BY id").all();return t||[]}catch{try{let{results:r}=await e.prepare("SELECT id, password, remark, up, down FROM trojan_users WHERE enable = 1 ORDER BY id").all();return(r||[]).map(a=>({path:"",expire_at:0,traffic_limit:0,traffic_reset_at:0,...a}))}catch{return[]}}}function an(e){let t=String(e||"").trim();if(!t)return"";for(t.startsWith("/")||(t="/"+t);t.length>1&&t.endsWith("/");)t=t.slice(0,-1);return t}async function Re(e,t,r){let a=Math.floor(Date.now()/1e3);for(let n of t)if(n.traffic_reset_at>0&&n.traffic_reset_at<=a)try{await e.prepare(`UPDATE ${r} SET up = 0, down = 0, traffic_reset_at = 0 WHERE id = ?`).bind(n.id).run(),n.up=0,n.down=0,n.traffic_reset_at=0}catch{}}function sn(e,t,r){let a=new Map,n=(s,o)=>{let c=an(s);if(!c)return;a.has(c)||a.set(c,[]),a.get(c).push(o);let u=`${c}/Tun`;a.has(u)||a.set(u,[]),a.get(u).push(o)};n(e,{kind:"all"});for(let s of t)s.path&&n(s.path,{kind:"vless",credential:s.uuid.toLowerCase()});for(let s of r)s.path&&n(s.path,{kind:"trojan",credential:s.password});return a}async function on(e){try{let{results:t}=await e.prepare("SELECT * FROM outbounds WHERE enable = 1 ORDER BY sort ASC, id ASC").all();return t||[]}catch{return[]}}async function ln(e){try{let{results:t}=await e.prepare("SELECT * FROM routing_rules WHERE enable = 1 ORDER BY sort ASC, id ASC").all();return t||[]}catch{return[]}}async function cn(e){try{let a=await e.prepare("SELECT value FROM settings WHERE key = ?").bind("admin_password_hash").first();if(a&&a.value)return{hash:a.value,tempPassword:null}}catch{}let t=dn().replace(/-/g,"").slice(0,12),r=await _e(t);try{await e.prepare("INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at").bind("admin_password_hash",r,Date.now()).run(),Q("settings")}catch{}return{hash:r,tempPassword:t}}function un(e){let t=[];try{let r=e.entry_list;if(r){let a=JSON.parse(r);Array.isArray(a)&&(t=a)}}catch{t=[]}return!t.length&&(e.entry_host||"").trim()&&(t=[{host:e.entry_host,port:e.entry_port||"",sni:e.entry_sni||"",wsHost:e.entry_ws_host||"",remark:"",transports:[]}]),t.map(r=>{let a=String(r.host||"").trim(),n=String(r.wsHost||"").trim()||a;return{host:a,port:String(r.port||"").trim()||"443",sni:String(r.sni||"").trim()||n,wsHost:n,remark:String(r.remark||"").trim(),transports:Array.isArray(r.transports)?r.transports.filter(s=>["ws","grpc","h2"].includes(s)):["ws","grpc","h2"]}}).filter(r=>r.host)}async function ct(e,t,r={}){let{DB:a}=t,n=await it("settings",()=>en(a)),s=n.ws_path||"/ws",o=n.entry_transport||"ws",c=n.default_outbound||I,u=n.admin_password_hash||"",i=null;if(!u&&r.ensureAdmin){let x=await cn(a);u=x.hash,i=x.tempPassword}let l=n.proxyip||"",d=await it("outbounds",()=>on(a)),h="",p=443,y="";if(l)if(d.find(S=>S.name===l&&S.type!==I&&S.type!==Z))y=l;else{let S=l.lastIndexOf(":");S>0&&!l.includes("]")&&/^\d+$/.test(l.slice(S+1))?(h=l.slice(0,S),p=Number(l.slice(S+1))||443):h=l}let m=n.udp_outbound||"",g=un(n),f=g.length?g[0].host:"",b=g.length?g[0].port:"",w=g.length?g[0].sni:"",k=g.length?g[0].wsHost:"",v=await it("vlessUsers",()=>rn(a)),A=await it("trojanUsers",()=>nn(a)),$=await it("routingRules",()=>ln(a));await Promise.all([Re(a,v,"vless_users"),Re(a,A,"trojan_users")]);let L=sn(s,v,A),_={};for(let x of v)_[x.uuid]=x;let O={};for(let x of A)O[x.password]=x;return{env:t,settings:n,wsPath:s,entryTransport:o,defaultOutbound:c,adminPasswordHash:u,adminTempPassword:i,proxyipHost:h,proxyipPort:p,proxyipOutbound:y,proxyipDisabled:c!==I,udpOutbound:m,entryHost:f,entryPort:b,entrySni:w,entryWsHost:k,entries:g,vlessUsers:v,trojanUsers:A,outbounds:d,routingRules:$,vlessIndex:_,trojanIndex:O,uuidSet:new Set(v.map(x=>x.uuid.toLowerCase())),passwordSet:new Set(A.map(x=>x.password)),outboundByName:d.reduce((x,S)=>(x[S.name]=S,x),{}),inboundPathMap:L}}function dn(){return globalThis.crypto&&typeof globalThis.crypto.randomUUID=="function"?globalThis.crypto.randomUUID():"xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(/[xy]/g,e=>{let t=Math.random()*16|0;return(e==="x"?t:t&3|8).toString(16)})}function Tt(e){let t=new Set,r=new Set;for(let a of e){if(a.kind==="all")return{all:!0,vless:t,trojan:r};a.kind==="vless"&&a.credential&&t.add(a.credential),a.kind==="trojan"&&a.credential&&r.add(a.credential)}return{all:!1,vless:t,trojan:r}}function pn(e){let t=r=>Ht[e[r]];return`${t(0)}${t(1)}${t(2)}${t(3)}-${t(4)}${t(5)}-${t(6)}${t(7)}-${t(8)}${t(9)}-${t(10)}${t(11)}${t(12)}${t(13)}${t(14)}${t(15)}`.toLowerCase()}function Ce(e,t){if(e.byteLength<24)return{hasError:!0,message:"invalid data"};let r=e instanceof Uint8Array?new DataView(e.buffer,e.byteOffset,e.byteLength):new DataView(e),a=r.getUint8(0),n=pn(new Uint8Array(e.slice(1,17)));if(!t.has(n))return{hasError:!0,message:"invalid user"};let o=18+r.getUint8(17);if(e.byteLength<o+4)return{hasError:!0,message:"invalid data"};let c=r.getUint8(o);if(c!==1&&c!==2)return{hasError:!0,message:`command ${c} is not supported`};let u=o+1,i=r.getUint16(u),l=r.getUint8(u+2),d,h,p;switch(l){case 1:h=4,p=u+3,d=Array.from(new Uint8Array(e.slice(p,p+h))).join(".");break;case 2:if(e.byteLength<u+4)return{hasError:!0,message:"invalid data"};h=r.getUint8(u+3),p=u+4,d=new TextDecoder().decode(e.slice(p,p+h));break;case 3:h=16,p=u+3,d=Array.from({length:8},(y,m)=>r.getUint16(p+m*2).toString(16)).join(":");break;default:return{hasError:!0,message:`invalid addressType: ${l}`}}return d?{hasError:!1,userUuid:n,addressRemote:d,addressType:l,portRemote:i,rawDataIndex:p+h,protocolVersion:new Uint8Array([a]),isUDP:c===2}:{hasError:!0,message:"addressValue is empty"}}function Pe(e,t,r,a,n){let s,o,c=[];switch(t){case 1:s=4,c=r.split(".").map(Number);break;case 2:o=new TextEncoder().encode(r),s=o.length+1;break;case 3:s=16,c=Bt(r).split(":").map(l=>[parseInt(l.slice(0,2),16),parseInt(l.slice(2),16)]).flat();break;default:throw new Error(`Unknown address type: ${t}`)}let u=n.replace(/-/g,""),i=new Uint8Array(22+s);i[0]=0;for(let l=0;l<u.length;l+=2)i[1+l/2]=parseInt(u.substr(l,2),16);return i[17]=0,i[18]=e,i[19]=a>>8,i[20]=a&255,i[21]=t,t===2?(i[22]=o.length,i.set(o,23)):i.set(c,22),i}function Bt(e){if(e=e.replace(/^\[|\]$/g,""),e.includes("::")){let t=e.split("::"),r=t[0]?t[0].split(":"):[],a=t[1]?t[1].split(":"):[],n=8-r.length-a.length,s=Array(Math.max(0,n)).fill("0");return[...r,...s,...a].map(o=>o.padStart(4,"0")).join(":")}return e.split(":").map(t=>t.padStart(4,"0")).join(":")}async function fn(e){let t=new TextEncoder().encode(e),r=await crypto.subtle.digest({name:"SHA-224"},t);return Array.from(new Uint8Array(r)).map(a=>a.toString(16).padStart(2,"0")).join("")}var jt=new Map;function hn(e){if(jt.has(e))return jt.get(e);let t=fn(e);return jt.set(e,t),t}function Me(e){if(e.byteLength<60)return!1;let t=new Uint8Array(e);return t[0]===0?!1:t[56]===13&&t[57]===10}async function Ie(e,t){if(e.byteLength<60)return{hasError:!0,message:"Invalid Trojan data: too short"};let r=new Uint8Array(e),a=e instanceof Uint8Array?new DataView(e.buffer,e.byteOffset,e.byteLength):new DataView(e);if(r[56]!==13||r[57]!==10)return{hasError:!0,message:"Invalid Trojan header: missing CRLF"};let n=new TextDecoder().decode(r.slice(0,56)),s=null;for(let y of t)try{if(await hn(y)===n){s=y;break}}catch{}if(!s)return{hasError:!0,message:"Invalid Trojan password"};let o=r[58];if(o!==1&&o!==3)return{hasError:!0,message:`Unsupported Trojan command: ${o}`};let c=r[59],u,i,l;switch(c){case 1:if(i=4,l=60,e.byteLength<l+i+2)return{hasError:!0,message:"Invalid Trojan header: IPv4 truncated"};u=Array.from(r.slice(l,l+i)).join(".");break;case 3:if(i=r[60],l=61,e.byteLength<l+i+2)return{hasError:!0,message:"Invalid Trojan header: domain truncated"};u=new TextDecoder().decode(r.slice(l,l+i));break;case 4:if(i=16,l=60,e.byteLength<l+i+2)return{hasError:!0,message:"Invalid Trojan header: IPv6 truncated"};u=Array.from({length:8},(y,m)=>a.getUint16(l+m*2).toString(16)).join(":");break;default:return{hasError:!0,message:`Invalid Trojan address type: ${c}`}}let d=l+i;if(e.byteLength<d+2)return{hasError:!0,message:"Invalid Trojan header: port truncated"};let h=a.getUint16(d),p=d+2;return e.byteLength<p+2?{hasError:!0,message:"Invalid Trojan header: missing final CRLF"}:r[p]!==13||r[p+1]!==10?{hasError:!0,message:"Invalid Trojan header: invalid final CRLF"}:{hasError:!1,userPassword:s,addressRemote:u,addressType:c===3?2:c===4?3:c,portRemote:h,rawDataIndex:p+2,isUDP:o===3}}function Ne(e){if(!e)return{earlyData:null,error:null};try{let t=e.replace(/-/g,"+").replace(/_/g,"/"),r=atob(t),a=new ArrayBuffer(r.length),n=new Uint8Array(a);for(let s=0;s<r.length;s++)n[s]=r.charCodeAt(s);return{earlyData:a,error:null}}catch(t){return{earlyData:null,error:t}}}function N(e){try{e&&e.readyState===1&&e.close()}catch{}}async function He(e,t){let r=e.sni&&e.sni!==""?e.sni:e.address,a=Number(e.port),n;try{n=globalThis.connect?globalThis.connect({hostname:r,port:a,secureTransport:e.tls?"on":"off"}):void 0}catch(i){return t(`[VLESS/raw] connect error: ${i.message}`),null}if(!n)return t("[VLESS/raw] connect unavailable"),null;let s=n.readable.getReader(),o,c=new Promise(i=>{o=i});return(n.closed||Promise.resolve()).then(o,o),{readable:new ReadableStream({start(i){(async()=>{try{for(;;){let{done:l,value:d}=await s.read();if(l)break;d&&d.byteLength>0&&i.enqueue(d)}try{i.close()}catch{}}catch(l){try{i.error(l)}catch{}}})()},cancel(){try{s.cancel()}catch{}}}),writable:n.writable,closed:c,send:async i=>{let l=n.writable.getWriter();try{await l.write(i)}finally{try{l.releaseLock()}catch{}}}}}function mn(e,t){let r=new Uint8Array(e.length+t.length);return r.set(e,0),r.set(t,e.length),r}function gn(e){for(let t=0;t+3<e.length;t++)if(e[t]===13&&e[t+1]===10&&e[t+2]===13&&e[t+3]===10)return t;return-1}function yn(e){for(let t=0;t+1<e.length;t++)if(e[t]===13&&e[t+1]===10)return new TextDecoder().decode(e.slice(0,t));return""}async function Fe(e,t){let r=e.sni&&e.sni!==""?e.sni:e.address,a=Number(e.port),n;try{n=globalThis.connect?globalThis.connect({hostname:r,port:a,secureTransport:e.tls?"on":"off"}):void 0}catch(y){return t(`[VLESS/httpupgrade] connect error: ${y.message}`),null}if(!n)return t("[VLESS/httpupgrade] connect unavailable"),null;let o=`GET ${e.path&&e.path.startsWith("/")?e.path:`/${e.path||""}`} HTTP/1.1\r
Host: ${r}:${a}\r
Connection: Upgrade\r
Upgrade: websocket\r
\r
`,c=n.readable.getReader(),u,i=new Promise(y=>{u=y});(n.closed||Promise.resolve()).then(u,u);let l=new Uint8Array(0),d=new Uint8Array(0);try{await Promise.race([(async()=>{let y=n.writable.getWriter();try{await y.write(new TextEncoder().encode(o))}finally{try{y.releaseLock()}catch{}}for(;;){let{done:m,value:g}=await c.read();if(m)break;if(g&&g.byteLength>0){l=mn(l,g);let f=gn(l);if(f>=0){d=l.slice(f+4);return}}}throw new Error("connection closed during handshake")})(),new Promise((y,m)=>setTimeout(()=>m(new Error("Handshake timeout")),1e4))])}catch(y){t(`[VLESS/httpupgrade] handshake failed: ${y.message}`);try{n.close()}catch{}return null}let h=yn(l);if(!/^HTTP\/1\.1 101/.test(h)){t(`[VLESS/httpupgrade] upgrade rejected: ${h}`);try{n.close()}catch{}return null}return{readable:new ReadableStream({start(y){d.byteLength>0&&y.enqueue(d),(async()=>{try{for(;;){let{done:m,value:g}=await c.read();if(m)break;g&&g.byteLength>0&&y.enqueue(g)}try{y.close()}catch{}}catch(m){try{y.error(m)}catch{}}})()},cancel(){try{c.cancel()}catch{}}}),writable:n.writable,closed:i,send:async y=>{let m=n.writable.getWriter();try{await m.write(y)}finally{try{m.releaseLock()}catch{}}}}}var bn=`PRI * HTTP/2.0\r
\r
SM\r
\r
`;var Gt=new TextEncoder;function wn(e,t){let r=Gt.encode(e),a=Gt.encode(t),n=new Uint8Array(2+r.length+1+a.length);return n[0]=0,n[1]=r.length,n.set(r,2),n[2+r.length]=a.length,n.set(a,3+r.length),n}function xn(e){let t=new Uint8Array(0);for(let[r,a]of e)t=ut(t,wn(r,a));return t}function K(e,t,r,a){let n=a.length,s=new Uint8Array(9+n);return s[0]=n>>16&255,s[1]=n>>8&255,s[2]=n&255,s[3]=e,s[4]=t,s[5]=r>>24&127,s[6]=r>>16&255,s[7]=r>>8&255,s[8]=r&255,s.set(a,9),s}function ze(e){let t=new Uint8Array(5+e.length);return t[0]=0,new DataView(t.buffer,t.byteOffset,5).setUint32(1,e.length,!1),t.set(e,5),t}function Be(e){let t=new Uint8Array(4);return new DataView(t.buffer).setUint32(0,e>>>0,!1),t}function ut(e,t){let r=new Uint8Array(e.length+t.length);return r.set(e,0),r.set(t,e.length),r}async function je(e,t){let r=[],a=0;for(;a<t;){let{done:s,value:o}=await e.read();if(s)return null;!o||o.byteLength===0||(r.push(o),a+=o.byteLength)}let n;if(r.length===1)n=r[0];else{n=ut(r[0],r[1]);for(let s=2;s<r.length;s++)n=ut(n,r[s])}return n.byteLength>t?{data:n.slice(0,t),extra:n.slice(t)}:{data:n,extra:null}}async function Ge(e,t){let r=e.sni&&e.sni!==""?e.sni:e.address,a=Number(e.port),n;try{n=globalThis.connect?globalThis.connect({hostname:r,port:a,secureTransport:e.tls?"on":"off"}):void 0}catch(m){return t(`[VLESS/grpc] connect error: ${m.message}`),null}if(!n)return t("[VLESS/grpc] connect unavailable"),null;let s=n.writable.getWriter();async function o(m){await s.write(m)}let c,u=new Promise(m=>{c=m});(n.closed||Promise.resolve()).then(c,c);try{await o(Gt.encode(bn)),await o(K(4,0,0,new Uint8Array(0)));let m=e.tls?"https":"http",g=(e.path||"").replace(/^\/+/,"").replace(/\/+$/,""),f=g?`/${g}/Tun`:"/Tun",b=xn([[":method","POST"],[":scheme",m],[":path",f],[":authority",`${r}:${a}`],["content-type","application/grpc"],["te","trailers"],["user-agent","grpc-go/1.68.0"]]);await o(K(1,4,1,b))}catch(m){t(`[VLESS/grpc] handshake failed: ${m.message}`);try{n.close()}catch{}return null}let i=n.readable.getReader(),l={needLen:5,buf:new Uint8Array(0),msgLen:0,controller:null,extra:null};function d(m,g){let f=m;for(;f.byteLength>0;)if(l.needLen>0){let b=Math.min(l.needLen,f.byteLength);l.buf=ut(l.buf,f.slice(0,b)),f=f.slice(b),l.needLen-=b,l.needLen===0&&(l.buf.byteLength===5?(l.msgLen=new DataView(l.buf.buffer,l.buf.byteOffset,5).getUint32(1,!1),l.buf=new Uint8Array(0),l.needLen=l.msgLen,l.msgLen===0&&(l.needLen=5)):(l.buf=new Uint8Array(0),l.needLen=5))}else{let b=Math.min(l.msgLen,f.byteLength);if(l.buf=ut(l.buf,f.slice(0,b)),f=f.slice(b),l.msgLen-=b,l.msgLen===0){if(l.buf.byteLength>0)try{g.enqueue(l.buf)}catch{}l.buf=new Uint8Array(0),l.needLen=5}}}let h=new ReadableStream({start(m){l.controller=m,(async()=>{try{for(;;){let g;if(l.extra)g=l.extra,l.extra=null;else{let f=await je(i,9);if(!f)break;let b=f.data[0]<<16|f.data[1]<<8|f.data[2],w=f.data[3],k=f.data[4],v=(f.data[5]&127)<<24|f.data[6]<<16|f.data[7]<<8|f.data[8];if(b===0)g=new Uint8Array(0);else{let A=await je(i,b);if(!A)break;g=A.data,l.extra=A.extra}if(w===0&&v===1){d(g,m),await o(K(8,0,1,Be(g.byteLength))),await o(K(8,0,0,Be(g.byteLength)));continue}if(w===4){k&1||await o(K(4,1,0,new Uint8Array(0)));continue}if(w===6){k&1||await o(K(6,1,v,g));continue}if(w===7||w===3)break}}try{m.close()}catch{}}catch(g){t(`[VLESS/grpc] read loop error: ${g.message}`);try{m.error(g)}catch{}}finally{try{c()}catch{}}})()},cancel(){try{i.cancel()}catch{}}});function p(m){let g=[],f=0,b=!0;for(;f<m.byteLength;){let w=Math.min(16384,m.byteLength-f);g.push(K(0,0,1,m.slice(f,f+w))),f+=w,b=!1}return g}let y=new WritableStream({write(m){let g=m instanceof Uint8Array?m:new Uint8Array(m),f=ze(g),b=p(f);return(async()=>{for(let w of b)await o(w)})()},close(){try{n.close()}catch{}},abort(){try{n.close()}catch{}}});return{readable:h,writable:y,closed:u,send:async m=>{let g=ze(m);for(let f of p(g))await o(f)}}}var vn=`PRI * HTTP/2.0\r
\r
SM\r
\r
`;var Wt=new TextEncoder;function Tn(e,t){let r=Wt.encode(e),a=Wt.encode(t),n=new Uint8Array(2+r.length+1+a.length);return n[0]=0,n[1]=r.length,n.set(r,2),n[2+r.length]=a.length,n.set(a,3+r.length),n}function kn(e){let t=new Uint8Array(0);for(let[r,a]of e)t=Vt(t,Tn(r,a));return t}function Y(e,t,r,a){let n=a.length,s=new Uint8Array(9+n);return s[0]=n>>16&255,s[1]=n>>8&255,s[2]=n&255,s[3]=e,s[4]=t,s[5]=r>>24&127,s[6]=r>>16&255,s[7]=r>>8&255,s[8]=r&255,s.set(a,9),s}function We(e){let t=new Uint8Array(4);return new DataView(t.buffer).setUint32(0,e>>>0,!1),t}function Vt(e,t){let r=new Uint8Array(e.length+t.length);return r.set(e,0),r.set(t,e.length),r}async function Ve(e,t){let r=[],a=0;for(;a<t;){let{done:s,value:o}=await e.read();if(s)return null;!o||o.byteLength===0||(r.push(o),a+=o.byteLength)}let n;if(r.length===1)n=r[0];else{n=Vt(r[0],r[1]);for(let s=2;s<r.length;s++)n=Vt(n,r[s])}return n.byteLength>t?{data:n.slice(0,t),extra:n.slice(t)}:{data:n,extra:null}}async function Ke(e,t){let r=e.sni&&e.sni!==""?e.sni:e.address,a=Number(e.port),n;try{n=globalThis.connect?globalThis.connect({hostname:r,port:a,secureTransport:e.tls?"on":"off"}):void 0}catch(p){return t(`[VLESS/h2] connect error: ${p.message}`),null}if(!n)return t("[VLESS/h2] connect unavailable"),null;let s=n.writable.getWriter();async function o(p){await s.write(p)}let c,u=new Promise(p=>{c=p});(n.closed||Promise.resolve()).then(c,c);try{await o(Wt.encode(vn)),await o(Y(4,0,0,new Uint8Array(0)));let p=e.tls?"https":"http",y=e.path&&e.path.startsWith("/")?e.path:`/${e.path||""}`,m=kn([[":method","POST"],[":scheme",p],[":path",y],[":authority",`${r}:${a}`],["content-length","0"],["user-agent","vless-h2/1.0.0"]]);await o(Y(1,4,1,m))}catch(p){t(`[VLESS/h2] handshake failed: ${p.message}`);try{n.close()}catch{}return null}let i=n.readable.getReader(),l=new ReadableStream({start(p){(async()=>{let y=null;try{for(;;){let m;if(y)m=y,y=null;else{let g=await Ve(i,9);if(!g)break;let f=g.data[0]<<16|g.data[1]<<8|g.data[2],b=g.data[3],w=g.data[4],k=(g.data[5]&127)<<24|g.data[6]<<16|g.data[7]<<8|g.data[8];if(f===0)m=new Uint8Array(0);else{let v=await Ve(i,f);if(!v)break;m=v.data,y=v.extra}if(b===0&&k===1){if(m.byteLength>0)try{p.enqueue(m)}catch{}await o(Y(8,0,1,We(m.byteLength))),await o(Y(8,0,0,We(m.byteLength)));continue}if(b===4){w&1||await o(Y(4,1,0,new Uint8Array(0)));continue}if(b===6){w&1||await o(Y(6,1,k,m));continue}if(b===7||b===3)break}}try{p.close()}catch{}}catch(m){t(`[VLESS/h2] read loop error: ${m.message}`);try{p.error(m)}catch{}}finally{try{c()}catch{}}})()},cancel(){try{i.cancel()}catch{}}});function d(p){let y=[],m=0;for(;m<p.byteLength;){let g=Math.min(16384,p.byteLength-m);y.push(Y(0,0,1,p.slice(m,m+g))),m+=g}return y}let h=new WritableStream({write(p){let y=p instanceof Uint8Array?p:new Uint8Array(p);return(async()=>{for(let m of d(y))await o(m)})()},close(){try{n.close()}catch{}},abort(){try{n.close()}catch{}}});return{readable:l,writable:h,closed:u,send:async p=>{for(let y of d(p))await o(y)}}}var Sn=1e4;async function tt(e,t,r,a,n,s,o){let c=e.transport||"ws";if(!xe.includes(c))return o(`[VLESS] unsupported transport: ${c}`),null;let u=null;try{c==="ws"?u=await An(e,o):c==="raw"?u=await He(e,o):c==="httpupgrade"?u=await Fe(e,o):c==="grpc"?u=await Ge(e,o):c==="h2"&&(u=await Ke(e,o))}catch(h){return o(`[VLESS/${c}] connect failed: ${h.message}`),null}if(!u)return null;let i=Pe(t,r,a,n,e.uuid),l=s instanceof Uint8Array?s:new Uint8Array(s||0),d=new Uint8Array(i.length+l.length);d.set(i,0),d.set(l,i.length);try{await u.send(d)}catch(h){o(`[VLESS/${c}] send header failed: ${h.message}`);try{u.close&&await u.close()}catch{}return null}return{readable:u.readable,writable:u.writable,closed:u.closed}}async function An(e,t){let r=e.tls?"wss":"ws",a=e.path&&e.path.startsWith("/")?e.path:`/${e.path||""}`,n=e.sni&&e.sni!==""?e.sni:e.address,s=`${r}://${n}:${e.port}${a}`,o;try{o=new WebSocket(s),"binaryType"in o&&(o.binaryType="arraybuffer")}catch(h){return t(`[VLESS/ws] create ws failed: ${h.message}`),null}let c,u=new Promise(h=>{c=h});try{await new Promise((h,p)=>{let y=setTimeout(()=>p(new Error("Connection timeout")),Sn);o.addEventListener("open",()=>{clearTimeout(y),h()}),o.addEventListener("close",m=>{clearTimeout(y),p(new Error(`closed ${m.code}`))}),o.addEventListener("error",()=>{clearTimeout(y),p(new Error("ws error"))})})}catch(h){t(`[VLESS/ws] connect failed: ${h.message}`);try{o.close()}catch{}return c(),null}o.addEventListener("close",()=>c()),o.addEventListener("error",()=>{});let i=new WritableStream({write(h){o.readyState===1&&o.send(h)},close(){N(o)},abort(){N(o)}}),l=!1;return{readable:new ReadableStream({start(h){o.addEventListener("message",p=>{let y;try{p.data instanceof ArrayBuffer?y=new Uint8Array(p.data):ArrayBuffer.isView(p.data)?y=new Uint8Array(p.data.buffer,p.data.byteOffset,p.data.byteLength):typeof p.data=="string"?y=new TextEncoder().encode(p.data):y=null}catch{y=null}if(y){if(!l&&(l=!0,y.length>=2&&y[0]===0)){let m=y[1];if(y.length>2+m)y=y.slice(2+m);else return}if(y.length>0)try{h.enqueue(y)}catch{}}}),o.addEventListener("close",()=>{try{h.close()}catch{}}),o.addEventListener("error",p=>{try{h.error(p)}catch{}})},cancel(){N(o)}}),writable:i,closed:u,send:async h=>{if(o.readyState!==1)throw new Error(`ws not open (state=${o.readyState})`);o.send(h)}}}async function dt(e,t,r){for(;t.buf.length<r;){let{done:n,value:s}=await e.read();if(n)return null;if(!s||s.byteLength===0)continue;let o=new Uint8Array(t.buf.length+s.byteLength);o.set(t.buf,0),o.set(s,t.buf.length),t.buf=o}let a=t.buf.slice(0,r);return t.buf=t.buf.slice(r),a}async function Ye(e,t,r,a,n,s){let{username:o,password:c,hostname:u,port:i}=n,l=s({hostname:u,port:i}),d=l.writable.getWriter(),h=l.readable.getReader(),p=new TextEncoder,y={buf:new Uint8Array(0)};try{await d.write(new Uint8Array([5,2,0,2]));let m=await dt(h,y,2);if(!m||m[0]!==5){a("socks version error");return}if(m[1]===255){a("no acceptable methods");return}if(m[1]===2){if(!o||!c){a("socks server requires auth but no credentials");return}let v=new Uint8Array([1,o.length,...p.encode(o),c.length,...p.encode(c)]);if(await d.write(v),m=await dt(h,y,2),!m||m[0]!==1||m[1]!==0){a("socks auth failed");return}}let g;switch(e){case 1:g=new Uint8Array([1,...t.split(".").map(Number)]);break;case 2:g=new Uint8Array([3,t.length,...p.encode(t)]);break;case 3:g=new Uint8Array([4,...Bt(t).split(":").flatMap(v=>[parseInt(v.slice(0,2),16),parseInt(v.slice(2),16)])]);break;default:a(`invalid addressType ${e}`);return}let f=new Uint8Array([5,1,0,...g,r>>8,r&255]);await d.write(f);let b=await dt(h,y,4);if(!b||b[0]!==5){a("socks version error");return}if(b[1]!==0){a(`socks connect failed rep=${b[1]}`);return}let w=0;switch(b[3]){case 1:w=6;break;case 3:w=3;break;case 4:w=18;break;default:a(`socks invalid ATYP ${b[3]}`);return}if(b[3]===3){let v=await dt(h,y,1);if(!v)return;w+=v[0]}if(!await dt(h,y,w))return;if(d.releaseLock(),y.buf.length>0){let v=y.buf.slice();return{readable:new ReadableStream({pull($){if(v.length>0){let L=v;v=new Uint8Array(0),$.enqueue(L);return}return h.read().then(({done:L,value:_})=>{L?$.close():_&&_.byteLength>0&&$.enqueue(_)})},cancel(){try{h.cancel()}catch{}}}),writable:l.writable,closed:l.closed||Promise.resolve()}}return h.releaseLock(),l}catch(m){a(`socks5 error: ${m.message}`);try{d.releaseLock()}catch{}try{h.releaseLock()}catch{}try{l.close()}catch{}return}}function qe(e,t={}){let r=String(e||"").trim().replace(/^socks5?:\/\//i,""),[a,n]=r.split("@").reverse(),s,o,c,u;if(n){let l=n.split(":");if(l.length!==2)throw new Error("Invalid SOCKS address format");[s,o]=l}let i=a.split(":");if(u=Number(i[i.length-1]),isNaN(u))if(t&&t.port!==void 0&&t.port!==null&&t.port!=="")u=Number(t.port),c=a;else throw new Error("Invalid SOCKS address format");else c=i.slice(0,-1).join(":");if(isNaN(u)||!c)throw new Error("Invalid SOCKS address format");return t&&t.username!==void 0&&t.username!==null&&t.username!==""&&(s=t.username),t&&t.password!==void 0&&t.password!==null&&t.password!==""&&(o=t.password),{username:s,password:o,hostname:c,port:u}}async function Je(e,t,r,a,n,s,o=new Uint8Array(0)){let{username:c,password:u,hostname:i,port:l}=n,d=s({hostname:i,port:l}),h=d.writable.getWriter(),p=d.readable.getReader();try{let y=c&&u?`Proxy-Authorization: Basic ${btoa(`${c}:${u}`)}\r
`:"",m=`CONNECT ${t}:${r} HTTP/1.1\r
Host: ${t}:${r}\r
${y}User-Agent: Mozilla/5.0\r
Connection: keep-alive\r
\r
`;await h.write(new TextEncoder().encode(m));let g=new Uint8Array(0),f=-1,b=0;for(;f===-1&&b<8192;){let{done:A,value:$}=await p.read();if(A)throw new Error("Connection closed before HTTP response");let L=new Uint8Array(g.length+$.length);L.set(g,0),L.set($,g.length),g=L,b=g.length;for(let _=0;_<g.length-3;_++)if(g[_]===13&&g[_+1]===10&&g[_+2]===13&&g[_+3]===10){f=_+4;break}}if(f===-1)throw new Error("Invalid HTTP response");let k=new TextDecoder().decode(g.slice(0,f)).split(`\r
`)[0].match(/HTTP\/\d\.\d\s+(\d+)/);if(!k)throw new Error("Invalid HTTP response format");let v=parseInt(k[1]);if(v<200||v>=300)throw new Error(`HTTP CONNECT failed: HTTP ${v}`);return o.length>0&&await h.write(o),h.releaseLock(),p.releaseLock(),d}catch(y){a(`http connect error: ${y.message}`);try{h.releaseLock()}catch{}try{p.releaseLock()}catch{}try{d.close()}catch{}return}}function Xe(e,t={}){let[r,a]=String(e||"").trim().split("@").reverse(),n,s,o,c;if(a){let i=a.split(":");if(i.length!==2)throw new Error("Invalid HTTP address format");[n,s]=i}let u=r.split(":");if(c=Number(u[u.length-1]),isNaN(c))if(t&&t.port!==void 0&&t.port!==null&&t.port!=="")c=Number(t.port),o=r;else throw new Error("Invalid HTTP address format");else o=u.slice(0,-1).join(":");if(isNaN(c)||!o)throw new Error("Invalid HTTP address format");return t&&t.username!==void 0&&t.username!==null&&t.username!==""&&(n=t.username),t&&t.password!==void 0&&t.password!==null&&t.password!==""&&(s=t.password),{username:n,password:s,hostname:o,port:c}}var _n=3e5,Ze=new Map;async function pt(e,t,r="A"){let a=`${r}:${e}`,n=Ze.get(a);if(n&&Date.now()-n.ts<_n)return t(`doh cache ${e} (${r}) -> ${n.ip}`),n.ip;let s=["https://8.8.8.8/resolve","https://8.8.4.4/resolve","https://doh.pub/resolve","https://dns.alidns.com/resolve"],o=r==="AAAA"?28:1,c=r==="AAAA"?/^[0-9a-fA-F:]+$/:/^\d{1,3}(\.\d{1,3}){3}$/,u=null;for(let i of s){let l=new AbortController,d=setTimeout(()=>l.abort(),2500);try{let h=`${i}?name=${encodeURIComponent(e)}&type=${r}`,p=await fetch(h,{headers:{accept:"application/dns-json"},signal:l.signal});if(p.ok){let y=await p.json(),g=(Array.isArray(y.Answer)?y.Answer:[]).find(f=>f.type===o&&c.test(f.data))?.data;if(g){clearTimeout(d),u=g,t(`doh resolved ${e} (${r}) -> ${g}`);break}}}catch{}finally{clearTimeout(d)}}return u?Ze.set(a,{ip:u,ts:Date.now()}):t(`doh resolve failed: ${e} (${r})`),u}var Ln=["173.245.48.0/20","103.21.244.0/22","103.22.200.0/22","103.31.4.0/22","141.101.64.0/18","108.162.192.0/18","190.93.240.0/20","188.114.96.0/20","197.234.240.0/22","198.41.128.0/17","162.158.0.0/15","104.16.0.0/13","104.24.0.0/14","172.64.0.0/13","131.0.72.0/22","1.0.0.0/24","1.1.1.0/24"].map(e=>{let[t,r]=e.split("/"),a=Number(r),n=a===0?0:4294967295<<32-a>>>0,s=t.split(".");return[(+s[0]<<24)+(+s[1]<<16)+(+s[2]<<8)+ +s[3]>>>0&n,n]});function $n(e){let t=e.split(".");return(+t[0]<<24)+(+t[1]<<16)+(+t[2]<<8)+ +t[3]>>>0}function ft(e){if(!/^\d{1,3}(\.\d{1,3}){3}$/.test(e))return!1;let t=$n(e);return Ln.some(([r,a])=>(t&a)===r)}var Un=[".cloudflare.com",".cloudflare.net",".jsdelivr.net",".workers.dev",".pages.dev",".trycloudflare.com",".cf-ipfs.com",".cloudflareinsights.com"];function Yt(e){let t=e.toLowerCase();return Un.some(r=>t===r.slice(1)||t.endsWith(r))}var tr=6e4,H={state:"unknown",downAt:0},G=new WeakMap;function q(e){H.state!=="down"&&(H.state="down",H.downAt=Date.now(),e("proxyip marked down (no response), degrade to direct for 60s"))}function On(e){H.state==="down"&&Date.now()-H.downAt>=tr&&(H.state="unknown",e("proxyip health reset to unknown, will retry proxyip"))}function er(){return H.state==="down"&&Date.now()-H.downAt<tr}function qt(e){if(!e.proxyipOutbound)return null;let t=V(e,e.proxyipOutbound);return!t||typeof t=="string"||t.type!==It&&t.type!==Pt&&t.type!==Mt?null:t}async function rr(e,t,r,a,n){let s=qt(e);if(!s)return null;let o=/^\d{1,3}(\.\d{1,3}){3}$/.test(t)?1:t.includes(":")?3:2;n(`direct ${t}:${r} -> retry via outbound ${s.name}`);let c=await W({config:e,outbound:s,addressType:o,addressRemote:t,portRemote:r,rawClientData:a||new Uint8Array(0),log:n,isUDP:!1});return c?(G.set(c,{usedProxyIp:!0}),c):null}async function nr(e,t,r,a,n){if(qt(e)){let l=await rr(e,t,r,a,n);return l||q(n),l}let o=e.proxyipHost,c=Number(e.proxyipPort||443);if(!o)return null;n(`direct ${t}:${r} -> retry via proxyip ${o}:${c}`);let u=await et(o,c,n);if(!u)return q(n),null;let i=await Jt(u,a,n);return i?(G.set(i,{usedProxyIp:!0}),i):(q(n),null)}async function Kt(e,t,r,a,n,s,o){let c=await Dn(t,r,a,n,o);if(!c)return o(`connect unavailable (${t}:${r})`),null;let u=await Jt(c,s,o);return u&&G.set(u,{usedProxyIp:!1}),u}async function et(e,t,r){let a;try{a=globalThis.connect?globalThis.connect({hostname:e,port:t}):void 0,a&&typeof a.then=="function"&&(a=await a)}catch(n){return r(`direct connect error: ${n.message}`),null}return a||null}async function Dn(e,t,r,a,n){if(!r&&!a){n(`direct ${e}:${t} -> native dns ${e}:${t}`);let s=await et(e,t,n);if(s)return s;let o=await pt(e,n);if(o&&(n(`direct ${e}:${t} -> doh fallback ${o}:${t}`),s=await et(o,t,n),s))return s;let c=await pt(e,n,"AAAA");if(c){let u=`[${c}]`;if(n(`direct ${e}:${t} -> doh aaaa fallback ${u}:${t}`),s=await et(u,t,n),s)return s}return null}return et(e,t,n)}async function Jt(e,t,r){if(t&&t.length>0){let a=e.writable.getWriter();try{await a.write(t)}catch(n){r(`direct initial write error: ${n.message}`)}finally{try{a.releaseLock()}catch{}}}return e}async function Qe(e,t,r,a,n){let s=(e.proxyipHost||e.proxyipOutbound)&&!e.proxyipDisabled,o=/^\d{1,3}(\.\d{1,3}){3}$/.test(t)||t.includes(":");On(n);let c=s&&H.state==="down",u=!o&&Yt(t),i=o&&!t.includes(":")&&ft(t),l=!1;if(s&&!c&&!o&&!u){let d=await pt(t,n);d&&ft(d)&&(l=!0,n(`doh cf-detect ${t} -> ${d} (cloudflare ip, use proxyip)`))}if(s&&!c&&(u||i||l)){let d=qt(e);if(d){let g=await rr(e,t,r,a,n);return g||(q(n),n(`proxyip outbound ${d.name} failed; degrade to direct ${t}:${r}`),Kt(e,t,r,o,u||l,a,n))}let h=e.proxyipHost,p=Number(e.proxyipPort||443);n(`direct ${t}:${r} -> proxyip ${h}:${p}`);let y=await et(h,p,n);if(!y)return q(n),n(`proxyip ${h}:${p} connect failed; degrade to direct ${t}:${r}`),Kt(e,t,r,o,u||l,a,n);let m=await Jt(y,a,n);return m&&G.set(m,{usedProxyIp:!0}),m}return Kt(e,t,r,o,u||l,a,n)}async function W(e){let{config:t,outbound:r,addressType:a,addressRemote:n,portRemote:s,rawClientData:o,log:c,isUDP:u}=e,i=r;if(!i||i===I)return Qe(t,n,s,o,c);if(i===Z)return c("rejected by routing rule"),null;switch(i.type){case I:return Qe(t,n,s,o,c);case Pt:{let l;try{l=qe(i.address,{username:i.username,password:i.password,port:i.port})}catch(h){return c(`bad socks5 address: ${h.message}`),null}let d=await Ye(a,n,s,c,l,globalThis.connect);if(!d)return null;if(o&&o.length>0){let h=d.writable.getWriter();try{await h.write(o)}catch(p){c(`socks5 write error: ${p.message}`)}finally{try{h.releaseLock()}catch{}}}return d}case Mt:{let l;try{l=Xe(i.address,{username:i.username,password:i.password,port:i.port})}catch(h){return c(`bad http address: ${h.message}`),null}return await Je(a,n,s,c,l,globalThis.connect,o||new Uint8Array(0))}case It:return tt({address:i.address,port:Number(i.port),uuid:i.uuid,path:i.path,tls:!!i.tls,sni:i.sni||"",transport:i.transport},u?2:1,a,n,s,o||new Uint8Array(0),c);default:return c(`unknown outbound type: ${i.type}`),null}}function V(e,t){return!t||t===I?I:t===Z?Z:e.outboundByName[t]||I}var Rn=3600*1e3,Xt=new Map;async function Zt(e,t,r){let a=`${t}:${r}`,n=Xt.get(a);if(n&&Date.now()-n.ts<Rn)return n.data;let s=null;try{let o=t==="geosite"?ve:Te,c=await e.GEO_KV.get(o+r);if(c){let u=JSON.parse(c);Array.isArray(u)&&(s=u)}}catch{}return s||(s=Cn(t,r)),Xt.set(a,{data:s,ts:Date.now()}),s}function Cn(e,t){if(e==="geosite")switch(t){case"cn":return ke;case"speedtest":return Ee;case"google":return Se;default:return[]}return[]}function ar(){Xt.clear()}function Pn(e){if(!e)return null;let t=String(e).trim();if(!t)return null;let r=t.match(/^geosite:(.+)$/i);if(r){let i=r[1].split(",").map(l=>l.trim()).filter(Boolean);return i.length===0?null:{type:"geosite",categories:i}}let a=t.match(/^geoip:(.+)$/i);if(a){let i=a[1].split(",").map(l=>l.trim()).filter(Boolean);return i.length===0?null:{type:"geoip",categories:i}}let n=t.match(/^domain:(.+)$/i);if(n)return{type:"domain",value:n[1].trim()};let s=t.match(/^full:(.+)$/i);if(s)return{type:"full",value:s[1].trim()};let o=t.match(/^keyword:(.+)$/i);if(o)return{type:"keyword",value:o[1].trim()};let c=t.match(/^ip-cidr:(.+)$/i);if(c)return{type:"ip-cidr",value:c[1].trim()};let u=t.match(/^regexp:(.+)$/i);return u?{type:"regexp",value:u[1].trim()}:{type:"domain",value:t}}function sr(e){let t=e.split(".");if(t.length!==4)return null;let r=0;for(let a of t){let n=Number(a);if(isNaN(n)||n<0||n>255)return null;r=r<<8|n}return r>>>0}function or(e){let t=String(e).replace(/^\[|\]$/g,""),r=t.indexOf("::"),a,n;if(r>=0?(a=r===0?[]:t.slice(0,r).split(":"),n=r===t.length-2?[]:t.slice(r+2).split(":")):(a=t.split(":"),n=[]),a.length+n.length>8)return null;let s=8-a.length-n.length,o=[...a,...Array(s).fill("0"),...n],c=0n;for(let u of o){if(!u)return null;let i=parseInt(u,16);if(isNaN(i))return null;c=c<<16n|BigInt(i)}return c}function ir(e,t){let r=t.indexOf("/"),a=r>=0?t.slice(0,r):t,n=e.includes(":")?128:32,s=r>=0?Number(t.slice(r+1)):n;if(e.includes(":")){let i=or(e),l=or(a);if(i===null||l===null||isNaN(s)||s<0||s>128)return!1;let d=s===0?0n:(1n<<128n)-1n^(1n<<BigInt(128-s))-1n;return(i&d)===(l&d)}let o=sr(e);if(o===null)return!1;let c=sr(a);if(c===null)return!1;let u=s<=0?0:4294967295<<32-s>>>0;return(o&u)===(c&u)}function lr(e,t){let r=e.toLowerCase(),a=t.toLowerCase();return r===a?!0:r.endsWith("."+a)||r.endsWith(a)}var cr=new Map;function Mn(e){let t=cr.get(e);if(!t){try{t=new RegExp(e)}catch{t=null}cr.set(e,t)}return t}async function In(e,t,r,a){switch(e.type){case"domain":return r?!1:lr(t,e.value);case"full":return r?!1:t.toLowerCase()===e.value.toLowerCase();case"keyword":return r?!1:t.toLowerCase().includes(e.value.toLowerCase());case"regexp":{if(r)return!1;let n=Mn(e.value);return n?n.test(t):!1}case"ip-cidr":return r?ir(t,e.value):!1;case"geosite":{if(r)return!1;for(let n of e.categories){let s=await Zt(a,"geosite",n);for(let o of s)if(lr(t,o))return!0}return!1}case"geoip":{if(!r)return!1;for(let n of e.categories){let s=await Zt(a,"geoip",n);for(let o of s)if(ir(t,o))return!0}return!1}default:return!1}}var Nn=6e4,Hn=1e4,Et=new Map;async function ht(e,t,r){let a=`${t}:${r.toLowerCase()}`,n=Et.get(a);if(n&&Date.now()-n.ts<Nn)return{outbound:n.outbound,rule:n.rule};let s=t===1||t===3,o=e.defaultOutbound||"direct",c=null;for(let u of e.routingRules){let i=Pn(u.rule);if(!i)continue;if(await In(i,r,s,e.env)){o=u.outbound||"direct",c=u;break}}return Et.size>=Hn&&Et.clear(),Et.set(a,{outbound:o,rule:c,ts:Date.now()}),{outbound:o,rule:c}}async function J(e,t,r,a){let n;try{n=await a.read()}catch(f){r(`read first packet error: ${f.message}`);try{await a.close()}catch{}return}if(!n){try{await a.close()}catch{}return}let s,o=null,c="vless",u=e._inboundScope||null,i=u&&!u.all?u.vless:e.uuidSet,l=u&&!u.all?u.trojan:e.passwordSet;if(Me(n)){if(s=await Ie(n,l),s.hasError){r(`trojan header error: ${s.message}`);try{await a.close()}catch{}return}c="trojan",o=e.trojanIndex[s.userPassword]||null}else{if(s=Ce(n,i),s.hasError){r(`vless header error: ${s.message}`);try{await a.close()}catch{}return}try{await a.write(new Uint8Array([0,0]))}catch{}o=e.vlessIndex[s.userUuid]||null}if(o){let f=Math.floor(Date.now()/1e3);if(o.expire_at>0&&o.expire_at<f){r(`${c} user '${o.remark||o.uuid||o.password}' expired`);try{await a.close()}catch{}return}if(o.traffic_limit>0&&Number(o.up)+Number(o.down)>=Number(o.traffic_limit)){r(`${c} user '${o.remark||o.uuid||o.password}' traffic limit reached`);try{await a.close()}catch{}return}}let{addressType:d,addressRemote:h,portRemote:p,isUDP:y}=s,m=new Uint8Array(n.slice(s.rawDataIndex)),g;try{g=await ht(e,d,h)}catch(f){r(`route error: ${f.message}`);try{await a.close()}catch{}return}y?await zn(a,e,d,h,p,m,o,c,g,r):await Fn(a,e,d,h,p,m,o,c,g,r)}async function Fn(e,t,r,a,n,s,o,c,u,i){let l=V(t,u.outbound),d=s&&s.length>0?s:new Uint8Array(0),h=[l];l!=="direct"&&l!=="reject"&&h.push("direct");let p=null,y=null;for(let x of h){try{p=await W({config:t,outbound:x,addressType:r,addressRemote:a,portRemote:n,rawClientData:d,log:i})}catch(S){y=S,p=null}if(p)break}if(!p){i(`tcp connect failed: ${y?y.message:"no outbound available"}`);try{await e.close()}catch{}return}let m=0,g=0,f=!1,b=15e3,w=Date.now(),k=setInterval(()=>{f||Date.now()-w>=b&&(w=Date.now(),e.write(new Uint8Array([0,0])).catch(()=>{}))},5e3),v=5e3,A=G.get(p)||null,$=!1,L=p.writable.getWriter(),_=async()=>{if($)return null;$=!0;let x=(!!t.proxyipHost||!!t.proxyipOutbound)&&!t.proxyipDisabled;try{await p.close()}catch{}if(A&&A.usedProxyIp){q(i),i(`proxyip ${a}:${n} no first packet, degrade to direct retry`);try{return await W({config:t,outbound:"direct",addressType:r,addressRemote:a,portRemote:n,rawClientData:d,log:i})||null}catch(S){return i(`direct retry error: ${S.message}`),null}}if(!x||n!==443)return null;i(`direct ${a}:${n} no first packet, retry via proxyip`);try{return await nr(t,a,n,d,i)}catch(S){return i(`proxyip retry error: ${S.message}`),null}},O=(async()=>{try{for(;;){let x=await e.read();if(x==null)break;x.byteLength!==0&&(m+=x.byteLength,w=Date.now(),await L.write(x))}}catch(x){i(`upstream read error: ${x.message}`)}})();try{let x=p.readable.getReader(),S=!1;for(;;){let D;if(!S&&!$){let U=null,M=x.read().then(B=>({tag:"read",...B})),z=new Promise(B=>{U=setTimeout(()=>B({tag:"timeout"}),v)});D=await Promise.race([M,z]),clearTimeout(U)}else D={tag:"read",...await x.read()};if(D.tag==="timeout"){i(`no first packet in ${v}ms (${a}:${n})`);let U=await _();if(!U)break;try{L.releaseLock()}catch{}p=U,L=p.writable.getWriter(),A=G.get(p)||null,x=p.readable.getReader(),S=!1;continue}if(D.done)break;D.value&&D.value.byteLength>0&&(S=!0,g+=D.value.byteLength,w=Date.now(),await e.write(D.value))}}catch(x){if(!$&&g===0){i(`tcp remote read error before first packet: ${x.message||x}`);let S=await _();if(S){try{L.releaseLock()}catch{}p=S,L=p.writable.getWriter(),A=G.get(p)||null,$=!0;let D=p.readable.getReader();try{for(;;){let{done:U,value:M}=await D.read();if(U)break;M&&M.byteLength>0&&(g+=M.byteLength,w=Date.now(),await e.write(M))}}catch(U){i(`fallback remote read error: ${U.message||U}`)}}}else i(`tcp remote read error: ${x.message||x}`)}f=!0,clearInterval(k);try{L.releaseLock()}catch{}try{await p.writable.close()}catch{}try{await e.close()}catch{}await O.catch(()=>{}),ur(t,o,c,m,g,i)}async function zn(e,t,r,a,n,s,o,c,u,i){let l=null,d=(t.udpOutbound||"").trim();if(d){let b=t.outboundByName[d];if(b&&b.type==="vless")l=b;else{i(`udp outbound '${d}' not found or not vless (only vless supports udp)`);try{await e.close()}catch{}return}}else{if(u.outbound&&u.outbound!=="direct"&&u.outbound!=="reject"){let b=V(t,u.outbound);b!=="direct"&&b!=="reject"&&b.type==="vless"&&(l=b)}l||(l=t.outbounds.find(b=>b.type==="vless"))}if(!l){i("udp requires a vless outbound, none configured");try{await e.close()}catch{}return}let h=s&&s.length>0?s:new Uint8Array([0,0]),p=await tt({address:l.address,port:Number(l.port),uuid:l.uuid,path:l.path,tls:!!l.tls,sni:l.sni||"",transport:l.transport||"ws"},2,r,a,n,h,i);if(!p){i("udp vless outbound connect failed");try{await e.close()}catch{}return}let y=0,m=0,g=p.writable.getWriter(),f=(async()=>{try{for(;;){let b=await e.read();if(b==null)break;b.byteLength!==0&&(y+=b.byteLength,await g.write(b))}}catch(b){i(`udp upstream read error: ${b.message}`)}})();try{let b=p.readable.getReader();for(;;){let{done:w,value:k}=await b.read();if(w)break;k&&k.byteLength>0&&(m+=k.byteLength,await e.write(k))}}catch(b){i(`udp read error: ${b.message}`)}try{g.releaseLock()}catch{}try{await p.writable.close()}catch{}try{await e.close()}catch{}await f.catch(()=>{}),ur(t,o,c,y,m,i)}async function ur(e,t,r,a,n,s){if(!t)return;let o=r==="vless"?"vless_users":"trojan_users";try{await e.env.DB.prepare(`UPDATE ${o} SET up = up + ?, down = down + ? WHERE id = ?`).bind(a,n,t.id).run()}catch(c){s(`record traffic error: ${c.message}`)}}function Bn(e){return e instanceof ArrayBuffer?new Uint8Array(e):ArrayBuffer.isView(e)?new Uint8Array(e.buffer,e.byteOffset,e.byteLength):typeof e=="string"?new TextEncoder().encode(e):Object.prototype.toString.call(e)==="[object ArrayBuffer]"?new Uint8Array(e):null}function Qt(e,t){let r=new URL(e.url).searchParams.get("ed"),a=e.headers.get("sec-websocket-protocol")||"";if(a){a.startsWith("base64,")&&(a=a.slice(7));let{earlyData:n,error:s}=Ne(a);if(s)return t(`early data decode error: ${s.message||s}`),null;if(n&&n.byteLength>0)return t(`early data injected: ${n.byteLength} B (ed=${r||"n/a"})`),new Uint8Array(n)}return r&&t(`ed=${r} declared but no sec-websocket-protocol payload`),null}async function dr(e,t,r){let a=e.headers.get("Upgrade");if(!a||a.toLowerCase()!=="websocket")return new Response("Expected WebSocket",{status:400});let[n,s]=Object.values(new WebSocketPair);s.accept();let o=(...u)=>console.log("[ws]",...u),c=Qt(e,o);return J(t,r,o,te(s,o,c)).catch(u=>{o(`ws handler error: ${u.message||u}`),N(s)}),new Response(null,{status:101,webSocket:n})}function te(e,t,r=null){let a=[],n=[],s=!1;r&&r.byteLength>0?a.push(r):setTimeout(()=>{!s&&a.length===0&&n.length>0&&(t("first packet timeout: no ws message within 6s"),N(e))},6e3);let o=async i=>{let l=i.data;typeof Blob<"u"&&l instanceof Blob&&(l=await l.arrayBuffer());let d=Bn(l);if(!d||d.byteLength===0){t(`message dropped: type=${Object.prototype.toString.call(i.data)} len=${l&&l.byteLength!=null?l.byteLength:l&&l.length!=null?l.length:"n/a"}`);return}let h=n.shift();h?h(d):a.push(d)},c=()=>{if(!s)for(s=!0;n.length;)n.shift()(null)},u=()=>c();return e.addEventListener("message",o),e.addEventListener("close",c),e.addEventListener("error",u),{read(){return a.length?Promise.resolve(a.shift()):s?Promise.resolve(null):new Promise(i=>n.push(i))},write(i){if(e.readyState===1)try{e.send(i)}catch{}return Promise.resolve()},close(){N(e)},feed(i){if(!i||i.byteLength===0)return;let l=n.shift();l?l(i):a.push(i)},signalClose(){c()}}}import{connect as jn}from"cloudflare:sockets";globalThis.connect=jn;var ee=class{constructor(t,r){this.state=t,this.env=r,this.io=null}async fetch(t){let r=t.headers.get("Upgrade");if(!r||r.toLowerCase()!=="websocket")return new Response("Expected WebSocket",{status:400});let a=(...l)=>console.log("[ws-do]",...l),n=await ct(t,this.env),s=new URL(t.url).pathname,o=n.inboundPathMap.get(s);if(!o||o.length===0)return new Response("Not Found",{status:404});n._inboundScope=Tt(o);let[c,u]=Object.values(new WebSocketPair);this.state.acceptWebSocket(u);let i=Qt(t,a);return this.io=te(u,a,i),J(n,this.env,a,this.io).catch(l=>{a(`ws session error: ${l.message||l}`);try{let d=String(l&&l.stack||l).slice(0,400);this.env.DB.prepare("INSERT INTO diag_log (ts, tag, result) VALUES (?, ?, ?)").bind(Date.now(),"session_error",d).run()}catch{}N(u)}),new Response(null,{status:101,webSocket:c})}async webSocketMessage(t,r){if(!this.io)return;let a=null;r instanceof ArrayBuffer?a=new Uint8Array(r):ArrayBuffer.isView(r)?a=new Uint8Array(r.buffer,r.byteOffset,r.byteLength):typeof r=="string"&&(a=new TextEncoder().encode(r)),!(!a||a.byteLength===0)&&this.io.feed(a)}async webSocketClose(t,r,a,n){console.log(`[ws-do] webSocketClose code=${r} wasClean=${n}`),this.io&&this.io.signalClose()}async webSocketError(t,r){console.log(`[ws-do] webSocketError ${r&&r.message||r}`),this.io&&this.io.signalClose()}};function re(e,t){let r=new Uint8Array(e.length+t.length);return r.set(e,0),r.set(t,e.length),r}function Gn(e){let t=new Uint8Array(5);return t[0]=0,t[1]=e>>>24&255,t[2]=e>>>16&255,t[3]=e>>>8&255,t[4]=e&255,t}function Wn(e){return re(Gn(e.byteLength),e)}async function pr(e,t,r){let a=(...i)=>console.log("[h2-in]",...i);if(!e.body)return new Response("Bad Request",{status:400});let n=e.body.getReader(),{readable:s,writable:o}=new TransformStream,c=o.getWriter();return J(t,r,a,{read:async()=>{let i=new Uint8Array(0);for(;;){let{done:l,value:d}=await n.read();if(l)return i.byteLength>0?i:null;if(i=re(i,d instanceof Uint8Array?d:new Uint8Array(d)),i.byteLength>=60)return i}},write:i=>c.write(i),close:async()=>{try{await n.cancel()}catch{}try{await c.close()}catch{}}}).catch(i=>{a(`h2 handler error: ${i.message||i}`),n.cancel().catch(()=>{}),c.close().catch(()=>{})}),new Response(s,{status:200,headers:{"Content-Type":"application/octet-stream","Cache-Control":"no-store"}})}async function fr(e,t,r){let a=(...l)=>console.log("[grpc-in]",...l);if(!e.body)return new Response("Bad Request",{status:400});let n=e.body.getReader(),{readable:s,writable:o}=new TransformStream,c=o.getWriter(),u=new Uint8Array(0);return J(t,r,a,{read:async()=>{for(;;){if(u.byteLength>=5){let h=u[1]<<24|u[2]<<16|u[3]<<8|u[4];if(u.byteLength>=5+h){let p=u.slice(5,5+h);return u=u.slice(5+h),p}}let{done:l,value:d}=await n.read();if(l){if(u.byteLength===0)return null;let h=u;return u=new Uint8Array(0),h}u=re(u,d instanceof Uint8Array?d:new Uint8Array(d))}},write:l=>c.write(Wn(l instanceof Uint8Array?l:new Uint8Array(l))),close:async()=>{try{await n.cancel()}catch{}try{await c.close()}catch{}}}).catch(l=>{a(`grpc handler error: ${l.message||l}`),n.cancel().catch(()=>{}),c.close().catch(()=>{})}),new Response(s,{status:200,headers:{"Content-Type":"application/grpc","Cache-Control":"no-store"}})}var hr="ed=2560",mt="random";function St(e){let t=e.startsWith("/")?e:`/${e}`;return/\?/.test(t)?`${t}&${hr}`:`${t}?${hr}`}function At(e){return(e.startsWith("/")?e:`/${e}`).replace(/\/+$/,"").replace(/^\//,"")}function gt(e){let t=e.transport||"ws",r=e.wsHost||e.host,a=e.sni||(e.tls?r:""),n=new URLSearchParams({encryption:"none",type:t,host:r,security:e.tls?"tls":"none",tfo:"1"});t==="grpc"?n.set("serviceName",`/${At(e.wsPath)}`):t==="h2"?n.set("path",e.wsPath.startsWith("/")?e.wsPath:`/${e.wsPath}`):n.set("path",St(e.wsPath)),e.tls&&a&&n.set("sni",a),e.tls&&n.set("fp",e.fp||mt);let s=encodeURIComponent(e.remark||`${e.host}:${e.port}`);return`vless://${e.uuid}@${e.host}:${e.port}?${n.toString()}#${s}`}function yt(e){let t=e.transport||"ws",r=e.wsHost||e.host,a=e.sni||(e.tls?r:""),n=new URLSearchParams({type:t,host:r,security:e.tls?"tls":"none",tfo:"1"});t==="grpc"?n.set("serviceName",`/${At(e.wsPath)}`):t==="h2"?n.set("path",e.wsPath.startsWith("/")?e.wsPath:`/${e.wsPath}`):n.set("path",St(e.wsPath)),e.tls&&a&&n.set("sni",a),e.tls&&n.set("fp",e.fp||mt);let s=encodeURIComponent(e.remark||`${e.host}:${e.port}`);return`trojan://${encodeURIComponent(e.password)}@${e.host}:${e.port}?${n.toString()}#${s}`}function mr(e){let t=e.headers.get("Host");return t?t.split(":")[0]:"example.com"}var bt=["ws","grpc","h2"];function Vn(e,t){let r=[],a=t.port||(t.tls?443:80),n=t.transports&&t.transports.length?t.transports:bt;for(let s of e.vlessUsers){let o=s.path||e.wsPath;for(let c of n)r.push(gt({uuid:s.uuid,host:t.host,port:a,wsPath:o,tls:t.tls,wsHost:t.wsHost,sni:t.sni,transport:c,remark:`vless-${s.remark||s.uuid.slice(0,8)}-${c}`}))}for(let s of e.trojanUsers){let o=s.path||e.wsPath;for(let c of n)r.push(yt({password:s.password,host:t.host,port:a,wsPath:o,tls:t.tls,wsHost:t.wsHost,sni:t.sni,transport:c,remark:`trojan-${s.remark||s.password.slice(0,8)}-${c}`}))}return r}function ne(e,t){return t.flatMap(a=>Vn(e,a)).join(`
`)+`
`}function gr(e,t){return btoa(ne(e,t))}function yr(e,t){let r=[],a=t.length>1;for(let s of t){let o=s.port||443,c=s.tls!==!1,u=s.wsHost||s.host,i=s.sni||(c?u:""),l=s.transports&&s.transports.length?s.transports:bt,d=a?(s.name||s.host)+"-":"",h=(p,y,m,g,f,b)=>{let w={name:d+p,type:y,server:s.host,port:o,[m]:g,network:b,tls:c,servername:i||void 0,"client-fingerprint":c?mt:void 0,tfo:!0,udp:!0,_wsHost:u};return b==="grpc"?w["grpc-opts"]={"grpc-service-name":`/${At(f)}`}:b==="h2"?w["h2-opts"]={path:f.startsWith("/")?f:`/${f}`,host:[u]}:w["ws-opts"]={path:St(f),headers:{Host:u}},w};e.vlessUsers.forEach((p,y)=>{for(let m of l)r.push(h(`vless-${p.remark||y+1}-${m}`,"vless","uuid",p.uuid,p.path||e.wsPath,m))}),e.trojanUsers.forEach((p,y)=>{for(let m of l)r.push(h(`trojan-${p.remark||y+1}-${m}`,"trojan","password",p.password,p.path||e.wsPath,m))})}let n=["proxies:"];for(let s of r)n.push(`  - name: "${s.name}"`),n.push(`    type: ${s.type}`),n.push(`    server: ${s.server}`),n.push(`    port: ${s.port}`),s.uuid&&n.push(`    uuid: ${s.uuid}`),s.password&&n.push(`    password: "${s.password}"`),n.push(`    network: ${s.network}`),n.push(`    tls: ${s.tls}`),s.servername&&n.push(`    servername: ${s.servername}`),s["client-fingerprint"]&&n.push(`    client-fingerprint: ${s["client-fingerprint"]}`),n.push("    tfo: true"),n.push("    udp: true"),s.network==="grpc"?(n.push("    grpc-opts:"),n.push(`      grpc-service-name: ${s["grpc-opts"]["grpc-service-name"]}`)):s.network==="h2"?(n.push("    h2-opts:"),n.push(`      path: ${s["h2-opts"].path}`),n.push("      host:"),n.push(`        - ${s._wsHost}`)):(n.push("    ws-opts:"),n.push(`      path: ${s["ws-opts"].path}`),n.push("      headers:"),n.push(`        Host: ${s._wsHost}`));return n.push(""),n.push("rules:"),n.push("  - MATCH,DIRECT"),n.join(`
`)}function br(e,t){let r=[],a=t.length>1,n=(s,o,c)=>o==="grpc"?{type:"grpc",service_name:`/${At(s)}`}:o==="h2"?{type:"http",host:[c],path:s.startsWith("/")?s:`/${s}`}:{type:"ws",path:St(s),headers:{Host:c}};for(let s of t){let o=s.port||443,c=s.wsHost||s.host,u=s.sni||(s.tls?c:""),i=s.transports&&s.transports.length?s.transports:bt,l=a?(s.name||s.host)+"-":"";for(let d of e.vlessUsers)for(let h of i)r.push({type:"vless",tag:l+`vless-${d.remark||d.uuid.slice(0,8)}-${h}`,server:s.host,server_port:o,uuid:d.uuid,transport:n(d.path||e.wsPath,h,c),tcp_fast_open:!0,tls:s.tls?{enabled:!0,server_name:u,fingerprint:mt}:null});for(let d of e.trojanUsers)for(let h of i)r.push({type:"trojan",tag:l+`trojan-${d.remark||d.password.slice(0,8)}-${h}`,server:s.host,server_port:o,password:d.password,transport:n(d.path||e.wsPath,h,c),tcp_fast_open:!0,tls:s.tls?{enabled:!0,server_name:u,fingerprint:mt}:null})}return JSON.stringify({outbounds:r,log:{level:"info"}},null,2)}function ae(e,t){let r=t.host,a=t.port||(t.tls?443:80),s=`/${(t.path||e.wsPath||"/ws").replace(/^\//,"")}`,o={host:r,port:a,wsPath:s,tls:t.tls,wsHost:t.wsHost,sni:t.sni},c=(p,y)=>t.kind==="vless"?gt({...o,uuid:t.credential,transport:p,remark:`vless-${y}`}):yt({...o,password:t.credential,transport:p,remark:`trojan-${y}`}),u=[{key:"ws",name:"WebSocket (ws)",link:c("ws","ws")},{key:"grpc",name:"gRPC",link:c("grpc","grpc")},{key:"h2",name:"HTTP/2 (h2)",link:c("h2","h2")}].filter(p=>(t.transports&&t.transports.length?t.transports:["ws","grpc","h2"]).includes(p.key)),i=t.kind==="vless"?"VLESS":"Trojan",l=u.map(p=>p.key).join(" / "),d=u.map((p,y)=>`
  <div class="row">
    <label>${p.name}</label>
    <div class="linkbox">
      <input type="text" readonly value="${p.link}" id="link${y}">
      <button onclick="copyLink(${y})">\u590D\u5236</button>
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
  <p class="desc">\u5165\u7AD9\u8DEF\u5F84\uFF1A<b>${s}</b>\uFF08\u5F53\u524D\u5165\u53E3\u652F\u6301\uFF1A${l||"\u65E0"}\uFF0C\u590D\u5236\u94FE\u63A5\u5BFC\u5165\u5BA2\u6237\u7AEF\uFF09</p>
  ${d}
</div>
<script>
function copyLink(i){ const el=document.getElementById('link'+i); el.select(); document.execCommand('copy'); el.style.borderColor='#34c759'; setTimeout(()=>el.style.borderColor='#d2d2d7',800); }
<\/script>
</body>
</html>`}function wr(e){let t=e.disguise_title||"AList",r=e.disguise_subtitle||"\u4E00\u4E2A\u652F\u6301\u591A\u5B58\u50A8\u7684\u6587\u4EF6\u5217\u8868\u7A0B\u5E8F";return`<!DOCTYPE html>
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
</html>`}function se(e,t=200){return new Response(e,{status:t,headers:{"Content-Type":"text/html; charset=utf-8","Cache-Control":"no-store"}})}function rt(e,t="text/plain; charset=utf-8"){return new Response(e,{headers:{"Content-Type":t,"Cache-Control":"no-store"}})}function Kn(e,t,r){switch((new URL(e.url).searchParams.get("format")||"base64").toLowerCase()){case"plain":return rt(ne(t,r));case"clash":case"yaml":return rt(yr(t,r),"text/yaml; charset=utf-8");case"singbox":case"sing-box":case"json":return rt(br(t,r),"application/json; charset=utf-8");default:return rt(gr(t,r))}}function Yn(e,t,r,a){let n=new URL(e.url),s=null;if(t.uuidSet.has(r)?s={kind:"vless",user:t.vlessIndex[r]}:t.passwordSet.has(r)&&(s={kind:"trojan",user:t.trojanIndex[r]}),!s)return new Response("Not Found",{status:404});let o=(n.searchParams.get("format")||"base64").toLowerCase(),c=a.host,u=a.port,i=s.user.path||t.wsPath,l=a.transports&&a.transports.length?a.transports:bt,d=[];for(let p of l)s.kind==="vless"?d.push(gt({uuid:s.user.uuid,host:c,port:u,wsPath:i,tls:a.tls,wsHost:a.wsHost,sni:a.sni,transport:p,remark:`vless-${s.user.remark||"node"}-${p}`})):d.push(yt({password:s.user.password,host:c,port:u,wsPath:i,tls:a.tls,wsHost:a.wsHost,sni:a.sni,transport:p,remark:`trojan-${s.user.remark||"node"}-${p}`}));let h=d.join(`
`)+`
`;return rt(o==="plain"?h:btoa(h))}async function xr(e,t,r){let a=new URL(e.url),n=a.pathname,s=mr(e),o=a.protocol==="https:",c=Number(a.port)||(o?443:80),u=s.toLowerCase().replace(/:\d+$/,""),i=m=>[m.host,m.wsHost].filter(Boolean).map(f=>f.toLowerCase().replace(/:\d+$/,"")).some(f=>f===u),l=t.entries.find(i),d=l?{host:l.host,port:Number(l.port)||443,tls:!0,wsHost:l.wsHost,sni:l.sni,transports:l.transports}:{host:s,port:c,tls:o,wsHost:s,sni:s},h;if(l?h=[{host:l.host,port:Number(l.port)||443,tls:!0,wsHost:l.wsHost,sni:l.sni,transports:l.transports,name:l.remark||l.host}]:t.entries.length?h=t.entries.map(m=>({host:m.host,port:Number(m.port)||443,tls:!0,wsHost:m.wsHost,sni:m.sni,transports:m.transports,name:m.remark||m.host})):h=[{host:s,port:c,tls:o,wsHost:s,sni:s}],n==="/subscribe")return Kn(e,t,h);let p=n.match(/^\/([^/]+)\/subscribe$/);if(p)return Yn(e,t,decodeURIComponent(p[1]),d);let y=n.match(/^\/([^/]+)$/);if(y){let m=decodeURIComponent(y[1]);if(t.uuidSet.has(m)){let g=t.vlessIndex[m];return se(ae(t,{host:d.host,port:d.port,tls:d.tls,wsHost:d.wsHost,sni:d.sni,transports:d.transports,credential:m,kind:"vless",path:g&&g.path||t.wsPath}))}if(t.passwordSet.has(m)){let g=t.trojanIndex[m];return se(ae(t,{host:d.host,port:d.port,tls:d.tls,wsHost:d.wsHost,sni:d.sni,transports:d.transports,credential:m,kind:"trojan",path:g&&g.path||t.wsPath}))}}return se(wr(t.settings))}var vr="1.0.43-20260926-2155";function qn(e){if(e.length<2)return{frame:null,remaining:e,needMore:!0};let t=e[0]<<8|e[1];return t===0?{frame:new Uint8Array(0),remaining:e.slice(2),needMore:!1}:e.length<2+t?{frame:null,remaining:e,needMore:!0}:{frame:e.slice(2,2+t),remaining:e.slice(2+t),needMore:!1}}function Tr(e){let t=new Uint8Array(2+e.length);return t[0]=e.length>>8,t[1]=e.length&255,t.set(e,2),t}async function kr(e,t,r){let a=e.getReader(),n=new Uint8Array(0);try{for(;;){let{done:s,value:o}=await a.read();if(s)break;if(!o||o.byteLength===0)continue;let c=new Uint8Array(n.length+o.byteLength);for(c.set(n,0),c.set(o,n.length),n=c;;){let{frame:u,remaining:i,needMore:l}=qn(n);if(l){n=i;break}if(n=i,u&&u.length>0)try{await t(u)}catch(d){r(`udp frame handler error: ${d.message}`)}if(n.length<2)break}}}catch(s){r(`readUdpFrames error: ${s.message}`)}finally{try{a.releaseLock()}catch{}}}var Er=[{name:"\u5B57\u8282\u8DF3\u52A8",host:"www.bytedance.com",port:80,region:"cn",icon:"\u{1F3B5}",color:"#325AB4"},{name:"Bilibili",host:"www.bilibili.com",port:80,region:"cn",icon:"\u{1F4FA}",color:"#FB7299"},{name:"\u5FAE\u4FE1",host:"weixin.qq.com",port:80,region:"cn",icon:"\u{1F4AC}",color:"#07C160"},{name:"\u6DD8\u5B9D",host:"www.taobao.com",port:80,region:"cn",icon:"\u{1F6D2}",color:"#FF5000"},{name:"GitHub",host:"github.com",port:80,region:"intl",icon:"\u{1F419}",color:"#24292F"},{name:"jsDelivr",host:"cdn.jsdelivr.net",port:80,region:"intl",icon:"\u{1F4E6}",color:"#E84D0E"},{name:"Cloudflare",host:"www.cloudflare.com",port:80,region:"intl",icon:"\u2601\uFE0F",color:"#F6821F"},{name:"Google",host:"www.google.com",port:80,region:"intl",icon:"\u{1F50D}",color:"#4285F4"},{name:"YouTube",host:"www.youtube.com",port:80,region:"intl",icon:"\u25B6\uFE0F",color:"#FF0000"}],Sr=16,oe=3e3,Ar=4;var Jn=5e3,Xn=5e3;function _t(e,t,r="/"){return new TextEncoder().encode(`GET ${r} HTTP/1.1\r
Host: ${e}\r
User-Agent: Mozilla/5.0 (netprobe)\r
Connection: close\r
\r
`)}function Zn(e,t){let r=new Uint8Array(e.length+t.length);return r.set(e,0),r.set(t,e.length),r}function Qn(e){for(let t=0;t<e.length-3;t++)if(e[t]===13&&e[t+1]===10&&e[t+2]===13&&e[t+3]===10)return t+4;return-1}function ie(e){try{typeof e.close=="function"?e.close():e.writable&&typeof e.writable.close=="function"&&e.writable.close().catch(()=>{})}catch{}}function Lt(e,t){return new Promise(r=>{let a=new Uint8Array(0),n=!1,s=c=>{n||(n=!0,clearTimeout(o),r(c))},o=setTimeout(()=>s(null),t);(async()=>{let c=e.readable.getReader();try{for(;!n;){let{done:u,value:i}=await c.read();if(u)break;if(!(!i||i.byteLength===0)){if(a=Zn(a,i),Qn(a)>=0){s(Date.now());break}if(a.length>65536){s(null);break}}}}catch{}s(null);try{c.releaseLock()}catch{}})()})}async function ta(e,t,r,a,n){let s=Date.now(),o;try{let u=await ht(e,2,t),i=V(e,u.outbound);o=await W({config:e,outbound:i,addressType:2,addressRemote:t,portRemote:r,rawClientData:a,log:n})}catch{return null}if(!o)return null;let c=await Lt(o,oe);return ie(o),c===null?null:c-s}async function ea(e,t,r){let a=[];for(let i=0;i<Sr;i+=Ar){let l=[],d=Math.min(i+Ar,Sr);for(let p=i;p<d;p++)l.push(ta(e,t.host,t.port,_t(t.host,t.port),r));let h=await Promise.all(l);for(let p of h)a.push(p)}let n=a.filter(i=>i!==null),s=n.length>0?Math.round(n.reduce((i,l)=>i+l,0)/n.length):null,o=n.length>0?Math.min(...n):null,c=n.length>0?Math.max(...n):null,u=a.length>0?Math.round((a.length-n.length)/a.length*100):100;return{...t,samples:a,latency:s,min:o,max:c,loss:u,success:n.length,total:a.length}}async function _r(e,t){let r=await Promise.allSettled(Er.map(a=>ea(e,a,t)));return{ok:!0,ts:Date.now(),targets:r.map((a,n)=>a.status==="fulfilled"?a.value:{...Er[n],samples:[],latency:null,success:0,total:0,error:a.reason&&a.reason.message||"error"})}}async function Lr(e,t,r){let a=String(t||"").trim().toLowerCase();if(!a)return{ok:!1,error:"domain required"};let n=2;/^\d{1,3}(\.\d{1,3}){3}$/.test(a)?n=1:a.includes(":")&&(n=3);let s=n!==2,o=await ht(e,n,a),c=!!o.rule,u=c?`\u5206\u6D41\u89C4\u5219 ${o.rule.rule} \u2192 `:"",i=V(e,o.outbound);if(i==="reject")return{ok:!0,domain:a,route:"reject",name:"reject",reason:c?`${u}reject\uFF08\u62D2\u7EDD\u8FDE\u63A5\uFF09`:"\u9ED8\u8BA4\u51FA\u7AD9 reject\uFF08\u62D2\u7EDD\u8FDE\u63A5\uFF09",rule:c?o.rule.rule:null};if(i==="direct"){let d=o.outbound,h=(!!e.proxyipHost||!!e.proxyipOutbound)&&!e.proxyipDisabled,p=h&&er(),y=!s&&Yt(a),m=s&&!a.includes(":")&&ft(a),g=!1;if(h&&!p&&!s&&!y){let f=await pt(a,r);f&&ft(f)&&(g=!0)}if(h&&!p&&(y||m||g)){if(e.proxyipOutbound)return{ok:!0,domain:a,route:"proxyip",name:`outbound:${e.proxyipOutbound}`,reason:`${u}Cloudflare \u7AD9\u70B9\uFF08\u5DF2\u77E5 CF \u540E\u7F00/IP \u6BB5\uFF09\u2192 \u4F7F\u7528\u51FA\u7AD9\u4EE3\u7406 ${e.proxyipOutbound} \u51FA\u7AD9`,rule:c?o.rule.rule:null};let f=`${e.proxyipHost}:${Number(e.proxyipPort||443)}`;return{ok:!0,domain:a,route:"proxyip",name:f,reason:`${u}Cloudflare \u7AD9\u70B9\uFF08\u5DF2\u77E5 CF \u540E\u7F00/IP \u6BB5\uFF09\u2192 proxyip ${f}`,rule:c?o.rule.rule:null}}return c?{ok:!0,domain:a,route:"direct",name:"direct",reason:`${u}direct`,rule:o.rule.rule}:d&&d!=="direct"&&d!=="reject"?{ok:!0,domain:a,route:"direct",name:"direct",reason:`\u9ED8\u8BA4\u51FA\u7AD9 ${d} \u4E0D\u5B58\u5728\uFF0C\u56DE\u9000 direct`,rule:null}:{ok:!0,domain:a,route:"direct",name:"direct",reason:"\u9ED8\u8BA4\u51FA\u7AD9 direct",rule:null}}let l=typeof i=="string"?i:i.name;return{ok:!0,domain:a,route:"outbound",name:l,reason:c?`${u}\u51FA\u7AD9 ${l}`:`\u9ED8\u8BA4\u51FA\u7AD9 ${l}`,rule:c?o.rule.rule:null}}async function $r(e,t){let r="www.cloudflare.com";if(e.proxyipOutbound){let c=V(e,e.proxyipOutbound);if(!c||typeof c=="string")return{ok:!1,mode:"outbound",error:`\u51FA\u7AD9 ${e.proxyipOutbound} \u4E0D\u5B58\u5728\uFF0C\u8BF7\u68C0\u67E5\u51FA\u7AD9\u914D\u7F6E`};let u=Date.now(),i=null;try{i=await W({config:e,outbound:c,addressType:2,addressRemote:r,portRemote:443,rawClientData:_t(r,443),log:t,isUDP:!1})}catch(d){return{ok:!1,mode:"outbound",outbound:e.proxyipOutbound,error:`\u51FA\u7AD9\u8FDE\u63A5\u5931\u8D25: ${d.message}`}}if(!i)return{ok:!1,mode:"outbound",outbound:e.proxyipOutbound,error:"\u51FA\u7AD9\u8FDE\u63A5\u5931\u8D25\u6216\u65E0\u54CD\u5E94"};let l=await Lt(i,oe);return ie(i),l===null?{ok:!1,mode:"outbound",outbound:e.proxyipOutbound,error:"\u8FDE\u63A5\u8D85\u65F6\u6216\u65E0\u54CD\u5E94"}:{ok:!0,latency:l-u,mode:"outbound",outbound:e.proxyipOutbound}}if(!e.proxyipHost)return{ok:!1,error:"\u672A\u914D\u7F6E proxyip\uFF0C\u8BF7\u5148\u5728\u7CFB\u7EDF\u8BBE\u7F6E\u4E2D\u586B\u5199"};let n=Date.now(),s=null;try{if(s=globalThis.connect?globalThis.connect({hostname:e.proxyipHost,port:Number(e.proxyipPort||443)}):null,!s)return{ok:!1,error:"connect \u4E0D\u53EF\u7528"};let c=s.writable.getWriter();await c.write(_t(r,443)),c.releaseLock()}catch(c){try{s&&s.close()}catch{}return{ok:!1,error:`\u8FDE\u63A5\u5931\u8D25: ${c.message}`}}let o=await Lt(s,oe);try{s.close()}catch{}return o===null?{ok:!1,error:"\u8FDE\u63A5\u8D85\u65F6\u6216\u65E0\u54CD\u5E94"}:{ok:!0,latency:o-n,mode:"proxyip",endpoint:`${e.proxyipHost}:${e.proxyipPort||443}`}}function ra(e){let r=[18,52];r.push(1,0),r.push(0,1),r.push(0,0,0,0,0,0);for(let a of String(e).split(".")){r.push(a.length);for(let n=0;n<a.length;n++)r.push(a.charCodeAt(n))}return r.push(0),r.push(0,1),r.push(0,1),new Uint8Array(r)}async function Ur(e,t){let r=null,a=(e.udpOutbound||"").trim();if(a){let i=e.outboundByName[a];if(i&&i.type==="vless")r=i;else return{ok:!1,error:`UDP \u51FA\u7AD9 '${a}' \u4E0D\u5B58\u5728\u6216\u975E vless\uFF08\u4EC5 vless \u652F\u6301 UDP\uFF09`}}else if(r=e.outbounds.find(i=>i.type==="vless"),!r)return{ok:!1,error:"\u672A\u914D\u7F6E vless \u51FA\u7AD9\uFF0C\u65E0\u6CD5\u6D4B\u8BD5 UDP"};let n=ra("example.com"),s=Tr(n),o=Date.now(),c;try{c=await tt({address:r.address,port:Number(r.port),uuid:r.uuid,path:r.path,tls:!!r.tls,sni:r.sni||"",transport:r.transport},2,1,"8.8.8.8",53,s,t)}catch(i){return{ok:!1,error:`UDP \u51FA\u7AD9\u8FDE\u63A5\u5931\u8D25: ${i.message}`}}if(!c)return{ok:!1,error:"UDP \u51FA\u7AD9\u8FDE\u63A5\u5931\u8D25"};let u=await new Promise(i=>{let l=setTimeout(()=>i({ok:!1,error:"UDP \u54CD\u5E94\u8D85\u65F6"}),Jn);kr(c.readable,d=>{d.length>=12&&d[0]===18&&d[1]===52&&(d[2]&128)!==0&&(clearTimeout(l),i({ok:!0,latency:Date.now()-o,bytes:d.length,outbound:r.name||a||"vless"}))},t)});try{c.writable.close().catch(()=>{})}catch{}return u}async function Or(e,t,r){let a="www.gstatic.com",s=Date.now(),o;try{o=await W({config:e,outbound:t,addressType:2,addressRemote:a,portRemote:80,rawClientData:_t(a,80,"/generate_204"),log:r})}catch(u){return{ok:!1,error:u.message}}if(!o)return{ok:!1,error:"\u96A7\u9053\u5EFA\u7ACB\u5931\u8D25"};let c=await Lt(o,Xn);return ie(o),c===null?{ok:!1,error:"\u8FDE\u63A5\u8D85\u65F6\u6216\u65E0\u54CD\u5E94"}:{ok:!0,latency:c-s}}var R=Uint8Array,nt=Uint16Array,na=Int32Array,Dr=new R([0,0,0,0,0,0,0,0,1,1,1,1,2,2,2,2,3,3,3,3,4,4,4,4,5,5,5,5,0,0,0,0]),Rr=new R([0,0,0,0,1,1,2,2,3,3,4,4,5,5,6,6,7,7,8,8,9,9,10,10,11,11,12,12,13,13,0,0]),aa=new R([16,17,18,0,8,7,9,6,10,5,11,4,12,3,13,2,14,1,15]),Cr=function(e,t){for(var r=new nt(31),a=0;a<31;++a)r[a]=t+=1<<e[a-1];for(var n=new na(r[30]),a=1;a<30;++a)for(var s=r[a];s<r[a+1];++s)n[s]=s-r[a]<<5|a;return{b:r,r:n}},Pr=Cr(Dr,2),Mr=Pr.b,sa=Pr.r;Mr[28]=258,sa[258]=28;var Ir=Cr(Rr,0),oa=Ir.b,Js=Ir.r,ue=new nt(32768);for(E=0;E<32768;++E)F=(E&43690)>>1|(E&21845)<<1,F=(F&52428)>>2|(F&13107)<<2,F=(F&61680)>>4|(F&3855)<<4,ue[E]=((F&65280)>>8|(F&255)<<8)>>1;var F,E,wt=(function(e,t,r){for(var a=e.length,n=0,s=new nt(t);n<a;++n)e[n]&&++s[e[n]-1];var o=new nt(t);for(n=1;n<t;++n)o[n]=o[n-1]+s[n-1]<<1;var c;if(r){c=new nt(1<<t);var u=15-t;for(n=0;n<a;++n)if(e[n])for(var i=n<<4|e[n],l=t-e[n],d=o[e[n]-1]++<<l,h=d|(1<<l)-1;d<=h;++d)c[ue[d]>>u]=i}else for(c=new nt(a),n=0;n<a;++n)e[n]&&(c[n]=ue[o[e[n]-1]++]>>15-e[n]);return c}),xt=new R(288);for(E=0;E<144;++E)xt[E]=8;var E;for(E=144;E<256;++E)xt[E]=9;var E;for(E=256;E<280;++E)xt[E]=7;var E;for(E=280;E<288;++E)xt[E]=8;var E,Nr=new R(32);for(E=0;E<32;++E)Nr[E]=5;var E;var ia=wt(xt,9,1);var la=wt(Nr,5,1),le=function(e){for(var t=e[0],r=1;r<e.length;++r)e[r]>t&&(t=e[r]);return t},C=function(e,t,r){var a=t/8|0;return(e[a]|e[a+1]<<8)>>(t&7)&r},ce=function(e,t){var r=t/8|0;return(e[r]|e[r+1]<<8|e[r+2]<<16)>>(t&7)},ca=function(e){return(e+7)/8|0},ua=function(e,t,r){return(t==null||t<0)&&(t=0),(r==null||r>e.length)&&(r=e.length),new R(e.subarray(t,r))};var da=["unexpected EOF","invalid block type","invalid length/literal","invalid distance","stream finished","no stream handler",,"no callback","invalid UTF-8 data","extra field too long","date not in range 1980-2099","filename too long","stream finishing","invalid zip data"],P=function(e,t,r){var a=new Error(t||da[e]);if(a.code=e,Error.captureStackTrace&&Error.captureStackTrace(a,P),!r)throw a;return a},pa=function(e,t,r,a){var n=e.length,s=a?a.length:0;if(!n||t.f&&!t.l)return r||new R(0);var o=!r,c=o||t.i!=2,u=t.i;o&&(r=new R(n*3));var i=function(ye){var be=r.length;if(ye>be){var we=new R(Math.max(be*2,ye));we.set(r),r=we}},l=t.f||0,d=t.p||0,h=t.b||0,p=t.l,y=t.d,m=t.m,g=t.n,f=n*8;do{if(!p){l=C(e,d,1);var b=C(e,d+1,3);if(d+=3,b)if(b==1)p=ia,y=la,m=9,g=5;else if(b==2){var A=C(e,d,31)+257,$=C(e,d+10,15)+4,L=A+C(e,d+5,31)+1;d+=14;for(var _=new R(L),O=new R(19),x=0;x<$;++x)O[aa[x]]=C(e,d+x*3,7);d+=$*3;for(var S=le(O),D=(1<<S)-1,U=wt(O,S,1),x=0;x<L;){var M=U[C(e,d,D)];d+=M&15;var w=M>>4;if(w<16)_[x++]=w;else{var z=0,B=0;for(w==16?(B=3+C(e,d,3),d+=2,z=_[x-1]):w==17?(B=3+C(e,d,7),d+=3):w==18&&(B=11+C(e,d,127),d+=7);B--;)_[x++]=z}}var fe=_.subarray(0,A),j=_.subarray(A);m=le(fe),g=le(j),p=wt(fe,m,1),y=wt(j,g,1)}else P(1);else{var w=ca(d)+4,k=e[w-4]|e[w-3]<<8,v=w+k;if(v>n){u&&P(0);break}c&&i(h+k),r.set(e.subarray(w,v),h),t.b=h+=k,t.p=d=v*8,t.f=l;continue}if(d>f){u&&P(0);break}}c&&i(h+131072);for(var Kr=(1<<m)-1,Yr=(1<<g)-1,Dt=d;;Dt=d){var z=p[ce(e,d)&Kr],X=z>>4;if(d+=z&15,d>f){u&&P(0);break}if(z||P(2),X<256)r[h++]=X;else if(X==256){Dt=d,p=null;break}else{var he=X-254;if(X>264){var x=X-257,st=Dr[x];he=C(e,d,(1<<st)-1)+Mr[x],d+=st}var Rt=y[ce(e,d)&Yr],Ct=Rt>>4;Rt||P(3),d+=Rt&15;var j=oa[Ct];if(Ct>3){var st=Rr[Ct];j+=ce(e,d)&(1<<st)-1,d+=st}if(d>f){u&&P(0);break}c&&i(h+131072);var me=h+he;if(h<j){var ge=s-j,qr=Math.min(j,me);for(ge+h<0&&P(3);h<qr;++h)r[h]=a[ge+h]}for(;h<me;++h)r[h]=r[h-j]}}t.l=p,t.p=Dt,t.b=h,t.f=l,p&&(l=1,t.m=m,t.d=y,t.n=g)}while(!l);return h!=r.length&&o?ua(r,0,h):r.subarray(0,h)};var fa=new R(0);var ha=function(e,t){return((e[0]&15)!=8||e[0]>>4>7||(e[0]<<8|e[1])%31)&&P(6,"invalid zlib data"),(e[1]>>5&1)==+!t&&P(6,"invalid zlib data: "+(e[1]&32?"need":"unexpected")+" dictionary"),(e[1]>>3&4)+2};function Hr(e,t){return pa(e.subarray(ha(e,t&&t.dictionary),-4),{i:2},t&&t.out,t&&t.dictionary)}var ma=typeof TextDecoder<"u"&&new TextDecoder,ga=0;try{ma.decode(fa,{stream:!0}),ga=1}catch{}var de={"Content-Type":"application/json; charset=utf-8"},ya="gcp:asia-east2";function T(e,t=200){return new Response(JSON.stringify(e),{status:t,headers:de})}async function vt(e){try{return await e.json()}catch{return null}}function ba(e){return e.admin_cookie_secret||e.admin_password_hash||"vtd-insecure-secret"}async function Br(e,t,r){let a=new URL(e.url),s=a.pathname.split("/").filter(Boolean),o=s[2]||"",c=s[3]||null,u=e.method,{DB:i,GEO_KV:l}=t.env,d=t.settings,h=ba(d);if(o==="login"&&u==="POST"){let f=await vt(e);if(!f||!f.password)return T({error:"password required"},400);if(!await Le(f.password,t.adminPasswordHash))return T({error:"invalid password"},401);let w=await Ue(h);return new Response(JSON.stringify({ok:!0}),{status:200,headers:{...de,"Set-Cookie":`${ot}=${w}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${7*86400}`}})}let p=De(e.headers.get("Cookie"));if(!await Oe(p[ot],h))return T({error:"unauthorized"},401);if(o==="logout"&&u==="POST")return new Response(JSON.stringify({ok:!0}),{status:200,headers:{...de,"Set-Cookie":`${ot}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0`}});if(o==="version"&&u==="GET")return T({ok:!0,version:vr});if(o==="colo"&&u==="GET"){let f=e&&e.cf||{},b=e.headers.get("cf-placement")||"",w=null,k=null;if(b){let v=b.indexOf("-");v>0?(w=b.slice(0,v),k=b.slice(v+1)||null):w=b}return T({ok:!0,placement_header:b||null,placement_mode:w,placement_colo:k,colo:f.colo||null,region:f.region||null,city:f.city||null,country:f.country||null,continent:f.continent||null,timezone:f.timezone||null,host:a.hostname||null,configured_placement_region:ya})}if(await Ra(i),o==="settings"){if(u==="GET"){let{results:f}=await i.prepare("SELECT key, value FROM settings").all();return T((f||[]).reduce((b,w)=>(b[w.key]=w.value,b),{}))}if(u==="PUT"){let f=await vt(e);if(!f)return T({error:"bad body"},400);let b=new Set(["ws_path","default_outbound","proxyip","udp_outbound","disguise_title","disguise_subtitle","entry_host","entry_port","entry_sni","entry_ws_host","entry_list","admin_password_hash","admin_cookie_secret"]);if(f.entry_list!==void 0)try{let w=JSON.parse(f.entry_list);if(!Array.isArray(w)||w.some(k=>!k||!String(k.host||"").trim()))return T({error:"entry_list \u5FC5\u987B\u4E3A\u5165\u53E3\u6570\u7EC4\uFF08\u6BCF\u9879\u9700\u5305\u542B host\uFF09"},400);if(w.some(k=>Array.isArray(k.transports)&&k.transports.some(v=>!["ws","grpc","h2"].includes(v))))return T({error:"entry_list transports \u4EC5\u5141\u8BB8 ws / grpc / h2"},400)}catch{return T({error:"entry_list \u4E0D\u662F\u5408\u6CD5 JSON \u6570\u7EC4"},400)}for(let[w,k]of Object.entries(f))typeof k=="string"&&b.has(w)&&await i.prepare("INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at").bind(w,k,Date.now()).run();return Q("settings"),T({ok:!0})}return T({error:"method not allowed"},405)}let g={"vless-users":{table:"vless_users",cacheKey:"vlessUsers",cols:["uuid","remark","enable","path","expire_at","traffic_limit","traffic_reset_at"]},"trojan-users":{table:"trojan_users",cacheKey:"trojanUsers",cols:["password","remark","enable","path","expire_at","traffic_limit","traffic_reset_at"]},outbounds:{table:"outbounds",cacheKey:"outbounds",cols:["type","name","address","port","uuid","path","tls","udp","enable","sort","username","password","sni","transport"],validate(f){if(f.type!==void 0&&!["socks5","http","vless"].includes(f.type))return"invalid outbound type";if(f.port!==void 0&&(!Number.isInteger(Number(f.port))||Number(f.port)<=0||Number(f.port)>65535))return"invalid port";if((f.type==="socks5"||f.type==="http")&&!f.address)return"address required";if(f.type==="vless"){if(!f.uuid)return"vless requires uuid";if(f.transport!==void 0&&!["raw","ws","grpc","httpupgrade","h2"].includes(f.transport))return"invalid vless transport"}return f.username&&!f.password||!f.username&&f.password?"username and password must be set together":((f.type==="socks5"||f.type==="http")&&(f.udp=0),f.type!=="vless"&&(f.transport="ws"),null)}},"routing-rules":{table:"routing_rules",cacheKey:"routingRules",cols:["rule","outbound","enable","sort"]}}[o];if(g)return wa(u,c,g,i,e);if(o==="stats"&&u==="GET"){let[f,b]=await Promise.all([i.prepare("SELECT remark, uuid, up, down, path, expire_at, traffic_limit, traffic_reset_at FROM vless_users ORDER BY (up + down) DESC").all(),i.prepare("SELECT remark, password, up, down, path, expire_at, traffic_limit, traffic_reset_at FROM trojan_users ORDER BY (up + down) DESC").all()]),w=Math.floor(Date.now()/1e3),k=v=>(v||[]).map(A=>{let $=Number(A.up||0),L=Number(A.down||0),_=Number(A.traffic_limit||0),O=$+L;return{...A,used:O,remaining:_>0?Math.max(0,_-O):null,expired:A.expire_at>0&&A.expire_at<w,limitReached:_>0&&O>=_}});return T({vless:k(f.results),trojan:k(b.results)})}if(o==="geo"&&s[3]==="update"&&u==="POST")try{if(await l.get("geo:updating")==="1")return T({ok:!0,started:!1,updating:!0});if(await l.put("geo:updating","1",{expirationTtl:600}),t.env&&t.env.GEO_QUEUE&&typeof t.env.GEO_QUEUE.send=="function")return await t.env.GEO_QUEUE.send({kind:"geo-update"}),await l.put("geo:update_status",JSON.stringify({startedAt:Date.now(),state:"updating",step:0,total:0,updated:0,failed:[],current:"",message:"\u5DF2\u5165\u961F\uFF0C\u7B49\u5F85\u6D88\u8D39\u8005\u6267\u884C\u2026"})).catch(()=>{}),T({ok:!0,started:!0,queued:!0,updating:!0});if(r&&typeof r.waitUntil=="function")return r.waitUntil(Ut(i,l)),T({ok:!0,started:!0,updating:!0});let b=await Ut(i,l);return T({ok:!0,started:!1,updated:b.updated,total:b.total,failed:b.failed})}catch(f){return await l.put("geo:updating","0").catch(()=>{}),T({error:f.message},500)}if(o==="geo"&&s[3]==="status"&&u==="GET"){let[f,b,w]=await Promise.all([l.get("geo:updating"),l.get("geo:update_status"),l.get(Nt)]),k=null;if(b)try{k=JSON.parse(b)}catch{}return T({ok:!0,updating:f==="1",version:w||null,status:k})}if(o==="netstatus"&&s[3]==="test"&&u==="POST")try{return T(await _r(t,f=>console.log(f)))}catch(f){return T({ok:!1,error:f.message},500)}if(o==="route-test"&&u==="POST")try{let f=await vt(e),b=f&&f.domain?String(f.domain).trim():"";return b?T(await Lr(t,b,w=>console.log(w))):T({ok:!1,error:"\u8BF7\u586B\u5199\u8981\u6D4B\u8BD5\u7684\u57DF\u540D\u6216 IP"},400)}catch(f){return T({ok:!1,error:f.message},500)}if(o==="test"){if(s[3]==="proxyip"&&u==="POST")try{return T(await $r(t,f=>console.log(f)))}catch(f){return T({ok:!1,error:f.message},500)}if(s[3]==="udp"&&u==="POST")try{return T(await Ur(t,f=>console.log(f)))}catch(f){return T({ok:!1,error:f.message},500)}if(s[3]==="outbound"&&s[4]&&u==="POST"){let f=await i.prepare("SELECT * FROM outbounds WHERE id = ?").bind(Number(s[4])).first();if(!f)return T({ok:!1,error:"outbound not found"},404);try{return T(await Or(t,f,b=>console.log(b)))}catch(b){return T({ok:!1,error:b.message},500)}}}return T({error:"not found"},404)}async function Fr(e){try{let{results:t}=await e.prepare("SELECT name FROM pragma_table_info('outbounds')").all();if((t||[]).some(r=>r.name==="transport"))return;await e.prepare("ALTER TABLE outbounds ADD COLUMN transport TEXT DEFAULT 'ws'").run(),console.log("[admin] outbounds.transport column added (migration)")}catch(t){console.log("[admin] outbounds transport migration skipped: "+t.message)}}async function wa(e,t,r,a,n){let{table:s,cols:o}=r,c="id";if(e==="GET"){let{results:u}=await a.prepare(`SELECT * FROM ${s} ORDER BY id`).all();return T(u||[])}if(e==="POST"){let u=await vt(n);if(!u)return T({error:"bad body"},400);if(r.validate){let p=r.validate(u);if(p)return T({error:p},400)}s==="outbounds"&&await Fr(a);let i=o.filter(p=>u[p]!==void 0);if(i.length===0)return T({error:"no fields"},400);let l=i.map(()=>"?").join(","),d=i.map(p=>u[p]),{meta:h}=await a.prepare(`INSERT INTO ${s} (${i.join(",")}) VALUES (${l})`).bind(...d).run();return r.cacheKey&&Q(r.cacheKey),T({ok:!0,id:h.last_row_id})}if(e==="PUT"&&t){let u=await vt(n);if(!u)return T({error:"bad body"},400);if(r.validate){let h=r.validate(u);if(h)return T({error:h},400)}s==="outbounds"&&await Fr(a);let i=o.filter(h=>u[h]!==void 0);if(i.length===0)return T({error:"no fields"},400);let l=i.map(h=>`${h} = ?`).join(","),d=i.map(h=>u[h]);return await a.prepare(`UPDATE ${s} SET ${l} WHERE ${c} = ?`).bind(...d,Number(t)).run(),r.cacheKey&&Q(r.cacheKey),T({ok:!0})}return e==="DELETE"&&t?(await a.prepare(`DELETE FROM ${s} WHERE ${c} = ?`).bind(Number(t)).run(),r.cacheKey&&Q(r.cacheKey),T({ok:!0})):T({error:"method not allowed"},405)}var $t={geosite:["cn","apple","google","microsoft","facebook","twitter","telegram","github","netflix","youtube","spotify","discord","tiktok","paypal","steam","cloudflare","openai","amazon","whatsapp","instagram","linkedin","mozilla","adobe","speedtest","oracle","digitalocean","vultr","jetbrains","gitee","baidu","aliyun","tencent","jd","bilibili","douyin","zhihu","iqiyi","youku","xiaomi","huawei"],geoip:["cn","hk","mo","tw","jp","kr","sg","my","th","vn","id","ph","us","ca","gb","de","fr","nl","se","au","nz","ru","in","br","ar","mx","za","tr","ae","sa","il","es","it","ch","at","be","dk","fi","no","pl","pt","ie","cz","hu","ro","ua","kz"]};async function Ot(e,t,r){let a={geosite:new Set($t.geosite),geoip:new Set($t.geoip)},n=$t.geosite.length+$t.geoip.length,s=u=>{if(typeof r=="function")try{r(u)}catch{}},o={updated:0,total:0,failed:[]},c=0;for(let u of["geosite","geoip"])for(let i of a[u]){o.total++,c++,s({state:"updating",step:c,total:n,current:`${u}:${i}`,updated:o.updated,failed:o.failed,message:`\u62C9\u53D6 ${u}:${i}`});try{let l=await xa(u,i);l&&l.length>0?(await t.put(`${u}:${i}`,JSON.stringify(l)),o.updated++):o.failed.push(`${u}:${i} (empty rules)`)}catch(l){o.failed.push(`${u}:${i} (${l.message||l})`)}}return await t.put(Nt,new Date().toISOString()),ar(),o}async function Ut(e,t){let r=Date.now(),a=n=>t.put("geo:update_status",JSON.stringify({startedAt:r,...n})).catch(()=>{});try{await a({state:"updating",step:0,total:0,updated:0,failed:[],current:"",message:"\u5F00\u59CB\u66F4\u65B0"});let n=await Ot(e,t,s=>a({...s}));return await a({state:"done",step:n.total,total:n.total,updated:n.updated,failed:n.failed,current:"",message:"\u66F4\u65B0\u5B8C\u6210"}),await t.put("geo:updating","0").catch(()=>{}),n}catch(n){throw await a({state:"error",message:n.message||String(n),failed:[]}).catch(()=>{}),n}}async function xa(e,t){if(e==="geosite"){let n=await jr(t,new Set);if(n.length===0)throw new Error("empty geosite rules");return n}let r=await _a(t),a=[];for(let[n,s]of r)if(n.length===4?a.push(...Ua(n,s)):a.push(...Oa(n,s)),a.length>=3e4)break;if(a.length===0)throw new Error("empty geoip cidrs");return a}var va="https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/",Ta="https://cdn.jsdelivr.net/gh/v2fly/domain-list-community@master/data/",ka=2e4;async function jr(e,t){if(t.has(e))return[];t.add(e);let r=encodeURIComponent(e),a=[va+r,Ta+r],n=null;for(let s of a)try{let o=await fetch(s,{cf:{cacheTtl:86400}});if(!o.ok){n=new Error(`HTTP ${o.status}`);continue}let c=await o.text(),u=[];for(let i of c.split(`
`)){if(i=i.trim(),!i||i.startsWith("#"))continue;if(i.startsWith("include:")){let h=i.slice(8).trim().split(/\s+/)[0];h&&u.push(...await jr(h,t));continue}let l=i;if(l.startsWith("full:"))l=l.slice(5);else if(l.startsWith("domain:"))l=l.slice(7);else if(l.startsWith("keyword:")||l.startsWith("regexp:"))continue;l=l.replace(/\s+@[^\s#]+/g,"");let d=l.indexOf("#");d>=0&&(l=l.slice(0,d)),l=l.trim().toLowerCase().replace(/^\.+/,""),l&&u.length<ka&&u.push(l)}return u}catch(o){n=o}throw n||new Error("v2fly geosite fetch failed")}var Ea="https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/",Sa="https://cdn.jsdelivr.net/gh/SagerNet/sing-geoip@rule-set/",Aa=3e4;async function _a(e){let t=encodeURIComponent(e),r=[Ea+"geoip-"+t+".srs",Sa+"geoip-"+t+".srs"],a=null;for(let n of r)try{let s=await fetch(n,{cf:{cacheTtl:86400}});if(!s.ok){a=new Error(`HTTP ${s.status}`);continue}let o=new Uint8Array(await s.arrayBuffer());if(o.length<5||o[0]!==83||o[1]!==82||o[2]!==83){a=new Error("bad srs magic");continue}if(o[3]>1){a=new Error(`unsupported srs version ${o[3]}`);continue}let c;try{c=Hr(o.subarray(4))}catch{a=new Error("zlib inflate failed");continue}return La(c)}catch(s){a=s}throw a||new Error("sing-geoip srs fetch failed")}function La(e){let t=0,r=at(e,t);t=r.p;let a=[];for(let n=0;n<r.v;n++){let s=e[t++];if(s!==0)throw new Error(`geoip logical rule unsupported (type ${s})`);for(;;){let o=e[t++];if(o===255)break;if(o===5||o===6){if(e[t++]!==1)throw new Error("bad ipset version");let c=$a(e,t);t+=8;for(let u=0;u<c&&a.length<Aa*2;u++){let i=at(e,t);t=i.p;let l=e.subarray(t,t+i.v);t+=i.v,i=at(e,t),t=i.p;let d=e.subarray(t,t+i.v);if(t+=i.v,l.length!==d.length||l.length!==4&&l.length!==16)throw new Error("bad ipset addr");a.push([l,d])}}else if(o===0||o===7||o===9){let c=at(e,t);t=c.p,t+=c.v*2}else if(o===1||o===3||o===4||o===8||o===10||o===11||o===12||o===13||o===14||o===15||o===17||o===18||o===19||o===20||o===21||o===22||o===23){let c=at(e,t);t=c.p;for(let u=0;u<c.v;u++){let i=at(e,t);t=i.p,t+=i.v}}else throw new Error(`geoip unsupported item type ${o}`)}}return a}function at(e,t){let r=0,a=0;for(;;){let n=e[t++];if(r|=(n&127)<<a,!(n&128))break;if(a+=7,a>63)throw new Error("uvarint overflow")}return{v:r,p:t}}function $a(e,t){let r=0;for(let a=0;a<8;a++)r=r*256+e[t+a];return r}function Ua(e,t){let r=(e[0]<<24>>>0)+(e[1]<<16)+(e[2]<<8)+e[3],a=(t[0]<<24>>>0)+(t[1]<<16)+(t[2]<<8)+t[3],n=[];for(;r<=a;){let s=0;for(;;){let o=1<<s+1;if((r&o-1)!==0||r+o-1>a)break;s++}n.push(`${r>>>24}.${r>>>16&255}.${r>>>8&255}.${r&255}/${32-s}`),r+=1<<s}return n}function Oa(e,t){let r=0n,a=0n;for(let s of e)r=r<<8n|BigInt(s);for(let s of t)a=a<<8n|BigInt(s);let n=[];for(;r<=a;){let s=0n;for(;;){let o=1n<<s+1n;if((r&o-1n)!==0n||r+o-1n>a)break;s++}n.push(`${Da(r)}/${128-Number(s)}`),r+=1n<<s}return n}function Da(e){let t=[];for(let c=7;c>=0;c--)t.push(Number(e>>BigInt(c*16)&0xffffn));let r=-1,a=0,n=-1,s=0;for(let c=0;c<8;c++)t[c]===0?(n<0&&(n=c),s++,s>a&&(a=s,r=n)):(n=-1,s=0);let o="";for(let c=0;c<8;c++)c===r&&a>=2?(o+=(o.length>0&&!o.endsWith(":"),"::"),c+=a-1):(o.length>0&&!o.endsWith(":")&&(o+=":"),o+=t[c].toString(16));return o}var zr=!1;async function Ra(e){if(zr)return;let t=[["path","TEXT DEFAULT ''"],["expire_at","INTEGER DEFAULT 0"],["traffic_limit","INTEGER DEFAULT 0"],["traffic_reset_at","INTEGER DEFAULT 0"]];for(let r of["vless_users","trojan_users"])try{let{results:a}=await e.prepare(`SELECT name FROM pragma_table_info('${r}')`).all(),n=new Set((a||[]).map(s=>s.name));for(let[s,o]of t)n.has(s)||(await e.prepare(`ALTER TABLE ${r} ADD COLUMN ${s} ${o}`).run(),console.log(`[admin] ${r}.${s} column added (migration)`))}catch(a){console.log(`[admin] ${r} migration skipped: ${a.message}`)}zr=!0}var pe=null;function Gr(e){if(!e&&pe)return pe;let r=`<!DOCTYPE html>
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
  .colo-bar { display:flex; gap:18px; align-items:center; flex-wrap:wrap; background:var(--card); border-radius:14px; padding:12px 16px; margin-bottom:14px; font-size:13px; box-shadow:0 1px 4px rgba(0,0,0,.04); }
  .colo-bar .colo-item { display:flex; align-items:center; gap:6px; }
  .colo-bar .colo-lbl { color:var(--muted); font-size:12px; }
  .colo-bar b { font-size:14px; letter-spacing:.3px; }
  .colo-bar .colo-muted { color:var(--muted); font-size:12px; }
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
    <div class="nav-item" data-tab="entry">\u{1F6AA} \u5165\u53E3\u8BBE\u7F6E</div>
    <div class="nav-item" data-tab="outbounds">\u{1F310} \u51FA\u7AD9\u4EE3\u7406</div>
    <div class="nav-item" data-tab="rules">\u{1F9ED} \u8DEF\u7531\u89C4\u5219</div>
    <div class="nav-item" data-tab="routetest">\u{1F9ED} \u8DEF\u7531\u6D4B\u8BD5</div>
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
  rules:   { title:'\u8DEF\u7531\u89C4\u5219', api:'routing-rules', fields:[{k:'rule',label:'\u89C4\u5219(geosite:cn / geoip:cn / domain: / full: / keyword: / ip-cidr: / regexp:)'},{k:'outbound',label:'\u51FA\u7AD9(direct / reject / \u51FA\u7AD9\u540D)'},{k:'enable',label:'\u542F\u7528',type:'checkbox'},{k:'sort',label:'\u6392\u5E8F',type:'number'}] }
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
  if (tab==='netstatus'){ clearNetAuto(); mc.innerHTML = '<div class="page-title">\u7F51\u7EDC\u72B6\u6001</div><div class="card" style="padding:12px 16px;font-size:13px;color:var(--muted)">\u68C0\u6D4B\u6309\u9879\u76EE\u7F51\u7EDC\u8BBE\u7F6E\u53D1\u8D77\uFF08\u8DEF\u7531\u89C4\u5219 + \u9ED8\u8BA4\u51FA\u7AD9 + proxyip + \u51FA\u7AD9\u96A7\u9053\uFF09\uFF0C\u5168\u90E8\u63A2\u6D4B\u5728 Worker \u5185\u5B8C\u6210\uFF0C\u591A\u76EE\u6807\u5E76\u884C\u3001\u6BCF\u76EE\u6807 16 \u6B21\u91C7\u6837\uFF0C\u7EA6 10-15 \u79D2\u5B8C\u6210\u3002\u7EFF=\u6B63\u5E38\uFF0C\u9EC4=\u9AD8\u5EF6\u8FDF\uFF0C\u7EA2/\u7070=\u5931\u8D25\u3002</div><div class="colo-bar" id="coloBar"><span class="colo-muted">\u6B63\u5728\u83B7\u53D6\u8FD0\u884C\u65F6\u4F4D\u7F6E\u2026</span></div><div class="net-toolbar"><button class="btn small" onclick="runNetstatus()">\u5F00\u59CB\u68C0\u6D4B</button><label class="auto-refresh"><input type="checkbox" id="netAuto" checked onchange="scheduleNetAuto()"> \u81EA\u52A8\u5237\u65B0</label><span class="net-update-time" id="netUpdateTime"></span></div><div class="net-grid" id="netGrid"></div>'; runNetstatus(); return; }
  if (tab==='settings'){ mc.innerHTML = '<div class="page-title">\u7CFB\u7EDF\u8BBE\u7F6E</div><div class="card">\u52A0\u8F7D\u4E2D...</div>'; await loadSettings(); return; }
  if (tab==='entry'){ mc.innerHTML = '<div class="page-title">\u5165\u53E3\u8BBE\u7F6E</div><div class="card">\u52A0\u8F7D\u4E2D...</div>'; await loadEntry(); return; }
  if (tab==='routetest'){ mc.innerHTML = '<div class="page-title">\u8DEF\u7531\u6D4B\u8BD5</div>'+ROUTE_TEST_CARD; return; }
  const def = TAB_DEFS[tab];
  mc.innerHTML = '<div class="page-title">'+def.title+'</div><div class="toolbar"><button class="btn small" onclick="openNew()">\uFF0B \u65B0\u589E</button></div><div class="card"><div class="table-wrap"><table><thead><tr>'+def.fields.map(f=>'<th>'+f.label+'</th>').join('')+'<th>\u64CD\u4F5C</th></tr></thead><tbody id="tbody"></tbody></table></div></div>';
  state.schema = def;
  await loadList();
}

// \u8DEF\u7531\u6D4B\u8BD5\u6A21\u5757\uFF1A\u72EC\u7ACB\u83DC\u5355 tab\uFF0C\u8F93\u5165\u57DF\u540D\u6309\u5F53\u524D\u914D\u7F6E\u5224\u5B9A\u771F\u5B9E\u8DEF\u7531\u8D70\u5411
const ROUTE_TEST_CARD = '<div class="card" id="routeTestCard" style="margin-top:16px">'+
  '<h3 style="font-size:15px;margin-bottom:8px">\u{1F9ED} \u8DEF\u7531\u6D4B\u8BD5</h3>'+
  '<div style="font-size:12px;color:var(--muted);margin-bottom:10px;line-height:1.6">\u8F93\u5165\u57DF\u540D\u6216 IP\uFF0C\u6309\u5F53\u524D\u914D\u7F6E\uFF08\u8DEF\u7531\u89C4\u5219 \u2192 \u9ED8\u8BA4\u51FA\u7AD9 \u2192 proxyip\uFF09\u5224\u5B9A\u771F\u5B9E\u8DEF\u7531\u8D70\u5411\u3002direct \u7EFF / proxyip \u84DD / outbound \u6A59 / reject \u7EA2\u3002</div>'+
  '<div style="display:flex;gap:8px"><input id="routeTestDomain" placeholder="\u4F8B\u5982 www.google.com / 1.1.1.1" style="flex:1;padding:10px 12px;border:1px solid var(--border);border-radius:10px;font-size:14px;background:#fafafa"><button class="btn small" onclick="runRouteTest()">\u6D4B\u8BD5</button></div>'+
  '<div id="routeTestResult" style="margin-top:12px;font-size:13px;line-height:1.8"></div></div>';

// \u8DEF\u7531\u6D4B\u8BD5\u8F93\u5165\u6846\u56DE\u8F66\u89E6\u53D1\uFF08\u4E8B\u4EF6\u59D4\u6258\uFF0C\u907F\u514D\u6A21\u677F\u5B57\u7B26\u4E32\u5185\u5D4C onkeydown \u5F15\u53F7\u8F6C\u4E49\u95EE\u9898\uFF09
document.addEventListener('keydown', function(e){
  if (e.target && e.target.id === 'routeTestDomain' && e.key === 'Enter'){ e.preventDefault(); runRouteTest(); }
});

async function runRouteTest(){
  const input = $('#routeTestDomain');
  const el = $('#routeTestResult');
  const domain = (input ? input.value : '').trim();
  if (!domain){ if (el) el.innerHTML = '<span style="color:var(--danger)">\u8BF7\u8F93\u5165\u57DF\u540D\u6216 IP</span>'; return; }
  const card = $('#routeTestCard');
  const btn = card ? card.querySelector('button') : null;
  if (btn){ btn.disabled = true; btn.textContent = '\u6D4B\u8BD5\u4E2D\u2026'; }
  if (el) el.innerHTML = '\u6D4B\u8BD5\u4E2D\u2026';
  try {
    const r = await api('/admin/api/route-test',{method:'POST',body:JSON.stringify({domain})});
    const map = { direct:{cls:'rt-direct',label:'DIRECT'}, proxyip:{cls:'rt-proxyip',label:'PROXYIP'}, outbound:{cls:'rt-outbound',label:'OUTBOUND'}, reject:{cls:'rt-reject',label:'REJECT'} };
    const m = map[r.route] || map.direct;
    el.innerHTML = '<div class="rt-box" style="background:'+(r.route==='proxyip'?'#0a84ff':(r.route==='outbound'?'#ff9500':(r.route==='reject'?'#ff3b30':'#34c759')))+'14;border:1px solid '+(r.route==='proxyip'?'#0a84ff':(r.route==='outbound'?'#ff9500':(r.route==='reject'?'#ff3b30':'#34c759')))+'66">'+
      '<div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap"><span class="rt-route '+m.cls+'">'+m.label+'</span><b style="font-size:15px">'+esc(r.name||'')+'</b></div>'+
      '<div class="rt-reason">'+esc(r.reason||'')+'</div></div>';
  } catch(e){ el.innerHTML = '<span style="color:var(--danger)">\u6D4B\u8BD5\u5931\u8D25\uFF1A'+esc(e.message)+'</span>'; }
  if (btn){ btn.disabled = false; btn.textContent = '\u6D4B\u8BD5'; }
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
      ['proxyip','proxyip\uFF08\u4EE3\u7406 IP \u6216\u57DF\u540D[:\u7AEF\u53E3]\uFF0C\u4E5F\u53EF\u76F4\u63A5\u586B\u51FA\u7AD9\u540D\u4F7F\u7528\u8BE5\u51FA\u7AD9\u4EE3\u7406\u51FA\u7AD9\uFF1B\u8BBF\u95EE Cloudflare \u53CA\u5F00 CF CDN \u7F51\u7AD9\u4F7F\u7528\uFF1B\u4EC5\u9ED8\u8BA4\u51FA\u7AD9\u4E3A direct \u65F6\u751F\u6548\uFF09'],
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

const ENTRY_TRANSPORTS = ['ws', 'grpc', 'h2'];
let entryBase = '';

function ensureEntryStyle(){
  if (document.getElementById('entryStyle')) return;
  const st = document.createElement('style');
  st.id = 'entryStyle';
  st.textContent =
    '.entry-card{background:#fff;border:1px solid var(--border,#e6e8ee);border-radius:16px;padding:16px;margin-bottom:14px;box-shadow:0 1px 4px rgba(0,0,0,.04);transition:box-shadow .25s ease,border-color .25s ease}' +
    '.entry-card:focus-within{box-shadow:0 4px 16px rgba(10,132,255,.10);border-color:rgba(10,132,255,.35)}' +
    '.entry-card-head{display:flex;align-items:center;gap:10px;margin-bottom:12px}' +
    '.entry-badge{width:24px;height:24px;border-radius:50%;background:var(--primary,#0a84ff);color:#fff;font-size:12px;font-weight:600;display:flex;align-items:center;justify-content:center;flex:none}' +
    '.entry-title{font-size:14px;font-weight:600;color:var(--text,#1d1d1f);flex:1}' +
    '.entry-del{color:#ff3b30 !important;border:1px solid rgba(255,59,48,.25) !important;background:rgba(255,59,48,.06) !important}' +
    '.entry-grid{display:grid;grid-template-columns:1fr 1fr;gap:12px 14px}' +
    '@media (max-width:560px){.entry-grid{grid-template-columns:1fr}}' +
    '.entry-field label{display:block;font-size:12px;color:var(--muted,#8a94a6);margin-bottom:5px;font-weight:500}' +
    '.entry-field input{width:100%;padding:9px 12px;border:1px solid var(--border,#e6e8ee);border-radius:10px;background:#f7f8fa;font-size:14px;color:var(--text,#1d1d1f);outline:none;transition:all .2s ease;box-sizing:border-box}' +
    '.entry-field input:focus{background:#fff;border-color:var(--primary,#0a84ff);box-shadow:0 0 0 3px rgba(10,132,255,.12)}' +
    '.entry-chips{display:flex;gap:8px;flex-wrap:wrap;padding-top:2px}' +
    '.entry-chip{display:inline-flex;align-items:center;padding:6px 14px;border-radius:20px;border:1px solid var(--border,#e6e8ee);background:#f2f3f7;color:#6b7280;font-size:13px;font-weight:500;cursor:pointer;transition:all .2s ease;user-select:none}' +
    '.entry-chip input{display:none}' +
    '.entry-chip.on{background:var(--primary,#0a84ff);border-color:var(--primary,#0a84ff);color:#fff;font-weight:600;box-shadow:0 2px 8px rgba(10,132,255,.35)}' +
    '.entry-actions{display:flex;gap:10px;margin-top:14px;align-items:center}' +
    '.entry-save{background:#e5e9f0 !important;color:#9aa3b2 !important;cursor:not-allowed !important;border:none !important;box-shadow:none !important;transition:all .25s ease !important;opacity:.8}' +
    '.entry-save.dirty{background:var(--primary,#0a84ff) !important;color:#fff !important;cursor:pointer !important;box-shadow:0 2px 10px rgba(10,132,255,.35) !important;opacity:1}';
  document.head.appendChild(st);
}

function entryCardHtml(e, i) {
  const transports = ENTRY_TRANSPORTS.map(t => {
    const on = (e.transports && e.transports.includes(t)) ? ' on' : '';
    return '<label class="entry-chip' + on + '"><input type="checkbox" data-t="' + t + '"' + (on ? ' checked' : '') + '>' + t + '</label>';
  }).join('');
  return '<div class="entry-card">' +
    '<div class="entry-card-head"><span class="entry-badge">' + (i + 1) + '</span><span class="entry-title">\u5165\u53E3 ' + (i + 1) + '</span>' +
    '<button class="btn small entry-del" onclick="removeEntry(this)">\u5220\u9664</button></div>' +
    '<div class="entry-grid">' +
    '<div class="entry-field"><label>\u5907\u6CE8</label><input data-f="remark" value="' + esc(e.remark || '') + '" placeholder="\u5982 \u79FB\u52A8\u7EBF\u8DEF / \u7535\u4FE1\u7EBF\u8DEF"></div>' +
    '<div class="entry-field"><label>\u5165\u53E3 IP / \u57DF\u540D *</label><input data-f="host" value="' + esc(e.host || '') + '" placeholder="\u5982 cdn.example.com \u6216 1.2.3.4"></div>' +
    '<div class="entry-field"><label>\u5165\u53E3\u7AEF\u53E3</label><input data-f="port" value="' + esc(e.port || '') + '" placeholder="443"></div>' +
    '<div class="entry-field"><label>\u5165\u53E3 SNI</label><input data-f="sni" value="' + esc(e.sni || '') + '" placeholder="\u9ED8\u8BA4\u540C\u5165\u53E3 Host"></div>' +
    '<div class="entry-field"><label>\u5165\u53E3 Host\uFF08Host \u5934\uFF09</label><input data-f="wsHost" value="' + esc(e.wsHost || '') + '" placeholder="\u9ED8\u8BA4\u540C\u5165\u53E3 Host"></div>' +
    '<div class="entry-field"><label>\u652F\u6301\u534F\u8BAE</label><div class="entry-chips">' + transports + '</div></div>' +
    '</div></div>';
}

function entrySnapshot(){
  const rows = [];
  document.querySelectorAll('#mainContent .entry-card').forEach(card => {
    const r = {
      host: card.querySelector('[data-f=host]').value.trim(),
      port: card.querySelector('[data-f=port]').value.trim(),
      sni: card.querySelector('[data-f=sni]').value.trim(),
      wsHost: card.querySelector('[data-f=wsHost]').value.trim(),
      remark: card.querySelector('[data-f=remark]').value.trim(),
      transports: [],
    };
    card.querySelectorAll('input[type=checkbox][data-t]').forEach(cb => { if (cb.checked) r.transports.push(cb.dataset.t); });
    r.transports.sort();
    rows.push(r);
  });
  return JSON.stringify(rows);
}

function checkEntryDirty(){
  const btn = $('#saveEntryBtn');
  if (!btn) return;
  const dirty = entrySnapshot() !== entryBase;
  btn.classList.toggle('dirty', dirty);
  btn.disabled = !dirty;
}

function onEntryInput(e){
  if (!e.target.closest('.entry-card')) return;
  // \u534F\u8BAE\u80F6\u56CA\uFF1A\u52FE\u9009\u72B6\u6001\u5B9E\u65F6\u540C\u6B65\u9AD8\u4EAE class
  if (e.target.matches && e.target.matches('input[type=checkbox][data-t]')) {
    const chip = e.target.closest('.entry-chip');
    if (chip) chip.classList.toggle('on', e.target.checked);
  }
  checkEntryDirty();
}

async function loadEntry(){
  const mc = $('#mainContent');
  try {
    const s = await api('/admin/api/settings');
    let list = [];
    try { const raw = s.entry_list; if (raw) { const arr = JSON.parse(raw); if (Array.isArray(arr)) list = arr; } } catch(e){ list = []; }
    if (!list.length && (s.entry_host || '').trim()) {
      list = [{ host: s.entry_host || '', port: s.entry_port || '', sni: s.entry_sni || '', wsHost: s.entry_ws_host || '', remark: '', transports: [] }];
    }
    if (!list.length) list = [{ host: '', port: '', sni: '', wsHost: '', remark: '', transports: [] }];
    ensureEntryStyle();
    mc.innerHTML = '<div class="page-title">\u5165\u53E3\u8BBE\u7F6E</div>' +
      '<div class="card" style="background:#e8f8ef;color:#1d7a3f;font-size:13px;border-radius:10px;padding:12px 16px;margin-bottom:16px">\u652F\u6301\u914D\u7F6E\u591A\u4E2A\u5165\u53E3\uFF0C\u6BCF\u4E2A\u5165\u53E3\u53EF\u72EC\u7ACB\u9009\u62E9\u652F\u6301\u7684\u534F\u8BAE\uFF08ws / grpc / h2\uFF09\u3002\u8BBF\u95EE\u5BF9\u5E94\u5165\u53E3\u57DF\u540D\u65F6\uFF0C\u5355\u51ED\u636E\u9875\u4E0E\u5355\u51ED\u636E\u8BA2\u9605\u53EA\u8F93\u51FA\u8BE5\u5165\u53E3\u52FE\u9009\u7684\u534F\u8BAE\uFF1B\u805A\u5408\u8BA2\u9605\u5728\u8BBE\u7F6E\u4E86\u5165\u53E3\u540E\u4EC5\u751F\u6210\u5404\u5165\u53E3\u52FE\u9009\u7684\u534F\u8BAE\u3002\u672A\u8BBE\u7F6E\u4EFB\u4F55\u5165\u53E3\u65F6\u4F7F\u7528\u5F53\u524D\u57DF\u540D\uFF08ws/grpc/h2 \u5168\u534F\u8BAE\uFF09\u3002</div>' +
      '<div id="entryCards">' + list.map(entryCardHtml).join('') + '</div>' +
      '<div class="entry-actions"><button class="btn small" onclick="addEntry()">+ \u6DFB\u52A0\u5165\u53E3</button>' +
      '<button id="saveEntryBtn" class="btn small entry-save" onclick="saveEntry()" disabled>\u4FDD\u5B58\u5165\u53E3\u8BBE\u7F6E</button></div>';
    const cards = $('#entryCards');
    if (cards) {
      cards.addEventListener('input', onEntryInput);
      cards.addEventListener('change', onEntryInput);
    }
    entryBase = entrySnapshot();
    checkEntryDirty();
  } catch(e){ mc.innerHTML = '<div class="page-title">\u5165\u53E3\u8BBE\u7F6E</div><div class="card">\u52A0\u8F7D\u5931\u8D25: '+esc(e.message)+'</div>'; }
}

function addEntry(){
  const box = $('#entryCards');
  if (!box) return;
  const div = document.createElement('div');
  div.innerHTML = entryCardHtml({ host:'', port:'', sni:'', wsHost:'', remark:'', transports: [] }, box.children.length);
  box.appendChild(div.firstChild);
  checkEntryDirty();
}
function removeEntry(btn){
  const card = btn.closest('.entry-card');
  if (card) card.remove();
  checkEntryDirty();
}

async function saveEntry(){
  const body = {};
  const list = [];
  document.querySelectorAll('#mainContent .entry-card').forEach(card => {
    const host = card.querySelector('[data-f=host]').value.trim();
    if (!host) return;
    const e = {
      host,
      port: card.querySelector('[data-f=port]').value.trim(),
      sni: card.querySelector('[data-f=sni]').value.trim(),
      wsHost: card.querySelector('[data-f=wsHost]').value.trim(),
      remark: card.querySelector('[data-f=remark]').value.trim(),
      transports: [],
    };
    card.querySelectorAll('input[type=checkbox][data-t]').forEach(cb => { if (cb.checked) e.transports.push(cb.dataset.t); });
    list.push(e);
  });
  body['entry_list'] = JSON.stringify(list);
  // \u6E05\u7A7A\u65E7\u5355\u5165\u53E3\u5B57\u6BB5\uFF0C\u907F\u514D\u4E0E\u591A\u5165\u53E3\u6DF7\u7528
  ['entry_host','entry_port','entry_sni','entry_ws_host'].forEach(k => body[k] = '');
  try {
    await api('/admin/api/settings',{method:'PUT',body:JSON.stringify(body)});
    toast('\u5165\u53E3\u8BBE\u7F6E\u5DF2\u4FDD\u5B58');
    entryBase = entrySnapshot();
    checkEntryDirty();
  }
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
  loadColo();
  try {
    const d = await api('/admin/api/netstatus/test',{method:'POST',body:'{}'});
    renderNetCards(grid, d.targets || []);
    const t = $('#netUpdateTime'); if (t) t.textContent = '\u66F4\u65B0\u4E8E ' + new Date(d.ts||Date.now()).toLocaleTimeString();
  } catch(e){ grid.innerHTML = '<div class="card" style="grid-column:1/-1">\u68C0\u6D4B\u5931\u8D25: '+esc(e.message)+'</div>'; }
  scheduleNetAuto();
}
// ---- \u8FD0\u884C\u65F6\u653E\u7F6E\u4F4D\u7F6E\uFF1A\u9875\u9762\u52A0\u8F7D\u81EA\u52A8\u8BF7\u6C42\u5C55\u793A\uFF08/admin/api/colo\uFF09----
async function loadColo(){
  const bar = $('#coloBar');
  if (!bar) return;
  try {
    const c = await api('/admin/api/colo');
    renderColoBar(c);
  } catch(e){ bar.innerHTML = '<span class="colo-muted">\u8FD0\u884C\u65F6\u4F4D\u7F6E\u83B7\u53D6\u5931\u8D25</span>'; }
}
function renderColoBar(c){
  const bar = $('#coloBar');
  if (!bar) return;
  if (!c || !c.ok){ bar.innerHTML = '<span class="colo-muted">\u65E0\u6CD5\u83B7\u53D6\u8FD0\u884C\u65F6\u4F4D\u7F6E</span>'; return; }
  const colo = c.colo || '\u2014';
  const city = c.city || '\u2014';
  const country = c.country || '\u2014';
  bar.innerHTML =
    '<span class="colo-item"><span class="colo-lbl">\u5B9E\u9645\u6267\u884C\u6570\u636E\u4E2D\u5FC3</span><b>'+esc(colo)+'</b></span>'+
    '<span class="colo-item"><span class="colo-lbl">\u57CE\u5E02</span>'+esc(city)+' / '+esc(country)+'</span>';
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
  el.innerHTML = 'proxyip \u6D4B\u8BD5\u4E2D\u2026';
  try {
    const r = await api('/admin/api/test/proxyip',{method:'POST',body:'{}'});
    el.innerHTML = r.ok
      ? (r.mode==='outbound'
          ? '<span style="color:#34c759">\u5F53\u524D\u4F7F\u7528\u51FA\u7AD9\u4EE3\u7406 '+esc(r.outbound)+' \u51FA\u7AD9\uFF0C\u53EF\u7528\uFF0C\u5EF6\u8FDF '+r.latency+' ms</span>'
          : '<span style="color:#34c759">proxyip \u53EF\u7528\uFF0C\u5EF6\u8FDF '+r.latency+' ms</span>\uFF08'+esc(r.endpoint||'')+'\uFF09')
      : '<span style="color:var(--danger)">proxyip \u4E0D\u53EF\u7528\uFF1A'+esc(r.error||'')+'</span>';
  } catch(e){ el.innerHTML = '<span style="color:var(--danger)">proxyip \u6D4B\u8BD5\u5931\u8D25\uFF1A'+esc(e.message)+'</span>'; }
}
async function testUdp(){
  const el = $('#testResult'); if (!el) return;
  el.innerHTML = 'UDP \u6D4B\u8BD5\u4E2D\u2026\uFF08\u7ECF UDP \u51FA\u7AD9\u5411 8.8.8.8:53 \u53D1\u8D77 DNS \u67E5\u8BE2\uFF09';
  try {
    const r = await api('/admin/api/test/udp',{method:'POST',body:'{}'});
    el.innerHTML = r.ok
      ? (r.outbound
          ? '<span style="color:#34c759">\u5F53\u524D\u4F7F\u7528\u51FA\u7AD9\u4EE3\u7406 '+esc(r.outbound)+' \u51FA\u7AD9\uFF0Cudp \u53EF\u7528\uFF0C\u5EF6\u8FDF '+r.latency+' ms</span>'
          : '<span style="color:#34c759">UDP \u53EF\u7528\uFF0C\u5EF6\u8FDF '+r.latency+' ms</span>')
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
</html>`;return e||(pe=r),r}async function Wr(e,t){let r=new URL(e.url);if(e.method==="POST"||e.method==="GET")try{let{DB:a,GEO_KV:n}=t,s=await Ot(a,n);return new Response(JSON.stringify({ok:!0,updated:s.updated,total:s.total,failed:s.failed}),{status:200,headers:{"Content-Type":"application/json; charset=utf-8"}})}catch(a){return new Response(JSON.stringify({ok:!1,error:a.message}),{status:500,headers:{"Content-Type":"application/json; charset=utf-8"}})}return new Response("Not Found",{status:404})}async function Vr(e,t,r){try{let a=await Ot(t.DB,t.GEO_KV);console.log(`[cron] geo update done: ${a.updated}/${a.total} categories${a.failed.length?", failed: "+a.failed.join("; "):""}`)}catch(a){console.log(`[cron] geo update failed: ${a.message}`)}}globalThis.connect=Ca;var wo={async fetch(e,t,r){let n=new URL(e.url).pathname;try{if(n.startsWith("/admin")){let c=await ct(e,t,{ensureAdmin:!0});if(n.startsWith("/admin/api/"))return await Br(e,c,r);let u=Gr(c.adminTempPassword),i=c.adminTempPassword?"no-store":"public, max-age=300";return new Response(u,{headers:{"Content-Type":"text/html; charset=utf-8","Cache-Control":i}})}if(n==="/geo-update-cron")return await Wr(e,t);let s=await ct(e,t),o=s.inboundPathMap.get(n);if(o&&o.length>0){s._inboundScope=Tt(o);let c=String(e.headers.get("Upgrade")||"").toLowerCase(),u=String(e.headers.get("Content-Type")||"").toLowerCase(),i=n.endsWith("/Tun")||u.includes("application/grpc");if(c==="websocket"&&!i){if(t.PROXY_DO){let l=t.PROXY_DO.newUniqueId();return await t.PROXY_DO.get(l).fetch(e)}return await dr(e,s,t)}if(i)return await fr(e,s,t);if(e.method==="POST")return await pr(e,s,t)}return await xr(e,s,t)}catch(s){return console.log(`[index] error: ${s.message||s}`),new Response(JSON.stringify({error:"internal error"}),{status:500,headers:{"Content-Type":"application/json; charset=utf-8"}})}},async scheduled(e,t,r){return Vr(e,t,r)},async queue(e,t,r){for(let a of e.messages)try{let n=await Ut(t.DB,t.GEO_KV);console.log(`[queue] geo update done: ${n.updated}/${n.total} categories${n.failed.length?", failed: "+n.failed.join("; "):""}`),a.ack()}catch(n){throw console.log(`[queue] geo update failed (will retry): ${n.message||n}`),n}}};export{ee as ProxySessionDO,wo as default};
