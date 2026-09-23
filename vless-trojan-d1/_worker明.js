var _="direct",H="reject",Z="socks5",ee="http",te="vless",re="geosite:",se="geoip:";var $="vtd_admin";var ne="/ws";var ae=["qq.com","taobao.com","tmall.com","jd.com","baidu.com","bilibili.com","douyin.com","weibo.com","zhihu.com","163.com","126.com","aliyun.com","tencent.com","weixin.qq.com","alipay.com","bankofchina.com","icbc.com.cn","ccb.com","abcchina.com","cmbchina.com","boc.cn","12306.cn","gov.cn","cn","com.cn","net.cn","org.cn"],oe=["speedtest.net","fast.com","ookla.com"],ie=["google.com","googleapis.com","gstatic.com","googleusercontent.com","ggpht.com","google.cn","google.com.hk","gvt1.com","gvt2.com","gvt3.com"],j=[];for(let t=0;t<=255;++t){let e=t.toString(16).padStart(2,"0");j.push(e)}var B=1e5;function z(t){return Array.from(new Uint8Array(t)).map(e=>e.toString(16).padStart(2,"0")).join("")}function Ze(){let t=new Uint8Array(16);return crypto.getRandomValues(t),z(t)}async function ce(t,e,r){let s=await crypto.subtle.importKey("raw",new TextEncoder().encode(t),"PBKDF2",!1,["deriveBits"]),n=await crypto.subtle.deriveBits({name:"PBKDF2",salt:new TextEncoder().encode(e),iterations:r,hash:"SHA-256"},s,256);return z(n)}async function de(t){let e=Ze(),r=await ce(t,e,B);return`${e}:${B}:${r}`}async function le(t,e){if(!e||!t)return!1;let r=String(e).split(":");if(r.length!==3)return!1;let[s,n,a]=r,c=parseInt(n,10)||B;return await ce(t,s,c)===a}async function ue(t,e){let r=await crypto.subtle.importKey("raw",new TextEncoder().encode(t),{name:"HMAC",hash:"SHA-256"},!1,["sign"]),s=await crypto.subtle.sign("HMAC",r,new TextEncoder().encode(e));return z(s)}async function pe(t){let r=`admin.${Math.floor(Date.now()/1e3)+604800}`,s=await ue(t,r);return`${r}.${s}`}async function fe(t,e){if(!t||!e)return!1;let r=String(t).split(".");if(r.length!==3)return!1;let[s,n,a]=r;if(s!=="admin")return!1;let c=Number(n);if(!Number.isFinite(c)||c<Date.now()/1e3)return!1;let o=await ue(e,`${s}.${n}`);if(o.length!==a.length)return!1;let d=0;for(let i=0;i<o.length;i++)d|=o.charCodeAt(i)^a.charCodeAt(i);return d===0}function me(t){let e={};if(!t)return e;for(let r of t.split(";")){let s=r.indexOf("=");if(s<0)continue;let n=r.slice(0,s).trim(),a=r.slice(s+1).trim();e[n]=decodeURIComponent(a)}return e}async function et(t){try{let{results:e}=await t.prepare("SELECT key, value FROM settings").all(),r={};for(let s of e||[])r[s.key]=s.value;return r}catch{return{}}}async function tt(t){try{let{results:e}=await t.prepare("SELECT id, uuid, remark, up, down FROM vless_users WHERE enable = 1 ORDER BY id").all();return e||[]}catch{return[]}}async function rt(t){try{let{results:e}=await t.prepare("SELECT id, password, remark, up, down FROM trojan_users WHERE enable = 1 ORDER BY id").all();return e||[]}catch{return[]}}async function st(t){try{let{results:e}=await t.prepare("SELECT * FROM outbounds WHERE enable = 1 ORDER BY sort ASC, id ASC").all();return e||[]}catch{return[]}}async function nt(t){try{let{results:e}=await t.prepare("SELECT * FROM routing_rules WHERE enable = 1 ORDER BY sort ASC, id ASC").all();return e||[]}catch{return[]}}async function at(t){try{let s=await t.prepare("SELECT value FROM settings WHERE key = ?").bind("admin_password_hash").first();if(s&&s.value)return{hash:s.value,tempPassword:null}}catch{}let e=ot().replace(/-/g,"").slice(0,12),r=await de(e);try{await t.prepare("INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at").bind("admin_password_hash",r,Date.now()).run()}catch{}return{hash:r,tempPassword:e}}async function W(t,e,r={}){let{DB:s}=e,n=await et(s),a=n.ws_path||ne,c=n.default_outbound||_,o=n.admin_password_hash||"",d=null;if(!o&&r.ensureAdmin){let k=await at(s);o=k.hash,d=k.tempPassword}let i=n.proxyip||"",l="",u=443;if(i){let k=i.lastIndexOf(":");k>0&&!i.includes("]")&&/^\d+$/.test(i.slice(k+1))?(l=i.slice(0,k),u=Number(i.slice(k+1))||443):l=i}let f=n.udp_outbound||"",m=n.entry_host||"",h=n.entry_port||"",x=n.entry_sni||"",p=n.entry_ws_host||"",w=await tt(s),T=await rt(s),g=await st(s),b=await nt(s),v={};for(let k of w)v[k.uuid]=k;let E={};for(let k of T)E[k.password]=k;return{env:e,settings:n,wsPath:a,defaultOutbound:c,adminPasswordHash:o,adminTempPassword:d,proxyipHost:l,proxyipPort:u,proxyipDisabled:c!==_,udpOutbound:f,entryHost:m,entryPort:h,entrySni:x,entryWsHost:p,vlessUsers:w,trojanUsers:T,outbounds:g,routingRules:b,vlessIndex:v,trojanIndex:E,uuidSet:new Set(w.map(k=>k.uuid)),passwordSet:new Set(T.map(k=>k.password)),outboundByName:g.reduce((k,P)=>(k[P.name]=P,k),{})}}function ot(){return globalThis.crypto&&typeof globalThis.crypto.randomUUID=="function"?globalThis.crypto.randomUUID():"xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(/[xy]/g,t=>{let e=Math.random()*16|0;return(t==="x"?e:e&3|8).toString(16)})}function it(t){let e=r=>j[t[r]];return`${e(0)}${e(1)}${e(2)}${e(3)}-${e(4)}${e(5)}-${e(6)}${e(7)}-${e(8)}${e(9)}-${e(10)}${e(11)}${e(12)}${e(13)}${e(14)}${e(15)}`.toLowerCase()}function he(t,e){if(t.byteLength<24)return{hasError:!0,message:"invalid data"};let r=new DataView(t),s=r.getUint8(0),n=it(new Uint8Array(t.slice(1,17)));if(!e.has(n))return{hasError:!0,message:"invalid user"};let c=18+r.getUint8(17);if(t.byteLength<c+4)return{hasError:!0,message:"invalid data"};let o=r.getUint8(c);if(o!==1&&o!==2)return{hasError:!0,message:`command ${o} is not supported`};let d=c+1,i=r.getUint16(d),l=r.getUint8(d+2),u,f,m;switch(l){case 1:f=4,m=d+3,u=Array.from(new Uint8Array(t.slice(m,m+f))).join(".");break;case 2:if(t.byteLength<d+4)return{hasError:!0,message:"invalid data"};f=r.getUint8(d+3),m=d+4,u=new TextDecoder().decode(t.slice(m,m+f));break;case 3:f=16,m=d+3,u=Array.from({length:8},(h,x)=>r.getUint16(m+x*2).toString(16)).join(":");break;default:return{hasError:!0,message:`invalid addressType: ${l}`}}return u?{hasError:!1,userUuid:n,addressRemote:u,addressType:l,portRemote:i,rawDataIndex:m+f,protocolVersion:new Uint8Array([s]),isUDP:o===2}:{hasError:!0,message:"addressValue is empty"}}function be(t,e,r,s,n){let a,c,o=[];switch(e){case 1:a=4,o=r.split(".").map(Number);break;case 2:c=new TextEncoder().encode(r),a=c.length+1;break;case 3:a=16,o=ct(r).split(":").map(l=>[parseInt(l.slice(0,2),16),parseInt(l.slice(2),16)]).flat();break;default:throw new Error(`Unknown address type: ${e}`)}let d=n.replace(/-/g,""),i=new Uint8Array(22+a);i[0]=0;for(let l=0;l<d.length;l+=2)i[1+l/2]=parseInt(d.substr(l,2),16);return i[17]=0,i[18]=t,i[19]=s>>8,i[20]=s&255,i[21]=e,e===2?(i[22]=c.length,i.set(c,23)):i.set(o,22),i}function ct(t){if(t=t.replace(/^\[|\]$/g,""),t.includes("::")){let e=t.split("::"),r=e[0]?e[0].split(":"):[],s=e[1]?e[1].split(":"):[],n=8-r.length-s.length,a=Array(Math.max(0,n)).fill("0");return[...r,...a,...s].map(c=>c.padStart(4,"0")).join(":")}return t.split(":").map(e=>e.padStart(4,"0")).join(":")}async function dt(t){let e=new TextEncoder().encode(t),r=await crypto.subtle.digest({name:"SHA-224"},e);return Array.from(new Uint8Array(r)).map(s=>s.toString(16).padStart(2,"0")).join("")}function we(t){if(t.byteLength<60)return!1;let e=new Uint8Array(t);return e[56]===13&&e[57]===10}async function xe(t,e){if(t.byteLength<60)return{hasError:!0,message:"Invalid Trojan data: too short"};let r=new Uint8Array(t),s=new DataView(t);if(r[56]!==13||r[57]!==10)return{hasError:!0,message:"Invalid Trojan header: missing CRLF"};let n=new TextDecoder().decode(r.slice(0,56)),a=null;for(let h of e)try{if(await dt(h)===n){a=h;break}}catch{}if(!a)return{hasError:!0,message:"Invalid Trojan password"};let c=r[58];if(c!==1&&c!==3)return{hasError:!0,message:`Unsupported Trojan command: ${c}`};let o=r[59],d,i,l;switch(o){case 1:if(i=4,l=60,t.byteLength<l+i+2)return{hasError:!0,message:"Invalid Trojan header: IPv4 truncated"};d=Array.from(r.slice(l,l+i)).join(".");break;case 3:if(i=r[60],l=61,t.byteLength<l+i+2)return{hasError:!0,message:"Invalid Trojan header: domain truncated"};d=new TextDecoder().decode(r.slice(l,l+i));break;case 4:if(i=16,l=60,t.byteLength<l+i+2)return{hasError:!0,message:"Invalid Trojan header: IPv6 truncated"};d=Array.from({length:8},(h,x)=>s.getUint16(l+x*2).toString(16)).join(":");break;default:return{hasError:!0,message:`Invalid Trojan address type: ${o}`}}let u=l+i;if(t.byteLength<u+2)return{hasError:!0,message:"Invalid Trojan header: port truncated"};let f=s.getUint16(u),m=u+2;return t.byteLength<m+2?{hasError:!0,message:"Invalid Trojan header: missing final CRLF"}:r[m]!==13||r[m+1]!==10?{hasError:!0,message:"Invalid Trojan header: invalid final CRLF"}:{hasError:!1,userPassword:a,addressRemote:d,addressType:o===3?2:o,portRemote:f,rawDataIndex:m+2,isUDP:c===3}}function S(t){try{t&&t.readyState===1&&t.close()}catch{}}var lt=1e4;async function L(t,e,r,s,n,a,c){let o=t.tls?"wss":"ws",d=t.path&&t.path.startsWith("/")?t.path:`/${t.path||""}`,i=t.sni&&t.sni!==""?t.sni:t.address,l=`${o}://${i}:${t.port}${d}`,u;try{u=new WebSocket(l)}catch(b){return c(`[VLESS] create ws failed: ${b.message}`),null}let f,m=new Promise(b=>{f=b});try{await new Promise((b,v)=>{let E=setTimeout(()=>v(new Error("Connection timeout")),lt);u.addEventListener("open",()=>{clearTimeout(E),b()}),u.addEventListener("close",k=>{clearTimeout(E),v(new Error(`closed ${k.code}`))}),u.addEventListener("error",()=>{clearTimeout(E),v(new Error("ws error"))})})}catch(b){c(`[VLESS] connect failed: ${b.message}`);try{u.close()}catch{}return f(),null}u.addEventListener("close",()=>f()),u.addEventListener("error",()=>{});let h=new WritableStream({write(b){u.readyState===1&&u.send(b)},close(){S(u)},abort(){S(u)}}),x=!1,p=new ReadableStream({start(b){u.addEventListener("message",v=>{let E=new Uint8Array(v.data);if(!x&&(x=!0,E.length>=2)){let k=E[1];if(E.length>2+k)E=E.slice(2+k);else return}if(E.length>0)try{b.enqueue(E)}catch{}}),u.addEventListener("close",()=>{try{b.close()}catch{}}),u.addEventListener("error",v=>{try{b.error(v)}catch{}})},cancel(){S(u)}}),w=be(e,r,s,n,t.uuid),T=a instanceof Uint8Array?a:new Uint8Array(a||0),g=new Uint8Array(w.length+T.length);g.set(w,0),g.set(T,w.length);try{u.send(g)}catch(b){return c(`[VLESS] send header failed: ${b.message}`),S(u),f(),null}return{readable:p,writable:h,closed:m}}async function ge(t,e,r,s,n,a){let{username:c,password:o,hostname:d,port:i}=n,l=a({hostname:d,port:i}),u=l.writable.getWriter(),f=l.readable.getReader(),m=new TextEncoder;try{await u.write(new Uint8Array([5,2,0,2]));let h=(await f.read()).value;if(!h||h[0]!==5){s("socks version error");return}if(h[1]===255){s("no acceptable methods");return}if(h[1]===2){if(!c||!o){s("socks server requires auth but no credentials");return}let w=new Uint8Array([1,c.length,...m.encode(c),o.length,...m.encode(o)]);if(await u.write(w),h=(await f.read()).value,!h||h[0]!==1||h[1]!==0){s("socks auth failed");return}}let x;switch(t){case 1:x=new Uint8Array([1,...e.split(".").map(Number)]);break;case 2:x=new Uint8Array([3,e.length,...m.encode(e)]);break;case 3:x=new Uint8Array([4,...e.split(":").flatMap(w=>[parseInt(w.slice(0,2),16),parseInt(w.slice(2),16)])]);break;default:s(`invalid addressType ${t}`);return}let p=new Uint8Array([5,1,0,...x,r>>8,r&255]);if(await u.write(p),h=(await f.read()).value,!h||h[1]!==0){s(`socks connect failed rep=${h?h[1]:"none"}`);return}return u.releaseLock(),f.releaseLock(),l}catch(h){s(`socks5 error: ${h.message}`);try{u.releaseLock()}catch{}try{f.releaseLock()}catch{}try{l.close()}catch{}return}}function ye(t,e={}){let[r,s]=t.split("@").reverse(),n,a,c,o;if(s){let i=s.split(":");if(i.length!==2)throw new Error("Invalid SOCKS address format");[n,a]=i}let d=r.split(":");if(o=Number(d.pop()),isNaN(o))throw new Error("Invalid SOCKS address format");return c=d.join(":"),e&&e.username!==void 0&&e.username!==null&&e.username!==""&&(n=e.username),e&&e.password!==void 0&&e.password!==null&&e.password!==""&&(a=e.password),{username:n,password:a,hostname:c,port:o}}async function ve(t,e,r,s,n,a,c=new Uint8Array(0)){let{username:o,password:d,hostname:i,port:l}=n,u=a({hostname:i,port:l}),f=u.writable.getWriter(),m=u.readable.getReader();try{let h=o&&d?`Proxy-Authorization: Basic ${btoa(`${o}:${d}`)}\r
`:"",x=`CONNECT ${e}:${r} HTTP/1.1\r
Host: ${e}:${r}\r
${h}User-Agent: Mozilla/5.0\r
Connection: keep-alive\r
\r
`;await f.write(new TextEncoder().encode(x));let p=new Uint8Array(0),w=-1,T=0;for(;w===-1&&T<8192;){let{done:E,value:k}=await m.read();if(E)throw new Error("Connection closed before HTTP response");let P=new Uint8Array(p.length+k.length);P.set(p,0),P.set(k,p.length),p=P,T=p.length;for(let O=0;O<p.length-3;O++)if(p[O]===13&&p[O+1]===10&&p[O+2]===13&&p[O+3]===10){w=O+4;break}}if(w===-1)throw new Error("Invalid HTTP response");let b=new TextDecoder().decode(p.slice(0,w)).split(`\r
`)[0].match(/HTTP\/\d\.\d\s+(\d+)/);if(!b)throw new Error("Invalid HTTP response format");let v=parseInt(b[1]);if(v<200||v>=300)throw new Error(`HTTP CONNECT failed: HTTP ${v}`);return c.length>0&&await f.write(c),f.releaseLock(),m.releaseLock(),u}catch(h){s(`http connect error: ${h.message}`);try{f.releaseLock()}catch{}try{m.releaseLock()}catch{}try{u.close()}catch{}return}}function ke(t,e={}){let[r,s]=t.split("@").reverse(),n,a,c,o;if(s){let i=s.split(":");if(i.length!==2)throw new Error("Invalid HTTP address format");[n,a]=i}let d=r.split(":");if(o=Number(d.pop()),isNaN(o))throw new Error("Invalid HTTP address format");return c=d.join(":"),e&&e.username!==void 0&&e.username!==null&&e.username!==""&&(n=e.username),e&&e.password!==void 0&&e.password!==null&&e.password!==""&&(a=e.password),{username:n,password:a,hostname:c,port:o}}function Te(t,e,r,s,n){let a=t.proxyipHost&&!t.proxyipDisabled,c=a?t.proxyipHost:e,o=a?Number(t.proxyipPort||443):r,d=globalThis.connect?globalThis.connect({hostname:c,port:o}):void 0;if(!d)return n("connect unavailable"),null;if(s&&s.length>0){let i=d.writable.getWriter();i.write(s).then(()=>i.releaseLock()).catch(l=>n(`direct initial write error: ${l.message}`))}return d}async function C(t){let{config:e,outbound:r,addressType:s,addressRemote:n,portRemote:a,rawClientData:c,log:o,isUDP:d}=t,i=r;if(!i||i===_)return Te(e,n,a,c,o);if(i===H)return o("rejected by routing rule"),null;switch(i.type){case _:return Te(e,n,a,c,o);case Z:{let l;try{l=ye(i.address,{username:i.username,password:i.password})}catch(f){return o(`bad socks5 address: ${f.message}`),null}let u=await ge(s,n,a,o,l,globalThis.connect);if(!u)return null;if(c&&c.length>0){let f=u.writable.getWriter();f.write(c).then(()=>f.releaseLock()).catch(m=>o(`socks5 write error: ${m.message}`))}return u}case ee:{let l;try{l=ke(i.address,{username:i.username,password:i.password})}catch(f){return o(`bad http address: ${f.message}`),null}return await ve(s,n,a,o,l,globalThis.connect,c||new Uint8Array(0))}case te:return L({address:i.address,port:Number(i.port),uuid:i.uuid,path:i.path,tls:!!i.tls,sni:i.sni||""},d?2:1,s,n,a,c||new Uint8Array(0),o);default:return o(`unknown outbound type: ${i.type}`),null}}function D(t,e){return!e||e===_?_:e===H?H:t.outboundByName[e]||_}var ut=60*60*1e3,V=new Map;async function G(t,e,r){let s=`${e}:${r}`,n=V.get(s);if(n&&Date.now()-n.ts<ut)return n.data;let a=null;try{let c=e==="geosite"?re:se,o=await t.GEO_KV.get(c+r);if(o){let d=JSON.parse(o);Array.isArray(d)&&(a=d)}}catch{}return a||(a=pt(e,r)),V.set(s,{data:a,ts:Date.now()}),a}function pt(t,e){if(t==="geosite")switch(e){case"cn":return ae;case"speedtest":return oe;case"google":return ie;default:return[]}return[]}function Ee(){V.clear()}function ft(t){if(!t)return null;let e=String(t).trim();if(!e)return null;let r=e.match(/^geosite:(.+)$/i);if(r){let i=r[1].split(",").map(l=>l.trim()).filter(Boolean);return i.length===0?null:{type:"geosite",categories:i}}let s=e.match(/^geoip:(.+)$/i);if(s){let i=s[1].split(",").map(l=>l.trim()).filter(Boolean);return i.length===0?null:{type:"geoip",categories:i}}let n=e.match(/^domain:(.+)$/i);if(n)return{type:"domain",value:n[1].trim()};let a=e.match(/^full:(.+)$/i);if(a)return{type:"full",value:a[1].trim()};let c=e.match(/^keyword:(.+)$/i);if(c)return{type:"keyword",value:c[1].trim()};let o=e.match(/^ip-cidr:(.+)$/i);if(o)return{type:"ip-cidr",value:o[1].trim()};let d=e.match(/^regexp:(.+)$/i);return d?{type:"regexp",value:d[1].trim()}:{type:"domain",value:e}}function Se(t){let e=t.split(".");if(e.length!==4)return null;let r=0;for(let s of e){let n=Number(s);if(isNaN(n)||n<0||n>255)return null;r=r<<8|n}return r>>>0}function _e(t,e){let[r,s]=e.split("/"),n=s!==void 0?Number(s):32,a=Se(t);if(a===null)return!1;let c=Se(r);if(c===null)return!1;let o=n<=0?0:4294967295<<32-n>>>0;return(a&o)===(c&o)}function Oe(t,e){let r=t.toLowerCase(),s=e.toLowerCase();return r===s?!0:r.endsWith("."+s)||r.endsWith(s)}var Pe=new Map;function mt(t){let e=Pe.get(t);if(!e){try{e=new RegExp(t)}catch{e=null}Pe.set(t,e)}return e}async function ht(t,e,r,s){switch(t.type){case"domain":return r?!1:Oe(e,t.value);case"full":return r?!1:e.toLowerCase()===t.value.toLowerCase();case"keyword":return r?!1:e.toLowerCase().includes(t.value.toLowerCase());case"regexp":{if(r)return!1;let n=mt(t.value);return n?n.test(e):!1}case"ip-cidr":return r?_e(e,t.value):!1;case"geosite":{if(r)return!1;for(let n of t.categories){let a=await G(s,"geosite",n);for(let c of a)if(Oe(e,c))return!0}return!1}case"geoip":{if(!r)return!1;for(let n of t.categories){let a=await G(s,"geoip",n);for(let c of a)if(_e(e,c))return!0}return!1}default:return!1}}async function N(t,e,r){let s=e===1||e===3;for(let n of t.routingRules){let a=ft(n.rule);if(!a)continue;if(await ht(a,r,s,t.env))return{outbound:n.outbound||"direct",rule:n}}return{outbound:t.defaultOutbound||"direct",rule:null}}async function Le(t,e,r){let s=t.headers.get("Upgrade");if(!s||s.toLowerCase()!=="websocket")return new Response("Expected WebSocket",{status:400});let[n,a]=Object.values(new WebSocketPair);a.accept();let c=(...o)=>console.log("[ws]",...o);return bt(a,e,r,c).catch(o=>{c(`ws handler error: ${o.message||o}`),S(a)}),new Response(null,{status:101,webSocket:n})}async function bt(t,e,r,s){let n;try{n=await wt(t,s)}catch(h){s(`read first packet error: ${h.message}`),S(t);return}if(!n){S(t);return}let a,c=null,o="vless";if(we(n)){if(a=await xe(n,e.passwordSet),a.hasError){s(`trojan header error: ${a.message}`),S(t);return}o="trojan",c=e.trojanIndex[a.userPassword]||null}else{if(a=he(n,e.uuidSet),a.hasError){s(`vless header error: ${a.message}`),S(t);return}c=e.vlessIndex[a.userUuid]||null}let{addressType:d,addressRemote:i,portRemote:l,isUDP:u}=a,f=new Uint8Array(n.slice(a.rawDataIndex)),m;try{m=await N(e,d,i)}catch(h){s(`route error: ${h.message}`),S(t);return}u?await gt(t,e,d,i,l,f,c,o,m,s):await xt(t,e,d,i,l,f,c,o,m,s)}function wt(t,e){return new Promise((r,s)=>{let n=!1,a=()=>{t.removeEventListener("message",c),t.removeEventListener("close",o),t.removeEventListener("error",d)},c=i=>{n||(n=!0,a(),r(i.data))},o=()=>{n||(n=!0,a(),r(null))},d=i=>{n||(n=!0,a(),s(i))};t.addEventListener("message",c),t.addEventListener("close",o),t.addEventListener("error",d),setTimeout(()=>{n||(n=!0,a(),r(null))},15e3)})}async function xt(t,e,r,s,n,a,c,o,d,i){let l=D(e,d.outbound),u=a&&a.length>0?a:new Uint8Array(0),f=[l];l!=="direct"&&l!=="reject"&&f.push("direct");let m=null,h=null;for(let b of f){try{m=await C({config:e,outbound:b,addressType:r,addressRemote:s,portRemote:n,rawClientData:u,log:i})}catch(v){h=v,m=null}if(m)break}if(!m){i(`tcp connect failed: ${h?h.message:"no outbound available"}`),S(t);return}let x=0,p=0,w=!1,T=m.writable.getWriter(),g=b=>{if(w)return;let v=b.data;if(v){x+=v.byteLength||0;try{T.write(v).catch(()=>{})}catch{}}};t.addEventListener("message",g);try{let b=m.readable.getReader();for(;;){let{done:v,value:E}=await b.read();if(v)break;E&&E.byteLength>0&&(p+=E.byteLength,t.readyState===1&&t.send(E))}}catch(b){i(`tcp remote read error: ${b.message}`)}w=!0,t.removeEventListener("message",g);try{T.releaseLock()}catch{}try{await m.writable.close()}catch{}try{t.close()}catch{}await Ue(e,c,o,x,p,i)}async function gt(t,e,r,s,n,a,c,o,d,i){let l=null,u=(e.udpOutbound||"").trim();if(u){let g=e.outboundByName[u];if(g&&g.type==="vless")l=g;else{i(`udp outbound '${u}' not found or not vless (only vless supports udp)`),S(t);return}}else{if(d.outbound&&d.outbound!=="direct"&&d.outbound!=="reject"){let g=D(e,d.outbound);g!=="direct"&&g!=="reject"&&g.type==="vless"&&(l=g)}l||(l=e.outbounds.find(g=>g.type==="vless"))}if(!l){i("udp requires a vless outbound, none configured"),S(t);return}let f=a&&a.length>0?a:new Uint8Array([0,0]),m=await L({address:l.address,port:Number(l.port),uuid:l.uuid,path:l.path,tls:!!l.tls,sni:l.sni||""},2,r,s,n,f,i);if(!m){i("udp vless outbound connect failed"),S(t);return}let h=0,x=0,p=!1,w=m.writable.getWriter(),T=g=>{if(p)return;let b=g.data;if(b){h+=b.byteLength||0;try{w.write(b).catch(()=>{})}catch{}}};t.addEventListener("message",T);try{let g=m.readable.getReader();for(;;){let{done:b,value:v}=await g.read();if(b)break;v&&v.byteLength>0&&(x+=v.byteLength,t.readyState===1&&t.send(v))}}catch(g){i(`udp read error: ${g.message}`)}p=!0,t.removeEventListener("message",T);try{w.releaseLock()}catch{}try{await m.writable.close()}catch{}S(t),await Ue(e,c,o,h,x,i)}async function Ue(t,e,r,s,n,a){if(!e)return;let c=r==="vless"?"vless_users":"trojan_users";try{await t.env.DB.prepare(`UPDATE ${c} SET up = up + ?, down = down + ? WHERE id = ?`).bind(s,n,e.id).run()}catch(o){a(`record traffic error: ${o.message}`)}}function A(t){let e=t.wsPath.startsWith("/")?t.wsPath:`/${t.wsPath}`,r=t.wsHost||t.host,s=t.sni||(t.tls?r:""),n=new URLSearchParams({encryption:"none",type:"ws",path:e,host:r,security:t.tls?"tls":"none"});t.tls&&s&&n.set("sni",s),t.fp&&n.set("fp",t.fp);let a=encodeURIComponent(t.remark||`${t.host}:${t.port}`);return`vless://${t.uuid}@${t.host}:${t.port}?${n.toString()}#${a}`}function R(t){let e=t.wsPath.startsWith("/")?t.wsPath:`/${t.wsPath}`,r=t.wsHost||t.host,s=t.sni||(t.tls?r:""),n=new URLSearchParams({type:"ws",path:e,host:r,security:t.tls?"tls":"none"});t.tls&&s&&n.set("sni",s);let a=encodeURIComponent(t.remark||`${t.host}:${t.port}`);return`trojan://${encodeURIComponent(t.password)}@${t.host}:${t.port}?${n.toString()}#${a}`}function $e(t){let e=t.headers.get("Host");return e?e.split(":")[0]:"example.com"}function yt(t,e){let r=[],s=e.port||(e.tls?443:80);for(let n of t.vlessUsers)r.push(A({uuid:n.uuid,host:e.host,port:s,wsPath:t.wsPath,tls:e.tls,wsHost:e.wsHost,sni:e.sni,remark:`vless-${n.remark||n.uuid.slice(0,8)}`}));for(let n of t.trojanUsers)r.push(R({password:n.password,host:e.host,port:s,wsPath:t.wsPath,tls:e.tls,wsHost:e.wsHost,sni:e.sni,remark:`trojan-${n.remark||n.password.slice(0,8)}`}));return r}function K(t,e){return yt(t,e).join(`
`)+`
`}function Ce(t,e){return btoa(K(t,e))}function De(t,e){let r=e.port||443,s=e.tls!==!1,n=t.wsPath.startsWith("/")?t.wsPath:`/${t.wsPath}`,a=e.wsHost||e.host,c=e.sni||(s?a:""),o=[],d=t.vlessUsers.map((u,f)=>({name:`vless-${u.remark||f+1}`,type:"vless",server:e.host,port:r,uuid:u.uuid,network:"ws",tls:s,servername:c||void 0,"ws-opts":{path:n,headers:{Host:a}},udp:!0})),i=t.trojanUsers.map((u,f)=>({name:`trojan-${u.remark||f+1}`,type:"trojan",server:e.host,port:r,password:u.password,network:"ws",tls:s,servername:c||void 0,"ws-opts":{path:n,headers:{Host:a}},udp:!0}));o.push(...d,...i);let l=["proxies:"];for(let u of o)l.push(`  - name: "${u.name}"`),l.push(`    type: ${u.type}`),l.push(`    server: ${u.server}`),l.push(`    port: ${u.port}`),u.uuid&&l.push(`    uuid: ${u.uuid}`),u.password&&l.push(`    password: "${u.password}"`),l.push("    network: ws"),l.push(`    tls: ${u.tls}`),u.servername&&l.push(`    servername: ${u.servername}`),l.push("    udp: true"),l.push("    ws-opts:"),l.push(`      path: ${u["ws-opts"].path}`),l.push("      headers:"),l.push(`        Host: ${a}`);return l.push(""),l.push("rules:"),l.push("  - MATCH,DIRECT"),l.join(`
`)}function Ae(t,e){let r=e.port||443,s=t.wsPath.startsWith("/")?t.wsPath:`/${t.wsPath}`,n=e.wsHost||e.host,a=e.sni||(e.tls?n:""),c=[];for(let o of t.vlessUsers)c.push({type:"vless",tag:`vless-${o.remark||o.uuid.slice(0,8)}`,server:e.host,server_port:r,uuid:o.uuid,transport:{type:"ws",path:s,headers:{Host:n}},tls:e.tls?{enabled:!0,server_name:a}:null});for(let o of t.trojanUsers)c.push({type:"trojan",tag:`trojan-${o.remark||o.password.slice(0,8)}`,server:e.host,server_port:r,password:o.password,transport:{type:"ws",path:s,headers:{Host:n}},tls:e.tls?{enabled:!0,server_name:a}:null});return JSON.stringify({outbounds:c,log:{level:"info"}},null,2)}function Y(t,e){let r=e.host,s=e.port||(e.tls?443:80),n=t.wsPath.startsWith("/")?t.wsPath:`/${t.wsPath}`,a="",c="";return e.kind==="vless"?(a=A({uuid:e.credential,host:r,port:s,wsPath:n,tls:e.tls,wsHost:e.wsHost,sni:e.sni,remark:"vless-node"}),c="VLESS"):e.kind==="trojan"&&(a=R({password:e.credential,host:r,port:s,wsPath:n,tls:e.tls,wsHost:e.wsHost,sni:e.sni,remark:"trojan-node"}),c="Trojan"),`<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>${c} \u8282\u70B9\u914D\u7F6E</title>
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
  <h1>${c} \u8282\u70B9 <span class="badge">${r}</span></h1>
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
</html>`}function Re(t){let e=t.disguise_title||"AList",r=t.disguise_subtitle||"\u4E00\u4E2A\u652F\u6301\u591A\u5B58\u50A8\u7684\u6587\u4EF6\u5217\u8868\u7A0B\u5E8F";return`<!DOCTYPE html>
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
<div class="footer">Powered by ${e} \xB7 ${r}</div>
</body>
</html>`}function J(t,e=200){return new Response(t,{status:e,headers:{"Content-Type":"text/html; charset=utf-8","Cache-Control":"no-store"}})}function U(t,e="text/plain; charset=utf-8"){return new Response(t,{headers:{"Content-Type":e,"Cache-Control":"no-store"}})}function vt(t,e,r){let n=(new URL(t.url).searchParams.get("format")||"base64").toLowerCase(),a={host:r.host,port:r.port,tls:r.tls,wsHost:r.wsHost,sni:r.sni};switch(n){case"plain":return U(K(e,a));case"clash":case"yaml":return U(De(e,a),"text/yaml; charset=utf-8");case"singbox":case"sing-box":case"json":return U(Ae(e,a),"application/json; charset=utf-8");case"base64":default:return U(Ce(e,a))}}function kt(t,e,r,s){let n=new URL(t.url),a=null;if(e.uuidSet.has(r)?a={kind:"vless",user:e.vlessIndex[r]}:e.passwordSet.has(r)&&(a={kind:"trojan",user:e.trojanIndex[r]}),!a)return new Response("Not Found",{status:404});let c=(n.searchParams.get("format")||"base64").toLowerCase(),o=s.host,d=s.port,i=e.wsPath,l;return a.kind==="vless"?l=A({uuid:a.user.uuid,host:o,port:d,wsPath:e.wsPath,tls:s.tls,wsHost:s.wsHost,sni:s.sni,remark:`vless-${a.user.remark||"node"}`}):l=R({password:a.user.password,host:o,port:d,wsPath:e.wsPath,tls:s.tls,wsHost:s.wsHost,sni:s.sni,remark:`trojan-${a.user.remark||"node"}`}),U(c==="plain"?l+`
`:btoa(l+`
`))}async function He(t,e,r){let s=new URL(t.url),n=s.pathname,a=$e(t),c=s.protocol==="https:",o=Number(s.port)||(c?443:80),d=(e.entryHost||"").trim(),i=d?{host:d,port:Number(e.entryPort)||443,tls:!0,wsHost:(e.entryWsHost||"").trim()||d,sni:(e.entrySni||"").trim()||d}:{host:a,port:o,tls:c,wsHost:a,sni:a};if(n==="/subscribe")return vt(t,e,i);let l=n.match(/^\/([^/]+)\/subscribe$/);if(l)return kt(t,e,decodeURIComponent(l[1]),i);let u=n.match(/^\/([^/]+)$/);if(u){let f=decodeURIComponent(u[1]);if(e.uuidSet.has(f))return J(Y(e,{host:i.host,port:i.port,tls:i.tls,wsHost:i.wsHost,sni:i.sni,credential:f,kind:"vless"}));if(e.passwordSet.has(f))return J(Y(e,{host:i.host,port:i.port,tls:i.tls,wsHost:i.wsHost,sni:i.sni,credential:f,kind:"trojan"}))}return J(Re(e.settings))}function Tt(t){if(t.length<2)return{frame:null,remaining:t,needMore:!0};let e=t[0]<<8|t[1];return e===0?{frame:new Uint8Array(0),remaining:t.slice(2),needMore:!1}:t.length<2+e?{frame:null,remaining:t,needMore:!0}:{frame:t.slice(2,2+e),remaining:t.slice(2+e),needMore:!1}}function Ne(t){let e=new Uint8Array(2+t.length);return e[0]=t.length>>8,e[1]=t.length&255,e.set(t,2),e}async function Ie(t,e,r){let s=t.getReader(),n=new Uint8Array(0);try{for(;;){let{done:a,value:c}=await s.read();if(a)break;if(!c||c.byteLength===0)continue;let o=new Uint8Array(n.length+c.byteLength);for(o.set(n,0),o.set(c,n.length),n=o;;){let{frame:d,remaining:i,needMore:l}=Tt(n);if(l){n=i;break}if(n=i,d&&d.length>0)try{await e(d)}catch(u){r(`udp frame handler error: ${u.message}`)}if(n.length<2)break}}}catch(a){r(`readUdpFrames error: ${a.message}`)}finally{try{s.releaseLock()}catch{}}}var Me=[{name:"\u5B57\u8282\u8DF3\u52A8",host:"www.bytedance.com",port:80,region:"cn",icon:"\u{1F3B5}"},{name:"Bilibili",host:"www.bilibili.com",port:80,region:"cn",icon:"\u{1F4FA}"},{name:"\u5FAE\u4FE1",host:"weixin.qq.com",port:80,region:"cn",icon:"\u{1F4AC}"},{name:"\u6DD8\u5B9D",host:"www.taobao.com",port:80,region:"cn",icon:"\u{1F6D2}"},{name:"GitHub",host:"github.com",port:80,region:"intl",icon:"\u{1F419}"},{name:"jsDelivr",host:"cdn.jsdelivr.net",port:80,region:"intl",icon:"\u{1F4E6}"},{name:"Cloudflare",host:"www.cloudflare.com",port:80,region:"intl",icon:"\u2601\uFE0F"},{name:"YouTube",host:"www.youtube.com",port:80,region:"intl",icon:"\u25B6\uFE0F"}],je=16,ze=3e3,Be=4;var Et=5e3,St=5e3;function q(t,e,r="/"){return new TextEncoder().encode(`GET ${r} HTTP/1.1\r
Host: ${t}\r
User-Agent: Mozilla/5.0 (netprobe)\r
Connection: close\r
\r
`)}function _t(t,e){let r=new Uint8Array(t.length+e.length);return r.set(t,0),r.set(e,t.length),r}function Ot(t){for(let e=0;e<t.length-3;e++)if(t[e]===13&&t[e+1]===10&&t[e+2]===13&&t[e+3]===10)return e+4;return-1}function We(t){try{typeof t.close=="function"?t.close():t.writable&&typeof t.writable.close=="function"&&t.writable.close().catch(()=>{})}catch{}}function X(t,e){return new Promise(r=>{let s=new Uint8Array(0),n=!1,a=o=>{n||(n=!0,clearTimeout(c),r(o))},c=setTimeout(()=>a(null),e);(async()=>{let o=t.readable.getReader();try{for(;!n;){let{done:d,value:i}=await o.read();if(d)break;if(!(!i||i.byteLength===0)){if(s=_t(s,i),Ot(s)>=0){a(Date.now());break}if(s.length>65536){a(null);break}}}}catch{}a(null);try{o.releaseLock()}catch{}})()})}async function Pt(t,e,r,s,n){let a=Date.now(),c;try{let d=await N(t,2,e),i=D(t,d.outbound);c=await C({config:t,outbound:i,addressType:2,addressRemote:e,portRemote:r,rawClientData:s,log:n})}catch{return null}if(!c)return null;let o=await X(c,ze);return We(c),o===null?null:o-a}async function Lt(t,e,r){let s=[];for(let c=0;c<je;c+=Be){let o=[],d=Math.min(c+Be,je);for(let l=c;l<d;l++)o.push(Pt(t,e.host,e.port,q(e.host,e.port),r));let i=await Promise.all(o);for(let l of i)s.push(l)}let n=s.filter(c=>c!==null),a=n.length>0?Math.round(n.reduce((c,o)=>c+o,0)/n.length):null;return{...e,samples:s,latency:a,success:n.length,total:s.length}}async function Fe(t,e){let r=await Promise.allSettled(Me.map(s=>Lt(t,s,e)));return{ok:!0,ts:Date.now(),targets:r.map((s,n)=>s.status==="fulfilled"?s.value:{...Me[n],samples:[],latency:null,success:0,total:0,error:s.reason&&s.reason.message||"error"})}}async function Ve(t,e){if(!t.proxyipHost)return{ok:!1,error:"\u672A\u914D\u7F6E proxyip\uFF0C\u8BF7\u5148\u5728\u7CFB\u7EDF\u8BBE\u7F6E\u4E2D\u586B\u5199"};let r="www.cloudflare.com",s=443,n=Date.now(),a=null;try{if(a=globalThis.connect?globalThis.connect({hostname:t.proxyipHost,port:Number(t.proxyipPort||443)}):null,!a)return{ok:!1,error:"connect \u4E0D\u53EF\u7528"};let o=a.writable.getWriter();await o.write(q(r,s)),o.releaseLock()}catch(o){try{a&&a.close()}catch{}return{ok:!1,error:`\u8FDE\u63A5\u5931\u8D25: ${o.message}`}}let c=await X(a,ze);try{a.close()}catch{}return c===null?{ok:!1,error:"\u8FDE\u63A5\u8D85\u65F6\u6216\u65E0\u54CD\u5E94"}:{ok:!0,latency:c-n,endpoint:`${t.proxyipHost}:${t.proxyipPort||443}`}}function Ut(t){let r=[18,52];r.push(1,0),r.push(0,1),r.push(0,0,0,0,0,0);for(let s of String(t).split(".")){r.push(s.length);for(let n=0;n<s.length;n++)r.push(s.charCodeAt(n))}return r.push(0),r.push(0,1),r.push(0,1),new Uint8Array(r)}async function Ge(t,e){let r=null,s=(t.udpOutbound||"").trim();if(s){let i=t.outboundByName[s];if(i&&i.type==="vless")r=i;else return{ok:!1,error:`UDP \u51FA\u7AD9 '${s}' \u4E0D\u5B58\u5728\u6216\u975E vless\uFF08\u4EC5 vless \u652F\u6301 UDP\uFF09`}}else if(r=t.outbounds.find(i=>i.type==="vless"),!r)return{ok:!1,error:"\u672A\u914D\u7F6E vless \u51FA\u7AD9\uFF0C\u65E0\u6CD5\u6D4B\u8BD5 UDP"};let n=Ut("example.com"),a=Ne(n),c=Date.now(),o;try{o=await L({address:r.address,port:Number(r.port),uuid:r.uuid,path:r.path,tls:!!r.tls,sni:r.sni||""},2,1,"1.1.1.1",53,a,e)}catch(i){return{ok:!1,error:`UDP \u51FA\u7AD9\u8FDE\u63A5\u5931\u8D25: ${i.message}`}}if(!o)return{ok:!1,error:"UDP \u51FA\u7AD9\u8FDE\u63A5\u5931\u8D25"};let d=await new Promise(i=>{let l=setTimeout(()=>i({ok:!1,error:"UDP \u54CD\u5E94\u8D85\u65F6"}),Et);Ie(o.readable,u=>{u.length>=12&&u[0]===18&&u[1]===52&&u[2]&128&&(clearTimeout(l),i({ok:!0,latency:Date.now()-c,bytes:u.length}))},e)});try{o.writable.close().catch(()=>{})}catch{}return d}async function Ke(t,e,r){let s="www.gstatic.com",a=Date.now(),c;try{c=await C({config:t,outbound:e,addressType:2,addressRemote:s,portRemote:80,rawClientData:q(s,80,"/generate_204"),log:r})}catch(d){return{ok:!1,error:d.message}}if(!c)return{ok:!1,error:"\u96A7\u9053\u5EFA\u7ACB\u5931\u8D25"};let o=await X(c,St);return We(c),o===null?{ok:!1,error:"\u8FDE\u63A5\u8D85\u65F6\u6216\u65E0\u54CD\u5E94"}:{ok:!0,latency:o-a}}var Q={"Content-Type":"application/json; charset=utf-8"};function y(t,e=200){return new Response(JSON.stringify(t),{status:e,headers:Q})}async function I(t){try{return await t.json()}catch{return null}}function $t(t){return t.admin_cookie_secret||t.admin_password_hash||"vtd-insecure-secret"}async function Ye(t,e){let n=new URL(t.url).pathname.split("/").filter(Boolean),a=n[2]||"",c=n[3]||null,o=t.method,{DB:d,GEO_KV:i}=e.env,l=e.settings,u=$t(l);if(a==="login"&&o==="POST"){let p=await I(t);if(!p||!p.password)return y({error:"password required"},400);if(!await le(p.password,e.adminPasswordHash))return y({error:"invalid password"},401);let T=await pe(u);return new Response(JSON.stringify({ok:!0}),{status:200,headers:{...Q,"Set-Cookie":`${$}=${T}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${7*86400}`}})}let f=me(t.headers.get("Cookie"));if(!await fe(f[$],u))return y({error:"unauthorized"},401);if(a==="logout"&&o==="POST")return new Response(JSON.stringify({ok:!0}),{status:200,headers:{...Q,"Set-Cookie":`${$}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0`}});if(a==="settings"){if(o==="GET"){let{results:p}=await d.prepare("SELECT key, value FROM settings").all();return y((p||[]).reduce((w,T)=>(w[T.key]=T.value,w),{}))}if(o==="PUT"){let p=await I(t);if(!p)return y({error:"bad body"},400);let w=new Set(["ws_path","default_outbound","proxyip","udp_outbound","disguise_title","disguise_subtitle","entry_host","entry_port","entry_sni","entry_ws_host","admin_password_hash","admin_cookie_secret"]);for(let[T,g]of Object.entries(p))typeof g=="string"&&w.has(T)&&await d.prepare("INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at").bind(T,g,Date.now()).run();return y({ok:!0})}return y({error:"method not allowed"},405)}let x={"vless-users":{table:"vless_users",cols:["uuid","remark","enable"]},"trojan-users":{table:"trojan_users",cols:["password","remark","enable"]},outbounds:{table:"outbounds",cols:["type","name","address","port","uuid","path","tls","udp","enable","sort","username","password","sni"],validate(p){return p.type!==void 0&&!["socks5","http","vless"].includes(p.type)?"invalid outbound type":p.port!==void 0&&(!Number.isInteger(Number(p.port))||Number(p.port)<=0||Number(p.port)>65535)?"invalid port":(p.type==="socks5"||p.type==="http")&&!p.address?"address required":p.type==="vless"&&!p.uuid?"vless requires uuid":p.username&&!p.password||!p.username&&p.password?"username and password must be set together":((p.type==="socks5"||p.type==="http")&&(p.udp=0),null)}},"routing-rules":{table:"routing_rules",cols:["rule","outbound","enable","sort"]}}[a];if(x)return Ct(o,c,x,d,t);if(a==="stats"&&o==="GET"){let[p,w]=await Promise.all([d.prepare("SELECT remark, uuid, up, down FROM vless_users ORDER BY (up + down) DESC").all(),d.prepare("SELECT remark, password, up, down FROM trojan_users ORDER BY (up + down) DESC").all()]);return y({vless:p.results||[],trojan:w.results||[]})}if(a==="geo"&&n[3]==="update"&&o==="POST")try{let p=await M(d,i);return y({ok:!0,updated:p})}catch(p){return y({error:p.message},500)}if(a==="netstatus"&&n[3]==="test"&&o==="POST")try{return y(await Fe(e,console))}catch(p){return y({ok:!1,error:p.message},500)}if(a==="test"){if(n[3]==="proxyip"&&o==="POST")try{return y(await Ve(e,console))}catch(p){return y({ok:!1,error:p.message},500)}if(n[3]==="udp"&&o==="POST")try{return y(await Ge(e,console))}catch(p){return y({ok:!1,error:p.message},500)}if(n[3]==="outbound"&&n[4]&&o==="POST"){let p=await d.prepare("SELECT * FROM outbounds WHERE id = ?").bind(Number(n[4])).first();if(!p)return y({ok:!1,error:"outbound not found"},404);try{return y(await Ke(e,p,console))}catch(w){return y({ok:!1,error:w.message},500)}}}return y({error:"not found"},404)}async function Ct(t,e,r,s,n){let{table:a,cols:c}=r,o="id";if(t==="GET"){let{results:d}=await s.prepare(`SELECT * FROM ${a} ORDER BY id`).all();return y(d||[])}if(t==="POST"){let d=await I(n);if(!d)return y({error:"bad body"},400);if(r.validate){let m=r.validate(d);if(m)return y({error:m},400)}let i=c.filter(m=>d[m]!==void 0);if(i.length===0)return y({error:"no fields"},400);let l=i.map(()=>"?").join(","),u=i.map(m=>d[m]),{meta:f}=await s.prepare(`INSERT INTO ${a} (${i.join(",")}) VALUES (${l})`).bind(...u).run();return y({ok:!0,id:f.last_row_id})}if(t==="PUT"&&e){let d=await I(n);if(!d)return y({error:"bad body"},400);if(r.validate){let f=r.validate(d);if(f)return y({error:f},400)}let i=c.filter(f=>d[f]!==void 0);if(i.length===0)return y({error:"no fields"},400);let l=i.map(f=>`${f} = ?`).join(","),u=i.map(f=>d[f]);return await s.prepare(`UPDATE ${a} SET ${l} WHERE ${o} = ?`).bind(...u,Number(e)).run(),y({ok:!0})}return t==="DELETE"&&e?(await s.prepare(`DELETE FROM ${a} WHERE ${o} = ?`).bind(Number(e)).run(),y({ok:!0})):y({error:"method not allowed"},405)}async function M(t,e){let{results:r}=await t.prepare("SELECT rule FROM routing_rules").all(),s={geosite:new Set,geoip:new Set};for(let a of r||[]){let c=String(a.rule||"").trim(),o=c.match(/^geosite:(.+)$/i);o&&o[1].split(",").forEach(d=>s.geosite.add(d.trim())),o=c.match(/^geoip:(.+)$/i),o&&o[1].split(",").forEach(d=>s.geoip.add(d.trim()))}let n=0;for(let a of["geosite","geoip"])for(let c of s[a])try{let o=await Dt(a,c);o&&o.length>0&&(await e.put(`${a}:${c}`,JSON.stringify(o)),n++)}catch{}return await e.put("geo:version",new Date().toISOString()),Ee(),n}async function Dt(t,e){let s=`https://raw.githubusercontent.com/${t==="geosite"?"MetaCubeX/sing-geosite":"MetaCubeX/sing-geoip"}/rule-set/${e}.json`,n=await fetch(s,{cf:{cacheTtl:86400}});if(!n.ok)return null;let a=await n.text(),c;try{c=JSON.parse(a)}catch{return null}let o=[],d=i=>{typeof i=="string"&&i&&o.length<2e4&&o.push(i)};for(let i of c.rules||[])if(t==="geosite"){for(let l of i.domain||[])d(l);for(let l of i.domain_suffix||[])d(String(l).replace(/^\.+/,""))}else for(let l of i.ip_cidr||[])d(l);return o}function Je(t){return`<!DOCTYPE html>
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

<div class="toast" id="toast"></div>

<script>
const $ = (s) => document.querySelector(s);
const state = { tab:'stats', editing:null, schema:null, records:[] };
const TAB_DEFS = {
  vless:   { title:'VLESS \u7528\u6237', api:'vless-users', fields:[{k:'uuid',label:'UUID'},{k:'remark',label:'\u5907\u6CE8'},{k:'enable',label:'\u542F\u7528',type:'checkbox'}] },
  trojan:  { title:'Trojan \u7528\u6237', api:'trojan-users', fields:[{k:'password',label:'\u5BC6\u7801'},{k:'remark',label:'\u5907\u6CE8'},{k:'enable',label:'\u542F\u7528',type:'checkbox'}] },
  outbounds:{ title:'\u51FA\u7AD9\u4EE3\u7406', api:'outbounds', fields:[{k:'type',label:'\u7C7B\u578B',type:'select',opts:['socks5','http','vless']},{k:'name',label:'\u540D\u79F0'},{k:'address',label:'\u5730\u5740'},{k:'port',label:'\u7AEF\u53E3',type:'number'},{k:'username',label:'\u7528\u6237\u540D(\u4EC5socks5/http)'},{k:'password',label:'\u5BC6\u7801(\u4EC5socks5/http)'},{k:'uuid',label:'UUID(\u4EC5vless)'},{k:'path',label:'Path(\u4EC5vless)'},{k:'tls',label:'TLS',type:'checkbox'},{k:'sni',label:'SNI(\u4EC5vless)',placeholder:'\u7559\u7A7A\u5219\u4F7F\u7528\u5730\u5740\u4F5C\u4E3A\u8FDE\u63A5\u4E3B\u673A\u4E0ESNI'},{k:'udp',label:'UDP',type:'checkbox'},{k:'enable',label:'\u542F\u7528',type:'checkbox'},{k:'sort',label:'\u6392\u5E8F',type:'number'}] },
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
  vless:  ['type','name','address','port','uuid','path','tls','sni','udp','enable','sort'],
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
</html>`}async function qe(t,e){let r=new URL(t.url);if(t.method==="POST"||t.method==="GET")try{let{DB:s,GEO_KV:n}=e,a=await M(s,n);return new Response(JSON.stringify({ok:!0,updated:a}),{status:200,headers:{"Content-Type":"application/json; charset=utf-8"}})}catch(s){return new Response(JSON.stringify({ok:!1,error:s.message}),{status:500,headers:{"Content-Type":"application/json; charset=utf-8"}})}return new Response("Not Found",{status:404})}async function Xe(t,e,r){try{let s=await M(e.DB,e.GEO_KV);console.log(`[cron] geo update done: ${s} categories`)}catch(s){console.log(`[cron] geo update failed: ${s.message}`)}}var Wr={async fetch(t,e,r){let n=new URL(t.url).pathname;try{if(n.startsWith("/admin")){let c=await W(t,e,{ensureAdmin:!0});return n.startsWith("/admin/api/")?await Ye(t,c):new Response(Je(c.adminTempPassword),{headers:{"Content-Type":"text/html; charset=utf-8","Cache-Control":"no-store"}})}if(n==="/geo-update-cron")return await qe(t,e);let a=await W(t,e);return n===a.wsPath?await Le(t,a,e):await He(t,a,e)}catch(a){return console.log(`[index] error: ${a.message||a}`),new Response(JSON.stringify({error:"internal error"}),{status:500,headers:{"Content-Type":"application/json; charset=utf-8"}})}},async scheduled(t,e,r){return Xe(t,e,r)}};export{Wr as default};
