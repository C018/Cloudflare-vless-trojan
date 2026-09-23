var S="direct",C="reject",Y="socks5",X="http",q="vless",Q="geosite:",Z="geoip:";var O="vtd_admin";var ee="/ws";var te=["qq.com","taobao.com","tmall.com","jd.com","baidu.com","bilibili.com","douyin.com","weibo.com","zhihu.com","163.com","126.com","aliyun.com","tencent.com","weixin.qq.com","alipay.com","bankofchina.com","icbc.com.cn","ccb.com","abcchina.com","cmbchina.com","boc.cn","12306.cn","gov.cn","cn","com.cn","net.cn","org.cn"],re=["speedtest.net","fast.com","ookla.com"],se=["google.com","googleapis.com","gstatic.com","googleusercontent.com","ggpht.com","google.cn","google.com.hk","gvt1.com","gvt2.com","gvt3.com"],ae=["visa.com","visa.co.kr","visa.com.hk","visa.com.tw","visa.com.sg","visa.co.jp","visa.com.my","visa.com.au","visa.co.th","visa.com.cn","visa.co.in","visa.com.ph","visa.co.id","visa.co.nz","visa.com.vn"],D=[];for(let e=0;e<=255;++e){let t=e.toString(16).padStart(2,"0");D.push(t)}var j=1e5;function N(e){return Array.from(new Uint8Array(e)).map(t=>t.toString(16).padStart(2,"0")).join("")}function He(){let e=new Uint8Array(16);return crypto.getRandomValues(e),N(e)}async function ne(e,t,r){let s=await crypto.subtle.importKey("raw",new TextEncoder().encode(e),"PBKDF2",!1,["deriveBits"]),n=await crypto.subtle.deriveBits({name:"PBKDF2",salt:new TextEncoder().encode(t),iterations:r,hash:"SHA-256"},s,256);return N(n)}async function oe(e){let t=He(),r=await ne(e,t,j);return`${t}:${j}:${r}`}async function ie(e,t){if(!t||!e)return!1;let r=String(t).split(":");if(r.length!==3)return!1;let[s,n,a]=r,o=parseInt(n,10)||j;return await ne(e,s,o)===a}async function ce(e,t){let r=await crypto.subtle.importKey("raw",new TextEncoder().encode(e),{name:"HMAC",hash:"SHA-256"},!1,["sign"]),s=await crypto.subtle.sign("HMAC",r,new TextEncoder().encode(t));return N(s)}async function de(e){let r=`admin.${Math.floor(Date.now()/1e3)+604800}`,s=await ce(e,r);return`${r}.${s}`}async function le(e,t){if(!e||!t)return!1;let r=String(e).split(".");if(r.length!==3)return!1;let[s,n,a]=r;if(s!=="admin")return!1;let o=Number(n);if(!Number.isFinite(o)||o<Date.now()/1e3)return!1;let c=await ce(t,`${s}.${n}`);if(c.length!==a.length)return!1;let d=0;for(let i=0;i<c.length;i++)d|=c.charCodeAt(i)^a.charCodeAt(i);return d===0}function ue(e){let t={};if(!e)return t;for(let r of e.split(";")){let s=r.indexOf("=");if(s<0)continue;let n=r.slice(0,s).trim(),a=r.slice(s+1).trim();t[n]=decodeURIComponent(a)}return t}async function Ve(e){try{let{results:t}=await e.prepare("SELECT key, value FROM settings").all(),r={};for(let s of t||[])r[s.key]=s.value;return r}catch{return{}}}async function We(e){try{let{results:t}=await e.prepare("SELECT id, uuid, remark, up, down FROM vless_users WHERE enable = 1 ORDER BY id").all();return t||[]}catch{return[]}}async function ze(e){try{let{results:t}=await e.prepare("SELECT id, password, remark, up, down FROM trojan_users WHERE enable = 1 ORDER BY id").all();return t||[]}catch{return[]}}async function Fe(e){try{let{results:t}=await e.prepare("SELECT * FROM outbounds WHERE enable = 1 ORDER BY sort ASC, id ASC").all();return t||[]}catch{return[]}}async function Ge(e){try{let{results:t}=await e.prepare("SELECT * FROM routing_rules WHERE enable = 1 ORDER BY sort ASC, id ASC").all();return t||[]}catch{return[]}}async function Ke(e){try{let s=await e.prepare("SELECT value FROM settings WHERE key = ?").bind("admin_password_hash").first();if(s&&s.value)return{hash:s.value,tempPassword:null}}catch{}let t=Je().replace(/-/g,"").slice(0,12),r=await oe(t);try{await e.prepare("INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at").bind("admin_password_hash",r,Date.now()).run()}catch{}return{hash:r,tempPassword:t}}async function M(e,t){let{DB:r}=t,s=await Ve(r),n=s.ws_path||ee,a=s.default_outbound||S,o=s.admin_password_hash||"",c=null;if(!o){let h=await Ke(r);o=h.hash,c=h.tempPassword}let d=s.proxyip||"",i=s.cdnip||"",l=[];for(let h=1;h<=13;h++){let g=s[`ip${h}`];if(g){let y=s[`pt${h}`]||"443";l.push(y&&!g.includes(":")?`${g}:${y}`:g)}}let p=await We(r),u=await ze(r),f=await Fe(r),m=await Ge(r),x={};for(let h of p)x[h.uuid]=h;let b={};for(let h of u)b[h.password]=h;return{env:t,settings:s,wsPath:n,defaultOutbound:a,adminPasswordHash:o,adminTempPassword:c,proxyip:d,cdnIP:i,preferredIPs:l,vlessUsers:p,trojanUsers:u,outbounds:f,routingRules:m,vlessIndex:x,trojanIndex:b,uuidSet:new Set(p.map(h=>h.uuid)),passwordSet:new Set(u.map(h=>h.password)),visaDomains:ae,outboundByName:f.reduce((h,g)=>(h[g.name]=g,h),{})}}function Je(){return globalThis.crypto&&typeof globalThis.crypto.randomUUID=="function"?globalThis.crypto.randomUUID():"xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(/[xy]/g,e=>{let t=Math.random()*16|0;return(e==="x"?t:t&3|8).toString(16)})}function Ye(e){let t=r=>D[e[r]];return`${t(0)}${t(1)}${t(2)}${t(3)}-${t(4)}${t(5)}-${t(6)}${t(7)}-${t(8)}${t(9)}-${t(10)}${t(11)}${t(12)}${t(13)}${t(14)}${t(15)}`.toLowerCase()}function pe(e,t){if(e.byteLength<24)return{hasError:!0,message:"invalid data"};let r=new DataView(e),s=r.getUint8(0),n=Ye(new Uint8Array(e.slice(1,17)));if(!t.has(n))return{hasError:!0,message:"invalid user"};let o=18+r.getUint8(17);if(e.byteLength<o+4)return{hasError:!0,message:"invalid data"};let c=r.getUint8(o);if(c!==1&&c!==2)return{hasError:!0,message:`command ${c} is not supported`};let d=o+1,i=r.getUint16(d),l=r.getUint8(d+2),p,u,f;switch(l){case 1:u=4,f=d+3,p=Array.from(new Uint8Array(e.slice(f,f+u))).join(".");break;case 2:if(e.byteLength<d+4)return{hasError:!0,message:"invalid data"};u=r.getUint8(d+3),f=d+4,p=new TextDecoder().decode(e.slice(f,f+u));break;case 3:u=16,f=d+3,p=Array.from({length:8},(m,x)=>r.getUint16(f+x*2).toString(16)).join(":");break;default:return{hasError:!0,message:`invalid addressType: ${l}`}}return p?{hasError:!1,userUuid:n,addressRemote:p,addressType:l,portRemote:i,rawDataIndex:f+u,protocolVersion:new Uint8Array([s]),isUDP:c===2}:{hasError:!0,message:"addressValue is empty"}}function fe(e,t,r,s,n){let a,o,c=[];switch(t){case 1:a=4,c=r.split(".").map(Number);break;case 2:o=new TextEncoder().encode(r),a=o.length+1;break;case 3:a=16,c=Xe(r).split(":").map(l=>[parseInt(l.slice(0,2),16),parseInt(l.slice(2),16)]).flat();break;default:throw new Error(`Unknown address type: ${t}`)}let d=n.replace(/-/g,""),i=new Uint8Array(22+a);i[0]=0;for(let l=0;l<d.length;l+=2)i[1+l/2]=parseInt(d.substr(l,2),16);return i[17]=0,i[18]=e,i[19]=s>>8,i[20]=s&255,i[21]=t,t===2?(i[22]=o.length,i.set(o,23)):i.set(c,22),i}function Xe(e){if(e=e.replace(/^\[|\]$/g,""),e.includes("::")){let t=e.split("::"),r=t[0]?t[0].split(":"):[],s=t[1]?t[1].split(":"):[],n=8-r.length-s.length,a=Array(Math.max(0,n)).fill("0");return[...r,...a,...s].map(o=>o.padStart(4,"0")).join(":")}return e.split(":").map(t=>t.padStart(4,"0")).join(":")}async function qe(e){let t=new TextEncoder().encode(e),r=await crypto.subtle.digest({name:"SHA-224"},t);return Array.from(new Uint8Array(r)).map(s=>s.toString(16).padStart(2,"0")).join("")}function he(e){if(e.byteLength<60)return!1;let t=new Uint8Array(e);return t[56]===13&&t[57]===10}async function me(e,t){if(e.byteLength<60)return{hasError:!0,message:"Invalid Trojan data: too short"};let r=new Uint8Array(e),s=new DataView(e);if(r[56]!==13||r[57]!==10)return{hasError:!0,message:"Invalid Trojan header: missing CRLF"};let n=new TextDecoder().decode(r.slice(0,56)),a=null;for(let m of t)try{if(await qe(m)===n){a=m;break}}catch{}if(!a)return{hasError:!0,message:"Invalid Trojan password"};let o=r[58];if(o!==1&&o!==3)return{hasError:!0,message:`Unsupported Trojan command: ${o}`};let c=r[59],d,i,l;switch(c){case 1:if(i=4,l=60,e.byteLength<l+i+2)return{hasError:!0,message:"Invalid Trojan header: IPv4 truncated"};d=Array.from(r.slice(l,l+i)).join(".");break;case 3:if(i=r[60],l=61,e.byteLength<l+i+2)return{hasError:!0,message:"Invalid Trojan header: domain truncated"};d=new TextDecoder().decode(r.slice(l,l+i));break;case 4:if(i=16,l=60,e.byteLength<l+i+2)return{hasError:!0,message:"Invalid Trojan header: IPv6 truncated"};d=Array.from({length:8},(m,x)=>s.getUint16(l+x*2).toString(16)).join(":");break;default:return{hasError:!0,message:`Invalid Trojan address type: ${c}`}}let p=l+i;if(e.byteLength<p+2)return{hasError:!0,message:"Invalid Trojan header: port truncated"};let u=s.getUint16(p),f=p+2;return e.byteLength<f+2?{hasError:!0,message:"Invalid Trojan header: missing final CRLF"}:r[f]!==13||r[f+1]!==10?{hasError:!0,message:"Invalid Trojan header: invalid final CRLF"}:{hasError:!1,userPassword:a,addressRemote:d,addressType:c===3?2:c,portRemote:u,rawDataIndex:f+2,isUDP:o===3}}function E(e){try{e&&e.readyState===1&&e.close()}catch{}}var Qe=1e4;async function U(e,t,r,s,n,a,o){let c=e.tls?"wss":"ws",d=e.path&&e.path.startsWith("/")?e.path:`/${e.path||""}`,i=`${c}://${e.address}:${e.port}${d}`,l;try{l=new WebSocket(i)}catch(y){return o(`[VLESS] create ws failed: ${y.message}`),null}let p,u=new Promise(y=>{p=y});try{await new Promise((y,w)=>{let v=setTimeout(()=>w(new Error("Connection timeout")),Qe);l.addEventListener("open",()=>{clearTimeout(v),y()}),l.addEventListener("close",T=>{clearTimeout(v),w(new Error(`closed ${T.code}`))}),l.addEventListener("error",()=>{clearTimeout(v),w(new Error("ws error"))})})}catch(y){o(`[VLESS] connect failed: ${y.message}`);try{l.close()}catch{}return p(),null}l.addEventListener("close",()=>p()),l.addEventListener("error",()=>{});let f=new WritableStream({write(y){l.readyState===1&&l.send(y)},close(){E(l)},abort(){E(l)}}),m=!1,x=new ReadableStream({start(y){l.addEventListener("message",w=>{let v=new Uint8Array(w.data);if(!m&&(m=!0,v.length>=2)){let T=v[1];if(v.length>2+T)v=v.slice(2+T);else return}if(v.length>0)try{y.enqueue(v)}catch{}}),l.addEventListener("close",()=>{try{y.close()}catch{}}),l.addEventListener("error",w=>{try{y.error(w)}catch{}})},cancel(){E(l)}}),b=fe(t,r,s,n,e.uuid),h=a instanceof Uint8Array?a:new Uint8Array(a||0),g=new Uint8Array(b.length+h.length);g.set(b,0),g.set(h,b.length);try{l.send(g)}catch(y){return o(`[VLESS] send header failed: ${y.message}`),E(l),p(),null}return{readable:x,writable:f,closed:u}}async function be(e,t,r,s,n,a){let{username:o,password:c,hostname:d,port:i}=n,l=a({hostname:d,port:i}),p=l.writable.getWriter(),u=l.readable.getReader(),f=new TextEncoder;try{await p.write(new Uint8Array([5,2,0,2]));let m=(await u.read()).value;if(!m||m[0]!==5){s("socks version error");return}if(m[1]===255){s("no acceptable methods");return}if(m[1]===2){if(!o||!c){s("socks server requires auth but no credentials");return}let h=new Uint8Array([1,o.length,...f.encode(o),c.length,...f.encode(c)]);if(await p.write(h),m=(await u.read()).value,!m||m[0]!==1||m[1]!==0){s("socks auth failed");return}}let x;switch(e){case 1:x=new Uint8Array([1,...t.split(".").map(Number)]);break;case 2:x=new Uint8Array([3,t.length,...f.encode(t)]);break;case 3:x=new Uint8Array([4,...t.split(":").flatMap(h=>[parseInt(h.slice(0,2),16),parseInt(h.slice(2),16)])]);break;default:s(`invalid addressType ${e}`);return}let b=new Uint8Array([5,1,0,...x,r>>8,r&255]);if(await p.write(b),m=(await u.read()).value,!m||m[1]!==0){s(`socks connect failed rep=${m?m[1]:"none"}`);return}return p.releaseLock(),u.releaseLock(),l}catch(m){s(`socks5 error: ${m.message}`);try{p.releaseLock()}catch{}try{u.releaseLock()}catch{}try{l.close()}catch{}return}}function ge(e){let[t,r]=e.split("@").reverse(),s,n,a,o;if(r){let d=r.split(":");if(d.length!==2)throw new Error("Invalid SOCKS address format");[s,n]=d}let c=t.split(":");if(o=Number(c.pop()),isNaN(o))throw new Error("Invalid SOCKS address format");return a=c.join(":"),{username:s,password:n,hostname:a,port:o}}async function xe(e,t,r,s,n,a,o=new Uint8Array(0)){let{username:c,password:d,hostname:i,port:l}=n,p=a({hostname:i,port:l}),u=p.writable.getWriter(),f=p.readable.getReader();try{let m=c&&d?`Proxy-Authorization: Basic ${btoa(`${c}:${d}`)}\r
`:"",x=`CONNECT ${t}:${r} HTTP/1.1\r
Host: ${t}:${r}\r
${m}User-Agent: Mozilla/5.0\r
Connection: keep-alive\r
\r
`;await u.write(new TextEncoder().encode(x));let b=new Uint8Array(0),h=-1,g=0;for(;h===-1&&g<8192;){let{done:T,value:J}=await f.read();if(T)throw new Error("Connection closed before HTTP response");let R=new Uint8Array(b.length+J.length);R.set(b,0),R.set(J,b.length),b=R,g=b.length;for(let $=0;$<b.length-3;$++)if(b[$]===13&&b[$+1]===10&&b[$+2]===13&&b[$+3]===10){h=$+4;break}}if(h===-1)throw new Error("Invalid HTTP response");let w=new TextDecoder().decode(b.slice(0,h)).split(`\r
`)[0].match(/HTTP\/\d\.\d\s+(\d+)/);if(!w)throw new Error("Invalid HTTP response format");let v=parseInt(w[1]);if(v<200||v>=300)throw new Error(`HTTP CONNECT failed: HTTP ${v}`);return o.length>0&&await u.write(o),u.releaseLock(),f.releaseLock(),p}catch(m){s(`http connect error: ${m.message}`);try{u.releaseLock()}catch{}try{f.releaseLock()}catch{}try{p.close()}catch{}return}}function we(e){let[t,r]=e.split("@").reverse(),s,n,a,o;if(r){let d=r.split(":");if(d.length!==2)throw new Error("Invalid HTTP address format");[s,n]=d}let c=t.split(":");if(o=Number(c.pop()),isNaN(o))throw new Error("Invalid HTTP address format");return a=c.join(":"),{username:s,password:n,hostname:a,port:o}}function ye(e,t,r,s){let n=globalThis.connect?globalThis.connect({hostname:e,port:t}):void 0;if(!n)return s("connect unavailable"),null;if(r&&r.length>0){let a=n.writable.getWriter();a.write(r).then(()=>a.releaseLock()).catch(o=>s(`direct initial write error: ${o.message}`))}return n}async function ve(e){let{config:t,outbound:r,addressType:s,addressRemote:n,portRemote:a,rawClientData:o,log:c,isUDP:d}=e,i=r;if(!i||i===S)return ye(n,a,o,c);if(i===C)return c("rejected by routing rule"),null;switch(i.type){case S:return ye(n,a,o,c);case Y:{let l;try{l=ge(i.address)}catch(u){return c(`bad socks5 address: ${u.message}`),null}let p=await be(s,n,a,c,l,globalThis.connect);if(!p)return null;if(o&&o.length>0){let u=p.writable.getWriter();u.write(o).then(()=>u.releaseLock()).catch(f=>c(`socks5 write error: ${f.message}`))}return p}case X:{let l;try{l=we(i.address)}catch(u){return c(`bad http address: ${u.message}`),null}return await xe(s,n,a,c,l,globalThis.connect,o||new Uint8Array(0))}case q:return U({address:i.address,port:Number(i.port),uuid:i.uuid,path:i.path,tls:!!i.tls},d?2:1,s,n,a,o||new Uint8Array(0),c);default:return c(`unknown outbound type: ${i.type}`),null}}function H(e,t){return!t||t===S?S:t===C?C:e.outboundByName[t]||S}var Ze=60*60*1e3,V=new Map;async function W(e,t,r){let s=`${t}:${r}`,n=V.get(s);if(n&&Date.now()-n.ts<Ze)return n.data;let a=null;try{let o=t==="geosite"?Q:Z,c=await e.GEO_KV.get(o+r);if(c){let d=JSON.parse(c);Array.isArray(d)&&(a=d)}}catch{}return a||(a=et(t,r)),V.set(s,{data:a,ts:Date.now()}),a}function et(e,t){if(e==="geosite")switch(t){case"cn":return te;case"speedtest":return re;case"google":return se;default:return[]}return[]}function ke(){V.clear()}function tt(e){if(!e)return null;let t=String(e).trim();if(!t)return null;let r=t.match(/^geosite:(.+)$/i);if(r){let i=r[1].split(",").map(l=>l.trim()).filter(Boolean);return i.length===0?null:{type:"geosite",categories:i}}let s=t.match(/^geoip:(.+)$/i);if(s){let i=s[1].split(",").map(l=>l.trim()).filter(Boolean);return i.length===0?null:{type:"geoip",categories:i}}let n=t.match(/^domain:(.+)$/i);if(n)return{type:"domain",value:n[1].trim()};let a=t.match(/^full:(.+)$/i);if(a)return{type:"full",value:a[1].trim()};let o=t.match(/^keyword:(.+)$/i);if(o)return{type:"keyword",value:o[1].trim()};let c=t.match(/^ip-cidr:(.+)$/i);if(c)return{type:"ip-cidr",value:c[1].trim()};let d=t.match(/^regexp:(.+)$/i);return d?{type:"regexp",value:d[1].trim()}:{type:"domain",value:t}}function Ee(e){let t=e.split(".");if(t.length!==4)return null;let r=0;for(let s of t){let n=Number(s);if(isNaN(n)||n<0||n>255)return null;r=r<<8|n}return r>>>0}function Te(e,t){let[r,s]=t.split("/"),n=s!==void 0?Number(s):32,a=Ee(e);if(a===null)return!1;let o=Ee(r);if(o===null)return!1;let c=n<=0?0:4294967295<<32-n>>>0;return(a&c)===(o&c)}function Se(e,t){let r=e.toLowerCase(),s=t.toLowerCase();return r===s?!0:r.endsWith("."+s)||r.endsWith(s)}var $e=new Map;function rt(e){let t=$e.get(e);if(!t){try{t=new RegExp(e)}catch{t=null}$e.set(e,t)}return t}async function st(e,t,r,s){switch(e.type){case"domain":return r?!1:Se(t,e.value);case"full":return r?!1:t.toLowerCase()===e.value.toLowerCase();case"keyword":return r?!1:t.toLowerCase().includes(e.value.toLowerCase());case"regexp":{if(r)return!1;let n=rt(e.value);return n?n.test(t):!1}case"ip-cidr":return r?Te(t,e.value):!1;case"geosite":{if(r)return!1;for(let n of e.categories){let a=await W(s,"geosite",n);for(let o of a)if(Se(t,o))return!0}return!1}case"geoip":{if(!r)return!1;for(let n of e.categories){let a=await W(s,"geoip",n);for(let o of a)if(Te(t,o))return!0}return!1}default:return!1}}async function Le(e,t,r){let s=t===1||t===3;for(let n of e.routingRules){let a=tt(n.rule);if(!a)continue;if(await st(a,r,s,e.env))return{outbound:n.outbound||"direct",rule:n}}return{outbound:e.defaultOutbound||"direct",rule:null}}async function Pe(e,t,r){let s=e.headers.get("Upgrade");if(!s||s.toLowerCase()!=="websocket")return new Response("Expected WebSocket",{status:400});let[n,a]=Object.values(new WebSocketPair);a.accept();let o=(...c)=>console.log("[ws]",...c);return at(a,t,r,o).catch(c=>{o(`ws handler error: ${c.message||c}`),E(a)}),new Response(null,{status:101,webSocket:n})}async function at(e,t,r,s){let n;try{n=await nt(e,s)}catch(m){s(`read first packet error: ${m.message}`),E(e);return}if(!n){E(e);return}let a,o=null,c="vless";if(he(n)){if(a=await me(n,t.passwordSet),a.hasError){s(`trojan header error: ${a.message}`),E(e);return}c="trojan",o=t.trojanIndex[a.userPassword]||null}else{if(a=pe(n,t.uuidSet),a.hasError){s(`vless header error: ${a.message}`),E(e);return}o=t.vlessIndex[a.userUuid]||null}let{addressType:d,addressRemote:i,portRemote:l,isUDP:p}=a,u=new Uint8Array(n.slice(a.rawDataIndex)),f;try{f=await Le(t,d,i)}catch(m){s(`route error: ${m.message}`),E(e);return}p?await it(e,t,d,i,l,u,o,c,f,s):await ot(e,t,d,i,l,u,o,c,f,s)}function nt(e,t){return new Promise((r,s)=>{let n=!1,a=()=>{e.removeEventListener("message",o),e.removeEventListener("close",c),e.removeEventListener("error",d)},o=i=>{n||(n=!0,a(),r(i.data))},c=()=>{n||(n=!0,a(),r(null))},d=i=>{n||(n=!0,a(),s(i))};e.addEventListener("message",o),e.addEventListener("close",c),e.addEventListener("error",d),setTimeout(()=>{n||(n=!0,a(),r(null))},15e3)})}async function ot(e,t,r,s,n,a,o,c,d,i){let l=H(t,d.outbound),p=a&&a.length>0?a:new Uint8Array(0),u=[l];l!=="direct"&&l!=="reject"&&u.push("direct");let f=null,m=null;for(let w of u){try{f=await ve({config:t,outbound:w,addressType:r,addressRemote:s,portRemote:n,rawClientData:p,log:i})}catch(v){m=v,f=null}if(f)break}if(!f){i(`tcp connect failed: ${m?m.message:"no outbound available"}`),E(e);return}let x=0,b=0,h=!1,g=f.writable.getWriter(),y=w=>{if(h)return;let v=w.data;if(v){x+=v.byteLength||0;try{g.write(v).catch(()=>{})}catch{}}};e.addEventListener("message",y);try{let w=f.readable.getReader();for(;;){let{done:v,value:T}=await w.read();if(v)break;T&&T.byteLength>0&&(b+=T.byteLength,e.readyState===1&&e.send(T))}}catch(w){i(`tcp remote read error: ${w.message}`)}h=!0,e.removeEventListener("message",y);try{g.releaseLock()}catch{}try{await f.writable.close()}catch{}try{e.close()}catch{}await Oe(t,o,c,x,b,i)}async function it(e,t,r,s,n,a,o,c,d,i){let l=null;if(d.outbound&&d.outbound!=="direct"&&d.outbound!=="reject"){let g=H(t,d.outbound);g!=="direct"&&g!=="reject"&&g.type==="vless"&&(l=g)}if(l||(l=t.outbounds.find(g=>g.type==="vless")),!l){i("udp requires a vless outbound, none configured"),E(e);return}let p=a&&a.length>0?a:new Uint8Array([0,0]),u=await U({address:l.address,port:Number(l.port),uuid:l.uuid,path:l.path,tls:!!l.tls},2,r,s,n,p,i);if(!u){i("udp vless outbound connect failed"),E(e);return}let f=0,m=0,x=!1,b=u.writable.getWriter(),h=g=>{if(x)return;let y=g.data;if(y){f+=y.byteLength||0;try{b.write(y).catch(()=>{})}catch{}}};e.addEventListener("message",h);try{let g=u.readable.getReader();for(;;){let{done:y,value:w}=await g.read();if(y)break;w&&w.byteLength>0&&(m+=w.byteLength,e.readyState===1&&e.send(w))}}catch(g){i(`udp read error: ${g.message}`)}x=!0,e.removeEventListener("message",h);try{b.releaseLock()}catch{}try{await u.writable.close()}catch{}E(e),await Oe(t,o,c,f,m,i)}async function Oe(e,t,r,s,n,a){if(!t)return;let o=r==="vless"?"vless_users":"trojan_users";try{await e.env.DB.prepare(`UPDATE ${o} SET up = up + ?, down = down + ? WHERE id = ?`).bind(s,n,t.id).run()}catch(c){a(`record traffic error: ${c.message}`)}}function L(e){let t=e.wsPath.startsWith("/")?e.wsPath:`/${e.wsPath}`,r=new URLSearchParams({encryption:"none",type:"ws",path:t,host:e.host,security:e.tls?"tls":"none"});e.tls&&e.host&&r.set("sni",e.host),e.fp&&r.set("fp",e.fp);let s=encodeURIComponent(e.remark||`${e.host}:${e.port}`);return`vless://${e.uuid}@${e.host}:${e.port}?${r.toString()}#${s}`}function _(e){let t=e.wsPath.startsWith("/")?e.wsPath:`/${e.wsPath}`,r=new URLSearchParams({type:"ws",path:t,host:e.host,security:e.tls?"tls":"none"});e.tls&&e.host&&r.set("sni",e.host);let s=encodeURIComponent(e.remark||`${e.host}:${e.port}`);return`trojan://${encodeURIComponent(e.password)}@${e.host}:${e.port}?${r.toString()}#${s}`}function _e(e){let t=e.headers.get("Host");return t?t.split(":")[0]:"example.com"}function ct(e,t){let r=[],s=t.port||(t.tls?443:80);for(let n of e.vlessUsers)r.push(L({uuid:n.uuid,host:t.host,port:s,wsPath:e.wsPath,tls:t.tls,remark:`vless-${n.remark||n.uuid.slice(0,8)}`}));for(let n of e.trojanUsers)r.push(_({password:n.password,host:t.host,port:s,wsPath:e.wsPath,tls:t.tls,remark:`trojan-${n.remark||n.password.slice(0,8)}`}));if(t.includePreferred&&e.preferredIPs.length>0)for(let n of e.preferredIPs){let[a,o]=n.includes(":")?n.split(":"):[n,s];for(let c of e.vlessUsers)r.push(L({uuid:c.uuid,host:a,port:Number(o),wsPath:e.wsPath,tls:!0,remark:`\u4F18\u9009-${c.remark||c.uuid.slice(0,8)}`}))}return r}function z(e,t){return ct(e,t).join(`
`)+`
`}function Ce(e,t){return btoa(z(e,t))}function Ue(e,t){let r=t.port||443,s=t.tls!==!1,n=e.wsPath.startsWith("/")?e.wsPath:`/${e.wsPath}`,a=[],o=e.vlessUsers.map((i,l)=>({name:`vless-${i.remark||l+1}`,type:"vless",server:t.host,port:r,uuid:i.uuid,network:"ws",tls:s,servername:s?t.host:void 0,"ws-opts":{path:n,headers:{Host:t.host}},udp:!0})),c=e.trojanUsers.map((i,l)=>({name:`trojan-${i.remark||l+1}`,type:"trojan",server:t.host,port:r,password:i.password,network:"ws",tls:s,servername:s?t.host:void 0,"ws-opts":{path:n,headers:{Host:t.host}},udp:!0}));a.push(...o,...c);let d=["proxies:"];for(let i of a)d.push(`  - name: "${i.name}"`),d.push(`    type: ${i.type}`),d.push(`    server: ${i.server}`),d.push(`    port: ${i.port}`),i.uuid&&d.push(`    uuid: ${i.uuid}`),i.password&&d.push(`    password: "${i.password}"`),d.push("    network: ws"),d.push(`    tls: ${i.tls}`),i.servername&&d.push(`    servername: ${i.servername}`),d.push("    udp: true"),d.push("    ws-opts:"),d.push(`      path: ${i["ws-opts"].path}`),d.push("      headers:"),d.push(`        Host: ${t.host}`);return d.push(""),d.push("rules:"),d.push("  - MATCH,DIRECT"),d.join(`
`)}function Ae(e,t){let r=t.port||443,s=e.wsPath.startsWith("/")?e.wsPath:`/${e.wsPath}`,n=[];for(let a of e.vlessUsers)n.push({type:"vless",tag:`vless-${a.remark||a.uuid.slice(0,8)}`,server:t.host,server_port:r,uuid:a.uuid,transport:{type:"ws",path:s,headers:{Host:t.host}},tls:t.tls?{enabled:!0,server_name:t.host}:null});for(let a of e.trojanUsers)n.push({type:"trojan",tag:`trojan-${a.remark||a.password.slice(0,8)}`,server:t.host,server_port:r,password:a.password,transport:{type:"ws",path:s,headers:{Host:t.host}},tls:t.tls?{enabled:!0,server_name:t.host}:null});return JSON.stringify({outbounds:n,log:{level:"info"}},null,2)}function F(e,t){let r=t.host,s=t.port||(t.tls?443:80),n=e.wsPath.startsWith("/")?e.wsPath:`/${e.wsPath}`,a="",o="";return t.kind==="vless"?(a=L({uuid:t.credential,host:r,port:s,wsPath:n,tls:t.tls,remark:"vless-node"}),o="VLESS"):t.kind==="trojan"&&(a=_({password:t.credential,host:r,port:s,wsPath:n,tls:t.tls,remark:"trojan-node"}),o="Trojan"),`<!DOCTYPE html>
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
</html>`}function Ie(e){let t=e.disguise_title||"AList",r=e.disguise_subtitle||"\u4E00\u4E2A\u652F\u6301\u591A\u5B58\u50A8\u7684\u6587\u4EF6\u5217\u8868\u7A0B\u5E8F";return`<!DOCTYPE html>
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
</html>`}function G(e,t=200){return new Response(e,{status:t,headers:{"Content-Type":"text/html; charset=utf-8","Cache-Control":"no-store"}})}function P(e,t="text/plain; charset=utf-8"){return new Response(e,{headers:{"Content-Type":t,"Cache-Control":"no-store"}})}function dt(e,t,r){let s=new URL(e.url),n=(s.searchParams.get("format")||"base64").toLowerCase(),a=s.searchParams.get("preferred")!=="0",o={host:r.host,port:r.port,tls:r.tls,includePreferred:a};switch(n){case"plain":return P(z(t,o));case"clash":case"yaml":return P(Ue(t,o),"text/yaml; charset=utf-8");case"singbox":case"sing-box":case"json":return P(Ae(t,o),"application/json; charset=utf-8");case"base64":default:return P(Ce(t,o))}}function lt(e,t,r,s){let n=new URL(e.url),a=null;if(t.uuidSet.has(r)?a={kind:"vless",user:t.vlessIndex[r]}:t.passwordSet.has(r)&&(a={kind:"trojan",user:t.trojanIndex[r]}),!a)return new Response("Not Found",{status:404});let o=(n.searchParams.get("format")||"base64").toLowerCase(),c=s.host,d=s.port,i=t.wsPath,l;return a.kind==="vless"?l=L({uuid:a.user.uuid,host:c,port:d,wsPath:t.wsPath,tls:s.tls,remark:`vless-${a.user.remark||"node"}`}):l=_({password:a.user.password,host:c,port:d,wsPath:t.wsPath,tls:s.tls,remark:`trojan-${a.user.remark||"node"}`}),P(o==="plain"?l+`
`:btoa(l+`
`))}async function Re(e,t,r){let s=new URL(e.url),n=s.pathname,a=_e(e),o=s.protocol==="https:",c=Number(s.port)||(o?443:80),d={host:a,tls:o,port:c};if(n==="/subscribe")return dt(e,t,d);let i=n.match(/^\/([^/]+)\/subscribe$/);if(i)return lt(e,t,decodeURIComponent(i[1]),d);let l=n.match(/^\/([^/]+)$/);if(l){let p=decodeURIComponent(l[1]);if(t.uuidSet.has(p))return G(F(t,{host:a,port:c,tls:o,credential:p,kind:"vless"}));if(t.passwordSet.has(p))return G(F(t,{host:a,port:c,tls:o,credential:p,kind:"trojan"}))}return G(Ie(t.settings))}var K={"Content-Type":"application/json; charset=utf-8"};function k(e,t=200){return new Response(JSON.stringify(e),{status:t,headers:K})}async function A(e){try{return await e.json()}catch{return null}}function ut(e){return e.admin_cookie_secret||e.admin_password_hash||"vtd-insecure-secret"}async function De(e,t){let n=new URL(e.url).pathname.split("/").filter(Boolean),a=n[2]||"",o=n[3]||null,c=e.method,{DB:d,GEO_KV:i}=t.env,l=t.settings,p=ut(l);if(a==="login"&&c==="POST"){let b=await A(e);if(!b||!b.password)return k({error:"password required"},400);if(!await ie(b.password,t.adminPasswordHash))return k({error:"invalid password"},401);let g=await de(p);return new Response(JSON.stringify({ok:!0}),{status:200,headers:{...K,"Set-Cookie":`${O}=${g}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${7*86400}`}})}let u=ue(e.headers.get("Cookie"));if(!await le(u[O],p))return k({error:"unauthorized"},401);if(a==="logout"&&c==="POST")return new Response(JSON.stringify({ok:!0}),{status:200,headers:{...K,"Set-Cookie":`${O}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0`}});if(a==="settings"){if(c==="GET"){let{results:b}=await d.prepare("SELECT key, value FROM settings").all();return k((b||[]).reduce((h,g)=>(h[g.key]=g.value,h),{}))}if(c==="PUT"){let b=await A(e);if(!b)return k({error:"bad body"},400);for(let[h,g]of Object.entries(b))typeof g=="string"&&await d.prepare("INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at").bind(h,g,Date.now()).run();return k({ok:!0})}return k({error:"method not allowed"},405)}let x={"vless-users":{table:"vless_users",cols:["uuid","remark","enable"]},"trojan-users":{table:"trojan_users",cols:["password","remark","enable"]},outbounds:{table:"outbounds",cols:["type","name","address","port","uuid","path","tls","udp","enable","sort"]},"routing-rules":{table:"routing_rules",cols:["rule","outbound","enable","sort"]}}[a];if(x)return pt(c,o,x,d,e);if(a==="stats"&&c==="GET"){let[b,h]=await Promise.all([d.prepare("SELECT remark, uuid, up, down FROM vless_users ORDER BY (up + down) DESC").all(),d.prepare("SELECT remark, password, up, down FROM trojan_users ORDER BY (up + down) DESC").all()]);return k({vless:b.results||[],trojan:h.results||[]})}if(a==="geo"&&n[3]==="update"&&c==="POST")try{let b=await I(d,i);return k({ok:!0,updated:b})}catch(b){return k({error:b.message},500)}return k({error:"not found"},404)}async function pt(e,t,r,s,n){let{table:a,cols:o}=r,c="id";if(e==="GET"){let{results:d}=await s.prepare(`SELECT * FROM ${a} ORDER BY id`).all();return k(d||[])}if(e==="POST"){let d=await A(n);if(!d)return k({error:"bad body"},400);let i=o.filter(f=>d[f]!==void 0);if(i.length===0)return k({error:"no fields"},400);let l=i.map(()=>"?").join(","),p=i.map(f=>d[f]),{meta:u}=await s.prepare(`INSERT INTO ${a} (${i.join(",")}) VALUES (${l})`).bind(...p).run();return k({ok:!0,id:u.last_row_id})}if(e==="PUT"&&t){let d=await A(n);if(!d)return k({error:"bad body"},400);let i=o.filter(u=>d[u]!==void 0);if(i.length===0)return k({error:"no fields"},400);let l=i.map(u=>`${u} = ?`).join(","),p=i.map(u=>d[u]);return await s.prepare(`UPDATE ${a} SET ${l} WHERE ${c} = ?`).bind(...p,Number(t)).run(),k({ok:!0})}return e==="DELETE"&&t?(await s.prepare(`DELETE FROM ${a} WHERE ${c} = ?`).bind(Number(t)).run(),k({ok:!0})):k({error:"method not allowed"},405)}async function I(e,t){let{results:r}=await e.prepare("SELECT rule FROM routing_rules").all(),s={geosite:new Set,geoip:new Set};for(let a of r||[]){let o=String(a.rule||"").trim(),c=o.match(/^geosite:(.+)$/i);c&&c[1].split(",").forEach(d=>s.geosite.add(d.trim())),c=o.match(/^geoip:(.+)$/i),c&&c[1].split(",").forEach(d=>s.geoip.add(d.trim()))}let n=0;for(let a of["geosite","geoip"])for(let o of s[a])try{let c=await ft(a,o);c&&c.length>0&&(await t.put(`${a}:${o}`,JSON.stringify(c)),n++)}catch{}return await t.put("geo:version",new Date().toISOString()),ke(),n}async function ft(e,t){let s=`https://raw.githubusercontent.com/${e==="geosite"?"MetaCubeX/sing-geosite":"MetaCubeX/sing-geoip"}/rule-set/${t}.json`,n=await fetch(s,{cf:{cacheTtl:86400}});if(!n.ok)return null;let a=await n.text(),o=[],c=/"(\S+?)"/g,d;for(;(d=c.exec(a))&&o.length<2e4;){let i=d[1];e==="geosite"?(i.startsWith("domain:")||i.startsWith("full:")||i.startsWith("keyword:")||i.startsWith("regexp:"))&&o.push(i.slice(i.indexOf(":")+1)):i.includes("/")&&o.push(i)}return o}function je(e){return`<!DOCTYPE html>
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
    <div class="nav-item" data-tab="vless">\u{1F511} VLESS \u7528\u6237</div>
    <div class="nav-item" data-tab="trojan">\u{1F6E1}\uFE0F Trojan \u7528\u6237</div>
    <div class="nav-item" data-tab="outbounds">\u{1F310} \u51FA\u7AD9\u4EE3\u7406</div>
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
  outbounds:{ title:'\u51FA\u7AD9\u4EE3\u7406', api:'outbounds', fields:[{k:'type',label:'\u7C7B\u578B',type:'select',opts:['socks5','http','vless']},{k:'name',label:'\u540D\u79F0'},{k:'address',label:'\u5730\u5740'},{k:'port',label:'\u7AEF\u53E3',type:'number'},{k:'uuid',label:'UUID(\u4EC5vless)'},{k:'path',label:'Path(\u4EC5vless)'},{k:'tls',label:'TLS',type:'checkbox'},{k:'udp',label:'UDP',type:'checkbox'},{k:'enable',label:'\u542F\u7528',type:'checkbox'},{k:'sort',label:'\u6392\u5E8F',type:'number'}] },
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
  if (tab==='settings'){ mc.innerHTML = '<div class="page-title">\u7CFB\u7EDF\u8BBE\u7F6E</div><div class="card">\u52A0\u8F7D\u4E2D...</div>'; await loadSettings(); return; }
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
    return '<tr>'+tds+'<td><button class="btn small" onclick="openEdit('+idx+')">\u7F16\u8F91</button> <button class="btn small danger" onclick="delRow('+idx+')">\u5220\u9664</button></td></tr>';
  }).join('') || '<tr><td colspan="99" style="text-align:center;color:var(--muted)">\u6682\u65E0\u6570\u636E</td></tr>';
}

function esc(s){ return String(s==null?'':s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }

function openNew(){ state.editing=null; openModal({}); }
function openEdit(idx){ state.editing = state.records[idx]; openModal(state.editing); }

function openModal(record){
  const def = state.schema;
  $('#modalTitle').textContent = state.editing ? '\u7F16\u8F91' : '\u65B0\u589E';
  $('#modalBody').innerHTML = def.fields.map(f=>{
    const val = record[f.k];
    if (f.type==='checkbox') return '<label><input type="checkbox" id="f_'+f.k+'" '+(val?'checked':'')+'> '+f.label+'</label>';
    if (f.type==='select') return '<label>'+f.label+'</label><select id="f_'+f.k+'">'+f.opts.map(o=>'<option '+(o===val?'selected':'')+'>'+o+'</option>').join('')+'</select>';
    return '<label>'+f.label+'</label><input type="'+ (f.type||'text') +'" id="f_'+f.k+'" value="'+esc(val)+'">';
  }).join('');
  $('#modalMask').classList.add('show');
}

async function saveModal(){
  const def = state.schema;
  const body = {};
  for (const f of def.fields){
    const el = $('#f_'+f.k);
    if (!el) continue;
    if (f.type==='checkbox') body[f.k] = el.checked ? 1 : 0;
    else if (f.type==='number') body[f.k] = Number(el.value);
    else body[f.k] = el.value;
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
      ['disguise_title','\u4F2A\u88C5\u9875\u6807\u9898'],
      ['disguise_subtitle','\u4F2A\u88C5\u9875\u526F\u6807\u9898'],
      ['cdnip','CDN IP'],
      ['proxyip','\u4E2D\u8F6C IP'],
      ['ip1','\u4F18\u9009IP 1'],['pt1','\u4F18\u9009\u7AEF\u53E3 1'],['ip2','\u4F18\u9009IP 2'],['pt2','\u4F18\u9009\u7AEF\u53E3 2'],
      ['ip3','\u4F18\u9009IP 3'],['pt3','\u4F18\u9009\u7AEF\u53E3 3'],['ip4','\u4F18\u9009IP 4'],['pt4','\u4F18\u9009\u7AEF\u53E3 4'],
      ['ip5','\u4F18\u9009IP 5'],['pt5','\u4F18\u9009\u7AEF\u53E3 5'],['ip6','\u4F18\u9009IP 6'],['pt6','\u4F18\u9009\u7AEF\u53E3 6'],
      ['ip7','\u4F18\u9009IP 7'],['pt7','\u4F18\u9009\u7AEF\u53E3 7'],['ip8','\u4F18\u9009IP 8'],['pt8','\u4F18\u9009\u7AEF\u53E3 8'],
      ['ip9','\u4F18\u9009IP 9'],['pt9','\u4F18\u9009\u7AEF\u53E3 9'],['ip10','\u4F18\u9009IP 10'],['pt10','\u4F18\u9009\u7AEF\u53E3 10'],
      ['ip11','\u4F18\u9009IP 11'],['pt11','\u4F18\u9009\u7AEF\u53E3 11'],['ip12','\u4F18\u9009IP 12'],['pt12','\u4F18\u9009\u7AEF\u53E3 12'],
      ['ip13','\u4F18\u9009IP 13'],['pt13','\u4F18\u9009\u7AEF\u53E3 13']
    ];
    mc.innerHTML = '<div class="page-title">\u7CFB\u7EDF\u8BBE\u7F6E</div><div class="card">'+
      fields.map(([k,label])=>'<label style="display:block;font-size:13px;color:var(--muted);margin:10px 0 4px">'+label+'</label><input id="s_'+k+'" value="'+esc(s[k]||'')+'" style="width:100%;padding:8px 12px;border:1px solid var(--border);border-radius:8px">').join('')+
      '<div style="margin-top:16px"><button class="btn small" onclick="saveSettings()">\u4FDD\u5B58\u8BBE\u7F6E</button> <button class="btn small" onclick="updateGeo()">\u66F4\u65B0 Geo \u89C4\u5219\u5E93</button></div></div>';
    state.settings = s;
  } catch(e){ mc.innerHTML = '<div class="page-title">\u7CFB\u7EDF\u8BBE\u7F6E</div><div class="card">\u52A0\u8F7D\u5931\u8D25: '+esc(e.message)+'</div>'; }
}

async function saveSettings(){
  const body = {};
  document.querySelectorAll('#mainContent input[id^=s_]').forEach(el=>{ body[el.id.slice(2)] = el.value; });
  try { await api('/admin/api/settings',{method:'PUT',body:JSON.stringify(body)}); toast('\u8BBE\u7F6E\u5DF2\u4FDD\u5B58'); }
  catch(e){ toast(e.message); }
}

async function updateGeo(){
  try { const d = await api('/admin/api/geo/update',{method:'POST',body:'{}'}); toast('\u5DF2\u66F4\u65B0 '+d.updated+' \u4E2A\u5206\u7C7B'); }
  catch(e){ toast('\u66F4\u65B0\u5931\u8D25: '+e.message); }
}

// \u521D\u59CB\uFF1A\u68C0\u67E5\u767B\u5F55\u6001
(async function init(){
  try { await api('/admin/api/settings'); showApp(); }
  catch(e){ showLogin(); }
})();
<\/script>
</body>
</html>`}async function Ne(e,t){let r=new URL(e.url);if(e.method==="POST"||e.method==="GET")try{let{DB:s,GEO_KV:n}=t,a=await I(s,n);return new Response(JSON.stringify({ok:!0,updated:a}),{status:200,headers:{"Content-Type":"application/json; charset=utf-8"}})}catch(s){return new Response(JSON.stringify({ok:!1,error:s.message}),{status:500,headers:{"Content-Type":"application/json; charset=utf-8"}})}return new Response("Not Found",{status:404})}async function Me(e,t,r){try{let s=await I(t.DB,t.GEO_KV);console.log(`[cron] geo update done: ${s} categories`)}catch(s){console.log(`[cron] geo update failed: ${s.message}`)}}var br={async fetch(e,t,r){let n=new URL(e.url).pathname;try{if(n.startsWith("/admin")){let o=await M(e,t);return n.startsWith("/admin/api/")?await De(e,o):new Response(je(o.adminTempPassword),{headers:{"Content-Type":"text/html; charset=utf-8","Cache-Control":"no-store"}})}if(n==="/geo-update-cron")return await Ne(e,t);let a=await M(e,t);return n===a.wsPath?await Pe(e,a,t):await Re(e,a,t)}catch(a){return console.log(`[index] error: ${a.message||a}`),new Response(JSON.stringify({error:"internal error"}),{status:500,headers:{"Content-Type":"application/json; charset=utf-8"}})}},async scheduled(e,t,r){return Me(e,t,r)}};export{br as default};
