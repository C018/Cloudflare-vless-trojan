var _="direct",A="reject",J="socks5",X="http",q="vless",Q="geosite:",Z="geoip:";var C="vtd_admin";var ee="/ws";var te=["qq.com","taobao.com","tmall.com","jd.com","baidu.com","bilibili.com","douyin.com","weibo.com","zhihu.com","163.com","126.com","aliyun.com","tencent.com","weixin.qq.com","alipay.com","bankofchina.com","icbc.com.cn","ccb.com","abcchina.com","cmbchina.com","boc.cn","12306.cn","gov.cn","cn","com.cn","net.cn","org.cn"],se=["speedtest.net","fast.com","ookla.com"],re=["google.com","googleapis.com","gstatic.com","googleusercontent.com","ggpht.com","google.cn","google.com.hk","gvt1.com","gvt2.com","gvt3.com"],N=[];for(let t=0;t<=255;++t){let e=t.toString(16).padStart(2,"0");N.push(e)}var H=1e5;function j(t){return Array.from(new Uint8Array(t)).map(e=>e.toString(16).padStart(2,"0")).join("")}function Me(){let t=new Uint8Array(16);return crypto.getRandomValues(t),j(t)}async function ae(t,e,s){let r=await crypto.subtle.importKey("raw",new TextEncoder().encode(t),"PBKDF2",!1,["deriveBits"]),n=await crypto.subtle.deriveBits({name:"PBKDF2",salt:new TextEncoder().encode(e),iterations:s,hash:"SHA-256"},r,256);return j(n)}async function ne(t){let e=Me(),s=await ae(t,e,H);return`${e}:${H}:${s}`}async function oe(t,e){if(!e||!t)return!1;let s=String(e).split(":");if(s.length!==3)return!1;let[r,n,a]=s,d=parseInt(n,10)||H;return await ae(t,r,d)===a}async function ie(t,e){let s=await crypto.subtle.importKey("raw",new TextEncoder().encode(t),{name:"HMAC",hash:"SHA-256"},!1,["sign"]),r=await crypto.subtle.sign("HMAC",s,new TextEncoder().encode(e));return j(r)}async function de(t){let s=`admin.${Math.floor(Date.now()/1e3)+604800}`,r=await ie(t,s);return`${s}.${r}`}async function ce(t,e){if(!t||!e)return!1;let s=String(t).split(".");if(s.length!==3)return!1;let[r,n,a]=s;if(r!=="admin")return!1;let d=Number(n);if(!Number.isFinite(d)||d<Date.now()/1e3)return!1;let i=await ie(e,`${r}.${n}`);if(i.length!==a.length)return!1;let l=0;for(let o=0;o<i.length;o++)l|=i.charCodeAt(o)^a.charCodeAt(o);return l===0}function le(t){let e={};if(!t)return e;for(let s of t.split(";")){let r=s.indexOf("=");if(r<0)continue;let n=s.slice(0,r).trim(),a=s.slice(r+1).trim();e[n]=decodeURIComponent(a)}return e}async function Be(t){try{let{results:e}=await t.prepare("SELECT key, value FROM settings").all(),s={};for(let r of e||[])s[r.key]=r.value;return s}catch{return{}}}async function We(t){try{let{results:e}=await t.prepare("SELECT id, uuid, remark, up, down FROM vless_users WHERE enable = 1 ORDER BY id").all();return e||[]}catch{return[]}}async function Ve(t){try{let{results:e}=await t.prepare("SELECT id, password, remark, up, down FROM trojan_users WHERE enable = 1 ORDER BY id").all();return e||[]}catch{return[]}}async function ze(t){try{let{results:e}=await t.prepare("SELECT * FROM outbounds WHERE enable = 1 ORDER BY sort ASC, id ASC").all();return e||[]}catch{return[]}}async function Fe(t){try{let{results:e}=await t.prepare("SELECT * FROM routing_rules WHERE enable = 1 ORDER BY sort ASC, id ASC").all();return e||[]}catch{return[]}}async function Ge(t){try{let r=await t.prepare("SELECT value FROM settings WHERE key = ?").bind("admin_password_hash").first();if(r&&r.value)return{hash:r.value,tempPassword:null}}catch{}let e=Ke().replace(/-/g,"").slice(0,12),s=await ne(e);try{await t.prepare("INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at").bind("admin_password_hash",s,Date.now()).run()}catch{}return{hash:s,tempPassword:e}}async function M(t,e,s={}){let{DB:r}=e,n=await Be(r),a=n.ws_path||ee,d=n.default_outbound||_,i=n.admin_password_hash||"",l=null;if(!i&&s.ensureAdmin){let v=await Ge(r);i=v.hash,l=v.tempPassword}let o=n.proxyip||"",c="",u=443;if(o){let v=o.lastIndexOf(":");v>0&&!o.includes("]")&&/^\d+$/.test(o.slice(v+1))?(c=o.slice(0,v),u=Number(o.slice(v+1))||443):c=o}let p=n.udp_outbound||"",m=n.entry_host||"",h=n.entry_port||"",w=n.entry_sni||"",f=n.entry_ws_host||"",g=await We(r),k=await Ve(r),x=await ze(r),b=await Fe(r),y={};for(let v of g)y[v.uuid]=v;let E={};for(let v of k)E[v.password]=v;return{env:e,settings:n,wsPath:a,defaultOutbound:d,adminPasswordHash:i,adminTempPassword:l,proxyipHost:c,proxyipPort:u,proxyipDisabled:d!==_,udpOutbound:p,entryHost:m,entryPort:h,entrySni:w,entryWsHost:f,vlessUsers:g,trojanUsers:k,outbounds:x,routingRules:b,vlessIndex:y,trojanIndex:E,uuidSet:new Set(g.map(v=>v.uuid)),passwordSet:new Set(k.map(v=>v.password)),outboundByName:x.reduce((v,L)=>(v[L.name]=L,v),{})}}function Ke(){return globalThis.crypto&&typeof globalThis.crypto.randomUUID=="function"?globalThis.crypto.randomUUID():"xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(/[xy]/g,t=>{let e=Math.random()*16|0;return(t==="x"?e:e&3|8).toString(16)})}function Ye(t){let e=s=>N[t[s]];return`${e(0)}${e(1)}${e(2)}${e(3)}-${e(4)}${e(5)}-${e(6)}${e(7)}-${e(8)}${e(9)}-${e(10)}${e(11)}${e(12)}${e(13)}${e(14)}${e(15)}`.toLowerCase()}function ue(t,e){if(t.byteLength<24)return{hasError:!0,message:"invalid data"};let s=new DataView(t),r=s.getUint8(0),n=Ye(new Uint8Array(t.slice(1,17)));if(!e.has(n))return{hasError:!0,message:"invalid user"};let d=18+s.getUint8(17);if(t.byteLength<d+4)return{hasError:!0,message:"invalid data"};let i=s.getUint8(d);if(i!==1&&i!==2)return{hasError:!0,message:`command ${i} is not supported`};let l=d+1,o=s.getUint16(l),c=s.getUint8(l+2),u,p,m;switch(c){case 1:p=4,m=l+3,u=Array.from(new Uint8Array(t.slice(m,m+p))).join(".");break;case 2:if(t.byteLength<l+4)return{hasError:!0,message:"invalid data"};p=s.getUint8(l+3),m=l+4,u=new TextDecoder().decode(t.slice(m,m+p));break;case 3:p=16,m=l+3,u=Array.from({length:8},(h,w)=>s.getUint16(m+w*2).toString(16)).join(":");break;default:return{hasError:!0,message:`invalid addressType: ${c}`}}return u?{hasError:!1,userUuid:n,addressRemote:u,addressType:c,portRemote:o,rawDataIndex:m+p,protocolVersion:new Uint8Array([r]),isUDP:i===2}:{hasError:!0,message:"addressValue is empty"}}function pe(t,e,s,r,n){let a,d,i=[];switch(e){case 1:a=4,i=s.split(".").map(Number);break;case 2:d=new TextEncoder().encode(s),a=d.length+1;break;case 3:a=16,i=Je(s).split(":").map(c=>[parseInt(c.slice(0,2),16),parseInt(c.slice(2),16)]).flat();break;default:throw new Error(`Unknown address type: ${e}`)}let l=n.replace(/-/g,""),o=new Uint8Array(22+a);o[0]=0;for(let c=0;c<l.length;c+=2)o[1+c/2]=parseInt(l.substr(c,2),16);return o[17]=0,o[18]=t,o[19]=r>>8,o[20]=r&255,o[21]=e,e===2?(o[22]=d.length,o.set(d,23)):o.set(i,22),o}function Je(t){if(t=t.replace(/^\[|\]$/g,""),t.includes("::")){let e=t.split("::"),s=e[0]?e[0].split(":"):[],r=e[1]?e[1].split(":"):[],n=8-s.length-r.length,a=Array(Math.max(0,n)).fill("0");return[...s,...a,...r].map(d=>d.padStart(4,"0")).join(":")}return t.split(":").map(e=>e.padStart(4,"0")).join(":")}async function Xe(t){let e=new TextEncoder().encode(t),s=await crypto.subtle.digest({name:"SHA-224"},e);return Array.from(new Uint8Array(s)).map(r=>r.toString(16).padStart(2,"0")).join("")}function fe(t){if(t.byteLength<60)return!1;let e=new Uint8Array(t);return e[56]===13&&e[57]===10}async function me(t,e){if(t.byteLength<60)return{hasError:!0,message:"Invalid Trojan data: too short"};let s=new Uint8Array(t),r=new DataView(t);if(s[56]!==13||s[57]!==10)return{hasError:!0,message:"Invalid Trojan header: missing CRLF"};let n=new TextDecoder().decode(s.slice(0,56)),a=null;for(let h of e)try{if(await Xe(h)===n){a=h;break}}catch{}if(!a)return{hasError:!0,message:"Invalid Trojan password"};let d=s[58];if(d!==1&&d!==3)return{hasError:!0,message:`Unsupported Trojan command: ${d}`};let i=s[59],l,o,c;switch(i){case 1:if(o=4,c=60,t.byteLength<c+o+2)return{hasError:!0,message:"Invalid Trojan header: IPv4 truncated"};l=Array.from(s.slice(c,c+o)).join(".");break;case 3:if(o=s[60],c=61,t.byteLength<c+o+2)return{hasError:!0,message:"Invalid Trojan header: domain truncated"};l=new TextDecoder().decode(s.slice(c,c+o));break;case 4:if(o=16,c=60,t.byteLength<c+o+2)return{hasError:!0,message:"Invalid Trojan header: IPv6 truncated"};l=Array.from({length:8},(h,w)=>r.getUint16(c+w*2).toString(16)).join(":");break;default:return{hasError:!0,message:`Invalid Trojan address type: ${i}`}}let u=c+o;if(t.byteLength<u+2)return{hasError:!0,message:"Invalid Trojan header: port truncated"};let p=r.getUint16(u),m=u+2;return t.byteLength<m+2?{hasError:!0,message:"Invalid Trojan header: missing final CRLF"}:s[m]!==13||s[m+1]!==10?{hasError:!0,message:"Invalid Trojan header: invalid final CRLF"}:{hasError:!1,userPassword:a,addressRemote:l,addressType:i===3?2:i,portRemote:p,rawDataIndex:m+2,isUDP:d===3}}function S(t){try{t&&t.readyState===1&&t.close()}catch{}}var qe=1e4;async function D(t,e,s,r,n,a,d){let i=t.tls?"wss":"ws",l=t.path&&t.path.startsWith("/")?t.path:`/${t.path||""}`,o=t.sni&&t.sni!==""?t.sni:t.address,c=`${i}://${o}:${t.port}${l}`,u;try{u=new WebSocket(c)}catch(b){return d(`[VLESS] create ws failed: ${b.message}`),null}let p,m=new Promise(b=>{p=b});try{await new Promise((b,y)=>{let E=setTimeout(()=>y(new Error("Connection timeout")),qe);u.addEventListener("open",()=>{clearTimeout(E),b()}),u.addEventListener("close",v=>{clearTimeout(E),y(new Error(`closed ${v.code}`))}),u.addEventListener("error",()=>{clearTimeout(E),y(new Error("ws error"))})})}catch(b){d(`[VLESS] connect failed: ${b.message}`);try{u.close()}catch{}return p(),null}u.addEventListener("close",()=>p()),u.addEventListener("error",()=>{});let h=new WritableStream({write(b){u.readyState===1&&u.send(b)},close(){S(u)},abort(){S(u)}}),w=!1,f=new ReadableStream({start(b){u.addEventListener("message",y=>{let E=new Uint8Array(y.data);if(!w&&(w=!0,E.length>=2)){let v=E[1];if(E.length>2+v)E=E.slice(2+v);else return}if(E.length>0)try{b.enqueue(E)}catch{}}),u.addEventListener("close",()=>{try{b.close()}catch{}}),u.addEventListener("error",y=>{try{b.error(y)}catch{}})},cancel(){S(u)}}),g=pe(e,s,r,n,t.uuid),k=a instanceof Uint8Array?a:new Uint8Array(a||0),x=new Uint8Array(g.length+k.length);x.set(g,0),x.set(k,g.length);try{u.send(x)}catch(b){return d(`[VLESS] send header failed: ${b.message}`),S(u),p(),null}return{readable:f,writable:h,closed:m}}async function he(t,e,s,r,n,a){let{username:d,password:i,hostname:l,port:o}=n,c=a({hostname:l,port:o}),u=c.writable.getWriter(),p=c.readable.getReader(),m=new TextEncoder;try{await u.write(new Uint8Array([5,2,0,2]));let h=(await p.read()).value;if(!h||h[0]!==5){r("socks version error");return}if(h[1]===255){r("no acceptable methods");return}if(h[1]===2){if(!d||!i){r("socks server requires auth but no credentials");return}let g=new Uint8Array([1,d.length,...m.encode(d),i.length,...m.encode(i)]);if(await u.write(g),h=(await p.read()).value,!h||h[0]!==1||h[1]!==0){r("socks auth failed");return}}let w;switch(t){case 1:w=new Uint8Array([1,...e.split(".").map(Number)]);break;case 2:w=new Uint8Array([3,e.length,...m.encode(e)]);break;case 3:w=new Uint8Array([4,...e.split(":").flatMap(g=>[parseInt(g.slice(0,2),16),parseInt(g.slice(2),16)])]);break;default:r(`invalid addressType ${t}`);return}let f=new Uint8Array([5,1,0,...w,s>>8,s&255]);if(await u.write(f),h=(await p.read()).value,!h||h[1]!==0){r(`socks connect failed rep=${h?h[1]:"none"}`);return}return u.releaseLock(),p.releaseLock(),c}catch(h){r(`socks5 error: ${h.message}`);try{u.releaseLock()}catch{}try{p.releaseLock()}catch{}try{c.close()}catch{}return}}function be(t,e={}){let[s,r]=t.split("@").reverse(),n,a,d,i;if(r){let o=r.split(":");if(o.length!==2)throw new Error("Invalid SOCKS address format");[n,a]=o}let l=s.split(":");if(i=Number(l.pop()),isNaN(i))throw new Error("Invalid SOCKS address format");return d=l.join(":"),e&&e.username!==void 0&&e.username!==null&&e.username!==""&&(n=e.username),e&&e.password!==void 0&&e.password!==null&&e.password!==""&&(a=e.password),{username:n,password:a,hostname:d,port:i}}async function we(t,e,s,r,n,a,d=new Uint8Array(0)){let{username:i,password:l,hostname:o,port:c}=n,u=a({hostname:o,port:c}),p=u.writable.getWriter(),m=u.readable.getReader();try{let h=i&&l?`Proxy-Authorization: Basic ${btoa(`${i}:${l}`)}\r
`:"",w=`CONNECT ${e}:${s} HTTP/1.1\r
Host: ${e}:${s}\r
${h}User-Agent: Mozilla/5.0\r
Connection: keep-alive\r
\r
`;await p.write(new TextEncoder().encode(w));let f=new Uint8Array(0),g=-1,k=0;for(;g===-1&&k<8192;){let{done:E,value:v}=await m.read();if(E)throw new Error("Connection closed before HTTP response");let L=new Uint8Array(f.length+v.length);L.set(f,0),L.set(v,f.length),f=L,k=f.length;for(let O=0;O<f.length-3;O++)if(f[O]===13&&f[O+1]===10&&f[O+2]===13&&f[O+3]===10){g=O+4;break}}if(g===-1)throw new Error("Invalid HTTP response");let b=new TextDecoder().decode(f.slice(0,g)).split(`\r
`)[0].match(/HTTP\/\d\.\d\s+(\d+)/);if(!b)throw new Error("Invalid HTTP response format");let y=parseInt(b[1]);if(y<200||y>=300)throw new Error(`HTTP CONNECT failed: HTTP ${y}`);return d.length>0&&await p.write(d),p.releaseLock(),m.releaseLock(),u}catch(h){r(`http connect error: ${h.message}`);try{p.releaseLock()}catch{}try{m.releaseLock()}catch{}try{u.close()}catch{}return}}function xe(t,e={}){let[s,r]=t.split("@").reverse(),n,a,d,i;if(r){let o=r.split(":");if(o.length!==2)throw new Error("Invalid HTTP address format");[n,a]=o}let l=s.split(":");if(i=Number(l.pop()),isNaN(i))throw new Error("Invalid HTTP address format");return d=l.join(":"),e&&e.username!==void 0&&e.username!==null&&e.username!==""&&(n=e.username),e&&e.password!==void 0&&e.password!==null&&e.password!==""&&(a=e.password),{username:n,password:a,hostname:d,port:i}}function ge(t,e,s,r,n){let a=t.proxyipHost&&!t.proxyipDisabled,d=a?t.proxyipHost:e,i=a?Number(t.proxyipPort||443):s,l=globalThis.connect?globalThis.connect({hostname:d,port:i}):void 0;if(!l)return n("connect unavailable"),null;if(r&&r.length>0){let o=l.writable.getWriter();o.write(r).then(()=>o.releaseLock()).catch(c=>n(`direct initial write error: ${c.message}`))}return l}async function ye(t){let{config:e,outbound:s,addressType:r,addressRemote:n,portRemote:a,rawClientData:d,log:i,isUDP:l}=t,o=s;if(!o||o===_)return ge(e,n,a,d,i);if(o===A)return i("rejected by routing rule"),null;switch(o.type){case _:return ge(e,n,a,d,i);case J:{let c;try{c=be(o.address,{username:o.username,password:o.password})}catch(p){return i(`bad socks5 address: ${p.message}`),null}let u=await he(r,n,a,i,c,globalThis.connect);if(!u)return null;if(d&&d.length>0){let p=u.writable.getWriter();p.write(d).then(()=>p.releaseLock()).catch(m=>i(`socks5 write error: ${m.message}`))}return u}case X:{let c;try{c=xe(o.address,{username:o.username,password:o.password})}catch(p){return i(`bad http address: ${p.message}`),null}return await we(r,n,a,i,c,globalThis.connect,d||new Uint8Array(0))}case q:return D({address:o.address,port:Number(o.port),uuid:o.uuid,path:o.path,tls:!!o.tls,sni:o.sni||""},l?2:1,r,n,a,d||new Uint8Array(0),i);default:return i(`unknown outbound type: ${o.type}`),null}}function W(t,e){return!e||e===_?_:e===A?A:t.outboundByName[e]||_}var Qe=60*60*1e3,V=new Map;async function z(t,e,s){let r=`${e}:${s}`,n=V.get(r);if(n&&Date.now()-n.ts<Qe)return n.data;let a=null;try{let d=e==="geosite"?Q:Z,i=await t.GEO_KV.get(d+s);if(i){let l=JSON.parse(i);Array.isArray(l)&&(a=l)}}catch{}return a||(a=Ze(e,s)),V.set(r,{data:a,ts:Date.now()}),a}function Ze(t,e){if(t==="geosite")switch(e){case"cn":return te;case"speedtest":return se;case"google":return re;default:return[]}return[]}function ve(){V.clear()}function et(t){if(!t)return null;let e=String(t).trim();if(!e)return null;let s=e.match(/^geosite:(.+)$/i);if(s){let o=s[1].split(",").map(c=>c.trim()).filter(Boolean);return o.length===0?null:{type:"geosite",categories:o}}let r=e.match(/^geoip:(.+)$/i);if(r){let o=r[1].split(",").map(c=>c.trim()).filter(Boolean);return o.length===0?null:{type:"geoip",categories:o}}let n=e.match(/^domain:(.+)$/i);if(n)return{type:"domain",value:n[1].trim()};let a=e.match(/^full:(.+)$/i);if(a)return{type:"full",value:a[1].trim()};let d=e.match(/^keyword:(.+)$/i);if(d)return{type:"keyword",value:d[1].trim()};let i=e.match(/^ip-cidr:(.+)$/i);if(i)return{type:"ip-cidr",value:i[1].trim()};let l=e.match(/^regexp:(.+)$/i);return l?{type:"regexp",value:l[1].trim()}:{type:"domain",value:e}}function ke(t){let e=t.split(".");if(e.length!==4)return null;let s=0;for(let r of e){let n=Number(r);if(isNaN(n)||n<0||n>255)return null;s=s<<8|n}return s>>>0}function Ee(t,e){let[s,r]=e.split("/"),n=r!==void 0?Number(r):32,a=ke(t);if(a===null)return!1;let d=ke(s);if(d===null)return!1;let i=n<=0?0:4294967295<<32-n>>>0;return(a&i)===(d&i)}function Te(t,e){let s=t.toLowerCase(),r=e.toLowerCase();return s===r?!0:s.endsWith("."+r)||s.endsWith(r)}var Se=new Map;function tt(t){let e=Se.get(t);if(!e){try{e=new RegExp(t)}catch{e=null}Se.set(t,e)}return e}async function st(t,e,s,r){switch(t.type){case"domain":return s?!1:Te(e,t.value);case"full":return s?!1:e.toLowerCase()===t.value.toLowerCase();case"keyword":return s?!1:e.toLowerCase().includes(t.value.toLowerCase());case"regexp":{if(s)return!1;let n=tt(t.value);return n?n.test(e):!1}case"ip-cidr":return s?Ee(e,t.value):!1;case"geosite":{if(s)return!1;for(let n of t.categories){let a=await z(r,"geosite",n);for(let d of a)if(Te(e,d))return!0}return!1}case"geoip":{if(!s)return!1;for(let n of t.categories){let a=await z(r,"geoip",n);for(let d of a)if(Ee(e,d))return!0}return!1}default:return!1}}async function _e(t,e,s){let r=e===1||e===3;for(let n of t.routingRules){let a=et(n.rule);if(!a)continue;if(await st(a,s,r,t.env))return{outbound:n.outbound||"direct",rule:n}}return{outbound:t.defaultOutbound||"direct",rule:null}}async function Oe(t,e,s){let r=t.headers.get("Upgrade");if(!r||r.toLowerCase()!=="websocket")return new Response("Expected WebSocket",{status:400});let[n,a]=Object.values(new WebSocketPair);a.accept();let d=(...i)=>console.log("[ws]",...i);return rt(a,e,s,d).catch(i=>{d(`ws handler error: ${i.message||i}`),S(a)}),new Response(null,{status:101,webSocket:n})}async function rt(t,e,s,r){let n;try{n=await at(t,r)}catch(h){r(`read first packet error: ${h.message}`),S(t);return}if(!n){S(t);return}let a,d=null,i="vless";if(fe(n)){if(a=await me(n,e.passwordSet),a.hasError){r(`trojan header error: ${a.message}`),S(t);return}i="trojan",d=e.trojanIndex[a.userPassword]||null}else{if(a=ue(n,e.uuidSet),a.hasError){r(`vless header error: ${a.message}`),S(t);return}d=e.vlessIndex[a.userUuid]||null}let{addressType:l,addressRemote:o,portRemote:c,isUDP:u}=a,p=new Uint8Array(n.slice(a.rawDataIndex)),m;try{m=await _e(e,l,o)}catch(h){r(`route error: ${h.message}`),S(t);return}u?await ot(t,e,l,o,c,p,d,i,m,r):await nt(t,e,l,o,c,p,d,i,m,r)}function at(t,e){return new Promise((s,r)=>{let n=!1,a=()=>{t.removeEventListener("message",d),t.removeEventListener("close",i),t.removeEventListener("error",l)},d=o=>{n||(n=!0,a(),s(o.data))},i=()=>{n||(n=!0,a(),s(null))},l=o=>{n||(n=!0,a(),r(o))};t.addEventListener("message",d),t.addEventListener("close",i),t.addEventListener("error",l),setTimeout(()=>{n||(n=!0,a(),s(null))},15e3)})}async function nt(t,e,s,r,n,a,d,i,l,o){let c=W(e,l.outbound),u=a&&a.length>0?a:new Uint8Array(0),p=[c];c!=="direct"&&c!=="reject"&&p.push("direct");let m=null,h=null;for(let b of p){try{m=await ye({config:e,outbound:b,addressType:s,addressRemote:r,portRemote:n,rawClientData:u,log:o})}catch(y){h=y,m=null}if(m)break}if(!m){o(`tcp connect failed: ${h?h.message:"no outbound available"}`),S(t);return}let w=0,f=0,g=!1,k=m.writable.getWriter(),x=b=>{if(g)return;let y=b.data;if(y){w+=y.byteLength||0;try{k.write(y).catch(()=>{})}catch{}}};t.addEventListener("message",x);try{let b=m.readable.getReader();for(;;){let{done:y,value:E}=await b.read();if(y)break;E&&E.byteLength>0&&(f+=E.byteLength,t.readyState===1&&t.send(E))}}catch(b){o(`tcp remote read error: ${b.message}`)}g=!0,t.removeEventListener("message",x);try{k.releaseLock()}catch{}try{await m.writable.close()}catch{}try{t.close()}catch{}await Le(e,d,i,w,f,o)}async function ot(t,e,s,r,n,a,d,i,l,o){let c=null,u=(e.udpOutbound||"").trim();if(u){let x=e.outboundByName[u];if(x&&x.type==="vless")c=x;else{o(`udp outbound '${u}' not found or not vless (only vless supports udp)`),S(t);return}}else{if(l.outbound&&l.outbound!=="direct"&&l.outbound!=="reject"){let x=W(e,l.outbound);x!=="direct"&&x!=="reject"&&x.type==="vless"&&(c=x)}c||(c=e.outbounds.find(x=>x.type==="vless"))}if(!c){o("udp requires a vless outbound, none configured"),S(t);return}let p=a&&a.length>0?a:new Uint8Array([0,0]),m=await D({address:c.address,port:Number(c.port),uuid:c.uuid,path:c.path,tls:!!c.tls,sni:c.sni||""},2,s,r,n,p,o);if(!m){o("udp vless outbound connect failed"),S(t);return}let h=0,w=0,f=!1,g=m.writable.getWriter(),k=x=>{if(f)return;let b=x.data;if(b){h+=b.byteLength||0;try{g.write(b).catch(()=>{})}catch{}}};t.addEventListener("message",k);try{let x=m.readable.getReader();for(;;){let{done:b,value:y}=await x.read();if(b)break;y&&y.byteLength>0&&(w+=y.byteLength,t.readyState===1&&t.send(y))}}catch(x){o(`udp read error: ${x.message}`)}f=!0,t.removeEventListener("message",k);try{g.releaseLock()}catch{}try{await m.writable.close()}catch{}S(t),await Le(e,d,i,h,w,o)}async function Le(t,e,s,r,n,a){if(!e)return;let d=s==="vless"?"vless_users":"trojan_users";try{await t.env.DB.prepare(`UPDATE ${d} SET up = up + ?, down = down + ? WHERE id = ?`).bind(r,n,e.id).run()}catch(i){a(`record traffic error: ${i.message}`)}}function P(t){let e=t.wsPath.startsWith("/")?t.wsPath:`/${t.wsPath}`,s=t.wsHost||t.host,r=t.sni||(t.tls?s:""),n=new URLSearchParams({encryption:"none",type:"ws",path:e,host:s,security:t.tls?"tls":"none"});t.tls&&r&&n.set("sni",r),t.fp&&n.set("fp",t.fp);let a=encodeURIComponent(t.remark||`${t.host}:${t.port}`);return`vless://${t.uuid}@${t.host}:${t.port}?${n.toString()}#${a}`}function U(t){let e=t.wsPath.startsWith("/")?t.wsPath:`/${t.wsPath}`,s=t.wsHost||t.host,r=t.sni||(t.tls?s:""),n=new URLSearchParams({type:"ws",path:e,host:s,security:t.tls?"tls":"none"});t.tls&&r&&n.set("sni",r);let a=encodeURIComponent(t.remark||`${t.host}:${t.port}`);return`trojan://${encodeURIComponent(t.password)}@${t.host}:${t.port}?${n.toString()}#${a}`}function $e(t){let e=t.headers.get("Host");return e?e.split(":")[0]:"example.com"}function it(t,e){let s=[],r=e.port||(e.tls?443:80);for(let n of t.vlessUsers)s.push(P({uuid:n.uuid,host:e.host,port:r,wsPath:t.wsPath,tls:e.tls,wsHost:e.wsHost,sni:e.sni,remark:`vless-${n.remark||n.uuid.slice(0,8)}`}));for(let n of t.trojanUsers)s.push(U({password:n.password,host:e.host,port:r,wsPath:t.wsPath,tls:e.tls,wsHost:e.wsHost,sni:e.sni,remark:`trojan-${n.remark||n.password.slice(0,8)}`}));return s}function F(t,e){return it(t,e).join(`
`)+`
`}function Ce(t,e){return btoa(F(t,e))}function Pe(t,e){let s=e.port||443,r=e.tls!==!1,n=t.wsPath.startsWith("/")?t.wsPath:`/${t.wsPath}`,a=e.wsHost||e.host,d=e.sni||(r?a:""),i=[],l=t.vlessUsers.map((u,p)=>({name:`vless-${u.remark||p+1}`,type:"vless",server:e.host,port:s,uuid:u.uuid,network:"ws",tls:r,servername:d||void 0,"ws-opts":{path:n,headers:{Host:a}},udp:!0})),o=t.trojanUsers.map((u,p)=>({name:`trojan-${u.remark||p+1}`,type:"trojan",server:e.host,port:s,password:u.password,network:"ws",tls:r,servername:d||void 0,"ws-opts":{path:n,headers:{Host:a}},udp:!0}));i.push(...l,...o);let c=["proxies:"];for(let u of i)c.push(`  - name: "${u.name}"`),c.push(`    type: ${u.type}`),c.push(`    server: ${u.server}`),c.push(`    port: ${u.port}`),u.uuid&&c.push(`    uuid: ${u.uuid}`),u.password&&c.push(`    password: "${u.password}"`),c.push("    network: ws"),c.push(`    tls: ${u.tls}`),u.servername&&c.push(`    servername: ${u.servername}`),c.push("    udp: true"),c.push("    ws-opts:"),c.push(`      path: ${u["ws-opts"].path}`),c.push("      headers:"),c.push(`        Host: ${a}`);return c.push(""),c.push("rules:"),c.push("  - MATCH,DIRECT"),c.join(`
`)}function Ue(t,e){let s=e.port||443,r=t.wsPath.startsWith("/")?t.wsPath:`/${t.wsPath}`,n=e.wsHost||e.host,a=e.sni||(e.tls?n:""),d=[];for(let i of t.vlessUsers)d.push({type:"vless",tag:`vless-${i.remark||i.uuid.slice(0,8)}`,server:e.host,server_port:s,uuid:i.uuid,transport:{type:"ws",path:r,headers:{Host:n}},tls:e.tls?{enabled:!0,server_name:a}:null});for(let i of t.trojanUsers)d.push({type:"trojan",tag:`trojan-${i.remark||i.password.slice(0,8)}`,server:e.host,server_port:s,password:i.password,transport:{type:"ws",path:r,headers:{Host:n}},tls:e.tls?{enabled:!0,server_name:a}:null});return JSON.stringify({outbounds:d,log:{level:"info"}},null,2)}function G(t,e){let s=e.host,r=e.port||(e.tls?443:80),n=t.wsPath.startsWith("/")?t.wsPath:`/${t.wsPath}`,a="",d="";return e.kind==="vless"?(a=P({uuid:e.credential,host:s,port:r,wsPath:n,tls:e.tls,wsHost:e.wsHost,sni:e.sni,remark:"vless-node"}),d="VLESS"):e.kind==="trojan"&&(a=U({password:e.credential,host:s,port:r,wsPath:n,tls:e.tls,wsHost:e.wsHost,sni:e.sni,remark:"trojan-node"}),d="Trojan"),`<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>${d} \u8282\u70B9\u914D\u7F6E</title>
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
  <h1>${d} \u8282\u70B9 <span class="badge">${s}</span></h1>
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
</html>`}function Ae(t){let e=t.disguise_title||"AList",s=t.disguise_subtitle||"\u4E00\u4E2A\u652F\u6301\u591A\u5B58\u50A8\u7684\u6587\u4EF6\u5217\u8868\u7A0B\u5E8F";return`<!DOCTYPE html>
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
<div class="footer">Powered by ${e} \xB7 ${s}</div>
</body>
</html>`}function K(t,e=200){return new Response(t,{status:e,headers:{"Content-Type":"text/html; charset=utf-8","Cache-Control":"no-store"}})}function $(t,e="text/plain; charset=utf-8"){return new Response(t,{headers:{"Content-Type":e,"Cache-Control":"no-store"}})}function dt(t,e,s){let n=(new URL(t.url).searchParams.get("format")||"base64").toLowerCase(),a={host:s.host,port:s.port,tls:s.tls,wsHost:s.wsHost,sni:s.sni};switch(n){case"plain":return $(F(e,a));case"clash":case"yaml":return $(Pe(e,a),"text/yaml; charset=utf-8");case"singbox":case"sing-box":case"json":return $(Ue(e,a),"application/json; charset=utf-8");case"base64":default:return $(Ce(e,a))}}function ct(t,e,s,r){let n=new URL(t.url),a=null;if(e.uuidSet.has(s)?a={kind:"vless",user:e.vlessIndex[s]}:e.passwordSet.has(s)&&(a={kind:"trojan",user:e.trojanIndex[s]}),!a)return new Response("Not Found",{status:404});let d=(n.searchParams.get("format")||"base64").toLowerCase(),i=r.host,l=r.port,o=e.wsPath,c;return a.kind==="vless"?c=P({uuid:a.user.uuid,host:i,port:l,wsPath:e.wsPath,tls:r.tls,wsHost:r.wsHost,sni:r.sni,remark:`vless-${a.user.remark||"node"}`}):c=U({password:a.user.password,host:i,port:l,wsPath:e.wsPath,tls:r.tls,wsHost:r.wsHost,sni:r.sni,remark:`trojan-${a.user.remark||"node"}`}),$(d==="plain"?c+`
`:btoa(c+`
`))}async function De(t,e,s){let r=new URL(t.url),n=r.pathname,a=$e(t),d=r.protocol==="https:",i=Number(r.port)||(d?443:80),l=(e.entryHost||"").trim(),o=l?{host:l,port:Number(e.entryPort)||443,tls:!0,wsHost:(e.entryWsHost||"").trim()||l,sni:(e.entrySni||"").trim()||l}:{host:a,port:i,tls:d,wsHost:a,sni:a};if(n==="/subscribe")return dt(t,e,o);let c=n.match(/^\/([^/]+)\/subscribe$/);if(c)return ct(t,e,decodeURIComponent(c[1]),o);let u=n.match(/^\/([^/]+)$/);if(u){let p=decodeURIComponent(u[1]);if(e.uuidSet.has(p))return K(G(e,{host:o.host,port:o.port,tls:o.tls,wsHost:o.wsHost,sni:o.sni,credential:p,kind:"vless"}));if(e.passwordSet.has(p))return K(G(e,{host:o.host,port:o.port,tls:o.tls,wsHost:o.wsHost,sni:o.sni,credential:p,kind:"trojan"}))}return K(Ae(e.settings))}var Y={"Content-Type":"application/json; charset=utf-8"};function T(t,e=200){return new Response(JSON.stringify(t),{status:e,headers:Y})}async function R(t){try{return await t.json()}catch{return null}}function lt(t){return t.admin_cookie_secret||t.admin_password_hash||"vtd-insecure-secret"}async function Re(t,e){let n=new URL(t.url).pathname.split("/").filter(Boolean),a=n[2]||"",d=n[3]||null,i=t.method,{DB:l,GEO_KV:o}=e.env,c=e.settings,u=lt(c);if(a==="login"&&i==="POST"){let f=await R(t);if(!f||!f.password)return T({error:"password required"},400);if(!await oe(f.password,e.adminPasswordHash))return T({error:"invalid password"},401);let k=await de(u);return new Response(JSON.stringify({ok:!0}),{status:200,headers:{...Y,"Set-Cookie":`${C}=${k}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${7*86400}`}})}let p=le(t.headers.get("Cookie"));if(!await ce(p[C],u))return T({error:"unauthorized"},401);if(a==="logout"&&i==="POST")return new Response(JSON.stringify({ok:!0}),{status:200,headers:{...Y,"Set-Cookie":`${C}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0`}});if(a==="settings"){if(i==="GET"){let{results:f}=await l.prepare("SELECT key, value FROM settings").all();return T((f||[]).reduce((g,k)=>(g[k.key]=k.value,g),{}))}if(i==="PUT"){let f=await R(t);if(!f)return T({error:"bad body"},400);let g=new Set(["ws_path","default_outbound","proxyip","udp_outbound","disguise_title","disguise_subtitle","entry_host","entry_port","entry_sni","entry_ws_host","admin_password_hash","admin_cookie_secret"]);for(let[k,x]of Object.entries(f))typeof x=="string"&&g.has(k)&&await l.prepare("INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at").bind(k,x,Date.now()).run();return T({ok:!0})}return T({error:"method not allowed"},405)}let w={"vless-users":{table:"vless_users",cols:["uuid","remark","enable"]},"trojan-users":{table:"trojan_users",cols:["password","remark","enable"]},outbounds:{table:"outbounds",cols:["type","name","address","port","uuid","path","tls","udp","enable","sort","username","password","sni"],validate(f){return f.type!==void 0&&!["socks5","http","vless"].includes(f.type)?"invalid outbound type":f.port!==void 0&&(!Number.isInteger(Number(f.port))||Number(f.port)<=0||Number(f.port)>65535)?"invalid port":(f.type==="socks5"||f.type==="http")&&!f.address?"address required":f.type==="vless"&&!f.uuid?"vless requires uuid":f.username&&!f.password||!f.username&&f.password?"username and password must be set together":((f.type==="socks5"||f.type==="http")&&(f.udp=0),null)}},"routing-rules":{table:"routing_rules",cols:["rule","outbound","enable","sort"]}}[a];if(w)return ut(i,d,w,l,t);if(a==="stats"&&i==="GET"){let[f,g]=await Promise.all([l.prepare("SELECT remark, uuid, up, down FROM vless_users ORDER BY (up + down) DESC").all(),l.prepare("SELECT remark, password, up, down FROM trojan_users ORDER BY (up + down) DESC").all()]);return T({vless:f.results||[],trojan:g.results||[]})}if(a==="geo"&&n[3]==="update"&&i==="POST")try{let f=await I(l,o);return T({ok:!0,updated:f})}catch(f){return T({error:f.message},500)}return T({error:"not found"},404)}async function ut(t,e,s,r,n){let{table:a,cols:d}=s,i="id";if(t==="GET"){let{results:l}=await r.prepare(`SELECT * FROM ${a} ORDER BY id`).all();return T(l||[])}if(t==="POST"){let l=await R(n);if(!l)return T({error:"bad body"},400);if(s.validate){let m=s.validate(l);if(m)return T({error:m},400)}let o=d.filter(m=>l[m]!==void 0);if(o.length===0)return T({error:"no fields"},400);let c=o.map(()=>"?").join(","),u=o.map(m=>l[m]),{meta:p}=await r.prepare(`INSERT INTO ${a} (${o.join(",")}) VALUES (${c})`).bind(...u).run();return T({ok:!0,id:p.last_row_id})}if(t==="PUT"&&e){let l=await R(n);if(!l)return T({error:"bad body"},400);if(s.validate){let p=s.validate(l);if(p)return T({error:p},400)}let o=d.filter(p=>l[p]!==void 0);if(o.length===0)return T({error:"no fields"},400);let c=o.map(p=>`${p} = ?`).join(","),u=o.map(p=>l[p]);return await r.prepare(`UPDATE ${a} SET ${c} WHERE ${i} = ?`).bind(...u,Number(e)).run(),T({ok:!0})}return t==="DELETE"&&e?(await r.prepare(`DELETE FROM ${a} WHERE ${i} = ?`).bind(Number(e)).run(),T({ok:!0})):T({error:"method not allowed"},405)}async function I(t,e){let{results:s}=await t.prepare("SELECT rule FROM routing_rules").all(),r={geosite:new Set,geoip:new Set};for(let a of s||[]){let d=String(a.rule||"").trim(),i=d.match(/^geosite:(.+)$/i);i&&i[1].split(",").forEach(l=>r.geosite.add(l.trim())),i=d.match(/^geoip:(.+)$/i),i&&i[1].split(",").forEach(l=>r.geoip.add(l.trim()))}let n=0;for(let a of["geosite","geoip"])for(let d of r[a])try{let i=await pt(a,d);i&&i.length>0&&(await e.put(`${a}:${d}`,JSON.stringify(i)),n++)}catch{}return await e.put("geo:version",new Date().toISOString()),ve(),n}async function pt(t,e){let r=`https://raw.githubusercontent.com/${t==="geosite"?"MetaCubeX/sing-geosite":"MetaCubeX/sing-geoip"}/rule-set/${e}.json`,n=await fetch(r,{cf:{cacheTtl:86400}});if(!n.ok)return null;let a=await n.text(),d;try{d=JSON.parse(a)}catch{return null}let i=[],l=o=>{typeof o=="string"&&o&&i.length<2e4&&i.push(o)};for(let o of d.rules||[])if(t==="geosite"){for(let c of o.domain||[])l(c);for(let c of o.domain_suffix||[])l(String(c).replace(/^\.+/,""))}else for(let c of o.ip_cidr||[])l(c);return i}function Ie(t){return`<!DOCTYPE html>
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
    ${t?`<p style="margin:-8px 0 16px;padding:10px 12px;background:#e8f8ef;color:#1d7a3f;border-radius:10px;font-size:13px">\u9996\u6B21\u90E8\u7F72\u521D\u59CB\u5BC6\u7801\uFF1A<b>${t}</b><br>\u767B\u5F55\u540E\u8BF7\u53CA\u65F6\u4FEE\u6539</p>`:""}
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
    return '<tr>'+tds+'<td><button class="btn small" onclick="openEdit('+idx+')">\u7F16\u8F91</button> <button class="btn small danger" onclick="delRow('+idx+')">\u5220\u9664</button></td></tr>';
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

// \u521D\u59CB\uFF1A\u68C0\u67E5\u767B\u5F55\u6001
(async function init(){
  try { await api('/admin/api/settings'); showApp(); }
  catch(e){ showLogin(); }
})();
<\/script>
</body>
</html>`}async function Ne(t,e){let s=new URL(t.url);if(t.method==="POST"||t.method==="GET")try{let{DB:r,GEO_KV:n}=e,a=await I(r,n);return new Response(JSON.stringify({ok:!0,updated:a}),{status:200,headers:{"Content-Type":"application/json; charset=utf-8"}})}catch(r){return new Response(JSON.stringify({ok:!1,error:r.message}),{status:500,headers:{"Content-Type":"application/json; charset=utf-8"}})}return new Response("Not Found",{status:404})}async function He(t,e,s){try{let r=await I(e.DB,e.GEO_KV);console.log(`[cron] geo update done: ${r} categories`)}catch(r){console.log(`[cron] geo update failed: ${r.message}`)}}var hs={async fetch(t,e,s){let n=new URL(t.url).pathname;try{if(n.startsWith("/admin")){let d=await M(t,e,{ensureAdmin:!0});return n.startsWith("/admin/api/")?await Re(t,d):new Response(Ie(d.adminTempPassword),{headers:{"Content-Type":"text/html; charset=utf-8","Cache-Control":"no-store"}})}if(n==="/geo-update-cron")return await Ne(t,e);let a=await M(t,e);return n===a.wsPath?await Oe(t,a,e):await De(t,a,e)}catch(a){return console.log(`[index] error: ${a.message||a}`),new Response(JSON.stringify({error:"internal error"}),{status:500,headers:{"Content-Type":"application/json; charset=utf-8"}})}},async scheduled(t,e,s){return He(t,e,s)}};export{hs as default};
