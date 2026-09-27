import{connect as as}from"cloudflare:sockets";var W="direct",ot="reject",Ft="socks5",Bt="http",Gt="vless",xe=["raw","ws","grpc","httpupgrade","h2"];var Te="geosite:",ke="geoip:",Lt="geo:version",ft="vtd_admin";var Ee=["qq.com","taobao.com","tmall.com","jd.com","baidu.com","bilibili.com","douyin.com","weibo.com","zhihu.com","163.com","126.com","aliyun.com","tencent.com","weixin.qq.com","alipay.com","bankofchina.com","icbc.com.cn","ccb.com","abcchina.com","cmbchina.com","boc.cn","12306.cn","gov.cn","cn","com.cn","net.cn","org.cn"],Se=["speedtest.net","fast.com","ookla.com"],Ae=["google.com","googleapis.com","gstatic.com","googleusercontent.com","ggpht.com","google.cn","google.com.hk","gvt1.com","gvt2.com","gvt3.com"],jt=[];for(let e=0;e<=255;++e){let t=e.toString(16).padStart(2,"0");jt.push(t)}var Wt=1e5;function Vt(e){return Array.from(new Uint8Array(e)).map(t=>t.toString(16).padStart(2,"0")).join("")}function ln(){let e=new Uint8Array(16);return crypto.getRandomValues(e),Vt(e)}async function _e(e,t,r){let n=await crypto.subtle.importKey("raw",new TextEncoder().encode(e),"PBKDF2",!1,["deriveBits"]),a=await crypto.subtle.deriveBits({name:"PBKDF2",salt:new TextEncoder().encode(t),iterations:r,hash:"SHA-256"},n,256);return Vt(a)}async function $e(e){let t=ln(),r=await _e(e,t,Wt);return`${t}:${Wt}:${r}`}async function Le(e,t){if(!t||!e)return!1;let r=String(t).split(":");if(r.length!==3)return!1;let[n,a,s]=r,o=parseInt(a,10)||Wt;return await _e(e,n,o)===s}async function Ue(e,t){let r=await crypto.subtle.importKey("raw",new TextEncoder().encode(e),{name:"HMAC",hash:"SHA-256"},!1,["sign"]),n=await crypto.subtle.sign("HMAC",r,new TextEncoder().encode(t));return Vt(n)}async function Oe(e){let r=`admin.${Math.floor(Date.now()/1e3)+604800}`,n=await Ue(e,r);return`${r}.${n}`}async function De(e,t){if(!e||!t)return!1;let r=String(e).split(".");if(r.length!==3)return!1;let[n,a,s]=r;if(n!=="admin")return!1;let o=Number(a);if(!Number.isFinite(o)||o<Date.now()/1e3)return!1;let l=await Ue(t,`${n}.${a}`);if(l.length!==s.length)return!1;let u=0;for(let i=0;i<l.length;i++)u|=l.charCodeAt(i)^s.charCodeAt(i);return u===0}function Ce(e){let t={};if(!e)return t;for(let r of e.split(";")){let n=r.indexOf("=");if(n<0)continue;let a=r.slice(0,n).trim(),s=r.slice(n+1).trim();t[a]=decodeURIComponent(s)}return t}var Me=3e4,dn=3e4,Re=0,mt={settings:{p:null,ts:0},vlessUsers:{p:null,ts:0},trojanUsers:{p:null,ts:0},outbounds:{p:null,ts:0},routingRules:{p:null,ts:0}},V={p:null,ts:0};function ht(e,t){let r=mt[e],n=Date.now();if(r.p&&n-r.ts<Me)return r.p;let a=Promise.resolve().then(t).catch(()=>null);return r.p=a,r.ts=n,a}function it(e){if(V.p=null,V.ts=0,e==="all"){for(let r of Object.keys(mt))mt[r].p=null,mt[r].ts=0;return}let t=mt[e];t&&(t.p=null,t.ts=0)}async function pn(e){try{let{results:t}=await e.prepare("SELECT key, value FROM settings").all(),r={};for(let n of t||[])r[n.key]=n.value;return r}catch{return{}}}async function fn(e){try{let{results:t}=await e.prepare("SELECT id, uuid, remark, up, down, path, expire_at, traffic_limit, traffic_reset_at FROM vless_users WHERE enable = 1 ORDER BY id").all();return t||[]}catch{try{let{results:r}=await e.prepare("SELECT id, uuid, remark, up, down FROM vless_users WHERE enable = 1 ORDER BY id").all();return(r||[]).map(n=>({path:"",expire_at:0,traffic_limit:0,traffic_reset_at:0,...n}))}catch{return[]}}}async function hn(e){try{let{results:t}=await e.prepare("SELECT id, password, remark, up, down, path, expire_at, traffic_limit, traffic_reset_at FROM trojan_users WHERE enable = 1 ORDER BY id").all();return t||[]}catch{try{let{results:r}=await e.prepare("SELECT id, password, remark, up, down FROM trojan_users WHERE enable = 1 ORDER BY id").all();return(r||[]).map(n=>({path:"",expire_at:0,traffic_limit:0,traffic_reset_at:0,...n}))}catch{return[]}}}function mn(e){let t=String(e||"").trim();if(!t)return"";for(t.startsWith("/")||(t="/"+t);t.length>1&&t.endsWith("/");)t=t.slice(0,-1);return t}async function Pe(e,t,r){let n=Math.floor(Date.now()/1e3);for(let a of t)if(a.traffic_reset_at>0&&a.traffic_reset_at<=n)try{await e.prepare(`UPDATE ${r} SET up = 0, down = 0, traffic_reset_at = 0 WHERE id = ?`).bind(a.id).run(),a.up=0,a.down=0,a.traffic_reset_at=0}catch{}}function gn(e,t,r){let n=new Map,a=(s,o)=>{let l=mn(s);if(!l)return;n.has(l)||n.set(l,[]),n.get(l).push(o);let u=`${l}/Tun`;n.has(u)||n.set(u,[]),n.get(u).push(o)};a(e,{kind:"all"});for(let s of t)s.path&&a(s.path,{kind:"vless",credential:s.uuid.toLowerCase()});for(let s of r)s.path&&a(s.path,{kind:"trojan",credential:s.password});return n}async function yn(e){try{let{results:t}=await e.prepare("SELECT * FROM outbounds WHERE enable = 1 ORDER BY sort ASC, id ASC").all();return t||[]}catch{return[]}}async function bn(e){try{let{results:t}=await e.prepare("SELECT * FROM routing_rules WHERE enable = 1 ORDER BY sort ASC, id ASC").all();return t||[]}catch{return[]}}async function wn(e){try{let n=await e.prepare("SELECT value FROM settings WHERE key = ?").bind("admin_password_hash").first();if(n&&n.value)return{hash:n.value,tempPassword:null}}catch{}let t=Tn().replace(/-/g,"").slice(0,12),r=await $e(t);try{await e.prepare("INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at").bind("admin_password_hash",r,Date.now()).run(),it("settings")}catch{}return{hash:r,tempPassword:t}}function vn(e){let t=[];try{let r=e.entry_list;if(r){let n=JSON.parse(r);Array.isArray(n)&&(t=n)}}catch{t=[]}return!t.length&&(e.entry_host||"").trim()&&(t=[{host:e.entry_host,port:e.entry_port||"",sni:e.entry_sni||"",wsHost:e.entry_ws_host||"",remark:"",transports:[]}]),t.map(r=>{let n=String(r.host||"").trim(),a=String(r.wsHost||"").trim()||n;return{host:n,port:String(r.port||"").trim()||"443",sni:String(r.sni||"").trim()||a,wsHost:a,remark:String(r.remark||"").trim(),transports:Array.isArray(r.transports)?r.transports.filter(s=>["ws","grpc","h2"].includes(s)):["ws","grpc","h2"]}}).filter(r=>r.host)}function xn(e,t,r,n){let a=e.ws_path||"/ws",s=e.entry_transport||"ws",o=e.default_outbound||W,l=e.ip_preference||"ipv4",u=e.proxyip||"",i="",c=443,d="";if(u)if(t.find(k=>k.name===u&&k.type!==W&&k.type!==ot))d=u;else{let k=u.lastIndexOf(":");k>0&&!u.includes("]")&&/^\d+$/.test(u.slice(k+1))?(i=u.slice(0,k),c=Number(u.slice(k+1))||443):i=u}let f=e.udp_outbound||"",p=vn(e),g=p.length?p[0].host:"",m=p.length?p[0].port:"",y=p.length?p[0].sni:"",h=p.length?p[0].wsHost:"",b=gn(a,r,n),w={};for(let v of r)w[v.uuid.toLowerCase()]=v;let x={};for(let v of n)x[v.password]=v;return{wsPath:a,entryTransport:s,defaultOutbound:o,ipPreference:l,adminPasswordHash:e.admin_password_hash||"",proxyipHost:i,proxyipPort:c,proxyipOutbound:d,proxyipDisabled:o!==W,udpOutbound:f,entryHost:g,entryPort:m,entrySni:y,entryWsHost:h,entries:p,vlessIndex:w,trojanIndex:x,uuidSet:new Set(r.map(v=>v.uuid.toLowerCase())),passwordSet:new Set(n.map(v=>v.password)),outboundByName:t.reduce((v,k)=>(v[k.name]=k,v),{}),inboundPathMap:b}}async function Kt(e,t,r={}){let{DB:n}=t,[a,s,o,l,u]=await Promise.all([ht("settings",()=>pn(n)),ht("outbounds",()=>yn(n)),ht("vlessUsers",()=>fn(n)),ht("trojanUsers",()=>hn(n)),ht("routingRules",()=>bn(n))]),i,c=Date.now();if(V.p&&c-V.ts<Me)i=await V.p;else{let g=Promise.resolve().then(()=>xn(a,s,o,l));V.p=g,V.ts=c;try{i=await g}catch(m){throw V.p=null,V.ts=0,m}}let d=i.adminPasswordHash,f=null;if(!d&&r.ensureAdmin){let g=await wn(n);d=g.hash,f=g.tempPassword}let p=Date.now();return p-Re>=dn&&(await Promise.all([Pe(n,o,"vless_users"),Pe(n,l,"trojan_users")]),Re=p),{env:t,settings:a,wsPath:i.wsPath,entryTransport:i.entryTransport,defaultOutbound:i.defaultOutbound,adminPasswordHash:d,adminTempPassword:f,proxyipHost:i.proxyipHost,proxyipPort:i.proxyipPort,proxyipOutbound:i.proxyipOutbound,proxyipDisabled:i.proxyipDisabled,ipPreference:i.ipPreference,udpOutbound:i.udpOutbound,entryHost:i.entryHost,entryPort:i.entryPort,entrySni:i.entrySni,entryWsHost:i.entryWsHost,entries:i.entries,vlessUsers:o,trojanUsers:l,outbounds:s,routingRules:u,vlessIndex:i.vlessIndex,trojanIndex:i.trojanIndex,uuidSet:i.uuidSet,passwordSet:i.passwordSet,outboundByName:i.outboundByName,inboundPathMap:i.inboundPathMap}}function Tn(){return globalThis.crypto&&typeof globalThis.crypto.randomUUID=="function"?globalThis.crypto.randomUUID():"xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(/[xy]/g,e=>{let t=Math.random()*16|0;return(e==="x"?t:t&3|8).toString(16)})}function Ie(e){let t=new Set,r=new Set;for(let n of e){if(n.kind==="all")return{all:!0,vless:t,trojan:r};n.kind==="vless"&&n.credential&&t.add(n.credential),n.kind==="trojan"&&n.credential&&r.add(n.credential)}return{all:!1,vless:t,trojan:r}}var kn=new TextDecoder,Ut=new Map,En=64;function Sn(e){let t=Ut.get(e);if(t)return t;let r=e.replace(/-/g,"");t=new Uint8Array(16);for(let n=0;n<16;n++)t[n]=parseInt(r.substr(n*2,2),16);return Ut.size>=En&&Ut.clear(),Ut.set(e,t),t}function An(e){let t=r=>jt[e[r]];return`${t(0)}${t(1)}${t(2)}${t(3)}-${t(4)}${t(5)}-${t(6)}${t(7)}-${t(8)}${t(9)}-${t(10)}${t(11)}${t(12)}${t(13)}${t(14)}${t(15)}`}function Ne(e,t){if(e.byteLength<24)return{hasError:!0,message:"invalid data"};let r=e instanceof Uint8Array?e:new Uint8Array(e),n=new DataView(r.buffer,r.byteOffset,r.byteLength),a=An(r.subarray(1,17));if(!t.has(a))return{hasError:!0,message:"invalid user"};let o=18+n.getUint8(17);if(e.byteLength<o+4)return{hasError:!0,message:"invalid data"};let l=n.getUint8(o);if(l!==1&&l!==2)return{hasError:!0,message:`command ${l} is not supported`};let u=o+1,i=n.getUint16(u),c=n.getUint8(u+2),d,f,p;switch(c){case 1:f=4,p=u+3,d=`${n.getUint8(p)}.${n.getUint8(p+1)}.${n.getUint8(p+2)}.${n.getUint8(p+3)}`;break;case 2:if(e.byteLength<u+4)return{hasError:!0,message:"invalid data"};f=n.getUint8(u+3),p=u+4,d=kn.decode(r.subarray(p,p+f));break;case 3:f=16,p=u+3,d=`${n.getUint16(p).toString(16)}:${n.getUint16(p+2).toString(16)}:${n.getUint16(p+4).toString(16)}:${n.getUint16(p+6).toString(16)}:${n.getUint16(p+8).toString(16)}:${n.getUint16(p+10).toString(16)}:${n.getUint16(p+12).toString(16)}:${n.getUint16(p+14).toString(16)}`;break;default:return{hasError:!0,message:`invalid addressType: ${c}`}}return d?{hasError:!1,userUuid:a,addressRemote:d,addressType:c,portRemote:i,rawDataIndex:p+f,isUDP:l===2}:{hasError:!0,message:"addressValue is empty"}}function He(e,t,r,n,a){let s,o,l=[];switch(t){case 1:s=4,l=r.split(".").map(Number);break;case 2:o=new TextEncoder().encode(r),s=o.length+1;break;case 3:s=16,l=qt(r).split(":").map(i=>[parseInt(i.slice(0,2),16),parseInt(i.slice(2),16)]).flat();break;default:throw new Error(`Unknown address type: ${t}`)}let u=new Uint8Array(22+s);return u[0]=0,u.set(Sn(a),1),u[17]=0,u[18]=e,u[19]=n>>8,u[20]=n&255,u[21]=t,t===2?(u[22]=o.length,u.set(o,23)):u.set(l,22),u}function qt(e){if(e=e.replace(/^\[|\]$/g,""),e.includes("::")){let t=e.split("::"),r=t[0]?t[0].split(":"):[],n=t[1]?t[1].split(":"):[],a=8-r.length-n.length,s=Array(Math.max(0,a)).fill("0");return[...r,...s,...n].map(o=>o.padStart(4,"0")).join(":")}return e.split(":").map(t=>t.padStart(4,"0")).join(":")}var ze=new TextDecoder;async function _n(e){let t=new TextEncoder().encode(e),r=await crypto.subtle.digest({name:"SHA-224"},t);return Array.from(new Uint8Array(r)).map(n=>n.toString(16).padStart(2,"0")).join("")}var Yt=new Map,Fe=new Map;function $n(e){if(Yt.has(e))return Yt.get(e);let t=_n(e);return Yt.set(e,t),t.then(r=>{r&&Fe.set(r,e)}).catch(()=>{}),t}function Be(e){if(e.byteLength<60)return!1;let t=e instanceof Uint8Array?e:new Uint8Array(e);return t[0]===0?!1:t[56]===13&&t[57]===10}async function Ge(e,t){if(e.byteLength<60)return{hasError:!0,message:"Invalid Trojan data: too short"};let r=e instanceof Uint8Array?e:new Uint8Array(e),n=e instanceof Uint8Array?new DataView(e.buffer,e.byteOffset,e.byteLength):new DataView(e);if(r[56]!==13||r[57]!==10)return{hasError:!0,message:"Invalid Trojan header: missing CRLF"};let a=ze.decode(r.subarray(0,56)),s=null,o=Fe.get(a);if(o!==void 0)s=o;else for(let m of t)try{if(await $n(m)===a){s=m;break}}catch{}if(!s)return{hasError:!0,message:"Invalid Trojan password"};let l=r[58];if(l!==1&&l!==3)return{hasError:!0,message:`Unsupported Trojan command: ${l}`};let u=r[59],i,c,d;switch(u){case 1:if(c=4,d=60,e.byteLength<d+c+2)return{hasError:!0,message:"Invalid Trojan header: IPv4 truncated"};i=`${n.getUint8(d)}.${n.getUint8(d+1)}.${n.getUint8(d+2)}.${n.getUint8(d+3)}`;break;case 3:if(c=r[60],d=61,e.byteLength<d+c+2)return{hasError:!0,message:"Invalid Trojan header: domain truncated"};i=ze.decode(r.subarray(d,d+c));break;case 4:if(c=16,d=60,e.byteLength<d+c+2)return{hasError:!0,message:"Invalid Trojan header: IPv6 truncated"};i=`${n.getUint16(d).toString(16)}:${n.getUint16(d+2).toString(16)}:${n.getUint16(d+4).toString(16)}:${n.getUint16(d+6).toString(16)}:${n.getUint16(d+8).toString(16)}:${n.getUint16(d+10).toString(16)}:${n.getUint16(d+12).toString(16)}:${n.getUint16(d+14).toString(16)}`;break;default:return{hasError:!0,message:`Invalid Trojan address type: ${u}`}}let f=d+c;if(e.byteLength<f+2)return{hasError:!0,message:"Invalid Trojan header: port truncated"};let p=n.getUint16(f),g=f+2;return e.byteLength<g+2?{hasError:!0,message:"Invalid Trojan header: missing final CRLF"}:r[g]!==13||r[g+1]!==10?{hasError:!0,message:"Invalid Trojan header: invalid final CRLF"}:{hasError:!1,userPassword:s,addressRemote:i,addressType:u===3?2:u===4?3:u,portRemote:p,rawDataIndex:g+2,isUDP:l===3}}function je(e){if(!e)return{earlyData:null,error:null};try{let t=e.replace(/-/g,"+").replace(/_/g,"/"),r=atob(t),n=new ArrayBuffer(r.length),a=new Uint8Array(n);for(let s=0;s<r.length;s++)a[s]=r.charCodeAt(s);return{earlyData:n,error:null}}catch(t){return{earlyData:null,error:t}}}function J(e){try{e&&e.readyState===1&&e.close()}catch{}}async function We(e,t){let r=e.sni&&e.sni!==""?e.sni:e.address,n=Number(e.port),a;try{a=globalThis.connect?globalThis.connect({hostname:r,port:n,secureTransport:e.tls?"on":"off"}):void 0}catch(i){return t(`[VLESS/raw] connect error: ${i.message}`),null}if(!a)return t("[VLESS/raw] connect unavailable"),null;let s=a.readable.getReader(),o,l=new Promise(i=>{o=i});return(a.closed||Promise.resolve()).then(o,o),{readable:new ReadableStream({start(i){(async()=>{try{for(;;){let{done:c,value:d}=await s.read();if(c)break;d&&d.byteLength>0&&i.enqueue(d)}try{i.close()}catch{}}catch(c){try{i.error(c)}catch{}}})()},cancel(){try{s.cancel()}catch{}}}),writable:a.writable,closed:l,send:async i=>{let c=a.writable.getWriter();try{await c.write(i)}finally{try{c.releaseLock()}catch{}}}}}function Ln(e,t){let r=new Uint8Array(e.length+t.length);return r.set(e,0),r.set(t,e.length),r}function Un(e){for(let t=0;t+3<e.length;t++)if(e[t]===13&&e[t+1]===10&&e[t+2]===13&&e[t+3]===10)return t;return-1}function On(e){for(let t=0;t+1<e.length;t++)if(e[t]===13&&e[t+1]===10)return new TextDecoder().decode(e.slice(0,t));return""}async function Ve(e,t){let r=e.sni&&e.sni!==""?e.sni:e.address,n=Number(e.port),a;try{a=globalThis.connect?globalThis.connect({hostname:r,port:n,secureTransport:e.tls?"on":"off"}):void 0}catch(g){return t(`[VLESS/httpupgrade] connect error: ${g.message}`),null}if(!a)return t("[VLESS/httpupgrade] connect unavailable"),null;let o=`GET ${e.path&&e.path.startsWith("/")?e.path:`/${e.path||""}`} HTTP/1.1\r
Host: ${r}:${n}\r
Connection: Upgrade\r
Upgrade: websocket\r
\r
`,l=a.readable.getReader(),u,i=new Promise(g=>{u=g});(a.closed||Promise.resolve()).then(u,u);let c=new Uint8Array(0),d=new Uint8Array(0);try{await Promise.race([(async()=>{let g=a.writable.getWriter();try{await g.write(new TextEncoder().encode(o))}finally{try{g.releaseLock()}catch{}}for(;;){let{done:m,value:y}=await l.read();if(m)break;if(y&&y.byteLength>0){c=Ln(c,y);let h=Un(c);if(h>=0){d=c.slice(h+4);return}}}throw new Error("connection closed during handshake")})(),new Promise((g,m)=>setTimeout(()=>m(new Error("Handshake timeout")),1e4))])}catch(g){t(`[VLESS/httpupgrade] handshake failed: ${g.message}`);try{a.close()}catch{}return null}let f=On(c);if(!/^HTTP\/1\.1 101/.test(f)){t(`[VLESS/httpupgrade] upgrade rejected: ${f}`);try{a.close()}catch{}return null}return{readable:new ReadableStream({start(g){d.byteLength>0&&g.enqueue(d),(async()=>{try{for(;;){let{done:m,value:y}=await l.read();if(m)break;y&&y.byteLength>0&&g.enqueue(y)}try{g.close()}catch{}}catch(m){try{g.error(m)}catch{}}})()},cancel(){try{l.cancel()}catch{}}}),writable:a.writable,closed:i,send:async g=>{let m=a.writable.getWriter();try{await m.write(g)}finally{try{m.releaseLock()}catch{}}}}}var Dn=`PRI * HTTP/2.0\r
\r
SM\r
\r
`;var Jt=new TextEncoder;function Cn(e,t){let r=Jt.encode(e),n=Jt.encode(t),a=new Uint8Array(2+r.length+1+n.length);return a[0]=0,a[1]=r.length,a.set(r,2),a[2+r.length]=n.length,a.set(n,3+r.length),a}function Rn(e){let t=new Uint8Array(0);for(let[r,n]of e)t=gt(t,Cn(r,n));return t}function et(e,t,r,n){let a=n.length,s=new Uint8Array(9+a);return s[0]=a>>16&255,s[1]=a>>8&255,s[2]=a&255,s[3]=e,s[4]=t,s[5]=r>>24&127,s[6]=r>>16&255,s[7]=r>>8&255,s[8]=r&255,s.set(n,9),s}function Ke(e){let t=new Uint8Array(5+e.length);return t[0]=0,new DataView(t.buffer,t.byteOffset,5).setUint32(1,e.length,!1),t.set(e,5),t}function qe(e){let t=new Uint8Array(4);return new DataView(t.buffer).setUint32(0,e>>>0,!1),t}function gt(e,t){let r=new Uint8Array(e.length+t.length);return r.set(e,0),r.set(t,e.length),r}async function Ye(e,t){let r=[],n=0;for(;n<t;){let{done:s,value:o}=await e.read();if(s)return null;!o||o.byteLength===0||(r.push(o),n+=o.byteLength)}let a;if(r.length===1)a=r[0];else{a=gt(r[0],r[1]);for(let s=2;s<r.length;s++)a=gt(a,r[s])}return a.byteLength>t?{data:a.slice(0,t),extra:a.slice(t)}:{data:a,extra:null}}async function Je(e,t){let r=e.sni&&e.sni!==""?e.sni:e.address,n=Number(e.port),a;try{a=globalThis.connect?globalThis.connect({hostname:r,port:n,secureTransport:e.tls?"on":"off"}):void 0}catch(m){return t(`[VLESS/grpc] connect error: ${m.message}`),null}if(!a)return t("[VLESS/grpc] connect unavailable"),null;let s=a.writable.getWriter();async function o(m){await s.write(m)}let l,u=new Promise(m=>{l=m});(a.closed||Promise.resolve()).then(l,l);try{await o(Jt.encode(Dn)),await o(et(4,0,0,new Uint8Array(0)));let m=e.tls?"https":"http",y=(e.path||"").replace(/^\/+/,"").replace(/\/+$/,""),h=y?`/${y}/Tun`:"/Tun",b=Rn([[":method","POST"],[":scheme",m],[":path",h],[":authority",`${r}:${n}`],["content-type","application/grpc"],["te","trailers"],["user-agent","grpc-go/1.68.0"]]);await o(et(1,4,1,b))}catch(m){t(`[VLESS/grpc] handshake failed: ${m.message}`);try{a.close()}catch{}return null}let i=a.readable.getReader(),c={needLen:5,buf:new Uint8Array(0),msgLen:0,controller:null,extra:null};function d(m,y){let h=m;for(;h.byteLength>0;)if(c.needLen>0){let b=Math.min(c.needLen,h.byteLength);c.buf=gt(c.buf,h.slice(0,b)),h=h.slice(b),c.needLen-=b,c.needLen===0&&(c.buf.byteLength===5?(c.msgLen=new DataView(c.buf.buffer,c.buf.byteOffset,5).getUint32(1,!1),c.buf=new Uint8Array(0),c.needLen=c.msgLen,c.msgLen===0&&(c.needLen=5)):(c.buf=new Uint8Array(0),c.needLen=5))}else{let b=Math.min(c.msgLen,h.byteLength);if(c.buf=gt(c.buf,h.slice(0,b)),h=h.slice(b),c.msgLen-=b,c.msgLen===0){if(c.buf.byteLength>0)try{y.enqueue(c.buf)}catch{}c.buf=new Uint8Array(0),c.needLen=5}}}let f=new ReadableStream({start(m){c.controller=m,(async()=>{try{for(;;){let y;if(c.extra)y=c.extra,c.extra=null;else{let h=await Ye(i,9);if(!h)break;let b=h.data[0]<<16|h.data[1]<<8|h.data[2],w=h.data[3],x=h.data[4],v=(h.data[5]&127)<<24|h.data[6]<<16|h.data[7]<<8|h.data[8];if(b===0)y=new Uint8Array(0);else{let k=await Ye(i,b);if(!k)break;y=k.data,c.extra=k.extra}if(w===0&&v===1){d(y,m),await o(et(8,0,1,qe(y.byteLength))),await o(et(8,0,0,qe(y.byteLength)));continue}if(w===4){x&1||await o(et(4,1,0,new Uint8Array(0)));continue}if(w===6){x&1||await o(et(6,1,v,y));continue}if(w===7||w===3)break}}try{m.close()}catch{}}catch(y){t(`[VLESS/grpc] read loop error: ${y.message}`);try{m.error(y)}catch{}}finally{try{l()}catch{}}})()},cancel(){try{i.cancel()}catch{}}});function p(m){let y=[],h=0,b=!0;for(;h<m.byteLength;){let w=Math.min(16384,m.byteLength-h);y.push(et(0,0,1,m.slice(h,h+w))),h+=w,b=!1}return y}let g=new WritableStream({write(m){let y=m instanceof Uint8Array?m:new Uint8Array(m),h=Ke(y),b=p(h);return(async()=>{for(let w of b)await o(w)})()},close(){try{a.close()}catch{}},abort(){try{a.close()}catch{}}});return{readable:f,writable:g,closed:u,send:async m=>{let y=Ke(m);for(let h of p(y))await o(h)}}}var Pn=`PRI * HTTP/2.0\r
\r
SM\r
\r
`;var Xt=new TextEncoder;function Mn(e,t){let r=Xt.encode(e),n=Xt.encode(t),a=new Uint8Array(2+r.length+1+n.length);return a[0]=0,a[1]=r.length,a.set(r,2),a[2+r.length]=n.length,a.set(n,3+r.length),a}function In(e){let t=new Uint8Array(0);for(let[r,n]of e)t=Zt(t,Mn(r,n));return t}function rt(e,t,r,n){let a=n.length,s=new Uint8Array(9+a);return s[0]=a>>16&255,s[1]=a>>8&255,s[2]=a&255,s[3]=e,s[4]=t,s[5]=r>>24&127,s[6]=r>>16&255,s[7]=r>>8&255,s[8]=r&255,s.set(n,9),s}function Xe(e){let t=new Uint8Array(4);return new DataView(t.buffer).setUint32(0,e>>>0,!1),t}function Zt(e,t){let r=new Uint8Array(e.length+t.length);return r.set(e,0),r.set(t,e.length),r}async function Ze(e,t){let r=[],n=0;for(;n<t;){let{done:s,value:o}=await e.read();if(s)return null;!o||o.byteLength===0||(r.push(o),n+=o.byteLength)}let a;if(r.length===1)a=r[0];else{a=Zt(r[0],r[1]);for(let s=2;s<r.length;s++)a=Zt(a,r[s])}return a.byteLength>t?{data:a.slice(0,t),extra:a.slice(t)}:{data:a,extra:null}}async function Qe(e,t){let r=e.sni&&e.sni!==""?e.sni:e.address,n=Number(e.port),a;try{a=globalThis.connect?globalThis.connect({hostname:r,port:n,secureTransport:e.tls?"on":"off"}):void 0}catch(p){return t(`[VLESS/h2] connect error: ${p.message}`),null}if(!a)return t("[VLESS/h2] connect unavailable"),null;let s=a.writable.getWriter();async function o(p){await s.write(p)}let l,u=new Promise(p=>{l=p});(a.closed||Promise.resolve()).then(l,l);try{await o(Xt.encode(Pn)),await o(rt(4,0,0,new Uint8Array(0)));let p=e.tls?"https":"http",g=e.path&&e.path.startsWith("/")?e.path:`/${e.path||""}`,m=In([[":method","POST"],[":scheme",p],[":path",g],[":authority",`${r}:${n}`],["content-length","0"],["user-agent","vless-h2/1.0.0"]]);await o(rt(1,4,1,m))}catch(p){t(`[VLESS/h2] handshake failed: ${p.message}`);try{a.close()}catch{}return null}let i=a.readable.getReader(),c=new ReadableStream({start(p){(async()=>{let g=null;try{for(;;){let m;if(g)m=g,g=null;else{let y=await Ze(i,9);if(!y)break;let h=y.data[0]<<16|y.data[1]<<8|y.data[2],b=y.data[3],w=y.data[4],x=(y.data[5]&127)<<24|y.data[6]<<16|y.data[7]<<8|y.data[8];if(h===0)m=new Uint8Array(0);else{let v=await Ze(i,h);if(!v)break;m=v.data,g=v.extra}if(b===0&&x===1){if(m.byteLength>0)try{p.enqueue(m)}catch{}await o(rt(8,0,1,Xe(m.byteLength))),await o(rt(8,0,0,Xe(m.byteLength)));continue}if(b===4){w&1||await o(rt(4,1,0,new Uint8Array(0)));continue}if(b===6){w&1||await o(rt(6,1,x,m));continue}if(b===7||b===3)break}}try{p.close()}catch{}}catch(m){t(`[VLESS/h2] read loop error: ${m.message}`);try{p.error(m)}catch{}}finally{try{l()}catch{}}})()},cancel(){try{i.cancel()}catch{}}});function d(p){let g=[],m=0;for(;m<p.byteLength;){let y=Math.min(16384,p.byteLength-m);g.push(rt(0,0,1,p.slice(m,m+y))),m+=y}return g}let f=new WritableStream({write(p){let g=p instanceof Uint8Array?p:new Uint8Array(p);return(async()=>{for(let m of d(g))await o(m)})()},close(){try{a.close()}catch{}},abort(){try{a.close()}catch{}}});return{readable:c,writable:f,closed:u,send:async p=>{for(let g of d(p))await o(g)}}}var Hn=1e4;async function lt(e,t,r,n,a,s,o){let l=e.transport||"ws";if(!xe.includes(l))return o(`[VLESS] unsupported transport: ${l}`),null;let u=null;try{l==="ws"?u=await zn(e,o):l==="raw"?u=await We(e,o):l==="httpupgrade"?u=await Ve(e,o):l==="grpc"?u=await Je(e,o):l==="h2"&&(u=await Qe(e,o))}catch(f){return o(`[VLESS/${l}] connect failed: ${f.message}`),null}if(!u)return null;let i=He(t,r,n,a,e.uuid),c=s instanceof Uint8Array?s:new Uint8Array(s||0),d=new Uint8Array(i.length+c.length);d.set(i,0),d.set(c,i.length);try{await u.send(d)}catch(f){o(`[VLESS/${l}] send header failed: ${f.message}`);try{u.close&&await u.close()}catch{}return null}return{readable:u.readable,writable:u.writable,closed:u.closed}}async function zn(e,t){let r=e.tls?"wss":"ws",n=e.path&&e.path.startsWith("/")?e.path:`/${e.path||""}`,a=e.sni&&e.sni!==""?e.sni:e.address,s=`${r}://${a}:${e.port}${n}`,o;try{o=new WebSocket(s),"binaryType"in o&&(o.binaryType="arraybuffer")}catch(f){return t(`[VLESS/ws] create ws failed: ${f.message}`),null}let l,u=new Promise(f=>{l=f});try{await new Promise((f,p)=>{let g=setTimeout(()=>p(new Error("Connection timeout")),Hn);o.addEventListener("open",()=>{clearTimeout(g),f()}),o.addEventListener("close",m=>{clearTimeout(g),p(new Error(`closed ${m.code}`))}),o.addEventListener("error",()=>{clearTimeout(g),p(new Error("ws error"))})})}catch(f){t(`[VLESS/ws] connect failed: ${f.message}`);try{o.close()}catch{}return l(),null}o.addEventListener("close",()=>l()),o.addEventListener("error",()=>{});let i=new WritableStream({write(f){o.readyState===1&&o.send(f)},close(){J(o)},abort(){J(o)}}),c=!1;return{readable:new ReadableStream({start(f){o.addEventListener("message",p=>{let g;try{p.data instanceof ArrayBuffer?g=new Uint8Array(p.data):ArrayBuffer.isView(p.data)?g=new Uint8Array(p.data.buffer,p.data.byteOffset,p.data.byteLength):typeof p.data=="string"?g=new TextEncoder().encode(p.data):g=null}catch{g=null}if(g){if(!c&&(c=!0,g.length>=2&&g[0]===0)){let m=g[1];if(g.length>2+m)g=g.slice(2+m);else return}if(g.length>0)try{f.enqueue(g)}catch{}}}),o.addEventListener("close",()=>{try{f.close()}catch{}}),o.addEventListener("error",p=>{try{f.error(p)}catch{}})},cancel(){J(o)}}),writable:i,closed:u,send:async f=>{if(o.readyState!==1)throw new Error(`ws not open (state=${o.readyState})`);o.send(f)}}}async function yt(e,t,r){for(;t.buf.length<r;){let{done:a,value:s}=await e.read();if(a)return null;if(!s||s.byteLength===0)continue;let o=new Uint8Array(t.buf.length+s.byteLength);o.set(t.buf,0),o.set(s,t.buf.length),t.buf=o}let n=t.buf.slice(0,r);return t.buf=t.buf.slice(r),n}async function tr(e,t,r,n,a,s){let{username:o,password:l,hostname:u,port:i}=a,c=s({hostname:u,port:i}),d=c.writable.getWriter(),f=c.readable.getReader(),p=new TextEncoder,g={buf:new Uint8Array(0)};try{await d.write(new Uint8Array([5,2,0,2]));let m=await yt(f,g,2);if(!m||m[0]!==5){n("socks version error");return}if(m[1]===255){n("no acceptable methods");return}if(m[1]===2){if(!o||!l){n("socks server requires auth but no credentials");return}let v=new Uint8Array([1,o.length,...p.encode(o),l.length,...p.encode(l)]);if(await d.write(v),m=await yt(f,g,2),!m||m[0]!==1||m[1]!==0){n("socks auth failed");return}}let y;switch(e){case 1:y=new Uint8Array([1,...t.split(".").map(Number)]);break;case 2:y=new Uint8Array([3,t.length,...p.encode(t)]);break;case 3:y=new Uint8Array([4,...qt(t).split(":").flatMap(v=>[parseInt(v.slice(0,2),16),parseInt(v.slice(2),16)])]);break;default:n(`invalid addressType ${e}`);return}let h=new Uint8Array([5,1,0,...y,r>>8,r&255]);await d.write(h);let b=await yt(f,g,4);if(!b||b[0]!==5){n("socks version error");return}if(b[1]!==0){n(`socks connect failed rep=${b[1]}`);return}let w=0;switch(b[3]){case 1:w=6;break;case 3:w=3;break;case 4:w=18;break;default:n(`socks invalid ATYP ${b[3]}`);return}if(b[3]===3){let v=await yt(f,g,1);if(!v)return;w+=v[0]}if(!await yt(f,g,w))return;if(d.releaseLock(),g.buf.length>0){let v=g.buf.slice();return{readable:new ReadableStream({pull(C){if(v.length>0){let $=v;v=new Uint8Array(0),C.enqueue($);return}return f.read().then(({done:$,value:E})=>{$?C.close():E&&E.byteLength>0&&C.enqueue(E)})},cancel(){try{f.cancel()}catch{}}}),writable:c.writable,closed:c.closed||Promise.resolve()}}return f.releaseLock(),c}catch(m){n(`socks5 error: ${m.message}`);try{d.releaseLock()}catch{}try{f.releaseLock()}catch{}try{c.close()}catch{}return}}function er(e,t={}){let r=String(e||"").trim().replace(/^socks5?:\/\//i,""),[n,a]=r.split("@").reverse(),s,o,l,u;if(a){let c=a.split(":");if(c.length!==2)throw new Error("Invalid SOCKS address format");[s,o]=c}let i=n.split(":");if(u=Number(i[i.length-1]),isNaN(u))if(t&&t.port!==void 0&&t.port!==null&&t.port!=="")u=Number(t.port),l=n;else throw new Error("Invalid SOCKS address format");else l=i.slice(0,-1).join(":");if(isNaN(u)||!l)throw new Error("Invalid SOCKS address format");return t&&t.username!==void 0&&t.username!==null&&t.username!==""&&(s=t.username),t&&t.password!==void 0&&t.password!==null&&t.password!==""&&(o=t.password),{username:s,password:o,hostname:l,port:u}}async function rr(e,t,r,n,a,s,o=new Uint8Array(0)){let{username:l,password:u,hostname:i,port:c}=a,d=s({hostname:i,port:c}),f=d.writable.getWriter(),p=d.readable.getReader();try{let g=l&&u?`Proxy-Authorization: Basic ${btoa(`${l}:${u}`)}\r
`:"",m=`CONNECT ${t}:${r} HTTP/1.1\r
Host: ${t}:${r}\r
${g}User-Agent: Mozilla/5.0\r
Connection: keep-alive\r
\r
`;await f.write(new TextEncoder().encode(m));let y=new Uint8Array(0),h=-1,b=0;for(;h===-1&&b<8192;){let{done:k,value:C}=await p.read();if(k)throw new Error("Connection closed before HTTP response");let $=new Uint8Array(y.length+C.length);$.set(y,0),$.set(C,y.length),y=$,b=y.length;for(let E=0;E<y.length-3;E++)if(y[E]===13&&y[E+1]===10&&y[E+2]===13&&y[E+3]===10){h=E+4;break}}if(h===-1)throw new Error("Invalid HTTP response");let x=new TextDecoder().decode(y.slice(0,h)).split(`\r
`)[0].match(/HTTP\/\d\.\d\s+(\d+)/);if(!x)throw new Error("Invalid HTTP response format");let v=parseInt(x[1]);if(v<200||v>=300)throw new Error(`HTTP CONNECT failed: HTTP ${v}`);return o.length>0&&await f.write(o),f.releaseLock(),p.releaseLock(),d}catch(g){n(`http connect error: ${g.message}`);try{f.releaseLock()}catch{}try{p.releaseLock()}catch{}try{d.close()}catch{}return}}function nr(e,t={}){let[r,n]=String(e||"").trim().split("@").reverse(),a,s,o,l;if(n){let i=n.split(":");if(i.length!==2)throw new Error("Invalid HTTP address format");[a,s]=i}let u=r.split(":");if(l=Number(u[u.length-1]),isNaN(l))if(t&&t.port!==void 0&&t.port!==null&&t.port!=="")l=Number(t.port),o=r;else throw new Error("Invalid HTTP address format");else o=u.slice(0,-1).join(":");if(isNaN(l)||!o)throw new Error("Invalid HTTP address format");return t&&t.username!==void 0&&t.username!==null&&t.username!==""&&(a=t.username),t&&t.password!==void 0&&t.password!==null&&t.password!==""&&(s=t.password),{username:a,password:s,hostname:o,port:l}}var Fn=3e5,ar=new Map,Bn=["https://8.8.8.8/resolve","https://8.8.4.4/resolve","https://doh.pub/resolve","https://dns.alidns.com/resolve"];async function K(e,t,r="A",n=2500){let a=`${r}:${e}`,s=ar.get(a);if(s&&Date.now()-s.ts<Fn)return s.ip;let o=r==="AAAA"?28:1,l=r==="AAAA"?/^[0-9a-fA-F:]+$/:/^\d{1,3}(\.\d{1,3}){3}$/,u=[],i=Bn.map(f=>{let p=new AbortController;u.push(p);let g=setTimeout(()=>p.abort(),n);return(async()=>{try{let m=`${f}?name=${encodeURIComponent(e)}&type=${r}`,y=await fetch(m,{headers:{accept:"application/dns-json"},signal:p.signal});if(y.ok){let h=await y.json(),w=(Array.isArray(h.Answer)?h.Answer:[]).find(x=>x.type===o&&l.test(x.data))?.data;if(w){for(let x of u)x!==p&&x.abort();return w}}}catch{}finally{clearTimeout(g)}return null})()}),d=(await Promise.all(i)).find(f=>f)||null;return d?ar.set(a,{ip:d,ts:Date.now()}):t(`doh resolve failed: ${e} (${r})`),d}var Gn=["173.245.48.0/20","103.21.244.0/22","103.22.200.0/22","103.31.4.0/22","141.101.64.0/18","108.162.192.0/18","190.93.240.0/20","188.114.96.0/20","197.234.240.0/22","198.41.128.0/17","162.158.0.0/15","104.16.0.0/13","104.24.0.0/14","172.64.0.0/13","131.0.72.0/22","1.0.0.0/24","1.1.1.0/24"].map(e=>{let[t,r]=e.split("/"),n=Number(r),a=n===0?0:4294967295<<32-n>>>0,s=t.split(".");return[(+s[0]<<24)+(+s[1]<<16)+(+s[2]<<8)+ +s[3]>>>0&a,a]});function jn(e){let t=e.split(".");return(+t[0]<<24)+(+t[1]<<16)+(+t[2]<<8)+ +t[3]>>>0}function bt(e){if(!/^\d{1,3}(\.\d{1,3}){3}$/.test(e))return!1;let t=jn(e);return Gn.some(([r,n])=>(t&n)===r)}var Wn=[".cloudflare.com",".cloudflare.net",".jsdelivr.net",".workers.dev",".pages.dev",".trycloudflare.com",".cf-ipfs.com",".cloudflareinsights.com"];function te(e){let t=e.toLowerCase();return Wn.some(r=>t===r.slice(1)||t.endsWith(r))}var or=6e4,q={state:"unknown",downAt:0},X=new WeakMap;function nt(e){q.state!=="down"&&(q.state="down",q.downAt=Date.now(),e("proxyip marked down (no response), degrade to direct for 60s"))}function Vn(e){q.state==="down"&&Date.now()-q.downAt>=or&&(q.state="unknown",e("proxyip health reset to unknown, will retry proxyip"))}function ir(){return q.state==="down"&&Date.now()-q.downAt<or}function ee(e){if(!e.proxyipOutbound)return null;let t=Q(e,e.proxyipOutbound);return!t||typeof t=="string"||t.type!==Gt&&t.type!==Ft&&t.type!==Bt?null:t}async function lr(e,t,r,n,a){let s=ee(e);if(!s)return null;let o=/^\d{1,3}(\.\d{1,3}){3}$/.test(t)?1:t.includes(":")?3:2;a(`direct ${t}:${r} -> retry via outbound ${s.name}`);let l=await Z({config:e,outbound:s,addressType:o,addressRemote:t,portRemote:r,rawClientData:n||new Uint8Array(0),log:a,isUDP:!1});return l?(X.set(l,{usedProxyIp:!0}),l):null}async function cr(e,t,r,n,a){if(ee(e)){let c=await lr(e,t,r,n,a);return c||nt(a),c}let o=e.proxyipHost,l=Number(e.proxyipPort||443);if(!o)return null;a(`direct ${t}:${r} -> retry via proxyip ${o}:${l}`);let u=await H(o,l,a);if(!u)return nt(a),null;let i=await re(u,n,a);return i?(X.set(i,{usedProxyIp:!0}),i):(nt(a),null)}async function Qt(e,t,r,n,a,s,o){let l=await Kn(e,t,r,n,a,o);if(!l)return o(`connect unavailable (${t}:${r})`),null;let u=await re(l,s,o);return u&&X.set(u,{usedProxyIp:!1}),u}async function H(e,t,r){let n;try{n=globalThis.connect?globalThis.connect({hostname:e,port:t}):void 0,n&&typeof n.then=="function"&&(n=await n)}catch(a){return r(`direct connect error: ${a.message}`),null}return n||null}async function Kn(e,t,r,n,a,s){if(!n&&!a){let o=e.ipPreference||"ipv4";if(o==="ipv4"){let c=await K(t,s,"A",1200);if(c){s(`direct ${t}:${r} -> ipv4 ${c}:${r}`);let p=await H(c,r,s);if(p)return p}s(`direct ${t}:${r} -> native dns ${t}:${r}`);let d=await H(t,r,s);if(d)return d;let f=await K(t,s,"AAAA");if(f){let p=`[${f}]`;if(s(`direct ${t}:${r} -> doh aaaa fallback ${p}:${r}`),d=await H(p,r,s),d)return d}return null}if(o==="ipv6"){let c=await K(t,s,"AAAA",1200);if(c){let p=`[${c}]`;s(`direct ${t}:${r} -> ipv6 ${p}:${r}`);let g=await H(p,r,s);if(g)return g}s(`direct ${t}:${r} -> native dns ${t}:${r}`);let d=await H(t,r,s);if(d)return d;let f=await K(t,s,"A");return f&&(s(`direct ${t}:${r} -> doh a fallback ${f}:${r}`),d=await H(f,r,s),d)?d:null}s(`direct ${t}:${r} -> native dns ${t}:${r}`);let l=await H(t,r,s);if(l)return l;let u=await K(t,s);if(u&&(s(`direct ${t}:${r} -> doh fallback ${u}:${r}`),l=await H(u,r,s),l))return l;let i=await K(t,s,"AAAA");if(i){let c=`[${i}]`;if(s(`direct ${t}:${r} -> doh aaaa fallback ${c}:${r}`),l=await H(c,r,s),l)return l}return null}return H(t,r,s)}async function re(e,t,r){if(t&&t.length>0){let n=e.writable.getWriter();try{await n.write(t)}catch(a){r(`direct initial write error: ${a.message}`)}finally{try{n.releaseLock()}catch{}}}return e}async function sr(e,t,r,n,a){let s=(e.proxyipHost||e.proxyipOutbound)&&!e.proxyipDisabled,o=/^\d{1,3}(\.\d{1,3}){3}$/.test(t)||t.includes(":");Vn(a);let l=s&&q.state==="down",u=!o&&te(t),i=o&&!t.includes(":")&&bt(t),c=!1;if(s&&!l&&!o&&!u){let d=await K(t,a,"A",800);d&&bt(d)&&(c=!0)}if(s&&!l&&(u||i||c)){let d=ee(e);if(d){let y=await lr(e,t,r,n,a);return y||(nt(a),a(`proxyip outbound ${d.name} failed; degrade to direct ${t}:${r}`),Qt(e,t,r,o,u||c,n,a))}let f=e.proxyipHost,p=Number(e.proxyipPort||443),g=await H(f,p,a);if(!g)return nt(a),a(`proxyip ${f}:${p} connect failed; degrade to direct ${t}:${r}`),Qt(e,t,r,o,u||c,n,a);let m=await re(g,n,a);return m&&X.set(m,{usedProxyIp:!0}),m}return Qt(e,t,r,o,u||c,n,a)}async function Z(e){let{config:t,outbound:r,addressType:n,addressRemote:a,portRemote:s,rawClientData:o,log:l,isUDP:u}=e,i=r;if(!i||i===W)return sr(t,a,s,o,l);if(i===ot)return l("rejected by routing rule"),null;switch(i.type){case W:return sr(t,a,s,o,l);case Ft:{let c;try{c=er(i.address,{username:i.username,password:i.password,port:i.port})}catch(f){return l(`bad socks5 address: ${f.message}`),null}let d=await tr(n,a,s,l,c,globalThis.connect);if(!d)return null;if(o&&o.length>0){let f=d.writable.getWriter();try{await f.write(o)}catch(p){l(`socks5 write error: ${p.message}`)}finally{try{f.releaseLock()}catch{}}}return d}case Bt:{let c;try{c=nr(i.address,{username:i.username,password:i.password,port:i.port})}catch(f){return l(`bad http address: ${f.message}`),null}return await rr(n,a,s,l,c,globalThis.connect,o||new Uint8Array(0))}case Gt:return lt({address:i.address,port:Number(i.port),uuid:i.uuid,path:i.path,tls:!!i.tls,sni:i.sni||"",transport:i.transport},u?2:1,n,a,s,o||new Uint8Array(0),l);default:return l(`unknown outbound type: ${i.type}`),null}}function Q(e,t){return!t||t===W?W:t===ot?ot:e.outboundByName[t]||W}var qn=3600*1e3,ne=new Map;async function ae(e,t,r){let n=`${t}:${r}`,a=ne.get(n);if(a&&Date.now()-a.ts<qn)return a.data;let s=null;try{let o=t==="geosite"?Te:ke,l=await e.GEO_KV.get(o+r);if(l){let u=JSON.parse(l);Array.isArray(u)&&(s=u)}}catch{}return s||(s=Yn(t,r)),ne.set(n,{data:s,ts:Date.now()}),s}function Yn(e,t){if(e==="geosite")switch(t){case"cn":return Ee;case"speedtest":return Se;case"google":return Ae;default:return[]}return[]}function ur(){ne.clear()}function Jn(e){if(!e)return null;let t=String(e).trim();if(!t)return null;let r=t.match(/^geosite:(.+)$/i);if(r){let i=r[1].split(",").map(c=>c.trim()).filter(Boolean);return i.length===0?null:{type:"geosite",categories:i}}let n=t.match(/^geoip:(.+)$/i);if(n){let i=n[1].split(",").map(c=>c.trim()).filter(Boolean);return i.length===0?null:{type:"geoip",categories:i}}let a=t.match(/^domain:(.+)$/i);if(a)return{type:"domain",value:a[1].trim()};let s=t.match(/^full:(.+)$/i);if(s)return{type:"full",value:s[1].trim()};let o=t.match(/^keyword:(.+)$/i);if(o)return{type:"keyword",value:o[1].trim()};let l=t.match(/^ip-cidr:(.+)$/i);if(l)return{type:"ip-cidr",value:l[1].trim()};let u=t.match(/^regexp:(.+)$/i);return u?{type:"regexp",value:u[1].trim()}:{type:"domain",value:t}}function dr(e){let t=e.split(".");if(t.length!==4)return null;let r=0;for(let n of t){let a=Number(n);if(isNaN(a)||a<0||a>255)return null;r=r<<8|a}return r>>>0}function pr(e){let t=String(e).replace(/^\[|\]$/g,""),r=t.indexOf("::"),n,a;if(r>=0?(n=r===0?[]:t.slice(0,r).split(":"),a=r===t.length-2?[]:t.slice(r+2).split(":")):(n=t.split(":"),a=[]),n.length+a.length>8)return null;let s=8-n.length-a.length,o=[...n,...Array(s).fill("0"),...a],l=0n;for(let u of o){if(!u)return null;let i=parseInt(u,16);if(isNaN(i))return null;l=l<<16n|BigInt(i)}return l}function fr(e,t){let r=t.indexOf("/"),n=r>=0?t.slice(0,r):t,a=e.includes(":")?128:32,s=r>=0?Number(t.slice(r+1)):a;if(e.includes(":")){let i=pr(e),c=pr(n);if(i===null||c===null||isNaN(s)||s<0||s>128)return!1;let d=s===0?0n:(1n<<128n)-1n^(1n<<BigInt(128-s))-1n;return(i&d)===(c&d)}let o=dr(e);if(o===null)return!1;let l=dr(n);if(l===null)return!1;let u=s<=0?0:4294967295<<32-s>>>0;return(o&u)===(l&u)}function hr(e,t){let r=e.toLowerCase(),n=t.toLowerCase();return r===n?!0:r.endsWith("."+n)||r.endsWith(n)}var mr=new Map;function Xn(e){let t=mr.get(e);if(!t){try{t=new RegExp(e)}catch{t=null}mr.set(e,t)}return t}async function Zn(e,t,r,n){switch(e.type){case"domain":return r?!1:hr(t,e.value);case"full":return r?!1:t.toLowerCase()===e.value.toLowerCase();case"keyword":return r?!1:t.toLowerCase().includes(e.value.toLowerCase());case"regexp":{if(r)return!1;let a=Xn(e.value);return a?a.test(t):!1}case"ip-cidr":return r?fr(t,e.value):!1;case"geosite":{if(r)return!1;for(let a of e.categories){let s=await ae(n,"geosite",a);for(let o of s)if(hr(t,o))return!0}return!1}case"geoip":{if(!r)return!1;for(let a of e.categories){let s=await ae(n,"geoip",a);for(let o of s)if(fr(t,o))return!0}return!1}default:return!1}}var Qn=6e4,ta=1e4,Dt=new Map;async function wt(e,t,r){let n=`${t}:${r.toLowerCase()}`,a=Dt.get(n);if(a&&Date.now()-a.ts<Qn)return{outbound:a.outbound,rule:a.rule};let s=t===1||t===3,o=e.defaultOutbound||"direct",l=null;for(let u of e.routingRules){let i=Jn(u.rule);if(!i)continue;if(await Zn(i,r,s,e.env)){o=u.outbound||"direct",l=u;break}}return Dt.size>=ta&&Dt.clear(),Dt.set(n,{outbound:o,rule:l,ts:Date.now()}),{outbound:o,rule:l}}var yr=new Uint8Array([0,0]),gr=32*1024,ea=15,ra=2*1024*1024,na=100,aa=300;async function vt(e,t,r,n){let a;try{a=await n.read()}catch(h){r(`read first packet error: ${h.message}`);try{await n.close()}catch{}return}if(!a){try{await n.close()}catch{}return}let s,o=null,l="vless",u=e._inboundScope||null,i=u&&!u.all?u.vless:e.uuidSet,c=u&&!u.all?u.trojan:e.passwordSet;if(Be(a)){if(s=await Ge(a,c),s.hasError){r(`trojan header error: ${s.message}`);try{await n.close()}catch{}return}l="trojan",o=e.trojanIndex[s.userPassword]||null}else{if(s=Ne(a,i),s.hasError){r(`vless header error: ${s.message}`);try{await n.close()}catch{}return}try{await n.write(yr)}catch{}o=e.vlessIndex[s.userUuid]||null}if(o){let h=Math.floor(Date.now()/1e3);if(o.expire_at>0&&o.expire_at<h){r(`${l} user '${o.remark||o.uuid||o.password}' expired`);try{await n.close()}catch{}return}if(o.traffic_limit>0&&Number(o.up)+Number(o.down)>=Number(o.traffic_limit)){r(`${l} user '${o.remark||o.uuid||o.password}' traffic limit reached`);try{await n.close()}catch{}return}}let{addressType:d,addressRemote:f,portRemote:p,isUDP:g}=s,m=(a instanceof Uint8Array?a:new Uint8Array(a)).subarray(s.rawDataIndex),y;try{y=await wt(e,d,f)}catch(h){r(`route error: ${h.message}`);try{await n.close()}catch{}return}g?await oa(n,e,d,f,p,m,o,l,y,r):await sa(n,e,d,f,p,m,o,l,y,r)}async function sa(e,t,r,n,a,s,o,l,u,i){let c=Q(t,u.outbound),d=s&&s.length>0?s:new Uint8Array(0),f=[c];c!=="direct"&&c!=="reject"&&f.push("direct");let p=null,g=null;for(let A of f){try{p=await Z({config:t,outbound:A,addressType:r,addressRemote:n,portRemote:a,rawClientData:d,log:i})}catch(L){g=L,p=null}if(p)break}if(!p){i(`tcp connect failed: ${g?g.message:"no outbound available"}`);try{await e.close()}catch{}return}let m=0,y=0,h=!1,b=Date.now(),w=0,x=15e3,v=Date.now(),k=setInterval(()=>{h||Date.now()-v>=x&&(v=Date.now(),e.write(yr).catch(()=>{}))},5e3),C=5e3,$=X.get(p)||null,E=!1,U=p.writable.getWriter(),O=async()=>{if(E)return null;E=!0;let A=(!!t.proxyipHost||!!t.proxyipOutbound)&&!t.proxyipDisabled;try{await p.close()}catch{}if($&&$.usedProxyIp){nt(i),i(`proxyip ${n}:${a} no first packet, degrade to direct retry`);try{return await Z({config:t,outbound:"direct",addressType:r,addressRemote:n,portRemote:a,rawClientData:d,log:i})||null}catch(L){return i(`direct retry error: ${L.message}`),null}}if(!A||a!==443)return null;i(`direct ${n}:${a} no first packet, retry via proxyip`);try{return await cr(t,n,a,d,i)}catch(L){return i(`proxyip retry error: ${L.message}`),null}},at=(async()=>{try{for(;;){let A=await e.read();if(A==null)break;if(A.byteLength===0)continue;m+=A.byteLength,v=Date.now();let L=Date.now();L-b>na&&(w=L+aa),b=L,await U.write(A)}}catch(A){i(`upstream read error: ${A.message}`)}})();try{let A=p.readable.getReader(),L=!1;for(;;){if(!L&&!E){let M=null,D=A.read().then(j=>({tag:"read",...j})),N=new Promise(j=>{M=setTimeout(()=>j({tag:"timeout"}),C)}),G=await Promise.race([D,N]);if(clearTimeout(M),G.tag==="timeout"){let j=await O();if(!j)break;try{U.releaseLock()}catch{}p=j,U=p.writable.getWriter(),$=X.get(p)||null,A=p.readable.getReader(),L=!1;continue}if(G.done)break;G.value&&G.value.byteLength>0&&(L=!0,y+=G.value.byteLength,v=Date.now(),await e.write(G.value));continue}let R=null,_=0,P=null,$t=()=>{P||(P=setTimeout(()=>{if(P=null,_>0){let M=R.subarray(0,_);R=null,_=0,e.write(M).catch(()=>{})}},ea))},I=async()=>{P&&(clearTimeout(P),P=null),_>0&&(await e.write(R.subarray(0,_)),R=null,_=0)},Ht=M=>{let D=_+M.byteLength;if(!R)R=new Uint8Array(Math.max(D,4096));else if(D>R.length){let N=new Uint8Array(Math.max(R.length*2,D));N.set(R.subarray(0,_),0),R=N}R.set(M,_),_=D},pt=0,st=!1;for(;;){pt>=ra&&(pt=0,await new Promise(N=>setTimeout(N,0)));let{done:M,value:D}=await A.read();if(M){await I(),st=!0;break}if(!(!D||D.byteLength===0)){if(L=!0,y+=D.byteLength,pt+=D.byteLength,v=Date.now(),Date.now()<w){await I(),await e.write(D);continue}_+D.byteLength<=gr?(Ht(D),_>=gr?await I():$t()):(await I(),await e.write(D))}}if(st)break}}catch(A){if(!E&&y===0){i(`tcp remote read error before first packet: ${A.message||A}`);let L=await O();if(L){try{U.releaseLock()}catch{}p=L,U=p.writable.getWriter(),$=X.get(p)||null,E=!0;let R=p.readable.getReader();try{for(;;){let{done:_,value:P}=await R.read();if(_)break;P&&P.byteLength>0&&(y+=P.byteLength,v=Date.now(),await e.write(P))}}catch(_){i(`fallback remote read error: ${_.message||_}`)}}}else i(`tcp remote read error: ${A.message||A}`)}h=!0,clearInterval(k);try{U.releaseLock()}catch{}try{await p.writable.close()}catch{}try{await e.close()}catch{}await at.catch(()=>{}),vr(t,o,l,m,y,i)}async function oa(e,t,r,n,a,s,o,l,u,i){let c=null,d=(t.udpOutbound||"").trim();if(d){let b=t.outboundByName[d];if(b&&b.type==="vless")c=b;else{i(`udp outbound '${d}' not found or not vless (only vless supports udp)`);try{await e.close()}catch{}return}}else{if(u.outbound&&u.outbound!=="direct"&&u.outbound!=="reject"){let b=Q(t,u.outbound);b!=="direct"&&b!=="reject"&&b.type==="vless"&&(c=b)}c||(c=t.outbounds.find(b=>b.type==="vless"))}if(!c){i("udp requires a vless outbound, none configured");try{await e.close()}catch{}return}let f=s&&s.length>0?s:new Uint8Array([0,0]),p=await lt({address:c.address,port:Number(c.port),uuid:c.uuid,path:c.path,tls:!!c.tls,sni:c.sni||"",transport:c.transport||"ws"},2,r,n,a,f,i);if(!p){i("udp vless outbound connect failed");try{await e.close()}catch{}return}let g=0,m=0,y=p.writable.getWriter(),h=(async()=>{try{for(;;){let b=await e.read();if(b==null)break;b.byteLength!==0&&(g+=b.byteLength,await y.write(b))}}catch(b){i(`udp upstream read error: ${b.message}`)}})();try{let b=p.readable.getReader();for(;;){let{done:w,value:x}=await b.read();if(w)break;x&&x.byteLength>0&&(m+=x.byteLength,await e.write(x))}}catch(b){i(`udp read error: ${b.message}`)}try{y.releaseLock()}catch{}try{await p.writable.close()}catch{}try{await e.close()}catch{}await h.catch(()=>{}),vr(t,o,l,g,m,i)}var ia=2e3,la=32,tt=new Map,se=null;async function br(e){if(!tt.size)return;let t=[...tt.entries()];tt.clear();try{let r=t.map(([n,a])=>{let s=n.lastIndexOf(":"),o=n.slice(0,s),l=Number(n.slice(s+1));return e.prepare(`UPDATE ${o} SET up = up + ?, down = down + ? WHERE id = ?`).bind(a.up,a.down,l)});await e.batch(r)}catch{for(let[n,a]of t){let s=tt.get(n);s?(s.up+=a.up,s.down+=a.down):tt.set(n,a)}wr(e)}}function wr(e){se||(se=setTimeout(()=>{se=null,br(e)},ia))}async function vr(e,t,r,n,a,s){if(!t)return;let l=`${r==="vless"?"vless_users":"trojan_users"}:${t.id}`,u=tt.get(l);if(u?(u.up+=n,u.down+=a):tt.set(l,{up:n,down:a}),wr(e.env.DB),tt.size>=la)try{await br(e.env.DB)}catch(i){s(`record traffic error: ${i.message}`)}}var ca=Promise.resolve();function ua(e){return e instanceof ArrayBuffer?new Uint8Array(e):ArrayBuffer.isView(e)?new Uint8Array(e.buffer,e.byteOffset,e.byteLength):typeof e=="string"?new TextEncoder().encode(e):Object.prototype.toString.call(e)==="[object ArrayBuffer]"?new Uint8Array(e):null}function da(e,t){let r=null,n=e.url.indexOf("?");if(n>=0){let o=e.url.slice(n+1).match(/(?:^|&)ed=([^&#]*)/);if(o)try{r=decodeURIComponent(o[1])}catch{r=o[1]}}let a=r==="2560",s=e.headers.get("sec-websocket-protocol")||"";if(s){s.startsWith("base64,")&&(s=s.slice(7));let{earlyData:o,error:l}=je(s);if(l)return t(`early data decode error: ${l.message||l}`),null;if(o&&o.byteLength>0)return a||t(`early data injected: ${o.byteLength} B (ed=${r||"n/a"})`),new Uint8Array(o)}return r&&!a&&t(`ed=${r} declared but no sec-websocket-protocol payload`),null}async function xr(e,t,r){let n=e.headers.get("Upgrade");if(!n||n.toLowerCase()!=="websocket")return new Response("Expected WebSocket",{status:400});let[a,s]=Object.values(new WebSocketPair);s.accept(),s.binaryType="arraybuffer";let o=(...u)=>console.log("[ws]",...u),l=da(e,o);return vt(t,r,o,pa(s,o,l)).catch(u=>{o(`ws handler error: ${u.message||u}`),J(s)}),new Response(null,{status:101,webSocket:a})}function pa(e,t,r=null){let n=[],a=[],s=!1;r&&r.byteLength>0?n.push(r):setTimeout(()=>{!s&&n.length===0&&a.length>0&&(t("first packet timeout: no ws message within 6s"),J(e))},6e3);let o=async i=>{let c=i.data;typeof Blob<"u"&&c instanceof Blob&&(c=await c.arrayBuffer());let d=ua(c);if(!d||d.byteLength===0){t(`message dropped: type=${Object.prototype.toString.call(i.data)} len=${c&&c.byteLength!=null?c.byteLength:c&&c.length!=null?c.length:"n/a"}`);return}let f=a.shift();f?f(d):n.push(d)},l=()=>{if(!s)for(s=!0;a.length;)a.shift()(null)},u=()=>l();return e.addEventListener("message",o),e.addEventListener("close",l),e.addEventListener("error",u),{read(){return n.length?Promise.resolve(n.shift()):s?Promise.resolve(null):new Promise(i=>a.push(i))},write(i){if(e.readyState===1)try{e.send(i)}catch{}return ca},close(){J(e)}}}function oe(e,t){let r=new Uint8Array(e.length+t.length);return r.set(e,0),r.set(t,e.length),r}function fa(e){let t=new Uint8Array(5);return t[0]=0,t[1]=e>>>24&255,t[2]=e>>>16&255,t[3]=e>>>8&255,t[4]=e&255,t}function ha(e){return oe(fa(e.byteLength),e)}async function Tr(e,t,r){let n=(...i)=>console.log("[h2-in]",...i);if(!e.body)return new Response("Bad Request",{status:400});let a=e.body.getReader(),{readable:s,writable:o}=new TransformStream,l=o.getWriter();return vt(t,r,n,{read:async()=>{let i=new Uint8Array(0);for(;;){let{done:c,value:d}=await a.read();if(c)return i.byteLength>0?i:null;if(i=oe(i,d instanceof Uint8Array?d:new Uint8Array(d)),i.byteLength>=60)return i}},write:i=>l.write(i),close:async()=>{try{await a.cancel()}catch{}try{await l.close()}catch{}}}).catch(i=>{n(`h2 handler error: ${i.message||i}`),a.cancel().catch(()=>{}),l.close().catch(()=>{})}),new Response(s,{status:200,headers:{"Content-Type":"application/octet-stream","Cache-Control":"no-store"}})}async function kr(e,t,r){let n=(...c)=>console.log("[grpc-in]",...c);if(!e.body)return new Response("Bad Request",{status:400});let a=e.body.getReader(),{readable:s,writable:o}=new TransformStream,l=o.getWriter(),u=new Uint8Array(0);return vt(t,r,n,{read:async()=>{for(;;){if(u.byteLength>=5){let f=u[1]<<24|u[2]<<16|u[3]<<8|u[4];if(u.byteLength>=5+f){let p=u.slice(5,5+f);return u=u.slice(5+f),p}}let{done:c,value:d}=await a.read();if(c){if(u.byteLength===0)return null;let f=u;return u=new Uint8Array(0),f}u=oe(u,d instanceof Uint8Array?d:new Uint8Array(d))}},write:c=>l.write(ha(c instanceof Uint8Array?c:new Uint8Array(c))),close:async()=>{try{await a.cancel()}catch{}try{await l.close()}catch{}}}).catch(c=>{n(`grpc handler error: ${c.message||c}`),a.cancel().catch(()=>{}),l.close().catch(()=>{})}),new Response(s,{status:200,headers:{"Content-Type":"application/grpc","Cache-Control":"no-store"}})}var Er="ed=2560",xt="random";function Ct(e){let t=e.startsWith("/")?e:`/${e}`;return/\?/.test(t)?`${t}&${Er}`:`${t}?${Er}`}function Rt(e){return(e.startsWith("/")?e:`/${e}`).replace(/\/+$/,"").replace(/^\//,"")}function Tt(e){let t=e.transport||"ws",r=e.wsHost||e.host,n=e.sni||(e.tls?r:""),a=new URLSearchParams({encryption:"none",type:t,host:r,security:e.tls?"tls":"none",tfo:"1"});t==="grpc"?a.set("serviceName",`/${Rt(e.wsPath)}`):t==="h2"?a.set("path",e.wsPath.startsWith("/")?e.wsPath:`/${e.wsPath}`):a.set("path",Ct(e.wsPath)),e.tls&&n&&a.set("sni",n),e.tls&&a.set("fp",e.fp||xt);let s=encodeURIComponent(e.remark||`${e.host}:${e.port}`);return`vless://${e.uuid}@${e.host}:${e.port}?${a.toString()}#${s}`}function kt(e){let t=e.transport||"ws",r=e.wsHost||e.host,n=e.sni||(e.tls?r:""),a=new URLSearchParams({type:t,host:r,security:e.tls?"tls":"none",tfo:"1"});t==="grpc"?a.set("serviceName",`/${Rt(e.wsPath)}`):t==="h2"?a.set("path",e.wsPath.startsWith("/")?e.wsPath:`/${e.wsPath}`):a.set("path",Ct(e.wsPath)),e.tls&&n&&a.set("sni",n),e.tls&&a.set("fp",e.fp||xt);let s=encodeURIComponent(e.remark||`${e.host}:${e.port}`);return`trojan://${encodeURIComponent(e.password)}@${e.host}:${e.port}?${a.toString()}#${s}`}function Sr(e){let t=e.headers.get("Host");return t?t.split(":")[0]:"example.com"}var Et=["ws","grpc","h2"];function ma(e,t){let r=[],n=t.port||(t.tls?443:80),a=t.transports&&t.transports.length?t.transports:Et;for(let s of e.vlessUsers){let o=s.path||e.wsPath;for(let l of a)r.push(Tt({uuid:s.uuid,host:t.host,port:n,wsPath:o,tls:t.tls,wsHost:t.wsHost,sni:t.sni,transport:l,remark:`vless-${s.remark||s.uuid.slice(0,8)}-${l}`}))}for(let s of e.trojanUsers){let o=s.path||e.wsPath;for(let l of a)r.push(kt({password:s.password,host:t.host,port:n,wsPath:o,tls:t.tls,wsHost:t.wsHost,sni:t.sni,transport:l,remark:`trojan-${s.remark||s.password.slice(0,8)}-${l}`}))}return r}function ie(e,t){return t.flatMap(n=>ma(e,n)).join(`
`)+`
`}function Ar(e,t){return btoa(ie(e,t))}function _r(e,t){let r=[],n=t.length>1;for(let s of t){let o=s.port||443,l=s.tls!==!1,u=s.wsHost||s.host,i=s.sni||(l?u:""),c=s.transports&&s.transports.length?s.transports:Et,d=n?(s.name||s.host)+"-":"",f=(p,g,m,y,h,b)=>{let w={name:d+p,type:g,server:s.host,port:o,[m]:y,network:b,tls:l,servername:i||void 0,"client-fingerprint":l?xt:void 0,tfo:!0,udp:!0,_wsHost:u};return b==="grpc"?w["grpc-opts"]={"grpc-service-name":`/${Rt(h)}`}:b==="h2"?w["h2-opts"]={path:h.startsWith("/")?h:`/${h}`,host:[u]}:w["ws-opts"]={path:Ct(h),headers:{Host:u}},w};e.vlessUsers.forEach((p,g)=>{for(let m of c)r.push(f(`vless-${p.remark||g+1}-${m}`,"vless","uuid",p.uuid,p.path||e.wsPath,m))}),e.trojanUsers.forEach((p,g)=>{for(let m of c)r.push(f(`trojan-${p.remark||g+1}-${m}`,"trojan","password",p.password,p.path||e.wsPath,m))})}let a=["proxies:"];for(let s of r)a.push(`  - name: "${s.name}"`),a.push(`    type: ${s.type}`),a.push(`    server: ${s.server}`),a.push(`    port: ${s.port}`),s.uuid&&a.push(`    uuid: ${s.uuid}`),s.password&&a.push(`    password: "${s.password}"`),a.push(`    network: ${s.network}`),a.push(`    tls: ${s.tls}`),s.servername&&a.push(`    servername: ${s.servername}`),s["client-fingerprint"]&&a.push(`    client-fingerprint: ${s["client-fingerprint"]}`),a.push("    tfo: true"),a.push("    udp: true"),s.network==="grpc"?(a.push("    grpc-opts:"),a.push(`      grpc-service-name: ${s["grpc-opts"]["grpc-service-name"]}`)):s.network==="h2"?(a.push("    h2-opts:"),a.push(`      path: ${s["h2-opts"].path}`),a.push("      host:"),a.push(`        - ${s._wsHost}`)):(a.push("    ws-opts:"),a.push(`      path: ${s["ws-opts"].path}`),a.push("      headers:"),a.push(`        Host: ${s._wsHost}`));return a.push(""),a.push("rules:"),a.push("  - MATCH,DIRECT"),a.join(`
`)}function $r(e,t){let r=[],n=t.length>1,a=(s,o,l)=>o==="grpc"?{type:"grpc",service_name:`/${Rt(s)}`}:o==="h2"?{type:"http",host:[l],path:s.startsWith("/")?s:`/${s}`}:{type:"ws",path:Ct(s),headers:{Host:l}};for(let s of t){let o=s.port||443,l=s.wsHost||s.host,u=s.sni||(s.tls?l:""),i=s.transports&&s.transports.length?s.transports:Et,c=n?(s.name||s.host)+"-":"";for(let d of e.vlessUsers)for(let f of i)r.push({type:"vless",tag:c+`vless-${d.remark||d.uuid.slice(0,8)}-${f}`,server:s.host,server_port:o,uuid:d.uuid,transport:a(d.path||e.wsPath,f,l),tcp_fast_open:!0,tls:s.tls?{enabled:!0,server_name:u,fingerprint:xt}:null});for(let d of e.trojanUsers)for(let f of i)r.push({type:"trojan",tag:c+`trojan-${d.remark||d.password.slice(0,8)}-${f}`,server:s.host,server_port:o,password:d.password,transport:a(d.path||e.wsPath,f,l),tcp_fast_open:!0,tls:s.tls?{enabled:!0,server_name:u,fingerprint:xt}:null})}return JSON.stringify({outbounds:r,log:{level:"info"}},null,2)}function le(e,t){let r=t.host,n=t.port||(t.tls?443:80),s=`/${(t.path||e.wsPath||"/ws").replace(/^\//,"")}`,o={host:r,port:n,wsPath:s,tls:t.tls,wsHost:t.wsHost,sni:t.sni},l=(p,g)=>t.kind==="vless"?Tt({...o,uuid:t.credential,transport:p,remark:`vless-${g}`}):kt({...o,password:t.credential,transport:p,remark:`trojan-${g}`}),u=[{key:"ws",name:"WebSocket (ws)",link:l("ws","ws")},{key:"grpc",name:"gRPC",link:l("grpc","grpc")},{key:"h2",name:"HTTP/2 (h2)",link:l("h2","h2")}].filter(p=>(t.transports&&t.transports.length?t.transports:["ws","grpc","h2"]).includes(p.key)),i=t.kind==="vless"?"VLESS":"Trojan",c=u.map(p=>p.key).join(" / "),d=u.map((p,g)=>`
  <div class="row">
    <label>${p.name}</label>
    <div class="linkbox">
      <input type="text" readonly value="${p.link}" id="link${g}">
      <button onclick="copyLink(${g})">\u590D\u5236</button>
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
  <p class="desc">\u5165\u7AD9\u8DEF\u5F84\uFF1A<b>${s}</b>\uFF08\u5F53\u524D\u5165\u53E3\u652F\u6301\uFF1A${c||"\u65E0"}\uFF0C\u590D\u5236\u94FE\u63A5\u5BFC\u5165\u5BA2\u6237\u7AEF\uFF09</p>
  ${d}
</div>
<script>
function copyLink(i){ const el=document.getElementById('link'+i); el.select(); document.execCommand('copy'); el.style.borderColor='#34c759'; setTimeout(()=>el.style.borderColor='#d2d2d7',800); }
<\/script>
</body>
</html>`}function Lr(e){let t=e.disguise_title||"AList",r=e.disguise_subtitle||"\u4E00\u4E2A\u652F\u6301\u591A\u5B58\u50A8\u7684\u6587\u4EF6\u5217\u8868\u7A0B\u5E8F";return`<!DOCTYPE html>
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
</html>`}function ce(e,t=200){return new Response(e,{status:t,headers:{"Content-Type":"text/html; charset=utf-8","Cache-Control":"no-store"}})}function ct(e,t="text/plain; charset=utf-8"){return new Response(e,{headers:{"Content-Type":t,"Cache-Control":"no-store"}})}function ga(e,t,r){switch((new URL(e.url).searchParams.get("format")||"base64").toLowerCase()){case"plain":return ct(ie(t,r));case"clash":case"yaml":return ct(_r(t,r),"text/yaml; charset=utf-8");case"singbox":case"sing-box":case"json":return ct($r(t,r),"application/json; charset=utf-8");default:return ct(Ar(t,r))}}function ya(e,t,r,n){let a=new URL(e.url),s=null;if(t.uuidSet.has(r)?s={kind:"vless",user:t.vlessIndex[r]}:t.passwordSet.has(r)&&(s={kind:"trojan",user:t.trojanIndex[r]}),!s)return new Response("Not Found",{status:404});let o=(a.searchParams.get("format")||"base64").toLowerCase(),l=n.host,u=n.port,i=s.user.path||t.wsPath,c=n.transports&&n.transports.length?n.transports:Et,d=[];for(let p of c)s.kind==="vless"?d.push(Tt({uuid:s.user.uuid,host:l,port:u,wsPath:i,tls:n.tls,wsHost:n.wsHost,sni:n.sni,transport:p,remark:`vless-${s.user.remark||"node"}-${p}`})):d.push(kt({password:s.user.password,host:l,port:u,wsPath:i,tls:n.tls,wsHost:n.wsHost,sni:n.sni,transport:p,remark:`trojan-${s.user.remark||"node"}-${p}`}));let f=d.join(`
`)+`
`;return ct(o==="plain"?f:btoa(f))}async function Ur(e,t,r){let n=new URL(e.url),a=n.pathname,s=Sr(e),o=n.protocol==="https:",l=Number(n.port)||(o?443:80),u=s.toLowerCase().replace(/:\d+$/,""),i=m=>[m.host,m.wsHost].filter(Boolean).map(h=>h.toLowerCase().replace(/:\d+$/,"")).some(h=>h===u),c=t.entries.find(i),d=c?{host:c.host,port:Number(c.port)||443,tls:!0,wsHost:c.wsHost,sni:c.sni,transports:c.transports}:{host:s,port:l,tls:o,wsHost:s,sni:s},f;if(c?f=[{host:c.host,port:Number(c.port)||443,tls:!0,wsHost:c.wsHost,sni:c.sni,transports:c.transports,name:c.remark||c.host}]:t.entries.length?f=t.entries.map(m=>({host:m.host,port:Number(m.port)||443,tls:!0,wsHost:m.wsHost,sni:m.sni,transports:m.transports,name:m.remark||m.host})):f=[{host:s,port:l,tls:o,wsHost:s,sni:s}],a==="/subscribe")return ga(e,t,f);let p=a.match(/^\/([^/]+)\/subscribe$/);if(p)return ya(e,t,decodeURIComponent(p[1]),d);let g=a.match(/^\/([^/]+)$/);if(g){let m=decodeURIComponent(g[1]);if(t.uuidSet.has(m)){let y=t.vlessIndex[m];return ce(le(t,{host:d.host,port:d.port,tls:d.tls,wsHost:d.wsHost,sni:d.sni,transports:d.transports,credential:m,kind:"vless",path:y&&y.path||t.wsPath}))}if(t.passwordSet.has(m)){let y=t.trojanIndex[m];return ce(le(t,{host:d.host,port:d.port,tls:d.tls,wsHost:d.wsHost,sni:d.sni,transports:d.transports,credential:m,kind:"trojan",path:y&&y.path||t.wsPath}))}}return ce(Lr(t.settings))}var Or="1.0.63-20260927-2325";function ba(e){if(e.length<2)return{frame:null,remaining:e,needMore:!0};let t=e[0]<<8|e[1];return t===0?{frame:new Uint8Array(0),remaining:e.slice(2),needMore:!1}:e.length<2+t?{frame:null,remaining:e,needMore:!0}:{frame:e.slice(2,2+t),remaining:e.slice(2+t),needMore:!1}}function Dr(e){let t=new Uint8Array(2+e.length);return t[0]=e.length>>8,t[1]=e.length&255,t.set(e,2),t}async function Cr(e,t,r){let n=e.getReader(),a=new Uint8Array(0);try{for(;;){let{done:s,value:o}=await n.read();if(s)break;if(!o||o.byteLength===0)continue;let l=new Uint8Array(a.length+o.byteLength);for(l.set(a,0),l.set(o,a.length),a=l;;){let{frame:u,remaining:i,needMore:c}=ba(a);if(c){a=i;break}if(a=i,u&&u.length>0)try{await t(u)}catch(d){r(`udp frame handler error: ${d.message}`)}if(a.length<2)break}}}catch(s){r(`readUdpFrames error: ${s.message}`)}finally{try{n.releaseLock()}catch{}}}var Rr=[{name:"\u5B57\u8282\u8DF3\u52A8",host:"www.bytedance.com",port:80,region:"cn",icon:"\u{1F3B5}",color:"#325AB4"},{name:"Bilibili",host:"www.bilibili.com",port:80,region:"cn",icon:"\u{1F4FA}",color:"#FB7299"},{name:"\u5FAE\u4FE1",host:"weixin.qq.com",port:80,region:"cn",icon:"\u{1F4AC}",color:"#07C160"},{name:"\u6DD8\u5B9D",host:"www.taobao.com",port:80,region:"cn",icon:"\u{1F6D2}",color:"#FF5000"},{name:"GitHub",host:"github.com",port:80,region:"intl",icon:"\u{1F419}",color:"#24292F"},{name:"jsDelivr",host:"cdn.jsdelivr.net",port:80,region:"intl",icon:"\u{1F4E6}",color:"#E84D0E"},{name:"Cloudflare",host:"www.cloudflare.com",port:80,region:"intl",icon:"\u2601\uFE0F",color:"#F6821F"},{name:"Google",host:"www.google.com",port:80,region:"intl",icon:"\u{1F50D}",color:"#4285F4"},{name:"YouTube",host:"www.youtube.com",port:80,region:"intl",icon:"\u25B6\uFE0F",color:"#FF0000"}],Pr=16,ue=3e3,Mr=4;var wa=5e3,va=5e3;function Pt(e,t,r="/"){return new TextEncoder().encode(`GET ${r} HTTP/1.1\r
Host: ${e}\r
User-Agent: Mozilla/5.0 (netprobe)\r
Connection: close\r
\r
`)}function xa(e,t){let r=new Uint8Array(e.length+t.length);return r.set(e,0),r.set(t,e.length),r}function Ta(e){for(let t=0;t<e.length-3;t++)if(e[t]===13&&e[t+1]===10&&e[t+2]===13&&e[t+3]===10)return t+4;return-1}function de(e){try{typeof e.close=="function"?e.close():e.writable&&typeof e.writable.close=="function"&&e.writable.close().catch(()=>{})}catch{}}function Mt(e,t){return new Promise(r=>{let n=new Uint8Array(0),a=!1,s=l=>{a||(a=!0,clearTimeout(o),r(l))},o=setTimeout(()=>s(null),t);(async()=>{let l=e.readable.getReader();try{for(;!a;){let{done:u,value:i}=await l.read();if(u)break;if(!(!i||i.byteLength===0)){if(n=xa(n,i),Ta(n)>=0){s(Date.now());break}if(n.length>65536){s(null);break}}}}catch{}s(null);try{l.releaseLock()}catch{}})()})}async function ka(e,t,r,n,a){let s=Date.now(),o;try{let u=await wt(e,2,t),i=Q(e,u.outbound);o=await Z({config:e,outbound:i,addressType:2,addressRemote:t,portRemote:r,rawClientData:n,log:a})}catch{return null}if(!o)return null;let l=await Mt(o,ue);return de(o),l===null?null:l-s}async function Ea(e,t,r){let n=[];for(let i=0;i<Pr;i+=Mr){let c=[],d=Math.min(i+Mr,Pr);for(let p=i;p<d;p++)c.push(ka(e,t.host,t.port,Pt(t.host,t.port),r));let f=await Promise.all(c);for(let p of f)n.push(p)}let a=n.filter(i=>i!==null),s=a.length>0?Math.round(a.reduce((i,c)=>i+c,0)/a.length):null,o=a.length>0?Math.min(...a):null,l=a.length>0?Math.max(...a):null,u=n.length>0?Math.round((n.length-a.length)/n.length*100):100;return{...t,samples:n,latency:s,min:o,max:l,loss:u,success:a.length,total:n.length}}async function Ir(e,t){let r=await Promise.allSettled(Rr.map(n=>Ea(e,n,t)));return{ok:!0,ts:Date.now(),targets:r.map((n,a)=>n.status==="fulfilled"?n.value:{...Rr[a],samples:[],latency:null,success:0,total:0,error:n.reason&&n.reason.message||"error"})}}async function Nr(e,t,r){let n=String(t||"").trim().toLowerCase();if(!n)return{ok:!1,error:"domain required"};let a=2;/^\d{1,3}(\.\d{1,3}){3}$/.test(n)?a=1:n.includes(":")&&(a=3);let s=a!==2,o=await wt(e,a,n),l=!!o.rule,u=l?`\u5206\u6D41\u89C4\u5219 ${o.rule.rule} \u2192 `:"",i=Q(e,o.outbound);if(i==="reject")return{ok:!0,domain:n,route:"reject",name:"reject",reason:l?`${u}reject\uFF08\u62D2\u7EDD\u8FDE\u63A5\uFF09`:"\u9ED8\u8BA4\u51FA\u7AD9 reject\uFF08\u62D2\u7EDD\u8FDE\u63A5\uFF09",rule:l?o.rule.rule:null};if(i==="direct"){let d=o.outbound,f=(!!e.proxyipHost||!!e.proxyipOutbound)&&!e.proxyipDisabled,p=f&&ir(),g=!s&&te(n),m=s&&!n.includes(":")&&bt(n),y=!1;if(f&&!p&&!s&&!g){let h=await K(n,r);h&&bt(h)&&(y=!0)}if(f&&!p&&(g||m||y)){if(e.proxyipOutbound)return{ok:!0,domain:n,route:"proxyip",name:`outbound:${e.proxyipOutbound}`,reason:`${u}Cloudflare \u7AD9\u70B9\uFF08\u5DF2\u77E5 CF \u540E\u7F00/IP \u6BB5\uFF09\u2192 \u4F7F\u7528\u51FA\u7AD9\u4EE3\u7406 ${e.proxyipOutbound} \u51FA\u7AD9`,rule:l?o.rule.rule:null};let h=`${e.proxyipHost}:${Number(e.proxyipPort||443)}`;return{ok:!0,domain:n,route:"proxyip",name:h,reason:`${u}Cloudflare \u7AD9\u70B9\uFF08\u5DF2\u77E5 CF \u540E\u7F00/IP \u6BB5\uFF09\u2192 proxyip ${h}`,rule:l?o.rule.rule:null}}return l?{ok:!0,domain:n,route:"direct",name:"direct",reason:`${u}direct`,rule:o.rule.rule}:d&&d!=="direct"&&d!=="reject"?{ok:!0,domain:n,route:"direct",name:"direct",reason:`\u9ED8\u8BA4\u51FA\u7AD9 ${d} \u4E0D\u5B58\u5728\uFF0C\u56DE\u9000 direct`,rule:null}:{ok:!0,domain:n,route:"direct",name:"direct",reason:"\u9ED8\u8BA4\u51FA\u7AD9 direct",rule:null}}let c=typeof i=="string"?i:i.name;return{ok:!0,domain:n,route:"outbound",name:c,reason:l?`${u}\u51FA\u7AD9 ${c}`:`\u9ED8\u8BA4\u51FA\u7AD9 ${c}`,rule:l?o.rule.rule:null}}async function Hr(e,t){let r="www.cloudflare.com";if(e.proxyipOutbound){let l=Q(e,e.proxyipOutbound);if(!l||typeof l=="string")return{ok:!1,mode:"outbound",error:`\u51FA\u7AD9 ${e.proxyipOutbound} \u4E0D\u5B58\u5728\uFF0C\u8BF7\u68C0\u67E5\u51FA\u7AD9\u914D\u7F6E`};let u=Date.now(),i=null;try{i=await Z({config:e,outbound:l,addressType:2,addressRemote:r,portRemote:443,rawClientData:Pt(r,443),log:t,isUDP:!1})}catch(d){return{ok:!1,mode:"outbound",outbound:e.proxyipOutbound,error:`\u51FA\u7AD9\u8FDE\u63A5\u5931\u8D25: ${d.message}`}}if(!i)return{ok:!1,mode:"outbound",outbound:e.proxyipOutbound,error:"\u51FA\u7AD9\u8FDE\u63A5\u5931\u8D25\u6216\u65E0\u54CD\u5E94"};let c=await Mt(i,ue);return de(i),c===null?{ok:!1,mode:"outbound",outbound:e.proxyipOutbound,error:"\u8FDE\u63A5\u8D85\u65F6\u6216\u65E0\u54CD\u5E94"}:{ok:!0,latency:c-u,mode:"outbound",outbound:e.proxyipOutbound}}if(!e.proxyipHost)return{ok:!1,error:"\u672A\u914D\u7F6E proxyip\uFF0C\u8BF7\u5148\u5728\u7CFB\u7EDF\u8BBE\u7F6E\u4E2D\u586B\u5199"};let a=Date.now(),s=null;try{if(s=globalThis.connect?globalThis.connect({hostname:e.proxyipHost,port:Number(e.proxyipPort||443)}):null,!s)return{ok:!1,error:"connect \u4E0D\u53EF\u7528"};let l=s.writable.getWriter();await l.write(Pt(r,443)),l.releaseLock()}catch(l){try{s&&s.close()}catch{}return{ok:!1,error:`\u8FDE\u63A5\u5931\u8D25: ${l.message}`}}let o=await Mt(s,ue);try{s.close()}catch{}return o===null?{ok:!1,error:"\u8FDE\u63A5\u8D85\u65F6\u6216\u65E0\u54CD\u5E94"}:{ok:!0,latency:o-a,mode:"proxyip",endpoint:`${e.proxyipHost}:${e.proxyipPort||443}`}}function Sa(e){let r=[18,52];r.push(1,0),r.push(0,1),r.push(0,0,0,0,0,0);for(let n of String(e).split(".")){r.push(n.length);for(let a=0;a<n.length;a++)r.push(n.charCodeAt(a))}return r.push(0),r.push(0,1),r.push(0,1),new Uint8Array(r)}async function zr(e,t){let r=null,n=(e.udpOutbound||"").trim();if(n){let i=e.outboundByName[n];if(i&&i.type==="vless")r=i;else return{ok:!1,error:`UDP \u51FA\u7AD9 '${n}' \u4E0D\u5B58\u5728\u6216\u975E vless\uFF08\u4EC5 vless \u652F\u6301 UDP\uFF09`}}else if(r=e.outbounds.find(i=>i.type==="vless"),!r)return{ok:!1,error:"\u672A\u914D\u7F6E vless \u51FA\u7AD9\uFF0C\u65E0\u6CD5\u6D4B\u8BD5 UDP"};let a=Sa("example.com"),s=Dr(a),o=Date.now(),l;try{l=await lt({address:r.address,port:Number(r.port),uuid:r.uuid,path:r.path,tls:!!r.tls,sni:r.sni||"",transport:r.transport},2,1,"8.8.8.8",53,s,t)}catch(i){return{ok:!1,error:`UDP \u51FA\u7AD9\u8FDE\u63A5\u5931\u8D25: ${i.message}`}}if(!l)return{ok:!1,error:"UDP \u51FA\u7AD9\u8FDE\u63A5\u5931\u8D25"};let u=await new Promise(i=>{let c=setTimeout(()=>i({ok:!1,error:"UDP \u54CD\u5E94\u8D85\u65F6"}),wa);Cr(l.readable,d=>{d.length>=12&&d[0]===18&&d[1]===52&&(d[2]&128)!==0&&(clearTimeout(c),i({ok:!0,latency:Date.now()-o,bytes:d.length,outbound:r.name||n||"vless"}))},t)});try{l.writable.close().catch(()=>{})}catch{}return u}async function Fr(e,t,r){let n="www.gstatic.com",s=Date.now(),o;try{o=await Z({config:e,outbound:t,addressType:2,addressRemote:n,portRemote:80,rawClientData:Pt(n,80,"/generate_204"),log:r})}catch(u){return{ok:!1,error:u.message}}if(!o)return{ok:!1,error:"\u96A7\u9053\u5EFA\u7ACB\u5931\u8D25"};let l=await Mt(o,va);return de(o),l===null?{ok:!1,error:"\u8FDE\u63A5\u8D85\u65F6\u6216\u65E0\u54CD\u5E94"}:{ok:!0,latency:l-s}}var z=Uint8Array,ut=Uint16Array,Aa=Int32Array,Br=new z([0,0,0,0,0,0,0,0,1,1,1,1,2,2,2,2,3,3,3,3,4,4,4,4,5,5,5,5,0,0,0,0]),Gr=new z([0,0,0,0,1,1,2,2,3,3,4,4,5,5,6,6,7,7,8,8,9,9,10,10,11,11,12,12,13,13,0,0]),_a=new z([16,17,18,0,8,7,9,6,10,5,11,4,12,3,13,2,14,1,15]),jr=function(e,t){for(var r=new ut(31),n=0;n<31;++n)r[n]=t+=1<<e[n-1];for(var a=new Aa(r[30]),n=1;n<30;++n)for(var s=r[n];s<r[n+1];++s)a[s]=s-r[n]<<5|n;return{b:r,r:a}},Wr=jr(Br,2),Vr=Wr.b,$a=Wr.r;Vr[28]=258,$a[258]=28;var Kr=jr(Gr,0),La=Kr.b,mo=Kr.r,he=new ut(32768);for(S=0;S<32768;++S)Y=(S&43690)>>1|(S&21845)<<1,Y=(Y&52428)>>2|(Y&13107)<<2,Y=(Y&61680)>>4|(Y&3855)<<4,he[S]=((Y&65280)>>8|(Y&255)<<8)>>1;var Y,S,St=(function(e,t,r){for(var n=e.length,a=0,s=new ut(t);a<n;++a)e[a]&&++s[e[a]-1];var o=new ut(t);for(a=1;a<t;++a)o[a]=o[a-1]+s[a-1]<<1;var l;if(r){l=new ut(1<<t);var u=15-t;for(a=0;a<n;++a)if(e[a])for(var i=a<<4|e[a],c=t-e[a],d=o[e[a]-1]++<<c,f=d|(1<<c)-1;d<=f;++d)l[he[d]>>u]=i}else for(l=new ut(n),a=0;a<n;++a)e[a]&&(l[a]=he[o[e[a]-1]++]>>15-e[a]);return l}),At=new z(288);for(S=0;S<144;++S)At[S]=8;var S;for(S=144;S<256;++S)At[S]=9;var S;for(S=256;S<280;++S)At[S]=7;var S;for(S=280;S<288;++S)At[S]=8;var S,qr=new z(32);for(S=0;S<32;++S)qr[S]=5;var S;var Ua=St(At,9,1);var Oa=St(qr,5,1),pe=function(e){for(var t=e[0],r=1;r<e.length;++r)e[r]>t&&(t=e[r]);return t},F=function(e,t,r){var n=t/8|0;return(e[n]|e[n+1]<<8)>>(t&7)&r},fe=function(e,t){var r=t/8|0;return(e[r]|e[r+1]<<8|e[r+2]<<16)>>(t&7)},Da=function(e){return(e+7)/8|0},Ca=function(e,t,r){return(t==null||t<0)&&(t=0),(r==null||r>e.length)&&(r=e.length),new z(e.subarray(t,r))};var Ra=["unexpected EOF","invalid block type","invalid length/literal","invalid distance","stream finished","no stream handler",,"no callback","invalid UTF-8 data","extra field too long","date not in range 1980-2099","filename too long","stream finishing","invalid zip data"],B=function(e,t,r){var n=new Error(t||Ra[e]);if(n.code=e,Error.captureStackTrace&&Error.captureStackTrace(n,B),!r)throw n;return n},Pa=function(e,t,r,n){var a=e.length,s=n?n.length:0;if(!a||t.f&&!t.l)return r||new z(0);var o=!r,l=o||t.i!=2,u=t.i;o&&(r=new z(a*3));var i=function(be){var we=r.length;if(be>we){var ve=new z(Math.max(we*2,be));ve.set(r),r=ve}},c=t.f||0,d=t.p||0,f=t.b||0,p=t.l,g=t.d,m=t.m,y=t.n,h=a*8;do{if(!p){c=F(e,d,1);var b=F(e,d+1,3);if(d+=3,b)if(b==1)p=Ua,g=Oa,m=9,y=5;else if(b==2){var k=F(e,d,31)+257,C=F(e,d+10,15)+4,$=k+F(e,d+5,31)+1;d+=14;for(var E=new z($),U=new z(19),O=0;O<C;++O)U[_a[O]]=F(e,d+O*3,7);d+=C*3;for(var at=pe(U),A=(1<<at)-1,L=St(U,at,1),O=0;O<$;){var R=L[F(e,d,A)];d+=R&15;var w=R>>4;if(w<16)E[O++]=w;else{var _=0,P=0;for(w==16?(P=3+F(e,d,3),d+=2,_=E[O-1]):w==17?(P=3+F(e,d,7),d+=3):w==18&&(P=11+F(e,d,127),d+=7);P--;)E[O++]=_}}var $t=E.subarray(0,k),I=E.subarray(k);m=pe($t),y=pe(I),p=St($t,m,1),g=St(I,y,1)}else B(1);else{var w=Da(d)+4,x=e[w-4]|e[w-3]<<8,v=w+x;if(v>a){u&&B(0);break}l&&i(f+x),r.set(e.subarray(w,v),f),t.b=f+=x,t.p=d=v*8,t.f=c;continue}if(d>h){u&&B(0);break}}l&&i(f+131072);for(var Ht=(1<<m)-1,pt=(1<<y)-1,st=d;;st=d){var _=p[fe(e,d)&Ht],M=_>>4;if(d+=_&15,d>h){u&&B(0);break}if(_||B(2),M<256)r[f++]=M;else if(M==256){st=d,p=null;break}else{var D=M-254;if(M>264){var O=M-257,N=Br[O];D=F(e,d,(1<<N)-1)+Vr[O],d+=N}var G=g[fe(e,d)&pt],j=G>>4;G||B(3),d+=G&15;var I=La[j];if(j>3){var N=Gr[j];I+=fe(e,d)&(1<<N)-1,d+=N}if(d>h){u&&B(0);break}l&&i(f+131072);var zt=f+D;if(f<I){var ye=s-I,sn=Math.min(I,zt);for(ye+f<0&&B(3);f<sn;++f)r[f]=n[ye+f]}for(;f<zt;++f)r[f]=r[f-I]}}t.l=p,t.p=st,t.b=f,t.f=c,p&&(c=1,t.m=m,t.d=g,t.n=y)}while(!c);return f!=r.length&&o?Ca(r,0,f):r.subarray(0,f)};var Ma=new z(0);var Ia=function(e,t){return((e[0]&15)!=8||e[0]>>4>7||(e[0]<<8|e[1])%31)&&B(6,"invalid zlib data"),(e[1]>>5&1)==+!t&&B(6,"invalid zlib data: "+(e[1]&32?"need":"unexpected")+" dictionary"),(e[1]>>3&4)+2};function Yr(e,t){return Pa(e.subarray(Ia(e,t&&t.dictionary),-4),{i:2},t&&t.out,t&&t.dictionary)}var Na=typeof TextDecoder<"u"&&new TextDecoder,Ha=0;try{Na.decode(Ma,{stream:!0}),Ha=1}catch{}var me={"Content-Type":"application/json; charset=utf-8"},za="gcp:asia-east2";function T(e,t=200){return new Response(JSON.stringify(e),{status:t,headers:me})}async function _t(e){try{return await e.json()}catch{return null}}function Fa(e){return e.admin_cookie_secret||e.admin_password_hash||"vtd-insecure-secret"}async function tn(e,t,r){let n=new URL(e.url),s=n.pathname.split("/").filter(Boolean),o=s[2]||"",l=s[3]||null,u=e.method,{DB:i,GEO_KV:c}=t.env,d=t.settings,f=Fa(d);if(o==="login"&&u==="POST"){let h=await _t(e);if(!h||!h.password)return T({error:"password required"},400);if(!await Le(h.password,t.adminPasswordHash))return T({error:"invalid password"},401);let w=await Oe(f);return new Response(JSON.stringify({ok:!0}),{status:200,headers:{...me,"Set-Cookie":`${ft}=${w}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${7*86400}`}})}let p=Ce(e.headers.get("Cookie"));if(!await De(p[ft],f))return T({error:"unauthorized"},401);if(o==="logout"&&u==="POST")return new Response(JSON.stringify({ok:!0}),{status:200,headers:{...me,"Set-Cookie":`${ft}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0`}});if(o==="version"&&u==="GET")return T({ok:!0,version:Or});if(o==="colo"&&u==="GET"){let h=e&&e.cf||{},b=e.headers.get("cf-placement")||"",w=null,x=null;if(b){let v=b.indexOf("-");v>0?(w=b.slice(0,v),x=b.slice(v+1)||null):w=b}return T({ok:!0,placement_header:b||null,placement_mode:w,placement_colo:x,colo:h.colo||null,region:h.region||null,city:h.city||null,country:h.country||null,continent:h.continent||null,timezone:h.timezone||null,host:n.hostname||null,configured_placement_region:za})}if(await ns(i),o==="settings"){if(u==="GET"){let{results:h}=await i.prepare("SELECT key, value FROM settings").all();return T((h||[]).reduce((b,w)=>(b[w.key]=w.value,b),{}))}if(u==="PUT"){let h=await _t(e);if(!h)return T({error:"bad body"},400);let b=new Set(["ws_path","default_outbound","proxyip","udp_outbound","ip_preference","disguise_title","disguise_subtitle","entry_host","entry_port","entry_sni","entry_ws_host","entry_list","admin_password_hash","admin_cookie_secret"]);if(h.ip_preference!==void 0&&!["ipv4","ipv6","auto"].includes(h.ip_preference))return T({error:"ip_preference \u4EC5\u5141\u8BB8 ipv4 / ipv6 / auto"},400);if(h.entry_list!==void 0)try{let w=JSON.parse(h.entry_list);if(!Array.isArray(w)||w.some(x=>!x||!String(x.host||"").trim()))return T({error:"entry_list \u5FC5\u987B\u4E3A\u5165\u53E3\u6570\u7EC4\uFF08\u6BCF\u9879\u9700\u5305\u542B host\uFF09"},400);if(w.some(x=>Array.isArray(x.transports)&&x.transports.some(v=>!["ws","grpc","h2"].includes(v))))return T({error:"entry_list transports \u4EC5\u5141\u8BB8 ws / grpc / h2"},400)}catch{return T({error:"entry_list \u4E0D\u662F\u5408\u6CD5 JSON \u6570\u7EC4"},400)}for(let[w,x]of Object.entries(h))typeof x=="string"&&b.has(w)&&await i.prepare("INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at").bind(w,x,Date.now()).run();return it("settings"),T({ok:!0})}return T({error:"method not allowed"},405)}let y={"vless-users":{table:"vless_users",cacheKey:"vlessUsers",cols:["uuid","remark","enable","path","expire_at","traffic_limit","traffic_reset_at"]},"trojan-users":{table:"trojan_users",cacheKey:"trojanUsers",cols:["password","remark","enable","path","expire_at","traffic_limit","traffic_reset_at"]},outbounds:{table:"outbounds",cacheKey:"outbounds",cols:["type","name","address","port","uuid","path","tls","udp","enable","sort","username","password","sni","transport"],validate(h){if(h.type!==void 0&&!["socks5","http","vless"].includes(h.type))return"invalid outbound type";if(h.port!==void 0&&(!Number.isInteger(Number(h.port))||Number(h.port)<=0||Number(h.port)>65535))return"invalid port";if((h.type==="socks5"||h.type==="http")&&!h.address)return"address required";if(h.type==="vless"){if(!h.uuid)return"vless requires uuid";if(h.transport!==void 0&&!["raw","ws","grpc","httpupgrade","h2"].includes(h.transport))return"invalid vless transport"}return h.username&&!h.password||!h.username&&h.password?"username and password must be set together":((h.type==="socks5"||h.type==="http")&&(h.udp=0),h.type!=="vless"&&(h.transport="ws"),null)}},"routing-rules":{table:"routing_rules",cacheKey:"routingRules",cols:["rule","outbound","enable","sort"]}}[o];if(y)return Ba(u,l,y,i,e);if(o==="stats"&&u==="GET"){let[h,b]=await Promise.all([i.prepare("SELECT remark, uuid, up, down, path, expire_at, traffic_limit, traffic_reset_at FROM vless_users ORDER BY (up + down) DESC").all(),i.prepare("SELECT remark, password, up, down, path, expire_at, traffic_limit, traffic_reset_at FROM trojan_users ORDER BY (up + down) DESC").all()]),w=Math.floor(Date.now()/1e3),x=v=>(v||[]).map(k=>{let C=Number(k.up||0),$=Number(k.down||0),E=Number(k.traffic_limit||0),U=C+$;return{...k,used:U,remaining:E>0?Math.max(0,E-U):null,expired:k.expire_at>0&&k.expire_at<w,limitReached:E>0&&U>=E}});return T({vless:x(h.results),trojan:x(b.results)})}if(o==="geo"&&s[3]==="update"&&u==="POST")try{if(await c.get("geo:updating")==="1")return T({ok:!0,started:!1,updating:!0});if(await c.put("geo:updating","1",{expirationTtl:7200}),t.env&&t.env.GEO_QUEUE&&typeof t.env.GEO_QUEUE.send=="function")return await t.env.GEO_QUEUE.send({kind:"geo-update"}),await c.put("geo:update_status",JSON.stringify({startedAt:Date.now(),state:"updating",step:0,total:0,updated:0,failed:[],current:"",message:"\u5DF2\u5165\u961F\uFF0C\u7B49\u5F85\u6D88\u8D39\u8005\u6267\u884C\u2026"})).catch(()=>{}),T({ok:!0,started:!0,queued:!0,updating:!0});if(r&&typeof r.waitUntil=="function")return r.waitUntil(It(i,c)),T({ok:!0,started:!0,updating:!0});let b=await It(i,c);return T({ok:!0,started:!1,updated:b.updated,total:b.total,failed:b.failed})}catch(h){return await c.put("geo:updating","0").catch(()=>{}),T({error:h.message},500)}if(o==="geo"&&s[3]==="status"&&u==="GET"){let[h,b,w]=await Promise.all([c.get("geo:updating"),c.get("geo:update_status"),c.get(Lt)]),x=null;if(b)try{x=JSON.parse(b)}catch{}return T({ok:!0,updating:h==="1",version:w||null,status:x})}if(o==="geo"&&s[3]==="info"&&u==="GET"){let[h,b,w]=await Promise.all([c.get("geo:updating"),c.get("geo:update_status"),c.get(Lt)]),x=null;if(b)try{x=JSON.parse(b)}catch{}let v=async $=>{let E=[],U;do{let O=await c.list({prefix:$,cursor:U});for(let at of O.keys||[])E.push(at.name.slice($.length));U=O.cursor}while(U);return E},[k,C]=await Promise.all([v("geosite:"),v("geoip:")]);return T({ok:!0,updating:h==="1",version:w||null,status:x,geositeCount:k.length,geoipCount:C.length,geositeCategories:k,geoipCategories:C})}if(o==="netstatus"&&s[3]==="test"&&u==="POST")try{return T(await Ir(t,h=>console.log(h)))}catch(h){return T({ok:!1,error:h.message},500)}if(o==="route-test"&&u==="POST")try{let h=await _t(e),b=h&&h.domain?String(h.domain).trim():"";return b?T(await Nr(t,b,w=>console.log(w))):T({ok:!1,error:"\u8BF7\u586B\u5199\u8981\u6D4B\u8BD5\u7684\u57DF\u540D\u6216 IP"},400)}catch(h){return T({ok:!1,error:h.message},500)}if(o==="test"){if(s[3]==="proxyip"&&u==="POST")try{return T(await Hr(t,h=>console.log(h)))}catch(h){return T({ok:!1,error:h.message},500)}if(s[3]==="udp"&&u==="POST")try{return T(await zr(t,h=>console.log(h)))}catch(h){return T({ok:!1,error:h.message},500)}if(s[3]==="outbound"&&s[4]&&u==="POST"){let h=await i.prepare("SELECT * FROM outbounds WHERE id = ?").bind(Number(s[4])).first();if(!h)return T({ok:!1,error:"outbound not found"},404);try{return T(await Fr(t,h,b=>console.log(b)))}catch(b){return T({ok:!1,error:b.message},500)}}}return T({error:"not found"},404)}async function Jr(e){try{let{results:t}=await e.prepare("SELECT name FROM pragma_table_info('outbounds')").all();if((t||[]).some(r=>r.name==="transport"))return;await e.prepare("ALTER TABLE outbounds ADD COLUMN transport TEXT DEFAULT 'ws'").run(),console.log("[admin] outbounds.transport column added (migration)")}catch(t){console.log("[admin] outbounds transport migration skipped: "+t.message)}}async function Ba(e,t,r,n,a){let{table:s,cols:o}=r,l="id";if(e==="GET"){let{results:u}=await n.prepare(`SELECT * FROM ${s} ORDER BY id`).all();return T(u||[])}if(e==="POST"){let u=await _t(a);if(!u)return T({error:"bad body"},400);if(r.validate){let p=r.validate(u);if(p)return T({error:p},400)}s==="outbounds"&&await Jr(n);let i=o.filter(p=>u[p]!==void 0);if(i.length===0)return T({error:"no fields"},400);let c=i.map(()=>"?").join(","),d=i.map(p=>u[p]),{meta:f}=await n.prepare(`INSERT INTO ${s} (${i.join(",")}) VALUES (${c})`).bind(...d).run();return r.cacheKey&&it(r.cacheKey),T({ok:!0,id:f.last_row_id})}if(e==="PUT"&&t){let u=await _t(a);if(!u)return T({error:"bad body"},400);if(r.validate){let f=r.validate(u);if(f)return T({error:f},400)}s==="outbounds"&&await Jr(n);let i=o.filter(f=>u[f]!==void 0);if(i.length===0)return T({error:"no fields"},400);let c=i.map(f=>`${f} = ?`).join(","),d=i.map(f=>u[f]);return await n.prepare(`UPDATE ${s} SET ${c} WHERE ${l} = ?`).bind(...d,Number(t)).run(),r.cacheKey&&it(r.cacheKey),T({ok:!0})}return e==="DELETE"&&t?(await n.prepare(`DELETE FROM ${s} WHERE ${l} = ?`).bind(Number(t)).run(),r.cacheKey&&it(r.cacheKey),T({ok:!0})):T({error:"method not allowed"},405)}var Xr={geosite:["cn","apple","google","microsoft","facebook","twitter","telegram","github","netflix","youtube","spotify","discord","tiktok","paypal","steam","cloudflare","openai","anthropic","amazon","whatsapp","instagram","linkedin","mozilla","adobe","speedtest","oracle","digitalocean","vultr","jetbrains","gitee","baidu","aliyun","tencent","jd","bilibili","douyin","zhihu","iqiyi","youku","xiaomi","huawei"],geoip:["cn","hk","mo","tw","jp","kr","sg","my","th","vn","id","ph","us","ca","gb","de","fr","nl","se","au","nz","ru","in","br","ar","mx","za","tr","ae","sa","il","es","it","ch","at","be","dk","fi","no","pl","pt","ie","cz","hu","ro","ua","kz"]};async function Nt(e,t,r){let n=await Ka();(!n||n.length===0)&&(n=Xr.geosite.slice(),console.log("[geo] v2fly category enumeration failed, fallback to DEFAULT_GEO_CATEGORIES.geosite"));let a={geosite:n,geoip:Xr.geoip},s=a.geosite.length+a.geoip.length,o=i=>{if(typeof r=="function")try{r(i)}catch{}},l={updated:0,total:0,failed:[]},u=0;for(let i of["geosite","geoip"])for(let c of a[i]){l.total++,u++,o({state:"updating",step:u,total:s,current:`${i}:${c}`,updated:l.updated,failed:l.failed,message:`\u62C9\u53D6 ${i}:${c}`});try{let d=await Ga(i,c);d&&d.length>0?(await t.put(`${i}:${c}`,JSON.stringify(d)),l.updated++):l.failed.push(`${i}:${c} (empty rules)`)}catch(d){l.failed.push(`${i}:${c} (${d.message||d})`)}}return await t.put(Lt,new Date().toISOString()),ur(),l}async function It(e,t){let r=Date.now(),n=a=>t.put("geo:update_status",JSON.stringify({startedAt:r,...a})).catch(()=>{});try{await n({state:"updating",step:0,total:0,updated:0,failed:[],current:"",message:"\u5F00\u59CB\u66F4\u65B0"});let a=await Nt(e,t,s=>n({...s}));return await n({state:"done",step:a.total,total:a.total,updated:a.updated,failed:a.failed,current:"",message:"\u66F4\u65B0\u5B8C\u6210"}),await t.put("geo:updating","0").catch(()=>{}),a}catch(a){throw await n({state:"error",message:a.message||String(a),failed:[]}).catch(()=>{}),a}}async function Ga(e,t){if(e==="geosite"){let a=await en(t,new Set);if(a.length===0)throw new Error("empty geosite rules");return a}let r=await Xa(t),n=[];for(let[a,s]of r)if(a.length===4?n.push(...ts(a,s)):n.push(...es(a,s)),n.length>=3e4)break;if(n.length===0)throw new Error("empty geoip cidrs");return n}var ja="https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/",Wa="https://cdn.jsdelivr.net/gh/v2fly/domain-list-community@master/data/",Va=2e4;function Zr(e){let t=e.indexOf(".");return t>0?e.slice(0,t):e}async function Ka(){try{let e=await fetch("https://api.github.com/repos/v2fly/domain-list-community/git/trees/master?recursive=1",{headers:{"User-Agent":"vless-trojan-d1"},cf:{cacheTtl:86400}});if(e.ok){let t=await e.json(),r=t&&Array.isArray(t.tree)?t.tree:[],n=new Set;for(let a of r){if(!a||a.type!=="blob"||typeof a.path!="string"||!a.path.startsWith("data/"))continue;let s=a.path.slice(5);!s||s.includes("/")||n.add(Zr(s))}if(n.size>0)return[...n].sort()}}catch{}try{let e=await fetch("https://api.github.com/repos/v2fly/domain-list-community/contents/data",{headers:{"User-Agent":"vless-trojan-d1"},cf:{cacheTtl:86400}});if(e.ok){let t=await e.json();if(Array.isArray(t)){let r=new Set;for(let n of t){if(!n||n.type!=="file"||typeof n.name!="string")continue;let a=Zr(n.name);a&&r.add(a)}if(r.size>0)return[...r].sort()}}}catch{}return null}async function en(e,t){if(t.has(e))return[];t.add(e);let r=encodeURIComponent(e),n=[ja+r,Wa+r],a=null;for(let s of n)try{let o=await fetch(s,{cf:{cacheTtl:86400}});if(!o.ok){a=new Error(`HTTP ${o.status}`);continue}let l=await o.text(),u=[];for(let i of l.split(`
`)){if(i=i.trim(),!i||i.startsWith("#"))continue;if(i.startsWith("include:")){let f=i.slice(8).trim().split(/\s+/)[0];f&&u.push(...await en(f,t));continue}let c=i;if(c.startsWith("full:"))c=c.slice(5);else if(c.startsWith("domain:"))c=c.slice(7);else if(c.startsWith("keyword:")||c.startsWith("regexp:"))continue;c=c.replace(/\s+@[^\s#]+/g,"");let d=c.indexOf("#");d>=0&&(c=c.slice(0,d)),c=c.trim().toLowerCase().replace(/^\.+/,""),c&&u.length<Va&&u.push(c)}return u}catch(o){a=o}throw a||new Error("v2fly geosite fetch failed")}var qa="https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/",Ya="https://cdn.jsdelivr.net/gh/SagerNet/sing-geoip@rule-set/",Ja=3e4;async function Xa(e){let t=encodeURIComponent(e),r=[qa+"geoip-"+t+".srs",Ya+"geoip-"+t+".srs"],n=null;for(let a of r)try{let s=await fetch(a,{cf:{cacheTtl:86400}});if(!s.ok){n=new Error(`HTTP ${s.status}`);continue}let o=new Uint8Array(await s.arrayBuffer());if(o.length<5||o[0]!==83||o[1]!==82||o[2]!==83){n=new Error("bad srs magic");continue}if(o[3]>1){n=new Error(`unsupported srs version ${o[3]}`);continue}let l;try{l=Yr(o.subarray(4))}catch{n=new Error("zlib inflate failed");continue}return Za(l)}catch(s){n=s}throw n||new Error("sing-geoip srs fetch failed")}function Za(e){let t=0,r=dt(e,t);t=r.p;let n=[];for(let a=0;a<r.v;a++){let s=e[t++];if(s!==0)throw new Error(`geoip logical rule unsupported (type ${s})`);for(;;){let o=e[t++];if(o===255)break;if(o===5||o===6){if(e[t++]!==1)throw new Error("bad ipset version");let l=Qa(e,t);t+=8;for(let u=0;u<l&&n.length<Ja*2;u++){let i=dt(e,t);t=i.p;let c=e.subarray(t,t+i.v);t+=i.v,i=dt(e,t),t=i.p;let d=e.subarray(t,t+i.v);if(t+=i.v,c.length!==d.length||c.length!==4&&c.length!==16)throw new Error("bad ipset addr");n.push([c,d])}}else if(o===0||o===7||o===9){let l=dt(e,t);t=l.p,t+=l.v*2}else if(o===1||o===3||o===4||o===8||o===10||o===11||o===12||o===13||o===14||o===15||o===17||o===18||o===19||o===20||o===21||o===22||o===23){let l=dt(e,t);t=l.p;for(let u=0;u<l.v;u++){let i=dt(e,t);t=i.p,t+=i.v}}else throw new Error(`geoip unsupported item type ${o}`)}}return n}function dt(e,t){let r=0,n=0;for(;;){let a=e[t++];if(r|=(a&127)<<n,!(a&128))break;if(n+=7,n>63)throw new Error("uvarint overflow")}return{v:r,p:t}}function Qa(e,t){let r=0;for(let n=0;n<8;n++)r=r*256+e[t+n];return r}function ts(e,t){let r=(e[0]<<24>>>0)+(e[1]<<16)+(e[2]<<8)+e[3],n=(t[0]<<24>>>0)+(t[1]<<16)+(t[2]<<8)+t[3],a=[];for(;r<=n;){let s=0;for(;;){let o=1<<s+1;if((r&o-1)!==0||r+o-1>n)break;s++}a.push(`${r>>>24}.${r>>>16&255}.${r>>>8&255}.${r&255}/${32-s}`),r+=1<<s}return a}function es(e,t){let r=0n,n=0n;for(let s of e)r=r<<8n|BigInt(s);for(let s of t)n=n<<8n|BigInt(s);let a=[];for(;r<=n;){let s=0n;for(;;){let o=1n<<s+1n;if((r&o-1n)!==0n||r+o-1n>n)break;s++}a.push(`${rs(r)}/${128-Number(s)}`),r+=1n<<s}return a}function rs(e){let t=[];for(let l=7;l>=0;l--)t.push(Number(e>>BigInt(l*16)&0xffffn));let r=-1,n=0,a=-1,s=0;for(let l=0;l<8;l++)t[l]===0?(a<0&&(a=l),s++,s>n&&(n=s,r=a)):(a=-1,s=0);let o="";for(let l=0;l<8;l++)l===r&&n>=2?(o+=(o.length>0&&!o.endsWith(":"),"::"),l+=n-1):(o.length>0&&!o.endsWith(":")&&(o+=":"),o+=t[l].toString(16));return o}var Qr=!1;async function ns(e){if(Qr)return;let t=[["path","TEXT DEFAULT ''"],["expire_at","INTEGER DEFAULT 0"],["traffic_limit","INTEGER DEFAULT 0"],["traffic_reset_at","INTEGER DEFAULT 0"]];for(let r of["vless_users","trojan_users"])try{let{results:n}=await e.prepare(`SELECT name FROM pragma_table_info('${r}')`).all(),a=new Set((n||[]).map(s=>s.name));for(let[s,o]of t)a.has(s)||(await e.prepare(`ALTER TABLE ${r} ADD COLUMN ${s} ${o}`).run(),console.log(`[admin] ${r}.${s} column added (migration)`))}catch(n){console.log(`[admin] ${r} migration skipped: ${n.message}`)}Qr=!0}var ge=null;function rn(e){if(!e&&ge)return ge;let r=`<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>\u8282\u70B9\u7BA1\u7406\u540E\u53F0</title>
<style>
  :root { --bg:#f2f2f7; --card:#fff; --text:#1c1c1e; --muted:#8e8e93; --accent:#0a84ff; --danger:#ff3b30; --border:rgba(60,60,67,.12);
  --input-bg:#fafafa; --info-bg:#f0f4ff; --info-text:#2b5db3; --ok-bg:#e8f8ef; --ok-text:#1d7a3f;
  --badge-info:#e9f5ff; --badge-on-bg:#e8f8ef; --badge-on-text:#34c759; --badge-off:#f2f2f7;
  --dot-idle:#d1d1d6; --logo-bg:#e9e9ee; --skeleton-a:#f2f2f7; --skeleton-b:#e4e4ea; --mask:rgba(0,0,0,.4); --entry-card:#fff; }
:root[data-theme="dark"] { color-scheme: dark;
  --bg:#000; --card:#1c1c1e; --text:#f2f2f7; --muted:#98989e; --accent:#0a84ff; --danger:#ff453a; --border:rgba(255,255,255,.14);
  --input-bg:#2c2c2e; --info-bg:rgba(10,132,255,.16); --info-text:#64b0ff; --ok-bg:rgba(52,199,89,.16); --ok-text:#3ddc68;
  --badge-info:rgba(10,132,255,.18); --badge-on-bg:rgba(52,199,89,.18); --badge-on-text:#30d158; --badge-off:#2c2c2e;
  --dot-idle:#48484a; --logo-bg:#3a3a3c; --skeleton-a:#2c2c2e; --skeleton-b:#3a3a3c; --mask:rgba(0,0,0,.6); --entry-card:#1c1c1e; }
  * { box-sizing:border-box; margin:0; padding:0; }
  body { font-family:-apple-system,BlinkMacSystemFont,"SF Pro Text","PingFang SC","Microsoft YaHei",sans-serif; background:var(--bg); color:var(--text); }
  .login-wrap { min-height:100vh; display:flex; align-items:center; justify-content:center; }
  .login-card { background:var(--card); border-radius:24px; padding:40px; width:340px; box-shadow:0 4px 24px rgba(0,0,0,.08); text-align:center; }
  .login-card h1 { font-size:24px; font-weight:700; margin-bottom:8px; }
  .login-card p { color:var(--muted); font-size:14px; margin-bottom:24px; }
  .login-card input { width:100%; padding:12px 16px; border:1px solid var(--border); border-radius:12px; font-size:15px; margin-bottom:16px; background:var(--input-bg); }
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
  .badge { display:inline-block; padding:2px 10px; border-radius:20px; font-size:12px; background:var(--badge-info); color:var(--accent); }
  .badge.off { background:var(--badge-off); color:var(--muted); }
  .badge.on { background:var(--badge-on-bg); color:var(--badge-on-text); }
  .toolbar { display:flex; gap:8px; margin-bottom:16px; }
  .toolbar .btn { width:auto; padding:8px 16px; }
  .modal-mask { position:fixed; inset:0; background:var(--mask); display:none; align-items:center; justify-content:center; z-index:50; }
  .modal-mask.show { display:flex; }
  .modal { background:var(--card); border-radius:20px; padding:24px; width:480px; max-width:92vw; max-height:80vh; overflow:auto; }
  .modal h3 { font-size:18px; margin-bottom:16px; }
  .modal label { display:block; font-size:13px; color:var(--muted); margin:12px 0 6px; }
  .modal input, .modal select, .modal textarea { width:100%; padding:10px 12px; border:1px solid var(--border); border-radius:10px; font-size:14px; background:var(--input-bg); }
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
  .net-dot { width:12px; height:12px; border-radius:50%; background:var(--dot-idle); flex:none; }
  .net-dot.ok { background:#34c759; }
  .net-dot.warn { background:#ffcc00; }
  .net-dot.bad { background:#ff9500; }
  .net-foot { display:flex; justify-content:space-between; align-items:center; margin-top:10px; font-size:12px; color:var(--muted); }
  /* ---- Geo \u66F4\u65B0\u8FDB\u5EA6\u5F39\u6846 ---- */
  .geo-modal { position:fixed; inset:0; background:var(--mask); display:none; align-items:center; justify-content:center; z-index:60; }
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
  .geo-done.ok { background:var(--ok-bg); color:var(--ok-text); }
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
  .net-logo { width:34px; height:34px; border-radius:9px; display:flex; align-items:center; justify-content:center; font-size:18px; background:var(--logo-bg); color:#fff; flex:none; box-shadow:0 2px 6px rgba(0,0,0,.14); }
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
  .net-latency.scan, .net-meta.scan { background:linear-gradient(90deg,var(--skeleton-a) 25%,var(--skeleton-b) 37%,var(--skeleton-a) 63%); background-size:400% 100%; animation:scanMove 1.2s ease infinite; border-radius:6px; }
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
    :root[data-theme="dark"] .sidebar { background:rgba(28,28,30,.92); }
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
.theme-seg { display:flex; background:var(--bg); border-radius:10px; padding:3px; gap:2px; }
.seg-item { flex:1; text-align:center; padding:8px 0; border-radius:8px; font-size:13px; color:var(--muted); cursor:pointer; transition:background .2s ease,color .2s ease; -webkit-tap-highlight-color:transparent; }
.seg-item.on { background:var(--card); color:var(--text); font-weight:600; box-shadow:0 1px 4px rgba(0,0,0,.08); }
</style>
<script>try{var m=localStorage.getItem('themeMode')||'system',d=m==='dark'||(m==='system'&&matchMedia('(prefers-color-scheme: dark)').matches);document.documentElement.dataset.theme=d?'dark':'light';}catch(e){}<\/script>
</head>
<body>
<div class="login-wrap" id="loginWrap">
  <div class="login-card">
    <h1>\u8282\u70B9\u7BA1\u7406</h1>
    <p>\u8BF7\u8F93\u5165\u7BA1\u7406\u5BC6\u7801</p>
    ${e?`<p style="margin:-8px 0 16px;padding:10px 12px;background:var(--ok-bg);color:var(--ok-text);border-radius:10px;font-size:13px">\u9996\u6B21\u90E8\u7F72\u521D\u59CB\u5BC6\u7801\uFF1A<b>${e}</b><br>\u767B\u5F55\u540E\u8BF7\u53CA\u65F6\u4FEE\u6539</p>`:""}
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
    <div class="nav-item" data-tab="geo">\u{1F30F} Geo \u89C4\u5219\u5E93</div>
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
// \u591C\u95F4\u6A21\u5F0F\uFF1A\u9ED8\u8BA4\u8DDF\u968F\u7CFB\u7EDF\uFF0C\u53EF\u624B\u52A8\u5207\u6362\uFF08localStorage.themeMode: system/light/dark\uFF09
function sysDark(){ return matchMedia('(prefers-color-scheme: dark)').matches; }
function currentTheme(){ const m = localStorage.getItem('themeMode') || 'system'; return m==='system' ? (sysDark()?'dark':'light') : m; }
function applyTheme(){ document.documentElement.dataset.theme = currentTheme(); }
function renderThemeSeg(){ const m = localStorage.getItem('themeMode') || 'system'; document.querySelectorAll('#themeSeg .seg-item').forEach(el=>{ el.classList.toggle('on', el.dataset.t===m); el.onclick = ()=>setTheme(el.dataset.t); }); }
function setTheme(mode){ localStorage.setItem('themeMode', mode); applyTheme(); renderThemeSeg(); toast(mode==='system'?'\u5DF2\u8DDF\u968F\u7CFB\u7EDF\u5916\u89C2':(mode==='dark'?'\u5DF2\u5207\u6362\u6DF1\u8272\u6A21\u5F0F':'\u5DF2\u5207\u6362\u6D45\u8272\u6A21\u5F0F')); }
(function(){ try{ if (matchMedia('(prefers-color-scheme: dark)').addEventListener) matchMedia('(prefers-color-scheme: dark)').addEventListener('change', applyTheme); }catch(e){} })();

async function switchTab(tab){
  state.tab = tab;
  document.querySelectorAll('.nav-item[data-tab]').forEach(el=>el.classList.toggle('active', el.dataset.tab===tab));
  const mc = $('#mainContent');
  if (tab==='stats'){ mc.innerHTML = '<div class="page-title">\u6D41\u91CF\u7EDF\u8BA1</div><div class="card">\u52A0\u8F7D\u4E2D...</div>'; await loadStats(); return; }
  if (tab==='netstatus'){ clearNetAuto(); mc.innerHTML = '<div class="page-title">\u7F51\u7EDC\u72B6\u6001</div><div class="card" style="padding:12px 16px;font-size:13px;color:var(--muted)">\u68C0\u6D4B\u6309\u9879\u76EE\u7F51\u7EDC\u8BBE\u7F6E\u53D1\u8D77\uFF08\u8DEF\u7531\u89C4\u5219 + \u9ED8\u8BA4\u51FA\u7AD9 + proxyip + \u51FA\u7AD9\u96A7\u9053\uFF09\uFF0C\u5168\u90E8\u63A2\u6D4B\u5728 Worker \u5185\u5B8C\u6210\uFF0C\u591A\u76EE\u6807\u5E76\u884C\u3001\u6BCF\u76EE\u6807 16 \u6B21\u91C7\u6837\uFF0C\u7EA6 10-15 \u79D2\u5B8C\u6210\u3002\u7EFF=\u6B63\u5E38\uFF0C\u9EC4=\u9AD8\u5EF6\u8FDF\uFF0C\u7EA2/\u7070=\u5931\u8D25\u3002</div><div class="colo-bar" id="coloBar"><span class="colo-muted">\u6B63\u5728\u83B7\u53D6\u8FD0\u884C\u65F6\u4F4D\u7F6E\u2026</span></div><div class="net-toolbar"><button class="btn small" onclick="runNetstatus()">\u5F00\u59CB\u68C0\u6D4B</button><label class="auto-refresh"><input type="checkbox" id="netAuto" checked onchange="scheduleNetAuto()"> \u81EA\u52A8\u5237\u65B0</label><span class="net-update-time" id="netUpdateTime"></span></div><div class="net-grid" id="netGrid"></div>'; runNetstatus(); return; }
  if (tab==='settings'){ mc.innerHTML = '<div class="page-title">\u7CFB\u7EDF\u8BBE\u7F6E</div><div class="card">\u52A0\u8F7D\u4E2D...</div>'; await loadSettings(); return; }
  if (tab==='entry'){ mc.innerHTML = '<div class="page-title">\u5165\u53E3\u8BBE\u7F6E</div><div class="card">\u52A0\u8F7D\u4E2D...</div>'; await loadEntry(); return; }
  if (tab==='routetest'){ mc.innerHTML = '<div class="page-title">\u8DEF\u7531\u6D4B\u8BD5</div>'+ROUTE_TEST_CARD; return; }
  if (tab==='geo'){ mc.innerHTML = '<div class="page-title">Geo \u89C4\u5219\u5E93</div>'+GEO_CARD; loadGeoInfo(); return; }
  const def = TAB_DEFS[tab];
  mc.innerHTML = '<div class="page-title">'+def.title+'</div><div class="toolbar"><button class="btn small" onclick="openNew()">\uFF0B \u65B0\u589E</button></div><div class="card"><div class="table-wrap"><table><thead><tr>'+def.fields.map(f=>'<th>'+f.label+'</th>').join('')+'<th>\u64CD\u4F5C</th></tr></thead><tbody id="tbody"></tbody></table></div></div>';
  state.schema = def;
  await loadList();
}

// \u8DEF\u7531\u6D4B\u8BD5\u6A21\u5757\uFF1A\u72EC\u7ACB\u83DC\u5355 tab\uFF0C\u8F93\u5165\u57DF\u540D\u6309\u5F53\u524D\u914D\u7F6E\u5224\u5B9A\u771F\u5B9E\u8DEF\u7531\u8D70\u5411
const ROUTE_TEST_CARD = '<div class="card" id="routeTestCard" style="margin-top:16px">'+
  '<h3 style="font-size:15px;margin-bottom:8px">\u{1F9ED} \u8DEF\u7531\u6D4B\u8BD5</h3>'+
  '<div style="font-size:12px;color:var(--muted);margin-bottom:10px;line-height:1.6">\u8F93\u5165\u57DF\u540D\u6216 IP\uFF0C\u6309\u5F53\u524D\u914D\u7F6E\uFF08\u8DEF\u7531\u89C4\u5219 \u2192 \u9ED8\u8BA4\u51FA\u7AD9 \u2192 proxyip\uFF09\u5224\u5B9A\u771F\u5B9E\u8DEF\u7531\u8D70\u5411\u3002direct \u7EFF / proxyip \u84DD / outbound \u6A59 / reject \u7EA2\u3002</div>'+
  '<div style="display:flex;gap:8px"><input id="routeTestDomain" placeholder="\u4F8B\u5982 www.google.com / 1.1.1.1" style="flex:1;padding:10px 12px;border:1px solid var(--border);border-radius:10px;font-size:14px;background:var(--input-bg)"><button class="btn small" onclick="runRouteTest()">\u6D4B\u8BD5</button></div>'+
  '<div id="routeTestResult" style="margin-top:12px;font-size:13px;line-height:1.8"></div></div>';

// Geo \u89C4\u5219\u5E93\uFF1A\u72EC\u7ACB\u83DC\u5355 tab\uFF0C\u5C55\u793A\u5DF2\u843D\u5E93\u89C4\u5219\u7EDF\u8BA1\u3001\u63D0\u4F9B\u66F4\u65B0\u5165\u53E3\uFF0C\u5E76\u652F\u6301\u6309\u5173\u952E\u8BCD\u67E5\u8BE2\u5DF2\u843D\u5E93\u5206\u7C7B\uFF08\u4FBF\u4E8E\u5728\u8DEF\u7531\u89C4\u5219\u4E2D\u5F15\u7528 geosite:/geoip:\uFF09
const GEO_CARD = '<div class="card" id="geoInfoCard" style="margin-top:16px">'+
  '<h3 style="font-size:15px;margin-bottom:8px">\u{1F30F} Geo \u89C4\u5219\u5E93</h3>'+
  '<div style="font-size:12px;color:var(--muted);margin-bottom:10px;line-height:1.6">\u5F53\u524D\u5DF2\u843D\u5E93\u7684 geosite\uFF08\u57DF\u540D\u5206\u7C7B\uFF09\u4E0E geoip\uFF08IP \u5206\u7C7B\uFF09\u89C4\u5219\u7EDF\u8BA1\u3002\u70B9\u51FB\u300C\u66F4\u65B0\u89C4\u5219\u300D\u4ECE\u4E0A\u6E38\u62C9\u53D6\u6700\u65B0\u89C4\u5219\uFF08geosite \u5168\u91CF\u7EA6 1589 \u7C7B\uFF0C\u8017\u65F6\u8F83\u957F\uFF09\u3002</div>'+
  '<div id="geoInfoStats" style="font-size:13px;line-height:1.9">\u52A0\u8F7D\u4E2D\u2026</div>'+
  '<div style="margin-top:14px"><button class="btn small" onclick="openGeoUpdate()">\u{1F504} \u66F4\u65B0\u89C4\u5219</button></div>'+
  '<div style="margin-top:18px;border-top:1px solid var(--border);padding-top:12px">'+
  '<div style="font-size:13px;font-weight:600;margin-bottom:6px">\u67E5\u8BE2\u5DF2\u843D\u5E93\u89C4\u5219</div>'+
  '<div style="font-size:12px;color:var(--muted);margin-bottom:8px;line-height:1.6">\u8F93\u5165\u5173\u952E\u8BCD\u8FC7\u6EE4\u53EF\u7528\u7684 geosite / geoip \u5206\u7C7B\uFF08\u5982 openai\u3001cn\uFF09\uFF0C\u5339\u914D\u9879\u53EF\u76F4\u63A5\u7528\u4E8E\u8DEF\u7531\u89C4\u5219\uFF08geosite:openai\u3001geoip:cn\uFF09\u3002</div>'+
  '<input id="geoRuleQuery" placeholder="\u8F93\u5165\u5173\u952E\u8BCD\uFF0C\u5982 openai / cn / telegram" oninput="filterGeoRules(this.value)" style="width:100%;padding:8px 12px;border:1px solid var(--border);border-radius:8px">'+
  '<div id="geoRuleResult" style="margin-top:10px;font-size:12px;color:var(--muted);line-height:1.6">\u8F93\u5165\u5173\u952E\u8BCD\u540E\u5C55\u793A\u5339\u914D\u5206\u7C7B\u3002</div>'+
  '</div></div>';

async function loadGeoInfo(){
  const el = $('#geoInfoStats'); if (!el) return;
  try {
    const d = await api('/admin/api/geo/info');
    const g = d.geositeCount || 0, ip = d.geoipCount || 0;
    window._geoCats = { geosite: d.geositeCategories || [], geoip: d.geoipCategories || [] };
    let html = '<div>geosite\uFF08\u57DF\u540D\uFF09\u5206\u7C7B\uFF1A<b>'+g+'</b> \u4E2A</div>';
    html += '<div>geoip\uFF08IP\uFF09\u5206\u7C7B\uFF1A<b>'+ip+'</b> \u4E2A</div>';
    html += '<div>\u89C4\u5219\u5E93\u7248\u672C\uFF1A<b>'+(d.version ? esc(d.version) : '\u672A\u66F4\u65B0')+'</b></div>';
    if (d.status && d.status.state === 'done') {
      html += '<div>\u4E0A\u6B21\u66F4\u65B0\uFF1A\u6210\u529F <b>'+(d.status.updated||0)+'</b> / '+(d.status.total||0)+' \u4E2A\u5206\u7C7B</div>';
    } else if (d.status && d.status.state === 'updating') {
      html += '<div style="color:var(--accent)">\u6B63\u5728\u66F4\u65B0\u4E2D\u2026 \u8FDB\u5EA6 <b>'+(d.status.step||0)+'</b> / '+(d.status.total||0)+'</div>';
    } else if (d.status && d.status.state === 'error') {
      html += '<div style="color:var(--danger)">\u4E0A\u6B21\u66F4\u65B0\u5931\u8D25\uFF1A'+esc(d.status.message||'')+'</div>';
    } else {
      html += '<div style="color:var(--muted)">\u5C1A\u65E0\u66F4\u65B0\u8BB0\u5F55\uFF0C\u70B9\u51FB\u300C\u66F4\u65B0\u89C4\u5219\u300D\u62C9\u53D6</div>';
    }
    el.innerHTML = html;
  } catch(e){ el.innerHTML = '<span style="color:var(--danger)">\u52A0\u8F7D\u5931\u8D25\uFF1A'+esc(e.message)+'</span>'; }
}

// \u6309\u5173\u952E\u8BCD\u8FC7\u6EE4\u5DF2\u843D\u5E93\u7684 geosite / geoip \u5206\u7C7B\uFF0C\u5C55\u793A\u5339\u914D\u9879\u4F9B\u6DFB\u52A0\u8DEF\u7531\u89C4\u5219\u65F6\u5F15\u7528
function filterGeoRules(kw){
  const el = $('#geoRuleResult'); if (!el) return;
  kw = (kw || '').trim().toLowerCase();
  if (!kw){ el.innerHTML = '<span style="color:var(--muted)">\u8F93\u5165\u5173\u952E\u8BCD\u540E\u5C55\u793A\u5339\u914D\u5206\u7C7B\u3002</span>'; return; }
  const cats = window._geoCats || { geosite: [], geoip: [] };
  const hitG = cats.geosite.filter(x => x.toLowerCase().includes(kw)).slice(0, 150).map(x => 'geosite:' + x);
  const hitI = cats.geoip.filter(x => x.toLowerCase().includes(kw)).slice(0, 50).map(x => 'geoip:' + x);
  if (!hitG.length && !hitI.length){ el.innerHTML = '<span style="color:var(--danger)">\u672A\u627E\u5230\u5339\u914D\u7684 geo \u89C4\u5219\uFF0C\u6362\u4E2A\u5173\u952E\u8BCD\u8BD5\u8BD5\u3002</span>'; return; }
  const all = hitG.concat(hitI);
  let html = '<div style="margin-bottom:8px">\u5339\u914D <b>'+all.length+'</b> \u6761'+(all.length >= 200 ? '\uFF08\u5DF2\u622A\u65AD\u663E\u793A\uFF09' : '')+'\uFF0C\u70B9\u51FB\u590D\u5236\uFF1A</div>';
  html += '<div style="display:flex;flex-wrap:wrap;gap:6px">' + all.map(x => '<span onclick="copyGeoRule(this)" title="\u70B9\u51FB\u590D\u5236" style="cursor:pointer;background:var(--input-bg);border:1px solid var(--border);border-radius:6px;padding:2px 8px;font-size:12px;font-family:monospace;color:var(--text)">'+x+'</span>').join('') + '</div>';
  el.innerHTML = html;
}

function copyGeoRule(el){
  const t = el.textContent || '';
  if (navigator.clipboard) { navigator.clipboard.writeText(t).then(()=>{ el.style.outline='2px solid var(--accent)'; setTimeout(()=>{ el.style.outline=''; }, 800); }).catch(()=>{}); }
  else { el.style.outline='2px solid var(--accent)'; setTimeout(()=>{ el.style.outline=''; }, 800); }
}

function openGeoUpdate(){ updateGeo(); }

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

// \u5217\u8868\u9875 5s TTL \u7F13\u5B58\uFF1A\u5207 tab \u4E0D\u91CD\u590D\u8BF7\u6C42\uFF0C\u51CF\u5C11 UI \u611F\u77E5\u5EF6\u8FDF\uFF1B\u7F16\u8F91/\u5220\u9664/\u65B0\u589E\u6210\u529F\u540E\u5931\u6548
const LIST_CACHE_TTL = 5000;
let listCache = { key:'', ts:0, rows:null };

async function loadList(){
  const def = state.schema;
  const now = Date.now();
  let rows;
  if (listCache.key === def.api && listCache.rows && now - listCache.ts < LIST_CACHE_TTL) {
    rows = listCache.rows;
  } else {
    rows = await api('/admin/api/'+def.api);
    listCache = { key: def.api, ts: now, rows };
  }
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
    closeModal(); listCache = { key:'', ts:0, rows:null }; await loadList(); toast('\u5DF2\u4FDD\u5B58');
  } catch(e){ toast(e.message); }
}

async function delRow(idx){
  const def = state.schema; const r = state.records[idx];
  if (!confirm('\u786E\u8BA4\u5220\u9664\u8BE5\u8BB0\u5F55\uFF1F')) return;
  try { await api('/admin/api/'+def.api+'/'+r.id,{method:'DELETE'}); listCache = { key:'', ts:0, rows:null }; await loadList(); toast('\u5DF2\u5220\u9664'); }
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
      '<div class="card" style="margin-bottom:16px">'+
        '<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:12px"><span style="font-size:14px;font-weight:600">\u5916\u89C2</span><span style="font-size:12px;color:var(--muted)">\u9ED8\u8BA4\u8DDF\u968F\u7CFB\u7EDF</span></div>'+
        '<div class="theme-seg" id="themeSeg">'+
          '<span class="seg-item" data-t="system">\u8DDF\u968F\u7CFB\u7EDF</span>'+
          '<span class="seg-item" data-t="light">\u6D45\u8272</span>'+
          '<span class="seg-item" data-t="dark">\u6DF1\u8272</span>'+
        '</div>'+
      '</div>'+
      '<div class="card" style="display:flex;align-items:center;justify-content:space-between;background:var(--info-bg);color:var(--info-text);font-size:13px;border-radius:10px;padding:10px 16px;margin-bottom:16px">'+
        '<span>\u7CFB\u7EDF\u7248\u672C</span><b id="sysVersion">'+(ver.version?esc(ver.version):'\u672A\u77E5')+'</b>'+
      '</div>'+
      '<div class="card" style="background:var(--ok-bg);color:var(--ok-text);font-size:13px;border-radius:10px;padding:12px 16px;margin-bottom:16px">\u5165\u7AD9\u5DF2\u81EA\u52A8\u517C\u5BB9 ws / grpc / h2 \u4E09\u79CD\u4F20\u8F93\u7C7B\u578B\uFF08\u540C\u4E00\u51ED\u636E\u540C\u65F6\u53EF\u7528\uFF09\u3002\u6B64\u5904\u4EC5\u9700\u8BBE\u7F6E\u5171\u4EAB\u5165\u7AD9\u8DEF\u5F84\uFF1B\u5355\u4E2A\u7528\u6237\u53EF\u5728\u300CVLESS \u7528\u6237 / Trojan \u7528\u6237\u300D\u4E2D\u81EA\u5B9A\u4E49\u8DEF\u5F84\uFF0C\u7559\u7A7A\u5219\u4F7F\u7528\u672C\u5168\u5C40\u8DEF\u5F84\u3002</div>'+
      '<div class="card">'+
      '<label style="display:block;font-size:13px;color:var(--muted);margin:10px 0 4px">\u51FA\u7AD9 IP \u534F\u8BAE\u4F18\u5148\u7EA7</label>'+
      '<select id="s_ip_preference" style="width:100%;padding:8px 12px;border:1px solid var(--border);border-radius:8px;background:var(--card);color:var(--text)">'+
        '<option value="ipv4"'+(s.ip_preference==='ipv6'||s.ip_preference==='auto'?'':'selected')+'>IPv4 \u4F18\u5148\uFF08\u9ED8\u8BA4\uFF09</option>'+
        '<option value="ipv6"'+(s.ip_preference==='ipv6'?'selected':'')+'>IPv6 \u4F18\u5148</option>'+
        '<option value="auto"'+(s.ip_preference==='auto'?'selected':'')+'>\u81EA\u52A8\uFF08\u539F\u751F DNS\uFF09</option>'+
      '</select>'+
      '<div style="font-size:11px;color:var(--muted);margin-top:4px">ipv4=\u51FA\u7AD9\u56FA\u5B9A\u8D70 IPv4\uFF1Bipv6=\u51FA\u7AD9 IPv6 \u4F18\u5148\uFF1Bauto=\u4EA4\u7ED9 Cloudflare \u8FD0\u884C\u65F6\u539F\u751F DNS\uFF08\u53EF\u80FD\u968F\u673A v4/v6\uFF09</div>'+
      fields.map(([k,label])=>'<label style="display:block;font-size:13px;color:var(--muted);margin:10px 0 4px">'+label+'</label><input id="s_'+k+'" value="'+esc(s[k]||'')+'" style="width:100%;padding:8px 12px;border:1px solid var(--border);border-radius:8px">').join('')+
      '<div style="margin-top:16px"><button class="btn small" onclick="saveSettings()">\u4FDD\u5B58\u8BBE\u7F6E</button> <button class="btn small" onclick="testProxyIp()">proxyip \u6D4B\u8BD5</button> <button class="btn small" onclick="testUdp()">UDP \u6D4B\u8BD5</button></div>'+
      '<div id="testResult" style="margin-top:12px;font-size:13px;line-height:1.8"></div></div>';
    state.settings = s;
    renderThemeSeg();
  } catch(e){ mc.innerHTML = '<div class="page-title">\u7CFB\u7EDF\u8BBE\u7F6E</div><div class="card">\u52A0\u8F7D\u5931\u8D25: '+esc(e.message)+'</div>'; }
}

async function saveSettings(){
  const body = {};
  document.querySelectorAll('#mainContent input[id^=s_], #mainContent select[id^=s_]').forEach(el=>{ body[el.id.slice(2)] = el.value; });
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
    '.entry-card{background:var(--entry-card);border:1px solid var(--border,#e6e8ee);border-radius:16px;padding:16px;margin-bottom:14px;box-shadow:0 1px 4px rgba(0,0,0,.04);transition:box-shadow .25s ease,border-color .25s ease}' +
    '.entry-card:focus-within{box-shadow:0 4px 16px rgba(10,132,255,.10);border-color:rgba(10,132,255,.35)}' +
    '.entry-card-head{display:flex;align-items:center;gap:10px;margin-bottom:12px}' +
    '.entry-badge{width:24px;height:24px;border-radius:50%;background:var(--primary,#0a84ff);color:#fff;font-size:12px;font-weight:600;display:flex;align-items:center;justify-content:center;flex:none}' +
    '.entry-title{font-size:14px;font-weight:600;color:var(--text,#1d1d1f);flex:1}' +
    '.entry-del{color:#ff3b30 !important;border:1px solid rgba(255,59,48,.25) !important;background:rgba(255,59,48,.06) !important}' +
    '.entry-grid{display:grid;grid-template-columns:1fr 1fr;gap:12px 14px}' +
    '@media (max-width:560px){.entry-grid{grid-template-columns:1fr}}' +
    '.entry-field label{display:block;font-size:12px;color:var(--muted,#8a94a6);margin-bottom:5px;font-weight:500}' +
    '.entry-field input{width:100%;padding:9px 12px;border:1px solid var(--border,#e6e8ee);border-radius:10px;background:#f7f8fa;font-size:14px;color:var(--text,#1d1d1f);outline:none;transition:all .2s ease;box-sizing:border-box}' +
    '.entry-field input:focus{background:var(--card);border-color:var(--primary,#0a84ff);box-shadow:0 0 0 3px rgba(10,132,255,.12)}' +
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
      '<div class="card" style="background:var(--ok-bg);color:var(--ok-text);font-size:13px;border-radius:10px;padding:12px 16px;margin-bottom:16px">\u652F\u6301\u914D\u7F6E\u591A\u4E2A\u5165\u53E3\uFF0C\u6BCF\u4E2A\u5165\u53E3\u53EF\u72EC\u7ACB\u9009\u62E9\u652F\u6301\u7684\u534F\u8BAE\uFF08ws / grpc / h2\uFF09\u3002\u8BBF\u95EE\u5BF9\u5E94\u5165\u53E3\u57DF\u540D\u65F6\uFF0C\u5355\u51ED\u636E\u9875\u4E0E\u5355\u51ED\u636E\u8BA2\u9605\u53EA\u8F93\u51FA\u8BE5\u5165\u53E3\u52FE\u9009\u7684\u534F\u8BAE\uFF1B\u805A\u5408\u8BA2\u9605\u5728\u8BBE\u7F6E\u4E86\u5165\u53E3\u540E\u4EC5\u751F\u6210\u5404\u5165\u53E3\u52FE\u9009\u7684\u534F\u8BAE\u3002\u672A\u8BBE\u7F6E\u4EFB\u4F55\u5165\u53E3\u65F6\u4F7F\u7528\u5F53\u524D\u57DF\u540D\uFF08ws/grpc/h2 \u5168\u534F\u8BAE\uFF09\u3002</div>' +
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
    if (d && d.started === false && d.updating) {
      // \u4E92\u65A5\u9501\u62D2\u7EDD\uFF1A\u5DF2\u6709\u66F4\u65B0\u4EFB\u52A1\u5728\u8FDB\u884C\u4E2D\u3002\u4EC5\u63D0\u793A\u3001\u4E0D\u8986\u76D6\u5F53\u524D\u8FDB\u5EA6\u3001\u4E0D\u542F\u52A8\u8F6E\u8BE2\uFF0C
      // \u907F\u514D\u89E6\u53D1"\u961F\u5217\u6D88\u8D39\u8005\u672A\u751F\u6548"\u7684 30s \u65E0\u8FDB\u5C55\u8BEF\u62A5
      line1.innerHTML = '<span class="geo-done">\u5DF2\u6709\u66F4\u65B0\u6B63\u5728\u8FDB\u884C\u4E2D\uFF0C\u8BF7\u7A0D\u5019\u2026</span>';
      line2.innerHTML = '';
      line3.innerHTML = '';
      return;
    }
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
        // \u5168\u91CF\u679A\u4E3E geosite\uFF08\u7EA6 1589 \u7C7B\uFF09\u540E\u5355\u6B21\u66F4\u65B0\u8017\u65F6\u53EF\u80FD\u8FDC\u8D85 30s\uFF0C
        // \u53EA\u8981 updating \u9501\u4ECD\u5B58\u6D3B\u5373\u89C6\u4E3A\u6B63\u5E38\uFF0C\u8D85\u65F6\u4EC5\u6E29\u548C\u63D0\u793A\u7B49\u5F85\uFF0C\u4E0D\u518D\u8BEF\u62A5"\u961F\u5217\u6D88\u8D39\u8005\u672A\u751F\u6548"
        if (step === 0 && p.message === '\u5DF2\u5165\u961F\uFF0C\u7B49\u5F85\u6D88\u8D39\u8005\u6267\u884C\u2026') {
          if (idleStart === null) idleStart = Date.now();
          if (Date.now() - idleStart > 30000) {
            line3.innerHTML = '<span class="dim">\u66F4\u65B0\u5DF2\u8FDB\u5165\u540E\u53F0\uFF0C\u8BF7\u8010\u5FC3\u7B49\u5F85\u2026</span>';
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
</html>`;return e||(ge=r),r}async function nn(e,t){let r=new URL(e.url);if(e.method==="POST"||e.method==="GET")try{let{DB:n,GEO_KV:a}=t,s=await Nt(n,a);return new Response(JSON.stringify({ok:!0,updated:s.updated,total:s.total,failed:s.failed}),{status:200,headers:{"Content-Type":"application/json; charset=utf-8"}})}catch(n){return new Response(JSON.stringify({ok:!1,error:n.message}),{status:500,headers:{"Content-Type":"application/json; charset=utf-8"}})}return new Response("Not Found",{status:404})}async function an(e,t,r){try{let n=await Nt(t.DB,t.GEO_KV);console.log(`[cron] geo update done: ${n.updated}/${n.total} categories${n.failed.length?", failed: "+n.failed.join("; "):""}`)}catch(n){console.log(`[cron] geo update failed: ${n.message}`)}}globalThis.connect=as;var Io={async fetch(e,t,r){let a=new URL(e.url).pathname;try{if(a.startsWith("/admin")){let l=await Kt(e,t,{ensureAdmin:!0});if(a.startsWith("/admin/api/"))return await tn(e,l,r);let u=rn(l.adminTempPassword),i=l.adminTempPassword?"no-store":"public, max-age=300";return new Response(u,{headers:{"Content-Type":"text/html; charset=utf-8","Cache-Control":i}})}if(a==="/geo-update-cron")return await nn(e,t);let s=await Kt(e,t),o=s.inboundPathMap.get(a);if(o&&o.length>0){s._inboundScope=Ie(o);let l=String(e.headers.get("Upgrade")||"").toLowerCase(),u=String(e.headers.get("Content-Type")||"").toLowerCase(),i=a.endsWith("/Tun")||u.includes("application/grpc");if(l==="websocket"&&!i)return await xr(e,s,t);if(i)return await kr(e,s,t);if(e.method==="POST")return await Tr(e,s,t)}return await Ur(e,s,t)}catch(s){return console.log(`[index] error: ${s.message||s}`),new Response(JSON.stringify({error:"internal error"}),{status:500,headers:{"Content-Type":"application/json; charset=utf-8"}})}},async scheduled(e,t,r){return an(e,t,r)},async queue(e,t,r){for(let n of e.messages)try{if(await t.GEO_KV.get("geo:update_busy")==="1"){console.log("[queue] geo update already in progress, skip message"),n.ack();continue}await t.GEO_KV.put("geo:update_busy","1",{expirationTtl:7200});try{let s=await It(t.DB,t.GEO_KV);console.log(`[queue] geo update done: ${s.updated}/${s.total} categories${s.failed.length?", failed: "+s.failed.join("; "):""}`),n.ack()}finally{await t.GEO_KV.put("geo:update_busy","0").catch(()=>{})}}catch(a){throw console.log(`[queue] geo update failed (will retry): ${a.message||a}`),a}}};export{Io as default};
