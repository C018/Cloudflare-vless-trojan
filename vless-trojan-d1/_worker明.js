import{connect as ws}from"cloudflare:sockets";var K="direct",ce="reject",Ke="socks5",qe="http",Ye="vless",_t=["raw","ws","grpc","httpupgrade"];var Lt="geosite:",$t="geoip:",Pe="geo:version",me="vtd_admin";var Ut=["qq.com","taobao.com","tmall.com","jd.com","baidu.com","bilibili.com","douyin.com","weibo.com","zhihu.com","163.com","126.com","aliyun.com","tencent.com","weixin.qq.com","alipay.com","bankofchina.com","icbc.com.cn","ccb.com","abcchina.com","cmbchina.com","boc.cn","12306.cn","gov.cn","cn","com.cn","net.cn","org.cn"],Ot=["speedtest.net","fast.com","ookla.com"],Ct=["google.com","googleapis.com","gstatic.com","googleusercontent.com","ggpht.com","google.cn","google.com.hk","gvt1.com","gvt2.com","gvt3.com"],Je=[];for(let t=0;t<=255;++t){let e=t.toString(16).padStart(2,"0");Je.push(e)}var Xe=1e5;function Ze(t){return Array.from(new Uint8Array(t)).map(e=>e.toString(16).padStart(2,"0")).join("")}function hn(){let t=new Uint8Array(16);return crypto.getRandomValues(t),Ze(t)}async function Dt(t,e,r){let n=await crypto.subtle.importKey("raw",new TextEncoder().encode(t),"PBKDF2",!1,["deriveBits"]),a=await crypto.subtle.deriveBits({name:"PBKDF2",salt:new TextEncoder().encode(e),iterations:r,hash:"SHA-256"},n,256);return Ze(a)}async function Rt(t){let e=hn(),r=await Dt(t,e,Xe);return`${e}:${Xe}:${r}`}async function Me(t,e){if(!e||!t)return!1;let r=String(e).split(":");if(r.length!==3)return!1;let[n,a,s]=r,o=parseInt(a,10)||Xe;return await Dt(t,n,o)===s}async function Pt(t,e){let r=await crypto.subtle.importKey("raw",new TextEncoder().encode(t),{name:"HMAC",hash:"SHA-256"},!1,["sign"]),n=await crypto.subtle.sign("HMAC",r,new TextEncoder().encode(e));return Ze(n)}async function Mt(t){let r=`admin.${Math.floor(Date.now()/1e3)+604800}`,n=await Pt(t,r);return`${r}.${n}`}async function It(t,e){if(!t||!e)return!1;let r=String(t).split(".");if(r.length!==3)return!1;let[n,a,s]=r;if(n!=="admin")return!1;let o=Number(a);if(!Number.isFinite(o)||o<Date.now()/1e3)return!1;let l=await Pt(e,`${n}.${a}`);if(l.length!==s.length)return!1;let u=0;for(let i=0;i<l.length;i++)u|=l.charCodeAt(i)^s.charCodeAt(i);return u===0}function Nt(t){let e={};if(!t)return e;for(let r of t.split(";")){let n=r.indexOf("=");if(n<0)continue;let a=r.slice(0,n).trim(),s=r.slice(n+1).trim();e[a]=decodeURIComponent(s)}return e}var Ft=3e4,bn=3e4,Ht=0,be={settings:{p:null,ts:0},vlessUsers:{p:null,ts:0},trojanUsers:{p:null,ts:0},outbounds:{p:null,ts:0},routingRules:{p:null,ts:0}},J={p:null,ts:0};function ge(t,e){let r=be[t],n=Date.now();if(r.p&&n-r.ts<Ft)return r.p;let a=Promise.resolve().then(e).catch(()=>null);return r.p=a,r.ts=n,a}function ue(t){if(J.p=null,J.ts=0,t==="all"){for(let r of Object.keys(be))be[r].p=null,be[r].ts=0;return}let e=be[t];e&&(e.p=null,e.ts=0)}async function yn(t){try{let{results:e}=await t.prepare("SELECT key, value FROM settings").all(),r={};for(let n of e||[])r[n.key]=n.value;return r}catch{return{}}}async function wn(t){try{let{results:e}=await t.prepare("SELECT id, uuid, remark, up, down, path, expire_at, traffic_limit, traffic_reset_at FROM vless_users WHERE enable = 1 ORDER BY id").all();return e||[]}catch{try{let{results:r}=await t.prepare("SELECT id, uuid, remark, up, down FROM vless_users WHERE enable = 1 ORDER BY id").all();return(r||[]).map(n=>({path:"",expire_at:0,traffic_limit:0,traffic_reset_at:0,...n}))}catch{return[]}}}async function xn(t){try{let{results:e}=await t.prepare("SELECT id, password, remark, up, down, path, expire_at, traffic_limit, traffic_reset_at FROM trojan_users WHERE enable = 1 ORDER BY id").all();return e||[]}catch{try{let{results:r}=await t.prepare("SELECT id, password, remark, up, down FROM trojan_users WHERE enable = 1 ORDER BY id").all();return(r||[]).map(n=>({path:"",expire_at:0,traffic_limit:0,traffic_reset_at:0,...n}))}catch{return[]}}}function vn(t){let e=String(t||"").trim();if(!e)return"";for(e.startsWith("/")||(e="/"+e);e.length>1&&e.endsWith("/");)e=e.slice(0,-1);return e}async function zt(t,e,r){let n=Math.floor(Date.now()/1e3);for(let a of e)if(a.traffic_reset_at>0&&a.traffic_reset_at<=n)try{await t.prepare(`UPDATE ${r} SET up = 0, down = 0, traffic_reset_at = 0 WHERE id = ?`).bind(a.id).run(),a.up=0,a.down=0,a.traffic_reset_at=0}catch{}}function Tn(t,e,r){let n=new Map,a=(s,o)=>{let l=vn(s);if(!l)return;n.has(l)||n.set(l,[]),n.get(l).push(o);let u=`${l}/Tun`;n.has(u)||n.set(u,[]),n.get(u).push(o)};a(t,{kind:"all"});for(let s of e)s.path&&a(s.path,{kind:"vless",credential:s.uuid.toLowerCase()});for(let s of r)s.path&&a(s.path,{kind:"trojan",credential:s.password});return n}async function kn(t){try{let{results:e}=await t.prepare("SELECT * FROM outbounds WHERE enable = 1 ORDER BY sort ASC, id ASC").all();return e||[]}catch{return[]}}async function En(t){try{let{results:e}=await t.prepare("SELECT * FROM routing_rules WHERE enable = 1 ORDER BY sort ASC, id ASC").all();return e||[]}catch{return[]}}async function Sn(t){try{let n=await t.prepare("SELECT value FROM settings WHERE key = ?").bind("admin_password_hash").first();if(n&&n.value)return{hash:n.value,tempPassword:null}}catch{}let e=Ln().replace(/-/g,"").slice(0,12),r=await Rt(e);try{await t.prepare("INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at").bind("admin_password_hash",r,Date.now()).run(),ue("settings")}catch{}return{hash:r,tempPassword:e}}function An(t){let e=[];try{let r=t.entry_list;if(r){let n=JSON.parse(r);Array.isArray(n)&&(e=n)}}catch{e=[]}return!e.length&&(t.entry_host||"").trim()&&(e=[{host:t.entry_host,port:t.entry_port||"",sni:t.entry_sni||"",wsHost:t.entry_ws_host||"",remark:"",transports:[]}]),e.map(r=>{let n=String(r.host||"").trim(),a=String(r.wsHost||"").trim()||n;return{host:n,port:String(r.port||"").trim()||"443",sni:String(r.sni||"").trim()||a,wsHost:a,remark:String(r.remark||"").trim(),transports:Array.isArray(r.transports)?r.transports.filter(s=>["ws","grpc","xhttp"].includes(s)):["ws","grpc","xhttp"]}}).filter(r=>r.host)}function _n(t,e,r,n){let a=t.ws_path||"/ws",s=t.entry_transport||"ws",o=t.default_outbound||K,l=t.ip_preference||"ipv4",u=t.proxyip||"",i="",c=443,d="";if(u)if(e.find(S=>S.name===u&&S.type!==K&&S.type!==ce))d=u;else{let S=u.lastIndexOf(":");S>0&&!u.includes("]")&&/^\d+$/.test(u.slice(S+1))?(i=u.slice(0,S),c=Number(u.slice(S+1))||443):i=u}let p=t.udp_outbound||"",h=An(t),b=h.length?h[0].host:"",g=h.length?h[0].port:"",m=h.length?h[0].sni:"",f=h.length?h[0].wsHost:"",y=Tn(a,r,n),x={};for(let w of r)x[w.uuid.toLowerCase()]=w;let v={};for(let w of n)v[w.password]=w;return{wsPath:a,entryTransport:s,defaultOutbound:o,ipPreference:l,adminPasswordHash:t.admin_password_hash||"",proxyipHost:i,proxyipPort:c,proxyipOutbound:d,proxyipDisabled:o!==K,udpOutbound:p,entryHost:b,entryPort:g,entrySni:m,entryWsHost:f,entries:h,vlessIndex:x,trojanIndex:v,uuidSet:new Set(r.map(w=>w.uuid.toLowerCase())),passwordSet:new Set(n.map(w=>w.password)),outboundByName:e.reduce((w,S)=>(w[S.name]=S,w),{}),inboundPathMap:y}}async function Qe(t,e,r={}){let{DB:n}=e,[a,s,o,l,u]=await Promise.all([ge("settings",()=>yn(n)),ge("outbounds",()=>kn(n)),ge("vlessUsers",()=>wn(n)),ge("trojanUsers",()=>xn(n)),ge("routingRules",()=>En(n))]),i,c=Date.now();if(J.p&&c-J.ts<Ft)i=await J.p;else{let b=Promise.resolve().then(()=>_n(a,s,o,l));J.p=b,J.ts=c;try{i=await b}catch(g){throw J.p=null,J.ts=0,g}}let d=i.adminPasswordHash,p=null;if(!d&&r.ensureAdmin){let b=await Sn(n);d=b.hash,p=b.tempPassword}let h=Date.now();return h-Ht>=bn&&(await Promise.all([zt(n,o,"vless_users"),zt(n,l,"trojan_users")]),Ht=h),{env:e,settings:a,wsPath:i.wsPath,entryTransport:i.entryTransport,defaultOutbound:i.defaultOutbound,adminPasswordHash:d,adminTempPassword:p,proxyipHost:i.proxyipHost,proxyipPort:i.proxyipPort,proxyipOutbound:i.proxyipOutbound,proxyipDisabled:i.proxyipDisabled,ipPreference:i.ipPreference,udpOutbound:i.udpOutbound,entryHost:i.entryHost,entryPort:i.entryPort,entrySni:i.entrySni,entryWsHost:i.entryWsHost,entries:i.entries,vlessUsers:o,trojanUsers:l,outbounds:s,routingRules:u,vlessIndex:i.vlessIndex,trojanIndex:i.trojanIndex,uuidSet:i.uuidSet,passwordSet:i.passwordSet,outboundByName:i.outboundByName,inboundPathMap:i.inboundPathMap}}function Ln(){return globalThis.crypto&&typeof globalThis.crypto.randomUUID=="function"?globalThis.crypto.randomUUID():"xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(/[xy]/g,t=>{let e=Math.random()*16|0;return(t==="x"?e:e&3|8).toString(16)})}function Bt(t){let e=new Set,r=new Set;for(let n of t){if(n.kind==="all")return{all:!0,vless:e,trojan:r};n.kind==="vless"&&n.credential&&e.add(n.credential),n.kind==="trojan"&&n.credential&&r.add(n.credential)}return{all:!1,vless:e,trojan:r}}var $n=new TextDecoder,Ie=new Map,Un=64;function On(t){let e=Ie.get(t);if(e)return e;let r=t.replace(/-/g,"");e=new Uint8Array(16);for(let n=0;n<16;n++)e[n]=parseInt(r.substr(n*2,2),16);return Ie.size>=Un&&Ie.clear(),Ie.set(t,e),e}function Cn(t){let e=r=>Je[t[r]];return`${e(0)}${e(1)}${e(2)}${e(3)}-${e(4)}${e(5)}-${e(6)}${e(7)}-${e(8)}${e(9)}-${e(10)}${e(11)}${e(12)}${e(13)}${e(14)}${e(15)}`}function jt(t,e){if(t.byteLength<24)return{hasError:!0,message:"invalid data"};let r=t instanceof Uint8Array?t:new Uint8Array(t),n=Cn(r.subarray(1,17));if(!e.has(n))return{hasError:!0,message:"invalid user"};let s=18+r[17];if(t.byteLength<s+4)return{hasError:!0,message:"invalid data"};let o=r[s];if(o!==1&&o!==2)return{hasError:!0,message:`command ${o} is not supported`};let l=s+1,u=r[l]<<8|r[l+1],i=r[l+2],c,d,p;switch(i){case 1:d=4,p=l+3,c=`${r[p]}.${r[p+1]}.${r[p+2]}.${r[p+3]}`;break;case 2:if(t.byteLength<l+4)return{hasError:!0,message:"invalid data"};d=r[l+3],p=l+4,c=$n.decode(r.subarray(p,p+d));break;case 3:d=16,p=l+3,c=`${(r[p]<<8|r[p+1]).toString(16)}:${(r[p+2]<<8|r[p+3]).toString(16)}:${(r[p+4]<<8|r[p+5]).toString(16)}:${(r[p+6]<<8|r[p+7]).toString(16)}:${(r[p+8]<<8|r[p+9]).toString(16)}:${(r[p+10]<<8|r[p+11]).toString(16)}:${(r[p+12]<<8|r[p+13]).toString(16)}:${(r[p+14]<<8|r[p+15]).toString(16)}`;break;default:return{hasError:!0,message:`invalid addressType: ${i}`}}return c?{hasError:!1,userUuid:n,addressRemote:c,addressType:i,portRemote:u,rawDataIndex:p+d,isUDP:o===2}:{hasError:!0,message:"addressValue is empty"}}function Gt(t,e,r,n,a){let s,o,l=[];switch(e){case 1:s=4,l=r.split(".").map(Number);break;case 2:o=new TextEncoder().encode(r),s=o.length+1;break;case 3:s=16,l=et(r).split(":").map(i=>[parseInt(i.slice(0,2),16),parseInt(i.slice(2),16)]).flat();break;default:throw new Error(`Unknown address type: ${e}`)}let u=new Uint8Array(22+s);return u[0]=0,u.set(On(a),1),u[17]=0,u[18]=t,u[19]=n>>8,u[20]=n&255,u[21]=e,e===2?(u[22]=o.length,u.set(o,23)):u.set(l,22),u}function et(t){if(t=t.replace(/^\[|\]$/g,""),t.includes("::")){let e=t.split("::"),r=e[0]?e[0].split(":"):[],n=e[1]?e[1].split(":"):[],a=8-r.length-n.length,s=Array(Math.max(0,a)).fill("0");return[...r,...s,...n].map(o=>o.padStart(4,"0")).join(":")}return t.split(":").map(e=>e.padStart(4,"0")).join(":")}var Vt=new TextDecoder,Dn=new Uint32Array([1116352408,1899447441,3049323471,3921009573,961987163,1508970993,2453635748,2870763221,3624381080,310598401,607225278,1426881987,1925078388,2162078206,2614888103,3248222580,3835390401,4022224774,264347078,604807628,770255983,1249150122,1555081692,1996064986,2554220882,2821834349,2952996808,3210313671,3336571891,3584528711,113926993,338241895,666307205,773529912,1294757372,1396182291,1695183700,1986661051,2177026350,2456956037,2730485921,2820302411,3259730800,3345764771,3516065817,3600352804,4094571909,275423344,430227734,506948616,659060556,883997877,958139571,1322822218,1537002063,1747873779,1955562222,2024104815,2227730452,2361852424,2428436474,2756734187,3204031479,3329325298]),Rn=new Uint32Array([3238371032,914150663,812702999,4144912697,4290775857,1750603025,1694076839,3204075428]),q=(t,e)=>t>>>e|t<<32-e;function Pn(t){let e=new TextEncoder().encode(t),r=Math.floor(e.length/536870912),n=e.length*8>>>0,a=(e.length+9)%64,s=a===0?0:64-a,o=e.length+1+s+8,l=new Uint8Array(o);l.set(e),l[e.length]=128;let u=new DataView(l.buffer);u.setUint32(o-8,r),u.setUint32(o-4,n);let i=Rn.slice(),c=new Uint32Array(64);for(let p=0;p<o;p+=64){for(let w=0;w<16;w++)c[w]=u.getUint32(p+w*4);for(let w=16;w<64;w++){let S=q(c[w-15],7)^q(c[w-15],18)^c[w-15]>>>3,L=q(c[w-2],17)^q(c[w-2],19)^c[w-2]>>>10;c[w]=c[w-16]+S+c[w-7]+L>>>0}let h=i[0],b=i[1],g=i[2],m=i[3],f=i[4],y=i[5],x=i[6],v=i[7];for(let w=0;w<64;w++){let S=q(f,6)^q(f,11)^q(f,25),L=f&y^~f&x,C=v+S+L+Dn[w]+c[w]>>>0,A=q(h,2)^q(h,13)^q(h,22),M=h&b^h&g^b&g,T=A+M>>>0;v=x,x=y,y=f,f=m+C>>>0,m=g,g=b,b=h,h=C+T>>>0}i[0]=i[0]+h>>>0,i[1]=i[1]+b>>>0,i[2]=i[2]+g>>>0,i[3]=i[3]+m>>>0,i[4]=i[4]+f>>>0,i[5]=i[5]+y>>>0,i[6]=i[6]+x>>>0,i[7]=i[7]+v>>>0}let d="";for(let p=0;p<7;p++)d+=i[p].toString(16).padStart(8,"0");return d}var tt=new Map,Wt=new Map;function Mn(t){if(tt.has(t))return tt.get(t);let e=Pn(t);return tt.set(t,e),Wt.set(e,t),e}function Kt(t){if(t.byteLength<60)return!1;let e=t instanceof Uint8Array?t:new Uint8Array(t);return e[0]===0?!1:e[56]===13&&e[57]===10}async function qt(t,e){if(t.byteLength<60)return{hasError:!0,message:"Invalid Trojan data: too short"};let r=t instanceof Uint8Array?t:new Uint8Array(t),n=t instanceof Uint8Array?new DataView(t.buffer,t.byteOffset,t.byteLength):new DataView(t);if(r[56]!==13||r[57]!==10)return{hasError:!0,message:"Invalid Trojan header: missing CRLF"};let a=Vt.decode(r.subarray(0,56)),s=null,o=Wt.get(a);if(o!==void 0&&e.has(o))s=o;else for(let f of e)try{if(await Mn(f)===a){s=f;break}}catch{}if(!s)return{hasError:!0,message:"Invalid Trojan password"};let l=r[58];if(l!==1&&l!==3)return{hasError:!0,message:`Unsupported Trojan command: ${l}`};let i=r[59]===13&&r[60]===10?61:59;if(t.byteLength<i+1)return{hasError:!0,message:"Invalid Trojan header: too short"};let c=r[i],d,p,h;switch(c){case 1:if(p=4,h=i+1,t.byteLength<h+p+2)return{hasError:!0,message:"Invalid Trojan header: IPv4 truncated"};d=`${n.getUint8(h)}.${n.getUint8(h+1)}.${n.getUint8(h+2)}.${n.getUint8(h+3)}`;break;case 3:if(p=r[i+1],h=i+2,t.byteLength<h+p+2)return{hasError:!0,message:"Invalid Trojan header: domain truncated"};d=Vt.decode(r.subarray(h,h+p));break;case 4:if(p=16,h=i+1,t.byteLength<h+p+2)return{hasError:!0,message:"Invalid Trojan header: IPv6 truncated"};d=`${n.getUint16(h).toString(16)}:${n.getUint16(h+2).toString(16)}:${n.getUint16(h+4).toString(16)}:${n.getUint16(h+6).toString(16)}:${n.getUint16(h+8).toString(16)}:${n.getUint16(h+10).toString(16)}:${n.getUint16(h+12).toString(16)}:${n.getUint16(h+14).toString(16)}`;break;default:return{hasError:!0,message:`Invalid Trojan address type: ${c}`}}let b=h+p;if(t.byteLength<b+2)return{hasError:!0,message:"Invalid Trojan header: port truncated"};let g=n.getUint16(b),m=b+2;return t.byteLength<m+2?{hasError:!0,message:"Invalid Trojan header: missing final CRLF"}:r[m]!==13||r[m+1]!==10?{hasError:!0,message:"Invalid Trojan header: invalid final CRLF"}:{hasError:!1,userPassword:s,addressRemote:d,addressType:c===3?2:c===4?3:c,portRemote:g,rawDataIndex:m+2,isUDP:l===3}}function Yt(t){if(!t)return{earlyData:null,error:null};try{let e=t.replace(/-/g,"+").replace(/_/g,"/"),r=atob(e),n=new ArrayBuffer(r.length),a=new Uint8Array(n);for(let s=0;s<r.length;s++)a[s]=r.charCodeAt(s);return{earlyData:n,error:null}}catch(e){return{earlyData:null,error:e}}}function te(t){try{t&&t.readyState===1&&t.close()}catch{}}async function Jt(t,e){let r=t.sni&&t.sni!==""?t.sni:t.address,n=Number(t.port),a;try{a=globalThis.connect?globalThis.connect({hostname:r,port:n,secureTransport:t.tls?"on":"off"}):void 0}catch(i){return e(`[VLESS/raw] connect error: ${i.message}`),null}if(!a)return e("[VLESS/raw] connect unavailable"),null;let s=a.readable.getReader(),o,l=new Promise(i=>{o=i});return(a.closed||Promise.resolve()).then(o,o),{readable:new ReadableStream({start(i){(async()=>{try{for(;;){let{done:c,value:d}=await s.read();if(c)break;d&&d.byteLength>0&&i.enqueue(d)}try{i.close()}catch{}}catch(c){try{i.error(c)}catch{}}})()},cancel(){try{s.cancel()}catch{}}}),writable:a.writable,closed:l,send:async i=>{let c=a.writable.getWriter();try{await c.write(i)}finally{try{c.releaseLock()}catch{}}}}}function In(t,e){let r=new Uint8Array(t.length+e.length);return r.set(t,0),r.set(e,t.length),r}function Nn(t){for(let e=0;e+3<t.length;e++)if(t[e]===13&&t[e+1]===10&&t[e+2]===13&&t[e+3]===10)return e;return-1}function Hn(t){for(let e=0;e+1<t.length;e++)if(t[e]===13&&t[e+1]===10)return new TextDecoder().decode(t.slice(0,e));return""}async function Xt(t,e){let r=t.sni&&t.sni!==""?t.sni:t.address,n=Number(t.port),a;try{a=globalThis.connect?globalThis.connect({hostname:r,port:n,secureTransport:t.tls?"on":"off"}):void 0}catch(b){return e(`[VLESS/httpupgrade] connect error: ${b.message}`),null}if(!a)return e("[VLESS/httpupgrade] connect unavailable"),null;let o=`GET ${t.path&&t.path.startsWith("/")?t.path:`/${t.path||""}`} HTTP/1.1\r
Host: ${r}:${n}\r
Connection: Upgrade\r
Upgrade: websocket\r
\r
`,l=a.readable.getReader(),u,i=new Promise(b=>{u=b});(a.closed||Promise.resolve()).then(u,u);let c=new Uint8Array(0),d=new Uint8Array(0);try{await Promise.race([(async()=>{let b=a.writable.getWriter();try{await b.write(new TextEncoder().encode(o))}finally{try{b.releaseLock()}catch{}}for(;;){let{done:g,value:m}=await l.read();if(g)break;if(m&&m.byteLength>0){c=In(c,m);let f=Nn(c);if(f>=0){d=c.slice(f+4);return}}}throw new Error("connection closed during handshake")})(),new Promise((b,g)=>setTimeout(()=>g(new Error("Handshake timeout")),1e4))])}catch(b){e(`[VLESS/httpupgrade] handshake failed: ${b.message}`);try{a.close()}catch{}return null}let p=Hn(c);if(!/^HTTP\/1\.1 101/.test(p)){e(`[VLESS/httpupgrade] upgrade rejected: ${p}`);try{a.close()}catch{}return null}return{readable:new ReadableStream({start(b){d.byteLength>0&&b.enqueue(d),(async()=>{try{for(;;){let{done:g,value:m}=await l.read();if(g)break;m&&m.byteLength>0&&b.enqueue(m)}try{b.close()}catch{}}catch(g){try{b.error(g)}catch{}}})()},cancel(){try{l.cancel()}catch{}}}),writable:a.writable,closed:i,send:async b=>{let g=a.writable.getWriter();try{await g.write(b)}finally{try{g.releaseLock()}catch{}}}}}var zn=`PRI * HTTP/2.0\r
\r
SM\r
\r
`;var rt=new TextEncoder;function Fn(t,e){let r=rt.encode(t),n=rt.encode(e),a=new Uint8Array(2+r.length+1+n.length);return a[0]=0,a[1]=r.length,a.set(r,2),a[2+r.length]=n.length,a.set(n,3+r.length),a}function Bn(t){let e=new Uint8Array(0);for(let[r,n]of t)e=nt(e,Fn(r,n));return e}function ie(t,e,r,n){let a=n.length,s=new Uint8Array(9+a);return s[0]=a>>16&255,s[1]=a>>8&255,s[2]=a&255,s[3]=t,s[4]=e,s[5]=r>>24&127,s[6]=r>>16&255,s[7]=r>>8&255,s[8]=r&255,s.set(n,9),s}function Zt(t){let e=new Uint8Array(5+t.length);return e[0]=0,new DataView(e.buffer,e.byteOffset,5).setUint32(1,t.length,!1),e.set(t,5),e}function Qt(t){let e=new Uint8Array(4);return new DataView(e.buffer).setUint32(0,t>>>0,!1),e}function nt(t,e){let r=new Uint8Array(t.length+e.length);return r.set(t,0),r.set(e,t.length),r}function er(t,e){if(!t.buf){t.buf=new Uint8Array(Math.max(e.byteLength,4096)),t.buf.set(e,0),t.len=e.byteLength;return}let r=t.len+e.byteLength;if(r>t.buf.length){let n=new Uint8Array(Math.max(t.buf.length*2,r));n.set(t.buf.subarray(0,t.len),0),t.buf=n}t.buf.set(e,t.len),t.len=r}async function tr(t,e){let r=[],n=0;for(;n<e;){let{done:s,value:o}=await t.read();if(s)return null;!o||o.byteLength===0||(r.push(o),n+=o.byteLength)}let a;if(r.length===1)a=r[0];else{a=nt(r[0],r[1]);for(let s=2;s<r.length;s++)a=nt(a,r[s])}return a.byteLength>e?{data:a.slice(0,e),extra:a.slice(e)}:{data:a,extra:null}}async function rr(t,e){let r=t.sni&&t.sni!==""?t.sni:t.address,n=Number(t.port),a;try{a=globalThis.connect?globalThis.connect({hostname:r,port:n,secureTransport:t.tls?"on":"off"}):void 0}catch(g){return e(`[VLESS/grpc] connect error: ${g.message}`),null}if(!a)return e("[VLESS/grpc] connect unavailable"),null;let s=a.writable.getWriter();async function o(g){await s.write(g)}let l,u=new Promise(g=>{l=g});(a.closed||Promise.resolve()).then(l,l);try{await o(rt.encode(zn)),await o(ie(4,0,0,new Uint8Array(0)));let g=t.tls?"https":"http",m=(t.path||"").replace(/^\/+/,"").replace(/\/+$/,""),f=m?`/${m}/Tun`:"/Tun",y=Bn([[":method","POST"],[":scheme",g],[":path",f],[":authority",`${r}:${n}`],["content-type","application/grpc"],["te","trailers"],["user-agent","grpc-go/1.68.0"]]);await o(ie(1,4,1,y))}catch(g){e(`[VLESS/grpc] handshake failed: ${g.message}`);try{a.close()}catch{}return null}let i=a.readable.getReader(),c={needLen:5,buf:null,len:0,msgLen:0,controller:null,extra:null};function d(g,m){let f=g;for(;f.byteLength>0;)if(c.needLen>0){let y=Math.min(c.needLen,f.byteLength);er(c,f.subarray(0,y)),f=f.subarray(y),c.needLen-=y,c.needLen===0&&(c.len===5?(c.msgLen=new DataView(c.buf.buffer,c.buf.byteOffset,5).getUint32(1,!1),c.buf=null,c.len=0,c.needLen=c.msgLen,c.msgLen===0&&(c.needLen=5)):(c.buf=null,c.len=0,c.needLen=5))}else{let y=Math.min(c.msgLen,f.byteLength);if(er(c,f.subarray(0,y)),f=f.subarray(y),c.msgLen-=y,c.msgLen===0){if(c.len>0)try{m.enqueue(c.buf.subarray(0,c.len))}catch{}c.buf=null,c.len=0,c.needLen=5}}}let p=new ReadableStream({start(g){c.controller=g,(async()=>{try{for(;;){let m;if(c.extra)m=c.extra,c.extra=null;else{let f=await tr(i,9);if(!f)break;let y=f.data[0]<<16|f.data[1]<<8|f.data[2],x=f.data[3],v=f.data[4],w=(f.data[5]&127)<<24|f.data[6]<<16|f.data[7]<<8|f.data[8];if(y===0)m=new Uint8Array(0);else{let S=await tr(i,y);if(!S)break;m=S.data,c.extra=S.extra}if(x===0&&w===1){d(m,g),await o(ie(8,0,1,Qt(m.byteLength))),await o(ie(8,0,0,Qt(m.byteLength)));continue}if(x===4){v&1||await o(ie(4,1,0,new Uint8Array(0)));continue}if(x===6){v&1||await o(ie(6,1,w,m));continue}if(x===7||x===3)break}}try{g.close()}catch{}}catch(m){e(`[VLESS/grpc] read loop error: ${m.message}`);try{g.error(m)}catch{}}finally{try{l()}catch{}}})()},cancel(){try{i.cancel()}catch{}}});function h(g){let m=[],f=0,y=!0;for(;f<g.byteLength;){let x=Math.min(16384,g.byteLength-f);m.push(ie(0,0,1,g.slice(f,f+x))),f+=x,y=!1}return m}let b=new WritableStream({write(g){let m=g instanceof Uint8Array?g:new Uint8Array(g),f=Zt(m),y=h(f);return(async()=>{for(let x of y)await o(x)})()},close(){try{a.close()}catch{}},abort(){try{a.close()}catch{}}});return{readable:p,writable:b,closed:u,send:async g=>{let m=Zt(g);for(let f of h(m))await o(f)}}}var Gn=1e4;async function de(t,e,r,n,a,s,o){let l=t.transport||"ws";if(!_t.includes(l))return o(`[VLESS] unsupported transport: ${l}`),null;let u=null;try{l==="ws"?u=await Vn(t,o):l==="raw"?u=await Jt(t,o):l==="httpupgrade"?u=await Xt(t,o):l==="grpc"&&(u=await rr(t,o))}catch(p){return o(`[VLESS/${l}] connect failed: ${p.message}`),null}if(!u)return null;let i=Gt(e,r,n,a,t.uuid),c=s instanceof Uint8Array?s:new Uint8Array(s||0),d=new Uint8Array(i.length+c.length);d.set(i,0),d.set(c,i.length);try{await u.send(d)}catch(p){o(`[VLESS/${l}] send header failed: ${p.message}`);try{u.close&&await u.close()}catch{}return null}return{readable:u.readable,writable:u.writable,closed:u.closed}}async function Vn(t,e){let r=t.tls?"wss":"ws",n=t.path&&t.path.startsWith("/")?t.path:`/${t.path||""}`,a=t.sni&&t.sni!==""?t.sni:t.address,s=`${r}://${a}:${t.port}${n}`,o;try{o=new WebSocket(s),"binaryType"in o&&(o.binaryType="arraybuffer")}catch(p){return e(`[VLESS/ws] create ws failed: ${p.message}`),null}let l,u=new Promise(p=>{l=p});try{await new Promise((p,h)=>{let b=setTimeout(()=>h(new Error("Connection timeout")),Gn);o.addEventListener("open",()=>{clearTimeout(b),p()}),o.addEventListener("close",g=>{clearTimeout(b),h(new Error(`closed ${g.code}`))}),o.addEventListener("error",()=>{clearTimeout(b),h(new Error("ws error"))})})}catch(p){e(`[VLESS/ws] connect failed: ${p.message}`);try{o.close()}catch{}return l(),null}o.addEventListener("close",()=>l()),o.addEventListener("error",()=>{});let i=new WritableStream({write(p){o.readyState===1&&o.send(p)},close(){te(o)},abort(){te(o)}}),c=!1;return{readable:new ReadableStream({start(p){o.addEventListener("message",h=>{let b;try{h.data instanceof ArrayBuffer?b=new Uint8Array(h.data):ArrayBuffer.isView(h.data)?b=new Uint8Array(h.data.buffer,h.data.byteOffset,h.data.byteLength):typeof h.data=="string"?b=new TextEncoder().encode(h.data):b=null}catch{b=null}if(b){if(!c&&(c=!0,b.length>=2&&b[0]===0)){let g=b[1];if(b.length>2+g)b=b.slice(2+g);else return}if(b.length>0)try{p.enqueue(b)}catch{}}}),o.addEventListener("close",()=>{try{p.close()}catch{}}),o.addEventListener("error",h=>{try{p.error(h)}catch{}})},cancel(){te(o)}}),writable:i,closed:u,send:async p=>{if(o.readyState!==1)throw new Error(`ws not open (state=${o.readyState})`);o.send(p)}}}async function ye(t,e,r){for(;e.buf.length<r;){let{done:a,value:s}=await t.read();if(a)return null;if(!s||s.byteLength===0)continue;let o=new Uint8Array(e.buf.length+s.byteLength);o.set(e.buf,0),o.set(s,e.buf.length),e.buf=o}let n=e.buf.slice(0,r);return e.buf=e.buf.slice(r),n}async function nr(t,e,r,n,a,s){let{username:o,password:l,hostname:u,port:i}=a,c=s({hostname:u,port:i}),d=c.writable.getWriter(),p=c.readable.getReader(),h=new TextEncoder,b={buf:new Uint8Array(0)};try{await d.write(new Uint8Array([5,2,0,2]));let g=await ye(p,b,2);if(!g||g[0]!==5){n("socks version error");return}if(g[1]===255){n("no acceptable methods");return}if(g[1]===2){if(!o||!l){n("socks server requires auth but no credentials");return}let w=new Uint8Array([1,o.length,...h.encode(o),l.length,...h.encode(l)]);if(await d.write(w),g=await ye(p,b,2),!g||g[0]!==1||g[1]!==0){n("socks auth failed");return}}let m;switch(t){case 1:m=new Uint8Array([1,...e.split(".").map(Number)]);break;case 2:m=new Uint8Array([3,e.length,...h.encode(e)]);break;case 3:m=new Uint8Array([4,...et(e).split(":").flatMap(w=>[parseInt(w.slice(0,2),16),parseInt(w.slice(2),16)])]);break;default:n(`invalid addressType ${t}`);return}let f=new Uint8Array([5,1,0,...m,r>>8,r&255]);await d.write(f);let y=await ye(p,b,4);if(!y||y[0]!==5){n("socks version error");return}if(y[1]!==0){n(`socks connect failed rep=${y[1]}`);return}let x=0;switch(y[3]){case 1:x=6;break;case 3:x=3;break;case 4:x=18;break;default:n(`socks invalid ATYP ${y[3]}`);return}if(y[3]===3){let w=await ye(p,b,1);if(!w)return;x+=w[0]}if(!await ye(p,b,x))return;if(d.releaseLock(),b.buf.length>0){let w=b.buf.slice();return{readable:new ReadableStream({pull(L){if(w.length>0){let C=w;w=new Uint8Array(0),L.enqueue(C);return}return p.read().then(({done:C,value:A})=>{C?L.close():A&&A.byteLength>0&&L.enqueue(A)})},cancel(){try{p.cancel()}catch{}}}),writable:c.writable,closed:c.closed||Promise.resolve()}}return p.releaseLock(),c}catch(g){n(`socks5 error: ${g.message}`);try{d.releaseLock()}catch{}try{p.releaseLock()}catch{}try{c.close()}catch{}return}}function ar(t,e={}){let r=String(t||"").trim().replace(/^socks5?:\/\//i,""),[n,a]=r.split("@").reverse(),s,o,l,u;if(a){let c=a.split(":");if(c.length!==2)throw new Error("Invalid SOCKS address format");[s,o]=c}let i=n.split(":");if(u=Number(i[i.length-1]),isNaN(u))if(e&&e.port!==void 0&&e.port!==null&&e.port!=="")u=Number(e.port),l=n;else throw new Error("Invalid SOCKS address format");else l=i.slice(0,-1).join(":");if(isNaN(u)||!l)throw new Error("Invalid SOCKS address format");return e&&e.username!==void 0&&e.username!==null&&e.username!==""&&(s=e.username),e&&e.password!==void 0&&e.password!==null&&e.password!==""&&(o=e.password),{username:s,password:o,hostname:l,port:u}}async function sr(t,e,r,n,a,s,o=new Uint8Array(0)){let{username:l,password:u,hostname:i,port:c}=a,d=s({hostname:i,port:c}),p=d.writable.getWriter(),h=d.readable.getReader();try{let b=l&&u?`Proxy-Authorization: Basic ${btoa(`${l}:${u}`)}\r
`:"",g=`CONNECT ${e}:${r} HTTP/1.1\r
Host: ${e}:${r}\r
${b}User-Agent: Mozilla/5.0\r
Connection: keep-alive\r
\r
`;await p.write(new TextEncoder().encode(g));let m=new Uint8Array(0),f=-1,y=0;for(;f===-1&&y<8192;){let{done:S,value:L}=await h.read();if(S)throw new Error("Connection closed before HTTP response");let C=new Uint8Array(m.length+L.length);C.set(m,0),C.set(L,m.length),m=C,y=m.length;for(let A=0;A<m.length-3;A++)if(m[A]===13&&m[A+1]===10&&m[A+2]===13&&m[A+3]===10){f=A+4;break}}if(f===-1)throw new Error("Invalid HTTP response");let v=new TextDecoder().decode(m.slice(0,f)).split(`\r
`)[0].match(/HTTP\/\d\.\d\s+(\d+)/);if(!v)throw new Error("Invalid HTTP response format");let w=parseInt(v[1]);if(w<200||w>=300)throw new Error(`HTTP CONNECT failed: HTTP ${w}`);return o.length>0&&await p.write(o),p.releaseLock(),h.releaseLock(),d}catch(b){n(`http connect error: ${b.message}`);try{p.releaseLock()}catch{}try{h.releaseLock()}catch{}try{d.close()}catch{}return}}function or(t,e={}){let[r,n]=String(t||"").trim().split("@").reverse(),a,s,o,l;if(n){let i=n.split(":");if(i.length!==2)throw new Error("Invalid HTTP address format");[a,s]=i}let u=r.split(":");if(l=Number(u[u.length-1]),isNaN(l))if(e&&e.port!==void 0&&e.port!==null&&e.port!=="")l=Number(e.port),o=r;else throw new Error("Invalid HTTP address format");else o=u.slice(0,-1).join(":");if(isNaN(l)||!o)throw new Error("Invalid HTTP address format");return e&&e.username!==void 0&&e.username!==null&&e.username!==""&&(a=e.username),e&&e.password!==void 0&&e.password!==null&&e.password!==""&&(s=e.password),{username:a,password:s,hostname:o,port:l}}var Wn=3e5,ir=new Map,Kn=45e3,we=new Map,qn=5e3,Yn=5e3,lr=new Map,Jn=["https://8.8.8.8/resolve","https://8.8.4.4/resolve","https://doh.pub/resolve","https://dns.alidns.com/resolve"];async function X(t,e,r="A",n=2500){let a=`${r}:${t}`,s=ir.get(a);if(s&&Date.now()-s.ts<Wn)return s.ip;let o=we.get(a);if(o&&Date.now()-o<Kn)return null;let l=r==="AAAA"?28:1,u=r==="AAAA"?/^[0-9a-fA-F:]+$/:/^\d{1,3}(\.\d{1,3}){3}$/,i=[],c=Jn.map(h=>{let b=new AbortController;i.push(b);let g=setTimeout(()=>b.abort(),n);return(async()=>{try{let m=`${h}?name=${encodeURIComponent(t)}&type=${r}`,f=await fetch(m,{headers:{accept:"application/dns-json"},signal:b.signal});if(f.ok){let y=await f.json(),v=(Array.isArray(y.Answer)?y.Answer:[]).find(w=>w.type===l&&u.test(w.data))?.data;if(v){for(let w of i)w!==b&&w.abort();return v}}}catch{}finally{clearTimeout(g)}return null})()}),p=(await Promise.all(c)).find(h=>h)||null;return p?(ir.set(a,{ip:p,ts:Date.now()}),we.delete(a)):(we.size>=qn&&we.clear(),we.set(a,Date.now()),e(`doh resolve failed: ${t} (${r})`)),p}var Xn=["173.245.48.0/20","103.21.244.0/22","103.22.200.0/22","103.31.4.0/22","141.101.64.0/18","108.162.192.0/18","190.93.240.0/20","188.114.96.0/20","197.234.240.0/22","198.41.128.0/17","162.158.0.0/15","104.16.0.0/13","104.24.0.0/14","172.64.0.0/13","131.0.72.0/22","1.0.0.0/24","1.1.1.0/24"].map(t=>{let[e,r]=t.split("/"),n=Number(r),a=n===0?0:4294967295<<32-n>>>0,s=e.split(".");return[(+s[0]<<24)+(+s[1]<<16)+(+s[2]<<8)+ +s[3]>>>0&a,a]});function Zn(t){let e=t.split(".");return(+e[0]<<24)+(+e[1]<<16)+(+e[2]<<8)+ +e[3]>>>0}function xe(t){if(!/^\d{1,3}(\.\d{1,3}){3}$/.test(t))return!1;let e=Zn(t);return Xn.some(([r,n])=>(e&n)===r)}var Qn=[".cloudflare.com",".cloudflare.net",".jsdelivr.net",".workers.dev",".pages.dev",".trycloudflare.com",".cf-ipfs.com",".cloudflareinsights.com"];function st(t){let e=t.toLowerCase();return Qn.some(r=>e===r.slice(1)||e.endsWith(r))}var ur=6e4,Z={state:"unknown",downAt:0},re=new WeakMap;function le(t){Z.state!=="down"&&(Z.state="down",Z.downAt=Date.now(),t("proxyip marked down (no response), degrade to direct for 60s"))}function ea(t){Z.state==="down"&&Date.now()-Z.downAt>=ur&&(Z.state="unknown",t("proxyip health reset to unknown, will retry proxyip"))}function dr(){return Z.state==="down"&&Date.now()-Z.downAt<ur}function ot(t){if(!t.proxyipOutbound)return null;let e=ae(t,t.proxyipOutbound);return!e||typeof e=="string"||e.type!==Ye&&e.type!==Ke&&e.type!==qe?null:e}async function pr(t,e,r,n,a){let s=ot(t);if(!s)return null;let o=/^\d{1,3}(\.\d{1,3}){3}$/.test(e)?1:e.includes(":")?3:2;a(`direct ${e}:${r} -> retry via outbound ${s.name}`);let l=await ne({config:t,outbound:s,addressType:o,addressRemote:e,portRemote:r,rawClientData:n||new Uint8Array(0),log:a,isUDP:!1});return l?(re.set(l,{usedProxyIp:!0}),l):null}async function fr(t,e,r,n,a){if(ot(t)){let c=await pr(t,e,r,n,a);return c||le(a),c}let o=t.proxyipHost,l=Number(t.proxyipPort||443);if(!o)return null;a(`direct ${e}:${r} -> retry via proxyip ${o}:${l}`);let u=await F(o,l,a);if(!u)return le(a),null;let i=await it(u,n,a);return i?(re.set(i,{usedProxyIp:!0}),i):(le(a),null)}async function at(t,e,r,n,a,s,o){let l=await ta(t,e,r,n,a,o);if(!l)return o(`connect unavailable (${e}:${r})`),null;let u=await it(l,s,o);return u&&re.set(u,{usedProxyIp:!1}),u}async function F(t,e,r){let n;try{n=globalThis.connect?globalThis.connect({hostname:t,port:e}):void 0,n&&typeof n.then=="function"&&(n=await n)}catch(a){return r(`direct connect error: ${a.message}`),null}return n||null}async function ta(t,e,r,n,a,s){let o=(()=>{let l=Date.now(),u=lr.get(e);return u&&l-u<Yn?()=>{}:(lr.set(e,l),s)})();if(!n&&!a){let l=t.ipPreference||"ipv4";if(l==="ipv4"){let d=await X(e,s,"A",1200);if(d){o(`direct ${e}:${r} -> ipv4 ${d}:${r}`);let b=await F(d,r,s);if(b)return b}o(`direct ${e}:${r} -> native dns ${e}:${r}`);let p=await F(e,r,s);if(p)return p;let h=await X(e,s,"AAAA");if(h){let b=`[${h}]`;if(s(`direct ${e}:${r} -> doh aaaa fallback ${b}:${r}`),p=await F(b,r,s),p)return p}return null}if(l==="ipv6"){let d=await X(e,s,"AAAA",1200);if(d){let b=`[${d}]`;s(`direct ${e}:${r} -> ipv6 ${b}:${r}`);let g=await F(b,r,s);if(g)return g}o(`direct ${e}:${r} -> native dns ${e}:${r}`);let p=await F(e,r,s);if(p)return p;let h=await X(e,s,"A");return h&&(s(`direct ${e}:${r} -> doh a fallback ${h}:${r}`),p=await F(h,r,s),p)?p:null}o(`direct ${e}:${r} -> native dns ${e}:${r}`);let u=await F(e,r,s);if(u)return u;let i=await X(e,s);if(i&&(s(`direct ${e}:${r} -> doh fallback ${i}:${r}`),u=await F(i,r,s),u))return u;let c=await X(e,s,"AAAA");if(c){let d=`[${c}]`;if(s(`direct ${e}:${r} -> doh aaaa fallback ${d}:${r}`),u=await F(d,r,s),u)return u}return null}return F(e,r,s)}async function it(t,e,r){if(e&&e.length>0){let n=t.writable.getWriter();try{await n.write(e)}catch(a){r(`direct initial write error: ${a.message}`)}finally{try{n.releaseLock()}catch{}}}return t}async function cr(t,e,r,n,a){let s=(t.proxyipHost||t.proxyipOutbound)&&!t.proxyipDisabled,o=/^\d{1,3}(\.\d{1,3}){3}$/.test(e)||e.includes(":");ea(a);let l=s&&Z.state==="down",u=!o&&st(e),i=o&&!e.includes(":")&&xe(e),c=!1;if(s&&!l&&!o&&!u){let d=null,p=await Promise.race([X(e,a,"A",800),new Promise(h=>{d=setTimeout(()=>h(null),150)})]);clearTimeout(d),p&&xe(p)&&(c=!0)}if(s&&!l&&(u||i||c)){let d=ot(t);if(d){let m=await pr(t,e,r,n,a);return m||(le(a),a(`proxyip outbound ${d.name} failed; degrade to direct ${e}:${r}`),at(t,e,r,o,u||c,n,a))}let p=t.proxyipHost,h=Number(t.proxyipPort||443),b=await F(p,h,a);if(!b)return le(a),a(`proxyip ${p}:${h} connect failed; degrade to direct ${e}:${r}`),at(t,e,r,o,u||c,n,a);let g=await it(b,n,a);return g&&re.set(g,{usedProxyIp:!0}),g}return at(t,e,r,o,u||c,n,a)}async function ne(t){let{config:e,outbound:r,addressType:n,addressRemote:a,portRemote:s,rawClientData:o,log:l,isUDP:u}=t,i=r;if(!i||i===K)return cr(e,a,s,o,l);if(i===ce)return l("rejected by routing rule"),null;switch(i.type){case K:return cr(e,a,s,o,l);case Ke:{let c;try{c=ar(i.address,{username:i.username,password:i.password,port:i.port})}catch(p){return l(`bad socks5 address: ${p.message}`),null}let d=await nr(n,a,s,l,c,globalThis.connect);if(!d)return null;if(o&&o.length>0){let p=d.writable.getWriter();try{await p.write(o)}catch(h){l(`socks5 write error: ${h.message}`)}finally{try{p.releaseLock()}catch{}}}return d}case qe:{let c;try{c=or(i.address,{username:i.username,password:i.password,port:i.port})}catch(p){return l(`bad http address: ${p.message}`),null}return await sr(n,a,s,l,c,globalThis.connect,o||new Uint8Array(0))}case Ye:return de({address:i.address,port:Number(i.port),uuid:i.uuid,path:i.path,tls:!!i.tls,sni:i.sni||"",transport:i.transport},u?2:1,n,a,s,o||new Uint8Array(0),l);default:return l(`unknown outbound type: ${i.type}`),null}}function ae(t,e){return!e||e===K?K:e===ce?ce:t.outboundByName[e]||K}function ve(t){let e=new Uint8Array(2+t.length);return e[0]=t.length>>8,e[1]=t.length&255,e.set(t,2),e}async function hr(t,e,r){let n=t.getReader(),a=new Uint8Array(0),s=0,o=0;try{for(;;){let{done:l,value:u}=await n.read();if(l)break;if(!(!u||u.byteLength===0)){if(o+u.byteLength>a.length){let i=o-s+u.byteLength,c=new Uint8Array(Math.max(a.length*2||4096,i));c.set(a.subarray(s,o),0),a=c,o-=s,s=0}else s>0&&(a.copyWithin(0,s,o),o-=s,s=0);for(a.set(u,o),o+=u.byteLength;!(o-s<2);){let i=a[s]<<8|a[s+1];if(i===0){s+=2;continue}if(o-s<2+i)break;let c=a.slice(s+2,s+2+i);s+=2+i;try{await e(c)}catch(d){r(`udp frame handler error: ${d.message}`)}}}}}catch(l){r(`readUdpFrames error: ${l.message}`)}finally{try{n.releaseLock()}catch{}}}var ra=3600*1e3,lt=new Map;async function ct(t,e,r){let n=`${e}:${r}`,a=lt.get(n);if(a&&Date.now()-a.ts<ra)return a.data;let s=null;try{let o=e==="geosite"?Lt:$t,l=await t.GEO_KV.get(o+r);if(l){let u=JSON.parse(l);Array.isArray(u)&&(s=u)}}catch{}return s||(s=na(e,r)),e==="geosite"&&Array.isArray(s)&&(s=s.map(o=>o.toLowerCase())),lt.set(n,{data:s,ts:Date.now()}),s}function na(t,e){if(t==="geosite")switch(e){case"cn":return Ut;case"speedtest":return Ot;case"google":return Ct;default:return[]}return[]}function mr(){lt.clear()}var Te=new Map,aa=512;function sa(t){if(!t)return null;let e=String(t).trim();if(!e)return null;if(Te.has(e))return Te.get(e);let r=oa(e);return r&&r.value&&(r._lcValue=r.value.toLowerCase()),Te.size>=aa&&Te.clear(),Te.set(e,r),r}function oa(t){let e=t.match(/^geosite:(.+)$/i);if(e){let u=e[1].split(",").map(i=>i.trim()).filter(Boolean);return u.length===0?null:{type:"geosite",categories:u}}let r=t.match(/^geoip:(.+)$/i);if(r){let u=r[1].split(",").map(i=>i.trim()).filter(Boolean);return u.length===0?null:{type:"geoip",categories:u}}let n=t.match(/^domain:(.+)$/i);if(n)return{type:"domain",value:n[1].trim()};let a=t.match(/^full:(.+)$/i);if(a)return{type:"full",value:a[1].trim()};let s=t.match(/^keyword:(.+)$/i);if(s)return{type:"keyword",value:s[1].trim()};let o=t.match(/^ip-cidr:(.+)$/i);if(o)return{type:"ip-cidr",value:o[1].trim()};let l=t.match(/^regexp:(.+)$/i);return l?{type:"regexp",value:l[1].trim()}:{type:"domain",value:t}}function gr(t){let e=t.split(".");if(e.length!==4)return null;let r=0;for(let n of e){let a=Number(n);if(isNaN(a)||a<0||a>255)return null;r=r<<8|a}return r>>>0}function br(t){let e=String(t).replace(/^\[|\]$/g,""),r=e.indexOf("::"),n,a;if(r>=0?(n=r===0?[]:e.slice(0,r).split(":"),a=r===e.length-2?[]:e.slice(r+2).split(":")):(n=e.split(":"),a=[]),n.length+a.length>8)return null;let s=8-n.length-a.length,o=[...n,...Array(s).fill("0"),...a],l=0n;for(let u of o){if(!u)return null;let i=parseInt(u,16);if(isNaN(i))return null;l=l<<16n|BigInt(i)}return l}function yr(t,e){let r=e.indexOf("/"),n=r>=0?e.slice(0,r):e,a=t.includes(":")?128:32,s=r>=0?Number(e.slice(r+1)):a;if(t.includes(":")){let i=br(t),c=br(n);if(i===null||c===null||isNaN(s)||s<0||s>128)return!1;let d=s===0?0n:(1n<<128n)-1n^(1n<<BigInt(128-s))-1n;return(i&d)===(c&d)}let o=gr(t);if(o===null)return!1;let l=gr(n);if(l===null)return!1;let u=s<=0?0:4294967295<<32-s>>>0;return(o&u)===(l&u)}function wr(t,e){return t===e?!0:t.endsWith(e)}var xr=new Map;function ia(t){let e=xr.get(t);if(!e){try{e=new RegExp(t)}catch{e=null}xr.set(t,e)}return e}async function la(t,e,r,n){let a=r?"":e.toLowerCase();switch(t.type){case"domain":return r?!1:wr(a,t._lcValue);case"full":return r?!1:a===t._lcValue;case"keyword":return r?!1:a.includes(t._lcValue);case"regexp":{if(r)return!1;let s=ia(t.value);return s?s.test(e):!1}case"ip-cidr":return r?yr(e,t.value):!1;case"geosite":{if(r)return!1;for(let s of t.categories){let o=await ct(n,"geosite",s);for(let l of o)if(wr(a,l))return!0}return!1}case"geoip":{if(!r)return!1;for(let s of t.categories){let o=await ct(n,"geoip",s);for(let l of o)if(yr(e,l))return!0}return!1}default:return!1}}var ca=6e4,ua=1e4,He=new Map;async function ke(t,e,r){let n=`${e}:${r.toLowerCase()}`,a=He.get(n);if(a&&Date.now()-a.ts<ca)return{outbound:a.outbound,rule:a.rule};let s=e===1||e===3,o=t.defaultOutbound||"direct",l=null;for(let u of t.routingRules){let i=sa(u.rule);if(!i)continue;if(await la(i,r,s,t.env)){o=u.outbound||"direct",l=u;break}}return He.size>=ua&&He.clear(),He.set(n,{outbound:o,rule:l,ts:Date.now()}),{outbound:o,rule:l}}var kr=new Uint8Array([0,0]),da=15e3,pa=5e3,Ee=new Set,ze=null;function fa(t){Ee.add(t),ze||(ze=setInterval(()=>{let e=Date.now();for(let r of Ee){if(r.isClosed()){Ee.delete(r);continue}e-r.lastActivity()>=da&&r.beat(e)}Ee.size===0&&(clearInterval(ze),ze=null)},pa))}function ha(t){Ee.delete(t)}var vr=8*1024,ma=15,Tr=32*1024,ga=15,ba=2*1024*1024,ya=100,wa=300;async function Se(t,e,r,n){let a;try{a=await n.read()}catch(f){r(`read first packet error: ${f.message}`);try{await n.close()}catch{}return}if(!a){try{await n.close()}catch{}return}let s,o=null,l="vless",u=t._inboundScope||null,i=u&&!u.all?u.vless:t.uuidSet,c=u&&!u.all?u.trojan:t.passwordSet;if(Kt(a)){if(s=await qt(a,c),s.hasError){r(`trojan header error: ${s.message}`);try{await n.close()}catch{}return}l="trojan",o=t.trojanIndex[s.userPassword]||null}else{if(s=jt(a,i),s.hasError){r(`vless header error: ${s.message}`);try{await n.close()}catch{}return}try{await n.write(kr)}catch{}o=t.vlessIndex[s.userUuid]||null}if(o){let f=Math.floor(Date.now()/1e3);if(o.expire_at>0&&o.expire_at<f){r(`${l} user '${o.remark||o.uuid||o.password}' expired`);try{await n.close()}catch{}return}if(o.traffic_limit>0&&Number(o.up)+Number(o.down)>=Number(o.traffic_limit)){r(`${l} user '${o.remark||o.uuid||o.password}' traffic limit reached`);try{await n.close()}catch{}return}}let{addressType:d,addressRemote:p,portRemote:h,isUDP:b}=s,g=(a instanceof Uint8Array?a:new Uint8Array(a)).subarray(s.rawDataIndex),m;try{m=await ke(t,d,p)}catch(f){r(`route error: ${f.message}`);try{await n.close()}catch{}return}b?await va(n,t,d,p,h,g,o,l,m,r):await xa(n,t,d,p,h,g,o,l,m,r)}async function xa(t,e,r,n,a,s,o,l,u,i){let c=ae(e,u.outbound),d=s&&s.length>0?s:new Uint8Array(0),p=[c];c!=="direct"&&c!=="reject"&&p.push("direct");let h=null,b=null;for(let k of p){try{h=await ne({config:e,outbound:k,addressType:r,addressRemote:n,portRemote:a,rawClientData:d,log:i})}catch($){b=$,h=null}if(h)break}if(!h){i(`tcp connect failed: ${b?b.message:"no outbound available"}`);try{await t.close()}catch{}return}let g=0,m=0,f=!1,y=Date.now(),x=0,v=Date.now(),w={isClosed:()=>f,lastActivity:()=>v,beat:k=>{v=k,t.write(kr).catch(()=>{})}};fa(w);let S=5e3,L=re.get(h)||null,C=!1,A=h.writable.getWriter(),M=async()=>{if(C)return null;C=!0;let k=(!!e.proxyipHost||!!e.proxyipOutbound)&&!e.proxyipDisabled;try{await h.close()}catch{}if(L&&L.usedProxyIp){le(i),i(`proxyip ${n}:${a} no first packet, degrade to direct retry`);try{return await ne({config:e,outbound:"direct",addressType:r,addressRemote:n,portRemote:a,rawClientData:d,log:i})||null}catch($){return i(`direct retry error: ${$.message}`),null}}if(!k||a!==443)return null;i(`direct ${n}:${a} no first packet, retry via proxyip`);try{return await fr(e,n,a,d,i)}catch($){return i(`proxyip retry error: ${$.message}`),null}},T=(async()=>{let k=null,$=0,U=null,D=()=>{U||(U=setTimeout(()=>{if(U=null,$>0){let R=k.subarray(0,$);k=null,$=0,A.write(R).catch(()=>{})}},ma))},_=async()=>{U&&(clearTimeout(U),U=null),$>0&&(await A.write(k.subarray(0,$)),k=null,$=0)};try{for(;;){let R=await t.read();if(R==null)break;if(R.byteLength===0)continue;g+=R.byteLength,v=Date.now();let N=Date.now();if(N-y>ya&&(x=N+wa),y=N,N<x||R.byteLength>=vr){await _(),await A.write(R);continue}let I=$+R.byteLength;if(!k)k=new Uint8Array(Math.max(I,4096));else if(I>k.length){let ee=new Uint8Array(Math.max(k.length*2,I));ee.set(k.subarray(0,$),0),k=ee}k.set(R,$),$=I,$>=vr?await _():D()}await _()}catch(R){i(`upstream read error: ${R.message}`)}})();try{let k=h.readable.getReader(),$=!1;for(;;){if(!$&&!C){let H=null,P=k.read().then(W=>({tag:"read",...W})),Y=new Promise(W=>{H=setTimeout(()=>W({tag:"timeout"}),S)}),z=await Promise.race([P,Y]);if(clearTimeout(H),z.tag==="timeout"){let W=await M();if(!W)break;try{A.releaseLock()}catch{}h=W,A=h.writable.getWriter(),L=re.get(h)||null,k=h.readable.getReader(),$=!1;continue}if(z.done)break;z.value&&z.value.byteLength>0&&($=!0,m+=z.value.byteLength,v=Date.now(),await t.write(z.value));continue}let U=null,D=0,_=null,R=()=>{_||(_=setTimeout(()=>{if(_=null,D>0){let H=U.subarray(0,D);U=null,D=0,t.write(H).catch(()=>{})}},ga))},N=async()=>{_&&(clearTimeout(_),_=null),D>0&&(await t.write(U.subarray(0,D)),U=null,D=0)},I=H=>{let P=D+H.byteLength;if(!U)U=new Uint8Array(Math.max(P,4096));else if(P>U.length){let Y=new Uint8Array(Math.max(U.length*2,P));Y.set(U.subarray(0,D),0),U=Y}U.set(H,D),D=P},ee=0,De=!1;for(;;){ee>=ba&&(ee=0,await new Promise(Y=>setTimeout(Y,0)));let{done:H,value:P}=await k.read();if(H){await N(),De=!0;break}if(!(!P||P.byteLength===0)){if($=!0,m+=P.byteLength,ee+=P.byteLength,v=Date.now(),Date.now()<x){await N(),await t.write(P);continue}D+P.byteLength<=Tr?(I(P),D>=Tr?await N():R()):(await N(),await t.write(P))}}if(De)break}}catch(k){if(!C&&m===0){i(`tcp remote read error before first packet: ${k.message||k}`);let $=await M();if($){try{A.releaseLock()}catch{}h=$,A=h.writable.getWriter(),L=re.get(h)||null,C=!0;let U=h.readable.getReader();try{for(;;){let{done:D,value:_}=await U.read();if(D)break;_&&_.byteLength>0&&(m+=_.byteLength,v=Date.now(),await t.write(_))}}catch(D){i(`fallback remote read error: ${D.message||D}`)}}}else i(`tcp remote read error: ${k.message||k}`)}f=!0,ha(w);try{A.releaseLock()}catch{}try{await h.writable.close()}catch{}try{await t.close()}catch{}await T.catch(()=>{}),Ar(e,o,l,g,m,i)}async function va(t,e,r,n,a,s,o,l,u,i){let c=null,d=(e.udpOutbound||"").trim();if(d){let T=e.outboundByName[d];if(T&&T.type==="vless")c=T;else{i(`udp outbound '${d}' not found or not vless (only vless supports udp)`);try{await t.close()}catch{}return}}else{if(u.outbound&&u.outbound!=="direct"&&u.outbound!=="reject"){let T=ae(e,u.outbound);T!=="direct"&&T!=="reject"&&T.type==="vless"&&(c=T)}c||(c=e.outbounds.find(T=>T.type==="vless"))}if(!c){i("udp requires a vless outbound, none configured");try{await t.close()}catch{}return}let h=(c.transport||"ws").trim().toLowerCase()==="raw",b=s&&s.length>0,g=h?b?ve(s):new Uint8Array([0,0]):b?s:new Uint8Array(0),m=await de({address:c.address,port:Number(c.port),uuid:c.uuid,path:c.path,tls:!!c.tls,sni:c.sni||"",transport:c.transport||"ws"},2,r,n,a,g,i);if(!m){i("udp vless outbound connect failed");try{await t.close()}catch{}return}let f=0,y=0,x=!1,v=null,w=m.writable.getWriter(),S=3e5,L=Date.now(),C=setInterval(()=>{x||Date.now()-L>=S&&(i(`udp session idle ${S}ms, closing`),A())},15e3),A=()=>{if(!x){x=!0,clearInterval(C);try{w.releaseLock()}catch{}try{m.writable.close().catch(()=>{})}catch{}try{v&&v.cancel().catch(()=>{})}catch{}try{t.close()}catch{}}},M=(async()=>{try{for(;;){let T=await t.read();if(T==null)break;T.byteLength!==0&&(f+=T.byteLength,L=Date.now(),await w.write(h?ve(T):T))}}catch(T){i(`udp upstream read error: ${T.message}`)}A()})();try{v=m.readable.getReader();let T=null,k=0;for(;;){let{done:$,value:U}=await v.read();if($||x)break;if(h){if(!U||U.byteLength===0)continue;let D=k+U.byteLength;if(!T)T=new Uint8Array(Math.max(D,4096));else if(D>T.length){let R=new Uint8Array(Math.max(T.length*2,D));R.set(T.subarray(0,k),0),T=R}T.set(U,k),k=D;let _=0;for(;!(k-_<2);){let R=T[_]<<8|T[_+1];if(R===0){_+=2;continue}if(k-_<2+R)break;let N=T.slice(_+2,_+2+R);if(_+=2+R,x)break;y+=N.length,L=Date.now();try{await t.write(N)}catch{}}_>0&&(T.copyWithin(0,_,k),k-=_)}else U&&U.byteLength>0&&(y+=U.byteLength,L=Date.now(),await t.write(U))}}catch(T){i(`udp read error: ${T.message}`)}A(),await M.catch(()=>{}),Ar(e,o,l,f,y,i)}var Ta=2e3,ka=32,se=new Map,ut=null;async function Er(t){if(!se.size)return;let e=[...se.entries()];se.clear();try{let r=e.map(([n,a])=>{let s=n.lastIndexOf(":"),o=n.slice(0,s),l=Number(n.slice(s+1));return t.prepare(`UPDATE ${o} SET up = up + ?, down = down + ? WHERE id = ?`).bind(a.up,a.down,l)});await t.batch(r)}catch{for(let[n,a]of e){let s=se.get(n);s?(s.up+=a.up,s.down+=a.down):se.set(n,a)}Sr(t)}}function Sr(t){ut||(ut=setTimeout(()=>{ut=null,Er(t)},Ta))}async function Ar(t,e,r,n,a,s){if(!e)return;let l=`${r==="vless"?"vless_users":"trojan_users"}:${e.id}`,u=se.get(l);if(u?(u.up+=n,u.down+=a):se.set(l,{up:n,down:a}),Sr(t.env.DB),se.size>=ka)try{await Er(t.env.DB)}catch(i){s(`record traffic error: ${i.message}`)}}var Ea=Promise.resolve();function Sa(t){return t instanceof ArrayBuffer?new Uint8Array(t):ArrayBuffer.isView(t)?new Uint8Array(t.buffer,t.byteOffset,t.byteLength):typeof t=="string"?new TextEncoder().encode(t):Object.prototype.toString.call(t)==="[object ArrayBuffer]"?new Uint8Array(t):null}function Aa(t,e){let r=null,n=t.url.indexOf("?");if(n>=0){let o=t.url.slice(n+1).match(/(?:^|&)ed=([^&#]*)/);if(o)try{r=decodeURIComponent(o[1])}catch{r=o[1]}}let a=r==="2560",s=t.headers.get("sec-websocket-protocol")||"";if(s){s.startsWith("base64,")&&(s=s.slice(7));let{earlyData:o,error:l}=Yt(s);if(l)return e(`early data decode error: ${l.message||l}`),null;if(o&&o.byteLength>0)return a||e(`early data injected: ${o.byteLength} B (ed=${r||"n/a"})`),new Uint8Array(o)}return r&&!a&&e(`ed=${r} declared but no sec-websocket-protocol payload`),null}async function _r(t,e,r){let n=t.headers.get("Upgrade");if(!n||n.toLowerCase()!=="websocket")return new Response("Expected WebSocket",{status:400});let[a,s]=Object.values(new WebSocketPair);s.accept(),s.binaryType="arraybuffer";let o=(...u)=>console.log("[ws]",...u),l=Aa(t,o);return Se(e,r,o,_a(s,o,l)).catch(u=>{o(`ws handler error: ${u.message||u}`),te(s)}),new Response(null,{status:101,webSocket:a})}function _a(t,e,r=null){let n=[],a=[],s=!1;r&&r.byteLength>0?n.push(r):setTimeout(()=>{!s&&n.length===0&&a.length>0&&(e("first packet timeout: no ws message within 6s"),te(t))},6e3);let o=async i=>{let c=i.data;typeof Blob<"u"&&c instanceof Blob&&(c=await c.arrayBuffer());let d=Sa(c);if(!d||d.byteLength===0){e(`message dropped: type=${Object.prototype.toString.call(i.data)} len=${c&&c.byteLength!=null?c.byteLength:c&&c.length!=null?c.length:"n/a"}`);return}let p=a.shift();p?p(d):n.push(d)},l=()=>{if(!s)for(s=!0;a.length;)a.shift()(null)},u=()=>l();return t.addEventListener("message",o),t.addEventListener("close",l),t.addEventListener("error",u),{read(){return n.length?Promise.resolve(n.shift()):s?Promise.resolve(null):new Promise(i=>a.push(i))},write(i){if(t.readyState===1)try{t.send(i)}catch{}return Ea},close(){te(t)}}}function $r(t,e){if(!t.buf){t.buf=new Uint8Array(Math.max(e.byteLength,4096)),t.buf.set(e,0),t.len=e.byteLength;return}let r=t.len+e.byteLength;if(r>t.buf.length){let n=new Uint8Array(Math.max(t.buf.length*2,r));n.set(t.buf.subarray(0,t.len),0),t.buf=n}t.buf.set(e,t.len),t.len=r}function La(t){let e=t.byteLength;if(e>=512)return e;if(e>=1&&t[0]===0){if(e<18)return null;let n=18+t[17];if(e<n+4)return null;let a=t[n+3],s;if(a===1)s=4;else if(a===2){if(e<n+5)return null;s=t[n+4]+1}else if(a===3)s=16;else return n+4;return n+4+s}if(e>=60&&t[56]===13&&t[57]===10){if(e<60)return null;let r=t[58];if(r!==1&&r!==3)return 60;let a=t[59]===13&&t[60]===10?61:59;if(e<a+1)return null;let s=t[a],o;if(s===1)o=4;else if(s===3){if(e<a+2)return null;o=t[a+1]+1}else if(s===4)o=16;else return a+1;return a+1+o+2+2}return e<60?null:e}function $a(t){let e=t.length,r=1;for(let o=e>>>7;o>0;o>>>=7)r++;let n=new Uint8Array(6+r+e);n[0]=0,n[1]=1+r+e>>>24&255,n[2]=1+r+e>>>16&255,n[3]=1+r+e>>>8&255,n[4]=1+r+e&255,n[5]=10;let a=6,s=e;for(;;){let o=s&127;if(s>>>=7,s>0&&(o|=128),n[a++]=o,s===0)break}return n.set(t,a),n}function Lr(t){if(t.length<2||t[0]!==10)return t;let e=0,r=0,n=1;for(;n<t.length&&r<35;n++){let s=t[n];if(e|=(s&127)<<r,(s&128)===0)break;r+=7}if(n>=t.length||(t[n]&128)!==0)return t;let a=n+1;return t.length-a<e?t:t.slice(a,a+e)}async function Ur(t,e,r){let n=(...i)=>console.log("[xhttp-in]",...i);if(!t.body)return new Response("Bad Request",{status:400});let a=t.body.getReader(),{readable:s,writable:o}=new TransformStream,l=o.getWriter(),u={firstReadDone:!1,read:async()=>{if(!u.firstReadDone){u.firstReadDone=!0;let d={buf:null,len:0};for(;;){let{done:p,value:h}=await a.read();if(p)return d.len>0?d.buf.subarray(0,d.len):null;$r(d,h instanceof Uint8Array?h:new Uint8Array(h));let b=La(d.buf.subarray(0,d.len));if(b!==null&&d.len>=b)return d.buf.subarray(0,d.len)}}let{done:i,value:c}=await a.read();return i?null:!c||c.byteLength===0?new Uint8Array(0):c instanceof Uint8Array?c:new Uint8Array(c)},write:i=>l.write(i),close:async()=>{try{await a.cancel()}catch{}try{await l.close()}catch{}}};return Se(e,r,n,u).catch(i=>{n(`xhttp handler error: ${i.message||i}`),a.cancel().catch(()=>{}),l.close().catch(()=>{})}),new Response(s,{status:200,headers:{"Content-Type":"text/event-stream","Cache-Control":"no-store","X-Accel-Buffering":"no"}})}async function Or(t,e,r){let n=(...c)=>console.log("[grpc-in]",...c);if(!t.body)return new Response("Bad Request",{status:400});let a=t.body.getReader(),{readable:s,writable:o}=new TransformStream,l=o.getWriter(),u={buf:null,len:0};return Se(e,r,n,{read:async()=>{for(;;){if(u.len>=5){let p=u.buf[1]<<24|u.buf[2]<<16|u.buf[3]<<8|u.buf[4];if(u.len>=5+p){let h=u.buf.slice(5,5+p);return u.buf.copyWithin(0,5+p,u.len),u.len-=5+p,Lr(h)}}let{done:c,value:d}=await a.read();if(c){if(u.len===0)return null;if(u.len<5)return u.len=0,new Uint8Array(0);let p=u.buf.slice(0,u.len);return u.len=0,Lr(p)}$r(u,d instanceof Uint8Array?d:new Uint8Array(d))}},write:c=>l.write($a(c instanceof Uint8Array?c:new Uint8Array(c))),close:async()=>{try{await a.cancel()}catch{}try{await l.close()}catch{}}}).catch(c=>{n(`grpc handler error: ${c.message||c}`),a.cancel().catch(()=>{}),l.close().catch(()=>{})}),new Response(s,{status:200,headers:{"Content-Type":"application/grpc","Cache-Control":"no-store"}})}var Cr="ed=2560",Ae="random";function Fe(t){let e=t.startsWith("/")?t:`/${t}`;return/\?/.test(e)?`${e}&${Cr}`:`${e}?${Cr}`}function Be(t){return(t.startsWith("/")?t:`/${t}`).replace(/\/+$/,"").replace(/^\//,"")}function _e(t){let e=t.transport||"ws",r=t.wsHost||t.host,n=t.sni||(t.tls?r:""),a=new URLSearchParams({encryption:"none",type:e,host:r,security:t.tls?"tls":"none",tfo:"1"});e==="grpc"?a.set("serviceName",Be(t.wsPath)):e==="xhttp"?(a.set("mode","stream-one"),a.set("path",t.wsPath.startsWith("/")?t.wsPath:`/${t.wsPath}`)):a.set("path",Fe(t.wsPath)),t.tls&&n&&a.set("sni",n),t.tls&&a.set("fp",t.fp||Ae);let s=encodeURIComponent(t.remark||`${t.host}:${t.port}`);return`vless://${t.uuid}@${t.host}:${t.port}?${a.toString()}#${s}`}function Le(t){let e=t.transport||"ws",r=t.wsHost||t.host,n=t.sni||(t.tls?r:""),a=new URLSearchParams({type:e,host:r,security:t.tls?"tls":"none",tfo:"1"});e==="grpc"?a.set("serviceName",Be(t.wsPath)):e==="xhttp"?(a.set("mode","stream-one"),a.set("path",t.wsPath.startsWith("/")?t.wsPath:`/${t.wsPath}`)):a.set("path",Fe(t.wsPath)),t.tls&&n&&a.set("sni",n),t.tls&&a.set("fp",t.fp||Ae);let s=encodeURIComponent(t.remark||`${t.host}:${t.port}`);return`trojan://${encodeURIComponent(t.password)}@${t.host}:${t.port}?${a.toString()}#${s}`}function Dr(t){let e=t.headers.get("Host");return e?e.split(":")[0]:"example.com"}var oe=["ws","grpc","xhttp"],Ua={ws:null,grpc:"g",xhttp:"x"};function j(t,e,r,n){if(!r)return`${n}-${e}`;let a=Ua[e];if(a===void 0)return t==="trojan"?`${r}-T`:r;let s=a?`-${a}`:"";return t==="trojan"?`${r}-T${s}`:`${r}${s}`}function Oa(t,e){let r=[],n=e.port||(e.tls?443:80),a=e.transports&&e.transports.length?e.transports:oe;for(let s of t.vlessUsers){let o=s.path||t.wsPath;for(let l of a)r.push(_e({uuid:s.uuid,host:e.host,port:n,wsPath:o,tls:e.tls,wsHost:e.wsHost,sni:e.sni,transport:l,remark:j("vless",l,e.name||s.remark,`vless-${s.uuid.slice(0,8)}`)}))}for(let s of t.trojanUsers){let o=s.path||t.wsPath;for(let l of a)r.push(Le({password:s.password,host:e.host,port:n,wsPath:o,tls:e.tls,wsHost:e.wsHost,sni:e.sni,transport:l,remark:j("trojan",l,e.name||s.remark,`trojan-${s.password.slice(0,8)}`)}))}return r}function dt(t,e){return e.flatMap(n=>Oa(t,n)).join(`
`)+`
`}function Rr(t,e){return btoa(dt(t,e))}function Pr(t,e){let r=[];for(let a of e){let s=a.port||443,o=a.tls!==!1,l=a.wsHost||a.host,u=a.sni||(o?l:""),i=a.transports&&a.transports.length?a.transports:oe,c=(d,p,h,b,g,m)=>{let f={name:d,type:p,server:a.host,port:s,[h]:b,network:m,tls:o,servername:u||void 0,"client-fingerprint":o?Ae:void 0,tfo:!0,udp:!0,_wsHost:l};return m==="grpc"?f["grpc-opts"]={"grpc-service-name":Be(g)}:m==="xhttp"?f["xhttp-opts"]={mode:"stream-one",path:g.startsWith("/")?g:`/${g}`,host:[l]}:f["ws-opts"]={path:Fe(g),headers:{Host:l}},f};t.vlessUsers.forEach((d,p)=>{for(let h of i)r.push(c(j("vless",h,a.name||d.remark,`vless-${p+1}`),"vless","uuid",d.uuid,d.path||t.wsPath,h))}),t.trojanUsers.forEach((d,p)=>{for(let h of i)r.push(c(j("trojan",h,a.name||d.remark,`trojan-${p+1}`),"trojan","password",d.password,d.path||t.wsPath,h))})}let n=["proxies:"];for(let a of r)n.push(`  - name: "${a.name}"`),n.push(`    type: ${a.type}`),n.push(`    server: ${a.server}`),n.push(`    port: ${a.port}`),a.uuid&&n.push(`    uuid: ${a.uuid}`),a.password&&n.push(`    password: "${a.password}"`),n.push(`    network: ${a.network}`),n.push(`    tls: ${a.tls}`),a.servername&&n.push(`    servername: ${a.servername}`),a["client-fingerprint"]&&n.push(`    client-fingerprint: ${a["client-fingerprint"]}`),n.push("    tfo: true"),n.push("    udp: true"),a.network==="grpc"?(n.push("    grpc-opts:"),n.push(`      grpc-service-name: ${a["grpc-opts"]["grpc-service-name"]}`)):a.network==="xhttp"?(n.push("    xhttp-opts:"),n.push(`      mode: ${a["xhttp-opts"].mode}`),n.push(`      path: ${a["xhttp-opts"].path}`),n.push("      host:"),n.push(`        - ${a._wsHost}`)):(n.push("    ws-opts:"),n.push(`      path: ${a["ws-opts"].path}`),n.push("      headers:"),n.push(`        Host: ${a._wsHost}`));return n.push(""),n.push("rules:"),n.push("  - MATCH,DIRECT"),n.join(`
`)}function Mr(t,e){let r=[],n=(a,s,o)=>s==="grpc"?{type:"grpc",service_name:Be(a)}:s==="xhttp"?{type:"xhttp",mode:"stream-one",path:a.startsWith("/")?a:`/${a}`,host:o}:{type:"ws",path:Fe(a),headers:{Host:o}};for(let a of e){let s=a.port||443,o=a.wsHost||a.host,l=a.sni||(a.tls?o:""),u=a.transports&&a.transports.length?a.transports:oe;for(let i of t.vlessUsers)for(let c of u)r.push({type:"vless",tag:j("vless",c,a.name||i.remark,`vless-${i.uuid.slice(0,8)}`),server:a.host,server_port:s,uuid:i.uuid,transport:n(i.path||t.wsPath,c,o),tcp_fast_open:!0,tls:a.tls?{enabled:!0,server_name:l,fingerprint:Ae}:null});for(let i of t.trojanUsers)for(let c of u)r.push({type:"trojan",tag:j("trojan",c,a.name||i.remark,`trojan-${i.password.slice(0,8)}`),server:a.host,server_port:s,password:i.password,transport:n(i.path||t.wsPath,c,o),tcp_fast_open:!0,tls:a.tls?{enabled:!0,server_name:l,fingerprint:Ae}:null})}return JSON.stringify({outbounds:r,log:{level:"info"}},null,2)}var pt={ws:"WebSocket (ws)",grpc:"gRPC",xhttp:"XHTTP (stream-one)"};function $e(t){return String(t??"").replace(/[&<>"']/g,e=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"})[e])}function ft(t,e){let n=`/${(e.path||t.wsPath||"/ws").replace(/^\//,"")}`,a=e.kind==="vless"?"VLESS":"Trojan",s=e.kind==="vless"?"vless":"trojan",o=Array.isArray(e.entries)&&e.entries.length?e.entries:null,l=o&&o.length>1,u=(m,f)=>{let y=m?m.host:e.host,x=m?Number(m.port)||443:e.port||(e.tls?443:80),v=m?!0:e.tls,w=m?m.wsHost||m.host:e.wsHost,S=m?m.sni||w:e.sni,L=j(e.kind,f,m?m.remark:"",`${s}-${f}`),C={host:y,port:x,wsPath:n,tls:v,wsHost:w,sni:S};return e.kind==="vless"?_e({...C,uuid:e.credential,transport:f,remark:L}):Le({...C,password:e.credential,transport:f,remark:L})},i=(m,f,y)=>`
  <div class="row">
    <label>${pt[f]}</label>
    <div class="linkbox">
      <input type="text" readonly value="${u(m,f)}" id="link${y}">
      <button onclick="copyLink(${y})">\u590D\u5236</button>
    </div>
  </div>`,c;if(o)c=o.map(m=>({title:m.remark||"",host:m.host,transports:m.transports&&m.transports.length?m.transports:oe,entry:m}));else{let m=e.transports&&e.transports.length?e.transports:oe;c=[{title:"",host:e.host,transports:m,entry:null}]}let d=0,p=c.map(m=>{let y=m.transports.filter(v=>pt[v]).map(v=>i(m.entry,v,d++)).join("");return`${m.title?`<div class="entry-title">${$e(m.title)}</div>`:l?`<div class="entry-title">${$e(m.host)}</div>`:""}${y}`}).join(""),h=l?"\u591A\u5165\u53E3":c[0].host,b=l?`${c.length} \u4E2A\u5165\u53E3\uFF0C\u6309\u4E0B\u65B9\u5206\u7EC4\u590D\u5236\u5BF9\u5E94\u8282\u70B9`:c[0].transports.filter(m=>pt[m]).join(" / ");return`<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>${a} \u8282\u70B9\u914D\u7F6E</title>
<style>
  body { font-family: -apple-system, system-ui, sans-serif; background: #f5f5f7; color: #1d1d1f; display: flex; justify-content: center; padding: 48px 16px; margin: 0; }
  .card { background: #fff; border-radius: 16px; padding: 32px; max-width: 640px; width: 100%; box-shadow: 0 2px 12px rgba(0,0,0,.08); }
  h1 { font-size: 22px; margin: 0 0 8px; }
  p.desc { color: #6e6e73; font-size: 14px; margin: 0 0 24px; }
  .entry-title { font-size: 15px; font-weight: 600; color: #1d1d1f; margin: 18px 0 10px; padding-top: 14px; border-top: 1px solid #ececf0; }
  .entry-title:first-of-type { border-top: 0; padding-top: 0; margin-top: 0; }
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
  <h1>${a} \u8282\u70B9 <span class="badge">${$e(h)}</span></h1>
  <p class="desc">\u5165\u7AD9\u8DEF\u5F84\uFF1A<b>${$e(n)}</b>\uFF08\u5F53\u524D\u5165\u53E3\u652F\u6301\uFF1A${$e(b)||"\u65E0"}\uFF0C\u590D\u5236\u94FE\u63A5\u5BFC\u5165\u5BA2\u6237\u7AEF\uFF09</p>
  ${p}
</div>
<script>
function copyLink(i){ const el=document.getElementById('link'+i); el.select(); document.execCommand('copy'); el.style.borderColor='#34c759'; setTimeout(()=>el.style.borderColor='#d2d2d7',800); }
<\/script>
</body>
</html>`}function Ir(t){let e=t.disguise_title||"AList",r=t.disguise_subtitle||"\u4E00\u4E2A\u652F\u6301\u591A\u5B58\u50A8\u7684\u6587\u4EF6\u5217\u8868\u7A0B\u5E8F";return`<!DOCTYPE html>
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
</html>`}function ht(t,e=200){return new Response(t,{status:e,headers:{"Content-Type":"text/html; charset=utf-8","Cache-Control":"no-store"}})}function pe(t,e="text/plain; charset=utf-8"){return new Response(t,{headers:{"Content-Type":e,"Cache-Control":"no-store"}})}async function Ca(t,e,r){let n=new URL(t.url),a=n.searchParams.get("token")||"",s=e;if(a)if(e.uuidSet.has(a)){let l=e.vlessIndex[a];s={...e,vlessUsers:[l],trojanUsers:[]}}else if(e.passwordSet.has(a)){let l=e.trojanIndex[a];s={...e,vlessUsers:[],trojanUsers:[l]}}else if(e.adminPasswordHash&&await Me(a,e.adminPasswordHash))s=e;else return new Response("Not Found",{status:404});else return new Response("Not Found",{status:404});switch((n.searchParams.get("format")||"base64").toLowerCase()){case"plain":return pe(dt(s,r));case"clash":case"yaml":return pe(Pr(s,r),"text/yaml; charset=utf-8");case"singbox":case"sing-box":case"json":return pe(Mr(s,r),"application/json; charset=utf-8");default:return pe(Rr(s,r))}}function Da(t,e,r,n){let a=new URL(t.url),s=null;if(e.uuidSet.has(r)?s={kind:"vless",user:e.vlessIndex[r]}:e.passwordSet.has(r)&&(s={kind:"trojan",user:e.trojanIndex[r]}),!s)return new Response("Not Found",{status:404});let o=(a.searchParams.get("format")||"base64").toLowerCase(),l=n.host,u=n.port,i=s.user.path||e.wsPath,c=n.transports&&n.transports.length?n.transports:oe,d=[];for(let h of c)s.kind==="vless"?d.push(_e({uuid:s.user.uuid,host:l,port:u,wsPath:i,tls:n.tls,wsHost:n.wsHost,sni:n.sni,transport:h,remark:j("vless",h,n.remark||s.user.remark,"vless-node")})):d.push(Le({password:s.user.password,host:l,port:u,wsPath:i,tls:n.tls,wsHost:n.wsHost,sni:n.sni,transport:h,remark:j("trojan",h,n.remark||s.user.remark,"trojan-node")}));let p=d.join(`
`)+`
`;return pe(o==="plain"?p:btoa(p))}async function Nr(t,e,r){let n=new URL(t.url),a=n.pathname,s=Dr(t),o=n.protocol==="https:",l=Number(n.port)||(o?443:80),u=s.toLowerCase().replace(/:\d+$/,""),i=g=>[g.host,g.wsHost].filter(Boolean).map(f=>f.toLowerCase().replace(/:\d+$/,"")).some(f=>f===u),c=e.entries.find(i),d=c?{host:c.host,port:Number(c.port)||443,tls:!0,wsHost:c.wsHost,sni:c.sni,transports:c.transports,remark:c.remark||c.host}:e.entries.length?{host:e.entries[0].host,port:Number(e.entries[0].port)||443,tls:!0,wsHost:e.entries[0].wsHost,sni:e.entries[0].sni,transports:e.entries[0].transports,remark:e.entries[0].remark||e.entries[0].host}:{host:s,port:l,tls:o,wsHost:s,sni:s},p;if(c?p=[{host:c.host,port:Number(c.port)||443,tls:!0,wsHost:c.wsHost,sni:c.sni,transports:c.transports,name:c.remark||c.host}]:e.entries.length?p=e.entries.map(g=>({host:g.host,port:Number(g.port)||443,tls:!0,wsHost:g.wsHost,sni:g.sni,transports:g.transports,name:g.remark||g.host})):p=[{host:s,port:l,tls:o,wsHost:s,sni:s}],a==="/subscribe")return await Ca(t,e,p);let h=a.match(/^\/([^/]+)\/subscribe$/);if(h)return Da(t,e,decodeURIComponent(h[1]),d);let b=a.match(/^\/([^/]+)$/);if(b){let g=decodeURIComponent(b[1]);if(e.uuidSet.has(g)){let m=e.vlessIndex[g];return ht(ft(e,{host:d.host,port:d.port,tls:d.tls,wsHost:d.wsHost,sni:d.sni,transports:d.transports,entries:e.entries,credential:g,kind:"vless",path:m&&m.path||e.wsPath}))}if(e.passwordSet.has(g)){let m=e.trojanIndex[g];return ht(ft(e,{host:d.host,port:d.port,tls:d.tls,wsHost:d.wsHost,sni:d.sni,transports:d.transports,entries:e.entries,credential:g,kind:"trojan",path:m&&m.path||e.wsPath}))}}return ht(Ir(e.settings))}var Hr="1.0.86-20260928-2345";var zr=[{name:"\u5B57\u8282\u8DF3\u52A8",host:"www.bytedance.com",port:80,region:"cn",icon:"\u{1F3B5}",color:"#325AB4"},{name:"Bilibili",host:"www.bilibili.com",port:80,region:"cn",icon:"\u{1F4FA}",color:"#FB7299"},{name:"\u5FAE\u4FE1",host:"weixin.qq.com",port:80,region:"cn",icon:"\u{1F4AC}",color:"#07C160"},{name:"\u6DD8\u5B9D",host:"www.taobao.com",port:80,region:"cn",icon:"\u{1F6D2}",color:"#FF5000"},{name:"GitHub",host:"github.com",port:80,region:"intl",icon:"\u{1F419}",color:"#24292F"},{name:"jsDelivr",host:"cdn.jsdelivr.net",port:80,region:"intl",icon:"\u{1F4E6}",color:"#E84D0E"},{name:"Cloudflare",host:"www.cloudflare.com",port:80,region:"intl",icon:"\u2601\uFE0F",color:"#F6821F"},{name:"Google",host:"www.google.com",port:80,region:"intl",icon:"\u{1F50D}",color:"#4285F4"},{name:"YouTube",host:"www.youtube.com",port:80,region:"intl",icon:"\u25B6\uFE0F",color:"#FF0000"}],Fr=16,mt=3e3,Br=4;var Ra=5e3,Pa=5e3;function je(t,e,r="/"){return new TextEncoder().encode(`GET ${r} HTTP/1.1\r
Host: ${t}\r
User-Agent: Mozilla/5.0 (netprobe)\r
Connection: close\r
\r
`)}function Ma(t,e){let r=new Uint8Array(t.length+e.length);return r.set(t,0),r.set(e,t.length),r}function Ia(t){for(let e=0;e<t.length-3;e++)if(t[e]===13&&t[e+1]===10&&t[e+2]===13&&t[e+3]===10)return e+4;return-1}function gt(t){try{typeof t.close=="function"?t.close():t.writable&&typeof t.writable.close=="function"&&t.writable.close().catch(()=>{})}catch{}}function Ge(t,e){return new Promise(r=>{let n=new Uint8Array(0),a=!1,s=l=>{a||(a=!0,clearTimeout(o),r(l))},o=setTimeout(()=>s(null),e);(async()=>{let l=t.readable.getReader();try{for(;!a;){let{done:u,value:i}=await l.read();if(u)break;if(!(!i||i.byteLength===0)){if(n=Ma(n,i),Ia(n)>=0){s(Date.now());break}if(n.length>65536){s(null);break}}}}catch{}s(null);try{l.releaseLock()}catch{}})()})}async function Na(t,e,r,n,a){let s=Date.now(),o;try{let u=await ke(t,2,e),i=ae(t,u.outbound);o=await ne({config:t,outbound:i,addressType:2,addressRemote:e,portRemote:r,rawClientData:n,log:a})}catch{return null}if(!o)return null;let l=await Ge(o,mt);return gt(o),l===null?null:l-s}async function Ha(t,e,r){let n=[];for(let i=0;i<Fr;i+=Br){let c=[],d=Math.min(i+Br,Fr);for(let h=i;h<d;h++)c.push(Na(t,e.host,e.port,je(e.host,e.port),r));let p=await Promise.all(c);for(let h of p)n.push(h)}let a=n.filter(i=>i!==null),s=a.length>0?Math.round(a.reduce((i,c)=>i+c,0)/a.length):null,o=a.length>0?Math.min(...a):null,l=a.length>0?Math.max(...a):null,u=n.length>0?Math.round((n.length-a.length)/n.length*100):100;return{...e,samples:n,latency:s,min:o,max:l,loss:u,success:a.length,total:n.length}}async function jr(t,e){let r=await Promise.allSettled(zr.map(n=>Ha(t,n,e)));return{ok:!0,ts:Date.now(),targets:r.map((n,a)=>n.status==="fulfilled"?n.value:{...zr[a],samples:[],latency:null,success:0,total:0,error:n.reason&&n.reason.message||"error"})}}async function Gr(t,e,r){let n=String(e||"").trim().toLowerCase();if(!n)return{ok:!1,error:"domain required"};let a=2;/^\d{1,3}(\.\d{1,3}){3}$/.test(n)?a=1:n.includes(":")&&(a=3);let s=a!==2,o=await ke(t,a,n),l=!!o.rule,u=l?`\u5206\u6D41\u89C4\u5219 ${o.rule.rule} \u2192 `:"",i=ae(t,o.outbound);if(i==="reject")return{ok:!0,domain:n,route:"reject",name:"reject",reason:l?`${u}reject\uFF08\u62D2\u7EDD\u8FDE\u63A5\uFF09`:"\u9ED8\u8BA4\u51FA\u7AD9 reject\uFF08\u62D2\u7EDD\u8FDE\u63A5\uFF09",rule:l?o.rule.rule:null};if(i==="direct"){let d=o.outbound,p=(!!t.proxyipHost||!!t.proxyipOutbound)&&!t.proxyipDisabled,h=p&&dr(),b=!s&&st(n),g=s&&!n.includes(":")&&xe(n),m=!1;if(p&&!h&&!s&&!b){let f=await X(n,r);f&&xe(f)&&(m=!0)}if(p&&!h&&(b||g||m)){if(t.proxyipOutbound)return{ok:!0,domain:n,route:"proxyip",name:`outbound:${t.proxyipOutbound}`,reason:`${u}Cloudflare \u7AD9\u70B9\uFF08\u5DF2\u77E5 CF \u540E\u7F00/IP \u6BB5\uFF09\u2192 \u4F7F\u7528\u51FA\u7AD9\u4EE3\u7406 ${t.proxyipOutbound} \u51FA\u7AD9`,rule:l?o.rule.rule:null};let f=`${t.proxyipHost}:${Number(t.proxyipPort||443)}`;return{ok:!0,domain:n,route:"proxyip",name:f,reason:`${u}Cloudflare \u7AD9\u70B9\uFF08\u5DF2\u77E5 CF \u540E\u7F00/IP \u6BB5\uFF09\u2192 proxyip ${f}`,rule:l?o.rule.rule:null}}return l?{ok:!0,domain:n,route:"direct",name:"direct",reason:`${u}direct`,rule:o.rule.rule}:d&&d!=="direct"&&d!=="reject"?{ok:!0,domain:n,route:"direct",name:"direct",reason:`\u9ED8\u8BA4\u51FA\u7AD9 ${d} \u4E0D\u5B58\u5728\uFF0C\u56DE\u9000 direct`,rule:null}:{ok:!0,domain:n,route:"direct",name:"direct",reason:"\u9ED8\u8BA4\u51FA\u7AD9 direct",rule:null}}let c=typeof i=="string"?i:i.name;return{ok:!0,domain:n,route:"outbound",name:c,reason:l?`${u}\u51FA\u7AD9 ${c}`:`\u9ED8\u8BA4\u51FA\u7AD9 ${c}`,rule:l?o.rule.rule:null}}async function Vr(t,e){let r="www.cloudflare.com";if(t.proxyipOutbound){let l=ae(t,t.proxyipOutbound);if(!l||typeof l=="string")return{ok:!1,mode:"outbound",error:`\u51FA\u7AD9 ${t.proxyipOutbound} \u4E0D\u5B58\u5728\uFF0C\u8BF7\u68C0\u67E5\u51FA\u7AD9\u914D\u7F6E`};let u=Date.now(),i=null;try{i=await ne({config:t,outbound:l,addressType:2,addressRemote:r,portRemote:443,rawClientData:je(r,443),log:e,isUDP:!1})}catch(d){return{ok:!1,mode:"outbound",outbound:t.proxyipOutbound,error:`\u51FA\u7AD9\u8FDE\u63A5\u5931\u8D25: ${d.message}`}}if(!i)return{ok:!1,mode:"outbound",outbound:t.proxyipOutbound,error:"\u51FA\u7AD9\u8FDE\u63A5\u5931\u8D25\u6216\u65E0\u54CD\u5E94"};let c=await Ge(i,mt);return gt(i),c===null?{ok:!1,mode:"outbound",outbound:t.proxyipOutbound,error:"\u8FDE\u63A5\u8D85\u65F6\u6216\u65E0\u54CD\u5E94"}:{ok:!0,latency:c-u,mode:"outbound",outbound:t.proxyipOutbound}}if(!t.proxyipHost)return{ok:!1,error:"\u672A\u914D\u7F6E proxyip\uFF0C\u8BF7\u5148\u5728\u7CFB\u7EDF\u8BBE\u7F6E\u4E2D\u586B\u5199"};let a=Date.now(),s=null;try{if(s=globalThis.connect?globalThis.connect({hostname:t.proxyipHost,port:Number(t.proxyipPort||443)}):null,!s)return{ok:!1,error:"connect \u4E0D\u53EF\u7528"};let l=s.writable.getWriter();await l.write(je(r,443)),l.releaseLock()}catch(l){try{s&&s.close()}catch{}return{ok:!1,error:`\u8FDE\u63A5\u5931\u8D25: ${l.message}`}}let o=await Ge(s,mt);try{s.close()}catch{}return o===null?{ok:!1,error:"\u8FDE\u63A5\u8D85\u65F6\u6216\u65E0\u54CD\u5E94"}:{ok:!0,latency:o-a,mode:"proxyip",endpoint:`${t.proxyipHost}:${t.proxyipPort||443}`}}function za(t){let r=[18,52];r.push(1,0),r.push(0,1),r.push(0,0,0,0,0,0);for(let n of String(t).split(".")){r.push(n.length);for(let a=0;a<n.length;a++)r.push(n.charCodeAt(a))}return r.push(0),r.push(0,1),r.push(0,1),new Uint8Array(r)}async function Wr(t,e){let r=null,n=(t.udpOutbound||"").trim();if(n){let i=t.outboundByName[n];if(i&&i.type==="vless")r=i;else return{ok:!1,error:`UDP \u51FA\u7AD9 '${n}' \u4E0D\u5B58\u5728\u6216\u975E vless\uFF08\u4EC5 vless \u652F\u6301 UDP\uFF09`}}else if(r=t.outbounds.find(i=>i.type==="vless"),!r)return{ok:!1,error:"\u672A\u914D\u7F6E vless \u51FA\u7AD9\uFF0C\u65E0\u6CD5\u6D4B\u8BD5 UDP"};let a=za("example.com"),s=ve(a),o=Date.now(),l;try{l=await de({address:r.address,port:Number(r.port),uuid:r.uuid,path:r.path,tls:!!r.tls,sni:r.sni||"",transport:r.transport},2,1,"8.8.8.8",53,s,e)}catch(i){return{ok:!1,error:`UDP \u51FA\u7AD9\u8FDE\u63A5\u5931\u8D25: ${i.message}`}}if(!l)return{ok:!1,error:"UDP \u51FA\u7AD9\u8FDE\u63A5\u5931\u8D25"};let u=await new Promise(i=>{let c=setTimeout(()=>i({ok:!1,error:"UDP \u54CD\u5E94\u8D85\u65F6"}),Ra);hr(l.readable,d=>{d.length>=12&&d[0]===18&&d[1]===52&&(d[2]&128)!==0&&(clearTimeout(c),i({ok:!0,latency:Date.now()-o,bytes:d.length,outbound:r.name||n||"vless"}))},e)});try{l.writable.close().catch(()=>{})}catch{}return u}async function Kr(t,e,r){let n="www.gstatic.com",s=Date.now(),o;try{o=await ne({config:t,outbound:e,addressType:2,addressRemote:n,portRemote:80,rawClientData:je(n,80,"/generate_204"),log:r})}catch(u){return{ok:!1,error:u.message}}if(!o)return{ok:!1,error:"\u96A7\u9053\u5EFA\u7ACB\u5931\u8D25"};let l=await Ge(o,Pa);return gt(o),l===null?{ok:!1,error:"\u8FDE\u63A5\u8D85\u65F6\u6216\u65E0\u54CD\u5E94"}:{ok:!0,latency:l-s}}var B=Uint8Array,fe=Uint16Array,Fa=Int32Array,qr=new B([0,0,0,0,0,0,0,0,1,1,1,1,2,2,2,2,3,3,3,3,4,4,4,4,5,5,5,5,0,0,0,0]),Yr=new B([0,0,0,0,1,1,2,2,3,3,4,4,5,5,6,6,7,7,8,8,9,9,10,10,11,11,12,12,13,13,0,0]),Ba=new B([16,17,18,0,8,7,9,6,10,5,11,4,12,3,13,2,14,1,15]),Jr=function(t,e){for(var r=new fe(31),n=0;n<31;++n)r[n]=e+=1<<t[n-1];for(var a=new Fa(r[30]),n=1;n<30;++n)for(var s=r[n];s<r[n+1];++s)a[s]=s-r[n]<<5|n;return{b:r,r:a}},Xr=Jr(qr,2),Zr=Xr.b,ja=Xr.r;Zr[28]=258,ja[258]=28;var Qr=Jr(Yr,0),Ga=Qr.b,Uo=Qr.r,wt=new fe(32768);for(O=0;O<32768;++O)Q=(O&43690)>>1|(O&21845)<<1,Q=(Q&52428)>>2|(Q&13107)<<2,Q=(Q&61680)>>4|(Q&3855)<<4,wt[O]=((Q&65280)>>8|(Q&255)<<8)>>1;var Q,O,Ue=(function(t,e,r){for(var n=t.length,a=0,s=new fe(e);a<n;++a)t[a]&&++s[t[a]-1];var o=new fe(e);for(a=1;a<e;++a)o[a]=o[a-1]+s[a-1]<<1;var l;if(r){l=new fe(1<<e);var u=15-e;for(a=0;a<n;++a)if(t[a])for(var i=a<<4|t[a],c=e-t[a],d=o[t[a]-1]++<<c,p=d|(1<<c)-1;d<=p;++d)l[wt[d]>>u]=i}else for(l=new fe(n),a=0;a<n;++a)t[a]&&(l[a]=wt[o[t[a]-1]++]>>15-t[a]);return l}),Oe=new B(288);for(O=0;O<144;++O)Oe[O]=8;var O;for(O=144;O<256;++O)Oe[O]=9;var O;for(O=256;O<280;++O)Oe[O]=7;var O;for(O=280;O<288;++O)Oe[O]=8;var O,en=new B(32);for(O=0;O<32;++O)en[O]=5;var O;var Va=Ue(Oe,9,1);var Wa=Ue(en,5,1),bt=function(t){for(var e=t[0],r=1;r<t.length;++r)t[r]>e&&(e=t[r]);return e},G=function(t,e,r){var n=e/8|0;return(t[n]|t[n+1]<<8)>>(e&7)&r},yt=function(t,e){var r=e/8|0;return(t[r]|t[r+1]<<8|t[r+2]<<16)>>(e&7)},Ka=function(t){return(t+7)/8|0},qa=function(t,e,r){return(e==null||e<0)&&(e=0),(r==null||r>t.length)&&(r=t.length),new B(t.subarray(e,r))};var Ya=["unexpected EOF","invalid block type","invalid length/literal","invalid distance","stream finished","no stream handler",,"no callback","invalid UTF-8 data","extra field too long","date not in range 1980-2099","filename too long","stream finishing","invalid zip data"],V=function(t,e,r){var n=new Error(e||Ya[t]);if(n.code=t,Error.captureStackTrace&&Error.captureStackTrace(n,V),!r)throw n;return n},Ja=function(t,e,r,n){var a=t.length,s=n?n.length:0;if(!a||e.f&&!e.l)return r||new B(0);var o=!r,l=o||e.i!=2,u=e.i;o&&(r=new B(a*3));var i=function(Et){var St=r.length;if(Et>St){var At=new B(Math.max(St*2,Et));At.set(r),r=At}},c=e.f||0,d=e.p||0,p=e.b||0,h=e.l,b=e.d,g=e.m,m=e.n,f=a*8;do{if(!h){c=G(t,d,1);var y=G(t,d+1,3);if(d+=3,y)if(y==1)h=Va,b=Wa,g=9,m=5;else if(y==2){var S=G(t,d,31)+257,L=G(t,d+10,15)+4,C=S+G(t,d+5,31)+1;d+=14;for(var A=new B(C),M=new B(19),T=0;T<L;++T)M[Ba[T]]=G(t,d+T*3,7);d+=L*3;for(var k=bt(M),$=(1<<k)-1,U=Ue(M,k,1),T=0;T<C;){var D=U[G(t,d,$)];d+=D&15;var x=D>>4;if(x<16)A[T++]=x;else{var _=0,R=0;for(x==16?(R=3+G(t,d,3),d+=2,_=A[T-1]):x==17?(R=3+G(t,d,7),d+=3):x==18&&(R=11+G(t,d,127),d+=7);R--;)A[T++]=_}}var N=A.subarray(0,S),I=A.subarray(S);g=bt(N),m=bt(I),h=Ue(N,g,1),b=Ue(I,m,1)}else V(1);else{var x=Ka(d)+4,v=t[x-4]|t[x-3]<<8,w=x+v;if(w>a){u&&V(0);break}l&&i(p+v),r.set(t.subarray(x,w),p),e.b=p+=v,e.p=d=w*8,e.f=c;continue}if(d>f){u&&V(0);break}}l&&i(p+131072);for(var ee=(1<<g)-1,De=(1<<m)-1,H=d;;H=d){var _=h[yt(t,d)&ee],P=_>>4;if(d+=_&15,d>f){u&&V(0);break}if(_||V(2),P<256)r[p++]=P;else if(P==256){H=d,h=null;break}else{var Y=P-254;if(P>264){var T=P-257,z=qr[T];Y=G(t,d,(1<<z)-1)+Zr[T],d+=z}var W=b[yt(t,d)&De],Re=W>>4;W||V(3),d+=W&15;var I=Ga[Re];if(Re>3){var z=Yr[Re];I+=yt(t,d)&(1<<z)-1,d+=z}if(d>f){u&&V(0);break}l&&i(p+131072);var Tt=p+Y;if(p<I){var kt=s-I,pn=Math.min(I,Tt);for(kt+p<0&&V(3);p<pn;++p)r[p]=n[kt+p]}for(;p<Tt;++p)r[p]=r[p-I]}}e.l=h,e.p=H,e.b=p,e.f=c,h&&(c=1,e.m=g,e.d=b,e.n=m)}while(!c);return p!=r.length&&o?qa(r,0,p):r.subarray(0,p)};var Xa=new B(0);var Za=function(t,e){return((t[0]&15)!=8||t[0]>>4>7||(t[0]<<8|t[1])%31)&&V(6,"invalid zlib data"),(t[1]>>5&1)==+!e&&V(6,"invalid zlib data: "+(t[1]&32?"need":"unexpected")+" dictionary"),(t[1]>>3&4)+2};function tn(t,e){return Ja(t.subarray(Za(t,e&&e.dictionary),-4),{i:2},e&&e.out,e&&e.dictionary)}var Qa=typeof TextDecoder<"u"&&new TextDecoder,es=0;try{Qa.decode(Xa,{stream:!0}),es=1}catch{}var xt={"Content-Type":"application/json; charset=utf-8"},ts="gcp:asia-east2";function E(t,e=200){return new Response(JSON.stringify(t),{status:e,headers:xt})}async function Ce(t){try{return await t.json()}catch{return null}}function rs(t){return t.admin_cookie_secret||t.admin_password_hash||"vtd-insecure-secret"}async function on(t,e,r){let n=new URL(t.url),s=n.pathname.split("/").filter(Boolean),o=s[2]||"",l=s[3]||null,u=t.method,{DB:i,GEO_KV:c}=e.env,d=e.settings,p=rs(d);if(o==="login"&&u==="POST"){let f=await Ce(t);if(!f||!f.password)return E({error:"password required"},400);if(!await Me(f.password,e.adminPasswordHash))return E({error:"invalid password"},401);let x=await Mt(p);return new Response(JSON.stringify({ok:!0}),{status:200,headers:{...xt,"Set-Cookie":`${me}=${x}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${7*86400}`}})}let h=Nt(t.headers.get("Cookie"));if(!await It(h[me],p))return E({error:"unauthorized"},401);if(o==="logout"&&u==="POST")return new Response(JSON.stringify({ok:!0}),{status:200,headers:{...xt,"Set-Cookie":`${me}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0`}});if(o==="version"&&u==="GET")return E({ok:!0,version:Hr});if(o==="colo"&&u==="GET"){let f=t&&t.cf||{},y=t.headers.get("cf-placement")||"",x=null,v=null;if(y){let w=y.indexOf("-");w>0?(x=y.slice(0,w),v=y.slice(w+1)||null):x=y}return E({ok:!0,placement_header:y||null,placement_mode:x,placement_colo:v,colo:f.colo||null,region:f.region||null,city:f.city||null,country:f.country||null,continent:f.continent||null,timezone:f.timezone||null,host:n.hostname||null,configured_placement_region:ts})}if(await ys(i),o==="settings"){if(u==="GET"){let{results:f}=await i.prepare("SELECT key, value FROM settings").all();return E((f||[]).reduce((y,x)=>(y[x.key]=x.value,y),{}))}if(u==="PUT"){let f=await Ce(t);if(!f)return E({error:"bad body"},400);let y=new Set(["ws_path","default_outbound","proxyip","udp_outbound","ip_preference","disguise_title","disguise_subtitle","entry_host","entry_port","entry_sni","entry_ws_host","entry_list","admin_password_hash","admin_cookie_secret"]);if(f.ip_preference!==void 0&&!["ipv4","ipv6","auto"].includes(f.ip_preference))return E({error:"ip_preference \u4EC5\u5141\u8BB8 ipv4 / ipv6 / auto"},400);if(f.entry_list!==void 0)try{let x=JSON.parse(f.entry_list);if(!Array.isArray(x)||x.some(v=>!v||!String(v.host||"").trim()))return E({error:"entry_list \u5FC5\u987B\u4E3A\u5165\u53E3\u6570\u7EC4\uFF08\u6BCF\u9879\u9700\u5305\u542B host\uFF09"},400);if(x.some(v=>Array.isArray(v.transports)&&v.transports.some(w=>!["ws","grpc","xhttp"].includes(w))))return E({error:"entry_list transports \u4EC5\u5141\u8BB8 ws / grpc / xhttp"},400)}catch{return E({error:"entry_list \u4E0D\u662F\u5408\u6CD5 JSON \u6570\u7EC4"},400)}for(let[x,v]of Object.entries(f))typeof v=="string"&&y.has(x)&&await i.prepare("INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at").bind(x,v,Date.now()).run();return ue("settings"),E({ok:!0})}return E({error:"method not allowed"},405)}let m={"vless-users":{table:"vless_users",cacheKey:"vlessUsers",cols:["uuid","remark","enable","path","expire_at","traffic_limit","traffic_reset_at"]},"trojan-users":{table:"trojan_users",cacheKey:"trojanUsers",cols:["password","remark","enable","path","expire_at","traffic_limit","traffic_reset_at"]},outbounds:{table:"outbounds",cacheKey:"outbounds",cols:["type","name","address","port","uuid","path","tls","udp","enable","sort","username","password","sni","transport"],validate(f){if(f.type!==void 0&&!["socks5","http","vless"].includes(f.type))return"invalid outbound type";if(f.port!==void 0&&(!Number.isInteger(Number(f.port))||Number(f.port)<=0||Number(f.port)>65535))return"invalid port";if((f.type==="socks5"||f.type==="http")&&!f.address)return"address required";if(f.type==="vless"){if(!f.uuid)return"vless requires uuid";if(f.transport!==void 0&&!["raw","ws","grpc","httpupgrade"].includes(f.transport))return"invalid vless transport"}return f.username&&!f.password||!f.username&&f.password?"username and password must be set together":((f.type==="socks5"||f.type==="http")&&(f.udp=0),f.type!=="vless"&&(f.transport="ws"),null)}},"routing-rules":{table:"routing_rules",cacheKey:"routingRules",cols:["rule","outbound","enable","sort"]}}[o];if(m)return ns(u,l,m,i,t);if(o==="stats"&&u==="GET"){let[f,y]=await Promise.all([i.prepare("SELECT remark, uuid, up, down, path, expire_at, traffic_limit, traffic_reset_at FROM vless_users ORDER BY (up + down) DESC").all(),i.prepare("SELECT remark, password, up, down, path, expire_at, traffic_limit, traffic_reset_at FROM trojan_users ORDER BY (up + down) DESC").all()]),x=Math.floor(Date.now()/1e3),v=w=>(w||[]).map(S=>{let L=Number(S.up||0),C=Number(S.down||0),A=Number(S.traffic_limit||0),M=L+C;return{...S,used:M,remaining:A>0?Math.max(0,A-M):null,expired:S.expire_at>0&&S.expire_at<x,limitReached:A>0&&M>=A}});return E({vless:v(f.results),trojan:v(y.results)})}if(o==="geo"&&s[3]==="update"&&u==="POST")try{if(await c.get("geo:updating")==="1")return E({ok:!0,started:!1,updating:!0});if(await c.put("geo:updating","1",{expirationTtl:7200}),e.env&&e.env.GEO_QUEUE&&typeof e.env.GEO_QUEUE.send=="function")return await e.env.GEO_QUEUE.send({kind:"geo-update"}),await c.put("geo:update_status",JSON.stringify({startedAt:Date.now(),state:"updating",step:0,total:0,updated:0,failed:[],current:"",message:"\u5DF2\u5165\u961F\uFF0C\u7B49\u5F85\u6D88\u8D39\u8005\u6267\u884C\u2026"})).catch(()=>{}),E({ok:!0,started:!0,queued:!0,updating:!0});if(r&&typeof r.waitUntil=="function")return r.waitUntil(Ve(i,c)),E({ok:!0,started:!0,updating:!0});let y=await Ve(i,c);return E({ok:!0,started:!1,updated:y.updated,total:y.total,failed:y.failed})}catch(f){return await c.put("geo:updating","0").catch(()=>{}),E({error:f.message},500)}if(o==="geo"&&s[3]==="status"&&u==="GET"){let[f,y,x]=await Promise.all([c.get("geo:updating"),c.get("geo:update_status"),c.get(Pe)]),v=null;if(y)try{v=JSON.parse(y)}catch{}return E({ok:!0,updating:f==="1",version:x||null,status:v})}if(o==="geo"&&s[3]==="info"&&u==="GET"){let[f,y,x]=await Promise.all([c.get("geo:updating"),c.get("geo:update_status"),c.get(Pe)]),v=null;if(y)try{v=JSON.parse(y)}catch{}let w=async C=>{let A=[],M;do{let T=await c.list({prefix:C,cursor:M});for(let k of T.keys||[])A.push(k.name.slice(C.length));M=T.cursor}while(M);return A},[S,L]=await Promise.all([w("geosite:"),w("geoip:")]);return E({ok:!0,updating:f==="1",version:x||null,status:v,geositeCount:S.length,geoipCount:L.length,geositeCategories:S,geoipCategories:L})}if(o==="netstatus"&&s[3]==="test"&&u==="POST")try{return E(await jr(e,f=>console.log(f)))}catch(f){return E({ok:!1,error:f.message},500)}if(o==="route-test"&&u==="POST")try{let f=await Ce(t),y=f&&f.domain?String(f.domain).trim():"";return y?E(await Gr(e,y,x=>console.log(x))):E({ok:!1,error:"\u8BF7\u586B\u5199\u8981\u6D4B\u8BD5\u7684\u57DF\u540D\u6216 IP"},400)}catch(f){return E({ok:!1,error:f.message},500)}if(o==="test"){if(s[3]==="proxyip"&&u==="POST")try{return E(await Vr(e,f=>console.log(f)))}catch(f){return E({ok:!1,error:f.message},500)}if(s[3]==="udp"&&u==="POST")try{return E(await Wr(e,f=>console.log(f)))}catch(f){return E({ok:!1,error:f.message},500)}if(s[3]==="outbound"&&s[4]&&u==="POST"){let f=await i.prepare("SELECT * FROM outbounds WHERE id = ?").bind(Number(s[4])).first();if(!f)return E({ok:!1,error:"outbound not found"},404);try{return E(await Kr(e,f,y=>console.log(y)))}catch(y){return E({ok:!1,error:y.message},500)}}}return E({error:"not found"},404)}async function rn(t){try{let{results:e}=await t.prepare("SELECT name FROM pragma_table_info('outbounds')").all();if((e||[]).some(r=>r.name==="transport"))return;await t.prepare("ALTER TABLE outbounds ADD COLUMN transport TEXT DEFAULT 'ws'").run(),console.log("[admin] outbounds.transport column added (migration)")}catch(e){console.log("[admin] outbounds transport migration skipped: "+e.message)}}async function ns(t,e,r,n,a){let{table:s,cols:o}=r,l="id";if(t==="GET"){let{results:u}=await n.prepare(`SELECT * FROM ${s} ORDER BY id`).all();return E(u||[])}if(t==="POST"){let u=await Ce(a);if(!u)return E({error:"bad body"},400);if(r.validate){let h=r.validate(u);if(h)return E({error:h},400)}s==="outbounds"&&await rn(n);let i=o.filter(h=>u[h]!==void 0);if(i.length===0)return E({error:"no fields"},400);let c=i.map(()=>"?").join(","),d=i.map(h=>u[h]),{meta:p}=await n.prepare(`INSERT INTO ${s} (${i.join(",")}) VALUES (${c})`).bind(...d).run();return r.cacheKey&&ue(r.cacheKey),E({ok:!0,id:p.last_row_id})}if(t==="PUT"&&e){let u=await Ce(a);if(!u)return E({error:"bad body"},400);if(r.validate){let p=r.validate(u);if(p)return E({error:p},400)}s==="outbounds"&&await rn(n);let i=o.filter(p=>u[p]!==void 0);if(i.length===0)return E({error:"no fields"},400);let c=i.map(p=>`${p} = ?`).join(","),d=i.map(p=>u[p]);return await n.prepare(`UPDATE ${s} SET ${c} WHERE ${l} = ?`).bind(...d,Number(e)).run(),r.cacheKey&&ue(r.cacheKey),E({ok:!0})}return t==="DELETE"&&e?(await n.prepare(`DELETE FROM ${s} WHERE ${l} = ?`).bind(Number(e)).run(),r.cacheKey&&ue(r.cacheKey),E({ok:!0})):E({error:"method not allowed"},405)}var nn={geosite:["cn","apple","google","microsoft","facebook","twitter","telegram","github","netflix","youtube","spotify","discord","tiktok","paypal","steam","cloudflare","openai","anthropic","amazon","whatsapp","instagram","linkedin","mozilla","adobe","speedtest","oracle","digitalocean","vultr","jetbrains","gitee","baidu","aliyun","tencent","jd","bilibili","douyin","zhihu","iqiyi","youku","xiaomi","huawei"],geoip:["cn","hk","mo","tw","jp","kr","sg","my","th","vn","id","ph","us","ca","gb","de","fr","nl","se","au","nz","ru","in","br","ar","mx","za","tr","ae","sa","il","es","it","ch","at","be","dk","fi","no","pl","pt","ie","cz","hu","ro","ua","kz"]};async function We(t,e,r){let n=await ls();(!n||n.length===0)&&(n=nn.geosite.slice(),console.log("[geo] v2fly category enumeration failed, fallback to DEFAULT_GEO_CATEGORIES.geosite"));let a={geosite:n,geoip:nn.geoip},s=a.geosite.length+a.geoip.length,o=i=>{if(typeof r=="function")try{r(i)}catch{}},l={updated:0,total:0,failed:[]},u=0;for(let i of["geosite","geoip"])for(let c of a[i]){l.total++,u++,o({state:"updating",step:u,total:s,current:`${i}:${c}`,updated:l.updated,failed:l.failed,message:`\u62C9\u53D6 ${i}:${c}`});try{let d=await as(i,c);d&&d.length>0?(await e.put(`${i}:${c}`,JSON.stringify(d)),l.updated++):l.failed.push(`${i}:${c} (empty rules)`)}catch(d){l.failed.push(`${i}:${c} (${d.message||d})`)}}return await e.put(Pe,new Date().toISOString()),mr(),l}async function Ve(t,e){let r=Date.now(),n=a=>e.put("geo:update_status",JSON.stringify({startedAt:r,...a})).catch(()=>{});try{await n({state:"updating",step:0,total:0,updated:0,failed:[],current:"",message:"\u5F00\u59CB\u66F4\u65B0"});let a=await We(t,e,s=>n({...s}));return await n({state:"done",step:a.total,total:a.total,updated:a.updated,failed:a.failed,current:"",message:"\u66F4\u65B0\u5B8C\u6210"}),await e.put("geo:updating","0").catch(()=>{}),a}catch(a){throw await n({state:"error",message:a.message||String(a),failed:[]}).catch(()=>{}),a}}async function as(t,e){if(t==="geosite"){let a=await ln(e,new Set);if(a.length===0)throw new Error("empty geosite rules");return a}let r=await ps(e),n=[];for(let[a,s]of r)if(a.length===4?n.push(...ms(a,s)):n.push(...gs(a,s)),n.length>=3e4)break;if(n.length===0)throw new Error("empty geoip cidrs");return n}var ss="https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/",os="https://cdn.jsdelivr.net/gh/v2fly/domain-list-community@master/data/",is=2e4;function an(t){let e=t.indexOf(".");return e>0?t.slice(0,e):t}async function ls(){try{let t=await fetch("https://api.github.com/repos/v2fly/domain-list-community/git/trees/master?recursive=1",{headers:{"User-Agent":"vless-trojan-d1"},cf:{cacheTtl:86400}});if(t.ok){let e=await t.json(),r=e&&Array.isArray(e.tree)?e.tree:[],n=new Set;for(let a of r){if(!a||a.type!=="blob"||typeof a.path!="string"||!a.path.startsWith("data/"))continue;let s=a.path.slice(5);!s||s.includes("/")||n.add(an(s))}if(n.size>0)return[...n].sort()}}catch{}try{let t=await fetch("https://api.github.com/repos/v2fly/domain-list-community/contents/data",{headers:{"User-Agent":"vless-trojan-d1"},cf:{cacheTtl:86400}});if(t.ok){let e=await t.json();if(Array.isArray(e)){let r=new Set;for(let n of e){if(!n||n.type!=="file"||typeof n.name!="string")continue;let a=an(n.name);a&&r.add(a)}if(r.size>0)return[...r].sort()}}}catch{}return null}async function ln(t,e){if(e.has(t))return[];e.add(t);let r=encodeURIComponent(t),n=[ss+r,os+r],a=null;for(let s of n)try{let o=await fetch(s,{cf:{cacheTtl:86400}});if(!o.ok){a=new Error(`HTTP ${o.status}`);continue}let l=await o.text(),u=[];for(let i of l.split(`
`)){if(i=i.trim(),!i||i.startsWith("#"))continue;if(i.startsWith("include:")){let p=i.slice(8).trim().split(/\s+/)[0];p&&u.push(...await ln(p,e));continue}let c=i;if(c.startsWith("full:"))c=c.slice(5);else if(c.startsWith("domain:"))c=c.slice(7);else if(c.startsWith("keyword:")||c.startsWith("regexp:"))continue;c=c.replace(/\s+@[^\s#]+/g,"");let d=c.indexOf("#");d>=0&&(c=c.slice(0,d)),c=c.trim().toLowerCase().replace(/^\.+/,""),c&&u.length<is&&u.push(c)}return u}catch(o){a=o}throw a||new Error("v2fly geosite fetch failed")}var cs="https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/",us="https://cdn.jsdelivr.net/gh/SagerNet/sing-geoip@rule-set/",ds=3e4;async function ps(t){let e=encodeURIComponent(t),r=[cs+"geoip-"+e+".srs",us+"geoip-"+e+".srs"],n=null;for(let a of r)try{let s=await fetch(a,{cf:{cacheTtl:86400}});if(!s.ok){n=new Error(`HTTP ${s.status}`);continue}let o=new Uint8Array(await s.arrayBuffer());if(o.length<5||o[0]!==83||o[1]!==82||o[2]!==83){n=new Error("bad srs magic");continue}if(o[3]>1){n=new Error(`unsupported srs version ${o[3]}`);continue}let l;try{l=tn(o.subarray(4))}catch{n=new Error("zlib inflate failed");continue}return fs(l)}catch(s){n=s}throw n||new Error("sing-geoip srs fetch failed")}function fs(t){let e=0,r=he(t,e);e=r.p;let n=[];for(let a=0;a<r.v;a++){let s=t[e++];if(s!==0)throw new Error(`geoip logical rule unsupported (type ${s})`);for(;;){let o=t[e++];if(o===255)break;if(o===5||o===6){if(t[e++]!==1)throw new Error("bad ipset version");let l=hs(t,e);e+=8;for(let u=0;u<l&&n.length<ds*2;u++){let i=he(t,e);e=i.p;let c=t.subarray(e,e+i.v);e+=i.v,i=he(t,e),e=i.p;let d=t.subarray(e,e+i.v);if(e+=i.v,c.length!==d.length||c.length!==4&&c.length!==16)throw new Error("bad ipset addr");n.push([c,d])}}else if(o===0||o===7||o===9){let l=he(t,e);e=l.p,e+=l.v*2}else if(o===1||o===3||o===4||o===8||o===10||o===11||o===12||o===13||o===14||o===15||o===17||o===18||o===19||o===20||o===21||o===22||o===23){let l=he(t,e);e=l.p;for(let u=0;u<l.v;u++){let i=he(t,e);e=i.p,e+=i.v}}else throw new Error(`geoip unsupported item type ${o}`)}}return n}function he(t,e){let r=0,n=0;for(;;){let a=t[e++];if(r|=(a&127)<<n,!(a&128))break;if(n+=7,n>63)throw new Error("uvarint overflow")}return{v:r,p:e}}function hs(t,e){let r=0;for(let n=0;n<8;n++)r=r*256+t[e+n];return r}function ms(t,e){let r=(t[0]<<24>>>0)+(t[1]<<16)+(t[2]<<8)+t[3],n=(e[0]<<24>>>0)+(e[1]<<16)+(e[2]<<8)+e[3],a=[];for(;r<=n;){let s=0;for(;;){let o=1<<s+1;if((r&o-1)!==0||r+o-1>n)break;s++}a.push(`${r>>>24}.${r>>>16&255}.${r>>>8&255}.${r&255}/${32-s}`),r+=1<<s}return a}function gs(t,e){let r=0n,n=0n;for(let s of t)r=r<<8n|BigInt(s);for(let s of e)n=n<<8n|BigInt(s);let a=[];for(;r<=n;){let s=0n;for(;;){let o=1n<<s+1n;if((r&o-1n)!==0n||r+o-1n>n)break;s++}a.push(`${bs(r)}/${128-Number(s)}`),r+=1n<<s}return a}function bs(t){let e=[];for(let l=7;l>=0;l--)e.push(Number(t>>BigInt(l*16)&0xffffn));let r=-1,n=0,a=-1,s=0;for(let l=0;l<8;l++)e[l]===0?(a<0&&(a=l),s++,s>n&&(n=s,r=a)):(a=-1,s=0);let o="";for(let l=0;l<8;l++)l===r&&n>=2?(o+=(o.length>0&&!o.endsWith(":"),"::"),l+=n-1):(o.length>0&&!o.endsWith(":")&&(o+=":"),o+=e[l].toString(16));return o}var sn=!1;async function ys(t){if(sn)return;let e=[["path","TEXT DEFAULT ''"],["expire_at","INTEGER DEFAULT 0"],["traffic_limit","INTEGER DEFAULT 0"],["traffic_reset_at","INTEGER DEFAULT 0"]];for(let r of["vless_users","trojan_users"])try{let{results:n}=await t.prepare(`SELECT name FROM pragma_table_info('${r}')`).all(),a=new Set((n||[]).map(s=>s.name));for(let[s,o]of e)a.has(s)||(await t.prepare(`ALTER TABLE ${r} ADD COLUMN ${s} ${o}`).run(),console.log(`[admin] ${r}.${s} column added (migration)`))}catch(n){console.log(`[admin] ${r} migration skipped: ${n.message}`)}sn=!0}var vt=null;function cn(t){if(!t&&vt)return vt;let r=`<!DOCTYPE html>
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
    ${t?`<p style="margin:-8px 0 16px;padding:10px 12px;background:var(--ok-bg);color:var(--ok-text);border-radius:10px;font-size:13px">\u9996\u6B21\u90E8\u7F72\u521D\u59CB\u5BC6\u7801\uFF1A<b>${t}</b><br>\u767B\u5F55\u540E\u8BF7\u53CA\u65F6\u4FEE\u6539</p>`:""}
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
  outbounds:{ title:'\u51FA\u7AD9\u4EE3\u7406', api:'outbounds', fields:[{k:'type',label:'\u7C7B\u578B',type:'select',opts:['socks5','http','vless']},{k:'name',label:'\u540D\u79F0'},{k:'address',label:'\u5730\u5740'},{k:'port',label:'\u7AEF\u53E3',type:'number'},{k:'username',label:'\u7528\u6237\u540D(\u4EC5socks5/http)'},{k:'password',label:'\u5BC6\u7801(\u4EC5socks5/http)'},{k:'uuid',label:'UUID(\u4EC5vless)'},{k:'transport',label:'\u4F20\u8F93(\u4EC5vless)',type:'select',opts:['raw','ws','grpc','httpupgrade']},{k:'path',label:'Path(\u4EC5vless; grpc \u4E3A serviceName)',placeholder:'ws/httpupgrade \u586B\u8DEF\u5F84; grpc \u586B serviceName(\u7559\u7A7A\u4E3A /Tun)'},{k:'tls',label:'TLS',type:'checkbox'},{k:'sni',label:'SNI(\u4EC5vless)',placeholder:'\u7559\u7A7A\u5219\u4F7F\u7528\u5730\u5740\u4F5C\u4E3A\u8FDE\u63A5\u4E3B\u673A\u4E0ESNI'},{k:'udp',label:'UDP',type:'checkbox'},{k:'enable',label:'\u542F\u7528',type:'checkbox'},{k:'sort',label:'\u6392\u5E8F',type:'number'}] },
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
      ['ws_path','\u5165\u7AD9\u8DEF\u5F84\uFF08ws / grpc / xhttp \u5171\u4EAB\uFF1B\u7528\u6237\u672A\u81EA\u5B9A\u4E49\u8DEF\u5F84\u65F6\u56DE\u9000\u5230\u6B64\u503C\uFF09'],
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
      '<div class="card" style="background:var(--ok-bg);color:var(--ok-text);font-size:13px;border-radius:10px;padding:12px 16px;margin-bottom:16px">\u5165\u7AD9\u5DF2\u81EA\u52A8\u517C\u5BB9 ws / grpc / xhttp \u4E09\u79CD\u4F20\u8F93\u7C7B\u578B\uFF08\u540C\u4E00\u51ED\u636E\u540C\u65F6\u53EF\u7528\uFF09\u3002\u6B64\u5904\u4EC5\u9700\u8BBE\u7F6E\u5171\u4EAB\u5165\u7AD9\u8DEF\u5F84\uFF1B\u5355\u4E2A\u7528\u6237\u53EF\u5728\u300CVLESS \u7528\u6237 / Trojan \u7528\u6237\u300D\u4E2D\u81EA\u5B9A\u4E49\u8DEF\u5F84\uFF0C\u7559\u7A7A\u5219\u4F7F\u7528\u672C\u5168\u5C40\u8DEF\u5F84\u3002</div>'+
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

const ENTRY_TRANSPORTS = ['ws', 'grpc', 'xhttp'];
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
    '.entry-field input{width:100%;padding:9px 12px;border:1px solid var(--border,#e6e8ee);border-radius:10px;background:var(--input-bg);font-size:14px;color:var(--text,#1d1d1f);outline:none;transition:all .2s ease;box-sizing:border-box}' +
    '.entry-field input:focus{background:var(--card);border-color:var(--primary,#0a84ff);box-shadow:0 0 0 3px rgba(10,132,255,.12)}' +
    '.entry-chips{display:flex;gap:8px;flex-wrap:wrap;padding-top:2px}' +
    '.entry-chip{display:inline-flex;align-items:center;padding:6px 14px;border-radius:20px;border:1px solid var(--border,#e6e8ee);background:var(--badge-off);color:var(--muted);font-size:13px;font-weight:500;cursor:pointer;transition:all .2s ease;user-select:none}' +
    '.entry-chip input{display:none}' +
    '.entry-chip.on{background:var(--primary,#0a84ff);border-color:var(--primary,#0a84ff);color:#fff;font-weight:600;box-shadow:0 2px 8px rgba(10,132,255,.35)}' +
    '.entry-actions{display:flex;gap:10px;margin-top:14px;align-items:center}' +
    '.entry-save{background:var(--badge-off) !important;color:var(--muted) !important;cursor:not-allowed !important;border:none !important;box-shadow:none !important;transition:all .25s ease !important;opacity:.8}' +
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
      '<div class="card" style="background:var(--ok-bg);color:var(--ok-text);font-size:13px;border-radius:10px;padding:12px 16px;margin-bottom:16px">\u652F\u6301\u914D\u7F6E\u591A\u4E2A\u5165\u53E3\uFF0C\u6BCF\u4E2A\u5165\u53E3\u53EF\u72EC\u7ACB\u9009\u62E9\u652F\u6301\u7684\u534F\u8BAE\uFF08ws / grpc / xhttp\uFF09\u3002\u8BBF\u95EE\u5BF9\u5E94\u5165\u53E3\u57DF\u540D\u65F6\uFF0C\u5355\u51ED\u636E\u9875\u4E0E\u5355\u51ED\u636E\u8BA2\u9605\u53EA\u8F93\u51FA\u8BE5\u5165\u53E3\u52FE\u9009\u7684\u534F\u8BAE\uFF1B\u805A\u5408\u8BA2\u9605\u5728\u8BBE\u7F6E\u4E86\u5165\u53E3\u540E\u4EC5\u751F\u6210\u5404\u5165\u53E3\u52FE\u9009\u7684\u534F\u8BAE\u3002\u672A\u8BBE\u7F6E\u4EFB\u4F55\u5165\u53E3\u65F6\u4F7F\u7528\u5F53\u524D\u57DF\u540D\uFF08\u5168\u534F\u8BAE\uFF09\u3002</div>' +
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
</html>`;return t||(vt=r),r}async function un(t,e){let r=new URL(t.url);if(t.method==="POST"||t.method==="GET")try{let{DB:n,GEO_KV:a}=e,s=await We(n,a);return new Response(JSON.stringify({ok:!0,updated:s.updated,total:s.total,failed:s.failed}),{status:200,headers:{"Content-Type":"application/json; charset=utf-8"}})}catch(n){return new Response(JSON.stringify({ok:!1,error:n.message}),{status:500,headers:{"Content-Type":"application/json; charset=utf-8"}})}return new Response("Not Found",{status:404})}async function dn(t,e,r){try{let n=await We(e.DB,e.GEO_KV);console.log(`[cron] geo update done: ${n.updated}/${n.total} categories${n.failed.length?", failed: "+n.failed.join("; "):""}`)}catch(n){console.log(`[cron] geo update failed: ${n.message}`)}}globalThis.connect=ws;var Zo={async fetch(t,e,r){let a=new URL(t.url).pathname;try{if(a.startsWith("/admin")){let l=await Qe(t,e,{ensureAdmin:!0});if(a.startsWith("/admin/api/"))return await on(t,l,r);let u=cn(l.adminTempPassword),i=l.adminTempPassword?"no-store":"public, max-age=300";return new Response(u,{headers:{"Content-Type":"text/html; charset=utf-8","Cache-Control":i}})}if(a==="/geo-update-cron")return await un(t,e);let s=await Qe(t,e),o=s.inboundPathMap.get(a)||s.inboundPathMap.get(a.length>1&&a.endsWith("/")?a.slice(0,-1):a)||s.inboundPathMap.get(a.includes("//")?a.replace(/\/+/g,"/"):a);if(o&&o.length>0){s._inboundScope=Bt(o);let l=String(t.headers.get("Upgrade")||"").toLowerCase(),u=String(t.headers.get("Content-Type")||"").toLowerCase(),i=a.endsWith("/Tun"),c=!i&&t.method==="POST"&&u.includes("application/grpc");if(l==="websocket"&&!i&&!c)return await _r(t,s,e);if(i)return await Or(t,s,e);if(c)return await Ur(t,s,e)}return await Nr(t,s,e)}catch(s){return console.log(`[index] error: ${s.message||s}`),new Response(JSON.stringify({error:"internal error"}),{status:500,headers:{"Content-Type":"application/json; charset=utf-8"}})}},async scheduled(t,e,r){return dn(t,e,r)},async queue(t,e,r){for(let n of t.messages)try{if(await e.GEO_KV.get("geo:update_busy")==="1"){console.log("[queue] geo update already in progress, skip message"),n.ack();continue}await e.GEO_KV.put("geo:update_busy","1",{expirationTtl:7200});try{let s=await Ve(e.DB,e.GEO_KV);console.log(`[queue] geo update done: ${s.updated}/${s.total} categories${s.failed.length?", failed: "+s.failed.join("; "):""}`),n.ack()}finally{await e.GEO_KV.put("geo:update_busy","0").catch(()=>{})}}catch(a){throw console.log(`[queue] geo update failed (will retry): ${a.message||a}`),a}}};export{Zo as default};
