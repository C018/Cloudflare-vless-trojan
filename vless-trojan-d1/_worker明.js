import{connect as ks}from"cloudflare:sockets";var K="direct",dt="reject",qt="socks5",Jt="http",Zt="vless",De=["raw","ws","grpc","httpupgrade","h2"];var Re="geosite:",Oe="geoip:",Pt="geo:version",bt="vtd_admin";var Ce=["qq.com","taobao.com","tmall.com","jd.com","baidu.com","bilibili.com","douyin.com","weibo.com","zhihu.com","163.com","126.com","aliyun.com","tencent.com","weixin.qq.com","alipay.com","bankofchina.com","icbc.com.cn","ccb.com","abcchina.com","cmbchina.com","boc.cn","12306.cn","gov.cn","cn","com.cn","net.cn","org.cn"],Pe=["speedtest.net","fast.com","ookla.com"],Me=["google.com","googleapis.com","gstatic.com","googleusercontent.com","ggpht.com","google.cn","google.com.hk","gvt1.com","gvt2.com","gvt3.com"],Qt=[];for(let t=0;t<=255;++t){let e=t.toString(16).padStart(2,"0");Qt.push(e)}var te=1e5;function ee(t){return Array.from(new Uint8Array(t)).map(e=>e.toString(16).padStart(2,"0")).join("")}function xr(){let t=new Uint8Array(16);return crypto.getRandomValues(t),ee(t)}async function Ie(t,e,n){let a=await crypto.subtle.importKey("raw",new TextEncoder().encode(t),"PBKDF2",!1,["deriveBits"]),r=await crypto.subtle.deriveBits({name:"PBKDF2",salt:new TextEncoder().encode(e),iterations:n,hash:"SHA-256"},a,256);return ee(r)}async function Ne(t){let e=xr(),n=await Ie(t,e,te);return`${e}:${te}:${n}`}async function Mt(t,e){if(!e||!t)return!1;let n=String(e).split(":");if(n.length!==3)return!1;let[a,r,s]=n,o=parseInt(r,10)||te;return await Ie(t,a,o)===s}async function He(t,e){let n=await crypto.subtle.importKey("raw",new TextEncoder().encode(t),{name:"HMAC",hash:"SHA-256"},!1,["sign"]),a=await crypto.subtle.sign("HMAC",n,new TextEncoder().encode(e));return ee(a)}async function Fe(t){let n=`admin.${Math.floor(Date.now()/1e3)+604800}`,a=await He(t,n);return`${n}.${a}`}async function ze(t,e){if(!t||!e)return!1;let n=String(t).split(".");if(n.length!==3)return!1;let[a,r,s]=n;if(a!=="admin")return!1;let o=Number(r);if(!Number.isFinite(o)||o<Date.now()/1e3)return!1;let l=await He(e,`${a}.${r}`);if(l.length!==s.length)return!1;let u=0;for(let i=0;i<l.length;i++)u|=l.charCodeAt(i)^s.charCodeAt(i);return u===0}function Be(t){let e={};if(!t)return e;for(let n of t.split(";")){let a=n.indexOf("=");if(a<0)continue;let r=n.slice(0,a).trim(),s=n.slice(a+1).trim();e[r]=decodeURIComponent(s)}return e}var We=3e4,kr=3e4,je=0,xt={settings:{p:null,ts:0},vlessUsers:{p:null,ts:0},trojanUsers:{p:null,ts:0},outbounds:{p:null,ts:0},routingRules:{p:null,ts:0}},X={p:null,ts:0};function wt(t,e){let n=xt[t],a=Date.now();if(n.p&&a-n.ts<We)return n.p;let r=Promise.resolve().then(e).catch(()=>null);return n.p=r,n.ts=a,r}function pt(t){if(X.p=null,X.ts=0,t==="all"){for(let n of Object.keys(xt))xt[n].p=null,xt[n].ts=0;return}let e=xt[t];e&&(e.p=null,e.ts=0)}async function Er(t){try{let{results:e}=await t.prepare("SELECT key, value FROM settings").all(),n={};for(let a of e||[])n[a.key]=a.value;return n}catch{return{}}}async function Sr(t){try{let{results:e}=await t.prepare("SELECT id, uuid, remark, up, down, path, expire_at, traffic_limit, traffic_reset_at FROM vless_users WHERE enable = 1 ORDER BY id").all();return e||[]}catch{try{let{results:n}=await t.prepare("SELECT id, uuid, remark, up, down FROM vless_users WHERE enable = 1 ORDER BY id").all();return(n||[]).map(a=>({path:"",expire_at:0,traffic_limit:0,traffic_reset_at:0,...a}))}catch{return[]}}}async function Ar(t){try{let{results:e}=await t.prepare("SELECT id, password, remark, up, down, path, expire_at, traffic_limit, traffic_reset_at FROM trojan_users WHERE enable = 1 ORDER BY id").all();return e||[]}catch{try{let{results:n}=await t.prepare("SELECT id, password, remark, up, down FROM trojan_users WHERE enable = 1 ORDER BY id").all();return(n||[]).map(a=>({path:"",expire_at:0,traffic_limit:0,traffic_reset_at:0,...a}))}catch{return[]}}}function _r(t){let e=String(t||"").trim();if(!e)return"";for(e.startsWith("/")||(e="/"+e);e.length>1&&e.endsWith("/");)e=e.slice(0,-1);return e}async function Ge(t,e,n){let a=Math.floor(Date.now()/1e3);for(let r of e)if(r.traffic_reset_at>0&&r.traffic_reset_at<=a)try{await t.prepare(`UPDATE ${n} SET up = 0, down = 0, traffic_reset_at = 0 WHERE id = ?`).bind(r.id).run(),r.up=0,r.down=0,r.traffic_reset_at=0}catch{}}function Lr(t,e,n){let a=new Map,r=(s,o)=>{let l=_r(s);if(!l)return;a.has(l)||a.set(l,[]),a.get(l).push(o);let u=`${l}/Tun`;a.has(u)||a.set(u,[]),a.get(u).push(o)};r(t,{kind:"all"});for(let s of e)s.path&&r(s.path,{kind:"vless",credential:s.uuid.toLowerCase()});for(let s of n)s.path&&r(s.path,{kind:"trojan",credential:s.password});return a}async function $r(t){try{let{results:e}=await t.prepare("SELECT * FROM outbounds WHERE enable = 1 ORDER BY sort ASC, id ASC").all();return e||[]}catch{return[]}}async function Ur(t){try{let{results:e}=await t.prepare("SELECT * FROM routing_rules WHERE enable = 1 ORDER BY sort ASC, id ASC").all();return e||[]}catch{return[]}}async function Dr(t){try{let a=await t.prepare("SELECT value FROM settings WHERE key = ?").bind("admin_password_hash").first();if(a&&a.value)return{hash:a.value,tempPassword:null}}catch{}let e=Cr().replace(/-/g,"").slice(0,12),n=await Ne(e);try{await t.prepare("INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at").bind("admin_password_hash",n,Date.now()).run(),pt("settings")}catch{}return{hash:n,tempPassword:e}}function Rr(t){let e=[];try{let n=t.entry_list;if(n){let a=JSON.parse(n);Array.isArray(a)&&(e=a)}}catch{e=[]}return!e.length&&(t.entry_host||"").trim()&&(e=[{host:t.entry_host,port:t.entry_port||"",sni:t.entry_sni||"",wsHost:t.entry_ws_host||"",remark:"",transports:[]}]),e.map(n=>{let a=String(n.host||"").trim(),r=String(n.wsHost||"").trim()||a;return{host:a,port:String(n.port||"").trim()||"443",sni:String(n.sni||"").trim()||r,wsHost:r,remark:String(n.remark||"").trim(),transports:Array.isArray(n.transports)?n.transports.filter(s=>["ws","grpc","h2","xhttp"].includes(s)):["ws","grpc","xhttp"]}}).filter(n=>n.host)}function Or(t,e,n,a){let r=t.ws_path||"/ws",s=t.entry_transport||"ws",o=t.default_outbound||K,l=t.ip_preference||"ipv4",u=t.proxyip||"",i="",c=443,d="";if(u)if(e.find(E=>E.name===u&&E.type!==K&&E.type!==dt))d=u;else{let E=u.lastIndexOf(":");E>0&&!u.includes("]")&&/^\d+$/.test(u.slice(E+1))?(i=u.slice(0,E),c=Number(u.slice(E+1))||443):i=u}let f=t.udp_outbound||"",p=Rr(t),y=p.length?p[0].host:"",g=p.length?p[0].port:"",m=p.length?p[0].sni:"",h=p.length?p[0].wsHost:"",b=Lr(r,n,a),x={};for(let w of n)x[w.uuid.toLowerCase()]=w;let v={};for(let w of a)v[w.password]=w;return{wsPath:r,entryTransport:s,defaultOutbound:o,ipPreference:l,adminPasswordHash:t.admin_password_hash||"",proxyipHost:i,proxyipPort:c,proxyipOutbound:d,proxyipDisabled:o!==K,udpOutbound:f,entryHost:y,entryPort:g,entrySni:m,entryWsHost:h,entries:p,vlessIndex:x,trojanIndex:v,uuidSet:new Set(n.map(w=>w.uuid.toLowerCase())),passwordSet:new Set(a.map(w=>w.password)),outboundByName:e.reduce((w,E)=>(w[E.name]=E,w),{}),inboundPathMap:b}}async function ne(t,e,n={}){let{DB:a}=e,[r,s,o,l,u]=await Promise.all([wt("settings",()=>Er(a)),wt("outbounds",()=>$r(a)),wt("vlessUsers",()=>Sr(a)),wt("trojanUsers",()=>Ar(a)),wt("routingRules",()=>Ur(a))]),i,c=Date.now();if(X.p&&c-X.ts<We)i=await X.p;else{let y=Promise.resolve().then(()=>Or(r,s,o,l));X.p=y,X.ts=c;try{i=await y}catch(g){throw X.p=null,X.ts=0,g}}let d=i.adminPasswordHash,f=null;if(!d&&n.ensureAdmin){let y=await Dr(a);d=y.hash,f=y.tempPassword}let p=Date.now();return p-je>=kr&&(await Promise.all([Ge(a,o,"vless_users"),Ge(a,l,"trojan_users")]),je=p),{env:e,settings:r,wsPath:i.wsPath,entryTransport:i.entryTransport,defaultOutbound:i.defaultOutbound,adminPasswordHash:d,adminTempPassword:f,proxyipHost:i.proxyipHost,proxyipPort:i.proxyipPort,proxyipOutbound:i.proxyipOutbound,proxyipDisabled:i.proxyipDisabled,ipPreference:i.ipPreference,udpOutbound:i.udpOutbound,entryHost:i.entryHost,entryPort:i.entryPort,entrySni:i.entrySni,entryWsHost:i.entryWsHost,entries:i.entries,vlessUsers:o,trojanUsers:l,outbounds:s,routingRules:u,vlessIndex:i.vlessIndex,trojanIndex:i.trojanIndex,uuidSet:i.uuidSet,passwordSet:i.passwordSet,outboundByName:i.outboundByName,inboundPathMap:i.inboundPathMap}}function Cr(){return globalThis.crypto&&typeof globalThis.crypto.randomUUID=="function"?globalThis.crypto.randomUUID():"xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(/[xy]/g,t=>{let e=Math.random()*16|0;return(t==="x"?e:e&3|8).toString(16)})}function Ve(t){let e=new Set,n=new Set;for(let a of t){if(a.kind==="all")return{all:!0,vless:e,trojan:n};a.kind==="vless"&&a.credential&&e.add(a.credential),a.kind==="trojan"&&a.credential&&n.add(a.credential)}return{all:!1,vless:e,trojan:n}}var Pr=new TextDecoder,It=new Map,Mr=64;function Ir(t){let e=It.get(t);if(e)return e;let n=t.replace(/-/g,"");e=new Uint8Array(16);for(let a=0;a<16;a++)e[a]=parseInt(n.substr(a*2,2),16);return It.size>=Mr&&It.clear(),It.set(t,e),e}function Nr(t){let e=n=>Qt[t[n]];return`${e(0)}${e(1)}${e(2)}${e(3)}-${e(4)}${e(5)}-${e(6)}${e(7)}-${e(8)}${e(9)}-${e(10)}${e(11)}${e(12)}${e(13)}${e(14)}${e(15)}`}function Ke(t,e){if(t.byteLength<24)return{hasError:!0,message:"invalid data"};let n=t instanceof Uint8Array?t:new Uint8Array(t),a=Nr(n.subarray(1,17));if(!e.has(a))return{hasError:!0,message:"invalid user"};let s=18+n[17];if(t.byteLength<s+4)return{hasError:!0,message:"invalid data"};let o=n[s];if(o!==1&&o!==2)return{hasError:!0,message:`command ${o} is not supported`};let l=s+1,u=n[l]<<8|n[l+1],i=n[l+2],c,d,f;switch(i){case 1:d=4,f=l+3,c=`${n[f]}.${n[f+1]}.${n[f+2]}.${n[f+3]}`;break;case 2:if(t.byteLength<l+4)return{hasError:!0,message:"invalid data"};d=n[l+3],f=l+4,c=Pr.decode(n.subarray(f,f+d));break;case 3:d=16,f=l+3,c=`${(n[f]<<8|n[f+1]).toString(16)}:${(n[f+2]<<8|n[f+3]).toString(16)}:${(n[f+4]<<8|n[f+5]).toString(16)}:${(n[f+6]<<8|n[f+7]).toString(16)}:${(n[f+8]<<8|n[f+9]).toString(16)}:${(n[f+10]<<8|n[f+11]).toString(16)}:${(n[f+12]<<8|n[f+13]).toString(16)}:${(n[f+14]<<8|n[f+15]).toString(16)}`;break;default:return{hasError:!0,message:`invalid addressType: ${i}`}}return c?{hasError:!1,userUuid:a,addressRemote:c,addressType:i,portRemote:u,rawDataIndex:f+d,isUDP:o===2}:{hasError:!0,message:"addressValue is empty"}}function Ye(t,e,n,a,r){let s,o,l=[];switch(e){case 1:s=4,l=n.split(".").map(Number);break;case 2:o=new TextEncoder().encode(n),s=o.length+1;break;case 3:s=16,l=re(n).split(":").map(i=>[parseInt(i.slice(0,2),16),parseInt(i.slice(2),16)]).flat();break;default:throw new Error(`Unknown address type: ${e}`)}let u=new Uint8Array(22+s);return u[0]=0,u.set(Ir(r),1),u[17]=0,u[18]=t,u[19]=a>>8,u[20]=a&255,u[21]=e,e===2?(u[22]=o.length,u.set(o,23)):u.set(l,22),u}function re(t){if(t=t.replace(/^\[|\]$/g,""),t.includes("::")){let e=t.split("::"),n=e[0]?e[0].split(":"):[],a=e[1]?e[1].split(":"):[],r=8-n.length-a.length,s=Array(Math.max(0,r)).fill("0");return[...n,...s,...a].map(o=>o.padStart(4,"0")).join(":")}return t.split(":").map(e=>e.padStart(4,"0")).join(":")}var Xe=new TextDecoder,Hr=new Uint32Array([1116352408,1899447441,3049323471,3921009573,961987163,1508970993,2453635748,2870763221,3624381080,310598401,607225278,1426881987,1925078388,2162078206,2614888103,3248222580,3835390401,4022224774,264347078,604807628,770255983,1249150122,1555081692,1996064986,2554220882,2821834349,2952996808,3210313671,3336571891,3584528711,113926993,338241895,666307205,773529912,1294757372,1396182291,1695183700,1986661051,2177026350,2456956037,2730485921,2820302411,3259730800,3345764771,3516065817,3600352804,4094571909,275423344,430227734,506948616,659060556,883997877,958139571,1322822218,1537002063,1747873779,1955562222,2024104815,2227730452,2361852424,2428436474,2756734187,3204031479,3329325298]),Fr=new Uint32Array([3238371032,914150663,812702999,4144912697,4290775857,1750603025,1694076839,3204075428]),Y=(t,e)=>t>>>e|t<<32-e;function zr(t){let e=new TextEncoder().encode(t),n=Math.floor(e.length/536870912),a=e.length*8>>>0,r=(e.length+9)%64,s=r===0?0:64-r,o=e.length+1+s+8,l=new Uint8Array(o);l.set(e),l[e.length]=128;let u=new DataView(l.buffer);u.setUint32(o-8,n),u.setUint32(o-4,a);let i=Fr.slice(),c=new Uint32Array(64);for(let f=0;f<o;f+=64){for(let w=0;w<16;w++)c[w]=u.getUint32(f+w*4);for(let w=16;w<64;w++){let E=Y(c[w-15],7)^Y(c[w-15],18)^c[w-15]>>>3,$=Y(c[w-2],17)^Y(c[w-2],19)^c[w-2]>>>10;c[w]=c[w-16]+E+c[w-7]+$>>>0}let p=i[0],y=i[1],g=i[2],m=i[3],h=i[4],b=i[5],x=i[6],v=i[7];for(let w=0;w<64;w++){let E=Y(h,6)^Y(h,11)^Y(h,25),$=h&b^~h&x,U=v+E+$+Hr[w]+c[w]>>>0,S=Y(p,2)^Y(p,13)^Y(p,22),O=p&y^p&g^y&g,T=S+O>>>0;v=x,x=b,b=h,h=m+U>>>0,m=g,g=y,y=p,p=U+T>>>0}i[0]=i[0]+p>>>0,i[1]=i[1]+y>>>0,i[2]=i[2]+g>>>0,i[3]=i[3]+m>>>0,i[4]=i[4]+h>>>0,i[5]=i[5]+b>>>0,i[6]=i[6]+x>>>0,i[7]=i[7]+v>>>0}let d="";for(let f=0;f<7;f++)d+=i[f].toString(16).padStart(8,"0");return d}var ae=new Map,qe=new Map;function Br(t){if(ae.has(t))return ae.get(t);let e=zr(t);return ae.set(t,e),qe.set(e,t),e}function Je(t){if(t.byteLength<60)return!1;let e=t instanceof Uint8Array?t:new Uint8Array(t);return e[0]===0?!1:e[56]===13&&e[57]===10}async function Ze(t,e){if(t.byteLength<60)return{hasError:!0,message:"Invalid Trojan data: too short"};let n=t instanceof Uint8Array?t:new Uint8Array(t),a=t instanceof Uint8Array?new DataView(t.buffer,t.byteOffset,t.byteLength):new DataView(t);if(n[56]!==13||n[57]!==10)return{hasError:!0,message:"Invalid Trojan header: missing CRLF"};let r=Xe.decode(n.subarray(0,56)),s=null,o=qe.get(r);if(o!==void 0&&e.has(o))s=o;else for(let h of e)try{if(await Br(h)===r){s=h;break}}catch{}if(!s)return{hasError:!0,message:"Invalid Trojan password"};let l=n[58];if(l!==1&&l!==3)return{hasError:!0,message:`Unsupported Trojan command: ${l}`};let i=n[59]===13&&n[60]===10?61:59;if(t.byteLength<i+1)return{hasError:!0,message:"Invalid Trojan header: too short"};let c=n[i],d,f,p;switch(c){case 1:if(f=4,p=i+1,t.byteLength<p+f+2)return{hasError:!0,message:"Invalid Trojan header: IPv4 truncated"};d=`${a.getUint8(p)}.${a.getUint8(p+1)}.${a.getUint8(p+2)}.${a.getUint8(p+3)}`;break;case 3:if(f=n[i+1],p=i+2,t.byteLength<p+f+2)return{hasError:!0,message:"Invalid Trojan header: domain truncated"};d=Xe.decode(n.subarray(p,p+f));break;case 4:if(f=16,p=i+1,t.byteLength<p+f+2)return{hasError:!0,message:"Invalid Trojan header: IPv6 truncated"};d=`${a.getUint16(p).toString(16)}:${a.getUint16(p+2).toString(16)}:${a.getUint16(p+4).toString(16)}:${a.getUint16(p+6).toString(16)}:${a.getUint16(p+8).toString(16)}:${a.getUint16(p+10).toString(16)}:${a.getUint16(p+12).toString(16)}:${a.getUint16(p+14).toString(16)}`;break;default:return{hasError:!0,message:`Invalid Trojan address type: ${c}`}}let y=p+f;if(t.byteLength<y+2)return{hasError:!0,message:"Invalid Trojan header: port truncated"};let g=a.getUint16(y),m=y+2;return t.byteLength<m+2?{hasError:!0,message:"Invalid Trojan header: missing final CRLF"}:n[m]!==13||n[m+1]!==10?{hasError:!0,message:"Invalid Trojan header: invalid final CRLF"}:{hasError:!1,userPassword:s,addressRemote:d,addressType:c===3?2:c===4?3:c,portRemote:g,rawDataIndex:m+2,isUDP:l===3}}function Qe(t){if(!t)return{earlyData:null,error:null};try{let e=t.replace(/-/g,"+").replace(/_/g,"/"),n=atob(e),a=new ArrayBuffer(n.length),r=new Uint8Array(a);for(let s=0;s<n.length;s++)r[s]=n.charCodeAt(s);return{earlyData:a,error:null}}catch(e){return{earlyData:null,error:e}}}function Q(t){try{t&&t.readyState===1&&t.close()}catch{}}async function tn(t,e){let n=t.sni&&t.sni!==""?t.sni:t.address,a=Number(t.port),r;try{r=globalThis.connect?globalThis.connect({hostname:n,port:a,secureTransport:t.tls?"on":"off"}):void 0}catch(i){return e(`[VLESS/raw] connect error: ${i.message}`),null}if(!r)return e("[VLESS/raw] connect unavailable"),null;let s=r.readable.getReader(),o,l=new Promise(i=>{o=i});return(r.closed||Promise.resolve()).then(o,o),{readable:new ReadableStream({start(i){(async()=>{try{for(;;){let{done:c,value:d}=await s.read();if(c)break;d&&d.byteLength>0&&i.enqueue(d)}try{i.close()}catch{}}catch(c){try{i.error(c)}catch{}}})()},cancel(){try{s.cancel()}catch{}}}),writable:r.writable,closed:l,send:async i=>{let c=r.writable.getWriter();try{await c.write(i)}finally{try{c.releaseLock()}catch{}}}}}function jr(t,e){let n=new Uint8Array(t.length+e.length);return n.set(t,0),n.set(e,t.length),n}function Gr(t){for(let e=0;e+3<t.length;e++)if(t[e]===13&&t[e+1]===10&&t[e+2]===13&&t[e+3]===10)return e;return-1}function Wr(t){for(let e=0;e+1<t.length;e++)if(t[e]===13&&t[e+1]===10)return new TextDecoder().decode(t.slice(0,e));return""}async function en(t,e){let n=t.sni&&t.sni!==""?t.sni:t.address,a=Number(t.port),r;try{r=globalThis.connect?globalThis.connect({hostname:n,port:a,secureTransport:t.tls?"on":"off"}):void 0}catch(y){return e(`[VLESS/httpupgrade] connect error: ${y.message}`),null}if(!r)return e("[VLESS/httpupgrade] connect unavailable"),null;let o=`GET ${t.path&&t.path.startsWith("/")?t.path:`/${t.path||""}`} HTTP/1.1\r
Host: ${n}:${a}\r
Connection: Upgrade\r
Upgrade: websocket\r
\r
`,l=r.readable.getReader(),u,i=new Promise(y=>{u=y});(r.closed||Promise.resolve()).then(u,u);let c=new Uint8Array(0),d=new Uint8Array(0);try{await Promise.race([(async()=>{let y=r.writable.getWriter();try{await y.write(new TextEncoder().encode(o))}finally{try{y.releaseLock()}catch{}}for(;;){let{done:g,value:m}=await l.read();if(g)break;if(m&&m.byteLength>0){c=jr(c,m);let h=Gr(c);if(h>=0){d=c.slice(h+4);return}}}throw new Error("connection closed during handshake")})(),new Promise((y,g)=>setTimeout(()=>g(new Error("Handshake timeout")),1e4))])}catch(y){e(`[VLESS/httpupgrade] handshake failed: ${y.message}`);try{r.close()}catch{}return null}let f=Wr(c);if(!/^HTTP\/1\.1 101/.test(f)){e(`[VLESS/httpupgrade] upgrade rejected: ${f}`);try{r.close()}catch{}return null}return{readable:new ReadableStream({start(y){d.byteLength>0&&y.enqueue(d),(async()=>{try{for(;;){let{done:g,value:m}=await l.read();if(g)break;m&&m.byteLength>0&&y.enqueue(m)}try{y.close()}catch{}}catch(g){try{y.error(g)}catch{}}})()},cancel(){try{l.cancel()}catch{}}}),writable:r.writable,closed:i,send:async y=>{let g=r.writable.getWriter();try{await g.write(y)}finally{try{g.releaseLock()}catch{}}}}}var Vr=`PRI * HTTP/2.0\r
\r
SM\r
\r
`;var se=new TextEncoder;function Kr(t,e){let n=se.encode(t),a=se.encode(e),r=new Uint8Array(2+n.length+1+a.length);return r[0]=0,r[1]=n.length,r.set(n,2),r[2+n.length]=a.length,r.set(a,3+n.length),r}function Yr(t){let e=new Uint8Array(0);for(let[n,a]of t)e=vt(e,Kr(n,a));return e}function ot(t,e,n,a){let r=a.length,s=new Uint8Array(9+r);return s[0]=r>>16&255,s[1]=r>>8&255,s[2]=r&255,s[3]=t,s[4]=e,s[5]=n>>24&127,s[6]=n>>16&255,s[7]=n>>8&255,s[8]=n&255,s.set(a,9),s}function nn(t){let e=new Uint8Array(5+t.length);return e[0]=0,new DataView(e.buffer,e.byteOffset,5).setUint32(1,t.length,!1),e.set(t,5),e}function rn(t){let e=new Uint8Array(4);return new DataView(e.buffer).setUint32(0,t>>>0,!1),e}function vt(t,e){let n=new Uint8Array(t.length+e.length);return n.set(t,0),n.set(e,t.length),n}async function an(t,e){let n=[],a=0;for(;a<e;){let{done:s,value:o}=await t.read();if(s)return null;!o||o.byteLength===0||(n.push(o),a+=o.byteLength)}let r;if(n.length===1)r=n[0];else{r=vt(n[0],n[1]);for(let s=2;s<n.length;s++)r=vt(r,n[s])}return r.byteLength>e?{data:r.slice(0,e),extra:r.slice(e)}:{data:r,extra:null}}async function sn(t,e){let n=t.sni&&t.sni!==""?t.sni:t.address,a=Number(t.port),r;try{r=globalThis.connect?globalThis.connect({hostname:n,port:a,secureTransport:t.tls?"on":"off"}):void 0}catch(g){return e(`[VLESS/grpc] connect error: ${g.message}`),null}if(!r)return e("[VLESS/grpc] connect unavailable"),null;let s=r.writable.getWriter();async function o(g){await s.write(g)}let l,u=new Promise(g=>{l=g});(r.closed||Promise.resolve()).then(l,l);try{await o(se.encode(Vr)),await o(ot(4,0,0,new Uint8Array(0)));let g=t.tls?"https":"http",m=(t.path||"").replace(/^\/+/,"").replace(/\/+$/,""),h=m?`/${m}/Tun`:"/Tun",b=Yr([[":method","POST"],[":scheme",g],[":path",h],[":authority",`${n}:${a}`],["content-type","application/grpc"],["te","trailers"],["user-agent","grpc-go/1.68.0"]]);await o(ot(1,4,1,b))}catch(g){e(`[VLESS/grpc] handshake failed: ${g.message}`);try{r.close()}catch{}return null}let i=r.readable.getReader(),c={needLen:5,buf:new Uint8Array(0),msgLen:0,controller:null,extra:null};function d(g,m){let h=g;for(;h.byteLength>0;)if(c.needLen>0){let b=Math.min(c.needLen,h.byteLength);c.buf=vt(c.buf,h.slice(0,b)),h=h.slice(b),c.needLen-=b,c.needLen===0&&(c.buf.byteLength===5?(c.msgLen=new DataView(c.buf.buffer,c.buf.byteOffset,5).getUint32(1,!1),c.buf=new Uint8Array(0),c.needLen=c.msgLen,c.msgLen===0&&(c.needLen=5)):(c.buf=new Uint8Array(0),c.needLen=5))}else{let b=Math.min(c.msgLen,h.byteLength);if(c.buf=vt(c.buf,h.slice(0,b)),h=h.slice(b),c.msgLen-=b,c.msgLen===0){if(c.buf.byteLength>0)try{m.enqueue(c.buf)}catch{}c.buf=new Uint8Array(0),c.needLen=5}}}let f=new ReadableStream({start(g){c.controller=g,(async()=>{try{for(;;){let m;if(c.extra)m=c.extra,c.extra=null;else{let h=await an(i,9);if(!h)break;let b=h.data[0]<<16|h.data[1]<<8|h.data[2],x=h.data[3],v=h.data[4],w=(h.data[5]&127)<<24|h.data[6]<<16|h.data[7]<<8|h.data[8];if(b===0)m=new Uint8Array(0);else{let E=await an(i,b);if(!E)break;m=E.data,c.extra=E.extra}if(x===0&&w===1){d(m,g),await o(ot(8,0,1,rn(m.byteLength))),await o(ot(8,0,0,rn(m.byteLength)));continue}if(x===4){v&1||await o(ot(4,1,0,new Uint8Array(0)));continue}if(x===6){v&1||await o(ot(6,1,w,m));continue}if(x===7||x===3)break}}try{g.close()}catch{}}catch(m){e(`[VLESS/grpc] read loop error: ${m.message}`);try{g.error(m)}catch{}}finally{try{l()}catch{}}})()},cancel(){try{i.cancel()}catch{}}});function p(g){let m=[],h=0,b=!0;for(;h<g.byteLength;){let x=Math.min(16384,g.byteLength-h);m.push(ot(0,0,1,g.slice(h,h+x))),h+=x,b=!1}return m}let y=new WritableStream({write(g){let m=g instanceof Uint8Array?g:new Uint8Array(g),h=nn(m),b=p(h);return(async()=>{for(let x of b)await o(x)})()},close(){try{r.close()}catch{}},abort(){try{r.close()}catch{}}});return{readable:f,writable:y,closed:u,send:async g=>{let m=nn(g);for(let h of p(m))await o(h)}}}var Xr=`PRI * HTTP/2.0\r
\r
SM\r
\r
`;var oe=new TextEncoder;function qr(t,e){let n=oe.encode(t),a=oe.encode(e),r=new Uint8Array(2+n.length+1+a.length);return r[0]=0,r[1]=n.length,r.set(n,2),r[2+n.length]=a.length,r.set(a,3+n.length),r}function Jr(t){let e=new Uint8Array(0);for(let[n,a]of t)e=ie(e,qr(n,a));return e}function it(t,e,n,a){let r=a.length,s=new Uint8Array(9+r);return s[0]=r>>16&255,s[1]=r>>8&255,s[2]=r&255,s[3]=t,s[4]=e,s[5]=n>>24&127,s[6]=n>>16&255,s[7]=n>>8&255,s[8]=n&255,s.set(a,9),s}function on(t){let e=new Uint8Array(4);return new DataView(e.buffer).setUint32(0,t>>>0,!1),e}function ie(t,e){let n=new Uint8Array(t.length+e.length);return n.set(t,0),n.set(e,t.length),n}async function ln(t,e){let n=[],a=0;for(;a<e;){let{done:s,value:o}=await t.read();if(s)return null;!o||o.byteLength===0||(n.push(o),a+=o.byteLength)}let r;if(n.length===1)r=n[0];else{r=ie(n[0],n[1]);for(let s=2;s<n.length;s++)r=ie(r,n[s])}return r.byteLength>e?{data:r.slice(0,e),extra:r.slice(e)}:{data:r,extra:null}}async function cn(t,e){let n=t.sni&&t.sni!==""?t.sni:t.address,a=Number(t.port),r;try{r=globalThis.connect?globalThis.connect({hostname:n,port:a,secureTransport:t.tls?"on":"off"}):void 0}catch(p){return e(`[VLESS/h2] connect error: ${p.message}`),null}if(!r)return e("[VLESS/h2] connect unavailable"),null;let s=r.writable.getWriter();async function o(p){await s.write(p)}let l,u=new Promise(p=>{l=p});(r.closed||Promise.resolve()).then(l,l);try{await o(oe.encode(Xr)),await o(it(4,0,0,new Uint8Array(0)));let p=t.tls?"https":"http",y=t.path&&t.path.startsWith("/")?t.path:`/${t.path||""}`,g=Jr([[":method","POST"],[":scheme",p],[":path",y],[":authority",`${n}:${a}`],["content-length","0"],["user-agent","vless-h2/1.0.0"]]);await o(it(1,4,1,g))}catch(p){e(`[VLESS/h2] handshake failed: ${p.message}`);try{r.close()}catch{}return null}let i=r.readable.getReader(),c=new ReadableStream({start(p){(async()=>{let y=null;try{for(;;){let g;if(y)g=y,y=null;else{let m=await ln(i,9);if(!m)break;let h=m.data[0]<<16|m.data[1]<<8|m.data[2],b=m.data[3],x=m.data[4],v=(m.data[5]&127)<<24|m.data[6]<<16|m.data[7]<<8|m.data[8];if(h===0)g=new Uint8Array(0);else{let w=await ln(i,h);if(!w)break;g=w.data,y=w.extra}if(b===0&&v===1){if(g.byteLength>0)try{p.enqueue(g)}catch{}await o(it(8,0,1,on(g.byteLength))),await o(it(8,0,0,on(g.byteLength)));continue}if(b===4){x&1||await o(it(4,1,0,new Uint8Array(0)));continue}if(b===6){x&1||await o(it(6,1,v,g));continue}if(b===7||b===3)break}}try{p.close()}catch{}}catch(g){e(`[VLESS/h2] read loop error: ${g.message}`);try{p.error(g)}catch{}}finally{try{l()}catch{}}})()},cancel(){try{i.cancel()}catch{}}});function d(p){let y=[],g=0;for(;g<p.byteLength;){let m=Math.min(16384,p.byteLength-g);y.push(it(0,0,1,p.slice(g,g+m))),g+=m}return y}let f=new WritableStream({write(p){let y=p instanceof Uint8Array?p:new Uint8Array(p);return(async()=>{for(let g of d(y))await o(g)})()},close(){try{r.close()}catch{}},abort(){try{r.close()}catch{}}});return{readable:c,writable:f,closed:u,send:async p=>{for(let y of d(p))await o(y)}}}var Qr=1e4;async function ft(t,e,n,a,r,s,o){let l=t.transport||"ws";if(!De.includes(l))return o(`[VLESS] unsupported transport: ${l}`),null;let u=null;try{l==="ws"?u=await ta(t,o):l==="raw"?u=await tn(t,o):l==="httpupgrade"?u=await en(t,o):l==="grpc"?u=await sn(t,o):l==="h2"&&(u=await cn(t,o))}catch(f){return o(`[VLESS/${l}] connect failed: ${f.message}`),null}if(!u)return null;let i=Ye(e,n,a,r,t.uuid),c=s instanceof Uint8Array?s:new Uint8Array(s||0),d=new Uint8Array(i.length+c.length);d.set(i,0),d.set(c,i.length);try{await u.send(d)}catch(f){o(`[VLESS/${l}] send header failed: ${f.message}`);try{u.close&&await u.close()}catch{}return null}return{readable:u.readable,writable:u.writable,closed:u.closed}}async function ta(t,e){let n=t.tls?"wss":"ws",a=t.path&&t.path.startsWith("/")?t.path:`/${t.path||""}`,r=t.sni&&t.sni!==""?t.sni:t.address,s=`${n}://${r}:${t.port}${a}`,o;try{o=new WebSocket(s),"binaryType"in o&&(o.binaryType="arraybuffer")}catch(f){return e(`[VLESS/ws] create ws failed: ${f.message}`),null}let l,u=new Promise(f=>{l=f});try{await new Promise((f,p)=>{let y=setTimeout(()=>p(new Error("Connection timeout")),Qr);o.addEventListener("open",()=>{clearTimeout(y),f()}),o.addEventListener("close",g=>{clearTimeout(y),p(new Error(`closed ${g.code}`))}),o.addEventListener("error",()=>{clearTimeout(y),p(new Error("ws error"))})})}catch(f){e(`[VLESS/ws] connect failed: ${f.message}`);try{o.close()}catch{}return l(),null}o.addEventListener("close",()=>l()),o.addEventListener("error",()=>{});let i=new WritableStream({write(f){o.readyState===1&&o.send(f)},close(){Q(o)},abort(){Q(o)}}),c=!1;return{readable:new ReadableStream({start(f){o.addEventListener("message",p=>{let y;try{p.data instanceof ArrayBuffer?y=new Uint8Array(p.data):ArrayBuffer.isView(p.data)?y=new Uint8Array(p.data.buffer,p.data.byteOffset,p.data.byteLength):typeof p.data=="string"?y=new TextEncoder().encode(p.data):y=null}catch{y=null}if(y){if(!c&&(c=!0,y.length>=2&&y[0]===0)){let g=y[1];if(y.length>2+g)y=y.slice(2+g);else return}if(y.length>0)try{f.enqueue(y)}catch{}}}),o.addEventListener("close",()=>{try{f.close()}catch{}}),o.addEventListener("error",p=>{try{f.error(p)}catch{}})},cancel(){Q(o)}}),writable:i,closed:u,send:async f=>{if(o.readyState!==1)throw new Error(`ws not open (state=${o.readyState})`);o.send(f)}}}async function Tt(t,e,n){for(;e.buf.length<n;){let{done:r,value:s}=await t.read();if(r)return null;if(!s||s.byteLength===0)continue;let o=new Uint8Array(e.buf.length+s.byteLength);o.set(e.buf,0),o.set(s,e.buf.length),e.buf=o}let a=e.buf.slice(0,n);return e.buf=e.buf.slice(n),a}async function un(t,e,n,a,r,s){let{username:o,password:l,hostname:u,port:i}=r,c=s({hostname:u,port:i}),d=c.writable.getWriter(),f=c.readable.getReader(),p=new TextEncoder,y={buf:new Uint8Array(0)};try{await d.write(new Uint8Array([5,2,0,2]));let g=await Tt(f,y,2);if(!g||g[0]!==5){a("socks version error");return}if(g[1]===255){a("no acceptable methods");return}if(g[1]===2){if(!o||!l){a("socks server requires auth but no credentials");return}let w=new Uint8Array([1,o.length,...p.encode(o),l.length,...p.encode(l)]);if(await d.write(w),g=await Tt(f,y,2),!g||g[0]!==1||g[1]!==0){a("socks auth failed");return}}let m;switch(t){case 1:m=new Uint8Array([1,...e.split(".").map(Number)]);break;case 2:m=new Uint8Array([3,e.length,...p.encode(e)]);break;case 3:m=new Uint8Array([4,...re(e).split(":").flatMap(w=>[parseInt(w.slice(0,2),16),parseInt(w.slice(2),16)])]);break;default:a(`invalid addressType ${t}`);return}let h=new Uint8Array([5,1,0,...m,n>>8,n&255]);await d.write(h);let b=await Tt(f,y,4);if(!b||b[0]!==5){a("socks version error");return}if(b[1]!==0){a(`socks connect failed rep=${b[1]}`);return}let x=0;switch(b[3]){case 1:x=6;break;case 3:x=3;break;case 4:x=18;break;default:a(`socks invalid ATYP ${b[3]}`);return}if(b[3]===3){let w=await Tt(f,y,1);if(!w)return;x+=w[0]}if(!await Tt(f,y,x))return;if(d.releaseLock(),y.buf.length>0){let w=y.buf.slice();return{readable:new ReadableStream({pull($){if(w.length>0){let U=w;w=new Uint8Array(0),$.enqueue(U);return}return f.read().then(({done:U,value:S})=>{U?$.close():S&&S.byteLength>0&&$.enqueue(S)})},cancel(){try{f.cancel()}catch{}}}),writable:c.writable,closed:c.closed||Promise.resolve()}}return f.releaseLock(),c}catch(g){a(`socks5 error: ${g.message}`);try{d.releaseLock()}catch{}try{f.releaseLock()}catch{}try{c.close()}catch{}return}}function dn(t,e={}){let n=String(t||"").trim().replace(/^socks5?:\/\//i,""),[a,r]=n.split("@").reverse(),s,o,l,u;if(r){let c=r.split(":");if(c.length!==2)throw new Error("Invalid SOCKS address format");[s,o]=c}let i=a.split(":");if(u=Number(i[i.length-1]),isNaN(u))if(e&&e.port!==void 0&&e.port!==null&&e.port!=="")u=Number(e.port),l=a;else throw new Error("Invalid SOCKS address format");else l=i.slice(0,-1).join(":");if(isNaN(u)||!l)throw new Error("Invalid SOCKS address format");return e&&e.username!==void 0&&e.username!==null&&e.username!==""&&(s=e.username),e&&e.password!==void 0&&e.password!==null&&e.password!==""&&(o=e.password),{username:s,password:o,hostname:l,port:u}}async function pn(t,e,n,a,r,s,o=new Uint8Array(0)){let{username:l,password:u,hostname:i,port:c}=r,d=s({hostname:i,port:c}),f=d.writable.getWriter(),p=d.readable.getReader();try{let y=l&&u?`Proxy-Authorization: Basic ${btoa(`${l}:${u}`)}\r
`:"",g=`CONNECT ${e}:${n} HTTP/1.1\r
Host: ${e}:${n}\r
${y}User-Agent: Mozilla/5.0\r
Connection: keep-alive\r
\r
`;await f.write(new TextEncoder().encode(g));let m=new Uint8Array(0),h=-1,b=0;for(;h===-1&&b<8192;){let{done:E,value:$}=await p.read();if(E)throw new Error("Connection closed before HTTP response");let U=new Uint8Array(m.length+$.length);U.set(m,0),U.set($,m.length),m=U,b=m.length;for(let S=0;S<m.length-3;S++)if(m[S]===13&&m[S+1]===10&&m[S+2]===13&&m[S+3]===10){h=S+4;break}}if(h===-1)throw new Error("Invalid HTTP response");let v=new TextDecoder().decode(m.slice(0,h)).split(`\r
`)[0].match(/HTTP\/\d\.\d\s+(\d+)/);if(!v)throw new Error("Invalid HTTP response format");let w=parseInt(v[1]);if(w<200||w>=300)throw new Error(`HTTP CONNECT failed: HTTP ${w}`);return o.length>0&&await f.write(o),f.releaseLock(),p.releaseLock(),d}catch(y){a(`http connect error: ${y.message}`);try{f.releaseLock()}catch{}try{p.releaseLock()}catch{}try{d.close()}catch{}return}}function fn(t,e={}){let[n,a]=String(t||"").trim().split("@").reverse(),r,s,o,l;if(a){let i=a.split(":");if(i.length!==2)throw new Error("Invalid HTTP address format");[r,s]=i}let u=n.split(":");if(l=Number(u[u.length-1]),isNaN(l))if(e&&e.port!==void 0&&e.port!==null&&e.port!=="")l=Number(e.port),o=n;else throw new Error("Invalid HTTP address format");else o=u.slice(0,-1).join(":");if(isNaN(l)||!o)throw new Error("Invalid HTTP address format");return e&&e.username!==void 0&&e.username!==null&&e.username!==""&&(r=e.username),e&&e.password!==void 0&&e.password!==null&&e.password!==""&&(s=e.password),{username:r,password:s,hostname:o,port:l}}var ea=3e5,hn=new Map,na=["https://8.8.8.8/resolve","https://8.8.4.4/resolve","https://doh.pub/resolve","https://dns.alidns.com/resolve"];async function q(t,e,n="A",a=2500){let r=`${n}:${t}`,s=hn.get(r);if(s&&Date.now()-s.ts<ea)return s.ip;let o=n==="AAAA"?28:1,l=n==="AAAA"?/^[0-9a-fA-F:]+$/:/^\d{1,3}(\.\d{1,3}){3}$/,u=[],i=na.map(f=>{let p=new AbortController;u.push(p);let y=setTimeout(()=>p.abort(),a);return(async()=>{try{let g=`${f}?name=${encodeURIComponent(t)}&type=${n}`,m=await fetch(g,{headers:{accept:"application/dns-json"},signal:p.signal});if(m.ok){let h=await m.json(),x=(Array.isArray(h.Answer)?h.Answer:[]).find(v=>v.type===o&&l.test(v.data))?.data;if(x){for(let v of u)v!==p&&v.abort();return x}}}catch{}finally{clearTimeout(y)}return null})()}),d=(await Promise.all(i)).find(f=>f)||null;return d?hn.set(r,{ip:d,ts:Date.now()}):e(`doh resolve failed: ${t} (${n})`),d}var ra=["173.245.48.0/20","103.21.244.0/22","103.22.200.0/22","103.31.4.0/22","141.101.64.0/18","108.162.192.0/18","190.93.240.0/20","188.114.96.0/20","197.234.240.0/22","198.41.128.0/17","162.158.0.0/15","104.16.0.0/13","104.24.0.0/14","172.64.0.0/13","131.0.72.0/22","1.0.0.0/24","1.1.1.0/24"].map(t=>{let[e,n]=t.split("/"),a=Number(n),r=a===0?0:4294967295<<32-a>>>0,s=e.split(".");return[(+s[0]<<24)+(+s[1]<<16)+(+s[2]<<8)+ +s[3]>>>0&r,r]});function aa(t){let e=t.split(".");return(+e[0]<<24)+(+e[1]<<16)+(+e[2]<<8)+ +e[3]>>>0}function kt(t){if(!/^\d{1,3}(\.\d{1,3}){3}$/.test(t))return!1;let e=aa(t);return ra.some(([n,a])=>(e&a)===n)}var sa=[".cloudflare.com",".cloudflare.net",".jsdelivr.net",".workers.dev",".pages.dev",".trycloudflare.com",".cf-ipfs.com",".cloudflareinsights.com"];function ce(t){let e=t.toLowerCase();return sa.some(n=>e===n.slice(1)||e.endsWith(n))}var gn=6e4,J={state:"unknown",downAt:0},tt=new WeakMap;function lt(t){J.state!=="down"&&(J.state="down",J.downAt=Date.now(),t("proxyip marked down (no response), degrade to direct for 60s"))}function oa(t){J.state==="down"&&Date.now()-J.downAt>=gn&&(J.state="unknown",t("proxyip health reset to unknown, will retry proxyip"))}function yn(){return J.state==="down"&&Date.now()-J.downAt<gn}function ue(t){if(!t.proxyipOutbound)return null;let e=nt(t,t.proxyipOutbound);return!e||typeof e=="string"||e.type!==Zt&&e.type!==qt&&e.type!==Jt?null:e}async function bn(t,e,n,a,r){let s=ue(t);if(!s)return null;let o=/^\d{1,3}(\.\d{1,3}){3}$/.test(e)?1:e.includes(":")?3:2;r(`direct ${e}:${n} -> retry via outbound ${s.name}`);let l=await et({config:t,outbound:s,addressType:o,addressRemote:e,portRemote:n,rawClientData:a||new Uint8Array(0),log:r,isUDP:!1});return l?(tt.set(l,{usedProxyIp:!0}),l):null}async function wn(t,e,n,a,r){if(ue(t)){let c=await bn(t,e,n,a,r);return c||lt(r),c}let o=t.proxyipHost,l=Number(t.proxyipPort||443);if(!o)return null;r(`direct ${e}:${n} -> retry via proxyip ${o}:${l}`);let u=await F(o,l,r);if(!u)return lt(r),null;let i=await de(u,a,r);return i?(tt.set(i,{usedProxyIp:!0}),i):(lt(r),null)}async function le(t,e,n,a,r,s,o){let l=await ia(t,e,n,a,r,o);if(!l)return o(`connect unavailable (${e}:${n})`),null;let u=await de(l,s,o);return u&&tt.set(u,{usedProxyIp:!1}),u}async function F(t,e,n){let a;try{a=globalThis.connect?globalThis.connect({hostname:t,port:e}):void 0,a&&typeof a.then=="function"&&(a=await a)}catch(r){return n(`direct connect error: ${r.message}`),null}return a||null}async function ia(t,e,n,a,r,s){if(!a&&!r){let o=t.ipPreference||"ipv4";if(o==="ipv4"){let c=await q(e,s,"A",1200);if(c){s(`direct ${e}:${n} -> ipv4 ${c}:${n}`);let p=await F(c,n,s);if(p)return p}s(`direct ${e}:${n} -> native dns ${e}:${n}`);let d=await F(e,n,s);if(d)return d;let f=await q(e,s,"AAAA");if(f){let p=`[${f}]`;if(s(`direct ${e}:${n} -> doh aaaa fallback ${p}:${n}`),d=await F(p,n,s),d)return d}return null}if(o==="ipv6"){let c=await q(e,s,"AAAA",1200);if(c){let p=`[${c}]`;s(`direct ${e}:${n} -> ipv6 ${p}:${n}`);let y=await F(p,n,s);if(y)return y}s(`direct ${e}:${n} -> native dns ${e}:${n}`);let d=await F(e,n,s);if(d)return d;let f=await q(e,s,"A");return f&&(s(`direct ${e}:${n} -> doh a fallback ${f}:${n}`),d=await F(f,n,s),d)?d:null}s(`direct ${e}:${n} -> native dns ${e}:${n}`);let l=await F(e,n,s);if(l)return l;let u=await q(e,s);if(u&&(s(`direct ${e}:${n} -> doh fallback ${u}:${n}`),l=await F(u,n,s),l))return l;let i=await q(e,s,"AAAA");if(i){let c=`[${i}]`;if(s(`direct ${e}:${n} -> doh aaaa fallback ${c}:${n}`),l=await F(c,n,s),l)return l}return null}return F(e,n,s)}async function de(t,e,n){if(e&&e.length>0){let a=t.writable.getWriter();try{await a.write(e)}catch(r){n(`direct initial write error: ${r.message}`)}finally{try{a.releaseLock()}catch{}}}return t}async function mn(t,e,n,a,r){let s=(t.proxyipHost||t.proxyipOutbound)&&!t.proxyipDisabled,o=/^\d{1,3}(\.\d{1,3}){3}$/.test(e)||e.includes(":");oa(r);let l=s&&J.state==="down",u=!o&&ce(e),i=o&&!e.includes(":")&&kt(e),c=!1;if(s&&!l&&!o&&!u){let d=await q(e,r,"A",800);d&&kt(d)&&(c=!0)}if(s&&!l&&(u||i||c)){let d=ue(t);if(d){let m=await bn(t,e,n,a,r);return m||(lt(r),r(`proxyip outbound ${d.name} failed; degrade to direct ${e}:${n}`),le(t,e,n,o,u||c,a,r))}let f=t.proxyipHost,p=Number(t.proxyipPort||443),y=await F(f,p,r);if(!y)return lt(r),r(`proxyip ${f}:${p} connect failed; degrade to direct ${e}:${n}`),le(t,e,n,o,u||c,a,r);let g=await de(y,a,r);return g&&tt.set(g,{usedProxyIp:!0}),g}return le(t,e,n,o,u||c,a,r)}async function et(t){let{config:e,outbound:n,addressType:a,addressRemote:r,portRemote:s,rawClientData:o,log:l,isUDP:u}=t,i=n;if(!i||i===K)return mn(e,r,s,o,l);if(i===dt)return l("rejected by routing rule"),null;switch(i.type){case K:return mn(e,r,s,o,l);case qt:{let c;try{c=dn(i.address,{username:i.username,password:i.password,port:i.port})}catch(f){return l(`bad socks5 address: ${f.message}`),null}let d=await un(a,r,s,l,c,globalThis.connect);if(!d)return null;if(o&&o.length>0){let f=d.writable.getWriter();try{await f.write(o)}catch(p){l(`socks5 write error: ${p.message}`)}finally{try{f.releaseLock()}catch{}}}return d}case Jt:{let c;try{c=fn(i.address,{username:i.username,password:i.password,port:i.port})}catch(f){return l(`bad http address: ${f.message}`),null}return await pn(a,r,s,l,c,globalThis.connect,o||new Uint8Array(0))}case Zt:return ft({address:i.address,port:Number(i.port),uuid:i.uuid,path:i.path,tls:!!i.tls,sni:i.sni||"",transport:i.transport},u?2:1,a,r,s,o||new Uint8Array(0),l);default:return l(`unknown outbound type: ${i.type}`),null}}function nt(t,e){return!e||e===K?K:e===dt?dt:t.outboundByName[e]||K}function Et(t){let e=new Uint8Array(2+t.length);return e[0]=t.length>>8,e[1]=t.length&255,e.set(t,2),e}async function xn(t,e,n){let a=t.getReader(),r=new Uint8Array(0),s=0,o=0;try{for(;;){let{done:l,value:u}=await a.read();if(l)break;if(!(!u||u.byteLength===0)){if(o+u.byteLength>r.length){let i=o-s+u.byteLength,c=new Uint8Array(Math.max(r.length*2||4096,i));c.set(r.subarray(s,o),0),r=c,o-=s,s=0}else s>0&&(r.copyWithin(0,s,o),o-=s,s=0);for(r.set(u,o),o+=u.byteLength;!(o-s<2);){let i=r[s]<<8|r[s+1];if(i===0){s+=2;continue}if(o-s<2+i)break;let c=r.slice(s+2,s+2+i);s+=2+i;try{await e(c)}catch(d){n(`udp frame handler error: ${d.message}`)}}}}}catch(l){n(`readUdpFrames error: ${l.message}`)}finally{try{a.releaseLock()}catch{}}}var la=3600*1e3,pe=new Map;async function fe(t,e,n){let a=`${e}:${n}`,r=pe.get(a);if(r&&Date.now()-r.ts<la)return r.data;let s=null;try{let o=e==="geosite"?Re:Oe,l=await t.GEO_KV.get(o+n);if(l){let u=JSON.parse(l);Array.isArray(u)&&(s=u)}}catch{}return s||(s=ca(e,n)),e==="geosite"&&Array.isArray(s)&&(s=s.map(o=>o.toLowerCase())),pe.set(a,{data:s,ts:Date.now()}),s}function ca(t,e){if(t==="geosite")switch(e){case"cn":return Ce;case"speedtest":return Pe;case"google":return Me;default:return[]}return[]}function vn(){pe.clear()}var St=new Map,ua=512;function da(t){if(!t)return null;let e=String(t).trim();if(!e)return null;if(St.has(e))return St.get(e);let n=pa(e);return n&&n.value&&(n._lcValue=n.value.toLowerCase()),St.size>=ua&&St.clear(),St.set(e,n),n}function pa(t){let e=t.match(/^geosite:(.+)$/i);if(e){let u=e[1].split(",").map(i=>i.trim()).filter(Boolean);return u.length===0?null:{type:"geosite",categories:u}}let n=t.match(/^geoip:(.+)$/i);if(n){let u=n[1].split(",").map(i=>i.trim()).filter(Boolean);return u.length===0?null:{type:"geoip",categories:u}}let a=t.match(/^domain:(.+)$/i);if(a)return{type:"domain",value:a[1].trim()};let r=t.match(/^full:(.+)$/i);if(r)return{type:"full",value:r[1].trim()};let s=t.match(/^keyword:(.+)$/i);if(s)return{type:"keyword",value:s[1].trim()};let o=t.match(/^ip-cidr:(.+)$/i);if(o)return{type:"ip-cidr",value:o[1].trim()};let l=t.match(/^regexp:(.+)$/i);return l?{type:"regexp",value:l[1].trim()}:{type:"domain",value:t}}function Tn(t){let e=t.split(".");if(e.length!==4)return null;let n=0;for(let a of e){let r=Number(a);if(isNaN(r)||r<0||r>255)return null;n=n<<8|r}return n>>>0}function kn(t){let e=String(t).replace(/^\[|\]$/g,""),n=e.indexOf("::"),a,r;if(n>=0?(a=n===0?[]:e.slice(0,n).split(":"),r=n===e.length-2?[]:e.slice(n+2).split(":")):(a=e.split(":"),r=[]),a.length+r.length>8)return null;let s=8-a.length-r.length,o=[...a,...Array(s).fill("0"),...r],l=0n;for(let u of o){if(!u)return null;let i=parseInt(u,16);if(isNaN(i))return null;l=l<<16n|BigInt(i)}return l}function En(t,e){let n=e.indexOf("/"),a=n>=0?e.slice(0,n):e,r=t.includes(":")?128:32,s=n>=0?Number(e.slice(n+1)):r;if(t.includes(":")){let i=kn(t),c=kn(a);if(i===null||c===null||isNaN(s)||s<0||s>128)return!1;let d=s===0?0n:(1n<<128n)-1n^(1n<<BigInt(128-s))-1n;return(i&d)===(c&d)}let o=Tn(t);if(o===null)return!1;let l=Tn(a);if(l===null)return!1;let u=s<=0?0:4294967295<<32-s>>>0;return(o&u)===(l&u)}function Sn(t,e){return t===e?!0:t.endsWith(e)}var An=new Map;function fa(t){let e=An.get(t);if(!e){try{e=new RegExp(t)}catch{e=null}An.set(t,e)}return e}async function ha(t,e,n,a){let r=n?"":e.toLowerCase();switch(t.type){case"domain":return n?!1:Sn(r,t._lcValue);case"full":return n?!1:r===t._lcValue;case"keyword":return n?!1:r.includes(t._lcValue);case"regexp":{if(n)return!1;let s=fa(t.value);return s?s.test(e):!1}case"ip-cidr":return n?En(e,t.value):!1;case"geosite":{if(n)return!1;for(let s of t.categories){let o=await fe(a,"geosite",s);for(let l of o)if(Sn(r,l))return!0}return!1}case"geoip":{if(!n)return!1;for(let s of t.categories){let o=await fe(a,"geoip",s);for(let l of o)if(En(e,l))return!0}return!1}default:return!1}}var ma=6e4,ga=1e4,Ht=new Map;async function At(t,e,n){let a=`${e}:${n.toLowerCase()}`,r=Ht.get(a);if(r&&Date.now()-r.ts<ma)return{outbound:r.outbound,rule:r.rule};let s=e===1||e===3,o=t.defaultOutbound||"direct",l=null;for(let u of t.routingRules){let i=da(u.rule);if(!i)continue;if(await ha(i,n,s,t.env)){o=u.outbound||"direct",l=u;break}}return Ht.size>=ga&&Ht.clear(),Ht.set(a,{outbound:o,rule:l,ts:Date.now()}),{outbound:o,rule:l}}var Ln=new Uint8Array([0,0]),_n=32*1024,ya=15,ba=2*1024*1024,wa=100,xa=300;async function ct(t,e,n,a){let r;try{r=await a.read()}catch(h){n(`read first packet error: ${h.message}`);try{await a.close()}catch{}return}if(!r){try{await a.close()}catch{}return}let s,o=null,l="vless",u=t._inboundScope||null,i=u&&!u.all?u.vless:t.uuidSet,c=u&&!u.all?u.trojan:t.passwordSet;if(Je(r)){if(s=await Ze(r,c),s.hasError){n(`trojan header error: ${s.message}`);try{await a.close()}catch{}return}l="trojan",o=t.trojanIndex[s.userPassword]||null}else{if(s=Ke(r,i),s.hasError){n(`vless header error: ${s.message}`);try{await a.close()}catch{}return}try{await a.write(Ln)}catch{}o=t.vlessIndex[s.userUuid]||null}if(o){let h=Math.floor(Date.now()/1e3);if(o.expire_at>0&&o.expire_at<h){n(`${l} user '${o.remark||o.uuid||o.password}' expired`);try{await a.close()}catch{}return}if(o.traffic_limit>0&&Number(o.up)+Number(o.down)>=Number(o.traffic_limit)){n(`${l} user '${o.remark||o.uuid||o.password}' traffic limit reached`);try{await a.close()}catch{}return}}let{addressType:d,addressRemote:f,portRemote:p,isUDP:y}=s,g=(r instanceof Uint8Array?r:new Uint8Array(r)).subarray(s.rawDataIndex),m;try{m=await At(t,d,f)}catch(h){n(`route error: ${h.message}`);try{await a.close()}catch{}return}y?await Ta(a,t,d,f,p,g,o,l,m,n):await va(a,t,d,f,p,g,o,l,m,n)}async function va(t,e,n,a,r,s,o,l,u,i){let c=nt(e,u.outbound),d=s&&s.length>0?s:new Uint8Array(0),f=[c];c!=="direct"&&c!=="reject"&&f.push("direct");let p=null,y=null;for(let D of f){try{p=await et({config:e,outbound:D,addressType:n,addressRemote:a,portRemote:r,rawClientData:d,log:i})}catch(L){y=L,p=null}if(p)break}if(!p){i(`tcp connect failed: ${y?y.message:"no outbound available"}`);try{await t.close()}catch{}return}let g=0,m=0,h=!1,b=Date.now(),x=0,v=15e3,w=Date.now(),E=setInterval(()=>{h||Date.now()-w>=v&&(w=Date.now(),t.write(Ln).catch(()=>{}))},5e3),$=5e3,U=tt.get(p)||null,S=!1,O=p.writable.getWriter(),T=async()=>{if(S)return null;S=!0;let D=(!!e.proxyipHost||!!e.proxyipOutbound)&&!e.proxyipDisabled;try{await p.close()}catch{}if(U&&U.usedProxyIp){lt(i),i(`proxyip ${a}:${r} no first packet, degrade to direct retry`);try{return await et({config:e,outbound:"direct",addressType:n,addressRemote:a,portRemote:r,rawClientData:d,log:i})||null}catch(L){return i(`direct retry error: ${L.message}`),null}}if(!D||r!==443)return null;i(`direct ${a}:${r} no first packet, retry via proxyip`);try{return await wn(e,a,r,d,i)}catch(L){return i(`proxyip retry error: ${L.message}`),null}},M=(async()=>{try{for(;;){let D=await t.read();if(D==null)break;if(D.byteLength===0)continue;g+=D.byteLength,w=Date.now();let L=Date.now();L-b>wa&&(x=L+xa),b=L,await O.write(D)}}catch(D){i(`upstream read error: ${D.message}`)}})();try{let D=p.readable.getReader(),L=!1;for(;;){if(!L&&!S){let I=null,P=D.read().then(V=>({tag:"read",...V})),H=new Promise(V=>{I=setTimeout(()=>V({tag:"timeout"}),$)}),W=await Promise.race([P,H]);if(clearTimeout(I),W.tag==="timeout"){let V=await T();if(!V)break;try{O.releaseLock()}catch{}p=V,O=p.writable.getWriter(),U=tt.get(p)||null,D=p.readable.getReader(),L=!1;continue}if(W.done)break;W.value&&W.value.byteLength>0&&(L=!0,m+=W.value.byteLength,w=Date.now(),await t.write(W.value));continue}let C=null,A=0,R=null,st=()=>{R||(R=setTimeout(()=>{if(R=null,A>0){let I=C.subarray(0,A);C=null,A=0,t.write(I).catch(()=>{})}},ya))},N=async()=>{R&&(clearTimeout(R),R=null),A>0&&(await t.write(C.subarray(0,A)),C=null,A=0)},Yt=I=>{let P=A+I.byteLength;if(!C)C=new Uint8Array(Math.max(P,4096));else if(P>C.length){let H=new Uint8Array(Math.max(C.length*2,P));H.set(C.subarray(0,A),0),C=H}C.set(I,A),A=P},yt=0,ut=!1;for(;;){yt>=ba&&(yt=0,await new Promise(H=>setTimeout(H,0)));let{done:I,value:P}=await D.read();if(I){await N(),ut=!0;break}if(!(!P||P.byteLength===0)){if(L=!0,m+=P.byteLength,yt+=P.byteLength,w=Date.now(),Date.now()<x){await N(),await t.write(P);continue}A+P.byteLength<=_n?(Yt(P),A>=_n?await N():st()):(await N(),await t.write(P))}}if(ut)break}}catch(D){if(!S&&m===0){i(`tcp remote read error before first packet: ${D.message||D}`);let L=await T();if(L){try{O.releaseLock()}catch{}p=L,O=p.writable.getWriter(),U=tt.get(p)||null,S=!0;let C=p.readable.getReader();try{for(;;){let{done:A,value:R}=await C.read();if(A)break;R&&R.byteLength>0&&(m+=R.byteLength,w=Date.now(),await t.write(R))}}catch(A){i(`fallback remote read error: ${A.message||A}`)}}}else i(`tcp remote read error: ${D.message||D}`)}h=!0,clearInterval(E);try{O.releaseLock()}catch{}try{await p.writable.close()}catch{}try{await t.close()}catch{}await M.catch(()=>{}),Dn(e,o,l,g,m,i)}async function Ta(t,e,n,a,r,s,o,l,u,i){let c=null,d=(e.udpOutbound||"").trim();if(d){let T=e.outboundByName[d];if(T&&T.type==="vless")c=T;else{i(`udp outbound '${d}' not found or not vless (only vless supports udp)`);try{await t.close()}catch{}return}}else{if(u.outbound&&u.outbound!=="direct"&&u.outbound!=="reject"){let T=nt(e,u.outbound);T!=="direct"&&T!=="reject"&&T.type==="vless"&&(c=T)}c||(c=e.outbounds.find(T=>T.type==="vless"))}if(!c){i("udp requires a vless outbound, none configured");try{await t.close()}catch{}return}let p=(c.transport||"ws").trim().toLowerCase()==="raw",y=s&&s.length>0,g=p?y?Et(s):new Uint8Array([0,0]):y?s:new Uint8Array(0),m=await ft({address:c.address,port:Number(c.port),uuid:c.uuid,path:c.path,tls:!!c.tls,sni:c.sni||"",transport:c.transport||"ws"},2,n,a,r,g,i);if(!m){i("udp vless outbound connect failed");try{await t.close()}catch{}return}let h=0,b=0,x=!1,v=null,w=m.writable.getWriter(),E=3e5,$=Date.now(),U=setInterval(()=>{x||Date.now()-$>=E&&(i(`udp session idle ${E}ms, closing`),S())},15e3),S=()=>{if(!x){x=!0,clearInterval(U);try{w.releaseLock()}catch{}try{m.writable.close().catch(()=>{})}catch{}try{v&&v.cancel().catch(()=>{})}catch{}try{t.close()}catch{}}},O=(async()=>{try{for(;;){let T=await t.read();if(T==null)break;T.byteLength!==0&&(h+=T.byteLength,$=Date.now(),await w.write(p?Et(T):T))}}catch(T){i(`udp upstream read error: ${T.message}`)}S()})();try{v=m.readable.getReader();let T=null,M=0;for(;;){let{done:D,value:L}=await v.read();if(D||x)break;if(p){if(!L||L.byteLength===0)continue;let C=M+L.byteLength;if(!T)T=new Uint8Array(Math.max(C,4096));else if(C>T.length){let R=new Uint8Array(Math.max(T.length*2,C));R.set(T.subarray(0,M),0),T=R}T.set(L,M),M=C;let A=0;for(;!(M-A<2);){let R=T[A]<<8|T[A+1];if(R===0){A+=2;continue}if(M-A<2+R)break;let st=T.slice(A+2,A+2+R);if(A+=2+R,x)break;b+=st.length,$=Date.now();try{await t.write(st)}catch{}}A>0&&(T.copyWithin(0,A,M),M-=A)}else L&&L.byteLength>0&&(b+=L.byteLength,$=Date.now(),await t.write(L))}}catch(T){i(`udp read error: ${T.message}`)}S(),await O.catch(()=>{}),Dn(e,o,l,h,b,i)}var ka=2e3,Ea=32,rt=new Map,he=null;async function $n(t){if(!rt.size)return;let e=[...rt.entries()];rt.clear();try{let n=e.map(([a,r])=>{let s=a.lastIndexOf(":"),o=a.slice(0,s),l=Number(a.slice(s+1));return t.prepare(`UPDATE ${o} SET up = up + ?, down = down + ? WHERE id = ?`).bind(r.up,r.down,l)});await t.batch(n)}catch{for(let[a,r]of e){let s=rt.get(a);s?(s.up+=r.up,s.down+=r.down):rt.set(a,r)}Un(t)}}function Un(t){he||(he=setTimeout(()=>{he=null,$n(t)},ka))}async function Dn(t,e,n,a,r,s){if(!e)return;let l=`${n==="vless"?"vless_users":"trojan_users"}:${e.id}`,u=rt.get(l);if(u?(u.up+=a,u.down+=r):rt.set(l,{up:a,down:r}),Un(t.env.DB),rt.size>=Ea)try{await $n(t.env.DB)}catch(i){s(`record traffic error: ${i.message}`)}}var Sa=Promise.resolve();function Aa(t){return t instanceof ArrayBuffer?new Uint8Array(t):ArrayBuffer.isView(t)?new Uint8Array(t.buffer,t.byteOffset,t.byteLength):typeof t=="string"?new TextEncoder().encode(t):Object.prototype.toString.call(t)==="[object ArrayBuffer]"?new Uint8Array(t):null}function _a(t,e){let n=null,a=t.url.indexOf("?");if(a>=0){let o=t.url.slice(a+1).match(/(?:^|&)ed=([^&#]*)/);if(o)try{n=decodeURIComponent(o[1])}catch{n=o[1]}}let r=n==="2560",s=t.headers.get("sec-websocket-protocol")||"";if(s){s.startsWith("base64,")&&(s=s.slice(7));let{earlyData:o,error:l}=Qe(s);if(l)return e(`early data decode error: ${l.message||l}`),null;if(o&&o.byteLength>0)return r||e(`early data injected: ${o.byteLength} B (ed=${n||"n/a"})`),new Uint8Array(o)}return n&&!r&&e(`ed=${n} declared but no sec-websocket-protocol payload`),null}async function Rn(t,e,n){let a=t.headers.get("Upgrade");if(!a||a.toLowerCase()!=="websocket")return new Response("Expected WebSocket",{status:400});let[r,s]=Object.values(new WebSocketPair);s.accept(),s.binaryType="arraybuffer";let o=(...u)=>console.log("[ws]",...u),l=_a(t,o);return ct(e,n,o,La(s,o,l)).catch(u=>{o(`ws handler error: ${u.message||u}`),Q(s)}),new Response(null,{status:101,webSocket:r})}function La(t,e,n=null){let a=[],r=[],s=!1;n&&n.byteLength>0?a.push(n):setTimeout(()=>{!s&&a.length===0&&r.length>0&&(e("first packet timeout: no ws message within 6s"),Q(t))},6e3);let o=async i=>{let c=i.data;typeof Blob<"u"&&c instanceof Blob&&(c=await c.arrayBuffer());let d=Aa(c);if(!d||d.byteLength===0){e(`message dropped: type=${Object.prototype.toString.call(i.data)} len=${c&&c.byteLength!=null?c.byteLength:c&&c.length!=null?c.length:"n/a"}`);return}let f=r.shift();f?f(d):a.push(d)},l=()=>{if(!s)for(s=!0;r.length;)r.shift()(null)},u=()=>l();return t.addEventListener("message",o),t.addEventListener("close",l),t.addEventListener("error",u),{read(){return a.length?Promise.resolve(a.shift()):s?Promise.resolve(null):new Promise(i=>r.push(i))},write(i){if(t.readyState===1)try{t.send(i)}catch{}return Sa},close(){Q(t)}}}function $a(t,e){let n=new Uint8Array(t.length+e.length);return n.set(t,0),n.set(e,t.length),n}function zt(t,e){if(!t.buf){t.buf=new Uint8Array(Math.max(e.byteLength,4096)),t.buf.set(e,0),t.len=e.byteLength;return}let n=t.len+e.byteLength;if(n>t.buf.length){let a=new Uint8Array(Math.max(t.buf.length*2,n));a.set(t.buf.subarray(0,t.len),0),t.buf=a}t.buf.set(e,t.len),t.len=n}function me(t){let e=t.byteLength;if(e>=512)return e;if(e>=1&&t[0]===0){if(e<18)return null;let a=18+t[17];if(e<a+4)return null;let r=t[a+3],s;if(r===1)s=4;else if(r===2){if(e<a+5)return null;s=t[a+4]+1}else if(r===3)s=16;else return a+4;return a+4+s}if(e>=60&&t[56]===13&&t[57]===10){if(e<60)return null;let n=t[58];if(n!==1&&n!==3)return 60;let r=t[59]===13&&t[60]===10?61:59;if(e<r+1)return null;let s=t[r],o;if(s===1)o=4;else if(s===3){if(e<r+2)return null;o=t[r+1]+1}else if(s===4)o=16;else return r+1;return r+1+o+2+2}return e<60?null:e}function Ua(t){let e=new Uint8Array(5);return e[0]=0,e[1]=t>>>24&255,e[2]=t>>>16&255,e[3]=t>>>8&255,e[4]=t&255,e}function Da(t){return $a(Ua(t.byteLength),t)}function On(t){if(t.length<2||t[0]!==10)return t;let e=0,n=0,a=1;for(;a<t.length&&n<35;a++){let s=t[a];if(e|=(s&127)<<n,(s&128)===0)break;n+=7}if(a>=t.length||(t[a]&128)!==0)return t;let r=a+1;return t.length-r<e?t:t.slice(r,r+e)}function Ra(t){let e=t.length,n=[];for(;;){let r=e&127;if(e>>>=7,e>0&&(r|=128),n.push(r),e===0)break}let a=new Uint8Array(1+n.length+t.length);return a[0]=10,a.set(n,1),a.set(t,1+n.length),a}async function Cn(t,e,n){let a=(...i)=>console.log("[h2-in]",...i);if(!t.body)return new Response("Bad Request",{status:400});let r=t.body.getReader(),{readable:s,writable:o}=new TransformStream,l=o.getWriter(),u={firstReadDone:!1,read:async()=>{if(!u.firstReadDone){u.firstReadDone=!0;let d={buf:null,len:0};for(;;){let{done:f,value:p}=await r.read();if(f)return d.len>0?d.buf.subarray(0,d.len):null;zt(d,p instanceof Uint8Array?p:new Uint8Array(p));let y=me(d.buf.subarray(0,d.len));if(y!==null&&d.len>=y)return d.buf.subarray(0,d.len)}}let{done:i,value:c}=await r.read();return i?null:!c||c.byteLength===0?new Uint8Array(0):c instanceof Uint8Array?c:new Uint8Array(c)},write:i=>l.write(i),close:async()=>{try{await r.cancel()}catch{}try{await l.close()}catch{}}};return ct(e,n,a,u).catch(i=>{a(`h2 handler error: ${i.message||i}`),r.cancel().catch(()=>{}),l.close().catch(()=>{})}),new Response(s,{status:200,headers:{"Content-Type":"application/octet-stream","Cache-Control":"no-store"}})}async function Pn(t,e,n){let a=(...i)=>console.log("[xhttp-in]",...i);if(!t.body)return new Response("Bad Request",{status:400});let r=t.body.getReader(),{readable:s,writable:o}=new TransformStream,l=o.getWriter(),u={firstReadDone:!1,read:async()=>{if(!u.firstReadDone){u.firstReadDone=!0;let d={buf:null,len:0};for(;;){let{done:f,value:p}=await r.read();if(f)return d.len>0?d.buf.subarray(0,d.len):null;zt(d,p instanceof Uint8Array?p:new Uint8Array(p));let y=me(d.buf.subarray(0,d.len));if(y!==null&&d.len>=y)return d.buf.subarray(0,d.len)}}let{done:i,value:c}=await r.read();return i?null:!c||c.byteLength===0?new Uint8Array(0):c instanceof Uint8Array?c:new Uint8Array(c)},write:i=>l.write(i),close:async()=>{try{await r.cancel()}catch{}try{await l.close()}catch{}}};return ct(e,n,a,u).catch(i=>{a(`xhttp handler error: ${i.message||i}`),r.cancel().catch(()=>{}),l.close().catch(()=>{})}),new Response(s,{status:200,headers:{"Content-Type":"text/event-stream","Cache-Control":"no-store","X-Accel-Buffering":"no"}})}var Ft=new Map,Oa=3e5;function _t(t){t.closed||(t.closed=!0,Ft.delete(t.uuid),clearTimeout(t.timer),t.upWriter.close().catch(()=>{}),t.downWriter.close().catch(()=>{}))}async function Mn(t,e,n,a){let r=(...d)=>console.log("[xhttp-down]",...d),s=new TransformStream,o=new TransformStream,l={uuid:a,upWriter:s.writable.getWriter(),downWriter:o.writable.getWriter(),lastActivity:Date.now(),tail:Promise.resolve(),closed:!1,timer:null},u=Ft.get(a);u&&_t(u),Ft.set(a,l),l.timer=setTimeout(()=>_t(l),Oa);let i=s.readable.getReader(),c={firstReadDone:!1,read:async()=>{if(!c.firstReadDone){c.firstReadDone=!0;let p={buf:null,len:0};for(;;){let{done:y,value:g}=await i.read();if(y)return p.len>0?p.buf.subarray(0,p.len):null;if(!g||g.byteLength===0)continue;l.lastActivity=Date.now(),zt(p,g instanceof Uint8Array?g:new Uint8Array(g));let m=me(p.buf.subarray(0,p.len));if(m!==null&&p.len>=m)return p.buf.subarray(0,p.len)}}let{done:d,value:f}=await i.read();return d?null:!f||f.byteLength===0?new Uint8Array(0):(l.lastActivity=Date.now(),f instanceof Uint8Array?f:new Uint8Array(f))},write:async d=>{try{await l.downWriter.write(d)}catch(f){throw _t(l),f}},close:async()=>{_t(l)}};return ct(e,n,r,c).catch(d=>{r(`xhttp-auto session error: ${d.message||d}`),_t(l)}),new Response(o.readable,{status:200,headers:{"Content-Type":"text/event-stream","Cache-Control":"no-store","X-Accel-Buffering":"no"}})}async function In(t,e,n,a){let r=(...u)=>console.log("[xhttp-up]",...u),s=Ft.get(a);if(!s||s.closed)return r(`session ${a} not found (cross-isolate or expired)`),new Response("Session not found",{status:404});if(!t.body)return new Response("Bad Request",{status:400});let o=t.body.getReader(),l=s.tail.then(async()=>{try{for(;;){let{done:u,value:i}=await o.read();if(u)break;!i||i.byteLength===0||(s.lastActivity=Date.now(),await s.upWriter.write(i))}}catch{}});return s.tail=l.catch(()=>{}),await l,new Response("OK",{status:200,headers:{"Content-Type":"text/plain; charset=utf-8"}})}async function Nn(t,e,n){let a=(...c)=>console.log("[grpc-in]",...c);if(!t.body)return new Response("Bad Request",{status:400});let r=t.body.getReader(),{readable:s,writable:o}=new TransformStream,l=o.getWriter(),u={buf:null,len:0};return ct(e,n,a,{read:async()=>{for(;;){if(u.len>=5){let f=u.buf[1]<<24|u.buf[2]<<16|u.buf[3]<<8|u.buf[4];if(u.len>=5+f){let p=u.buf.slice(5,5+f);return u.buf.copyWithin(0,5+f,u.len),u.len-=5+f,On(p)}}let{done:c,value:d}=await r.read();if(c){if(u.len===0)return null;if(u.len<5)return u.len=0,new Uint8Array(0);let f=u.buf.slice(0,u.len);return u.len=0,On(f)}zt(u,d instanceof Uint8Array?d:new Uint8Array(d))}},write:c=>l.write(Da(Ra(c instanceof Uint8Array?c:new Uint8Array(c)))),close:async()=>{try{await r.cancel()}catch{}try{await l.close()}catch{}}}).catch(c=>{a(`grpc handler error: ${c.message||c}`),r.cancel().catch(()=>{}),l.close().catch(()=>{})}),new Response(s,{status:200,headers:{"Content-Type":"application/grpc","Cache-Control":"no-store"}})}var Hn="ed=2560",Lt="random";function Bt(t){let e=t.startsWith("/")?t:`/${t}`;return/\?/.test(e)?`${e}&${Hn}`:`${e}?${Hn}`}function jt(t){return(t.startsWith("/")?t:`/${t}`).replace(/\/+$/,"").replace(/^\//,"")}function $t(t){let e=t.transport||"ws",n=t.wsHost||t.host,a=t.sni||(t.tls?n:""),r=new URLSearchParams({encryption:"none",type:e,host:n,security:t.tls?"tls":"none",tfo:"1"});e==="grpc"?r.set("serviceName",jt(t.wsPath)):e==="xhttp"?(r.set("mode","stream-one"),r.set("path",t.wsPath.startsWith("/")?t.wsPath:`/${t.wsPath}`)):e==="h2"?r.set("path",t.wsPath.startsWith("/")?t.wsPath:`/${t.wsPath}`):r.set("path",Bt(t.wsPath)),t.tls&&a&&r.set("sni",a),t.tls&&r.set("fp",t.fp||Lt);let s=encodeURIComponent(t.remark||`${t.host}:${t.port}`);return`vless://${t.uuid}@${t.host}:${t.port}?${r.toString()}#${s}`}function Ut(t){let e=t.transport||"ws",n=t.wsHost||t.host,a=t.sni||(t.tls?n:""),r=new URLSearchParams({type:e,host:n,security:t.tls?"tls":"none",tfo:"1"});e==="grpc"?r.set("serviceName",jt(t.wsPath)):e==="xhttp"?(r.set("mode","stream-one"),r.set("path",t.wsPath.startsWith("/")?t.wsPath:`/${t.wsPath}`)):e==="h2"?r.set("path",t.wsPath.startsWith("/")?t.wsPath:`/${t.wsPath}`):r.set("path",Bt(t.wsPath)),t.tls&&a&&r.set("sni",a),t.tls&&r.set("fp",t.fp||Lt);let s=encodeURIComponent(t.remark||`${t.host}:${t.port}`);return`trojan://${encodeURIComponent(t.password)}@${t.host}:${t.port}?${r.toString()}#${s}`}function Fn(t){let e=t.headers.get("Host");return e?e.split(":")[0]:"example.com"}var at=["ws","grpc","h2","xhttp"],Ca={ws:null,grpc:"g",xhttp:"x",h2:"h"};function B(t,e,n,a){if(!n)return`${a}-${e}`;let r=Ca[e];if(r===void 0)return t==="trojan"?`${n}-T`:n;let s=r?`-${r}`:"";return t==="trojan"?`${n}-T${s}`:`${n}${s}`}function Pa(t,e){let n=[],a=e.port||(e.tls?443:80),r=e.transports&&e.transports.length?e.transports:at;for(let s of t.vlessUsers){let o=s.path||t.wsPath;for(let l of r)n.push($t({uuid:s.uuid,host:e.host,port:a,wsPath:o,tls:e.tls,wsHost:e.wsHost,sni:e.sni,transport:l,remark:B("vless",l,e.name||s.remark,`vless-${s.uuid.slice(0,8)}`)}))}for(let s of t.trojanUsers){let o=s.path||t.wsPath;for(let l of r)n.push(Ut({password:s.password,host:e.host,port:a,wsPath:o,tls:e.tls,wsHost:e.wsHost,sni:e.sni,transport:l,remark:B("trojan",l,e.name||s.remark,`trojan-${s.password.slice(0,8)}`)}))}return n}function ge(t,e){return e.flatMap(a=>Pa(t,a)).join(`
`)+`
`}function zn(t,e){return btoa(ge(t,e))}function Bn(t,e){let n=[];for(let r of e){let s=r.port||443,o=r.tls!==!1,l=r.wsHost||r.host,u=r.sni||(o?l:""),i=r.transports&&r.transports.length?r.transports:at,c=(d,f,p,y,g,m)=>{let h={name:d,type:f,server:r.host,port:s,[p]:y,network:m,tls:o,servername:u||void 0,"client-fingerprint":o?Lt:void 0,tfo:!0,udp:!0,_wsHost:l};return m==="grpc"?h["grpc-opts"]={"grpc-service-name":jt(g)}:m==="xhttp"?h["xhttp-opts"]={mode:"stream-one",path:g.startsWith("/")?g:`/${g}`,host:[l]}:m==="h2"?h["h2-opts"]={path:g.startsWith("/")?g:`/${g}`,host:[l]}:h["ws-opts"]={path:Bt(g),headers:{Host:l}},h};t.vlessUsers.forEach((d,f)=>{for(let p of i)n.push(c(B("vless",p,r.name||d.remark,`vless-${f+1}`),"vless","uuid",d.uuid,d.path||t.wsPath,p))}),t.trojanUsers.forEach((d,f)=>{for(let p of i)n.push(c(B("trojan",p,r.name||d.remark,`trojan-${f+1}`),"trojan","password",d.password,d.path||t.wsPath,p))})}let a=["proxies:"];for(let r of n)a.push(`  - name: "${r.name}"`),a.push(`    type: ${r.type}`),a.push(`    server: ${r.server}`),a.push(`    port: ${r.port}`),r.uuid&&a.push(`    uuid: ${r.uuid}`),r.password&&a.push(`    password: "${r.password}"`),a.push(`    network: ${r.network}`),a.push(`    tls: ${r.tls}`),r.servername&&a.push(`    servername: ${r.servername}`),r["client-fingerprint"]&&a.push(`    client-fingerprint: ${r["client-fingerprint"]}`),a.push("    tfo: true"),a.push("    udp: true"),r.network==="grpc"?(a.push("    grpc-opts:"),a.push(`      grpc-service-name: ${r["grpc-opts"]["grpc-service-name"]}`)):r.network==="xhttp"?(a.push("    xhttp-opts:"),a.push(`      mode: ${r["xhttp-opts"].mode}`),a.push(`      path: ${r["xhttp-opts"].path}`),a.push("      host:"),a.push(`        - ${r._wsHost}`)):r.network==="h2"?(a.push("    h2-opts:"),a.push(`      path: ${r["h2-opts"].path}`),a.push("      host:"),a.push(`        - ${r._wsHost}`)):(a.push("    ws-opts:"),a.push(`      path: ${r["ws-opts"].path}`),a.push("      headers:"),a.push(`        Host: ${r._wsHost}`));return a.push(""),a.push("rules:"),a.push("  - MATCH,DIRECT"),a.join(`
`)}function jn(t,e){let n=[],a=(r,s,o)=>s==="grpc"?{type:"grpc",service_name:jt(r)}:s==="xhttp"?{type:"xhttp",mode:"stream-one",path:r.startsWith("/")?r:`/${r}`,host:o}:s==="h2"?{type:"http",host:[o],path:r.startsWith("/")?r:`/${r}`}:{type:"ws",path:Bt(r),headers:{Host:o}};for(let r of e){let s=r.port||443,o=r.wsHost||r.host,l=r.sni||(r.tls?o:""),u=r.transports&&r.transports.length?r.transports:at;for(let i of t.vlessUsers)for(let c of u)n.push({type:"vless",tag:B("vless",c,r.name||i.remark,`vless-${i.uuid.slice(0,8)}`),server:r.host,server_port:s,uuid:i.uuid,transport:a(i.path||t.wsPath,c,o),tcp_fast_open:!0,tls:r.tls?{enabled:!0,server_name:l,fingerprint:Lt}:null});for(let i of t.trojanUsers)for(let c of u)n.push({type:"trojan",tag:B("trojan",c,r.name||i.remark,`trojan-${i.password.slice(0,8)}`),server:r.host,server_port:s,password:i.password,transport:a(i.path||t.wsPath,c,o),tcp_fast_open:!0,tls:r.tls?{enabled:!0,server_name:l,fingerprint:Lt}:null})}return JSON.stringify({outbounds:n,log:{level:"info"}},null,2)}var ye={ws:"WebSocket (ws)",grpc:"gRPC",h2:"HTTP/2 (h2)",xhttp:"XHTTP (stream-one)"};function Dt(t){return String(t??"").replace(/[&<>"']/g,e=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"})[e])}function be(t,e){let a=`/${(e.path||t.wsPath||"/ws").replace(/^\//,"")}`,r=e.kind==="vless"?"VLESS":"Trojan",s=e.kind==="vless"?"vless":"trojan",o=Array.isArray(e.entries)&&e.entries.length?e.entries:null,l=o&&o.length>1,u=(m,h)=>{let b=m?m.host:e.host,x=m?Number(m.port)||443:e.port||(e.tls?443:80),v=m?!0:e.tls,w=m?m.wsHost||m.host:e.wsHost,E=m?m.sni||w:e.sni,$=B(e.kind,h,m?m.remark:"",`${s}-${h}`),U={host:b,port:x,wsPath:a,tls:v,wsHost:w,sni:E};return e.kind==="vless"?$t({...U,uuid:e.credential,transport:h,remark:$}):Ut({...U,password:e.credential,transport:h,remark:$})},i=(m,h,b)=>`
  <div class="row">
    <label>${ye[h]}</label>
    <div class="linkbox">
      <input type="text" readonly value="${u(m,h)}" id="link${b}">
      <button onclick="copyLink(${b})">\u590D\u5236</button>
    </div>
  </div>`,c;if(o)c=o.map(m=>({title:m.remark||"",host:m.host,transports:m.transports&&m.transports.length?m.transports:at,entry:m}));else{let m=e.transports&&e.transports.length?e.transports:at;c=[{title:"",host:e.host,transports:m,entry:null}]}let d=0,f=c.map(m=>{let b=m.transports.filter(v=>ye[v]).map(v=>i(m.entry,v,d++)).join("");return`${m.title?`<div class="entry-title">${Dt(m.title)}</div>`:l?`<div class="entry-title">${Dt(m.host)}</div>`:""}${b}`}).join(""),p=l?"\u591A\u5165\u53E3":c[0].host,y=l?`${c.length} \u4E2A\u5165\u53E3\uFF0C\u6309\u4E0B\u65B9\u5206\u7EC4\u590D\u5236\u5BF9\u5E94\u8282\u70B9`:c[0].transports.filter(m=>ye[m]).join(" / ");return`<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>${r} \u8282\u70B9\u914D\u7F6E</title>
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
  <h1>${r} \u8282\u70B9 <span class="badge">${Dt(p)}</span></h1>
  <p class="desc">\u5165\u7AD9\u8DEF\u5F84\uFF1A<b>${Dt(a)}</b>\uFF08\u5F53\u524D\u5165\u53E3\u652F\u6301\uFF1A${Dt(y)||"\u65E0"}\uFF0C\u590D\u5236\u94FE\u63A5\u5BFC\u5165\u5BA2\u6237\u7AEF\uFF09</p>
  ${f}
</div>
<script>
function copyLink(i){ const el=document.getElementById('link'+i); el.select(); document.execCommand('copy'); el.style.borderColor='#34c759'; setTimeout(()=>el.style.borderColor='#d2d2d7',800); }
<\/script>
</body>
</html>`}function Gn(t){let e=t.disguise_title||"AList",n=t.disguise_subtitle||"\u4E00\u4E2A\u652F\u6301\u591A\u5B58\u50A8\u7684\u6587\u4EF6\u5217\u8868\u7A0B\u5E8F";return`<!DOCTYPE html>
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
</html>`}function we(t,e=200){return new Response(t,{status:e,headers:{"Content-Type":"text/html; charset=utf-8","Cache-Control":"no-store"}})}function ht(t,e="text/plain; charset=utf-8"){return new Response(t,{headers:{"Content-Type":e,"Cache-Control":"no-store"}})}async function Ma(t,e,n){let a=new URL(t.url),r=a.searchParams.get("token")||"",s=e;if(r)if(e.uuidSet.has(r)){let l=e.vlessIndex[r];s={...e,vlessUsers:[l],trojanUsers:[]}}else if(e.passwordSet.has(r)){let l=e.trojanIndex[r];s={...e,vlessUsers:[],trojanUsers:[l]}}else if(e.adminPasswordHash&&await Mt(r,e.adminPasswordHash))s=e;else return new Response("Not Found",{status:404});else return new Response("Not Found",{status:404});switch((a.searchParams.get("format")||"base64").toLowerCase()){case"plain":return ht(ge(s,n));case"clash":case"yaml":return ht(Bn(s,n),"text/yaml; charset=utf-8");case"singbox":case"sing-box":case"json":return ht(jn(s,n),"application/json; charset=utf-8");default:return ht(zn(s,n))}}function Ia(t,e,n,a){let r=new URL(t.url),s=null;if(e.uuidSet.has(n)?s={kind:"vless",user:e.vlessIndex[n]}:e.passwordSet.has(n)&&(s={kind:"trojan",user:e.trojanIndex[n]}),!s)return new Response("Not Found",{status:404});let o=(r.searchParams.get("format")||"base64").toLowerCase(),l=a.host,u=a.port,i=s.user.path||e.wsPath,c=a.transports&&a.transports.length?a.transports:at,d=[];for(let p of c)s.kind==="vless"?d.push($t({uuid:s.user.uuid,host:l,port:u,wsPath:i,tls:a.tls,wsHost:a.wsHost,sni:a.sni,transport:p,remark:B("vless",p,a.remark||s.user.remark,"vless-node")})):d.push(Ut({password:s.user.password,host:l,port:u,wsPath:i,tls:a.tls,wsHost:a.wsHost,sni:a.sni,transport:p,remark:B("trojan",p,a.remark||s.user.remark,"trojan-node")}));let f=d.join(`
`)+`
`;return ht(o==="plain"?f:btoa(f))}async function Wn(t,e,n){let a=new URL(t.url),r=a.pathname,s=Fn(t),o=a.protocol==="https:",l=Number(a.port)||(o?443:80),u=s.toLowerCase().replace(/:\d+$/,""),i=g=>[g.host,g.wsHost].filter(Boolean).map(h=>h.toLowerCase().replace(/:\d+$/,"")).some(h=>h===u),c=e.entries.find(i),d=c?{host:c.host,port:Number(c.port)||443,tls:!0,wsHost:c.wsHost,sni:c.sni,transports:c.transports,remark:c.remark||c.host}:e.entries.length?{host:e.entries[0].host,port:Number(e.entries[0].port)||443,tls:!0,wsHost:e.entries[0].wsHost,sni:e.entries[0].sni,transports:e.entries[0].transports,remark:e.entries[0].remark||e.entries[0].host}:{host:s,port:l,tls:o,wsHost:s,sni:s},f;if(c?f=[{host:c.host,port:Number(c.port)||443,tls:!0,wsHost:c.wsHost,sni:c.sni,transports:c.transports,name:c.remark||c.host}]:e.entries.length?f=e.entries.map(g=>({host:g.host,port:Number(g.port)||443,tls:!0,wsHost:g.wsHost,sni:g.sni,transports:g.transports,name:g.remark||g.host})):f=[{host:s,port:l,tls:o,wsHost:s,sni:s}],r==="/subscribe")return await Ma(t,e,f);let p=r.match(/^\/([^/]+)\/subscribe$/);if(p)return Ia(t,e,decodeURIComponent(p[1]),d);let y=r.match(/^\/([^/]+)$/);if(y){let g=decodeURIComponent(y[1]);if(e.uuidSet.has(g)){let m=e.vlessIndex[g];return we(be(e,{host:d.host,port:d.port,tls:d.tls,wsHost:d.wsHost,sni:d.sni,transports:d.transports,entries:e.entries,credential:g,kind:"vless",path:m&&m.path||e.wsPath}))}if(e.passwordSet.has(g)){let m=e.trojanIndex[g];return we(be(e,{host:d.host,port:d.port,tls:d.tls,wsHost:d.wsHost,sni:d.sni,transports:d.transports,entries:e.entries,credential:g,kind:"trojan",path:m&&m.path||e.wsPath}))}}return we(Gn(e.settings))}var Vn="1.0.81-20260928-1907";var Kn=[{name:"\u5B57\u8282\u8DF3\u52A8",host:"www.bytedance.com",port:80,region:"cn",icon:"\u{1F3B5}",color:"#325AB4"},{name:"Bilibili",host:"www.bilibili.com",port:80,region:"cn",icon:"\u{1F4FA}",color:"#FB7299"},{name:"\u5FAE\u4FE1",host:"weixin.qq.com",port:80,region:"cn",icon:"\u{1F4AC}",color:"#07C160"},{name:"\u6DD8\u5B9D",host:"www.taobao.com",port:80,region:"cn",icon:"\u{1F6D2}",color:"#FF5000"},{name:"GitHub",host:"github.com",port:80,region:"intl",icon:"\u{1F419}",color:"#24292F"},{name:"jsDelivr",host:"cdn.jsdelivr.net",port:80,region:"intl",icon:"\u{1F4E6}",color:"#E84D0E"},{name:"Cloudflare",host:"www.cloudflare.com",port:80,region:"intl",icon:"\u2601\uFE0F",color:"#F6821F"},{name:"Google",host:"www.google.com",port:80,region:"intl",icon:"\u{1F50D}",color:"#4285F4"},{name:"YouTube",host:"www.youtube.com",port:80,region:"intl",icon:"\u25B6\uFE0F",color:"#FF0000"}],Yn=16,xe=3e3,Xn=4;var Na=5e3,Ha=5e3;function Gt(t,e,n="/"){return new TextEncoder().encode(`GET ${n} HTTP/1.1\r
Host: ${t}\r
User-Agent: Mozilla/5.0 (netprobe)\r
Connection: close\r
\r
`)}function Fa(t,e){let n=new Uint8Array(t.length+e.length);return n.set(t,0),n.set(e,t.length),n}function za(t){for(let e=0;e<t.length-3;e++)if(t[e]===13&&t[e+1]===10&&t[e+2]===13&&t[e+3]===10)return e+4;return-1}function ve(t){try{typeof t.close=="function"?t.close():t.writable&&typeof t.writable.close=="function"&&t.writable.close().catch(()=>{})}catch{}}function Wt(t,e){return new Promise(n=>{let a=new Uint8Array(0),r=!1,s=l=>{r||(r=!0,clearTimeout(o),n(l))},o=setTimeout(()=>s(null),e);(async()=>{let l=t.readable.getReader();try{for(;!r;){let{done:u,value:i}=await l.read();if(u)break;if(!(!i||i.byteLength===0)){if(a=Fa(a,i),za(a)>=0){s(Date.now());break}if(a.length>65536){s(null);break}}}}catch{}s(null);try{l.releaseLock()}catch{}})()})}async function Ba(t,e,n,a,r){let s=Date.now(),o;try{let u=await At(t,2,e),i=nt(t,u.outbound);o=await et({config:t,outbound:i,addressType:2,addressRemote:e,portRemote:n,rawClientData:a,log:r})}catch{return null}if(!o)return null;let l=await Wt(o,xe);return ve(o),l===null?null:l-s}async function ja(t,e,n){let a=[];for(let i=0;i<Yn;i+=Xn){let c=[],d=Math.min(i+Xn,Yn);for(let p=i;p<d;p++)c.push(Ba(t,e.host,e.port,Gt(e.host,e.port),n));let f=await Promise.all(c);for(let p of f)a.push(p)}let r=a.filter(i=>i!==null),s=r.length>0?Math.round(r.reduce((i,c)=>i+c,0)/r.length):null,o=r.length>0?Math.min(...r):null,l=r.length>0?Math.max(...r):null,u=a.length>0?Math.round((a.length-r.length)/a.length*100):100;return{...e,samples:a,latency:s,min:o,max:l,loss:u,success:r.length,total:a.length}}async function qn(t,e){let n=await Promise.allSettled(Kn.map(a=>ja(t,a,e)));return{ok:!0,ts:Date.now(),targets:n.map((a,r)=>a.status==="fulfilled"?a.value:{...Kn[r],samples:[],latency:null,success:0,total:0,error:a.reason&&a.reason.message||"error"})}}async function Jn(t,e,n){let a=String(e||"").trim().toLowerCase();if(!a)return{ok:!1,error:"domain required"};let r=2;/^\d{1,3}(\.\d{1,3}){3}$/.test(a)?r=1:a.includes(":")&&(r=3);let s=r!==2,o=await At(t,r,a),l=!!o.rule,u=l?`\u5206\u6D41\u89C4\u5219 ${o.rule.rule} \u2192 `:"",i=nt(t,o.outbound);if(i==="reject")return{ok:!0,domain:a,route:"reject",name:"reject",reason:l?`${u}reject\uFF08\u62D2\u7EDD\u8FDE\u63A5\uFF09`:"\u9ED8\u8BA4\u51FA\u7AD9 reject\uFF08\u62D2\u7EDD\u8FDE\u63A5\uFF09",rule:l?o.rule.rule:null};if(i==="direct"){let d=o.outbound,f=(!!t.proxyipHost||!!t.proxyipOutbound)&&!t.proxyipDisabled,p=f&&yn(),y=!s&&ce(a),g=s&&!a.includes(":")&&kt(a),m=!1;if(f&&!p&&!s&&!y){let h=await q(a,n);h&&kt(h)&&(m=!0)}if(f&&!p&&(y||g||m)){if(t.proxyipOutbound)return{ok:!0,domain:a,route:"proxyip",name:`outbound:${t.proxyipOutbound}`,reason:`${u}Cloudflare \u7AD9\u70B9\uFF08\u5DF2\u77E5 CF \u540E\u7F00/IP \u6BB5\uFF09\u2192 \u4F7F\u7528\u51FA\u7AD9\u4EE3\u7406 ${t.proxyipOutbound} \u51FA\u7AD9`,rule:l?o.rule.rule:null};let h=`${t.proxyipHost}:${Number(t.proxyipPort||443)}`;return{ok:!0,domain:a,route:"proxyip",name:h,reason:`${u}Cloudflare \u7AD9\u70B9\uFF08\u5DF2\u77E5 CF \u540E\u7F00/IP \u6BB5\uFF09\u2192 proxyip ${h}`,rule:l?o.rule.rule:null}}return l?{ok:!0,domain:a,route:"direct",name:"direct",reason:`${u}direct`,rule:o.rule.rule}:d&&d!=="direct"&&d!=="reject"?{ok:!0,domain:a,route:"direct",name:"direct",reason:`\u9ED8\u8BA4\u51FA\u7AD9 ${d} \u4E0D\u5B58\u5728\uFF0C\u56DE\u9000 direct`,rule:null}:{ok:!0,domain:a,route:"direct",name:"direct",reason:"\u9ED8\u8BA4\u51FA\u7AD9 direct",rule:null}}let c=typeof i=="string"?i:i.name;return{ok:!0,domain:a,route:"outbound",name:c,reason:l?`${u}\u51FA\u7AD9 ${c}`:`\u9ED8\u8BA4\u51FA\u7AD9 ${c}`,rule:l?o.rule.rule:null}}async function Zn(t,e){let n="www.cloudflare.com";if(t.proxyipOutbound){let l=nt(t,t.proxyipOutbound);if(!l||typeof l=="string")return{ok:!1,mode:"outbound",error:`\u51FA\u7AD9 ${t.proxyipOutbound} \u4E0D\u5B58\u5728\uFF0C\u8BF7\u68C0\u67E5\u51FA\u7AD9\u914D\u7F6E`};let u=Date.now(),i=null;try{i=await et({config:t,outbound:l,addressType:2,addressRemote:n,portRemote:443,rawClientData:Gt(n,443),log:e,isUDP:!1})}catch(d){return{ok:!1,mode:"outbound",outbound:t.proxyipOutbound,error:`\u51FA\u7AD9\u8FDE\u63A5\u5931\u8D25: ${d.message}`}}if(!i)return{ok:!1,mode:"outbound",outbound:t.proxyipOutbound,error:"\u51FA\u7AD9\u8FDE\u63A5\u5931\u8D25\u6216\u65E0\u54CD\u5E94"};let c=await Wt(i,xe);return ve(i),c===null?{ok:!1,mode:"outbound",outbound:t.proxyipOutbound,error:"\u8FDE\u63A5\u8D85\u65F6\u6216\u65E0\u54CD\u5E94"}:{ok:!0,latency:c-u,mode:"outbound",outbound:t.proxyipOutbound}}if(!t.proxyipHost)return{ok:!1,error:"\u672A\u914D\u7F6E proxyip\uFF0C\u8BF7\u5148\u5728\u7CFB\u7EDF\u8BBE\u7F6E\u4E2D\u586B\u5199"};let r=Date.now(),s=null;try{if(s=globalThis.connect?globalThis.connect({hostname:t.proxyipHost,port:Number(t.proxyipPort||443)}):null,!s)return{ok:!1,error:"connect \u4E0D\u53EF\u7528"};let l=s.writable.getWriter();await l.write(Gt(n,443)),l.releaseLock()}catch(l){try{s&&s.close()}catch{}return{ok:!1,error:`\u8FDE\u63A5\u5931\u8D25: ${l.message}`}}let o=await Wt(s,xe);try{s.close()}catch{}return o===null?{ok:!1,error:"\u8FDE\u63A5\u8D85\u65F6\u6216\u65E0\u54CD\u5E94"}:{ok:!0,latency:o-r,mode:"proxyip",endpoint:`${t.proxyipHost}:${t.proxyipPort||443}`}}function Ga(t){let n=[18,52];n.push(1,0),n.push(0,1),n.push(0,0,0,0,0,0);for(let a of String(t).split(".")){n.push(a.length);for(let r=0;r<a.length;r++)n.push(a.charCodeAt(r))}return n.push(0),n.push(0,1),n.push(0,1),new Uint8Array(n)}async function Qn(t,e){let n=null,a=(t.udpOutbound||"").trim();if(a){let i=t.outboundByName[a];if(i&&i.type==="vless")n=i;else return{ok:!1,error:`UDP \u51FA\u7AD9 '${a}' \u4E0D\u5B58\u5728\u6216\u975E vless\uFF08\u4EC5 vless \u652F\u6301 UDP\uFF09`}}else if(n=t.outbounds.find(i=>i.type==="vless"),!n)return{ok:!1,error:"\u672A\u914D\u7F6E vless \u51FA\u7AD9\uFF0C\u65E0\u6CD5\u6D4B\u8BD5 UDP"};let r=Ga("example.com"),s=Et(r),o=Date.now(),l;try{l=await ft({address:n.address,port:Number(n.port),uuid:n.uuid,path:n.path,tls:!!n.tls,sni:n.sni||"",transport:n.transport},2,1,"8.8.8.8",53,s,e)}catch(i){return{ok:!1,error:`UDP \u51FA\u7AD9\u8FDE\u63A5\u5931\u8D25: ${i.message}`}}if(!l)return{ok:!1,error:"UDP \u51FA\u7AD9\u8FDE\u63A5\u5931\u8D25"};let u=await new Promise(i=>{let c=setTimeout(()=>i({ok:!1,error:"UDP \u54CD\u5E94\u8D85\u65F6"}),Na);xn(l.readable,d=>{d.length>=12&&d[0]===18&&d[1]===52&&(d[2]&128)!==0&&(clearTimeout(c),i({ok:!0,latency:Date.now()-o,bytes:d.length,outbound:n.name||a||"vless"}))},e)});try{l.writable.close().catch(()=>{})}catch{}return u}async function tr(t,e,n){let a="www.gstatic.com",s=Date.now(),o;try{o=await et({config:t,outbound:e,addressType:2,addressRemote:a,portRemote:80,rawClientData:Gt(a,80,"/generate_204"),log:n})}catch(u){return{ok:!1,error:u.message}}if(!o)return{ok:!1,error:"\u96A7\u9053\u5EFA\u7ACB\u5931\u8D25"};let l=await Wt(o,Ha);return ve(o),l===null?{ok:!1,error:"\u8FDE\u63A5\u8D85\u65F6\u6216\u65E0\u54CD\u5E94"}:{ok:!0,latency:l-s}}var z=Uint8Array,mt=Uint16Array,Wa=Int32Array,er=new z([0,0,0,0,0,0,0,0,1,1,1,1,2,2,2,2,3,3,3,3,4,4,4,4,5,5,5,5,0,0,0,0]),nr=new z([0,0,0,0,1,1,2,2,3,3,4,4,5,5,6,6,7,7,8,8,9,9,10,10,11,11,12,12,13,13,0,0]),Va=new z([16,17,18,0,8,7,9,6,10,5,11,4,12,3,13,2,14,1,15]),rr=function(t,e){for(var n=new mt(31),a=0;a<31;++a)n[a]=e+=1<<t[a-1];for(var r=new Wa(n[30]),a=1;a<30;++a)for(var s=n[a];s<n[a+1];++s)r[s]=s-n[a]<<5|a;return{b:n,r}},ar=rr(er,2),sr=ar.b,Ka=ar.r;sr[28]=258,Ka[258]=28;var or=rr(nr,0),Ya=or.b,Io=or.r,Ee=new mt(32768);for(_=0;_<32768;++_)Z=(_&43690)>>1|(_&21845)<<1,Z=(Z&52428)>>2|(Z&13107)<<2,Z=(Z&61680)>>4|(Z&3855)<<4,Ee[_]=((Z&65280)>>8|(Z&255)<<8)>>1;var Z,_,Rt=(function(t,e,n){for(var a=t.length,r=0,s=new mt(e);r<a;++r)t[r]&&++s[t[r]-1];var o=new mt(e);for(r=1;r<e;++r)o[r]=o[r-1]+s[r-1]<<1;var l;if(n){l=new mt(1<<e);var u=15-e;for(r=0;r<a;++r)if(t[r])for(var i=r<<4|t[r],c=e-t[r],d=o[t[r]-1]++<<c,f=d|(1<<c)-1;d<=f;++d)l[Ee[d]>>u]=i}else for(l=new mt(a),r=0;r<a;++r)t[r]&&(l[r]=Ee[o[t[r]-1]++]>>15-t[r]);return l}),Ot=new z(288);for(_=0;_<144;++_)Ot[_]=8;var _;for(_=144;_<256;++_)Ot[_]=9;var _;for(_=256;_<280;++_)Ot[_]=7;var _;for(_=280;_<288;++_)Ot[_]=8;var _,ir=new z(32);for(_=0;_<32;++_)ir[_]=5;var _;var Xa=Rt(Ot,9,1);var qa=Rt(ir,5,1),Te=function(t){for(var e=t[0],n=1;n<t.length;++n)t[n]>e&&(e=t[n]);return e},j=function(t,e,n){var a=e/8|0;return(t[a]|t[a+1]<<8)>>(e&7)&n},ke=function(t,e){var n=e/8|0;return(t[n]|t[n+1]<<8|t[n+2]<<16)>>(e&7)},Ja=function(t){return(t+7)/8|0},Za=function(t,e,n){return(e==null||e<0)&&(e=0),(n==null||n>t.length)&&(n=t.length),new z(t.subarray(e,n))};var Qa=["unexpected EOF","invalid block type","invalid length/literal","invalid distance","stream finished","no stream handler",,"no callback","invalid UTF-8 data","extra field too long","date not in range 1980-2099","filename too long","stream finishing","invalid zip data"],G=function(t,e,n){var a=new Error(e||Qa[t]);if(a.code=t,Error.captureStackTrace&&Error.captureStackTrace(a,G),!n)throw a;return a},ts=function(t,e,n,a){var r=t.length,s=a?a.length:0;if(!r||e.f&&!e.l)return n||new z(0);var o=!n,l=o||e.i!=2,u=e.i;o&&(n=new z(r*3));var i=function(Le){var $e=n.length;if(Le>$e){var Ue=new z(Math.max($e*2,Le));Ue.set(n),n=Ue}},c=e.f||0,d=e.p||0,f=e.b||0,p=e.l,y=e.d,g=e.m,m=e.n,h=r*8;do{if(!p){c=j(t,d,1);var b=j(t,d+1,3);if(d+=3,b)if(b==1)p=Xa,y=qa,g=9,m=5;else if(b==2){var E=j(t,d,31)+257,$=j(t,d+10,15)+4,U=E+j(t,d+5,31)+1;d+=14;for(var S=new z(U),O=new z(19),T=0;T<$;++T)O[Va[T]]=j(t,d+T*3,7);d+=$*3;for(var M=Te(O),D=(1<<M)-1,L=Rt(O,M,1),T=0;T<U;){var C=L[j(t,d,D)];d+=C&15;var x=C>>4;if(x<16)S[T++]=x;else{var A=0,R=0;for(x==16?(R=3+j(t,d,3),d+=2,A=S[T-1]):x==17?(R=3+j(t,d,7),d+=3):x==18&&(R=11+j(t,d,127),d+=7);R--;)S[T++]=A}}var st=S.subarray(0,E),N=S.subarray(E);g=Te(st),m=Te(N),p=Rt(st,g,1),y=Rt(N,m,1)}else G(1);else{var x=Ja(d)+4,v=t[x-4]|t[x-3]<<8,w=x+v;if(w>r){u&&G(0);break}l&&i(f+v),n.set(t.subarray(x,w),f),e.b=f+=v,e.p=d=w*8,e.f=c;continue}if(d>h){u&&G(0);break}}l&&i(f+131072);for(var Yt=(1<<g)-1,yt=(1<<m)-1,ut=d;;ut=d){var A=p[ke(t,d)&Yt],I=A>>4;if(d+=A&15,d>h){u&&G(0);break}if(A||G(2),I<256)n[f++]=I;else if(I==256){ut=d,p=null;break}else{var P=I-254;if(I>264){var T=I-257,H=er[T];P=j(t,d,(1<<H)-1)+sr[T],d+=H}var W=y[ke(t,d)&yt],V=W>>4;W||G(3),d+=W&15;var N=Ya[V];if(V>3){var H=nr[V];N+=ke(t,d)&(1<<H)-1,d+=H}if(d>h){u&&G(0);break}l&&i(f+131072);var Xt=f+P;if(f<N){var _e=s-N,br=Math.min(N,Xt);for(_e+f<0&&G(3);f<br;++f)n[f]=a[_e+f]}for(;f<Xt;++f)n[f]=n[f-N]}}e.l=p,e.p=ut,e.b=f,e.f=c,p&&(c=1,e.m=g,e.d=y,e.n=m)}while(!c);return f!=n.length&&o?Za(n,0,f):n.subarray(0,f)};var es=new z(0);var ns=function(t,e){return((t[0]&15)!=8||t[0]>>4>7||(t[0]<<8|t[1])%31)&&G(6,"invalid zlib data"),(t[1]>>5&1)==+!e&&G(6,"invalid zlib data: "+(t[1]&32?"need":"unexpected")+" dictionary"),(t[1]>>3&4)+2};function lr(t,e){return ts(t.subarray(ns(t,e&&e.dictionary),-4),{i:2},e&&e.out,e&&e.dictionary)}var rs=typeof TextDecoder<"u"&&new TextDecoder,as=0;try{rs.decode(es,{stream:!0}),as=1}catch{}var Se={"Content-Type":"application/json; charset=utf-8"},ss="gcp:asia-east2";function k(t,e=200){return new Response(JSON.stringify(t),{status:e,headers:Se})}async function Ct(t){try{return await t.json()}catch{return null}}function os(t){return t.admin_cookie_secret||t.admin_password_hash||"vtd-insecure-secret"}async function fr(t,e,n){let a=new URL(t.url),s=a.pathname.split("/").filter(Boolean),o=s[2]||"",l=s[3]||null,u=t.method,{DB:i,GEO_KV:c}=e.env,d=e.settings,f=os(d);if(o==="login"&&u==="POST"){let h=await Ct(t);if(!h||!h.password)return k({error:"password required"},400);if(!await Mt(h.password,e.adminPasswordHash))return k({error:"invalid password"},401);let x=await Fe(f);return new Response(JSON.stringify({ok:!0}),{status:200,headers:{...Se,"Set-Cookie":`${bt}=${x}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${7*86400}`}})}let p=Be(t.headers.get("Cookie"));if(!await ze(p[bt],f))return k({error:"unauthorized"},401);if(o==="logout"&&u==="POST")return new Response(JSON.stringify({ok:!0}),{status:200,headers:{...Se,"Set-Cookie":`${bt}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0`}});if(o==="version"&&u==="GET")return k({ok:!0,version:Vn});if(o==="colo"&&u==="GET"){let h=t&&t.cf||{},b=t.headers.get("cf-placement")||"",x=null,v=null;if(b){let w=b.indexOf("-");w>0?(x=b.slice(0,w),v=b.slice(w+1)||null):x=b}return k({ok:!0,placement_header:b||null,placement_mode:x,placement_colo:v,colo:h.colo||null,region:h.region||null,city:h.city||null,country:h.country||null,continent:h.continent||null,timezone:h.timezone||null,host:a.hostname||null,configured_placement_region:ss})}if(await Ts(i),o==="settings"){if(u==="GET"){let{results:h}=await i.prepare("SELECT key, value FROM settings").all();return k((h||[]).reduce((b,x)=>(b[x.key]=x.value,b),{}))}if(u==="PUT"){let h=await Ct(t);if(!h)return k({error:"bad body"},400);let b=new Set(["ws_path","default_outbound","proxyip","udp_outbound","ip_preference","disguise_title","disguise_subtitle","entry_host","entry_port","entry_sni","entry_ws_host","entry_list","admin_password_hash","admin_cookie_secret"]);if(h.ip_preference!==void 0&&!["ipv4","ipv6","auto"].includes(h.ip_preference))return k({error:"ip_preference \u4EC5\u5141\u8BB8 ipv4 / ipv6 / auto"},400);if(h.entry_list!==void 0)try{let x=JSON.parse(h.entry_list);if(!Array.isArray(x)||x.some(v=>!v||!String(v.host||"").trim()))return k({error:"entry_list \u5FC5\u987B\u4E3A\u5165\u53E3\u6570\u7EC4\uFF08\u6BCF\u9879\u9700\u5305\u542B host\uFF09"},400);if(x.some(v=>Array.isArray(v.transports)&&v.transports.some(w=>!["ws","grpc","h2","xhttp"].includes(w))))return k({error:"entry_list transports \u4EC5\u5141\u8BB8 ws / grpc / h2 / xhttp"},400)}catch{return k({error:"entry_list \u4E0D\u662F\u5408\u6CD5 JSON \u6570\u7EC4"},400)}for(let[x,v]of Object.entries(h))typeof v=="string"&&b.has(x)&&await i.prepare("INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at").bind(x,v,Date.now()).run();return pt("settings"),k({ok:!0})}return k({error:"method not allowed"},405)}let m={"vless-users":{table:"vless_users",cacheKey:"vlessUsers",cols:["uuid","remark","enable","path","expire_at","traffic_limit","traffic_reset_at"]},"trojan-users":{table:"trojan_users",cacheKey:"trojanUsers",cols:["password","remark","enable","path","expire_at","traffic_limit","traffic_reset_at"]},outbounds:{table:"outbounds",cacheKey:"outbounds",cols:["type","name","address","port","uuid","path","tls","udp","enable","sort","username","password","sni","transport"],validate(h){if(h.type!==void 0&&!["socks5","http","vless"].includes(h.type))return"invalid outbound type";if(h.port!==void 0&&(!Number.isInteger(Number(h.port))||Number(h.port)<=0||Number(h.port)>65535))return"invalid port";if((h.type==="socks5"||h.type==="http")&&!h.address)return"address required";if(h.type==="vless"){if(!h.uuid)return"vless requires uuid";if(h.transport!==void 0&&!["raw","ws","grpc","httpupgrade","h2"].includes(h.transport))return"invalid vless transport"}return h.username&&!h.password||!h.username&&h.password?"username and password must be set together":((h.type==="socks5"||h.type==="http")&&(h.udp=0),h.type!=="vless"&&(h.transport="ws"),null)}},"routing-rules":{table:"routing_rules",cacheKey:"routingRules",cols:["rule","outbound","enable","sort"]}}[o];if(m)return is(u,l,m,i,t);if(o==="stats"&&u==="GET"){let[h,b]=await Promise.all([i.prepare("SELECT remark, uuid, up, down, path, expire_at, traffic_limit, traffic_reset_at FROM vless_users ORDER BY (up + down) DESC").all(),i.prepare("SELECT remark, password, up, down, path, expire_at, traffic_limit, traffic_reset_at FROM trojan_users ORDER BY (up + down) DESC").all()]),x=Math.floor(Date.now()/1e3),v=w=>(w||[]).map(E=>{let $=Number(E.up||0),U=Number(E.down||0),S=Number(E.traffic_limit||0),O=$+U;return{...E,used:O,remaining:S>0?Math.max(0,S-O):null,expired:E.expire_at>0&&E.expire_at<x,limitReached:S>0&&O>=S}});return k({vless:v(h.results),trojan:v(b.results)})}if(o==="geo"&&s[3]==="update"&&u==="POST")try{if(await c.get("geo:updating")==="1")return k({ok:!0,started:!1,updating:!0});if(await c.put("geo:updating","1",{expirationTtl:7200}),e.env&&e.env.GEO_QUEUE&&typeof e.env.GEO_QUEUE.send=="function")return await e.env.GEO_QUEUE.send({kind:"geo-update"}),await c.put("geo:update_status",JSON.stringify({startedAt:Date.now(),state:"updating",step:0,total:0,updated:0,failed:[],current:"",message:"\u5DF2\u5165\u961F\uFF0C\u7B49\u5F85\u6D88\u8D39\u8005\u6267\u884C\u2026"})).catch(()=>{}),k({ok:!0,started:!0,queued:!0,updating:!0});if(n&&typeof n.waitUntil=="function")return n.waitUntil(Vt(i,c)),k({ok:!0,started:!0,updating:!0});let b=await Vt(i,c);return k({ok:!0,started:!1,updated:b.updated,total:b.total,failed:b.failed})}catch(h){return await c.put("geo:updating","0").catch(()=>{}),k({error:h.message},500)}if(o==="geo"&&s[3]==="status"&&u==="GET"){let[h,b,x]=await Promise.all([c.get("geo:updating"),c.get("geo:update_status"),c.get(Pt)]),v=null;if(b)try{v=JSON.parse(b)}catch{}return k({ok:!0,updating:h==="1",version:x||null,status:v})}if(o==="geo"&&s[3]==="info"&&u==="GET"){let[h,b,x]=await Promise.all([c.get("geo:updating"),c.get("geo:update_status"),c.get(Pt)]),v=null;if(b)try{v=JSON.parse(b)}catch{}let w=async U=>{let S=[],O;do{let T=await c.list({prefix:U,cursor:O});for(let M of T.keys||[])S.push(M.name.slice(U.length));O=T.cursor}while(O);return S},[E,$]=await Promise.all([w("geosite:"),w("geoip:")]);return k({ok:!0,updating:h==="1",version:x||null,status:v,geositeCount:E.length,geoipCount:$.length,geositeCategories:E,geoipCategories:$})}if(o==="netstatus"&&s[3]==="test"&&u==="POST")try{return k(await qn(e,h=>console.log(h)))}catch(h){return k({ok:!1,error:h.message},500)}if(o==="route-test"&&u==="POST")try{let h=await Ct(t),b=h&&h.domain?String(h.domain).trim():"";return b?k(await Jn(e,b,x=>console.log(x))):k({ok:!1,error:"\u8BF7\u586B\u5199\u8981\u6D4B\u8BD5\u7684\u57DF\u540D\u6216 IP"},400)}catch(h){return k({ok:!1,error:h.message},500)}if(o==="test"){if(s[3]==="proxyip"&&u==="POST")try{return k(await Zn(e,h=>console.log(h)))}catch(h){return k({ok:!1,error:h.message},500)}if(s[3]==="udp"&&u==="POST")try{return k(await Qn(e,h=>console.log(h)))}catch(h){return k({ok:!1,error:h.message},500)}if(s[3]==="outbound"&&s[4]&&u==="POST"){let h=await i.prepare("SELECT * FROM outbounds WHERE id = ?").bind(Number(s[4])).first();if(!h)return k({ok:!1,error:"outbound not found"},404);try{return k(await tr(e,h,b=>console.log(b)))}catch(b){return k({ok:!1,error:b.message},500)}}}return k({error:"not found"},404)}async function cr(t){try{let{results:e}=await t.prepare("SELECT name FROM pragma_table_info('outbounds')").all();if((e||[]).some(n=>n.name==="transport"))return;await t.prepare("ALTER TABLE outbounds ADD COLUMN transport TEXT DEFAULT 'ws'").run(),console.log("[admin] outbounds.transport column added (migration)")}catch(e){console.log("[admin] outbounds transport migration skipped: "+e.message)}}async function is(t,e,n,a,r){let{table:s,cols:o}=n,l="id";if(t==="GET"){let{results:u}=await a.prepare(`SELECT * FROM ${s} ORDER BY id`).all();return k(u||[])}if(t==="POST"){let u=await Ct(r);if(!u)return k({error:"bad body"},400);if(n.validate){let p=n.validate(u);if(p)return k({error:p},400)}s==="outbounds"&&await cr(a);let i=o.filter(p=>u[p]!==void 0);if(i.length===0)return k({error:"no fields"},400);let c=i.map(()=>"?").join(","),d=i.map(p=>u[p]),{meta:f}=await a.prepare(`INSERT INTO ${s} (${i.join(",")}) VALUES (${c})`).bind(...d).run();return n.cacheKey&&pt(n.cacheKey),k({ok:!0,id:f.last_row_id})}if(t==="PUT"&&e){let u=await Ct(r);if(!u)return k({error:"bad body"},400);if(n.validate){let f=n.validate(u);if(f)return k({error:f},400)}s==="outbounds"&&await cr(a);let i=o.filter(f=>u[f]!==void 0);if(i.length===0)return k({error:"no fields"},400);let c=i.map(f=>`${f} = ?`).join(","),d=i.map(f=>u[f]);return await a.prepare(`UPDATE ${s} SET ${c} WHERE ${l} = ?`).bind(...d,Number(e)).run(),n.cacheKey&&pt(n.cacheKey),k({ok:!0})}return t==="DELETE"&&e?(await a.prepare(`DELETE FROM ${s} WHERE ${l} = ?`).bind(Number(e)).run(),n.cacheKey&&pt(n.cacheKey),k({ok:!0})):k({error:"method not allowed"},405)}var ur={geosite:["cn","apple","google","microsoft","facebook","twitter","telegram","github","netflix","youtube","spotify","discord","tiktok","paypal","steam","cloudflare","openai","anthropic","amazon","whatsapp","instagram","linkedin","mozilla","adobe","speedtest","oracle","digitalocean","vultr","jetbrains","gitee","baidu","aliyun","tencent","jd","bilibili","douyin","zhihu","iqiyi","youku","xiaomi","huawei"],geoip:["cn","hk","mo","tw","jp","kr","sg","my","th","vn","id","ph","us","ca","gb","de","fr","nl","se","au","nz","ru","in","br","ar","mx","za","tr","ae","sa","il","es","it","ch","at","be","dk","fi","no","pl","pt","ie","cz","hu","ro","ua","kz"]};async function Kt(t,e,n){let a=await ps();(!a||a.length===0)&&(a=ur.geosite.slice(),console.log("[geo] v2fly category enumeration failed, fallback to DEFAULT_GEO_CATEGORIES.geosite"));let r={geosite:a,geoip:ur.geoip},s=r.geosite.length+r.geoip.length,o=i=>{if(typeof n=="function")try{n(i)}catch{}},l={updated:0,total:0,failed:[]},u=0;for(let i of["geosite","geoip"])for(let c of r[i]){l.total++,u++,o({state:"updating",step:u,total:s,current:`${i}:${c}`,updated:l.updated,failed:l.failed,message:`\u62C9\u53D6 ${i}:${c}`});try{let d=await ls(i,c);d&&d.length>0?(await e.put(`${i}:${c}`,JSON.stringify(d)),l.updated++):l.failed.push(`${i}:${c} (empty rules)`)}catch(d){l.failed.push(`${i}:${c} (${d.message||d})`)}}return await e.put(Pt,new Date().toISOString()),vn(),l}async function Vt(t,e){let n=Date.now(),a=r=>e.put("geo:update_status",JSON.stringify({startedAt:n,...r})).catch(()=>{});try{await a({state:"updating",step:0,total:0,updated:0,failed:[],current:"",message:"\u5F00\u59CB\u66F4\u65B0"});let r=await Kt(t,e,s=>a({...s}));return await a({state:"done",step:r.total,total:r.total,updated:r.updated,failed:r.failed,current:"",message:"\u66F4\u65B0\u5B8C\u6210"}),await e.put("geo:updating","0").catch(()=>{}),r}catch(r){throw await a({state:"error",message:r.message||String(r),failed:[]}).catch(()=>{}),r}}async function ls(t,e){if(t==="geosite"){let r=await hr(e,new Set);if(r.length===0)throw new Error("empty geosite rules");return r}let n=await gs(e),a=[];for(let[r,s]of n)if(r.length===4?a.push(...ws(r,s)):a.push(...xs(r,s)),a.length>=3e4)break;if(a.length===0)throw new Error("empty geoip cidrs");return a}var cs="https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/",us="https://cdn.jsdelivr.net/gh/v2fly/domain-list-community@master/data/",ds=2e4;function dr(t){let e=t.indexOf(".");return e>0?t.slice(0,e):t}async function ps(){try{let t=await fetch("https://api.github.com/repos/v2fly/domain-list-community/git/trees/master?recursive=1",{headers:{"User-Agent":"vless-trojan-d1"},cf:{cacheTtl:86400}});if(t.ok){let e=await t.json(),n=e&&Array.isArray(e.tree)?e.tree:[],a=new Set;for(let r of n){if(!r||r.type!=="blob"||typeof r.path!="string"||!r.path.startsWith("data/"))continue;let s=r.path.slice(5);!s||s.includes("/")||a.add(dr(s))}if(a.size>0)return[...a].sort()}}catch{}try{let t=await fetch("https://api.github.com/repos/v2fly/domain-list-community/contents/data",{headers:{"User-Agent":"vless-trojan-d1"},cf:{cacheTtl:86400}});if(t.ok){let e=await t.json();if(Array.isArray(e)){let n=new Set;for(let a of e){if(!a||a.type!=="file"||typeof a.name!="string")continue;let r=dr(a.name);r&&n.add(r)}if(n.size>0)return[...n].sort()}}}catch{}return null}async function hr(t,e){if(e.has(t))return[];e.add(t);let n=encodeURIComponent(t),a=[cs+n,us+n],r=null;for(let s of a)try{let o=await fetch(s,{cf:{cacheTtl:86400}});if(!o.ok){r=new Error(`HTTP ${o.status}`);continue}let l=await o.text(),u=[];for(let i of l.split(`
`)){if(i=i.trim(),!i||i.startsWith("#"))continue;if(i.startsWith("include:")){let f=i.slice(8).trim().split(/\s+/)[0];f&&u.push(...await hr(f,e));continue}let c=i;if(c.startsWith("full:"))c=c.slice(5);else if(c.startsWith("domain:"))c=c.slice(7);else if(c.startsWith("keyword:")||c.startsWith("regexp:"))continue;c=c.replace(/\s+@[^\s#]+/g,"");let d=c.indexOf("#");d>=0&&(c=c.slice(0,d)),c=c.trim().toLowerCase().replace(/^\.+/,""),c&&u.length<ds&&u.push(c)}return u}catch(o){r=o}throw r||new Error("v2fly geosite fetch failed")}var fs="https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/",hs="https://cdn.jsdelivr.net/gh/SagerNet/sing-geoip@rule-set/",ms=3e4;async function gs(t){let e=encodeURIComponent(t),n=[fs+"geoip-"+e+".srs",hs+"geoip-"+e+".srs"],a=null;for(let r of n)try{let s=await fetch(r,{cf:{cacheTtl:86400}});if(!s.ok){a=new Error(`HTTP ${s.status}`);continue}let o=new Uint8Array(await s.arrayBuffer());if(o.length<5||o[0]!==83||o[1]!==82||o[2]!==83){a=new Error("bad srs magic");continue}if(o[3]>1){a=new Error(`unsupported srs version ${o[3]}`);continue}let l;try{l=lr(o.subarray(4))}catch{a=new Error("zlib inflate failed");continue}return ys(l)}catch(s){a=s}throw a||new Error("sing-geoip srs fetch failed")}function ys(t){let e=0,n=gt(t,e);e=n.p;let a=[];for(let r=0;r<n.v;r++){let s=t[e++];if(s!==0)throw new Error(`geoip logical rule unsupported (type ${s})`);for(;;){let o=t[e++];if(o===255)break;if(o===5||o===6){if(t[e++]!==1)throw new Error("bad ipset version");let l=bs(t,e);e+=8;for(let u=0;u<l&&a.length<ms*2;u++){let i=gt(t,e);e=i.p;let c=t.subarray(e,e+i.v);e+=i.v,i=gt(t,e),e=i.p;let d=t.subarray(e,e+i.v);if(e+=i.v,c.length!==d.length||c.length!==4&&c.length!==16)throw new Error("bad ipset addr");a.push([c,d])}}else if(o===0||o===7||o===9){let l=gt(t,e);e=l.p,e+=l.v*2}else if(o===1||o===3||o===4||o===8||o===10||o===11||o===12||o===13||o===14||o===15||o===17||o===18||o===19||o===20||o===21||o===22||o===23){let l=gt(t,e);e=l.p;for(let u=0;u<l.v;u++){let i=gt(t,e);e=i.p,e+=i.v}}else throw new Error(`geoip unsupported item type ${o}`)}}return a}function gt(t,e){let n=0,a=0;for(;;){let r=t[e++];if(n|=(r&127)<<a,!(r&128))break;if(a+=7,a>63)throw new Error("uvarint overflow")}return{v:n,p:e}}function bs(t,e){let n=0;for(let a=0;a<8;a++)n=n*256+t[e+a];return n}function ws(t,e){let n=(t[0]<<24>>>0)+(t[1]<<16)+(t[2]<<8)+t[3],a=(e[0]<<24>>>0)+(e[1]<<16)+(e[2]<<8)+e[3],r=[];for(;n<=a;){let s=0;for(;;){let o=1<<s+1;if((n&o-1)!==0||n+o-1>a)break;s++}r.push(`${n>>>24}.${n>>>16&255}.${n>>>8&255}.${n&255}/${32-s}`),n+=1<<s}return r}function xs(t,e){let n=0n,a=0n;for(let s of t)n=n<<8n|BigInt(s);for(let s of e)a=a<<8n|BigInt(s);let r=[];for(;n<=a;){let s=0n;for(;;){let o=1n<<s+1n;if((n&o-1n)!==0n||n+o-1n>a)break;s++}r.push(`${vs(n)}/${128-Number(s)}`),n+=1n<<s}return r}function vs(t){let e=[];for(let l=7;l>=0;l--)e.push(Number(t>>BigInt(l*16)&0xffffn));let n=-1,a=0,r=-1,s=0;for(let l=0;l<8;l++)e[l]===0?(r<0&&(r=l),s++,s>a&&(a=s,n=r)):(r=-1,s=0);let o="";for(let l=0;l<8;l++)l===n&&a>=2?(o+=(o.length>0&&!o.endsWith(":"),"::"),l+=a-1):(o.length>0&&!o.endsWith(":")&&(o+=":"),o+=e[l].toString(16));return o}var pr=!1;async function Ts(t){if(pr)return;let e=[["path","TEXT DEFAULT ''"],["expire_at","INTEGER DEFAULT 0"],["traffic_limit","INTEGER DEFAULT 0"],["traffic_reset_at","INTEGER DEFAULT 0"]];for(let n of["vless_users","trojan_users"])try{let{results:a}=await t.prepare(`SELECT name FROM pragma_table_info('${n}')`).all(),r=new Set((a||[]).map(s=>s.name));for(let[s,o]of e)r.has(s)||(await t.prepare(`ALTER TABLE ${n} ADD COLUMN ${s} ${o}`).run(),console.log(`[admin] ${n}.${s} column added (migration)`))}catch(a){console.log(`[admin] ${n} migration skipped: ${a.message}`)}pr=!0}var Ae=null;function mr(t){if(!t&&Ae)return Ae;let n=`<!DOCTYPE html>
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

const ENTRY_TRANSPORTS = ['ws', 'grpc', 'h2', 'xhttp'];
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
      '<div class="card" style="background:var(--ok-bg);color:var(--ok-text);font-size:13px;border-radius:10px;padding:12px 16px;margin-bottom:16px">\u652F\u6301\u914D\u7F6E\u591A\u4E2A\u5165\u53E3\uFF0C\u6BCF\u4E2A\u5165\u53E3\u53EF\u72EC\u7ACB\u9009\u62E9\u652F\u6301\u7684\u534F\u8BAE\uFF08ws / grpc / h2 / xhttp\uFF09\u3002\u8BBF\u95EE\u5BF9\u5E94\u5165\u53E3\u57DF\u540D\u65F6\uFF0C\u5355\u51ED\u636E\u9875\u4E0E\u5355\u51ED\u636E\u8BA2\u9605\u53EA\u8F93\u51FA\u8BE5\u5165\u53E3\u52FE\u9009\u7684\u534F\u8BAE\uFF1B\u805A\u5408\u8BA2\u9605\u5728\u8BBE\u7F6E\u4E86\u5165\u53E3\u540E\u4EC5\u751F\u6210\u5404\u5165\u53E3\u52FE\u9009\u7684\u534F\u8BAE\u3002\u672A\u8BBE\u7F6E\u4EFB\u4F55\u5165\u53E3\u65F6\u4F7F\u7528\u5F53\u524D\u57DF\u540D\uFF08\u5168\u534F\u8BAE\uFF09\u3002</div>' +
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
</html>`;return t||(Ae=n),n}async function gr(t,e){let n=new URL(t.url);if(t.method==="POST"||t.method==="GET")try{let{DB:a,GEO_KV:r}=e,s=await Kt(a,r);return new Response(JSON.stringify({ok:!0,updated:s.updated,total:s.total,failed:s.failed}),{status:200,headers:{"Content-Type":"application/json; charset=utf-8"}})}catch(a){return new Response(JSON.stringify({ok:!1,error:a.message}),{status:500,headers:{"Content-Type":"application/json; charset=utf-8"}})}return new Response("Not Found",{status:404})}async function yr(t,e,n){try{let a=await Kt(e.DB,e.GEO_KV);console.log(`[cron] geo update done: ${a.updated}/${a.total} categories${a.failed.length?", failed: "+a.failed.join("; "):""}`)}catch(a){console.log(`[cron] geo update failed: ${a.message}`)}}globalThis.connect=ks;function Es(t,e){if(e.length<=2)return null;for(let n of t.inboundPathMap.keys()){if(n.length<2)continue;let a=n+"/";if(e.startsWith(a)){let r=e.slice(a.length),s=r.indexOf("/"),o=s>=0?r.slice(0,s):r,l=o.length;if(l===36&&o[8]==="-"&&o[13]==="-"&&o[18]==="-"&&o[23]==="-"&&/^[0-9a-fA-F-]{36}$/.test(o)||l===32&&/^[0-9a-fA-F]{32}$/.test(o))return{basePath:n,uuid:o,scopes:t.inboundPathMap.get(n)}}}return null}var si={async fetch(t,e,n){let r=new URL(t.url).pathname;try{if(r.startsWith("/admin")){let u=await ne(t,e,{ensureAdmin:!0});if(r.startsWith("/admin/api/"))return await fr(t,u,n);let i=mr(u.adminTempPassword),c=u.adminTempPassword?"no-store":"public, max-age=300";return new Response(i,{headers:{"Content-Type":"text/html; charset=utf-8","Cache-Control":c}})}if(r==="/geo-update-cron")return await gr(t,e);let s=await ne(t,e),o=s.inboundPathMap.get(r)||s.inboundPathMap.get(r.length>1&&r.endsWith("/")?r.slice(0,-1):r)||s.inboundPathMap.get(r.includes("//")?r.replace(/\/+/g,"/"):r),l=null;if(!o&&(t.method==="GET"||t.method==="POST")&&r.length>2&&(l=Es(s,r),l&&(o=l.scopes)),o&&o.length>0){s._inboundScope=Ve(o);let u=String(t.headers.get("Upgrade")||"").toLowerCase(),i=String(t.headers.get("Content-Type")||"").toLowerCase(),c=r.endsWith("/Tun");if(l&&t.method==="GET")return await Mn(t,s,e,l.uuid);if(l&&t.method==="POST")return await In(t,s,e,l.uuid);let d=!c&&t.method==="POST"&&i.includes("application/grpc");if(u==="websocket"&&!c&&!d)return await Rn(t,s,e);if(c)return await Nn(t,s,e);if(d)return await Pn(t,s,e);if(t.method==="POST"||t.method==="PUT"||t.method==="GET"&&t.body)return await Cn(t,s,e)}return await Wn(t,s,e)}catch(s){return console.log(`[index] error: ${s.message||s}`),new Response(JSON.stringify({error:"internal error"}),{status:500,headers:{"Content-Type":"application/json; charset=utf-8"}})}},async scheduled(t,e,n){return yr(t,e,n)},async queue(t,e,n){for(let a of t.messages)try{if(await e.GEO_KV.get("geo:update_busy")==="1"){console.log("[queue] geo update already in progress, skip message"),a.ack();continue}await e.GEO_KV.put("geo:update_busy","1",{expirationTtl:7200});try{let s=await Vt(e.DB,e.GEO_KV);console.log(`[queue] geo update done: ${s.updated}/${s.total} categories${s.failed.length?", failed: "+s.failed.join("; "):""}`),a.ack()}finally{await e.GEO_KV.put("geo:update_busy","0").catch(()=>{})}}catch(r){throw console.log(`[queue] geo update failed (will retry): ${r.message||r}`),r}}};export{si as default};
