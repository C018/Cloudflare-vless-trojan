import{connect as ns}from"cloudflare:sockets";var j="direct",st="reject",zt="socks5",Bt="http",Gt="vless",Se=["raw","ws","grpc","httpupgrade","h2"];var Ae="geosite:",_e="geoip:",Lt="geo:version",pt="vtd_admin";var Le=["qq.com","taobao.com","tmall.com","jd.com","baidu.com","bilibili.com","douyin.com","weibo.com","zhihu.com","163.com","126.com","aliyun.com","tencent.com","weixin.qq.com","alipay.com","bankofchina.com","icbc.com.cn","ccb.com","abcchina.com","cmbchina.com","boc.cn","12306.cn","gov.cn","cn","com.cn","net.cn","org.cn"],$e=["speedtest.net","fast.com","ookla.com"],Ue=["google.com","googleapis.com","gstatic.com","googleusercontent.com","ggpht.com","google.cn","google.com.hk","gvt1.com","gvt2.com","gvt3.com"],jt=[];for(let e=0;e<=255;++e){let t=e.toString(16).padStart(2,"0");jt.push(t)}var Wt=1e5;function Vt(e){return Array.from(new Uint8Array(e)).map(t=>t.toString(16).padStart(2,"0")).join("")}function cr(){let e=new Uint8Array(16);return crypto.getRandomValues(e),Vt(e)}async function Oe(e,t,n){let r=await crypto.subtle.importKey("raw",new TextEncoder().encode(e),"PBKDF2",!1,["deriveBits"]),a=await crypto.subtle.deriveBits({name:"PBKDF2",salt:new TextEncoder().encode(t),iterations:n,hash:"SHA-256"},r,256);return Vt(a)}async function De(e){let t=cr(),n=await Oe(e,t,Wt);return`${t}:${Wt}:${n}`}async function Re(e,t){if(!t||!e)return!1;let n=String(t).split(":");if(n.length!==3)return!1;let[r,a,s]=n,o=parseInt(a,10)||Wt;return await Oe(e,r,o)===s}async function Ce(e,t){let n=await crypto.subtle.importKey("raw",new TextEncoder().encode(e),{name:"HMAC",hash:"SHA-256"},!1,["sign"]),r=await crypto.subtle.sign("HMAC",n,new TextEncoder().encode(t));return Vt(r)}async function Me(e){let n=`admin.${Math.floor(Date.now()/1e3)+604800}`,r=await Ce(e,n);return`${n}.${r}`}async function Pe(e,t){if(!e||!t)return!1;let n=String(e).split(".");if(n.length!==3)return!1;let[r,a,s]=n;if(r!=="admin")return!1;let o=Number(a);if(!Number.isFinite(o)||o<Date.now()/1e3)return!1;let i=await Ce(t,`${r}.${a}`);if(i.length!==s.length)return!1;let u=0;for(let l=0;l<i.length;l++)u|=i.charCodeAt(l)^s.charCodeAt(l);return u===0}function Ie(e){let t={};if(!e)return t;for(let n of e.split(";")){let r=n.indexOf("=");if(r<0)continue;let a=n.slice(0,r).trim(),s=n.slice(r+1).trim();t[a]=decodeURIComponent(s)}return t}var pr=3e4,fr=3e4,Ne=0,ht={settings:{p:null,ts:0},vlessUsers:{p:null,ts:0},trojanUsers:{p:null,ts:0},outbounds:{p:null,ts:0},routingRules:{p:null,ts:0}};function ft(e,t){let n=ht[e],r=Date.now();if(n.p&&r-n.ts<pr)return n.p;let a=Promise.resolve().then(t).catch(()=>null);return n.p=a,n.ts=r,a}function ot(e){if(e==="all"){for(let n of Object.keys(ht))ht[n].p=null,ht[n].ts=0;return}let t=ht[e];t&&(t.p=null,t.ts=0)}async function hr(e){try{let{results:t}=await e.prepare("SELECT key, value FROM settings").all(),n={};for(let r of t||[])n[r.key]=r.value;return n}catch{return{}}}async function mr(e){try{let{results:t}=await e.prepare("SELECT id, uuid, remark, up, down, path, expire_at, traffic_limit, traffic_reset_at FROM vless_users WHERE enable = 1 ORDER BY id").all();return t||[]}catch{try{let{results:n}=await e.prepare("SELECT id, uuid, remark, up, down FROM vless_users WHERE enable = 1 ORDER BY id").all();return(n||[]).map(r=>({path:"",expire_at:0,traffic_limit:0,traffic_reset_at:0,...r}))}catch{return[]}}}async function gr(e){try{let{results:t}=await e.prepare("SELECT id, password, remark, up, down, path, expire_at, traffic_limit, traffic_reset_at FROM trojan_users WHERE enable = 1 ORDER BY id").all();return t||[]}catch{try{let{results:n}=await e.prepare("SELECT id, password, remark, up, down FROM trojan_users WHERE enable = 1 ORDER BY id").all();return(n||[]).map(r=>({path:"",expire_at:0,traffic_limit:0,traffic_reset_at:0,...r}))}catch{return[]}}}function yr(e){let t=String(e||"").trim();if(!t)return"";for(t.startsWith("/")||(t="/"+t);t.length>1&&t.endsWith("/");)t=t.slice(0,-1);return t}async function He(e,t,n){let r=Math.floor(Date.now()/1e3);for(let a of t)if(a.traffic_reset_at>0&&a.traffic_reset_at<=r)try{await e.prepare(`UPDATE ${n} SET up = 0, down = 0, traffic_reset_at = 0 WHERE id = ?`).bind(a.id).run(),a.up=0,a.down=0,a.traffic_reset_at=0}catch{}}function br(e,t,n){let r=new Map,a=(s,o)=>{let i=yr(s);if(!i)return;r.has(i)||r.set(i,[]),r.get(i).push(o);let u=`${i}/Tun`;r.has(u)||r.set(u,[]),r.get(u).push(o)};a(e,{kind:"all"});for(let s of t)s.path&&a(s.path,{kind:"vless",credential:s.uuid.toLowerCase()});for(let s of n)s.path&&a(s.path,{kind:"trojan",credential:s.password});return r}async function wr(e){try{let{results:t}=await e.prepare("SELECT * FROM outbounds WHERE enable = 1 ORDER BY sort ASC, id ASC").all();return t||[]}catch{return[]}}async function vr(e){try{let{results:t}=await e.prepare("SELECT * FROM routing_rules WHERE enable = 1 ORDER BY sort ASC, id ASC").all();return t||[]}catch{return[]}}async function xr(e){try{let r=await e.prepare("SELECT value FROM settings WHERE key = ?").bind("admin_password_hash").first();if(r&&r.value)return{hash:r.value,tempPassword:null}}catch{}let t=kr().replace(/-/g,"").slice(0,12),n=await De(t);try{await e.prepare("INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at").bind("admin_password_hash",n,Date.now()).run(),ot("settings")}catch{}return{hash:n,tempPassword:t}}function Tr(e){let t=[];try{let n=e.entry_list;if(n){let r=JSON.parse(n);Array.isArray(r)&&(t=r)}}catch{t=[]}return!t.length&&(e.entry_host||"").trim()&&(t=[{host:e.entry_host,port:e.entry_port||"",sni:e.entry_sni||"",wsHost:e.entry_ws_host||"",remark:"",transports:[]}]),t.map(n=>{let r=String(n.host||"").trim(),a=String(n.wsHost||"").trim()||r;return{host:r,port:String(n.port||"").trim()||"443",sni:String(n.sni||"").trim()||a,wsHost:a,remark:String(n.remark||"").trim(),transports:Array.isArray(n.transports)?n.transports.filter(s=>["ws","grpc","h2"].includes(s)):["ws","grpc","h2"]}}).filter(n=>n.host)}async function mt(e,t,n={}){let{DB:r}=t,[a,s,o,i,u]=await Promise.all([ft("settings",()=>hr(r)),ft("outbounds",()=>wr(r)),ft("vlessUsers",()=>mr(r)),ft("trojanUsers",()=>gr(r)),ft("routingRules",()=>vr(r))]),l=a.ws_path||"/ws",c=a.entry_transport||"ws",d=a.default_outbound||j,h=a.admin_password_hash||"",p=null;if(!h&&n.ensureAdmin){let E=await xr(r);h=E.hash,p=E.tempPassword}let g=a.proxyip||"",m="",y=443,f="";if(g)if(s.find($=>$.name===g&&$.type!==j&&$.type!==st))f=g;else{let $=g.lastIndexOf(":");$>0&&!g.includes("]")&&/^\d+$/.test(g.slice($+1))?(m=g.slice(0,$),y=Number(g.slice($+1))||443):m=g}let b=a.udp_outbound||"",w=Tr(a),T=w.length?w[0].host:"",k=w.length?w[0].port:"",_=w.length?w[0].sni:"",U=w.length?w[0].wsHost:"",L=Date.now();L-Ne>=fr&&(await Promise.all([He(r,o,"vless_users"),He(r,i,"trojan_users")]),Ne=L);let A=br(l,o,i),M={};for(let E of o)M[E.uuid.toLowerCase()]=E;let v={};for(let E of i)v[E.password]=E;return{env:t,settings:a,wsPath:l,entryTransport:c,defaultOutbound:d,adminPasswordHash:h,adminTempPassword:p,proxyipHost:m,proxyipPort:y,proxyipOutbound:f,proxyipDisabled:d!==j,udpOutbound:b,entryHost:T,entryPort:k,entrySni:_,entryWsHost:U,entries:w,vlessUsers:o,trojanUsers:i,outbounds:s,routingRules:u,vlessIndex:M,trojanIndex:v,uuidSet:new Set(o.map(E=>E.uuid.toLowerCase())),passwordSet:new Set(i.map(E=>E.password)),outboundByName:s.reduce((E,$)=>(E[$.name]=$,E),{}),inboundPathMap:A}}function kr(){return globalThis.crypto&&typeof globalThis.crypto.randomUUID=="function"?globalThis.crypto.randomUUID():"xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(/[xy]/g,e=>{let t=Math.random()*16|0;return(e==="x"?t:t&3|8).toString(16)})}function $t(e){let t=new Set,n=new Set;for(let r of e){if(r.kind==="all")return{all:!0,vless:t,trojan:n};r.kind==="vless"&&r.credential&&t.add(r.credential),r.kind==="trojan"&&r.credential&&n.add(r.credential)}return{all:!1,vless:t,trojan:n}}var Er=new TextDecoder,Ut=new Map,Sr=64;function Ar(e){let t=Ut.get(e);if(t)return t;let n=e.replace(/-/g,"");t=new Uint8Array(16);for(let r=0;r<16;r++)t[r]=parseInt(n.substr(r*2,2),16);return Ut.size>=Sr&&Ut.clear(),Ut.set(e,t),t}function _r(e){let t=n=>jt[e[n]];return`${t(0)}${t(1)}${t(2)}${t(3)}-${t(4)}${t(5)}-${t(6)}${t(7)}-${t(8)}${t(9)}-${t(10)}${t(11)}${t(12)}${t(13)}${t(14)}${t(15)}`}function Fe(e,t){if(e.byteLength<24)return{hasError:!0,message:"invalid data"};let n=e instanceof Uint8Array?e:new Uint8Array(e),r=new DataView(n.buffer,n.byteOffset,n.byteLength),a=_r(n.subarray(1,17));if(!t.has(a))return{hasError:!0,message:"invalid user"};let o=18+r.getUint8(17);if(e.byteLength<o+4)return{hasError:!0,message:"invalid data"};let i=r.getUint8(o);if(i!==1&&i!==2)return{hasError:!0,message:`command ${i} is not supported`};let u=o+1,l=r.getUint16(u),c=r.getUint8(u+2),d,h,p;switch(c){case 1:h=4,p=u+3,d=`${r.getUint8(p)}.${r.getUint8(p+1)}.${r.getUint8(p+2)}.${r.getUint8(p+3)}`;break;case 2:if(e.byteLength<u+4)return{hasError:!0,message:"invalid data"};h=r.getUint8(u+3),p=u+4,d=Er.decode(n.subarray(p,p+h));break;case 3:h=16,p=u+3,d=`${r.getUint16(p).toString(16)}:${r.getUint16(p+2).toString(16)}:${r.getUint16(p+4).toString(16)}:${r.getUint16(p+6).toString(16)}:${r.getUint16(p+8).toString(16)}:${r.getUint16(p+10).toString(16)}:${r.getUint16(p+12).toString(16)}:${r.getUint16(p+14).toString(16)}`;break;default:return{hasError:!0,message:`invalid addressType: ${c}`}}return d?{hasError:!1,userUuid:a,addressRemote:d,addressType:c,portRemote:l,rawDataIndex:p+h,isUDP:i===2}:{hasError:!0,message:"addressValue is empty"}}function ze(e,t,n,r,a){let s,o,i=[];switch(t){case 1:s=4,i=n.split(".").map(Number);break;case 2:o=new TextEncoder().encode(n),s=o.length+1;break;case 3:s=16,i=Kt(n).split(":").map(l=>[parseInt(l.slice(0,2),16),parseInt(l.slice(2),16)]).flat();break;default:throw new Error(`Unknown address type: ${t}`)}let u=new Uint8Array(22+s);return u[0]=0,u.set(Ar(a),1),u[17]=0,u[18]=e,u[19]=r>>8,u[20]=r&255,u[21]=t,t===2?(u[22]=o.length,u.set(o,23)):u.set(i,22),u}function Kt(e){if(e=e.replace(/^\[|\]$/g,""),e.includes("::")){let t=e.split("::"),n=t[0]?t[0].split(":"):[],r=t[1]?t[1].split(":"):[],a=8-n.length-r.length,s=Array(Math.max(0,a)).fill("0");return[...n,...s,...r].map(o=>o.padStart(4,"0")).join(":")}return e.split(":").map(t=>t.padStart(4,"0")).join(":")}var Be=new TextDecoder;async function Lr(e){let t=new TextEncoder().encode(e),n=await crypto.subtle.digest({name:"SHA-224"},t);return Array.from(new Uint8Array(n)).map(r=>r.toString(16).padStart(2,"0")).join("")}var Yt=new Map,Ge=new Map;function $r(e){if(Yt.has(e))return Yt.get(e);let t=Lr(e);return Yt.set(e,t),t.then(n=>{n&&Ge.set(n,e)}).catch(()=>{}),t}function je(e){if(e.byteLength<60)return!1;let t=e instanceof Uint8Array?e:new Uint8Array(e);return t[0]===0?!1:t[56]===13&&t[57]===10}async function We(e,t){if(e.byteLength<60)return{hasError:!0,message:"Invalid Trojan data: too short"};let n=e instanceof Uint8Array?e:new Uint8Array(e),r=e instanceof Uint8Array?new DataView(e.buffer,e.byteOffset,e.byteLength):new DataView(e);if(n[56]!==13||n[57]!==10)return{hasError:!0,message:"Invalid Trojan header: missing CRLF"};let a=Be.decode(n.subarray(0,56)),s=null,o=Ge.get(a);if(o!==void 0)s=o;else for(let m of t)try{if(await $r(m)===a){s=m;break}}catch{}if(!s)return{hasError:!0,message:"Invalid Trojan password"};let i=n[58];if(i!==1&&i!==3)return{hasError:!0,message:`Unsupported Trojan command: ${i}`};let u=n[59],l,c,d;switch(u){case 1:if(c=4,d=60,e.byteLength<d+c+2)return{hasError:!0,message:"Invalid Trojan header: IPv4 truncated"};l=`${r.getUint8(d)}.${r.getUint8(d+1)}.${r.getUint8(d+2)}.${r.getUint8(d+3)}`;break;case 3:if(c=n[60],d=61,e.byteLength<d+c+2)return{hasError:!0,message:"Invalid Trojan header: domain truncated"};l=Be.decode(n.subarray(d,d+c));break;case 4:if(c=16,d=60,e.byteLength<d+c+2)return{hasError:!0,message:"Invalid Trojan header: IPv6 truncated"};l=`${r.getUint16(d).toString(16)}:${r.getUint16(d+2).toString(16)}:${r.getUint16(d+4).toString(16)}:${r.getUint16(d+6).toString(16)}:${r.getUint16(d+8).toString(16)}:${r.getUint16(d+10).toString(16)}:${r.getUint16(d+12).toString(16)}:${r.getUint16(d+14).toString(16)}`;break;default:return{hasError:!0,message:`Invalid Trojan address type: ${u}`}}let h=d+c;if(e.byteLength<h+2)return{hasError:!0,message:"Invalid Trojan header: port truncated"};let p=r.getUint16(h),g=h+2;return e.byteLength<g+2?{hasError:!0,message:"Invalid Trojan header: missing final CRLF"}:n[g]!==13||n[g+1]!==10?{hasError:!0,message:"Invalid Trojan header: invalid final CRLF"}:{hasError:!1,userPassword:s,addressRemote:l,addressType:u===3?2:u===4?3:u,portRemote:p,rawDataIndex:g+2,isUDP:i===3}}function Ve(e){if(!e)return{earlyData:null,error:null};try{let t=e.replace(/-/g,"+").replace(/_/g,"/"),n=atob(t),r=new ArrayBuffer(n.length),a=new Uint8Array(r);for(let s=0;s<n.length;s++)a[s]=n.charCodeAt(s);return{earlyData:r,error:null}}catch(t){return{earlyData:null,error:t}}}function W(e){try{e&&e.readyState===1&&e.close()}catch{}}async function Ke(e,t){let n=e.sni&&e.sni!==""?e.sni:e.address,r=Number(e.port),a;try{a=globalThis.connect?globalThis.connect({hostname:n,port:r,secureTransport:e.tls?"on":"off"}):void 0}catch(l){return t(`[VLESS/raw] connect error: ${l.message}`),null}if(!a)return t("[VLESS/raw] connect unavailable"),null;let s=a.readable.getReader(),o,i=new Promise(l=>{o=l});return(a.closed||Promise.resolve()).then(o,o),{readable:new ReadableStream({start(l){(async()=>{try{for(;;){let{done:c,value:d}=await s.read();if(c)break;d&&d.byteLength>0&&l.enqueue(d)}try{l.close()}catch{}}catch(c){try{l.error(c)}catch{}}})()},cancel(){try{s.cancel()}catch{}}}),writable:a.writable,closed:i,send:async l=>{let c=a.writable.getWriter();try{await c.write(l)}finally{try{c.releaseLock()}catch{}}}}}function Ur(e,t){let n=new Uint8Array(e.length+t.length);return n.set(e,0),n.set(t,e.length),n}function Or(e){for(let t=0;t+3<e.length;t++)if(e[t]===13&&e[t+1]===10&&e[t+2]===13&&e[t+3]===10)return t;return-1}function Dr(e){for(let t=0;t+1<e.length;t++)if(e[t]===13&&e[t+1]===10)return new TextDecoder().decode(e.slice(0,t));return""}async function Ye(e,t){let n=e.sni&&e.sni!==""?e.sni:e.address,r=Number(e.port),a;try{a=globalThis.connect?globalThis.connect({hostname:n,port:r,secureTransport:e.tls?"on":"off"}):void 0}catch(g){return t(`[VLESS/httpupgrade] connect error: ${g.message}`),null}if(!a)return t("[VLESS/httpupgrade] connect unavailable"),null;let o=`GET ${e.path&&e.path.startsWith("/")?e.path:`/${e.path||""}`} HTTP/1.1\r
Host: ${n}:${r}\r
Connection: Upgrade\r
Upgrade: websocket\r
\r
`,i=a.readable.getReader(),u,l=new Promise(g=>{u=g});(a.closed||Promise.resolve()).then(u,u);let c=new Uint8Array(0),d=new Uint8Array(0);try{await Promise.race([(async()=>{let g=a.writable.getWriter();try{await g.write(new TextEncoder().encode(o))}finally{try{g.releaseLock()}catch{}}for(;;){let{done:m,value:y}=await i.read();if(m)break;if(y&&y.byteLength>0){c=Ur(c,y);let f=Or(c);if(f>=0){d=c.slice(f+4);return}}}throw new Error("connection closed during handshake")})(),new Promise((g,m)=>setTimeout(()=>m(new Error("Handshake timeout")),1e4))])}catch(g){t(`[VLESS/httpupgrade] handshake failed: ${g.message}`);try{a.close()}catch{}return null}let h=Dr(c);if(!/^HTTP\/1\.1 101/.test(h)){t(`[VLESS/httpupgrade] upgrade rejected: ${h}`);try{a.close()}catch{}return null}return{readable:new ReadableStream({start(g){d.byteLength>0&&g.enqueue(d),(async()=>{try{for(;;){let{done:m,value:y}=await i.read();if(m)break;y&&y.byteLength>0&&g.enqueue(y)}try{g.close()}catch{}}catch(m){try{g.error(m)}catch{}}})()},cancel(){try{i.cancel()}catch{}}}),writable:a.writable,closed:l,send:async g=>{let m=a.writable.getWriter();try{await m.write(g)}finally{try{m.releaseLock()}catch{}}}}}var Rr=`PRI * HTTP/2.0\r
\r
SM\r
\r
`;var qt=new TextEncoder;function Cr(e,t){let n=qt.encode(e),r=qt.encode(t),a=new Uint8Array(2+n.length+1+r.length);return a[0]=0,a[1]=n.length,a.set(n,2),a[2+n.length]=r.length,a.set(r,3+n.length),a}function Mr(e){let t=new Uint8Array(0);for(let[n,r]of e)t=gt(t,Cr(n,r));return t}function et(e,t,n,r){let a=r.length,s=new Uint8Array(9+a);return s[0]=a>>16&255,s[1]=a>>8&255,s[2]=a&255,s[3]=e,s[4]=t,s[5]=n>>24&127,s[6]=n>>16&255,s[7]=n>>8&255,s[8]=n&255,s.set(r,9),s}function qe(e){let t=new Uint8Array(5+e.length);return t[0]=0,new DataView(t.buffer,t.byteOffset,5).setUint32(1,e.length,!1),t.set(e,5),t}function Je(e){let t=new Uint8Array(4);return new DataView(t.buffer).setUint32(0,e>>>0,!1),t}function gt(e,t){let n=new Uint8Array(e.length+t.length);return n.set(e,0),n.set(t,e.length),n}async function Xe(e,t){let n=[],r=0;for(;r<t;){let{done:s,value:o}=await e.read();if(s)return null;!o||o.byteLength===0||(n.push(o),r+=o.byteLength)}let a;if(n.length===1)a=n[0];else{a=gt(n[0],n[1]);for(let s=2;s<n.length;s++)a=gt(a,n[s])}return a.byteLength>t?{data:a.slice(0,t),extra:a.slice(t)}:{data:a,extra:null}}async function Ze(e,t){let n=e.sni&&e.sni!==""?e.sni:e.address,r=Number(e.port),a;try{a=globalThis.connect?globalThis.connect({hostname:n,port:r,secureTransport:e.tls?"on":"off"}):void 0}catch(m){return t(`[VLESS/grpc] connect error: ${m.message}`),null}if(!a)return t("[VLESS/grpc] connect unavailable"),null;let s=a.writable.getWriter();async function o(m){await s.write(m)}let i,u=new Promise(m=>{i=m});(a.closed||Promise.resolve()).then(i,i);try{await o(qt.encode(Rr)),await o(et(4,0,0,new Uint8Array(0)));let m=e.tls?"https":"http",y=(e.path||"").replace(/^\/+/,"").replace(/\/+$/,""),f=y?`/${y}/Tun`:"/Tun",b=Mr([[":method","POST"],[":scheme",m],[":path",f],[":authority",`${n}:${r}`],["content-type","application/grpc"],["te","trailers"],["user-agent","grpc-go/1.68.0"]]);await o(et(1,4,1,b))}catch(m){t(`[VLESS/grpc] handshake failed: ${m.message}`);try{a.close()}catch{}return null}let l=a.readable.getReader(),c={needLen:5,buf:new Uint8Array(0),msgLen:0,controller:null,extra:null};function d(m,y){let f=m;for(;f.byteLength>0;)if(c.needLen>0){let b=Math.min(c.needLen,f.byteLength);c.buf=gt(c.buf,f.slice(0,b)),f=f.slice(b),c.needLen-=b,c.needLen===0&&(c.buf.byteLength===5?(c.msgLen=new DataView(c.buf.buffer,c.buf.byteOffset,5).getUint32(1,!1),c.buf=new Uint8Array(0),c.needLen=c.msgLen,c.msgLen===0&&(c.needLen=5)):(c.buf=new Uint8Array(0),c.needLen=5))}else{let b=Math.min(c.msgLen,f.byteLength);if(c.buf=gt(c.buf,f.slice(0,b)),f=f.slice(b),c.msgLen-=b,c.msgLen===0){if(c.buf.byteLength>0)try{y.enqueue(c.buf)}catch{}c.buf=new Uint8Array(0),c.needLen=5}}}let h=new ReadableStream({start(m){c.controller=m,(async()=>{try{for(;;){let y;if(c.extra)y=c.extra,c.extra=null;else{let f=await Xe(l,9);if(!f)break;let b=f.data[0]<<16|f.data[1]<<8|f.data[2],w=f.data[3],T=f.data[4],k=(f.data[5]&127)<<24|f.data[6]<<16|f.data[7]<<8|f.data[8];if(b===0)y=new Uint8Array(0);else{let _=await Xe(l,b);if(!_)break;y=_.data,c.extra=_.extra}if(w===0&&k===1){d(y,m),await o(et(8,0,1,Je(y.byteLength))),await o(et(8,0,0,Je(y.byteLength)));continue}if(w===4){T&1||await o(et(4,1,0,new Uint8Array(0)));continue}if(w===6){T&1||await o(et(6,1,k,y));continue}if(w===7||w===3)break}}try{m.close()}catch{}}catch(y){t(`[VLESS/grpc] read loop error: ${y.message}`);try{m.error(y)}catch{}}finally{try{i()}catch{}}})()},cancel(){try{l.cancel()}catch{}}});function p(m){let y=[],f=0,b=!0;for(;f<m.byteLength;){let w=Math.min(16384,m.byteLength-f);y.push(et(0,0,1,m.slice(f,f+w))),f+=w,b=!1}return y}let g=new WritableStream({write(m){let y=m instanceof Uint8Array?m:new Uint8Array(m),f=qe(y),b=p(f);return(async()=>{for(let w of b)await o(w)})()},close(){try{a.close()}catch{}},abort(){try{a.close()}catch{}}});return{readable:h,writable:g,closed:u,send:async m=>{let y=qe(m);for(let f of p(y))await o(f)}}}var Pr=`PRI * HTTP/2.0\r
\r
SM\r
\r
`;var Jt=new TextEncoder;function Ir(e,t){let n=Jt.encode(e),r=Jt.encode(t),a=new Uint8Array(2+n.length+1+r.length);return a[0]=0,a[1]=n.length,a.set(n,2),a[2+n.length]=r.length,a.set(r,3+n.length),a}function Nr(e){let t=new Uint8Array(0);for(let[n,r]of e)t=Xt(t,Ir(n,r));return t}function nt(e,t,n,r){let a=r.length,s=new Uint8Array(9+a);return s[0]=a>>16&255,s[1]=a>>8&255,s[2]=a&255,s[3]=e,s[4]=t,s[5]=n>>24&127,s[6]=n>>16&255,s[7]=n>>8&255,s[8]=n&255,s.set(r,9),s}function Qe(e){let t=new Uint8Array(4);return new DataView(t.buffer).setUint32(0,e>>>0,!1),t}function Xt(e,t){let n=new Uint8Array(e.length+t.length);return n.set(e,0),n.set(t,e.length),n}async function tn(e,t){let n=[],r=0;for(;r<t;){let{done:s,value:o}=await e.read();if(s)return null;!o||o.byteLength===0||(n.push(o),r+=o.byteLength)}let a;if(n.length===1)a=n[0];else{a=Xt(n[0],n[1]);for(let s=2;s<n.length;s++)a=Xt(a,n[s])}return a.byteLength>t?{data:a.slice(0,t),extra:a.slice(t)}:{data:a,extra:null}}async function en(e,t){let n=e.sni&&e.sni!==""?e.sni:e.address,r=Number(e.port),a;try{a=globalThis.connect?globalThis.connect({hostname:n,port:r,secureTransport:e.tls?"on":"off"}):void 0}catch(p){return t(`[VLESS/h2] connect error: ${p.message}`),null}if(!a)return t("[VLESS/h2] connect unavailable"),null;let s=a.writable.getWriter();async function o(p){await s.write(p)}let i,u=new Promise(p=>{i=p});(a.closed||Promise.resolve()).then(i,i);try{await o(Jt.encode(Pr)),await o(nt(4,0,0,new Uint8Array(0)));let p=e.tls?"https":"http",g=e.path&&e.path.startsWith("/")?e.path:`/${e.path||""}`,m=Nr([[":method","POST"],[":scheme",p],[":path",g],[":authority",`${n}:${r}`],["content-length","0"],["user-agent","vless-h2/1.0.0"]]);await o(nt(1,4,1,m))}catch(p){t(`[VLESS/h2] handshake failed: ${p.message}`);try{a.close()}catch{}return null}let l=a.readable.getReader(),c=new ReadableStream({start(p){(async()=>{let g=null;try{for(;;){let m;if(g)m=g,g=null;else{let y=await tn(l,9);if(!y)break;let f=y.data[0]<<16|y.data[1]<<8|y.data[2],b=y.data[3],w=y.data[4],T=(y.data[5]&127)<<24|y.data[6]<<16|y.data[7]<<8|y.data[8];if(f===0)m=new Uint8Array(0);else{let k=await tn(l,f);if(!k)break;m=k.data,g=k.extra}if(b===0&&T===1){if(m.byteLength>0)try{p.enqueue(m)}catch{}await o(nt(8,0,1,Qe(m.byteLength))),await o(nt(8,0,0,Qe(m.byteLength)));continue}if(b===4){w&1||await o(nt(4,1,0,new Uint8Array(0)));continue}if(b===6){w&1||await o(nt(6,1,T,m));continue}if(b===7||b===3)break}}try{p.close()}catch{}}catch(m){t(`[VLESS/h2] read loop error: ${m.message}`);try{p.error(m)}catch{}}finally{try{i()}catch{}}})()},cancel(){try{l.cancel()}catch{}}});function d(p){let g=[],m=0;for(;m<p.byteLength;){let y=Math.min(16384,p.byteLength-m);g.push(nt(0,0,1,p.slice(m,m+y))),m+=y}return g}let h=new WritableStream({write(p){let g=p instanceof Uint8Array?p:new Uint8Array(p);return(async()=>{for(let m of d(g))await o(m)})()},close(){try{a.close()}catch{}},abort(){try{a.close()}catch{}}});return{readable:c,writable:h,closed:u,send:async p=>{for(let g of d(p))await o(g)}}}var Fr=1e4;async function it(e,t,n,r,a,s,o){let i=e.transport||"ws";if(!Se.includes(i))return o(`[VLESS] unsupported transport: ${i}`),null;let u=null;try{i==="ws"?u=await zr(e,o):i==="raw"?u=await Ke(e,o):i==="httpupgrade"?u=await Ye(e,o):i==="grpc"?u=await Ze(e,o):i==="h2"&&(u=await en(e,o))}catch(h){return o(`[VLESS/${i}] connect failed: ${h.message}`),null}if(!u)return null;let l=ze(t,n,r,a,e.uuid),c=s instanceof Uint8Array?s:new Uint8Array(s||0),d=new Uint8Array(l.length+c.length);d.set(l,0),d.set(c,l.length);try{await u.send(d)}catch(h){o(`[VLESS/${i}] send header failed: ${h.message}`);try{u.close&&await u.close()}catch{}return null}return{readable:u.readable,writable:u.writable,closed:u.closed}}async function zr(e,t){let n=e.tls?"wss":"ws",r=e.path&&e.path.startsWith("/")?e.path:`/${e.path||""}`,a=e.sni&&e.sni!==""?e.sni:e.address,s=`${n}://${a}:${e.port}${r}`,o;try{o=new WebSocket(s),"binaryType"in o&&(o.binaryType="arraybuffer")}catch(h){return t(`[VLESS/ws] create ws failed: ${h.message}`),null}let i,u=new Promise(h=>{i=h});try{await new Promise((h,p)=>{let g=setTimeout(()=>p(new Error("Connection timeout")),Fr);o.addEventListener("open",()=>{clearTimeout(g),h()}),o.addEventListener("close",m=>{clearTimeout(g),p(new Error(`closed ${m.code}`))}),o.addEventListener("error",()=>{clearTimeout(g),p(new Error("ws error"))})})}catch(h){t(`[VLESS/ws] connect failed: ${h.message}`);try{o.close()}catch{}return i(),null}o.addEventListener("close",()=>i()),o.addEventListener("error",()=>{});let l=new WritableStream({write(h){o.readyState===1&&o.send(h)},close(){W(o)},abort(){W(o)}}),c=!1;return{readable:new ReadableStream({start(h){o.addEventListener("message",p=>{let g;try{p.data instanceof ArrayBuffer?g=new Uint8Array(p.data):ArrayBuffer.isView(p.data)?g=new Uint8Array(p.data.buffer,p.data.byteOffset,p.data.byteLength):typeof p.data=="string"?g=new TextEncoder().encode(p.data):g=null}catch{g=null}if(g){if(!c&&(c=!0,g.length>=2&&g[0]===0)){let m=g[1];if(g.length>2+m)g=g.slice(2+m);else return}if(g.length>0)try{h.enqueue(g)}catch{}}}),o.addEventListener("close",()=>{try{h.close()}catch{}}),o.addEventListener("error",p=>{try{h.error(p)}catch{}})},cancel(){W(o)}}),writable:l,closed:u,send:async h=>{if(o.readyState!==1)throw new Error(`ws not open (state=${o.readyState})`);o.send(h)}}}async function yt(e,t,n){for(;t.buf.length<n;){let{done:a,value:s}=await e.read();if(a)return null;if(!s||s.byteLength===0)continue;let o=new Uint8Array(t.buf.length+s.byteLength);o.set(t.buf,0),o.set(s,t.buf.length),t.buf=o}let r=t.buf.slice(0,n);return t.buf=t.buf.slice(n),r}async function nn(e,t,n,r,a,s){let{username:o,password:i,hostname:u,port:l}=a,c=s({hostname:u,port:l}),d=c.writable.getWriter(),h=c.readable.getReader(),p=new TextEncoder,g={buf:new Uint8Array(0)};try{await d.write(new Uint8Array([5,2,0,2]));let m=await yt(h,g,2);if(!m||m[0]!==5){r("socks version error");return}if(m[1]===255){r("no acceptable methods");return}if(m[1]===2){if(!o||!i){r("socks server requires auth but no credentials");return}let k=new Uint8Array([1,o.length,...p.encode(o),i.length,...p.encode(i)]);if(await d.write(k),m=await yt(h,g,2),!m||m[0]!==1||m[1]!==0){r("socks auth failed");return}}let y;switch(e){case 1:y=new Uint8Array([1,...t.split(".").map(Number)]);break;case 2:y=new Uint8Array([3,t.length,...p.encode(t)]);break;case 3:y=new Uint8Array([4,...Kt(t).split(":").flatMap(k=>[parseInt(k.slice(0,2),16),parseInt(k.slice(2),16)])]);break;default:r(`invalid addressType ${e}`);return}let f=new Uint8Array([5,1,0,...y,n>>8,n&255]);await d.write(f);let b=await yt(h,g,4);if(!b||b[0]!==5){r("socks version error");return}if(b[1]!==0){r(`socks connect failed rep=${b[1]}`);return}let w=0;switch(b[3]){case 1:w=6;break;case 3:w=3;break;case 4:w=18;break;default:r(`socks invalid ATYP ${b[3]}`);return}if(b[3]===3){let k=await yt(h,g,1);if(!k)return;w+=k[0]}if(!await yt(h,g,w))return;if(d.releaseLock(),g.buf.length>0){let k=g.buf.slice();return{readable:new ReadableStream({pull(U){if(k.length>0){let L=k;k=new Uint8Array(0),U.enqueue(L);return}return h.read().then(({done:L,value:A})=>{L?U.close():A&&A.byteLength>0&&U.enqueue(A)})},cancel(){try{h.cancel()}catch{}}}),writable:c.writable,closed:c.closed||Promise.resolve()}}return h.releaseLock(),c}catch(m){r(`socks5 error: ${m.message}`);try{d.releaseLock()}catch{}try{h.releaseLock()}catch{}try{c.close()}catch{}return}}function rn(e,t={}){let n=String(e||"").trim().replace(/^socks5?:\/\//i,""),[r,a]=n.split("@").reverse(),s,o,i,u;if(a){let c=a.split(":");if(c.length!==2)throw new Error("Invalid SOCKS address format");[s,o]=c}let l=r.split(":");if(u=Number(l[l.length-1]),isNaN(u))if(t&&t.port!==void 0&&t.port!==null&&t.port!=="")u=Number(t.port),i=r;else throw new Error("Invalid SOCKS address format");else i=l.slice(0,-1).join(":");if(isNaN(u)||!i)throw new Error("Invalid SOCKS address format");return t&&t.username!==void 0&&t.username!==null&&t.username!==""&&(s=t.username),t&&t.password!==void 0&&t.password!==null&&t.password!==""&&(o=t.password),{username:s,password:o,hostname:i,port:u}}async function an(e,t,n,r,a,s,o=new Uint8Array(0)){let{username:i,password:u,hostname:l,port:c}=a,d=s({hostname:l,port:c}),h=d.writable.getWriter(),p=d.readable.getReader();try{let g=i&&u?`Proxy-Authorization: Basic ${btoa(`${i}:${u}`)}\r
`:"",m=`CONNECT ${t}:${n} HTTP/1.1\r
Host: ${t}:${n}\r
${g}User-Agent: Mozilla/5.0\r
Connection: keep-alive\r
\r
`;await h.write(new TextEncoder().encode(m));let y=new Uint8Array(0),f=-1,b=0;for(;f===-1&&b<8192;){let{done:_,value:U}=await p.read();if(_)throw new Error("Connection closed before HTTP response");let L=new Uint8Array(y.length+U.length);L.set(y,0),L.set(U,y.length),y=L,b=y.length;for(let A=0;A<y.length-3;A++)if(y[A]===13&&y[A+1]===10&&y[A+2]===13&&y[A+3]===10){f=A+4;break}}if(f===-1)throw new Error("Invalid HTTP response");let T=new TextDecoder().decode(y.slice(0,f)).split(`\r
`)[0].match(/HTTP\/\d\.\d\s+(\d+)/);if(!T)throw new Error("Invalid HTTP response format");let k=parseInt(T[1]);if(k<200||k>=300)throw new Error(`HTTP CONNECT failed: HTTP ${k}`);return o.length>0&&await h.write(o),h.releaseLock(),p.releaseLock(),d}catch(g){r(`http connect error: ${g.message}`);try{h.releaseLock()}catch{}try{p.releaseLock()}catch{}try{d.close()}catch{}return}}function sn(e,t={}){let[n,r]=String(e||"").trim().split("@").reverse(),a,s,o,i;if(r){let l=r.split(":");if(l.length!==2)throw new Error("Invalid HTTP address format");[a,s]=l}let u=n.split(":");if(i=Number(u[u.length-1]),isNaN(i))if(t&&t.port!==void 0&&t.port!==null&&t.port!=="")i=Number(t.port),o=n;else throw new Error("Invalid HTTP address format");else o=u.slice(0,-1).join(":");if(isNaN(i)||!o)throw new Error("Invalid HTTP address format");return t&&t.username!==void 0&&t.username!==null&&t.username!==""&&(a=t.username),t&&t.password!==void 0&&t.password!==null&&t.password!==""&&(s=t.password),{username:a,password:s,hostname:o,port:i}}var Br=3e5,on=new Map;async function bt(e,t,n="A"){let r=`${n}:${e}`,a=on.get(r);if(a&&Date.now()-a.ts<Br)return a.ip;let s=["https://8.8.8.8/resolve","https://8.8.4.4/resolve","https://doh.pub/resolve","https://dns.alidns.com/resolve"],o=n==="AAAA"?28:1,i=n==="AAAA"?/^[0-9a-fA-F:]+$/:/^\d{1,3}(\.\d{1,3}){3}$/,u=null;for(let l of s){let c=new AbortController,d=setTimeout(()=>c.abort(),2500);try{let h=`${l}?name=${encodeURIComponent(e)}&type=${n}`,p=await fetch(h,{headers:{accept:"application/dns-json"},signal:c.signal});if(p.ok){let g=await p.json(),y=(Array.isArray(g.Answer)?g.Answer:[]).find(f=>f.type===o&&i.test(f.data))?.data;if(y){clearTimeout(d),u=y;break}}}catch{}finally{clearTimeout(d)}}return u?on.set(r,{ip:u,ts:Date.now()}):t(`doh resolve failed: ${e} (${n})`),u}var Gr=["173.245.48.0/20","103.21.244.0/22","103.22.200.0/22","103.31.4.0/22","141.101.64.0/18","108.162.192.0/18","190.93.240.0/20","188.114.96.0/20","197.234.240.0/22","198.41.128.0/17","162.158.0.0/15","104.16.0.0/13","104.24.0.0/14","172.64.0.0/13","131.0.72.0/22","1.0.0.0/24","1.1.1.0/24"].map(e=>{let[t,n]=e.split("/"),r=Number(n),a=r===0?0:4294967295<<32-r>>>0,s=t.split(".");return[(+s[0]<<24)+(+s[1]<<16)+(+s[2]<<8)+ +s[3]>>>0&a,a]});function jr(e){let t=e.split(".");return(+t[0]<<24)+(+t[1]<<16)+(+t[2]<<8)+ +t[3]>>>0}function wt(e){if(!/^\d{1,3}(\.\d{1,3}){3}$/.test(e))return!1;let t=jr(e);return Gr.some(([n,r])=>(t&r)===n)}var Wr=[".cloudflare.com",".cloudflare.net",".jsdelivr.net",".workers.dev",".pages.dev",".trycloudflare.com",".cf-ipfs.com",".cloudflareinsights.com"];function Qt(e){let t=e.toLowerCase();return Wr.some(n=>t===n.slice(1)||t.endsWith(n))}var cn=6e4,K={state:"unknown",downAt:0},J=new WeakMap;function rt(e){K.state!=="down"&&(K.state="down",K.downAt=Date.now(),e("proxyip marked down (no response), degrade to direct for 60s"))}function Vr(e){K.state==="down"&&Date.now()-K.downAt>=cn&&(K.state="unknown",e("proxyip health reset to unknown, will retry proxyip"))}function un(){return K.state==="down"&&Date.now()-K.downAt<cn}function te(e){if(!e.proxyipOutbound)return null;let t=Z(e,e.proxyipOutbound);return!t||typeof t=="string"||t.type!==Gt&&t.type!==zt&&t.type!==Bt?null:t}async function dn(e,t,n,r,a){let s=te(e);if(!s)return null;let o=/^\d{1,3}(\.\d{1,3}){3}$/.test(t)?1:t.includes(":")?3:2;a(`direct ${t}:${n} -> retry via outbound ${s.name}`);let i=await X({config:e,outbound:s,addressType:o,addressRemote:t,portRemote:n,rawClientData:r||new Uint8Array(0),log:a,isUDP:!1});return i?(J.set(i,{usedProxyIp:!0}),i):null}async function pn(e,t,n,r,a){if(te(e)){let c=await dn(e,t,n,r,a);return c||rt(a),c}let o=e.proxyipHost,i=Number(e.proxyipPort||443);if(!o)return null;a(`direct ${t}:${n} -> retry via proxyip ${o}:${i}`);let u=await lt(o,i,a);if(!u)return rt(a),null;let l=await ee(u,r,a);return l?(J.set(l,{usedProxyIp:!0}),l):(rt(a),null)}async function Zt(e,t,n,r,a,s,o){let i=await Kr(t,n,r,a,o);if(!i)return o(`connect unavailable (${t}:${n})`),null;let u=await ee(i,s,o);return u&&J.set(u,{usedProxyIp:!1}),u}async function lt(e,t,n){let r;try{r=globalThis.connect?globalThis.connect({hostname:e,port:t}):void 0,r&&typeof r.then=="function"&&(r=await r)}catch(a){return n(`direct connect error: ${a.message}`),null}return r||null}async function Kr(e,t,n,r,a){if(!n&&!r){a(`direct ${e}:${t} -> native dns ${e}:${t}`);let s=await lt(e,t,a);if(s)return s;let o=await bt(e,a);if(o&&(a(`direct ${e}:${t} -> doh fallback ${o}:${t}`),s=await lt(o,t,a),s))return s;let i=await bt(e,a,"AAAA");if(i){let u=`[${i}]`;if(a(`direct ${e}:${t} -> doh aaaa fallback ${u}:${t}`),s=await lt(u,t,a),s)return s}return null}return lt(e,t,a)}async function ee(e,t,n){if(t&&t.length>0){let r=e.writable.getWriter();try{await r.write(t)}catch(a){n(`direct initial write error: ${a.message}`)}finally{try{r.releaseLock()}catch{}}}return e}async function ln(e,t,n,r,a){let s=(e.proxyipHost||e.proxyipOutbound)&&!e.proxyipDisabled,o=/^\d{1,3}(\.\d{1,3}){3}$/.test(t)||t.includes(":");Vr(a);let i=s&&K.state==="down",u=!o&&Qt(t),l=o&&!t.includes(":")&&wt(t),c=!1;if(s&&!i&&!o&&!u){let d=await bt(t,a);d&&wt(d)&&(c=!0)}if(s&&!i&&(u||l||c)){let d=te(e);if(d){let y=await dn(e,t,n,r,a);return y||(rt(a),a(`proxyip outbound ${d.name} failed; degrade to direct ${t}:${n}`),Zt(e,t,n,o,u||c,r,a))}let h=e.proxyipHost,p=Number(e.proxyipPort||443),g=await lt(h,p,a);if(!g)return rt(a),a(`proxyip ${h}:${p} connect failed; degrade to direct ${t}:${n}`),Zt(e,t,n,o,u||c,r,a);let m=await ee(g,r,a);return m&&J.set(m,{usedProxyIp:!0}),m}return Zt(e,t,n,o,u||c,r,a)}async function X(e){let{config:t,outbound:n,addressType:r,addressRemote:a,portRemote:s,rawClientData:o,log:i,isUDP:u}=e,l=n;if(!l||l===j)return ln(t,a,s,o,i);if(l===st)return i("rejected by routing rule"),null;switch(l.type){case j:return ln(t,a,s,o,i);case zt:{let c;try{c=rn(l.address,{username:l.username,password:l.password,port:l.port})}catch(h){return i(`bad socks5 address: ${h.message}`),null}let d=await nn(r,a,s,i,c,globalThis.connect);if(!d)return null;if(o&&o.length>0){let h=d.writable.getWriter();try{await h.write(o)}catch(p){i(`socks5 write error: ${p.message}`)}finally{try{h.releaseLock()}catch{}}}return d}case Bt:{let c;try{c=sn(l.address,{username:l.username,password:l.password,port:l.port})}catch(h){return i(`bad http address: ${h.message}`),null}return await an(r,a,s,i,c,globalThis.connect,o||new Uint8Array(0))}case Gt:return it({address:l.address,port:Number(l.port),uuid:l.uuid,path:l.path,tls:!!l.tls,sni:l.sni||"",transport:l.transport},u?2:1,r,a,s,o||new Uint8Array(0),i);default:return i(`unknown outbound type: ${l.type}`),null}}function Z(e,t){return!t||t===j?j:t===st?st:e.outboundByName[t]||j}var Yr=3600*1e3,ne=new Map;async function re(e,t,n){let r=`${t}:${n}`,a=ne.get(r);if(a&&Date.now()-a.ts<Yr)return a.data;let s=null;try{let o=t==="geosite"?Ae:_e,i=await e.GEO_KV.get(o+n);if(i){let u=JSON.parse(i);Array.isArray(u)&&(s=u)}}catch{}return s||(s=qr(t,n)),ne.set(r,{data:s,ts:Date.now()}),s}function qr(e,t){if(e==="geosite")switch(t){case"cn":return Le;case"speedtest":return $e;case"google":return Ue;default:return[]}return[]}function fn(){ne.clear()}function Jr(e){if(!e)return null;let t=String(e).trim();if(!t)return null;let n=t.match(/^geosite:(.+)$/i);if(n){let l=n[1].split(",").map(c=>c.trim()).filter(Boolean);return l.length===0?null:{type:"geosite",categories:l}}let r=t.match(/^geoip:(.+)$/i);if(r){let l=r[1].split(",").map(c=>c.trim()).filter(Boolean);return l.length===0?null:{type:"geoip",categories:l}}let a=t.match(/^domain:(.+)$/i);if(a)return{type:"domain",value:a[1].trim()};let s=t.match(/^full:(.+)$/i);if(s)return{type:"full",value:s[1].trim()};let o=t.match(/^keyword:(.+)$/i);if(o)return{type:"keyword",value:o[1].trim()};let i=t.match(/^ip-cidr:(.+)$/i);if(i)return{type:"ip-cidr",value:i[1].trim()};let u=t.match(/^regexp:(.+)$/i);return u?{type:"regexp",value:u[1].trim()}:{type:"domain",value:t}}function hn(e){let t=e.split(".");if(t.length!==4)return null;let n=0;for(let r of t){let a=Number(r);if(isNaN(a)||a<0||a>255)return null;n=n<<8|a}return n>>>0}function mn(e){let t=String(e).replace(/^\[|\]$/g,""),n=t.indexOf("::"),r,a;if(n>=0?(r=n===0?[]:t.slice(0,n).split(":"),a=n===t.length-2?[]:t.slice(n+2).split(":")):(r=t.split(":"),a=[]),r.length+a.length>8)return null;let s=8-r.length-a.length,o=[...r,...Array(s).fill("0"),...a],i=0n;for(let u of o){if(!u)return null;let l=parseInt(u,16);if(isNaN(l))return null;i=i<<16n|BigInt(l)}return i}function gn(e,t){let n=t.indexOf("/"),r=n>=0?t.slice(0,n):t,a=e.includes(":")?128:32,s=n>=0?Number(t.slice(n+1)):a;if(e.includes(":")){let l=mn(e),c=mn(r);if(l===null||c===null||isNaN(s)||s<0||s>128)return!1;let d=s===0?0n:(1n<<128n)-1n^(1n<<BigInt(128-s))-1n;return(l&d)===(c&d)}let o=hn(e);if(o===null)return!1;let i=hn(r);if(i===null)return!1;let u=s<=0?0:4294967295<<32-s>>>0;return(o&u)===(i&u)}function yn(e,t){let n=e.toLowerCase(),r=t.toLowerCase();return n===r?!0:n.endsWith("."+r)||n.endsWith(r)}var bn=new Map;function Xr(e){let t=bn.get(e);if(!t){try{t=new RegExp(e)}catch{t=null}bn.set(e,t)}return t}async function Zr(e,t,n,r){switch(e.type){case"domain":return n?!1:yn(t,e.value);case"full":return n?!1:t.toLowerCase()===e.value.toLowerCase();case"keyword":return n?!1:t.toLowerCase().includes(e.value.toLowerCase());case"regexp":{if(n)return!1;let a=Xr(e.value);return a?a.test(t):!1}case"ip-cidr":return n?gn(t,e.value):!1;case"geosite":{if(n)return!1;for(let a of e.categories){let s=await re(r,"geosite",a);for(let o of s)if(yn(t,o))return!0}return!1}case"geoip":{if(!n)return!1;for(let a of e.categories){let s=await re(r,"geoip",a);for(let o of s)if(gn(t,o))return!0}return!1}default:return!1}}var Qr=6e4,ta=1e4,Dt=new Map;async function vt(e,t,n){let r=`${t}:${n.toLowerCase()}`,a=Dt.get(r);if(a&&Date.now()-a.ts<Qr)return{outbound:a.outbound,rule:a.rule};let s=t===1||t===3,o=e.defaultOutbound||"direct",i=null;for(let u of e.routingRules){let l=Jr(u.rule);if(!l)continue;if(await Zr(l,n,s,e.env)){o=u.outbound||"direct",i=u;break}}return Dt.size>=ta&&Dt.clear(),Dt.set(r,{outbound:o,rule:i,ts:Date.now()}),{outbound:o,rule:i}}var wn=new Uint8Array([0,0]),ae=32*1024,ea=15,na=2*1024*1024;async function at(e,t,n,r){let a;try{a=await r.read()}catch(f){n(`read first packet error: ${f.message}`);try{await r.close()}catch{}return}if(!a){try{await r.close()}catch{}return}let s,o=null,i="vless",u=e._inboundScope||null,l=u&&!u.all?u.vless:e.uuidSet,c=u&&!u.all?u.trojan:e.passwordSet;if(je(a)){if(s=await We(a,c),s.hasError){n(`trojan header error: ${s.message}`);try{await r.close()}catch{}return}i="trojan",o=e.trojanIndex[s.userPassword]||null}else{if(s=Fe(a,l),s.hasError){n(`vless header error: ${s.message}`);try{await r.close()}catch{}return}try{await r.write(wn)}catch{}o=e.vlessIndex[s.userUuid]||null}if(o){let f=Math.floor(Date.now()/1e3);if(o.expire_at>0&&o.expire_at<f){n(`${i} user '${o.remark||o.uuid||o.password}' expired`);try{await r.close()}catch{}return}if(o.traffic_limit>0&&Number(o.up)+Number(o.down)>=Number(o.traffic_limit)){n(`${i} user '${o.remark||o.uuid||o.password}' traffic limit reached`);try{await r.close()}catch{}return}}let{addressType:d,addressRemote:h,portRemote:p,isUDP:g}=s,m=(a instanceof Uint8Array?a:new Uint8Array(a)).subarray(s.rawDataIndex),y;try{y=await vt(e,d,h)}catch(f){n(`route error: ${f.message}`);try{await r.close()}catch{}return}g?await aa(r,e,d,h,p,m,o,i,y,n):await ra(r,e,d,h,p,m,o,i,y,n)}async function ra(e,t,n,r,a,s,o,i,u,l){let c=Z(t,u.outbound),d=s&&s.length>0?s:new Uint8Array(0),h=[c];c!=="direct"&&c!=="reject"&&h.push("direct");let p=null,g=null;for(let v of h){try{p=await X({config:t,outbound:v,addressType:n,addressRemote:r,portRemote:a,rawClientData:d,log:l})}catch(E){g=E,p=null}if(p)break}if(!p){l(`tcp connect failed: ${g?g.message:"no outbound available"}`);try{await e.close()}catch{}return}let m=0,y=0,f=!1,b=15e3,w=Date.now(),T=setInterval(()=>{f||Date.now()-w>=b&&(w=Date.now(),e.write(wn).catch(()=>{}))},5e3),k=5e3,_=J.get(p)||null,U=!1,L=p.writable.getWriter(),A=async()=>{if(U)return null;U=!0;let v=(!!t.proxyipHost||!!t.proxyipOutbound)&&!t.proxyipDisabled;try{await p.close()}catch{}if(_&&_.usedProxyIp){rt(l),l(`proxyip ${r}:${a} no first packet, degrade to direct retry`);try{return await X({config:t,outbound:"direct",addressType:n,addressRemote:r,portRemote:a,rawClientData:d,log:l})||null}catch(E){return l(`direct retry error: ${E.message}`),null}}if(!v||a!==443)return null;l(`direct ${r}:${a} no first packet, retry via proxyip`);try{return await pn(t,r,a,d,l)}catch(E){return l(`proxyip retry error: ${E.message}`),null}},M=(async()=>{try{for(;;){let v=await e.read();if(v==null)break;v.byteLength!==0&&(m+=v.byteLength,w=Date.now(),await L.write(v))}}catch(v){l(`upstream read error: ${v.message}`)}})();try{let v=p.readable.getReader(),E=!1;for(;;){if(!E&&!U){let O=null,R=v.read().then(D=>({tag:"read",...D})),q=new Promise(D=>{O=setTimeout(()=>D({tag:"timeout"}),k)}),P=await Promise.race([R,q]);if(clearTimeout(O),P.tag==="timeout"){let D=await A();if(!D)break;try{L.releaseLock()}catch{}p=D,L=p.writable.getWriter(),_=J.get(p)||null,v=p.readable.getReader(),E=!1;continue}if(P.done)break;P.value&&P.value.byteLength>0&&(E=!0,y+=P.value.byteLength,w=Date.now(),await e.write(P.value));continue}let $=null,C=0,I=async()=>{C>0&&(await e.write($.subarray(0,C)),$=null,C=0)},V=O=>{let R=C+O.byteLength;if(!$)$=new Uint8Array(Math.max(R,4096));else if(R>$.length){let q=new Uint8Array(Math.max($.length*2,R));q.set($.subarray(0,C),0),$=q}$.set(O,C),C=R},G=0,tt=!1;for(;;)if(G>=na&&(G=0,await new Promise(O=>setTimeout(O,0))),C>0){let O=v.read().then(H=>({tag:"read",done:H.done,value:H.value})),R=null,q=new Promise(H=>{R=setTimeout(()=>H({tag:"timeout"}),ea)}),P=await Promise.race([O,q]);if(clearTimeout(R),P.tag==="timeout"){await I();let H=await O;if(H.done){tt=!0;break}let F=H.value;F&&F.byteLength>0&&(E=!0,y+=F.byteLength,G+=F.byteLength,w=Date.now(),await e.write(F));continue}if(P.done){await I(),tt=!0;break}let D=P.value;if(!D||D.byteLength===0)continue;E=!0,y+=D.byteLength,G+=D.byteLength,w=Date.now(),C+D.byteLength<=ae?(V(D),C>=ae&&await I()):(await I(),await e.write(D))}else{let{done:O,value:R}=await v.read();if(O){tt=!0;break}if(!R||R.byteLength===0)continue;E=!0,y+=R.byteLength,G+=R.byteLength,w=Date.now(),R.byteLength>=ae?await e.write(R):V(R)}if(tt)break}}catch(v){if(!U&&y===0){l(`tcp remote read error before first packet: ${v.message||v}`);let E=await A();if(E){try{L.releaseLock()}catch{}p=E,L=p.writable.getWriter(),_=J.get(p)||null,U=!0;let $=p.readable.getReader();try{for(;;){let{done:C,value:I}=await $.read();if(C)break;I&&I.byteLength>0&&(y+=I.byteLength,w=Date.now(),await e.write(I))}}catch(C){l(`fallback remote read error: ${C.message||C}`)}}}else l(`tcp remote read error: ${v.message||v}`)}f=!0,clearInterval(T);try{L.releaseLock()}catch{}try{await p.writable.close()}catch{}try{await e.close()}catch{}await M.catch(()=>{}),Tn(t,o,i,m,y,l)}async function aa(e,t,n,r,a,s,o,i,u,l){let c=null,d=(t.udpOutbound||"").trim();if(d){let b=t.outboundByName[d];if(b&&b.type==="vless")c=b;else{l(`udp outbound '${d}' not found or not vless (only vless supports udp)`);try{await e.close()}catch{}return}}else{if(u.outbound&&u.outbound!=="direct"&&u.outbound!=="reject"){let b=Z(t,u.outbound);b!=="direct"&&b!=="reject"&&b.type==="vless"&&(c=b)}c||(c=t.outbounds.find(b=>b.type==="vless"))}if(!c){l("udp requires a vless outbound, none configured");try{await e.close()}catch{}return}let h=s&&s.length>0?s:new Uint8Array([0,0]),p=await it({address:c.address,port:Number(c.port),uuid:c.uuid,path:c.path,tls:!!c.tls,sni:c.sni||"",transport:c.transport||"ws"},2,n,r,a,h,l);if(!p){l("udp vless outbound connect failed");try{await e.close()}catch{}return}let g=0,m=0,y=p.writable.getWriter(),f=(async()=>{try{for(;;){let b=await e.read();if(b==null)break;b.byteLength!==0&&(g+=b.byteLength,await y.write(b))}}catch(b){l(`udp upstream read error: ${b.message}`)}})();try{let b=p.readable.getReader();for(;;){let{done:w,value:T}=await b.read();if(w)break;T&&T.byteLength>0&&(m+=T.byteLength,await e.write(T))}}catch(b){l(`udp read error: ${b.message}`)}try{y.releaseLock()}catch{}try{await p.writable.close()}catch{}try{await e.close()}catch{}await f.catch(()=>{}),Tn(t,o,i,g,m,l)}var sa=2e3,oa=32,Q=new Map,se=null;async function vn(e){if(!Q.size)return;let t=[...Q.entries()];Q.clear();try{let n=t.map(([r,a])=>{let s=r.lastIndexOf(":"),o=r.slice(0,s),i=Number(r.slice(s+1));return e.prepare(`UPDATE ${o} SET up = up + ?, down = down + ? WHERE id = ?`).bind(a.up,a.down,i)});await e.batch(n)}catch{for(let[r,a]of t){let s=Q.get(r);s?(s.up+=a.up,s.down+=a.down):Q.set(r,a)}xn(e)}}function xn(e){se||(se=setTimeout(()=>{se=null,vn(e)},sa))}async function Tn(e,t,n,r,a,s){if(!t)return;let i=`${n==="vless"?"vless_users":"trojan_users"}:${t.id}`,u=Q.get(i);if(u?(u.up+=r,u.down+=a):Q.set(i,{up:r,down:a}),xn(e.env.DB),Q.size>=oa)try{await vn(e.env.DB)}catch(l){s(`record traffic error: ${l.message}`)}}var ia=Promise.resolve();function la(e){return e instanceof ArrayBuffer?new Uint8Array(e):ArrayBuffer.isView(e)?new Uint8Array(e.buffer,e.byteOffset,e.byteLength):typeof e=="string"?new TextEncoder().encode(e):Object.prototype.toString.call(e)==="[object ArrayBuffer]"?new Uint8Array(e):null}function oe(e,t){let n=null,r=e.url.indexOf("?");if(r>=0){let o=e.url.slice(r+1).match(/(?:^|&)ed=([^&#]*)/);if(o)try{n=decodeURIComponent(o[1])}catch{n=o[1]}}let a=n==="2560",s=e.headers.get("sec-websocket-protocol")||"";if(s){s.startsWith("base64,")&&(s=s.slice(7));let{earlyData:o,error:i}=Ve(s);if(i)return t(`early data decode error: ${i.message||i}`),null;if(o&&o.byteLength>0)return a||t(`early data injected: ${o.byteLength} B (ed=${n||"n/a"})`),new Uint8Array(o)}return n&&!a&&t(`ed=${n} declared but no sec-websocket-protocol payload`),null}async function kn(e,t,n){let r=e.headers.get("Upgrade");if(!r||r.toLowerCase()!=="websocket")return new Response("Expected WebSocket",{status:400});let[a,s]=Object.values(new WebSocketPair);s.accept(),s.binaryType="arraybuffer";let o=(...u)=>console.log("[ws]",...u),i=oe(e,o);return at(t,n,o,ie(s,o,i)).catch(u=>{o(`ws handler error: ${u.message||u}`),W(s)}),new Response(null,{status:101,webSocket:a})}function ie(e,t,n=null){let r=[],a=[],s=!1;n&&n.byteLength>0?r.push(n):setTimeout(()=>{!s&&r.length===0&&a.length>0&&(t("first packet timeout: no ws message within 6s"),W(e))},6e3);let o=async l=>{let c=l.data;typeof Blob<"u"&&c instanceof Blob&&(c=await c.arrayBuffer());let d=la(c);if(!d||d.byteLength===0){t(`message dropped: type=${Object.prototype.toString.call(l.data)} len=${c&&c.byteLength!=null?c.byteLength:c&&c.length!=null?c.length:"n/a"}`);return}let h=a.shift();h?h(d):r.push(d)},i=()=>{if(!s)for(s=!0;a.length;)a.shift()(null)},u=()=>i();return e.addEventListener("message",o),e.addEventListener("close",i),e.addEventListener("error",u),{read(){return r.length?Promise.resolve(r.shift()):s?Promise.resolve(null):new Promise(l=>a.push(l))},write(l){if(e.readyState===1)try{e.send(l)}catch{}return ia},close(){W(e)},feed(l){if(!l||l.byteLength===0)return;let c=a.shift();c?c(l):r.push(l)},signalClose(){i()}}}import{connect as ca}from"cloudflare:sockets";globalThis.connect=ca;var ua=new TextEncoder,le=class{constructor(t,n){this.state=t,this.env=n,this.io=null}async fetch(t){let n=t.headers.get("Upgrade");if(!n||n.toLowerCase()!=="websocket")return new Response("Expected WebSocket",{status:400});let r=(...c)=>console.log("[ws-do]",...c),a=await mt(t,this.env),s=new URL(t.url).pathname,o=a.inboundPathMap.get(s);if(!o||o.length===0)return new Response("Not Found",{status:404});a._inboundScope=$t(o);let[i,u]=Object.values(new WebSocketPair);this.state.acceptWebSocket(u);let l=oe(t,r);return this.io=ie(u,r,l),at(a,this.env,r,this.io).catch(c=>{r(`ws session error: ${c.message||c}`);try{let d=Date.now();if(d-(this._lastDiagTs||0)>=6e4){this._lastDiagTs=d;let h=String(c&&c.stack||c).slice(0,400);this.env.DB.prepare("INSERT INTO diag_log (ts, tag, result) VALUES (?, ?, ?)").bind(d,"session_error",h).run()}}catch{}W(u)}),new Response(null,{status:101,webSocket:i})}async webSocketMessage(t,n){if(!this.io)return;let r=null;n instanceof ArrayBuffer?r=new Uint8Array(n):ArrayBuffer.isView(n)?r=new Uint8Array(n.buffer,n.byteOffset,n.byteLength):typeof n=="string"&&(r=ua.encode(n)),!(!r||r.byteLength===0)&&this.io.feed(r)}async webSocketClose(t,n,r,a){n!==1e3&&n!==1001&&console.log(`[ws-do] webSocketClose code=${n} wasClean=${a}`),this.io&&this.io.signalClose()}async webSocketError(t,n){let r=Date.now();r-(this._lastWSErrTs||0)>=6e4&&(this._lastWSErrTs=r,console.log(`[ws-do] webSocketError ${n&&n.message||n}`)),this.io&&this.io.signalClose()}};function ce(e,t){let n=new Uint8Array(e.length+t.length);return n.set(e,0),n.set(t,e.length),n}function da(e){let t=new Uint8Array(5);return t[0]=0,t[1]=e>>>24&255,t[2]=e>>>16&255,t[3]=e>>>8&255,t[4]=e&255,t}function pa(e){return ce(da(e.byteLength),e)}async function En(e,t,n){let r=(...l)=>console.log("[h2-in]",...l);if(!e.body)return new Response("Bad Request",{status:400});let a=e.body.getReader(),{readable:s,writable:o}=new TransformStream,i=o.getWriter();return at(t,n,r,{read:async()=>{let l=new Uint8Array(0);for(;;){let{done:c,value:d}=await a.read();if(c)return l.byteLength>0?l:null;if(l=ce(l,d instanceof Uint8Array?d:new Uint8Array(d)),l.byteLength>=60)return l}},write:l=>i.write(l),close:async()=>{try{await a.cancel()}catch{}try{await i.close()}catch{}}}).catch(l=>{r(`h2 handler error: ${l.message||l}`),a.cancel().catch(()=>{}),i.close().catch(()=>{})}),new Response(s,{status:200,headers:{"Content-Type":"application/octet-stream","Cache-Control":"no-store"}})}async function Sn(e,t,n){let r=(...c)=>console.log("[grpc-in]",...c);if(!e.body)return new Response("Bad Request",{status:400});let a=e.body.getReader(),{readable:s,writable:o}=new TransformStream,i=o.getWriter(),u=new Uint8Array(0);return at(t,n,r,{read:async()=>{for(;;){if(u.byteLength>=5){let h=u[1]<<24|u[2]<<16|u[3]<<8|u[4];if(u.byteLength>=5+h){let p=u.slice(5,5+h);return u=u.slice(5+h),p}}let{done:c,value:d}=await a.read();if(c){if(u.byteLength===0)return null;let h=u;return u=new Uint8Array(0),h}u=ce(u,d instanceof Uint8Array?d:new Uint8Array(d))}},write:c=>i.write(pa(c instanceof Uint8Array?c:new Uint8Array(c))),close:async()=>{try{await a.cancel()}catch{}try{await i.close()}catch{}}}).catch(c=>{r(`grpc handler error: ${c.message||c}`),a.cancel().catch(()=>{}),i.close().catch(()=>{})}),new Response(s,{status:200,headers:{"Content-Type":"application/grpc","Cache-Control":"no-store"}})}var An="ed=2560",xt="random";function Rt(e){let t=e.startsWith("/")?e:`/${e}`;return/\?/.test(t)?`${t}&${An}`:`${t}?${An}`}function Ct(e){return(e.startsWith("/")?e:`/${e}`).replace(/\/+$/,"").replace(/^\//,"")}function Tt(e){let t=e.transport||"ws",n=e.wsHost||e.host,r=e.sni||(e.tls?n:""),a=new URLSearchParams({encryption:"none",type:t,host:n,security:e.tls?"tls":"none",tfo:"1"});t==="grpc"?a.set("serviceName",`/${Ct(e.wsPath)}`):t==="h2"?a.set("path",e.wsPath.startsWith("/")?e.wsPath:`/${e.wsPath}`):a.set("path",Rt(e.wsPath)),e.tls&&r&&a.set("sni",r),e.tls&&a.set("fp",e.fp||xt);let s=encodeURIComponent(e.remark||`${e.host}:${e.port}`);return`vless://${e.uuid}@${e.host}:${e.port}?${a.toString()}#${s}`}function kt(e){let t=e.transport||"ws",n=e.wsHost||e.host,r=e.sni||(e.tls?n:""),a=new URLSearchParams({type:t,host:n,security:e.tls?"tls":"none",tfo:"1"});t==="grpc"?a.set("serviceName",`/${Ct(e.wsPath)}`):t==="h2"?a.set("path",e.wsPath.startsWith("/")?e.wsPath:`/${e.wsPath}`):a.set("path",Rt(e.wsPath)),e.tls&&r&&a.set("sni",r),e.tls&&a.set("fp",e.fp||xt);let s=encodeURIComponent(e.remark||`${e.host}:${e.port}`);return`trojan://${encodeURIComponent(e.password)}@${e.host}:${e.port}?${a.toString()}#${s}`}function _n(e){let t=e.headers.get("Host");return t?t.split(":")[0]:"example.com"}var Et=["ws","grpc","h2"];function fa(e,t){let n=[],r=t.port||(t.tls?443:80),a=t.transports&&t.transports.length?t.transports:Et;for(let s of e.vlessUsers){let o=s.path||e.wsPath;for(let i of a)n.push(Tt({uuid:s.uuid,host:t.host,port:r,wsPath:o,tls:t.tls,wsHost:t.wsHost,sni:t.sni,transport:i,remark:`vless-${s.remark||s.uuid.slice(0,8)}-${i}`}))}for(let s of e.trojanUsers){let o=s.path||e.wsPath;for(let i of a)n.push(kt({password:s.password,host:t.host,port:r,wsPath:o,tls:t.tls,wsHost:t.wsHost,sni:t.sni,transport:i,remark:`trojan-${s.remark||s.password.slice(0,8)}-${i}`}))}return n}function ue(e,t){return t.flatMap(r=>fa(e,r)).join(`
`)+`
`}function Ln(e,t){return btoa(ue(e,t))}function $n(e,t){let n=[],r=t.length>1;for(let s of t){let o=s.port||443,i=s.tls!==!1,u=s.wsHost||s.host,l=s.sni||(i?u:""),c=s.transports&&s.transports.length?s.transports:Et,d=r?(s.name||s.host)+"-":"",h=(p,g,m,y,f,b)=>{let w={name:d+p,type:g,server:s.host,port:o,[m]:y,network:b,tls:i,servername:l||void 0,"client-fingerprint":i?xt:void 0,tfo:!0,udp:!0,_wsHost:u};return b==="grpc"?w["grpc-opts"]={"grpc-service-name":`/${Ct(f)}`}:b==="h2"?w["h2-opts"]={path:f.startsWith("/")?f:`/${f}`,host:[u]}:w["ws-opts"]={path:Rt(f),headers:{Host:u}},w};e.vlessUsers.forEach((p,g)=>{for(let m of c)n.push(h(`vless-${p.remark||g+1}-${m}`,"vless","uuid",p.uuid,p.path||e.wsPath,m))}),e.trojanUsers.forEach((p,g)=>{for(let m of c)n.push(h(`trojan-${p.remark||g+1}-${m}`,"trojan","password",p.password,p.path||e.wsPath,m))})}let a=["proxies:"];for(let s of n)a.push(`  - name: "${s.name}"`),a.push(`    type: ${s.type}`),a.push(`    server: ${s.server}`),a.push(`    port: ${s.port}`),s.uuid&&a.push(`    uuid: ${s.uuid}`),s.password&&a.push(`    password: "${s.password}"`),a.push(`    network: ${s.network}`),a.push(`    tls: ${s.tls}`),s.servername&&a.push(`    servername: ${s.servername}`),s["client-fingerprint"]&&a.push(`    client-fingerprint: ${s["client-fingerprint"]}`),a.push("    tfo: true"),a.push("    udp: true"),s.network==="grpc"?(a.push("    grpc-opts:"),a.push(`      grpc-service-name: ${s["grpc-opts"]["grpc-service-name"]}`)):s.network==="h2"?(a.push("    h2-opts:"),a.push(`      path: ${s["h2-opts"].path}`),a.push("      host:"),a.push(`        - ${s._wsHost}`)):(a.push("    ws-opts:"),a.push(`      path: ${s["ws-opts"].path}`),a.push("      headers:"),a.push(`        Host: ${s._wsHost}`));return a.push(""),a.push("rules:"),a.push("  - MATCH,DIRECT"),a.join(`
`)}function Un(e,t){let n=[],r=t.length>1,a=(s,o,i)=>o==="grpc"?{type:"grpc",service_name:`/${Ct(s)}`}:o==="h2"?{type:"http",host:[i],path:s.startsWith("/")?s:`/${s}`}:{type:"ws",path:Rt(s),headers:{Host:i}};for(let s of t){let o=s.port||443,i=s.wsHost||s.host,u=s.sni||(s.tls?i:""),l=s.transports&&s.transports.length?s.transports:Et,c=r?(s.name||s.host)+"-":"";for(let d of e.vlessUsers)for(let h of l)n.push({type:"vless",tag:c+`vless-${d.remark||d.uuid.slice(0,8)}-${h}`,server:s.host,server_port:o,uuid:d.uuid,transport:a(d.path||e.wsPath,h,i),tcp_fast_open:!0,tls:s.tls?{enabled:!0,server_name:u,fingerprint:xt}:null});for(let d of e.trojanUsers)for(let h of l)n.push({type:"trojan",tag:c+`trojan-${d.remark||d.password.slice(0,8)}-${h}`,server:s.host,server_port:o,password:d.password,transport:a(d.path||e.wsPath,h,i),tcp_fast_open:!0,tls:s.tls?{enabled:!0,server_name:u,fingerprint:xt}:null})}return JSON.stringify({outbounds:n,log:{level:"info"}},null,2)}function de(e,t){let n=t.host,r=t.port||(t.tls?443:80),s=`/${(t.path||e.wsPath||"/ws").replace(/^\//,"")}`,o={host:n,port:r,wsPath:s,tls:t.tls,wsHost:t.wsHost,sni:t.sni},i=(p,g)=>t.kind==="vless"?Tt({...o,uuid:t.credential,transport:p,remark:`vless-${g}`}):kt({...o,password:t.credential,transport:p,remark:`trojan-${g}`}),u=[{key:"ws",name:"WebSocket (ws)",link:i("ws","ws")},{key:"grpc",name:"gRPC",link:i("grpc","grpc")},{key:"h2",name:"HTTP/2 (h2)",link:i("h2","h2")}].filter(p=>(t.transports&&t.transports.length?t.transports:["ws","grpc","h2"]).includes(p.key)),l=t.kind==="vless"?"VLESS":"Trojan",c=u.map(p=>p.key).join(" / "),d=u.map((p,g)=>`
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
<title>${l} \u8282\u70B9\u914D\u7F6E</title>
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
  <h1>${l} \u8282\u70B9 <span class="badge">${n}</span></h1>
  <p class="desc">\u5165\u7AD9\u8DEF\u5F84\uFF1A<b>${s}</b>\uFF08\u5F53\u524D\u5165\u53E3\u652F\u6301\uFF1A${c||"\u65E0"}\uFF0C\u590D\u5236\u94FE\u63A5\u5BFC\u5165\u5BA2\u6237\u7AEF\uFF09</p>
  ${d}
</div>
<script>
function copyLink(i){ const el=document.getElementById('link'+i); el.select(); document.execCommand('copy'); el.style.borderColor='#34c759'; setTimeout(()=>el.style.borderColor='#d2d2d7',800); }
<\/script>
</body>
</html>`}function On(e){let t=e.disguise_title||"AList",n=e.disguise_subtitle||"\u4E00\u4E2A\u652F\u6301\u591A\u5B58\u50A8\u7684\u6587\u4EF6\u5217\u8868\u7A0B\u5E8F";return`<!DOCTYPE html>
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
<div class="footer">Powered by ${t} \xB7 ${n}</div>
</body>
</html>`}function pe(e,t=200){return new Response(e,{status:t,headers:{"Content-Type":"text/html; charset=utf-8","Cache-Control":"no-store"}})}function ct(e,t="text/plain; charset=utf-8"){return new Response(e,{headers:{"Content-Type":t,"Cache-Control":"no-store"}})}function ha(e,t,n){switch((new URL(e.url).searchParams.get("format")||"base64").toLowerCase()){case"plain":return ct(ue(t,n));case"clash":case"yaml":return ct($n(t,n),"text/yaml; charset=utf-8");case"singbox":case"sing-box":case"json":return ct(Un(t,n),"application/json; charset=utf-8");default:return ct(Ln(t,n))}}function ma(e,t,n,r){let a=new URL(e.url),s=null;if(t.uuidSet.has(n)?s={kind:"vless",user:t.vlessIndex[n]}:t.passwordSet.has(n)&&(s={kind:"trojan",user:t.trojanIndex[n]}),!s)return new Response("Not Found",{status:404});let o=(a.searchParams.get("format")||"base64").toLowerCase(),i=r.host,u=r.port,l=s.user.path||t.wsPath,c=r.transports&&r.transports.length?r.transports:Et,d=[];for(let p of c)s.kind==="vless"?d.push(Tt({uuid:s.user.uuid,host:i,port:u,wsPath:l,tls:r.tls,wsHost:r.wsHost,sni:r.sni,transport:p,remark:`vless-${s.user.remark||"node"}-${p}`})):d.push(kt({password:s.user.password,host:i,port:u,wsPath:l,tls:r.tls,wsHost:r.wsHost,sni:r.sni,transport:p,remark:`trojan-${s.user.remark||"node"}-${p}`}));let h=d.join(`
`)+`
`;return ct(o==="plain"?h:btoa(h))}async function Dn(e,t,n){let r=new URL(e.url),a=r.pathname,s=_n(e),o=r.protocol==="https:",i=Number(r.port)||(o?443:80),u=s.toLowerCase().replace(/:\d+$/,""),l=m=>[m.host,m.wsHost].filter(Boolean).map(f=>f.toLowerCase().replace(/:\d+$/,"")).some(f=>f===u),c=t.entries.find(l),d=c?{host:c.host,port:Number(c.port)||443,tls:!0,wsHost:c.wsHost,sni:c.sni,transports:c.transports}:{host:s,port:i,tls:o,wsHost:s,sni:s},h;if(c?h=[{host:c.host,port:Number(c.port)||443,tls:!0,wsHost:c.wsHost,sni:c.sni,transports:c.transports,name:c.remark||c.host}]:t.entries.length?h=t.entries.map(m=>({host:m.host,port:Number(m.port)||443,tls:!0,wsHost:m.wsHost,sni:m.sni,transports:m.transports,name:m.remark||m.host})):h=[{host:s,port:i,tls:o,wsHost:s,sni:s}],a==="/subscribe")return ha(e,t,h);let p=a.match(/^\/([^/]+)\/subscribe$/);if(p)return ma(e,t,decodeURIComponent(p[1]),d);let g=a.match(/^\/([^/]+)$/);if(g){let m=decodeURIComponent(g[1]);if(t.uuidSet.has(m)){let y=t.vlessIndex[m];return pe(de(t,{host:d.host,port:d.port,tls:d.tls,wsHost:d.wsHost,sni:d.sni,transports:d.transports,credential:m,kind:"vless",path:y&&y.path||t.wsPath}))}if(t.passwordSet.has(m)){let y=t.trojanIndex[m];return pe(de(t,{host:d.host,port:d.port,tls:d.tls,wsHost:d.wsHost,sni:d.sni,transports:d.transports,credential:m,kind:"trojan",path:y&&y.path||t.wsPath}))}}return pe(On(t.settings))}var Rn="1.0.59-20260927-1349";function ga(e){if(e.length<2)return{frame:null,remaining:e,needMore:!0};let t=e[0]<<8|e[1];return t===0?{frame:new Uint8Array(0),remaining:e.slice(2),needMore:!1}:e.length<2+t?{frame:null,remaining:e,needMore:!0}:{frame:e.slice(2,2+t),remaining:e.slice(2+t),needMore:!1}}function Cn(e){let t=new Uint8Array(2+e.length);return t[0]=e.length>>8,t[1]=e.length&255,t.set(e,2),t}async function Mn(e,t,n){let r=e.getReader(),a=new Uint8Array(0);try{for(;;){let{done:s,value:o}=await r.read();if(s)break;if(!o||o.byteLength===0)continue;let i=new Uint8Array(a.length+o.byteLength);for(i.set(a,0),i.set(o,a.length),a=i;;){let{frame:u,remaining:l,needMore:c}=ga(a);if(c){a=l;break}if(a=l,u&&u.length>0)try{await t(u)}catch(d){n(`udp frame handler error: ${d.message}`)}if(a.length<2)break}}}catch(s){n(`readUdpFrames error: ${s.message}`)}finally{try{r.releaseLock()}catch{}}}var Pn=[{name:"\u5B57\u8282\u8DF3\u52A8",host:"www.bytedance.com",port:80,region:"cn",icon:"\u{1F3B5}",color:"#325AB4"},{name:"Bilibili",host:"www.bilibili.com",port:80,region:"cn",icon:"\u{1F4FA}",color:"#FB7299"},{name:"\u5FAE\u4FE1",host:"weixin.qq.com",port:80,region:"cn",icon:"\u{1F4AC}",color:"#07C160"},{name:"\u6DD8\u5B9D",host:"www.taobao.com",port:80,region:"cn",icon:"\u{1F6D2}",color:"#FF5000"},{name:"GitHub",host:"github.com",port:80,region:"intl",icon:"\u{1F419}",color:"#24292F"},{name:"jsDelivr",host:"cdn.jsdelivr.net",port:80,region:"intl",icon:"\u{1F4E6}",color:"#E84D0E"},{name:"Cloudflare",host:"www.cloudflare.com",port:80,region:"intl",icon:"\u2601\uFE0F",color:"#F6821F"},{name:"Google",host:"www.google.com",port:80,region:"intl",icon:"\u{1F50D}",color:"#4285F4"},{name:"YouTube",host:"www.youtube.com",port:80,region:"intl",icon:"\u25B6\uFE0F",color:"#FF0000"}],In=16,fe=3e3,Nn=4;var ya=5e3,ba=5e3;function Mt(e,t,n="/"){return new TextEncoder().encode(`GET ${n} HTTP/1.1\r
Host: ${e}\r
User-Agent: Mozilla/5.0 (netprobe)\r
Connection: close\r
\r
`)}function wa(e,t){let n=new Uint8Array(e.length+t.length);return n.set(e,0),n.set(t,e.length),n}function va(e){for(let t=0;t<e.length-3;t++)if(e[t]===13&&e[t+1]===10&&e[t+2]===13&&e[t+3]===10)return t+4;return-1}function he(e){try{typeof e.close=="function"?e.close():e.writable&&typeof e.writable.close=="function"&&e.writable.close().catch(()=>{})}catch{}}function Pt(e,t){return new Promise(n=>{let r=new Uint8Array(0),a=!1,s=i=>{a||(a=!0,clearTimeout(o),n(i))},o=setTimeout(()=>s(null),t);(async()=>{let i=e.readable.getReader();try{for(;!a;){let{done:u,value:l}=await i.read();if(u)break;if(!(!l||l.byteLength===0)){if(r=wa(r,l),va(r)>=0){s(Date.now());break}if(r.length>65536){s(null);break}}}}catch{}s(null);try{i.releaseLock()}catch{}})()})}async function xa(e,t,n,r,a){let s=Date.now(),o;try{let u=await vt(e,2,t),l=Z(e,u.outbound);o=await X({config:e,outbound:l,addressType:2,addressRemote:t,portRemote:n,rawClientData:r,log:a})}catch{return null}if(!o)return null;let i=await Pt(o,fe);return he(o),i===null?null:i-s}async function Ta(e,t,n){let r=[];for(let l=0;l<In;l+=Nn){let c=[],d=Math.min(l+Nn,In);for(let p=l;p<d;p++)c.push(xa(e,t.host,t.port,Mt(t.host,t.port),n));let h=await Promise.all(c);for(let p of h)r.push(p)}let a=r.filter(l=>l!==null),s=a.length>0?Math.round(a.reduce((l,c)=>l+c,0)/a.length):null,o=a.length>0?Math.min(...a):null,i=a.length>0?Math.max(...a):null,u=r.length>0?Math.round((r.length-a.length)/r.length*100):100;return{...t,samples:r,latency:s,min:o,max:i,loss:u,success:a.length,total:r.length}}async function Hn(e,t){let n=await Promise.allSettled(Pn.map(r=>Ta(e,r,t)));return{ok:!0,ts:Date.now(),targets:n.map((r,a)=>r.status==="fulfilled"?r.value:{...Pn[a],samples:[],latency:null,success:0,total:0,error:r.reason&&r.reason.message||"error"})}}async function Fn(e,t,n){let r=String(t||"").trim().toLowerCase();if(!r)return{ok:!1,error:"domain required"};let a=2;/^\d{1,3}(\.\d{1,3}){3}$/.test(r)?a=1:r.includes(":")&&(a=3);let s=a!==2,o=await vt(e,a,r),i=!!o.rule,u=i?`\u5206\u6D41\u89C4\u5219 ${o.rule.rule} \u2192 `:"",l=Z(e,o.outbound);if(l==="reject")return{ok:!0,domain:r,route:"reject",name:"reject",reason:i?`${u}reject\uFF08\u62D2\u7EDD\u8FDE\u63A5\uFF09`:"\u9ED8\u8BA4\u51FA\u7AD9 reject\uFF08\u62D2\u7EDD\u8FDE\u63A5\uFF09",rule:i?o.rule.rule:null};if(l==="direct"){let d=o.outbound,h=(!!e.proxyipHost||!!e.proxyipOutbound)&&!e.proxyipDisabled,p=h&&un(),g=!s&&Qt(r),m=s&&!r.includes(":")&&wt(r),y=!1;if(h&&!p&&!s&&!g){let f=await bt(r,n);f&&wt(f)&&(y=!0)}if(h&&!p&&(g||m||y)){if(e.proxyipOutbound)return{ok:!0,domain:r,route:"proxyip",name:`outbound:${e.proxyipOutbound}`,reason:`${u}Cloudflare \u7AD9\u70B9\uFF08\u5DF2\u77E5 CF \u540E\u7F00/IP \u6BB5\uFF09\u2192 \u4F7F\u7528\u51FA\u7AD9\u4EE3\u7406 ${e.proxyipOutbound} \u51FA\u7AD9`,rule:i?o.rule.rule:null};let f=`${e.proxyipHost}:${Number(e.proxyipPort||443)}`;return{ok:!0,domain:r,route:"proxyip",name:f,reason:`${u}Cloudflare \u7AD9\u70B9\uFF08\u5DF2\u77E5 CF \u540E\u7F00/IP \u6BB5\uFF09\u2192 proxyip ${f}`,rule:i?o.rule.rule:null}}return i?{ok:!0,domain:r,route:"direct",name:"direct",reason:`${u}direct`,rule:o.rule.rule}:d&&d!=="direct"&&d!=="reject"?{ok:!0,domain:r,route:"direct",name:"direct",reason:`\u9ED8\u8BA4\u51FA\u7AD9 ${d} \u4E0D\u5B58\u5728\uFF0C\u56DE\u9000 direct`,rule:null}:{ok:!0,domain:r,route:"direct",name:"direct",reason:"\u9ED8\u8BA4\u51FA\u7AD9 direct",rule:null}}let c=typeof l=="string"?l:l.name;return{ok:!0,domain:r,route:"outbound",name:c,reason:i?`${u}\u51FA\u7AD9 ${c}`:`\u9ED8\u8BA4\u51FA\u7AD9 ${c}`,rule:i?o.rule.rule:null}}async function zn(e,t){let n="www.cloudflare.com";if(e.proxyipOutbound){let i=Z(e,e.proxyipOutbound);if(!i||typeof i=="string")return{ok:!1,mode:"outbound",error:`\u51FA\u7AD9 ${e.proxyipOutbound} \u4E0D\u5B58\u5728\uFF0C\u8BF7\u68C0\u67E5\u51FA\u7AD9\u914D\u7F6E`};let u=Date.now(),l=null;try{l=await X({config:e,outbound:i,addressType:2,addressRemote:n,portRemote:443,rawClientData:Mt(n,443),log:t,isUDP:!1})}catch(d){return{ok:!1,mode:"outbound",outbound:e.proxyipOutbound,error:`\u51FA\u7AD9\u8FDE\u63A5\u5931\u8D25: ${d.message}`}}if(!l)return{ok:!1,mode:"outbound",outbound:e.proxyipOutbound,error:"\u51FA\u7AD9\u8FDE\u63A5\u5931\u8D25\u6216\u65E0\u54CD\u5E94"};let c=await Pt(l,fe);return he(l),c===null?{ok:!1,mode:"outbound",outbound:e.proxyipOutbound,error:"\u8FDE\u63A5\u8D85\u65F6\u6216\u65E0\u54CD\u5E94"}:{ok:!0,latency:c-u,mode:"outbound",outbound:e.proxyipOutbound}}if(!e.proxyipHost)return{ok:!1,error:"\u672A\u914D\u7F6E proxyip\uFF0C\u8BF7\u5148\u5728\u7CFB\u7EDF\u8BBE\u7F6E\u4E2D\u586B\u5199"};let a=Date.now(),s=null;try{if(s=globalThis.connect?globalThis.connect({hostname:e.proxyipHost,port:Number(e.proxyipPort||443)}):null,!s)return{ok:!1,error:"connect \u4E0D\u53EF\u7528"};let i=s.writable.getWriter();await i.write(Mt(n,443)),i.releaseLock()}catch(i){try{s&&s.close()}catch{}return{ok:!1,error:`\u8FDE\u63A5\u5931\u8D25: ${i.message}`}}let o=await Pt(s,fe);try{s.close()}catch{}return o===null?{ok:!1,error:"\u8FDE\u63A5\u8D85\u65F6\u6216\u65E0\u54CD\u5E94"}:{ok:!0,latency:o-a,mode:"proxyip",endpoint:`${e.proxyipHost}:${e.proxyipPort||443}`}}function ka(e){let n=[18,52];n.push(1,0),n.push(0,1),n.push(0,0,0,0,0,0);for(let r of String(e).split(".")){n.push(r.length);for(let a=0;a<r.length;a++)n.push(r.charCodeAt(a))}return n.push(0),n.push(0,1),n.push(0,1),new Uint8Array(n)}async function Bn(e,t){let n=null,r=(e.udpOutbound||"").trim();if(r){let l=e.outboundByName[r];if(l&&l.type==="vless")n=l;else return{ok:!1,error:`UDP \u51FA\u7AD9 '${r}' \u4E0D\u5B58\u5728\u6216\u975E vless\uFF08\u4EC5 vless \u652F\u6301 UDP\uFF09`}}else if(n=e.outbounds.find(l=>l.type==="vless"),!n)return{ok:!1,error:"\u672A\u914D\u7F6E vless \u51FA\u7AD9\uFF0C\u65E0\u6CD5\u6D4B\u8BD5 UDP"};let a=ka("example.com"),s=Cn(a),o=Date.now(),i;try{i=await it({address:n.address,port:Number(n.port),uuid:n.uuid,path:n.path,tls:!!n.tls,sni:n.sni||"",transport:n.transport},2,1,"8.8.8.8",53,s,t)}catch(l){return{ok:!1,error:`UDP \u51FA\u7AD9\u8FDE\u63A5\u5931\u8D25: ${l.message}`}}if(!i)return{ok:!1,error:"UDP \u51FA\u7AD9\u8FDE\u63A5\u5931\u8D25"};let u=await new Promise(l=>{let c=setTimeout(()=>l({ok:!1,error:"UDP \u54CD\u5E94\u8D85\u65F6"}),ya);Mn(i.readable,d=>{d.length>=12&&d[0]===18&&d[1]===52&&(d[2]&128)!==0&&(clearTimeout(c),l({ok:!0,latency:Date.now()-o,bytes:d.length,outbound:n.name||r||"vless"}))},t)});try{i.writable.close().catch(()=>{})}catch{}return u}async function Gn(e,t,n){let r="www.gstatic.com",s=Date.now(),o;try{o=await X({config:e,outbound:t,addressType:2,addressRemote:r,portRemote:80,rawClientData:Mt(r,80,"/generate_204"),log:n})}catch(u){return{ok:!1,error:u.message}}if(!o)return{ok:!1,error:"\u96A7\u9053\u5EFA\u7ACB\u5931\u8D25"};let i=await Pt(o,ba);return he(o),i===null?{ok:!1,error:"\u8FDE\u63A5\u8D85\u65F6\u6216\u65E0\u54CD\u5E94"}:{ok:!0,latency:i-s}}var N=Uint8Array,ut=Uint16Array,Ea=Int32Array,jn=new N([0,0,0,0,0,0,0,0,1,1,1,1,2,2,2,2,3,3,3,3,4,4,4,4,5,5,5,5,0,0,0,0]),Wn=new N([0,0,0,0,1,1,2,2,3,3,4,4,5,5,6,6,7,7,8,8,9,9,10,10,11,11,12,12,13,13,0,0]),Sa=new N([16,17,18,0,8,7,9,6,10,5,11,4,12,3,13,2,14,1,15]),Vn=function(e,t){for(var n=new ut(31),r=0;r<31;++r)n[r]=t+=1<<e[r-1];for(var a=new Ea(n[30]),r=1;r<30;++r)for(var s=n[r];s<n[r+1];++s)a[s]=s-n[r]<<5|r;return{b:n,r:a}},Kn=Vn(jn,2),Yn=Kn.b,Aa=Kn.r;Yn[28]=258,Aa[258]=28;var qn=Vn(Wn,0),_a=qn.b,wo=qn.r,ye=new ut(32768);for(S=0;S<32768;++S)Y=(S&43690)>>1|(S&21845)<<1,Y=(Y&52428)>>2|(Y&13107)<<2,Y=(Y&61680)>>4|(Y&3855)<<4,ye[S]=((Y&65280)>>8|(Y&255)<<8)>>1;var Y,S,St=(function(e,t,n){for(var r=e.length,a=0,s=new ut(t);a<r;++a)e[a]&&++s[e[a]-1];var o=new ut(t);for(a=1;a<t;++a)o[a]=o[a-1]+s[a-1]<<1;var i;if(n){i=new ut(1<<t);var u=15-t;for(a=0;a<r;++a)if(e[a])for(var l=a<<4|e[a],c=t-e[a],d=o[e[a]-1]++<<c,h=d|(1<<c)-1;d<=h;++d)i[ye[d]>>u]=l}else for(i=new ut(r),a=0;a<r;++a)e[a]&&(i[a]=ye[o[e[a]-1]++]>>15-e[a]);return i}),At=new N(288);for(S=0;S<144;++S)At[S]=8;var S;for(S=144;S<256;++S)At[S]=9;var S;for(S=256;S<280;++S)At[S]=7;var S;for(S=280;S<288;++S)At[S]=8;var S,Jn=new N(32);for(S=0;S<32;++S)Jn[S]=5;var S;var La=St(At,9,1);var $a=St(Jn,5,1),me=function(e){for(var t=e[0],n=1;n<e.length;++n)e[n]>t&&(t=e[n]);return t},z=function(e,t,n){var r=t/8|0;return(e[r]|e[r+1]<<8)>>(t&7)&n},ge=function(e,t){var n=t/8|0;return(e[n]|e[n+1]<<8|e[n+2]<<16)>>(t&7)},Ua=function(e){return(e+7)/8|0},Oa=function(e,t,n){return(t==null||t<0)&&(t=0),(n==null||n>e.length)&&(n=e.length),new N(e.subarray(t,n))};var Da=["unexpected EOF","invalid block type","invalid length/literal","invalid distance","stream finished","no stream handler",,"no callback","invalid UTF-8 data","extra field too long","date not in range 1980-2099","filename too long","stream finishing","invalid zip data"],B=function(e,t,n){var r=new Error(t||Da[e]);if(r.code=e,Error.captureStackTrace&&Error.captureStackTrace(r,B),!n)throw r;return r},Ra=function(e,t,n,r){var a=e.length,s=r?r.length:0;if(!a||t.f&&!t.l)return n||new N(0);var o=!n,i=o||t.i!=2,u=t.i;o&&(n=new N(a*3));var l=function(Te){var ke=n.length;if(Te>ke){var Ee=new N(Math.max(ke*2,Te));Ee.set(n),n=Ee}},c=t.f||0,d=t.p||0,h=t.b||0,p=t.l,g=t.d,m=t.m,y=t.n,f=a*8;do{if(!p){c=z(e,d,1);var b=z(e,d+1,3);if(d+=3,b)if(b==1)p=La,g=$a,m=9,y=5;else if(b==2){var _=z(e,d,31)+257,U=z(e,d+10,15)+4,L=_+z(e,d+5,31)+1;d+=14;for(var A=new N(L),M=new N(19),v=0;v<U;++v)M[Sa[v]]=z(e,d+v*3,7);d+=U*3;for(var E=me(M),$=(1<<E)-1,C=St(M,E,1),v=0;v<L;){var I=C[z(e,d,$)];d+=I&15;var w=I>>4;if(w<16)A[v++]=w;else{var V=0,G=0;for(w==16?(G=3+z(e,d,3),d+=2,V=A[v-1]):w==17?(G=3+z(e,d,7),d+=3):w==18&&(G=11+z(e,d,127),d+=7);G--;)A[v++]=V}}var tt=A.subarray(0,_),O=A.subarray(_);m=me(tt),y=me(O),p=St(tt,m,1),g=St(O,y,1)}else B(1);else{var w=Ua(d)+4,T=e[w-4]|e[w-3]<<8,k=w+T;if(k>a){u&&B(0);break}i&&l(h+T),n.set(e.subarray(w,k),h),t.b=h+=T,t.p=d=k*8,t.f=c;continue}if(d>f){u&&B(0);break}}i&&l(h+131072);for(var R=(1<<m)-1,q=(1<<y)-1,P=d;;P=d){var V=p[ge(e,d)&R],D=V>>4;if(d+=V&15,d>f){u&&B(0);break}if(V||B(2),D<256)n[h++]=D;else if(D==256){P=d,p=null;break}else{var H=D-254;if(D>264){var v=D-257,F=jn[v];H=z(e,d,(1<<F)-1)+Yn[v],d+=F}var Ht=g[ge(e,d)&q],Ft=Ht>>4;Ht||B(3),d+=Ht&15;var O=_a[Ft];if(Ft>3){var F=Wn[Ft];O+=ge(e,d)&(1<<F)-1,d+=F}if(d>f){u&&B(0);break}i&&l(h+131072);var ve=h+H;if(h<O){var xe=s-O,ir=Math.min(O,ve);for(xe+h<0&&B(3);h<ir;++h)n[h]=r[xe+h]}for(;h<ve;++h)n[h]=n[h-O]}}t.l=p,t.p=P,t.b=h,t.f=c,p&&(c=1,t.m=m,t.d=g,t.n=y)}while(!c);return h!=n.length&&o?Oa(n,0,h):n.subarray(0,h)};var Ca=new N(0);var Ma=function(e,t){return((e[0]&15)!=8||e[0]>>4>7||(e[0]<<8|e[1])%31)&&B(6,"invalid zlib data"),(e[1]>>5&1)==+!t&&B(6,"invalid zlib data: "+(e[1]&32?"need":"unexpected")+" dictionary"),(e[1]>>3&4)+2};function Xn(e,t){return Ra(e.subarray(Ma(e,t&&t.dictionary),-4),{i:2},t&&t.out,t&&t.dictionary)}var Pa=typeof TextDecoder<"u"&&new TextDecoder,Ia=0;try{Pa.decode(Ca,{stream:!0}),Ia=1}catch{}var be={"Content-Type":"application/json; charset=utf-8"},Na="gcp:asia-east2";function x(e,t=200){return new Response(JSON.stringify(e),{status:t,headers:be})}async function _t(e){try{return await e.json()}catch{return null}}function Ha(e){return e.admin_cookie_secret||e.admin_password_hash||"vtd-insecure-secret"}async function nr(e,t,n){let r=new URL(e.url),s=r.pathname.split("/").filter(Boolean),o=s[2]||"",i=s[3]||null,u=e.method,{DB:l,GEO_KV:c}=t.env,d=t.settings,h=Ha(d);if(o==="login"&&u==="POST"){let f=await _t(e);if(!f||!f.password)return x({error:"password required"},400);if(!await Re(f.password,t.adminPasswordHash))return x({error:"invalid password"},401);let w=await Me(h);return new Response(JSON.stringify({ok:!0}),{status:200,headers:{...be,"Set-Cookie":`${pt}=${w}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${7*86400}`}})}let p=Ie(e.headers.get("Cookie"));if(!await Pe(p[pt],h))return x({error:"unauthorized"},401);if(o==="logout"&&u==="POST")return new Response(JSON.stringify({ok:!0}),{status:200,headers:{...be,"Set-Cookie":`${pt}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0`}});if(o==="version"&&u==="GET")return x({ok:!0,version:Rn});if(o==="colo"&&u==="GET"){let f=e&&e.cf||{},b=e.headers.get("cf-placement")||"",w=null,T=null;if(b){let k=b.indexOf("-");k>0?(w=b.slice(0,k),T=b.slice(k+1)||null):w=b}return x({ok:!0,placement_header:b||null,placement_mode:w,placement_colo:T,colo:f.colo||null,region:f.region||null,city:f.city||null,country:f.country||null,continent:f.continent||null,timezone:f.timezone||null,host:r.hostname||null,configured_placement_region:Na})}if(await es(l),o==="settings"){if(u==="GET"){let{results:f}=await l.prepare("SELECT key, value FROM settings").all();return x((f||[]).reduce((b,w)=>(b[w.key]=w.value,b),{}))}if(u==="PUT"){let f=await _t(e);if(!f)return x({error:"bad body"},400);let b=new Set(["ws_path","default_outbound","proxyip","udp_outbound","disguise_title","disguise_subtitle","entry_host","entry_port","entry_sni","entry_ws_host","entry_list","admin_password_hash","admin_cookie_secret"]);if(f.entry_list!==void 0)try{let w=JSON.parse(f.entry_list);if(!Array.isArray(w)||w.some(T=>!T||!String(T.host||"").trim()))return x({error:"entry_list \u5FC5\u987B\u4E3A\u5165\u53E3\u6570\u7EC4\uFF08\u6BCF\u9879\u9700\u5305\u542B host\uFF09"},400);if(w.some(T=>Array.isArray(T.transports)&&T.transports.some(k=>!["ws","grpc","h2"].includes(k))))return x({error:"entry_list transports \u4EC5\u5141\u8BB8 ws / grpc / h2"},400)}catch{return x({error:"entry_list \u4E0D\u662F\u5408\u6CD5 JSON \u6570\u7EC4"},400)}for(let[w,T]of Object.entries(f))typeof T=="string"&&b.has(w)&&await l.prepare("INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at").bind(w,T,Date.now()).run();return ot("settings"),x({ok:!0})}return x({error:"method not allowed"},405)}let y={"vless-users":{table:"vless_users",cacheKey:"vlessUsers",cols:["uuid","remark","enable","path","expire_at","traffic_limit","traffic_reset_at"]},"trojan-users":{table:"trojan_users",cacheKey:"trojanUsers",cols:["password","remark","enable","path","expire_at","traffic_limit","traffic_reset_at"]},outbounds:{table:"outbounds",cacheKey:"outbounds",cols:["type","name","address","port","uuid","path","tls","udp","enable","sort","username","password","sni","transport"],validate(f){if(f.type!==void 0&&!["socks5","http","vless"].includes(f.type))return"invalid outbound type";if(f.port!==void 0&&(!Number.isInteger(Number(f.port))||Number(f.port)<=0||Number(f.port)>65535))return"invalid port";if((f.type==="socks5"||f.type==="http")&&!f.address)return"address required";if(f.type==="vless"){if(!f.uuid)return"vless requires uuid";if(f.transport!==void 0&&!["raw","ws","grpc","httpupgrade","h2"].includes(f.transport))return"invalid vless transport"}return f.username&&!f.password||!f.username&&f.password?"username and password must be set together":((f.type==="socks5"||f.type==="http")&&(f.udp=0),f.type!=="vless"&&(f.transport="ws"),null)}},"routing-rules":{table:"routing_rules",cacheKey:"routingRules",cols:["rule","outbound","enable","sort"]}}[o];if(y)return Fa(u,i,y,l,e);if(o==="stats"&&u==="GET"){let[f,b]=await Promise.all([l.prepare("SELECT remark, uuid, up, down, path, expire_at, traffic_limit, traffic_reset_at FROM vless_users ORDER BY (up + down) DESC").all(),l.prepare("SELECT remark, password, up, down, path, expire_at, traffic_limit, traffic_reset_at FROM trojan_users ORDER BY (up + down) DESC").all()]),w=Math.floor(Date.now()/1e3),T=k=>(k||[]).map(_=>{let U=Number(_.up||0),L=Number(_.down||0),A=Number(_.traffic_limit||0),M=U+L;return{..._,used:M,remaining:A>0?Math.max(0,A-M):null,expired:_.expire_at>0&&_.expire_at<w,limitReached:A>0&&M>=A}});return x({vless:T(f.results),trojan:T(b.results)})}if(o==="geo"&&s[3]==="update"&&u==="POST")try{if(await c.get("geo:updating")==="1")return x({ok:!0,started:!1,updating:!0});if(await c.put("geo:updating","1",{expirationTtl:7200}),t.env&&t.env.GEO_QUEUE&&typeof t.env.GEO_QUEUE.send=="function")return await t.env.GEO_QUEUE.send({kind:"geo-update"}),await c.put("geo:update_status",JSON.stringify({startedAt:Date.now(),state:"updating",step:0,total:0,updated:0,failed:[],current:"",message:"\u5DF2\u5165\u961F\uFF0C\u7B49\u5F85\u6D88\u8D39\u8005\u6267\u884C\u2026"})).catch(()=>{}),x({ok:!0,started:!0,queued:!0,updating:!0});if(n&&typeof n.waitUntil=="function")return n.waitUntil(It(l,c)),x({ok:!0,started:!0,updating:!0});let b=await It(l,c);return x({ok:!0,started:!1,updated:b.updated,total:b.total,failed:b.failed})}catch(f){return await c.put("geo:updating","0").catch(()=>{}),x({error:f.message},500)}if(o==="geo"&&s[3]==="status"&&u==="GET"){let[f,b,w]=await Promise.all([c.get("geo:updating"),c.get("geo:update_status"),c.get(Lt)]),T=null;if(b)try{T=JSON.parse(b)}catch{}return x({ok:!0,updating:f==="1",version:w||null,status:T})}if(o==="geo"&&s[3]==="info"&&u==="GET"){let[f,b,w]=await Promise.all([c.get("geo:updating"),c.get("geo:update_status"),c.get(Lt)]),T=null;if(b)try{T=JSON.parse(b)}catch{}let k=async L=>{let A=[],M;do{let v=await c.list({prefix:L,cursor:M});for(let E of v.keys||[])A.push(E.name.slice(L.length));M=v.cursor}while(M);return A},[_,U]=await Promise.all([k("geosite:"),k("geoip:")]);return x({ok:!0,updating:f==="1",version:w||null,status:T,geositeCount:_.length,geoipCount:U.length,geositeCategories:_,geoipCategories:U})}if(o==="netstatus"&&s[3]==="test"&&u==="POST")try{return x(await Hn(t,f=>console.log(f)))}catch(f){return x({ok:!1,error:f.message},500)}if(o==="route-test"&&u==="POST")try{let f=await _t(e),b=f&&f.domain?String(f.domain).trim():"";return b?x(await Fn(t,b,w=>console.log(w))):x({ok:!1,error:"\u8BF7\u586B\u5199\u8981\u6D4B\u8BD5\u7684\u57DF\u540D\u6216 IP"},400)}catch(f){return x({ok:!1,error:f.message},500)}if(o==="test"){if(s[3]==="proxyip"&&u==="POST")try{return x(await zn(t,f=>console.log(f)))}catch(f){return x({ok:!1,error:f.message},500)}if(s[3]==="udp"&&u==="POST")try{return x(await Bn(t,f=>console.log(f)))}catch(f){return x({ok:!1,error:f.message},500)}if(s[3]==="outbound"&&s[4]&&u==="POST"){let f=await l.prepare("SELECT * FROM outbounds WHERE id = ?").bind(Number(s[4])).first();if(!f)return x({ok:!1,error:"outbound not found"},404);try{return x(await Gn(t,f,b=>console.log(b)))}catch(b){return x({ok:!1,error:b.message},500)}}}return x({error:"not found"},404)}async function Zn(e){try{let{results:t}=await e.prepare("SELECT name FROM pragma_table_info('outbounds')").all();if((t||[]).some(n=>n.name==="transport"))return;await e.prepare("ALTER TABLE outbounds ADD COLUMN transport TEXT DEFAULT 'ws'").run(),console.log("[admin] outbounds.transport column added (migration)")}catch(t){console.log("[admin] outbounds transport migration skipped: "+t.message)}}async function Fa(e,t,n,r,a){let{table:s,cols:o}=n,i="id";if(e==="GET"){let{results:u}=await r.prepare(`SELECT * FROM ${s} ORDER BY id`).all();return x(u||[])}if(e==="POST"){let u=await _t(a);if(!u)return x({error:"bad body"},400);if(n.validate){let p=n.validate(u);if(p)return x({error:p},400)}s==="outbounds"&&await Zn(r);let l=o.filter(p=>u[p]!==void 0);if(l.length===0)return x({error:"no fields"},400);let c=l.map(()=>"?").join(","),d=l.map(p=>u[p]),{meta:h}=await r.prepare(`INSERT INTO ${s} (${l.join(",")}) VALUES (${c})`).bind(...d).run();return n.cacheKey&&ot(n.cacheKey),x({ok:!0,id:h.last_row_id})}if(e==="PUT"&&t){let u=await _t(a);if(!u)return x({error:"bad body"},400);if(n.validate){let h=n.validate(u);if(h)return x({error:h},400)}s==="outbounds"&&await Zn(r);let l=o.filter(h=>u[h]!==void 0);if(l.length===0)return x({error:"no fields"},400);let c=l.map(h=>`${h} = ?`).join(","),d=l.map(h=>u[h]);return await r.prepare(`UPDATE ${s} SET ${c} WHERE ${i} = ?`).bind(...d,Number(t)).run(),n.cacheKey&&ot(n.cacheKey),x({ok:!0})}return e==="DELETE"&&t?(await r.prepare(`DELETE FROM ${s} WHERE ${i} = ?`).bind(Number(t)).run(),n.cacheKey&&ot(n.cacheKey),x({ok:!0})):x({error:"method not allowed"},405)}var Qn={geosite:["cn","apple","google","microsoft","facebook","twitter","telegram","github","netflix","youtube","spotify","discord","tiktok","paypal","steam","cloudflare","openai","anthropic","amazon","whatsapp","instagram","linkedin","mozilla","adobe","speedtest","oracle","digitalocean","vultr","jetbrains","gitee","baidu","aliyun","tencent","jd","bilibili","douyin","zhihu","iqiyi","youku","xiaomi","huawei"],geoip:["cn","hk","mo","tw","jp","kr","sg","my","th","vn","id","ph","us","ca","gb","de","fr","nl","se","au","nz","ru","in","br","ar","mx","za","tr","ae","sa","il","es","it","ch","at","be","dk","fi","no","pl","pt","ie","cz","hu","ro","ua","kz"]};async function Nt(e,t,n){let r=await Wa();(!r||r.length===0)&&(r=Qn.geosite.slice(),console.log("[geo] v2fly category enumeration failed, fallback to DEFAULT_GEO_CATEGORIES.geosite"));let a={geosite:r,geoip:Qn.geoip},s=a.geosite.length+a.geoip.length,o=l=>{if(typeof n=="function")try{n(l)}catch{}},i={updated:0,total:0,failed:[]},u=0;for(let l of["geosite","geoip"])for(let c of a[l]){i.total++,u++,o({state:"updating",step:u,total:s,current:`${l}:${c}`,updated:i.updated,failed:i.failed,message:`\u62C9\u53D6 ${l}:${c}`});try{let d=await za(l,c);d&&d.length>0?(await t.put(`${l}:${c}`,JSON.stringify(d)),i.updated++):i.failed.push(`${l}:${c} (empty rules)`)}catch(d){i.failed.push(`${l}:${c} (${d.message||d})`)}}return await t.put(Lt,new Date().toISOString()),fn(),i}async function It(e,t){let n=Date.now(),r=a=>t.put("geo:update_status",JSON.stringify({startedAt:n,...a})).catch(()=>{});try{await r({state:"updating",step:0,total:0,updated:0,failed:[],current:"",message:"\u5F00\u59CB\u66F4\u65B0"});let a=await Nt(e,t,s=>r({...s}));return await r({state:"done",step:a.total,total:a.total,updated:a.updated,failed:a.failed,current:"",message:"\u66F4\u65B0\u5B8C\u6210"}),await t.put("geo:updating","0").catch(()=>{}),a}catch(a){throw await r({state:"error",message:a.message||String(a),failed:[]}).catch(()=>{}),a}}async function za(e,t){if(e==="geosite"){let a=await rr(t,new Set);if(a.length===0)throw new Error("empty geosite rules");return a}let n=await qa(t),r=[];for(let[a,s]of n)if(a.length===4?r.push(...Za(a,s)):r.push(...Qa(a,s)),r.length>=3e4)break;if(r.length===0)throw new Error("empty geoip cidrs");return r}var Ba="https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/",Ga="https://cdn.jsdelivr.net/gh/v2fly/domain-list-community@master/data/",ja=2e4;function tr(e){let t=e.indexOf(".");return t>0?e.slice(0,t):e}async function Wa(){try{let e=await fetch("https://api.github.com/repos/v2fly/domain-list-community/git/trees/master?recursive=1",{headers:{"User-Agent":"vless-trojan-d1"},cf:{cacheTtl:86400}});if(e.ok){let t=await e.json(),n=t&&Array.isArray(t.tree)?t.tree:[],r=new Set;for(let a of n){if(!a||a.type!=="blob"||typeof a.path!="string"||!a.path.startsWith("data/"))continue;let s=a.path.slice(5);!s||s.includes("/")||r.add(tr(s))}if(r.size>0)return[...r].sort()}}catch{}try{let e=await fetch("https://api.github.com/repos/v2fly/domain-list-community/contents/data",{headers:{"User-Agent":"vless-trojan-d1"},cf:{cacheTtl:86400}});if(e.ok){let t=await e.json();if(Array.isArray(t)){let n=new Set;for(let r of t){if(!r||r.type!=="file"||typeof r.name!="string")continue;let a=tr(r.name);a&&n.add(a)}if(n.size>0)return[...n].sort()}}}catch{}return null}async function rr(e,t){if(t.has(e))return[];t.add(e);let n=encodeURIComponent(e),r=[Ba+n,Ga+n],a=null;for(let s of r)try{let o=await fetch(s,{cf:{cacheTtl:86400}});if(!o.ok){a=new Error(`HTTP ${o.status}`);continue}let i=await o.text(),u=[];for(let l of i.split(`
`)){if(l=l.trim(),!l||l.startsWith("#"))continue;if(l.startsWith("include:")){let h=l.slice(8).trim().split(/\s+/)[0];h&&u.push(...await rr(h,t));continue}let c=l;if(c.startsWith("full:"))c=c.slice(5);else if(c.startsWith("domain:"))c=c.slice(7);else if(c.startsWith("keyword:")||c.startsWith("regexp:"))continue;c=c.replace(/\s+@[^\s#]+/g,"");let d=c.indexOf("#");d>=0&&(c=c.slice(0,d)),c=c.trim().toLowerCase().replace(/^\.+/,""),c&&u.length<ja&&u.push(c)}return u}catch(o){a=o}throw a||new Error("v2fly geosite fetch failed")}var Va="https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/",Ka="https://cdn.jsdelivr.net/gh/SagerNet/sing-geoip@rule-set/",Ya=3e4;async function qa(e){let t=encodeURIComponent(e),n=[Va+"geoip-"+t+".srs",Ka+"geoip-"+t+".srs"],r=null;for(let a of n)try{let s=await fetch(a,{cf:{cacheTtl:86400}});if(!s.ok){r=new Error(`HTTP ${s.status}`);continue}let o=new Uint8Array(await s.arrayBuffer());if(o.length<5||o[0]!==83||o[1]!==82||o[2]!==83){r=new Error("bad srs magic");continue}if(o[3]>1){r=new Error(`unsupported srs version ${o[3]}`);continue}let i;try{i=Xn(o.subarray(4))}catch{r=new Error("zlib inflate failed");continue}return Ja(i)}catch(s){r=s}throw r||new Error("sing-geoip srs fetch failed")}function Ja(e){let t=0,n=dt(e,t);t=n.p;let r=[];for(let a=0;a<n.v;a++){let s=e[t++];if(s!==0)throw new Error(`geoip logical rule unsupported (type ${s})`);for(;;){let o=e[t++];if(o===255)break;if(o===5||o===6){if(e[t++]!==1)throw new Error("bad ipset version");let i=Xa(e,t);t+=8;for(let u=0;u<i&&r.length<Ya*2;u++){let l=dt(e,t);t=l.p;let c=e.subarray(t,t+l.v);t+=l.v,l=dt(e,t),t=l.p;let d=e.subarray(t,t+l.v);if(t+=l.v,c.length!==d.length||c.length!==4&&c.length!==16)throw new Error("bad ipset addr");r.push([c,d])}}else if(o===0||o===7||o===9){let i=dt(e,t);t=i.p,t+=i.v*2}else if(o===1||o===3||o===4||o===8||o===10||o===11||o===12||o===13||o===14||o===15||o===17||o===18||o===19||o===20||o===21||o===22||o===23){let i=dt(e,t);t=i.p;for(let u=0;u<i.v;u++){let l=dt(e,t);t=l.p,t+=l.v}}else throw new Error(`geoip unsupported item type ${o}`)}}return r}function dt(e,t){let n=0,r=0;for(;;){let a=e[t++];if(n|=(a&127)<<r,!(a&128))break;if(r+=7,r>63)throw new Error("uvarint overflow")}return{v:n,p:t}}function Xa(e,t){let n=0;for(let r=0;r<8;r++)n=n*256+e[t+r];return n}function Za(e,t){let n=(e[0]<<24>>>0)+(e[1]<<16)+(e[2]<<8)+e[3],r=(t[0]<<24>>>0)+(t[1]<<16)+(t[2]<<8)+t[3],a=[];for(;n<=r;){let s=0;for(;;){let o=1<<s+1;if((n&o-1)!==0||n+o-1>r)break;s++}a.push(`${n>>>24}.${n>>>16&255}.${n>>>8&255}.${n&255}/${32-s}`),n+=1<<s}return a}function Qa(e,t){let n=0n,r=0n;for(let s of e)n=n<<8n|BigInt(s);for(let s of t)r=r<<8n|BigInt(s);let a=[];for(;n<=r;){let s=0n;for(;;){let o=1n<<s+1n;if((n&o-1n)!==0n||n+o-1n>r)break;s++}a.push(`${ts(n)}/${128-Number(s)}`),n+=1n<<s}return a}function ts(e){let t=[];for(let i=7;i>=0;i--)t.push(Number(e>>BigInt(i*16)&0xffffn));let n=-1,r=0,a=-1,s=0;for(let i=0;i<8;i++)t[i]===0?(a<0&&(a=i),s++,s>r&&(r=s,n=a)):(a=-1,s=0);let o="";for(let i=0;i<8;i++)i===n&&r>=2?(o+=(o.length>0&&!o.endsWith(":"),"::"),i+=r-1):(o.length>0&&!o.endsWith(":")&&(o+=":"),o+=t[i].toString(16));return o}var er=!1;async function es(e){if(er)return;let t=[["path","TEXT DEFAULT ''"],["expire_at","INTEGER DEFAULT 0"],["traffic_limit","INTEGER DEFAULT 0"],["traffic_reset_at","INTEGER DEFAULT 0"]];for(let n of["vless_users","trojan_users"])try{let{results:r}=await e.prepare(`SELECT name FROM pragma_table_info('${n}')`).all(),a=new Set((r||[]).map(s=>s.name));for(let[s,o]of t)a.has(s)||(await e.prepare(`ALTER TABLE ${n} ADD COLUMN ${s} ${o}`).run(),console.log(`[admin] ${n}.${s} column added (migration)`))}catch(r){console.log(`[admin] ${n} migration skipped: ${r.message}`)}er=!0}var we=null;function ar(e){if(!e&&we)return we;let n=`<!DOCTYPE html>
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
      fields.map(([k,label])=>'<label style="display:block;font-size:13px;color:var(--muted);margin:10px 0 4px">'+label+'</label><input id="s_'+k+'" value="'+esc(s[k]||'')+'" style="width:100%;padding:8px 12px;border:1px solid var(--border);border-radius:8px">').join('')+
      '<div style="margin-top:16px"><button class="btn small" onclick="saveSettings()">\u4FDD\u5B58\u8BBE\u7F6E</button> <button class="btn small" onclick="testProxyIp()">proxyip \u6D4B\u8BD5</button> <button class="btn small" onclick="testUdp()">UDP \u6D4B\u8BD5</button></div>'+
      '<div id="testResult" style="margin-top:12px;font-size:13px;line-height:1.8"></div></div>';
    state.settings = s;
    renderThemeSeg();
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
</html>`;return e||(we=n),n}async function sr(e,t){let n=new URL(e.url);if(e.method==="POST"||e.method==="GET")try{let{DB:r,GEO_KV:a}=t,s=await Nt(r,a);return new Response(JSON.stringify({ok:!0,updated:s.updated,total:s.total,failed:s.failed}),{status:200,headers:{"Content-Type":"application/json; charset=utf-8"}})}catch(r){return new Response(JSON.stringify({ok:!1,error:r.message}),{status:500,headers:{"Content-Type":"application/json; charset=utf-8"}})}return new Response("Not Found",{status:404})}async function or(e,t,n){try{let r=await Nt(t.DB,t.GEO_KV);console.log(`[cron] geo update done: ${r.updated}/${r.total} categories${r.failed.length?", failed: "+r.failed.join("; "):""}`)}catch(r){console.log(`[cron] geo update failed: ${r.message}`)}}globalThis.connect=ns;var zo={async fetch(e,t,n){let a=new URL(e.url).pathname;try{if(a.startsWith("/admin")){let i=await mt(e,t,{ensureAdmin:!0});if(a.startsWith("/admin/api/"))return await nr(e,i,n);let u=ar(i.adminTempPassword),l=i.adminTempPassword?"no-store":"public, max-age=300";return new Response(u,{headers:{"Content-Type":"text/html; charset=utf-8","Cache-Control":l}})}if(a==="/geo-update-cron")return await sr(e,t);let s=await mt(e,t),o=s.inboundPathMap.get(a);if(o&&o.length>0){s._inboundScope=$t(o);let i=String(e.headers.get("Upgrade")||"").toLowerCase(),u=String(e.headers.get("Content-Type")||"").toLowerCase(),l=a.endsWith("/Tun")||u.includes("application/grpc");if(i==="websocket"&&!l){if(t.PROXY_DO){let c=t.PROXY_DO.newUniqueId();return await t.PROXY_DO.get(c).fetch(e)}return await kn(e,s,t)}if(l)return await Sn(e,s,t);if(e.method==="POST")return await En(e,s,t)}return await Dn(e,s,t)}catch(s){return console.log(`[index] error: ${s.message||s}`),new Response(JSON.stringify({error:"internal error"}),{status:500,headers:{"Content-Type":"application/json; charset=utf-8"}})}},async scheduled(e,t,n){return or(e,t,n)},async queue(e,t,n){for(let r of e.messages)try{if(await t.GEO_KV.get("geo:update_busy")==="1"){console.log("[queue] geo update already in progress, skip message"),r.ack();continue}await t.GEO_KV.put("geo:update_busy","1",{expirationTtl:7200});try{let s=await It(t.DB,t.GEO_KV);console.log(`[queue] geo update done: ${s.updated}/${s.total} categories${s.failed.length?", failed: "+s.failed.join("; "):""}`),r.ack()}finally{await t.GEO_KV.put("geo:update_busy","0").catch(()=>{})}}catch(a){throw console.log(`[queue] geo update failed (will retry): ${a.message||a}`),a}}};export{le as ProxySessionDO,zo as default};
