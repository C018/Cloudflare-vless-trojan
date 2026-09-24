/**
 * Admin UI: iOS settings style single-page app
 */

export function buildAdminUI(tempPassword) {
	const initPwdHtml = tempPassword
		? `<p style="margin:-8px 0 16px;padding:10px 12px;background:#e8f8ef;color:#1d7a3f;border-radius:10px;font-size:13px">首次部署初始密码：<b>${tempPassword}</b><br>登录后请及时修改</p>`
		: '';
	return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>节点管理后台</title>
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
    <h1>节点管理</h1>
    <p>请输入管理密码</p>
    ${initPwdHtml}
    <input type="password" id="loginPwd" placeholder="管理密码" autocomplete="current-password">
    <button class="btn" id="loginBtn">登 录</button>
  </div>
</div>

<div id="app" style="display:none">
  <aside class="sidebar">
    <h2>⚙️ 节点管理</h2>
    <div class="nav-item active" data-tab="stats">📊 流量统计</div>
    <div class="nav-item" data-tab="netstatus">📡 网络状态</div>
    <div class="nav-item" data-tab="vless">🔑 VLESS 用户</div>
    <div class="nav-item" data-tab="trojan">🛡️ Trojan 用户</div>
    <div class="nav-item" data-tab="outbounds">🌐 出站代理</div>
    <div class="nav-item" data-tab="entry">🚪 入口设置</div>
    <div class="nav-item" data-tab="rules">🧭 分流规则</div>
    <div class="nav-item" data-tab="settings">⚙️ 系统设置</div>
    <div class="nav-item" id="logoutBtn" style="margin-top:20px;color:var(--danger)">↩ 退出登录</div>
  </aside>
  <main class="main" id="mainContent"></main>
</div>

<div class="modal-mask" id="modalMask">
  <div class="modal">
    <h3 id="modalTitle"></h3>
    <div id="modalBody"></div>
    <div class="actions">
      <button class="btn small danger" onclick="closeModal()">取消</button>
      <button class="btn small" onclick="saveModal()">保存</button>
    </div>
  </div>
</div>

<div class="toast" id="toast"></div>

<script>
const $ = (s) => document.querySelector(s);
const state = { tab:'stats', editing:null, schema:null, records:[] };
const TAB_DEFS = {
  vless:   { title:'VLESS 用户', api:'vless-users', fields:[
    {k:'uuid',label:'UUID'},
    {k:'remark',label:'备注'},
    {k:'path',label:'入站路径',placeholder:'留空使用全局入站路径（如 /ws）'},
    {k:'expire_at',label:'到期时间',type:'datetime-local'},
    {k:'traffic_limit',label:'流量限制(GB)',type:'number',placeholder:'0=不限'},
    {k:'traffic_reset_at',label:'流量重置时间',type:'datetime-local',placeholder:'到此后自动清零已用流量'},
    {k:'enable',label:'启用',type:'checkbox'},
    {k:'status',label:'状态',type:'status'}
  ]},
  trojan:  { title:'Trojan 用户', api:'trojan-users', fields:[
    {k:'password',label:'密码'},
    {k:'remark',label:'备注'},
    {k:'path',label:'入站路径',placeholder:'留空使用全局入站路径（如 /ws）'},
    {k:'expire_at',label:'到期时间',type:'datetime-local'},
    {k:'traffic_limit',label:'流量限制(GB)',type:'number',placeholder:'0=不限'},
    {k:'traffic_reset_at',label:'流量重置时间',type:'datetime-local',placeholder:'到此后自动清零已用流量'},
    {k:'enable',label:'启用',type:'checkbox'},
    {k:'status',label:'状态',type:'status'}
  ]},
  outbounds:{ title:'出站代理', api:'outbounds', fields:[{k:'type',label:'类型',type:'select',opts:['socks5','http','vless']},{k:'name',label:'名称'},{k:'address',label:'地址'},{k:'port',label:'端口',type:'number'},{k:'username',label:'用户名(仅socks5/http)'},{k:'password',label:'密码(仅socks5/http)'},{k:'uuid',label:'UUID(仅vless)'},{k:'transport',label:'传输(仅vless)',type:'select',opts:['raw','ws','grpc','httpupgrade','h2']},{k:'path',label:'Path(仅vless; grpc 为 serviceName)',placeholder:'ws/httpupgrade/h2 填路径; grpc 填 serviceName(留空为 /Tun)'},{k:'tls',label:'TLS',type:'checkbox'},{k:'sni',label:'SNI(仅vless)',placeholder:'留空则使用地址作为连接主机与SNI'},{k:'udp',label:'UDP',type:'checkbox'},{k:'enable',label:'启用',type:'checkbox'},{k:'sort',label:'排序',type:'number'}] },
  rules:   { title:'分流规则', api:'routing-rules', fields:[{k:'rule',label:'规则(geosite:cn / geoip:cn / domain: / full: / keyword: / ip-cidr: / regexp:)'},{k:'outbound',label:'出站(direct / reject / 出站名)'},{k:'enable',label:'启用',type:'checkbox'},{k:'sort',label:'排序',type:'number'}] }
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
  try { await api('/admin/api/login',{method:'POST',body:JSON.stringify({password:pwd})}); showApp(); toast('登录成功'); }
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
  if (tab==='stats'){ mc.innerHTML = '<div class="page-title">流量统计</div><div class="card">加载中...</div>'; await loadStats(); return; }
  if (tab==='netstatus'){ mc.innerHTML = '<div class="page-title">网络状态</div><div class="card" style="padding:12px 16px;font-size:13px;color:var(--muted)">检测按项目网络设置发起（分流规则 + 默认出站 + proxyip + 出站隧道），多目标并行、每目标 16 次采样，约 10-15 秒完成。绿色=正常，黄色/橙色=高延迟，灰色=超时/失败。</div><div class="toolbar"><button class="btn small" onclick="runNetstatus()">开始检测</button></div><div class="net-grid" id="netGrid"></div>'; runNetstatus(); return; }
  if (tab==='settings'){ mc.innerHTML = '<div class="page-title">系统设置</div><div class="card">加载中...</div>'; await loadSettings(); return; }
  if (tab==='entry'){ mc.innerHTML = '<div class="page-title">入口设置</div><div class="card">加载中...</div>'; await loadEntry(); return; }
  const def = TAB_DEFS[tab];
  mc.innerHTML = '<div class="page-title">'+def.title+'</div><div class="toolbar"><button class="btn small" onclick="openNew()">＋ 新增</button></div><div class="card"><div class="table-wrap"><table><thead><tr>'+def.fields.map(f=>'<th>'+f.label+'</th>').join('')+'<th>操作</th></tr></thead><tbody id="tbody"></tbody></table></div></div>';
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
      if (f.type==='checkbox') return '<td>'+(r[f.k]? '<span class="badge on">开</span>':'<span class="badge off">关</span>')+'</td>';
      if (f.type==='status') return statusCell(r);
      if (f.k==='uuid'||f.k==='password') return '<td class="mono">'+esc(r[f.k])+'</td>';
      return '<td>'+esc(r[f.k])+'</td>';
    }).join('');
    const testBtn = def.api==='outbounds' ? '<button class="btn small" onclick="testOutbound('+idx+', event)">测试</button> ' : '';
    return '<tr>'+tds+'<td>'+testBtn+'<button class="btn small" onclick="openEdit('+idx+')">编辑</button> <button class="btn small danger" onclick="delRow('+idx+')">删除</button></td></tr>';
  }).join('') || '<tr><td colspan="99" style="text-align:center;color:var(--muted)">暂无数据</td></tr>';
}

function statusCell(r){
  const used = Number(r.up||0) + Number(r.down||0);
  const limit = Number(r.traffic_limit||0);
  const exp = Number(r.expire_at||0);
  const now = Math.floor(Date.now()/1000);
  let badge = '<span class="badge on">正常</span>';
  if (exp>0 && exp<now) badge = '<span class="badge off">已到期</span>';
  else if (limit>0 && used>=limit) badge = '<span class="badge off">已超限</span>';
  const quota = limit>0 ? (fmtBytes(limit)) : '∞';
  return '<td>'+badge+'<div style="font-size:11px;color:var(--muted);margin-top:2px">已用 '+fmtBytes(used)+' / '+quota+'</div></td>';
}

function esc(s){ return String(s==null?'':s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }

function openNew(){ state.editing=null; openModal({}); }
function openEdit(idx){ state.editing = state.records[idx]; openModal(state.editing); }

// 出站表单按类型显示的字段集合（socks5/http 显示认证，隐藏 uuid/path/tls/sni/udp；vless 反之）
const OUTBOUND_TYPE_FIELDS = {
  socks5: ['type','name','address','port','username','password','enable','sort'],
  http:   ['type','name','address','port','username','password','enable','sort'],
  vless:  ['type','name','address','port','uuid','transport','path','tls','sni','udp','enable','sort'],
};

function openModal(record){
  const def = state.schema;
  state.draft = Object.assign({}, record);
  $('#modalTitle').textContent = state.editing ? '编辑' : '新增';
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
  // 出站：仅发送当前类型可见字段；socks5/http 不支持 UDP，强制 udp=0
  if (def.api === 'outbounds'){
    const t = state.draft.type || 'socks5';
    const allowed = OUTBOUND_TYPE_FIELDS[t] || OUTBOUND_TYPE_FIELDS.socks5;
    for (const k of Object.keys(body)) if (allowed.indexOf(k) === -1) delete body[k];
    if (t === 'socks5' || t === 'http') body.udp = 0;
  }
  try {
    if (state.editing) await api('/admin/api/'+def.api+'/'+state.editing.id,{method:'PUT',body:JSON.stringify(body)});
    else await api('/admin/api/'+def.api,{method:'POST',body:JSON.stringify(body)});
    closeModal(); await loadList(); toast('已保存');
  } catch(e){ toast(e.message); }
}

async function delRow(idx){
  const def = state.schema; const r = state.records[idx];
  if (!confirm('确认删除该记录？')) return;
  try { await api('/admin/api/'+def.api+'/'+r.id,{method:'DELETE'}); await loadList(); toast('已删除'); }
  catch(e){ toast(e.message); }
}

function closeModal(){ $('#modalMask').classList.remove('show'); }

async function loadStats(){
  const mc = $('#mainContent');
  try {
    const d = await api('/admin/api/stats');
    mc.innerHTML = '<div class="page-title">流量统计</div>'+
      statBlock('VLESS 用户', d.vless) + statBlock('Trojan 用户', d.trojan);
  } catch(e){ mc.innerHTML = '<div class="page-title">流量统计</div><div class="card">加载失败: '+esc(e.message)+'</div>'; }
}
function statBlock(title, rows){
  const items = rows.map(r=>{
    const used = Number(r.used || 0);
    const remaining = r.remaining;
    const limit = Number(r.traffic_limit||0);
    let badge = '<span class="badge">不限流量</span>';
    if (r.expired) badge = '<span class="badge off">已到期</span>';
    else if (r.limitReached) badge = '<span class="badge off">已超限</span>';
    else if (remaining!==null) badge = '<span class="badge on">剩余 '+fmtBytes(remaining)+'</span>';
    const expTxt = r.expire_at ? fmtDate(r.expire_at) : '永久';
    const quotaTxt = limit>0 ? (' / '+fmtBytes(limit)) : '';
    return '<div class="stat-item"><div class="num">'+fmtBytes(used)+'</div><div class="lbl">'+esc(r.remark||r.uuid||r.password)+'</div>'+
      '<div class="lbl" style="font-size:11px">↑ '+fmtBytes(r.up||0)+' ↓ '+fmtBytes(r.down||0)+quotaTxt+'</div>'+
      '<div style="margin-top:6px">'+badge+'</div>'+
      '<div class="lbl" style="font-size:11px;margin-top:2px">到期 '+expTxt+(r.traffic_reset_at? ' · 重置 '+fmtDate(r.traffic_reset_at):'')+'</div></div>';
  }).join('');
  return '<h3 style="margin:16px 0 12px;font-size:18px">'+title+'</h3><div class="stat-grid">'+(items||'<div class="card">暂无数据</div>')+'</div>';
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
      ['ws_path','入站路径（ws / grpc / h2 共享；用户未自定义路径时回退到此值）'],
      ['default_outbound','默认出站 (direct / 出站名)'],
      ['proxyip','proxyip（代理 IP 或域名[:端口]，访问 Cloudflare 及开 CF CDN 网站使用；仅默认出站为 direct 时生效）'],
      ['udp_outbound','UDP 出站代理（出站名，仅 vless 支持 UDP）'],
      ['disguise_title','伪装页标题'],
      ['disguise_subtitle','伪装页副标题'],
    ];
    mc.innerHTML = '<div class="page-title">系统设置</div>'+
      '<div class="card" style="background:#e8f8ef;color:#1d7a3f;font-size:13px;border-radius:10px;padding:12px 16px;margin-bottom:16px">入站已自动兼容 ws / grpc / h2 三种传输类型（同一凭据同时可用）。此处仅需设置共享入站路径；单个用户可在「VLESS 用户 / Trojan 用户」中自定义路径，留空则使用本全局路径。</div>'+
      '<div class="card">'+
      fields.map(([k,label])=>'<label style="display:block;font-size:13px;color:var(--muted);margin:10px 0 4px">'+label+'</label><input id="s_'+k+'" value="'+esc(s[k]||'')+'" style="width:100%;padding:8px 12px;border:1px solid var(--border);border-radius:8px">').join('')+
      '<div style="margin-top:16px"><button class="btn small" onclick="saveSettings()">保存设置</button> <button class="btn small" onclick="updateGeo()">更新 Geo 规则库</button> <button class="btn small" onclick="testProxyIp()">proxyip 测试</button> <button class="btn small" onclick="testUdp()">UDP 测试</button></div>'+
      '<div id="testResult" style="margin-top:12px;font-size:13px;line-height:1.8"></div></div>';
    state.settings = s;
  } catch(e){ mc.innerHTML = '<div class="page-title">系统设置</div><div class="card">加载失败: '+esc(e.message)+'</div>'; }
}

async function saveSettings(){
  const body = {};
  document.querySelectorAll('#mainContent input[id^=s_]').forEach(el=>{ body[el.id.slice(2)] = el.value; });
  try { await api('/admin/api/settings',{method:'PUT',body:JSON.stringify(body)}); toast('设置已保存'); }
  catch(e){ toast(e.message); }
}

async function loadEntry(){
  const mc = $('#mainContent');
  try {
    const s = await api('/admin/api/settings');
    const fields = [
      ['entry_host','入口 IP / 域名'],
      ['entry_port','入口端口（默认 443）'],
      ['entry_sni','入口 SNI'],
      ['entry_ws_host','入口 Host（Host 头）'],
    ];
    mc.innerHTML = '<div class="page-title">入口设置</div>'+
      '<div class="card" style="background:#e8f8ef;color:#1d7a3f;font-size:13px;border-radius:10px;padding:12px 16px;margin-bottom:16px">入站已自动支持 ws / grpc / h2 全类型传输（同一凭据自动分发），无需再选择传输模式。设置入口后，节点/订阅将使用入口 IP/域名、端口、SNI、Host 生成配置（不再使用当前域名）；未设置则使用当前域名。</div>'+
      '<div class="card">'+
      fields.map(([k,label])=>{
        return '<label style="display:block;font-size:13px;color:var(--muted);margin:10px 0 4px">'+label+'</label><input id="s_'+k+'" value="'+esc(s[k]||'')+'" style="width:100%;padding:8px 12px;border:1px solid var(--border);border-radius:8px" placeholder="'+(k==='entry_port'?'443':'')+'">';
      }).join('')+
      '<div style="margin-top:16px"><button class="btn small" onclick="saveEntry()">保存入口设置</button></div></div>';
  } catch(e){ mc.innerHTML = '<div class="page-title">入口设置</div><div class="card">加载失败: '+esc(e.message)+'</div>'; }
}

async function saveEntry(){
  const body = {};
  document.querySelectorAll('#mainContent input[id^=s_], #mainContent select[id^=s_]').forEach(el=>{ body[el.id.slice(2)] = el.value; });
  try { await api('/admin/api/settings',{method:'PUT',body:JSON.stringify(body)}); toast('入口设置已保存'); }
  catch(e){ toast(e.message); }
}

async function updateGeo(){
  try {
    const d = await api('/admin/api/geo/update',{method:'POST',body:'{}'});
    const msg = '已更新 '+d.updated+' / '+d.total+' 个分类' + ((d.failed && d.failed.length) ? ('；失败: '+d.failed.join(', ')) : '');
    toast(msg);
  }
  catch(e){ toast('更新失败: '+e.message); }
}

// ---- 网络状态 ----
async function runNetstatus(){
  const grid = $('#netGrid');
  if (!grid) return;
  grid.innerHTML = '<div class="card" style="grid-column:1/-1">检测中，请稍候…（多目标并行采样，约 10-15 秒）</div>';
  try {
    const d = await api('/admin/api/netstatus/test',{method:'POST',body:'{}'});
    renderNetCards(grid, d.targets || []);
  } catch(e){ grid.innerHTML = '<div class="card" style="grid-column:1/-1">检测失败: '+esc(e.message)+'</div>'; }
}
function renderNetCards(grid, targets){
  grid.innerHTML = targets.map(t=>{
    const region = t.region==='cn' ? '<span class="badge">国内</span>' : '<span class="badge on">国际</span>';
    const lat = (t.latency===null || t.latency===undefined)
      ? '<div class="net-latency fail">超时 / 失败</div>'
      : '<div class="net-latency">'+t.latency+'<span class="unit">ms</span></div>';
    const dots = (t.samples||[]).map(s=>dotCls(s)).join('');
    return '<div class="net-card"><div class="net-head"><span class="net-icon">'+esc(t.icon||'')+'</span><span class="net-name">'+esc(t.name||t.host||'')+'</span>'+region+'</div>'+lat+'<div class="net-dots">'+dots+'</div><div class="net-foot"><span>'+(t.success||0)+'/'+(t.total||0)+' 成功</span><span class="mono">'+esc(t.host||'')+'</span></div></div>';
  }).join('');
}
function dotCls(ms){
  if (ms===null || ms===undefined) return '<span class="net-dot"></span>';
  if (ms < 200) return '<span class="net-dot ok"></span>';
  if (ms < 500) return '<span class="net-dot warn"></span>';
  return '<span class="net-dot bad"></span>';
}

// ---- 系统设置：proxyip / UDP 测试 ----
async function testProxyIp(){
  const el = $('#testResult'); if (!el) return;
  el.innerHTML = 'proxyip 测试中…（连接 proxyip 裸 TCP 探测 Cloudflare 站点）';
  try {
    const r = await api('/admin/api/test/proxyip',{method:'POST',body:'{}'});
    el.innerHTML = r.ok
      ? '<span style="color:#34c759">proxyip 可用，延迟 '+r.latency+' ms</span>（'+esc(r.endpoint||'')+'）'
      : '<span style="color:var(--danger)">proxyip 不可用：'+esc(r.error||'')+'</span>';
  } catch(e){ el.innerHTML = '<span style="color:var(--danger)">proxyip 测试失败：'+esc(e.message)+'</span>'; }
}
async function testUdp(){
  const el = $('#testResult'); if (!el) return;
  el.innerHTML = 'UDP 测试中…（经 UDP 出站向 1.1.1.1:53 发起 DNS 查询）';
  try {
    const r = await api('/admin/api/test/udp',{method:'POST',body:'{}'});
    el.innerHTML = r.ok
      ? '<span style="color:#34c759">UDP 可用，延迟 '+r.latency+' ms</span>'
      : '<span style="color:var(--danger)">UDP 不可用：'+esc(r.error||'')+'</span>';
  } catch(e){ el.innerHTML = '<span style="color:var(--danger)">UDP 测试失败：'+esc(e.message)+'</span>'; }
}

// ---- 出站代理测试 ----
async function testOutbound(idx, ev){
  const r = state.records[idx];
  const btn = ev && ev.target;
  if (btn){ btn.disabled = true; btn.textContent = '测试中…'; }
  try {
    const res = await api('/admin/api/test/outbound/'+r.id,{method:'POST',body:'{}'});
    toast(res.ok ? ('出站可用，延迟 '+res.latency+' ms') : ('出站不可用：'+(res.error||'未知错误')));
  } catch(e){ toast('出站测试失败：'+e.message); }
  if (btn){ btn.disabled = false; btn.textContent = '测试'; }
}

// 初始：检查登录态
(async function init(){
  try { await api('/admin/api/settings'); showApp(); }
  catch(e){ showLogin(); }
})();
</script>
</body>
</html>`;
}
