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
    <div class="nav-item" data-tab="vless">🔑 VLESS 用户</div>
    <div class="nav-item" data-tab="trojan">🛡️ Trojan 用户</div>
    <div class="nav-item" data-tab="outbounds">🌐 出站代理</div>
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
  vless:   { title:'VLESS 用户', api:'vless-users', fields:[{k:'uuid',label:'UUID'},{k:'remark',label:'备注'},{k:'enable',label:'启用',type:'checkbox'}] },
  trojan:  { title:'Trojan 用户', api:'trojan-users', fields:[{k:'password',label:'密码'},{k:'remark',label:'备注'},{k:'enable',label:'启用',type:'checkbox'}] },
  outbounds:{ title:'出站代理', api:'outbounds', fields:[{k:'type',label:'类型',type:'select',opts:['socks5','http','vless']},{k:'name',label:'名称'},{k:'address',label:'地址'},{k:'port',label:'端口',type:'number'},{k:'uuid',label:'UUID(仅vless)'},{k:'path',label:'Path(仅vless)'},{k:'tls',label:'TLS',type:'checkbox'},{k:'udp',label:'UDP',type:'checkbox'},{k:'enable',label:'启用',type:'checkbox'},{k:'sort',label:'排序',type:'number'}] },
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
  if (tab==='settings'){ mc.innerHTML = '<div class="page-title">系统设置</div><div class="card">加载中...</div>'; await loadSettings(); return; }
  const def = TAB_DEFS[tab];
  mc.innerHTML = '<div class="page-title">'+def.title+'</div><div class="toolbar"><button class="btn small" onclick="openNew()">＋ 新增</button></div><div class="card"><table><thead><tr>'+def.fields.map(f=>'<th>'+f.label+'</th>').join('')+'<th>操作</th></tr></thead><tbody id="tbody"></tbody></table></div>';
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
      if (f.k==='uuid'||f.k==='password') return '<td class="mono">'+esc(r[f.k])+'</td>';
      return '<td>'+esc(r[f.k])+'</td>';
    }).join('');
    return '<tr>'+tds+'<td><button class="btn small" onclick="openEdit('+idx+')">编辑</button> <button class="btn small danger" onclick="delRow('+idx+')">删除</button></td></tr>';
  }).join('') || '<tr><td colspan="99" style="text-align:center;color:var(--muted)">暂无数据</td></tr>';
}

function esc(s){ return String(s==null?'':s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }

function openNew(){ state.editing=null; openModal({}); }
function openEdit(idx){ state.editing = state.records[idx]; openModal(state.editing); }

function openModal(record){
  const def = state.schema;
  $('#modalTitle').textContent = state.editing ? '编辑' : '新增';
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
  const items = rows.map(r=>'<div class="stat-item"><div class="num">'+fmtBytes((r.up||0)+(r.down||0))+'</div><div class="lbl">'+esc(r.remark||r.uuid||r.password)+'</div><div class="lbl" style="font-size:11px">↑ '+fmtBytes(r.up||0)+' ↓ '+fmtBytes(r.down||0)+'</div></div>').join('');
  return '<h3 style="margin:16px 0 12px;font-size:18px">'+title+'</h3><div class="stat-grid">'+(items||'<div class="card">暂无数据</div>')+'</div>';
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
      ['ws_path','WebSocket 路径'],
      ['default_outbound','默认出站 (direct / 出站名)'],
      ['disguise_title','伪装页标题'],
      ['disguise_subtitle','伪装页副标题'],
      ['cdnip','CDN IP'],
      ['proxyip','中转 IP'],
      ['ip1','优选IP 1'],['pt1','优选端口 1'],['ip2','优选IP 2'],['pt2','优选端口 2'],
      ['ip3','优选IP 3'],['pt3','优选端口 3'],['ip4','优选IP 4'],['pt4','优选端口 4'],
      ['ip5','优选IP 5'],['pt5','优选端口 5'],['ip6','优选IP 6'],['pt6','优选端口 6'],
      ['ip7','优选IP 7'],['pt7','优选端口 7'],['ip8','优选IP 8'],['pt8','优选端口 8'],
      ['ip9','优选IP 9'],['pt9','优选端口 9'],['ip10','优选IP 10'],['pt10','优选端口 10'],
      ['ip11','优选IP 11'],['pt11','优选端口 11'],['ip12','优选IP 12'],['pt12','优选端口 12'],
      ['ip13','优选IP 13'],['pt13','优选端口 13']
    ];
    mc.innerHTML = '<div class="page-title">系统设置</div><div class="card">'+
      fields.map(([k,label])=>'<label style="display:block;font-size:13px;color:var(--muted);margin:10px 0 4px">'+label+'</label><input id="s_'+k+'" value="'+esc(s[k]||'')+'" style="width:100%;padding:8px 12px;border:1px solid var(--border);border-radius:8px">').join('')+
      '<div style="margin-top:16px"><button class="btn small" onclick="saveSettings()">保存设置</button> <button class="btn small" onclick="updateGeo()">更新 Geo 规则库</button></div></div>';
    state.settings = s;
  } catch(e){ mc.innerHTML = '<div class="page-title">系统设置</div><div class="card">加载失败: '+esc(e.message)+'</div>'; }
}

async function saveSettings(){
  const body = {};
  document.querySelectorAll('#mainContent input[id^=s_]').forEach(el=>{ body[el.id.slice(2)] = el.value; });
  try { await api('/admin/api/settings',{method:'PUT',body:JSON.stringify(body)}); toast('设置已保存'); }
  catch(e){ toast(e.message); }
}

async function updateGeo(){
  try { const d = await api('/admin/api/geo/update',{method:'POST',body:'{}'}); toast('已更新 '+d.updated+' 个分类'); }
  catch(e){ toast('更新失败: '+e.message); }
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
