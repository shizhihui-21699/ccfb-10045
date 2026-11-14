// Admin UI: single-page app served at /.
export function renderUI(): string {
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<title>SSH CA 管理</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
  :root { --bg:#0f1420; --panel:#1a2233; --border:#2a3550; --fg:#dbe4f5; --dim:#8b98b5;
          --accent:#4f8cff; --ok:#3ecf8e; --warn:#f5a623; --bad:#ef5b6b; }
  * { box-sizing:border-box; }
  body { margin:0; font:14px/1.5 -apple-system,"SF Pro Text","PingFang SC",sans-serif;
         background:var(--bg); color:var(--fg); }
  header { padding:14px 24px; border-bottom:1px solid var(--border); display:flex;
           align-items:center; gap:16px; flex-wrap:wrap; }
  header h1 { font-size:17px; margin:0; }
  header .spacer { flex:1; }
  input,select,textarea,button { font:inherit; color:var(--fg); background:#121a2b;
         border:1px solid var(--border); border-radius:6px; padding:7px 10px; }
  textarea { width:100%; font-family:ui-monospace,Menlo,monospace; font-size:12px; }
  button { background:var(--accent); border-color:var(--accent); color:#fff; cursor:pointer; }
  button.ghost { background:transparent; color:var(--fg); }
  button.danger { background:var(--bad); border-color:var(--bad); }
  button:disabled { opacity:.5; cursor:default; }
  nav { display:flex; gap:4px; padding:10px 24px 0; }
  nav button { background:transparent; border:none; color:var(--dim); padding:8px 12px;
               border-bottom:2px solid transparent; border-radius:0; }
  nav button.active { color:var(--fg); border-bottom-color:var(--accent); }
  main { padding:20px 24px; max-width:1200px; }
  .panel { background:var(--panel); border:1px solid var(--border); border-radius:10px;
           padding:16px; margin-bottom:16px; }
  table { width:100%; border-collapse:collapse; font-size:13px; }
  th,td { text-align:left; padding:8px 10px; border-bottom:1px solid var(--border);
          vertical-align:top; }
  th { color:var(--dim); font-weight:600; white-space:nowrap; }
  td.mono,.mono { font-family:ui-monospace,Menlo,monospace; font-size:12px; }
  .tag { display:inline-block; padding:1px 8px; border-radius:99px; font-size:12px; }
  .tag.user { background:#1d3a6e; } .tag.host { background:#4a2d6e; }
  .tag.pending { background:#6e551d; } .tag.approved { background:#1d5e41; }
  .tag.rejected,.tag.revoked { background:#6e1d28; }
  .row { display:flex; gap:12px; flex-wrap:wrap; margin-bottom:10px; }
  .row > label { flex:1 1 220px; display:flex; flex-direction:column; gap:4px;
                 color:var(--dim); font-size:12px; }
  .row > label > input,.row > label > select { width:100%; }
  .muted { color:var(--dim); } .ok { color:var(--ok); } .bad { color:var(--bad); }
  #toast { position:fixed; right:20px; bottom:20px; padding:10px 16px; border-radius:8px;
           background:var(--panel); border:1px solid var(--border); display:none; max-width:480px; }
  pre { background:#0b101c; border:1px solid var(--border); border-radius:8px;
        padding:10px; overflow:auto; font-size:12px; }
</style>
</head>
<body>
<header>
  <h1>🔐 SSH CA</h1>
  <span class="muted" id="whoami"></span>
  <span class="spacer"></span>
  <input id="token" placeholder="Bearer token" size="36" type="password">
  <button class="ghost" onclick="saveToken()">保存令牌</button>
</header>
<nav>
  <button data-tab="pending" class="active" onclick="showTab('pending')">待审批 <span id="pendingCount"></span></button>
  <button data-tab="new" onclick="showTab('new')">新申请</button>
  <button data-tab="certs" onclick="showTab('certs')">证书</button>
  <button data-tab="krl" onclick="showTab('krl')">吊销 / KRL</button>
  <button data-tab="audit" onclick="showTab('audit')">审计</button>
  <button data-tab="ca" onclick="showTab('ca')">CA 信息</button>
</nav>
<main>
  <section id="tab-pending" class="tab"></section>
  <section id="tab-new" class="tab" style="display:none">
    <div class="panel">
      <h3>提交证书申请</h3>
      <div class="row">
        <label>类型
          <select id="f-type"><option value="user">用户证书</option><option value="host">主机证书</option></select>
        </label>
        <label>签名 CA
          <select id="f-ca"><option value="ed25519">ed25519（默认）</option><option value="nistp256">ecdsa nistp256</option></select>
        </label>
        <label>有效期（秒，留空用默认）<input id="f-ttl" placeholder="如 28800"></label>
      </div>
      <div class="row">
        <label>Principals（逗号分隔，用户证书填登录名，主机证书填主机名）
          <input id="f-principals" placeholder="alice,ops">
        </label>
        <label>Key ID（可选）<input id="f-keyid"></label>
      </div>
      <div class="row">
        <label>force-command（可选，用户证书）<input id="f-forcecmd" placeholder="/usr/bin/rrsync /backup"></label>
        <label>source-address（可选，逗号分隔 CIDR）<input id="f-srcaddr" placeholder="10.0.0.0/8,192.168.0.0/16"></label>
      </div>
      <div class="row">
        <label>扩展（逗号分隔）
          <input id="f-exts" value="permit-pty,permit-agent-forwarding,permit-port-forwarding">
        </label>
        <label>备注<input id="f-comment" placeholder="工单号 / 用途"></label>
      </div>
      <label class="muted" style="font-size:12px">公钥（authorized_keys 格式，ssh-ed25519 / ecdsa-sha2-nistp256 / ssh-rsa）</label>
      <textarea id="f-pubkey" rows="3" placeholder="ssh-ed25519 AAAA... user@host"></textarea>
      <div style="margin-top:10px"><button onclick="submitRequest()">提交申请</button></div>
    </div>
  </section>
  <section id="tab-certs" class="tab" style="display:none"></section>
  <section id="tab-krl" class="tab" style="display:none"></section>
  <section id="tab-audit" class="tab" style="display:none"></section>
  <section id="tab-ca" class="tab" style="display:none"></section>
</main>
<div id="toast"></div>
<script>
const $ = (id) => document.getElementById(id);
const tokenInput = $('token');
tokenInput.value = localStorage.getItem('sshca.token') || '';

function saveToken() { localStorage.setItem('sshca.token', tokenInput.value.trim()); toast('令牌已保存'); refresh(); }
function token() { return localStorage.getItem('sshca.token') || ''; }

async function api(path, opts = {}) {
  const res = await fetch(path, {
    ...opts,
    headers: { 'authorization': 'Bearer ' + token(), 'content-type': 'application/json', ...(opts.headers || {}) },
  });
  if (!res.ok) {
    let msg = res.status + ' ' + res.statusText;
    try { msg = (await res.json()).error || msg; } catch {}
    throw new Error(msg);
  }
  const ct = res.headers.get('content-type') || '';
  return ct.includes('json') ? res.json() : res.text();
}

function toast(msg, bad) {
  const t = $('toast');
  t.textContent = msg;
  t.style.borderColor = bad ? 'var(--bad)' : 'var(--ok)';
  t.style.display = 'block';
  setTimeout(() => t.style.display = 'none', 3500);
}

const fmtTime = (s) => s ? new Date(s * 1000).toLocaleString() : '-';
const esc = (s) => String(s ?? '').replace(/[&<>"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));

function showTab(name) {
  document.querySelectorAll('.tab').forEach(el => el.style.display = 'none');
  document.querySelectorAll('nav button').forEach(b => b.classList.toggle('active', b.dataset.tab === name));
  $('tab-' + name).style.display = 'block';
  refresh();
}

async function refresh() {
  const active = document.querySelector('nav button.active').dataset.tab;
  try {
    if (active === 'pending') await renderPending();
    else if (active === 'certs') await renderCerts();
    else if (active === 'krl') await renderKrl();
    else if (active === 'audit') await renderAudit();
    else if (active === 'ca') await renderCa();
  } catch (e) { toast(e.message, true); }
}

async function renderPending() {
  const { requests } = await api('/api/requests?status=pending');
  $('pendingCount').textContent = requests.length ? '(' + requests.length + ')' : '';
  $('tab-pending').innerHTML = '<div class="panel"><h3>待审批申请</h3>' +
    (requests.length ? '<table><tr><th>类型</th><th>申请人</th><th>Principals</th><th>指纹</th><th>有效期</th><th>关键选项</th><th>备注</th><th></th></tr>' +
    requests.map(r => '<tr>' +
      '<td><span class="tag ' + r.kind + '">' + r.kind + '</span></td>' +
      '<td>' + esc(r.requestedBy) + '<br><span class="muted">' + fmtTime(r.requestedAt) + '</span></td>' +
      '<td class="mono">' + esc(r.principals.join(', ')) + '</td>' +
      '<td class="mono">' + esc(r.fingerprint) + '</td>' +
      '<td class="muted">' + fmtTime(r.validAfter) + '<br>→ ' + fmtTime(r.validBefore) + '</td>' +
      '<td class="mono">' + esc([r.criticalOptions.forceCommand && 'force-command=' + r.criticalOptions.forceCommand,
        r.criticalOptions.sourceAddress && 'source-address=' + r.criticalOptions.sourceAddress.join(',')]
        .filter(Boolean).join('\\n') || '-') + '</td>' +
      '<td>' + esc(r.comment || '-') + '</td>' +
      '<td style="white-space:nowrap">' +
        '<button onclick="approve(\\'' + r.id + '\\')">批准</button> ' +
        '<button class="danger" onclick="rejectReq(\\'' + r.id + '\\')">拒绝</button></td>' +
      '</tr>').join('') + '</table>' : '<p class="muted">没有待审批的申请。</p>') + '</div>';
}

async function approve(id) {
  try { await api('/api/requests/' + id + '/approve', { method: 'POST', body: '{}' }); toast('已签发'); refresh(); }
  catch (e) { toast(e.message, true); }
}
async function rejectReq(id) {
  const reason = prompt('拒绝原因：') || '';
  try { await api('/api/requests/' + id + '/reject', { method: 'POST', body: JSON.stringify({ reason }) }); toast('已拒绝'); refresh(); }
  catch (e) { toast(e.message, true); }
}

async function renderCerts() {
  const { certs } = await api('/api/certs');
  $('tab-certs').innerHTML = '<div class="panel"><h3>已签发证书</h3>' +
    (certs.length ? '<table><tr><th>Serial</th><th>类型</th><th>Key ID</th><th>Principals</th><th>签发</th><th>有效期至</th><th>状态</th><th></th></tr>' +
    certs.slice().reverse().map(c => '<tr>' +
      '<td class="mono">' + c.serial + '</td>' +
      '<td><span class="tag ' + c.kind + '">' + c.kind + '</span></td>' +
      '<td class="mono">' + esc(c.keyId) + '</td>' +
      '<td class="mono">' + esc(c.principals.join(', ')) + '</td>' +
      '<td>' + esc(c.issuedBy) + '<br><span class="muted">' + fmtTime(c.issuedAt) + '</span></td>' +
      '<td class="muted">' + fmtTime(c.validBefore) + '</td>' +
      '<td>' + (c.revoked ? '<span class="tag revoked">已吊销</span>' : '<span class="ok">有效</span>') + '</td>' +
      '<td style="white-space:nowrap"><button class="ghost" onclick="downloadCert(\\'' + c.serial + '\\')">下载</button> ' +
      (c.revoked ? '' : '<button class="danger" onclick="revoke(\\'' + c.serial + '\\')">吊销</button>') + '</td>' +
      '</tr>').join('') + '</table>' : '<p class="muted">还没有签发过证书。</p>') + '</div>';
}

async function downloadCert(serial) {
  try {
    const text = await api('/api/certs/' + serial + '/cert.pub');
    const blob = new Blob([text], { type: 'text/plain' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'cert-' + serial + '.pub';
    a.click();
  } catch (e) { toast(e.message, true); }
}

async function revoke(serial) {
  const reason = prompt('吊销原因：') || '';
  if (!confirm('确认吊销 serial=' + serial + '？吊销后记得让各服务器更新 KRL。')) return;
  try { await api('/api/certs/' + serial + '/revoke', { method: 'POST', body: JSON.stringify({ reason }) }); toast('已吊销'); refresh(); }
  catch (e) { toast(e.message, true); }
}

async function renderKrl() {
  const { certs } = await api('/api/certs');
  const revoked = certs.filter(c => c.revoked);
  $('tab-krl').innerHTML =
    '<div class="panel"><h3>吊销列表（KRL）</h3>' +
    '<p class="muted">当前吊销 ' + revoked.length + ' 张证书。服务器定期拉取 KRL 即可生效：</p>' +
    '<pre># crontab（每 5 分钟）\\n*/5 * * * * curl -sf -H "Authorization: Bearer <token>" ' + location.origin + '/api/krl -o /etc/ssh/revoked.krl.tmp && mv /etc/ssh/revoked.krl.tmp /etc/ssh/revoked.krl</pre>' +
    '<p><button onclick="downloadKrl()">下载 revoked.krl</button></p>' +
    (revoked.length ? '<table><tr><th>Serial</th><th>Key ID</th><th>吊销人</th><th>时间</th><th>原因</th></tr>' +
      revoked.map(c => '<tr><td class="mono">' + c.serial + '</td><td class="mono">' + esc(c.keyId) + '</td><td>' +
        esc(c.revokedBy) + '</td><td class="muted">' + fmtTime(c.revokedAt) + '</td><td>' + esc(c.revokeReason || '-') + '</td></tr>').join('') +
      '</table>' : '<p class="muted">暂无吊销记录。</p>') + '</div>';
}

async function downloadKrl() {
  try {
    const res = await fetch('/api/krl', { headers: { authorization: 'Bearer ' + token() } });
    if (!res.ok) throw new Error(res.status + ' ' + res.statusText);
    const blob = await res.blob();
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'revoked.krl';
    a.click();
  } catch (e) { toast(e.message, true); }
}

async function renderAudit() {
  const { audit } = await api('/api/audit');
  $('tab-audit').innerHTML = '<div class="panel"><h3>审计日志</h3><table>' +
    '<tr><th>时间</th><th>操作人</th><th>动作</th><th>详情</th></tr>' +
    audit.map(a => '<tr><td class="muted" style="white-space:nowrap">' + fmtTime(a.ts) + '</td><td>' + esc(a.actor) +
      '</td><td class="mono">' + esc(a.action) + '</td><td class="mono">' + esc(JSON.stringify(a.detail)) + '</td></tr>').join('') +
    '</table></div>';
}

async function renderCa() {
  const data = await api('/api/ca');
  $('tab-ca').innerHTML = '<div class="panel"><h3>CA 公钥</h3>' +
    data.cas.map(ca => '<p><b>' + esc(ca.id) + '</b> <span class="mono muted">' + esc(ca.fingerprint) + '</span></p>' +
      '<pre>' + esc(ca.publicKey) + '</pre>').join('') +
    '<h4>sshd 配置示例</h4><pre>' + esc(data.hints.sshd_config.join('\\n')) + '</pre></div>';
}

async function submitRequest() {
  const ttl = $('f-ttl').value.trim();
  const body = {
    type: $('f-type').value,
    ca: $('f-ca').value,
    publicKey: $('f-pubkey').value.trim(),
    principals: $('f-principals').value.split(',').map(s => s.trim()).filter(Boolean),
    keyId: $('f-keyid').value.trim() || undefined,
    comment: $('f-comment').value.trim() || undefined,
    validBefore: ttl ? Math.floor(Date.now() / 1000) + Number(ttl) : undefined,
    criticalOptions: {
      forceCommand: $('f-forcecmd').value.trim() || undefined,
      sourceAddress: $('f-srcaddr').value.split(',').map(s => s.trim()).filter(Boolean),
    },
    extensions: $('f-exts').value.split(',').map(s => s.trim()).filter(Boolean),
  };
  try {
    await api('/api/requests', { method: 'POST', body: JSON.stringify(body) });
    toast('申请已提交，等待审批');
    showTab('pending');
  } catch (e) { toast(e.message, true); }
}

refresh();
</script>
</body>
</html>`;
}
