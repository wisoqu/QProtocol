// ---------------------------------------------------------------------------
// 60. HTTP-сервер: дашборд + JSON API (занимает порт — это интерфейс бинаря)
// ---------------------------------------------------------------------------

const HTML_PAGE = `<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>QPD — диагностика QProtocol</title>
<style>
  :root {
    --bg: #0d1117; --panel: #161b22; --border: #30363d; --text: #e6edf3;
    --muted: #8b949e; --ok: #3fb950; --warn: #d29922; --bad: #f85149; --info: #58a6ff;
    --accent: #58a6ff;
  }
  * { box-sizing: border-box; }
  body { margin: 0; background: var(--bg); color: var(--text);
    font: 14px/1.55 "SF Mono", "Cascadia Code", Consolas, "JetBrains Mono", monospace; }
  header { padding: 18px 28px; border-bottom: 1px solid var(--border);
    display: flex; align-items: center; gap: 18px; flex-wrap: wrap;
    background: linear-gradient(180deg, #101826, var(--bg)); }
  h1 { font-size: 19px; margin: 0; letter-spacing: .3px; }
  h1 .ver { color: var(--muted); font-size: 12px; margin-left: 8px; }
  .sub { color: var(--muted); font-size: 12px; }
  button { background: var(--accent); color: #fff; border: 0; border-radius: 7px;
    padding: 8px 15px; font: inherit; font-weight: 600; cursor: pointer; }
  button.sec { background: transparent; color: var(--accent); border: 1px solid var(--accent); }
  button:disabled { opacity: .5; cursor: wait; }
  main { padding: 22px 28px 60px; max-width: 1180px; margin: 0 auto; }
  section { margin: 26px 0; }
  h2 { font-size: 15px; color: var(--accent); border-bottom: 1px solid var(--border);
    padding-bottom: 7px; letter-spacing: .4px; text-transform: uppercase; }
  .cards { display: grid; grid-template-columns: repeat(auto-fill, minmax(240px, 1fr)); gap: 12px; }
  .card { background: var(--panel); border: 1px solid var(--border); border-radius: 9px; padding: 13px 15px; }
  .card .k { color: var(--muted); font-size: 11px; text-transform: uppercase; letter-spacing: .6px; }
  .card .v { font-size: 15px; margin-top: 4px; word-break: break-all; }
  table { width: 100%; border-collapse: collapse; background: var(--panel);
    border: 1px solid var(--border); border-radius: 9px; overflow: hidden; font-size: 12.5px; }
  th, td { text-align: left; padding: 8px 11px; border-bottom: 1px solid var(--border); vertical-align: top; }
  th { color: var(--muted); font-weight: 600; font-size: 11px; text-transform: uppercase; letter-spacing: .5px; }
  tr:last-child td { border-bottom: 0; }
  .chip { display: inline-block; padding: 1px 9px; border-radius: 20px; font-size: 11px; font-weight: 700; }
  .chip.ok { background: rgba(63,185,80,.15); color: var(--ok); }
  .chip.warn { background: rgba(210,153,34,.15); color: var(--warn); }
  .chip.block, .chip.bad { background: rgba(248,81,73,.15); color: var(--bad); }
  .chip.info { background: rgba(88,166,255,.13); color: var(--info); }
  .mono { color: var(--muted); font-size: 11.5px; }
  .target { background: var(--panel); border: 1px solid var(--border); border-radius: 10px;
    padding: 15px 17px; margin: 12px 0; }
  .target h3 { margin: 0 0 6px; font-size: 14.5px; display: flex; gap: 10px; align-items: center; flex-wrap: wrap; }
  .role { font-size: 10.5px; padding: 1px 8px; border: 1px solid var(--border); border-radius: 20px; color: var(--muted); }
  .vlist { margin: 9px 0 0; padding: 0; list-style: none; }
  .vlist li { padding: 6px 10px; margin: 4px 0; border-radius: 7px; background: #10151c; border-left: 3px solid var(--muted); }
  .vlist li.ok { border-left-color: var(--ok); }
  .vlist li.warn { border-left-color: var(--warn); }
  .vlist li.block, .vlist li.bad { border-left-color: var(--bad); }
  .vlist li.info { border-left-color: var(--info); }
  .muted { color: var(--muted); }
  .rec { background: #101826; border: 1px solid var(--border); border-left: 4px solid var(--accent);
    padding: 13px 16px; border-radius: 9px; margin-top: 14px; }
  .score { font-weight: 800; font-size: 15px; }
  .score.low { color: var(--ok); } .score.mid { color: var(--warn); } .score.high { color: var(--bad); }
  footer { color: var(--muted); font-size: 11.5px; padding: 10px 28px 30px; text-align: center; }
  .grid2 { display: grid; grid-template-columns: 1fr 1fr; gap: 14px; }
  @media (max-width: 800px) { .grid2 { grid-template-columns: 1fr; } }
</style>
</head>
<body>
<header>
  <h1>QPD · QProtocol Diagnostics<span class="ver" id="ver"></span></h1>
  <span class="sub" id="status">готов</span>
  <span style="flex:1"></span>
  <button id="run">Запустить диагностику</button>
  <button class="sec" onclick="location.href='/api/report'">JSON</button>
  <button class="sec" onclick="location.href='/api/lab'">Лаборатория</button>
</header>
<main id="main"><p class="muted">Загрузка…</p></main>
<footer>QPD — диагностический бинарь проекта QProtocol. Данные собираются на этой машине;
  «заморозки» ТСПУ проявляются только в целевой сети.</footer>
<script>
function esc(s){return String(s==null?'':s).replace(/[&<>"]/g,function(c){
  return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c];});}
function chip(v){var m={ok:'ok',warn:'warn',block:'block',bad:'bad',info:'info'};
  return '<span class="chip '+(m[v]||'info')+'">'+esc(v)+'</span>';}
function sc(n){var c=n<40?'low':(n<66?'mid':'high');
  return '<span class="score '+c+'">'+n+'%</span>';}

function render(rep){
  var h='';
  h+='<section><h2>Среда</h2><div class="cards">'+
    '<div class="card"><div class="k">Запущено</div><div class="v">'+esc(rep.meta.started_at)+'</div></div>'+
    '<div class="card"><div class="k">Node / платформа</div><div class="v">'+esc(rep.meta.node)+' · '+esc(rep.meta.platform)+'</div></div>'+
    '<div class="card"><div class="k">Длительность</div><div class="v">'+rep.duration_ms+' ms</div></div>'+
    '<div class="card"><div class="k">Интерфейсы</div><div class="v">'+esc(rep.environment.net_ifaces)+'</div></div>'+
    '<div class="card"><div class="k">Эталонный JA3 (наш ClientHello)</div><div class="v mono">'+
      esc(rep.meta.reference_fingerprint?rep.meta.reference_fingerprint.ja3:'—')+'</div></div>'+
    '<div class="card"><div class="k">Эталонный JA4</div><div class="v mono">'+
      esc(rep.meta.reference_fingerprint?rep.meta.reference_fingerprint.ja4:'—')+'</div></div>'+
    '</div></section>';

  h+='<section><h2>Вердикты</h2><ul class="vlist">';
  (rep.verdicts||[]).forEach(function(v){
    h+='<li class="'+esc(v.level)+'">'+chip(v.level)+' <b>'+esc(v.code)+'</b>'+
       (v.host?' <span class="mono">'+esc(v.host)+'</span>':'')+
       ' — '+esc(v.text)+'</li>';
  });
  h+='</ul></section>';

  if(rep.dns){
    h+='<section><h2>DNS</h2><table><tr><th>Резолвер</th><th>Хост</th><th>Статус</th><th>Ответы</th><th>мс</th></tr>';
    (rep.dns.raw||[]).forEach(function(d){
      h+='<tr><td>'+esc(d.resolver_name||d.resolver_ip)+'</td><td>'+esc(d.query_name||'—')+'</td>'+
        '<td>'+chip(d.ok?'ok':(d.icmp?'warn':'bad'))+(d.poisoned?' отравление':'')+'</td>'+
        '<td class="mono">'+esc((d.answers||[]).map(function(a){return a.data;}).join(', ')||d.error||'—')+'</td>'+
        '<td>'+esc(d.ms)+'</td></tr>';
    });
    (rep.dns.system||[]).forEach(function(d){
      h+='<tr><td>system</td><td>'+esc(d.host)+'</td><td>'+chip(d.ok?'ok':'bad')+'</td>'+
        '<td class="mono">'+esc((d.addrs||[]).join(', ')||d.error||'—')+'</td><td>'+esc(d.ms)+'</td></tr>';
    });
    (rep.dns.doh||[]).forEach(function(d){
      h+='<tr><td>DoH '+esc(d.name)+'</td><td>'+esc(d.host)+'</td><td>'+chip(d.ok?'ok':'warn')+'</td>'+
        '<td class="mono">'+esc((d.answers||[]).map(function(a){return a.data;}).join(', ')||d.error||'—')+'</td>'+
        '<td>'+esc(d.ms)+'</td></tr>';
    });
    h+='</table></section>';
  }

  h+='<section><h2>Цели: TCP / TLS / SNI / фрагментация</h2>';
  (rep.targets||[]).forEach(function(t){
    h+='<div class="target"><h3>'+esc(t.host)+' <span class="role">'+esc(t.role)+'</span> '+
       '<span class="mono">'+esc(t.note||'')+'</span></h3>';
    var st=t.steps||{};
    if(st.tcp){
      h+='<div class="mono">TCP '+esc(st.tcp.kind)+' · '+esc(st.tcp.ms)+' ms' +
        (st.tls&&st.tls.ok
          ? ' · TLS '+esc(st.tls.protocol)+' '+esc(st.tls.cipher)+' · ALPN '+esc(st.tls.alpn)+
            ' · JA3 <b>'+esc(st.tls.clienthello?st.tls.clienthello.ja3:'')+'</b>'+
            ' · JA4 <b>'+esc(st.tls.clienthello?st.tls.clienthello.ja4:'')+'</b>'
          : (st.tls?(' · TLS: '+esc(st.tls.error)):''))+'</div>';
    }
    if(st.tls&&st.tls.cert){
      h+='<div class="mono">cert: '+esc(st.tls.cert.subject)+' / issuer '+esc(st.tls.cert.issuer)+
        ' · до '+esc(st.tls.cert.valid_to)+'</div>';
    }
    if(st.sni){
      h+='<div class="mono">SNI-тест: '+chip(st.sni.verdict==='ok'?'ok':'warn')+' '+esc(st.sni.note)+'</div>';
    }
    if(st.frag){
      h+='<table style="margin-top:9px"><tr><th>Режим отправки ClientHello</th><th>Результат</th><th>Заметка</th><th>мс</th></tr>';
      st.frag.forEach(function(f){
        h+='<tr><td>'+esc(f.mode)+'</td><td>'+chip(f.ok?'ok':'bad')+'</td>'+
          '<td class="mono">'+esc(f.note||f.error||'')+'</td><td>'+esc(f.ms)+'</td></tr>';
      });
      h+='</table>';
    }
    h+='<ul class="vlist">';
    (t.verdicts||[]).forEach(function(v){
      h+='<li class="'+esc(v.level)+'">'+chip(v.level)+' '+esc(v.text)+'</li>';
    });
    h+='</ul></div>';
  });
  h+='</section>';

  if(rep.behavioral){
    var b=rep.behavioral;
    h+='<section><h2>Поведение: порог параллельных хендшейков (Сигнал 3)</h2>'+
      '<div class="target"><div class="mono">Залп из '+b.burst.length+' соединений: '+
      b.burst.filter(function(x){return x.ok;}).length+' OK · '+
      'одиночное после паузы: '+(b.singleAfter&&b.singleAfter.ok?'OK':'FAIL')+
      ' · вердикт '+chip(b.verdict==='ok'?'ok':'warn')+'</div>'+
      '<ul class="vlist"><li class="'+(b.verdict==='ok'?'ok':'warn')+'">'+esc(b.note)+'</li></ul></div></section>';
  }

  if(rep.udp){
    h+='<section><h2>UDP / QUIC</h2><table><tr><th>Проба</th><th>Результат</th><th>Ответ</th><th>мс</th></tr>';
    (rep.udp.probes||[]).forEach(function(p){
      h+='<tr><td>'+esc(p.name)+'</td><td>'+chip(p.ok?'ok':(p.icmp?'warn':'bad'))+'</td>'+
        '<td class="mono">'+esc((p.firstBytes||'')+(p.error?' '+p.error:''))+'</td><td>'+esc(p.ms)+'</td></tr>';
    });
    h+='</table><ul class="vlist">';
    (rep.udp.verdicts||[]).forEach(function(v){
      h+='<li class="'+esc(v.level)+'">'+chip(v.level)+' '+esc(v.text)+'</li>';
    });
    h+='</ul></section>';
  }

  if(rep.lab){
    h+='<section><h2>Лаборатория детектируемости «Пиросто»</h2>'+
      '<table><tr><th>Режим</th><th>Сценарий</th><th>1 сигн.</th><th>2 случ.</th><th>3 поток</th><th>4 тайминги</th><th>5 эндп.</th><th>Риск</th></tr>';
    (rep.lab.rows||[]).forEach(function(r){
      h+='<tr><td><b>'+esc(r.mode)+'</b></td><td>'+esc(r.scenario)+'</td>'+
        '<td>'+r.signals['1_сигнатура']+'</td><td>'+r.signals['2_случайность/структура']+'</td>'+
        '<td>'+r.signals['3_форма_потока']+'</td><td>'+r.signals['4_тайминги']+'</td>'+
        '<td>'+r.signals['5_эндпоинт(конфиг)']+'</td><td>'+sc(r.detectability_score)+'</td></tr>';
    });
    h+='</table>';
    h+='<table style="margin-top:12px"><tr><th>Режим</th><th>Сценарий</th><th>Энтропия потока 16КБ</th><th>Записей</th><th>Энтропия размеров</th><th>in/out</th><th>CV таймингов</th></tr>';
    (rep.lab.rows||[]).forEach(function(r){
      h+='<tr><td>'+esc(r.mode)+'</td><td>'+esc(r.scenario)+'</td><td>'+r.metrics.entropy_flow_16kb+'</td>'+
        '<td>'+r.metrics.record_count+'</td><td>'+r.metrics.record_size_entropy+'</td>'+
        '<td>'+r.metrics.in_out_ratio+'</td><td>'+r.metrics.timing_cv+'</td></tr>';
    });
    h+='</table>';
    if(rep.lab.recommendation){
      h+='<div class="rec"><b>Вывод:</b> '+esc(rep.lab.recommendation)+'</div>';
    }
    h+='</section>';
  }
  document.getElementById('main').innerHTML=h;
}

function load(){
  fetch('/api/report').then(function(r){return r.json();}).then(function(rep){
    window.__rep=rep;
    document.getElementById('ver').textContent='v'+rep.meta.version;
    render(rep);
    document.getElementById('status').textContent='отчёт от '+rep.meta.finished_at;
  }).catch(function(e){
    document.getElementById('main').innerHTML='<p class="muted">Ошибка: '+esc(e)+'</p>';
  });
}
document.getElementById('run').addEventListener('click',function(){
  var b=this; b.disabled=true; b.textContent='Идёт диагностика…';
  document.getElementById('status').textContent='выполняется…';
  fetch('/api/run',{method:'POST'}).then(function(r){return r.json();}).then(function(){
    b.disabled=false; b.textContent='Запустить диагностику'; load();
  }).catch(function(){ b.disabled=false; b.textContent='Запустить диагностику'; });
});
load();
</script>
</body>
</html>`;

function startServer(opts) {
  const host = opts.host || '0.0.0.0';
  const port = opts.port || 8787;
  let report = opts.report || null;
  let running = false;

  const server = http.createServer((req, res) => {
    const url = new URL(req.url, 'http://localhost');
    res.setHeader('Access-Control-Allow-Origin', '*');
    try {
      if (url.pathname === '/' || url.pathname === '/index.html') {
        res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
        res.end(HTML_PAGE);
      } else if (url.pathname === '/api/report') {
        res.writeHead(200, { 'content-type': 'application/json; charset=utf-8' });
        res.end(JSON.stringify(report || { ready: false, meta: { version: VERSION, started_at: new Date().toISOString(), node: process.version, platform: os.platform() }, environment: { net_ifaces: '' }, verdicts: [], targets: [], duration_ms: 0 }, null, 2));
      } else if (url.pathname === '/api/health') {
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ ok: true, app: APP_NAME, version: VERSION, hasReport: !!report, running }));
      } else if (url.pathname === '/api/lab') {
        runLab().then((lab) => {
          res.writeHead(200, { 'content-type': 'application/json; charset=utf-8' });
          res.end(JSON.stringify(lab, null, 2));
        }).catch((e) => {
          res.writeHead(500, { 'content-type': 'application/json' });
          res.end(JSON.stringify({ error: String(e) }));
        });
      } else if (url.pathname === '/api/run' && req.method === 'POST') {
        if (running) {
          res.writeHead(429, { 'content-type': 'application/json' });
          res.end(JSON.stringify({ ok: false, error: 'already running' }));
          return;
        }
        running = true;
        res.writeHead(202, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ ok: true, started: true }));
        runFullDiagnostics({ targets: opts.targets, lab: true })
          .then((r) => { report = r; })
          .catch((e) => {
            report = report || { meta: { version: VERSION, started_at: new Date().toISOString() }, verdicts: [], duration_ms: 0 };
            report.error = String(e);
          })
          .finally(() => { running = false; });
      } else {
        res.writeHead(404, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ error: 'not found' }));
      }
    } catch (e) {
      res.writeHead(500, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ error: String(e) }));
    }
  });

  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, host, () => resolve({
      server,
      setReport: (r) => { report = r; },
      getReport: () => report,
    }));
  });
}
