// ---------------------------------------------------------------------------
// 70. CLI-точка входа
// ---------------------------------------------------------------------------

function printHelp() {
  console.log(`
${APP_NAME} v${VERSION}
Диагностика цензурных ограничений + лаборатория детектируемости транспортов.

Использование:
  qprotocol [serve] [--port N] [--host H] [--targets a,b,c]   занять порт и показать дашборд
  qprotocol diag [--targets a,b,c] [--out report.json]        разовая диагностика в JSON
  qprotocol lab                                               только лаборатория «Пиросто»
  qprotocol help                                              эта справка

Опции:
  --port N        порт HTTP-интерфейса (по умолчанию 8787)
  --host H        адрес привязки (по умолчанию 0.0.0.0)
  --targets a,b   список хостов для диагностики
  --out file      записать JSON-отчёт в файл
  --no-lab        не запускать лабораторию в отчёте
  --timeout ms    таймаут сетевых проб (по умолчанию 6000)

Примеры:
  qprotocol serve --port 8787
  qprotocol diag --targets youtube.com,www.google.com --out report.json
  qprotocol lab
`);
}

function parseArgs(argv) {
  const args = {
    cmd: 'serve', port: 8787, host: '0.0.0.0', targets: null,
    out: null, lab: true, timeoutMs: 6000,
  };
  const a = argv.slice(2);
  if (a.length && !a[0].startsWith('--')) { args.cmd = a.shift(); }
  for (let i = 0; i < a.length; i++) {
    const k = a[i];
    if (k === '--port') args.port = parseInt(a[++i], 10) || 8787;
    else if (k === '--host') args.host = a[++i];
    else if (k === '--targets') {
      args.targets = a[++i].split(',').map((s) => ({ host: s.trim(), role: 'target' })).filter((t) => t.host);
    } else if (k === '--out') args.out = a[++i];
    else if (k === '--no-lab') args.lab = false;
    else if (k === '--timeout') args.timeoutMs = parseInt(a[++i], 10) || 6000;
    else if (k === 'help' || k === '--help' || k === '-h') args.cmd = 'help';
  }
  return args;
}

async function main() {
  const args = parseArgs(process.argv);

  if (args.cmd === 'help') {
    printHelp();
    return;
  }

  if (args.cmd === 'lab') {
    const lab = await runLab();
    console.log(JSON.stringify(lab, null, 2));
    return;
  }

  if (args.cmd === 'diag') {
    console.error('[qpd] запуск диагностики…');
    const rep = await runFullDiagnostics({
      targets: args.targets || DEFAULT_TARGETS,
      lab: args.lab,
      timeoutMs: args.timeoutMs,
    });
    const json = JSON.stringify(rep, null, 2);
    if (args.out) {
      fs.writeFileSync(args.out, json);
      console.error('[qpd] отчёт записан в ' + args.out);
    }
    console.log(json);
    return;
  }

  // serve (по умолчанию)
  const targets = args.targets || DEFAULT_TARGETS;
  console.log(`${APP_NAME} v${VERSION}`);
  console.log(`[qpd] HTTP-интерфейс: http://${args.host}:${args.port}/`);
  console.log(`[qpd] цели: ${targets.map((t) => t.host).join(', ')}`);

  // Порт занимается сразу; диагностика идёт в фоне и заполняет отчёт.
  const ctl = await startServer({ host: args.host, port: args.port, targets, report: null });
  console.log(`[qpd] порт ${args.port} занят, сервер слушает. Ctrl+C — выход.`);
  console.log(`[qpd] фоновая диагностика запущена…`);

  runFullDiagnostics({ targets, lab: args.lab, timeoutMs: args.timeoutMs })
    .then((report) => {
      ctl.setReport(report);
      if (args.out) fs.writeFileSync(args.out, JSON.stringify(report, null, 2));
      console.log(`[qpd] диагностика готова (${report.duration_ms} ms), вердиктов: ${report.verdicts.length}`);
    })
    .catch((e) => console.error('[qpd] ошибка диагностики:', e));

  process.on('SIGINT', () => { console.log('\n[qpd] останов'); process.exit(0); });
  process.on('SIGTERM', () => process.exit(0));
}

main().catch((e) => {
  console.error('[qpd] фатальная ошибка:', e);
  process.exit(1);
});
