// ---------------------------------------------------------------------------
// 50. Оркестрация диагностики → единый отчёт
// ---------------------------------------------------------------------------

function classifyTargetError(r) {
  if (r.ok) return 'ok';
  const e = String(r.error || '').toLowerCase();
  if (e.includes('timeout')) return 'timeout';
  if (e.includes('econnrefused')) return 'refused';
  if (e.includes('econnreset') || e.includes('reset')) return 'reset';
  if (e.includes('ehostunreach') || e.includes('enetunreach')) return 'unreachable';
  if (e.includes('eai_again') || e.includes('dns')) return 'dns';
  return 'error';
}

/**
 * Полная диагностика одного хоста.
 * controlOk — достигаем ли контрольный хост (для разделения «цензура» vs «нет сети»).
 */
async function diagnoseTarget(t, timeoutMs, controlOk) {
  const out = {
    host: t.host,
    role: t.role,
    note: t.note || '',
    steps: {},
    verdicts: [],
  };

  // 1) TCP
  const tcp = await tcpConnect(t.host, 443, timeoutMs);
  out.steps.tcp = tcp;
  out.steps.tcp.kind = classifyTargetError(tcp);

  if (!tcp.ok) {
    const level = controlOk ? 'block' : 'info';
    out.verdicts.push({
      level,
      code: 'tcp-fail',
      text: controlOk
        ? `TCP:443 недоступен (${out.steps.tcp.kind}) при живом контрольном хосте — признак IP-блокировки или обрыва.`
        : `TCP:443 недоступен (${out.steps.tcp.kind}); контрольный хост тоже недоступен — сеть/среда ограничена, это не похоже на точечную цензуру.`,
    });
    return out;
  }

  // 2) Реальный TLS + JA3/JA4 «как видит DPI»
  const tlsr = await realTlsHandshake(t.host, 443, t.host, timeoutMs);
  out.steps.tls = tlsr;
  if (!tlsr.ok) {
    out.verdicts.push({
      level: 'block',
      code: 'tls-fail',
      text: `TCP установлен, но TLS-хендшейк не завершается (${tlsr.error}) — классический «freeze mid-handshake» либо глубокая фильтрация.`,
    });
    return out;
  }
  out.verdicts.push({
    level: 'ok',
    code: 'tls-ok',
    text: `TLS ${tlsr.protocol}, ${tlsr.cipher}, ALPN=${tlsr.alpn}; наш JA3=${tlsr.clienthello ? tlsr.clienthello.ja3 : 'n/a'}, JA4=${tlsr.clienthello ? tlsr.clienthello.ja4 : 'n/a'}`,
  });

  // 3) SNI-тест (только для доменных имён)
  if (!net.isIP(t.host)) {
    const ip = await dns.promises.lookup(t.host).then((r) => r.address).catch(() => null);
    if (ip) {
      const sni = await sniFilterTest(ip, t.host, 'www.microsoft.com', timeoutMs);
      out.steps.sni = sni;
      out.verdicts.push({
        level: sni.verdict === 'ok' ? 'ok' : 'warn',
        code: 'sni-' + sni.verdict,
        text: sni.note,
      });
    }
  }

  // 4) Тесты фрагментации ClientHello
  const modes = ['naive', 'split1', 'split-mid-sni', 'record-split', 'tiny-records'];
  const frag = [];
  for (const m of modes) {
    frag.push(await fragProbe(t.host, 443, t.host, m, Math.min(timeoutMs, 5000)));
  }
  out.steps.frag = frag;
  const naive = frag.find((f) => f.mode === 'naive');
  const splitWorks = frag.filter((f) => f.mode !== 'naive' && f.ok);
  if (naive && naive.ok) {
    out.verdicts.push({
      level: 'ok',
      code: 'frag-all',
      text: 'ClientHello проходит без фрагментации — SNI-фильтрация на первом пакете не обнаружена.',
    });
  } else if (splitWorks.length > 0) {
    out.verdicts.push({
      level: 'warn',
      code: 'frag-needed',
      text: `Наивный ClientHello не проходит, но работают: ${splitWorks.map((f) => f.mode).join(', ')} — фильтр смотрит SNI в первом сегменте; помогает split/record-split.`,
    });
  }

  return out;
}

async function runFullDiagnostics(opts) {
  const t0 = now();
  const timeoutMs = opts.timeoutMs || 6000;
  const targets = opts.targets || DEFAULT_TARGETS;
  const report = {
    meta: {
      app: APP_NAME,
      version: VERSION,
      started_at: new Date().toISOString(),
      node: process.version,
      platform: `${os.platform()} ${os.release()} ${os.arch()}`,
    },
    environment: {
      hostname: os.hostname(),
      cpus: os.cpus().length,
      load: os.loadavg()[0],
      net_ifaces: Object.keys(os.networkInterfaces()).join(', '),
    },
    dns: null,
    targets: [],
    behavioral: null,
    udp: null,
    lab: null,
    verdicts: [],
    duration_ms: 0,
  };

  // Референсный отпечаток нашего «Chrome-подобного» ClientHello (эталон для сравнения)
  const refHello = buildChromeClientHello('example.com');
  const refParsed = parseClientHello(refHello.record);
  report.meta.reference_fingerprint = {
    note: 'JA3/JA4 ClientHello, который QPD отправляет в тестах фрагментации (Chrome-подобный профиль)',
    ja3: computeJa3(refParsed).md5,
    ja4: computeJa4(refParsed),
  };

  // DNS
  report.dns = await runDnsDiagnostics(targets.map((t) => t.host));
  report.verdicts.push(...report.dns.verdicts);

  // Сначала контрольные хосты — чтобы понять, есть ли вообще сеть
  const ordered = [...targets].sort((a, b) => (a.role === 'control' ? -1 : 1) - (b.role === 'control' ? -1 : 1));
  const controlHosts = ordered.filter((t) => t.role === 'control');
  let controlOk = false;

  for (const t of ordered) {
    const r = await diagnoseTarget(t, timeoutMs, controlOk);
    if (t.role === 'control' && r.steps && r.steps.tcp && r.steps.tcp.ok) controlOk = true;
    report.targets.push(r);
    report.verdicts.push(...r.verdicts.map((v) => ({ ...v, host: t.host })));
  }

  // Поведенческий тест (Сигнал 3) — на первом доступном хосте
  const firstOk = report.targets.find((x) => x.steps && x.steps.tls && x.steps.tls.ok);
  if (firstOk) {
    report.behavioral = await parallelismTest(firstOk.host, firstOk.host, 5, timeoutMs);
    report.verdicts.push({
      level: report.behavioral.verdict === 'ok' ? 'ok' : 'warn',
      code: 'behavior-' + report.behavioral.verdict,
      host: firstOk.host,
      text: report.behavioral.note,
    });
  }

  // UDP/QUIC — на первом хосте
  if (firstOk) {
    report.udp = await udpDiagnostics(firstOk.host);
    report.verdicts.push(...report.udp.verdicts.map((v) => ({ ...v, host: firstOk.host })));
  }

  // Лаборатория детектируемости
  if (opts.lab !== false) {
    report.lab = await runLab();
    report.verdicts.push({
      level: 'info',
      code: 'lab',
      text: `Лаборатория «Пиросто»: риск raw-magic=${report.lab.scores['raw-magic']}%, ` +
        `tls-random=${report.lab.scores['tls-random']}%, browser-shaped=${report.lab.scores['browser-shaped']}%.`,
    });
  }

  if (!controlOk) {
    report.verdicts.push({
      level: 'info',
      code: 'env-no-network',
      text: 'Ни один контрольный хост не достигнут: в среде нет полного выхода в интернет. ' +
        'Вердикты «блокировка» для отдельных целей в таком режиме ненадёжны — запустите бинарь в целевой сети (у пользователя).',
    });
  }

  report.duration_ms = now() - t0;
  report.meta.finished_at = new Date().toISOString();
  return report;
}
