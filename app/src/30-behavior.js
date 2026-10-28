// ---------------------------------------------------------------------------
// 30. Поведенческая диагностика: порог параллельных хендшейков (Сигнал 3),
//     UDP/QUIC, деградация канала
// ---------------------------------------------------------------------------

/**
 * Тест «Сигнал 3» (замирание ~120 c при ≥4 параллельных хендшейках к одному SNI).
 * Идея из полевых наблюдений ТСПУ 2026: одно соединение проходит, залп из 4+ —
 * замораживается. Методика: залп -> пауза -> одиночное соединение; сравниваем.
 */
async function parallelismTest(host, sni, count, timeoutMs) {
  const results = { burst: [], singleAfter: null, verdict: null, note: '' };

  const runOne = async () => {
    const r = await realTlsHandshake(host, 443, sni, timeoutMs);
    return { ok: r.ok, ms: r.ms, error: r.error || null };
  };

  // Залп: count одновременных хендшейков
  const t0 = now();
  const burst = await Promise.all(Array.from({ length: count }, runOne));
  const burstTotal = now() - t0;
  results.burst = burst.map((r, i) => ({ i, ...r }));
  results.burstTotalMs = burstTotal;

  await sleep(1500);

  // Одиночное соединение после паузы
  results.singleAfter = await runOne();

  const burstOk = burst.filter((r) => r.ok).length;
  const burstFail = count - burstOk;
  const singleOk = results.singleAfter.ok;

  if (burstOk === count && singleOk) {
    results.verdict = 'ok';
    results.note = `Все ${count} параллельных и одиночное соединение проходят — порог параллелизма не сработал.`;
  } else if (burstFail > 0 && singleOk) {
    results.verdict = 'parallelism-threshold';
    results.note = `Одиночное соединение проходит, а из ${count} параллельных прошло ${burstOk} — похоже на порог параллелизма/«заморозку» (Сигнал 3 ТСПУ).`;
  } else if (burstOk === count && !singleOk) {
    results.verdict = 'anomaly';
    results.note = 'Залп прошёл, а одиночное соединение после паузы — нет. Проверьте стабильность канала.';
  } else {
    results.verdict = 'blocked';
    results.note = 'Соединения не проходят ни залпом, ни по одному — вероятна блокировка узла/IP либо недоступна сеть.';
  }
  return results;
}

/** UDP-пробы: QUIC-подобный Initial на 443, «шум», оценка фильтрации UDP. */
function udpProbe(host, port, payload, timeoutMs) {
  return new Promise((resolve) => {
    const t0 = now();
    const sock = dgram.createSocket('udp4');
    const result = { ok: false, response: 0, error: null, ms: 0 };
    let done = false;
    const finish = () => {
      if (done) return;
      done = true;
      result.ms = now() - t0;
      try { sock.close(); } catch (_) {}
      resolve(result);
    };
    sock.on('message', (msg) => {
      result.ok = true;
      result.response = msg.length;
      result.firstBytes = msg.subarray(0, 8).toString('hex');
      finish();
    });
    sock.on('error', (e) => {
      // ICMP unreachable приходит сюда — значит, UDP-путь жив, но порт закрыт
      result.error = String(e.message || e);
      result.icmp = true;
      finish();
    });
    dns.lookup(host, (err, addr) => {
      if (err) {
        result.error = 'dns: ' + String(err.message || err);
        finish();
        return;
      }
      result.addr = addr;
      sock.send(payload, port, addr, (e) => {
        if (e) {
          result.error = String(e.message || e);
          finish();
        }
      });
    });
    setTimeout(finish, timeoutMs);
  });
}

/** QUIC Initial (форма пакета как у HTTP/3 клиента) — длинный заголовок, версия 1. */
function buildQuicInitial(version) {
  const p = Buffer.alloc(1200);
  crypto.randomFillSync(p);
  p[0] = 0xc0; // long header (0x80) + fixed bit (0x40) + type Initial (00)
  p.writeUInt32BE(version != null ? version : 0x00000001, 1); // QUIC v1 по умолчанию
  const dcidLen = 8;
  p[5] = dcidLen;
  // dcid random уже
  p[5 + 1 + dcidLen] = 0; // scid len = 0
  let o = 5 + 1 + dcidLen + 1;
  p[o] = 0x00; o += 1; // token length 0
  const restLen = 1200 - o - 2;
  p.writeUInt16BE(0x4000 | (restLen & 0x3fff), o); // length + 2 flag bits
  return p;
}

async function udpDiagnostics(host) {
  const out = { probes: [], verdicts: [] };
  // Проба с НЕИЗВЕСТНОЙ версией QUIC: RFC 9000 обязывает сервер ответить
  // Version Negotiation — это лучший сигнал «UDP-путь жив и кто-то слушает».
  const quicVn = buildQuicInitial(0x0a0a0a0a);
  const r0 = await udpProbe(host, 443, quicVn, 3000);
  out.probes.push({ name: 'quic-version-negotiate:443', ...r0 });
  const quic = buildQuicInitial();
  const r1 = await udpProbe(host, 443, quic, 3000);
  out.probes.push({ name: 'quic-initial:443', ...r1 });
  const r2 = await udpProbe(host, 443, crypto.randomBytes(64), 3000);
  out.probes.push({ name: 'udp-junk:443', ...r2 });
  const r3 = await udpProbe(host, 53, Buffer.from([0x12, 0x34, 0x01, 0x00, 0x00, 0x01]), 2000);
  out.probes.push({ name: 'udp:53', ...r3 });

  const anyIcmp = out.probes.some((p) => p.icmp);
  const anyResp = out.probes.some((p) => p.ok);
  if (anyResp) {
    out.verdicts.push({
      level: 'ok',
      code: 'udp-open',
      text: 'UDP-ответы получены — QUIC/Hysteria-подобные транспорты потенциально работоспособны.',
    });
  } else if (anyIcmp) {
    out.verdicts.push({
      level: 'warn',
      code: 'udp-icmp',
      text: 'UDP без ответов, но есть ICMP «порт недоступен» — UDP не блокируется целиком, QUIC/Hysteria стоит проверить точечной пробой.',
    });
  } else {
    out.verdicts.push({
      level: 'warn',
      code: 'udp-drop',
      text: 'UDP-пробы молча отбрасываются — либо фильтрация UDP (Hysteria/QUIC не заработают), либо блокировка UDP в локальной среде/файрволе. Проверьте из целевой сети.',
    });
  }
  return out;
}

/** Оценка «типичности» профиля трафика (in/out, размеры, тайминги). */
function trafficProfileStats(writesC, writesS, timingsC) {
  const sizesC = writesC.map((b) => b.length);
  const sizesS = writesS.map((b) => b.length);
  const bytesC = sizesC.reduce((a, b) => a + b, 0);
  const bytesS = sizesS.reduce((a, b) => a + b, 0);
  return {
    client_writes: writesC.length,
    server_writes: writesS.length,
    client_bytes: bytesC,
    server_bytes: bytesS,
    in_out_ratio: bytesC > 0 ? +(bytesS / bytesC).toFixed(2) : null,
    client_size_median: median(sizesC),
    client_size_max: sizesC.length ? Math.max(...sizesC) : 0,
    server_size_median: median(sizesS),
    timing_cv: timingsC ? +cv(timingsC).toFixed(2) : null,
  };
}
