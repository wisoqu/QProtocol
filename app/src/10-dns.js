// ---------------------------------------------------------------------------
// 10. DNS-диагностика: системный резолвер, сырой UDP DNS, отравление
// ---------------------------------------------------------------------------

/** Собрать сырой DNS-запрос A/AAAA. */
function buildDnsQuery(name, qtype, id) {
  const parts = name.split('.').filter(Boolean);
  const q = Buffer.alloc(256);
  let o = 0;
  q.writeUInt16BE(id, o); o += 2;
  q.writeUInt16BE(0x0100, o); o += 2; // RD
  q.writeUInt16BE(1, o); o += 2;      // QDCOUNT
  q.writeUInt16BE(0, o); o += 2;
  q.writeUInt16BE(0, o); o += 2;
  q.writeUInt16BE(0, o); o += 2;
  for (const label of parts) {
    q[o++] = label.length;
    q.write(label, o, 'ascii'); o += label.length;
  }
  q[o++] = 0;
  q.writeUInt16BE(qtype, o); o += 2;
  q.writeUInt16BE(1, o); o += 2; // IN
  return q.subarray(0, o);
}

/** Разобрать DNS-ответ (только A/AAAA/CNAME и RCODE). */
function parseDnsResponse(buf) {
  const out = { rcode: null, answers: [], truncated: false };
  if (!buf || buf.length < 12) return out;
  out.rcode = buf[3] & 0x0f;
  const qd = buf.readUInt16BE(4);
  const an = buf.readUInt16BE(6);
  let o = 12;
  // пропускаем вопросы
  for (let i = 0; i < qd && o < buf.length; i++) {
    while (o < buf.length && buf[o] !== 0) {
      if ((buf[o] & 0xc0) === 0xc0) { o += 2; break; }
      o += buf[o] + 1;
    }
    if (o < buf.length && buf[o] === 0) o++;
    o += 4;
  }
  for (let i = 0; i < an && o + 12 <= buf.length; i++) {
    // имя (может быть указателем)
    if ((buf[o] & 0xc0) === 0xc0) o += 2;
    else {
      while (o < buf.length && buf[o] !== 0) o += buf[o] + 1;
      o++;
    }
    if (o + 10 > buf.length) break;
    const type = buf.readUInt16BE(o); o += 2;
    o += 2; // class
    o += 4; // ttl
    const rdlen = buf.readUInt16BE(o); o += 2;
    if (o + rdlen > buf.length) { out.truncated = true; break; }
    if (type === 1 && rdlen === 4) {
      out.answers.push({ type: 'A', data: `${buf[o]}.${buf[o + 1]}.${buf[o + 2]}.${buf[o + 3]}` });
    } else if (type === 28 && rdlen === 16) {
      const seg = [];
      for (let j = 0; j < 16; j += 2) seg.push(buf.readUInt16BE(o + j).toString(16));
      out.answers.push({ type: 'AAAA', data: seg.join(':') });
    } else if (type === 5) {
      out.answers.push({ type: 'CNAME', data: '<cname>' });
    }
    o += rdlen;
  }
  return out;
}

/** Сырой UDP DNS-запрос к конкретному резолверу. */
function rawDnsQuery(resolverIp, name, qtype, timeoutMs) {
  return new Promise((resolve) => {
    const t0 = now();
    const id = crypto.randomInt(1, 65535);
    const query = buildDnsQuery(name, qtype, id);
    const sock = dgram.createSocket('udp4');
    let done = false;
    const finish = (result) => {
      if (done) return;
      done = true;
      try { sock.close(); } catch (_) {}
      resolve({ ...result, ms: now() - t0, resolver: resolverIp, name, qtype });
    };
    sock.on('error', (e) => finish({ ok: false, error: String(e.message || e) }));
    sock.on('message', (msg) => {
      const parsed = parseDnsResponse(msg);
      const poisoned = parsed.answers.some((a) => a.type === 'A' && isPrivateIPv4(a.data));
      finish({ ok: parsed.rcode === 0, rcode: parsed.rcode, answers: parsed.answers, poisoned });
    });
    sock.send(query, 53, resolverIp, (err) => {
      if (err) finish({ ok: false, error: String(err.message || err) });
    });
    setTimeout(() => finish({ ok: false, error: 'timeout' }), timeoutMs);
  });
}

async function runDnsDiagnostics(targetHosts) {
  const results = { system: [], raw: [], doh: [], verdicts: [] };

  // Системный резолвер
  for (const host of targetHosts.slice(0, 4)) {
    const r = await timed(() => dns.promises.lookup(host, { all: true }), 4000);
    results.system.push({
      host,
      ok: r.ok,
      addrs: r.ok ? r.value.map((v) => v.address) : [],
      error: r.ok ? null : r.error,
      ms: r.ms,
    });
  }

  // Сырой UDP DNS к каждому резолверу (A-запрос на первый хост)
  const probeHost = targetHosts[0];
  for (const resolver of RESOLVERS) {
    if (!resolver.host) continue;
    const r = await rawDnsQuery(resolver.host, probeHost, 1, 3000);
    results.raw.push({ ...r, name: resolver.name });
  }

  // DoH (может быть недоступен из песочницы — это тоже диагностический сигнал)
  const dohRes = await timed(async () => {
    const u = `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(probeHost)}&type=A`;
    const resp = await fetch(u, { headers: { accept: 'application/dns-json' }, signal: AbortSignal.timeout(4000) });
    const j = await resp.json();
    return (j.Answer || []).map((a) => ({ type: a.type, data: a.data }));
  }, 5000);
  results.doh.push({
    name: 'cloudflare-dns.com',
    host: probeHost,
    ok: dohRes.ok,
    answers: dohRes.ok ? dohRes.value : [],
    error: dohRes.ok ? null : dohRes.error,
    ms: dohRes.ms,
  });

  // Вердикты
  const anyRawPoison = results.raw.some((r) => r.poisoned);
  const rawOk = results.raw.filter((r) => r.ok);
  if (anyRawPoison) {
    results.verdicts.push({
      level: 'warn',
      code: 'dns-poisoning',
      text: 'Сырой UDP DNS возвращает приватные/loopback-адреса — похоже на отравление DNS.',
    });
  }
  const sysFail = results.system.filter((s) => !s.ok).length;
  if (sysFail === results.system.length && rawOk.length === 0) {
    results.verdicts.push({
      level: 'info',
      code: 'dns-env',
      text: 'DNS-запросы не проходят ни системным резолвером, ни напрямую — проверьте выход в сеть (это может быть ограничение среды, а не цензура).',
    });
  } else if (sysFail > 0 && rawOk.length > 0) {
    results.verdicts.push({
      level: 'warn',
      code: 'dns-interference',
      text: 'Системный резолвер сбоит, а прямые DNS-резолверы отвечают — признак манипуляций с DNS на уровне ОС/роутера.',
    });
  }
  return results;
}
