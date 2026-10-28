// ---------------------------------------------------------------------------
// 20. TCP/TLS: ClientHello-билдер, JA3/JA4, перехват «как видит DPI»,
//     тесты фрагментации, SNI-фильтрация
// ---------------------------------------------------------------------------

const GREASE_TABLE = [0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
  0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa];

function pickGrease(seed) {
  return GREASE_TABLE[crypto.randomInt(0, GREASE_TABLE.length)] ^ (seed || 0);
}

function extRecord(id, body) {
  const b = Buffer.alloc(4 + body.length);
  b.writeUInt16BE(id, 0);
  b.writeUInt16BE(body.length, 2);
  body.copy(b, 4);
  return b;
}

/**
 * Построить ClientHello в стиле Chrome (TLS 1.3, GREASE, порядок расширений
 * как у браузера). Возвращает { record, hello, sniOffset } — sniOffset нужен
 * для тестов фрагментации «посередине SNI».
 */
function buildChromeClientHello(sni, opts = {}) {
  const grease1 = opts.grease1 != null ? opts.grease1 : 0x0a0a;
  const grease2 = opts.grease2 != null ? opts.grease2 : 0x1a1a;
  const alpn = opts.alpn || ['h2', 'http/1.1'];

  const exts = [];
  // GREASE (первое расширение)
  exts.push(extRecord(grease1, Buffer.from([0x00])));

  // server_name
  const host = Buffer.from(sni, 'ascii');
  const sniBody = Buffer.alloc(5 + host.length);
  sniBody.writeUInt16BE(3 + host.length, 0); // server_name_list length
  sniBody[2] = 0;                            // name_type = host_name
  sniBody.writeUInt16BE(host.length, 3);
  host.copy(sniBody, 5);
  const sniExt = extRecord(0x0000, sniBody);
  exts.push(sniExt);

  // extended_master_secret
  exts.push(extRecord(0x0017, Buffer.alloc(0)));
  // renegotiation_info
  exts.push(extRecord(0xff01, Buffer.from([0x00])));
  // supported_groups: GREASE, x25519, secp256r1, secp384r1
  const groups = Buffer.alloc(2 + 8);
  groups.writeUInt16BE(8, 0);
  groups.writeUInt16BE(grease2, 2);
  groups.writeUInt16BE(0x001d, 4); // x25519
  groups.writeUInt16BE(0x0017, 6); // secp256r1
  groups.writeUInt16BE(0x0018, 8); // secp384r1
  exts.push(extRecord(0x000a, groups));
  // ec_point_formats
  exts.push(extRecord(0x000b, Buffer.from([0x01, 0x00])));
  // session_ticket
  exts.push(extRecord(0x0023, Buffer.alloc(0)));
  // ALPN
  const alpnList = Buffer.concat(alpn.map((p) => {
    const pb = Buffer.from(p, 'ascii');
    return Buffer.concat([Buffer.from([pb.length]), pb]);
  }));
  const alpnBody = Buffer.alloc(2 + alpnList.length);
  alpnBody.writeUInt16BE(alpnList.length, 0);
  alpnList.copy(alpnBody, 2);
  exts.push(extRecord(0x0010, alpnBody));
  // status_request (OCSP)
  exts.push(extRecord(0x0005, Buffer.from([0x01, 0x00, 0x00, 0x00, 0x00])));
  // signature_algorithms
  const sigAlgs = [
    0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
    0x0201, 0x0402, 0x0807, 0x0808, 0x0809, 0x080a, 0x080b, 0x0603, 0x0502, 0x0403,
  ];
  const sigBody = Buffer.alloc(2 + sigAlgs.length * 2);
  sigBody.writeUInt16BE(sigAlgs.length * 2, 0);
  sigAlgs.forEach((v, i) => sigBody.writeUInt16BE(v, 2 + i * 2));
  exts.push(extRecord(0x000d, sigBody));
  // key_share: GREASE (1 байт, как у Chrome) + x25519
  const x25519pub = opts.keyShare || crypto.randomBytes(32);
  const ks = Buffer.alloc(2 + 2 + 2 + 1 + 2 + 2 + 32);
  let k = 0;
  ks.writeUInt16BE(2 + 3 + 36, k); k += 2; // client_shares length
  ks.writeUInt16BE(grease2, k); k += 2;    // GREASE group
  ks.writeUInt16BE(1, k); k += 2;          // share length = 1
  ks[k++] = 0x00;                          // GREASE share
  ks.writeUInt16BE(0x001d, k); k += 2;     // x25519
  ks.writeUInt16BE(32, k); k += 2;
  x25519pub.copy(ks, k);
  exts.push(extRecord(0x0033, ks));
  // psk_key_exchange_modes
  exts.push(extRecord(0x002d, Buffer.from([0x01, 0x01])));
  // supported_versions: GREASE + TLS1.3 + TLS1.2 (length = 6)
  const sv = Buffer.from([0x06, (grease1 >> 8) & 0xff, grease1 & 0xff, 0x03, 0x04, 0x03, 0x03]);
  exts.push(extRecord(0x002b, sv));
  // compress_certificate (brotli) — как у Chrome: [u16 len=2][u16 alg=2]
  exts.push(extRecord(0x001b, Buffer.from([0x00, 0x02, 0x00, 0x02])));
  // application_settings (ALPS) — как у Chrome (ext 0x4469)
  const alpsBody = Buffer.alloc(2 + alpnList.length);
  alpsBody.writeUInt16BE(alpnList.length, 0);
  alpnList.copy(alpsBody, 2);
  exts.push(extRecord(0x4469, alpsBody));
  // GREASE (предпоследнее)
  exts.push(extRecord(grease2, Buffer.from([0x00])));
  // padding до 512 байт полезной нагрузки ClientHello (поведение Chrome)
  const extLenNow = exts.reduce((a, b) => a + b.length, 0);
  const helloBase = 2 + 32 + 1 + 32 + 2 + 18 + 1 + 2 + extLenNow; // приблизительно
  if (opts.pad !== false && helloBase < 512) {
    const padLen = Math.min(400, 512 - helloBase);
    const pad = Buffer.alloc(padLen);
    exts.push(extRecord(0x0015, pad));
  }

  const extsBuf = Buffer.concat(exts);
  const cipherSuites = [
    grease1,
    0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030,
    0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
  ];
  const csBuf = Buffer.alloc(2 + cipherSuites.length * 2);
  csBuf.writeUInt16BE(cipherSuites.length * 2, 0);
  cipherSuites.forEach((v, i) => csBuf.writeUInt16BE(v, 2 + i * 2));

  const sessionId = opts.sessionId || crypto.randomBytes(32);
  const randomBytes = opts.random || crypto.randomBytes(32);

  const body = Buffer.concat([
    Buffer.from([0x03, 0x03]),          // client_version
    randomBytes,
    Buffer.from([32]), sessionId,
    csBuf,
    Buffer.from([0x01, 0x00]),          // compression
    (() => { const l = Buffer.alloc(2); l.writeUInt16BE(extsBuf.length, 0); return l; })(),
    extsBuf,
  ]);

  const handshake = Buffer.concat([Buffer.from([0x01]), (() => {
    const l = Buffer.alloc(3); l.writeUIntBE(body.length, 0, 3); return l;
  })(), body]);

  const record = Buffer.concat([Buffer.from([0x16, 0x03, 0x01]), (() => {
    const l = Buffer.alloc(2); l.writeUInt16BE(handshake.length, 0); return l;
  })(), handshake]);

  // Смещение значения SNI внутри record (для split-mid-sni) — ищем маркер точным поиском:
  // [ext id 0000][ext len][server_name_list len][type 00][name len][host]
  const marker = Buffer.concat([Buffer.from([0x00, 0x00]), (() => {
    const l = Buffer.alloc(2); l.writeUInt16BE(5 + host.length, 0); return l;
  })(), (() => {
    const l = Buffer.alloc(2); l.writeUInt16BE(3 + host.length, 0); return l;
  })(), Buffer.from([0x00]), (() => {
    const l = Buffer.alloc(2); l.writeUInt16BE(host.length, 0); return l;
  })(), host]);
  const idx = record.indexOf(marker);
  const sniValueOffset = idx >= 0 ? idx + marker.length - host.length : -1;

  return { record, hello: handshake, sniValueOffset, ciphers: cipherSuites, groups: [grease2, 0x001d, 0x0017, 0x0018], alpn };
}

/** Распарсить ClientHello (record) в поля для JA3/JA4. */
function parseClientHello(record) {
  const r = {
    version: 0x0303,
    ciphers: [],
    extIds: [],
    groups: [],
    pointFormats: [],
    sigAlgs: [],
    sni: null,
    alpn: [],
    versions: [],
  };
  if (!record || record.length < 9 || record[0] !== 0x16) return r;
  let o = 5 + 4; // record + handshake header
  if (record[o] !== 0x03) return r;
  r.version = record.readUInt16BE(o); o += 2;
  o += 32; // random
  const sidLen = record[o]; o += 1 + sidLen;
  const csLen = record.readUInt16BE(o); o += 2;
  for (let i = 0; i < csLen; i += 2) r.ciphers.push(record.readUInt16BE(o + i));
  o += csLen;
  const compLen = record[o]; o += 1 + compLen;
  const extLen = record.readUInt16BE(o); o += 2;
  const extEnd = o + extLen;
  while (o + 4 <= extEnd && o + 4 <= record.length) {
    const id = record.readUInt16BE(o);
    const len = record.readUInt16BE(o + 2);
    const body = record.subarray(o + 4, o + 4 + len);
    r.extIds.push(id);
    if (id === 0x0000 && body.length >= 5) {
      const nl = body.readUInt16BE(3);
      r.sni = body.subarray(5, 5 + nl).toString('ascii');
    } else if (id === 0x000a && body.length >= 2) {
      const gl = body.readUInt16BE(0);
      for (let i = 2; i + 1 < 2 + gl && i + 1 < body.length; i += 2) r.groups.push(body.readUInt16BE(i));
    } else if (id === 0x000b && body.length >= 1) {
      const n = body[0];
      for (let i = 1; i <= n && i < body.length; i++) r.pointFormats.push(body[i]);
    } else if (id === 0x000d && body.length >= 2) {
      const sl = body.readUInt16BE(0);
      for (let i = 2; i + 1 < 2 + sl && i + 1 < body.length; i += 2) r.sigAlgs.push(body.readUInt16BE(i));
    } else if (id === 0x0010 && body.length >= 2) {
      let i = 2;
      while (i < body.length) {
        const l = body[i];
        r.alpn.push(body.subarray(i + 1, i + 1 + l).toString('ascii'));
        i += 1 + l;
      }
    } else if (id === 0x002b && body.length >= 1) {
      const n = body[0];
      for (let i = 1; i + 1 < 2 + n && i + 1 < body.length; i += 2) r.versions.push(body.readUInt16BE(i));
    }
    o += 4 + len;
  }
  return r;
}

function isGrease(v) {
  return (v & 0x0f0f) === 0x0a0a && (v >> 8) === (v & 0xff);
}

/** JA3: MD5(Version,Ciphers,Extensions,EllipticCurves,PointFormats) — значения в десятичном виде. */
function computeJa3(parsed) {
  const filt = (arr) => arr.filter((v) => !isGrease(v));
  const s = [
    parsed.version,
    filt(parsed.ciphers).join('-'),
    filt(parsed.extIds).join('-'),
    filt(parsed.groups).join('-'),
    parsed.pointFormats.join('-'),
  ].join(',');
  return { md5: md5hex(Buffer.from(s, 'ascii')), raw: s };
}

// Карта версий TLS для JA4 (спецификация FoxIO JA4).
const JA4_VERSION_MAP = {
  0x0304: '13', 0x0303: '12', 0x0302: '11', 0x0301: '10', 0x0300: 's3',
  0x0002: 's2', 0xfeff: 'd1', 0xfefd: 'd2', 0xfefc: 'd3',
};

/** JA4-ALPN: первый и последний ASCII-алфавитно-цифровой символ первого значения;
 *  если первый/последний байт не алфанумерический — первая и последняя цифры hex-представления;
 *  пусто/нет → "00"; одиночный символ удваивается. */
function ja4AlpnValue(alpnList) {
  const v = Array.isArray(alpnList) ? (alpnList.length ? alpnList[0] : '') : (alpnList || '');
  if (!v) return '00';
  const isAlnum = (c) => /^[0-9A-Za-z]$/.test(c);
  const first = v[0];
  const last = v[v.length - 1];
  if (isAlnum(first) && isAlnum(last)) return first + last;
  const hex = Buffer.from(v, 'latin1').toString('hex');
  return (hex[0] || '0') + (hex[hex.length - 1] || '0');
}

/**
 * JA4 (по спецификации FoxIO): t13d1516h2_<sha ciphers>_<sha exts+sigalgs>
 * — версия: верхняя из supported_versions (без GREASE), иначе legacy version;
 * — счётчик расширений: все кроме GREASE (SNI/ALPN/padding считаются);
 * — hash ciphers: сортированный hex-список без GREASE, пусто → 000000000000;
 * — hash extensions: сортированный hex-список без GREASE, SNI(0000) и ALPN(0010)
 *   исключены (padding остаётся), затем "_" + sigalgs В ПОРЯДКЕ ПОЯВЛЕНИЯ (не сорт.);
 *   без sigalgs подчёркивание не добавляется; пусто → 000000000000.
 */
function computeJa4(parsed) {
  const noGrease = (arr) => arr.filter((v) => !isGrease(v));
  const hex4 = (v) => v.toString(16).padStart(4, '0');

  // Версия
  let ver = '00';
  if (parsed.versions && parsed.versions.length) {
    const vs = noGrease(parsed.versions);
    if (vs.length) ver = JA4_VERSION_MAP[Math.max(...vs)] || '00';
  } else {
    ver = JA4_VERSION_MAP[parsed.version] || '00';
  }

  const ciphers = noGrease(parsed.ciphers).map(hex4).sort();
  const extAll = noGrease(parsed.extIds);
  const extCount = Math.min(extAll.length, 99);
  const extHashList = extAll
    .filter((e) => e !== 0x0000 && e !== 0x0010)
    .map(hex4)
    .sort();

  const sniChar = parsed.sni ? 'd' : 'i';
  const alpnStr = ja4AlpnValue(parsed.alpn);

  const a = `t${ver}${sniChar}${String(Math.min(ciphers.length, 99)).padStart(2, '0')}${String(extCount).padStart(2, '0')}${alpnStr}`;

  const b = ciphers.length ? sha256hex(Buffer.from(ciphers.join(','), 'ascii')).slice(0, 12) : '000000000000';

  let c = '000000000000';
  if (extHashList.length) {
    let s = extHashList.join(',');
    if (parsed.sigAlgs && parsed.sigAlgs.length) {
      s += '_' + parsed.sigAlgs.map(hex4).join(','); // в порядке появления
    }
    c = sha256hex(Buffer.from(s, 'ascii')).slice(0, 12);
  }
  return `${a}_${b}_${c}`;
}

/**
 * TCP-соединение с перехватом исходящих байт («что видит DPI»),
 * опционально — ручная отправка кусков (fragmentation).
 * Возвращает { socket, captured: Buffer[] }.
 */
function connectCaptured(host, port, timeoutMs) {
  return new Promise((resolve, reject) => {
    const socket = net.connect({ host, port });
    const captured = [];
    const origWrite = socket.write.bind(socket);
    socket.write = (chunk, ...rest) => {
      try { captured.push(Buffer.from(chunk)); } catch (_) {}
      return origWrite(chunk, ...rest);
    };
    const timer = setTimeout(() => {
      socket.destroy();
      reject(new Error('connect timeout'));
    }, timeoutMs);
    socket.once('connect', () => { clearTimeout(timer); resolve({ socket, captured }); });
    socket.once('error', (e) => { clearTimeout(timer); reject(e); });
  });
}

/** Ждать первый TLS record (0x16...) от сервера; вернуть { got, bytes, ms }. */
function waitTlsRecord(socket, timeoutMs) {
  return new Promise((resolve) => {
    const chunks = [];
    const t0 = now();
    let done = false;
    const finish = (got, note) => {
      if (done) return;
      done = true;
      socket.removeListener('data', onData);
      resolve({ got, note: note || null, bytes: Buffer.concat(chunks), ms: now() - t0 });
    };
    const onData = (d) => {
      chunks.push(d);
      const all = Buffer.concat(chunks);
      if (all.length >= 5 && all[0] === 0x16) {
        const need = 5 + all.readUInt16BE(3);
        if (all.length >= need) finish(true, 'server-hello');
      } else if (all.length >= 1 && all[0] !== 0x16 && all[0] !== 0x15) {
        finish(false, 'non-tls-first-byte:' + all[0].toString(16));
      } else if (all.length >= 5 && all[0] === 0x15) {
        // alert — сервер/файрвол отвечает алертом
        finish(false, 'tls-alert');
      }
    };
    socket.on('data', onData);
    socket.on('close', () => finish(chunks.length > 0, 'closed'));
    socket.on('error', () => finish(false, 'socket-error'));
    setTimeout(() => finish(false, 'timeout'), timeoutMs);
  });
}

/**
 * Полный тест одного способа отправки ClientHello.
 * mode: naive | split1 | split-mid-sni | record-split | tiny-records
 */
async function fragProbe(host, port, sni, mode, timeoutMs) {
  const t0 = now();
  let conn;
  try {
    conn = await connectCaptured(host, port, timeoutMs);
  } catch (e) {
    return { mode, ok: false, stage: 'connect', error: String(e.message || e), ms: now() - t0 };
  }
  const { socket, captured } = conn;
  const built = buildChromeClientHello(sni);
  const rec = built.record;
  try {
    if (mode === 'naive') {
      socket.write(rec);
    } else if (mode === 'split1') {
      socket.write(rec.subarray(0, 1));
      await sleep(30);
      socket.write(rec.subarray(1));
    } else if (mode === 'split-mid-sni') {
      const mid = built.sniValueOffset > 0 ? built.sniValueOffset + Math.floor(sni.length / 2) : Math.floor(rec.length / 2);
      socket.write(rec.subarray(0, mid));
      await sleep(30);
      socket.write(rec.subarray(mid));
    } else if (mode === 'record-split') {
      // Первый record содержит 1 байт handshake-сообщения, второй — остальное (RFC 8446 §5.1)
      const head = Buffer.from([0x16, 0x03, 0x01, 0x00, 0x01, rec[5]]);
      const rest = rec.subarray(6);
      const rec2 = Buffer.concat([Buffer.from([0x16, 0x03, 0x01]), (() => {
        const l = Buffer.alloc(2); l.writeUInt16BE(rest.length, 0); return l;
      })(), rest]);
      socket.write(head);
      await sleep(30);
      socket.write(rec2);
    } else if (mode === 'tiny-records') {
      // ClientHello, разложенный на много мелких TLS records (по 8 байт handshake)
      const payload = rec.subarray(5);
      let first = true;
      for (let i = 0; i < payload.length; i += 8) {
        const chunk = payload.subarray(i, i + 8);
        const r = Buffer.concat([Buffer.from([0x16, 0x03, 0x01]), (() => {
          const l = Buffer.alloc(2); l.writeUInt16BE(chunk.length, 0); return l;
        })(), chunk]);
        socket.write(r);
        if (first) { first = false; await sleep(10); }
      }
    } else {
      socket.write(rec);
    }
    const res = await waitTlsRecord(socket, timeoutMs);
    socket.destroy();
    return {
      mode,
      ok: res.got,
      note: res.note,
      ms: now() - t0,
      respBytes: res.bytes.length,
      sentBytes: captured.reduce((a, b) => a + b.length, 0),
      writes: captured.length,
    };
  } catch (e) {
    try { socket.destroy(); } catch (_) {}
    return { mode, ok: false, stage: 'send', error: String(e.message || e), ms: now() - t0 };
  }
}

/**
 * TCP-релей с записью потока «клиент -> сервер» (надёжный захват того,
 * что реально уходит в сеть — «как это видит DPI»).
 */
function startCaptureRelay(targetHost, targetPort) {
  return new Promise((resolve, reject) => {
    const clientChunks = [];
    const sockets = new Set();
    const server = net.createServer((client) => {
      const upstream = net.connect({ host: targetHost, port: targetPort });
      sockets.add(client);
      sockets.add(upstream);
      client.on('data', (d) => clientChunks.push(Buffer.from(d)));
      client.pipe(upstream);
      upstream.pipe(client);
      const kill = () => {
        sockets.delete(client);
        sockets.delete(upstream);
        try { client.destroy(); } catch (_) {}
        try { upstream.destroy(); } catch (_) {}
      };
      client.on('error', kill);
      upstream.on('error', kill);
      client.on('close', () => sockets.delete(client));
      upstream.on('close', () => sockets.delete(upstream));
    });
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      resolve({
        port: server.address().port,
        clientBytes: () => Buffer.concat(clientChunks),
        close: () => {
          for (const s of sockets) {
            try { s.destroy(); } catch (_) {}
          }
          sockets.clear();
          try { server.close(); } catch (_) {}
        },
      });
    });
  });
}

/** Реальный TLS-хендшейк; захват ClientHello через релей («как видит DPI»). */
async function realTlsHandshake(host, port, servername, timeoutMs, alpn) {
  const t0 = now();
  let relay = null;
  try {
    relay = await startCaptureRelay(host, port);
  } catch (e) {
    return { ok: false, error: 'relay: ' + String(e.message || e), ms: now() - t0 };
  }
  return new Promise((resolve) => {
    let done = false;
    const finish = (r) => {
      if (done) return;
      done = true;
      const wire = relay.clientBytes();
      const parsed = wire.length ? parseClientHello(wire) : null;
      const ch = parsed && parsed.ciphers.length ? {
        ja3: computeJa3(parsed).md5,
        ja4: computeJa4(parsed),
        sni: parsed.sni,
        ciphers: parsed.ciphers.length,
        exts: parsed.extIds.length,
        versions: parsed.versions.map((v) => v.toString(16)),
      } : null;
      relay.close();
      resolve({ ...r, clienthello: r.clienthello || ch, sentBytes: wire.length, ms: now() - t0 });
    };
    const timer = setTimeout(() => {
      finish({ ok: false, error: 'timeout' });
    }, timeoutMs);

    let t;
    try {
      t = tls.connect({
        host: '127.0.0.1',
        port: relay.port,
        servername: net.isIP(host) ? servername : (servername || host),
        ALPNProtocols: alpn || ['h2', 'http/1.1'],
        minVersion: 'TLSv1.2',
        rejectUnauthorized: false,
      });
    } catch (e) {
      clearTimeout(timer);
      finish({ ok: false, error: String(e.message || e) });
      return;
    }

    t.on('secureConnect', () => {
      clearTimeout(timer);
      const cert = (typeof t.getPeerCertificate === 'function' && t.getPeerCertificate(false)) || {};
      let proto = null;
      try { proto = (t.getProtocol && t.getProtocol()) || t.protocol || null; } catch (_) {}
      const info = {
        ok: true,
        protocol: proto,
        cipher: t.getCipher() ? t.getCipher().name : null,
        alpn: t.alpnProtocol || null,
        authorized: t.authorized,
        cert: cert && cert.subject ? {
          subject: cert.subject.CN || (cert.subject.O || ''),
          issuer: cert.issuer ? (cert.issuer.O || cert.issuer.CN || '') : '',
          valid_from: cert.valid_from || null,
          valid_to: cert.valid_to || null,
          san: (cert.subjectaltname || '').split(',').slice(0, 4).map((s) => s.trim()),
        } : null,
      };
      try { t.destroy(); } catch (_) {}
      finish(info);
    });
    t.on('error', (e) => {
      clearTimeout(timer);
      finish({ ok: false, error: String(e.message || e), code: e.code || null });
    });
  });
}

/** TCP connect + RTT. */
function tcpConnect(host, port, timeoutMs) {
  return new Promise((resolve) => {
    const t0 = now();
    const sock = net.connect({ host, port });
    const timer = setTimeout(() => {
      sock.destroy();
      resolve({ ok: false, error: 'timeout', ms: now() - t0 });
    }, timeoutMs);
    sock.once('connect', () => {
      clearTimeout(timer);
      const ms = now() - t0;
      sock.destroy();
      resolve({ ok: true, ms });
    });
    sock.once('error', (e) => {
      clearTimeout(timer);
      resolve({ ok: false, error: String(e.message || e), code: e.code || null, ms: now() - t0 });
    });
  });
}

/** SNI-тест: один и тот же IP, разные SNI — как фильтруют. */
async function sniFilterTest(ip, realHost, coverSni, timeoutMs) {
  const a = await realTlsHandshake(ip, 443, realHost, timeoutMs);
  const b = await realTlsHandshake(ip, 443, coverSni, timeoutMs);
  let verdict = 'ok';
  let note = 'Оба хендшейка проходят — SNI-фильтрации на пути не видно.';
  if (a.ok && !b.ok) {
    verdict = 'mismatch';
    note = `Родной SNI (${realHost}) проходит, cover-SNI (${coverSni}) — нет. ` +
      'Это может быть как SNI-фильтрацией на пути, так и виртуальным хостингом сервера (чужой SNI отвергает сам сервер). ' +
      'Тест информативен, когда cover-SNI принадлежит той же CDN/инфраструктуре.';
  } else if (!a.ok && b.ok) {
    verdict = 'blocklist';
    note = `SNI ${realHost} блокируется, cover-SNI проходит — блок-лист по домену на пути.`;
  } else if (!a.ok && !b.ok) {
    verdict = 'both-fail';
    note = 'Не проходит ни один хендшейк — вероятна блокировка по IP/подсети либо недоступна сеть.';
  }
  return { real: a, cover: b, verdict, note };
}
