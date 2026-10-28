// ---------------------------------------------------------------------------
// 80. Selftest: регрессионные проверки движка QPD (CI-ready)
//
// Золотые векторы взяты из официальной спецификации FoxIO JA4
// (FoxIO-LLC/ja4, technical_details/JA4.md) — рабочий пример:
//   JA4 = t13d1516h2_8daaf6152771_e5627efa2ab1
// и из алгоритма JA3 (MD5 десятичных полей ClientHello).
// ---------------------------------------------------------------------------

const SELFTEST_RESULTS = [];

function st(name, ok, detail) {
  SELFTEST_RESULTS.push({ name, ok: !!ok, detail: detail == null ? '' : String(detail) });
}

function stEq(name, actual, expected) {
  const ok = JSON.stringify(actual) === JSON.stringify(expected);
  st(name, ok, ok ? '' : `got=${JSON.stringify(actual)} want=${JSON.stringify(expected)}`);
}

/** Синтетический ClientHello из атрибутов рабочего примера спецификации JA4. */
function buildSpecExampleHello() {
  const ciphers = [
    0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030,
    0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
  ];
  const sigAlgs = [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601];
  const host = 'example.com';

  const u16 = (v) => { const b = Buffer.alloc(2); b.writeUInt16BE(v, 0); return b; };
  const ext = (id, body) => Buffer.concat([u16(id), u16(body.length), body]);

  const sniBody = Buffer.concat([
    u16(3 + host.length), Buffer.from([0x00]), u16(host.length), Buffer.from(host, 'ascii'),
  ]);
  const alpnList = Buffer.concat([Buffer.from([0x02]), Buffer.from('h2', 'ascii')]);
  const alpnBody = Buffer.concat([u16(alpnList.length), alpnList]);
  const sigBody = Buffer.concat([u16(sigAlgs.length * 2), ...sigAlgs.map(u16)]);
  const groupsBody = Buffer.concat([u16(6), u16(0x001d), u16(0x0017), u16(0x0018)]);
  const versionsBody = Buffer.from([0x04, 0x03, 0x04, 0x03, 0x03]); // [len][0304][0303]

  // Порядок расширений — как в рабочем примере спецификации (важно для JA3)
  const extensions = [
    ext(0x001b, Buffer.from([0x00, 0x02, 0x00, 0x02])),
    ext(0x0000, sniBody),
    ext(0x0033, u16(0)),
    ext(0x0010, alpnBody),
    ext(0x4469, u16(0)),
    ext(0x0017, Buffer.alloc(0)),
    ext(0x002d, Buffer.from([0x01, 0x01])),
    ext(0x000d, sigBody),
    ext(0x0005, Buffer.from([0x01, 0x00, 0x00, 0x00, 0x00])),
    ext(0x0023, Buffer.alloc(0)),
    ext(0x0012, Buffer.alloc(0)),
    ext(0x002b, versionsBody),
    ext(0xff01, Buffer.from([0x00])),
    ext(0x000b, Buffer.from([0x01, 0x00])),
    ext(0x000a, groupsBody),
    ext(0x0015, Buffer.alloc(4)),
  ];

  const csBuf = Buffer.concat([u16(ciphers.length * 2), ...ciphers.map(u16)]);
  const extsBuf = Buffer.concat(extensions);
  const body = Buffer.concat([
    Buffer.from([0x03, 0x03]),
    Buffer.alloc(32, 7),                    // random
    Buffer.from([0x00]),                    // session_id пустой
    csBuf,
    Buffer.from([0x01, 0x00]),              // compression
    u16(extsBuf.length),
    extsBuf,
  ]);
  const hs = Buffer.concat([
    Buffer.from([0x01]),
    Buffer.from([(body.length >> 16) & 0xff, (body.length >> 8) & 0xff, body.length & 0xff]),
    body,
  ]);
  return Buffer.concat([Buffer.from([0x16, 0x03, 0x01]), u16(hs.length), hs]);
}

/** Синтетический DNS-ответ: вопрос со сжатым именем (0xc00c) + A-ответ. */
function buildDnsResponseFixture(poison) {
  const parts = [];
  const hdr = Buffer.alloc(12);
  hdr.writeUInt16BE(0x1234, 0);   // id
  hdr.writeUInt16BE(0x8180, 2);   // flags: response, recursion
  hdr.writeUInt16BE(1, 4);        // qd
  hdr.writeUInt16BE(1, 6);        // an
  parts.push(hdr);
  // Вопрос: имя = указатель 0xc00c (сжатие) + type A + class IN
  parts.push(Buffer.from([0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01]));
  // Ответ: имя-указатель + A + IN + ttl 60 + 1.2.3.4 (или 10.0.0.1)
  const rdata = poison ? Buffer.from([10, 0, 0, 1]) : Buffer.from([1, 2, 3, 4]);
  const ans = Buffer.concat([
    Buffer.from([0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01]),
    Buffer.from([0, 0, 0, 60]),
    Buffer.from([0x00, 0x04]),
    rdata,
  ]);
  parts.push(ans);
  return Buffer.concat(parts);
}

function runSelftest() {
  // ---------------------------------------------------------------- JA4/JA3
  const rec = buildSpecExampleHello();
  stEq('hello.record_header', [rec[0], rec[5]], [0x16, 0x01]);
  stEq('hello.length_consistent', rec.readUInt16BE(3), rec.length - 5);

  const parsed = parseClientHello(rec);
  stEq('parse.sni', parsed.sni, 'example.com');
  stEq('parse.ciphers_count', parsed.ciphers.length, 15);
  stEq('parse.ext_order', parsed.extIds.map((e) => e.toString(16)),
    ['1b', '0', '33', '10', '4469', '17', '2d', 'd', '5', '23', '12', '2b', 'ff01', 'b', 'a', '15']);
  stEq('parse.sigalgs_order', parsed.sigAlgs.map((e) => e.toString(16)),
    ['403', '804', '401', '503', '805', '501', '806', '601']);
  stEq('parse.alpn', parsed.alpn, ['h2']);
  stEq('parse.versions', parsed.versions, [0x0304, 0x0303]);
  stEq('parse.groups', parsed.groups, [0x001d, 0x0017, 0x0018]);

  // JA4: рабочий пример спецификации FoxIO
  stEq('ja4.spec_example', computeJa4(parsed), 't13d1516h2_8daaf6152771_e5627efa2ab1');

  // JA3: десятичная конкатенация по алгоритму Salesforce JA3
  const ja3 = computeJa3(parsed);
  stEq('ja3.raw_string', ja3.raw,
    '771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,' +
    '27-0-51-16-17513-23-45-13-5-35-18-43-65281-11-10-21,29-23-24,0');
  stEq('ja3.md5', ja3.md5, 'c000e2caf3a25423f9de6c8a4b12a975');

  // ---------------------------------------------------------- JA4-векторы ALPN
  stEq('ja4.alpn.h2', ja4AlpnValue(['h2']), 'h2');
  stEq('ja4.alpn.http11', ja4AlpnValue(['http/1.1']), 'h1');
  stEq('ja4.alpn.single', ja4AlpnValue(['x']), 'xx');
  stEq('ja4.alpn.empty', ja4AlpnValue(['']), '00');
  stEq('ja4.alpn.none', ja4AlpnValue(null), '00');
  stEq('ja4.alpn.empty_first', ja4AlpnValue(['', 'h2']), '00');
  stEq('ja4.alpn.list_first', ja4AlpnValue(['x', 'h2']), 'xx');
  stEq('ja4.alpn.hex_fallback', ja4AlpnValue(['a ']), '60'); // 0x61 0x20 → "6120" → "60"

  // ------------------------------------------------------------- JA4-версии
  const mk = (o) => Object.assign({ version: 0x0303, ciphers: [0x1301], extIds: [0x0000, 0x0010], groups: [], pointFormats: [], sigAlgs: [], sni: 'x', alpn: ['h2'], versions: [] }, o);
  st('ja4.ver_tls13', computeJa4(mk({ versions: [0x0303, 0x0304] })).startsWith('t13'), computeJa4(mk({ versions: [0x0303, 0x0304] })));
  st('ja4.ver_tls12', computeJa4(mk({ versions: [0x0302, 0x0303] })).startsWith('t12'), computeJa4(mk({ versions: [0x0302, 0x0303] })));
  st('ja4.ver_legacy10', computeJa4(mk({ versions: [], version: 0x0301 })).startsWith('t10'), computeJa4(mk({ versions: [], version: 0x0301 })));
  st('ja4.no_sni_i', computeJa4(mk({ sni: null, versions: [0x0304], extIds: [0x0010] })).startsWith('t13i'), computeJa4(mk({ sni: null, versions: [0x0304], extIds: [0x0010] })));

  // --------------------------------------------------------------- GREASE
  st('grease.0a0a', isGrease(0x0a0a));
  st('grease.fafa', isGrease(0xfafa));
  st('grease.not_0a0b', !isGrease(0x0a0b));
  st('grease.not_cipher', !isGrease(0x1301));

  // ------------------------------------------------------- Билдер ClientHello
  const built = buildChromeClientHello('example.com');
  stEq('builder.record_header', [built.record[0], built.record[5]], [0x16, 0x01]);
  stEq('builder.length_consistent', built.record.readUInt16BE(3), built.record.length - 5);
  const bp = parseClientHello(built.record);
  stEq('builder.roundtrip_sni', bp.sni, 'example.com');
  stEq('builder.ciphers_nongrease', bp.ciphers.filter((c) => !isGrease(c)).length, 15);
  st('builder.sni_offset', built.sniValueOffset > 0 &&
    built.record.subarray(built.sniValueOffset, built.sniValueOffset + 11).toString('ascii') === 'example.com');
  const bj = computeJa4(bp);
  st('builder.ja4_shape', /^t13d151[45]h2_[0-9a-f]{12}_[0-9a-f]{12}$/.test(bj), bj);
  st('builder.ja4_version', bj.startsWith('t13'), bj);
  // стабильность: два построения с одинаковым random/keys дают одинаковый JA4
  const fixed = { random: Buffer.alloc(32, 1), sessionId: Buffer.alloc(32, 2), keyShare: Buffer.alloc(32, 3) };
  const b1 = computeJa4(parseClientHello(buildChromeClientHello('example.com', fixed).record));
  const b2 = computeJa4(parseClientHello(buildChromeClientHello('example.com', fixed).record));
  stEq('builder.ja4_deterministic', b1, b2);

  // -------------------------------------------------------- DNS-парсер
  const dnsOk = parseDnsResponse(buildDnsResponseFixture(false));
  stEq('dns.rcode', dnsOk.rcode, 0);
  stEq('dns.answers', dnsOk.answers, [{ type: 'A', data: '1.2.3.4' }]);
  const dnsPoison = parseDnsResponse(buildDnsResponseFixture(true));
  st('dns.poison_detect', dnsPoison.answers.length === 1 && isPrivateIPv4(dnsPoison.answers[0].data));
  st('dns.private_check', isPrivateIPv4('192.168.1.1') && isPrivateIPv4('127.0.0.1') && !isPrivateIPv4('8.8.8.8') && !isPrivateIPv4('1.1.1.1'));

  // ------------------------------------------------- Инварианты лаборатории
  for (const mode of ['raw-magic', 'tls-random', 'browser-shaped']) {
    for (const scenario of ['web', 'tunnel']) {
      const traffic = generateTraffic(mode, scenario);
      const row = inspectTraffic(
        mode, scenario,
        Buffer.concat(traffic.client.map((w) => w.buf)),
        Buffer.concat(traffic.server.map((w) => w.buf)),
        traffic.client.map((w) => w.delay || 0),
        { endpointHygiene: 0.5 }
      );
      if (mode === 'raw-magic') {
        stEq(`lab.sig1.${mode}.${scenario}`, row.signals['1_сигнатура'], 1.0);
        stEq(`lab.records.${mode}.${scenario}`, row.metrics.record_count, 0);
      } else {
        stEq(`lab.sig1.${mode}.${scenario}`, row.signals['1_сигнатура'], 0.0);
        st(`lab.records.${mode}.${scenario}`, row.metrics.record_count > 2, row.metrics.record_count);
      }
      if (mode === 'browser-shaped' && scenario === 'tunnel') {
        stEq('lab.sig3.browser.tunnel', row.signals['3_форма_потока'], 1.0);
      }
      if (mode === 'browser-shaped' && scenario === 'web') {
        stEq('lab.sig3.browser.web', row.signals['3_форма_потока'], 0.15);
      }
      if (mode === 'tls-random' && scenario === 'tunnel') {
        stEq('lab.uniform_records_tls_random', row.metrics.record_size_entropy, 0);
        stEq('lab.sig2_tls_random_tunnel', row.signals['2_случайность/структура'], 1.0);
      }
    }
  }

  // ------------------------------------------------------------------ итог
  const failed = SELFTEST_RESULTS.filter((r) => !r.ok);
  return { total: SELFTEST_RESULTS.length, failed: failed.length, results: SELFTEST_RESULTS };
}
