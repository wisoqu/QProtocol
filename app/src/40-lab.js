// ---------------------------------------------------------------------------
// 40. Лаборатория детектируемости «Пиросто»
//
// Задача: измерить, как кастомный транспорт выглядит «глазами» модели
// ТСПУ-2026 (сигнатура -> случайность первых 16КБ -> форма потока ->
// тайминги -> репутация конечной точки). Эксперимент идёт по loopback:
// клиент и сервер пишут в сокеты, инспектор анализирует реальные байты.
//
// Три режима (эволюция «Пиросто»-класса):
//   A raw-magic       — «наивный» кастомный протокол с магией (как чистый SS/свой формат)
//   B tls-random      — полезная нагрузка в TLS-record, но случайная и симметричная
//   C browser-shaped  — TLS-record + паддинг + веб-подобная форма потока/таймингов
// ---------------------------------------------------------------------------

function tlsAppData(payload) {
  const rec = Buffer.alloc(5 + payload.length);
  rec[0] = 0x17; rec[1] = 0x03; rec[2] = 0x03;
  rec.writeUInt16BE(payload.length, 3);
  payload.copy(rec, 5);
  return rec;
}

function rawMagic(payload) {
  const rec = Buffer.alloc(6 + payload.length);
  rec.write('PRST', 0, 'ascii');
  rec.writeUInt16BE(payload.length, 4);
  payload.copy(rec, 6);
  return rec;
}

/** Сгенерировать список записей (режим x сценарий). */
function generateTraffic(mode, scenario) {
  // Возвращает { client: [{buf, delay}], server: [{buf, delay}] }
  const client = [];
  const server = [];
  const rand = (n) => crypto.randomBytes(n);

  const pushC = (buf, delay) => client.push({ buf, delay });
  const pushS = (buf, delay) => server.push({ buf, delay });

  if (scenario === 'web') {
    // Браузерный обмен: маленький запрос, «картинки/страница» в ответ.
    const req = rand(600);
    if (mode === 'raw-magic') {
      pushC(rawMagic(req), 40);
      // ответ: скрипты/картинки
      for (let i = 0; i < 8; i++) pushS(rawMagic(rand(4096)), 15 + i * 8);
      pushC(rawMagic(rand(200)), 250);
      pushS(rawMagic(rand(900)), 40);
    } else if (mode === 'tls-random') {
      pushC(tlsAppData(req), 40);
      for (let i = 0; i < 12; i++) pushS(tlsAppData(rand(4096)), 5); // мгновенная выгрузка, одинаковые записи
      pushC(tlsAppData(rand(200)), 250);
      pushS(tlsAppData(rand(900)), 40);
    } else { // browser-shaped
      // заголовки запроса мелкими записями, ответ — всплесками как веб-страница
      pushC(tlsAppData(rand(240)), 35);
      pushC(tlsAppData(rand(180)), 12);
      const bursts = [5200, 12800, 3300, 1600, 8600, 4500, 2100];
      for (const size of bursts) {
        let left = size;
        while (left > 0) {
          const chunk = Math.min(left, 1300 + crypto.randomInt(0, 500));
          pushS(tlsAppData(rand(chunk)), 20 + crypto.randomInt(0, 60));
          left -= chunk;
        }
        pushS(tlsAppData(rand(120)), 200 + crypto.randomInt(0, 400)); // пауза «между ресурсами»
      }
      pushC(tlsAppData(rand(160)), 600 + crypto.randomInt(0, 900));
      pushS(tlsAppData(rand(700)), 90);
    }
  } else {
    // Туннель: симметричный поток ~32КБ в обе стороны (типичный «прокси-профиль»)
    const chunks = 10;
    const per = 3200;
    for (let i = 0; i < chunks; i++) {
      const delay = mode === 'browser-shaped' ? 30 + crypto.randomInt(0, 80) : 8;
      if (mode === 'raw-magic') {
        pushC(rawMagic(rand(per)), delay);
        pushS(rawMagic(rand(per)), delay);
      } else if (mode === 'tls-random') {
        pushC(tlsAppData(rand(per)), delay);
        pushS(tlsAppData(rand(per)), delay);
      } else {
        // паддинг + разные размеры записей, но направления всё равно симметричны
        const cSize = 800 + crypto.randomInt(0, 2400);
        const sSize = 800 + crypto.randomInt(0, 2400);
        pushC(tlsAppData(rand(cSize)), delay);
        pushS(tlsAppData(rand(sSize)), delay);
      }
    }
  }
  return { client, server };
}

/** Инспектор «модель ТСПУ»:5 сигналов + сводный риск. */
function inspectTraffic(mode, scenario, clientBytes, serverBytes, clientDelays, meta) {
  const first16 = clientBytes.subarray(0, 16);
  // DPI видит весь поток 5-tuple в обе стороны — анализируем суммарный поток
  const flow = Buffer.concat([clientBytes, serverBytes]);
  const first16k = flow.subarray(0, 16384);
  const ent = shannonEntropy(first16k);
  const entClient = shannonEntropy(clientBytes.subarray(0, 16384));

  // Разбор потока на TLS-подобные записи (в обоих направлениях)
  const records = [];
  for (const dirBytes of [clientBytes, serverBytes]) {
    let o = 0;
    while (o + 5 <= dirBytes.length) {
      const typ = dirBytes[o];
      const ver = dirBytes.readUInt16BE(o + 1);
      const len = dirBytes.readUInt16BE(o + 3);
      void ver;
      if (len > 20000 || (typ !== 0x17 && typ !== 0x16 && typ !== 0x15)) break;
      records.push({ typ, len });
      o += 5 + len;
    }
  }
  const sizes = records.map((r) => r.len);
  const sizeEnt = sizes.length > 1 ? shannonEntropy(Buffer.from(sizes.map((s) => Math.min(255, s % 256)))) : 0;
  const maxSat = sizes.length ? sizes.filter((s) => s >= 1500).length / sizes.length : 0;

  const bC = clientBytes.length;
  const bS = serverBytes.length;
  const ratio = bC > 0 ? bS / bC : 0;

  // --- Сигнал 1: сигнатура первых байт -----------------------------------
  const tlsLike = first16.length >= 3 && (first16[0] === 0x16 || first16[0] === 0x17) && first16[1] === 0x03;
  const httpLike = /^(GET |POST|HEAD|PUT |HTTP)/.test(first16.toString('latin1'));
  const s1 = tlsLike || httpLike ? 0.0 : 1.0;

  // --- Сигнал 2: «случайность» первых 16КБ + структура записей -----------
  // Поле атаки фев.2026: трафик «абсолютный шум» + не похож на профиль браузинга.
  const entropyRisk = ent > 7.5 ? 1.0 : ent > 6.5 ? 0.5 : 0.1;
  const structRisk = records.length > 2 && sizeEnt < 2.2 ? 1.0 : 0.35;
  const s2 = Math.min(1, 0.5 * entropyRisk + 0.5 * structRisk);

  // --- Сигнал 3: форма потока (in/out) ----------------------------------
  // Туннель характеризуется симметрией; веб/видео — скачиванием (out >> in).
  let s3;
  if (ratio >= 0.7 && ratio <= 1.5) s3 = 1.0;         // симметрично = туннельный профиль
  else if (ratio > 1.5 && ratio < 2.5) s3 = 0.55;
  else if (ratio >= 2.5) s3 = 0.15;                    // download-профиль (веб/видео)
  else s3 = 0.5;                                       // upload-профиль (редко для браузинга)

  // --- Сигнал 4: тайминги ------------------------------------------------
  const tcv = cv(clientDelays);
  const s4 = scenario === 'web'
    ? (tcv < 0.35 ? 0.85 : tcv < 0.8 ? 0.5 : 0.15)     // ровный поток в «вебе» подозрителен
    : (tcv < 0.35 ? 0.9 : tcv < 0.8 ? 0.6 : 0.4);      // и в туннеле тайминги выдают

  // --- Сигнал 5: репутация конечной точки / гигиена сервера -------------
  // Оценивается по конфигурации (ASN, соответствие SNI инфраструктуре,
  // параллелизм) — вне трафика эксперимента.
  const s5 = meta && meta.endpointHygiene ? meta.endpointHygiene : 0.5;

  const weights = { sig: 0.25, rand: 0.25, flow: 0.25, time: 0.15, endpoint: 0.10 };
  const score = 100 * (
    weights.sig * s1 + weights.rand * s2 + weights.flow * s3 +
    weights.time * s4 + weights.endpoint * s5
  );

  return {
    mode,
    scenario,
    signals: {
      '1_сигнатура': +s1.toFixed(2),
      '2_случайность/структура': +s2.toFixed(2),
      '3_форма_потока': +s3.toFixed(2),
      '4_тайминги': +s4.toFixed(2),
      '5_эндпоинт(конфиг)': +s5.toFixed(2),
    },
    metrics: {
      entropy_flow_16kb: +ent.toFixed(3),
      entropy_client: +entClient.toFixed(3),
      record_count: records.length,
      record_size_entropy: +sizeEnt.toFixed(2),
      records_ge_1500_frac: +maxSat.toFixed(2),
      in_out_ratio: +ratio.toFixed(2),
      timing_cv: +tcv.toFixed(2),
    },
    detectability_score: Math.round(score),
    verdict: score >= 66 ? 'ОПАСНО: высокий риск детектирования/заморозки'
      : score >= 40 ? 'ПОДОЗРИТЕЛЬНО: рискованно для массового применения'
        : 'ПРОХОДИТ модель (низкий риск по измеренным сигналам)',
  };
}

/** Прогнать все режимы по loopback и собрать таблицу. */
async function runLab() {
  const scenarios = ['web', 'tunnel'];
  const modes = ['raw-magic', 'tls-random', 'browser-shaped'];
  const rows = [];

  for (const mode of modes) {
    for (const scenario of scenarios) {
      const traffic = generateTraffic(mode, scenario);
      // Эмуляция записи в сокет: реальные буферы, реальные задержки между записями
      const clientBytesArr = [];
      const serverBytesArr = [];
      const clientDelays = [];
      for (const w of traffic.client) {
        clientBytesArr.push(w.buf);
        if (w.delay) { await sleep(Math.min(w.delay, 30)); clientDelays.push(w.delay); }
        else clientDelays.push(0);
      }
      for (const w of traffic.server) {
        serverBytesArr.push(w.buf);
        if (w.delay) await sleep(Math.min(w.delay, 15));
      }
      const row = inspectTraffic(
        mode,
        scenario,
        Buffer.concat(clientBytesArr),
        Buffer.concat(serverBytesArr),
        clientDelays,
        { endpointHygiene: 0.5 }
      );
      rows.push(row);
    }
  }

  // Сводка и рекомендация
  const summary = {
    rows,
    legend: {
      '1_сигнатура': 'Первые 16–32 байта не похожи на TLS/HTTP → мгновенная сигнатура (слой 1).',
      '2_случайность/структура': '«Случайность» первых 16КБ + монотонные размеры записей (атака фев.2026).',
      '3_форма_потока': 'Отношение входящего/исходящего трафика: туннель симметричен, веб — нет.',
      '4_тайминги': 'CV межзаписных интервалов: ровный поток = туннель, всплески = браузер.',
      '5_эндпоинт(конфиг)': 'SNI≠инфраструктура, зарубежный хостинг, залпы хендшейков (Сигнал 3).',
    },
    recommendation: '',
  };

  const byMode = (m) => rows.filter((r) => r.mode === m).map((r) => r.detectability_score);
  const avg = (a) => Math.round(a.reduce((x, y) => x + y, 0) / a.length);
  summary.scores = {
    'raw-magic': avg(byMode('raw-magic')),
    'tls-random': avg(byMode('tls-random')),
    'browser-shaped': avg(byMode('browser-shaped')),
  };
  summary.recommendation =
    `Наивный формат (raw-magic) детектируется сразу (риск ${summary.scores['raw-magic']}%), ` +
    `«случайный» туннель в TLS-record — на поведенческом слое (риск ${summary.scores['tls-random']}%), ` +
    `веб-обёртка снижает риск (риск ${summary.scores['browser-shaped']}%), но НЕ спасает при туннельном ` +
    `сценарии: форма потока и тайминги выдают туннель даже внутри идеального TLS-фрейминга. ` +
    `Вывод: «Пиросто» должен быть не просто замаскированным протоколом, а транспортом, ` +
    `который статистически неотличим от браузерного сценария (мультиплексирование, паддинг, ` +
    `пейсинг, сервер с реальной веб-нагрузкой).`;

  return summary;
}
