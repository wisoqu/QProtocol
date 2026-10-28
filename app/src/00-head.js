#!/usr/bin/env node
/*
 * QPD — QProtocol Diagnostics
 * Полноценное приложение диагностики цензурных ограничений и детектируемости
 * транспортов (лаборатория «Пиросто»).
 *
 * Сборка: build.sh превращает app/src/*.js в единый app/main.js,
 * затем node SEA упаковывает его в бинарь bin/qprotocol.
 */
'use strict';

const net = require('net');
const tls = require('tls');
const dns = require('dns');
const dgram = require('dgram');
const http = require('http');
const fs = require('fs');
const os = require('os');
const crypto = require('crypto');
const { URL } = require('url');

const VERSION = '0.1.0';
const APP_NAME = 'QPD (QProtocol Diagnostics)';

// ---------------------------------------------------------------------------
// Утилиты
// ---------------------------------------------------------------------------

function now() { return Date.now(); }

function sleep(ms) { return new Promise((r) => setTimeout(r, ms)); }

/** Выполнить fn с таймаутом; возвращает {ok, value|error, ms}. */
async function timed(fn, timeoutMs) {
  const t0 = now();
  let timer;
  try {
    const value = await Promise.race([
      fn(),
      new Promise((_, rej) => {
        timer = setTimeout(() => rej(new Error('timeout ' + timeoutMs + 'ms')), timeoutMs);
      }),
    ]);
    return { ok: true, value, ms: now() - t0 };
  } catch (error) {
    return { ok: false, error: String(error && error.message ? error.message : error), ms: now() - t0 };
  } finally {
    if (timer) clearTimeout(timer);
  }
}

function ipToLong(ip) {
  const p = ip.split('.').map(Number);
  return ((p[0] << 24) >>> 0) + (p[1] << 16) + (p[2] << 8) + p[3];
}

function isPrivateIPv4(ip) {
  if (!net.isIPv4(ip)) return false;
  const n = ipToLong(ip);
  const ranges = [
    [ipToLong('10.0.0.0'), ipToLong('10.255.255.255')],
    [ipToLong('172.16.0.0'), ipToLong('172.31.255.255')],
    [ipToLong('192.168.0.0'), ipToLong('192.168.255.255')],
    [ipToLong('127.0.0.0'), ipToLong('127.255.255.255')],
    [ipToLong('169.254.0.0'), ipToLong('169.254.255.255')],
    [ipToLong('0.0.0.0'), ipToLong('0.255.255.255')],
  ];
  return ranges.some(([a, b]) => n >= a && n <= b);
}

/** Энтропия Шеннона на байт (бит/байт). */
function shannonEntropy(buf) {
  if (!buf || buf.length === 0) return 0;
  const counts = new Array(256).fill(0);
  for (let i = 0; i < buf.length; i++) counts[buf[i]]++;
  let h = 0;
  for (let i = 0; i < 256; i++) {
    if (counts[i] === 0) continue;
    const p = counts[i] / buf.length;
    h -= p * Math.log2(p);
  }
  return h;
}

function md5hex(buf) { return crypto.createHash('md5').update(buf).digest('hex'); }
function sha256hex(buf) { return crypto.createHash('sha256').update(buf).digest('hex'); }

/** Стандартное отклонение / коэффициент вариации массива чисел. */
function cv(arr) {
  if (!arr || arr.length < 2) return 0;
  const m = arr.reduce((a, b) => a + b, 0) / arr.length;
  if (m === 0) return 0;
  const v = arr.reduce((a, b) => a + (b - m) * (b - m), 0) / arr.length;
  return Math.sqrt(v) / Math.abs(m);
}

function median(arr) {
  if (!arr.length) return null;
  const s = [...arr].sort((a, b) => a - b);
  return s[Math.floor(s.length / 2)];
}

// ---------------------------------------------------------------------------
// Конфигурация по умолчанию
// ---------------------------------------------------------------------------

// «Контрольные» хосты (обычно не блокируются) помогают отличить цензуру
// от поломки сети/песочницы.
const DEFAULT_TARGETS = [
  { host: 'github.com', role: 'control', note: 'контрольный хост' },
  { host: 'api.github.com', role: 'control', note: 'контрольный хост' },
  { host: 'www.google.com', role: 'target', note: 'часто под фильтрацией (SNI/IP)' },
  { host: 'www.youtube.com', role: 'target', note: 'троттлинг/блокировки' },
  { host: 'telegram.org', role: 'target', note: 'MTProto/блокировки' },
  { host: 'www.microsoft.com', role: 'cover', note: 'типичный dest для REALITY' },
  { host: 'cloudflare.com', role: 'cover', note: 'типичный cover-SNI' },
];

const RESOLVERS = [
  { name: 'system', host: null },
  { name: 'google-8.8.8.8', host: '8.8.8.8' },
  { name: 'cloudflare-1.1.1.1', host: '1.1.1.1' },
  { name: 'rf-77.88.8.8', host: '77.88.8.8', note: 'Яндекс DNS (часто локально ближе)' },
];
