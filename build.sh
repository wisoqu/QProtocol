#!/usr/bin/env bash
# Сборка бинаря QPD: склейка модулей + Node SEA + postject.
set -euo pipefail
cd "$(dirname "$0")"

mkdir -p bin app

echo "[build] склейка app/src/*.js -> app/main.js"
cat app/src/00-head.js \
    app/src/10-dns.js \
    app/src/20-tcp-tls.js \
    app/src/30-behavior.js \
    app/src/40-lab.js \
    app/src/50-report.js \
    app/src/60-server.js \
    app/src/80-selftest.js \
    app/src/70-main.js > app/main.js

echo "[build] синтаксическая проверка"
node --check app/main.js

echo "[build] генерация SEA-блоба"
cat > app/sea-config.json <<'EOF'
{
  "main": "app/main.js",
  "output": "app/sea-prep.blob",
  "disableExperimentalSEAWarning": true,
  "useSnapshot": false,
  "useCodeCache": true
}
EOF
node --experimental-sea-config app/sea-config.json

echo "[build] копирование node-рантайма -> bin/qprotocol"
cp "$(command -v node)" bin/qprotocol
rm -f bin/qprotocol.blob 2>/dev/null || true

echo "[build] внедрение блоба (postject)"
if [ -x node_modules/.bin/postject ]; then
  PJ=node_modules/.bin/postject
else
  PJ="npx --yes postject"
fi
$PJ bin/qprotocol NODE_SEA_BLOB app/sea-prep.blob \
  --sentinel-fuse NODE_SEA_FUSE_fce680ab2cc467b6e072b8b5df1996b2 >/dev/null

chmod +x bin/qprotocol
echo "[build] готово: bin/qprotocol"
./bin/qprotocol help | head -5
