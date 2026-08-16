#!/usr/bin/env bash
# End-to-end HTTP test for ThreatPulse AI endpoints (guest flow).
set -u
BASE="http://localhost:3999"

echo "== 1. Guest session =="
RESP=$(curl -s -i -X POST "$BASE/api/auth/guest")
echo "$RESP" | tail -1; echo
ACCESS=$(echo "$RESP" | grep -io 'Set-Cookie: tp_access=[^;]*' | sed 's/.*=//')
CSRF=$(echo "$RESP" | grep -io 'Set-Cookie: tp_csrf=[^;]*' | sed 's/.*=//')
if [ -z "$ACCESS" ] || [ -z "$CSRF" ]; then
  echo "FATAL: failed to extract tokens"; echo "$RESP" | grep -i set-cookie; exit 1
fi
echo "access token len: ${#ACCESS}, csrf len: ${#CSRF}"

# Bearer for auth, Cookie for CSRF double-submit (tp_csrf cookie must match X-CSRF-Token header)
H=(-H "Authorization: Bearer $ACCESS" -H "X-CSRF-Token: $CSRF" -H "Cookie: tp_access=$ACCESS; tp_csrf=$CSRF")

echo; echo "== 2. AI status =="
curl -s "${H[@]}" "$BASE/api/ai/status"; echo

echo; echo "== 3. Fetch an article id =="
ARTICLES=$(curl -s "${H[@]}" "$BASE/api/articles?limit=1")
echo "$ARTICLES" | head -c 200; echo
ART_ID=$(echo "$ARTICLES" | node -e "let s='';process.stdin.on('data',d=>s+=d).on('end',()=>{try{const j=JSON.parse(s);const a=j.articles||j.data||[];console.log(a[0]?.id||'')}catch(e){console.log('')}})")
echo "articleId: ${ART_ID:-<none>}"

if [ -n "$ART_ID" ]; then
  echo; echo "== 4. Summarize =="
  curl -s "${H[@]}" -X POST "$BASE/api/ai/summarize" -H "Content-Type: application/json" -d "{\"articleId\":$ART_ID}"; echo

  echo; echo "== 5. Triage =="
  curl -s "${H[@]}" -X POST "$BASE/api/ai/triage" -H "Content-Type: application/json" -d "{\"articleId\":$ART_ID}"; echo
fi

echo; echo "== 6. Ask (RAG mode) =="
curl -s "${H[@]}" -X POST "$BASE/api/ai/ask" -H "Content-Type: application/json" -d '{"question":"What critical vulnerabilities appeared recently?","mode":"rag"}'; echo

echo; echo "== 7. Ask (web mode) =="
curl -s "${H[@]}" -X POST "$BASE/api/ai/ask" -H "Content-Type: application/json" -d '{"question":"What is the latest on the MOVEit breach?","mode":"web"}'; echo

echo; echo "DONE"
