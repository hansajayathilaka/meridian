#!/usr/bin/env bash
# Validate docs: mermaid syntax (via mermaid-cli + chromium) + relative-link resolution.
# Present in the devcontainer; degrades gracefully if mermaid-cli is absent.
set -uo pipefail
FAIL=0

echo "▶ Checking relative links…"
python3 - << 'PY'
import os,re,sys
link_re=re.compile(r'\[([^\]]*)\]\(([^)]+)\)')
broken=[];checked=0
for dp,_,fs in os.walk("."):
    if any(x in dp for x in ("/.git","/target","/node_modules","/.ca")): continue
    for fn in fs:
        if not fn.endswith(".md"): continue
        # Skip task/phase templates: their relative links are written for the copy
        # destination (docs/tasks/phase-N/) and contain intentional placeholders.
        if fn.startswith("TEMPLATE"): continue
        fp=os.path.join(dp,fn)
        for m in link_re.finditer(open(fp,encoding="utf-8").read()):
            t=m.group(2).strip()
            if t.startswith(("http://","https://","mailto:")): continue
            p=t.split("#")[0]
            if not p: continue
            checked+=1
            if not os.path.exists(os.path.normpath(os.path.join(dp,p))):
                broken.append((fp,t))
print(f"  links checked: {checked}")
if broken:
    for fp,t in broken[:80]: print(f"  BROKEN: {fp} -> {t}")
    sys.exit(1)
print("  no broken relative links ✔")
PY
[ $? -ne 0 ] && FAIL=1

echo "▶ Checking mermaid syntax…"
if command -v mmdc >/dev/null 2>&1; then
  tmp="$(mktemp -d)"
  cat > "$tmp/pp.json" << 'JSON'
{ "args": ["--no-sandbox", "--disable-setuid-sandbox"] }
JSON
  ok=0; bad=0
  while IFS= read -r f; do
    if mmdc -i "$f" -o "$tmp/out.svg" -p "$tmp/pp.json" -b transparent >/dev/null 2>&1; then
      ok=$((ok+1)); else bad=$((bad+1)); echo "  MERMAID FAIL: $f"; fi
  done < <(find docs -name '*.mermaid')
  echo "  mermaid ok=$ok fail=$bad"
  [ "$bad" -ne 0 ] && FAIL=1
  rm -rf "$tmp"
else
  echo "  (mmdc not found — skipping mermaid syntax check)"
fi

[ "$FAIL" -eq 0 ] && echo "✅ docs OK" || echo "❌ docs check failed"
exit "$FAIL"
