# LensIQ Desktop ↔ Management Server — Integration Spec

This is the implementation plan for wiring the Electron tool
(`LensIQ-source/renderer/index.html` + `main.js`) to the management server.
**Golden rule: the tool must keep working fully if the server is unreachable.**
The server only enriches: pushes config, collects usage, broadcasts, ships updates.

Server base URL (make it editable in the tool admin panel, default):
`http://129.159.20.37:7788`  (WS: `ws://129.159.20.37:7788`)

---

## 0. Tiny server client (renderer)
```js
const MGMT = localStorage.getItem('lensiqServerUrl') || 'http://129.159.20.37:7788';
let SERVER_ALIVE = false;
async function srv(path, opts={}, timeoutMs=4000){
  const ctl = new AbortController(); const t=setTimeout(()=>ctl.abort(), timeoutMs);
  try{ const r = await fetch(MGMT+path, {...opts, signal:ctl.signal,
        headers:{'Content-Type':'application/json', ...(opts.headers||{})}});
       SERVER_ALIVE = true; return await r.json(); }
  catch(e){ SERVER_ALIVE = false; return null; }       // null ⇒ offline, caller must cope
  finally{ clearTimeout(t); }
}
```

## 1. Employee-ID gate (blocking modal at launch)
- On boot, before allowing use, show a modal: "Enter Employee ID".
- `const res = await srv('/api/employee/verify',{method:'POST',body:JSON.stringify({employee_id})})`
  - `res.ok` → store `EMPLOYEE_ID` in localStorage `lensiqEmployeeId`, add to cached allow-list `lensiqKnownEmps`, proceed.
  - `res.ok===false` (server reachable, inactive/unknown) → deny with reason.
  - `res===null` (**offline**) → accept if `employee_id` ∈ cached `lensiqKnownEmps`, else accept with a soft "unverified – will validate when online" flag and still let them work (offline-first). Queue a verify for later.
- Keep `EMPLOYEE_ID` for tagging usage. Provide a "switch user" control.

## 2. Offline-first usage queue
- Keep a localStorage array `lensiqUsageQueue`.
- In `processQueue`/single-run, after each image: push `{employee_id:EMPLOYEE_ID, ts:Date.now()/1000|0, engine: activeTab==='gemini'?'vision-api':'offline-deberta', images:1, records:n, ocr_ms, classify_ms}`.
- Flusher (every ~30s and on reconnect): `srv('/api/usage',{method:'POST',body:JSON.stringify({events:queue})})`; on success clear queue. On null keep queue. (Server accepts batches.)
- This *augments* the existing local `engineStats` (keep that as-is).

## 3. Config sync (pull; cache; never block offline)
- On boot and on WS `config_changed`: `const cfg = await srv('/api/config?employee_id='+EMPLOYEE_ID)`.
- If `cfg` (online): update in-memory + localStorage:
  - `GEMINI_API_KEY = cfg.gemini_api_key || GEMINI_API_KEY`
  - `GEMINI_API_KEY_2 = cfg.gemini_api_key_2 || GEMINI_API_KEY_2`   ← **fallback key**
  - `GEMINI_MODEL/FB1/FB2`, tool admin password ← cfg.*
  - Cache the whole cfg in `lensiqConfigCache`.
- If `cfg===null` (offline): load from `lensiqConfigCache` (or the values already in localStorage). **Tool keeps working with the last-known key.**
- Important: the existing local admin-panel edits must still work and should be the source when offline; when the server pushes, server wins (then local edits push back up — see §7).

## 4. Fallback API key in geminiCall (tool-side, editable locally too)
- Add `GEMINI_API_KEY_2` global (localStorage `kycAdminApiKey2`), and a field in the admin panel next to the primary key.
- In `geminiCall`, on auth/quota failure with the primary key, retry once with the fallback key before falling back to models/offline:
```js
// inside geminiCall catch, when status 400/401/403/429 and using primary:
if (usingPrimaryKey && GEMINI_API_KEY_2) {
   return await geminiCall(parts, temp, fallbackAttempt, busyRetries, /*useFallbackKey=*/true);
}
```
  Pass a flag that swaps `GEMINI_API_KEY → GEMINI_API_KEY_2` in the URL. Keep all existing
  model-fallback (FB1/FB2) and offline-tab fallback intact.
- Admin "Save" writes both keys to localStorage AND (if online) `POST /api/settings`
  so the dashboard reflects tool edits.

## 5. Broadcast popups (realtime + missed-while-offline)
- Connect WS `ws(MGMT)+'/ws/tool/'+EMPLOYEE_ID`; on `{type:'broadcast'}` show a popup.
- De-dup by `broadcast.id`: store `lensiqLastBroadcastId`; also check `cfg.broadcast.id` on each config pull so tools that were offline show the latest message once on reconnect.
- `{type:'config_changed'}` → re-pull config (§3). `{type:'update_available'}` → show update chip (§6).

## 6. Check for updates (download + install)
- Admin panel "Check for updates": `GET /api/updates/latest`. If `version > APP_VERSION` and `pushed`:
  - Confirm → ask **main process** (IPC) to download `${MGMT}/api/updates/download/${filename}` to a temp path, then `shell.openPath(path)` (runs the NSIS installer) and quit.
- `main.js` additions:
```js
ipcMain.handle('download-and-run-update', async (_e, url) => {
  const fs=require('fs'), https=require('http'); const tmp=path.join(app.getPath('temp'),'LensIQ-Update.exe');
  await new Promise((res,rej)=>{const f=fs.createWriteStream(tmp);require('http').get(url,r=>{r.pipe(f);f.on('finish',()=>f.close(res));}).on('error',rej);});
  shell.openPath(tmp); setTimeout(()=>app.quit(),1500); return {ok:true};
});
```
  expose via preload. (Use `http`/`https` matching the server scheme.)

## 7. QR admin login (no typing password in front of staff)
- Double-click logo → admin overlay shows **two options**: password field (existing) OR a **QR**.
- QR flow:
  1. `const {token} = await srv('/api/qr/create',{method:'POST'})`.
  2. Render QR encoding `http://129.159.20.37:7789/dashboard.html?qr=${token}` (use a small JS QR lib bundled locally, e.g. `qrcode.min.js`).
  3. Poll `GET /api/qr/status/${token}` every ~2s. When `status==='approved'` → you have `auth_token`; unlock the tool's admin panel (and optionally `shell.openExternal` the dashboard).
- Admin scans with phone → opens dashboard in QR mode → enters email+password once on the phone → approves. Password never shown on the shared screen.
- Changing the admin/tool password from the dashboard (`/api/settings` → `tool_admin_password`, or `/api/admin/change_password`) **syncs down** via §3.

## 8. Keep ALL current features
Everything already shipped stays: local OCR (Gemini direct + Tesseract), DeBERTa
extraction with the record-merge self-heal, resizable table, cell-select/Ctrl+C,
queue drag/retry, remarks grammar, dataset capture, timings, themed UI. The server
layer is purely additive and guarded by `SERVER_ALIVE`/null checks.

## Build/test loop (unchanged)
Edit `LensIQ-source/renderer/index.html` (+ `main.js`), `node --check` the inline JS,
`npm run dist:win`, smoke-test. Point the tool at a locally-running `mgmt_server.py`
(set `lensiqServerUrl=http://127.0.0.1:7788`) for development.
