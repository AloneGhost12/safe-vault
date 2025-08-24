// API base: set VITE_API_BASE_URL (e.g. http://localhost:4000 or your Render URL)
// Falls back to same-origin relative requests when unset.
const base = (import.meta.env.VITE_API_BASE_URL || '').replace(/\/$/, '');

async function json(res){
  if(!res.ok){
    let body = '';
    try { body = await res.text(); } catch { /* ignore */ }
    throw new Error(`HTTP ${res.status} ${res.statusText} ${body.slice(0,200)}`);
  }
  return res.json();
}

async function doFetch(url, options){
  try {
    return await json(await fetch(url, options));
  } catch (e){
    console.error('[mongoApi]', options?.method||'GET', url, e.message);
    throw e;
  }
}

export async function listFiles(email){
  return doFetch(base + `/api/files?email=${encodeURIComponent(email)}`);
}
export async function createFile(fileMeta){
  return doFetch(base + '/api/files', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(fileMeta) });
}
export async function patchFile(id, patch){
  return doFetch(base + `/api/files/${id}`, { method:'PATCH', headers:{'Content-Type':'application/json'}, body: JSON.stringify(patch) });
}
export async function deleteFile(id){
  return doFetch(base + `/api/files/${id}`, { method:'DELETE' });
}
export async function addActivity(entry){
  return doFetch(base + '/api/activity', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(entry) });
}
export async function listActivity(email, limit=25){
  return doFetch(base + `/api/activity?email=${encodeURIComponent(email)}&limit=${limit}`);
}
export async function mongoStatus(){
  return doFetch(base + '/api/mongo/status');
}
