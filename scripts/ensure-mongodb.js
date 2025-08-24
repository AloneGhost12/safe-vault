// Attempt to ensure mongodb dependency is present at runtime (Render cache fallback)
import { execSync } from 'child_process';
import fs from 'fs';

function hasMongo(){
  try { return !!JSON.parse(fs.readFileSync('./node_modules/mongodb/package.json','utf-8')).version; } catch { return false; }
}

async function main(){
  if(hasMongo()) { console.log('[ensure-mongodb] mongodb already present'); return; }
  console.log('[ensure-mongodb] mongodb missing – installing now...');
  try {
    execSync('npm install mongodb@6.8.0 --no-audit --no-fund', { stdio: 'inherit' });
    if(hasMongo()) console.log('[ensure-mongodb] install complete'); else console.log('[ensure-mongodb] install attempt finished but still missing');
  } catch(e){
    console.error('[ensure-mongodb] install failed', e.message);
  }
}
main();
