// Simple preflight to log installed versions on server start
import fs from 'fs';

function safeStat(p){ try { return fs.statSync(p); } catch { return null; } }

async function main(){
  try {
    const pkg = JSON.parse(fs.readFileSync('./package.json','utf-8'));
    console.log('[preflight] Node version:', process.version);
    console.log('[preflight] Declared deps: mongodb@', pkg.dependencies?.mongodb);
    let mongodbVersion = null;
    try {
      const mongodbPkg = JSON.parse(fs.readFileSync('./node_modules/mongodb/package.json','utf-8'));
      mongodbVersion = mongodbPkg.version;
    } catch(e){
      console.log('[preflight] mongodb package.json not found');
    }
    console.log('[preflight] Installed mongodb version:', mongodbVersion || 'MISSING');
  } catch(e){
    console.log('[preflight] error', e.message);
  }
}
main();
