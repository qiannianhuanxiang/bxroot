import fs from 'node:fs';
import { pathToFileURL, fileURLToPath } from 'node:url';
const TAG = process.env.PROBE_TAG || '?';
const REF = '/usr/local/lib/node_modules/@deepseek-ai/dsh/node_modules/@deepseek-ai/cordis-plugin-loader/lib/index.js';
console.log('### WALK TAG=' + TAG);
console.log('### referrer = ' + REF);
// 精确复刻 Node ESM packageResolve 的 node_modules 上溯
function* cands(refPath, name) {
  const isScoped = name[0] === '@';
  const suffix = (isScoped ? '../../../../node_modules/' : '../../../node_modules/') + name + '/package.json';
  let u = new URL(`./node_modules/${name}/package.json`, pathToFileURL(refPath));
  const guard = new Set();
  for (let i = 0; i < 20; i++) {
    const p = fileURLToPath(u);
    if (guard.has(p)) return; guard.add(p);
    yield p;
    u = new URL(suffix, u);
  }
}
for (const name of ['dsh-device-shell-guide','dsh-task-notifier','dsh-status-overlay','dsh-web-mobile','dsh-app-integration']) {
  console.log('=== ' + name);
  let hit = false;
  for (const c of cands(REF, name)) {
    const dir = c.replace(/\/package\.json$/, '');
    let v; try { v = fs.statSync(dir).isDirectory(); } catch (e) { v = e.code; }
    console.log('   ' + (v === true ? '★' : ' ') + ' ' + dir + '  -> ' + v);
    if (v === true) { hit = true; break; }
  }
  console.log('   >>> 命中: ' + (hit ? '是' : '否'));
}
console.log('### WALK END');
