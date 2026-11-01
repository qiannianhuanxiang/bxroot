import { spawn } from "node:child_process";
import { Worker } from "node:worker_threads";

const keep = new Set(["PATH", "PATHEXT", "SYSTEMROOT", "WINDIR", "TEMP", "TMP", "HOME", "PWD", "LD_PRELOAD"]);
for (const key of Object.keys(process.env)) if (!keep.has(key)) delete process.env[key];

const worker = new Worker("setInterval(() => { const a = []; for (let i = 0; i < 5000; i++) a.push(i); }, 1)", { eval: true });
let failed = 0;
let completed = 0;

await new Promise((resolve) => {
  const next = () => {
    if (completed === 120) return resolve();
    const index = completed;
    const child = spawn("/bin/true", []);
    let finished = false;
    const finish = (bad) => {
      if (finished) return;
      finished = true;
      clearTimeout(timer);
      if (bad) failed++;
      completed++;
      next();
    };
    const timer = setTimeout(() => { child.kill("SIGKILL"); finish(true); }, 1000);
    child.once("error", (error) => { console.error("PTC_CHILD_ERROR", index, child.pid, error.code, error.message); finish(true); });
    child.once("close", (code, signal) => { if (code !== 0 || signal !== null) console.error("PTC_CHILD_CLOSE_BAD", index, child.pid, code, signal); finish(code !== 0 || signal !== null); });
  };
  next();
});
await worker.terminate();
if (failed !== 0) { console.error("PTC_FORK_EXEC_FAIL", failed); process.exit(1); }
console.log("PTC_FORK_EXEC_PASS");

await new Promise((resolve, reject) => {
  const child = spawn("/bin/sleep", ["30"]);
  const timer = setTimeout(() => { try { child.kill("SIGTERM"); } catch (error) { reject(error); } }, 100);
  child.once("error", reject);
  child.once("close", (code, signal) => {
    clearTimeout(timer);
    if (signal !== "SIGTERM") reject(new Error("unexpected cancellation result: " + String(code) + "/" + String(signal)));
    else resolve();
  });
});
console.log("PTC_CANCEL_PASS");
