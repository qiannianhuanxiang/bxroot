#!/usr/bin/env python3
"""Process probes inside the existing outer proroot; never Android acceptance."""
import hashlib,json,os,pathlib,subprocess,sys
out=pathlib.Path(sys.argv[1]).resolve()
env=dict(os.environ)
for k in list(env):
    if k.startswith(('BXROOT_','PROROOT_')): env.pop(k)
results=[]
def run(name,argv,e,expected=None):
    try:
        r=subprocess.run(argv,env=e,capture_output=True,text=True,timeout=20)
        result={'name':name,'rc':r.returncode,'stdout':r.stdout[:1500],'stderr':r.stderr[:2500]}
        if expected is not None: result['matches']=r.returncode==0 and r.stdout==expected
    except subprocess.TimeoutExpired as ex:
        result={'name':name,'timeout':True}
    results.append(result)
    print(json.dumps(result,ensure_ascii=False),flush=True)
for n in (17,32,64,65):
    fixture=out/('fixture-'+str(n))
    expected='FINAL_BIND_'+str(n)+'\n'
    fixture.write_text(expected)
    args=[str(out/'libbxroot.so'),'-r','/']
    for i in range(n): args+=['-b',str(fixture)+':/__bind64_probe_'+str(i)]
    run('launcher-runtime-'+str(n),args+['/bin/cat','/__bind64_probe_'+str(n-1)],env,expected if n<=64 else None)
# Direct ULX->ld.so->env comparison: no bxroot runtime injected by this probe.
# Keep the complete value in the equality assertion, log only its checksum.
for n in (32,64):
    value=';'.join('/src/'+str(i)+':/guest/'+str(i) for i in range(n))
    e=env|{'BXROOT_BINDS':value}
    args=[str(out/'libbxroot-ulx.so'),'/lib/ld-linux-aarch64.so.1','/usr/bin/printenv','BXROOT_BINDS']
    run('ulx-env-'+str(n),args,e,value+'\n')
value='/src:/'+('x'*(16370-len('/src:/')))
run('ulx-env-16384',[str(out/'libbxroot-ulx.so'),'/lib/ld-linux-aarch64.so.1','/usr/bin/printenv','BXROOT_BINDS'],env|{'BXROOT_BINDS':value},value+'\n')
(out/'process-results.json').write_text(json.dumps(results,ensure_ascii=False,indent=2)+'\n')
print('OBSERVATIONS ONLY: outer proroot, no independent Android acceptance')
