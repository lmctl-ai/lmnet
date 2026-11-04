"""Invocation framing, builder order, validation, and real dry metadata controls."""
import json, os, subprocess, sys
from pathlib import Path
from invocation import run_sources
work=Path(sys.argv[1])/'protocol'; work.mkdir()
host=os.environ['LMNET_HOST']
schema=Path('schema/lmnet.dsl.json').resolve()
def source(name,body):
 path=work/(name+'.lms')
 path.write_text('p = _lmcode_ schema='+json.dumps(str(schema))+';\n'+body+'\nend _lmcode_\n')
 return path
first,second=work/'first.txt',work/'second.txt'
a=source('a','file_write('+json.dumps(str(first))+',"a"); println("diagnostic");')
b=source('b','file_write('+json.dumps(str(second))+',file_read('+json.dumps(str(first))+')+"b");')
bad=source('bad','let x = int_list().at(9);')
r=run_sources([a,b],capture=work/'capture')
assert r.returncode==0 and json.loads(r.stdout)=={'ok':True,'result':[None,None],'parts':2},r
assert second.read_text()=='ab' and 'diagnostic' in r.stderr,r
first.unlink();second.unlink()
r=run_sources([a,bad,b],capture=work/'failed-capture')
assert r.returncode==3 and json.loads(r.stdout)['part']==1 and first.exists() and not second.exists(),r
first.unlink()
files=[str((work/'capture'/f'{i}.lmcode').resolve()) for i in range(2)]
def hostrun(args,env=None):
 return subprocess.run([host,*args],env=env,capture_output=True,text=True,timeout=30)
def frame(r):
 lines=r.stdout.splitlines()
 assert len(lines)==3 and lines[0]=='LMCODE_RETURN_BEGIN' and lines[2]=='LMCODE_RETURN_END',r
 return json.loads(lines[1])
r=hostrun(['--dry-run','--lmcode',str((work/'failed-capture'/'1.lmcode').resolve())])
assert r.returncode==0 and frame(r)['dry'] is True and not r.stderr,r
r=hostrun(['--lmcode',*files,str(work/'missing.lmcode')])
assert r.returncode==3 and frame(r)['phase']=='load' and not first.exists(),r
manifest=work/'invocation.json'
metadata={'version':1,'mode':'builder','dry':True,'parts':[{'index':i,'file':p} for i,p in enumerate(files)]}
manifest.write_text(json.dumps(metadata))
env=dict(os.environ,LMCODE_INVOCATION_FILE=str(manifest.resolve()))
r=hostrun(['--lmcode',*files],env)
assert r.returncode==0 and frame(r)['dry'] is True and not first.exists() and not second.exists(),r
metadata['dry']=False;manifest.write_text(json.dumps(metadata))
r=hostrun(['--dry-run','--lmcode',*files],env)
assert r.returncode==2 and frame(r)['phase']=='cli' and not first.exists(),r
env['LMCODE_INVOCATION_FILE']=str(work/'absent.json')
r=hostrun(['--lmcode',*files],env)
assert r.returncode==2 and frame(r)['phase']=='cli' and not first.exists(),r
r=hostrun(['--lmcode-schema','--json'],env)
assert r.returncode==0 and r.stdout==schema.read_text(),r
r=hostrun(['--lmcode',*files])
assert r.returncode==0 and frame(r)['parts']==2 and 'diagnostic' in r.stderr,r
print('PASS framing, builder order, stop-on-error, load-before-write, dry metadata and passive introspection')

# A real invocation fails to bind this occupied port; dry mode must not try.
import socket
with socket.socket() as listener:
 listener.bind(('127.0.0.1',0)); listener.listen()
 netprog=source('occupied-listener',f'let l = net.tcp_listen({listener.getsockname()[1]});')
 r=run_sources([netprog],capture=work/'network-capture',capture_only=True)
 assert r.returncode==0,r
 bytecode=str((work/'network-capture'/'0.lmcode').resolve())
 r=hostrun(['--dry-run','--lmcode',bytecode])
 assert r.returncode==0 and frame(r)['dry'] is True,r
 r=hostrun(['--lmcode',bytecode])
 assert r.returncode==3 and frame(r)['phase']=='run' and 'tcp_listen' in r.stdout,r
print('PASS dry mode does not attempt to open a listening socket (real-run negative control)')
