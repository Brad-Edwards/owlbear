"""Run the actual registry-pinned worker under BigRAE's isolation constraints."""
import json
import os
from pathlib import Path
import subprocess
import sys
from uuid import uuid4

from bigrae_adapter_sdk.runtime import RuntimeInput, parse_input, parse_result
from owlbear_bigrae import manifest

image, receipt_path=sys.argv[1:]
selection=manifest(image)
config=dict(release='/opt/owlbear/releases/integration',manifest_sha256='a'*64,build_id='b'*64,
            version='0.1.0',source_commit='c'*40,kernel_release='6.17.0-integration',target_pid=123,
            sensors=['lsm'],enforce=True)
flags=['docker','run','--rm','--network','none','--read-only','--cap-drop','ALL',
       '--security-opt','no-new-privileges','--pids-limit','64','--memory','256m',
       '--tmpfs','/tmp:rw,noexec,nosuid,size=16m']
checks=[]
for phase in ('inspect','validate','configure','verify','cleanup'):
    request=RuntimeInput(protocol=selection.protocol,invocation_id=uuid4(),operation_id=uuid4(),
        pack_digest='sha256:'+'d'*64,manifest=selection,phase='verify',provider='aws',range_id=1,
        targets={'guest':dict(node_address='nodes.integration',os_family='linux')},
        parameters={'configuration':json.dumps(config)})
    data=request.model_dump(mode='json')
    data['phase']=phase
    if phase == 'inspect':
        data={k:data[k] for k in ('protocol','invocation_id','manifest','phase')}
    original=parse_input(json.dumps(data))
    result=subprocess.run([*flags,'--env','BIGRAE_PLUGIN_INPUT',image],
        env=dict(os.environ,BIGRAE_PLUGIN_INPUT=original.model_dump_json()),
        capture_output=True,text=True,timeout=30,check=True)
    parsed=parse_result(result.stdout,original)
    if parsed.status != ('compatible' if phase == 'inspect' else 'planned'):
        raise RuntimeError('worker did not complete '+phase)
    checks.append(phase)
# Verify the package cannot import platform modules and the effective UID is fixed.
probe="import os,importlib.util; assert os.getuid()==65532; assert importlib.util.find_spec('shifter_platform') is None; assert not os.access('/',os.W_OK)"
subprocess.run([*flags,'--entrypoint','python',image,'-I','-c',probe],check=True,timeout=30)
Path(receipt_path).write_text(json.dumps(dict(schema='owlbear.bigrae.worker-integration/v1',
    worker_image=image,ok=True,checks=checks,uid=65532,network='none',root_filesystem='read-only',live_tenant=False),indent=2)+'\n')
