#!/usr/bin/env python3
"""Build and integration-test a relocatable worker release. Never publish externally."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import time
from uuid import uuid4
from zipfile import ZipFile

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
BASE = 'python:3.12-slim@sha256:aa943ce411423c7582288f18707ff66eddcbaeb510502d747a72aeb34f30d159'
REGISTRY = 'registry:3@sha256:d4032d4cc323c1731c707931ecada07a53076eac38e3b61ae57533f170f2c6c3'


def run(args, **kwargs):
    return subprocess.run([str(arg) for arg in args],check=True,timeout=600,**kwargs)


def output(args):
    return run(args,stdout=subprocess.PIPE,text=True).stdout.strip()


def sha(path):
    return hashlib.file_digest(path.open('rb'),'sha256').hexdigest()


def write(path, value):
    path.write_text(json.dumps(value,sort_keys=True,indent=2)+'\n')


def build(destination, guest):
    destination=destination.resolve()
    destination.mkdir(parents=True,exist_ok=False)
    wheelhouse=destination/'wheelhouse'
    wheelhouse.mkdir()
    sdk=json.loads((HERE/'sdk.json').read_text())
    sdk_wheel=HERE/'vendor'/sdk['wheel']
    if sha(sdk_wheel) != sdk['wheel_sha256']:
        raise ValueError('SDK distribution differs from the published candidate')
    shutil.copy2(sdk_wheel,wheelhouse/sdk_wheel.name)
    # Build only this project; the SDK is consumed as the published wheel, not rebuilt.
    run(['uv','build','--wheel','--out-dir',wheelhouse,HERE])
    shutil.copy2(HERE/'constraints.txt',wheelhouse/'constraints.txt')
    wheels=sorted('/wheelhouse/'+p.name for p in wheelhouse.glob('*.whl'))
    run(['docker','run','--rm','--user',f'{os.getuid()}:{os.getgid()}',
         '--mount',f'type=bind,src={wheelhouse},dst=/wheelhouse',BASE,
         'python','-m','pip','download','--no-cache-dir','--only-binary=:all:',
         '--constraint','/wheelhouse/constraints.txt','--dest','/wheelhouse',*wheels])
    requirements=[]
    for wheel in sorted(wheelhouse.glob('*.whl')):
        with ZipFile(wheel) as archive:
            metadata=archive.read(next(n for n in archive.namelist() if n.endswith('.dist-info/METADATA'))).decode()
        fields=dict(line.split(': ',1) for line in metadata.splitlines() if line.startswith(('Name: ','Version: ')))
        requirements.append(f"{fields['Name']}=={fields['Version']} --hash=sha256:{sha(wheel)}")
    (wheelhouse/'requirements.lock').write_text('\n'.join(requirements)+'\n')
    shutil.copy2(HERE/'Dockerfile',destination/'Dockerfile')
    image='owlbear-integration-'+uuid4().hex
    registry='owlbear-registry-'+uuid4().hex
    run(['docker','build','--build-arg','PYTHON_IMAGE='+BASE,'--tag',image,destination])
    image_id=output(['docker','image','inspect',image,'--format','{{.Id}}'])
    # A loopback-only disposable registry exercises a REAL registry manifest digest.
    # It has no tenant credentials and receives only this local test image.
    run(['docker','run','--detach','--name',registry,'--publish','127.0.0.1::5000',REGISTRY],stdout=subprocess.DEVNULL)
    try:
        port=output(['docker','port',registry,'5000/tcp']).rsplit(':',1)[1]
        tagged=f'127.0.0.1:{port}/owlbear-worker:integration'
        run(['docker','tag',image,tagged])
        for attempt in range(10):
            try:
                run(['docker','push',tagged])
                break
            except subprocess.CalledProcessError:
                if attempt == 9:
                    raise
                time.sleep(.5)
        repository_digest=next(value for value in json.loads(output(
            ['docker','image','inspect',tagged,'--format','{{json .RepoDigests}}']))
            if value.startswith(tagged.rsplit(':',1)[0]+'@'))
        digest=repository_digest.rsplit('@',1)[1]
        run(['docker','pull',repository_digest])
        # Docker's classic `save` rewrites/discards the registry manifest. Use
        # the standard containers/image directory transport to preserve its bytes.
        image_directory=destination/'image'
        run(['skopeo','copy','--all','--preserve-digests','--src-tls-verify=false',
             'docker://'+repository_digest,'dir:'+str(image_directory)])
        if sha(image_directory/'manifest.json') != digest.removeprefix('sha256:'):
            raise ValueError('exported image does not preserve the registry manifest')
        with tarfile.open(destination/'worker.tar','w') as archive:
            archive.add(image_directory,arcname='.')
        # The release's runner installs only wheels, never application source.
        environment=destination/'test-runtime'
        run(['uv','venv','--python','3.12',environment])
        python=environment/'bin/python'
        run(['uv','pip','install','--python',python,'--no-index','--find-links',wheelhouse,
             '--require-hashes','--requirements',wheelhouse/'requirements.lock'])
        selection=json.loads(output([environment/'bin/owlbear-bigrae-manifest','--worker-image',repository_digest]))
        write(destination/'integration-installation.json',selection)
        run([python,HERE/'integration/worker_test.py',repository_digest,destination/'worker-integration.json'])
        run([python,'-I','-m','unittest','discover','-s',HERE/'tests','-v'])
        if guest:
            context=destination/'guest-context'
            context.mkdir()
            shutil.copytree(wheelhouse,context/'wheelhouse')
            for path in ['daemon','include','signatures']:
                shutil.copytree(REPO/path,context/'source'/path,ignore=shutil.ignore_patterns('*.o','*.d','owlbeard'))
            for path in ['scripts/research-artifact.py','tests/experiment_fixture.c']:
                target=context/'source'/path
                target.parent.mkdir(parents=True,exist_ok=True)
                shutil.copy2(REPO/path,target)
            shutil.copytree(HERE/'integration',context/'source/integration')
            shutil.copy2(HERE/'integration/Dockerfile',context/'Dockerfile')
            guest_image=image+'-guest'
            run(['docker','build','--build-arg','PYTHON_IMAGE='+BASE,'--tag',guest_image,context])
            result=output(['docker','run','--rm','--init','--network','none','--user','0:0',
                '--cap-add','SYS_PTRACE','--security-opt','apparmor=unconfined','--security-opt','systempaths=unconfined',
                '--tmpfs','/sys:rw',guest_image])
            # Keep guest compiler output in logs; receipt is the final JSON line.
            receipt=json.loads(result.splitlines()[-1])
            write(destination/'guest-integration.json',receipt)
        write(destination/'image.json',dict(schema='owlbear.bigrae.worker/v1',image_digest=digest,
            image_id=image_id,architecture=output(['docker','image','inspect',image,'--format','{{.Architecture}}']),base_image=BASE,sdk=sdk,worker_archive_sha256=sha(destination/'worker.tar'),
            integration_only=True,guest_integration=guest))
        shutil.copy2(HERE/'sdk.json',destination/'sdk.json')
        shutil.copy2(wheelhouse/'requirements.lock',destination/'requirements.lock')
        (destination/'SHA256SUMS').write_text(''.join(f'{sha(p)}  {p.name}\n' for p in sorted(destination.iterdir())
                                                  if p.is_file() and p.name != 'Dockerfile'))
        print('Verified worker release:',destination)
    finally:
        run(['docker','rm','--force',registry],stdout=subprocess.DEVNULL)


if __name__ == '__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True,help='new release directory')
    parser.add_argument('--guest-integration',action='store_true',help='ARM64 fake-kernel guest test; never a live tenant')
    args=parser.parse_args()
    build(args.output,args.guest_integration)
