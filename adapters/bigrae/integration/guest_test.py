"""Integration only: real guest scripts and daemon, fake module/device and BPF.

Runs in an isolated ARM64 container. /sys is a private tmpfs, never host sysfs.
No real module is loaded. No BigRAE tenant or provider is contacted.
"""
import ctypes
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import struct
import subprocess
import sys
import uuid

from bigrae_adapter_sdk.runtime import RuntimeInput, parse_result
from owlbear_bigrae import manifest

source = Path('/source')
spec = importlib.util.spec_from_file_location('artifact', source / 'scripts/research-artifact.py')
artifact = importlib.util.module_from_spec(spec)
spec.loader.exec_module(artifact)


def main():
    if platform.machine() != 'aarch64':
        raise SystemExit('guest integration requires native ARM64; not a live tenant')
    # Allow the child daemon to baseline this fixture target under Yama.
    if ctypes.CDLL(None).prctl(0x59616d61, ctypes.c_ulong(-1), 0, 0, 0):
        raise RuntimeError('fixture ptrace authorization failed')
    root = Path('/opt/owlbear/releases/integration')
    root.mkdir(parents=True)
    identity = dict(schema='owlbear.build/v1', version='0.1.0', source_commit='a'*40,
                    source_date_epoch=1, architecture='arm64', kernel_release=platform.release())
    identity['build_id'] = artifact.digest(artifact.encoded({'build': identity, 'inputs': {}}))
    header = Path('/source/generated')
    header.mkdir()
    (header / 'owlbear_build.h').write_text('#define OWL_BUILD_INFO_JSON ' + json.dumps(json.dumps(identity)) + '\n')
    daemon = root / 'daemon/owlbeard'
    daemon.parent.mkdir()
    names = ['main', 'experiment', 'event_pipeline', 'process_tree', 'sig_loader', 'integrity',
             'hmac_sha256', 'self_protect', 'debugger_detect', 'preload_detect', 'clock_validator',
             'vdso_integrity', 'policy', 'scanner', 'net_allowlist']
    subprocess.run(['gcc','-std=c11','-D_GNU_SOURCE','-O1', '-I'+str(header),'-I/source/include',
                    '-I/source/daemon', *[str(source/'daemon'/f'{name}.c') for name in names],
                    '/source/tests/experiment_fixture.c','-lcrypto','-o',str(daemon)], check=True)
    module = root / 'kernel/owlbear.ko'
    module.parent.mkdir()
    subprocess.run(['gcc','-shared','-Wl,--build-id','-x','c','-','-o',str(module)],
                   input='int fixture(void) { return 0; }', text=True, check=True)
    for name in artifact.REQUIRED:
        path = root / name
        if path.exists():
            continue
        path.parent.mkdir(parents=True, exist_ok=True)
        data = b'fixture\n'
        if name.endswith(('.o','.ko','.so','.bin')) or name == 'game/owlbear-game':
            data = bytearray(64)
            data[:6] = b'\x7fELF\x02\x01'
            data[18:20] = (247 if name.endswith('.bpf.o') else 183).to_bytes(2,'little')
        if name in ('scripts/research-artifact.py','signatures/default.sigs'):
            data = (source / name).read_bytes()
        path.write_bytes(data)
        path.chmod(0o644)
    recorded = {name: dict(sha256=artifact.digest((root/name).read_bytes()),
                          size=(root/name).stat().st_size, mode=(root/name).stat().st_mode & 0o7777)
                for name in artifact.REQUIRED}
    metadata = dict(schema=artifact.SCHEMA,build=identity,inputs={},files=recorded)
    (root/'manifest.json').write_bytes(artifact.encoded(metadata))
    # Explicit module-loader fixture: save the authenticated ELF note in PRIVATE sysfs.
    loader = Path('/usr/local/bin/insmod')
    loader.write_text('''#!/usr/local/bin/python
from pathlib import Path
import subprocess,sys
note=Path('/sys/module/owlbear/notes/.note.gnu.build-id')
note.parent.mkdir(parents=True)
subprocess.run(['objcopy','--dump-section','.note.gnu.build-id='+str(note),sys.argv[1],'/run/fixture-module-copy'],check=True)
''')
    loader.chmod(0o755)
    os.mkfifo('/dev/owlbear',0o600)
    device = os.open('/dev/owlbear',os.O_RDWR | os.O_NONBLOCK)
    config = dict(release=str(root),manifest_sha256=artifact.digest((root/'manifest.json').read_bytes()),
                  **{key: identity[key] for key in ('version','build_id','source_commit','kernel_release')},
                  target_pid=os.getpid(),sensors=[],enforce=True)
    operation = uuid.uuid4()
    selection = manifest('registry.integration.test/owlbear/worker@sha256:'+'a'*64)
    # This process executes the guest plan; the production worker is independently
    # tested from its actual registry digest under the SDK container restrictions.
    def execute(phase, values=config, success=True):
        request=RuntimeInput(protocol=selection.protocol,invocation_id=uuid.uuid4(),operation_id=operation,
            pack_digest='sha256:'+'b'*64,manifest=selection,phase=phase,provider='aws',range_id=1,
            targets={'guest':dict(node_address='nodes.integration',os_family='linux')},
            parameters={'configuration':json.dumps(values)})
        environment=dict(os.environ,BIGRAE_PLUGIN_INPUT=request.model_dump_json())
        worker=subprocess.run([sys.executable,'-I','-m','bigrae_adapter_sdk.worker'],env=environment,
                              capture_output=True,text=True,timeout=10,check=True)
        plan=parse_result(worker.stdout,request)
        if plan.status != 'planned':
            raise RuntimeError('worker did not plan guest action')
        action=plan.actions[0]
        result=subprocess.run(['sh','-s'],input=action.script,text=True,capture_output=True,
                              timeout=action.timeout_seconds)
        if (result.returncode == 0) != success:
            raise RuntimeError(f'guest {phase}: unexpected exit {result.returncode}: {result.stderr}')
        if success:
            receipt=json.loads(result.stdout)
            if receipt['build'] != identity or receipt['health']['kernel_enforce'] is not values['enforce']:
                raise RuntimeError('guest readback did not preserve identity or parameters')
            return receipt
    receipt=execute('configure')
    pid=receipt['health']['pid']
    try:
        if execute('configure')['health']['pid'] != pid:
            raise RuntimeError('retry replaced the daemon')
        execute('verify')
        execute('verify',dict(config,build_id='f'*64),success=False)
        execute('verify',dict(config,enforce=False),success=False)
        signature=root/'signatures/default.sigs'
        signature.write_text(signature.read_text()+'\n# tampered\n')
        execute('verify',success=False)
        print(json.dumps(dict(schema='owlbear.bigrae.guest-integration/v1',ok=True,
            architecture=platform.machine(),checks=['configure','retry','verify','wrong-release',
            'wrong-enforcement','tampered-artifact'],kernel='explicit FIFO/ioctl/module-note fixture',
            live_tenant=False)))
    finally:
        os.kill(pid,15)
        os.close(device)


if __name__ == '__main__':
    main()
