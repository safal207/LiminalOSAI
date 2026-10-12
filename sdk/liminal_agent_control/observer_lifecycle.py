"""Managed observer ring and independent host watchdog; no agent authority.

Only this managed path registers all three services before launch. The low-level
DockerObserver remains an explicitly unmanaged experimental adapter. A trusted
host/daemon/SQLite store is assumed; no global orchestration or rollback proof.
"""
from __future__ import annotations

import argparse
import json
import math
import os
from pathlib import Path
import re
import selectors
import shutil
import subprocess
import sys
import time
from typing import Any

from .authority import ControlError, canonical_bytes, validate_id
from .brakes_store import SessionAuthority
from .brakes_watchdog import TERMINAL_STATES
from .observer_container import DockerObserver, validate_source_directories
from .observer_process import _exchange, _kill_and_reap, MAX_REPORT_BYTES
from .observer_registry import ObserverRingRegistry, ObserverRegistryError, ownership_labels
from .runtime import BoundedHostCall

ROLES = ('reality', 'continuity', 'projection')
_ID = re.compile(r'[0-9a-f]{64}\Z')
_INSPECT = ('{"id":{{json .Id}},"name":{{json .Name}},'
            '"image":{{json .Image}},"labels":{{json .Config.Labels}}}')


def _positive(value: float, maximum: float) -> float:
    if type(value) not in (int, float) or not math.isfinite(value) or not 0 < value <= maximum:
        raise ControlError('OBSERVER_LIFECYCLE_CONFIGURATION_INVALID')
    return float(value)


def _docker(binary: str, arguments: list[str], timeout: float) -> bytes:
    process = None
    try:
        process = DockerObserver._spawn([binary, *arguments])
        output, errors, failure = _exchange(process, b'', timeout)
        if failure or process.returncode != 0 or errors:
            raise ControlError('OBSERVER_DOCKER_OBSERVATION_UNAVAILABLE')
        return output
    except (OSError, ValueError) as exc:
        if isinstance(exc, ControlError):
            raise
        raise ControlError('OBSERVER_DOCKER_OBSERVATION_UNAVAILABLE') from exc
    finally:
        if process is not None:
            _kill_and_reap(process)
            for stream in (process.stdin, process.stdout, process.stderr):
                if stream is not None and not stream.closed:
                    stream.close()


def _listed(binary: str, selector: str, timeout: float) -> str | None:
    output = _docker(binary, ['container', 'ls', '--all', '--no-trunc', '--filter',
                             selector, '--format', '{{.ID}}'], timeout)
    values = output.decode('ascii', errors='strict').splitlines()
    if not values:
        return None
    if len(values) != 1 or not _ID.fullmatch(values[0]):
        raise ControlError('OBSERVER_DOCKER_OBSERVATION_INVALID')
    return values[0]


def _owned(binary: str, container_id: str, record: dict, observer_id: str,
           timeout: float) -> dict:
    document = json.loads(_docker(binary, ['inspect', '--format', _INSPECT, container_id], timeout))
    if (type(document) is not dict or document.get('id') != container_id
            or document.get('image') != record['image_id'] or type(document.get('labels')) is not dict
            or any(document['labels'].get(k) != v for k,v in ownership_labels(record, observer_id).items())):
        raise ControlError('OBSERVER_CONTAINER_OWNERSHIP_MISMATCH')
    return document


def _closure(authority: SessionAuthority, root_id: str, reason: str) -> tuple[bool, dict]:
    call = BoundedHostCall(lambda: authority.stop(root_id, reason=reason), name='observer-ring-stop')
    try:
        status = call.result_before(time.monotonic() + 1.1)
        verified = (type(status) is dict and status.get('root_id') == root_id
                    and status.get('control_profile') == 'durable-session-v1'
                    and status.get('status') in TERMINAL_STATES)
        return verified, {'session':status, 'call':call.observation()}
    except Exception:
        return False, {'session':None, 'call':call.observation()}


def _active(authority: SessionAuthority, root_id: str) -> None:
    call = BoundedHostCall(lambda: authority.status(root_id), name='observer-controller-observe')
    try:
        status = call.result_before(time.monotonic()+1.1)
        if (type(status) is not dict or status.get('root_id') != root_id
                or status.get('control_profile') != 'durable-session-v1' or status.get('status') != 'ACTIVE'):
            raise ControlError('OBSERVER_ROOT_NOT_ACTIVE')
    except Exception as exc:
        if isinstance(exc,ControlError):
            raise
        raise ControlError('OBSERVER_AUTHORITY_UNAVAILABLE') from exc


def recover_observer_ring(registry: ObserverRingRegistry, record: dict, *,
                          authority: SessionAuthority, docker_binary: str,
                          reason: str, timeout_seconds: float = 3) -> dict[str, Any]:
    """Close admission first, then inspect/remove only positively owned IDs.

    Unknown create outcomes remain incomplete even after a positively discovered
    candidate is removed. Current absence does not cancel a late daemon request.
    No completion or cleanup observation reopens an authority root.
    """
    timeout = _positive(timeout_seconds, 30)
    report = {'schema':'liminal.observer-ring-watchdog.v1', 'ring_id':record['ring_id'],
              'root_id':record['root_id'], 'status':'INCOMPLETE', 'reason':reason,
              'admission_closed':False, 'observers_removed':False, 'cleanup':[],
              'closure_recorded_at':None, 'cleanup_started_at':None,
              'external_effect_completion_verified':False}
    # Validate the immutable registry and exact authority store before even STOP:
    # a mismatched record must not mutate an unrelated root or database.
    try:
        registry.snapshot(record)
        if authority.db_path.resolve() != Path(record['authority_db']).resolve():
            raise ControlError('OBSERVER_AUTHORITY_BINDING_MISMATCH')
        validate_id(reason,'reason')
    except (ObserverRegistryError,ControlError,OSError,ValueError) as exc:
        report['reason']=str(exc); return report
    closed, observation = _closure(authority, record['root_id'], reason)
    report.update(admission_closed=closed, authority=observation)
    if closed:
        report['closure_recorded_at'] = time.time()
    try:
        registry.begin_closing(record, reason)
        snapshot = registry.snapshot(record)
    except ObserverRegistryError as exc:
        report['reason'] = str(exc)
        return report
    report['cleanup_started_at'] = time.time()
    deadline=time.monotonic()+min(30.0,6*timeout+1)
    def remaining() -> float:
        value=min(timeout,deadline-time.monotonic())
        if value<=0:
            raise ControlError('OBSERVER_RECOVERY_DEADLINE')
        return value
    for child in snapshot['children']:
        item = {k:child[k] for k in ('observer_id','role','container_id')}
        item.update(removed=False, reason=None, phase=child['phase'])
        try:
            named = _listed(docker_binary, 'name=^/' + child['container_name'] + '$', remaining())
            pinned = child['container_id']
            reused = pinned is not None and named is not None and named != pinned
            candidate = pinned or named
            present = None if candidate is None else _listed(docker_binary, 'id=' + candidate, remaining())
            if present is not None:
                if present != candidate:
                    raise ControlError('OBSERVER_CONTAINER_ID_MISMATCH')
                _owned(docker_binary, present, record, child['observer_id'], remaining())
                _docker(docker_binary, ['rm','--force',present], remaining())
                item['observed_removed_id'] = present
                if _listed(docker_binary, 'id=' + present, remaining()) is not None:
                    raise ControlError('OBSERVER_CONTAINER_REMOVAL_UNVERIFIED')
            if reused:
                raise ControlError('OBSERVER_CONTAINER_NAME_REUSED')
            if child['phase'] == 'CREATE_PENDING':
                raise ControlError('CREATE_OUTCOME_UNCONFIRMED')
            if child['phase'] == 'REGISTERED' and named is not None:
                raise ControlError('OBSERVER_UNREGISTERED_CREATE_OBSERVED')
            registry.complete_child(record, child['observer_id'], pinned, verified_absent=True)
            item['removed'] = True
        except (ControlError, ObserverRegistryError, OSError, ValueError, TypeError, UnicodeError) as exc:
            item['reason'] = str(exc) if isinstance(exc,(ControlError,ObserverRegistryError)) else 'OBSERVER_DOCKER_OBSERVATION_INVALID'
        report['cleanup'].append(item)
    try:
        if all(x['removed'] for x in report['cleanup']) and len(report['cleanup']) == 3:
            registry.complete_ring(record)
        final = registry.snapshot(record)
        report['registry_status'] = final['status']
        report['observers_removed'] = final['status'] == 'CLOSED' and all(x['removed'] for x in report['cleanup'])
    except ObserverRegistryError as exc:
        report['reason'] = str(exc)
    if report['admission_closed'] and report['observers_removed']:
        report['status'] = 'RECOVERED'
    return report


def _publish(path: Path, report: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + '.pending')
    descriptor = os.open(temporary, os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(descriptor,'wb') as stream:
            stream.write(canonical_bytes(report) + b'\n'); stream.flush(); os.fsync(stream.fileno())
        os.link(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def run_observer_watchdog(registry_path: str | Path, root_id: str, ring_id: str, *,
                          docker_binary: str, output: Path, timeout_seconds: float = 3,
                          announce_ready: bool = False) -> dict:
    """Independent process watches lease, root state and finite lifetime.

    It never heartbeats or grants actions. The controller flock, not a PID alone,
    detects loss; the monotonic bound does not depend on authority wall time.
    """
    registry = ObserverRingRegistry(registry_path, create=False)
    records = [r for r in registry.unfinished() if r['root_id']==root_id and r['ring_id']==ring_id]
    if len(records) != 1:
        raise ControlError('OBSERVER_RING_IDENTITY_UNAVAILABLE')
    record = records[0]
    authority = SessionAuthority(record['authority_db'],create=False)
    remaining = min(record['lifetime_seconds'], max(0.0,record['deadline_at']-time.time()))
    deadline = time.monotonic() + remaining
    if not registry.controller_present():
        raise ControlError('OBSERVER_CONTROLLER_NOT_PRESENT_AT_READY')
    if announce_ready:
        print(json.dumps({'schema':'liminal.observer-watchdog-ready.v1','root_id':root_id,
                          'ring_id':ring_id,'registry_id':registry.registry_id,'pid':os.getpid()}), flush=True)
    reason = 'OBSERVER_WATCHDOG_LIFETIME'
    while time.monotonic() < deadline:
        try:
            snapshot = registry.snapshot(record)
            if snapshot['status'] != 'REGISTERED':
                reason = snapshot['closing_reason'] or 'OBSERVER_RING_CLOSING'; break
            if not registry.controller_present():
                reason = 'OBSERVER_CONTROLLER_LOST'; break
            call = BoundedHostCall(lambda: authority.status(root_id), name='observer-watchdog-observe')
            status = call.result_before(time.monotonic()+1.1)
            if (type(status) is not dict or status.get('root_id') != root_id
                    or status.get('control_profile') != 'durable-session-v1'):
                raise ControlError('OBSERVER_AUTHORITY_UNVERIFIED')
            if status.get('status') != 'ACTIVE':
                reason = 'OBSERVER_ROOT_NOT_ACTIVE'; break
        except Exception:
            reason = 'OBSERVER_WATCHDOG_OBSERVATION_UNAVAILABLE'; break
        time.sleep(min(.05,max(0.0,deadline-time.monotonic())))
    report = recover_observer_ring(registry,record,authority=authority,docker_binary=docker_binary,
                                  reason=reason,timeout_seconds=timeout_seconds)
    report['watchdog_pid'] = os.getpid()
    _publish(output,report)
    return report


class _Lifecycle:
    def __init__(self, supervisor: 'ObserverRingSupervisor', observer_id: str) -> None:
        self.supervisor, self.observer_id = supervisor, observer_id

    def labels(self) -> dict:
        return ownership_labels(self.supervisor.record,self.observer_id)

    def check(self, request: dict | None = None) -> None:
        self.supervisor._healthy()
        if request is not None and request.get('root_id') != self.supervisor.root_id:
            raise ControlError('OBSERVER_LIFECYCLE_ROOT_MISMATCH')

    def prepare(self) -> None:
        self.check(); self.supervisor.registry.mark_create_pending(self.supervisor.record,self.observer_id)

    def created(self, container_id: str) -> None:
        self.check()
        _owned(self.supervisor.docker_binary,container_id,self.supervisor.record,self.observer_id,self.supervisor.timeout_seconds)
        self.supervisor.registry.confirm_created(self.supervisor.record,self.observer_id,container_id)

    def enrolled(self, enrollment: dict) -> None:
        self.check(); self.supervisor.registry.confirm_enrolled(self.supervisor.record,self.observer_id,enrollment)

    def close(self) -> dict:
        report = self.supervisor.close()
        child = next((x for x in report.get('cleanup',[]) if x['observer_id']==self.observer_id),{})
        return {'container_id':child.get('container_id'),'removed':child.get('removed') is True,'execution_authorized':False}


class ObserverRingSupervisor:
    """Host-only managed ring; caller still installs immutable auth/source profiles."""
    def __init__(self, authority: SessionAuthority, root_id: str, *, registry_path: str | Path,
                 image_id: str, source_directories: dict[str,str|Path], lifetime_seconds: float = 30,
                 timeout_seconds: float = 5, docker_binary: str = 'docker') -> None:
        validate_id(root_id,'root_id')
        self.timeout_seconds = _positive(timeout_seconds,30)
        self.lifetime_seconds = _positive(lifetime_seconds,86400)
        if type(source_directories) is not dict or set(source_directories) != set(ROLES):
            raise ControlError('OBSERVER_LIFECYCLE_CONFIGURATION_INVALID')
        validate_source_directories(source_directories)
        self.authority,self.root_id = authority,root_id
        self.registry = ObserverRingRegistry(registry_path)
        if self.registry.path == authority.db_path.resolve():
            raise ControlError('OBSERVER_LIFECYCLE_CONFIGURATION_INVALID')
        self.services = {role:DockerObserver(image_id=image_id,observer_id=role+'-observer',role=role,
            key_id=role+'-key',source_directory=source_directories[role],timeout_seconds=self.timeout_seconds,
            docker_binary=docker_binary) for role in ROLES}
        self.docker_binary = self.services[ROLES[0]].docker_binary
        self.image_id = image_id
        self.record = None; self.enrollments = []; self.watchdog = None; self.watchdog_output = None
        self._lease = None; self._closed = False; self.last_report = None
        self._monotonic_deadline = None

    def _healthy(self) -> None:
        if self._closed or self.watchdog is None or self.watchdog.poll() is not None:
            raise ControlError('OBSERVER_WATCHDOG_UNAVAILABLE')
        if self.registry.snapshot(self.record)['status'] != 'REGISTERED':
            raise ControlError('OBSERVER_RING_CLOSING')
        self._check_deadline()
        _active(self.authority,self.root_id)
        self._check_deadline()  # Authority observation may cross the deadline.

    def _check_deadline(self) -> None:
        now=time.time()
        if (not math.isfinite(now) or now<self.record['registered_at']
                or now>=self.record['deadline_at']
                or (self._monotonic_deadline is not None and time.monotonic()>=self._monotonic_deadline)):
            raise ControlError('OBSERVER_RING_EXPIRED')

    def _ready(self) -> None:
        output = bytearray(); deadline = time.monotonic()+self.timeout_seconds
        with selectors.DefaultSelector() as selector:
            selector.register(self.watchdog.stdout,selectors.EVENT_READ)
            while time.monotonic() < deadline:
                if self.watchdog.poll() is not None:
                    break
                for _,_ in selector.select(min(.05,max(0.0,deadline-time.monotonic()))):
                    chunk = os.read(self.watchdog.stdout.fileno(),MAX_REPORT_BYTES+1-len(output))
                    output.extend(chunk)
                    if len(output)>MAX_REPORT_BYTES or not chunk:
                        raise ControlError('OBSERVER_WATCHDOG_READY_INVALID')
                    if b'\n' in output:
                        line,tail=bytes(output).split(b'\n',1)
                        try:
                            ready=json.loads(line)
                        except (ValueError,UnicodeError) as exc:
                            raise ControlError('OBSERVER_WATCHDOG_READY_INVALID') from exc
                        if (tail or ready != {'schema':'liminal.observer-watchdog-ready.v1','root_id':self.root_id,
                            'ring_id':self.record['ring_id'],'registry_id':self.registry.registry_id,'pid':self.watchdog.pid}):
                            raise ControlError('OBSERVER_WATCHDOG_READY_INVALID')
                        return
        raise ControlError('OBSERVER_WATCHDOG_READY_UNAVAILABLE')

    def start(self) -> 'ObserverRingSupervisor':
        if self.record is not None or self._closed:
            raise ControlError('OBSERVER_RING_RESTART_FORBIDDEN')
        _active(self.authority,self.root_id)
        self._lease = self.registry.controller_lease(); self._lease.__enter__()
        try:
            self.record = self.registry.register_ring(root_id=self.root_id,authority_db=self.authority.db_path.resolve(),
                image_id=self.image_id,lifetime_seconds=self.lifetime_seconds,observers=[
                    {'observer_id':s.observer_id,'role':s.role,'key_id':s.key_id,'container_name':s.container_name}
                    for s in self.services.values()])
            self._monotonic_deadline=time.monotonic()+self.lifetime_seconds
            self.watchdog_output = self.registry.path.with_name(self.registry.path.name+'.'+self.record['ring_id']+'.watchdog.json')
            command=[sys.executable,'-m','liminal_agent_control.observer_lifecycle','--watchdog','--registry',str(self.registry.path),
                '--root-id',self.root_id,'--ring-id',self.record['ring_id'],'--docker-binary',self.docker_binary,
                '--output',str(self.watchdog_output),'--timeout',str(self.timeout_seconds)]
            self.watchdog=subprocess.Popen(command,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,
                close_fds=True,start_new_session=True,env={'PATH':'/usr/bin:/bin','LC_ALL':'C.UTF-8',
                'PYTHONDONTWRITEBYTECODE':'1','PYTHONPATH':str(Path(__file__).resolve().parents[1])})
            self._ready()
            for service in self.services.values():
                service.lifecycle=_Lifecycle(self,service.observer_id)
                self.enrollments.append(service.start())
            return self
        except Exception:
            self.close(); raise

    def close(self) -> dict:
        if self._closed:
            return self.last_report or {'status':'INCOMPLETE','cleanup':[]}
        self._closed=True
        if self.record is None:
            if self._lease is not None:
                self._lease.__exit__(None,None,None); self._lease=None
            self.last_report={'status':'INCOMPLETE','cleanup':[]}; return self.last_report
        _closure(self.authority,self.root_id,'OBSERVER_RING_CLOSED')
        try:
            self.registry.begin_closing(self.record,'OBSERVER_RING_CLOSED')
        except ObserverRegistryError:
            pass
        if self._lease is not None:
            self._lease.__exit__(None,None,None); self._lease=None
        if self.watchdog is not None:
            try:
                self.watchdog.wait(timeout=min(30.0,6*self.timeout_seconds+1)+8)
            except subprocess.TimeoutExpired:
                pass  # A timeout does not cancel independent recovery.
        if self.watchdog_output is not None and self.watchdog_output.is_file():
            try:
                report=json.loads(self.watchdog_output.read_bytes())
                if report.get('ring_id')!=self.record['ring_id'] or report.get('root_id')!=self.root_id:
                    raise ValueError()
                self.last_report=report
            except (ValueError,OSError):
                self.last_report={'status':'INCOMPLETE','cleanup':[]}
        elif self.watchdog is None or self.watchdog.poll() is not None:
            self.last_report=recover_observer_ring(self.registry,self.record,authority=self.authority,
                docker_binary=self.docker_binary,reason='OBSERVER_WATCHDOG_UNAVAILABLE',timeout_seconds=self.timeout_seconds)
        else:
            self.last_report={'status':'INCOMPLETE','reason':'OBSERVER_RECOVERY_STILL_RUNNING','cleanup':[]}
        for service in self.services.values():
            if service._process is not None:
                _kill_and_reap(service._process)
                for stream in (service._process.stdin,service._process.stdout,service._process.stderr):
                    if stream is not None and not stream.closed:
                        stream.close()
            service._closed=True
        if self.watchdog is not None and self.watchdog.stdout is not None:
            self.watchdog.stdout.close()
        return self.last_report

    def __enter__(self) -> 'ObserverRingSupervisor':
        return self.start()

    def __exit__(self,*_) -> None:
        self.close()


def main() -> int:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--watchdog',action='store_true',required=True)
    parser.add_argument('--registry',type=Path,required=True); parser.add_argument('--root-id',required=True)
    parser.add_argument('--ring-id',required=True); parser.add_argument('--docker-binary',required=True)
    parser.add_argument('--output',type=Path,required=True); parser.add_argument('--timeout',type=float,default=3)
    args=parser.parse_args()
    binary=shutil.which(args.docker_binary)
    if binary is None:
        raise ControlError('OBSERVER_CONTAINER_DOCKER_UNAVAILABLE')
    report=run_observer_watchdog(args.registry,args.root_id,args.ring_id,docker_binary=binary,
        output=args.output,timeout_seconds=_positive(args.timeout,30),announce_ready=True)
    return 0 if report['status']=='RECOVERED' else 1


if __name__=='__main__':
    raise SystemExit(main())
