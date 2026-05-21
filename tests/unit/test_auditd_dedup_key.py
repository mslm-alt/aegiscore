import hashlib
from unittest.mock import Mock

from core.normalize import NormalizedEvent
from core.phase_manager import Phase
from tests.unit.test_phase_contracts import _make_pipeline


def _auditd_event(*, ts=1710000000.0, action='syscall', category='process', outcome='success', process='bash', message='type=SYSCALL msg=audit', raw='type=SYSCALL msg=audit', user='1000', src_ip='', dst_ip='', fields=None):
    return NormalizedEvent(
        ts=ts,
        source='auditd',
        category=category,
        action=action,
        outcome=outcome,
        user=user,
        src_ip=src_ip,
        dst_ip=dst_ip,
        process=process,
        host='srv-audit',
        message=message,
        raw=raw,
        fields=fields or {},
        distro_family='debian',
    )


def test_auditd_event_hash_uses_file_path_not_message_prefix_collision():
    prefix = 'type=PATH msg=audit(1710000000.000:10): item=0 cwd="/root" dev=00:00 inode=1 ' + ('x' * 40)
    evt1 = _auditd_event(
        action='file_access',
        category='filesystem',
        process='cat',
        message=prefix + ' one',
        raw=prefix + ' one',
        fields={'audit_type': 'PATH', 'file_path': '/etc/passwd', 'nametype': 'UNKNOWN'},
    )
    evt2 = _auditd_event(
        action='file_access',
        category='filesystem',
        process='cat',
        message=prefix + ' two',
        raw=prefix + ' two',
        fields={'audit_type': 'PATH', 'file_path': '/etc/shadow', 'nametype': 'UNKNOWN'},
    )

    assert evt1.message[:80] == evt2.message[:80]
    assert evt1.event_hash() != evt2.event_hash()


def test_auditd_event_hash_matches_when_core_syscall_fields_match():
    base_fields = {
        'audit_type': 'SYSCALL',
        'syscall': '59',
        'exit': '-2',
        'comm': 'python3',
        'exe': '/usr/bin/python3',
        'file_path': '/usr/bin/id',
        'uid': '1000',
        'auid': '1000',
    }
    evt1 = _auditd_event(process='python3', message='syscall=59 exit=-2', raw='raw1', fields=base_fields)
    evt2 = _auditd_event(process='python3', message='same prefix but reformatted', raw='raw2', fields=dict(base_fields))

    assert evt1.event_hash() == evt2.event_hash()


def test_auditd_event_hash_differs_for_different_syscall():
    evt1 = _auditd_event(fields={'audit_type': 'SYSCALL', 'syscall': '59', 'exit': '0', 'comm': 'python3'})
    evt2 = _auditd_event(fields={'audit_type': 'SYSCALL', 'syscall': '42', 'exit': '0', 'comm': 'python3'})

    assert evt1.event_hash() != evt2.event_hash()


def test_auditd_path_hash_differs_for_nametype_and_path():
    evt1 = _auditd_event(
        action='file_access',
        category='filesystem',
        fields={'audit_type': 'PATH', 'file_path': '/etc/cron.d/backdoor', 'nametype': 'CREATE'},
    )
    evt2 = _auditd_event(
        action='file_access',
        category='filesystem',
        fields={'audit_type': 'PATH', 'file_path': '/etc/cron.d/backdoor', 'nametype': 'UNKNOWN'},
    )
    evt3 = _auditd_event(
        action='file_access',
        category='filesystem',
        fields={'audit_type': 'PATH', 'file_path': '/etc/systemd/system/evil.service', 'nametype': 'CREATE'},
    )

    assert evt1.event_hash() != evt2.event_hash()
    assert evt1.event_hash() != evt3.event_hash()


def test_auditd_connect_hash_differs_for_network_target():
    evt1 = _auditd_event(
        action='connect',
        category='network',
        process='python3',
        dst_ip='198.51.100.10',
        fields={'audit_type': 'SOCKADDR', 'syscall': '42', 'dst_port': '443'},
    )
    evt2 = _auditd_event(
        action='connect',
        category='network',
        process='python3',
        dst_ip='198.51.100.11',
        fields={'audit_type': 'SOCKADDR', 'syscall': '42', 'dst_port': '443'},
    )
    evt3 = _auditd_event(
        action='connect',
        category='network',
        process='python3',
        dst_ip='198.51.100.10',
        fields={'audit_type': 'SOCKADDR', 'syscall': '42', 'dst_port': '8443'},
    )

    assert evt1.event_hash() != evt2.event_hash()
    assert evt1.event_hash() != evt3.event_hash()


def test_non_auditd_event_hash_contract_is_unchanged():
    evt = NormalizedEvent(
        ts=1710000000.0,
        source='auth.log',
        category='auth',
        action='ssh_login',
        outcome='success',
        user='alice',
        src_ip='203.0.113.10',
        process='sshd',
        host='srv1',
        message='accepted password for alice from 203.0.113.10',
        raw='raw',
        fields={},
        distro_family='debian',
    )

    expected = hashlib.md5(
        f'{evt.source}|{evt.action}|{evt.user}|{evt.src_ip}|{evt.message[:80]}|{int(evt.ts)}'.encode()
    ).hexdigest()
    assert evt.event_hash() == expected


def test_cross_source_hash_contract_is_unchanged_for_telemetry_dedup():
    evt1 = _auditd_event(action='login', category='auth', user='alice', src_ip='203.0.113.10', message='accepted password')
    evt2 = NormalizedEvent(
        ts=1710000002.0,
        source='auth.log',
        category='auth',
        action='login',
        outcome='success',
        user='alice',
        src_ip='203.0.113.10',
        process='sshd',
        host='srv1',
        message='accepted password',
        raw='raw',
        fields={},
        distro_family='debian',
    )

    assert evt1.cross_source_hash() == evt2.cross_source_hash()


def test_pipeline_exact_duplicate_uses_auditd_specific_hash_without_false_collision():
    pipeline, _ = _make_pipeline(Phase.PHASE_0, active_layers=[])
    pipeline.phase.record_duplicate = Mock()
    first = _auditd_event(
        action='file_access',
        category='filesystem',
        process='cat',
        message='type=PATH msg=audit probe /etc/passwd',
        raw='type=PATH msg=audit item=0 name="/etc/passwd" nametype=UNKNOWN',
        fields={'audit_type': 'PATH', 'file_path': '/etc/passwd', 'nametype': 'UNKNOWN'},
    )
    second = _auditd_event(
        action='file_access',
        category='filesystem',
        process='cat',
        message='type=PATH msg=audit probe /etc/shadow',
        raw='type=PATH msg=audit item=0 name="/etc/shadow" nametype=UNKNOWN',
        fields={'audit_type': 'PATH', 'file_path': '/etc/shadow', 'nametype': 'UNKNOWN'},
    )
    dup = _auditd_event(
        action='file_access',
        category='filesystem',
        process='cat',
        message='type=PATH msg=audit probe /etc/passwd',
        raw='type=PATH msg=audit item=0 name="/etc/passwd" nametype=UNKNOWN',
        fields={'audit_type': 'PATH', 'file_path': '/etc/passwd', 'nametype': 'UNKNOWN'},
    )

    pipeline.normalizer = type('_N', (), {'normalize': staticmethod(lambda raw, source: first)})()
    pipeline._process_event_locked('raw1', 'auditd')
    pipeline.normalizer = type('_N', (), {'normalize': staticmethod(lambda raw, source: second)})()
    pipeline._process_event_locked('raw2', 'auditd')
    pipeline.normalizer = type('_N', (), {'normalize': staticmethod(lambda raw, source: dup)})()
    pipeline._process_event_locked('raw3', 'auditd')

    pipeline.phase.record_duplicate.assert_called_once_with(kind='exact_same_source', source='auditd')
