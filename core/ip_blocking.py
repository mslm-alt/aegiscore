from __future__ import annotations

import ipaddress
import logging
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

_RESERVED_V4_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]

_KNOWN_BACKENDS = ("firewalld", "ufw", "nftables", "iptables")
_REAL_APPLY_BACKENDS = {"firewalld", "ufw"}


@dataclass
class CommandPlan:
    argv: List[str]
    description: str


@dataclass
class BlockExecutionResult:
    ok: bool
    action: str
    status: str
    ip: str
    backend: str = ""
    backend_rule_ref: str = ""
    reason: str = ""
    guard_reason: str = ""
    error: str = ""
    suggestion_id: Optional[int] = None
    dry_run: bool = False
    commands: List[CommandPlan] = field(default_factory=list)
    supported: bool = False
    plan_supported: bool = False
    real_apply_supported: bool = False
    action_id: Optional[int] = None

    def to_dict(self) -> Dict:
        return {
            "ok": self.ok,
            "action": self.action,
            "status": self.status,
            "ip": self.ip,
            "backend": self.backend,
            "backend_rule_ref": self.backend_rule_ref,
            "reason": self.reason,
            "guard_reason": self.guard_reason,
            "error": self.error,
            "suggestion_id": self.suggestion_id,
            "dry_run": self.dry_run,
            "supported": self.supported,
            "plan_supported": self.plan_supported,
            "real_apply_supported": self.real_apply_supported,
            "commands": [dict(argv=cmd.argv, description=cmd.description) for cmd in self.commands],
            "action_id": self.action_id,
        }


class IPBlocker:
    def __init__(
        self,
        config: Dict,
        db,
        command_runner: Optional[Callable[[List[str]], Tuple[int, str, str]]] = None,
    ):
        self._cfg = (config or {}).get("ip_blocking", {}) or {}
        self._db = db
        self._command_runner = command_runner or self._run_command
        self._allowlist = self._parse_allowlist(self._cfg.get("allowlist", []) or [])

    @staticmethod
    def _normalize_backend(raw: object) -> str:
        token = str(raw or "").strip().lower()
        aliases = {
            "auto": "auto",
            "firewalld": "firewalld",
            "ufw": "ufw",
            "nft": "nftables",
            "nftables": "nftables",
            "iptables": "iptables",
        }
        return aliases.get(token, "")

    @staticmethod
    def _run_command(argv: List[str]) -> Tuple[int, str, str]:
        try:
            proc = subprocess.run(argv, capture_output=True, text=True, timeout=15)
            return proc.returncode, proc.stdout.strip(), proc.stderr.strip()
        except subprocess.TimeoutExpired:
            return 124, "", "command_timeout"

    @staticmethod
    def _parse_allowlist(items: List[str]) -> List[ipaddress._BaseNetwork]:
        parsed: List[ipaddress._BaseNetwork] = []
        for raw in items:
            token = str(raw or "").strip()
            if not token:
                continue
            try:
                if "/" in token:
                    parsed.append(ipaddress.ip_network(token, strict=False))
                else:
                    ip = ipaddress.ip_address(token)
                    parsed.append(ipaddress.ip_network(f"{ip}/{ip.max_prefixlen}", strict=False))
            except ValueError:
                logger.warning("[IPBlock] Geçersiz allowlist girdisi atlandı: %s", token)
        return parsed

    def _parse_ip(self, raw_ip: str) -> ipaddress._BaseAddress:
        return ipaddress.ip_address((raw_ip or "").strip())

    def _guard_ip(self, ip_obj: ipaddress._BaseAddress) -> str:
        if ip_obj.is_unspecified:
            return "unspecified_ip"
        if ip_obj.is_loopback:
            return "loopback_ip"
        if ip_obj.version == 4:
            for net in _RESERVED_V4_NETWORKS:
                if ip_obj in net:
                    return f"internal_ip:{net}"
            if str(ip_obj) == "255.255.255.255":
                return "broadcast_ip"
        if ip_obj.is_multicast:
            return "multicast_ip"
        if ip_obj.is_reserved:
            return "reserved_ip"
        if ip_obj.is_private:
            return "private_ip"
        if getattr(ip_obj, "is_link_local", False):
            return "link_local_ip"
        for net in self._allowlist:
            if ip_obj in net:
                return f"allowlist_hit:{net}"
        return ""

    def _detect_backend(self) -> Tuple[str, bool]:
        preferred = self._normalize_backend(self._cfg.get("default_backend", "auto"))

        def _probe(backend: str) -> Tuple[str, bool]:
            if backend == "firewalld":
                if not shutil.which("firewall-cmd"):
                    return "firewalld", False
                rc, stdout, _stderr = self._command_runner(["firewall-cmd", "--state"])
                if rc == 0 and stdout.strip().lower() == "running":
                    return "firewalld", True
                return "firewalld", False
            if backend == "ufw":
                if not shutil.which("ufw"):
                    return "ufw", False
                rc, stdout, stderr = self._command_runner(["ufw", "status"])
                if rc != 0:
                    return "ufw", False
                status_text = " ".join(part for part in (stdout, stderr) if part).strip().lower()
                if "inactive" in status_text:
                    return "ufw", False
                if "status: active" in status_text or stdout.strip():
                    return "ufw", True
                return "ufw", False
            if backend == "nftables":
                return ("nftables", False) if shutil.which("nft") else ("nftables", False)
            if backend == "iptables":
                return ("iptables", False) if shutil.which("iptables") else ("iptables", False)
            return "", False

        if preferred and preferred != "auto":
            return _probe(preferred)

        for backend in _KNOWN_BACKENDS:
            if backend == "firewalld" and shutil.which("firewall-cmd"):
                return _probe("firewalld")
            if backend == "ufw" and shutil.which("ufw"):
                return _probe("ufw")
            if backend == "nftables" and shutil.which("nft"):
                return "nftables", False
            if backend == "iptables" and shutil.which("iptables"):
                return "iptables", False
        return "", False

    def _real_apply_error(self, backend: str, supported: bool) -> str:
        configured = self._normalize_backend(self._cfg.get("real_backend", "firewalld")) or "firewalld"
        if configured == "auto":
            configured = backend or "auto"
        if configured not in _REAL_APPLY_BACKENDS:
            return "real_apply_unsupported_for_backend"
        if not backend:
            return "backend_unavailable_for_real_apply"
        if backend != configured:
            return "real_apply_unsupported_for_backend"
        if backend not in _REAL_APPLY_BACKENDS or not supported:
            if backend == "firewalld":
                return "firewalld_unavailable_for_real_apply"
            if backend == "ufw":
                return "ufw_unavailable_for_real_apply"
            return "real_apply_unsupported_for_backend"
        return ""

    @staticmethod
    def _firewalld_rich_rule(ip_obj: ipaddress._BaseAddress) -> str:
        family = "ipv4" if ip_obj.version == 4 else "ipv6"
        return f'rule family="{family}" source address="{ip_obj.compressed}" drop'

    @staticmethod
    def _ufw_rule_spec(ip_obj: ipaddress._BaseAddress) -> str:
        return f"deny from {ip_obj.compressed} to any"

    @staticmethod
    def _nft_rule_spec(ip_obj: ipaddress._BaseAddress) -> str:
        family = "ip6" if ip_obj.version == 6 else "ip"
        return f"add rule inet filter input {family} saddr {ip_obj.compressed} drop"

    @staticmethod
    def _iptables_rule_spec(ip_obj: ipaddress._BaseAddress) -> List[str]:
        binary = "ip6tables" if ip_obj.version == 6 else "iptables"
        return [binary, "-I", "INPUT", "-s", ip_obj.compressed, "-j", "DROP"]

    def _query_firewalld_rule(self, rich_rule: str) -> Tuple[bool, str]:
        rc, _stdout, stderr = self._command_runner(
            ["firewall-cmd", "--permanent", "--query-rich-rule", rich_rule]
        )
        if rc == 0:
            return True, ""
        if rc == 1:
            return False, ""
        return False, stderr or "firewalld_query_failed"

    def _query_ufw_rule(self, ip_obj: ipaddress._BaseAddress) -> Tuple[bool, str]:
        rc, stdout, stderr = self._command_runner(["ufw", "status"])
        if rc != 0:
            text = " ".join(part for part in (stderr, stdout) if part).strip().lower()
            if "permission denied" in text or "must be root" in text or "you need to be root" in text:
                return False, "permission_denied"
            return False, stderr or stdout or "ufw_status_failed"
        status_text = str(stdout or "").strip().lower()
        if "inactive" in status_text:
            return False, "ufw_inactive"
        ip_token = ip_obj.compressed.lower()
        for line in str(stdout or "").splitlines():
            lowered = line.strip().lower()
            if ip_token in lowered and "deny" in lowered:
                return True, ""
        return False, ""

    @staticmethod
    def _command_error(argv: List[str], stdout: str, stderr: str) -> str:
        text = " ".join(part for part in (stderr, stdout) if part).strip().lower()
        if "permission denied" in text or "must be root" in text or "you need to be root" in text:
            return "permission_denied"
        if "not found" in text:
            return "binary_not_found"
        if "timeout" in text:
            return "command_timeout"
        return stderr or stdout or f"command_failed:{' '.join(argv)}"

    def _build_command_plan(self, action: str, ip_obj: ipaddress._BaseAddress, backend: str) -> Tuple[str, List[CommandPlan]]:
        if backend == "firewalld":
            rich_rule = self._firewalld_rich_rule(ip_obj)
            flag = "--add-rich-rule" if action == "block" else "--remove-rich-rule"
            return rich_rule, [
                CommandPlan(
                    argv=["firewall-cmd", "--permanent", flag, rich_rule],
                    description=f"firewalld {'block' if action == 'block' else 'unblock'} rule",
                ),
                CommandPlan(
                    argv=["firewall-cmd", "--reload"],
                    description="firewalld reload",
                ),
            ]
        if backend == "ufw":
            spec = self._ufw_rule_spec(ip_obj)
            if action == "block":
                argv = ["ufw", "deny", "from", ip_obj.compressed, "to", "any"]
            else:
                argv = ["ufw", "delete", "deny", "from", ip_obj.compressed, "to", "any"]
            return spec, [
                CommandPlan(
                    argv=argv,
                    description=f"ufw {'block' if action == 'block' else 'unblock'} rule",
                ),
            ]
        if backend == "nftables":
            spec = self._nft_rule_spec(ip_obj)
            if action == "block":
                argv = ["nft", *spec.split()]
            else:
                argv = ["nft", "delete", "rule", "inet", "filter", "input", "handle", "<AegisCore-handle-required>"]
            return spec, [
                CommandPlan(
                    argv=argv,
                    description=f"nftables {'block' if action == 'block' else 'unblock'} plan only",
                ),
            ]
        if backend == "iptables":
            argv = self._iptables_rule_spec(ip_obj)
            if action == "unblock":
                argv = [argv[0], "-D", "INPUT", "-s", ip_obj.compressed, "-j", "DROP"]
            return " ".join(argv), [
                CommandPlan(
                    argv=argv,
                    description=f"iptables {'block' if action == 'block' else 'unblock'} plan only",
                ),
            ]
        return "", []

    def _record_action(self, result: BlockExecutionResult, executed_by: str) -> BlockExecutionResult:
        details = result.to_dict()
        if self._db and hasattr(self._db, "add_ip_block_action"):
            result.action_id = self._db.add_ip_block_action(
                ip=result.ip,
                action=result.action,
                status=result.status,
                dry_run=bool(result.dry_run),
                backend=result.backend,
                backend_rule_ref=result.backend_rule_ref,
                reason=result.reason,
                guard_reason=result.guard_reason,
                error=result.error,
                executed_by=executed_by,
                suggestion_id=result.suggestion_id,
            )
            details["action_id"] = result.action_id
        if self._db and hasattr(self._db, "log_action"):
            summary = (
                f"IP {result.action} {result.status}: {result.ip}"
                + (f" ({result.guard_reason})" if result.guard_reason else "")
            )
            self._db.log_action(
                action=f"ip_{result.action}",
                status=result.status,
                actor=executed_by,
                screen="cli",
                entity_type="ip",
                entity_id=result.ip,
                target=result.ip,
                summary=summary[:200],
                details=details,
            )
        return result

    def block_ip(
        self,
        ip: str,
        reason: str = "",
        dry_run: bool = False,
        executed_by: str = "terminal",
        suggestion_id: Optional[int] = None,
    ) -> BlockExecutionResult:
        try:
            ip_obj = self._parse_ip(ip)
        except ValueError as exc:
            return self._record_action(BlockExecutionResult(
                ok=False,
                action="block",
                status="refused",
                ip=(ip or "").strip(),
                reason=reason,
                error=str(exc),
                guard_reason="invalid_ip",
                suggestion_id=suggestion_id,
                dry_run=dry_run,
            ), executed_by)

        guard_reason = self._guard_ip(ip_obj)
        if guard_reason:
            return self._record_action(BlockExecutionResult(
                ok=False,
                action="block",
                status="refused",
                ip=ip_obj.compressed,
                reason=reason,
                guard_reason=guard_reason,
                suggestion_id=suggestion_id,
                dry_run=dry_run,
            ), executed_by)

        active = self._db.get_active_ip_block(ip_obj.compressed) if self._db and hasattr(self._db, "get_active_ip_block") else None
        if active:
            return self._record_action(BlockExecutionResult(
                ok=False,
                action="block",
                status="refused",
                ip=ip_obj.compressed,
                reason=reason,
                guard_reason="already_blocked",
                backend=str(active.get("backend", "") or ""),
                backend_rule_ref=str(active.get("backend_rule_ref", "") or ""),
                suggestion_id=suggestion_id,
                dry_run=dry_run,
            ), executed_by)

        backend, supported = self._detect_backend()
        rule_ref, commands = self._build_command_plan("block", ip_obj, backend)
        plan_supported = bool(backend and commands)
        real_apply_error = self._real_apply_error(backend, supported)
        real_apply_supported = not bool(real_apply_error)

        if dry_run:
            if not plan_supported:
                return self._record_action(BlockExecutionResult(
                    ok=False,
                    action="block",
                    status="unsupported",
                    ip=ip_obj.compressed,
                    backend=backend,
                    backend_rule_ref=rule_ref,
                    reason=reason,
                    suggestion_id=suggestion_id,
                    dry_run=True,
                    commands=commands,
                    supported=False,
                    plan_supported=False,
                    real_apply_supported=real_apply_supported,
                ), executed_by)
            return self._record_action(BlockExecutionResult(
                ok=True,
                action="block",
                status="dry_run",
                ip=ip_obj.compressed,
                backend=backend,
                backend_rule_ref=rule_ref,
                reason=reason,
                suggestion_id=suggestion_id,
                dry_run=True,
                commands=commands,
                supported=True,
                plan_supported=True,
                real_apply_supported=real_apply_supported,
            ), executed_by)

        if real_apply_error:
            return self._record_action(BlockExecutionResult(
                ok=False,
                action="block",
                status="failed",
                ip=ip_obj.compressed,
                backend=backend,
                backend_rule_ref=rule_ref,
                reason=reason,
                suggestion_id=suggestion_id,
                commands=commands,
                supported=supported,
                plan_supported=plan_supported,
                real_apply_supported=False,
                error=real_apply_error,
            ), executed_by)

        if backend == "firewalld":
            exists, query_error = self._query_firewalld_rule(rule_ref)
        elif backend == "ufw":
            exists, query_error = self._query_ufw_rule(ip_obj)
        else:
            exists, query_error = False, ""
        if query_error:
            return self._record_action(BlockExecutionResult(
                ok=False,
                action="block",
                status="failed",
                ip=ip_obj.compressed,
                backend=backend,
                backend_rule_ref=rule_ref,
                reason=reason,
                suggestion_id=suggestion_id,
                commands=commands,
                supported=True,
                plan_supported=plan_supported,
                real_apply_supported=True,
                error=query_error,
            ), executed_by)
        if exists:
            return self._record_action(BlockExecutionResult(
                ok=False,
                action="block",
                status="refused",
                ip=ip_obj.compressed,
                backend=backend,
                backend_rule_ref=rule_ref,
                reason=reason,
                guard_reason="already_blocked_backend",
                suggestion_id=suggestion_id,
                commands=commands,
                supported=True,
                plan_supported=plan_supported,
                real_apply_supported=True,
            ), executed_by)

        for cmd in commands:
            rc, stdout, stderr = self._command_runner(cmd.argv)
            if rc != 0:
                return self._record_action(BlockExecutionResult(
                    ok=False,
                    action="block",
                    status="failed",
                    ip=ip_obj.compressed,
                    backend=backend,
                    backend_rule_ref=rule_ref,
                    reason=reason,
                    suggestion_id=suggestion_id,
                    commands=commands,
                    supported=True,
                    plan_supported=plan_supported,
                    real_apply_supported=True,
                    error=self._command_error(cmd.argv, stdout, stderr),
                ), executed_by)

        return self._record_action(BlockExecutionResult(
            ok=True,
            action="block",
            status="applied",
            ip=ip_obj.compressed,
            backend=backend,
            backend_rule_ref=rule_ref,
            reason=reason,
            suggestion_id=suggestion_id,
            commands=commands,
            supported=True,
            plan_supported=plan_supported,
            real_apply_supported=True,
        ), executed_by)

    def unblock_ip(
        self,
        ip: str,
        reason: str = "",
        dry_run: bool = False,
        executed_by: str = "terminal",
    ) -> BlockExecutionResult:
        try:
            ip_obj = self._parse_ip(ip)
        except ValueError as exc:
            return self._record_action(BlockExecutionResult(
                ok=False,
                action="unblock",
                status="refused",
                ip=(ip or "").strip(),
                reason=reason,
                error=str(exc),
                guard_reason="invalid_ip",
                dry_run=dry_run,
            ), executed_by)

        active = self._db.get_active_ip_block(ip_obj.compressed) if self._db and hasattr(self._db, "get_active_ip_block") else None
        if not active:
            return self._record_action(BlockExecutionResult(
                ok=False,
                action="unblock",
                status="refused",
                ip=ip_obj.compressed,
                reason=reason,
                guard_reason="not_blocked",
                dry_run=dry_run,
            ), executed_by)

        backend = str(active.get("backend", "") or "")
        supported = backend in _REAL_APPLY_BACKENDS
        rule_ref = str(active.get("backend_rule_ref", "") or "")
        commands = []
        if backend == "firewalld" and rule_ref:
            commands = [
                CommandPlan(
                    argv=["firewall-cmd", "--permanent", "--remove-rich-rule", rule_ref],
                    description="firewalld unblock rule",
                ),
                CommandPlan(
                    argv=["firewall-cmd", "--reload"],
                    description="firewalld reload",
                ),
            ]
        elif backend == "ufw":
            rule_ref = rule_ref or self._ufw_rule_spec(ip_obj)
            commands = [
                CommandPlan(
                    argv=["ufw", "delete", "deny", "from", ip_obj.compressed, "to", "any"],
                    description="ufw unblock rule",
                ),
            ]
        plan_supported = bool(backend and commands)
        real_apply_error = self._real_apply_error(backend, supported)
        real_apply_supported = not bool(real_apply_error)

        if dry_run:
            if not plan_supported:
                return self._record_action(BlockExecutionResult(
                    ok=False,
                    action="unblock",
                    status="unsupported",
                    ip=ip_obj.compressed,
                    backend=backend,
                    backend_rule_ref=rule_ref,
                    reason=reason,
                    dry_run=True,
                    commands=commands,
                    supported=False,
                    plan_supported=False,
                    real_apply_supported=real_apply_supported,
                ), executed_by)
            return self._record_action(BlockExecutionResult(
                ok=True,
                action="unblock",
                status="dry_run",
                ip=ip_obj.compressed,
                backend=backend,
                backend_rule_ref=rule_ref,
                reason=reason,
                dry_run=True,
                commands=commands,
                supported=True,
                plan_supported=True,
                real_apply_supported=real_apply_supported,
            ), executed_by)

        if real_apply_error:
            return self._record_action(BlockExecutionResult(
                ok=False,
                action="unblock",
                status="failed",
                ip=ip_obj.compressed,
                backend=backend,
                backend_rule_ref=rule_ref,
                reason=reason,
                commands=commands,
                supported=supported,
                plan_supported=plan_supported,
                real_apply_supported=False,
                error=real_apply_error,
            ), executed_by)

        if backend == "firewalld":
            exists, query_error = self._query_firewalld_rule(rule_ref)
        elif backend == "ufw":
            exists, query_error = self._query_ufw_rule(ip_obj)
        else:
            exists, query_error = False, ""
        if query_error:
            return self._record_action(BlockExecutionResult(
                ok=False,
                action="unblock",
                status="failed",
                ip=ip_obj.compressed,
                backend=backend,
                backend_rule_ref=rule_ref,
                reason=reason,
                commands=commands,
                supported=True,
                plan_supported=plan_supported,
                real_apply_supported=True,
                error=query_error,
            ), executed_by)
        if not exists:
            return self._record_action(BlockExecutionResult(
                ok=False,
                action="unblock",
                status="failed",
                ip=ip_obj.compressed,
                backend=backend,
                backend_rule_ref=rule_ref,
                reason=reason,
                commands=commands,
                supported=True,
                plan_supported=plan_supported,
                real_apply_supported=True,
                error="backend_rule_missing",
            ), executed_by)

        for cmd in commands:
            rc, stdout, stderr = self._command_runner(cmd.argv)
            if rc != 0:
                return self._record_action(BlockExecutionResult(
                    ok=False,
                    action="unblock",
                    status="failed",
                    ip=ip_obj.compressed,
                    backend=backend,
                    backend_rule_ref=rule_ref,
                    reason=reason,
                    commands=commands,
                    supported=True,
                    plan_supported=plan_supported,
                    real_apply_supported=True,
                    error=self._command_error(cmd.argv, stdout, stderr),
                ), executed_by)

        return self._record_action(BlockExecutionResult(
            ok=True,
            action="unblock",
            status="applied",
            ip=ip_obj.compressed,
            backend=backend,
            backend_rule_ref=rule_ref,
            reason=reason,
            commands=commands,
            supported=True,
            plan_supported=plan_supported,
            real_apply_supported=True,
        ), executed_by)
