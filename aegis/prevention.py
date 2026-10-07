import platform
import re
import subprocess
import time

MAC_RE = re.compile(r"^[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}$")

class PreventionEngine:
    """Linux iptables+ebtables backend plus a safe simulation backend."""

    def __init__(self, logger, simulation=True, block_duration=300):
        self.logger = logger
        self.simulation = simulation
        self.block_duration = block_duration
        self.blocks = {}  # mac -> expiry or None

    def _valid_mac(self, mac):
        return bool(MAC_RE.fullmatch(mac or ""))

    def _run(self, args):
        return subprocess.run(args, capture_output=True, text=True, check=False)

    def _run_checked(self, args):
        result = self._run(args)
        if result.returncode != 0:
            raise RuntimeError(result.stderr.strip() or f"Command failed: {' '.join(args)}")
        return result

    def block(self, mac, ip, attack_type, raw, decoded, confidence, reason):
        if not self._valid_mac(mac):
            raise ValueError("Invalid MAC address")
        expiry = None if self.block_duration <= 0 else time.time() + self.block_duration
        if self.simulation:
            self.blocks[mac.lower()] = expiry
        else:
            if platform.system().lower() != "linux":
                raise RuntimeError("iptables/ebtables prevention requires Linux")
            rules = [
                ["iptables", "-I", "INPUT", "-m", "mac", "--mac-source", mac, "-j", "DROP"],
                ["ebtables", "-I", "INPUT", "-s", mac, "-j", "DROP"],
            ]
            applied = []
            try:
                for cmd in rules:
                    self._run_checked(cmd)
                    applied.append(cmd)
            except (OSError, RuntimeError):
                for cmd in reversed(applied):
                    rollback = cmd.copy()
                    rollback[1] = "-D"
                    self._run(rollback)
                raise
            self.blocks[mac.lower()] = expiry
        self.logger.append_block(mac, ip, attack_type, raw, decoded, confidence, reason)

    def unblock(self, mac, admin, reason):
        if not self._valid_mac(mac):
            raise ValueError("Invalid MAC address")
        key = mac.lower()
        if not self.simulation:
            if platform.system().lower() != "linux":
                raise RuntimeError("iptables/ebtables prevention requires Linux")
            cmds = [
                ["iptables", "-D", "INPUT", "-m", "mac", "--mac-source", mac, "-j", "DROP"],
                ["ebtables", "-D", "INPUT", "-s", mac, "-j", "DROP"],
            ]
            removed = []
            try:
                for cmd in cmds:
                    self._run_checked(cmd)
                    removed.append(cmd)
            except (OSError, RuntimeError):
                for cmd in reversed(removed):
                    rollback = cmd.copy()
                    rollback[1] = "-I"
                    self._run(rollback)
                raise
        self.blocks.pop(key, None)
        self.logger.append_unblock(mac, admin, reason)

    def expire(self):
        now = time.time()
        for mac, expiry in list(self.blocks.items()):
            if expiry is not None and now >= expiry:
                try:
                    self.unblock(mac, "SYSTEM", "Automatic block expiry")
                except (OSError, RuntimeError) as exc:
                    self.logger.append_error(mac, f"Automatic block expiry failed: {exc}")

    def is_blocked(self, mac):
        self.expire()
        return mac.lower() in self.blocks
