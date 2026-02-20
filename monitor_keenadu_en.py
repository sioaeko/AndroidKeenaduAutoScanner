import argparse
import json
import re
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

ADB_PATH = "adb"


@dataclass
class Detection:
    severity: str
    title: str
    details: str


@dataclass
class Check:
    name: str
    executed: bool
    detected: bool
    details: str
    findings: List[Detection] = field(default_factory=list)


@dataclass
class Device:
    serial: str
    state: str


@dataclass
class Opt:
    reboot_for_logcat: bool
    logcat_seconds: int
    post_boot_snapshots: int
    snapshot_interval: int
    verbose: bool
    command_log_file: Optional[Path]


def now_iso() -> str:
    return datetime.now().isoformat(timespec="seconds")


def run_adb(args: List[str], serial: Optional[str], logs: List[Dict], verbose: bool, allow_fail: bool = False) -> Tuple[bool, str, str]:
    cmd = [ADB_PATH] + (["-s", serial] if serial else []) + args
    p = subprocess.run(cmd, capture_output=True, text=True)
    out, err = p.stdout or "", p.stderr or ""
    logs.append({"time": now_iso(), "serial": serial, "cmd": cmd, "rc": p.returncode, "stdout": out, "stderr": err})
    if verbose:
        print(f"[verbose] {' '.join(cmd)} rc={p.returncode}")
        if out.strip():
            print(f"[verbose] stdout:\n{out[:1200]}")
        if err.strip():
            print(f"[verbose] stderr:\n{err[:1200]}")
    if p.returncode != 0 and not allow_fail:
        return False, out, err
    return p.returncode == 0, out, err


def run_shell(serial: str, cmd: str, logs: List[Dict], verbose: bool, allow_fail: bool = False) -> Tuple[bool, str, str]:
    return run_adb(["shell", cmd], serial, logs, verbose, allow_fail)


def load_iocs(path: Path) -> Dict:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def list_devices(logs: List[Dict], verbose: bool) -> List[Device]:
    ok, out, _ = run_adb(["devices"], None, logs, verbose)
    if not ok:
        return []
    items = []
    for line in out.splitlines()[1:]:
        cols = line.split()
        if len(cols) >= 2:
            items.append(Device(cols[0], cols[1]))
    return items


def parse_md5(text: str) -> Optional[str]:
    for line in text.splitlines():
        m = re.match(r"^([a-fA-F0-9]{32})\b", line.strip())
        if m:
            return m.group(1).lower()
    return None


def contains_any(text: str, markers: List[str]) -> List[str]:
    t = text.lower()
    return [m for m in markers if m.lower() in t]


def get_installed(serial: str, logs: List[Dict], verbose: bool) -> Tuple[bool, Set[str], str]:
    ok, out, err = run_shell(serial, "pm list packages", logs, verbose)
    if not ok:
        return False, set(), err.strip() or "pm list packages failed"
    pkgs = {x.replace("package:", "").strip() for x in out.splitlines() if x.strip().startswith("package:")}
    return True, pkgs, "package list collected"


def check_ak_cpp(serial: str, iocs: Dict, opt: Opt, logs: List[Dict]) -> Check:
    tag = iocs.get("debug_log_tag", "AK_CPP")
    if opt.reboot_for_logcat:
        run_adb(["logcat", "-c"], serial, logs, opt.verbose, allow_fail=True)
        ok, _, err = run_adb(["reboot"], serial, logs, opt.verbose)
        if not ok:
            return Check("AK_CPP logcat check", False, False, f"reboot failed: {err.strip()}")
        ok, _, err = run_adb(["wait-for-device"], serial, logs, opt.verbose)
        if not ok:
            return Check("AK_CPP logcat check", False, False, f"wait-for-device failed: {err.strip()}")
        time.sleep(max(1, opt.logcat_seconds))
    ok, out, err = run_adb(["logcat", "-d"], serial, logs, opt.verbose)
    if not ok:
        return Check("AK_CPP logcat check", False, False, f"logcat failed: {err.strip()}")
    hits = [l.strip() for l in out.splitlines() if tag.lower() in l.lower()]
    if not hits:
        return Check("AK_CPP logcat check", True, False, f"no '{tag}' match")
    return Check("AK_CPP logcat check", True, True, f"{len(hits)} line(s) matched", [Detection("high", "Keenadu debug log tag detected", hits[0][:220])])


def check_text_cmd(serial: str, name: str, shell_cmd: str, markers: List[str], logs: List[Dict], verbose: bool, severity: str = "high") -> Check:
    ok, out, err = run_shell(serial, shell_cmd, logs, verbose)
    if not ok:
        return Check(name, False, False, err.strip() or "command failed")
    hits = contains_any(out, markers)
    if not hits:
        return Check(name, True, False, "no marker matched")
    return Check(name, True, True, f"matched {sorted(set(hits))}", [Detection(severity, f"{name} marker detected", str(sorted(set(hits))))])


def check_loader(serial: str, iocs: Dict, logs: List[Dict], verbose: bool) -> Check:
    findings: List[Detection] = []
    executed = False
    for p in iocs.get("suspicious_file_paths", []):
        ok, out, _ = run_shell(serial, f"if [ -e '{p}' ]; then echo FOUND; else echo MISSING; fi", logs, verbose, allow_fail=True)
        executed = executed or ok
        if ok and "FOUND" in out:
            findings.append(Detection("high", "Known Keenadu loader artifact found", p))
    ok, out, _ = run_shell(serial, "for d in /storage/emulated/0/Android/data/*/files/.dx; do [ -d \"$d\" ] && echo $d; done", logs, verbose, allow_fail=True)
    executed = executed or ok
    hits = [x.strip() for x in out.splitlines() if x.strip()] if ok else []
    if hits:
        findings.append(Detection("high", "Encrypted payload staging directory found", str(hits[:5])))
    if not executed:
        return Check("Loader artifact (vndx_10x/.dx) check", False, False, "artifact check not executed")
    return Check("Loader artifact (vndx_10x/.dx) check", True, bool(findings), f"{len(findings)} finding(s)" if findings else "no marker matched", findings)


def check_hashes(serial: str, iocs: Dict, installed: Set[str], logs: List[Dict], verbose: bool) -> List[Check]:
    checks: List[Check] = []
    bad_lib = {x.lower() for x in iocs.get("ioc_hashes", {}).get("libandroid_runtime_md5", [])}
    lib_find: List[Detection] = []
    executed = False
    for p in ["/system/lib64/libandroid_runtime.so", "/system/lib/libandroid_runtime.so"]:
        ok, out, _ = run_shell(serial, f"if [ -r '{p}' ]; then md5sum '{p}'; else echo NOREAD; fi", logs, verbose, allow_fail=True)
        executed = executed or ok
        md5 = parse_md5(out) if ok else None
        if md5 and md5 in bad_lib:
            lib_find.append(Detection("high", "Compromised Android runtime library hash match", f"{p} {md5}"))
    checks.append(Check("libandroid_runtime.so MD5 check", executed, bool(lib_find), "matched bad hash" if lib_find else ("no hash match" if executed else "not executed"), lib_find))

    bad_app = {x.lower() for x in iocs.get("ioc_hashes", {}).get("infected_system_app_md5", [])}
    app_find: List[Detection] = []
    executed = False
    for pkg in iocs.get("infected_sample_packages", []):
        if pkg not in installed:
            continue
        ok, out, _ = run_shell(serial, f"pm path {pkg}", logs, verbose, allow_fail=True)
        executed = executed or ok
        for line in out.splitlines():
            if not line.startswith("package:"):
                continue
            apk = line.replace("package:", "").strip()
            ok_h, out_h, _ = run_shell(serial, f"if [ -r '{apk}' ]; then md5sum '{apk}'; else echo NOREAD; fi", logs, verbose, allow_fail=True)
            executed = executed or ok_h
            md5 = parse_md5(out_h) if ok_h else None
            if md5 and md5 in bad_app:
                app_find.append(Detection("high", "Known infected system app hash matched", f"{pkg} {apk} {md5}"))
    checks.append(Check("Infected sample APK MD5 check", executed, bool(app_find), "matched bad hash" if app_find else ("no hash match" if executed else "not executed"), app_find))
    return checks


def check_static_strings(serial: str, iocs: Dict, logs: List[Dict], verbose: bool) -> Check:
    markers = iocs.get("libandroid_runtime_string_markers", [])
    if not markers:
        return Check("libandroid_runtime.so static string check", False, False, "marker list missing")
    rgx = "|".join(re.escape(x) for x in markers)
    findings: List[Detection] = []
    executed = False
    for p in ["/system/lib64/libandroid_runtime.so", "/system/lib/libandroid_runtime.so"]:
        cmd = f"if [ -r '{p}' ]; then grep -a -E -o '{rgx}' '{p}' 2>/dev/null | sort -u | head -n 20; else echo NOREAD; fi"
        ok, out, _ = run_shell(serial, cmd, logs, verbose, allow_fail=True)
        executed = executed or ok
        hits = [x.strip() for x in out.splitlines() if x.strip() and x.strip() != "NOREAD"] if ok else []
        if hits:
            findings.append(Detection("high", "Suspicious string marker in libandroid_runtime.so", f"{p}: {hits[:10]}"))
    return Check("libandroid_runtime.so static string check", executed, bool(findings), "matched marker" if findings else ("no marker matched" if executed else "not executed"), findings)


def check_boot_snapshots(serial: str, iocs: Dict, opt: Opt, logs: List[Dict]) -> Check:
    markers = iocs.get("protected_broadcast_markers", []) + iocs.get("badbox_binder_markers", []) + iocs.get("suspicious_process_markers", []) + iocs.get("suspicious_shell_command_markers", [])
    findings: List[Detection] = []
    executed = False
    for i in range(max(1, opt.post_boot_snapshots)):
        ok1, o1, _ = run_shell(serial, "ps -A", logs, opt.verbose, allow_fail=True)
        ok2, o2, _ = run_shell(serial, "service list", logs, opt.verbose, allow_fail=True)
        ok3, o3, _ = run_shell(serial, "dumpsys activity broadcasts", logs, opt.verbose, allow_fail=True)
        executed = executed or ok1 or ok2 or ok3
        hits = contains_any("\n".join([o1, o2, o3]), markers)
        if hits:
            findings.append(Detection("high", "Intermittent marker detected in post-boot snapshot", f"snapshot {i+1}: {sorted(set(hits))}"))
        if i < max(1, opt.post_boot_snapshots) - 1:
            time.sleep(max(1, opt.snapshot_interval))
    return Check("Post-boot repeated snapshot check", executed, bool(findings), "marker observed" if findings else ("no marker matched" if executed else "not executed"), findings)


def check_network(serial: str, iocs: Dict, logs: List[Dict], verbose: bool) -> Check:
    domains = iocs.get("c2_endpoints", [])
    if not domains:
        return Check("Network IOC check", False, False, "domain list missing")
    findings: List[Detection] = []
    executed = False
    for name, runner in [("logcat", lambda: run_adb(["logcat", "-d"], serial, logs, verbose, allow_fail=True)), ("connectivity", lambda: run_shell(serial, "dumpsys connectivity", logs, verbose, allow_fail=True))]:
        ok, out, _ = runner()
        executed = executed or ok
        hits = contains_any(out, domains) if ok else []
        if hits:
            sev = "high" if name == "logcat" else "medium"
            findings.append(Detection(sev, f"C2 marker observed in {name}", str(sorted(set(hits)))))
    return Check("Network IOC check", executed, bool(findings), "C2 marker observed" if findings else ("no marker matched" if executed else "not executed"), findings)


def check_build(serial: str, iocs: Dict, logs: List[Dict], verbose: bool) -> Check:
    props = ["ro.build.fingerprint", "ro.build.version.incremental", "ro.product.manufacturer", "ro.product.model", "ro.build.version.security_patch"]
    vals: Dict[str, str] = {}
    for p in props:
        ok, out, err = run_shell(serial, f"getprop {p}", logs, verbose, allow_fail=True)
        if not ok:
            return Check("OTA/build lineage check", False, False, f"getprop failed: {p} {err.strip()}")
        vals[p] = out.strip()
    findings: List[Detection] = []
    hits = contains_any("\n".join(vals.values()), iocs.get("suspicious_build_markers", []))
    if hits:
        findings.append(Detection("medium", "Suspicious build marker observed", str(hits)))
    allow = set(iocs.get("known_good_fingerprints", []))
    fp = vals.get("ro.build.fingerprint", "")
    if allow and fp and fp not in allow:
        findings.append(Detection("medium", "Build fingerprint not in allowlist", fp))
    return Check("OTA/build lineage check", True, bool(findings), "anomaly detected" if findings else "no anomaly", findings)


def check_focus_components(serial: str, iocs: Dict, installed: Set[str], logs: List[Dict], verbose: bool) -> Check:
    focus = [p for p in iocs.get("focus_component_packages", []) if p in installed]
    if not iocs.get("focus_component_packages", []):
        return Check("Focus component check", False, False, "focus list missing")
    if not focus:
        return Check("Focus component check", True, False, "focus package not installed")
    markers = iocs.get("focus_permission_markers", []) + iocs.get("focus_service_markers", [])
    findings: List[Detection] = []
    for pkg in focus:
        ok, out, err = run_shell(serial, f"dumpsys package {pkg}", logs, verbose, allow_fail=True)
        if not ok:
            findings.append(Detection("low", "Focus package inspection incomplete", f"{pkg}: {err.strip()}"))
            continue
        hits = contains_any(out, markers)
        if hits:
            findings.append(Detection("medium", "Suspicious marker in focus package", f"{pkg}: {sorted(set(hits))}"))
    det = any(f.severity in {"medium", "high"} for f in findings)
    return Check("Focus component check", True, det, "marker found" if det else "no suspicious marker", findings)


def check_system_integrity(serial: str, iocs: Dict, installed: Set[str], logs: List[Dict], verbose: bool) -> Check:
    ok, out, err = run_shell(serial, "pm list packages -s -f", logs, verbose, allow_fail=True)
    if not ok:
        return Check("System app integrity check", False, False, err.strip() or "pm list packages -s -f failed")
    path_by_pkg: Dict[str, str] = {}
    for line in out.splitlines():
        if line.startswith("package:") and "=" in line:
            p, pkg = line.replace("package:", "", 1).split("=", 1)
            path_by_pkg[pkg.strip()] = p.strip()
    focus = set(iocs.get("focus_component_packages", [])) | set(iocs.get("infected_sample_packages", []))
    baseline = iocs.get("known_good_system_apk_md5", {})
    findings: List[Detection] = []
    for pkg in sorted(focus):
        if pkg not in installed or pkg not in path_by_pkg:
            continue
        apk = path_by_pkg[pkg]
        if not apk.startswith(("/system/", "/product/", "/vendor/", "/system_ext/", "/odm/")):
            findings.append(Detection("high", "System focus package path anomaly", f"{pkg}: {apk}"))
        ok_h, out_h, _ = run_shell(serial, f"if [ -r '{apk}' ]; then md5sum '{apk}'; else echo NOREAD; fi", logs, verbose, allow_fail=True)
        md5 = parse_md5(out_h) if ok_h else None
        exp = baseline.get(pkg)
        if exp and md5 and md5.lower() != exp.lower():
            findings.append(Detection("medium", "System package hash mismatch", f"{pkg}: expected={exp.lower()} actual={md5}"))
    det = any(f.severity in {"medium", "high"} for f in findings)
    return Check("System app integrity check", True, det, "anomaly found" if det else "no anomaly", findings)


def check_side_loading(serial: str, logs: List[Dict], verbose: bool) -> Check:
    ok, out, err = run_shell(serial, "settings get secure install_non_market_apps", logs, verbose, allow_fail=True)
    if not ok:
        return Check("Sideloading setting check", False, False, err.strip() or "settings read failed")
    if out.strip() == "1":
        return Check("Sideloading setting check", True, True, "enabled", [Detection("low", "Side-loading enabled", "install_non_market_apps=1")])
    return Check("Sideloading setting check", True, False, "disabled or unknown")


def scan(serial: str, iocs: Dict, opt: Opt, logs: List[Dict]) -> Tuple[List[Check], List[Detection]]:
    checks: List[Check] = []
    findings: List[Detection] = []
    ok, installed, msg = get_installed(serial, logs, opt.verbose)
    if not ok:
        checks.append(Check("Package list collection", False, False, msg))
        return checks, findings
    checks.append(Check("Package list collection", True, False, msg))

    checks.extend([
        check_ak_cpp(serial, iocs, opt, logs),
        check_text_cmd(serial, "Protected Broadcast check", "dumpsys activity broadcasts", iocs.get("protected_broadcast_markers", []), logs, opt.verbose, "high"),
        check_text_cmd(serial, "BADBOX Binder check", "service list", iocs.get("badbox_binder_markers", []), logs, opt.verbose, "high"),
        Check("Infected sample package check", True, any(p in installed for p in iocs.get("infected_sample_packages", [])), "matched sample package" if any(p in installed for p in iocs.get("infected_sample_packages", [])) else "no sample package"),
        check_text_cmd(serial, "Process/command marker check", "ps -A", iocs.get("suspicious_process_markers", []) + iocs.get("suspicious_shell_command_markers", []), logs, opt.verbose, "medium"),
        check_loader(serial, iocs, logs, opt.verbose),
    ])
    checks.extend(check_hashes(serial, iocs, installed, logs, opt.verbose))
    checks.extend([
        check_static_strings(serial, iocs, logs, opt.verbose),
        check_system_integrity(serial, iocs, installed, logs, opt.verbose),
        check_boot_snapshots(serial, iocs, opt, logs),
        check_network(serial, iocs, logs, opt.verbose),
        check_build(serial, iocs, logs, opt.verbose),
        check_focus_components(serial, iocs, installed, logs, opt.verbose),
        check_side_loading(serial, logs, opt.verbose),
    ])
    for c in checks:
        findings.extend(c.findings)
    return checks, findings


def print_report(serial: str, checks: List[Check], findings: List[Detection]) -> None:
    print(f"\n=== Scan report for {serial} @ {now_iso()} ===")
    print("[Check Summary]")
    for c in checks:
        if not c.executed:
            print(f"- [NOT_EXECUTED] {c.name} :: {c.details}")
        else:
            print(f"- [EXECUTED][{'DETECTED' if c.detected else 'NOT DETECTED'}] {c.name} :: {c.details}")
    print("\n[Findings]")
    if not findings:
        print("- No Keenadu IOC match found in current checks.")
    else:
        for i, f in enumerate(findings, 1):
            print(f"{i}. [{f.severity.upper()}] {f.title}")
            print(f"   - {f.details}")


def save_logs(logs: List[Dict], base: Path) -> Path:
    base.parent.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out = base.with_name(f"{base.stem}_{ts}{base.suffix or '.json'}")
    with out.open("w", encoding="utf-8") as f:
        json.dump(logs, f, ensure_ascii=False, indent=2)
    return out


def monitor(ioc_file: Path, interval: float, opt: Opt) -> None:
    iocs = load_iocs(ioc_file)
    known: Set[str] = set()
    print("Watching for Android devices. Press Ctrl+C to stop.")
    while True:
        logs: List[Dict] = []
        scanned_this_loop = False
        try:
            devices = list_devices(logs, opt.verbose)
            ready = {d.serial for d in devices if d.state == "device"}
            for d in [x for x in devices if x.state in {"unauthorized", "offline"}]:
                print(f"[i] Device not ready: {d.serial} ({d.state})")
                print("    -> Please unlock the device and allow USB debugging when connected.")
            for s in sorted(ready - known):
                print(f"\n[+] New device connected: {s}")
                print("    -> Please unlock the device and allow USB debugging when connected.")
                scanned_this_loop = True
                checks, findings = scan(s, iocs, opt, logs)
                print_report(s, checks, findings)
            for s in sorted(known - ready):
                print(f"[-] Device disconnected: {s}")
            if opt.command_log_file and scanned_this_loop and logs:
                out = save_logs(logs, opt.command_log_file)
                if opt.verbose:
                    print(f"[verbose] command logs saved: {out}")
            known = ready
            time.sleep(interval)
        except KeyboardInterrupt:
            if opt.command_log_file and scanned_this_loop and logs:
                print(f"[i] command logs saved: {save_logs(logs, opt.command_log_file)}")
            print("\nStopped by user.")
            return
        except Exception as e:
            print(f"[!] Error: {e}", file=sys.stderr)
            if opt.command_log_file and logs:
                save_logs(logs, opt.command_log_file)
            time.sleep(interval)


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Monitor connected Android devices and scan for Keenadu IOC matches.")
    p.add_argument("--ioc-file", type=Path, default=Path("keenadu_iocs.json"))
    p.add_argument("--interval", type=float, default=3.0)
    p.add_argument("--reboot-for-logcat", action="store_true")
    p.add_argument("--logcat-seconds", type=int, default=20)
    p.add_argument("--post-boot-snapshots", type=int, default=3)
    p.add_argument("--snapshot-interval", type=int, default=15)
    p.add_argument("--verbose", action="store_true", help="Print detailed per-command logs")
    p.add_argument("--command-log-file", type=Path, default=None, help="Save full command stdout/stderr to JSON")
    return p.parse_args()


def main() -> int:
    a = parse_args()
    if not a.ioc_file.exists():
        print(f"IOC file not found: {a.ioc_file}", file=sys.stderr)
        return 1
    opt = Opt(a.reboot_for_logcat, a.logcat_seconds, a.post_boot_snapshots, a.snapshot_interval, a.verbose, a.command_log_file)
    monitor(a.ioc_file, a.interval, opt)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
