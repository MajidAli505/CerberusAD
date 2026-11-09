#!/usr/bin/env python3
"""
Cerberus Collector - one entry point for the whole scan.

What it does, in order:
  1. Collects Active Directory data from a domain controller
     (collector.py - LDAP, plus per-machine RPC when impacket is present).
  2. Runs the full 165-check analysis locally (checks.py + paths.py).
  3. Builds ONE small scan package file (CerberusScan-<domain>-<date>.json)
     that the Cerberus web dashboard imports via Clients -> Add Scan.

Privacy by design: the raw collected.json never leaves this machine.
Only the findings summary (the scan package) is uploaded to the dashboard.
The local report.html and remediation.ps1 are also kept next to the package.

Usage:
  CerberusCollector.exe --dc 192.168.1.10 --user "DOMAIN\\user"
  python cerberus.py --dc dc01.domain.local --user "DOMAIN\\user" --password ****
  python cerberus.py --from-collected collected.json     (repackage an old run)

Options:
  --dc              Domain controller IP or hostname (required unless
                    --from-collected is used)
  --user            Domain user, e.g. DOMAIN\\user (any ordinary domain user)
  --password        Asked securely at a prompt when not given
  --skip-remote     Skip per-machine RPC collection (local admins, RDP
                    users, sessions) - faster, slightly fewer attack paths
  --from-collected  Skip collection; build the package from an existing
                    collected.json
  --out             Folder for the scan package (default: current folder)
"""

import argparse
import getpass
import importlib.util
import json
import os
import runpy
import shutil
import sys
import tempfile
from datetime import date

SEVERITY_SCORE = {"Critical": 10, "High": 5, "Medium": 2, "Low": 1}
ITEM_CAP = 50          # evidence items kept per finding in the package
MAX_GROUP_REACHERS = 40  # cap for accounts that only reach privileged groups
MAX_PATHS_PER_ACCOUNT = 5


def bundle_dir():
    """Folder holding collector.py / checks.py / paths.py (exe or source)."""
    if getattr(sys, "frozen", False):
        return sys._MEIPASS
    return os.path.dirname(os.path.abspath(__file__))


def run_script(path, argv, cwd):
    """Run a sibling script as __main__ with its own argv, inside cwd."""
    old_argv, old_cwd = sys.argv, os.getcwd()
    sys.argv = argv
    os.chdir(cwd)
    try:
        runpy.run_path(path, run_name="__main__")
    finally:
        sys.argv = old_argv
        os.chdir(old_cwd)


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def path_to_str(path):
    out = path[0][0]
    for (_frm, kind, to, *_rest) in path:
        out += " -[" + kind + "]-> " + ("Domain Admin" if to.startswith("the domain") else to)
    return out


def build_package(collected, findings, paths_mod):
    """Assemble the dashboard scan package from local results."""
    domain_name = collected.get("domain", {}).get("name") or collected.get("domain", {}).get("dns") or ""
    if not domain_name:
        base = collected.get("domain", {}).get("base_dn", "")
        domain_name = ".".join(p.replace("DC=", "") for p in base.split(",") if p.strip().upper().startswith("DC="))

    score = sum(SEVERITY_SCORE.get(f.get("severity"), 0)
                for f in findings if f.get("status") == "FAIL")

    capped = []
    for f in findings:
        entry = dict(f)
        items = f.get("items") or []
        if len(items) > ITEM_CAP:
            items = items[:ITEM_CAP] + ["... and " + str(len(items) - ITEM_CAP) + " more in the full findings file"]
        entry["items"] = items
        capped.append(entry)

    _already, tier0_reaching, _ap = paths_mod.find_reachability(collected)
    _a2, _r2, all_paths = paths_mod.find_all_reachability(collected)

    # Display names of the privileged groups (a path that passes through one
    # of them also counts as a path ENDING there - BloodHound-style).
    group_names = set()
    try:
        priv_dns = paths_mod.privileged_group_dns(collected)
        dn2name = {(g.get("dn") or ""): g.get("name") for g in collected.get("groups", [])}
        group_names = {dn2name.get(dn) for dn in priv_dns}
        group_names.discard(None)
    except Exception:
        group_names = set()

    def with_group_prefixes(ps):
        out = list(ps)
        for p in ps:
            for i, step in enumerate(p):
                if step[2] in group_names and i < len(p) - 1:
                    out.append(p[:i + 1])
        return out

    def covered(ps):
        """Shortest path per distinct final target, then shortest extras."""
        by_target = {}
        for p in ps:
            by_target.setdefault(p[-1][2], []).append(p)
        chosen = [min(v, key=len) for v in by_target.values()]
        rest = sorted((p for p in ps if p not in chosen), key=len)
        return sorted((chosen + rest)[:MAX_PATHS_PER_ACCOUNT], key=len)

    pkg_paths = {}
    da_names = {n for (n, _s) in tier0_reaching}
    for name in sorted(da_names):
        pkg_paths[name] = [path_to_str(p) for p in covered(with_group_prefixes(all_paths.get(name, [])))]
    group_only = sorted(n for n in all_paths if n not in da_names)
    for name in group_only[:MAX_GROUP_REACHERS]:
        pkg_paths[name] = [path_to_str(p) for p in covered(with_group_prefixes(all_paths[name]))]
    if len(group_only) > MAX_GROUP_REACHERS:
        print("Note: " + str(len(group_only)) + " accounts reach a privileged group; the package "
              "lists the first " + str(MAX_GROUP_REACHERS) + " plus every account that reaches "
              "Domain Admin. The full list is in the local report.")

    return {"domain": domain_name, "date": date.today().isoformat(),
            "risk_score": score, "findings": capped, "paths": pkg_paths}


def main():
    ap = argparse.ArgumentParser(description="Cerberus Collector - scan a domain, build the dashboard package")
    ap.add_argument("--dc")
    ap.add_argument("--user")
    ap.add_argument("--password")
    ap.add_argument("--skip-remote", action="store_true")
    ap.add_argument("--from-collected")
    ap.add_argument("--out", default=".")
    args = ap.parse_args()

    here = bundle_dir()
    for needed in ("collector.py", "checks.py", "paths.py"):
        if not os.path.exists(os.path.join(here, needed)):
            print("ERROR: " + needed + " is missing next to this program.")
            return 1

    work = tempfile.mkdtemp(prefix="cerberus-")
    try:
        # ---- Step 1: collect -------------------------------------------------
        if args.from_collected:
            shutil.copyfile(args.from_collected, os.path.join(work, "collected.json"))
            print("Step 1/3: using existing collection " + args.from_collected)
        else:
            if not args.dc or not args.user:
                print("ERROR: --dc and --user are required (or use --from-collected).")
                return 1
            password = vars(args)["password"] or getpass.getpass("Password for " + args.user + ": ")
            argv = ["collector.py", "--dc", args.dc, "--user", args.user, "--password", password]
            if args.skip_remote:
                argv.append("--skip-remote")
            print("Step 1/3: collecting from " + args.dc + " ...")
            run_script(os.path.join(here, "collector.py"), argv, work)

        # ---- Step 2: analyse -------------------------------------------------
        print("Step 2/3: running the 165 checks ...")
        sys.path.insert(0, here)
        run_script(os.path.join(here, "checks.py"), ["checks.py"], work)

        # ---- Step 3: package -------------------------------------------------
        print("Step 3/3: building the dashboard scan package ...")
        with open(os.path.join(work, "collected.json")) as fh:
            collected = json.load(fh)
        with open(os.path.join(work, "findings.json")) as fh:
            findings = json.load(fh)
        paths_mod = load_module("cerberus_paths", os.path.join(here, "paths.py"))
        package = build_package(collected, findings, paths_mod)

        out_dir = os.path.abspath(args.out)
        os.makedirs(out_dir, exist_ok=True)
        safe_domain = package["domain"].replace("/", "_") or "domain"
        pkg_file = os.path.join(out_dir, "CerberusScan-" + safe_domain + "-" + package["date"] + ".json")
        with open(pkg_file, "w") as fh:
            json.dump(package, fh, indent=1)
        for extra in ("report.html", "remediation.ps1"):
            src = os.path.join(work, extra)
            if os.path.exists(src):
                shutil.copyfile(src, os.path.join(out_dir, extra))

        fails = sum(1 for f in findings if f["status"] == "FAIL")
        print("")
        print("Done. " + str(len(findings)) + " checks, " + str(fails) + " FAIL, risk score "
              + str(package["risk_score"]) + ", attack paths for " + str(len(package["paths"])) + " accounts.")
        print("Scan package: " + pkg_file)
        print("Upload it in the Cerberus dashboard: Clients -> Add Scan.")
        print("collected.json stayed on this machine (it was processed in a temp folder and removed).")
        return 0
    finally:
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
