# paths.py - Privilege Reachability
# Which account can reach Domain Admin, through which permission,
# what its impact is, and how to close it.
# Run: python3 paths.py   (collector.py must have been run first)
import json
import re
from collections import deque

RESET_GUID    = "00299570-246d-11d0-a768-00aa006e0529"  # password reset right
GETCHANGES    = "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"  # replication right 1
GETCHANGESALL = "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"  # replication right 2
MEMBER_GUID   = "bf9679c0-0de6-11d0-a285-00aa003049e2"  # group 'member' attribute
ENROLL_GUID   = "0e10c968-78fb-11d2-90d4-00c04f79dc55"  # certificate enrollment
CLIENT_AUTH   = "1.3.6.1.5.5.7.3.2"
ANY_PURPOSE   = "2.5.29.37.0"

CONTROL_ACCESS = 0x100
WRITE_PROP     = 0x20
GENERIC_ALL    = 0x10000000
GENERIC_WRITE  = 0x40000000
WRITE_DACL     = 0x00040000
WRITE_OWNER    = 0x00080000
DANGER = GENERIC_ALL | GENERIC_WRITE | WRITE_DACL | WRITE_OWNER

DOMAIN     = "DOMAIN"      # special node: the entire domain
EVERYONE   = "S-1-1-0"
AUTH_USERS = "S-1-5-11"


def rid(sid):
    try:
        return int(str(sid).rsplit("-", 1)[1])
    except Exception:
        return -1


def find_reachability(d, extra_targets=None, path_limit=10):
    users  = {u["dn"]: u for u in d.get("users", [])  if u.get("dn")}
    groups = {g["dn"]: g for g in d.get("groups", []) if g.get("dn")}
    comps  = {c["dn"]: c for c in d.get("computers", []) if c.get("dn")}

    name_of = {}
    sid_of  = {}
    for store in (users, groups, comps):
        for dn, o in store.items():
            name_of[dn] = o.get("name", dn)
            if o.get("sid"):
                sid_of[o["sid"]] = dn
    name_of[DOMAIN]     = "the domain (Domain Admin level)"
    name_of[EVERYONE]   = "Everyone"
    name_of[AUTH_USERS] = "Authenticated Users"

    def label(node):
        return name_of.get(node, node)

    # Targets: Domain / Enterprise / Schema Admins + DOMAIN node, plus
    # BUILTIN\Administrators (S-1-5-32-544). On a Domain Controller the
    # Administrators group holds full local control of the DC itself, so
    # reaching it is Tier Zero in practice; the S-1-5-32 prefix check
    # matters - a domain group can share RID 544 without being the
    # built-in group. Note: Administrators is a target for pathfinding,
    # but its members are NOT "already privileged" (see the closure
    # below) - a member is not a Domain Admin, it reaches Tier Zero
    # through the DC, so it must still get paths.
    targets = {dn for dn, g in groups.items() if rid(g.get("sid")) in (512, 518, 519)}
    targets |= {dn for dn, g in groups.items()
                if str(g.get("sid", "")).startswith("S-1-5-32-") and rid(g.get("sid")) == 544}
    targets.add(DOMAIN)
    tier0_targets = set(targets)
    if extra_targets:
        # BloodHound-style widened run: privileged groups count as targets
        # too, so paths that end at an admin group are reported, not hidden.
        targets |= set(extra_targets)

    # Trusted trustees: their rights are not a risk (admins themselves, SYSTEM, DCs)
    legit = {"S-1-5-18", "S-1-3-0", "S-1-5-10", "S-1-5-9", "S-1-5-32-544"}
    for dn, g in groups.items():
        if rid(g.get("sid")) in (512, 518, 519, 516, 544) and g.get("sid"):
            legit.add(g["sid"])
    for dn, c in comps.items():
        if c.get("uac", 0) & 0x2000 and c.get("sid"):   # Domain Controllers
            legit.add(c["sid"])

    edges = {}   # node -> list of (next_node, kind, text, risk, fix)
    def add(a, b, kind, text, risk, fix):
        if a == b:
            return
        lst = edges.setdefault(a, [])
        if (b, kind) not in [(x[0], x[1]) for x in lst]:
            lst.append((b, kind, text, risk, fix))

    def trustee_node(sid):
        if sid in legit:
            return None
        if sid in (EVERYONE, AUTH_USERS):
            return sid
        return sid_of.get(sid)

    # --- 1) Membership ---
    for dn, u in users.items():
        for gdn in u.get("member_of", []):
            if gdn in groups:
                add(dn, gdn, "MemberOf",
                    f"{u['name']} is a member of {groups[gdn]['name']}",
                    "Membership gives this account every right of that group.",
                    "Remove the account from this group if the access is not required.")
        for gdn, g in groups.items():
            if rid(g.get("sid")) == 513:   # Domain Users (primary group)
                add(dn, gdn, "MemberOf",
                    f"{u['name']} is a member of {g['name']} (default for every account)",
                    "Membership gives this account every right of that group.",
                    "Review any extra rights given to this group - they reach every account.")
        add(dn, EVERYONE, "MemberOf",
            f"{u['name']} is part of Everyone",
            "Rights given to Everyone apply to this account too.",
            "Avoid giving extra rights to Everyone.")
        add(dn, AUTH_USERS, "MemberOf",
            f"{u['name']} is an Authenticated User",
            "Rights given to Authenticated Users apply to every logged-in account.",
            "Avoid giving extra rights to Authenticated Users.")
    for gdn, g in groups.items():
        for mdn in g.get("members", []):
            if mdn in groups:
                add(mdn, gdn, "MemberOf",
                    f"Group {groups[mdn]['name']} is a member of {g['name']}",
                    "Members of the nested group inherit every right of this group.",
                    "Remove the nested group if that inheritance is not intended.")
            if mdn in users:
                add(mdn, gdn, "MemberOf",
                    f"{users[mdn]['name']} is a member of {g['name']}",
                    "Membership gives this account every right of that group.",
                    "Remove the account from this group if the access is not required.")

    # --- 2) Control rights on user objects ---
    for uname, aces in d.get("user_acls", {}).items():
        tdn = next((dn for dn, u in users.items() if u["name"] == uname), None)
        if not tdn:
            continue
        for ace in aces:
            a = trustee_node(ace.get("sid"))
            if not a:
                continue
            mask = ace.get("mask", 0)
            ots  = ace.get("object_types", [])
            if (mask & CONTROL_ACCESS and RESET_GUID in ots) or (mask & GENERIC_ALL):
                add(a, tdn, "ResetPassword",
                    f"{label(a)} can reset the password of {uname}",
                    "This right lets the holder set a new password for that account without knowing the old one - in practice, control of the account.",
                    "Remove this access entry from the account's security settings unless an approved helpdesk process needs it.")
            elif mask & DANGER:
                add(a, tdn, "FullControl",
                    f"{label(a)} has full control over the account {uname}",
                    "Full control means the holder can change the account's settings and take control of it.",
                    "Remove this access entry, or reduce it to the minimum the holder actually needs.")

    # --- 3) Control rights on group objects ---
    for gname, aces in d.get("group_acls", {}).items():
        tdn = next((dn for dn, g in groups.items() if g["name"] == gname), None)
        if not tdn:
            continue
        for ace in aces:
            a = trustee_node(ace.get("sid"))
            if not a:
                continue
            mask = ace.get("mask", 0)
            ots  = ace.get("object_types", [])
            if (mask & DANGER) or (mask & WRITE_PROP and MEMBER_GUID in ots):
                add(a, tdn, "ChangeMembers",
                    f"{label(a)} can change the members of group {gname}",
                    "Whoever can edit this group's membership can give its rights to any account.",
                    "Remove this access entry - group membership should only be managed by the admin team.")

    # --- 4) Replication rights (on the domain) ---
    rights = {}
    for ace in d.get("domain_acl", []):
        if ace.get("flags", 0) & 0x08:   # INHERIT_ONLY: flows to child objects, grants nothing on the root itself
            continue
        sid  = ace.get("sid")
        mask = ace.get("mask", 0)
        if mask & GENERIC_ALL:
            rights.setdefault(sid, set()).update([GETCHANGES, GETCHANGESALL])
        elif mask & CONTROL_ACCESS:
            for g in ace.get("object_types", []):
                if g in (GETCHANGES, GETCHANGESALL):
                    rights.setdefault(sid, set()).add(g)
    for sid, got in rights.items():
        if got == {GETCHANGES, GETCHANGESALL}:
            a = trustee_node(sid)
            if a:
                add(a, DOMAIN, "Replication",
                    f"{label(a)} holds domain replication rights",
                    "Replication rights are meant for Domain Controllers copying the directory. In other hands they expose the password data of every account in the domain.",
                    "Remove replication rights from this account - only Domain Controller computer accounts need them.")

    # --- 5) GPO edit rights + link scope ---
    link_strings = []
    dom = d.get("domain", {})
    for k in ("gplink", "gpLink", "gPLink"):
        if dom.get(k):
            link_strings.append(("the domain root", dom[k]))
    for ou in d.get("ous", []):
        for k in ("gplink", "gpLink", "gPLink"):
            if ou.get(k):
                link_strings.append((f"the '{ou.get('name', 'OU')}' OU", ou[k]))

    def gpo_scope(gpo_dn):
        m = re.search(r"\{[0-9A-Fa-f\-]+\}", gpo_dn or "")
        if not m:
            return None
        guid = m.group(0).lower()
        for scope, s in link_strings:
            if guid in s.lower():
                return scope
        return None

    gpo_by_name = {g["name"]: g for g in d.get("gpos", [])}
    for gname, aces in d.get("gpo_acls", {}).items():
        g = gpo_by_name.get(gname)
        if not g:
            continue
        scope = gpo_scope(g.get("dn"))
        if not scope:
            continue
        for ace in aces:
            a = trustee_node(ace.get("sid"))
            if not a:
                continue
            if ace.get("mask", 0) & DANGER:
                add(a, DOMAIN, "GPOEdit",
                    f"{label(a)} can edit the GPO '{gname}' (linked at {scope})",
                    "This GPO's settings apply at that scope. If it is linked at the domain root or the Domain Controllers OU, a harmful change reaches the Domain Controllers themselves.",
                    "Limit who can edit this GPO to the admin team only.")

    # --- 6) AD CS: enrollment on a published ESC1 template ---
    published = set()
    for ca in d.get("cas", []):
        published.update(ca.get("published", []))
    tmpl_by_name = {t["name"]: t for t in d.get("cert_templates", [])}
    for tname, aces in d.get("template_acls", {}).items():
        t = tmpl_by_name.get(tname)
        if not t or tname not in published:
            continue
        ekus = t.get("eku") or []
        esc1 = (t.get("name_flag", 0) & 1) and (CLIENT_AUTH in ekus) and not t.get("ra_signature")
        esc2 = (t.get("name_flag", 0) & 1) and (not ekus or ANY_PURPOSE in ekus) and not t.get("ra_signature")
        if esc1:
            kind = "ESC1"
            text = f"can enroll in the certificate template '{tname}' (ESC1 configuration)"
            risk = ("This template lets the person enrolling ask for a certificate in another identity's name. "
                    "Such a certificate can then be used to sign in as that identity - including an administrator.")
        elif esc2:
            kind = "ESC2"
            text = f"can enroll in the certificate template '{tname}' (ESC2 configuration)"
            risk = ("This template can issue a certificate for any purpose (or has no EKU restriction) and lets the person "
                    "enrolling supply the subject name - so it can mint a certificate in an administrator's name.")
        else:
            continue
        fix = "Restrict enrollment on this template to approved groups, or turn off 'supply subject name' / require manager approval."
        for ace in aces:
            a = trustee_node(ace.get("sid"))
            if not a:
                continue
            mask = ace.get("mask", 0)
            if (mask & CONTROL_ACCESS and ENROLL_GUID in ace.get("object_types", [])) or (mask & GENERIC_ALL):
                add(a, DOMAIN, kind,
                    f"{label(a)} {text}",
                    risk,
                    fix)

    # --- 7) SID history: an old privileged identity still carried by the account ---
    for dn, u in users.items():
        for hsid in u.get("sid_history", []) or []:
            tgt = sid_of.get(hsid)
            if tgt and tgt != dn:
                add(dn, tgt, "SIDHistory",
                    f"{u['name']} carries a historical SID of {label(tgt)} in its SID history",
                    "SID history makes the account be treated as if it still held that old identity's access - including group memberships and rights left over from a migration.",
                    "Clear the sIDHistory attribute once the migration is finished, or remove the access it grants.")

    # --- 8) Write control over the domain root or AdminSDHolder ---
    # INHERIT_ONLY ACEs are skipped in both loops: such an entry grants its
    # holder nothing on the root/AdminSDHolder object itself - the right
    # only flows down to child objects, where the per-object ACL sections
    # above model it. Counting it here minted one-step "FullControl ->
    # Domain Admin" edges for trustees (e.g. Protected Users, Replicator)
    # whose real power is over child objects, not the domain root.
    for ace in d.get("domain_acl", []):
        if ace.get("flags", 0) & 0x08:
            continue
        mask = ace.get("mask", 0)
        if mask & (GENERIC_WRITE | WRITE_DACL | WRITE_OWNER):
            a = trustee_node(ace.get("sid"))
            if a:
                add(a, DOMAIN, "FullControl",
                    f"{label(a)} has write control over the domain root object",
                    "Write control over the domain root lets the holder change the domain's own security settings and seize further control from there.",
                    "Remove this access entry from the domain root - only the admin team should hold rights there.")
    for ace in d.get("adminsdholder_acl", []):
        if ace.get("flags", 0) & 0x08:
            continue
        mask = ace.get("mask", 0)
        if mask & DANGER:
            a = trustee_node(ace.get("sid"))
            if a:
                add(a, DOMAIN, "FullControl",
                    f"{label(a)} has control rights on AdminSDHolder",
                    "AdminSDHolder is the template whose permissions are copied onto every protected admin account and group. Controlling it means controlling them all within an hour.",
                    "Remove this access entry from AdminSDHolder - only SYSTEM and the admin team should hold rights there.")

    # --- 9) Delegation to a Domain Controller, and DCs themselves ---
    comp_by_name = {}
    for dn, c in comps.items():
        _nm = str(c.get("name", "")).lower()
        comp_by_name.setdefault(_nm, dn)
        comp_by_name.setdefault(_nm.rstrip("$"), dn)
        # SPNs name the host without the trailing $ (cifs/DC01), and a
        # collected computer name may carry it (DC01$) - register every
        # spelling or delegation edges silently never match. This miss hid
        # svc.scanner's delegation path to DC01 on ctf.local (2026-11-09).
        comp_by_name.setdefault(dn.split(",", 1)[0].split("=", 1)[-1].lower(), dn)

    def spn_host(spn):
        try:
            h = str(spn).split("/", 1)[1]
            return h.split(".")[0].split(":")[0].lower()
        except Exception:
            return ""

    for store in (users, comps):
        for dn, o in store.items():
            for spn in o.get("delegate_to", []) or []:
                hdn = comp_by_name.get(spn_host(spn))
                if hdn and hdn != dn and comps[hdn].get("uac", 0) & 0x2000:
                    add(dn, hdn, "Delegation",
                        f"{label(dn)} is trusted for delegation to '{spn}' on {comps[hdn]['name']} (a Domain Controller)",
                        "Delegation to a Domain Controller lets this account request service tickets impersonating other users - including administrators - for that DC's services.",
                        "Remove the delegation entry (msDS-AllowedToDelegateTo) unless a documented service needs it; never delegate to a Domain Controller.")
    for dn, c in comps.items():
        if c.get("uac", 0) & 0x2000:
            add(dn, DOMAIN, "DCControl",
                f"{c['name']} is a Domain Controller",
                "Domain Controllers hold a full copy of the directory, including every account's password data. Control of a DC is control of the domain.",
                "This is expected - Domain Controllers are Tier Zero by design and must be protected like the domain itself.")

    # --- 10) Built-in operator groups: inherent privileges no ACL records ---
    # Backup Operators hold SeBackupPrivilege on every DC: a backup of a DC
    # includes the directory database and the SYSTEM hive - the domain's
    # credential material. Server Operators can log on to DCs and control
    # services there. Neither right appears in any collected ACL, so without
    # these edges a member's chain wrongly dead-ends at the group (found on
    # ctf.local, 2026-11-09: svc.mssql in Backup Operators, zero ACL entries).
    # Built-in SIDs, verified against Microsoft's list: 551 Backup
    # Operators, 549 Server Operators, 550 Print Operators. (555 is
    # Remote Desktop Users - NOT an operator group; an earlier version of
    # this table keyed 555 and was corrected on 2026-11-09.)
    OPERATOR_EDGES = {
        551: ("BackupPrivilege",
              "Members of {g} can back up {dc} (SeBackupPrivilege), including the directory database and the SYSTEM hive.",
              "A backup of a Domain Controller contains every account's password data - Backup Operators are Tier Zero in practice, even though no ACL says so.",
              "Keep only accounts that actively perform backups in Backup Operators; treat its members as Domain Admin equivalents and monitor the group."),
        549: ("ServiceControl",
              "Members of {g} can log on to {dc} and start or stop services on it.",
              "Controlling services on a Domain Controller can be turned into code execution on the DC, and control of a DC is control of the domain.",
              "Keep only accounts that actively administer DC services in Server Operators; treat its members as Tier Zero."),
        550: ("PrintOperator",
              "Members of {g} can log on to {dc} and manage printers and printer drivers on it.",
              "Loading a printer driver on a Domain Controller is a known route to code execution on the DC, and control of a DC is control of the domain.",
              "Keep Print Operators empty unless a documented print role needs it; treat its members as Tier Zero."),
    }
    _dc_dns = [dn for dn, c in comps.items() if c.get("uac", 0) & 0x2000]
    for gdn, g in groups.items():
        # Built-in operator groups live in the S-1-5-32 namespace; a domain
        # group can share the RID number (a domain Remote Desktop Users is
        # also -555) and must NOT inherit these edges.
        _spec = OPERATOR_EDGES.get(rid(g.get("sid"))) if str(g.get("sid", "")).startswith("S-1-5-32-") else None
        if not _spec:
            continue
        _kind, _t_tpl, _risk, _fix = _spec
        for _dcdn in _dc_dns:
            add(gdn, _dcdn, _kind,
                _t_tpl.format(g=g["name"], dc=comps[_dcdn]["name"]),
                _risk, _fix)

    # --- 11) Local admin rights (AdminTo), when the data carries them ---
    # SharpHound collects LocalAdmins per computer; Cerberus's own collector
    # does not (yet), so this fires only when a computer dict has the field.
    for dn, c in comps.items():
        for sid in c.get("local_admins", []) or []:
            src = sid_of.get(sid)
            if src and src != dn:
                add(src, dn, "AdminTo",
                    f"{label(src)} is a local administrator on {c['name']}",
                    "Local admin means full control of that machine and of any credentials in its memory. On a Domain Controller it is control of the domain itself.",
                    "Remove local admin rights that are not needed; prefer LAPS-managed per-machine passwords and tiered admin workstations.")

    # --- 12) Live sessions and RDP access (when the data carries them) ---
    # A session means the account's credentials are present on that
    # machine; RDP membership means interactive logon. Chained the
    # BloodHound way: principal -CanRDP-> machine -HasSession-> user.
    for dn, c in comps.items():
        for sid in c.get("sessions", []) or []:
            usr = sid_of.get(sid)
            if usr and usr != dn:
                add(dn, usr, "HasSession",
                    f"{label(usr)} has a session on {c['name']}",
                    "A live session leaves the account's credentials in this machine's memory. Whoever controls the machine must be treated as able to act as the session's owner.",
                    "Treat any machine where a privileged account has a session as Tier Zero itself; use dedicated admin workstations so privileged sessions never land on ordinary machines.")
        for sid in c.get("rdp_users", []) or []:
            src = sid_of.get(sid)
            if src and src != dn:
                add(src, dn, "CanRDP",
                    f"{label(src)} can log on to {c['name']} over Remote Desktop",
                    "RDP logon alone does not hand over the machine, but it puts the account one step from everything on it - including other users' live sessions.",
                    "Remove Remote Desktop access that is not needed; never grant broad groups RDP access to servers.")

    # --- Already privileged: reaches a target through membership alone ---
    # Administrators (S-1-5-32-544) is deliberately NOT a seed here, even
    # though it is a target above: its membership is a ROUTE to Tier Zero
    # (members control the DC), not Tier Zero identity itself. Seeding
    # from it classified its members as "already privileged", which skips
    # them in the loop below - so they got no paths at all, the exact
    # opposite of the fix (found on thm.corp BloodHound data, 2026-11-14:
    # MICHEL_ROBINSON / CHRISTINA_MCCORMICK / TREVOR_MELTON lost every
    # path, including their AdminTo routes). Direct Domain / Enterprise /
    # Schema Admins members stay "already" - they ARE Tier Zero.
    admin544_dns = {dn for dn, g in groups.items()
                    if str(g.get("sid", "")).startswith("S-1-5-32-") and rid(g.get("sid")) == 544}
    rev_member = {}
    for a, lst in edges.items():
        for (b, kind, _t, _r, _f) in lst:
            if kind == "MemberOf":
                rev_member.setdefault(b, []).append(a)
    member_only = set(targets) - admin544_dns
    dq = deque(member_only)
    while dq:
        n = dq.popleft()
        for a in rev_member.get(n, []):
            if a not in member_only:
                member_only.add(a)
                dq.append(a)
    privileged_users = {dn for dn in users if dn in member_only}

    # --- Reverse BFS: distance from every node to a target ---
    radj = {}
    for a, lst in edges.items():
        for (b, kind, t, r, f) in lst:
            radj.setdefault(b, []).append((a, kind, t, r, f))
    dist = {t: 0 for t in targets}
    dq = deque(targets)
    while dq:
        n = dq.popleft()
        for (a, kind, t, r, f) in radj.get(n, []):
            if a not in dist:
                dist[a] = dist[n] + 1
                dq.append(a)

    def build_paths(start, limit=10):
        # Enumerate the distinct routes from start to a target, shortest first.
        # Routes may be up to 2 steps longer than the shortest one; a hard
        # expansion budget keeps dense graphs from exploding.
        if start not in dist:
            return []
        # Slack of 3 (was 2): with several target classes, the nearest
        # target can shadow a longer route to a stronger one.
        max_depth = dist[start] + 3
        found = []
        budget = [20000]

        def dfs(node, acc, seen):
            if len(found) >= limit or budget[0] <= 0:
                return
            budget[0] -= 1
            if node in targets:
                found.append(list(acc))
                if node in tier0_targets:
                    return
                # Privileged-group target: the path is recorded, but keep
                # walking - the same route may continue on to Tier Zero.
            if len(acc) >= max_depth:
                return
            for (b, kind, t, r, f) in sorted(edges.get(node, []), key=lambda x: dist.get(x[0], 10 ** 9)):
                if b in seen:
                    continue
                if dist.get(b, 10 ** 9) + len(acc) + 1 > max_depth:
                    continue
                acc.append((label(node), kind, label(b), t, r, f))
                seen.add(b)
                dfs(b, acc, seen)
                seen.discard(b)
                acc.pop()
                if len(found) >= limit:
                    return

        dfs(start, [], {start})
        found.sort(key=len)
        uniq = []
        for p in found:
            if p not in uniq:
                uniq.append(p)
        return uniq[:limit]

    already = []
    reaching = []
    all_paths = {}
    for dn, u in users.items():
        if not u.get("enabled", True):
            continue
        if dn in privileged_users:
            already.append(u["name"])
            continue
        paths = build_paths(dn, limit=path_limit)
        if paths:
            reaching.append((u["name"], paths[0]))
            all_paths[u["name"]] = paths
    return already, reaching, all_paths


def privileged_group_dns(d):
    """Groups that count as BloodHound-style high-value targets beyond
    Tier Zero. A group qualifies when ANY of these holds:
    - it is a built-in operator/admin group (S-1-5-32-548/549/550/
      551 - the S-1-5-32 prefix matters: a domain group can share the
      RID; 555 is Remote Desktop Users and is deliberately excluded;
      544 Administrators is Tier Zero now, not a widened target);
    - it is a local administrator on at least one computer (the practical
      definition of an admin group - this is what marks Tier 1/2 Admins);
    - it is Group Policy Creator Owners (domain RID 520 - its members
      can create GPOs, a recognised privilege-escalation foothold);
    - its name marks it as an admin group and it has enabled members.
    (An earlier rule - "holds an adminCount=1 account" - was dropped: on
    real data it marked Remote Desktop Users privileged just because one
    protected account sat in it, hiding every longer real path.)
    """
    users_by_dn = {u.get("dn"): u for u in d.get("users", []) if u.get("dn")}
    local_admin_sids = set()
    for c in d.get("computers", []) or []:
        local_admin_sids.update(c.get("local_admins", []) or [])
    out = set()
    for g in d.get("groups", []):
        if not g.get("dn"):
            continue
        sid = str(g.get("sid", ""))
        if rid(sid) in (512, 518, 519):
            continue  # already Tier Zero
        if sid.startswith("S-1-5-32-") and rid(sid) in (548, 549, 550, 551):
            out.add(g["dn"])
            continue
        if sid and sid in local_admin_sids:
            out.add(g["dn"])
            continue
        if rid(sid) == 520:
            out.add(g["dn"])
            continue
        members = g.get("members", []) or []
        enabled_members = [users_by_dn[m] for m in members
                           if m in users_by_dn and users_by_dn[m].get("enabled", True)]
        if "admin" in str(g.get("name", "")).lower() and (enabled_members or members):
            out.add(g["dn"])
    return out


def find_all_reachability(d, path_limit=10):
    """BloodHound-style widened reachability: Tier Zero paths PLUS paths
    ending at a privileged group. Returns (already, reaching, all_paths)
    in the same shape as find_reachability; a path's final step names its
    target, so callers can tell a Domain Admin path from a group path.
    Tier Zero results always win per account; group-ending paths from the
    widened run are merged in for everyone else (and as extra routes for
    accounts that have both). path_limit caps the routes kept per account
    (default 10, the report behaviour; the dashboard package builder asks
    for more so the graph can show the full fan-out of parallel routes)."""
    already0, reaching0, paths0 = find_reachability(d, path_limit=path_limit)
    pg = privileged_group_dns(d)
    if not pg:
        return already0, reaching0, paths0
    already_w, _r, paths_w = find_reachability(d, extra_targets=pg, path_limit=path_limit)
    merged = {name: list(ps) for name, ps in paths0.items()}
    for name, ps in paths_w.items():
        extra = [p for p in ps if p not in merged.get(name, [])]
        if extra:
            merged.setdefault(name, []).extend(extra)
            merged[name].sort(key=len)
            merged[name] = merged[name][:path_limit]
    already = list(already0)
    for n in already_w:
        if n not in already:
            already.append(n)
    reaching = [(name, ps[0]) for name, ps in merged.items()]
    return already, reaching, merged


if __name__ == "__main__":
    with open("collected.json") as f:
        data = json.load(f)
    already, reaching, all_paths = find_reachability(data)

    print("=== ALREADY PRIVILEGED (direct Domain Admin level) ===")
    print(f"Count: {len(already)}")
    for n in already:
        print(" -", n)

    print()
    print(f"=== ACCOUNTS THAT CAN REACH DOMAIN ADMIN: {len(reaching)} ===")
    for i, (name, steps) in enumerate(reaching, 1):
        paths = all_paths.get(name, [steps])
        print(f"\nAccount {i}: {name} - {len(paths)} path(s)")
        for pi, path in enumerate(paths, 1):
            print(f"  Path {pi}:")
            for j, (frm, kind, to, text, risk, fix) in enumerate(path, 1):
                print(f"    Step {j}: {text}.")
                print(f"            Risk: {risk}")
                print(f"            Fix:  {fix}")
        print("  Result: this account can reach Domain Admin level - treat it as a critical exposure.")
