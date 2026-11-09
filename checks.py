import json
from datetime import datetime, timezone

with open("collected.json") as f:
    data = json.load(f)

users     = data["users"]
groups    = data["groups"]
domain    = data["domain"]
computers = data["computers"]
ous       = data.get("ous", [])
gpos      = data.get("gpos", [])
trusts    = data.get("trusts", [])
cert_templates = data.get("cert_templates", [])
cas            = data.get("cas", [])
psos = data.get("psos", [])



# ---------- small helpers ----------
def group_by_name(d, name):
    for g in d["groups"]:
        if g["name"].lower() == name.lower():
            return g
    return None

def group_member_names(d, name):
    g = group_by_name(d, name)
    if not g:
        return []
    return [dn_to_name(m) for m in g.get("members", [])]


def dn_to_name(dn):
    # "CN=USER1,CN=Users,DC=domain,DC=local"  ->  "USER1"
    return dn.split(",")[0].replace("CN=", "")

def group_by_rid(rid):
    for g in groups:
        if g["sid"].endswith("-" + str(rid)):
            return g
    return None

def days_ago(date_str):
    if date_str in (None, "None"):
        return None
    dt = datetime.fromisoformat(date_str)
    return (datetime.now(timezone.utc) - dt).days

def is_priv(u):
    return u["admin_count"] == 1

group_dns = {g["dn"] for g in groups if g.get("dn")}

def members_of_rid(rid):
    g = group_by_rid(rid)
    return g["members"] if g else []

def list_group(rid):
    return [dn_to_name(m) for m in members_of_rid(rid)]

def replication_trustees(d):
    # Collect each trustee's replication rights from the domain root ACL
    rights = {}
    for ace in d.get("domain_acl", []):
        s = rights.setdefault(ace["sid"], set())
        if ace["mask"] & 0x10000000:   # GENERIC_ALL — all rights, including replication
            s.update([REPL_GET_CHANGES, REPL_GET_CHANGES_ALL])
        for g in ace.get("object_types", []):
            if g in (REPL_GET_CHANGES, REPL_GET_CHANGES_ALL):
                s.add(g)
    return rights



# ---------- CHECKS ----------
def reg_val(entry, key):
    # A [Registry Values] line in GptTmpl.inf looks like "4,1" — the last part is the actual value
    v = entry.get("sec", {}).get("registry values", {}).get(key)
    return v.split(",")[-1].strip() if v else None

def check_gpo_rights_bad(d):
    allowed = legit_acl_sids(d) | {"S-1-5-19", "S-1-5-20",
                               "S-1-5-32-548", "S-1-5-32-549",
                               "S-1-5-32-550", "S-1-5-32-551"}
    names = name_by_sid(d)
    risky = ("seimpersonateprivilege", "sedebugprivilege", "sebackupprivilege",
             "setakeownershipprivilege", "seassignprimarytokenprivilege")
    out = []
    for gpo_name, e in d.get("gpo_content", {}).items():
        for right, val in e.get("sec", {}).get("privilege rights", {}).items():
            if right in risky:
                for who in val.split(","):
                    sid = who.strip().lstrip("*")
                    if sid and sid not in allowed:
                        out.append(f"{gpo_name} {right}: {names.get(sid, sid)}")
    return out

def check_defender_gpo(d):
    out = []
    for gpo_name, e in d.get("gpo_content", {}).items():
        for k, v in e.get("registry", {}).items():
            if "windows defender" in k and k.endswith("|disableantispyware") and v == 1:
                out.append(gpo_name)
            if "real-time protection" in k and k.endswith("|disablerealtimemonitoring") and v == 1:
                out.append(gpo_name)
    return out


def check_transitive_da(d):
    by_dn = {g["dn"]: g for g in d["groups"]}
    users_found, groups_seen = set(), set()
    def expand(g):
        if not g or g["dn"] in groups_seen:
            return
        groups_seen.add(g["dn"])
        for m in g.get("members", []):
            if m in by_dn:
                expand(by_dn[m])
            else:
                users_found.add(dn_to_name(m))
    expand(group_by_rid(512))
    return [f"Total Domain Admins (including nested groups): {len(users_found)}"] + sorted(users_found)

def check_empty_ous(d):
    all_dns = ([u["dn"] for u in d["users"]] + [g["dn"] for g in d["groups"]]
               + [c["dn"] for c in d["computers"]] + [o["dn"] for o in d.get("ous", [])])
    return [o["name"] for o in d.get("ous", [])
            if o.get("dn") and not any(x != o["dn"] and x.endswith(o["dn"]) for x in all_dns)]

def check_disabled_links(d):
    links = []
    if d.get("domain", {}).get("gp_link"):
        links.append(d["domain"]["gp_link"])
    for o in d.get("ous", []):
        if o.get("gplink"):
            links.append(o["gplink"])
    out = []
    for link in links:
        for part in link.strip("[]").split("]["):
            if ";" in part and part.rsplit(";", 1)[1] in ("1", "3"):
                out.append(gpo_name_by_guid(d, gpo_guid(part)))
    return out


DANGER = 0x10000000 | 0x00040000 | 0x00080000   # GenericAll | WriteDacl | WriteOwner
RESET_PWD_GUID = "00299570-246d-11d0-a768-00aa006e0529"

def acl_findings(d, acls, masks=DANGER, guid=None):
    names = name_by_sid(d)
    legit = legit_acl_sids(d)
    out = []
    for obj_name, acl in acls.items():
        for ace in acl:
            if ace["sid"] in legit:
                continue
            if (ace["mask"] & masks) or (guid and guid in ace.get("object_types", [])):
                out.append(f"{obj_name}: {names.get(ace['sid'], ace['sid'])}")
    return list(dict.fromkeys(out))

def check_partial_repl(d):
    names = name_by_sid(d)
    legit = legit_acl_sids(d)
    out = []
    for sid, r in replication_trustees(d).items():
        if REPL_GET_CHANGES in r and REPL_GET_CHANGES_ALL not in r and sid not in legit:
            out.append(names.get(sid, sid))
    return out

FL_NAMES = {0: "2000", 2: "2003", 3: "2008", 4: "2008 R2", 5: "2012", 6: "2012 R2", 7: "2016"}

def check_print_on_dc(d):
    dc_names = [c["name"].replace("$", "").lower() for c in d["computers"] if c["is_dc"]]
    return [f"{q['name']} ({q['server']})" for q in d.get("print_queues", [])
            if any(dc in q["server"].lower() for dc in dc_names)]


def weak_enc(items):
    # enc_types: 0x3 = DES, 0x4 = RC4, 0x8 = AES128, 0x10 = AES256.
    # If only DES/RC4 is allowed (the AES bits are absent), the encryption is weak.
    out = []
    for x in items:
        v = x.get("enc_types")
        if v is not None and int(v) != 0 and (int(v) & 0x18) == 0:
            out.append(x["name"])
    return out

def check_desc_password(d):
    words = ("pass", "pwd", "cred")
    return [u["name"] for u in d["users"]
            if any(w in (u.get("description") or "").lower() for w in words)]

def check_gpo_rights(d):
    names = name_by_sid(d)
    legit = legit_acl_sids(d)
    out = []
    for gpo_name, acl in d.get("gpo_acls", {}).items():
        for ace in acl:
            if ace["mask"] & (0x10000000 | 0x00040000 | 0x00080000) and ace["sid"] not in legit:
                out.append(f"{gpo_name}: {names.get(ace['sid'], ace['sid'])}")
    return out

def check_orphan_acl(d):
    names = name_by_sid(d)
    return [sid for sid in {a["sid"] for a in d.get("domain_acl", [])}
            if sid not in names and "-21-" in sid]


def gpo_name_by_guid(d, guid):
    for g in d.get("gpos", []):
        if gpo_guid(g.get("dn", "")) == guid or guid in (g.get("dn") or ""):
            return g["name"]
    return guid


def check_krbtgt_enabled(d):
    return [u["name"] for u in d["users"]
            if u["name"].lower() == "krbtgt" and u["enabled"]]

def check_pwd_365(d):
    out = []
    for u in d["users"]:
        days = days_ago(u["pwd_set"])
        if u["enabled"] and days is not None and days > 365:
            out.append(f"{u['name']} ({days} days old)")
    return out

def check_sidhistory_priv(d):
    return [u["name"] for u in d["users"]
            if is_priv(u) and u.get("sid_history")]

def check_not_protected_users(d):
    # Domain Admins members who are not in the 'Protected Users' group —
    # Membership in Protected Users prevents delegation and provides protection from NTLM
    pu = group_by_name(d, "Protected Users")
    pu_dn = pu["dn"] if pu else None
    da = group_by_rid(512)
    by_dn = {u["dn"]: u for u in d["users"]}
    out = []
    for m_dn in (da.get("members", []) if da else []):
        u = by_dn.get(m_dn)
        if u and pu_dn not in u.get("member_of", []):
            out.append(u["name"])
    return out

def check_disabled_priv(d):
    return [u["name"] for u in d["users"]
            if (u.get("admin_count") or 0) == 1 and not u["enabled"]
            and u["name"].lower() != "krbtgt"]

def check_admin500(d):
    return [f"{u['name']} (enabled: {u['enabled']})" for u in d["users"]
            if (u.get("sid") or "").endswith("-500")]

def check_orphan_members(d):
    known = ({u["dn"] for u in d["users"]} | {g["dn"] for g in d["groups"]}
             | {c["dn"] for c in d["computers"]})
    return [f"{g['name']}: {dn_to_name(m)}" for g in d["groups"]
            for m in g.get("members", []) if m not in known
            and not dn_to_name(m).startswith("S-1-")]

def check_os_summary(d):
    counts = {}
    for c in d["computers"]:
        os_name = c.get("os") or "unknown"
        counts[os_name] = counts.get(os_name, 0) + 1
    return [f"{k}: {v}" for k, v in counts.items()]

def check_upn_mismatch(d):
    return [u["name"] for u in d["users"]
            if u.get("upn") and u["upn"].split("@")[0].lower() != u["name"].lower()]

def check_latent_clientauth(d):
    pub = published_names(d)
    return [t["name"] for t in d.get("cert_templates", [])
            if t["name"] not in pub
            and "1.3.6.1.5.5.7.3.2" in t.get("eku", [])]

def check_enforced_links(d):
    # A gPLink ends in ;0, ;1, ;2, or ;3 — 2 or 3 means the link is ENFORCED
    links = []
    if d.get("domain", {}).get("gplink"):
        links.append(d["domain"]["gplink"])
    for o in d.get("ous", []):
        if o.get("gplink"):
            links.append(o["gplink"])
    out = []
    for link in links:
        for part in link.strip("[]").split("]["):
            if ";" in part:
                opts = part.rsplit(";", 1)[1]
                if opts in ("2", "3"):
                    out.append(gpo_name_by_guid(d, gpo_guid(part)))
    return out

REPL_GET_CHANGES     = "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"
REPL_GET_CHANGES_ALL = "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"

def name_by_sid(d):
    m = {}
    for u in d["users"]:
        if u.get("sid"):
            m[u["sid"]] = u["name"]
    for g in d["groups"]:
        if g.get("sid"):
            m[g["sid"]] = g["name"]
    for c in d["computers"]:
        if c.get("sid"):
            m[c["sid"]] = c["name"]
    return m

def legit_acl_sids(d):
    # Principals that are supposed to have rights on the domain root by DESIGN — do not treat them as findings
    legit = {"S-1-5-18", "S-1-3-0"}   # SYSTEM
    for g in d["groups"]:
        if g["name"] in ("Domain Controllers", "Enterprise Domain Controllers",
                         "Domain Admins", "Enterprise Admins", "Administrators"):
            legit.add(g["sid"])
    for c in d["computers"]:
        if c["is_dc"] and c.get("sid"):
            legit.add(c["sid"])
    return legit

def check_dcsync(d):
    names = name_by_sid(d)
    legit = legit_acl_sids(d)
    rights = {}
    for ace in d.get("domain_acl", []):
        s = rights.setdefault(ace["sid"], set())
        if ace["mask"] & 0x10000000:   # GENERIC_ALL — everything, including replication
            s.update([REPL_GET_CHANGES, REPL_GET_CHANGES_ALL])
        for g in ace.get("object_types", []):
            if g in (REPL_GET_CHANGES, REPL_GET_CHANGES_ALL):
                s.add(g)
    return [names.get(sid, sid) for sid, r in rights.items()
            if REPL_GET_CHANGES in r and REPL_GET_CHANGES_ALL in r
            and sid not in legit]

def dangerous_trustees(d, acl_key):
    names = name_by_sid(d)
    legit = legit_acl_sids(d)
    bad, seen = [], set()
    for ace in d.get(acl_key, []):
        if ace["mask"] & (0x10000000 | 0x00040000 | 0x00080000):  # GenericAll | WriteDacl | WriteOwner
            if ace["sid"] not in legit and ace["sid"] not in seen:
                seen.add(ace["sid"])
                bad.append(names.get(ace["sid"], ace["sid"]))
    return bad

def check_laps(d):
    if d.get("laps_schema"):
        return []
    return ["No sign of LAPS — local admin passwords are not managed"]


def check_fsmo_single(d):
    srvs = {s for s in d.get("fsmo", {}).values() if s}
    if len(srvs) == 1 and len(d.get("fsmo", {})) >= 2:
        return [f"All FSMO roles are on a single DC: {list(srvs)[0]}"]
    return []

def check_recycle_bin(d):
    if d.get("recycle_bin_enabled"):
        return []
    return ["AD Recycle Bin is not enabled — recovering a deleted object will be very difficult"]

def check_tombstone(d):
    t = d.get("tombstone_days")
    if t is not None and t < 180:
        return [f"Tombstone lifetime is only {t} days (it should be 180)"]
    return []

def check_dc_outside_ou(d):
    return [c["name"] for c in d["computers"]
            if c["is_dc"] and c.get("dn") and "OU=Domain Controllers" not in c["dn"]]

def check_asrep_never_expires(d):
    return [u["name"] for u in d["users"]
            if u["enabled"] and (u["uac"] & 0x400000) and (u["uac"] & 0x10000)]


def check_spn_on_privileged(d):
    return [u["name"] for u in d["users"]
            if u["enabled"] and is_priv(u) and len(u["spns"]) > 0
            and u["name"].lower() != "krbtgt"]


def check_duplicate_spns(d):
    # The same SPN on two accounts breaks Kerberos, and this often happens by mistake
    seen = {}
    for u in d["users"]:
        for s in u["spns"]:
            seen.setdefault(s.lower(), []).append(u["name"])
    return [f"{spn} -> {', '.join(names)}" for spn, names in seen.items() if len(names) > 1]

def check_sid_history(d):
    # sIDHistory = carrying an identity from an old domain — a migration necessity or a hidden doorway
    return [u["name"] for u in d["users"] if len(u.get("sid_history", [])) > 0]

def check_multiple_spns(d):
    return [f'{u["name"]} ({len(u["spns"])} SPNs)' for u in d["users"] if len(u["spns"]) > 1]

def check_nested_in_any_priv(d):
    bad = []
    for rid in PRIV_RIDS:
        g = group_by_rid(rid)
        if not g:
            continue
        for m in g["members"]:
            if m in group_dns:
                bad.append(f'{g["name"]} contains nested group: {dn_to_name(m)}')
    return bad

def check_empty_priv_groups(d):
    bad = []
    for rid in PRIV_RIDS:
        g = group_by_rid(rid)
        if g and len(g["members"]) == 0:
            bad.append(g["name"])
    return bad

def check_users_without_upn(d):
    return [u["name"] for u in d["users"] if not u.get("upn")]

def check_duplicate_upns(d):
    seen = {}
    for u in d["users"]:
        if u.get("upn"):
            seen.setdefault(u["upn"].lower(), []).append(u["name"])
    return [f"{upn} -> {', '.join(names)}" for upn, names in seen.items() if len(names) > 1]

def check_local_upn_suffix(d):
    # A UPN with a .local suffix cannot sync to the cloud — an obstacle when preparing for hybrid identity
    return [f'{u["name"]} ({u["upn"]})' for u in d["users"]
            if u.get("upn") and u["upn"].lower().endswith(".local")]

def gpo_guid(g):
    dn = g.get("dn") or ""
    s, e = dn.find("{"), dn.find("}") + 1
    return dn[s:e].lower() if s >= 0 and e > 0 else ""

def gpos_in_link(d, link_str):
    link_str = (link_str or "").lower()
    return [g["name"] for g in d.get("gpos", []) if gpo_guid(g) and gpo_guid(g) in link_str]

def check_gpo_on_dc_ou(d):
    for o in d.get("ous", []):
        if o["name"] == "Domain Controllers":
            return gpos_in_link(d, o.get("gp_link"))
    return []

def check_latent_esc1(d):
    pub = published_names(d)
    return [t["name"] for t in d.get("cert_templates", [])
            if t["name"] not in pub and (t["name_flag"] & 1)
            and t["ra_signature"] == 0 and has_client_auth(t)]


def published_names(d):
    names = set()
    for ca in d.get("cas", []):
        names.update(ca["published"])
    return names

def check_esc1_published(d):
    # True ESC1: dangerous flags AND published on a CA — this needs immediate attention
    pub = published_names(d)
    return [t["name"] for t in d.get("cert_templates", [])
            if t["name"] in pub and (t["name_flag"] & 1)
            and t["ra_signature"] == 0 and has_client_auth(t)]

def check_esc9(d):
    # ESC9: the template strips the certificate security extension
    # (CT_FLAG_NO_SECURITY_EXTENSION, 0x80000000 in msPKI-Enrollment-Flag),
    # which weakens certificate binding on accounts that use the certificate.
    pub = published_names(d)
    return [t["name"] for t in d.get("cert_templates", [])
            if t["name"] in pub and has_client_auth(t) and (t.get("enroll_flag", 0) & 0x80000000)]

def check_esc15(d):
    # ESC15 (EKUwu): a schema version 1 template where the enrollee supplies
    # the subject - on v1 templates the enrollee can also influence the
    # application policies, which modern templates do not allow.
    pub = published_names(d)
    return [t["name"] for t in d.get("cert_templates", [])
            if t["name"] in pub and t.get("schema_version") == 1 and (t["name_flag"] & 1)]

def check_esc13(d):
    # ESC13: a published client-auth template whose issuance policy is linked
    # to a Tier-Zero group. Only an exact OID + group match fails this check;
    # a policy that cannot be resolved to a group never fails it.
    pub = published_names(d)
    groups_by_dn = {g.get("dn"): g for g in d.get("groups", [])}
    links = {}
    for o in d.get("oid_links", []):
        g = groups_by_dn.get(o.get("group_dn", ""))
        if g and (g.get("sid") or "").rsplit("-", 1)[-1] in ("512", "518", "519"):
            links[o.get("oid", "")] = g.get("name", "")
    bad = []
    for t in d.get("cert_templates", []):
        if t["name"] in pub and has_client_auth(t):
            for pol in t.get("cert_policies", []):
                if pol in links:
                    bad.append(t["name"] + " (issuance policy linked to " + links[pol] + ")")
                    break
    return bad

def check_esc14(d):
    # ESC14: explicit certificate mappings (altSecurityIdentities) sitting on
    # a privileged account or a Domain Controller - a stale or weak mapping
    # there is a logon path that bypasses the account's password.
    bad = [u["name"] + " (user)" for u in d.get("users", []) if is_priv(u) and u.get("alt_sec_identities")]
    bad += [c["name"] + " (DC computer)" for c in d.get("computers", []) if c.get("is_dc") and c.get("alt_sec_identities")]
    return bad

def check_published_no_approval(d):
    pub = published_names(d)
    return [t["name"] for t in d.get("cert_templates", [])
            if t["name"] in pub and not (t["enroll_flag"] & 0x2)
            and t["ra_signature"] == 0 and has_client_auth(t)]

def check_ca_on_dc(d):
    # A CA installed on a DC — two critical roles on the same machine
    dc_names = {c["name"].replace("$", "").lower() for c in d["computers"] if c["is_dc"]}
    bad = []
    for ca in d.get("cas", []):
        host = (ca.get("host") or "").split(".")[0].lower()
        if host in dc_names:
            bad.append(f'{ca["name"]} is installed on DC ({ca["host"]})')
    return bad

def check_msol_accounts(d):
    return [u["name"] for u in d["users"] if u["name"].lower().startswith("msol_")]

def check_sso_account(d):
    return [c["name"] for c in d["computers"]
            if c["name"].lower().startswith("azureadssoacc")]

def check_synced_privileged(d):
    # A privileged account linked to the cloud — an on-premises compromise also compromises the cloud
    return [u["name"] for u in d["users"] if is_priv(u) and u.get("synced")]

def check_weak_pso(d):
    return [f'{p["name"]} (min length {p["min_length"]})'
            for p in d.get("psos", []) if 0 < p["min_length"] < 14]


PRIV_RIDS = (512, 519, 518, 551, 549, 548, 550)

CLIENT_AUTH  = "1.3.6.1.5.5.7.3.2"
ANY_PURPOSE  = "2.5.29.37.0"
ENROLL_AGENT = "1.3.6.1.4.1.311.20.2.1"

def has_client_auth(t):
    return CLIENT_AUTH in t["eku"] or ANY_PURPOSE in t["eku"] or len(t["eku"]) == 0

def check_esc1(d):
    # Lets the requester supply any name + no approval/signature + a logon purpose
    # = anyone can obtain a certificate by claiming to be Administrator
    return [t["name"] for t in d.get("cert_templates", [])
            if (t["name_flag"] & 1) and t["ra_signature"] == 0 and has_client_auth(t)]

def check_esc2(d):
    return [t["name"] for t in d.get("cert_templates", [])
            if ANY_PURPOSE in t["eku"] or len(t["eku"]) == 0]

def check_esc3(d):
    return [t["name"] for t in d.get("cert_templates", [])
            if ENROLL_AGENT in t["eku"]]

def check_supplies_subject(d):
    return [t["name"] for t in d.get("cert_templates", [])
            if t["name_flag"] & 1]

def check_no_approval(d):
    # If bit 0x2 of enroll_flag is ON, manager approval is required; if OFF and the signature count is 0, a certificate is issued directly
    return [t["name"] for t in d.get("cert_templates", [])
            if not (t["enroll_flag"] & 0x2) and t["ra_signature"] == 0 and has_client_auth(t)]

def check_schema_v1(d):
    return [t["name"] for t in d.get("cert_templates", [])
            if t["schema_version"] == 1]

def check_weak_key(d):
    return [f'{t["name"]} ({t["min_key_size"]} bit)'
            for t in d.get("cert_templates", [])
            if 0 < t["min_key_size"] < 2048]

def check_published_templates(d):
    bad = []
    for ca in d.get("cas", []):
        for tname in ca["published"]:
            bad.append(f'{ca["name"]}: {tname}')
    return bad


def check_functional_level(d):
    fl = d["domain"].get("functional_level", 0)
    names = {0: "2000", 2: "2003", 3: "2008", 4: "2008 R2", 5: "2012", 6: "2012 R2", 7: "2016"}
    if fl < 7:
        return [f"Domain functional level {names.get(fl, fl)} — it should be 2016"]
    return []

def check_default_containers(d):
    bad = []
    n_users = sum(1 for u in d["users"] if u.get("dn") and ",CN=Users," in u["dn"])
    n_comps = sum(1 for c in d["computers"] if c.get("dn") and ",CN=Computers," in c["dn"])
    if n_users:
        bad.append(f"{n_users} users are in the default 'Users' container — no proper OU structure has been created")
    if n_comps:
        bad.append(f"{n_comps} computers are in the default 'Computers' container")
    return bad

def check_unlinked_gpos(d):
    # A GPO's GUID is in its DN; a linked GPO's GUID appears in some gPLink
    links = (d["domain"].get("gp_link") or "") + " ".join(o.get("gp_link") or "" for o in d.get("ous", []))
    bad = []
    for g in d.get("gpos", []):
        dn = g.get("dn") or ""
        s, e = dn.find("{"), dn.find("}") + 1
        guid = dn[s:e] if s >= 0 and e > 0 else ""
        if guid and guid.lower() not in links.lower():
            bad.append(g["name"])
    return bad

def check_trust_sid_filtering(d):
    # If bit 0x4 of trustAttributes is ON, SID filtering is on; if OFF, forged SIDs from the other domain may also be accepted
    return [t["partner"] for t in d.get("trusts", []) if not (t["attributes"] & 0x4)]

def check_trust_bidirectional(d):
    return [t["partner"] for t in d.get("trusts", []) if t["direction"] == 3]


def priv_group_count(u):
    n = 0
    for rid in PRIV_RIDS:
        if u.get("dn") in members_of_rid(rid):
            n += 1
    return n

def check_multi_priv(d):
    # One account in multiple privileged groups — one password, multiple doors
    return [f'{u["name"]} ({priv_group_count(u)} privileged groups)'
            for u in d["users"] if priv_group_count(u) >= 2]

def check_da_never_logon(d):
    # A Domain Admin who has never logged on — why is the account kept?
    da = set(members_of_rid(512))
    return [u["name"] for u in d["users"]
            if u.get("dn") in da and u["last_logon"] in (None, "None")]

def check_asrep_priv(d):
    # AS-REP roastable AND privileged — the most dangerous combination
    return [u["name"] for u in d["users"]
            if u["enabled"] and is_priv(u) and (u["uac"] & 0x400000)]

def check_kerb_never_expires(d):
    return [u["name"] for u in d["users"]
            if u["enabled"] and len(u["spns"]) > 0 and (u["uac"] & 0x10000)]

def check_pwd_180(d):
    return [f'{u["name"]} ({days_ago(u["pwd_set"])} days old)'
            for u in d["users"]
            if u["enabled"] and days_ago(u["pwd_set"]) is not None
            and days_ago(u["pwd_set"]) > 180]

def check_dormant_priv(d):
    # A privileged account dormant for 90 days — it receives no attention, but retains its power
    return [f'{u["name"]} ({days_ago(u["last_logon"])} days absent)'
            for u in d["users"]
            if is_priv(u) and days_ago(u["last_logon"]) is not None
            and days_ago(u["last_logon"]) > 90]

def check_stale_users_180(d):
    return [u["name"] for u in d["users"]
            if u["enabled"] and days_ago(u["last_logon"]) is not None
            and days_ago(u["last_logon"]) > 180]

def check_stale_computers_180(d):
    return [c["name"] for c in d["computers"]
            if days_ago(c.get("last_logon")) is not None
            and days_ago(c["last_logon"]) > 180]


def check_unconstrained_computers(d):
    # Unconstrained delegation on a machine other than a DC = the identity of any user who logs on there can be stolen
    return [c["name"] for c in d["computers"]
            if not c["is_dc"] and (c.get("uac", 0) & 0x80000)]

def check_constrained_delegation(d):
    bad = []
    for u in d["users"]:
        if u.get("delegate_to"):
            bad.append(f'{u["name"]} -> {", ".join(u["delegate_to"])}')
    for c in d["computers"]:
        if c.get("delegate_to"):
            bad.append(f'{c["name"]} -> {", ".join(c["delegate_to"])}')
    return bad

def check_protocol_transition(d):
    # TRUSTED_TO_AUTH = this account can create a ticket in anyone's name, without that person's password
    bad = [u["name"] for u in d["users"] if u["enabled"] and (u["uac"] & 0x1000000)]
    bad += [c["name"] for c in d["computers"] if not c["is_dc"] and (c.get("uac", 0) & 0x1000000)]
    return bad

def check_delegation_on_privileged(d):
    return [u["name"] for u in d["users"]
            if is_priv(u) and (u.get("delegate_to") or (u["uac"] & 0x80000))]

def check_computer_old_passwords(d):
    return [f'{c["name"]} ({days_ago(c["pwd_set"])} days old)'
            for c in d["computers"]
            if days_ago(c.get("pwd_set")) is not None and days_ago(c["pwd_set"]) > 90]

def check_computers_in_priv_groups(d):
    comp_dns = {c["dn"] for c in d["computers"] if c.get("dn")}
    bad = []
    for rid in (512, 519, 518):
        for m in members_of_rid(rid):
            if m in comp_dns:
                bad.append(dn_to_name(m))
    return bad

def check_dc_list(d):
    return [c["name"] for c in d["computers"] if c["is_dc"]]

def check_lockout_duration(d):
    mins = d["domain"].get("lockout_duration_min")
    if mins is not None and mins < 30:
        return [f"Lockout duration is only {mins} minutes (it should be 30+)"]
    return []

def check_max_pwd_age(d):
    age = d["domain"].get("max_pwd_age_days")
    if age is None or age == 0 or age > 365:
        return [f"Maximum password age {age} — passwords remain valid for a very long time"]
    return []


def check_priv_never_expires(d):
    return [u["name"] for u in d["users"]
            if u["enabled"] and is_priv(u) and (u["uac"] & 0x10000)]

def check_priv_old_password(d):
    return [f'{u["name"]} ({days_ago(u["pwd_set"])} days old)'
            for u in d["users"]
            if u["enabled"] and is_priv(u)
            and days_ago(u["pwd_set"]) is not None and days_ago(u["pwd_set"]) > 90]

def check_kerb_old_password(d):
    # Kerberoastable + an old password = more time has been available to crack it
    return [u["name"] for u in d["users"]
            if u["enabled"] and len(u["spns"]) > 0
            and days_ago(u["pwd_set"]) is not None and days_ago(u["pwd_set"]) > 90]

def check_pwd_not_required(d):
    # This account does not require a password at all — logon with a blank password is possible
    return [u["name"] for u in d["users"]
            if u["enabled"] and (u["uac"] & 0x20)]

def check_reversible_encryption(d):
    # The password is stored in a way that lets it be recovered in its original form
    return [u["name"] for u in d["users"]
            if u["enabled"] and (u["uac"] & 0x80)]

def check_des_only(d):
    # DES encryption only — the weakest, oldest technology
    return [u["name"] for u in d["users"]
            if u["enabled"] and (u["uac"] & 0x200000)]

def check_never_logged_on(d):
    return [u["name"] for u in d["users"]
            if u["enabled"] and u["last_logon"] in (None, "None")]

def check_inactive_users(d):
    return [f'{u["name"]} ({days_ago(u["last_logon"])} days absent)'
            for u in d["users"]
            if u["enabled"]
            and days_ago(u["last_logon"]) is not None and days_ago(u["last_logon"]) > 90]

def check_protected_accounts(d):
    return [u["name"] for u in d["users"] if u["admin_count"] == 1]

def check_disabled_accounts(d):
    return [u["name"] for u in d["users"] if not u["enabled"]]

def check_eol_os(d):
    bad_os = ["2003", "2008", "2012", "Windows 7", "Windows 8", "Windows XP"]
    return [f'{c["name"]} ({c["os"]})' for c in d["computers"]
            if c["os"] and any(x in c["os"] for x in bad_os)]

def check_single_dc(d):
    dcs = [c for c in d["computers"] if c["is_dc"]]
    if len(dcs) == 1:
        return ["Only 1 Domain Controller exists — if it goes down, the whole domain goes down"]
    return []

def check_machine_quota(d):
    q = d["domain"]["machine_account_quota"]
    if q > 0:
        return [f"Machine account quota {q} — any ordinary user can add that many machines to the domain"]
    return []

def check_da_too_many(d):
    n = len(members_of_rid(512))
    if n > 5:
        return [f"Domain Admins has {n} members — more than 5 is risky"]
    return []

def check_service_in_da(d):
    # A service account that is a Domain Admin = if it is cracked, the whole domain is directly compromised
    da = set(members_of_rid(512))
    return [u["name"] for u in d["users"]
            if u.get("dn") in da and len(u["spns"]) > 0]

def check_nested_in_da(d):
    # Hiding a group inside a group — the actual members are not visible
    return [dn_to_name(m) for m in members_of_rid(512) if m in group_dns]

def check_admincount_orphans(d):
    # Former admins who left the group but kept the administrative protection (adminCount)
    priv = set()
    for rid in (512, 519, 518):
        priv.update(members_of_rid(rid))
    return [u["name"] for u in d["users"]
            if u["admin_count"] == 1 and u.get("dn") not in priv
            and u["name"].lower() != "krbtgt"]   # krbtgt is always protected — do not count it

def check_never_expires(d):
    # The password never expires — an old password remains valid forever
    return [u["name"] for u in d["users"]
            if u["enabled"] and (u["uac"] & 0x10000)]

def check_old_passwords(d):
    # The password has not changed in 90 days
    bad = []
    now = datetime.now(timezone.utc)
    for u in d["users"]:
        if not u["enabled"] or u["pwd_set"] in (None, "None"):
            continue
        dt = datetime.fromisoformat(u["pwd_set"])
        age = (now - dt).days
        if age > 90:
            bad.append(f'{u["name"]} ({age} days old)')
    return bad

def check_guest_enabled(d):
    # An enabled Guest account is never acceptable
    return [u["name"] for u in d["users"]
            if u["name"].lower() == "guest" and u["enabled"]]

def check_krbtgt_age(d):
    # An old krbtgt password = the ticket store for the whole domain is old
    now = datetime.now(timezone.utc)
    for u in d["users"]:
        if u["name"].lower() == "krbtgt" and u["pwd_set"] not in (None, "None"):
            dt = datetime.fromisoformat(u["pwd_set"])
            age = (now - dt).days
            if age > 180:
                return [f"krbtgt password {age} days old"]
    return []

def check_stale_computers(d):
    # Not seen on the network for 90 days — forgotten machines
    bad = []
    now = datetime.now(timezone.utc)
    for c in d["computers"]:
        if c["last_logon"] in (None, "None"):
            bad.append(f'{c["name"]} (no recorded logon)')
            continue
        dt = datetime.fromisoformat(c["last_logon"])
        age = (now - dt).days
        if age > 90:
            bad.append(f'{c["name"]} ({age} days absent)')
    return bad

def check_weak_policy(d):
    # Weaknesses in the domain password policy — this check returns problems, not names
    dom = d["domain"]
    problems = []
    if dom["min_pwd_length"] < 14:
        problems.append(f'Minimum password length is only {dom["min_pwd_length"]} (it should be 14)')
    if dom["lockout_threshold"] == 0:
        problems.append("Account lockout threshold is not set — there is no barrier to brute force")
    if dom["pwd_history_length"] < 24:
        problems.append(f'Password history is only {dom["pwd_history_length"]} (it should be 24)')
    return problems

def check_unconstrained_delegation(d):
    # An ordinary machine has the right to forward your identity — a risk everywhere except DCs
    bad = []
    for c in d["computers"]:
        pass  # uac was not saved for computers — read the note below
    for u in d["users"]:
        if u["enabled"] and (u["uac"] & 0x80000):
            bad.append(u["name"])
    return bad

def check_asrep(d):
    # Kerberos pre-authentication disabled = a hash can be requested without a password
    return [u["name"] for u in d["users"]
            if u["enabled"] and (u["uac"] & 0x400000)]

def check_kerberoastable(d):
    # Accounts with an SPN have passwords that can be cracked from a ticket
    return [u["name"] for u in d["users"]
            if u["enabled"] and len(u["spns"]) > 0]

def check_da_members(d):
    # The Domain Admins list — always show the list, even if the count itself is a finding
    g = group_by_rid(512)
    if not g:
        return []
    return [dn_to_name(m) for m in g["members"]]

# Har check ka record: (ID, name, severity, function)
CHECKS = [
    ("AUTH-01", "AS-REP Roastable Accounts",        "High",   check_asrep),
    ("AUTH-02", "Kerberoastable Accounts (SPN)",     "High",   check_kerberoastable),
    ("AUTH-03", "Password Never Expires",            "Medium", check_never_expires),
    ("AUTH-04", "Passwords Older Than 90 Days",      "Medium", check_old_passwords),
    ("AUTH-05", "krbtgt Password Age",               "High",   check_krbtgt_age),
    ("AUTH-06", "Unconstrained Delegation (Users)",  "High",   check_unconstrained_delegation),
    ("PRIV-01", "Domain Admins Members",             "Info",   check_da_members),
    ("PRIV-02", "Guest Account Enabled",             "Medium", check_guest_enabled),
    ("DS-01",   "Stale Computers (90+ Days)",        "Low",    check_stale_computers),
    ("POL-01",  "Weak Domain Password Policy",       "High",   check_weak_policy),
    ("PRIV-03", "Enterprise Admins Members",         "Info",     lambda d: list_group(519)),
    ("PRIV-04", "Schema Admins Members",             "Info",     lambda d: list_group(518)),
    ("PRIV-05", "Backup Operators Members",          "Info",     lambda d: list_group(551)),
    ("PRIV-06", "Server Operators Members",          "Info",     lambda d: list_group(549)),
    ("PRIV-07", "Account Operators Members",         "Info",     lambda d: list_group(548)),
    ("PRIV-08", "Print Operators Members",           "Info",     lambda d: list_group(550)),
    ("PRIV-09", "Domain Admins Too Many Members",    "Medium",   check_da_too_many),
    ("PRIV-10", "Service Accounts in Domain Admins", "Critical", check_service_in_da),
    ("PRIV-11", "Nested Groups in Domain Admins",    "High",     check_nested_in_da),
    ("PRIV-12", "Orphaned AdminCount Accounts",      "Medium",   check_admincount_orphans),
    ("AUTH-07", "Privileged + Password Never Expires",   "High",     check_priv_never_expires),
    ("AUTH-08", "Privileged + Password 90+ Days Old",    "High",     check_priv_old_password),
    ("AUTH-09", "Kerberoastable + Old Password",         "Critical", check_kerb_old_password),
    ("AUTH-10", "Password Not Required Flag",            "Critical", check_pwd_not_required),
    ("AUTH-11", "Reversible Encryption Password",       "High",     check_reversible_encryption),
    ("AUTH-12", "DES-Only Kerberos Encryption",          "Medium",   check_des_only),
    ("AUTH-13", "Enabled But Never Logged On",           "Medium",   check_never_logged_on),
    ("AUTH-14", "Inactive Users (90+ Days)",             "Medium",   check_inactive_users),
    ("AUTH-15", "Protected Accounts (adminCount=1)",     "Info",     check_protected_accounts),
    ("DS-02",   "Disabled Accounts",                     "Info",     check_disabled_accounts),
    ("DS-03",   "End-of-Life Operating Systems",         "High",     check_eol_os),
    ("DS-04",   "Single Domain Controller",              "Medium",   check_single_dc),
    ("POL-02",  "Machine Account Quota Open",            "Medium",   check_machine_quota),
    ("AUTH-16", "Unconstrained Delegation (Computers)", "High",     check_unconstrained_computers),
    ("AUTH-17", "Constrained Delegation Configured",    "Info",     check_constrained_delegation),
    ("AUTH-18", "Protocol Transition Delegation",       "High",     check_protocol_transition),
    ("AUTH-19", "Delegation on Privileged Accounts",    "Critical", check_delegation_on_privileged),
    ("DS-05",   "Computer Passwords 90+ Days Old",      "Medium",   check_computer_old_passwords),
    ("DS-06",   "Domain Controllers List",              "Info",     check_dc_list),
    ("PRIV-13", "Computers in Privileged Groups",       "High",     check_computers_in_priv_groups),
    ("POL-03",  "Lockout Duration Too Short",           "Medium",   check_lockout_duration),
    ("POL-04",  "Max Password Age Too Long",            "Low",      check_max_pwd_age),
    ("PRIV-14", "Accounts in 2+ Privileged Groups",   "High",     check_multi_priv),
    ("PRIV-15", "Domain Admins Who Never Logged On",  "Critical", check_da_never_logon),    
    ("AUTH-20", "AS-REP on Privileged Account",       "Critical", check_asrep_priv),
    ("AUTH-21", "Kerberoastable + Never Expires",     "High",     check_kerb_never_expires),
    ("AUTH-22", "Passwords Older Than 180 Days",      "Medium",   check_pwd_180),
    ("AUTH-23", "Dormant Privileged Accounts",        "High",     check_dormant_priv),
    ("DS-09",   "Stale Users (180+ Days)",            "Low",      check_stale_users_180),
    ("DS-10",   "Stale Computers (180+ Days)",        "Low",      check_stale_computers_180),
    ("DS-11",   "Domain Functional Level",        "Medium", check_functional_level),
    ("DS-12",   "OU List",                        "Info",   lambda d: [o["name"] for o in d.get("ous", [])]),   
    ("POL-06",  "Objects in Default Containers",  "Medium", check_default_containers),
    ("POL-07",  "Unlinked GPOs",                  "Low",    check_unlinked_gpos),
    ("POL-08",  "GPO List",                       "Info",   lambda d: [g["name"] for g in d.get("gpos", [])]),
    ("DS-13",   "Trusts List",                    "Info",   lambda d: [t["partner"] for t in d.get("trusts", [])]),
    ("DS-14",   "Trusts Without SID Filtering",   "High",   check_trust_sid_filtering),
    ("DS-15",   "Bidirectional Trusts",           "Medium", check_trust_bidirectional),
    ("CS-01", "Certificate Templates List",       "Info",     lambda d: [t["name"] for t in d.get("cert_templates", [])]),
    ("CS-02", "Certificate Authorities List",     "Info",     lambda d: [f'{c["name"]} ({c["host"]})' for c in d.get("cas", [])]),
    ("CS-03", "ESC1-Style Templates",             "Critical", check_esc1),
    ("CS-04", "ESC2 Any-Purpose Templates",       "High",     check_esc2),
    ("CS-05", "ESC3 Enrollment Agent Templates",  "Medium",   check_esc3),
    ("CS-06", "Enrollee Supplies Subject (SAN)",  "High",     check_supplies_subject),
    ("CS-07", "Templates Needing No Approval",    "High",     check_no_approval),
    ("CS-08", "Schema V1 Templates",              "Low",      check_schema_v1),
    ("CS-09", "Weak Certificate Key Size",        "Low",      check_weak_key),
    ("CS-10", "Published Templates on CAs",       "Info",     check_published_templates),
    ("CS-11", "ESC1 on Published Templates",        "Critical", check_esc1_published),
    ("CS-12", "Published Templates, No Approval",   "High",     check_published_no_approval),
    ("CS-13", "CA Installed on Domain Controller",  "Medium",   check_ca_on_dc),
    ("HYB-01", "Entra Connect Sync Accounts (MSOL)", "Info",    check_msol_accounts),
    ("HYB-02", "Seamless SSO Account (AZUREADSSOACC)", "Info",  check_sso_account),
    ("HYB-03", "Synced Privileged Accounts",        "High",     check_synced_privileged),
    ("HYB-04", "Sync Account in Domain Admins",     "Critical", lambda d: [u["name"] for u in d["users"] if u["name"].lower().startswith("msol_") and u.get("dn") in set(members_of_rid(512))]),
    ("HYB-05", "SSO Account Password Age",          "Medium",   lambda d: [f'{c["name"]} ({days_ago(c.get("pwd_set"))} days old)' for c in d["computers"] if c["name"].lower().startswith("azureadssoacc") and days_ago(c.get("pwd_set")) is not None and days_ago(c["pwd_set"]) > 90]),
    ("POL-09", "Fine-Grained Password Policies",   "Info",     lambda d: [p["name"] for p in d.get("psos", [])]),
    ("POL-10", "Weak PSO (Min Length < 14)",       "Medium",   check_weak_pso),
    ("AUTH-24", "SPN on Privileged Accounts",        "High",   check_spn_on_privileged),
    ("AUTH-25", "Duplicate SPNs",                    "Medium", check_duplicate_spns),
    ("AUTH-26", "SID History Present",               "High",   check_sid_history),
    ("AUTH-27", "Accounts With Multiple SPNs",       "Info",   check_multiple_spns),
    ("PRIV-16", "Nested Groups in Privileged Groups", "High",  check_nested_in_any_priv),
    ("PRIV-17", "Empty Privileged Groups",           "Info",   check_empty_priv_groups),
    ("DS-17",   "Users Without UPN",                 "Low",    check_users_without_upn),
    ("DS-18",   "Duplicate UPNs",                    "Medium", check_duplicate_upns),
    ("HYB-06",  "Non-Routable (.local) UPN Suffix",  "Medium", check_local_upn_suffix),
    ("POL-11",  "GPOs on Domain Controllers OU",     "Info",   check_gpo_on_dc_ou),
    ("POL-12",  "GPOs Linked at Domain Root",        "Info",   lambda d: gpos_in_link(d, d["domain"].get("gp_link"))),
    ("CS-14",   "Latent ESC1 Templates (Unpublished)", "Info", check_latent_esc1),
    ("DS-19", "AD Sites List",                  "Info",   lambda d: [s["name"] for s in d.get("sites", [])]),
    ("DS-20", "AD Subnets List",                "Info",   lambda d: [s["name"] for s in d.get("subnets", [])]),
    ("DS-21", "FSMO Role Holders",              "Info",   lambda d: [f"{r}: {s}" for r, s in d.get("fsmo", {}).items() if s]),
    ("DS-22", "All FSMO Roles on One DC",       "Medium", check_fsmo_single),
    ("DS-23", "AD Recycle Bin Not Enabled",     "Medium", check_recycle_bin),
    ("DS-24", "Tombstone Lifetime Too Short",   "Low",    check_tombstone),
    ("DS-25", "DC Outside Domain Controllers OU", "Medium", check_dc_outside_ou),
    ("AUTH-28", "AS-REP + Password Never Expires", "High", check_asrep_never_expires),
    ("PRIV-18", "DCSync Rights (Non-Admin Holders)",  "Critical", check_dcsync),
    ("PRIV-19", "Dangerous Rights on Domain Root",   "Critical", lambda d: dangerous_trustees(d, "domain_acl")),
    ("PRIV-20", "Dangerous Rights on AdminSDHolder", "High",     lambda d: dangerous_trustees(d, "adminsdholder_acl")),
    ("DS-26",   "LAPS Not Deployed",                 "Medium",   check_laps),
    ("AUTH-29", "Passwords Older Than 365 Days",      "High",     check_pwd_365),
    ("AUTH-30", "krbtgt Account Enabled",             "Critical", check_krbtgt_enabled),
    ("AUTH-31", "SID History on Privileged Accounts", "High",     check_sidhistory_priv),
    ("PRIV-21", "DnsAdmins Members",                  "Medium",   lambda d: group_member_names(d, "DnsAdmins")),
    ("PRIV-22", "Domain Admins Not in Protected Users", "Medium", check_not_protected_users),
    ("PRIV-23", "Privileged Accounts Without Smartcard", "Info",  lambda d: [u["name"] for u in d["users"] if is_priv(u) and u["enabled"] and not (u["uac"] & 0x40000)]),
    ("PRIV-24", "Cert Publishers Members",            "Info",     lambda d: group_member_names(d, "Cert Publishers")),
    ("PRIV-25", "Pre-Windows 2000 Compatible Access Members", "Info", lambda d: group_member_names(d, "Pre-Windows 2000 Compatible Access")),
    ("DS-27",   "Built-in Administrator (RID 500)",   "Info",     check_admin500),
    ("DS-28",   "Disabled Privileged Accounts",       "Low",      check_disabled_priv),
    ("DS-29",   "Read-Only Domain Controllers",       "Info",     lambda d: [c["name"] for c in d["computers"] if c["is_dc"] and (c["uac"] & 0x4000000)]),
    ("DS-30",   "Orphaned Group Members",             "Low",      check_orphan_members),
    ("DS-31",   "Operating System Summary",           "Info",     check_os_summary),
    ("HYB-07",  "UPN / Account Name Mismatch",        "Low",      check_upn_mismatch),
    ("CS-15",   "Latent Client-Auth Templates",       "Info",     check_latent_clientauth),
    ("POL-13",  "Enforced GPO Links",                 "Info",     check_enforced_links),
    ("AUTH-32", "Password-Like Text in Description",  "Medium", check_desc_password),
    ("AUTH-33", "Weak Kerberos Encryption (Users)",   "Medium", lambda d: weak_enc(d["users"])),
    ("AUTH-34", "krbtgt Weak Kerberos Encryption",    "High",   lambda d: weak_enc([u for u in d["users"] if u["name"].lower() == "krbtgt"])),
    ("DS-32",   "Weak Kerberos Encryption (Computers)", "Medium", lambda d: weak_enc(d["computers"])),
    ("DS-33",   "Orphaned Trustees on Domain Root",   "Low",    check_orphan_acl),
    ("POL-14",  "Password Complexity Not Enforced",   "High",   lambda d: ["Password complexity requirement is not enabled"] if d["domain"].get("pwd_properties") is not None and (d["domain"]["pwd_properties"] & 1) == 0 else []),
    ("POL-15",  "Password History Too Low (<24)",     "Low",    lambda d: [f"Password history is only {d['domain']['pwd_history']} (it should be 24)"] if d["domain"].get("pwd_history") is not None and d["domain"]["pwd_history"] < 24 else []),
    ("POL-16",  "Minimum Password Age is Zero",       "Low",    lambda d: ["Minimum password age is 0 — a user can immediately reuse an old password"] if d["domain"].get("min_pwd_age_days") == 0 else []),
    ("CS-16",   "Templates Allowing Exportable Private Key", "Medium", lambda d: [t["name"] for t in d.get("cert_templates", []) if t.get("exportable")]),
    ("CS-17",   "HTTP Certificate Enrollment (ESC8-Style)", "High", lambda d: [f"{ca['name']}: {url}" for ca in d.get("cas", []) for url in ca.get("enrollment_servers", []) if str(url).lower().startswith("http://")]),
    ("PRIV-26", "Dangerous Rights on GPOs",           "High",   check_gpo_rights),
    ("PRIV-27", "ForceChangePassword Rights on Privileged Users", "High", lambda d: acl_findings(d, d.get("user_acls", {}), masks=0, guid=RESET_PWD_GUID)),
    ("PRIV-28", "Dangerous Rights on Privileged User Objects", "Critical", lambda d: acl_findings(d, d.get("user_acls", {}))),
    ("PRIV-29", "Dangerous Rights on Privileged Groups", "High", lambda d: acl_findings(d, d.get("group_acls", {}))),
    ("PRIV-30", "Partial Replication Rights (GetChanges Only)", "Info", check_partial_repl),
    ("CS-18",   "Dangerous Rights on Certificate Templates (ESC4-Style)", "Critical", lambda d: acl_findings(d, d.get("template_acls", {}), masks=DANGER | 0x40000000)),
    ("CS-19",   "Dangerous Rights on CA Object (ESC7-Style)", "High", lambda d: acl_findings(d, d.get("ca_acls", {}))),
    ("DS-34",   "Print Queues List",                    "Info",   lambda d: [f"{q['name']} ({q['server']})" for q in d.get("print_queues", [])]),
    ("DS-35",   "Print Queue Hosted on Domain Controller", "Medium", check_print_on_dc),
    ("DS-36",   "Group Managed Service Accounts (gMSA)", "Info",  lambda d: [g["name"] for g in d.get("gmsa", [])]),
    ("AUTH-35", "Key Credentials Present (Shadow Credentials)", "Info", lambda d: [u["name"] for u in d["users"] if u.get("key_cred_count")]),
    ("AUTH-36", "Key Credentials on Privileged Accounts", "High", lambda d: [u["name"] for u in d["users"] if is_priv(u) and u.get("key_cred_count")]),
    ("DS-37",   "Forest Functional Level",              "Info",   lambda d: [f"Forest functional level: {FL_NAMES.get(d.get('forest_fl', 0), d.get('forest_fl'))}"]),
    ("DS-38",   "Forest Level Lower Than Domain Level", "Medium", lambda d: ["Forest level is older than domain level"] if d.get("forest_fl", 0) < d["domain"].get("functional_level", 0) else []),
    ("PRIV-31", "All Domain Admins (Transitive)",    "Info",   check_transitive_da),
    ("PRIV-32", "Privileged Accounts in Default Container", "Low", lambda d: [u["name"] for u in d["users"] if is_priv(u) and u.get("dn") and ",CN=Users," in u["dn"]]),
    ("AUTH-37", "Privileged Accounts That Can Be Delegated", "Medium", lambda d: [u["name"] for u in d["users"] if is_priv(u) and u["enabled"] and not (u["uac"] & 0x100000)]),
    ("AUTH-38", "Passwords Older Than Domain Max Age", "Medium", lambda d: [f"{u['name']} ({days_ago(u['pwd_set'])} days — policy {d['domain'].get('max_pwd_age_days')} days)" for u in d["users"] if u["enabled"] and not (u["uac"] & 0x10000) and days_ago(u["pwd_set"]) is not None and d["domain"].get("max_pwd_age_days") and days_ago(u["pwd_set"]) > d["domain"]["max_pwd_age_days"]]),
    ("AUTH-39", "Built-in Guest (RID 501) Status",   "Info",   lambda d: [f"{u['name']} (enabled: {u['enabled']})" for u in d["users"] if (u.get("sid") or "").endswith("-501")]),
    ("DS-39",   "Empty OUs",                         "Low",    check_empty_ous),
    ("CS-20",   "Published Code-Signing Templates",  "Medium", lambda d: [t["name"] for t in d.get("cert_templates", []) if t["name"] in published_names(d) and "1.3.6.1.5.5.7.3.3" in t.get("eku", [])]),
    ("CS-21",   "ESC9 Templates (No Security Extension)", "High",   check_esc9),
    ("CS-22",   "ESC15 Schema V1 Templates (EKUwu)",      "High",   check_esc15),
    ("CS-23",   "ESC13 Issuance Policy Linked to Tier-Zero Group", "Critical", check_esc13),
    ("CS-24",   "ESC14 Certificate Mappings on Privileged Accounts", "High",   check_esc14),
    ("POL-17",  "Anonymous LDAP Bind Allowed",       "Medium", lambda d: ["The directory can be read without logging in"] if d.get("anon_bind") else []),
    ("POL-18",  "Disabled GPO Links",                "Info",   check_disabled_links),
    ("HYB-08",  "Privileged Accounts With Non-Routable UPN", "Medium", lambda d: [u["name"] for u in d["users"] if is_priv(u) and u.get("upn") and u["upn"].lower().endswith(".local")]),
    ("POL-19", "GPO Content Coverage",            "Info",     lambda d: [f"{len(d.get('gpo_content', {}))} of {len(d.get('gpos', []))} GPOs had content read"] if d.get("gpo_content") is not None else []),
    ("POL-20", "GPP Password (cpassword) in GPO Files", "Critical", lambda d: [n for n, e in d.get("gpo_content", {}).items() if e.get("cpassword")]),
    ("POL-21", "SMB Signing Explicitly Not Required (GPO)", "Medium", lambda d: [n for n, e in d.get("gpo_content", {}).items() if reg_val(e, "machine\\system\\currentcontrolset\\services\\lanmanserver\\parameters\\requiresecuritysignature") == "0"]),
    ("POL-22", "LDAP Signing Not Required (GPO)",  "Medium",   lambda d: [n for n, e in d.get("gpo_content", {}).items() if reg_val(e, "machine\\system\\currentcontrolset\\services\\ntds\\parameters\\ldapserverintegrity") in ("0", "1")]),
    ("POL-23", "No Logon Auditing in DC Policy",   "Medium",   lambda d: ["Logon auditing is disabled in the Default Domain Controllers Policy"] if d.get("gpo_content", {}).get("Default Domain Controllers Policy", {}).get("sec", {}).get("event audit", {}).get("auditlogonevents") == "0" and d.get("gpo_content", {}).get("Default Domain Controllers Policy", {}).get("sec", {}).get("event audit", {}).get("auditaccountlogonevents") == "0" else []),
    ("POL-24", "Dangerous User Rights Assigned in GPOs", "High", check_gpo_rights_bad), 
    ("POL-25", "Weak LM/NTLM Level Set in GPO",    "Medium",   lambda d: [n for n, e in d.get("gpo_content", {}).items() if reg_val(e, "machine\\system\\currentcontrolset\\control\\lsa\\lmcompatibilitylevel") in ("0", "1", "2")]),
    ("POL-26", "Windows Defender Disabled by GPO", "High",     check_defender_gpo),
    ("POL-27", "Scripts Inside GPOs",              "Info",     lambda d: [f"{n}: {', '.join(e['scripts'])}" for n, e in d.get("gpo_content", {}).items() if e.get("scripts")]),
]

# ---------- RUNNER ----------
passed = failed = 0
for cid, title, sev, fn in CHECKS:
    bad = fn(data)
    if sev == "Info":
        print(f"[INFO] {cid}  {title}")
        for name in bad:
            print(f"         -> {name}")
    elif bad:
        failed += 1
        print(f"[FAIL] {cid}  {title}  ({sev})")
        for name in bad:
            print(f"         -> {name}")
    else:
        passed += 1
        print(f"[PASS] {cid}  {title}")

print()
print(f"Total: {len(CHECKS)} checks | PASS: {passed} | FAIL: {failed}")

# ================= REPORT EXPORT =================
import json as _json
import csv as _csv
from datetime import datetime as _dt
from collections import Counter as _Counter

_D = _json.load(open("collected.json"))
results = []
for _cid, _title, _sev, _fn in CHECKS:
    _items = _fn(_D)
    if _sev == "Info":
        _status = "INFO"
    elif _items:
        _status = "FAIL"
    else:
        _status = "PASS"
    results.append({"id": _cid, "title": _title, "severity": _sev,
                    "status": _status, "items": [str(i) for i in _items]})

BUMPABLE = {"AUTH-01": "Critical", "AUTH-02": "Critical", "AUTH-32": "Critical",
            "AUTH-03": "High", "AUTH-04": "High", "AUTH-13": "High", "AUTH-14": "High"}
_priv_names = [u.get("name", "") for u in _D.get("users", []) if u.get("admin_count") == 1]
for r in results:
    if r["status"] == "FAIL" and r["id"] in BUMPABLE:
        if any(n and any(n in it for it in r["items"]) for n in _priv_names):
            r["orig_severity"] = r["severity"]
            r["severity"] = BUMPABLE[r["id"]]

MITRE_MAP = {
 "AUTH-01": ("T1558.004 AS-REP Roasting", None), "AUTH-28": ("T1558.004 AS-REP Roasting", None),
 "AUTH-02": ("T1558.003 Kerberoasting", None), "AUTH-09": ("T1558.003 Kerberoasting", None),
 "AUTH-21": ("T1558.003 Kerberoasting", None), "AUTH-24": ("T1558.003 Kerberoasting", None),
 "AUTH-03": ("T1078.002 Domain Accounts", None), "AUTH-04": ("T1078.002 Domain Accounts", None),
 "AUTH-07": ("T1078.002 Domain Accounts", None), "AUTH-08": ("T1078.002 Domain Accounts", None),
 "AUTH-13": ("T1078.002 Domain Accounts", None), "AUTH-14": ("T1078.002 Domain Accounts", None),
 "AUTH-23": ("T1078.002 Domain Accounts", None),
 "AUTH-32": ("T1552 Unsecured Credentials", None),
 "POL-01": ("T1110 Brute Force", "1.1.4 Minimum password length"),
 "POL-02": ("T1136.002 Create Account: Domain Account", None),
 "POL-20": ("T1552.001 Credentials In Files", None),
 "POL-22": ("T1557 Adversary-in-the-Middle", None),
 "POL-25": ("T1557.001 LLMNR/NBT-NS Poisoning and Relay", "2.3.11.7 LAN Manager authentication level"),
 "PRIV-10": ("T1078.002 Domain Accounts", None), "PRIV-14": ("T1078.002 Domain Accounts", None),
 "PRIV-15": ("T1078.002 Domain Accounts", None), "PRIV-22": ("T1078.002 Domain Accounts", None),
 "PRIV-31": ("T1078.002 Domain Accounts", None),
 "PRIV-18": ("T1003.006 DCSync", None),
 "PRIV-29": ("T1098 Account Manipulation", None),
 "CS-03": ("T1649 Steal or Forge Authentication Certificates", None),
 "CS-04": ("T1649 Steal or Forge Authentication Certificates", None),
 "CS-06": ("T1649 Steal or Forge Authentication Certificates", None),
 "CS-07": ("T1649 Steal or Forge Authentication Certificates", None),
 "CS-11": ("T1649 Steal or Forge Authentication Certificates", None),
 "CS-12": ("T1649 Steal or Forge Authentication Certificates", None),
 "CS-05": ("T1649 Steal or Forge Authentication Certificates", None),
 "CS-17": ("T1557 Adversary-in-the-Middle", None),
 "CS-18": ("T1649 Steal or Forge Authentication Certificates", None),
 "CS-19": ("T1649 Steal or Forge Authentication Certificates", None),
 "CS-21": ("T1649 Steal or Forge Authentication Certificates", None),
 "CS-22": ("T1649 Steal or Forge Authentication Certificates", None),
 "CS-23": ("T1649 Steal or Forge Authentication Certificates", None),
 "CS-24": ("T1649 Steal or Forge Authentication Certificates", None),
}


with open("findings.json", "w") as f:
    _json.dump(results, f, indent=2)
with open("findings.csv", "w", newline="") as f:
    w = _csv.writer(f)
    w.writerow(["ID", "Title", "Severity", "Status", "Items"])
    for r in results:
        w.writerow([r["id"], r["title"], r["severity"], r["status"], "; ".join(r["items"])])

SEV_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
fails = [r for r in results if r["status"] == "FAIL"]
fails.sort(key=lambda r: SEV_ORDER.get(r["severity"], 9))
npass = sum(1 for r in results if r["status"] == "PASS")
ninfo = sum(1 for r in results if r["status"] == "INFO")
sev_count = {s: sum(1 for r in fails if r["severity"] == s) for s in ("Critical", "High", "Medium", "Low")}
score = sev_count["Critical"] * 10 + sev_count["High"] * 5 + sev_count["Medium"] * 2 + sev_count["Low"]
grade = "CRITICAL" if score >= 40 else "HIGH" if score >= 20 else "MEDIUM" if score >= 8 else "LOW"
GRADE_COLORS = {"CRITICAL": "#b00020", "HIGH": "#e65100", "MEDIUM": "#b8860b", "LOW": "#607d8b"}

QUICK_WINS = {"AUTH-01", "AUTH-03", "AUTH-07", "AUTH-13", "AUTH-32", "POL-02", "PRIV-22", "DS-23"}
quick = [r for r in fails if r["id"] in QUICK_WINS]

try:
    from paths import find_reachability
    already_priv, reaching, all_paths = find_reachability(_D)
except Exception:
    already_priv, reaching, all_paths = [], [], {}
    print("Note: reachability data not found (paths.py)")

_cnt = _Counter()
_names = [u.get("name", "") for u in _D.get("users", [])]
for r in fails:
    for it in r["items"]:
        for n in _names:
            if n and n in it:
                _cnt[n] += 1
most_at_risk = _cnt.most_common(1)

def esc(s):
    return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

def finding_html(r):
    items = "".join("<li>" + esc(i) + "</li>" for i in r["items"])
    mapline = ""
    if r["id"] in MITRE_MAP:
        _m, _c = MITRE_MAP[r["id"]]
        mapline = ' <span class="mitre">MITRE ' + esc(_m) + ((' &middot; CIS ' + esc(_c)) if _c else "") + '</span>'


    raised = (' <span class="raised">raised from ' + esc(r.get("orig_severity", "")) + ' - privileged account</span>') if r.get("orig_severity") else ""
    return ('<div class="finding fl-' + r["severity"].lower() + '"><div class="fhead"><span class="sev ' +
        r["severity"].lower() + '">' + esc(r["severity"]) + '</span><span class="fid">' + esc(r["id"]) +
        '</span><span class="ftitle">' + esc(r["title"]) + '</span>' + raised + mapline + '</div><ul>' + items + '</ul></div>')


FIXES = {
 "PRIV-18": ("Remove the 'Replicating Directory Changes' and 'Replicating Directory Changes All' permissions from these accounts on the domain root (ADSI Edit / domain security settings). Only Domain Controller computer accounts need replication rights.",
             "Re-run the scan - PRIV-18 should PASS, and the Privilege Paths tab should show 0 chains."),
 "PRIV-10": ("Remove the service account from Domain Admins. Run the service with a dedicated account that has only the rights the application truly needs, and change its password after the removal.",
             "Re-run the scan - PRIV-10 should PASS and the account should be gone from the PRIV-01 list."),
 "PRIV-15": ("Investigate each account. If it is not in active use, disable it. If it is a break-glass account, document it, give it a long random password stored safely offline, and review it on a schedule.",
             "Re-run the scan - PRIV-15 should PASS (accounts disabled or in use)."),
 "AUTH-09": ("Change this account's password to a long random one (25+ characters). Better: use a group Managed Service Account (gMSA) so the password rotates automatically, and check the SPN is still needed.",
             "Re-run the scan - AUTH-09 and AUTH-02 should PASS."),
 "CS-03": ("On each template, turn off 'Supply in the request' (enrollee supplies subject), or require CA manager approval and authorized signatures. Disable templates nobody uses.",
             "Re-run the scan - CS-03 should PASS."),
 "CS-11": ("Remove this template from the CA's list of issued templates until it is fixed, then apply the CS-03 fix to the template itself.",
             "Re-run the scan - CS-11 should PASS."),
 "AUTH-01": ("On the account, enable Kerberos preauthentication (untick 'Do not require Kerberos preauthentication' in the account options) and set a strong password.",
             "Re-run the scan - AUTH-01 should PASS."),
 "AUTH-02": ("Give the account a long random password (25+ characters) or move the service to a gMSA. Remove SPNs that are no longer needed.",
             "Re-run the scan - AUTH-02 should PASS (or the account becomes much harder to crack)."),
 "POL-01": ("In the Default Domain Policy, set the minimum password length to 14 and set an account lockout threshold (for example 10 attempts with a 15-minute lockout).",
             "Re-run the scan - POL-01 should PASS."),
 "PRIV-14": ("Review why each account is in several privileged groups and remove it from the groups it does not actively need. People should use a separate admin account, not their daily account.",
             "Re-run the scan - PRIV-14 should shrink or PASS."),
 "AUTH-07": ("Remove 'Password never expires' from these privileged accounts and set long passwords. Control rotation through the domain password policy or a fine-grained policy for admins.",
             "Re-run the scan - AUTH-07 should PASS."),
 "AUTH-08": ("Reset the passwords of these privileged accounts now, to long random values, and make sure the domain maximum password age applies to them.",
             "Re-run the scan - AUTH-08 and AUTH-38 should PASS."),
 "AUTH-21": ("Apply both fixes: a long random password (or gMSA) for the Kerberoastable account, and remove 'Password never expires' from it.",
             "Re-run the scan - AUTH-21 should PASS."),
 "AUTH-23": ("Confirm with the account's owner. If the privileged account is unused, disable it. If it must stay, reset its password and keep it monitored.",
             "Re-run the scan - AUTH-23 should PASS."),
 "AUTH-24": ("Remove the SPN from the privileged account, or move the service onto a dedicated non-privileged service account.",
             "Re-run the scan - AUTH-24 should PASS."),
 "AUTH-28": ("Enable Kerberos preauthentication on the account and remove 'Password never expires', then set a strong password.",
             "Re-run the scan - AUTH-28 and AUTH-01 should PASS."),
 "CS-04": ("Restrict each template's application policies/EKUs to the one purpose it is really for, or disable the template. Any-purpose certificates are effectively master keys.",
             "Re-run the scan - CS-04 should PASS."),
 "CS-06": ("On these templates, turn off 'Supply in the request' and use 'Build from Active Directory information' instead, or require authorized signatures before issuance.",
             "Re-run the scan - CS-06 should shrink or PASS."),
 "CS-07": ("For sensitive templates, enable 'CA certificate manager approval' so a person approves each request. Review whether each template still needs to exist.",
             "Re-run the scan - CS-07 should shrink or PASS."),
 "CS-12": ("Unpublish templates that are not in use. For the ones that stay published, enable CA manager approval - a published template without approval can be requested by any user allowed to enroll.",
             "Re-run the scan - CS-12 should PASS."),
 "CS-21": ("Clear the NO_SECURITY_EXTENSION bit (0x80000000) in the template's msPKI-Enrollment-Flag, so certificates it issues carry the security extension that strong certificate binding relies on.",
             "Re-run the scan - CS-21 should PASS."),
 "CS-22": ("Retire the schema v1 template: duplicate it as a schema version 2 (or higher) template, publish the new one, and unpublish the v1 original. If it must stay, turn off 'Supply in the request' on it.",
             "Re-run the scan - CS-22 should PASS."),
 "CS-23": ("Remove the group link from the issuance policy (clear msDS-OIDToGroupLink on the policy's OID object), or point the policy at a non-privileged group instead. Until that is done, unpublish the template.",
             "Re-run the scan - CS-23 should PASS."),
 "CS-24": ("Review every altSecurityIdentities mapping on these accounts. Remove the ones that are not actively needed, and replace weak issuer/subject mappings with strong ones (subject key identifier, or the certificate SHA-1 hash).",
             "Re-run the scan - CS-24 should PASS, or list only mappings you have reviewed and accepted."),
}

fixplan = ""
_step = 0
for r in fails:
    _step += 1
    if r["id"] in FIXES:
        _fix, _verify = FIXES[r["id"]]
    else:
        _fix = ("Generic fix - review the accounts, groups, settings or templates listed in this finding, "
                "remove or correct the risky setting shown, and document any account that must legitimately stay.")
        _verify = "Re-run the scan - " + r["id"] + " should PASS, or shrink to only the accounts you deliberately kept and documented."
    fixplan += ('<div class="finding fl-' + r["severity"].lower() + '"><div class="fhead"><span class="sev ' +
                r["severity"].lower() + '">' + esc(r["severity"]) + '</span><span class="fid">Step ' + str(_step) +
                ' &middot; ' + esc(r["id"]) + '</span><span class="ftitle">' + esc(r["title"]) + '</span></div>'
                '<div class="rf"><span class="tag fix">Fix</span> ' + esc(_fix) + '</div>'
                '<div class="rf"><span class="tag verify">Verify</span> ' + esc(_verify) + '</div></div>')
if not fixplan:
    fixplan = '<p>No findings - nothing in the fix plan.</p>'

_opt_w = {"Critical": 10, "High": 5, "Medium": 2, "Low": 1}
_targets = {}
for u in _D.get("users", []):
    if _cnt.get(u.get("name", ""), 0) > 0:
        _targets[u.get("name", "")] = "Account"
for t in _D.get("cert_templates", []):
    _targets.setdefault(t.get("name", ""), "Template")
for g in _D.get("gpos", []):
    _targets.setdefault(g.get("name", ""), "GPO")

def _opt_stats(nm):
    cleared, shrunk, drop = 0, 0, 0
    for r in fails:
        if not r["items"]:
            continue
        hits = [nm in it for it in r["items"]]
        if all(hits):
            cleared += 1
            drop += _opt_w.get(r["severity"], 0)
        elif any(hits):
            shrunk += 1
    return cleared, shrunk, drop

_opt_rows = []
for nm, typ in _targets.items():
    if not nm:
        continue
    c, s, dr = _opt_stats(nm)
    if c + s == 0:
        continue
    paths_blocked = len(all_paths.get(nm, [])) if typ == "Account" else 0
    _opt_rows.append((nm, typ, c, s, paths_blocked, dr))
_opt_rows.sort(key=lambda x: (-x[5], -x[2], -x[3], x[0].lower()))
_opt_rows = _opt_rows[:8]

optimizer_html = ""
if _opt_rows:
    _trs = ""
    for i, (nm, typ, c, s, pb, dr) in enumerate(_opt_rows, 1):
        _trs += ('<tr><td>' + str(i) + '</td><td><b>' + esc(nm) + '</b></td><td>' + esc(typ) + '</td><td>' +
                 str(c) + '</td><td>' + str(s) + '</td><td>' + str(pb) + '</td><td>' + str(dr) + '</td></tr>')
    _cleared_ids = set()
    _covered_names = []
    _rm = score
    _journey = [str(score)]
    for (nm, typ, c, s, pb, dr) in _opt_rows:
        _covered_names.append(nm)
        for r in fails:
            if r["id"] in _cleared_ids or not r["items"]:
                continue
            if all(any(tn in it for tn in _covered_names) for it in r["items"]):
                _cleared_ids.add(r["id"])
                _rm -= _opt_w.get(r["severity"], 0)
        _journey.append(str(_rm))
    optimizer_html = ('<p>Each row is one work package: fully remediate that account, template or GPO and this is what it buys you. '
                      '"Cleared" means the finding disappears completely; "Reduced" means it shrinks but other objects keep it alive.</p>'
                      '<table class="dtable"><tr><th>#</th><th>Fix this first</th><th>Type</th><th>Findings cleared</th>'
                      '<th>Findings reduced</th><th>Paths blocked</th><th>Score drop (alone)</th></tr>' + _trs + '</table>'
                      '<p><b>Projected score if you work in this order:</b> ' + ' &#8594; '.join(_journey) + '</p>')

AUTO_PS = {
 "AUTH-03": lambda nm: ["Set-ADUser -Identity '" + nm + "' -PasswordNeverExpires $false -WhatIf"],
 "AUTH-07": lambda nm: ["Set-ADUser -Identity '" + nm + "' -ChangePasswordAtLogon $true -WhatIf"],
 "AUTH-32": lambda nm: ["Set-ADUser -Identity '" + nm + "' -Clear Description -WhatIf"],
}
_dns = ".".join(p.replace("DC=", "") for p in _D["domain"].get("base_dn", "").split(",") if p.strip().upper().startswith("DC="))
_ps = ["# CerberusAD remediation script - generated " + _dt.now().strftime("%d %B %Y"),
       "# Domain: " + _dns,
       "# REVIEW EVERY STEP BEFORE RUNNING. Commands that change something end in -WhatIf:",
       "# they only SHOW what would happen. Remove -WhatIf from a block when you are ready.",
       "# Steps without a ready command are manual - the comments tell you exactly what to do.",
       "# Run as a Domain Admin on a DC or a machine with the ActiveDirectory PowerShell module.",
       "", "Import-Module ActiveDirectory", ""]
_psn = 0
for r in fails:
    _psn += 1
    if r["id"] in FIXES:
        _pfix, _pverify = FIXES[r["id"]]
    else:
        _pfix = ("Generic fix - review the accounts, groups, settings or templates listed in this finding, "
                 "remove or correct the risky setting shown, and document any account that must legitimately stay.")
        _pverify = "Re-run the scan - " + r["id"] + " should PASS."
    _ps.append("# ------------------------------------------------------------")
    _ps.append("# Step " + str(_psn) + ": [" + r["id"] + "] " + r["title"] + " (" + r["severity"] + ")")
    _ps.append("# Fix: " + _pfix)
    _ps.append("# Verify: " + _pverify)
    if r["items"]:
        _ps.append("# Affected: " + "; ".join(r["items"][:12]))
    _cmds = []
    if r["id"] in AUTO_PS:
        for _it in r["items"]:
            _cmds += AUTO_PS[r["id"]](_it.split(" (")[0].replace("'", ""))
    elif r["id"] == "POL-01" and _dns:
        _cmds = ["Set-ADDefaultDomainPasswordPolicy -Identity '" + _dns + "' -MinPasswordLength 14 -WhatIf"]
    elif r["id"] == "POL-02" and _dns:
        _cmds = ["Set-ADDomain -Identity '" + _dns + "' -Replace @{'ms-DS-MachineAccountQuota'=0} -WhatIf"]
    if _cmds:
        _ps += _cmds
    else:
        _ps.append("# (manual step - no safe automatic command for this one)")
    _ps.append("")
with open("remediation.ps1", "w", encoding="utf-8") as fh:
    fh.write("\n".join(_ps))

_reach_names = {n for (n, _s) in reaching}
_prof_users = [u for u in _D.get("users", []) if u.get("admin_count") == 1 or u.get("name") in _reach_names]
_prof_users.sort(key=lambda u: -_cnt.get(u.get("name", ""), 0))

def _pwd_age(u):
    try:
        dt = _dt.fromisoformat(str(u.get("pwd_set", "")).replace("Z", "+00:00")).replace(tzinfo=None)
        return (_dt.now() - dt).days
    except Exception:
        return None

_groups_by_dn2 = {g.get("dn"): g.get("name", "") for g in _D.get("groups", [])}
profiles = ""
for u in _prof_users:
    nm = u.get("name", "")
    badges = ""
    if nm in already_priv:
        badges += '<span class="sev critical">Domain Admin level</span> '
    if nm in _reach_names:
        badges += '<span class="sev high">Can reach Domain Admin</span> '
    if not u.get("enabled", True):
        badges += '<span class="sev low">Disabled</span> '
    grps = [g for g in (_groups_by_dn2.get(dn, "") for dn in u.get("member_of", [])) if g]
    facts = ["Appears in <b>" + str(_cnt.get(nm, 0)) + "</b> failed checks"]
    age = _pwd_age(u)
    if age is not None:
        facts.append("Password age: <b>" + str(age) + " days</b>")
    facts.append("Password never expires: <b>" + ("yes" if (u.get("uac", 0) & 0x10000) else "no") + "</b>")
    facts.append("Has SPN (Kerberoastable): <b>" + ("yes" if u.get("spns") else "no") + "</b>")
    if grps:
        facts.append("Groups: " + esc(", ".join(grps)))
    profiles += ('<div class="finding"><div class="fhead"><span class="ftitle">' + esc(nm) + '</span> ' + badges +
                 '</div><p class="pfacts">' + ' &middot; '.join(facts) + '</p></div>')

if not profiles:
    profiles = '<p>No privileged or reaching accounts to profile.</p>'

def _guid_of_dn(dn):
    if "{" in dn and "}" in dn:
        return dn.split("{", 1)[1].split("}", 1)[0].lower()
    return ""

_dom_links = (_D.get("domain", {}).get("gplink", "") or "").lower()
_ou_links = [(o.get("gplink", "") or "").lower() for o in _D.get("ous", [])]
_gc = {}
_raw_gc = _D.get("gpo_content", {})
if isinstance(_raw_gc, dict):
    for _k, _v in _raw_gc.items():
        if isinstance(_v, dict):
            _gc[_v.get("name") or _k] = _v
elif isinstance(_raw_gc, list):
    for _v in _raw_gc:
        if isinstance(_v, dict) and _v.get("name"):
            _gc[_v["name"]] = _v
gpo_rows = ""
for g in sorted(_D.get("gpos", []), key=lambda x: x.get("name", "").lower()):
    nm = g.get("name", "")
    guid = _guid_of_dn(g.get("dn", ""))
    linked = []
    if guid and guid in _dom_links:
        linked.append("Domain root")
    _n = sum(1 for s in _ou_links if guid and guid in s)
    if _n:
        linked.append(str(_n) + " OU(s)")
    e = _gc.get(nm) or _gc.get(guid) or {}
    gpo_rows += ('<tr><td>' + esc(nm) + '</td><td>' + esc(", ".join(linked) if linked else "Not linked") +
                 '</td><td>' + str(e.get("files", 0)) + '</td><td>' +
                 ("YES" if e.get("cpassword") else "no") + '</td></tr>')
gpo_table = '<table class="dtable"><tr><th>GPO</th><th>Linked at</th><th>SYSVOL files read</th><th>cpassword</th></tr>' + gpo_rows + '</table>'

CLIENT_AUTH = "1.3.6.1.5.5.7.3.2"
_published_on = {}
for ca in _D.get("cas", []):
    for t in ca.get("published", []):
        _published_on.setdefault(t, []).append(ca.get("name", ""))
_cs_shown, _cs_folded = [], []
for t in sorted(_D.get("cert_templates", []), key=lambda x: x.get("name", "").lower()):
    nm = t.get("name", "")
    ekus = t.get("eku", [])
    cauth = CLIENT_AUTH in ekus or "1.3.6.1.5.5.7.3.1" in ekus
    anyp = (not ekus) or ("2.5.29.37.0" in ekus)
    supplies = bool(t.get("name_flag", 0) & 1)
    approval = (t.get("ra_signature", 0) or 0) > 0
    pubs = _published_on.get(nm, [])
    if pubs and supplies and (cauth or anyp) and not approval:
        risk, rcls, rank = "ESC1 risk", "critical", 0
    elif supplies or anyp:
        risk, rcls, rank = "Review", "high", 1
    else:
        risk, rcls, rank = "Standard", "low", 2
    row = ('<tr><td>' + esc(nm) + '</td><td>' + esc(", ".join(pubs) if pubs else "-") + '</td><td>' +
           ("yes" if cauth else "no") + '</td><td>' + ("yes" if supplies else "no") + '</td><td>' +
           ("yes" if approval else "no") + '</td><td><span class="sev ' + rcls + '">' + risk + '</span></td></tr>')
    if pubs or risk != "Standard":
        _cs_shown.append((rank, row))
    else:
        _cs_folded.append(nm)
_cs_shown.sort(key=lambda x: x[0])
cs_table = ('<table class="dtable"><tr><th>Template</th><th>Published on</th><th>Client Auth</th><th>Supplies Subject</th>' +
            '<th>Approval</th><th>Risk</th></tr>' + "".join(r for _k, r in _cs_shown) + '</table>')
if _cs_folded:
    cs_table += ('<p class="folded">' + str(len(_cs_folded)) + ' more templates are Standard risk and not published: ' +
                 esc(", ".join(sorted(_cs_folded))) + '</p>')

_whatif_rows = ""
_ages = []
for u in _D.get("users", []):
    _a = _pwd_age(u)
    if _a is not None and u.get("enabled", True):
        _ages.append((u.get("name", ""), _a, u.get("admin_count") == 1, bool(u.get("uac", 0) & 0x10000)))
_scenarios = []
for _limit in (90, 180):
    _hit = [x for x in _ages if x[1] > _limit]
    _scenarios.append(("Force a password change every " + str(_limit) + " days",
                       str(len(_hit)) + " enabled accounts (" + str(sum(1 for x in _hit if x[2])) + " privileged) are already past that age and would have to change their password"))
_nev = [x for x in _ages if x[3]]
_scenarios.append(("Remove 'password never expires' from every account",
                   str(len(_nev)) + " enabled accounts (" + str(sum(1 for x in _nev if x[2])) + " privileged) would start expiring like everyone else"))
for _t, _e in _scenarios:
    _whatif_rows += '<tr><td>' + esc(_t) + '</td><td>' + esc(_e) + '</td></tr>'
whatif_html = ('<table class="dtable"><tr><th>If this policy changed...</th><th>...this is what would happen</th></tr>' + _whatif_rows + '</table>') if _whatif_rows else ""



_mcount = {}
for r in fails:
    if r["id"] in MITRE_MAP:
        _mcount.setdefault(MITRE_MAP[r["id"]][0], []).append(r["id"])
mitre_rows = ""
for _t in sorted(_mcount, key=lambda t: -len(_mcount[t])):
    mitre_rows += ('<tr><td>' + esc(_t) + '</td><td>' + str(len(_mcount[_t])) + '</td><td>' +
                   esc(", ".join(_mcount[_t])) + '</td></tr>')
mitre_html = ('<table><tr><th>Technique</th><th>Failed findings</th><th>Checks</th></tr>' + mitre_rows + '</table>') if mitre_rows else '<p>No mapped findings.</p>'

TACTICS = {"T1003.006": "credential-access", "T1078.002": "persistence", "T1098": "persistence",
           "T1110": "credential-access", "T1136.002": "persistence", "T1552": "credential-access",
           "T1552.001": "credential-access", "T1557": "credential-access", "T1557.001": "credential-access",
           "T1558.003": "credential-access", "T1558.004": "credential-access", "T1649": "credential-access"}
DETECTION = {
 "T1003.006": "Watch Event 4662 directory-replication accesses (replication GUIDs) coming from any host that is not a Domain Controller.",
 "T1078.002": "Alert on 4624 logons by privileged or dormant accounts from new hosts or at unusual hours.",
 "T1098": "Monitor 4728 / 4732 / 4756 (member added to a privileged group) and 4738 (account changed) for privileged accounts.",
 "T1110": "Monitor bursts of 4625 failed logons and 4771 / 4776 failures concentrated on single accounts.",
 "T1136.002": "Alert on 4720 (account created) followed quickly by 4728 (added to a privileged group).",
 "T1552": "Scan account descriptions, logon scripts and GPO files for stored secrets on a schedule; alert on bulk reads of user attributes.",
 "T1552.001": "Scan SYSVOL and GPP files for cpassword and plaintext credentials; alert on unusual reads of SYSVOL shares.",
 "T1557": "Require SMB and LDAP signing, disable LLMNR / NBT-NS, and alert on NTLM (4624, package NTLM) logons to servers from unexpected hosts.",
 "T1557.001": "Disable LLMNR / NBT-NS via GPO; alert when a workstation answers name-resolution broadcasts for names that do not exist in DNS.",
 "T1558.003": "Monitor 4769 service-ticket requests using RC4 (0x17) or by accounts that never normally request them; plant a honey SPN account and alert on any ticket for it.",
 "T1558.004": "Monitor 4771 pre-auth failures (code 0x18) and alert on any account found with pre-authentication disabled.",
 "T1649": "Monitor CA events 4886 / 4887 for certificates issued from templates that allow a requester-supplied subject; alert on certificate logons (4624) by admin accounts from new hosts.",
}
_tech = {}
for r in fails:
    _m = MITRE_MAP.get(r["id"])
    if _m:
        _tech.setdefault(_m[0].split()[0], {"name": _m[0], "ids": []})["ids"].append(r["id"])
_layer = {"name": "CerberusAD findings layer",
          "versions": {"attack": "13", "navigator": "4.9.1", "layer": "4.4"},
          "domain": "enterprise-attack",
          "description": "MITRE ATT&CK techniques behind the failed checks in this CerberusAD report. Score = number of failed checks mapped to the technique (max 10).",
          "techniques": [],
          "gradient": {"colors": ["#ffffff", "#ff6666", "#b00020"], "minValue": 0, "maxValue": 10},
          "legendItems": [], "showTacticRowBackground": True, "tacticRowBackground": "#205b85",
          "selectTechniquesAcrossTactics": True, "selectSubtechniquesWithParent": False}
for _tid, _info in sorted(_tech.items()):
    _e = {"techniqueID": _tid, "comment": ", ".join(_info["ids"]),
          "score": min(len(_info["ids"]), 10), "enabled": True,
          "metadata": [{"name": "Checks", "value": ", ".join(_info["ids"])}]}
    if _tid in TACTICS:
        _e["tactic"] = TACTICS[_tid]
    _layer["techniques"].append(_e)
with open("attack_layer.json", "w", encoding="utf-8") as fh:
    json.dump(_layer, fh, indent=1)
_dp = ["# Detection Pack", "",
       "For every failed check that maps to MITRE ATT&CK: the technique behind it and what to monitor.", ""]
for r in fails:
    _m = MITRE_MAP.get(r["id"])
    if not _m:
        continue
    _dp.append("## " + r["id"] + " - " + r["title"])
    _dp.append("- Technique: " + _m[0])
    _dp.append("- Monitor: " + DETECTION.get(_m[0].split()[0], "Monitor authentication and directory-change events around the affected objects."))
    _dp.append("")
with open("detection_pack.md", "w", encoding="utf-8") as fh:
    fh.write("\n".join(_dp))


KIND_LABELS = {"MemberOf": "member of", "ResetPassword": "can reset password",
               "FullControl": "full control", "ChangeMembers": "can change members",
               "Replication": "replication rights", "GPOEdit": "can edit GPO",
               "ESC1": "ESC1 enrollment", "ESC2": "ESC2 enrollment",
               "SIDHistory": "SID history", "Delegation": "delegation to a DC",
               "DCControl": "domain controller"}
_user_names = {u.get("name") for u in _D.get("users", [])}
_group_names = {g.get("name") for g in _D.get("groups", [])}

def node_type(nm):
    if nm.startswith("the domain"):
        return "DOMAIN"
    if nm in _group_names or nm in ("Everyone", "Authenticated Users"):
        return "GROUP"
    return "USER"

def node_html(nm):
    return ('<div class="pnode t-' + node_type(nm).lower() + '"><span class="ptag">' +
            node_type(nm) + '</span><span class="pname">' + esc(nm) + '</span></div>')

def diagram_html(steps):
    if not steps:
        return ""
    out = node_html(steps[0][0])
    for (frm, kind, to, text, risk, fix) in steps:
        out += ('<div class="parrow"><span class="plink">' + esc(KIND_LABELS.get(kind, kind)) +
                '</span><span class="parr">&#8595;</span></div>')
        out += node_html(to)
    return '<div class="pdiagram">' + out + '</div>'

def steps_table_html(steps):
    rows = ""
    for j, (frm, kind, to, text, risk, fix) in enumerate(steps, 1):
        rows += ('<tr><td>' + str(j) + '</td><td><b>' + esc(KIND_LABELS.get(kind, kind)) + '</b><br>' +
                 esc(frm) + ' &#8594; ' + esc(to) + '</td><td>' + esc(risk) + '</td><td>' + esc(fix) + '</td></tr>')
    return ('<table class="ptable"><tr><th>Step</th><th>Permission</th><th>Risk</th><th>Fix</th></tr>' + rows + '</table>')

_total_paths = sum(len(v) for v in all_paths.values())
_cut = _Counter()
for (_n, _paths) in all_paths.items():
    for _p in _paths:
        for _k in {s[1] for s in _p}:
            _cut[_k] += 1
cut_html = ""
if reaching and _cut:
    _top_kind, _top_n = _cut.most_common(1)[0]
    _pct = round(100 * _top_n / max(_total_paths, 1))
    cut_html = ('<div class="card cut-card"><b>Cut these first:</b> the permission creating the most paths is <b>' +
                esc(KIND_LABELS.get(_top_kind, _top_kind)) + '</b> - it appears in ' + str(_top_n) + ' of ' +
                str(_total_paths) + ' paths (' + str(_pct) + '%). Fixing it removes those paths at once.</div>')

_groups_by_dn = {g.get("dn"): g for g in _D.get("groups", [])}
_users_by_name = {u.get("name"): u for u in _D.get("users", [])}
def _rid_of(sid):
    try:
        return int(str(sid).rsplit("-", 1)[1])
    except Exception:
        return -1
tz = ""
for nm in already_priv:
    u = _users_by_name.get(nm, {})
    chips = ""
    for dn in u.get("member_of", []):
        g = _groups_by_dn.get(dn)
        if g and _rid_of(g.get("sid")) in (512, 518, 519, 544):
            chips += '<span class="chip">' + esc(g.get("name", "")) + '</span>'
    tz += '<div class="tzrow"><b>' + esc(nm) + '</b> ' + chips + '</div>'
tierzero = '<div class="card">' + (tz or '<p>None.</p>') + '</div>'

ov_rows = ""
for (n, steps) in reaching:
    psev = "Critical" if len(steps) <= 1 else "High" if len(steps) == 2 else "Medium"
    ov_rows += ('<tr><td><b>' + esc(n) + '</b></td><td>' + str(len(all_paths.get(n, []))) + '</td><td>' + str(len(steps)) + '</td><td>' +
                esc(KIND_LABELS.get(steps[-1][1], steps[-1][1])) + '</td><td><span class="sev ' +
                psev.lower() + '">' + psev + '</span></td></tr>')
overview = ('<table class="ptable"><tr><th>Account</th><th>Paths</th><th>Shortest (steps)</th><th>Final permission</th><th>Path severity</th></tr>' +
            ov_rows + '</table>') if reaching else '<p>No account can reach Domain Admin.</p>'

_lens = [len(s) for (_n, s) in reaching]
_all_lens = [len(p) for v in all_paths.values() for p in v]
tab2_kpis = ('<div class="kpis">'
             '<div class="kpi"><div class="num red">' + str(_total_paths) + '</div><div class="lbl">Paths to DA</div></div>'
             '<div class="kpi"><div class="num">' + str(min(_lens) if _lens else 0) + '</div><div class="lbl">Shortest path</div></div>'
             '<div class="kpi"><div class="num">' + str(max(_all_lens) if _all_lens else 0) + '</div><div class="lbl">Longest path</div></div>'
             '<div class="kpi"><div class="num orange">' + str(len(already_priv)) + '</div><div class="lbl">Already privileged</div></div></div>')


sev_rows = ""
for s in ("Critical", "High", "Medium", "Low"):
    sev_rows += ('<tr><td><span class="dot-sev ' + s.lower() + '"></span>' + s + '</td><td><b>' +
                 str(sev_count[s]) + '</b></td></tr>')

kpis = ('<div class="kpis">'
        '<div class="kpi"><div class="num">' + str(len(results)) + '</div><div class="lbl">Checks run</div></div>'
        '<div class="kpi"><div class="num green">' + str(npass) + '</div><div class="lbl">Passed</div></div>'
        '<div class="kpi"><div class="num red">' + str(len(fails)) + '</div><div class="lbl">Failed</div></div>'
        '<div class="kpi"><div class="num red">' + str(sev_count["Critical"]) + '</div><div class="lbl">Critical</div></div>'
        '<div class="kpi"><div class="num">' + str(score) + '</div><div class="lbl">Risk score</div></div>'
        '<div class="kpi"><div class="num orange">' + str(len(reaching)) + '</div><div class="lbl">Can reach DA</div></div>'
        '</div>')

summary = ('<p>' + str(len(results)) + ' checks run: <b>' + str(npass) + ' passed</b>, <b>' + str(len(fails)) +
           ' failed</b>, ' + str(ninfo) + ' information.</p>'
           '<table class="sevtable"><tr><th>Severity</th><th>Failed checks</th></tr>' + sev_rows + '</table>'
           '<p>Accounts already at Domain Admin level: <b>' + str(len(already_priv)) +
           '</b>. Accounts that can reach Domain Admin: <b>' + str(len(reaching)) + '</b>.</p>')
if most_at_risk:
    summary += ('<p>Most at-risk account: <b>' + esc(most_at_risk[0][0]) + '</b> (appears in ' +
                str(most_at_risk[0][1]) + ' failed checks).</p>')
summary += ('<p><b>Top risks</b></p><ul>' +
            "".join('<li><b>' + esc(r["id"]) + '</b> ' + esc(r["title"]) + ' (' + esc(r["severity"]) + ')</li>' for r in fails[:5]) +
            '</ul>')

_step_key_ids = {}
def step_key(frm, kind, to):
    k = (frm, kind, to)
    if k not in _step_key_ids:
        _step_key_ids[k] = "k" + str(len(_step_key_ids))
    return _step_key_ids[k]

def step_cards_html(idx, steps):
    out = ""
    for j, (frm, kind, to, text, risk, fix) in enumerate(steps, 1):
        out += ('<div class="stepcard"><div class="schead">Step ' + str(j) + ' &middot; ' +
                esc(KIND_LABELS.get(kind, kind)) + '</div><b>' + esc(text) + '.</b>'
                '<div class="rf"><span class="tag risk">Risk</span> ' + esc(risk) + '</div>'
                '<div class="rf"><span class="tag fix">Fix</span> ' + esc(fix) + '</div>'
                '<label class="fixrow"><input type="checkbox" class="fixbox" data-key="' +
                step_key(frm, kind, to) + '" onchange="fixChanged(this)"> Fixed</label></div>')
    return out

side_items = ""
panels = ""
for i, (n, steps) in enumerate(reaching):
    _paths = all_paths.get(n, [steps])
    psev = "Critical" if len(steps) <= 1 else "High" if len(steps) == 2 else "Medium"
    side_items += ('<button class="sideitem' + (' active' if i == 0 else '') + '" data-name="' + esc(n) +
                   '" data-idx="' + str(i) + '" onclick="showChain(' + str(i) + ', this)"><b>' + esc(n) +
                   '</b> &#8594; DA &middot; ' + str(len(steps)) + ' step(s)' +
                   (' &middot; ' + str(len(_paths)) + ' paths' if len(_paths) > 1 else '') + ' &middot; ' +
                   '<span class="sev ' + psev.lower() + '">' + psev + '</span></button>')
    _chips = ""
    if len(_paths) > 1:
        _chips = ('<div class="pathchips">' + "".join(
            '<button class="pathchip' + (' active' if j == 0 else '') + '" onclick="showPath(' + str(i) + ', ' + str(j) +
            ', this)">Path ' + str(j + 1) + ' &middot; ' + str(len(p)) + ' step(s)</button>'
            for j, p in enumerate(_paths)) + '</div>')
    _pdivs = ""
    for j, p in enumerate(_paths):
        _pdivs += ('<div class="pathdiv" id="pd' + str(i) + '_' + str(j) + '"' + ('' if j == 0 else ' style="display:none"') +
                   '>' + diagram_html(p) +
                   '<div class="progwrap"><div class="progbar"></div></div>' +
                   '<div class="progtxt">Fix progress: 0 of ' + str(len(p)) + '</div>' +
                   step_cards_html(i, p) + '</div>')
    panels += ('<div class="chainpanel" id="cp' + str(i) + '"' + ('' if i == 0 else ' style="display:none"') +
               '><div class="chain-head"><b>' + esc(n) + '</b> can reach Domain Admin - ' + str(len(_paths)) +
               ' path(s), shortest ' + str(len(steps)) + ' step(s)</div>' + _chips + _pdivs + '</div>')

SIM_KIND_FINDINGS = {"Replication": ["PRIV-18"], "ESC1": ["CS-11"], "ESC2": ["CS-04"]}
_sev_w = {"Critical": 10, "High": 5, "Medium": 2, "Low": 1}
_fail_w = {r["id"]: _sev_w.get(r["severity"], 0) for r in fails}
_sim_chains = []
_sim_step_findings = {}
for (n, _paths) in all_paths.items():
    for steps in _paths:
        _keys = []
        for (frm, kind, to, _t, _r, _f) in steps:
            _k = step_key(frm, kind, to)
            _keys.append(_k)
            _fids = list(SIM_KIND_FINDINGS.get(kind, []))
            if kind in ("ChangeMembers", "FullControl") and node_type(to) == "GROUP":
                _fids.append("PRIV-29")
            for _fid in _fids:
                if _fid in _fail_w:
                    _sim_step_findings.setdefault(_k, []).append(_fid)
        _sim_chains.append({"start": n, "keys": _keys})
sim_json = json.dumps({"base": score, "chains": _sim_chains,
                       "stepFindings": _sim_step_findings, "weights": _fail_w})

if reaching:
    sim_html = ('<div class="card sim-card"><div class="simtitle">Fix Simulator</div>'
                '<p class="simnote">Tick <b>Fixed</b> on any step in the Path Explorer below and watch the effect - no re-scan needed. '
                'A path counts as blocked as soon as one of its steps is fixed. The projected score only counts the findings a step on this tab '
                'provably belongs to (PRIV-18, CS-11, CS-04, PRIV-29). Direct group memberships are removed in Active Directory and show up on the next scan.</p>'
                '<div class="kpis">'
                '<div class="kpi"><div class="num red" id="simReach">' + str(len(reaching)) + '</div><div class="lbl">Accounts can still reach DA</div></div>'
                '<div class="kpi"><div class="num orange" id="simPaths">' + str(_total_paths) + '</div><div class="lbl">Open paths</div></div>'
                '<div class="kpi"><div class="num" id="simScore">' + str(score) + '</div><div class="lbl">Projected risk score</div></div>'
                '</div></div>')
else:
    sim_html = ""

_gname_by_dn = {g.get("dn"): g.get("name") for g in _D.get("groups", [])}
_name_by_dn = dict(_gname_by_dn)
for _u in _D.get("users", []):
    _name_by_dn[_u.get("dn")] = _u.get("name")
_parents = {}
for _g in _D.get("groups", []):
    for _mdn in _g.get("members", []):
        _cn = _name_by_dn.get(_mdn)
        if _cn:
            _parents.setdefault(_cn, set()).add(_g.get("name"))
_step_edges = {}
_domain_labels = set()
for (_n, _paths) in all_paths.items():
    for _steps in _paths:
        for (_frm, _kind, _to, _t, _r, _f) in _steps:
            _step_edges.setdefault(_frm, set()).add(_to)
            if str(_to).startswith("the domain"):
                _domain_labels.add(_to)
_tz_names = {g.get("name") for g in _D.get("groups", [])
             if str(g.get("sid", "")).rsplit("-", 1)[-1] in ("512", "518", "519")}
_reach_map = {n: len(s) for (n, s) in reaching}
_already_set = set(already_priv)
COMP = {}
_rank = []
for _u in _D.get("users", []):
    _nm = _u.get("name")
    if not _nm or not _u.get("enabled", True):
        continue
    _seen = set()
    _stack = [_nm]
    while _stack:
        _x = _stack.pop()
        if _x in _seen:
            continue
        _seen.add(_x)
        for _y in _step_edges.get(_x, ()):
            if _y not in _seen:
                _stack.append(_y)
        for _p in _parents.get(_x, ()):
            if _p not in _seen:
                _stack.append(_p)
    _da = _nm in _already_set or any(t in _seen for t in _tz_names) or any(d in _seen for d in _domain_labels)
    _c = {"da": bool(_da),
          "steps": 0 if _nm in _already_set else _reach_map.get(_nm),
          "users": sum(1 for x in _seen if x != _nm and node_type(x) == "USER"),
          "groups": sum(1 for x in _seen if node_type(x) == "GROUP")}
    COMP[_nm] = _c
    if _c["da"] or _c["users"] or _c["groups"]:
        _rank.append((_nm, _c))
_rank.sort(key=lambda kv: (not kv[1]["da"], kv[1]["steps"] is None, kv[1]["steps"] or 99, -kv[1]["users"], -kv[1]["groups"]))
comp_json = json.dumps(COMP)
if COMP:
    _copts = "".join('<option value="' + esc(n) + '">' + esc(n) + '</option>' for n in sorted(COMP))
    _ctrs = ""
    for (_nm, _c) in _rank[:8]:
        _ctrs += ('<tr><td><b>' + esc(_nm) + '</b></td><td>' + ("Yes" if _c["da"] else "No") + '</td><td>' +
                  ("-" if _c["steps"] is None else str(_c["steps"])) + '</td><td>' + str(_c["users"]) +
                  '</td><td>' + str(_c["groups"]) + '</td></tr>')
    comp_html = ('<div class="card sim-card"><div class="simtitle">Compromise Simulator</div>'
                 '<p class="simnote">Pick any account and see what falls if it is phished or its password leaks - '
                 'computed from the same permissions as the paths below.</p>'
                 '<select id="compSel" class="sbox" onchange="compShow()">' + _copts + '</select>'
                 '<div class="compout" id="compOut"></div>'
                 + (('<h3 class="subh">Most dangerous accounts if compromised</h3>'
                     '<table class="dtable"><tr><th>Account</th><th>Reaches DA</th><th>Steps to DA</th>'
                     '<th>Accounts reachable</th><th>Groups reachable</th></tr>' + _ctrs + '</table>') if _ctrs else '')
                 + '</div>')
else:
    comp_html = ""

_dom_label = next(iter(_domain_labels), "the domain (Domain Admin level)")
_med = {}
_mnodes = {}
def _madd(lbl):
    if lbl not in _mnodes:
        _mnodes[lbl] = node_type(lbl)
_flat_paths = sorted([p for v in all_paths.values() for p in v], key=len)[:25]
for _steps in _flat_paths:
    for (_frm, _kind, _to, _t, _r, _f) in _steps:
        _med[(_frm, _to)] = _kind
        _madd(_frm)
        _madd(_to)
for _nm in already_priv[:25]:
    _u = next((x for x in _D.get("users", []) if x.get("name") == _nm), None)
    if not _u:
        continue
    _madd(_nm)
    for _gdn in _u.get("member_of", []):
        _gn = _gname_by_dn.get(_gdn)
        if _gn in _tz_names:
            _med[(_nm, _gn)] = "MemberOf"
            _madd(_gn)
            _med[(_gn, _dom_label)] = "TierZero"
            _madd(_dom_label)
_mdepth = {_dom_label: 0}
for _ in range(len(_mnodes) + 1):
    for (_a, _b) in _med:
        if _b in _mdepth:
            _nd = _mdepth[_b] + 1
            if _nd < _mdepth.get(_a, 99):
                _mdepth[_a] = _nd
_maxd = max(_mdepth.values()) if _mdepth else 0
_nlist = sorted(_mnodes)
_nidx = {lbl: i for i, lbl in enumerate(_nlist)}
MAP = {"nodes": [{"i": _nidx[lbl], "label": lbl, "type": _mnodes[lbl], "depth": _mdepth.get(lbl, _maxd + 1)} for lbl in _nlist],
       "edges": [{"a": _nidx[a], "b": _nidx[b], "kind": KIND_LABELS.get(k, k)} for (a, b), k in sorted(_med.items())]}
map_json = json.dumps(MAP)
if _mnodes:
    map_section = ('<h3 class="subh">Domain Privilege Map</h3><div class="card">'
                   '<p class="simnote">Every account and group sitting on a path to Domain Admin (25 shortest paths plus already-privileged accounts). '
                   'The domain sits on the right - the closer a circle is to it, the closer that account is to full control. Click a circle to light up its routes; hover a line to see the permission.</p>'
                   '<svg id="dommap" role="img" aria-label="Privilege map"></svg>'
                   '<div class="maplegend"><span class="dot du"></span> User &nbsp; <span class="dot dg"></span> Group &nbsp; <span class="dot dd"></span> Domain</div></div>')
else:
    map_section = ""

sf_options = '<option value="ALL">All accounts</option>' + "".join(
    '<option value="' + esc(n) + '">' + esc(n) + '</option>' for (n, _s) in reaching)

if reaching:
    explorer = ('<div class="explorer"><div class="side">'
                '<input id="chainSearch" class="sbox" type="text" placeholder="Search account..." onkeyup="filterChains()">'
                '<select id="startFrom" class="sbox" onchange="filterChains()">' + sf_options + '</select>' +
                side_items +
                '<div class="sidenote">Click an account to see every path it has to Domain Admin - use the Path buttons to switch between them. Tick Fixed as you remediate; the Fix Simulator above updates live.</div>'
                '</div><div class="mainpanel">' + panels + '</div></div>')
else:
    explorer = '<div class="card"><p>No account outside the admin groups can reach Domain Admin through the permissions collected.</p></div>'

# ---- Privileged-group paths: the BloodHound-style widened view ----
# The DA numbers above stay exact; this separate panel shows accounts
# whose best route ends at a privileged group (Tier 1/2 Admins, operator
# groups, local-admin groups) instead of Domain Admin, plus accounts
# that simply sit inside such a group. Nothing here is double-counted
# into the Tier Zero figures.
try:
    from paths import find_all_reachability as _far
    _ga, _gr, _gpaths = _far(_D)
except Exception:
    _ga, _gr, _gpaths = [], [], {}
_gp_rows = []
for _n, _ps in _gpaths.items():
    if _n in all_paths:
        continue  # has a DA path - already in the Explorer above
    _best = min(_ps, key=len)
    _chain = esc(_best[0][0])
    for (_f, _k, _t, _x, _r, _fx) in _best:
        _chain += ' -[' + esc(_k) + ']-&gt; ' + esc(_t)
    _gp_rows.append((len(_best), -len(_ps), _n, _best[-1][2], _chain))
_gp_rows.sort()
_gp_members = [n for n in _ga if n not in already_priv]
group_paths_html = ""
if _gp_rows or _gp_members:
    group_paths_html = ('<h3 class="subh">Paths to Privileged Groups (BloodHound-style)</h3>'
                        '<div class="card"><p class="simnote">These accounts cannot reach Domain Admin directly, '
                        'but they can reach a group that is privileged in its own right - a local-admin group, '
                        'an operator group, or a Tier 1/2 admin group. BloodHound counts these as attack paths; '
                        'so do we, listed separately so the Domain Admin figures above stay exact.</p>')
    if _gp_members:
        _shown = ", ".join(esc(n) for n in _gp_members[:25])
        if len(_gp_members) > 25:
            _shown += ' and ' + str(len(_gp_members) - 25) + ' more'
        group_paths_html += ('<p><b>' + str(len(_gp_members)) +
                             ' account(s) are members of a privileged group:</b> ' + _shown + '</p>')
    if _gp_rows:
        group_paths_html += ('<table><tr><th>Account</th><th>Reaches</th><th>Steps</th><th>Paths</th><th>Shortest route</th></tr>')
        for (_ln, _np, _n, _tgt, _chain) in _gp_rows[:75]:
            group_paths_html += ('<tr><td><b>' + esc(_n) + '</b></td><td>' + esc(_tgt) + '</td><td>' +
                                 str(_ln) + '</td><td>' + str(-_np) + '</td><td>' + _chain + '</td></tr>')
        group_paths_html += '</table>'
        if len(_gp_rows) > 75:
            group_paths_html += ('<p>Showing the 75 shortest of ' + str(len(_gp_rows)) + ' accounts.</p>')
    group_paths_html += '</div>'

tab2 = ('<h2 style="margin-top:6px">Privilege Paths</h2>' + tab2_kpis + cut_html + sim_html + comp_html +
        '<h3 class="subh">Tier Zero - already at Domain Admin level (' + str(len(already_priv)) + ')</h3>' + tierzero +
        map_section + '<h3 class="subh">Path Explorer</h3>' + explorer + group_paths_html)


header = ('<div class="header"><div><h1>Active Directory Security Report</h1>'
          '<div class="date">' + _dt.now().strftime("%d %B %Y, %H:%M") + '</div></div>'
          '<div class="grade" style="background:' + GRADE_COLORS[grade] + '">Risk: ' + grade + '</div></div>')

tabbar = ('<div class="tabbar"><button class="tabbtn active" onclick="showTab(\'t1\', this)">Findings</button>'
          '<button class="tabbtn" onclick="showTab(\'t2\', this)">Privilege Paths (' + str(len(reaching)) + ')</button></div>')

tab1 = ('<div id="t1" class="tabpage">'
        '<h2 id="summary">Executive Summary</h2><div class="card">' + summary + '</div>'
        '<h2 id="quick">Quick Wins - fix these first (big impact, easy to fix)</h2><div class="card quick-card">' +
        ("".join(finding_html(r) for r in quick) or "<p>None.</p>") + '</div>'
        '<h2>MITRE ATT&amp;CK Coverage</h2>' + mitre_html + '<p class="folded">Exports saved next to this report: <b>attack_layer.json</b> (open it in the MITRE ATT&amp;CK Navigator to see these techniques as a heat layer) and <b>detection_pack.md</b> (what to monitor for each technique).</p>' + '<h2 id="findings">All Findings (worst first)</h2>' + "".join(finding_html(r) for r in fails) +
        '<h2 id="fixplan">Fix Plan - do these in this order</h2>' + fixplan + '<p class="folded">A ready-to-review PowerShell version of this plan was saved as <b>remediation.ps1</b> next to this report. Every command in it runs in -WhatIf mode until you remove that flag yourself.</p>' + (('<h2>Remediation Roadmap - biggest impact first</h2>' + optimizer_html) if optimizer_html else '') + '<h2 id="profiles">Account Risk Profiles</h2>' + profiles + '<h2>GPO Summary</h2>' + gpo_table + '<h2>AD CS Template Summary</h2>' + cs_table + (('<h2>Password Policy What-If</h2>' + whatif_html) if whatif_html else '') + '</div>')




tab2page = '<div id="t2" class="tabpage" style="display:none">' + tab2 + '</div>'

script = ('<script>function showTab(id, btn){'
          'document.querySelectorAll(\'.tabpage\').forEach(function(p){p.style.display=\'none\'});'
          'document.getElementById(id).style.display=\'block\';'
          'document.querySelectorAll(\'.tabbtn\').forEach(function(b){b.classList.remove(\'active\')});'
          'btn.classList.add(\'active\');}'
          'function showChain(i, el){'
          'document.querySelectorAll(\'.chainpanel\').forEach(function(p){p.style.display=\'none\'});'
          'var p=document.getElementById(\'cp\'+i); if(p){p.style.display=\'block\';}'
          'document.querySelectorAll(\'.sideitem\').forEach(function(b){b.classList.remove(\'active\')});'
          'if(el){el.classList.add(\'active\');}}'
          'function filterChains(){'
          'var q=document.getElementById(\'chainSearch\').value.toLowerCase();'
          'var sf=document.getElementById(\'startFrom\').value; var first=-1;'
          'document.querySelectorAll(\'.sideitem\').forEach(function(b){'
          'var nm=b.getAttribute(\'data-name\').toLowerCase();'
          'var ok=(nm.indexOf(q)>=0)&&((sf===\'ALL\')||(nm===sf.toLowerCase()));'
          'b.style.display=ok?\'block\':\'none\'; if(ok&&first<0){first=b.getAttribute(\'data-idx\');}});'
          'if(first>=0){showChain(first, document.querySelector(\'.sideitem[data-idx="\'+first+\'"]\'));}}'
          'function updProgressDiv(d){'
          'var boxes=d.querySelectorAll(\'.fixbox\'); var done=0;'
          'boxes.forEach(function(b){if(b.checked){done++;}});'
          'var pct=boxes.length?Math.round(100*done/boxes.length):0;'
          'var bar=d.querySelector(\'.progbar\'); if(bar){bar.style.width=pct+\'%\';}'
          'var txt=d.querySelector(\'.progtxt\'); if(txt){txt.textContent=\'Fix progress: \'+done+\' of \'+boxes.length+(done===boxes.length&&boxes.length>0?\' - path closed\':\'\');}}'
          'function showPath(i, j, el){'
          'var panel=document.getElementById(\'cp\'+i); if(!panel){return;}'
          'panel.querySelectorAll(\'.pathdiv\').forEach(function(d){d.style.display=\'none\';});'
          'var d=document.getElementById(\'pd\'+i+\'_\'+j); if(d){d.style.display=\'block\';}'
          'panel.querySelectorAll(\'.pathchip\').forEach(function(c){c.classList.remove(\'active\');});'
          'if(el){el.classList.add(\'active\');}}'
          'var SIM=' + sim_json + ';'
          'var COMP=' + comp_json + ';'
          'var MAP=' + map_json + ';'
          'function fixChanged(el){'
          'var k=el.getAttribute(\'data-key\');'
          'document.querySelectorAll(\'.fixbox\').forEach(function(b){if(b.getAttribute(\'data-key\')===k){b.checked=el.checked;}});'
          'document.querySelectorAll(\'.pathdiv\').forEach(function(d){updProgressDiv(d);});'
          'simRecalc();}'
          'function simRecalc(){'
          'if(!SIM||!SIM.chains||!document.getElementById(\'simReach\')){return;}'
          'var checked={};'
          'document.querySelectorAll(\'.fixbox\').forEach(function(b){if(b.checked){checked[b.getAttribute(\'data-key\')]=true;}});'
          'var openPaths=0; var reach={};'
          'SIM.chains.forEach(function(c){var blocked=false;'
          'c.keys.forEach(function(k){if(checked[k]){blocked=true;}});'
          'if(!blocked){openPaths++; reach[c.start]=true;}});'
          'var byFinding={};'
          'Object.keys(SIM.stepFindings).forEach(function(k){SIM.stepFindings[k].forEach(function(f){(byFinding[f]=byFinding[f]||[]).push(k);});});'
          'var saved=0;'
          'Object.keys(byFinding).forEach(function(f){var ks=byFinding[f];'
          'if(ks.length>0&&ks.every(function(k){return checked[k];})){saved+=(SIM.weights[f]||0);}});'
          'document.getElementById(\'simReach\').textContent=Object.keys(reach).length;'
          'document.getElementById(\'simPaths\').textContent=openPaths;'
          'document.getElementById(\'simScore\').textContent=SIM.base-saved;}'
          'function compShow(){'
          'var sel=document.getElementById(\'compSel\'); var out=document.getElementById(\'compOut\');'
          'if(!sel||!out){return;} var c=COMP[sel.value]; if(!c){out.textContent=\'\'; return;}'
          'var msg;'
          'if(c.da&&c.steps===0){msg=sel.value+\' is ALREADY at Domain Admin level. If this account falls, the whole domain falls with it.\';}'
          'else if(c.da){msg=sel.value+\' reaches Domain Admin in \'+c.steps+\' step(s). Along the way it can reach \'+c.users+\' other account(s) and \'+c.groups+\' group(s).\';}'
          'else{msg=sel.value+\' does not reach Domain Admin through the permissions collected. Blast radius: \'+c.users+\' account(s) and \'+c.groups+\' group(s) reachable.\';}'
          'out.textContent=msg;}'
          'function buildMap(){'
          'var svg=document.getElementById(\'dommap\'); if(!svg||!MAP||!MAP.nodes.length){return;}'
          'var NS=\'http://www.w3.org/2000/svg\';'
          'var cols={}; MAP.nodes.forEach(function(n){(cols[n.depth]=cols[n.depth]||[]).push(n);});'
          'var depths=Object.keys(cols).map(Number); var maxD=Math.max.apply(null,depths);'
          'var maxCol=0; depths.forEach(function(d){if(cols[d].length>maxCol){maxCol=cols[d].length;}});'
          'var H=maxCol*58+34; var W=880;'
          'svg.setAttribute(\'viewBox\',\'0 0 \'+W+\' \'+H);'
          'var pos={};'
          'depths.forEach(function(d){var x=W-76-d*((W-150)/Math.max(maxD,1));'
          'var arr=cols[d].slice().sort(function(p,q){return p.label<q.label?-1:1;});'
          'arr.forEach(function(n,i){pos[n.i]=[x,30+i*58];});});'
          'MAP.edges.forEach(function(e){var p=pos[e.a],q=pos[e.b]; if(!p||!q){return;}'
          'var ln=document.createElementNS(NS,\'line\');'
          'ln.setAttribute(\'x1\',p[0]); ln.setAttribute(\'y1\',p[1]); ln.setAttribute(\'x2\',q[0]); ln.setAttribute(\'y2\',q[1]);'
          'ln.setAttribute(\'class\',\'mapedge\'); ln.setAttribute(\'data-a\',e.a); ln.setAttribute(\'data-b\',e.b);'
          'var tt=document.createElementNS(NS,\'title\'); tt.textContent=e.kind; ln.appendChild(tt); svg.appendChild(ln);});'
          'MAP.nodes.forEach(function(n){var p=pos[n.i]; if(!p){return;}'
          'var g=document.createElementNS(NS,\'g\'); g.setAttribute(\'class\',\'mapnode\'); g.setAttribute(\'data-i\',n.i);'
          'var c=document.createElementNS(NS,\'circle\'); c.setAttribute(\'cx\',p[0]); c.setAttribute(\'cy\',p[1]); c.setAttribute(\'r\',13);'
          'c.setAttribute(\'class\',\'npc \'+n.type); g.appendChild(c);'
          'var t=document.createElementNS(NS,\'text\'); t.setAttribute(\'x\',p[0]); t.setAttribute(\'y\',p[1]+30);'
          't.setAttribute(\'text-anchor\',\'middle\'); t.setAttribute(\'class\',\'npt\');'
          't.textContent=n.label.length>24?n.label.substring(0,23)+\'...\':n.label; g.appendChild(t);'
          'g.addEventListener(\'click\',function(){mapHi(n.i);}); svg.appendChild(g);});}'
          'function mapHi(i){'
          'var cur=document.querySelector(\'.mapnode.sel\'); var was=cur&&cur.getAttribute(\'data-i\')==String(i);'
          'document.querySelectorAll(\'.mapnode\').forEach(function(g){g.classList.remove(\'sel\');});'
          'document.querySelectorAll(\'.mapedge\').forEach(function(l){l.classList.remove(\'on\');});'
          'if(was){return;}'
          'var g=document.querySelector(\'.mapnode[data-i="\'+i+\'"]\'); if(g){g.classList.add(\'sel\');}'
          'document.querySelectorAll(\'.mapedge\').forEach(function(l){'
          'if(l.getAttribute(\'data-a\')==String(i)||l.getAttribute(\'data-b\')==String(i)){l.classList.add(\'on\');}});}'
          'buildMap(); compShow();'
          '</script>')


html = """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>AD Security Report</title>
<style>
* { box-sizing: border-box; }
html { scroll-behavior: smooth; }
body { font-family: -apple-system, "Segoe UI", Roboto, Arial, sans-serif; margin: 0; background: #f2f4f7; color: #263238; -webkit-print-color-adjust: exact; print-color-adjust: exact; }
.wrap { max-width: 920px; margin: 0 auto; padding: 28px 18px 40px; }
.header { display: flex; justify-content: space-between; align-items: center; background: #263238; color: #fff; border-radius: 12px; padding: 22px 24px; }
.header h1 { margin: 0; font-size: 24px; letter-spacing: .01em; }
.header .date { opacity: .7; font-size: 13px; margin-top: 4px; }
.grade { font-weight: 700; padding: 8px 18px; border-radius: 999px; font-size: 14px; white-space: nowrap; }
.tabbar { display: flex; gap: 8px; margin: 16px 0 4px; }
.tabbtn { border: 1px solid #cfd8dc; background: #fff; border-radius: 999px; padding: 8px 20px; font-size: 14px; font-weight: 600; cursor: pointer; color: #37474f; }
.tabbtn.active { background: #263238; color: #fff; border-color: #263238; }
.kpis { display: flex; gap: 12px; flex-wrap: wrap; margin-top: 12px; }
.kpi { flex: 1 1 100px; background: #fff; border: 1px solid #e3e6ea; border-radius: 10px; padding: 14px 10px; text-align: center; }
.kpi .num { font-size: 26px; font-weight: 700; }
.kpi .lbl { font-size: 11px; color: #78909c; text-transform: uppercase; letter-spacing: .06em; margin-top: 2px; }
.num.green { color: #2e7d32; } .num.red { color: #b00020; } .num.orange { color: #e65100; }
h2 { font-size: 18px; margin: 30px 0 12px; padding-bottom: 6px; border-bottom: 2px solid #263238; }
.subh { font-size: 15px; margin: 22px 0 8px; }
.card { background: #fff; border: 1px solid #e3e6ea; border-radius: 10px; padding: 16px 18px; }
.card.quick-card { background: #eef7ee; border-color: #b9dcb9; }
.card.cut-card { background: #fff8e1; border-color: #ffe082; margin-top: 12px; }
.card.sim-card { background: #eef4fb; border-color: #bcd3ee; margin-top: 12px; }
.simtitle { font-weight: 700; font-size: 15px; }
.simnote { font-size: 12.5px; color: #455a64; margin: 4px 0 10px; }
.compout { margin-top: 10px; font-size: 14px; font-weight: 600; color: #263238; }
.pathchips { display: flex; gap: 6px; flex-wrap: wrap; margin: 8px 0 4px; }
.pathchip { border: 1px solid #b0bec5; background: #fff; border-radius: 999px; padding: 4px 12px; font-size: 12px; font-weight: 600; cursor: pointer; color: #37474f; }
.pathchip.active { background: #263238; color: #fff; border-color: #263238; }
#dommap { width: 100%; height: auto; }
.mapedge { stroke: #c3ced4; stroke-width: 1.5; }
.mapedge.on { stroke: #b00020; stroke-width: 3; }
.npc { fill: #90a4ae; stroke: #fff; stroke-width: 2; }
.npc.USER { fill: #1e88e5; } .npc.GROUP { fill: #8e24aa; } .npc.DOMAIN { fill: #263238; }
.mapnode { cursor: pointer; }
.mapnode.sel circle { stroke: #b00020; stroke-width: 3.5; }
.npt { font-size: 10.5px; fill: #37474f; }
.maplegend { font-size: 12px; color: #607d8b; margin-top: 6px; }
.dot { display: inline-block; width: 10px; height: 10px; border-radius: 50%; vertical-align: middle; }
.dot.du { background: #1e88e5; } .dot.dg { background: #8e24aa; } .dot.dd { background: #263238; }
.sevtable { border-collapse: collapse; margin: 10px 0; }
.sevtable th, .sevtable td { text-align: left; padding: 5px 18px 5px 0; font-size: 14px; }
.dot-sev { display: inline-block; width: 10px; height: 10px; border-radius: 50%; margin-right: 8px; }
.sev { color: #fff; padding: 2px 9px; border-radius: 999px; font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: .04em; }
.critical { background: #b00020; } .high { background: #e65100; } .medium { background: #f9a825; color: #263238; } .low { background: #607d8b; }
.finding { background: #fff; border: 1px solid #e3e6ea; border-left: 4px solid #90a4ae; border-radius: 8px; padding: 12px 14px; margin: 10px 0; }
.fl-critical { border-left-color: #b00020; } .fl-high { border-left-color: #e65100; } .fl-medium { border-left-color: #f9a825; } .fl-low { border-left-color: #607d8b; }
.fhead { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
.fid { font-weight: 700; color: #37474f; }
.ftitle { font-weight: 600; }
.finding ul { margin: 8px 0 0 18px; color: #455a64; }
.chain { background: #fff; border: 1px solid #e3e6ea; border-radius: 8px; padding: 14px 16px; margin: 10px 0; }
.chain-head { font-size: 15px; margin-bottom: 6px; }
.pdiagram { display: flex; flex-direction: column; align-items: center; padding: 12px 0 4px; }
.pnode { border: 2px solid #90a4ae; border-radius: 10px; padding: 8px 18px; background: #fff; text-align: center; min-width: 230px; }
.pnode .ptag { display: block; font-size: 10px; letter-spacing: .08em; color: #78909c; font-weight: 700; }
.pnode .pname { font-weight: 700; }
.t-user { border-color: #42a5f5; } .t-group { border-color: #ab47bc; }
.t-domain { border-color: #263238; background: #263238; color: #fff; } .t-domain .ptag { color: #b0bec5; }
.parrow { display: flex; flex-direction: column; align-items: center; color: #546e7a; padding: 3px 0; }
.plink { font-size: 12px; background: #eceff1; border-radius: 999px; padding: 2px 12px; }
.parr { font-size: 16px; line-height: 1.1; }
.ptable { border-collapse: collapse; width: 100%; margin-top: 12px; font-size: 14px; }
.ptable th, .ptable td { border: 1px solid #e3e6ea; padding: 7px 9px; text-align: left; vertical-align: top; }
.ptable th { background: #f5f7f9; }
.chip { display: inline-block; background: #eceff1; border: 1px solid #cfd8dc; border-radius: 999px; padding: 2px 10px; font-size: 12px; margin: 2px 4px 2px 0; }
.tzrow { padding: 6px 0; border-bottom: 1px solid #f0f0f0; }
.tzrow:last-child { border-bottom: none; }
.foot { margin-top: 34px; font-size: 12px; color: #90a4ae; text-align: center; }
.explorer { display: flex; gap: 14px; align-items: flex-start; }
.side { flex: 0 0 250px; background: #fff; border: 1px solid #e3e6ea; border-radius: 10px; padding: 12px; }
.sbox { width: 100%; padding: 7px 9px; margin-bottom: 8px; border: 1px solid #cfd8dc; border-radius: 8px; font-size: 13px; }
.sideitem { display: block; width: 100%; text-align: left; background: #f7f9fa; border: 1px solid #e3e6ea; border-radius: 8px; padding: 8px 10px; margin-bottom: 8px; cursor: pointer; font-size: 13px; color: #37474f; }
.sideitem.active { background: #263238; color: #fff; border-color: #263238; }
.sidenote { font-size: 12px; color: #78909c; margin-top: 4px; }
.mainpanel { flex: 1; min-width: 0; }
.chainpanel { background: #fff; border: 1px solid #e3e6ea; border-radius: 8px; padding: 14px 16px; }
.stepcard { border: 1px solid #e3e6ea; border-left: 4px solid #90a4ae; border-radius: 8px; padding: 10px 12px; margin-top: 10px; }
.schead { font-size: 12px; font-weight: 700; text-transform: uppercase; letter-spacing: .05em; color: #607d8b; margin-bottom: 4px; }
.rf { margin-top: 3px; font-size: 14px; color: #546e7a; }
.tag { font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: .05em; }
.tag.risk { color: #b00020; } .tag.fix { color: #2e7d32; } .tag.verify { color: #1565c0; }
.fixrow { display: block; margin-top: 8px; font-size: 13px; font-weight: 600; color: #37474f; cursor: pointer; }
.progwrap { background: #eceff1; border-radius: 999px; height: 10px; margin-top: 12px; overflow: hidden; }
.progbar { background: #2e7d32; height: 10px; width: 0; border-radius: 999px; }
.progtxt { font-size: 12px; color: #607d8b; margin-top: 4px; }
.raised { font-size: 11px; color: #b00020; font-weight: 700; }
.mapline { font-size: 11px; color: #607d8b; margin: 2px 0 4px; }
.dtable { font-size: 12.5px; }
.dtable td, .dtable th { padding: 5px 8px; }
.dtable tr:nth-child(even) td { background: #f7f9fa; }
.mitre { font-size: 11px; color: #78909c; font-weight: 600; }
.pfacts { margin: 2px 0 0; font-size: 12.5px; color: #37474f; }
.folded { font-size: 12px; color: #607d8b; }


@media print { body { background: #fff; } .tabbar { display: none; } .tabpage { display: block !important; } .explorer { display: block; } .side { display: none; } .chainpanel { display: block !important; margin-bottom: 12px; } .pathdiv { display: block !important; } .pathchips { display: none; } .finding, .card, .chain, .kpi { break-inside: avoid; } }
</style></head><body><div class="wrap">
""" + header + kpis + tabbar + tab1 + tab2page + """
<p class="foot">Generated from collected domain data. Counts are computed from the scan results, not typed by hand.</p>
</div>""" + script + """</body></html>"""
with open("report.html", "w") as f:
    f.write(html)
print("Saved: findings.json, findings.csv, report.html")

with open("report.html", "w") as f:
    f.write(html)
print("Saved: findings.json, findings.csv, report.html")

