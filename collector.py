import argparse, json, os
from ldap3 import Server, Connection, ALL, NTLM

p = argparse.ArgumentParser()
p.add_argument("--dc", required=True, help="IP address or name of the DC")
p.add_argument("--user", required=True, help="e.g. DOMAIN\\user")
p.add_argument("--password", required=True)
p.add_argument("--skip-remote", action="store_true",
               help="Skip per-machine RPC collection (local admins, RDP users, sessions)")
args = p.parse_args()

server = Server(args.dc, get_info=ALL)
conn = Connection(server, user=args.user, password=args.password,
                  authentication=NTLM, auto_bind=True)
BASE = conn.server.info.other["defaultNamingContext"][0]
CONFIG = conn.server.info.other["configurationNamingContext"][0]
print("Connected. Base DN:", BASE)

from datetime import datetime, timedelta, timezone

def sid_to_str(val):
    # Convert objectSid (raw bytes) into the readable "S-1-5-21-..." form
    if val is None:
        return ""
    if isinstance(val, str):
        return val
    b = bytes(val)
    rev, count = b[0], b[1]
    auth = int.from_bytes(b[2:8], "big")
    parts = ["S", str(rev), str(auth)]
    for i in range(count):
        parts.append(str(int.from_bytes(b[8 + i * 4:12 + i * 4], "little")))
    return "-".join(parts)


def filetime(ft):
    ft = first(ft)
    if ft is None:
        return None
    if isinstance(ft, datetime):     # ldap3 already produced a datetime — leave it as is
        return ft
    ft = int(ft)
    if ft == 0 or ft == 9223372036854775807:
        return None                  # 0 or the maximum value = "never"
    return datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=ft / 10)

def has_flag(uac, flag):
    return bool(int(uac) & flag)

def first(v):
    if isinstance(v, list):
        return v[0] if v else None
    return v

def as_list(v):
    if v is None:
        return []
    if isinstance(v, list):
        return v
    return [v]

# Key flags to remember:
DISABLED        = 0x2        # account is disabled
NEVER_EXPIRES   = 0x10000    # password never expires
PREAUTH_NOT_REQ = 0x400000   # AS-REP roastable!
UNCONSTRAINED   = 0x80000    # unconstrained delegation

def search_all(base, filter_str, attrs):
    results = conn.extend.standard.paged_search(
        base, filter_str, attributes=attrs, paged_size=500)
    return [e for e in results if e.get("type") == "searchResEntry"]

# ---------- Domain info + password policy ----------
dom_entry = search_all(BASE, "(objectClass=domain)",
      ["minPwdLength", "maxPwdAge", "pwdProperties", "minPwdAge", "pwdHistoryLength", "lockoutThreshold", "msDS-Behavior-Version", "gPLink",
       "pwdHistoryLength", "ms-DS-MachineAccountQuota", "objectSid"])[0]
dom_a = dom_entry.get("attributes") or {}

mpa = first(dom_a.get("maxPwdAge"))
if isinstance(mpa, timedelta):
    max_age_days = abs(mpa.days)
elif mpa is None:
    max_age_days = None
else:
    max_age_days = round(abs(int(mpa)) / 864000000000, 1)

ld = first(dom_a.get("lockoutDuration"))
if isinstance(ld, timedelta):
    lockout_min = abs(int(ld.total_seconds())) // 60
else:
    lockout_min = None

    domain = {}
for e in search_all(BASE, "(objectClass=domainDNS)",
                    ["minPwdLength", "maxPwdAge", "lockoutThreshold",
                     "lockoutDuration", "minPwdAge", "pwdHistoryLength",
                     "pwdProperties", "ms-DS-MachineAccountQuota",
                     "msDS-Behavior-Version", "gPLink"]):
    a = e.get("attributes")
    if a is None:
        continue
    max_age = first(a.get("maxPwdAge"))
    lock_dur = first(a.get("lockoutDuration"))
    min_age = first(a.get("minPwdAge"))
    domain = {
        "functional_level": int(first(a.get("msDS-Behavior-Version")) or 0),
        "gp_link": first(a.get("gPLink")) or "",
        "base_dn": BASE,
        "min_pwd_length": int(first(a.get("minPwdLength")) or 0),
        "max_pwd_age_days": max_age.days if hasattr(max_age, "days") else None,
        "lockout_threshold": int(first(a.get("lockoutThreshold")) or 0),
        "lockout_duration_min": (lock_dur.total_seconds() / 60) if hasattr(lock_dur, "total_seconds") else None,
        "machine_account_quota": int(first(a.get("ms-DS-MachineAccountQuota")) or 0),
        "pwd_properties": int(first(a.get("pwdProperties")) or 0),
        "pwd_history": int(first(a.get("pwdHistoryLength")) or 0),
        "pwd_history_length": int(first(a.get("pwdHistoryLength")) or 0),
        "min_pwd_age_days": min_age.days if hasattr(min_age, "days") else None,
    }
    break

# ---------- AD CS ----------
cert_templates = []
for e in search_all(CONFIG, "(objectClass=pKICertificateTemplate)",
                    ["cn", "pKIExtendedKeyUsage", "distinguishedName", "msPKI-Certificate-Name-Flag",
                     "msPKI-Enrollment-Flag", "msPKI-RA-Signature", "msPKI-Certificate-Policy",
                     "msPKI-Template-Schema-Version", "msPKI-Private-Key-Flag", "msPKI-Minimal-Key-Size"]):
    a = e.get("attributes")
    if a is None:
        continue
    cert_templates.append({
        "name": first(a.get("cn")),
        "eku": as_list(a.get("pKIExtendedKeyUsage")),
        "dn": first(a.get("distinguishedName")),
        "exportable": bool(int(first(a.get("msPKI-Private-Key-Flag")) or 0) & 0x10),
        "name_flag": int(first(a.get("msPKI-Certificate-Name-Flag")) or 0),
        "enroll_flag": int(first(a.get("msPKI-Enrollment-Flag")) or 0),
        "ra_signature": int(first(a.get("msPKI-RA-Signature")) or 0),
        "schema_version": int(first(a.get("msPKI-Template-Schema-Version")) or 0),
        "min_key_size": int(first(a.get("msPKI-Minimal-Key-Size")) or 0),
        "cert_policies": as_list(a.get("msPKI-Certificate-Policy")),
    })
print("Cert Templates:", len(cert_templates))

cas = []
for e in search_all(CONFIG, "(objectClass=pKIEnrollmentService)",
                    ["cn", "dNSHostName", "msPKI-Enrollment-Servers", "distinguishedName", "certificateTemplates"]):
    a = e.get("attributes")
    if a is None:
        continue
    cas.append({"name": first(a.get("cn")),
                "enrollment_servers": as_list(a.get("msPKI-Enrollment-Servers")),
                "dn": first(a.get("distinguishedName")),
                "host": first(a.get("dNSHostName")),
                "published": as_list(a.get("certificateTemplates"))})
print("CAs:", len(cas))


# ---------- Issuance policy OID links (for ESC13) ----------
oid_links = []
for e in search_all(CONFIG, "(objectClass=msPKI-Enterprise-Oid)",
                    ["cn", "displayName", "msDS-OIDToGroupLink", "distinguishedName"]):
    a = e.get("attributes")
    if a is None:
        continue
    link = first(a.get("msDS-OIDToGroupLink"))
    if link:
        oid_links.append({
            "oid": first(a.get("cn")),
            "name": first(a.get("displayName")) or "",
            "group_dn": link,
            "dn": first(a.get("distinguishedName")),
        })
print("OID group links:", len(oid_links))


# ---------- OUs ----------
ous = []
for e in search_all(BASE, "(objectClass=organizationalUnit)",
                    ["name", "distinguishedName", "gPLink"]):
    a = e.get("attributes")
    if a is None:
        continue
    ous.append({"name": first(a.get("name")),
                "dn": first(a.get("distinguishedName")),
                "gp_link": first(a.get("gPLink")) or ""})
print("OUs:", len(ous))

# ---------- Sites / Subnets ----------
sites = []
for e in search_all(CONFIG, "(objectClass=site)", ["cn"]):
    a = e.get("attributes")
    if a is None:
        continue
    sites.append({"name": first(a.get("cn"))})
print("Sites:", len(sites))

subnets = []
for e in search_all(CONFIG, "(objectClass=subnet)", ["cn"]):
    a = e.get("attributes")
    if a is None:
        continue
    subnets.append({"name": first(a.get("cn"))})
print("Subnets:", len(subnets))

# ---------- Recycle Bin + Tombstone ----------
recycle_bin_enabled = False
for e in search_all(CONFIG, "(objectClass=msDS-OptionalFeature)",
                    ["cn", "msDS-EnabledFeatureBL"]):
    a = e.get("attributes")
    if a is None:
        continue
    if "recycle" in (first(a.get("cn")) or "").lower() and a.get("msDS-EnabledFeatureBL"):
        recycle_bin_enabled = True

tombstone_days = None
for e in search_all("CN=Directory Service,CN=Windows NT,CN=Services," + CONFIG,
                    "(objectClass=*)", ["tombstoneLifetime"]):
    a = e.get("attributes")
    if a is None:
        continue
    tombstone_days = int(first(a.get("tombstoneLifetime")) or 0)

# ---------- FSMO roles ----------
SCHEMA = conn.server.info.other["schemaNamingContext"][0]

def fsmo_of(base, filt):
    for e in search_all(base, filt, ["fSMORoleOwner"]):
        a = e.get("attributes")
        if a and a.get("fSMORoleOwner"):
            parts = (first(a.get("fSMORoleOwner")) or "").split(",")
            if len(parts) > 1:
                return parts[1].replace("CN=", "")
    return None

fsmo = {
    "PDC Emulator":       fsmo_of(BASE, "(objectClass=domainDNS)"),
    "RID Master":         fsmo_of(BASE, "(objectClass=rIDManager)"),
    "Infrastructure":     fsmo_of(BASE, "(objectClass=infrastructureUpdate)"),
    "Schema Master":      fsmo_of(SCHEMA, "(objectClass=dMD)"),
    "Domain Naming":      fsmo_of(CONFIG, "(&(objectClass=crossRefContainer)(cn=Partitions))"),
}

# ---------- GPOs ----------
gpos = []
for e in search_all(BASE, "(objectClass=groupPolicyContainer)",
                    ["displayName", "distinguishedName"]):
    a = e.get("attributes")
    if a is None:
        continue
    gpos.append({"name": first(a.get("displayName")),
                 "dn": first(a.get("distinguishedName"))})
print("GPOs:", len(gpos))

# ---------- Trusts ----------
trusts = []
for e in search_all("CN=System," + BASE, "(objectClass=trustedDomain)",
                    ["trustPartner", "trustDirection", "trustAttributes"]):
    a = e.get("attributes")
    if a is None:
        continue
    trusts.append({"partner": first(a.get("trustPartner")),
                   "direction": int(first(a.get("trustDirection")) or 0),
                   "attributes": int(first(a.get("trustAttributes")) or 0)})
print("Trusts:", len(trusts))


# ---------- Users ----------
users = []
for e in search_all(BASE, "(&(objectClass=user)(objectCategory=person))",
        ["sAMAccountName", "msDS-KeyCredentialLink", "objectSid", "ms-DS-ConsistencyGuid", "distinguishedName", "userAccountControl", "pwdLastSet",
         "lastLogonTimestamp", "servicePrincipalName", "adminCount", "sIDHistory",
         "memberOf", "msDS-AllowedToDelegateTo", "description", "msDS-SupportedEncryptionTypes", "userPrincipalName", "whenCreated", "altSecurityIdentities"]):
    a = e.get("attributes")
    if a is None:
        continue
    uac = int(first(a.get("userAccountControl")) or 0)
    users.append({
    "name": first(a.get("sAMAccountName")),
    "uac": uac,
    "key_cred_count": len(as_list(a.get("msDS-KeyCredentialLink"))),
    "description": first(a.get("description")) or "",
    "enc_types": first(a.get("msDS-SupportedEncryptionTypes")),
    "sid": sid_to_str(first(a.get("objectSid"))),
    "upn": first(a.get("userPrincipalName")),
    "sid_history": as_list(a.get("sIDHistory")),
    "synced": bool(a.get("ms-DS-ConsistencyGuid")),
    "enabled": not has_flag(uac, DISABLED),
    "delegate_to": as_list(a.get("msDS-AllowedToDelegateTo")),
    "pwd_set": str(filetime(a.get("pwdLastSet"))),
    "last_logon": str(filetime(a.get("lastLogonTimestamp"))),
    "spns": as_list(a.get("servicePrincipalName")),
    "admin_count": int(first(a.get("adminCount")) or 0),
    "dn": first(a.get("distinguishedName")),
    "member_of": as_list(a.get("memberOf")),
    "alt_sec_identities": as_list(a.get("altSecurityIdentities")),
})
print("Users:", len(users))

# ---------- Password Settings Objects (PSO) ----------
psos = []
for e in search_all("CN=Password Settings Container,CN=System," + BASE,
                    "(objectClass=msDS-PasswordSettings)",
                    ["cn", "msDS-MinimumPasswordLength", "msDS-PSOAppliesTo"]):
    a = e.get("attributes")
    if a is None:
        continue
    psos.append({"name": first(a.get("cn")),
                 "min_length": int(first(a.get("msDS-MinimumPasswordLength")) or 0),
                 "applies_to": as_list(a.get("msDS-PSOAppliesTo"))})
print("PSOs:", len(psos))


# ---------- Groups ----------
groups = []
for e in search_all(BASE, "(objectClass=group)",
                    ["sAMAccountName", "distinguishedName", "member", "objectSid"]):
    a = e.get("attributes")
    if a is None:
        continue
    groups.append({"name": first(a.get("sAMAccountName")),
               "members": as_list(a.get("member")),
               "sid": str(first(a.get("objectSid"))),
               "dn": first(a.get("distinguishedName")),
               })
print("Groups:", len(groups))

def by_rid(rid):
    return [g for g in groups if g["sid"].endswith("-" + str(rid))]

da_group = by_rid(512)   # Domain Admins — present in every AD, in every language
if da_group:
    print("Domain Admins members:", len(da_group[0]["members"]))
else:
    print("Domain Admins group not found — check the SID-based lookup")

# ---------- Computers ----------
computers = []
for e in search_all(BASE, "(objectClass=computer)",
        ["sAMAccountName", "objectSid", "distinguishedName", "pwdLastSet", "msDS-AllowedToDelegateTo",
         "operatingSystem", "description", "msDS-SupportedEncryptionTypes", "userAccountControl", "lastLogonTimestamp", "altSecurityIdentities", "dNSHostName"]):
    a = e.get("attributes")
    if a is None:
        continue
    uac = int(first(a.get("userAccountControl")) or 0)
    computers.append({
        "dn": first(a.get("distinguishedName")),
        "uac": uac,
        "description": first(a.get("description")) or "",
        "enc_types": first(a.get("msDS-SupportedEncryptionTypes")),
        "sid": sid_to_str(first(a.get("objectSid"))),
        "pwd_set": str(filetime(a.get("pwdLastSet"))),
        "delegate_to": as_list(a.get("msDS-AllowedToDelegateTo")),
        "name": first(a.get("sAMAccountName")),
        "os": first(a.get("operatingSystem")),
        "is_dc": has_flag(uac, 0x2000),
        "last_logon": str(filetime(a.get("lastLogonTimestamp"))),
        "alt_sec_identities": as_list(a.get("altSecurityIdentities")),
        "host": first(a.get("dNSHostName")),
        # Filled by the remote-collection phase below (empty when a
        # machine cannot be reached - the fields always exist).
        "local_admins": [],
        "rdp_users": [],
        "sessions": [],
    })
print("Computers:", len(computers))


# ---------- Remote collection: what LDAP cannot see ----------
# Local admin membership, RDP membership and live sessions live on each
# machine, not in the directory - SharpHound asks the machines directly
# over RPC, and so do we (impacket). Best effort by design: a machine
# that is off, firewalled or access-denied is skipped and counted,
# never fatal, and its three fields simply stay empty.
# One-time setup on the machine running this collector:
#     pip install impacket
_user_sid_by_name = {}
for _u in users:
    if _u.get("name") and _u.get("sid"):
        _user_sid_by_name[str(_u["name"]).upper()] = _u["sid"]
_domain_dns = ".".join(x.split("=")[1] for x in BASE.split(",") if x.upper().startswith("DC="))

def _rpc_dce(host, pipe, uuid, cred):
    from impacket.dcerpc.v5 import transport
    rpc = transport.SMBTransport(host, filename=pipe, username=cred[0],
                                 password=cred[1], domain=cred[2], remote_host=host)
    dce = rpc.get_dce_rpc()
    dce.set_timeout(6)
    dce.connect()
    dce.bind(uuid)
    return dce

def _alias_sids(host, cred, alias_rid):
    # Members of a local group (alias) in the machine's Builtin domain:
    # 544 = Administrators, 555 = Remote Desktop Users.
    from impacket.dcerpc.v5 import samr
    dce = _rpc_dce(host, r"\samr", samr.MSRPC_UUID_SAMR, cred)
    try:
        srv = samr.hSamrConnect(dce)["ServerHandle"]
        dom = samr.hSamrLookupDomainInSamServer(dce, srv, "Builtin")["DomainId"]
        dh = samr.hSamrOpenDomain(dce, serverHandle=srv, domainId=dom)["DomainHandle"]
        ah = samr.hSamrOpenAlias(dce, dh, aliasId=alias_rid)["AliasHandle"]
        resp = samr.hSamrGetMembersInAlias(dce, ah)
        return sorted({m["SidPointer"].formatCanonical() for m in resp["Members"]["Sids"]})
    finally:
        try: dce.disconnect()
        except Exception: pass

def _session_sids(host, cred):
    # Who is on this machine: SMB sessions (srvsvc) + logged-on users
    # (wkssvc), mapped from usernames to directory SIDs.
    from impacket.dcerpc.v5 import srvs, wkst
    from impacket.dcerpc.v5.rpcrt import DCERPCException
    names = set()
    try:
        dce = _rpc_dce(host, r"\srvsvc", srvs.MSRPC_UUID_SRVS, cred)
        try:
            try:
                resp = srvs.hNetrSessionEnum(dce, None, None, 10)
            except DCERPCException as e:
                if "STATUS_MORE_ENTRIES" not in str(e): raise
                resp = e.get_packet()
            for ent in resp["InfoStruct"]["SessionInfo"]["Level10"]["Entries"]:
                if ent["sesi10_username"]:
                    names.add(str(ent["sesi10_username"]))
        finally:
            try: dce.disconnect()
            except Exception: pass
    except Exception:
        pass
    try:
        dce = _rpc_dce(host, r"\wkssvc", wkst.MSRPC_UUID_WKST, cred)
        try:
            try:
                resp = wkst.hNetrWkstaUserEnum(dce, 1)
            except DCERPCException as e:
                if "STATUS_MORE_ENTRIES" not in str(e): raise
                resp = e.get_packet()
            for ent in resp["UserInfo"]["Level1"]["Entries"]:
                if ent["wkui1_username"]:
                    names.add(str(ent["wkui1_username"]))
        finally:
            try: dce.disconnect()
            except Exception: pass
    except Exception:
        pass
    out = set()
    for n in names:
        if not n or n.endswith("$") or n.upper() == "GUEST":
            continue
        s = _user_sid_by_name.get(n.upper())
        if s:
            out.add(s)
    return sorted(out)

if args.skip_remote:
    print("Remote collection: skipped (--skip-remote)")
else:
    try:
        import impacket  # noqa: F401
        _have_impacket = True
    except ImportError:
        _have_impacket = False
    if not _have_impacket:
        print("Remote collection: impacket is not installed, so local admins,")
        print("  RDP users and sessions were NOT collected. Install once with:")
        print("      pip install impacket")
        print("  then re-run this collector (or pass --skip-remote to silence).")
    else:
        _raw_user = args.user.replace("/", "\\")
        if "\\" in _raw_user:
            _cred_dom, _cred_user = _raw_user.split("\\", 1)
        elif "@" in _raw_user:
            _cred_user, _cred_dom = _raw_user.split("@", 1)
        else:
            _cred_user, _cred_dom = _raw_user, _domain_dns
        _cred = (_cred_user, args.password, _cred_dom)
        _answered = 0
        for _c in computers:
            _host = _c.get("host") or ((_c.get("name") or "").rstrip("$") + "." + _domain_dns)
            if not _host:
                continue
            try:
                _c["local_admins"] = _alias_sids(_host, _cred, 544)
                _c["rdp_users"] = _alias_sids(_host, _cred, 555)
                _c["sessions"] = _session_sids(_host, _cred)
                _answered += 1
            except Exception:
                pass  # off / firewalled / access denied - fields stay empty
        print(f"Remote collection: {_answered}/{len(computers)} machines answered "
              "(local admins, RDP users, sessions)")



# ---------- Reading ACLs (permissions) ----------
import uuid
from ldap3.protocol.microsoft import security_descriptor_control

def get_sd(dn):
    # Without the SD-flags control, the DC returns only part of the permissions — this control asks for "only the DACL"
    try:
        ok = conn.search(dn, "(objectClass=*)", search_scope=0,
                         attributes=["nTSecurityDescriptor"],
                         controls=security_descriptor_control(sdflags=0x04))
        if ok and conn.entries:
            vals = conn.entries[0].entry_attributes_as_dict.get("nTSecurityDescriptor")
            if vals:
                return vals[0]
    except Exception:
        return None
    return None

def parse_sid(b, off):
    rev, count = b[off], b[off + 1]
    auth = int.from_bytes(b[off + 2:off + 8], "big")
    parts = ["S", str(rev), str(auth)]
    for i in range(count):
        parts.append(str(int.from_bytes(b[off + 8 + i * 4:off + 12 + i * 4], "little")))
    return "-".join(parts)

def parse_acl(sd):
    # Find the DACL inside the binary security descriptor and read each ACE (permission entry)
    if not sd:
        return []
    dacl_off = int.from_bytes(sd[16:20], "little")
    if dacl_off == 0:
        return []
    ace_count = int.from_bytes(sd[dacl_off + 4:dacl_off + 6], "little")
    pos = dacl_off + 8
    out = []
    for _ in range(ace_count):
        ace_type = sd[pos]
        ace_size = int.from_bytes(sd[pos + 2:pos + 4], "little")
        if ace_type in (0, 5):   # 0 = simple permission, 5 = permission carrying a specific right (extended right)
            mask = int.from_bytes(sd[pos + 4:pos + 8], "little")
            obj_types = []
            sid_off = pos + 8
            if ace_type == 5:
                flags = int.from_bytes(sd[pos + 8:pos + 12], "little")
                sid_off = pos + 12
                if flags & 1:
                    obj_types.append(str(uuid.UUID(bytes_le=sd[sid_off:sid_off + 16])))
                    sid_off += 16
                if flags & 2:
                    sid_off += 16
            out.append({"sid": parse_sid(sd, sid_off), "mask": mask,
                        "object_types": obj_types})
        pos += ace_size
    return out

domain_acl = parse_acl(get_sd(BASE))
adminsdholder_acl = parse_acl(get_sd("CN=AdminSDHolder,CN=System," + BASE))
print("Domain ACL entries:", len(domain_acl))

gpo_acls = {}
for g in gpos:
    if g.get("dn"):
        gpo_acls[g["name"]] = parse_acl(get_sd(g["dn"]))
print("GPO ACLs:", len(gpo_acls))

user_acls = {}
for u in users:
    if u.get("admin_count") == 1 and u.get("dn"):
        user_acls[u["name"]] = parse_acl(get_sd(u["dn"]))
print("Privileged user ACLs:", len(user_acls))

group_acls = {}
for g in groups:
    rid = (g.get("sid") or "").rsplit("-", 1)[-1]
    if rid in ("512", "518", "519", "548", "549", "550", "551") and g.get("dn"):
        group_acls[g["name"]] = parse_acl(get_sd(g["dn"]))
print("Privileged group ACLs:", len(group_acls))

template_acls = {}
for t in cert_templates:
    if t.get("dn"):
        template_acls[t["name"]] = parse_acl(get_sd(t["dn"]))
print("Template ACLs:", len(template_acls))

ca_acls = {}
for ca in cas:
    if ca.get("dn"):
        ca_acls[ca["name"]] = parse_acl(get_sd(ca["dn"]))
print("CA ACLs:", len(ca_acls))

# ---------- Print queues / gMSA / Forest level ----------
print_queues = []
for e in search_all(BASE, "(objectClass=printQueue)", ["cn", "serverName"]):
    a = e.get("attributes")
    if a is None:
        continue
    print_queues.append({"name": first(a.get("cn")),
                         "server": first(a.get("serverName")) or ""})
print("Print queues:", len(print_queues))

gmsa = []
for e in search_all(BASE, "(objectClass=msDS-GroupManagedServiceAccount)",
                    ["sAMAccountName"]):
    a = e.get("attributes")
    if a is None:
        continue
    gmsa.append({"name": first(a.get("sAMAccountName"))})
print("gMSA accounts:", len(gmsa))

forest_fl = 0
for e in search_all(CONFIG, "(objectClass=crossRefContainer)",
                    ["msDS-Behavior-Version"]):
    a = e.get("attributes")
    if a is None:
        continue
    forest_fl = int(first(a.get("msDS-Behavior-Version")) or 0)
    break


# Whether the LAPS marker exists in the schema
laps_schema = len(search_all(SCHEMA, "(lDAPDisplayName=ms-Mcs-AdmPwd)", ["cn"])) > 0

# ---------- Anonymous bind test ----------
anon_bind = False
try:
    c2 = Connection(server, user="", password="")
    if c2.bind():
        c2.search(BASE, "(objectClass=domainDNS)", attributes=["cn"])
        anon_bind = len(c2.entries) > 0
        c2.unbind()
except Exception:
    anon_bind = False
print("Anonymous bind works:", anon_bind)

# ---------- GPO content (reading files from SYSVOL) ----------
import subprocess, tempfile, re

def parse_inf(raw):
    if raw[:2] in (b"\xff\xfe", b"\xfe\xff"):
        text = raw.decode("utf-16", "replace")
    else:
        text = raw.decode("utf-8", "replace")
    out, section = {}, ""
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1].lower()
            out[section] = {}
        elif "=" in line and section:
            k, v = line.split("=", 1)
            out[section][k.strip().lower()] = v.strip()
    return out

def parse_pol(data):
    # Binary format of registry.pol: "PReg" followed by [key;value;type;size;data] entries
    out = {}
    if data[:4] != b"PReg":
        return out
    i, n = 8, len(data)
    def read_text(i):
        start = i
        while i + 1 < n and data[i + 1] == 0 and data[i] not in (0x3B, 0x5D):
            i += 2
        return data[start:i].decode("utf-16le", "replace"), i
    while i < n and data[i] == 0x5B:   # '['
        i += 2
        key, i = read_text(i); i += 2
        val, i = read_text(i); i += 2
        rtype = int.from_bytes(data[i:i + 4], "little"); i += 6
        size = int.from_bytes(data[i:i + 4], "little"); i += 6
        raw = data[i:i + size]; i += size + 2
        if rtype == 4 and size >= 4:
            out[key.lower() + "|" + val.lower()] = int.from_bytes(raw[:4], "little")
        elif rtype == 1:
            out[key.lower() + "|" + val.lower()] = raw.decode("utf-16le", "replace").strip("\x00")
    return out

domain_dns = ".".join(p.split("=")[1] for p in BASE.split(",") if p.startswith("DC="))
gpo_content = {}
tmp_root = tempfile.mkdtemp(prefix="gpo_")
for g in gpos:
    m = re.search(r"\{[0-9A-Fa-f\-]+\}", g.get("dn") or "")
    if not m:
        continue
    dest = os.path.join(tmp_root, m.group(0))
    os.makedirs(dest, exist_ok=True)
    try:
        subprocess.run(["smbclient", f"//{args.dc}/SYSVOL",
                        "-U", f"{args.user}%{args.password}",
                        "-c", f"cd {domain_dns}\\Policies\\{m.group(0)}; prompt OFF; recurse ON; mget *"],
                       cwd=dest, capture_output=True, timeout=120)
    except Exception:
        continue
    entry = {"sec": {}, "registry": {}, "cpassword": False, "scripts": [], "files": 0}
    for root, _dirs, fnames in os.walk(dest):
        for fn in fnames:
            full = os.path.join(root, fn)
            rel = os.path.relpath(full, dest).replace(os.sep, "/").lower()
            try:
                raw = open(full, "rb").read()
                entry["files"] += 1
            except Exception:
                continue
            if "cpassword" in raw.decode("utf-8", "replace"):
                entry["cpassword"] = True
            if rel.endswith("gpttmpl.inf"):
                entry["sec"] = parse_inf(raw)
            if rel.endswith("registry.pol"):
                entry["registry"].update(parse_pol(raw))
            if "/scripts/" in rel or fn.lower().endswith((".bat", ".cmd", ".ps1", ".vbs")):
                entry["scripts"].append(fn)
    if entry["files"]:
        gpo_content[g["name"]] = entry
print("GPO content read:", len(gpo_content), "of", len(gpos))



# ---------- Save ----------
data = {"domain": domain, "gpo_content": gpo_content, "users": users, "user_acls": user_acls, "group_acls": group_acls, "template_acls": template_acls, "ca_acls": ca_acls, "print_queues": print_queues, "gmsa": gmsa, "forest_fl": forest_fl, "groups": groups, "ous": ous, "gpos": gpos, "trusts": trusts,
        "computers": computers, "anon_bind": anon_bind, "cert_templates": cert_templates, "cas": cas, "psos": psos,
        "oid_links": oid_links, "sites": sites, "subnets": subnets, "fsmo": fsmo, "recycle_bin_enabled": recycle_bin_enabled,
        "tombstone_days": tombstone_days, "gpo_acls": gpo_acls, "domain_acl": domain_acl, "adminsdholder_acl": adminsdholder_acl, "laps_schema": laps_schema}
with open("collected.json", "w") as f:
    json.dump(data, f, indent=1, default=str)
print("Saved collected.json")