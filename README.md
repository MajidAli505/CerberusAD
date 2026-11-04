# CerberusAD

**Active Directory security assessment scanner** — named after Cerberus, the three-headed guard dog of the underworld, the same creature the Kerberos protocol itself is named after. CerberusAD stands at the gate of a domain and reports what is weak, what is dangerous, and what to fix first.

CerberusAD is a two-stage defensive scanner. A collector queries a Domain Controller **live** over LDAP (plus SYSVOL over SMB for GPO internals) and saves everything to one JSON file. An analyser then runs **163 security checks** against that data and produces a self-contained HTML report with a risk score, an ordered fix plan, and a privilege-reachability analysis.

It is domain-agnostic by design: the DC, credentials and base DN come from command-line arguments and auto-detection, and privileged groups are located by well-known RID rather than by name, so it runs unchanged against any domain.

## Highlights

- **163 checks in 6 groups** — Authentication (39), Privileged Access (32), Directory Services (36), Policy & Configuration (26), AD Certificate Services (22), Hybrid Identity (8). Every check reports PASS (clean), FAIL (weakness found, with the affected objects listed) or INFO.
- **Hand-written binary ACL parser** — security descriptors are parsed byte-by-byte to find hidden replication (DCSync) rights and dangerous permissions that name-based reviews miss.
- **Privilege reachability engine** — builds a permission graph (memberships, password-reset rights, group-write rights, replication rights, GPO edit rights, ESC1-style certificate paths) and computes which accounts can reach Domain Admin, how many steps away they are, and which single fix cuts the most paths.
- **GPO internals, not GPO names** — SYSVOL content is downloaded and parsed directly (GptTmpl.inf and registry.pol, with a hand-written PReg parser), so settings such as LDAP signing and LM authentication level are read from the files themselves. A GPO with an alarming name but empty content is correctly reported clean.
- **Contextual severity** — the same weakness scores higher on a privileged account than on a normal one (for example, password-like text in a Domain Admin's description is Critical, not Medium), with the original severity kept for audit.
- **Report that reads like an assessment** — risk score and grade, executive summary, Quick Wins, an ordered Fix Plan with a verification step for every fix, MITRE ATT&CK mapping, per-account risk profiles, GPO and AD CS summary tables, and an interactive privilege-path explorer.

## How it works

| File | Role |
|---|---|
| `collector.py` | Connects to the DC (LDAP, NTLM) and collects users, groups, computers, OUs, GPOs and their content, trusts, sites, AD CS templates and CAs, ACLs and policy data into `collected.json`. Runs fine as an ordinary domain user. |
| `checks.py` | Runs all 163 checks, prints the results, and writes `findings.json`, `findings.csv` and the full `report.html` (findings tab + privilege-paths tab). |
| `paths.py` | The reachability engine: who is already privileged, who can reach Domain Admin, and the shortest chain for each account — every step labelled with the permission, its risk, and its fix. |

## Usage

```bash
pip install ldap3        # plus smbclient on the system, for GPO content
python3 collector.py --dc <DC-IP-or-name> --user "DOMAIN\user" --password <password>
python3 checks.py        # checks + report.html
python3 paths.py         # reachability summary
```

Example console output:

```
Total: 163 checks | PASS: 74 | FAIL: 43 | INFO: 46
```

## Validation

CerberusAD was built and verified against a live lab domain. Among other results it correctly identified:

- two non-admin accounts holding full directory replication rights (a hidden DCSync path),
- a Domain Admin service account that was also the only Kerberoastable account, with its own password stored in its description field,
- an ESC1-style certificate template published on the CA.

It was also **break-and-detect tested**: weaknesses deliberately introduced into the lab (a new Domain Admin, AS-REP roasting enabled, a new SPN, a weakened GPO security setting, a dangerous ACL on the Domain Admins group) were each detected by the relevant check — and cleared after the change was reverted.

## Requirements

- Python 3.10+
- `ldap3`
- `smbclient` (used to read GPO content from SYSVOL)
- Any valid domain user account for collection

## Disclaimer

CerberusAD is a **defensive assessment tool** for lab environments and authorised security reviews. Use it only on systems you own or are explicitly authorised to assess.

---

*Built by [Majid Ali](https://github.com/MajidAli505) — cybersecurity student and aspiring penetration tester.*
