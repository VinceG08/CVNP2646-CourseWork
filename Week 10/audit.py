import json
from datetime import datetime, timedelta
from collections import defaultdict

# ----------------------
# LOAD DATA
# ----------------------
def load_json(filename):
    with open(filename, 'r') as f:
        return json.load(f)

users_data = load_json('users.json')
roles_data = load_json('roles.json')

# ----------------------
# BUILD LOOKUPS (O(1))
# ----------------------
users_dict = {u['user_id']: u for u in users_data}

roles_by_user = defaultdict(list)
for r in roles_data:
    roles_by_user[r['user_id']].append(r)

# ----------------------
# RULE 1: Disabled with Roles
# ----------------------
def check_disabled_with_roles():
    violations = []
    users_with_roles = {r['user_id'] for r in roles_data}

    for user_id, user in users_dict.items():
        if user['status'] == 'disabled' and user_id in users_with_roles:
            roles = [r['role'] for r in roles_by_user[user_id]]
            violations.append({
                'user_id': user_id,
                'username': user['username'],
                'violation_type': 'disabled_with_roles',
                'severity': 'CRITICAL',
                'details': f"Disabled user has roles: {', '.join(roles)}"
            })
    return violations

# ----------------------
# RULE 2: Unauthorized Admin
# ----------------------
def check_unauthorized_admin():
    violations = []
    allowed = {'IT', 'Security'}

    for r in roles_data:
        if 'admin' in r['role'].lower():
            user = users_dict.get(r['user_id'])
            if user and user['department'] not in allowed:
                violations.append({
                    'user_id': user['user_id'],
                    'username': user['username'],
                    'violation_type': 'unauthorized_admin',
                    'severity': 'HIGH',
                    'details': f"{user['department']} user has admin role: {r['role']}"
                })
    return violations

# ----------------------
# RULE 3: Stale Accounts
# ----------------------
def check_stale_accounts(days=90):
    violations = []
    cutoff = datetime.now() - timedelta(days=days)

    for user_id, user in users_dict.items():
        if user['status'] != 'active':
            continue

        last_login_str = user.get('last_login')

        if not last_login_str:
            violations.append({
                'user_id': user_id,
                'username': user['username'],
                'violation_type': 'stale_account',
                'severity': 'MEDIUM',
                'details': 'No login date recorded'
            })
            continue

        try:
            last_login = datetime.strptime(last_login_str, "%Y-%m-%d")
        except ValueError:
            continue

        if last_login < cutoff:
            days_inactive = (datetime.now() - last_login).days
            violations.append({
                'user_id': user_id,
                'username': user['username'],
                'violation_type': 'stale_account',
                'severity': 'MEDIUM',
                'details': f"No login for {days_inactive} days"
            })

    return violations

# ----------------------
# AI RULE 1: Conflicting Roles
# ----------------------
def check_conflicting_roles():
    violations = []

    for user_id, roles in roles_by_user.items():
        roles_lower = {r['role'].lower() for r in roles}
        if any('admin' in r for r in roles_lower) and any('audit' in r for r in roles_lower):
            violations.append({
                'user_id': user_id,
                'username': users_dict[user_id]['username'],
                'violation_type': 'conflicting_roles',
                'severity': 'CRITICAL',
                'details': 'User has both admin and auditor roles'
            })

    return violations

# ----------------------
# AI RULE 3: Excessive Roles
# ----------------------
def check_excessive_roles(threshold=3):
    violations = []
    for user_id, roles in roles_by_user.items():
        if len(roles) > threshold:
            violations.append({
                'user_id': user_id,
                'username': users_dict[user_id]['username'],
                'violation_type': 'excessive_roles',
                'severity': 'LOW',
                'details': f"{len(roles)} roles assigned"
            })
    return violations

# ----------------------
# REPORTING
# ----------------------
def generate_text_report(violations):
    severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
    violations.sort(key=lambda v: severity_order[v['severity']])

    # Summary counts
    severity_counts = {sev: 0 for sev in severity_order}
    for v in violations:
        severity_counts[v['severity']] += 1

    print("="*70)
    print("AUDIT REPORT")
    print("="*70)
    print(f"Generated: {datetime.now()}\n")

    print("VIOLATIONS SUMMARY BY SEVERITY")
    for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
        bar = "█" * severity_counts[sev]
        print(f"{sev:10s} [{severity_counts[sev]:3d}] {bar}")
    print("\nDETAILED VIOLATIONS\n")

    for v in violations:
        print(f"{v['user_id']} ({v['username']})")
        print(f"  Type: {v['violation_type']}")
        print(f"  Severity: {v['severity']}")
        print(f"  Details: {v['details']}\n")

    # Save text report
    with open("report.txt", "w") as f:
        f.write("="*70 + "\n")
        f.write("AUDIT REPORT\n")
        f.write("="*70 + "\n")
        f.write(f"Generated: {datetime.now()}\n\n")
        f.write("VIOLATIONS SUMMARY BY SEVERITY\n")
        for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            bar = "█" * severity_counts[sev]
            f.write(f"{sev:10s} [{severity_counts[sev]:3d}] {bar}\n")
        f.write("\nDETAILED VIOLATIONS\n")
        for v in violations:
            f.write(f"{v['user_id']} ({v['username']})\n")
            f.write(f"  Type: {v['violation_type']}\n")
            f.write(f"  Severity: {v['severity']}\n")
            f.write(f"  Details: {v['details']}\n\n")

# ----------------------
# RUN AUDIT
# ----------------------
all_violations = []
all_violations += check_disabled_with_roles()
all_violations += check_unauthorized_admin()
all_violations += check_stale_accounts()
all_violations += check_conflicting_roles()
all_violations += check_excessive_roles()

generate_text_report(all_violations)

print("Audit Complete")
print(f"Total Violations: {len(all_violations)}")