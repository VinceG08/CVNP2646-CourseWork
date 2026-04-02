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
# AI RULE 2: Orphaned Roles
# ----------------------
def check_orphaned_roles():
    violations = []

    for r in roles_data:
        if r['user_id'] not in users_dict:
            violations.append({
                'user_id': r['user_id'],
                'username': 'UNKNOWN',
                'violation_type': 'orphaned_role',
                'severity': 'HIGH',
                'details': f"Role {r['role']} has no matching user"
            })

    return violations

# ----------------------
# AI RULE 3: Excessive Permissions
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
def generate_json_report(violations):
    severity_counts = {}
    type_counts = {}

    for v in violations:
        severity_counts[v['severity']] = severity_counts.get(v['severity'], 0) + 1
        type_counts[v['violation_type']] = type_counts.get(v['violation_type'], 0) + 1

    report = {
        'audit_metadata': {
            'timestamp': datetime.now().isoformat(),
            'total_users_audited': len(users_dict),
            'total_role_assignments': len(roles_data),
            'total_violations': len(violations)
        },
        'violation_summary': {
            'by_severity': severity_counts,
            'by_type': type_counts
        },
        'all_violations': violations
    }

    with open('report.json', 'w') as f:
        json.dump(report, f, indent=4)

def generate_text_report(violations):
    severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
    violations.sort(key=lambda v: severity_order[v['severity']])

    lines = []
    lines.append("=" * 70)
    lines.append("AUDIT REPORT")
    lines.append("=" * 70)
    lines.append(f"Generated: {datetime.now()}\n")

    for v in violations:
        lines.append(f"{v['user_id']} ({v['username']})")
        lines.append(f"  Type: {v['violation_type']}")
        lines.append(f"  Severity: {v['severity']}")
        lines.append(f"  Details: {v['details']}\n")

    with open("report.txt", "w") as f:
        f.write("\n".join(lines))

# ----------------------
# RUN
# ----------------------
all_violations = []
all_violations += check_disabled_with_roles()
all_violations += check_unauthorized_admin()
all_violations += check_stale_accounts()
all_violations += check_conflicting_roles()
all_violations += check_orphaned_roles()
all_violations += check_excessive_roles()

generate_json_report(all_violations)
generate_text_report(all_violations)

print("Audit Complete")
print(f"Total Violations: {len(all_violations)}")