let users = [];
let roles = [];
let violations = [];

function readFile(file, callback) {
    const reader = new FileReader();
    reader.onload = e => callback(JSON.parse(e.target.result));
    reader.readAsText(file);
}

function runAudit() {
    const usersFile = document.getElementById("usersFile").files[0];
    const rolesFile = document.getElementById("rolesFile").files[0];

    readFile(usersFile, u => {
        users = u;
        readFile(rolesFile, r => {
            roles = r;
            auditLogic();
        });
    });
}

function auditLogic() {
    const usersDict = {};
    const rolesByUser = {};

    users.forEach(u => usersDict[u.user_id] = u);

    roles.forEach(r => {
        if (!rolesByUser[r.user_id]) rolesByUser[r.user_id] = [];
        rolesByUser[r.user_id].push(r.role);
    });

    violations = [];

    // Rule 1: Disabled with roles
    users.forEach(u => {
        if (u.status === "disabled" && rolesByUser[u.user_id]) {
            violations.push({
                user: u.username,
                type: "disabled_with_roles",
                severity: "CRITICAL",
                details: rolesByUser[u.user_id].join(", ")
            });
        }
    });

    // Rule 2: Unauthorized admin
    roles.forEach(r => {
        if (r.role.toLowerCase().includes("admin")) {
            let user = usersDict[r.user_id];
            if (user && !["IT", "Security"].includes(user.department)) {
                violations.push({
                    user: user.username,
                    type: "unauthorized_admin",
                    severity: "HIGH",
                    details: user.department
                });
            }
        }
    });

    renderTable();
    renderChart();
}

function renderTable() {
    const tbody = document.querySelector("#resultsTable tbody");
    tbody.innerHTML = "";

    violations.forEach(v => {
        let row = `<tr>
            <td>${v.user}</td>
            <td>${v.type}</td>
            <td>${v.severity}</td>
            <td>${v.details}</td>
        </tr>`;
        tbody.innerHTML += row;
    });
}

function renderChart() {
    const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };

    violations.forEach(v => counts[v.severity]++);

    new Chart(document.getElementById("severityChart"), {
        type: "bar",
        data: {
            labels: Object.keys(counts),
            datasets: [{
                label: "Violations",
                data: Object.values(counts),
                backgroundColor: ["red", "orange", "yellow", "green"]
            }]
        }
    });
}

function filterTable() {
    const filter = document.getElementById("filterInput").value.toLowerCase();
    const rows = document.querySelectorAll("#resultsTable tbody tr");

    rows.forEach(row => {
        row.style.display = row.innerText.toLowerCase().includes(filter)
            ? ""
            : "none";
    });
}

function exportCSV() {
    let csv = "User,Type,Severity,Details\n";

    violations.forEach(v => {
        csv += `${v.user},${v.type},${v.severity},${v.details}\n`;
    });

    const blob = new Blob([csv], { type: "text/csv" });
    const link = document.createElement("a");
    link.href = URL.createObjectURL(blob);
    link.download = "audit_report.csv";
    link.click();
}