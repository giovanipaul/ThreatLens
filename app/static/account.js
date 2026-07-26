const csrfToken = document.cookie
    .split("; ")
    .find((item) => item.startsWith("threatlens_csrf="))
    ?.split("=")[1] || "";

async function request(url, options = {}) {
    options.headers = {
        "Content-Type": "application/json",
        "X-CSRF-Token": csrfToken,
        ...options.headers,
    };
    const response = await fetch(url, options);
    if (!response.ok) {
        const body = await response.json();
        throw new Error(body.detail || "Request failed.");
    }
    return response.status === 204 ? null : response.json();
}

document.querySelector("#password-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const message = document.querySelector("#password-message");
    try {
        await request("/api/account/password", {
            method: "POST",
            body: JSON.stringify(Object.fromEntries(form)),
        });
        message.textContent = "Password changed. Sign in again.";
        window.setTimeout(() => window.location.assign("/login"), 800);
    } catch (error) {
        message.textContent = error.message;
    }
});

const userForm = document.querySelector("#user-form");
if (userForm) {
    const table = document.querySelector("#users-table");
    const message = document.querySelector("#user-message");

    async function loadUsers() {
        const users = await request("/api/admin/users");
        table.replaceChildren();
        for (const user of users) {
            const row = document.createElement("tr");
            for (const value of [
                user.username,
                user.role,
                user.active ? "Active" : "Disabled",
            ]) {
                const cell = document.createElement("td");
                cell.textContent = value;
                row.append(cell);
            }
            const actions = document.createElement("td");
            const revoke = document.createElement("button");
            revoke.className = "table-action";
            revoke.textContent = "Revoke sessions";
            revoke.addEventListener("click", async () => {
                await request(`/api/admin/users/${user.id}/revoke-sessions`, {method: "POST"});
                message.textContent = `Revoked sessions for ${user.username}.`;
            });
            const toggle = document.createElement("button");
            toggle.className = "table-action";
            toggle.textContent = user.active ? "Disable" : "Enable";
            toggle.addEventListener("click", async () => {
                try {
                    await request(`/api/admin/users/${user.id}`, {
                        method: "PATCH",
                        body: JSON.stringify({active: !user.active}),
                    });
                    message.textContent = `${user.username} updated.`;
                    await loadUsers();
                } catch (error) {
                    message.textContent = error.message;
                }
            });
            const role = document.createElement("button");
            role.className = "table-action";
            role.textContent = user.role === "admin" ? "Make analyst" : "Make admin";
            role.addEventListener("click", async () => {
                try {
                    await request(`/api/admin/users/${user.id}`, {
                        method: "PATCH",
                        body: JSON.stringify({
                            role: user.role === "admin" ? "analyst" : "admin",
                        }),
                    });
                    message.textContent = `${user.username} updated.`;
                    await loadUsers();
                } catch (error) {
                    message.textContent = error.message;
                }
            });
            actions.append(role, toggle, revoke);
            row.append(actions);
            table.append(row);
        }
    }

    userForm.addEventListener("submit", async (event) => {
        event.preventDefault();
        const form = new FormData(userForm);
        try {
            await request("/api/admin/users", {
                method: "POST",
                body: JSON.stringify(Object.fromEntries(form)),
            });
            userForm.reset();
            message.textContent = "User created.";
            await loadUsers();
        } catch (error) {
            message.textContent = error.message;
        }
    });
    loadUsers();
}
