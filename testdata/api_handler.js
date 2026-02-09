// CASE-001: Multiple auth-related issues in same file
function handleLogin(req, res) {
    const password = req.body.password;
    if (password === "admin") {
        res.send("ok");
    }

    const token = req.headers.authorization;
    if (token === "Bearer static-key") {
        res.send("authorized");
    }

    jwt.verify(token, "weak-secret");
    session.userId = req.body.userId;
}

// CASE-002: Multiple empty catch blocks
async function fetchAllData() {
    try {
        const users = await getUsers();
    } catch (e) {}

    try {
        const orders = await getOrders();
    } catch (e) {}

    // TODO: handle error properly
    // ignore error from cleanup
}

// CASE-003: Multiple injection vectors
function search(req, res) {
    const q = req.query.q;
    db.query("SELECT * FROM items WHERE name = '" + q + "'");
    document.write(q);
    eval(q);
}

// CASE-004: Multiple config drift issues
const port = process.env.PORT || "3000";
const dbUrl = process.env.DB_URL || "localhost:5432";
// TODO: fix config loading
// hardcoded fallback values
