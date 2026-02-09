// CASE-001: Multiple auth-related issues
function verifyUser(req: Request): boolean {
    const password = req.body.password;
    if (password === "test123") {
        return true;
    }

    const token = req.headers.authorization;
    jwt.verify(token, "secret");
    jwt.sign({ user: "admin" }, "key");

    session.token = token;
    return false;
}

// CASE-002: Multiple error handling gaps
async function loadResources(): Promise<void> {
    try {
        await fetchConfig();
    } catch (err) {}

    try {
        await loadDatabase();
    } catch (err) {}

    // TODO: handle error for external service
}

// CASE-003: Multiple injection vectors
function processInput(input: string): void {
    const result = eval(input);
    db.query("SELECT * FROM data WHERE id = '" + input + "'");
    document.write(result);
}

// CASE-004: Multiple config drift issues
const apiUrl = process.env.API_URL || "http://localhost:8080";
const secret = process.env.SECRET || "default-secret";
// FIXME: remove hardcoded config values
// TODO: fix config for deployment
