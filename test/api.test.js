// Backend integration tests, run against a real (throwaway) server instance.
// Isolated from the developer's real database.db/uploads via env vars set
// before app.js is required below.
process.env.PORT ??= "0";
process.env.DB_PATH ??= "test.db";
process.env.UPLOADS_DIR ??= "test-uploads";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const os = require("node:os");
const Database = require("better-sqlite3");

const { server } = require("../app");

const BASE_URL = `http://localhost:${server.address().port}`;
const DB_PATH = path.join(__dirname, "..", process.env.DB_PATH);

function tempFile(name, content) {
    const filePath = path.join(os.tmpdir(), `drova-test-${Date.now()}-${name}`);
    fs.writeFileSync(filePath, content);
    return filePath;
}

async function upload(filePaths, fields = {}) {
    const form = new FormData();
    for (const filePath of filePaths) {
        form.append("files", new Blob([fs.readFileSync(filePath)]), path.basename(filePath));
    }
    for (const [key, value] of Object.entries(fields)) {
        form.append(key, value);
    }
    const res = await fetch(`${BASE_URL}/api/upload`, { method: "POST", body: form });
    const data = await res.json();
    return { res, data };
}

function idFromUrl(url) {
    return url.split("/").pop();
}

function expire(id) {
    const db = new Database(DB_PATH);
    db.prepare("UPDATE files SET expires_at = ? WHERE id = ?").run(Date.now() - 1000, id);
    db.close();
}

test.after(() => {
    server.close();
    fs.rmSync(DB_PATH, { force: true });
    fs.rmSync(path.join(__dirname, "..", process.env.UPLOADS_DIR), { recursive: true, force: true });
});

test("single file upload and download round-trip", async () => {
    const file = tempFile("single.txt", "hello world");
    const { res, data } = await upload([file]);
    assert.equal(res.status, 200);
    assert.equal(data.success, true);
    assert.match(data.url, /^http:\/\/localhost:\d+\/f\/[\w-]+$/);

    const downloadRes = await fetch(`${BASE_URL}/api/files/${idFromUrl(data.url)}`);
    assert.equal(downloadRes.status, 200);
    assert.equal(await downloadRes.text(), "hello world");
});

test("multi-file upload is bundled into a downloadable ZIP", async () => {
    const f1 = tempFile("a.txt", "content a");
    const f2 = tempFile("b.txt", "content b");
    const { data } = await upload([f1, f2]);

    const downloadRes = await fetch(`${BASE_URL}/api/files/${idFromUrl(data.url)}`);
    assert.equal(downloadRes.status, 200);
    assert.equal(downloadRes.headers.get("content-disposition").includes("archive.zip"), true);

    const buffer = Buffer.from(await downloadRes.arrayBuffer());
    assert.equal(buffer.subarray(0, 4).toString("hex"), "504b0304"); // ZIP local file header magic
    assert.ok(buffer.length > 0);
});

test("file-info reports passwordProtected/downloadCount/maxDownloads", async () => {
    const file = tempFile("info.txt", "info");
    const { data } = await upload([file]);
    const id = idFromUrl(data.url);

    const info = await (await fetch(`${BASE_URL}/api/file-info/${id}`)).json();
    assert.equal(info.passwordProtected, false);
    assert.equal(info.maxDownloads, null);
    assert.equal(info.downloadCount, 0);

    await fetch(`${BASE_URL}/api/files/${id}`);
    const infoAfter = await (await fetch(`${BASE_URL}/api/file-info/${id}`)).json();
    assert.equal(infoAfter.downloadCount, 1);
});

test("nonexistent file returns 404 on both endpoints", async () => {
    assert.equal((await fetch(`${BASE_URL}/api/files/does-not-exist`)).status, 404);
    assert.equal((await fetch(`${BASE_URL}/api/file-info/does-not-exist`)).status, 404);
});

test("dangerous file extensions are rejected", async () => {
    const file = tempFile("payload.exe", "MZ fake executable");
    const { res, data } = await upload([file]);
    assert.equal(res.status, 415);
    assert.equal(data.details[0].filename, path.basename(file));
});

test("password-protected download requires verification", async () => {
    const file = tempFile("secret.txt", "top secret");
    const { data } = await upload([file], { password: "hunter2" });
    const id = idFromUrl(data.url);

    assert.equal((await fetch(`${BASE_URL}/api/files/${id}`)).status, 401);

    const wrong = await fetch(`${BASE_URL}/api/files/${id}/verify`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ password: "wrong" })
    });
    assert.equal(wrong.status, 401);
    assert.equal((await wrong.json()).error, "Mot de passe invalide.");

    const correct = await fetch(`${BASE_URL}/api/files/${id}/verify`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ password: "hunter2" })
    });
    assert.equal(correct.status, 200);
    const { token } = await correct.json();

    const downloadRes = await fetch(`${BASE_URL}/api/files/${id}?token=${token}`);
    assert.equal(downloadRes.status, 200);
    assert.equal(await downloadRes.text(), "top secret");
});

test("password token is scoped to its own file id", async () => {
    const fileA = tempFile("a.txt", "a");
    const fileB = tempFile("b.txt", "b");
    const { data: dataA } = await upload([fileA], { password: "pw-a" });
    const { data: dataB } = await upload([fileB], { password: "pw-b" });

    const verifyA = await fetch(`${BASE_URL}/api/files/${idFromUrl(dataA.url)}/verify`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ password: "pw-a" })
    });
    const { token } = await verifyA.json();

    const crossUse = await fetch(`${BASE_URL}/api/files/${idFromUrl(dataB.url)}?token=${token}`);
    assert.equal(crossUse.status, 401);
});

test("download limit blocks access once exhausted, without over-counting", async () => {
    const file = tempFile("limited.txt", "limited");
    const { data } = await upload([file], { maxDownloads: "1" });
    const id = idFromUrl(data.url);

    assert.equal((await fetch(`${BASE_URL}/api/files/${id}`)).status, 200);
    const second = await fetch(`${BASE_URL}/api/files/${id}`);
    assert.equal(second.status, 410);
    assert.equal((await second.json()).error, "Ce lien n'est plus disponible.");

    const info = await (await fetch(`${BASE_URL}/api/file-info/${id}`)).json();
    assert.equal(info.downloadCount, 1);
});

test("expired file is refused with the expiry message, not the limit message", async () => {
    const file = tempFile("expired.txt", "expired");
    const { data } = await upload([file], { maxDownloads: "5" });
    const id = idFromUrl(data.url);
    expire(id);

    const downloadRes = await fetch(`${BASE_URL}/api/files/${id}`);
    assert.equal(downloadRes.status, 410);
    assert.equal((await downloadRes.json()).error, "File has expired.");

    const infoRes = await fetch(`${BASE_URL}/api/file-info/${id}`);
    assert.equal(infoRes.status, 410);
});

test("combined ZIP + password + download limit share works end to end", async () => {
    const f1 = tempFile("combo1.txt", "combo1");
    const f2 = tempFile("combo2.txt", "combo2");
    const { data } = await upload([f1, f2], { password: "combo-pw", maxDownloads: "5" });
    const id = idFromUrl(data.url);

    const info = await (await fetch(`${BASE_URL}/api/file-info/${id}`)).json();
    assert.equal(info.passwordProtected, true);
    assert.equal(info.maxDownloads, 5);

    const verify = await fetch(`${BASE_URL}/api/files/${id}/verify`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ password: "combo-pw" })
    });
    const { token } = await verify.json();

    const downloadRes = await fetch(`${BASE_URL}/api/files/${id}?token=${token}`);
    assert.equal(downloadRes.status, 200);
});

test("static assets are served", async () => {
    assert.equal((await fetch(`${BASE_URL}/js/qrcode.js`)).status, 200);
    assert.equal((await fetch(`${BASE_URL}/css/style.css`)).status, 200);
    assert.equal((await fetch(`${BASE_URL}/`)).status, 200);
    assert.equal((await fetch(`${BASE_URL}/f/anything`)).status, 200);
});
