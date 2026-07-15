const express = require("express");
const Database = require("better-sqlite3");
const { nanoid } = require("nanoid");
const multer = require("multer");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const bcrypt = require("bcrypt");
const rateLimit = require("express-rate-limit");
const { ZipArchive } = require("archiver");

const BCRYPT_COST_FACTOR = 12;
const DOWNLOAD_TOKEN_SECRET = crypto.randomBytes(32);
const DOWNLOAD_TOKEN_TTL_MS = 5 * 60 * 1000; // 5 minutes
const GENERIC_INVALID_PASSWORD_MESSAGE = "Mot de passe invalide.";
const GENERIC_LINK_UNAVAILABLE_MESSAGE = "Ce lien n'est plus disponible.";
const ALLOWED_MAX_DOWNLOADS = [1, 5, 20];

// Returns one of ALLOWED_MAX_DOWNLOADS, or null for unlimited (also the
// fallback for missing/unrecognized input).
function parseMaxDownloads(value) {
    const parsed = Number(value);
    return ALLOWED_MAX_DOWNLOADS.includes(parsed) ? parsed : null;
}

// Used as a stand-in bcrypt.compare() target when there is nothing real to
// compare against, so the response time doesn't leak whether a file exists
// or is password-protected.
const DUMMY_BCRYPT_HASH = bcrypt.hashSync(crypto.randomBytes(32).toString("hex"), BCRYPT_COST_FACTOR);

function createDownloadToken(fileId) {
    const payload = JSON.stringify({ id: fileId, exp: Date.now() + DOWNLOAD_TOKEN_TTL_MS });
    const payloadB64 = Buffer.from(payload).toString("base64url");
    const signature = crypto.createHmac("sha256", DOWNLOAD_TOKEN_SECRET).update(payloadB64).digest("base64url");
    return `${payloadB64}.${signature}`;
}

function verifyDownloadToken(token, fileId) {
    if (!token || typeof token !== "string") return false;

    const parts = token.split(".");
    if (parts.length !== 2) return false;
    const [payloadB64, signature] = parts;

    const expectedSignature = crypto.createHmac("sha256", DOWNLOAD_TOKEN_SECRET).update(payloadB64).digest("base64url");
    const signatureBuf = Buffer.from(signature);
    const expectedBuf = Buffer.from(expectedSignature);
    if (signatureBuf.length !== expectedBuf.length || !crypto.timingSafeEqual(signatureBuf, expectedBuf)) {
        return false;
    }

    let payload;
    try {
        payload = JSON.parse(Buffer.from(payloadB64, "base64url").toString());
    } catch (err) {
        return false;
    }

    return payload.id === fileId && Date.now() <= payload.exp;
}

const db = new Database(path.join(__dirname, "database.db"));
const UPLOADS_DIR = path.join(__dirname, "uploads");

if (!fs.existsSync(UPLOADS_DIR)) {
    fs.mkdirSync(UPLOADS_DIR);
}

// Extensions that can execute code on the recipient's machine when opened.
// Based on the set Gmail blocks for attachments.
const DANGEROUS_EXTENSIONS = new Set([
    "exe", "dll", "com", "bat", "cmd", "msi", "msp", "msix", "msixbundle",
    "appx", "appxbundle", "scr", "ps1", "psc1", "psm1", "vb", "vbe", "vbs",
    "js", "jse", "wsf", "wsh", "hta", "cpl", "msc", "jar", "apk",
    "sh", "bash", "bin", "run", "out", "action", "workflow",
    "reg", "scf", "sct", "shb", "shs", "lnk", "pif", "vxd", "sys", "iso", "img"
]);

// Magic-byte signatures of executable/script formats, used to catch files
// that were renamed to hide their real type (e.g. malware.exe -> photo.jpg).
const EXECUTABLE_SIGNATURES = [
    { name: "Windows PE executable (.exe/.dll)", bytes: [0x4d, 0x5a] },
    { name: "ELF executable", bytes: [0x7f, 0x45, 0x4c, 0x46] },
    { name: "Mach-O executable", bytes: [0xfe, 0xed, 0xfa, 0xce] },
    { name: "Mach-O executable", bytes: [0xfe, 0xed, 0xfa, 0xcf] },
    { name: "Mach-O executable", bytes: [0xce, 0xfa, 0xed, 0xfe] },
    { name: "Mach-O executable", bytes: [0xcf, 0xfa, 0xed, 0xfe] },
    { name: "Mach-O universal binary / Java class", bytes: [0xca, 0xfe, 0xba, 0xbe] },
    { name: "shell script (shebang)", bytes: [0x23, 0x21] }
];

function matchesSignature(buffer, bytes) {
    if (buffer.length < bytes.length) return false;
    return bytes.every((byte, i) => buffer[i] === byte);
}

function detectExecutableSignature(buffer) {
    return EXECUTABLE_SIGNATURES.find((sig) => matchesSignature(buffer, sig.bytes)) || null;
}

function validateFile(filePath, originalname) {
    const ext = path.extname(originalname).slice(1).toLowerCase();

    if (DANGEROUS_EXTENSIONS.has(ext)) {
        return { valid: false, reason: `Files of type ".${ext}" are not allowed.` };
    }

    const header = Buffer.alloc(4);
    const fd = fs.openSync(filePath, "r");
    const bytesRead = fs.readSync(fd, header, 0, 4, 0);
    fs.closeSync(fd);

    const signature = detectExecutableSignature(header.subarray(0, bytesRead));
    if (signature) {
        return {
            valid: false,
            reason: `File content was identified as a ${signature.name}, which is not allowed.`
        };
    }

    return { valid: true };
}

async function createZip(files, zipPath) {
    return new Promise((resolve, reject) => {
        const output = fs.createWriteStream(zipPath);
        const archive = new ZipArchive({ zlib: { level: 9 } });

        output.on("close", () => resolve());
        archive.on("error", (err) => reject(err));

        archive.pipe(output);

        for (const file of files) {
            archive.file(file.path, { name: file.originalname });
        }

        archive.finalize();
    });
}

const MAX_FILE_SIZE = 5 * 1024 * 1024 * 1024; // 5 GB

const storage = multer.diskStorage({
    destination: UPLOADS_DIR,
    filename: (req, file, cb) => {
        const storedName = `${nanoid(16)}${path.extname(file.originalname)}`;
        cb(null, storedName);
    }
});

const upload = multer({
     storage,
     limits: { fileSize: MAX_FILE_SIZE }
});

db.prepare(`
CREATE TABLE IF NOT EXISTS files (
    id TEXT PRIMARY KEY,
    filename TEXT NOT NULL,
    stored_name TEXT NOT NULL,
    size INTEGER,
    created_at INTEGER,
    expires_at INTEGER,
    isZip INTEGER,
    password_hash TEXT,
    max_downloads INTEGER DEFAULT NULL,
    download_count INTEGER NOT NULL DEFAULT 0
)
`).run();

// Migrations for pre-existing databases created before these columns
// existed: add whichever ones are missing.
const existingColumns = db.prepare("PRAGMA table_info(files)").all().map((col) => col.name);
if (!existingColumns.includes("password_hash")) {
    db.prepare("ALTER TABLE files ADD COLUMN password_hash TEXT").run();
}
if (!existingColumns.includes("max_downloads")) {
    db.prepare("ALTER TABLE files ADD COLUMN max_downloads INTEGER DEFAULT NULL").run();
}
if (!existingColumns.includes("download_count")) {
    db.prepare("ALTER TABLE files ADD COLUMN download_count INTEGER NOT NULL DEFAULT 0").run();
}

const app = express();

app.use(express.static("public"));

const uploadLimiter = rateLimit({
    windowMs: 60 * 60 * 1000,
    max: 10,
    message: {
        error: "Too many uploads. Try again later."
    }
});

const verifyLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 20,
    message: {
        error: "Too many attempts. Try again later."
    }
});

// return page
app.get("/", (req, res) => {
    res.sendFile(__dirname + "/public/index.html");
});

app.get("/f/:id", (req, res) => {
    res.sendFile(__dirname + "/public/download.html");
});

// front-end API
app.get("/api/file-info/:id", (req, res) => {
    const file = db.prepare("SELECT * FROM files WHERE id = ?").get(req.params.id);

    if (!file) {
        return res.status(404).send("File not found.");
    }
    if (Date.now() > file.expires_at) {
        return res.status(410).send("File has expired.");
    }

    res.json({
        filename: file.filename,
        size: file.size,
        expiresAt: file.expires_at,
        passwordProtected: Boolean(file.password_hash),
        downloadCount: file.download_count,
        maxDownloads: file.max_downloads,
        link: `/api/files/${file.id}`
    });
});

app.get("/api/files/:id", (req, res) => {
    const file = db.prepare("SELECT * FROM files WHERE id = ?").get(req.params.id);

    if (!file) {
        return res.status(404).json({ error: "File not found." });
    }

    if (Date.now() > file.expires_at) {
        return res.status(410).json({ error: "File has expired." });
    }

    if (file.max_downloads !== null && file.download_count >= file.max_downloads) {
        return res.status(410).json({ error: GENERIC_LINK_UNAVAILABLE_MESSAGE });
    }

    if (file.password_hash) {
        const token = req.query.token;
        if (!verifyDownloadToken(token, file.id)) {
            return res.status(401).json({ error: "Password verification required." });
        }
    }

    const filePath = path.join(UPLOADS_DIR, file.stored_name);
    if (!fs.existsSync(filePath)) {
        return res.status(500).json({ error: "Error sending file." });
    }

    // Increment atomically and re-check the limit in the same statement, so
    // a file never ends up downloaded more than max_downloads times even
    // under concurrent requests racing the check above.
    const { changes } = db.prepare(`
        UPDATE files
        SET download_count = download_count + 1
        WHERE id = ? AND (max_downloads IS NULL OR download_count < max_downloads)
    `).run(file.id);

    if (changes === 0) {
        return res.status(410).json({ error: GENERIC_LINK_UNAVAILABLE_MESSAGE });
    }

    res.download(filePath, file.filename, (err) => {
    if (err) {
        return res.status(500).json({ error: "Error sending file." });
    }
});
});

app.post("/api/files/:id/verify", verifyLimiter, express.json(), async (req, res) => {
    const file = db.prepare("SELECT * FROM files WHERE id = ?").get(req.params.id);

    if (!file) {
        return res.status(404).json({ error: "File not found." });
    }

    if (Date.now() > file.expires_at) {
        return res.status(410).json({ error: "File has expired." });
    }

    const password = typeof req.body.password === "string" ? req.body.password : "";

    // Always run bcrypt.compare(), even when the file has no password set,
    // so response timing doesn't reveal whether a file is protected.
    const passwordMatches = await bcrypt.compare(password, file.password_hash || DUMMY_BCRYPT_HASH);
    const isValid = !file.password_hash || passwordMatches;

    if (!isValid) {
        return res.status(401).json({ error: GENERIC_INVALID_PASSWORD_MESSAGE });
    }

    res.json({
        success: true,
        token: createDownloadToken(file.id)
    });
});

app.post("/api/upload", uploadLimiter, upload.array("files"), async (req, res) => {
    if (!req.files || req.files.length === 0) {
        return res.status(400).json({ error: "No file uploaded." });
    }

    const invalidFiles = [];
    for (const file of req.files) {
        const result = validateFile(file.path, file.originalname);
        if (!result.valid) {
            invalidFiles.push({ filename: file.originalname, reason: result.reason });
        }
    }

    if (invalidFiles.length > 0) {
        for (const file of req.files) {
            fs.unlink(file.path, () => {});
        }
        return res.status(415).json({
            error: "One or more files failed validation.",
            details: invalidFiles
        });
    }

    let isZip = 0;
    let filename;
    let storedName;
    let size;
    const id = nanoid(8);
    const createdAt = Date.now();
    const expiresAt = createdAt + (24 * 60 * 60 * 1000);

    const password = typeof req.body.password === "string" ? req.body.password : "";
    const passwordHash = password ? await bcrypt.hash(password, BCRYPT_COST_FACTOR) : null;
    const maxDownloads = parseMaxDownloads(req.body.maxDownloads);

    if (req.files.length === 1) {
    filename = req.files[0].originalname;
    storedName = req.files[0].filename;
    size = req.files[0].size;
    } else {
    isZip = 1;

    const zipPath = path.join(UPLOADS_DIR, `${nanoid(16)}.zip`);

    await createZip(req.files, zipPath);

    filename = "archive.zip";
    storedName = path.basename(zipPath);
    size = fs.statSync(zipPath).size;

    for (const file of req.files) {
        fs.unlinkSync(file.path);
    }
    }

    db.prepare(`
        INSERT INTO files (id, filename, stored_name, size, created_at, expires_at, isZip, password_hash, max_downloads, download_count)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0)
    `).run(
        id,
        filename,
        storedName,
        size,
        createdAt,
        expiresAt,
        isZip,
        passwordHash,
        maxDownloads
    );

    const url = `${req.protocol}://${req.get("host")}/f/${id}`;

    res.json({
        success: true,
        url,
        expiresAt
    });
});

app.use((err, req, res, next) => {
    if (err instanceof multer.MulterError && err.code === "LIMIT_FILE_SIZE") {
        return res.status(413).json({
            error: "File is too large."
        });
    }

    next(err);
});

// Clear expired files
function clearExpiredFiles() {
    const timestamp = Date.now();
    const files = db.prepare("SELECT * FROM files WHERE expires_at < ?").all(timestamp)
    for (const file of files) {
        fs.unlink(
            path.join(UPLOADS_DIR, file.stored_name),
            (err) => {
                if (err) {
                    console.log(err)
                }
                db.prepare("DELETE FROM files WHERE id = ?").run(file.id);
            }
        )
    }
}

clearExpiredFiles();
setInterval(clearExpiredFiles, 60 * 60 * 1000);

app.listen(3000, () => {
    console.log("Server running on http://localhost:3000");
});
