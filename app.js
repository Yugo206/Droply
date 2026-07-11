const express = require("express");
const Database = require("better-sqlite3");
const db = new Database("database.db");
const { nanoid } = require("nanoid");
const multer = require("multer");
const path = require("path");
const fs = require("fs");
const { ZipArchive } = require("archiver");

if (!fs.existsSync("uploads")) {
    fs.mkdirSync("uploads");
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
    destination: "uploads/",
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
    isZip INTEGER
)
`).run();

const app = express();

app.use(express.static("public"));

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

    res.download(path.join(__dirname, "uploads", file.stored_name), file.filename, (err) => {
    if (err) {
        return res.status(500).json({ error: "Error sending file." });
    }
});
});

app.post("/api/upload", upload.array("files"), async (req, res) => {
    if (!req.files || req.files.length === 0) {
        return res.status(400).json({ error: "No file uploaded." });
    }

    let isZip = 0;
    let filename;
    let storedName;
    let size;
    const id = nanoid(8);
    const createdAt = Date.now();
    const expiresAt = createdAt + (24 * 60 * 60 * 1000);

    if (req.files.length === 1) {
    filename = req.files[0].originalname;
    storedName = req.files[0].filename;
    size = req.files[0].size;
    } else {
    isZip = 1;

    const zipPath = path.join("uploads", `${nanoid(16)}.zip`);

    await createZip(req.files, zipPath);

    filename = "archive.zip";
    storedName = path.basename(zipPath);
    size = fs.statSync(zipPath).size;

    for (const file of req.files) {
        fs.unlinkSync(file.path);
    }
    }

    db.prepare(`
        INSERT INTO files (id, filename, stored_name, size, created_at, expires_at, isZip)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run(
        id,
        filename,
        storedName,
        size,
        createdAt,
        expiresAt,
        isZip
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

app.listen(3000, () => {
    console.log("Server running on http://localhost:3000");
});