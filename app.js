const express = require("express");
const Database = require("better-sqlite3");
const db = new Database("database.db");
const { nanoid } = require("nanoid");
const multer = require("multer");
const path = require("path");
const fs = require("fs");

if (!fs.existsSync("uploads")) {
    fs.mkdirSync("uploads");
}

const storage = multer.diskStorage({
    destination: "uploads/",
    filename: (req, file, cb) => {
        const storedName = `${nanoid(16)}${path.extname(file.originalname)}`;
        cb(null, storedName);
    }
});

const upload = multer({ storage });

db.prepare(`
CREATE TABLE IF NOT EXISTS files (
    id TEXT PRIMARY KEY,
    filename TEXT NOT NULL,
    stored_name TEXT NOT NULL,
    size INTEGER,
    created_at INTEGER,
    expires_at INTEGER
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

app.post("/api/upload", upload.single("file"), (req, res) => {
    if (!req.file) {
        return res.status(400).json({ error: "No file uploaded." });
    }

    const id = nanoid(8);
    const createdAt = Date.now();
    const expiresAt = createdAt + (24 * 60 * 60 * 1000);

    db.prepare(`
        INSERT INTO files (id, filename, stored_name, size, created_at, expires_at)
        VALUES (?, ?, ?, ?, ?, ?)
    `).run(
        id,
        req.file.originalname,
        req.file.filename,
        req.file.size,
        createdAt,
        expiresAt
    );

    res.json({
        success: true,
        url: `/f/${id}`,
        expiresAt
    });
});

app.listen(3000, () => {
    console.log("Server running on http://localhost:3000");
});