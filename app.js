const express = require("express");
const Database = require("better-sqlite3");
const db = new Database("database.db");
const { nanoid } = require("nanoid");

const id = nanoid(8);
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

// front-end API

app.post("/api/upload", (req, res) => {
    // handle file upload
});

app.listen(3000, () => {
    console.log("Server running on http://localhost:3000");
});