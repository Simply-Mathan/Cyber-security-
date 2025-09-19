const express = require("express");
const session = require("express-session");
const bodyParser = require("body-parser");
const sqlite3 = require("sqlite3").verbose();
const bcrypt = require("bcrypt");
const helmet = require("helmet");
const csurf = require("csurf");
const xss = require("xss");

const app = express();
const db = new sqlite3.Database("lab.db");

// 🔐 security middleware
app.use(helmet());
app.use(bodyParser.json());
app.use(
  session({
    secret: "keyboard cat",
    resave: false,
    saveUninitialized: true,
  })
);

const csrfProtection = csurf({ cookie: false });

// serve static files (frontend)
app.use(express.static("public"));

// ✅ safe login route
app.post("/api/login", (req, res) => {
  const { username, password } = req.body;
  db.get("SELECT * FROM users WHERE username = ?", [username], (err, user) => {
    if (err) return res.status(500).json({ error: err.message });
    if (!user)
      return res.status(401).json({ success: false, message: "User not found" });

    bcrypt.compare(password, user.password, (err, result) => {
      if (result) {
        req.session.user = user.username;
        res.json({ success: true, message: "Login successful" });
      } else {
        res.status(401).json({ success: false, message: "Invalid credentials" });
      }
    });
  });
});

// ❌ vulnerable search
app.post("/api/search-vuln", (req, res) => {
  const { q } = req.body;
  const query = `SELECT username FROM users WHERE username LIKE '%${q}%'`; // SQL injection risk
  db.all(query, [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

// ✅ safe search
app.post("/api/search-safe", (req, res) => {
  const { q } = req.body;
  db.all(
    "SELECT username FROM users WHERE username LIKE ?",
    [`%${q}%`],
    (err, rows) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json(rows);
    }
  );
});

// ❌ vulnerable comment
app.post("/api/comment-vuln", (req, res) => {
  const { username, comment } = req.body;
  db.run("INSERT INTO comments (username, comment) VALUES (?, ?)", [
    username,
    comment, // stored as-is
  ]);
  res.json({ success: true, message: "Comment stored (unsafe)" });
});

// ✅ safe comment
app.post("/api/comment-safe", (req, res) => {
  const { username, comment } = req.body;
  const safeComment = xss(comment); // sanitized
  db.run("INSERT INTO comments (username, comment) VALUES (?, ?)", [
    username,
    safeComment,
  ]);
  res.json({ success: true, message: "Comment stored safely" });
});

// fetch comments
app.get("/api/comments", (req, res) => {
  db.all("SELECT * FROM comments", [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

// CSRF demo
app.get("/api/csrf-token", csrfProtection, (req, res) => {
  res.json({ csrfToken: req.csrfToken() });
});

app.post("/api/protected-action", csrfProtection, (req, res) => {
  res.json({ success: true, message: "Protected action executed" });
});

app.post("/api/vulnerable-action", (req, res) => {
  res.json({ success: true, message: "Vulnerable action executed" });
});

const PORT = 3000;
app.listen(PORT, () =>
  console.log(`🚀 Security Lab running at http://localhost:${PORT}`)
);
