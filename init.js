const sqlite3 = require("sqlite3").verbose();
const bcrypt = require("bcrypt");

const db = new sqlite3.Database("lab.db");

db.serialize(() => {
  db.run("DROP TABLE IF EXISTS users");
  db.run("DROP TABLE IF EXISTS comments");

  db.run(
    "CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, password TEXT)"
  );

  db.run(
    "CREATE TABLE comments (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, comment TEXT)"
  );

  const saltRounds = 10;
  const password = "P@ssw0rd123";

  bcrypt.hash(password, saltRounds, (err, hash) => {
    if (err) throw err;

    db.run("INSERT INTO users (username, password) VALUES (?, ?)", [
      "alice",
      hash,
    ]);
  });
});

db.close(() => console.log("✅ Database initialized with demo user"));
