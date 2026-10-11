const express = require("express");
const db = require("./db");
const app = express();

app.get("/users", (req, res) => {
  const name = req.query.name;
  db.query("SELECT id, email FROM users WHERE name = ?", [name], (err, rows) => res.json(rows));
});

module.exports = app;
