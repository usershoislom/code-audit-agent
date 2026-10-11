const express = require("express");
const db = require("./db");
const app = express();

app.get("/badge", (req, res) => {
  const n = parseInt(req.query.n, 10);
  res.send("<span>" + n + "</span>");
});

module.exports = app;
