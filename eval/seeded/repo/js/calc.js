const express = require("express");
const db = require("./db");
const app = express();

app.post("/calc", (req, res) => {
  const result = eval(req.body.expr);
  res.json({ result });
});

module.exports = app;
