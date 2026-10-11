const express = require("express");
const db = require("./db");
const app = express();

app.get("/hello", (req, res) => {
  res.send("<h1>Hello " + req.query.name + "</h1>");
});

module.exports = app;
