const express = require("express");
const { exec, execFile } = require("child_process");
const app = express();

app.get("/ping", (req, res) => {
  const host = req.query.host;
  execFile("ping", ["-c", "1", host], (err, out) => res.type("text/plain").send(out));
});

module.exports = app;
