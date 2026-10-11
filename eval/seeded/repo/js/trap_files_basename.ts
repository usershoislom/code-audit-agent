import express, { Request, Response } from "express";
import path from "path";

const app = express();
const BASE = "/srv/files";

app.get("/files/:name", (req: Request, res: Response) => {
  const safe = path.basename(req.params.name);
  res.sendFile(path.join(BASE, safe));
});

export default app;
