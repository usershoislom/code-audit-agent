import express, { Request, Response } from "express";
import path from "path";

const app = express();
const BASE = "/srv/files";

app.get("/files/:name", (req: Request, res: Response) => {
  res.sendFile(path.join(BASE, req.params.name));
});

export default app;
