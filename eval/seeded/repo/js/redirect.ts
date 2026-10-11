import express, { Request, Response } from "express";

const app = express();

app.get("/go", (req: Request, res: Response) => {
  res.redirect(req.query.next as string);
});

export default app;
