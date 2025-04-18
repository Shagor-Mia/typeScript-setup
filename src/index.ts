import cookieParser from "cookie-parser";
import cors from "cors";
import express, { Request, Response } from "express";
import morgan from "morgan";
import dbConnection from "./database/connect";

const app = express();

app.use(morgan("dev"));
app.use(cookieParser());
app.use(express.json());

app.use(
  cors({
    origin: "http://localhost:5173",
    methods: ["GET", "POST", "DELETE", "PUT"],
    allowedHeaders: [
      "Content-Type",
      "Authorization",
      "Cache-Control",
      "Expires",
      "Pragma",
    ],
    credentials: true,
  })
);

const port = 3000;

app.get("/", (req: Request, res: Response) => {
  res.send("Hello World!");
});

dbConnection();

app.listen(port, () => {
  console.log(`Example app listening on port ${port}`);
});
