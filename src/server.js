import express from "express";
import cors from "cors";
import cookieParser from "cookie-parser";

import dotenv from "dotenv";
import route from "./routes/route.js";
import { connecttoDB } from "./lib/db.js";
import usersroute from "./routes/userroute.js";
import chatRoutes from "./routes/chatroute.js";

dotenv.config();

const app = express();

app.use(express.json({ limit: "500mb" }));
app.use(express.urlencoded({ extended: true, limit: "500mb" }));
app.use(cookieParser());

app.use(
  cors({
    origin: process.env.FRONTEND_URL || "http://localhost:5173",
    credentials: true, // allow frontend to send cookies
  }),
);

app.get("/", (req, res) => {
  res.send("Hello World!");
});

app.use("/api/auth", route);
app.use("/api/users", usersroute);
app.use("/api/chat", chatRoutes);

const PORT = process.env.PORT || 5000;
const mongo_uri = process.env.MONGO_URI;

async function connecting() {
  try {
    await connecttoDB();
    app.listen(PORT, () => {
      console.log(`Server is running on port ${process.env.PORT}`);
    });
  } catch (error) {
    console.log("error connecting to db", error);
    process.exit(1);
  }
}
connecting();
