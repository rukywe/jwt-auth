import dotenv from "dotenv";
dotenv.config();

import express from "express";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";

const app = express();

app.use(express.json());

const users = [];
console.log(users);

const verifyUserToken = (req, res, next) => {
  if (!req.headers.authorization) {
    return res.status(401).send("Unauthorized request");
  }

  const token = req.headers["authorization"].split(" ")[1];

  if (!token) {
    return res.status(401).send("Access denied, No token provided.");
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded.user;
    next();
  } catch (error) {
    res.status(400).send("Invalid token.");
  }
};

app.get("/api/users", verifyUserToken, async (req, res) => {
  res.json(users);
});

app.post("/api/register", async (req, res) => {
  const user = req.body;

  if (!user.email || !user.password) {
    return res.status(400).send("Username and password are required");
  }

  const hash = await bcrypt.hash(user.password, 10);
  user.password = hash;
  users.push(user);
  res.json(user);
});

app.post("/api/login", async (req, res) => {
  const user = req.body;
  const foundUser = users.find((user) => user.email === req.body.email);
  if (!foundUser) {
    return res.status(400).send("Invalid email or password");
  }
  const isPasswordValid = await bcrypt.compare(
    user.password,
    foundUser.password
  );
  if (!isPasswordValid) {
    return res.status(400).send("Invalid email or password");
  }
  const token = jwt.sign({ user }, process.env.JWT_SECRET, {
    expiresIn: "1h"
  });
  res.json({ token });
});

app.listen(3000, () => {
  console.log("listening on port 3000");
});
