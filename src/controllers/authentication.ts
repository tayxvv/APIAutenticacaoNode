import express from "express";
import { getUsersByEmail, createUser } from "../db/users";
import { random, authentication } from "../helpers";

export const login = async (req: express.Request, res: express.Response) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      res.sendStatus(400);
      throw new Error("Please provide all values");
    }

    const user = await getUsersByEmail(email).select(
      "+authentication.salt +authentication.password"
    );

    if (!user) {
      res.sendStatus(400);
      throw new Error("User does not exist");
    }

    const expectedHash = authentication(password, user.authentication.salt);
    if (expectedHash !== user.authentication.password) {
      res.sendStatus(400);
      throw new Error("Invalid credentials");
    }

    const salt = random();
    user.authentication.sessionToken = authentication(
      salt,
      user._id.toString()
    );
    await user.save();
    res.cookie("TAY-AUTH", user.authentication.sessionToken, {
      domain: "localhost",
      path: "/",
    });

    return res.status(200).json(user).end;
  } catch (error) {
    console.log(error);
    return res.sendStatus(400);
  }
};

export const register = async (req: express.Request, res: express.Response) => {
  try {
    const { email, password, username } = req.body;

    if (!email || !password || !username) {
      res.status(400);
      throw new Error("Please provide all values");
    }
    const existingUser = await getUsersByEmail(email);
    if (existingUser) {
      res.status(400);
      throw new Error("User already exists");
    }

    const salt = random();
    const user = await createUser({
      email,
      username,
      authentication: {
        salt,
        password: authentication(password, salt),
      },
    });

    return res.status(200).json(user).end;
  } catch (error) {
    console.log(error);
    res.status(400);
  }
};
