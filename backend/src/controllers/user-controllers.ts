import { NextFunction, Request, Response } from "express";
import { compare, hash } from "bcrypt";
import User from "../models/user-model.js";
import { createToken } from "../utils/token-manager.js";
import { COOKIE_NAME } from "../utils/constants.js";

export const getAllUsers = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  try {
    //  get all user data
    const users = await User.find();
    return res.status(200).json({ message: "OK", users });
  } catch (error) {
    console.log(error);
    return res.status(400).json({ message: "Error", cause: error.message });
  }
};

export const userSignup = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  try {
    //  user signup
    const { name, email, password } = req.body;

    const checkUser = await User.findOne({ email: email });
    if (checkUser) {
      return res.status(401).send("User already registered");
    }

    const hashedPassword = await hash(password, 10);

    const user = new User({ name, email, password: hashedPassword });
    await user.save()
    .then(() => console.log("User saved into the database"))
    .catch((err) => console.log(err));
    
    //  create token and store cookie

    res.clearCookie(COOKIE_NAME , {
        path: '/',
        domain: 'localhost',
        httpOnly: true,
        signed: true
    })

    const token = createToken(user._id.toString() , user.email , "7d");
    const expires = new Date();
    expires.setDate(expires.getDate() +7);
    res.cookie(COOKIE_NAME , token , {
        path: '/',
        domain: 'localhost',
        expires,
        httpOnly: true,
        signed: true
    })


    return res.status(201).json({ message: "OK", id: user._id.toString() });
  } catch (error) {
    console.log(error);
    return res.status(400).json({ message: "Error", cause: error.message });
  }
};

export const userLogin = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  try {
    //  user signup
    const { email, password } = req.body;

    const user = await User.findOne({ email: email });
    if (!user) {
      return res.status(401).send("User not registered");
    }

    const isPasswordCorrect = await compare(password, user.password);
    if (!isPasswordCorrect) {
      return res.status(403).send("Incorrect Password");
    }

    //  create token and store cookie


    res.clearCookie(COOKIE_NAME , {
        path: '/',
        domain: 'localhost',
        httpOnly: true,
        signed: true
    })

    const token = createToken(user._id.toString() , user.email , "7d");
    const expires = new Date();
    expires.setDate(expires.getDate() +7);
    res.cookie(COOKIE_NAME , token , {
        path: '/',
        domain: 'localhost',
        expires,
        httpOnly: true,
        signed: true
    })

    return res.status(200).json({ message: "OK", id: user._id.toString() });
  } catch (error) {
    console.log(error);
    return res.status(400).json({ message: "Error", cause: error.message });
  }
};
