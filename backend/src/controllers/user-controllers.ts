import { NextFunction, Request, Response } from "express";
import User from "../models/user-model.js";

export const getAllUsers = async (req: Request , res: Response , next: NextFunction) => {
    try {
        const users = await User.find();
        return res.status(200).json({message:"OK" , users});
    } catch (error) {
        console.log(error);
        return res.status(400).json({message: "Error" , cause: error.message });
    }
}