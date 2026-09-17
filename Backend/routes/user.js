const express = require("express");
const router = express.Router();
const zod = require("zod");
const { User, Account } = require("../db");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const { JWT_SECRET } = process.env;
const authMiddleware = require("../middleware");


// ================= SIGNUP VALIDATION =================

const signupBody = zod.object({
    username: zod.string().email(),
    firstname: zod.string(),
    lastname: zod.string(),
    password: zod.string()
});


// ================= SIGNIN VALIDATION =================

const signinBody = zod.object({
    username: zod.string().email(),
    password: zod.string()
});


// ================= UPDATE VALIDATION =================

const updateBody = zod.object({
    password: zod.string().optional(),
    firstName: zod.string().optional(),
    lastName: zod.string().optional()
});


// ================= GET MY ACCOUNT INFO =================

router.get("/getMyinfo", authMiddleware, async (req, res) => {

    const userId = req.userId;

    try {

        const existingUser = await Account.findOne({
            userId
        });

        res.json({
            existingUser
        });

    } catch (error) {

        console.error("GET MY INFO ERROR:", error);

        res.json({
            message: "User not found"
        });
    }
});


// ================= SIGNUP =================

router.post("/signup", async (req, res) => {

    const body = req.body;

    try {

        const { success } = signupBody.safeParse(body);

        if (!success) {

            return res.status(411).json({
                message: "Incorrect inputs"
            });
        }


        const existingUser = await User.findOne({
            username: body.username
        });


        if (existingUser) {

            return res.status(411).json({
                message: "User already exists"
            });
        }


        // Hash password
        const hashedPassword = await bcrypt.hash(
            body.password,
            10
        );


        // Create user
        const newUser = await User.create({

            username: body.username,

            password: hashedPassword,

            firstName: body.firstname,

            lastName: body.lastname
        });


        const userId = newUser._id;


        // Create account
        await Account.create({

            userId,

            balance: Math.floor(
                1 + Math.random() * 10000
            )
        });


        // Create JWT
        const token = jwt.sign(
            {
                userId
            },
            JWT_SECRET
        );


        res.json({

            message: "User created successfully",

            token
        });

    } catch (error) {

        console.error("SIGNUP ERROR:", error);

        return res.status(500).json({

            message: "Something went wrong"
        });
    }
});


// ================= CHECK LOGIN =================

router.get("/me", authMiddleware, (req, res) => {

    res.json({

        message: "previously logged user found"
    });
});


// ================= SIGNIN =================

router.post("/signin", async (req, res) => {

    const body = req.body;

    try {

        console.log("SIGNIN BODY:", body);


        // Validate input
        const { success } = signinBody.safeParse(body);

        if (!success) {

            return res.status(411).json({

                message: "Incorrect Inputs"
            });
        }


        // Find user
        const existingUser = await User.findOne({

            username: body.username
        });


        console.log(
            "USER FOUND:",
            !!existingUser
        );


        // FIX:
        // Pehle existingUser._id use ho raha tha.
        // Agar user nahi milta tha to existingUser null hota
        // aur error throw ho jata tha.

        if (!existingUser) {

            return res.status(411).json({

                message: "User not found"
            });
        }


        console.log(
            "PASSWORD HASH EXISTS:",
            !!existingUser.password
        );


        // Compare password
        const checkPassword = await bcrypt.compare(

            body.password,

            existingUser.password
        );


        console.log(
            "PASSWORD MATCH:",
            checkPassword
        );


        if (!checkPassword) {

            return res.status(411).json({

                message: "Incorrect Password"
            });
        }


        console.log(
            "JWT SECRET EXISTS:",
            !!JWT_SECRET
        );


        // Create token
        const token = jwt.sign(

            {
                userId: existingUser._id
            },

            JWT_SECRET
        );


        console.log("LOGIN SUCCESS");


        return res.status(200).json({

            message: "User logged in",

            token
        });

    } catch (error) {

        console.error(
            "SIGNIN ERROR:",
            error
        );


        return res.status(500).json({

            message: "Signin server error"
        });
    }
});


// ================= UPDATE USER =================

router.put("/", authMiddleware, async (req, res) => {

    const body = req.body;

    try {

        const { success } = updateBody.safeParse(body);


        if (!success) {

            return res.status(411).json({

                message: "Error while updating information"
            });
        }


        await User.updateOne(

            {
                _id: req.userId
            },

            body
        );


        res.json({

            message: "Update successfull"
        });

    } catch (error) {

        console.error(
            "UPDATE USER ERROR:",
            error
        );


        return res.status(411).json({

            message: "Error while updating information"
        });
    }
});


// ================= GET ALL USERS =================

router.get("/bulk", async (req, res) => {

    const filter = req.query.filter || "";

    try {

        const users = await User.find({

            $or: [

                {
                    firstName: {
                        "$regex": filter
                    }
                },

                {
                    lastName: {
                        "$regex": filter
                    }
                }
            ]
        });


        res.json({

            user: users.map(user => ({

                username: user.username,

                firstName: user.firstName,

                lastName: user.lastName,

                _id: user._id
            }))
        });

    } catch (error) {

        console.error(
            "BULK USER ERROR:",
            error
        );


        return res.status(500).json({

            message: "Something went wrong"
        });
    }
});


module.exports = router;

