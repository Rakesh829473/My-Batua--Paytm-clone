router.post("/signin", async (req, res) => {
    const body = req.body;

    try {
        const { success } = signinBody.safeParse(body);

        if (!success) {
            return res.status(411).json({
                message: "Incorrect Inputs"
            });
        }

        const existingUser = await User.findOne({
            username: body.username
        });

        // FIX: existingUser null ho sakta hai
        if (!existingUser) {
            return res.status(411).json({
                message: "User not found"
            });
        }

        const checkPassword = await bcrypt.compare(
            body.password,
            existingUser.password
        );

        if (!checkPassword) {
            return res.status(411).json({
                message: "Incorrect Password"
            });
        }

        const token = jwt.sign(
            { userId: existingUser._id },
            JWT_SECRET
        );

        res.status(200).json({
            message: "User logged in",
            token
        });

    } catch (error) {
        // Actual error Render logs me dikhega
        console.error("SIGNIN ERROR:", error);

        res.status(500).json({
            message: "Something went wrong"
        });
    }
});
