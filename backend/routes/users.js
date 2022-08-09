const router = require("express").Router();
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const auth = require("../middleware/auth");
const User = require("../models/User").User;
const validator = require("validator").default

router.post("/register", async (req, res) => {
    try {
        let { email, username, password, repeatPassword } = req.body;

        let errors = {};

        // validate
        


        if (await User.find({ email: email }).length > 0) {
            errors["email"] = "Email has already been registered.";
        }
        if (!validator.isEmail(email)) {
            errors["email"] = "Please enter a valid email.";
        }
        if (validator.isEmpty(email)) {
            errors["email"] = "Email field is required.";
        }
        if (await User.find({ username: username }).length > 0) {
            errors["username"] = "Username has already been registered.";
        }
        if (validator.isEmpty(username)) {
            errors["username"] = "Username field is required.";
        }
        if (!validator.isLength(password, { min: 10 })) {
            errors["password"] = "Please enter a valid password. It has to have at least 10 characters, one uppercase letter, one lowercase letter, one number and one special character";
        }
        if (!("ABCDEFGHIJKLMNÑOPQRSTUVWXYZ".split("").some(l => password.indexOf(l) > -1))) {
            errors["password"] = "Please enter a valid password. It has to have at least 10 characters, one uppercase letter, one lowercase letter, one number and one special character";
        }
        if (!("ABCDEFGHIJKLMNÑOPQRSTUVWXYZ".toLowerCase().split("").some(l => password.indexOf(l) > -1))) {
            errors["password"] = "Please enter a valid password. It has to have at least 10 characters, one uppercase letter, one lowercase letter, one number and one special character";
        }
        if (!("0123456789".split("").some(l => password.indexOf(l) > -1))) {
            errors["password"] = "Please enter a valid password. It has to have at least 10 characters, one uppercase letter, one lowercase letter, one number and one special character";
        }
        if (!(["@", "%", "+", String.fromCharCode(92), "/", "'", "!", "#", "$", "^", "?", ":", ",", "(", ")", "[", "]", "~", "`", "-", "_", "."].some(l => password.indexOf(l) > -1))) {
            errors["password"] = "Please enter a valid password. It has to have at least 10 characters, one uppercase letter, one lowercase letter, one number and one special character";
        }
        
        if (validator.isEmpty(password)) {
            errors["password"] = "Password field is required.";
        }
        if (!validator.equals(password, repeatPassword)) {
            errors["repeatPassword"] = "Password must be equals.";
        }
        
        if (validator.isEmpty(repeatPassword)) {
            errors["repeatPassword"] = "Repeat password field is required.";
        }


        if (errors.length > 0) {
            return res.status(500).json(errors);
        }

        const salt = await bcrypt.genSalt();
        const passwordHash = await bcrypt.hash(password,salt);

        const newUser = new User({
            email,
            username,
            password: passwordHash
        })

        const savedUser = await newUser.save();
        res.json(savedUser);

    } catch (err) {
        return res.status(500).json({ error: err.message });
    }
})

router.post("/login", async (req, res) => {
    try {
        let { email, password } = req.body;

        if (validator.isEmpty(email) || validator.isEmpty(password)) {
            return res.status(400).json({ msg: "Not all fields have been entered." })
        }

        if (validator.isEmail(email)) {
            const user = await User.findOne({ email: email });
            if (!user) {
                return res.status(400).json({ msg: "No account with this email have been registered." })
            }
            const isMatch = await bcrypt.compare(password, user.password);
            if (!isMatch) return res.status(400).json({ msg: "Invalid credentials." });

            const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET);
            console.log("token", token);
            res.json({
                token,
                user: {
                    id: user._id,
                    username: user.username
                }
            });
        } else {
            const user = await User.findOne({ username: email });
            if (!user) {
                return res.status(400).json({ msg: "No account with this email have been registered." })
            }
            const isMatch = await bcrypt.compare(password, user.password);
            if (!isMatch) return res.status(400).json({ msg: "Invalid credentials." });

            const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET);
            console.log("token", token);
            res.json({
                token,
                user: {
                    id: user._id,
                    username: user.username
                }
            });
        }

    } catch (err) {
        return res.status(500).json({ error: err.message });
    }
})

router.delete("/delete", auth, async (req, res) => {
    try {
        const deletedUser = await User.findByIdAndDelete(req.user);
        res.json(deletedUser)
    } catch (err) {
        return res.status(500).json({ error: err.message });
    }
});

router.post("/tokenIsValid", async (req, res) => {
    try {
      const token = req.header("x-auth-token");
      if (!token) return res.json(false);
  
      const verified = jwt.verify(token, process.env.JWT_SECRET);
      if (!verified) return res.json(false);
  
      const user = await User.findById(verified.id);
      if (!user) return res.json(false);
  
      return res.json(true);
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });
  
  router.get("/", auth, async (req, res) => {
    const user = await User.findById(req.user);
    res.json({
      username: user.username,
      id: user._id,
    });
  });
  
  module.exports = router;