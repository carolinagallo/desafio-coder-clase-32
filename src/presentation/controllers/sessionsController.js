import UserManager from "../../domain/managers/users.js";
import {
  createHash,
  generateToken,
  isValidPassword,
} from "../../shared/index.js";
import loginValidation from "../../domain/validations/session/loginValidation.js";

export const login =
  ("/login",
  async (req, res) => {
    const data = req.body;

    const { email, password } = data;

    await loginValidation.parseAsync(data);

    const userManager = new UserManager();

    const user = await userManager.getOneByEmail(email);

    const isHashedPassword = await isValidPassword(password, user.password);

    if (!isHashedPassword) {
      return res
        .status(401)
        .send({ message: "Login failed, invalid password." });
    }

    const accessToken = await generateToken(user);

    res.status(200).send({
      status: 200,
      message: "Bienvenido!",
      accessToken,
    });
  });

export const current = async (req, res, next) => {
  try {
    res
      .status(200)
      .send({ status: 200, message: "Success", payload: req.user });
  } catch (e) {
    next(e);
  }
};

export const logout =
  ("/logout/:id",
  async (req, res) => {
    req.session.destroy((err) => {
      if (!err) {
        return res.send({ message: "Logout ok!" });
      }

      res.send({ message: "Logout error!", body: err });
    });
  });

export const signup =
  ("/signup",
  async (req, res) => {
    const userManager = new UserManager();
    const data = req.body;
    const user = await userManager.create(data);

    res.status(201).send({ status: 201, user, message: "User created" });
  });
