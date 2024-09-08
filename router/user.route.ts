import express from 'express';
import { generateToken, SignIn, SignUp, updatePassword } from '../Controller/user.controller';
// import VerifyToken from '../Middleware/VerifyToken';

const router = express.Router();

// Define routes with their respective controllers
router.post("/signup", SignUp);
router.post("/signin", SignIn);
router.post("/generate-token", generateToken);
router.put("/update-password", updatePassword);

export default router;