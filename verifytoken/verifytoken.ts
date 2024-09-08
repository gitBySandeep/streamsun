import { Request, Response, NextFunction } from 'express';
import jwt, { JwtPayload } from 'jsonwebtoken';


export const verifyUser = async (req: Request, res: Response, next: NextFunction): Promise<Response | void> => {
    try {
        // Extract token from Authorization header
        const authHeader = req.headers.authorization;

        if (!authHeader) {
            return res.status(401).json({ message: "Authorization header is missing" });
        }

        const token = authHeader.split(' ')[1];

        if (!token) {
            return res.status(401).json({ message: "Token is missing" });
        }

        // Verify the token
        const decodedToken = jwt.verify(token, process.env.SECRET_KEY as string) as JwtPayload;

        // Attach user info to the request object if needed
        req.user = decodedToken;

        // Proceed to the next middleware or route handler
        next();

    } catch (error) {
        console.error(error);
        return res.status(403).json({ message: "Invalid or expired token" });
    }
};
