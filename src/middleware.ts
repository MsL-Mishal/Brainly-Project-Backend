import jwt from 'jsonwebtoken';
import { Request, Response, NextFunction } from 'express';

import { JWT_SECRET } from './config';

export function authenticateTokenMiddleware(req: Request, res: Response, next: NextFunction) {

    try {
        const token = req.cookies?.token;

        if (!token) {
            return res.status(401).json({ message: 'Kindly Log in First' });
        }

        const verify = jwt.verify(token, JWT_SECRET);

        if (!verify) {
            return res.status(401).json({ message: 'Unauthorized Token. Please Log in to Continue' });
        }

        //@ts-ignore
        req.userId = verify.id;
        next();
    }
    catch (error: any) {
        return res.status(500).json({ message: 'Internal Server Error', error: error.message });
    }
}