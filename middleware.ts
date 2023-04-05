import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';
import { DbUser } from './types';
import {  Request, Response, NextFunction } from 'express';
dotenv.config();

const verifyToken = (req: Request, res: Response, next: NextFunction) => {

    const token =
        req.body.token || req.query.token || req.headers['x-access-token'] || req.headers.authorization?.replace('Bearer ', '');
    if (!token) {
        return res.status(403).send('A token is required for authentication');
    }
    try {
        const decoded = jwt.verify(token, process.env.TOKEN_KEY || '') as DbUser;
        const newToken = jwt.sign({ user_id: decoded.Id, username: decoded.Username },
            process.env.TOKEN_KEY || '', {
                expiresIn: '30d', // 60s = 60 seconds - (60m = 60 minutes, 2h = 2 hours, 2d = 2 days)
            }
        );
        res.set('Token', newToken);
        res.set('Access-Control-Expose-Headers', 'Token');
    } catch (err) {
        return res.status(401).send('Invalid Token');
    }
    return next();
};

module.exports = verifyToken;
export default verifyToken;