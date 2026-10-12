import jwt from 'jsonwebtoken';
import { Request, Response, NextFunction } from 'express';
import { TOKEN_KEY, TOKEN_TTL } from './config';

interface TokenPayload {
    user_id: number;
    username: string;
}

const verifyToken = (req: Request, res: Response, next: NextFunction) => {
    const header = req.headers.authorization;
    const token = header?.startsWith('Bearer ') ? header.slice(7) : undefined;
    if (!token) {
        return res.status(401).json({ error: 'A token is required for authentication' });
    }
    try {
        const decoded = jwt.verify(token, TOKEN_KEY, { algorithms: [ 'HS256' ] }) as unknown as TokenPayload;
        res.locals.userId = decoded.user_id;
        const newToken = jwt.sign({ user_id: decoded.user_id, username: decoded.username }, TOKEN_KEY, { expiresIn: TOKEN_TTL });
        res.set('Token', newToken);
        res.set('Access-Control-Expose-Headers', 'Token');
    } catch (err) {
        return res.status(401).json({ error: 'Invalid Token' });
    }
    return next();
};

export default verifyToken;
