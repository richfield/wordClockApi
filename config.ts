import dotenv from 'dotenv';
import type { SignOptions } from 'jsonwebtoken';
dotenv.config();

export const TOKEN_KEY = process.env.TOKEN_KEY || '';
if (TOKEN_KEY.length < 32) {
    throw new Error('TOKEN_KEY must be set in the environment and be at least 32 characters long');
}

type Ttl = NonNullable<SignOptions['expiresIn']>;
export const TOKEN_TTL = (process.env.TOKEN_TTL || '30d') as Ttl;
export const LOGIN_TOKEN_TTL = (process.env.LOGIN_TOKEN_TTL || '1h') as Ttl;
