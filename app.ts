import express, { NextFunction, Request, Response } from 'express';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import sqlite3 from 'sqlite3';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import { DbError, DbUser, Settings } from './types';
import { defaultSettings } from './Constants';
import { LOGIN_TOKEN_TTL, TOKEN_KEY } from './config';
import auth from './middleware';

const app = express();
const port = process.env.PORT || 3004;
const DBSOURCE = process.env.DBSOURCE || 'usersdb.sqlite';

const db = new sqlite3.Database(DBSOURCE, (err): void => {
    if (err) {
        console.error(err.message);
        throw err;
    }
    db.run(`CREATE TABLE IF NOT EXISTS Users (
        Id INTEGER PRIMARY KEY AUTOINCREMENT,
        Username TEXT,
        Email TEXT,
        Password TEXT,
        Salt TEXT,
        Token TEXT,
        DateLoggedIn DATE,
        DateCreated DATE,
        Settings TEXT
    )`, (err) => {
        if (err) {
            console.error('Error creating table:', err.message);
            return;
        }
        db.run('CREATE UNIQUE INDEX IF NOT EXISTS idx_users_username ON Users (Username)', (err) => {
            if (err) {
                console.error('Error creating unique username index (duplicate usernames present?):', err.message);
            }
        });
    });
});

const allowedOrigins: string[] = process.env.CORS_URLS?.split(',').map(o => o.trim()).filter(Boolean) || [];

app.disable('x-powered-by');
app.set('trust proxy', process.env.TRUST_PROXY ? Number(process.env.TRUST_PROXY) : false);
app.use(helmet());
app.use(cors({
    origin: (origin, callback) => {
        if (!origin) return callback(null, true);
        if (!allowedOrigins.includes(origin)) {
            return callback(new Error('Origin not allowed by CORS policy'), false);
        }
        return callback(null, true);
    }
}), express.json({ limit: '100kb' }));

const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 20,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Too many attempts, please try again later' }
});

// Compared against when the user does not exist, so response time doesn't reveal valid usernames
const DUMMY_HASH = bcrypt.hashSync('dummy-password', 10);

const isNonEmptyString = (value: unknown, min: number, max: number): value is string =>
    typeof value === 'string' && value.length >= min && value.length <= max;

app.get('/', (req, res: Response) => res.send('API Root'));

app.post('/api/register', authLimiter, async (req, res, next) => {
    try {
        const { Username, Password } = req.body ?? {};
        if (!isNonEmptyString(Username, 3, 64)) {
            res.status(400).json('Username must be between 3 and 64 characters');
            return;
        }
        // bcrypt only uses the first 72 bytes
        if (!isNonEmptyString(Password, 8, 72)) {
            res.status(400).json('Password must be between 8 and 72 characters');
            return;
        }
        const hashedPassword = await bcrypt.hash(Password, 10);
        const insertSql = 'INSERT INTO Users (Username, Password, DateCreated) VALUES (?,?,?)';
        db.run(insertSql, [ Username, hashedPassword, new Date().toISOString() ], (err: (DbError & { code?: string }) | null) => {
            if (err) {
                if (err.code === 'SQLITE_CONSTRAINT') {
                    res.status(409).json('Record already exists. Please login');
                    return;
                }
                console.error(err);
                res.status(500).json('Internal server error');
                return;
            }
            res.status(201).json('Success');
        });
    } catch (err) {
        next(err);
    }
});

app.post('/api/login', authLimiter, async (req, res, next) => {
    try {
        const { Username, Password } = req.body ?? {};
        if (!isNonEmptyString(Username, 1, 64) || !isNonEmptyString(Password, 1, 72)) {
            res.status(400).json('All input is required');
            return;
        }
        db.get('SELECT Id, Username, Password FROM Users WHERE Username = ?', Username, async (err: DbError, user: DbUser | undefined) => {
            try {
                if (err) {
                    console.error(err);
                    res.status(500).json('Internal server error');
                    return;
                }
                const isPasswordValid = await bcrypt.compare(Password, user?.Password ?? DUMMY_HASH);
                if (!user || !isPasswordValid) {
                    res.status(401).json('Invalid username or password');
                    return;
                }
                const token = jwt.sign({ user_id: user.Id, username: user.Username }, TOKEN_KEY, { expiresIn: LOGIN_TOKEN_TTL });
                db.run('UPDATE Users SET DateLoggedIn = ? WHERE Id = ?', [ new Date().toISOString(), user.Id ]);
                res.status(200).send([ { Id: user.Id, Username: user.Username, Token: token } ]);
            } catch (error) {
                next(error);
            }
        });
    } catch (err) {
        next(err);
    }
});

app.get('/api/settings', auth, (req, res) => {
    db.get('SELECT Settings FROM Users WHERE Id = ?', res.locals.userId, (err: DbError, data: Pick<DbUser, 'Settings'> | undefined) => {
        if (err || !data) {
            console.error({ err, settings: data });
            res.status(err ? 500 : 404).json({ error: err ? 'Internal server error' : 'User not found' });
            return;
        }
        let settings: Settings = defaultSettings;
        try {
            const parsed = data.Settings ? JSON.parse(data.Settings) : undefined;
            if (parsed && typeof parsed === 'object') {
                settings = parsed as Settings;
            }
        } catch (error) {
            console.error('Invalid stored settings, returning defaults', { userId: res.locals.userId });
        }
        if (!settings.ClockClock24DefaultSettings) {
            settings = { ...settings, ClockClock24DefaultSettings: defaultSettings.ClockClock24DefaultSettings };
        }
        res.status(200).json(settings);
    });
});

app.get('/api/me', auth, (req, res) => {
    db.get('SELECT Username FROM Users WHERE Id = ?', res.locals.userId, (err: DbError, data: Pick<DbUser, 'Username'> | undefined) => {
        if (err || !data) {
            console.error({ err, me: data });
            res.status(err ? 500 : 404).json({ error: err ? 'Internal server error' : 'User not found' });
            return;
        }
        res.status(200).json({ Username: data.Username });
    });
});

app.post('/api/settings', auth, (req, res) => {
    const settings: unknown = req.body;
    if (!settings || typeof settings !== 'object' || Array.isArray(settings)) {
        res.status(400).json({ error: 'Settings must be an object' });
        return;
    }
    db.run('UPDATE Users SET Settings = ? WHERE Id = ?', [ JSON.stringify(settings), res.locals.userId ], (err) => {
        if (err) {
            console.error(err);
            res.status(500).json({ error: 'Internal server error' });
            return;
        }
        res.status(200).json(settings);
    });
});

// eslint-disable-next-line @typescript-eslint/no-unused-vars
app.use((err: Error, req: Request, res: Response, next: NextFunction) => {
    console.error(err);
    res.status(500).json({ error: 'Internal server error' });
});

app.listen(port, () => console.log(`API listening on port ${port} using database ${DBSOURCE}`));
