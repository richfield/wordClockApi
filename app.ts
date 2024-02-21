import express, { Request, Response } from 'express';
import dotenv from 'dotenv';
import cors from 'cors';
import sqlite3 from 'sqlite3';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import { DbError, DbUser, Settings } from './types';
import { defaultSettings } from './Constants';
import auth from './middleware';

const app = express();
dotenv.config();
const port = process.env.PORT || 3004;
const DBSOURCE = process.env.DBSOURCE || 'usersdb.sqlite';
const TOKEN: string = process.env.TOKEN_KEY || ""

const db = new sqlite3.Database(DBSOURCE, (err): void => {
    if (err) {
        console.error(err.message);
        throw err;
    } else {
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
            }
        });
    }
});

const allowedOrigins: string[] = process.env.CORS_URLS?.split(',') || [];
app.use(cors({
    origin: (origin, callback) => {
        if (!origin) return callback(null, true);
        if (allowedOrigins.indexOf(origin) === -1) {
            const msg = `The CORS policy for this site does not allow access from the specified Origin: ${origin}`;
            return callback(new Error(msg), false);
        }
        return callback(null, true);
    }
}), express.urlencoded({ extended: true }), express.json());

app.get('/', (req, res: Response) => res.send('API Root'));

app.get('/api/users', (req, res) => {
    const sql = 'SELECT * FROM Users';
    db.all(sql, [], (err: DbError, rows: DbUser[]) => {
        if (err) {
            res.status(400).json({ 'error': err.message });
            return;
        }
        res.json({
            'message': 'success',
            'data': rows
        });
    });
});

app.get('/api/user/:id', (req, res) => {
    const sql = 'SELECT * FROM Users WHERE Id = ?';
    db.get(sql, req.params.id, (err: DbError, row: DbUser) => {
        if (err) {
            res.status(400).json({ 'error': err.message });
            return;
        }
        res.json({
            'message': 'success',
            'data': row
        });
    });
});

app.post('/api/register', async (req, res) => {
    const errors: string[] = [];
    try {
        const { Username, Password } = req.body;
        if (!Username) {
            errors.push('Username is missing');
        }
        if (errors.length) {
            res.status(400).json({ "error": errors.join(',') });
            return;
        }
        const sql = 'SELECT * FROM Users WHERE Username = ?';
        db.get(sql, Username, (err: DbError, result: DbUser) => {
            if (err) {
                res.status(402).json({ "error": err.message });
                return;
            }
            if (!result) {
                const salt = bcrypt.genSaltSync(10);
                const hashedPassword = bcrypt.hashSync(Password, salt);
                const data = {
                    Username: Username,
                    Password: hashedPassword,
                    Salt: salt,
                    DateCreated: new Date(),
                    Settings: {}
                };
                const insertSql = 'INSERT INTO Users (Username, Password, Salt, DateCreated, Settings) VALUES (?,?,?,?,?)';
                const params = [data.Username, data.Password, data.Salt, data.DateCreated, JSON.stringify(data.Settings)];
                db.run(insertSql, params, (err) => {
                    if (err) {
                        res.status(400).json({ "error": err.message });
                        return;
                    }
                    res.status(201).json('Success');
                });
            } else {
                res.status(400).json('Record already exists. Please login');
            }
        });
    } catch (err) {
        console.log(err);
    }
});

app.post('/api/login', async (req, res) => {
    try {
        const { Username, Password } = req.body;
        if (!(Username && Password)) {
            res.status(400).json('All input is required');
            return;
        }
        const sql = 'SELECT * FROM Users WHERE Username = ?';
        db.get(sql, Username, (err: DbError, user: DbUser) => {
            if (err) {
                res.status(400).json({ "error": err.message });
                return;
            }
            if (!user) {
                res.status(400).json('User not found');
                return;
            }
            const isPasswordValid = bcrypt.compareSync(Password, user.Password);
            if (!isPasswordValid) {
                res.status(400).json('Incorrect password');
                return;
            }
            const token = jwt.sign({ user_id: user.Id, username: user.Username }, TOKEN, { expiresIn: '1h' });
            user.Token = token;
            res.status(200).send([user]);
        });
    } catch (err) {
        console.log(err);
    }
});

app.get('/api/settings', auth, (req, res) => {
    const userId = req.headers['user_id'];
    db.get('SELECT * FROM Users WHERE Id = ?', userId, (err: DbError, data: DbUser) => {
        if (err || !data) {
            res.status(500).json(err);
            console.log({err, settings:data})
            return;
        }

        if (!data.Settings.DefaultClock) {
            data.Settings = defaultSettings;
            console.log({defaultSettings})
        }
        res.status(200).json(data.Settings);
    });
});

app.get('/api/me', auth, (req, res) => {
    const userId = req.headers['user_id'];
    db.get('SELECT * FROM Users WHERE Id = ?', userId, (err: DbError, data: DbUser) => {
        if (err || !data) {
            res.status(500).json(err);
            console.log({ err, me: data })
            return;
        }
        res.status(200).json({ Username: data.Username });
    });
});

app.post('/api/settings', auth, (req, res) => {
    const userId = req.headers['user_id'];
    const settings: Settings = req.body;
    const statement = db.prepare('UPDATE Users SET Settings=? WHERE Id=?');
    statement.run([JSON.stringify(settings), userId], (err) => {
        if (err) {
            res.status(500).json(err);
            return;
        }
        console.log({updated: settings, firstSchedule: settings.Schedule[0]});
        res.status(200).json(settings);
    });
});

app.listen(port, () => console.log(`API listening on port ${port}! from path: ${DBSOURCE} \nenv:\n${JSON.stringify(process.env)}\nDefaultSettings: \n${JSON.stringify(defaultSettings)}`));
