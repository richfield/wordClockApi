import express from 'express';
const app = express();
import dotenv from 'dotenv';
const port = 3004;
import cors from 'cors';
import  * as sqlite3  from 'sqlite3';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
const DBSOURCE = 'usersdb.sqlite';

dotenv.config();
import auth from './middleware';
import { DbError, DbUser, Settings } from './types';
import { defaultSettings } from './Constants';

const db = new sqlite3.Database(DBSOURCE, (err): void => {
    if (err) {
        // Cannot open database
        console.error(err.message);
        throw err;
    } else {

        db.run(`CREATE TABLE Users (
            Id INTEGER PRIMARY KEY AUTOINCREMENT,
            Username text,
            Email text,
            Password text,
            Salt text,
            Token text,
            DateLoggedIn DATE,
            DateCreated DATE,
            Settings text
            )`,
            (err) => {
                if (err) {
                    // Table already created
                } else {
                    // Table just created, creating some rows
                }
            });
    }
});


module.exports = db;
const allowedOrigins: string[] = `${process.env.CORS_URLS}`.split(',');
app.use(
    cors({
        origin: function (origin, callback) {
            if (!origin) return callback(null, true);
            if (allowedOrigins.indexOf(origin) === -1) {
                const msg = `The CORS policy for this site does not allow access from the specified Origin: ${origin} ${JSON.stringify(allowedOrigins)}`;
                return callback(new Error(msg), false);
            }
            return callback(null, true);
        }
    }),
    express.urlencoded({ extended: true }),
    express.json()
);

app.get('/', (req, res: { send: (arg0: string) => unknown; }) => res.send('API Root'));


//*  G E T   A L L

app.get('/api/users', (req, res): void => {
    const sql = 'SELECT * FROM Users';
    const params: string[] = [];
    db.all(sql, params, (err: DbError, rows: DbUser[]) => {
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


//* G E T   S I N G L E   U S E R

app.get('/api/user/:id', (req, res) => {
    const sql = 'SELECT * FROM Users WHERE Id = ?';
    db.all(sql, req.params.id, (err: DbError, rows: DbUser[]) => {
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


// * R E G I S T E R   N E W   U S E R

app.post('/api/register', async(req, res) => {
    const errors : string[] = [];
    try {
        const { Username, Password } = req.body;
        if (!Username) {
            errors.push('Username is missing');
        }
        if (errors.length) {
            res.status(400).json(`{ "error": ${errors.join(',')} }`);
            return;
        }
        let userExists = false;


        const sql = 'SELECT * FROM Users WHERE Username = ?';
        db.all(sql, Username, (err: DbError, result: string | DbUser[]) => {
            if (err) {
                res.status(402).json(`{ "error": ${err.message} }`);
                return;
            }

            if (result.length === 0) {

                const salt = bcrypt.genSaltSync(10);

                const data = {
                    Username: Username,
                    Password: bcrypt.hashSync(Password, salt),
                    Salt: salt,
                    DateCreated: new Date('now'),
                    Settings: {}
                };

                const sql = 'INSERT INTO Users (Username, Password, Salt, DateCreated, Settings) VALUES (?,?,?,?,?)';
                const params = [ data.Username, data.Password, data.Salt, new Date('now') ];
                db.run(sql, params, function (err: DbError) {
                    if (err) {
                        res.status(400).json(`{ "error": ${err.message} }`);
                        return;
                    }

                });
            } else {
                userExists = true;
                // res.status(404).send("User Already Exist. Please Login");
            }
        });

        setTimeout(() => {
            if (!userExists) {
                res.status(201).json('Success');
            } else {
                res.status(400).json('Record already exists. Please login');
            }
        }, 500);


    } catch (err) {
        console.log(err);
    }
});


// * L O G I N

app.post('/api/login', async(req , res) => {

    try {
        const { Username, Password } = req.body;
        // Make sure there is an Email and Password in the request
        if (!(Username && Password)) {
            res.status(400).json('All input is required');
        }

        const user: DbUser[] = [];

        const sql = 'SELECT * FROM Users WHERE Username = ?';
        db.all(sql, Username, function(err: DbError, rows: DbUser[]) {
            if (err) {
                res.status(400).json(`{ "error": ${err.message} }`);
                return;
            }
            rows.forEach(function(row) {
                user.push(row);
            });
            if(!user[0]) {
                return res.status(400).json('User not found');
            }

            const PHash = bcrypt.hashSync(Password, user[0].Salt);

            if (PHash === user[0].Password) {
                // * CREATE JWT TOKEN
                const token = jwt.sign({ user_id: user[0].Id, username: user[0].Username, Username },
                    `${process.env.TOKEN_KEY}`, {
                        expiresIn: '1h', // 60s = 60 seconds - (60m = 60 minutes, 2h = 2 hours, 2d = 2 days)
                    }
                );

                user[0].Token = token;

            } else {
                return res.status(400).json('No Match');
            }

            return res.status(200).send(user);
        });

    } catch (err) {
        console.log(err);
    }
});

app.get('/api/settings', auth, (req, res) => {
    const user = req.headers['user_id'];
    db.get('SELECT * FROM Users WHERE Id = ?', user, function (err, data: DbUser) {
        if (err) {
            res.status(500).json(err);
            return;
        } else {
            res.status(200).json(data?.Settings || JSON.stringify(defaultSettings));
        }
    });

});

app.get('/api/me', auth, (req, res) => {
    const user = req.headers['user_id'];
    db.get('SELECT * FROM Users WHERE Id = ?', user, function (err, data: DbUser) {
        if (err) {
            res.status(500).json(err);
            return;
        } else {
            res.status(200).json({Username:data.Username});
        }
    });
});

app.post('/api/settings', auth, (req, res) => {
    const user = req.headers['user_id'];
    const settings: Settings = req.body;
    console.log({ user,settings });
    const statement = db.prepare('UPDATE Users SET Settings=? WHERE Id=?');
     statement.run([ JSON.stringify(settings), user ], ((err) => {
         if (err) {
             res.status(500).json(err);
             return;
         } else {
             res.status(200).json(settings);
         }
     }));

});


app.listen(port, () => console.log(`API listening on port ${port}!`));