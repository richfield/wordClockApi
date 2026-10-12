import jwt from 'jsonwebtoken';
import request from 'supertest';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const TOKEN_KEY = 'test-key-test-key-test-key-test-key-1234';
const ORIGIN = 'https://clock.example.com';

type Loaded = typeof import('./app');

const load = async (env: Record<string, string> = {}): Promise<Loaded> => {
    vi.resetModules();
    process.env.TOKEN_KEY = TOKEN_KEY;
    process.env.DBSOURCE = ':memory:';
    process.env.CORS_URLS = ORIGIN;
    process.env.AUTH_RATE_LIMIT = '1000';
    Object.assign(process.env, env);
    const loaded = await import('./app');
    // The unique index is created last during start-up, so wait for it before sending requests
    for (let i = 0; i < 100; i++) {
        const ready = await new Promise((resolve) => {
            loaded.db.get("SELECT name FROM sqlite_master WHERE name = 'idx_users_username'", (err, row) => resolve(!err && Boolean(row)));
        });
        if (ready) return loaded;
        await new Promise((resolve) => setTimeout(resolve, 10));
    }
    throw new Error('Database did not initialize');
};

const credentials = (Username = 'alice', Password = 'password-123') => ({ Username, Password });

const registerAndLogin = async (app: Loaded['app'], username = 'alice', password = 'password-123') => {
    await request(app).post('/api/register').send(credentials(username, password)).expect(201);
    const res = await request(app).post('/api/login').send(credentials(username, password)).expect(200);
    return { token: res.body[0].Token as string, id: res.body[0].Id as number };
};

const bearer = (token: string) => ({ Authorization: `Bearer ${token}` });

describe('API', () => {
    let app: Loaded['app'];
    let db: Loaded['db'];

    beforeEach(async () => {
        ({ app, db } = await load());
    });

    afterEach(() => {
        db.close();
    });

    describe('general', () => {
        it('serves the root without authentication', async () => {
            await request(app).get('/').expect(200, 'API Root');
        });

        it('sets security headers and hides the framework', async () => {
            const res = await request(app).get('/');
            expect(res.headers['x-content-type-options']).toBe('nosniff');
            expect(res.headers['x-powered-by']).toBeUndefined();
        });

        it('no longer exposes user listings', async () => {
            await registerAndLogin(app);
            await request(app).get('/api/users').expect(404);
            await request(app).get('/api/user/1').expect(404);
        });

        it('allows configured origins and rejects others', async () => {
            const allowed = await request(app).get('/').set('Origin', ORIGIN);
            expect(allowed.status).toBe(200);
            expect(allowed.headers['access-control-allow-origin']).toBe(ORIGIN);

            const denied = await request(app).get('/').set('Origin', 'https://evil.example.com');
            expect(denied.status).toBe(403);
            expect(denied.headers['access-control-allow-origin']).toBeUndefined();
        });

        it('answers malformed JSON with a 400 instead of a 500', async () => {
            const res = await request(app).post('/api/login').set('Content-Type', 'application/json').send('{"Username":');
            expect(res.status).toBe(400);
        });

        it('rejects bodies over 100kb', async () => {
            const res = await request(app).post('/api/login').send({ Username: 'a', Password: 'x'.repeat(200_000) });
            expect(res.status).toBe(413);
        });
    });

    describe('POST /api/register', () => {
        it('creates a user and stores only a bcrypt hash', async () => {
            await request(app).post('/api/register').send(credentials()).expect(201);
            const row: any = await new Promise((resolve, reject) =>
                db.get('SELECT * FROM Users WHERE Username = ?', 'alice', (err, r) => (err ? reject(err) : resolve(r))));
            expect(row.Password).toMatch(/^\$2[aby]\$10\$/);
            expect(row.Password).not.toContain('password-123');
            expect(row.Salt).toBeNull();
        });

        it.each([
            [ 'a missing body', undefined ],
            [ 'a short username', credentials('ab') ],
            [ 'a long username', credentials('a'.repeat(65)) ],
            [ 'a missing password', { Username: 'alice' } ],
            [ 'a short password', credentials('alice', 'short') ],
            [ 'a password longer than bcrypt supports', credentials('alice', 'p'.repeat(73)) ],
            [ 'non-string values', { Username: { $ne: '' }, Password: 12345678 } ],
        ])('rejects %s', async (_name, body) => {
            const res = await request(app).post('/api/register').send(body as object);
            expect(res.status).toBe(400);
        });

        it('rejects a duplicate username with 409', async () => {
            await request(app).post('/api/register').send(credentials()).expect(201);
            await request(app).post('/api/register').send(credentials('alice', 'another-pass-1')).expect(409);
        });

        it('creates only one user when registrations race', async () => {
            const results = await Promise.all(Array.from({ length: 5 }, () => request(app).post('/api/register').send(credentials())));
            expect(results.filter((r) => r.status === 201)).toHaveLength(1);
            expect(results.filter((r) => r.status === 409)).toHaveLength(4);
        });
    });

    describe('POST /api/login', () => {
        beforeEach(async () => {
            await request(app).post('/api/register').send(credentials()).expect(201);
        });

        it('returns only the id, username and a signed token', async () => {
            const res = await request(app).post('/api/login').send(credentials()).expect(200);
            expect(res.body).toHaveLength(1);
            expect(Object.keys(res.body[0]).sort()).toEqual([ 'Id', 'Token', 'Username' ]);
            const payload = jwt.verify(res.body[0].Token, TOKEN_KEY) as jwt.JwtPayload;
            expect(payload.user_id).toBe(res.body[0].Id);
            expect(payload.username).toBe('alice');
            expect(payload.exp! - payload.iat!).toBe(3600);
        });

        it('gives the same answer for a wrong password and an unknown user', async () => {
            const wrongPassword = await request(app).post('/api/login').send(credentials('alice', 'wrong-password'));
            const unknownUser = await request(app).post('/api/login').send(credentials('nobody', 'wrong-password'));
            expect(wrongPassword.status).toBe(401);
            expect(unknownUser.status).toBe(401);
            expect(unknownUser.body).toEqual(wrongPassword.body);
        });

        it.each([
            [ 'an empty body', {} ],
            [ 'a missing password', { Username: 'alice' } ],
            [ 'non-string values', { Username: [ 'alice' ], Password: { $gt: '' } } ],
        ])('rejects %s with 400', async (_name, body) => {
            await request(app).post('/api/login').send(body).expect(400);
        });

        it('records the last login date', async () => {
            await request(app).post('/api/login').send(credentials()).expect(200);
            const row: any = await new Promise((resolve) => db.get('SELECT DateLoggedIn FROM Users WHERE Username = ?', 'alice', (_e, r) => resolve(r)));
            expect(row.DateLoggedIn).toBeTruthy();
        });
    });

    describe('authentication middleware', () => {
        it('requires a token', async () => {
            await request(app).get('/api/settings').expect(401);
            await request(app).get('/api/me').expect(401);
            await request(app).post('/api/settings').send({}).expect(401);
        });

        it('rejects invalid tokens', async () => {
            await request(app).get('/api/me').set(bearer('garbage')).expect(401);
        });

        it('only accepts the Authorization header, not the query string, body or x-access-token', async () => {
            const { token } = await registerAndLogin(app);
            await request(app).get(`/api/me?token=${token}`).expect(401);
            await request(app).post('/api/settings').send({ token }).expect(401);
            await request(app).get('/api/me').set('x-access-token', token).expect(401);
            await request(app).get('/api/me').set('Authorization', token).expect(401);
        });

        it('rejects tokens signed with another key', async () => {
            const forged = jwt.sign({ user_id: 1, username: 'alice' }, 'some-other-key-some-other-key-123456');
            await request(app).get('/api/me').set(bearer(forged)).expect(401);
        });

        it('rejects expired tokens', async () => {
            const expired = jwt.sign({ user_id: 1, username: 'alice' }, TOKEN_KEY, { expiresIn: -10 });
            await request(app).get('/api/me').set(bearer(expired)).expect(401);
        });

        it('rejects unsigned (alg none) tokens', async () => {
            const encode = (o: object) => Buffer.from(JSON.stringify(o)).toString('base64url');
            const unsigned = `${encode({ alg: 'none', typ: 'JWT' })}.${encode({ user_id: 1, username: 'alice' })}.`;
            await request(app).get('/api/me').set(bearer(unsigned)).expect(401);
        });

        it('rejects tokens using another HMAC algorithm', async () => {
            const hs512 = jwt.sign({ user_id: 1, username: 'alice' }, TOKEN_KEY, { algorithm: 'HS512' });
            await request(app).get('/api/me').set(bearer(hs512)).expect(401);
        });

        it('hands out a refreshed 30 day token in an exposed Token header', async () => {
            const { token, id } = await registerAndLogin(app);
            const res = await request(app).get('/api/me').set(bearer(token)).expect(200);
            expect(res.headers['access-control-expose-headers']).toContain('Token');
            const refreshed = jwt.verify(res.headers.token, TOKEN_KEY) as jwt.JwtPayload;
            expect(refreshed.user_id).toBe(id);
            expect(refreshed.exp! - refreshed.iat!).toBe(30 * 24 * 3600);
        });
    });

    describe('GET /api/me', () => {
        it('returns only the username', async () => {
            const { token } = await registerAndLogin(app);
            const res = await request(app).get('/api/me').set(bearer(token)).expect(200);
            expect(res.body).toEqual({ Username: 'alice' });
        });

        it('returns 404 when the user no longer exists', async () => {
            const { token, id } = await registerAndLogin(app);
            await new Promise((resolve) => db.run('DELETE FROM Users WHERE Id = ?', id, resolve));
            await request(app).get('/api/me').set(bearer(token)).expect(404);
        });
    });

    describe('settings', () => {
        it('returns default settings for a user without stored settings', async () => {
            const { token } = await registerAndLogin(app);
            const res = await request(app).get('/api/settings').set(bearer(token)).expect(200);
            expect(res.body.DefaultClock).toBeDefined();
            expect(res.body.ClockClock24DefaultSettings).toBeDefined();
        });

        it('saves and returns settings', async () => {
            const { token } = await registerAndLogin(app);
            const post = await request(app).post('/api/settings').set(bearer(token)).send({ Timer: 5, RefreshRate: 30 }).expect(200);
            expect(post.body).toEqual({ Timer: 5, RefreshRate: 30 });
            const get = await request(app).get('/api/settings').set(bearer(token)).expect(200);
            expect(get.body).toMatchObject({ Timer: 5, RefreshRate: 30 });
            expect(get.body.ClockClock24DefaultSettings).toBeDefined();
        });

        it('keeps settings separate per user', async () => {
            const alice = await registerAndLogin(app, 'alice');
            const bob = await registerAndLogin(app, 'bob');
            await request(app).post('/api/settings').set(bearer(alice.token)).send({ Timer: 111 }).expect(200);
            await request(app).post('/api/settings').set(bearer(bob.token)).send({ Timer: 222 }).expect(200);
            expect((await request(app).get('/api/settings').set(bearer(alice.token))).body.Timer).toBe(111);
            expect((await request(app).get('/api/settings').set(bearer(bob.token))).body.Timer).toBe(222);
        });

        it('ignores a forged user_id header', async () => {
            const alice = await registerAndLogin(app, 'alice');
            const bob = await registerAndLogin(app, 'bob');
            await request(app).post('/api/settings').set(bearer(alice.token)).send({ Timer: 111 }).expect(200);

            const read = await request(app).get('/api/settings').set(bearer(bob.token)).set('user_id', String(alice.id)).expect(200);
            expect(read.body.Timer).not.toBe(111);

            await request(app).post('/api/settings').set(bearer(bob.token)).set('user_id', String(alice.id)).send({ Timer: 999 }).expect(200);
            expect((await request(app).get('/api/settings').set(bearer(alice.token))).body.Timer).toBe(111);

            const me = await request(app).get('/api/me').set(bearer(bob.token)).set('user_id', String(alice.id)).expect(200);
            expect(me.body.Username).toBe('bob');
        });

        it('falls back to defaults when stored settings are corrupt', async () => {
            const { token, id } = await registerAndLogin(app);
            await new Promise((resolve) => db.run('UPDATE Users SET Settings = ? WHERE Id = ?', [ '{not json', id ], resolve));
            const res = await request(app).get('/api/settings').set(bearer(token)).expect(200);
            expect(res.body.DefaultClock).toBeDefined();
        });

        it.each([
            [ 'an array', [ 1, 2, 3 ] ],
            [ 'a JSON null', null ],
        ])('rejects %s as settings', async (_name, body) => {
            const { token } = await registerAndLogin(app);
            const res = await request(app)
                .post('/api/settings')
                .set(bearer(token))
                .set('Content-Type', 'application/json')
                .send(JSON.stringify(body));
            expect(res.status).toBe(400);
        });
    });
});

describe('rate limiting', () => {
    it('blocks repeated login and register attempts', async () => {
        const { app, db } = await load({ AUTH_RATE_LIMIT: '3' });
        const statuses: number[] = [];
        for (let i = 0; i < 5; i++) {
            statuses.push((await request(app).post('/api/login').send(credentials('nobody', 'wrong-password'))).status);
        }
        expect(statuses).toEqual([ 401, 401, 401, 429, 429 ]);
        expect((await request(app).post('/api/register').send(credentials())).status).toBe(429);
        db.close();
    });

    it('does not limit authenticated settings requests', async () => {
        const { app, db } = await load({ AUTH_RATE_LIMIT: '2' });
        const { token } = await registerAndLogin(app);
        for (let i = 0; i < 5; i++) {
            await request(app).get('/api/me').set(bearer(token)).expect(200);
        }
        db.close();
    });
});

describe('configuration', () => {
    it('refuses to start without a strong TOKEN_KEY', async () => {
        await expect(load({ TOKEN_KEY: '' })).rejects.toThrow(/TOKEN_KEY/);
        await expect(load({ TOKEN_KEY: 'too-short' })).rejects.toThrow(/TOKEN_KEY/);
    });
});
