// src/gateway.js

const path = require('path');
require('dotenv').config({
    path: path.resolve(__dirname, '..', '.env'),
});

const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');

const { db } = require('./db');
const {
    evaluatePolicy,
    isDeviceRegistered,
} = require('./policy');

const app = express();

app.disable('x-powered-by');
app.use(express.json({ limit: '1mb' }));

const PORT = Number(process.env.PORT || 3000);
const JWT_SECRET = process.env.JWT_SECRET;
const GATEWAY_SECRET = process.env.GATEWAY_SECRET;
const ACCESS_TOKEN_TTL = process.env.ACCESS_TOKEN_TTL || '10m';
const REFRESH_TOKEN_TTL = process.env.REFRESH_TOKEN_TTL || '1d';
const SERVICE_TOKEN_TTL = process.env.SERVICE_TOKEN_TTL || '5m';

if (!JWT_SECRET || !GATEWAY_SECRET) {
    console.error('ERROR: JWT_SECRET dan GATEWAY_SECRET wajib diisi di .env');
    process.exit(1);
}

// Mengubah durasi seperti 10m, 5m, atau 1d ke milidetik.
function durationMs(value, fallback) {
    const match = /^(\d+)(s|m|h|d)$/i.exec(String(value || '').trim());

    if (!match) return fallback;

    const units = {
        s: 1000,
        m: 60 * 1000,
        h: 60 * 60 * 1000,
        d: 24 * 60 * 60 * 1000,
    };

    return Number(match[1]) * units[match[2].toLowerCase()];
}

function hashToken(token) {
    return crypto.createHash('sha256').update(token).digest('hex');
}

function newRefreshToken() {
    return crypto.randomBytes(48).toString('base64url');
}

// Mencatat keputusan akses di database.
function audit(subject, endpoint, deviceId, result, reason) {
    try {
        db.prepare(`
      INSERT INTO audit_logs
        (subject, endpoint, device_id, result, reason)
      VALUES (?, ?, ?, ?, ?)
    `).run(
            subject || 'anonymous',
            endpoint,
            deviceId || null,
            result,
            reason
        );
    } catch (error) {
        console.error('Gagal menyimpan audit log:', error.message);
    }
}

function issueAccessToken(user) {
    return jwt.sign({
            sub: user.id,
            role: user.role,
            username: user.username,
        },
        JWT_SECRET, { expiresIn: ACCESS_TOKEN_TTL }
    );
}

function saveRefreshToken(userId, deviceId, rawToken) {
    const expiresAt = new Date(
        Date.now() + durationMs(REFRESH_TOKEN_TTL, 24 * 60 * 60 * 1000)
    ).toISOString();

    db.prepare(`
    INSERT INTO refresh_tokens
      (id, user_id, token_hash, device_id, expires_at)
    VALUES (?, ?, ?, ?, ?)
  `).run(
        crypto.randomUUID(),
        userId,
        hashToken(rawToken),
        deviceId,
        expiresAt
    );

    return expiresAt;
}

function publicUser(user) {
    return {
        id: user.id,
        username: user.username,
        fullName: user.full_name,
        role: user.role,
        nim: user.nim,
    };
}

function refreshSessionIsValid(session) {
    return Boolean(
        session &&
        !session.revoked_at &&
        Number.isFinite(Date.parse(session.expires_at)) &&
        Date.parse(session.expires_at) > Date.now()
    );
}

// =============================================
// 1. LOGIN
// POST /auth/login
// Header: X-Device-ID
// Body: { "username": "...", "password": "..." }
// =============================================
app.post('/auth/login', (req, res) => {
    const username =
        typeof req.body?.username === 'string' ?
        req.body.username.trim() :
        '';

    const password =
        typeof req.body?.password === 'string' ?
        req.body.password :
        '';

    const deviceId = req.get('X-Device-ID');

    const user = db.prepare(`
    SELECT id, username, password_hash, full_name, role, nim
    FROM users
    WHERE username = ?
  `).get(username);

    const passwordValid = user ?
        bcrypt.compareSync(password, user.password_hash) :
        false;

    if (!user || !passwordValid) {
        audit(
            username || 'anonymous',
            req.originalUrl,
            deviceId,
            'deny',
            'Username atau password tidak valid'
        );

        return res.status(401).json({
            error: 'Username atau password tidak valid',
        });
    }

    if (!isDeviceRegistered(db, user.id, deviceId)) {
        audit(
            user.id,
            req.originalUrl,
            deviceId,
            'deny',
            'Device tidak terdaftar untuk pengguna'
        );

        return res.status(403).json({
            error: 'Device tidak terdaftar untuk pengguna ini',
        });
    }

    const accessToken = issueAccessToken(user);
    const refreshToken = newRefreshToken();

    try {
        saveRefreshToken(user.id, deviceId, refreshToken);

        audit(
            user.id,
            req.originalUrl,
            deviceId,
            'allow',
            'Login dan verifikasi device berhasil'
        );

        return res.json({
            accessToken,
            refreshToken,
            tokenType: 'Bearer',
            expiresIn: durationMs(ACCESS_TOKEN_TTL, 600000) / 1000,
            user: publicUser(user),
        });
    } catch (error) {
        console.error('Login gagal membuat session:', error.message);

        return res.status(500).json({
            error: 'Gagal membuat session login',
        });
    }
});

// =============================================
// 2. REFRESH TOKEN
// POST /auth/refresh
// Header: X-Device-ID
// Body: { "refreshToken": "..." }
// Token lama dicabut dan diganti token baru.
// =============================================
app.post('/auth/refresh', (req, res) => {
    const rawToken = req.body?.refreshToken;
    const deviceId = req.get('X-Device-ID');

    if (typeof rawToken !== 'string' || !rawToken) {
        audit(
            'anonymous',
            req.originalUrl,
            deviceId,
            'deny',
            'Refresh token tidak diberikan'
        );

        return res.status(401).json({
            error: 'Refresh token wajib diberikan',
        });
    }

    const session = db.prepare(`
    SELECT *
    FROM refresh_tokens
    WHERE token_hash = ?
  `).get(hashToken(rawToken));

    if (!refreshSessionIsValid(session)) {
        audit(
            'refresh-token',
            req.originalUrl,
            deviceId,
            'deny',
            'Refresh token tidak valid, kedaluwarsa, atau dicabut'
        );

        return res.status(401).json({
            error: 'Refresh token tidak valid atau sudah kedaluwarsa',
        });
    }

    if (!deviceId ||
        session.device_id !== deviceId ||
        !isDeviceRegistered(db, session.user_id, deviceId)
    ) {
        audit(
            session.user_id,
            req.originalUrl,
            deviceId,
            'deny',
            'Device tidak cocok dengan refresh token'
        );

        return res.status(403).json({
            error: 'Device tidak sesuai dengan session',
        });
    }

    const user = db.prepare(`
    SELECT id, username, full_name, role, nim
    FROM users
    WHERE id = ?
  `).get(session.user_id);

    if (!user) {
        audit(
            session.user_id,
            req.originalUrl,
            deviceId,
            'deny',
            'Pengguna tidak ditemukan'
        );

        return res.status(401).json({
            error: 'Session tidak valid',
        });
    }

    const nextRefreshToken = newRefreshToken();
    const now = new Date().toISOString();

    // Rotasi refresh token dilakukan dalam satu transaksi database.
    try {
        const rotate = db.transaction(() => {
            const current = db.prepare(`
        SELECT *
        FROM refresh_tokens
        WHERE id = ?
      `).get(session.id);

            if (!refreshSessionIsValid(current)) {
                return false;
            }

            const revoked = db.prepare(`
        UPDATE refresh_tokens
        SET revoked_at = ?
        WHERE id = ? AND revoked_at IS NULL
      `).run(now, session.id);

            if (revoked.changes !== 1) {
                return false;
            }

            saveRefreshToken(user.id, deviceId, nextRefreshToken);

            return true;
        });

        if (!rotate()) {
            audit(
                user.id,
                req.originalUrl,
                deviceId,
                'deny',
                'Refresh token sudah digunakan atau dicabut'
            );

            return res.status(401).json({
                error: 'Refresh token tidak valid atau sudah digunakan',
            });
        }

        const accessToken = issueAccessToken(user);

        audit(
            user.id,
            req.originalUrl,
            deviceId,
            'allow',
            'Refresh berhasil dan token lama dicabut'
        );

        return res.json({
            accessToken,
            refreshToken: nextRefreshToken,
            tokenType: 'Bearer',
            expiresIn: durationMs(ACCESS_TOKEN_TTL, 600000) / 1000,
        });
    } catch (error) {
        console.error('Refresh gagal:', error.message);

        return res.status(500).json({
            error: 'Gagal memperbarui session',
        });
    }
});

// =============================================
// 3. LOGOUT
// POST /auth/logout
// Header: X-Device-ID
// Body: { "refreshToken": "..." }
// =============================================
app.post('/auth/logout', (req, res) => {
    const rawToken = req.body?.refreshToken;
    const deviceId = req.get('X-Device-ID');

    if (typeof rawToken !== 'string' || !rawToken) {
        audit(
            'anonymous',
            req.originalUrl,
            deviceId,
            'deny',
            'Refresh token tidak diberikan untuk logout'
        );

        return res.status(401).json({
            error: 'Refresh token wajib diberikan',
        });
    }

    const session = db.prepare(`
    SELECT *
    FROM refresh_tokens
    WHERE token_hash = ?
  `).get(hashToken(rawToken));

    if (!refreshSessionIsValid(session)) {
        audit(
            'refresh-token',
            req.originalUrl,
            deviceId,
            'deny',
            'Refresh token tidak valid atau sudah dicabut'
        );

        return res.status(401).json({
            error: 'Refresh token tidak valid atau sudah dicabut',
        });
    }

    if (!deviceId ||
        session.device_id !== deviceId ||
        !isDeviceRegistered(db, session.user_id, deviceId)
    ) {
        audit(
            session.user_id,
            req.originalUrl,
            deviceId,
            'deny',
            'Device tidak cocok untuk logout'
        );

        return res.status(403).json({
            error: 'Device tidak sesuai dengan session',
        });
    }

    const result = db.prepare(`
    UPDATE refresh_tokens
    SET revoked_at = ?
    WHERE id = ? AND revoked_at IS NULL
  `).run(new Date().toISOString(), session.id);

    if (result.changes !== 1) {
        audit(
            session.user_id,
            req.originalUrl,
            deviceId,
            'deny',
            'Refresh token sudah dicabut'
        );

        return res.status(401).json({
            error: 'Refresh token sudah dicabut',
        });
    }

    audit(
        session.user_id,
        req.originalUrl,
        deviceId,
        'allow',
        'Logout berhasil dan refresh token dicabut'
    );

    return res.json({
        message: 'Logout berhasil',
    });
});

// =============================================
// 4. TOKEN SERVICE
// POST /auth/service
// Body: { "clientId": "...", "clientSecret": "..." }
// =============================================
function safeEqualStrings(valueA, valueB) {
    const a = Buffer.from(
        typeof valueA === 'string' ? valueA : ''
    );

    const b = Buffer.from(
        typeof valueB === 'string' ? valueB : ''
    );

    return a.length === b.length && crypto.timingSafeEqual(a, b);
}

app.post('/auth/service', (req, res) => {
    const clientId =
        req.body?.clientId ?? req.body?.client_id ?? '';

    const clientSecret =
        req.body?.clientSecret ?? req.body?.client_secret ?? '';

    const expectedClientId = process.env.SERVICE_CLIENT_ID || '';
    const expectedClientSecret = process.env.SERVICE_CLIENT_SECRET || '';

    const valid =
        expectedClientId.length > 0 &&
        expectedClientSecret.length > 0 &&
        safeEqualStrings(clientId, expectedClientId) &&
        safeEqualStrings(clientSecret, expectedClientSecret);

    if (!valid) {
        audit(
            clientId || 'unknown-service',
            req.originalUrl,
            null,
            'deny',
            'Client ID atau client secret tidak valid'
        );

        return res.status(401).json({
            error: 'Kredensial service tidak valid',
        });
    }

    try {
        const serviceToken = jwt.sign({
                sub: 'nilai-service',
                role: 'service',
                clientId: expectedClientId,
            },
            JWT_SECRET, { expiresIn: SERVICE_TOKEN_TTL }
        );

        audit(
            'nilai-service',
            req.originalUrl,
            null,
            'allow',
            'Penerbitan token service berhasil'
        );

        return res.json({
            accessToken: serviceToken,
            tokenType: 'Bearer',
            expiresIn: durationMs(SERVICE_TOKEN_TTL, 300000) / 1000,
        });
    } catch (error) {
        console.error('Gagal menerbitkan token service:', error.message);

        return res.status(500).json({
            error: 'Gagal menerbitkan token service',
        });
    }
});

// =============================================
// 5. PENERUSAN REQUEST KE SERVICE
// =============================================

function getTargetPort(pathname) {
    if (
        pathname === '/nilai' ||
        pathname.startsWith('/nilai/') ||
        pathname.startsWith('/kelas/')
    ) {
        return Number(process.env.NILAI_PORT || 3001);
    }

    if (
        pathname === '/transkrip' ||
        pathname.startsWith('/transkrip/')
    ) {
        return Number(process.env.TRANSKRIP_PORT || 3002);
    }

    return null;
}

async function forwardRequest(req, res, targetPort) {
    const targetUrl =
        `http://127.0.0.1:${targetPort}${req.originalUrl}`;

    const headers = {};

    // Jangan meneruskan header hop-by-hop atau gateway secret dari client.
    const blockedHeaders = new Set([
        'host',
        'connection',
        'content-length',
        'transfer-encoding',
        'x-gateway-secret',
        'expect',
    ]);

    for (const [key, value] of Object.entries(req.headers)) {
        if (
            value === undefined ||
            blockedHeaders.has(key.toLowerCase())
        ) {
            continue;
        }

        headers[key] = Array.isArray(value) ?
            value.join(', ') :
            value;
    }

    // Gateway selalu memasang secret miliknya sendiri.
    headers['x-gateway-secret'] = GATEWAY_SECRET;

    let body;

    if (!['GET', 'HEAD'].includes(req.method)) {
        if (req.body !== undefined) {
            body = JSON.stringify(req.body);

            if (!headers['content-type']) {
                headers['content-type'] = 'application/json';
            }
        }
    }

    try {
        const upstream = await fetch(targetUrl, {
            method: req.method,
            headers,
            body,
            signal: AbortSignal.timeout(10000),
        });

        const responseBody = Buffer.from(
            await upstream.arrayBuffer()
        );

        res.status(upstream.status);

        // Fetch dapat mendekompresi respons; jangan teruskan metadata
        // panjang dan encoding yang mungkin sudah tidak sesuai.
        const blockedResponseHeaders = new Set([
            'connection',
            'content-length',
            'transfer-encoding',
            'content-encoding',
        ]);

        upstream.headers.forEach((value, key) => {
            if (!blockedResponseHeaders.has(key.toLowerCase())) {
                res.setHeader(key, value);
            }
        });

        return res.send(responseBody);
    } catch (error) {
        console.error('Gagal meneruskan request:', error.message);

        return res.status(502).json({
            error: 'Service tujuan tidak tersedia',
        });
    }
}

// =============================================
// 6. POLICY ENFORCEMENT POINT (PEP)
// Semua endpoint selain endpoint autentikasi
// melewati pemeriksaan ini.
// =============================================
app.use(async(req, res) => {
    const endpoint = req.path;
    const deviceId = req.get('X-Device-ID') || null;

    // Endpoint autentikasi yang tidak didefinisikan ditolak.
    if (endpoint.startsWith('/auth/')) {
        audit(
            'anonymous',
            req.originalUrl,
            deviceId,
            'deny',
            'Endpoint autentikasi tidak ditemukan'
        );

        return res.status(404).json({
            error: 'Endpoint autentikasi tidak ditemukan',
        });
    }

    const authorization = req.get('Authorization') || '';
    const match = /^Bearer\s+(\S+)$/i.exec(authorization);

    if (!match) {
        audit(
            'anonymous',
            req.originalUrl,
            deviceId,
            'deny',
            'Bearer token wajib diberikan'
        );

        return res.status(401).json({
            error: 'Authorization Bearer token wajib diberikan',
        });
    }

    let principal;

    try {
        principal = jwt.verify(match[1], JWT_SECRET);
    } catch (error) {
        audit(
            'invalid-token',
            req.originalUrl,
            deviceId,
            'deny',
            'Token tidak valid atau kedaluwarsa'
        );

        return res.status(401).json({
            error: 'Token tidak valid atau sudah kedaluwarsa',
        });
    }

    const policy = evaluatePolicy({
        method: req.method,
        path: endpoint,
        user: principal,
        deviceId,
        query: req.query,
        database: db,
    });

    if (!policy.allow) {
        audit(
            principal.sub,
            req.originalUrl,
            deviceId,
            'deny',
            policy.reason
        );

        return res.status(403).json({
            error: 'Akses ditolak',
            reason: policy.reason,
        });
    }

    const targetPort = getTargetPort(endpoint);

    if (!targetPort) {
        audit(
            principal.sub,
            req.originalUrl,
            deviceId,
            'deny',
            'Service tujuan tidak ditemukan'
        );

        return res.status(404).json({
            error: 'Endpoint tidak ditemukan',
        });
    }

    audit(
        principal.sub,
        req.originalUrl,
        deviceId,
        'allow',
        policy.reason
    );

    return forwardRequest(req, res, targetPort);
});

// Penanganan error agar kesalahan input tidak membuat server mati.
app.use((error, req, res, next) => {
    console.error('Gateway error:', error.message);

    if (res.headersSent) {
        return next(error);
    }

    return res.status(400).json({
        error: 'Request tidak dapat diproses',
    });
});

app.listen(PORT, '127.0.0.1', () => {
    console.log('========================================');
    console.log(' Zero Trust API Gateway aktif');
    console.log(` URL: http://127.0.0.1:${PORT}`);
    console.log(' Policy Engine: aktif');
    console.log(' Audit Log: aktif');
    console.log('========================================');
});

