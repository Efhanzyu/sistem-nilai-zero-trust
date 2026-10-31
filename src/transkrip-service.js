// src/transkrip-service.js

const path = require('path');

require('dotenv').config({
    path: path.resolve(__dirname, '..', '.env'),
});

const express = require('express');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

const { db } = require('./db');

const app = express();

app.disable('x-powered-by');
app.use(express.json({ limit: '1mb' }));

const PORT = Number(process.env.TRANSKRIP_PORT || 3002);
const JWT_SECRET = process.env.JWT_SECRET;
const GATEWAY_SECRET = process.env.GATEWAY_SECRET;
const SERVICE_CLIENT_ID = process.env.SERVICE_CLIENT_ID || '';

if (!JWT_SECRET || !GATEWAY_SECRET || !SERVICE_CLIENT_ID) {
    console.error('Konfigurasi keamanan Service Transkrip belum lengkap.');
    process.exit(1);
}

// Membandingkan secret secara aman.
function safeEqual(a, b) {
    const left = Buffer.from(typeof a === 'string' ? a : '');
    const right = Buffer.from(typeof b === 'string' ? b : '');

    return (
        left.length === right.length &&
        crypto.timingSafeEqual(left, right)
    );
}

// =============================================
// 1. VERIFIKASI GATEWAY DAN TOKEN
// =============================================
app.use((req, res, next) => {
    // Service hanya menerima request yang membawa secret Gateway.
    const incomingSecret = req.get('X-Gateway-Secret');

    if (!safeEqual(incomingSecret, GATEWAY_SECRET)) {
        return res.status(403).json({
            error: 'Gateway secret tidak valid',
        });
    }

    // Setiap request harus mempunyai JWT yang valid.
    const authorization = req.get('Authorization') || '';
    const match = /^Bearer\s+(\S+)$/i.exec(authorization);

    if (!match) {
        return res.status(401).json({
            error: 'Bearer token wajib diberikan',
        });
    }

    let principal;

    try {
        principal = jwt.verify(match[1], JWT_SECRET);
    } catch (error) {
        return res.status(401).json({
            error: 'Token tidak valid atau kedaluwarsa',
        });
    }

    // Endpoint sinkronisasi hanya menerima token khusus service.
    if (req.method === 'POST' && req.path === '/transkrip/sinkron') {
        if (
            principal.role !== 'service' ||
            principal.sub !== 'nilai-service' ||
            principal.clientId !== SERVICE_CLIENT_ID
        ) {
            return res.status(403).json({
                error: 'Sinkronisasi hanya diizinkan untuk Service Nilai',
            });
        }

        req.principal = principal;
        return next();
    }

    // Request pengguna hanya boleh membaca transkrip.
    if (
        req.method !== 'GET' ||
        !/^\/transkrip\/[^/]+$/.test(req.path)
    ) {
        return res.status(404).json({
            error: 'Endpoint Service Transkrip tidak ditemukan',
        });
    }

    if (!['mahasiswa', 'admin'].includes(principal.role)) {
        return res.status(403).json({
            error: 'Role tidak diizinkan melihat transkrip',
        });
    }

    // Periksa kembali identitas dan role dari database.
    const user = db.prepare(`
    SELECT id, username, role, nim
    FROM users
    WHERE id = ?
  `).get(principal.sub);

    if (!user || user.role !== principal.role) {
        return res.status(403).json({
            error: 'Identitas atau role tidak sesuai database',
        });
    }

    req.principal = principal;
    req.dbUser = user;

    next();
});

// =============================================
// 2. GET /transkrip/:nim
// Mahasiswa hanya boleh melihat transkrip sendiri.
// Admin dapat melihat transkrip seluruh mahasiswa.
// =============================================
app.get('/transkrip/:nim', (req, res) => {
    const principal = req.principal;
    const requestedNim = req.params.nim;

    const student = db.prepare(`
    SELECT id, nim, full_name
    FROM users
    WHERE nim = ? AND role = 'mahasiswa'
  `).get(requestedNim);

    if (!student) {
        return res.status(404).json({
            error: 'Mahasiswa dengan NIM tersebut tidak ditemukan',
        });
    }

    if (
        principal.role === 'mahasiswa' &&
        student.id !== principal.sub
    ) {
        return res.status(403).json({
            error: 'Mahasiswa hanya boleh melihat transkrip sendiri',
        });
    }

    const transcripts = db.prepare(`
    SELECT
      t.class_id AS classId,
      c.name AS className,
      t.score,
      t.finalized_at AS finalizedAt,
      t.synced_at AS syncedAt
    FROM transcripts t
    JOIN classes c ON c.id = t.class_id
    WHERE t.student_id = ?
    ORDER BY c.id
  `).all(student.id);

    return res.json({
        student: {
            nim: student.nim,
            name: student.full_name,
        },
        data: transcripts,
    });
});

// =============================================
// 3. POST /transkrip/sinkron
// Hanya token service yang boleh menjalankan.
// Body: { "classId": "IF101" }
// =============================================
app.post('/transkrip/sinkron', (req, res) => {
    const classId = req.body && req.body.classId;

    if (
        typeof classId !== 'string' ||
        !/^[A-Za-z0-9_-]{1,30}$/.test(classId)
    ) {
        return res.status(400).json({
            error: 'classId wajib diisi dengan format yang valid',
        });
    }

    const selectedClass = db.prepare(`
    SELECT id, name
    FROM classes
    WHERE id = ?
  `).get(classId);

    if (!selectedClass) {
        return res.status(404).json({
            error: 'Kelas tidak ditemukan',
        });
    }

    const counts = db.prepare(`
    SELECT
      COUNT(*) AS total,
      SUM(CASE WHEN is_final = 0 THEN 1 ELSE 0 END) AS pending
    FROM grades
    WHERE class_id = ?
  `).get(classId);

    if (counts.total === 0) {
        return res.status(409).json({
            error: 'Belum ada nilai untuk kelas ini',
        });
    }

    if (counts.pending > 0) {
        return res.status(409).json({
            error: 'Semua nilai harus difinalisasi sebelum sinkronisasi',
        });
    }

    const finalizedGrades = db.prepare(`
    SELECT student_id, class_id, score, updated_at
    FROM grades
    WHERE class_id = ? AND is_final = 1
  `).all(classId);

    // UPSERT menjaga agar sinkronisasi berulang tidak membuat duplikasi.
    const upsert = db.prepare(`
    INSERT INTO transcripts (
      student_id,
      class_id,
      score,
      finalized_at,
      synced_at
    )
    VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
    ON CONFLICT(class_id, student_id)
    DO UPDATE SET
      score = excluded.score,
      finalized_at = excluded.finalized_at,
      synced_at = CURRENT_TIMESTAMP
  `);

    try {
        const sync = db.transaction(() => {
            for (const grade of finalizedGrades) {
                upsert.run(
                    grade.student_id,
                    grade.class_id,
                    grade.score,
                    grade.updated_at
                );
            }
        });

        sync();

        return res.json({
            message: 'Sinkronisasi transkrip berhasil',
            classId: selectedClass.id,
            className: selectedClass.name,
            syncedCount: finalizedGrades.length,
        });
    } catch (error) {
        console.error('Sinkronisasi gagal:', error.message);

        return res.status(500).json({
            error: 'Gagal menyimpan data transkrip',
        });
    }
});

// =============================================
// 4. ENDPOINT TIDAK DIKENAL
// =============================================
app.use((req, res) => {
    return res.status(404).json({
        error: 'Endpoint Service Transkrip tidak ditemukan',
    });
});

app.listen(PORT, '127.0.0.1', () => {
    console.log('========================================');
    console.log(' Service Transkrip aktif');
    console.log(` URL: http://127.0.0.1:${PORT}`);
    console.log(' Gateway secret: diwajibkan');
    console.log(' JWT verification: aktif');
    console.log('========================================');
});