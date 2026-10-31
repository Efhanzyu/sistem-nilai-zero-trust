// src/nilai-service.js

const path = require('path');
require('dotenv').config({
    path: path.resolve(__dirname, '..', '.env'),
});

const express = require('express');
const jwt = require('jsonwebtoken');

const { db } = require('./db');

const app = express();
app.disable('x-powered-by');
app.use(express.json({ limit: '1mb' }));

const PORT = Number(process.env.NILAI_PORT || 3001);
const JWT_SECRET = process.env.JWT_SECRET;
const GATEWAY_SECRET = process.env.GATEWAY_SECRET;

if (!JWT_SECRET || !GATEWAY_SECRET) {
    console.error('JWT_SECRET dan GATEWAY_SECRET wajib diisi.');
    process.exit(1);
}

// Perbandingan secret tanpa membandingkan panjangnya secara biasa.
const crypto = require('crypto');

function safeEqual(a, b) {
    const left = Buffer.from(typeof a === 'string' ? a : '');
    const right = Buffer.from(typeof b === 'string' ? b : '');

    return (
        left.length === right.length &&
        crypto.timingSafeEqual(left, right)
    );
}

// Pemeriksaan jam akses, menggunakan zona waktu lokal komputer.
function withinAccessWindow() {
    function parseTime(value) {
        if (!/^(?:[01]\d|2[0-3]):[0-5]\d$/.test(value || '')) {
            return null;
        }

        const parts = value.split(':').map(Number);
        return parts[0] * 60 + parts[1];
    }

    const start = parseTime(
        process.env.ACCESS_WINDOW_START || '07:00'
    );

    const end = parseTime(
        process.env.ACCESS_WINDOW_END || '21:00'
    );

    if (start === null || end === null) {
        return false;
    }

    const now = new Date();
    const current = now.getHours() * 60 + now.getMinutes();

    if (start <= end) {
        return current >= start && current <= end;
    }

    return current >= start || current <= end;
}

// Setiap request harus membawa secret Gateway dan JWT valid.
app.use((req, res, next) => {
    const incomingSecret = req.get('X-Gateway-Secret');

    if (!safeEqual(incomingSecret, GATEWAY_SECRET)) {
        return res.status(403).json({
            error: 'Gateway secret tidak valid',
        });
    }

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

    // Service Nilai hanya melayani dosen dan mahasiswa.
    if (
        principal.role !== 'dosen' &&
        principal.role !== 'mahasiswa'
    ) {
        return res.status(403).json({
            error: 'Role tidak diizinkan mengakses Service Nilai',
        });
    }

    // Verifikasi ulang role dan status identitas dari database.
    const user = db.prepare(`
    SELECT id, username, role
    FROM users
    WHERE id = ?
  `).get(principal.sub);

    if (!user || user.role !== principal.role) {
        return res.status(403).json({
            error: 'Identitas atau role tidak sesuai database',
        });
    }

    req.principal = principal;
    next();
});

// GET /nilai
// Mahasiswa hanya mendapatkan nilainya sendiri.
// Dosen hanya mendapatkan nilai kelas yang diampunya.
app.get('/nilai', (req, res) => {
    const principal = req.principal;
    const classId = req.query.classId || req.query.kelasId || '';

    if (principal.role === 'mahasiswa') {
        const grades = db.prepare(`
      SELECT
        g.id,
        g.class_id AS classId,
        c.name AS className,
        u.nim,
        g.score,
        g.is_final AS isFinal,
        g.updated_at AS updatedAt
      FROM grades g
      JOIN classes c ON c.id = g.class_id
      JOIN users u ON u.id = g.student_id
      WHERE g.student_id = ?
        AND (? = '' OR g.class_id = ?)
      ORDER BY c.id
    `).all(principal.sub, classId, classId);

        return res.json({
            data: grades,
        });
    }

    if (classId) {
        const ownedClass = db.prepare(`
      SELECT id
      FROM classes
      WHERE id = ? AND lecturer_id = ?
    `).get(classId, principal.sub);

        if (!ownedClass) {
            return res.status(403).json({
                error: 'Dosen bukan pengampu kelas tersebut',
            });
        }
    }

    const grades = db.prepare(`
    SELECT
      g.id,
      g.class_id AS classId,
      c.name AS className,
      u.nim,
      u.full_name AS studentName,
      g.score,
      g.is_final AS isFinal,
      g.updated_at AS updatedAt
    FROM grades g
    JOIN classes c ON c.id = g.class_id
    JOIN users u ON u.id = g.student_id
    WHERE c.lecturer_id = ?
      AND (? = '' OR g.class_id = ?)
    ORDER BY c.id, u.nim
  `).all(principal.sub, classId, classId);

    return res.json({
        data: grades,
    });
});

// PUT /nilai/:id
// Dosen dapat mengubah nilai yang belum final,
// hanya jika dosen mengampu kelasnya dan masih dalam jam akses.
app.put('/nilai/:id', (req, res) => {
    const principal = req.principal;
    const gradeId = req.params.id;
    const score = req.body && req.body.score;

    if (!/^\d+$/.test(gradeId)) {
        return res.status(400).json({
            error: 'ID nilai tidak valid',
        });
    }

    if (
        typeof score !== 'number' ||
        !Number.isFinite(score) ||
        score < 0 ||
        score > 100
    ) {
        return res.status(400).json({
            error: 'Nilai harus berupa angka antara 0 dan 100',
        });
    }

    const grade = db.prepare(`
    SELECT
      g.id,
      g.is_final,
      c.lecturer_id
    FROM grades g
    JOIN classes c ON c.id = g.class_id
    WHERE g.id = ?
  `).get(Number(gradeId));

    if (!grade) {
        return res.status(404).json({
            error: 'Data nilai tidak ditemukan',
        });
    }

    if (grade.lecturer_id !== principal.sub) {
        return res.status(403).json({
            error: 'Dosen bukan pengampu kelas nilai ini',
        });
    }

    if (grade.is_final === 1) {
        return res.status(409).json({
            error: 'Nilai sudah final dan tidak dapat diubah',
        });
    }

    if (!withinAccessWindow()) {
        return res.status(403).json({
            error: 'Perubahan nilai hanya diizinkan pukul 07.00–21.00',
        });
    }

    const result = db.prepare(`
    UPDATE grades
    SET score = ?, updated_at = CURRENT_TIMESTAMP
    WHERE id = ? AND is_final = 0
  `).run(score, Number(gradeId));

    if (result.changes !== 1) {
        return res.status(409).json({
            error: 'Nilai tidak berubah; periksa status finalisasi',
        });
    }

    return res.json({
        message: 'Nilai berhasil diperbarui',
        id: Number(gradeId),
        score,
    });
});

// Memanggil token service melalui Gateway,
// kemudian meminta Gateway meneruskan sinkronisasi transkrip.
async function syncTranscriptThroughGateway(classId) {
    const gatewayUrl =
        'http://127.0.0.1:' + Number(process.env.PORT || 3000);

    const authResponse = await fetch(
        gatewayUrl + '/auth/service', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                clientId: process.env.SERVICE_CLIENT_ID,
                clientSecret: process.env.SERVICE_CLIENT_SECRET,
            }),
            signal: AbortSignal.timeout(10000),
        }
    );

    if (!authResponse.ok) {
        throw new Error('Gagal mendapatkan token service dari Gateway');
    }

    const authData = await authResponse.json();

    if (!authData.accessToken) {
        throw new Error('Gateway tidak menerbitkan token service');
    }

    const syncResponse = await fetch(
        gatewayUrl + '/transkrip/sinkron', {
            method: 'POST',
            headers: {
                'Authorization': 'Bearer ' + authData.accessToken,
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ classId }),
            signal: AbortSignal.timeout(15000),
        }
    );

    const responseText = await syncResponse.text();

    if (!syncResponse.ok) {
        throw new Error(
            'Sinkronisasi transkrip gagal dengan HTTP ' +
            syncResponse.status
        );
    }

    return {
        status: syncResponse.status,
        response: responseText,
    };
}

// POST /kelas/:id/finalisasi
app.post('/kelas/:id/finalisasi', async(req, res) => {
    const principal = req.principal;
    const classId = req.params.id;

    const ownedClass = db.prepare(`
    SELECT id, name
    FROM classes
    WHERE id = ? AND lecturer_id = ?
  `).get(classId, principal.sub);

    if (!ownedClass) {
        return res.status(403).json({
            error: 'Dosen bukan pengampu kelas tersebut',
        });
    }

    if (!withinAccessWindow()) {
        return res.status(403).json({
            error: 'Finalisasi hanya diizinkan pukul 07.00–21.00',
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

    if (counts.pending === 0) {
        return res.status(409).json({
            error: 'Semua nilai pada kelas ini sudah final',
        });
    }

    // Transaksi memastikan perubahan finalisasi dilakukan secara konsisten.
    db.transaction(() => {
        db.prepare(`
      UPDATE grades
      SET is_final = 1, updated_at = CURRENT_TIMESTAMP
      WHERE class_id = ? AND is_final = 0
    `).run(classId);
    })();

    // Finalisasi sudah tersimpan. Jika sinkronisasi gagal,
    // jangan membatalkan status final nilai yang sudah tercatat.
    try {
        const syncResult = await syncTranscriptThroughGateway(classId);

        return res.json({
            message: 'Nilai berhasil difinalisasi',
            classId,
            className: ownedClass.name,
            transcriptSync: 'success',
            syncStatus: syncResult.status,
        });
    } catch (error) {
        console.error('Sinkronisasi transkrip gagal:', error.message);

        return res.status(200).json({
            message: 'Nilai telah difinalisasi, tetapi sinkronisasi transkrip gagal',
            classId,
            transcriptSync: 'failed',
        });
    }
});

// Endpoint yang tidak dikenal
app.use((req, res) => {
    return res.status(404).json({
        error: 'Endpoint Service Nilai tidak ditemukan',
    });
});

app.listen(PORT, '127.0.0.1', () => {
    console.log('========================================');
    console.log(' Service Nilai aktif');
    console.log(' URL: http://127.0.0.1:' + PORT);
    console.log(' Gateway secret: diwajibkan');
    console.log(' JWT verification: aktif');
    console.log('========================================');
});