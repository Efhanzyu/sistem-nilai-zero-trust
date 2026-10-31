// src/policy.js

// Membuat hasil keputusan yang konsisten
function decision(allow, reason) {
    return {
        allow,
        decision: allow ? 'allow' : 'deny',
        reason,
    };
}

// Memeriksa format jam HH:mm
function parseTime(value) {
    if (!/^(?:[01]\d|2[0-3]):[0-5]\d$/.test(value || '')) {
        return null;
    }

    const [hours, minutes] = value.split(':').map(Number);
    return hours * 60 + minutes;
}

// Memeriksa apakah saat ini berada dalam jam akses
function isWithinAccessWindow(
    now = new Date(),
    start = process.env.ACCESS_WINDOW_START || '07:00',
    end = process.env.ACCESS_WINDOW_END || '21:00'
) {
    const startMinutes = parseTime(start);
    const endMinutes = parseTime(end);

    // Konfigurasi tidak valid: tolak secara aman
    if (startMinutes === null || endMinutes === null) {
        return false;
    }

    const currentMinutes = now.getHours() * 60 + now.getMinutes();

    if (startMinutes <= endMinutes) {
        return currentMinutes >= startMinutes &&
            currentMinutes <= endMinutes;
    }

    // Mendukung rentang jam yang melewati tengah malam
    return currentMinutes >= startMinutes ||
        currentMinutes <= endMinutes;
}

// Memastikan device terdaftar untuk pengguna yang bersangkutan
function isDeviceRegistered(database, userId, deviceCode) {
    if (!database || !userId || !deviceCode) {
        return false;
    }

    const device = database.prepare(`
    SELECT id
    FROM devices
    WHERE user_id = ? AND device_code = ?
  `).get(userId, deviceCode);

    return Boolean(device);
}

// Policy Engine utama
function evaluatePolicy({
    method,
    path,
    user,
    deviceId,
    query = {},
    database,
    now = new Date(),
}) {
    const httpMethod = String(method || '').toUpperCase();
    const endpoint = String(path || '/').replace(/\/+$/, '') || '/';

    if (!database) {
        return decision(false, 'Database tidak tersedia');
    }

    if (!user || !user.sub || !user.role) {
        return decision(false, 'Token atau identitas pengguna tidak valid');
    }

    // Token service hanya boleh melakukan sinkronisasi transkrip
    if (user.role === 'service') {
        if (
            httpMethod === 'POST' &&
            endpoint === '/transkrip/sinkron' &&
            user.sub === 'nilai-service'
        ) {
            return decision(true, 'Token service valid untuk sinkronisasi');
        }

        return decision(
            false,
            'Token service tidak diizinkan mengakses endpoint ini'
        );
    }

    // Identitas pengguna dan role diperiksa kembali melalui database
    const dbUser = database.prepare(`
    SELECT id, username, full_name, role, nim
    FROM users
    WHERE id = ?
  `).get(user.sub);

    if (!dbUser) {
        return decision(false, 'Pengguna tidak ditemukan');
    }

    if (dbUser.role !== user.role) {
        return decision(false, 'Role token tidak sesuai dengan database');
    }

    // Semua request pengguna di luar /auth wajib memakai device terdaftar
    if (!isDeviceRegistered(database, dbUser.id, deviceId)) {
        return decision(false, 'Device tidak terdaftar untuk pengguna ini');
    }

    // GET /nilai
    if (httpMethod === 'GET' && endpoint === '/nilai') {
        if (!['mahasiswa', 'dosen'].includes(dbUser.role)) {
            return decision(false, 'Role tidak diizinkan melihat nilai');
        }

        // Mahasiswa hanya boleh meminta data nilainya sendiri.
        // Service tetap wajib memfilter hasil berdasarkan identitas token.
        if (
            dbUser.role === 'mahasiswa' &&
            query.studentId &&
            query.studentId !== dbUser.id
        ) {
            return decision(false, 'Mahasiswa hanya boleh melihat nilai sendiri');
        }

        if (dbUser.role === 'mahasiswa') {
            return decision(true, 'Mahasiswa diizinkan melihat nilai sendiri');
        }

        // Jika dosen meminta kelas tertentu, pastikan ia pengampunya.
        const requestedClass = query.classId || query.kelasId;

        if (requestedClass) {
            const ownedClass = database.prepare(`
        SELECT id
        FROM classes
        WHERE id = ? AND lecturer_id = ?
      `).get(requestedClass, dbUser.id);

            if (!ownedClass) {
                return decision(false, 'Dosen bukan pengampu kelas tersebut');
            }
        } else {
            // Tanpa filter kelas, dosen hanya dapat melihat kelas yang diampu.
            const hasClass = database.prepare(`
        SELECT id
        FROM classes
        WHERE lecturer_id = ?
        LIMIT 1
      `).get(dbUser.id);

            if (!hasClass) {
                return decision(false, 'Dosen tidak memiliki kelas yang diampu');
            }
        }

        return decision(true, 'Dosen diizinkan melihat kelas yang diampu');
    }

    // PUT /nilai/:id
    if (httpMethod === 'PUT' && /^\/nilai\/[^/]+$/.test(endpoint)) {
        if (dbUser.role !== 'dosen') {
            return decision(false, 'Hanya dosen yang boleh mengubah nilai');
        }

        const gradeId = endpoint.split('/')[2];

        if (!/^\d+$/.test(gradeId)) {
            return decision(false, 'ID nilai tidak valid');
        }

        const grade = database.prepare(`
      SELECT g.id, g.is_final, c.lecturer_id
      FROM grades g
      JOIN classes c ON c.id = g.class_id
      WHERE g.id = ?
    `).get(Number(gradeId));

        if (!grade) {
            return decision(false, 'Data nilai tidak ditemukan');
        }

        if (grade.lecturer_id !== dbUser.id) {
            return decision(false, 'Dosen bukan pengampu kelas nilai ini');
        }

        if (grade.is_final === 1) {
            return decision(false, 'Nilai sudah final dan tidak dapat diubah');
        }

        if (!isWithinAccessWindow(now)) {
            return decision(false, 'Perubahan nilai di luar jam akses');
        }

        return decision(true, 'Dosen berwenang mengubah nilai');
    }

    // POST /kelas/:id/finalisasi
    if (
        httpMethod === 'POST' &&
        /^\/kelas\/[^/]+\/finalisasi$/.test(endpoint)
    ) {
        if (dbUser.role !== 'dosen') {
            return decision(false, 'Hanya dosen yang boleh memfinalisasi nilai');
        }

        const classId = endpoint.split('/')[2];

        const ownedClass = database.prepare(`
      SELECT id
      FROM classes
      WHERE id = ? AND lecturer_id = ?
    `).get(classId, dbUser.id);

        if (!ownedClass) {
            return decision(false, 'Dosen bukan pengampu kelas tersebut');
        }

        if (!isWithinAccessWindow(now)) {
            return decision(false, 'Finalisasi di luar jam akses');
        }

        return decision(true, 'Dosen berwenang memfinalisasi kelas');
    }

    // GET /transkrip/:nim
    if (
        httpMethod === 'GET' &&
        /^\/transkrip\/[^/]+$/.test(endpoint)
    ) {
        if (!['mahasiswa', 'admin'].includes(dbUser.role)) {
            return decision(false, 'Role tidak diizinkan melihat transkrip');
        }

        const nim = endpoint.split('/')[2];

        const targetStudent = database.prepare(`
      SELECT id, nim
      FROM users
      WHERE nim = ? AND role = 'mahasiswa'
    `).get(nim);

        if (!targetStudent) {
            return decision(false, 'Mahasiswa dengan NIM tersebut tidak ditemukan');
        }

        if (
            dbUser.role === 'mahasiswa' &&
            targetStudent.id !== dbUser.id
        ) {
            return decision(false, 'Mahasiswa hanya boleh melihat transkrip sendiri');
        }

        return decision(true, 'Akses transkrip diizinkan');
    }

    // Endpoint yang tidak didefinisikan secara eksplisit ditolak
    return decision(false, 'Endpoint tidak memiliki kebijakan akses');
}

// Modul digunakan oleh API Gateway
module.exports = {
    evaluatePolicy,
    isDeviceRegistered,
    isWithinAccessWindow,
};