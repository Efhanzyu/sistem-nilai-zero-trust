const path = require('path');
const fs = require('fs');
const bcrypt = require('bcryptjs');
const Database = require('better-sqlite3');

require('dotenv').config({
    path: path.resolve(__dirname, '..', '.env'),
});

// Lokasi database
const dbPath = path.resolve(
    __dirname,
    '..',
    process.env.DB_PATH || 'data/zero-trust.db'
);

fs.mkdirSync(path.dirname(dbPath), { recursive: true });

const db = new Database(dbPath);

db.pragma('foreign_keys = ON');
db.pragma('journal_mode = WAL');

// Membuat tabel database
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    full_name TEXT NOT NULL,
    role TEXT NOT NULL CHECK (
      role IN ('admin', 'dosen', 'mahasiswa')
    ),
    nim TEXT UNIQUE,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CHECK (role <> 'mahasiswa' OR nim IS NOT NULL)
  );

  CREATE TABLE IF NOT EXISTS devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_code TEXT NOT NULL UNIQUE,
    device_name TEXT NOT NULL,
    registered_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS classes (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    lecturer_id TEXT NOT NULL REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS enrollments (
    class_id TEXT NOT NULL REFERENCES classes(id) ON DELETE CASCADE,
    student_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    PRIMARY KEY (class_id, student_id)
  );

  CREATE TABLE IF NOT EXISTS grades (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    class_id TEXT NOT NULL,
    student_id TEXT NOT NULL,
    score REAL NOT NULL CHECK (score BETWEEN 0 AND 100),
    is_final INTEGER NOT NULL DEFAULT 0 CHECK (is_final IN (0, 1)),
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (class_id, student_id)
      REFERENCES enrollments(class_id, student_id) ON DELETE CASCADE,
    UNIQUE (class_id, student_id)
  );

  CREATE TABLE IF NOT EXISTS transcripts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    student_id TEXT NOT NULL,
    class_id TEXT NOT NULL,
    score REAL NOT NULL CHECK (score BETWEEN 0 AND 100),
    finalized_at TEXT NOT NULL,
    synced_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (class_id, student_id)
      REFERENCES enrollments(class_id, student_id) ON DELETE CASCADE,
    UNIQUE (class_id, student_id)
  );

  CREATE TABLE IF NOT EXISTS refresh_tokens (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    device_id TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    revoked_at TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_time TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    subject TEXT,
    endpoint TEXT NOT NULL,
    device_id TEXT,
    result TEXT NOT NULL CHECK (result IN ('allow', 'deny')),
    reason TEXT NOT NULL
  );

  CREATE INDEX IF NOT EXISTS idx_devices_user
    ON devices(user_id);

  CREATE INDEX IF NOT EXISTS idx_classes_lecturer
    ON classes(lecturer_id);

  CREATE INDEX IF NOT EXISTS idx_enrollments_student
    ON enrollments(student_id);

  CREATE INDEX IF NOT EXISTS idx_grades_student
    ON grades(student_id);

  CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user
    ON refresh_tokens(user_id);

  CREATE INDEX IF NOT EXISTS idx_audit_event_time
    ON audit_logs(event_time);
`);

// Data awal untuk praktikum
const seedUsers = [{
        id: 'u-admin',
        username: 'admin',
        password: 'Admin@12345',
        fullName: 'Administrator',
        role: 'admin',
        nim: null,
        deviceId: 'DEV-ADMIN-001',
        deviceName: 'Laptop Admin',
    },
    {
        id: 'u-dosen1',
        username: 'dosen1',
        password: 'Dosen@12345',
        fullName: 'Dosen Informatika 1',
        role: 'dosen',
        nim: null,
        deviceId: 'DEV-DOSEN-001',
        deviceName: 'Laptop Dosen 1',
    },
    {
        id: 'u-dosen2',
        username: 'dosen2',
        password: 'Dosen@12345',
        fullName: 'Dosen Informatika 2',
        role: 'dosen',
        nim: null,
        deviceId: 'DEV-DOSEN-002',
        deviceName: 'Laptop Dosen 2',
    },
    {
        id: 'u-mhs1',
        username: 'mhs1',
        password: 'Mhs@12345',
        fullName: 'Mahasiswa 1',
        role: 'mahasiswa',
        nim: '2024001',
        deviceId: 'DEV-MHS-001',
        deviceName: 'Laptop Mahasiswa 1',
    },
    {
        id: 'u-mhs2',
        username: 'mhs2',
        password: 'Mhs@12345',
        fullName: 'Mahasiswa 2',
        role: 'mahasiswa',
        nim: '2024002',
        deviceId: 'DEV-MHS-002',
        deviceName: 'Laptop Mahasiswa 2',
    },
    {
        id: 'u-mhs3',
        username: 'mhs3',
        password: 'Mhs@12345',
        fullName: 'Mahasiswa 3',
        role: 'mahasiswa',
        nim: '2024003',
        deviceId: 'DEV-MHS-003',
        deviceName: 'Laptop Mahasiswa 3',
    },
];

function seedDatabase() {
    const seed = db.transaction(() => {
        const insertUser = db.prepare(`
      INSERT OR IGNORE INTO users
        (id, username, password_hash, full_name, role, nim)
      VALUES (?, ?, ?, ?, ?, ?)
    `);

        const insertDevice = db.prepare(`
      INSERT OR IGNORE INTO devices
        (user_id, device_code, device_name)
      VALUES (?, ?, ?)
    `);

        // Membuat akun dan device terdaftar
        for (const user of seedUsers) {
            const passwordHash = bcrypt.hashSync(user.password, 10);

            insertUser.run(
                user.id,
                user.username,
                passwordHash,
                user.fullName,
                user.role,
                user.nim
            );

            insertDevice.run(
                user.id,
                user.deviceId,
                user.deviceName
            );
        }

        // Dua kelas dengan dosen yang berbeda
        const insertClass = db.prepare(`
      INSERT OR IGNORE INTO classes (id, name, lecturer_id)
      VALUES (?, ?, ?)
    `);

        insertClass.run(
            'IF101',
            'Keamanan Informasi',
            'u-dosen1'
        );

        insertClass.run(
            'IF102',
            'Sistem Keamanan Komputer',
            'u-dosen2'
        );

        // Ketiga mahasiswa terdaftar pada kedua kelas
        const insertEnrollment = db.prepare(`
      INSERT OR IGNORE INTO enrollments (class_id, student_id)
      VALUES (?, ?)
    `);

        const students = ['u-mhs1', 'u-mhs2', 'u-mhs3'];
        const classes = ['IF101', 'IF102'];

        for (const classId of classes) {
            for (const studentId of students) {
                insertEnrollment.run(classId, studentId);
            }
        }

        // Nilai awal belum difinalisasi
        const insertGrade = db.prepare(`
      INSERT OR IGNORE INTO grades
        (class_id, student_id, score, is_final)
      VALUES (?, ?, ?, 0)
    `);

        const initialGrades = [
            ['IF101', 'u-mhs1', 85],
            ['IF101', 'u-mhs2', 78],
            ['IF101', 'u-mhs3', 90],
            ['IF102', 'u-mhs1', 88],
            ['IF102', 'u-mhs2', 82],
            ['IF102', 'u-mhs3', 76],
        ];

        for (const grade of initialGrades) {
            insertGrade.run(...grade);
        }
    });

    seed();
}

// Database dapat digunakan oleh gateway dan kedua service
module.exports = { db, dbPath, seedDatabase };

// Saat dijalankan langsung melalui npm run seed
if (require.main === module) {
    seedDatabase();

    console.log('\nDatabase berhasil disiapkan!');
    console.log('Lokasi:', dbPath);
    console.log('Akun awal dan device ID:');

    for (const user of seedUsers) {
        console.log(
            `${user.username} | ${user.password} | ${user.deviceId}`
        );
    }

    console.log('\nJumlah akun:', db.prepare(
        'SELECT COUNT(*) AS total FROM users'
    ).get().total);

    console.log('Jumlah kelas:', db.prepare(
        'SELECT COUNT(*) AS total FROM classes'
    ).get().total);

    console.log('Jumlah nilai:', db.prepare(
        'SELECT COUNT(*) AS total FROM grades'
    ).get().total);
}