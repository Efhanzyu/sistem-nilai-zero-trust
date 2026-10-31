# Sistem Nilai - Zero Trust Security

**Tugas Praktikum Individu**  
Mata Kuliah Keamanan Informasi (KP70065004)  
Informatika - Universitas Siliwangi

## 1. Deskripsi

Sistem Nilai adalah aplikasi API berbasis Node.js, Express, dan SQLite untuk mempraktikkan prinsip Zero Trust Security:

- **Never trust, always verify**: request diperiksa sebelum diteruskan.
- **Least privilege**: pengguna hanya memperoleh akses sesuai perannya.
- **Assume breach**: setiap service tetap memverifikasi gateway secret dan token.

Aplikasi terdiri dari API Gateway, Policy Engine, Service Nilai, Service Transkrip, database SQLite bersama, dan audit log.

## 2. Arsitektur

| Komponen | Port | Fungsi |
|---|---:|---|
| API Gateway | 3000 | Login/token, pemeriksaan kebijakan, audit log, penerusan request |
| Service Nilai | 3001 | Membaca, mengubah, dan memfinalisasi nilai |
| Service Transkrip | 3002 | Membaca transkrip dan menerima sinkronisasi nilai final |
| SQLite | - | Menyimpan pengguna, device, kelas, nilai, token, transkrip, dan audit log |

Request pengguna ke endpoint aplikasi harus melewati Gateway. Ketika meneruskan request, Gateway menambahkan `X-Gateway-Secret`. Kedua service juga memverifikasi secret tersebut serta tanda tangan dan masa berlaku JWT.

## 3. Persyaratan

- Node.js 18 atau lebih baru.
- npm.
- PowerShell atau terminal lain.
- Postman bersifat opsional; pengujian dapat dilakukan dengan PowerShell atau `curl`.

Dependensi utama: `express`, `jsonwebtoken`, `bcryptjs`, `better-sqlite3`, dan `dotenv`.

## 4. Instalasi dan konfigurasi

Jalankan perintah berikut dari folder proyek:

```powershell
npm install
```

Pastikan file `.env` tersedia. Jika belum, salin contoh konfigurasi:

```powershell
Copy-Item .env.example .env
```

Isi `.env` dengan konfigurasi berikut. Ganti setiap placeholder secret dengan nilai acak yang kuat; jangan memakai teks placeholder sebagai secret sebenarnya.

```dotenv
PORT=3000
NILAI_PORT=3001
TRANSKRIP_PORT=3002
DB_PATH=data/zero-trust.db

JWT_SECRET=ganti-dengan-secret-acak
GATEWAY_SECRET=ganti-dengan-secret-acak

SERVICE_CLIENT_ID=nilai-service
SERVICE_CLIENT_SECRET=ganti-dengan-secret-acak

ACCESS_TOKEN_TTL=10m
REFRESH_TOKEN_TTL=1d
SERVICE_TOKEN_TTL=5m

ACCESS_WINDOW_START=07:00
ACCESS_WINDOW_END=21:00
```

Di PowerShell, secret dapat dibuat secara lokal dengan perintah seperti berikut (jalankan terpisah untuk setiap secret):

```powershell
node -e "process.stdout.write(require('crypto').randomBytes(32).toString('hex'))"
```

Jangan pernah mengunggah `.env` atau membagikan nilainya. File `.env.example` hanya berisi placeholder.

## 5. Membuat database dan data awal

Jalankan:

```powershell
npm run seed
```

Database akan dibuat pada `data/zero-trust.db`. Seed menyiapkan enam pengguna, enam device terdaftar, dua kelas, pendaftaran tiga mahasiswa pada kedua kelas, dan enam nilai awal.

Seed menggunakan `INSERT OR IGNORE`. Menjalankan seed kembali pada database yang sudah ada tidak mereset nilai atau status finalisasi yang sudah berubah.

## 6. Menjalankan aplikasi

Jalankan setiap komponen pada terminal terpisah. Biarkan ketiga terminal tetap berjalan.

**Terminal 1 - API Gateway:**

```powershell
npm start
```

**Terminal 2 - Service Nilai:**

```powershell
npm run start:nilai
```

**Terminal 3 - Service Transkrip:**

```powershell
npm run start:transkrip
```

Alamat lokal:

- Gateway: `http://127.0.0.1:3000`
- Service Nilai: `http://127.0.0.1:3001`
- Service Transkrip: `http://127.0.0.1:3002`

Ketiga proses harus hidup bersamaan untuk mendukung finalisasi dan sinkronisasi transkrip.

## 7. Akun demo dan data awal

Semua akun berikut khusus untuk pengujian praktikum lokal.

| Role | Username | Password | Device ID |
|---|---|---|---|
| Admin | `admin` | `Admin@12345` | `DEV-ADMIN-001` |
| Dosen 1 | `dosen1` | `Dosen@12345` | `DEV-DOSEN-001` |
| Dosen 2 | `dosen2` | `Dosen@12345` | `DEV-DOSEN-002` |
| Mahasiswa 1 | `mhs1` | `Mhs@12345` | `DEV-MHS-001` |
| Mahasiswa 2 | `mhs2` | `Mhs@12345` | `DEV-MHS-002` |
| Mahasiswa 3 | `mhs3` | `Mhs@12345` | `DEV-MHS-003` |

NIM: `mhs1` = `2024001`, `mhs2` = `2024002`, `mhs3` = `2024003`.

| Kode | Mata Kuliah | Dosen pengampu |
|---|---|---|
| IF101 | Keamanan Informasi | `dosen1` |
| IF102 | Sistem Keamanan Komputer | `dosen2` |

## 8. Endpoint API

Endpoint pengguna di bawah ini dipanggil melalui Gateway.

| Method | Endpoint | Keterangan |
|---|---|---|
| `POST` | `/auth/login` | Login dan menerbitkan access serta refresh token |
| `POST` | `/auth/refresh` | Memutar refresh token dan menerbitkan token baru |
| `POST` | `/auth/logout` | Mencabut refresh token |
| `POST` | `/auth/service` | Menerbitkan token service menggunakan client ID dan secret |
| `GET` | `/nilai` | Melihat nilai sesuai role; dapat memakai query `classId` |
| `PUT` | `/nilai/:id` | Mengubah nilai yang belum final |
| `POST` | `/kelas/:id/finalisasi` | Finalisasi semua nilai dalam kelas dan meminta sinkronisasi transkrip |
| `GET` | `/transkrip/:nim` | Melihat transkrip sesuai role dan NIM |
| `POST` | `/transkrip/sinkron` | Sinkronisasi hanya dengan token service yang sah |

Request pengguna pada endpoint terlindungi memerlukan header:

```http
Authorization: Bearer <access-token>
X-Device-ID: <device-terdaftar>
```

Gateway menambahkan header `X-Gateway-Secret` saat meneruskan request ke service. Jangan mengirim secret ini dari client.

### Contoh login menggunakan PowerShell

```powershell
$body = @{ username = 'mhs1'; password = 'Mhs@12345' } | ConvertTo-Json
$session = Invoke-RestMethod -Method Post `
  -Uri 'http://127.0.0.1:3000/auth/login' `
  -Headers @{ 'X-Device-ID' = 'DEV-MHS-001' } `
  -ContentType 'application/json' -Body $body

# Jangan mencetak atau membagikan token rahasia.
```

Contoh membaca nilai mahasiswa:

```powershell
Invoke-RestMethod -Method Get `
  -Uri 'http://127.0.0.1:3000/nilai' `
  -Headers @{
    'Authorization' = "Bearer $($session.accessToken)"
    'X-Device-ID' = 'DEV-MHS-001'
  }
```

Contoh body perubahan nilai untuk `PUT /nilai/1`:

```json
{
  "score": 86
}
```

Contoh finalisasi kelas: `POST /kelas/IF101/finalisasi` dengan body JSON kosong `{}`. Finalisasi hanya boleh dilakukan dosen pengampu selama jam akses yang dikonfigurasi.

## 9. Kebijakan akses

- Mahasiswa hanya dapat melihat nilai dan transkrip miliknya sendiri.
- Dosen hanya dapat melihat nilai kelas yang diampu.
- Dosen hanya dapat mengubah nilai yang belum final.
- Hanya dosen pengampu yang boleh memfinalisasi kelas.
- Admin dapat melihat transkrip seluruh mahasiswa.
- Hanya token service yang sah yang boleh menjalankan sinkronisasi transkrip.
- Request pengguna memerlukan device ID yang terdaftar bagi pengguna tersebut.
- Perubahan dan finalisasi nilai dibatasi pada jam akses yang dikonfigurasi, default 07.00-21.00.
- Service memeriksa gateway secret serta tanda tangan dan masa berlaku JWT.
- Gateway mencatat keputusan akses ke tabel `audit_logs`.

## 10. Token

| Jenis token | Masa berlaku |
|---|---|
| Access token pengguna | 10 menit |
| Refresh token | 1 hari |
| Token service | 5 menit |

Refresh token disimpan sebagai hash di database. Proses refresh mencabut token lama dan menerbitkan token baru. Logout mencabut refresh token. Access token JWT yang sudah diterbitkan tetap berlaku sampai kedaluwarsa karena aplikasi ini belum menerapkan pencabutan access token secara langsung.

## 11. Memeriksa audit log

Jalankan perintah berikut untuk menampilkan 20 audit log terakhir:

```powershell
node -e "const {db}=require('./src/db'); console.table(db.prepare('SELECT event_time, subject, endpoint, device_id, result, reason FROM audit_logs ORDER BY id DESC LIMIT 20').all()); db.close();"
```

Audit log berisi waktu, subjek, endpoint, device ID, keputusan (`allow` atau `deny`), dan alasan.

## 12. Skenario pengujian

Pengujian yang telah dilakukan pada aplikasi:

1. Login admin, dosen, dan mahasiswa menggunakan device terdaftar.
2. Mahasiswa melihat nilai miliknya.
3. Mahasiswa ditolak saat meminta transkrip mahasiswa lain (HTTP 403).
4. Dosen melihat nilai kelas yang diampu dan ditolak saat meminta kelas dosen lain (HTTP 403).
5. Dosen mengubah nilai melalui Gateway.
6. Nilai kelas IF101 difinalisasi dan ditampilkan di transkrip.
7. Perubahan nilai final ditolak (HTTP 403).
8. Login dari device tidak terdaftar ditolak (HTTP 403).
9. Refresh token berhasil; pemakaian ulang refresh token lama ditolak (HTTP 401).
10. Logout mencabut refresh token; refresh sesudah logout ditolak (HTTP 401).
11. Audit log mencatat keputusan allow dan deny.
12. Admin dapat membaca transkrip mahasiswa lain.
13. Sinkronisasi transkrip menggunakan token mahasiswa ditolak (HTTP 403).
14. Akses langsung ke Service Nilai dan Service Transkrip tanpa gateway secret ditolak (HTTP 403).

## 13. Struktur folder

```text
sistem-nilai-zero-trust/
|-- src/
|   |-- db.js
|   |-- policy.js
|   |-- gateway.js
|   |-- nilai-service.js
|   `-- transkrip-service.js
|-- data/
|   `-- zero-trust.db          (dibuat secara lokal; tidak di-commit)
|-- .env                       (rahasia lokal; tidak di-commit)
|-- .env.example
|-- .gitignore
|-- package.json
|-- package-lock.json
`-- README.md
```

Pastikan `.gitignore` memuat setidaknya:

```gitignore
node_modules/
.env
data/*.db
data/*.db-shm
data/*.db-wal
```

## 14. Batasan dan pengembangan

Aplikasi ini dibuat untuk praktikum lokal. Sebelum digunakan di lingkungan produksi, diperlukan penguatan tambahan, antara lain pencabutan access token jika diperlukan, pengelolaan secret yang lebih aman, validasi request yang lebih menyeluruh, pembatasan jaringan, pengujian konkurensi, serta penanganan kegagalan audit log.
