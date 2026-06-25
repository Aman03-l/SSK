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
