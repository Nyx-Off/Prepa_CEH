# Reconnaissance de root-me.org

**Date de l'analyse:** 27 Février 2026
**Contexte:** Exercice éducatif - Cours de cybersécurité
**Type:** Reconnaissance passive et active (cartographie)

---

## 1. Adresse IP Publique

### Commande utilisée:
```bash
host root-me.org
dig root-me.org +short
```

### Résultat:
```
root-me.org has address 212.129.28.16
root-me.org mail is handled by 1 mx1.mail.ovh.net.
root-me.org mail is handled by 5 mx2.mail.ovh.net.
root-me.org mail is handled by 100 mx3.mail.ovh.net.
```

| Information | Valeur |
|-------------|--------|
| **IPv4** | 212.129.28.16 |
| **IPv6** | Non configuré sur le domaine principal |
| **Localisation** | France (Paris) |
| **Hébergeur** | Scaleway Dedibox / Online SAS |
| **ASN** | AS12876 |

---

## 2. WHOIS

### Commande utilisée:
```bash
whois root-me.org
```

### Résultat:
```
Domain Name: root-me.org
Registry Domain ID: REDACTED
Registrar WHOIS Server: http://whois.ovh.com
Registrar URL: http://www.ovh.com
Updated Date: 2025-05-20T06:03:15Z
Creation Date: 2010-02-19T16:01:27Z
Registry Expiry Date: 2030-02-19T16:01:27Z
Registrar: OVH sas
Registrar IANA ID: 433
Registrar Abuse Contact Email: abuse@ovh.net
Registrar Abuse Contact Phone: +33.972101007
Domain Status: clientDeleteProhibited
Domain Status: clientTransferProhibited
Name Server: dns200.anycast.me
Name Server: ns200.anycast.me
DNSSEC: signedDelegation
```

| Information | Valeur |
|-------------|--------|
| **Registrar** | OVH SAS |
| **Date de création** | 19 Février 2010 |
| **Date d'expiration** | 19 Février 2030 |
| **Serveurs DNS** | dns200.anycast.me, ns200.anycast.me |
| **DNSSEC** | Activé (signedDelegation) |

---

## 3. Sous-domaines découverts

### Commandes utilisées:
```bash
subfinder -d root-me.org -silent
amass enum -passive -d root-me.org
dnsrecon -d root-me.org -t std
```

### Résultats:

#### Infrastructure principale:
| Sous-domaine | IP | Description |
|--------------|-----|-------------|
| www.root-me.org | 212.129.28.16 | Site principal |
| challenge01.root-me.org | 212.129.38.224 | Serveur de challenges |
| challenge02.root-me.org | 212.129.38.224 | Serveur de challenges |
| challenge03.root-me.org | 212.129.38.224 | Serveur de challenges |
| challenge05.root-me.org | 212.129.38.224 | Serveur de challenges |
| webssh.root-me.org | CNAME → challenge01 | Accès SSH web |
| static.root-me.org | CNAME → challenge01 | Ressources statiques |
| dev.root-me.org | - | Environnement dev |
| myavatar.root-me.org | - | Service avatars |
| ipv6.www.root-me.org | - | Accès IPv6 |

#### Serveurs CTF (Capture The Flag):
| Sous-domaine | IP |
|--------------|-----|
| ctf03.root-me.org | 212.129.29.185 |
| ctf10.root-me.org | - |
| ctf12.root-me.org | - |
| ctf15.root-me.org | 212.83.175.152 |
| ctf20.root-me.org | 163.172.195.228 |
| ctf25.root-me.org | 163.172.228.174 |
| ctf27.root-me.org | 163.172.228.194 |
| ctf30.root-me.org | 163.172.229.107 |
| ctf44.root-me.org | 212.83.172.192 |
| ctf45.root-me.org | 212.83.172.198 |
| ctf50.root-me.org | 212.83.173.35 |

#### Instances AWS EC2:
```
ec2-35-180-4-28.aws.root-me.org
ec2-13-39-48-40.aws.root-me.org
ec2-13-37-57-31.aws.root-me.org
ec2-35-180-138-146.aws.root-me.org
ec2-35-180-36-160.aws.root-me.org
ec2-15-188-54-124.aws.root-me.org
ec2-13-39-82-197.aws.root-me.org
ec2-15-188-64-68.aws.root-me.org
ec2-15-188-56-53.aws.root-me.org
ec2-35-180-100-117.aws.root-me.org
ec2-35-180-192-30.aws.root-me.org
ec2-15-236-207-233.aws.root-me.org
ec2-13-38-228-184.aws.root-me.org
ec2-13-38-216-171.aws.root-me.org
```

#### Services professionnels (Root-Me PRO):
| Sous-domaine | Description |
|--------------|-------------|
| pro.root-me.org | Portail entreprises/écoles |
| shop.root-me.org | Boutique officielle |
| ac-paris.pro.root-me.org | Académie de Paris |
| csi-ctf.pro.root-me.org | CSI CTF |
| ctf-certa.pro.root-me.org | CERTA CTF |
| ctf-ipi.pro.root-me.org | IPI CTF |
| challenges.airbus.pro.root-me.org | Challenges Airbus |

#### Services mail:
| Sous-domaine | Cible |
|--------------|-------|
| imap.root-me.org | CNAME → ssl0.ovh.net |

---

## 4. Technologies Web

### Commandes utilisées:
```bash
whatweb root-me.org
curl -s -I https://root-me.org
```

### Résultats:
```
https://www.root-me.org/ [200 OK]
- Country: FRANCE
- HTTPServer: nginx
- IP: 212.129.28.16
- SPIP (CMS)
- HTML5
- Script: text/javascript
- Strict-Transport-Security: max-age=15768000
- X-XSS-Protection: 1; mode=block
- Content-Security-Policy: configuré
```

### Stack technologique identifié:

| Composant | Technologie |
|-----------|-------------|
| **Serveur Web** | Nginx |
| **CMS** | SPIP (Système de Publication pour Internet Partagé) |
| **Frontend** | HTML5, JavaScript, jQuery |
| **Certificat SSL** | Let's Encrypt (R13) - RSA 2048-bit |
| **CDN/Proxy** | HAProxy 2.0.0+ |
| **Analytics** | Google Analytics (G-SRYSKX09J7) |

### Headers de sécurité:
```http
HTTP/2 301
server: nginx
strict-transport-security: max-age=15768000
x-xss-protection: 1; mode=block
content-security-policy: [configuré]
x-spip-cache: [présent]
```

---

## 5. Services Exposés

### Commande utilisée:
```bash
nmap -sV -sC -T4 --top-ports 100 212.129.28.16
```

### Résultat:
```
Starting Nmap 7.95 ( https://nmap.org )
Nmap scan report for www.root-me.org (212.129.28.16)
Host is up (0.0043s latency).
Not shown: 98 filtered tcp ports (no-response)

PORT    STATE SERVICE    VERSION
80/tcp  open  http-proxy HAProxy http proxy 2.0.0 or later
443/tcp open  ssl/https  nginx

Service Info: Device: load balancer
```

### Résumé des services:

| Port | État | Service | Version |
|------|------|---------|---------|
| 80/tcp | Open | HTTP | HAProxy 2.0.0+ (redirect vers HTTPS) |
| 443/tcp | Open | HTTPS | Nginx |

### Informations Shodan:
- **Ports ouverts:** 80, 443
- **Serveur:** Nginx
- **Certificat:** Let's Encrypt R13, valide du 28/12/2025 au 28/03/2026
- **Hébergeur:** Scaleway Dedibox IPFO, Paris, France

---

## 6. Enregistrements DNS

### Commandes utilisées:
```bash
dig root-me.org ANY
dig +short TXT root-me.org
dnsrecon -d root-me.org -t std
```

### Enregistrements:

| Type | Valeur |
|------|--------|
| **A** | 212.129.28.16 |
| **SOA** | dns200.anycast.me (46.105.206.200) |
| **NS** | ns200.anycast.me, dns200.anycast.me |
| **MX** | mx1.mail.ovh.net (priorité 1), mx2.mail.ovh.net (5), mx3.mail.ovh.net (100) |
| **TXT (SPF)** | v=spf1 a:service.root-me.org include:mx.ovh.com ~all |
| **TXT** | google-site-verification=fhnZ_3PpIq5HepVdk4DXFmjsWmUBabr7PKLMG1gszhA |

### Enregistrements SRV:
| Service | Cible | Port |
|---------|-------|------|
| _submission._tcp | ssl0.ovh.net | 465 |
| _imaps._tcp | ssl0.ovh.net | 993 |
| _autodiscover._tcp | mailconfig.ovh.net | 443 |

---

## 7. Emails et Contacts

### Commande utilisée:
```bash
theHarvester -d root-me.org -b all
```

### Emails identifiés:

| Email | Source |
|-------|--------|
| contact@pro.root-me.org | Site officiel |
| abuse@ovh.net | WHOIS (registrar) |

### Réseaux sociaux:
- **Twitter/X:** @rootme_org
- **LinkedIn:** Root-Me Pro (15,700+ followers)
- **Discord:** Serveur communautaire

### Informations complémentaires:
- **Localisation (Root-Me Pro):** Saint-Cyr-au-Mont-d'Or, Auvergne-Rhône-Alpes, France
- **Type d'organisation:** Association à but non lucratif
- **Employés (PRO):** ~37 personnes

---

## 8. Google Dorking

### Requêtes utilisées:

```
site:root-me.org filetype:pdf
site:root-me.org inurl:admin OR inurl:login
```

### Résultats intéressants:

#### Repository de documentation:
Le domaine `repository.root-me.org` héberge de nombreuses ressources éducatives:

| Document | URL |
|----------|-----|
| Hacking WiFi | repository.root-me.org/Réseau/EN - Hacking wifi.pdf |
| Malicious PDF | repository.root-me.org/Stéganographie/EN - Malicious Origami in PDF.pdf |
| JavaScript Basics | repository.root-me.org/Programmation/Javascript/FR - Bases du javascript.pdf |
| Printer Steganography | repository.root-me.org/Stéganographie/EN - Printer-Steganography.pdf |
| Computer Viruses | repository.root-me.org/Virologie/EN - Computer viruses from theory to applications.pdf |
| Commandes Google (Dorks) | repository.root-me.org/Exploitation - Web/FR - commandes google.pdf |

---

## 9. Résumé de l'infrastructure

### Architecture réseau:

```
                    ┌─────────────────────┐
                    │   Internet          │
                    └──────────┬──────────┘
                               │
                    ┌──────────▼──────────┐
                    │  HAProxy (LB)       │
                    │  212.129.28.16      │
                    └──────────┬──────────┘
                               │
          ┌────────────────────┼────────────────────┐
          │                    │                    │
┌─────────▼─────────┐ ┌────────▼────────┐ ┌────────▼────────┐
│  www.root-me.org  │ │ challenge0X     │ │ ctfXX.root-me   │
│  (Nginx + SPIP)   │ │ 212.129.38.224  │ │ (Scaleway VPS)  │
└───────────────────┘ └─────────────────┘ └─────────────────┘
                               │
                    ┌──────────▼──────────┐
                    │  AWS EC2 Instances  │
                    │  (eu-west-3)        │
                    └─────────────────────┘
```

### Netblocks identifiés:
- 212.129.0.0/18 (Online SAS / Scaleway)
- 212.83.128.0/18 (Online SAS / Scaleway)
- 163.172.224.0/19 (Online SAS / Scaleway)
- 2001:bc8:2000::/35 (IPv6)

### Services tiers:
| Service | Fournisseur |
|---------|-------------|
| DNS | OVH Anycast |
| Email | OVH Mail |
| Certificat SSL | Let's Encrypt |
| Analytics | Google Analytics |
| Cloud | AWS EC2 (eu-west-3) |
| Hébergement | Scaleway Dedibox |

---

## 10. Points d'attention (Sans exploitation)

### Observations:

1. **Wildcard DNS activé** - Le domaine résout toutes les requêtes non existantes vers www.root-me.org
2. **DNSSEC activé** - Bonne pratique de sécurité
3. **HSTS activé** - Protection contre le downgrade HTTPS
4. **CSP configuré** - Content Security Policy présente
5. **Multiple serveurs CTF** - Infrastructure distribuée pour les challenges
6. **Instances AWS dynamiques** - Utilisation de cloud pour certains services

### Headers de sécurité présents:
- Strict-Transport-Security
- X-XSS-Protection
- Content-Security-Policy

---

## Outils utilisés

| Outil | Usage |
|-------|-------|
| `host` | Résolution DNS basique |
| `dig` | Requêtes DNS avancées |
| `whois` | Informations d'enregistrement |
| `nmap` | Scan de ports et services |
| `whatweb` | Fingerprinting web |
| `subfinder` | Énumération de sous-domaines |
| `amass` | OSINT et énumération |
| `dnsrecon` | Reconnaissance DNS |
| `theHarvester` | Recherche d'emails et sous-domaines |
| `curl` | Requêtes HTTP manuelles |
| Shodan | Reconnaissance d'infrastructure |
| Google Dorks | Recherche de fichiers exposés |

---

## Conclusion

Root-me.org est une plateforme de formation en cybersécurité bien structurée, hébergée principalement chez Scaleway (France) avec une extension sur AWS pour certains services. L'infrastructure montre de bonnes pratiques de sécurité (DNSSEC, HSTS, CSP). La plateforme utilise le CMS SPIP derrière un load balancer HAProxy et un serveur Nginx. Le domaine est enregistré depuis 2010 et dispose d'une infrastructure distribuée pour les challenges CTF.

---

*Ce rapport a été généré à des fins éducatives uniquement.*
