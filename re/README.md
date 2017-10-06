
During the RadareCON 2017 in Barcelona a binary to win a RHme3 board was provided. The binary was an OLLVM obfuscated binary with some anti-debugging and anti-hooking techniques to thwart reversers. Thus the binary was named `antir2`.

The following r2con attendants solved the challenge:
  - Cyrill Leutwiler
  - Roberto Gutierrez
  - Quentin Casasnovas

Other write-ups that are worth mentioning them:
  - Irdeto team (Jonathan Beverley, Colin deWinter, Ben Gardiner)
  - Vegard Nossum


# Write-up by Quentin Casasnovas
Running the binary shows some plaintext which is then cyphered, printed,
decyphered and printed again.  The goal seems to find the AES key:

```sh
r2@57f5b63ba13a prequals-rhme3 $ ./antir2
*******************************************
* Radare2con 2017 rhme3 pre-quals edition *
*******************************************

r<< Can you r2 me?

Plaintext : 47 65 74 20 74 68 65 20 61 65 73 6B 65 79 21 21
Encrypted : FD DA 9B 78 FC F8 E9 BF 33 72 6E 0A 8A E5 F6 8C
Decrypted : 47 65 74 20 74 68 65 20 61 65 73 6B 65 79 21 21
```

OK let's see what rabin2 tells us about the binary:

```sh
r2@57f5b63ba13a prequals-rhme3 $ rabin2 -I antir2
arch     x86
binsz    1200746
bintype  elf
bits     64
canary   false
class    ELF64
crypto   false
endian   little
havecode true
lang     c
linenum  false
lsyms    false
machine  AMD x86-64 architecture
maxopsz  16
minopsz  1
nx       true
os       linux
pcalign  0
pic      false
relocs   false
rpath    NONE
static   true
stripped true
subsys   linux
va       true
```

It's statically linked and stripped.  Next logical step is to have a look
around at the strings:

```sh
r2@57f5b63ba13a prequals-rhme3 $ rabin2 -z antir2
```

Loads of them, as expected since it's statically linked. The first few ones
are interestings and shows the binary probably has some built-in
anti-debugging features, and that it might look for frida as well:

```sh
r2@57f5b63ba13a wargames/prequals-rhme3 $ rabin2 -z antir2 | head -n20                        0
vaddr=0x004e1b8f paddr=0x000e1b8f ordinal=000 sz=38 len=37 section=.rodata type=ascii string=.Get the aeskey!!r<< Can you r2 me?\n\n
vaddr=0x004e1bb5 paddr=0x000e1bb5 ordinal=001 sz=10 len=9 section=.rodata type=ascii string=Plaintext
vaddr=0x004e1bbf paddr=0x000e1bbf ordinal=002 sz=10 len=9 section=.rodata type=ascii string=Encrypted
vaddr=0x004e1bc9 paddr=0x000e1bc9 ordinal=003 sz=10 len=9 section=.rodata type=ascii string=Decrypted
vaddr=0x004e1bd3 paddr=0x000e1bd3 ordinal=004 sz=45 len=44 section=.rodata type=ascii string=*******************************************\n
vaddr=0x004e1c00 paddr=0x000e1c00 ordinal=005 sz=45 len=44 section=.rodata type=ascii string=* Radare2con 2017 rhme3 pre-quals edition *\n
vaddr=0x004e1c2d paddr=0x000e1c2d ordinal=006 sz=46 len=45 section=.rodata type=ascii string=*******************************************\n\n
vaddr=0x004e1c5b paddr=0x000e1c5b ordinal=007 sz=6 len=5 section=.rodata type=ascii string=%s :
vaddr=0x004e1c61 paddr=0x000e1c61 ordinal=008 sz=6 len=5 section=.rodata type=ascii string=%02X
vaddr=0x004e1c67 paddr=0x000e1c67 ordinal=009 sz=57 len=56 section=.rodata type=ascii string=r2 in debug mode won't help you much! ha ha ha...... :)\n
vaddr=0x004e1ca0 paddr=0x000e1ca0 ordinal=010 sz=31 len=30 section=.rodata type=ascii string=Breakpoint detected @ %p+%x !\n
vaddr=0x004e1cbf paddr=0x000e1cbf ordinal=011 sz=16 len=15 section=.rodata type=ascii string=/proc/self/maps
vaddr=0x004e1ccf paddr=0x000e1ccf ordinal=012 sz=6 len=5 section=.rodata type=ascii string=frida
vaddr=0x004e1cd5 paddr=0x000e1cd5 ordinal=013 sz=49 len=48 section=.rodata type=ascii string=Damn it! You're so shady! h00king isn't allowed\n
vaddr=0x004e1d06 paddr=0x000e1d06 ordinal=014 sz=13 len=12 section=.rodata type=ascii string=aes(partial)
vaddr=0x004e1d20 paddr=0x000e1d20 ordinal=015 sz=39 len=38 section=.rodata type=ascii string=AES part of OpenSSL 1.0.2g  1 Mar 2016
vaddr=0x004e1d47 paddr=0x000e1d47 ordinal=016 sz=11 len=10 section=.rodata type=ascii string=cryptlib.c
vaddr=0x004e1d52 paddr=0x000e1d52 ordinal=017 sz=8 len=7 section=.rodata type=ascii string=dynamic
vaddr=0x004e1d5a paddr=0x000e1d5a ordinal=018 sz=6 len=5 section=.rodata type=ascii string=ERROR
vaddr=0x004e1d60 paddr=0x000e1d60 ordinal=019 sz=16 len=15 section=.rodata type=ascii string=OPENSSL_ia32cap
```

It's statically linked with OpenSSL 1.0.2g, compiled 1 Mars 2016 so we
could probably generate some signatures provided we can find which
distributions it was compiled on to help with sorting out the mess.  Well
grepping for "Ubuntu" in the strings gives it away but let's try to dive in
first.

We fire radare2 in debug mode and run the binary:

```sh
r2@57f5b63ba13a wargames/prequals-rhme3 $ radare2 -d antir2
Process with PID 132 started...
= attach 132 132
bin.baddr 0x00400000
Using 0x400000
Warning: Cannot initialize dynamic strings
asm.bits 64
 -- Change the graph block definition with graph.callblocks, graph.jmpblocks, graph.flagblocks
[0x004008c0]> dc
*******************************************
* Radare2con 2017 rhme3 pre-quals edition *
*******************************************

r2 in debug mode won't help you much! ha ha ha...... :)
```

As expected we get rejected.  Let's have a look at the syscalls the binary
is using:

```sh
[0x004008c0]> dcs*
[0x004008c0]> dcs*
...

child stopped with signal 133
--> SN 0x00485fba syscall 101 ptrace (0x0 0x0 0x1 0x0)
child stopped with signal 133
--> SN 0x00485fba syscall 101 ptrace (0x0 0x0 0x1 0x0)
```

Ohoh, some `ptrace()` syscalls, looks like the binary is ptracing itself.  A
quick look from the ptrace.h header file, we see `0x0` is `PTRACE_ME`, so the
binary tries to ptrace itself, twice.  As we're debugging it already, both
calls will fail, and we're told out by antir2.  Alright, let's patch this
syscall instruction to clear eax so that it appears to succeed.  To do
this, we can use the Visual assembler from radare2 (need to re-open the
binary in write mode for this):

```sh
[0x00485fba]> s 0x00485fba
[0x00485fba]> V
```

We can hit `A` and then either `nop;nop<ENTER>`, or `xor eax, eax<ENTER>`.
We run the binary again, and... failure, the binary still complains.
Alright, it checks that the first call succeeds, and the second should
fail. Let's patch the two other call site with NOPs, we can find them by
looking at the cross references:

```sh
/ (fcn) fcn.00485f70 114
|   fcn.00485f70 ();
|              ; CALL XREF from 0x0041b5b0 (main)
|              ; CALL XREF from 0x0042116a (main)
|              ; CALL XREF from 0x0041a1bc (main)
|           0x00485f70      488d442408     lea rax, [rsp + 8]          ; 8
|           0x00485f75      448d47ff       lea r8d, [rdi - 1]
|           0x00485f79      4c8d5424b0     lea r10, [rsp - 0x50]
|           0x00485f7e      48897424d8     mov qword [rsp - 0x28], rsi
|           0x00485f83      48895424e0     mov qword [rsp - 0x20], rdx
```

That still doesn't work, instead of trying to understand the internal
logic, we can pretend the first ptrace succeeds right after the syscall
opcode by clearing eax, then let it fail as it ought to afterwards.

```sh
# I've used equivalent commands on gdb when solving this but am including
# how I would have done in r2land...
[0x00485fba]> dcs ptrace
[0x00485fba]> dr rax = 0
[0x00485fba]> dc
```

Alright, now let's keep looking.  We assume from the binary that some
routine cyphers/decyphers the text, so we can look at cross references from
the string Encrypted:

```sh
[0x004008c0]> f ~Encrypted  # This grep all flags for "Ecrypted"
0x004e1bbf 10 str.Encrypted
0x004f46e0 32 str.Microsoft_Encrypted_File_System
```

First one is a match, and we want to find where it's used from:
```sh
[0x004008c0]> axt `f ~Encrypted:0[0]`
data 0x400c7e mov eax, str.Encrypted in main
```

The syntax above takes the first line of the match, first column in a
subshell, which is then passed to axt to look for cross references.  We end
up on `0x400c7e`, around:

```sh
|           0x00400c51      41b9b51b4e00   mov r9d, str.Plaintext      ; 0x4e1bb5 ; "Plaintext"
|           0x00400c57      4489cf         mov edi, r9d
|           0x00400c5a      41b9901b4e00   mov r9d, 0x4e1b90           ; "Get the aeskey!!r<< Can you r2 me?\n\n"
|           0x00400c60      4489ce         mov esi, r9d
|           0x00400c63      41b910000000   mov r9d, 0x10               ; 16
|           0x00400c69      4489ca         mov edx, r9d
|           0x00400c6c      898550fdffff   mov dword [local_2b0h], eax
|           0x00400c72      44898d4cfdff.  mov dword [local_2b4h], r9d
|           0x00400c79      e8c20a0100     call 0x411740               ;[2]
|           0x00400c7e      b8bf1b4e00     mov eax, str.Encrypted      ; 0x4e1bbf ; "Encrypted"
|           0x00400c83      89c7           mov edi, eax
|           0x00400c85      488bb568fdff.  mov rsi, qword [local_298h]
|           0x00400c8c      8b954cfdffff   mov edx, dword [local_2b4h]
|           0x00400c92      e8a90a0100     call 0x411740               ;[2]
|           0x00400c97      b8c91b4e00     mov eax, str.Decrypted      ; 0x4e1bc9 ; "Decrypted"
|           0x00400c9c      89c7           mov edi, eax
|           0x00400c9e      488bb558fdff.  mov rsi, qword [local_2a8h]
|           0x00400ca5      8b954cfdffff   mov edx, dword [local_2b4h]
|           0x00400cab      e8900a0100     call 0x411740               ;[2]
```

Looks like `0x411740` is the function printing the line with the buffer.
Let's find where the buffer is in memory first:
```sh
drx 1 0x00400c92 x # Add hardware breakpoint to the tracee
dc
dr
```

We use hardware breakpoints in case there are other anti-debugging
techniques looking for int3 in the code (remember the string from running
rabin2 -z about the detected breakpoint!).  The two buffers for
encrypted/decrypted are at `0x7fffffffd860` and `0x7fffffffd870`.  We can now
add a watchpoints to see when this is being written to:

```sh
# Re-open binary
doo
# Setup our watchpoints
drw 1 0x7fffffffd860 8 w
drw 2 0x7fffffffd870 8 w
# Continue
dc
# Look at what's in there
px 32 @ 0x7fffffffd860
dc
```

BTW, `dm` will show us this address is on stack, and we keep hitting it at
the program startup for false positive until finally it gets written the
bytes we expect.  At that point we can use `dbt` to get a backtrace or just
print `dr rip` to get the instruction pointer.  We appear to be at
0x0042d17a, which is writing `eax` into `[r9]`, and the last thing that
happened before that is `fcn.0042bff0`...
```sh
|       |   0x0042d166      e885eeffff     call fcn.0042bff0           ;[1]
|       |   0x0042d16b      4c8b442418     mov r8, qword [rsp + 0x18]  ; [0x18:8]=-1 ; 24
|       |   0x0042d170      4c8b4c2420     mov r9, qword [rsp + 0x20]  ; [0x20:8]=-1 ; 32
|       |   0x0042d175      4c8b542428     mov r10, qword [rsp + 0x28] ; [0x28:8]=-1 ; '(' ; 40
|       |   0x0042d17a      418901         mov dword [r9], eax
|       |   0x0042d17d      41895904       mov dword [r9 + 4], ebx
|       |   0x0042d181      41894908       mov dword [r9 + 8], ecx
|       |   0x0042d185      4189510c       mov dword [r9 + 0xc], edx
|       |   0x0042d189      4d8d4010       lea r8, [r8 + 0x10]         ; 16
```

Let's have a look at that function:
```sh
[0x0042bff0 14% 140 ./antir2]> pd $r @ fcn.0042bff0
/ (fcn) fcn.0042bff0 591
|   fcn.0042bff0 ();
|              ; CALL XREF from 0x0042c2d6 (fcn.0042bff0 + 742)
|              ; CALL XREF from 0x0042d166 (fcn.0042cd90)
|           0x0042bff0      4d8d86800000.  lea r8, [r14 + 0x80]        ; 128
|           0x0042bff7      418b7880       mov edi, dword [r8 - 0x80]
|           0x0042bffb      418b68a0       mov ebp, dword [r8 - 0x60]
|           0x0042bfff      458b50c0       mov r10d, dword [r8 - 0x40]
|           0x0042c003      458b58e0       mov r11d, dword [r8 - 0x20]
|           0x0042c007      418b38         mov edi, dword [r8]
|           0x0042c00a      418b6820       mov ebp, dword [r8 + 0x20]  ; [0x20:4]=-1 ; 32
|           0x0042c00e      458b5040       mov r10d, dword [r8 + 0x40] ; [0x40:4]=-1 ; '@' ; 64
|           0x0042c012      458b5860       mov r11d, dword [r8 + 0x60] ; [0x60:4]=-1 ; '`' ; 96
|       ,=< 0x0042c016      eb08           jmp 0x42c020                ;[1]
  |   0x0042c018      0f1f84000000.  nop dword [rax + rax]
|       |      ; JMP XREF from 0x0042c016 (fcn.0042bff0)
|       |      ; JMP XREF from 0x0042c231 (fcn.0042bff0)
|       `-> 0x0042c020      413307         xor eax, dword [r15]
|           0x0042c023      41335f04       xor ebx, dword [r15 + 4]
|           0x0042c027      41334f08       xor ecx, dword [r15 + 8]
|           0x0042c02b      4133570c       xor edx, dword [r15 + 0xc]
```

That looks very interesting, it loads many registers and the starts XOR'ing
eax, ebx, ecx, edx with what's pointed to by `r15`, and xoring the key with
clear text is the first step of AES.  Let's add a breakpoint there and look
at the registers:
```sh
dbx 1 0x0042c020 1 x
dr
```

Interestingly, eax, ebx, ecx and edx are loaded with what appears to be
ascii text, and in fact it is "Get the aeskey!!".  Now let's look at what's
pointed to by `r15`...
```sh
ps @ r15
radare2con4ever!>!\x...
```

Looks like we got the flag :) We can make sure in python repl quickly:
```sh
In [1]: from Crypto.Cipher import AES

In [2]: key = 'radare2con4ever!'

In [3]: enc = AES.new(key, AES.MODE_ECB)

In [4]: enc.encrypt('Get the aeskey!!')
Out[4]: '\xfd\xda\x9bx\xfc\xf8\xe9\xbf3rn\n\x8a\xe5\xf6\x8c'
```


# Write-up by Cyrill Leutwiler

The crackme is a single file called `antir2`. What is it? file will tell us:

```sh
$ file antir2
antir2: ELF 64-bit LSB executable, x86-64, version 1 (GNU/Linux), statically linked, for GNU/Linux 2.6.32, stripped
```

It's a stripped and statically linked 64bit ELF binary Let's run it!

```sh
# ./antir2
*******************************************
* Radare2con 2017 rhme3 pre-quals edition *
*******************************************

r<< Can you r2 me?

Plaintext : 47 65 74 20 74 68 65 20 61 65 73 6B 65 79 21 21
Encrypted : FD DA 9B 78 FC F8 E9 BF 33 72 6E 0A 8A E5 F6 8C
Decrypted : 47 65 74 20 74 68 65 20 61 65 73 6B 65 79 21 21
```

We can see that it's probably doing some crypto stuff. The plaintext converted to ascii is:

```
Get the aeskey!!
```

To the r2land!
```sh
# r2 -AAwd antir2
[...]
[0x004008c0]> dc
*******************************************
* Radare2con 2017 rhme3 pre-quals edition *
*******************************************

r2 in debug mode won't help you much! ha ha ha...... :)
```


orly? I think you're underestimating the power of r2 but we will talk about this later :) Jokes aside, there are obviously some antidebug measures around.
The most common way to do such stuff is by just calling `ptrace`. Simplified, with the `ptrace` syscall you can debug a program. But a program can only have one debugger attached at the same time. The syscall will fail in that case. So if a program tries to debug itself by calling `ptrace` and it fails, it does know that it is being debugged. We can find out with r2 easily (open it again):

```sh
[0x004008c0]> dcs ptrace
Running child until syscalls:101
child stopped with signal 133
--> SN 0x004b5357 syscall 63 uname (0x7ffe3dfcf0f0)
child stopped with signal 133
--> SN 0x004b55b9 syscall 12 brk (0x0)
child stopped with signal 133
--> SN 0x004b55b9 syscall 12 brk (0x1a3c1c0)
child stopped with signal 133
--> SN 0x0043d9ec syscall 158 arch_prctl (0x1002 0x1a3b880 0x0)
child stopped with signal 133
--> SN 0x004bf8af syscall 89 readlink (0x50c343 0x7ffe3dfce220 0x1000)
child stopped with signal 133
--> SN 0x004b55b9 syscall 12 brk (0x1a5d1c0)
child stopped with signal 133
--> SN 0x004b55b9 syscall 12 brk (0x1a5e000)
child stopped with signal 133
--> SN 0x004b5467 syscall 21 access (0x50be7e 0x0)
child stopped with signal 133
--> SN 0x004854a4 syscall 5 fstat (0x1 0x7ffe3dfce7c0)
child stopped with signal 133
--> SN 0x004855b0 syscall 1 write (0x1 0x1a3dbe0 0x2c)
*******************************************
child stopped with signal 133
--> SN 0x004855b0 syscall 1 write (0x1 0x1a3dbe0 0x2c)
* Radare2con 2017 rhme3 pre-quals edition *
child stopped with signal 133
--> SN 0x004855b0 syscall 1 write (0x1 0x1a3dbe0 0x2d)
*******************************************

child stopped with signal 133
--> SN 0x00485fba syscall 101 ptrace (0x0 0x0 0x1 0x0)
```

People are often complaining that r2 cli is hard... `dcs ptrace` simply stands for "Debug Continue Systemcall ptrace" (or something like that). One command and we know where to look, nice. The code around RIP is the following:

```sh
      0x00485fb3      b865000000     mov eax, 0x65               ; orax
      0x00485fb8      0f05           syscall
      ;-- rcx:
      ;-- rip:
      0x00485fba      483d00f0ffff   cmp rax, 0xfffffffffffff000
  ┌─< 0x00485fc0      7726           ja 0x485fe8                 ;[1]
  │   0x00485fc2      4183f802       cmp r8d, 2                  ; 2
 ┌──< 0x00485fc6      7718           ja 0x485fe0                 ;[2]
 ││   0x00485fc8      4885c0         test rax, rax
┌───< 0x00485fcb      7813           js 0x485fe0                 ;[2]
│││   0x00485fcd      48c7c0d0ffff.  mov rax, 0xffffffffffffffd0
│││   0x00485fd4      64c700000000.  mov dword fs:[rax], 0
│││   0x00485fdb      488b4424b0     mov rax, qword [rsp - 0x50]
└└──> 0x00485fe0      f3c3           ret
  │   0x00485fe2      660f1f440000   nop word [rax + rax]
  └─> 0x00485fe8      48c7c2d0ffff.  mov rdx, 0xffffffffffffffd0
      0x00485fef      f7d8           neg eax
      0x00485ff1      648902         mov dword fs:[rdx], eax
      0x00485ff4      48c7c0ffffff.  mov rax, 0xffffffffffffffff
      0x00485ffb      c3             ret
```

This might look a bit strange. But you can run `dcs ptrace` again and it will hit again. So its called twice. With debugger: `ptrace` will fail twice. Without debugger: `ptrace` will work the first time and return the PID and fail the second time. To make debugging great again we need to simulate the latter situation. Peace of cake with r2. Reopen the program and:

```sh
[0x004008c0]> s 0x00485fb3;wx b827000000;s 0x00485fc2;wx 909090909090;dcu 0x00485fb3;dcu 0x00485fb3;wx b865000000
Continue until 0x00485fb3 using 1 bpsize
*******************************************
* Radare2con 2017 rhme3 pre-quals edition *
*******************************************

hit breakpoint at: 485fb3
Continue until 0x00485fb3 using 1 bpsize
hit breakpoint at: 485fb3
[0x00485fb3]> dc
r<< Can you r2 me?

Plaintext : 47 65 74 20 74 68 65 20 61 65 73 6B 65 79 21 21
Encrypted : FD DA 9B 78 FC F8 E9 BF 33 72 6E 0A 8A E5 F6 8C
Decrypted : 47 65 74 20 74 68 65 20 61 65 73 6B 65 79 21 21
```

You can chain commands together with ";" as you would in bash. So just copy paste `0x00485fb3;wx b827000000;s 0x00485fc2;wx 909090909090;dcu 0x00485fb3;dcu 0x00485fb3;wx b865000000` after opening the file and your fine.
What it does it simply seeks to the location where we found the `ptrace` syscall, patches it so it becomes a `getpid` syscall, continues until the next call to that location and patches it again so it's a `ptrace` command (that actually is supposed to fail the 2nd time) again.
Side note: I found hints that there might be more antidebug stuff but I did never trigger them and thus not further investigate:

```sh
[0x00484b88]> iz | less
vaddr=0x004e1ca0 paddr=0x000e1ca0 ordinal=010 sz=31 len=30 section=.rodata type=ascii string=Breakpoint detected @ %p+%x !\n
vaddr=0x004e1cbf paddr=0x000e1cbf ordinal=011 sz=16 len=15 section=.rodata type=ascii string=/proc/self/maps
vaddr=0x004e1ccf paddr=0x000e1ccf ordinal=012 sz=6 len=5 section=.rodata type=ascii string=frida
vaddr=0x004e1cd5 paddr=0x000e1cd5 ordinal=013 sz=49 len=48 section=.rodata type=ascii string=Damn it! You're so shady! h00king isn't allowed\n
```

So we can start digging around. And prepare to getting headaches, since this binary is clearly obfuscated. The main function is huge and there are several big blocks of binary operations (xor,and,or,...). I tried to navigate around and sniff the aeskey out of memory by stepping but didn't get anywhere and gave up on that quickly. We need to get a higher level understanding of the binary. By looking at the strings again I've found the following (interestingly, right next to the anti debug messages):

```sh
vaddr=0x004e1d06 paddr=0x000e1d06 ordinal=014 sz=13 len=12 section=.rodata type=ascii string=aes(partial)
vaddr=0x004e1d20 paddr=0x000e1d20 ordinal=015 sz=39 len=38 section=.rodata type=ascii string=AES part of OpenSSL 1.0.2g  1 Mar 2016
```

Neat, this is very valuable Information. The binary does crypto stuff and this is how it's done. Why using a decompiler if we already have the source? I download said Version of OpenSSL to find the code in question:

```sh
root@computer ~/openssl-OpenSSL_1_0_2g # grep -r partial * | grep aes
crypto/aes/aes_misc.c:    return "aes(partial)";
[...]
```

Looks good. The code file is very small and easy to understand. Import part out of it:

```c
const char *AES_options(void)
{
#ifdef FULL_UNROLL
    return "aes(full)";
#else
    return "aes(partial)";
#endif
}

/* FIPS wrapper functions to block low level AES calls in FIPS mode */

int AES_set_encrypt_key(const unsigned char *userKey, const int bits,
                        AES_KEY *key)
{
#ifdef OPENSSL_FIPS
    fips_cipher_abort(AES);
#endif
    return private_AES_set_encrypt_key(userKey, bits, key);
}
```

Around the function `*AES_options(void)` we should be able to find the function `int AES_set_encrypt_key(...)` nearby! This is a great fact, because:
  - Thanks to the cross reference analysis by r2 we have a reference to `*AES_options()`
  - The aes key will be in the function arguments (`rdi` will hold the key)

Lets do this:

```sh
[0x004008c0]> pd 1 @ vaddr=0x004e1d06
            ;-- str.aes_partial_:
               ; DATA XREF from 0x0042bdd0 (main)
            0x004e1d06     .string "aes(partial)" ; len=13
```

Right after the function where the string is being reference comes the next function:

```sh
┌ (fcn) fcn.0042bde0 40
│   fcn.0042bde0 ();
│              ; CALL XREF from 0x00400b50 (main)
│              ; DATA XREF from 0x00400b31 (main)
└       ┌─< 0x0042bde0      e9cb0a0000     jmp loc.0042c8b0            ;[1]
        │   0x0042bde5      90             nop
        │   0x0042bde6      662e0f1f8400.  nop word cs:[rax + rax]
```

We might want to debug a bit there: We got a jump to location `0x0042c8b0`.

```sh
[0x0042c8b0]> pd 10 @0x0042c8b0
            ;-- rip:
            0x0042c8b0      53             push rbx
            0x0042c8b1      55             push rbp
            0x0042c8b2      4154           push r12
            0x0042c8b4      4155           push r13
            0x0042c8b6      4156           push r14
            0x0042c8b8      4157           push r15
            0x0042c8ba      4883ec08       sub rsp, 8
            0x0042c8be      e81d000000     call 0x42c8e0
            0x0042c8c3      488b6c2428     mov rbp, qword [rsp + 0x28] ; [0x28:8]=-1 ; '(' ; 40
            0x0042c8c8      488b5c2430     mov rbx, qword [rsp + 0x30] ; [0x30:8]=-1 ; '0' ; 48
```

Here is our function. Now we only have to break there and print out the flag! \o/

```sh
[0x0042c8b0]> ps@rdi
radare2con4ever!`\xdbC
```

The key is `radare2con4ever!`.


# Write-up by Roberto Gutierrez


Let's inspect a bit the binary:

```sh
$ rabin2 -I antir2
arch     x86
binsz    1200746
bintype  elf
bits     64
canary   false
class    ELF64
crypto   false
endian   little
havecode true
lang     c
linenum  false
lsyms    false
machine  AMD x86-64 architecture
maxopsz  16
minopsz  1
nx       true
os       linux
pcalign  0
pic      false
relocs   false
rpath    NONE
static   true
stripped true
subsys   linux
va       true
```

So we have a static ELF x64 with no symbols. if we execute it, we get the following output:

```sh
$ ./antir2
*******************************************
* Radare2con 2017 rhme3 pre-quals edition *
*******************************************

r<< Can you r2 me?

Plaintext : 47 65 74 20 74 68 65 20 61 65 73 6B 65 79 21 21
Encrypted : FD DA 9B 78 FC F8 E9 BF 33 72 6E 0A 8A E5 F6 8C
Decrypted : 47 65 74 20 74 68 65 20 61 65 73 6B 65 79 21 21
```

It seems that the objective is to find the encryption key. Let's open IDA Pro and load the bina....just kidding :) The first idea is to debug the binary and trace the key, but If you try, you will get this annoying message...

```sh
$ r2 -d antir2
[0x004008c0]> dc
Selecting and continuing: 30699
*******************************************
* Radare2con 2017 rhme3 pre-quals edition *
*******************************************

r2 in debug mode won't help you much! ha ha ha...... :)
PTRACE_EVENT_EXIT pid=30699, status=0x0
[0x00484b88]>
```
It seems we will need to deal with some kind of anti-debugging trick. Let's start the analysis:

```sh
$ r2 -Aw antir2
```

Taking a look into the code, immediately we realise that there's something wrong...the main function apparently is huge, there are a lot of conditional and unconditional jumps and radare stop responding when we open the graph mode. Interesting...

 Definitely the code is obfuscated or it contains some kind of anti-disassemble tricks. After some minutes reviewing the code, I found a string that confirms the obfuscator used:

```sh
Obfuscator-LLVM clang version 4.0.1  (based on Obfuscator-LLVM 4.0.1)
```

With the obfuscation, the automatic analysis of radare fails to detect the boundaries of the functions. Let's fix that manually.

In visual mode, let's go down in the main function until the start of the next function. Just after printing the strings "Plaintext", "Encrypted" and "Decrypted", it's easy to identify the preamble of the next function:

```sh
[0x004009e0]> s 0x400cdb
[0x00400cdb]> pd 4 @ $$-5
│              ; JMP XREF from 0x00400cc0 (main)
│           0x00400cd6      e855830800     CALL fcn.00489030
│           0x00400cdb      0f1f440000     NOP DWORD [RAX + RAX]
│
│              ; XREFS: CALL 0x00400a74  CALL 0x00400a86  CALL 0x00400bbe  CALL 0x00400bca  CALL 0x00400b2c  CALL 0x00400b3b
│           0x00400ce0      55             PUSH RBP
│           0x00400ce1      4889e5         MOV RBP, RSP
[0x00400cdb]>
```

Now we can define  the end of the main function manually.  Some useful commands in visual mode:

```sh
de : set the end of the function
df : analyze the next function
dr : rename the function
```
Move the cursor to 0x00400cdb, press 'de' , then move the cursor one instruction down (0x00400ce0) and then press 'df'.

```sh
# In visual mode
o 0x00400cdb  # NOP DWORD [RAX + RAX]
de # sets the end of the main function
j  # seek next instruction
df # defines the start of the next function
```

Probably this is not the best way to do it, but the trick works here and now it's possible to open the main function in the graph mode without problems.

```sh
[0x00400cdb]> s main
[0x004009e0]> VV
```

After that, I did the same with all the functions called in the main (that were not detected properly). The typical function prologue and the Xrefs can be used to clearly identify the boundaries of the functions. In less than one minute you can have all the necessary functions well defined.

Now, it's time to get ride of the anti-debugging tricks. Let's locate the text message below:

```sh
[0x004009e0]> iz~debug
vaddr=0x004e1c67 paddr=0x000e1c67 ordinal=009 sz=57 len=56 section=.rodata type=ascii string=r2 in debug mode won't help you much! ha ha ha...... :)\n
```
Find where the anti-dbg string is used.

```sh
[0x00400b88]> axt 0x004e1c67
data 0x421208 movabs rdi, str.r2_in_debug_mode_won_t_help_you_much__ha_ha_ha......_:__n in fcn.00418db0
data 0x41f9e4 movabs rdi, str.r2_in_debug_mode_won_t_help_you_much__ha_ha_ha......_:__n in fcn.00418db0
```

Let's patch the function fcn.00418db0 then:

```sh
[0x00421208]> s fcn.00418db0
[0x00418db0]> wa ret
Written 1 bytes (ret) = wx c3
```

Now there won't be problems to run the debugger. The binary contains other anti-reversing tricks, but you can follow the same procedure to find and patch those functions using the below messages:

```sh
vaddr=0x004e1ca0 paddr=0x000e1ca0 ordinal=010 sz=31 len=30 section=.rodata type=ascii string=Breakpoint detected @ %p+%x !\n
vaddr=0x004e1cbf paddr=0x000e1cbf ordinal=011 sz=16 len=15 section=.rodata type=ascii string=/proc/self/maps
vaddr=0x004e1ccf paddr=0x000e1ccf ordinal=012 sz=6 len=5 section=.rodata type=ascii string=frida
vaddr=0x004e1cd5 paddr=0x000e1cd5 ordinal=013 sz=49 len=48 section=.rodata type=ascii string=Damn it! You're so shady! h00king isn't allowed\n
```

With the debugger ready, the objective is to identify the encryption function and stop the execution somewhere before to obtain the encryption key. My approach was pretty simple, locate where the program prints the encrypted string and trace it back until the encryption function.

```sh
[0x00400c7e]> iz~Encrypted
vaddr=0x004e1bbf paddr=0x000e1bbf ordinal=002 sz=10 len=9 section=.rodata type=ascii string=Encrypted

[0x00400c7e]> axt 0x4e1bbf
data 0x400c7e mov eax, str.Encrypted in main

[0x00400c7e]> s 0x400c7e
[0x00400c7e]> pd 5
│           0x00400c7e      b8bf1b4e00     MOV EAX, str.Encrypted      ; 0x4e1bbf ; "Encrypted"
│           0x00400c83      89c7           MOV EDI, EAX
│           0x00400c85      488bb568fdff.  MOV RSI, QWORD [LOCAL_298H]
│           0x00400c8c      8b954cfdffff   MOV EDX, DWORD [LOCAL_2B4H]
│           0x00400c92      e8a90a0100     CALL fcn.00411740
```
Checking the arguments of the function, we can confirm in the debugger that `local_298h`  contains the encrypted string. Let's trace back this value until we find the encryption function.

```sh
# Previously "local_298h" is used here:
0x00400c03      4889bd68fdff.  MOV QWORD [LOCAL_298H], RDI

# Tracing back the value of rdi. It's set here:
0x00400bf5      488d7dc0       LEA RDI, [LOCAL_40H]

# Going back the value of local_40h. It is used as a param in the following call:

│       │   0x00400b6a      48bf901b4e00.  MOVABS RDI, 0x4E1B90        ; 0x4e1b90 ; "Get the aeskey!!r<< Can you r2 me?\n\n"
│       │   0x00400b74      b810000000     MOV EAX, 0x10
│       │   0x00400b79      89c2           MOV EDX, EAX
│       │   0x00400b7b      488d8db8feff.  LEA RCX, [LOCAL_148H]
│       │   0x00400b82      41b901000000   MOV R9D, 1
│       │   0x00400b88      4c8d45d0       LEA R8, [LOCAL_30H]
│       │   0x00400b8c      488d75c0       LEA RSI, [LOCAL_40H]
│       │   0x00400b90      e8fbc10200     CALL fcn.0042cd90           ;[3]
```

This function takes the following params:

    1) Arg 1 (rdi): The plain text string (@ `0x4e1b90) "Get the aeskey!!r<< Can you r2 me?\n\n"
    2) Arg 2 (rsi): Based on our trace, the encrypted string should be stored in this address (local_40h).
    3) Arg 3 (rdx): The value 0x10 (the size of the encrypted string).
    4) Arg 4 (rcx): Other variable local_148h.
    5) Arg 5 (r8): Other variable local_30h.
    6) Arg 6 (r9): The value 1.

It looks like the encryption function we were looking for!! It receives as parameter the plaintext, the size and the address to store the encrypted string. So any of the other params (`rcx` or `r8`) should contain the encryption key. Let's confirm it with the debugger:

```sh

[0x004008c0]> db 0x00400b90 # Breakpoint in the call
[0x004008c0]> dc
Selecting and continuing: 32381
*******************************************
* Radare2con 2017 rhme3 pre-quals edition *
*******************************************

hit breakpoint at: 400b90
[0x00400b90]>
[0x00400b2c]> drr
   rax 0x0000000000000010  (.comment) rdx
   rbx 0x00000000004002b8  (.init) (/home/ictsec/security/challenges/r2con-prequals-rhme3/re/antir2_mod) rbx program R X 'sub rsp, 8' 'antir2_mod'
   rcx 0x00007ffc92697768  rcx stack R W 0x6332657261646172 --> ascii
   rdx 0x0000000000000010  (.comment) rdx
    r8 0x00007ffc92697880  r8 stack R W 0x0 --> r15
    r9 0x0000000000000001  (.comment) r11
   r10 0x0000000000000000  r15
   r11 0x0000000000000001  (.comment) r11
   r12 0x000000000043db60  (.text) (/home/ictsec/security/challenges/r2con-prequals-rhme3/re/antir2_mod) r12 program R X 'push r14' 'antir2_mod'
   r13 0x000000000043dbf0  (.text) (/home/ictsec/security/challenges/r2con-prequals-rhme3/re/antir2_mod) r13 program R X 'push rbx' 'antir2_mod'
   r14 0x0000000000000000  r15
   r15 0x0000000000000000  r15
   rsi 0x00007ffc92697870  rsi stack R W 0x1 --> (.comment) r11
   rdi 0x00000000004e1b90  (.rodata) (/home/ictsec/security/challenges/r2con-prequals-rhme3/re/antir2_mod) rdi program R X 'je 0x4e1bb4' 'antir2_mod' (Get the aeskey!!r<< Can you r2 me?

)

[0x00400b2c]> pxr @ rcx
0x7ffc92697768  0x6332657261646172   radare2c @rcx ascii
0x7ffc92697770  0x2172657665346e6f   on4ever! ascii
0x7ffc92697778  0x3aab444c5999213e   >!.YLD.:
0x7ffc92697780  0x7eed4f555f9f2a23   #*._UO.~
0x7ffc92697788  0x9fc130f4a56a74b8   .tj..0..
```

And here it is, the encryption key: `"radare2con4ever!"`.



# Write-up by Irdeto team (Jonathan Beverley, Colin deWinter, Ben Gardiner)

* Open challenge binary and analyze it

```sh
r2 -d antir2
[...]
[0x004008c0]> aaa
[ ] Analyze all flags starting with sym. and entry0 (aa)
[...]
```

* When attempting to debug the program, there is a certain text string "r2 in debug.....hahahaha" printed before force-quitting you

* I was able to cross reference the strings through a radare / search and then using axt find the point in which its mentioned.

```sh
[0x004008c0]> s str.r2_in_debug_mode_won_t_help_you_much__ha_ha_ha......_:__n
[0x004e1c67]> axt
data 0x421208 movabs rdi, str.r2_in_debug_mode_won_t_help_you_much__ha_ha_ha......_:__n in main
data 0x41f9e4 movabs rdi, str.r2_in_debug_mode_won_t_help_you_much__ha_ha_ha......_:__n in main
[0x004e1c67]> s 0x421208
```

* It seems to be referenced from `main`; the anti-debug printout is called from a jump in `main` at `0x418fa6`

```sh
[0x004e1c67]> axt
data 0x421208 movabs rdi, str.r2_in_debug_mode_won_t_help_you_much__ha_ha_ha......_:__n in main
data 0x41f9e4 movabs rdi, str.r2_in_debug_mode_won_t_help_you_much__ha_ha_ha......_:__n in main
[0x00000000]> s 0x421208
[0x00421208]> axt
code 0x418fa6 je 0x421208 in main
[0x00421208]> s 0x418fa6
```

* which looks like a million jump statements... they all seem to reference loading [`local_54h`]

```sh
[0x00418fa6]> f antidebug_fromhere
[0x00418fa6]> pD 128 @ $$-64~..
│              ; JMP XREF from 0x00418f61 (main)
│           0x00418f66      8b45ac         mov eax, dword [local_54h]
│           0x00418f69      2dd355df15     sub eax, 0x15df55d3
│           0x00418f6e      898564ffffff   mov dword [local_9ch], eax
│       ┌─< 0x00418f74      0f8431150000   je 0x41a4ab
│      ┌──< 0x00418f7a      e900000000     jmp 0x418f7f
│      ││      ; JMP XREF from 0x00418f7a (main)
│      └──> 0x00418f7f      8b45ac         mov eax, dword [local_54h]
│       │   0x00418f82      2d6f9f2b19     sub eax, 0x192b9f6f
│       │   0x00418f87      898560ffffff   mov dword [local_a0h], eax
│      ┌──< 0x00418f8d      0f843c7a0000   je 0x4209cf
│     ┌───< 0x00418f93      e900000000     jmp 0x418f98
│     │││      ; JMP XREF from 0x00418f93 (main)
│     └───> 0x00418f98      8b45ac         mov eax, dword [local_54h]
│      ││   0x00418f9b      2d2f99231a     sub eax, 0x1a23992f
│      ││   0x00418fa0      89855cffffff   mov dword [local_a4h], eax
|     ┌───< ;-- antidebug_fromhere:
│     ┌───< 0x00418fa6      0f845c820000   je 0x421208
│    ┌────< 0x00418fac      e900000000     jmp 0x418fb1
│    ││││      ; JMP XREF from 0x00418fac (main)
│    └────> 0x00418fb1      8b45ac         mov eax, dword [local_54h]
│     │││   0x00418fb4      2dfa6b571d     sub eax, 0x1d576bfa
│     │││   0x00418fb9      898558ffffff   mov dword [local_a8h], eax
│    ┌────< 0x00418fbf      0f84cb140000   je 0x41a490
│   ┌─────< 0x00418fc5      e900000000     jmp 0x418fca
│   │││││      ; JMP XREF from 0x00418fc5 (main)
│   └─────> 0x00418fca      8b45ac         mov eax, dword [local_54h]
│    ││││   0x00418fcd      2df3fce31d     sub eax, 0x1de3fcf3
│    ││││   0x00418fd2      898554ffffff   mov dword [local_ach], eax
│   ┌─────< 0x00418fd8      0f84b7810000   je 0x421195
│  ┌──────< 0x00418fde      e900000000     jmp 0x418fe3
│  ││││││      ; JMP XREF from 0x00418fde (main)
│  └──────> 0x00418fe3      8b45ac         mov eax, dword [local_54h]
[0x00418fa6]> afvW~local_54h
 local_54h  0x416625,0x418de3,0x418df4,0x418e0a,0x418e20,0x418e36,0x418e4c,0x418e62,0x418e78,0x418e8e,0x418ea4,0x418eba,0x418ed0,0x418ee9,0x418f02,0x418f1b,0x418f34,0x418f4d,0x418f66,0x418f7f,0x418f98,0x418fb1,0x418fca,0x418fe3,0x418ffc,0x419015,0x41902e,0x419047,0x419060,0x419079,0x419092,0x4190ab,0x4190c4,0x4190dd,0x4190f6,0x41910f,0x4231a2
```

* Inspecting around the function, all are reads, this local is only written to at `0x00418de3` with data from `[local_50h]`.

```sh
[0x00418fa6]> pdb @ 0x00418dd8
│              ; JMP XREF from 0x00421239 (main)
│           0x00418dd8      8b45b0         mov eax, dword [local_50h]
│           0x00418ddb      89c1           mov ecx, eax
│           0x00418ddd      81e905e77080   sub ecx, 0x8070e705
│           0x00418de3      8945ac         mov dword [local_54h], eax
│           0x00418de6      894da8         mov dword [local_58h], ecx
│       ┌─< 0x00418de9      0f84e74d0000   je 0x41dbd6
```

* Attempting to find the end, it looks like this whole function is cyclic. There are 33 jumpXREFs to the bottom. this might be some sort of.... loop? Switch statement?

```sh
[0x00418fa6]> pdf
[...]
│ ────────> 0x0042bdb5      c78568ffffff.  mov dword [local_98h], 0xd648722e
│ │││││││      ; XREFS: JMP 0x0042bdb0  JMP 0x00427b28  JMP 0x00426458  JMP 0x0042a251  JMP 0x00428b2b  JMP 0x0042bd62  JMP 0x0042aebc  JMP 0x00427265
│ │││││││      ; XREFS: JMP 0x00427b93  JMP 0x0042b9e0  JMP 0x0042bd92  JMP 0x004274e4  JMP 0x004276df  JMP 0x0042bda1  JMP 0x0042bce3  JMP 0x00427b0a
│ │││││││      ; XREFS: JMP 0x00427b51  JMP 0x0042aed9  JMP 0x0042bd48  JMP 0x0042bd19  JMP 0x0042b56b  JMP 0x00427bb3  JMP 0x00428f6b  JMP 0x0042b55c
│ │││││││      ; XREFS: JMP 0x00427bcd  JMP 0x00427b37  JMP 0x00429baa  JMP 0x00428f2d  JMP 0x00428f1e  JMP 0x0042aead  JMP 0x0042aef7  JMP 0x00427b6e
│ │││││││      ; XREFS: JMP 0x0042a094  JMP 0x00428f4d  JMP 0x0042bd7c  JMP 0x0042751e  JMP 0x0042a085  JMP 0x004274f3  JMP 0x00428f91  JMP 0x004260f0
│ │││││││      ; XREFS: JMP 0x00426467  JMP 0x0042b2f7  JMP 0x0042549c
│ └└└└└└└─< 0x0042bdbf      e9e391ffff     jmp 0x424fa7
│              ; JMP XREF from 0x0042bcf8 (main)
│ ────────> 0x0042bdc4      e867d20500     call fcn.00489030
│           0x0042bdc9      0f1f80000000.  nop dword [rax]
│           0x0042bdd0      b8061d4e00     mov eax, str.aes_partial_   ; 0x4e1d06 ; "aes(partial)"
└           0x0042bdd5      c3             ret
```

* How does it know it is being debugged? The message only plays when the `local_54h` is equal to `1A23992F`.

```sh
[0x00418fa6]> pdb @ 0x00418fa6
│              ; JMP XREF from 0x00418f93 (main)
│           0x00418f98      8b45ac         mov eax, dword [local_54h]
│           0x00418f9b      2d2f99231a     sub eax, 0x1a23992f
│           0x00418fa0      89855cffffff   mov dword [local_a4h], eax
|       ┌─< ;-- antidebug_fromhere:
│       ┌─< 0x00418fa6      0f845c820000   je 0x421208
```

* The magic value `0x1a23992f` shows up only three times; the last is not in code, the first is the test against that value. Let's look at the second

```sh
[0x00418fa6]> /v 0x1a23992f
Searching 4 bytes in [0x400000-0x522000]
hits: 3
0x00418f9c hit1_0 2f99231a
0x0041ebbd hit1_1 2f99231a
0x0041fa03 hit1_2 2f99231a
[0x00418fa6]> pd @ hit1_1-5
│       ┌─< 0x0041ebb8      7d26           jge 0x41ebe0
│       │   0x0041ebba      0000           add byte [rax], al
│       │      ; JMP XREF from 0x00418f5b (main)
│       │   0x0041ebbc  ~   b82f99231a     mov eax, 0x1a23992f
|       │   ;-- hit1_1:
│       │   0x0041ebbd      2f             invalid                     ; 0x1a23992f
│       │   0x0041ebbe      99             cdq
│       │   0x0041ebbf      231a           and ebx, dword [rdx]
[...]
```

NB: the flag on the immediate is breaking the disassembly there, we'll remove flags in the following to avoid this.

* that value, once loaded into `eax` makes its way magically to `local_54h` (the EBB is very very long)

* the above is only called is `local_54h` is equal to `0xae2d291`

```sh
[0x004008c0]> s 0x00418f5b
[0x00418f5b]> pd
[0x00418f5b]> pdb
│              ; JMP XREF from 0x00418f48 (main)
│           0x00418f4d      8b45ac         mov eax, dword [local_54h]
│           0x00418f50      2d91d2e20a     sub eax, 0xae2d291
│           0x00418f55      898568ffffff   mov dword [local_98h], eax
│       ┌─< 0x00418f5b      0f845b5c0000   je 0x41ebbc
```

* which is called only if `local_54h` is not `0x94524fa`

```sh
│       │      ; JMP XREF from 0x00418f2f (main)
│       └─> 0x00418f34      8b45ac         mov eax, dword [local_54h]
│           0x00418f37      2dfa244509     sub eax, 0x94524fa
│           0x00418f3c      89856cffffff   mov dword [local_94h], eax
│       ┌─< 0x00418f42      0f84e2810000   je 0x42112a                 ;[2]
│      ┌──< 0x00418f48      e900000000     jmp 0x418f4d                ;[3]
```

* and so on, testing for various other values of `local_54h` that it is not. We'll focus on the test for the concrete value `0xae2d291`

* the value `0xae2d291` which `local_54h` must attain is written to `local_50h` when `local_34h` is `6`

```sh
[0x0041eba7]> /v 0xae2d291
Searching 4 bytes in [0x400000-0x522000]
hits: 2
0x00418f51 hit3_0 91d2e20a
0x0041eba7 hit3_1 91d2e20a
[0x0041eba7]> s 0x0041eba7
[0x0041eba7]> f-hit*
[0x0041eba7]> pdb
│              ; JMP XREF from 0x00418eaf (main)
│           0x0041eba1      b82f82de24     mov eax, 0x24de822f
│           0x0041eba6      b991d2e20a     mov ecx, 0xae2d291
│           0x0041ebab      8b55cc         mov edx, dword [local_34h]
│           0x0041ebae      83fa06         cmp edx, 6                  ; 6
│           0x0041ebb1      0f45c1         cmovne eax, ecx
│           0x0041ebb4      8945b0         mov dword [local_50h], eax
│       ┌─< 0x0041ebb7      e97d260000     jmp 0x421239
```

* it's not clear how that would also propagate to `local_54h` -- but let's just roll with it. Assuming it will, then if we prevent the magic value `0xae2d291` from getting into `local_50h`, we will prevent detection of debugging. So we can patch-out the conditional mov, `cmovne` at `0x41ebb1`

```sh
[0x0041eba7]> s 0x0041ebb1
[0x0041ebb1]> "wa nop;nop;nop"
Written 3 bytes (nop;nop;nop) = wx 909090
[0x0041ebb1]> pdb
│              ; JMP XREF from 0x00418eaf (main)
│           0x0041eba1      b82f82de24     mov eax, 0x24de822f
│           0x0041eba6      b991d2e20a     mov ecx, 0xae2d291
│           0x0041ebab      8b55cc         mov edx, dword [local_34h]
│           0x0041ebae      83fa06         cmp edx, 6                  ; 6
│           0x0041ebb1      90             nop
│           0x0041ebb2      90             nop
│           0x0041ebb3      90             nop
│           0x0041ebb4      8945b0         mov dword [local_50h], eax
│       ┌─< 0x0041ebb7      e97d260000     jmp 0x421239
[0x0041ebb1]>
```
* yay! we patched-out the anti-debug check!

```sh
[0x0041ebb1]> dc
child stopped with signal 28
[+] SIGNAL 28 errno=0 addr=0x00000000 code=128 ret=0
got signal...
[0x004008c0]> dc
*******************************************
* Radare2con 2017 rhme3 pre-quals edition *
*******************************************

r<< Can you r2 me?

Plaintext : 47 65 74 20 74 68 65 20 61 65 73 6B 65 79 21 21
Encrypted : FD DA 9B 78 FC F8 E9 BF 33 72 6E 0A 8A E5 F6 8C
Decrypted : 47 65 74 20 74 68 65 20 61 65 73 6B 65 79 21 21
[0x00484b88]>
```

* Let's restart that debug session and plan a breakpoint. Working backwards from the "Decrypted" string

```sh
[0x0041ebb1]> s str.Decrypted
[0x004e1bc9]> axt
data 0x400c97 mov eax, str.Decrypted in main
[0x004e1bc9]> s 0x400c97
[0x00400c97]> pdb
[...]
│           0x00400c34      e857c10200     call fcn.0042cd90
│           0x00400c39      b8a01b4e00     mov eax, 0x4e1ba0
│           0x00400c3e      89c7           mov edi, eax
│           0x00400c40      8b8564fdffff   mov eax, dword [local_29ch]
│           0x00400c46      4188c3         mov r11b, al
│           0x00400c49      4488d8         mov al, r11b
│           0x00400c4c      e8bfad0400     call fcn.0044ba10
│           0x00400c51      41b9b51b4e00   mov r9d, str.Plaintext      ; 0x4e1bb5 ; "Plaintext"
│           0x00400c57      4489cf         mov edi, r9d
│           0x00400c5a      41b9901b4e00   mov r9d, 0x4e1b90
│           0x00400c60      4489ce         mov esi, r9d
│           0x00400c63      41b910000000   mov r9d, 0x10               ; 16
│           0x00400c69      4489ca         mov edx, r9d
│           0x00400c6c      898550fdffff   mov dword [local_2b0h], eax
│           0x00400c72      44898d4cfdff.  mov dword [local_2b4h], r9d
│           0x00400c79      e8c20a0100     call 0x411740
│           0x00400c7e      b8bf1b4e00     mov eax, str.Encrypted      ; 0x4e1bbf ; "Encrypted"
│           0x00400c83      89c7           mov edi, eax
│           0x00400c85      488bb568fdff.  mov rsi, qword [local_298h]
│           0x00400c8c      8b954cfdffff   mov edx, dword [local_2b4h]
│           0x00400c92      e8a90a0100     call 0x411740
│           0x00400c97      b8c91b4e00     mov eax, str.Decrypted      ; 0x4e1bc9 ; "Decrypted"
│           0x00400c9c      89c7           mov edi, eax
│           0x00400c9e      488bb558fdff.  mov rsi, qword [local_2a8h]
│           0x00400ca5      8b954cfdffff   mov edx, dword [local_2b4h]
│           0x00400cab      e8900a0100     call 0x411740
│           0x00400cb0      64488b0c2528.  mov rcx, qword fs:[0x28]    ; [0x28:8]=-1 ; '(' ; 40
│           0x00400cb9      488b75f8       mov rsi, qword [local_8h]
│           0x00400cbd      4839f1         cmp rcx, rsi
│       ┌─< 0x00400cc0      0f8510000000   jne 0x400cd6
```

* The first call to `0x411740` seems like a good spot.

```sh
[0x00400c97]> db 0x00400c79
[0x00400c97]> dc
child stopped with signal 28
[+] SIGNAL 28 errno=0 addr=0x00000000 code=128 ret=0
got signal...
[0x004008c0]> dc
*******************************************
* Radare2con 2017 rhme3 pre-quals edition *
*******************************************

r<< Can you r2 me?

hit breakpoint at: 400c79
[0x00400c79]>
```

* Let's check the stack

```sh
[0x00400c79]> ad 10 @rsp
0x7fff1ecc6bb0  0000000000000000  (null)
0x7fff1ecc6bb8  0000000010000000  pointer  0x1000000000
`- 0x1000000000  ffffffffffffffff  invalid
0x7fff1ecc6bc0  1400000000000000  pointer  0x00000014
`- 0x00000014  ffffffffffffffff  invalid
0x7fff1ecc6bc8  206ecc1eff7f0000  pointer  0x7fff1ecc6e20
`- 0x7fff1ecc6e20  4765742074686520  pointer  0x2065687420746547
`- 0x7fff1ecc6bd0  0000000000000000  (null)
0x7fff1ecc6bd8  306ecc1eff7f0000  pointer  0x7fff1ecc6e30
`- 0x7fff1ecc6e30  fdda9b78fcf8e9bf  pointer  0xbfe9f8fc789bdafd
`- 0x7fff1ecc6be0  306ccc1eff7f0000  pointer  0x7fff1ecc6c30
`- 0x7fff1ecc6c30  7ccdaca5e94484fb  pointer  0xfb8444e9a5accd7c
`- 0x7fff1ecc6be8  4500000000000000  pointer  0x00000045
`- 0x00000045  ffffffffffffffff  invalid
0x7fff1ecc6bf0  00000000a9085105  pointer  0x55108a900000000
`- 0x55108a900000000  ffffffffffffffff  invalid
0x7fff1ecc6bf8  0000000086aa782f  pointer  0x2f78aa8600000000
`- 0x2f78aa8600000000  ffffffffffffffff  invalid
```

* we recognize `4765742074686520` as the plaintext. I wonder what is around there?

```sh
[0x00400c79]> px @ 0x7fff1ecc6e20
- offset -       0 1  2 3  4 5  6 7  8 9  A B  C D  E F  0123456789ABCDEF
0x7fff1ecc6e20  4765 7420 7468 6520 6165 736b 6579 2121  Get the aeskey!!
0x7fff1ecc6e30  fdda 9b78 fcf8 e9bf 3372 6e0a 8ae5 f68c  ...x....3rn.....
0x7fff1ecc6e40  fdda 9b78 fcf8 e9bf 3372 6e0a 8ae5 f68c  ...x....3rn.....
0x7fff1ecc6e50  7261 6461 7265 3263 6f6e 3465 7665 7221  radare2con4ever!
0x7fff1ecc6e60  60db 4300 0000 0000 003f 3c3c d183 316e  `.C......?<<..1n
0x7fff1ecc6e70  1820 7200 0000 0000 46d2 4300 0000 0000  . r.....F.C.....
0x7fff1ecc6e80  0000 0000 0000 0000 0000 0000 0100 0000  ................
0x7fff1ecc6e90  b86f cc1e ff7f 0000 e009 4000 0000 0000  .o........@.....
0x7fff1ecc6ea0  b802 4000 0000 0000 4f84 4b96 1557 d8fe  ..@.....O.K..W..
0x7fff1ecc6eb0  60db 4300 0000 0000 f0db 4300 0000 0000  `.C.......C.....
0x7fff1ecc6ec0  0000 0000 0000 0000 0000 0000 0000 0000  ................
0x7fff1ecc6ed0  4f84 7b0b 696a 2601 4f84 7972 7657 d8fe  O.{.ij&.O.yrvW..
0x7fff1ecc6ee0  0000 0000 0000 0000 0000 0000 0000 0000  ................
0x7fff1ecc6ef0  0000 0000 0000 0000 0000 0000 0000 0000  ................
0x7fff1ecc6f00  0000 0000 0000 0000 0000 0000 0000 0000  ................
0x7fff1ecc6f10  bb07 0000 0000 0000 b86f cc1e ff7f 0000  .........o......
```

* EYYYYYYYYYYYYYYYYYYYYYYYY found it.

```sh
$echo -n 'Get the aeskey!!' | openssl aes-128-ecb -e -nopad -nosalt -K $(echo -n 'radare2con4ever!' | xxd -ps) | xxd -u -g1
00000000: FD DA 9B 78 FC F8 E9 BF 33 72 6E 0A 8A E5 F6 8C  ...x....3rn.....
```


# Write-up by Vegard Nossum without using radare2

The very first thing I did was to run 'strings' on the binary, which after scrolling for a bit you start seeing the strings from the .rodata section, including the plaintext and some other hints at what the challenge actually is (finding the AES key used to encrypt/decrypt the plaintext):
```
.Get the aeskey!!r<< Can you r2 me?
Plaintext
Encrypted
Decrypted
*******************************************
* Radare2con 2017 rhme3 pre-quals edition *
*******************************************
%s :
%02X
r2 in debug mode won't help you much! ha ha ha...... :)
Breakpoint detected @ %p+%x !
/proc/self/maps
frida
Damn it! You're so shady! h00king isn't allowed
aes(partial)
AES part of OpenSSL 1.0.2g  1 Mar 2016
cryptlib.c
dynamic
```

From here, I tried gdb, strace, etc. without much luck because of the self-ptrace and debugger protection (on the other hand, I did notice that valgrind was fine). So the next step was to try to find a way to disable the debugger protection.

I used readelf to find the address of the "debug mode" string:
```sh
$ readelf -S antir2 | grep rodata
  [ 9] .rodata           PROGBITS         00000000004e1b40  000e1b40
$ readelf -p .rodata antir2 | grep 'debug mode'
  [   127]  r2 in debug mode won't help you much! ha ha ha...... :)^J
```

(so the address is 0x4e1b40 + 0x127 = 0x4e1c67) and then look where this address is used:
```
$ objdump -d antir2 | grep -A3 0x4e1c67
  41f9e4:       48 bf 67 1c 4e 00 00    movabs $0x4e1c67,%rdi
  41f9eb:       00 00 00
  41f9ee:       b0 00                   mov    $0x0,%al
  41f9f0:       e8 1b c0 02 00          callq  0x44ba10
--
  421208:       48 bf 67 1c 4e 00 00    movabs $0x4e1c67,%rdi
  42120f:       00 00 00
  421212:       b0 00                   mov    $0x0,%al
  421214:       e8 f7 a7 02 00          callq  0x44ba10
```

These calls are probably calls to printf() or puts() and so patching them out wouldn't do much beyond simply skipping the output, but I noticed that these two stubs were preceded by "jmp" instructions, so I figured they must themselves be jump targets, and that seemed correct:
```
  4190a0:       0f 84 3e 69 00 00       je     0x41f9e4
  418fa6:       0f 84 5c 82 00 00       je     0x421208
```

Now, I tried patching out these calls (one by one) using a simple Python script:
```python
with open('antir2', 'rb') as f:
    antir2 = f.read()

nop = '\x90'

antir2 = antir2.replace('\x0f\x84\x3e\x69\x00\x00', nop * 6)

with open('antir2.patched', 'wb') as f:
    f.write(antir2)
```

When I ran this one in particular under GDB, it would hang, BUT if I pressed Ctrl-C and then told it to return from the current function, it would allow me to continue past the debugging check:
```
$ gdb ./antir2.patched
[...]
Reading symbols from ./antir2.patched...(no debugging symbols found)...done.
(gdb) run
Starting program: antir2.patched
*******************************************
* Radare2con 2017 rhme3 pre-quals edition *
*******************************************

^C
Program received signal SIGINT, Interrupt.
0x0000000000418dd8 in ?? ()
(gdb) ret
Make selected stack frame return now? (y or n) y
#0  0x0000000000400a0c in ?? ()
(gdb) c
Continuing.
r<< Can you r2 me?

Plaintext : 47 65 74 20 74 68 65 20 61 65 73 6B 65 79 21 21
Encrypted : FD DA 9B 78 FC F8 E9 BF 33 72 6E 0A 8A E5 F6 8C
Decrypted : 47 65 74 20 74 68 65 20 61 65 73 6B 65 79 21 21
[Inferior 1 (process 2519) exited normally]
```

I still don't know what the infinite loop is doing, and I always hit Ctrl-C in a slightly different spot, but it consistently allowed me to bypass the check, so I was satisfied to have this as a tool for later use.

Now I got curious about other call instructions, so I started patching them out one by one (using a combination of bash and a Python script similar to the one above). For each one, I saved the output of the program and compared it with the output from the unpatched program. Of these, there were two call instructions that caught my eye in particular, the ~16th (0x400a4e) and ~21st (0x400aa8), not counting a few weird ones.

For the ~21st, I got this diff:
```
$ diff -u <(./antir2) <(./antir2.patched)
--- /dev/fd/63  2017-09-15 00:21:54.208447723 +0200
+++ /dev/fd/62  2017-09-15 00:21:54.216447711 +0200
@@ -5,5 +5,5 @@
 r<< Can you r2 me?

 Plaintext : 47 65 74 20 74 68 65 20 61 65 73 6B 65 79 21 21
-Encrypted : FD DA 9B 78 FC F8 E9 BF 33 72 6E 0A 8A E5 F6 8C
+Encrypted : E2 4B C5 BA 63 67 89 32 7F CC F0 A9 E9 BD 22 2D
 Decrypted : 47 65 74 20 74 68 65 20 61 65 73 6B 65 79 21 21
```

This caught my eye because the encryption was different, but the decryption was still the same. This suggested that the key had been modified by this specific call instruction. If I could somehow look at what addresses this function was writing to, maybe I could find the location of the key in memory.

However, before I got any further on that lead, I also ran valgrind and diffed its outputs (unpatched vs. patched) and then the ~16th call instruction really caught my eye:
```
$ valgrind ./antir2.patched 2>&1 | grep -A1 'Use of'
==3318== Use of uninitialised value of size 8
==3318==    at 0x42C04F: ???
--
==3318== Use of uninitialised value of size 8
==3318==    at 0x42C054: ???
--
==3318== Use of uninitialised value of size 8
==3318==    at 0x42C059: ???
--
==3318== Use of uninitialised value of size 8
==3318==    at 0x42C05E: ???
--
==3318== Use of uninitialised value of size 8
==3318==    at 0x42C063: ???
--
==3318== Use of uninitialised value of size 8
==3318==    at 0x42C06B: ???
--
==3318== Use of uninitialised value of size 8
==3318==    at 0x42C073: ???
--
==3318== Use of uninitialised value of size 8
==3318==    at 0x42C078: ???
--
==3318== Use of uninitialised value of size 8
==3318==    at 0x42C09F: ???
--
==3318== Use of uninitialised value of size 8
==3318==    at 0x42C0B3: ???
--
==3318== Use of uninitialised value of size 8
==3318==    at 0x42C0BB: ???
--
==3318== Use of uninitialised value of size 8
==3318==    at 0x42C0D7: ???
--
==3318== Use of uninitialised value of size 8
==3318==    at 0x42C0DC: ???
--
==3318== Use of uninitialised value of size 8
==3318==    at 0x42C0E1: ???
--
==3318== Use of uninitialised value of size 8
==3318==    at 0x42C0E6: ???
--
==3318== Use of uninitialised value of size 8
==3318==    at 0x42C0EB: ???
```

Exactly 16 reads of uninitialised memory, and 16 bytes is the key size. At first I actually thought the "size 8" gave a size in bits, and so I was excited to see 16 individual byte-sized reads, but these are actually 8-byte reads.

Valgrind is helpful and tells us exactly where the reads are coming from. This is the disassembly (with annotations):
```
42c04f:       47 0f b6 14 16          movzbl (%r14,%r10,1),%r10d
42c054:       47 0f b6 1c 1e          movzbl (%r14,%r11,1),%r11d
42c059:       47 0f b6 24 26          movzbl (%r14,%r12,1),%r12d
42c05e:       47 0f b6 04 06          movzbl (%r14,%r8,1),%r8d
42c063:       45 0f b6 0c 36          movzbl (%r14,%rsi,1),%r9d
42c068:       0f b6 f4                movzbl %ah,%esi
42c06b:       45 0f b6 2c 3e          movzbl (%r14,%rdi,1),%r13d
42c070:       0f b6 f9                movzbl %cl,%edi
42c073:       41 0f b6 2c 2e          movzbl (%r14,%rbp,1),%ebp
42c078:       41 0f b6 34 36          movzbl (%r14,%rsi,1),%esi
```

I spent a while looking at this and then checking in gdb what the actual values of those registers were after the block had executed, but I didn't know if the reads were happening in the right order to be the key, and I also made the mistake of confusing valgrind's addresses as the addresses where the key was _read_ as opposed to where it was _used_.

Eventually I realised that I had to see what the values were _before_ getting to this particular block of instructions, so I scrolled up just a tiny bit:
```
42c016:       eb 08                   jmp    0x42c020
42c018:       0f 1f 84 00 00 00 00    nopl   0x0(%rax,%rax,1)
42c01f:       00
42c020:       41 33 07                xor    (%r15),%eax
42c023:       41 33 5f 04             xor    0x4(%r15),%ebx
42c027:       41 33 4f 08             xor    0x8(%r15),%ecx
42c02b:       41 33 57 0c             xor    0xc(%r15),%edx
42c02f:       4d 8d 7f 10             lea    0x10(%r15),%r15
42c033:       44 0f b6 d0             movzbl %al,%r10d
42c037:       44 0f b6 db             movzbl %bl,%r11d
42c03b:       44 0f b6 e1             movzbl %cl,%r12d
42c03f:       44 0f b6 c2             movzbl %dl,%r8d
42c043:       0f b6 f7                movzbl %bh,%esi
42c046:       0f b6 fd                movzbl %ch,%edi
42c049:       c1 e9 10                shr    $0x10,%ecx
42c04c:       0f b6 ee                movzbl %dh,%ebp
```

The jump/nop instructions at 0x42c016 indicate that 0x42c020 must be the start of this function (as it cannot be reached otherwise), and by simply reading the code it becomes clear that %r15 at the start of this function is where all the values come from. We have 4x4-byte reads from it, which is exactly the 16 bytes of the key! So loading up gdb again, we get:
```
(gdb) run
Starting program: antir2.patched
*******************************************
* Radare2con 2017 rhme3 pre-quals edition *
*******************************************

^C
Program received signal SIGINT, Interrupt.
0x0000000000418fb9 in ?? ()
(gdb) break *0x42c020
Breakpoint 1 at 0x42c020
(gdb) ret
Make selected stack frame return now? (y or n) y
#0  0x0000000000400a0c in ?? ()
(gdb) c
Continuing.

Breakpoint 1, 0x000000000042c020 in ?? ()
(gdb) info registers
rax            0x20746547       544499015
rbx            0x20656874       543516788
rcx            0x6b736561       1802724705
rdx            0x21217965       555841893
rsi            0x7fffffffde60   140737488346720
rdi            0xec130ccd       3960671437
rbp            0xa3a32e0        0xa3a32e0
rsp            0x7fffffffd8f8   0x7fffffffd8f8
r8             0x42dbc0 4381632
r9             0x7fffffffde60   140737488346720
r10            0x2e2578ba       774207674
r11            0x1198f8e1       295237857
r12            0x43db60 4447072
r13            0x43dbf0 4447216
r14            0x42db40 4381504
r15            0x7fffffffdd58   140737488346456
rip            0x42c020 0x42c020
eflags         0x206    [ PF IF ]
cs             0x33     51
ss             0x2b     43
ds             0x0      0
es             0x0      0
fs             0x63     99
gs             0x0      0
(gdb) x/16b 0x7fffffffdd58
0x7fffffffdd58: 0x72    0x61    0x64    0x61    0x72    0x65    0x32    0x63
0x7fffffffdd60: 0x6f    0x6e    0x34    0x65    0x76    0x65    0x72    0x21
(gdb)
```

(You can tell I'm a gdb noob from the fact that I didn't use "x/s $r15").

These bytes at *%r15 are clearly ASCII (0x6*/0x7* is a dead giveaway) so it's not surprising that they are, in fact, the key. And again I used a short Python script to verify it:
```python
from Crypto.Cipher import AES
import binascii
import os

"""
>>> [chr(int(x, 16)) for x in "0x72    0x61    0x64    0x61
0x72    0x65    0x32    0x63".split()]
['r', 'a', 'd', 'a', 'r', 'e', '2', 'c']
>>> [chr(int(x, 16)) for x in "0x6f    0x6e    0x34    0x65
0x76    0x65    0x72    0x21".split()]
['o', 'n', '4', 'e', 'v', 'e', 'r', '!']
"""

key = 'radare2con4ever!'

print "key len =", len(key)
encryptor = AES.new(key, AES.MODE_ECB)
text = 'Get the aeskey!!'
ciphertext = encryptor.encrypt(text)
print "encrypted:", binascii.hexlify(ciphertext).upper()
```

And this prints the same as the program itself:
```sh
$ python aes.py
key len = 16
encrypted:  FDDA9B78FCF8E9BF33726E0A8AE5F68C
```

