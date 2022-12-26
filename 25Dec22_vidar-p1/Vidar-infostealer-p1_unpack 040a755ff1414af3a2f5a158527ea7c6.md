# Vidar-infostealer-p1_unpack

After load file into x32dbg, i set break point at VirtualAlloc, VirtualProtect. Then click [Run], it stopped at VirtualProtect.

![Untitled](Vidar-infostealer-p1_unpack%20040a755ff1414af3a2f5a158527ea7c6/Untitled.png)

![Untitled](Vidar-infostealer-p1_unpack%20040a755ff1414af3a2f5a158527ea7c6/Untitled%201.png)

By [run till return] and out of the VirtualProtect function, we see a huge of mov byte instruction (for push shellcode onto stack segment) right before call VirtualProtect. More over, the shellcode is executed using **GrayStringA.**

```c
hDC = GetDC(0);
GrayStringA(hDC, 0, dec_shellcode, &app_defined_function, 0, 0, 0, 0, 0);
```

![Untitled](Vidar-infostealer-p1_unpack%20040a755ff1414af3a2f5a158527ea7c6/Untitled%202.png)

Run and VirtualAlloc breakpoint hit. It allocates reserve|commit 0xaa3ce bytes.

```c
VirtualAlloc(0, 0xaa3ce, 0x3000, 4);
```

Stepping over virtualAlloc function, in next few instructions after VirtualAlloc called. We meet ReadFile, which reads 0xaa3ce bytes from parent process image into above allocated buffer.

> 0x19FD** that is stack addr, look like we are executing in dec_shellcode
> 

![Untitled](Vidar-infostealer-p1_unpack%20040a755ff1414af3a2f5a158527ea7c6/Untitled%203.png)

We can confirm that by tool [process hacker].

![Untitled](Vidar-infostealer-p1_unpack%20040a755ff1414af3a2f5a158527ea7c6/Untitled%204.png)

So, run over ReadFile, our buffer is filled with itself image. Click [Run] and we hit VirtualAlloc (allocate `0x14F0` bytes with `rwx` perm) again, get buffer2 address into Dump2. Then put a **write breakpoint** in the this buffer to see how data gets filled in the mem region. U can see this loop use edx reg as a iteration variable (go through `0x14F0` times loop). This loop copy 0x14F0 bytes from certain offset of buffer1 into buffer2

![Untitled](Vidar-infostealer-p1_unpack%20040a755ff1414af3a2f5a158527ea7c6/Untitled%205.png)

Click [Run] we hit `VirtualAlloc(0, 0x350DE, 0x3000, 0x40)`, this allocated mem called buffer3. After tracing out, we see `memcpy(eax-des, ecx-src, edi-numOfBytes)` in previous pic. This copy 0x350DE bytes from certain offset of buffer1 into buffer3.

![Untitled](Vidar-infostealer-p1_unpack%20040a755ff1414af3a2f5a158527ea7c6/Untitled%206.png)

Loop in the following figure is decrypting first 0x14F0 bytes of buffer2.

![Untitled](Vidar-infostealer-p1_unpack%20040a755ff1414af3a2f5a158527ea7c6/Untitled%207.png)

Step into **call edx**, after push “Shlwapi.dll” string to stack, it finds the base addr of `kernel32.dll` by parsing PEB struct (`call 72099F`), then push hash value coresponding with (FF7F721A - GetModuleFileNameW) to resolve API function (`call 720A4E`) 

![Untitled](Vidar-infostealer-p1_unpack%20040a755ff1414af3a2f5a158527ea7c6/Untitled%208.png)

Then decrypt buf3 at routine 720BE9

![Untitled](Vidar-infostealer-p1_unpack%20040a755ff1414af3a2f5a158527ea7c6/Untitled%209.png)

![Untitled](Vidar-infostealer-p1_unpack%20040a755ff1414af3a2f5a158527ea7c6/Untitled%2010.png)

Once buffer3 contents are decrypted, it continues to resolve other important APIs (GetModuleFileNameW, CreateProcessW, GetThreadContext, ReadProcessMemory, CloseHandle, SetThreadContext, GetCommandLineW, TerminateProcess) in next routine (`call 72F86`). After this  routine resolved all required APIs, it will:

```c
1. retrives the full path of this process file
2. Get command line when run this process
3. Creat process with SUSPEND mode
```

![Untitled](Vidar-infostealer-p1_unpack%20040a755ff1414af3a2f5a158527ea7c6/Untitled%2011.png)

![Untitled](Vidar-infostealer-p1_unpack%20040a755ff1414af3a2f5a158527ea7c6/Untitled%2012.png)

and then final payload is injected into newly created process using `SetThreadContext` API, **CONTEXT** structure for remote thread is set up with ContextFlag and required memory buffers and **SetThreadContext** API is called with current thread handle and remote thread CONTEXT structure for code injection