# ascii-table test case

This is a simple test case for the delinker, adapted from this [case study](https://boricj.net/reverse-engineering/2023/05/15/part-2.html), suitable as a basic end-to-end integration test.

Any supported ISA should at least successfully delink its corresponding Linux nolibc (freestanding) artifact, in order to demonstrate a minimum level of functionality, as well as having its test harness integrated for basic anti-regression testing.

## Execution

Any ascii-table executable artifact should produce the following output when run:

```
0000     c              0020    p s             0040 @ gp  !            0060 ` gp  !     
0001     c              0021 ! gp  !            0041 A gp   Aa U        0061 a gp   Aa  l
0002     c              0022 " gp  !            0042 B gp   Aa U        0062 b gp   Aa  l
0003     c              0023 # gp  !            0043 C gp   Aa U        0063 c gp   Aa  l
0004     c              0024 $ gp  !            0044 D gp   Aa U        0064 d gp   Aa  l
0005     c              0025 % gp  !            0045 E gp   Aa U        0065 e gp   Aa  l
0006     c              0026 & gp  !            0046 F gp   Aa U        0066 f gp   Aa  l
0007     c              0027 ' gp  !            0047 G gp   Aa U        0067 g gp   Aa  l
0008     c              0028 ( gp  !            0048 H gp   Aa U        0068 h gp   Aa  l
0009     cs             0029 ) gp  !            0049 I gp   Aa U        0069 i gp   Aa  l
000a     cs             002a * gp  !            004a J gp   Aa U        006a j gp   Aa  l
000b     cs             002b + gp  !            004b K gp   Aa U        006b k gp   Aa  l
000c     cs             002c , gp  !            004c L gp   Aa U        006c l gp   Aa  l
000d     cs             002d - gp  !            004d M gp   Aa U        006d m gp   Aa  l
000e     c              002e . gp  !            004e N gp   Aa U        006e n gp   Aa  l
000f     c              002f / gp  !            004f O gp   Aa U        006f o gp   Aa  l
0010     c              0030 0 gp   A d         0050 P gp   Aa U        0070 p gp   Aa  l
0011     c              0031 1 gp   A d         0051 Q gp   Aa U        0071 q gp   Aa  l
0012     c              0032 2 gp   A d         0052 R gp   Aa U        0072 r gp   Aa  l
0013     c              0033 3 gp   A d         0053 S gp   Aa U        0073 s gp   Aa  l
0014     c              0034 4 gp   A d         0054 T gp   Aa U        0074 t gp   Aa  l
0015     c              0035 5 gp   A d         0055 U gp   Aa U        0075 u gp   Aa  l
0016     c              0036 6 gp   A d         0056 V gp   Aa U        0076 v gp   Aa  l
0017     c              0037 7 gp   A d         0057 W gp   Aa U        0077 w gp   Aa  l
0018     c              0038 8 gp   A d         0058 X gp   Aa U        0078 x gp   Aa  l
0019     c              0039 9 gp   A d         0059 Y gp   Aa U        0079 y gp   Aa  l
001a     c              003a : gp  !            005a Z gp   Aa U        007a z gp   Aa  l
001b     c              003b ; gp  !            005b [ gp  !            007b { gp  !     
001c     c              003c < gp  !            005c \ gp  !            007c | gp  !     
001d     c              003d = gp  !            005d ] gp  !            007d } gp  !     
001e     c              003e > gp  !            005e ^ gp  !            007e ~ gp  !     
001f     c              003f ? gp  !            005f _ gp  !            007f     c       
```

The artifacts for foreign architectures or platforms can usually be run under emulation, like for example [QEMU's user-mode emulation](https://www.qemu.org/docs/master/user/index.html).
