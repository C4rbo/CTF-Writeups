## Description 

Say hello to RudeFrida, it is like your toxic ex who gaslighted you for loving her.

## Challenge

Being a **mobile application**, the attachment for the challenge is an .apk file. Performing static analysis provides the following information:


```java
 package com.pwnsec.RudeFrida;

import android.os.Bundle;
import android.util.Log;
import android.widget.Toast;
import androidx.appcompat.app.AppCompatActivity;
import com.pwnsec.RudeFrida.databinding.ActivityMainBinding;

/* loaded from: classes.dex */
public class MainActivity extends AppCompatActivity {
    private ActivityMainBinding binding;

    public native String stringFromJNI();

    static {
        System.loadLibrary("Rudefrida"); // LIB
    }

    @Override // androidx.fragment.app.FragmentActivity, androidx.activity.ComponentActivity, androidx.core.app.ComponentActivity, android.app.Activity
    protected void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        Toast.makeText(this, "Oh look, a clown 🤡", 1).show();
        ActivityMainBinding activityMainBindingInflate = ActivityMainBinding.inflate(getLayoutInflater());
        this.binding = activityMainBindingInflate;
        setContentView(activityMainBindingInflate.getRoot());
        Log.d("RudeFrida: ", stringFromJNI()); // la flag viene stampata nei log da stringFromJNI()
    }
}
```

Alright, I only know that the flag will be printed in the logs. So we need to figure out what happens inside the native library...

I extract all the files with **apktool**, go into the lib folder, and open it with Ida for reverse engineering.

So, there’s already some interesting information:

* anti-frida
* anti-root
* get_flag(int a, int b)
* JNI_OnLoad
* Java_com_pwnsec_RudeFrida_MainActivity_stringFromJNI

> Where I write “to patch” means that I’ve inserted NOPs in place of function calls, etc.

Let’s go step by step:

JNI_OnLoad has only one annoying function: antiFrida()."

---

This sounds like you're diving deep into reversing an APK with some protections in place. Is there a specific part you're stuck on or need more insight about?


```c
__int64 JNI_OnLoad()
{
  __android_log_print(
    4,
    "RudeFrida",
    "Well Hello bozo, I hope your not here for the flag or smth. Fine fine, the flag is here yes, but can you pass the phantom of frida");
  FridaCheck(); // to patch
  return 65542;
}
```

The address of **get_flag** is:

```bash
➜  ~ python3 
Python 3.13.5 (main, Jun 25 2025, 18:55:22) [GCC 14.2.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> 0x00000000000618e0 # address
399584
>>> exit
```

Java_com_pwnsec_RudeFrida_MainActivity_stringFromJNI: 

```c
__int64 __fastcall Java_com_pwnsec_RudeFrida_MainActivity_stringFromJNI(__int64 a1)
{
  char *v1; // rbx
  __int64 v2; // r14

  is_rooted_simple(); // to patch
  FridaCheck();  // da patchare
  v1 = (char *)operator new(0x30u);
  strcpy(v1, "Oh look — another Frida enthusiast. Cute.");
  v2 = (*(__int64 (__fastcall **)(__int64, char *))(*(_QWORD *)a1 + 1336LL))(a1, v1);
  operator delete(v1);
  return v2;
}
```
get_flag: 

```c
unsigned __int64 __fastcall get_flag(int a1, int a2)
{
  unsigned __int64 v2; // rsi
  __int64 v3; // rcx
  __int64 i; // rdx
  unsigned __int64 v5; // rdi
  __int64 v6; // r8
  _OWORD *v7; // rbx
  unsigned __int64 v8; // rcx
  __int64 v9; // r14
  __int64 v10; // r11
  __int64 v11; // r14
  unsigned __int64 v12; // rdx
  unsigned __int64 v13; // rax
  _OWORD *v14; // rax
  __int128 v15; // xmm0
  std::ios_base *v16; // r14
  __int64 (__fastcall **v17)(); // rax
  __int64 v18; // rax
  char *v19; // r13
  __int64 v20; // rax
  _OWORD *v21; // r13
  void *ptr; // [rsp+20h] [rbp-A38h]
  void *v24[3]; // [rsp+28h] [rbp-A30h] BYREF
  _QWORD v25[2]; // [rsp+40h] [rbp-A18h] BYREF
  void *v26; // [rsp+50h] [rbp-A08h]
  __int64 (__fastcall **v27)(); // [rsp+58h] [rbp-A00h] BYREF
  _QWORD v28[8]; // [rsp+60h] [rbp-9F8h] BYREF
  __int128 v29; // [rsp+A0h] [rbp-9B8h]
  void *v30[2]; // [rsp+B0h] [rbp-9A8h]
  int v31; // [rsp+C0h] [rbp-998h]
  _QWORD v32[298]; // [rsp+C8h] [rbp-990h] BYREF
  __int64 v33; // [rsp+A18h] [rbp-40h]
  unsigned __int64 v34; // [rsp+A20h] [rbp-38h]

  v34 = __readfsqword(0x28u);
  if ( a2 + a1 == 1337 ) // to patch
  {
    v2 = 0xDEADBEEFCAFEBABELL;
    v27 = (__int64 (__fastcall **)())0xDEADBEEFCAFEBABELL;
    v3 = 1;
    for ( i = 2; ; i += 2 )
    {
      v5 = i + 0x5851F42D4C957F2DLL * (v2 ^ (v2 >> 62)) - 1;
      *(&v26 + i) = (void *)v5;
      if ( i == 312 )
        break;
      v6 = 0x5851F42D4C957F2DLL * (v5 ^ (v5 >> 62));
      v2 = v6 + v3 + 1;
      v28[i - 1] = i + v6;
      v3 += 2;
    }
    v33 = 0;
    v7 = (_OWORD *)operator new(0x20u);
    *v7 = 0;
    v7[1] = 0;
    v8 = -8;
    v9 = 0;
    do
    {
      v10 = 0;
      if ( v9 != 311 )
        v10 = v9 + 1;
      v28[v9 - 1] = v28[(_DWORD)v9
                      + 156
                      - 312
                      * ((unsigned int)((0xD20D20D20D20D21LL * (unsigned __int128)((unsigned __int64)(v9 + 156) >> 3)) >> 64) >> 1)
                      - 1]
                  ^ ((v28[v9 - 1] & 0xFFFFFFFF80000000LL | v28[v10 - 1] & 0x7FFFFFFE) >> 1)
                  ^ -(v28[v10 - 1] & 1)
                  & 0xB5026F5AA96619E9LL;
      v11 = v28[v33 - 1] ^ ((unsigned __int64)v28[v33 - 1] >> 29) & 0x555555555LL;
      v33 = v10;
      v12 = v11 ^ (v11 << 17) & 0x71D67FFFEDA60000LL;
      v13 = v12 ^ ((unsigned __int64)(((unsigned int)v11 ^ ((_DWORD)v11 << 17) & 0xEDA60000) & 0x7FFBF77) << 37);
      LODWORD(v11) = v12 ^ (v13 >> 43);
      *((_BYTE *)v7 + v8 + 8) = v11;
      *((_BYTE *)v7 + v8 + 9) = (unsigned int)v11 >> 7;
      *((_BYTE *)v7 + v8 + 10) = (unsigned int)v11 >> 14;
      *((_BYTE *)v7 + v8 + 11) = (unsigned int)v12 >> 21;
      *((_BYTE *)v7 + v8 + 12) = v12 >> 28;
      *((_BYTE *)v7 + v8 + 13) = v13 >> 35;
      *((_BYTE *)v7 + v8 + 14) = v13 >> 42;
      *((_BYTE *)v7 + v8 + 15) = v13 >> 49;
      v8 += 8LL;
      v9 = v10;
    }
    while ( v8 < 0x18 );
    v14 = (_OWORD *)operator new(0x30u);
    v26 = v14;
    v25[0] = 49;
    v25[1] = 32;
    v15 = *v7;
    v14[1] = v7[1];
    *v14 = v15;
    *((_BYTE *)v14 + 32) = 0;
    v32[0] = off_CD0D0;
    v27 = &off_CD118;
    *(_QWORD *)((char *)&v28[-1] + (_QWORD)*(&off_CD118 - 3)) = off_CD140;
    v16 = (std::ios_base *)((char *)&v28[-1] + (_QWORD)*(v27 - 3));
    std::ios_base::init(v16, v28);
    *((_QWORD *)v16 + 17) = 0;
    *((_DWORD *)v16 + 36) = -1;
    v27 = &off_CD0A8;
    v32[0] = off_CD0D0;
    std::streambuf::basic_streambuf(v28);
    v28[0] = &off_CCB88;
    v29 = 0;
    *(_OWORD *)v30 = 0;
    v31 = 16;
    v17 = v27;
    *(_DWORD *)((char *)v28 + (_QWORD)*(v27 - 3)) = *(_DWORD *)((_BYTE *)v28 + (_QWORD)*(v27 - 3)) & 0xFFFFFFB5 | 8;
    v18 = (__int64)*(v17 - 3);
    v19 = (char *)&v28[-1] + v18;
    if ( *(_DWORD *)((char *)&v32[4] + v18) == -1 )
    {
      std::ios_base::getloc((std::ios_base *)v24);
      v20 = std::locale::use_facet((std::locale *)v24, (std::locale::id *)&std::ctype<char>::id);
      (*(void (__fastcall **)(__int64, __int64))(*(_QWORD *)v20 + 56LL))(v20, 32);
      std::locale::~locale((std::locale *)v24);
    }
    *((_DWORD *)v19 + 36) = 48;
    v21 = (_OWORD *)operator new(0x3Cu);
    v24[0] = v21;
    v24[2] = (char *)v21 + 60;
    *(_OWORD *)((char *)v21 + 44) = *(__int128 *)((char *)&xmmword_43D97 + 12);
    v21[2] = xmmword_43D97;
    v21[1] = xmmword_43D87;
    *v21 = xmmword_43D77;
    v24[1] = (char *)v21 + 60;
    Z(v24, v25);
    ptr = (void *)operator new(0x40u);
    memmove(ptr, v21, 0x3Cu);
    *((_BYTE *)ptr + 60) = 0;
    __android_log_print(4, "RudeFrida", byte_42C41);
    operator delete(ptr);
    if ( v24[0] )
      operator delete(v24[0]);
    v27 = &off_CD0A8;
    *(_QWORD *)((char *)&v28[-1] + (_QWORD)*(&off_CD0A8 - 3)) = off_CD0D0;
    v28[0] = &off_CCB88;
    if ( (v29 & 1) != 0 )
      operator delete(v30[0]);
    std::streambuf::~streambuf(v28);
    std::ostream::~ostream(&v27, &off_CD0E8);
    std::ios::~ios(v32);
    if ( (v25[0] & 1) != 0 )
      operator delete(v26);
    operator delete(v7);
  }
  return __readfsqword(0x28u);
}
```

> Patch **get_flag** first and then patch **JNI_OnLoad**.

Rebuild everything with **apktool** and then re-sign the app using **objection**.

```bash
adb logcat | grep RudeFrida  # since the flag is printed in logcat
```

![](/img/flag.png)

~ Carbo