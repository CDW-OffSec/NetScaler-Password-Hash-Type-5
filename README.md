# NetScaler Password Hash Research
Ian Odette      (ian.odette@cdw.com/[@stumblebot](https://github.com/stumblebot))<br>
Tyler Booth     (tyler.booth@cdw.com/[@dru1d-foofus](https://github.com/dru1d-foofus))

## Background
During a red team engagement, we recovered a lot of Citrix NetScaler configuration files from a SharePoint website. Some values we were able to extract using pre-exisiting methods; however, there appeared to be a newer hash type being used for the local system users. We set out to determine what that is and are using this to document our process.

## Analysis of libnscli90.so

We knew where to look initially because the [dozer.nz blog post](https://dozer.nz/posts/citrix-decrypt/)  showed that the `libnscli90.so` library was used for handling legacy hashing algorithms used by NetScaler ADC. This includes previously broken SHA1 and SHA512 implementations of the hashing algorithm. 

While reviewing the functions in Binary Ninja, we found several functions that are used by the library for hashing system user passwords. We even see references to the previously identified hashing schemes - SHA1 and SHA512. While searching through those functions, we landed on `sys_hash_password_init` and `sys_hash_password_Current` which calls the `sub_273440` function. 

```c++
void sys_hash_password_init()
    *sys_hash_password_Current = sub_273440
```

We are greeted immediately with references to a different cryptography function from the OpenSSL library - `PKCS5_PBKDF2_HMAC`. After some further research, [documentation](https://developer-docs.netscaler.com/en-us/adc-nitro-api/13/configuration/system/systemuser.html) was found from NetScaler that explicitly details what user hashing functions they use. 

| Name | Data Type | Permissions | Description |
| ---      | ---      | ---      | --- |
|...|...|...|...|
|hashmethod|<string>|Read-only|Possible values = SHA1, SHA512, PBKDF2|
|...|...|...|...|

```c++
uint64_t sub_273440(void* arg1, char* hashVersion)

    uint64_t rax = 0
    if (hashVersion != 0)
        void* const password = &data_422ba0
        if (arg1 != 0)
            password = arg1
        *hashVersion = 0x35  // ASCII: 5
        void salt
        void* rbx_1 = &salt
        RAND_bytes(&salt, 0x20)  // 32-byte random salt
        int64_t i = 0
        do
            uint64_t rsi = zx.q(*rbx_1)
            hashVersion[i + 1] = *(nibble_2_ascii + (rsi u>> 4))
            hashVersion[2 + i] = *(nibble_2_ascii + zx.q(rsi.d & 0xf))
            i = i + 2
            rbx_1 = rbx_1 + 1
        while (i u< 0x40)
        void bufDerivedKey
        if (PKCS5_PBKDF2_HMAC(password, 0xffffffff, &salt, zx.q(0x20), 0x9c4, EVP_sha256(), 0x20, &bufDerivedKey) == 0)
            *gpaudit_logbuf = gaudit_databuf
            *(gaudit_databuf + 0x46) = 0
            *(gaudit_databuf + 0x44) = 0
            *(gaudit_databuf + 0x40) = 0
            *(gaudit_databuf + 0x4c) = 0xdeadbabe
            *(gaudit_databuf + 8) = 1
            *(gaudit_databuf + 0x14) = data_41b3f0
            *(gaudit_databuf + 0x50) = (*"_nsapp_sys_hashpbkdf2_password()…")[0].o
            *(gaudit_databuf + 0x60) = (*"bkdf2_password() failed")[0].o
            *(gaudit_databuf + 0x70) = 0x64656c69616620
            *(gaudit_databuf + 0x24) = 0x28
            *gaudit_databuf = 0x1500000078
            nsapps_audit_sendmsg(1)
        int64_t i_1 = 0
        int64_t rcx_2 = 0
        do
            uint64_t rsi_2 = zx.q(*(&bufDerivedKey + i_1))
            hashVersion[(i_1 << 1) + 0x41] = *(nibble_2_ascii + (rsi_2 u>> 4))
            hashVersion[0x42 + (i_1 << 1)] = *(nibble_2_ascii + zx.q(rsi_2.d & 0xf))
            i_1 = i_1 + 1
            rcx_2 = rcx_2 + 2
        while (i_1 u< 0x20)
        hashVersion[0x41 + rcx_2] = 0
        rax = zx.q(rcx_2.d + (&hashVersion[0x41]).d - hashVersion.d + 1)
    return rax
```

```c++
PKCS5_PBKDF2_HMAC(password, 0xffffffff, &salt, zx.q(0x20), 0x9c4, EVP_sha256(), 0x20, &bufDerivedKey)
```

### OpenSSL Documentation
```c++
int PKCS5_PBKDF2_HMAC(
                    const char *pass,               //Password 
                    int passlen,                    //Length of password
                    const unsigned char *salt,      //Salt
                    int saltlen,                    //Salt length 
                    int iter,                       //Iterations
                    const EVP_MD *digest,           //Message digest function
                    int keylen,                     //Key length
                    unsigned char *out);            //Derived key buffer
```

In our case, this proves that we are using `PBKDF2-HMAC-SHA256` with 2,500 (`0x9cf`) iterations. We now know that our hash should be structured like this:
- 32-bytes (64 hex characters) for the salt
- 32-bytes (64 hex characters) for the hash

## Additional Analysis of nsppe Binary
We decided to see if other binaries on the NetScaler had references to these functions and decided to grep for strings based on previously identified function names. 

It turns out that the `nsppe` binary actually defines its own version of the functions in question. However, this decompiled set of functions are a bit more complicated than our previous library.

```c++
int64_t sys_hash_password_init()

{
    sys_hash_password_Current = sys_hashpbkdf2_password;
}
```

```c++
uint64_t sys_hashpbkdf2_password(char* arg1, char* arg2)

{
    int32_t rbx = 0;
    if (arg2 != 0)
    {
        char* r15_1 = &data_21099de;
        if (arg1 != 0)
        {
            r15_1 = arg1;
        }
        char* rax_1 = sys_password_version(0x35); //Version: 5
        if ((rax_1 != 0 && (rax_1[1] == 1 && (rax_1[2] <= 0x40 && rax_1[3] <= 0x20))))
        {
            *(uint8_t*)arg2 = 0x35;
            void var_78;
            void* rbx_1 = &var_78;
            RAND_bytes(&var_78, 0x20); //32-byte random salt
            uint64_t r8_1 = ((uint64_t)rax_1[1]);
            uint64_t rdx_1;
            rdx_1 = rax_1[2];
            if (rdx_1 != 0)
            {
                int64_t rcx_1 = 0;
                do
                {
                    uint64_t rdx_2 = ((uint64_t)*(uint8_t*)rbx_1);
                    arg2[(((r8_1 + 1) + rcx_1) - 1)] = nibble_2_ascii[(rdx_2 >> 4)];
                    arg2[((r8_1 + 1) + rcx_1)] = nibble_2_ascii[((uint64_t)(rdx_2 & 0xf))];
                    rcx_1 = (rcx_1 + 2);
                    rdx_1 = ((uint64_t)rax_1[2]);
                    rbx_1 = ((char*)rbx_1 + 1);
                } while (rcx_1 < rdx_1);
            }
            rdx_1 = (rdx_1 >> 1);
            void var_58;
            if (_ns_pe_sys_hashpbkdf2_password(&var_78, r15_1, ((uint32_t)rdx_1), *(uint32_t*)(rax_1 + 4), &var_58) == 1)
            {
                uint64_t cur_partition_ptr_1 = cur_partition_ptr;
                if (((*(uint8_t*)(cur_partition_ptr_1 + 0x318a) & 1) == 0 && (*(uint8_t*)(cur_partition_ptr_1 + 0x9e7b8) & 8) != 0))
                {
                    void* var_38;
                    NSMP_AUDITLOG_GET_LOCKED_BUF(&var_38, 0xb, 0x44, 3, 0, 0, 0);
                    void* rdi_4 = var_38;
                    __builtin_strcpy(((char*)rdi_4 + 0x38), "_ns_pe_sys_hashpbkdf2_password() failed");
                    *(uint16_t*)((char*)rdi_4 + 0xc) = 0x28;
                    NSMP_AUDITLOG_UNLOCK_BUF(rdi_4);
                    NSMP_AUDIT_MSG_PROCESS(0xff, 0);
                }
            }
            uint64_t rax_5 = ((uint64_t)rax_1[2]);
            void* r13_2 = &arg2[(r8_1 + rax_5)];
            int64_t rax_6;
            if (rax_1[3] == 0)
            {
                rax_6 = 0;
            }
            else
            {
                int64_t i = 0;
                rax_6 = 0;
                do
                {
                    uint64_t rsi_3 = ((uint64_t)*(uint8_t*)(&var_58 + i));
                    arg2[((((r8_1 + rax_5) + 1) + (i << 1)) - 1)] = nibble_2_ascii[(rsi_3 >> 4)];
                    arg2[(((r8_1 + rax_5) + 1) + (i << 1))] = nibble_2_ascii[((uint64_t)(rsi_3 & 0xf))];
                    i = (i + 1);
                    rax_6 = (rax_6 + 2);
                } while (i < ((uint64_t)rax_1[3]));
            }
            *(uint8_t*)((char*)r13_2 + rax_6) = 0;
            rbx = (((r13_2 + rax_6) - arg2) + 1);
        }
    }
    return ((uint64_t)rbx);
}
```
### Review of sys_password_version Function
We see some additional functionality that helps inform our analysis is headed in the right direction. For example, we have a new function `sys_password_version` that is present in this hashing function.

```c++
char const* sys_password_version(char arg1)

{
    char rcx = 0x31;
    char const* rax_1 = "1";
    while (((uint32_t)rcx) != ((int32_t)arg1))
    {
        rcx = rax_1[8];
        rax_1 = &rax_1[8];
        if (rcx == 0)
        {
            rax_1 = nullptr;
            break;
        }
    }
    return rax_1;
}
```
This function actually determines the hashing algorithm that should be used. Older hashing algorithms will use `0x31`, or in ASCII, `1`. For our newer hashing algorithm, the password version is set to `0x35`, or in ASCII, `5`. 

### Review of _ns_pe_sys_hashpbkdf2_password Function
We also have a pointer to the `_ns_pe_sys_hashpbkdf2_password` function.
```c++
uint64_t _ns_pe_sys_hashpbkdf2_password(int64_t arg1, char* arg2, int32_t arg3, int32_t arg4, int128_t* arg5)

{
    int64_t rax;
    int64_t var_38 = rax;
    int32_t rcx_1;
    rcx_1 = PKCS5_PBKDF2_HMAC_SHA256(arg2, strlen(arg2), arg1, arg3, arg4, arg5) == 0;
    return ((uint64_t)rcx_1);
}
```
We can see that this function also calls the OpenSSL library to handle hashing. However, the arguments aren't as clearly defined (hardcoded) as the `libnscli90.so` library's decompilation.

## Proof with Example Hash

`52c334c4a4c2e593b6c3942622e5fcbd13c7bc895f24b9403f51ff18dc00505d81f99045cc6d393c17be5ce3c6c8efea8b0de19726ff081fd1b8cf0cc3515a7a7`

The composition of this string is as follows:
```
Hash Version Identifier  : 5
Salt                     : 2c334c4a4c2e593b6c3942622e5fcbd13c7bc895f24b9403f51ff18dc00505d8
Hash                     : 1f99045cc6d393c17be5ce3c6c8efea8b0de19726ff081fd1b8cf0cc3515a7a7
```

We can actually crack this with the [hashcat PBKDF2-HMAC-SHA256](https://github.com/hashcat/hashcat/blob/master/src/modules/module_10900.c) module by formatting the hash in a specific way:

`sha256:ITERATIONS:<SALT>:<HASH>`
1. We strip of the version identifer character from the beginning of the hash (`5`).
2. We add the number of iterations - `2500`.
3. We take the first 32-bytes, `base64(hex(2c334c4a4c2e593b6c3942622e5fcbd13c7bc895f24b9403f51ff18dc00505d8))` and use it as the salt.
4. We take the second 32-bytes, `base64(hex(1f99045cc6d393c17be5ce3c6c8efea8b0de19726ff081fd1b8cf0cc3515a7a7))` and use it as the hash

The completed hash value will be:
`sha256:2500:LDNMSkwuWTtsOUJiLl/L0Tx7yJXyS5QD9R/xjcAFBdg=:H5kEXMbTk8F75c48bI7+qLDeGXJv8IH9G4zwzDUVp6c=`

This can now be cracked with `hashcat -m 10900`. ~~A new module specifically for this hash type is currently in development.~~ The PR to hashcat is here: https://github.com/hashcat/hashcat/pull/3984

New hash-mode benchmark:
```
./hashcat -m 33700 -b 
hashcat (v6.2.6) starting in benchmark mode

***SNIP***
CUDA API (CUDA 12.2)
====================
* Device #1: NVIDIA GeForce GTX 1080 Ti, 11025/11164 MB, 28MCU

***SNIP***
Benchmark relevant options:===========================
* --backend-devices-virtual=1
* --optimized-kernel-enable

----------------------------------------------------------------------------
* Hash-Mode 33700 (Citrix NetScaler (PBKDF2-HMAC-SHA256)) [Iterations: 2499]
----------------------------------------------------------------------------

Speed.#1.........:   694.7 kH/s (63.70ms) @ Accel:16 Loops:256 Thr:1024 Vec:1

Started: Fri Apr  5 03:53:41 2024
Stopped: Fri Apr  5 03:53:55 2024
```
New hash-mode running:
```
./hashcat -m 33700 -a0 netscaler.hash hashcat.dic 
hashcat (v6.2.6) starting

***SNIP***
Minimum password length supported by kernel: 0Maximum password length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

***SNIP***
Dictionary cache hit:
* Filename..: hashcat.dic
* Passwords.: 1
* Bytes.....: 8
* Keyspace..: 1

***SNIP***
5567243c55099b6b10a714a350db53beea8be6ac9c247fd40fea7e96d206a9f11fd1c45735556ac2004138640de206d0e1522607ab3c3f92816156d2d7845068e:hashcat
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 33700 (Citrix NetScaler (PBKDF2-HMAC-SHA256))
Hash.Target......: 5567243c55099b6b10a714a350db53beea8be6ac9c247fd40fe...45068e
Time.Started.....: Fri Apr  5 04:00:00 2024 (0 secs)
Time.Estimated...: Fri Apr  5 04:00:00 2024 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (hashcat.dic)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:       44 H/s (0.54ms) @ Accel:256 Loops:64 Thr:32 Vec:1
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 1/1 (100.00%)
Rejected.........: 0/1 (0.00%)
Restore.Point....: 0/1 (0.00%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:2496-2499
Candidate.Engine.: Device Generator
Candidates.#1....: hashcat -> hashcat
Hardware.Mon.#1..: Temp: 44c Fan: 24% Util: 98% Core:1480MHz Mem:5005MHz Bus:16

Started: Fri Apr  5 03:59:58 2024
Stopped: Fri Apr  5 04:00:01 2024

```
## Thanks
Thanks to [@cstalhood](https://github.com/cstalhood) for providing NetScaler OVAs and fielding our questions about the product. Thanks to sw0rdf1sh2 for helping to work through some issues during hashcat module development. 

## Sources
1. https://github.com/hashcat/hashcat/blob/fafb277e0736a45775fbcadc1ca5caf0db07a308/src/modules/module_08100.c
2. https://github.com/hashcat/hashcat/blob/fafb277e0736a45775fbcadc1ca5caf0db07a308/src/modules/module_22200.c
3. https://developer-docs.netscaler.com/en-us/adc-nitro-api/13/configuration/system/systemuser.html
4. https://dozer.nz/posts/citrix-decrypt/
5. https://www.ferroquesystems.com/resource/citrix-adc-security-kek-files/
6. https://www.openssl.org/docs/man3.0/man3/PKCS5_PBKDF2_HMAC.html
