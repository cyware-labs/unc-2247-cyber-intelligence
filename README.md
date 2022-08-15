# UNC 2247 (Yanluowang Ransomware Group) Cyber Intelligence Tracker
## Table Of Contents:

- [Introduction](#Introduction)
- [IOCs](#IOCs)
  - IP Addresses
  - Domains
  - Email Addresses
  - C2C Communication User Agents
  - Command Syntax
- [Detections](#Detections)
  - YARA Rules
- [Tools Used](#Tools-Used-By-Group)
- [Potential Relations](#Potential-Relations)
- [MITRE ATT&CK Techniques](#MITRE-ATT&CK-Techniques)
- [Credits and Further Reading ](#Credits-and-Further-Reading)
- [Contribution](#Contribution)

## Introduction
On May 24, 2022, Cisco became aware of a potential compromise executed via a Cisco employee’s compromised credentials after an attacker gained control of a personal Google account through phishing. The victim’s credentials were saved in the browser from where the attacker stole them. 

The attacker conducted a series of sophisticated voice phishing attacks under the guise of various trusted organizations attempting to convince the victim to accept multi-factor authentication (MFA) push notifications initiated by the attacker. The attacker ultimately succeeded in achieving an MFA push acceptance, granting them access to VPN of the targeted user. 

The attack was attributed to UNC 2247, a financially motivated threat actor who has been previously seen conducting ransomware attacks and leveraging a technique called double extortion where data is extracted prior to data encryption. 

This repository created by Cyware is a collection of actionable threat intelligence on the threat actor and the attack from across the internet. The repository has been created to provide a single window, and centralized access to security teams to threat intelligence against UNC 2247.  

## IOCs
Below mentioned are the indicators of compromise (IOCs) observed to be involved with UNC 2247 across attacks using the Yanluowang Ransomware.

_Note: IOCs shared below are fanged IOCs_
### IP Addresses
| **IOC Value**   | **IOC Type** |
|-----------------|--------------|
| 172.58.239.34   | IPv4         |
| 176.59.109.115  | IPv4         |
| 131.150.216.118 | IPv4         |
| 134.209.88.140  | IPv4         |
| 139.177.192.145 | IPv4         |
| 162.33.177.27   | IPv4         |
| 162.33.179.17   | IPv4         |
| 165.227.219.211 | IPv4         |
| 45.227.255.215  | IPv4         |
| 73.153.192.98   | IPv4         |
| 104.131.30.201  | IPv4         |
| 108.191.224.47  | IPv4         |
| 138.68.227.71   | IPv4         |
| 139.60.160.20   | IPv4         |
| 139.60.161.99   | IPv4         |
| 143.198.110.248 | IPv4         |
| 143.198.131.210 | IPv4         |
| 159.65.246.188  | IPv4         |
| 161.35.137.163  | IPv4         |
| 162.33.178.244  | IPv4         |
| 165.227.23.218  | IPv4         |
| 165.232.154.73  | IPv4         |
| 166.205.190.23  | IPv4         |
| 172.56.42.39    | IPv4         |
| 172.58.220.52   | IPv4         |
| 174.205.239.164 | IPv4         |
| 192.241.133.130 | IPv4         |
| 194.165.16.98   | IPv4         |
| 195.149.87.136  | IPv4         |
| 24.6.144.43     | IPv4         |
| 45.145.67.170   | IPv4         |
| 45.32.228.189   | IPv4         |
| 45.32.228.190   | IPv4         |
| 45.61.136.207   | IPv4         |
| 45.61.136.5     | IPv4         |
| 45.61.136.83    | IPv4         |
| 46.161.27.117   | IPv4         |
| 5.165.200.7     | IPv4         |
| 64.227.0.177    | IPv4         |
| 64.4.238.56     | IPv4         |
| 65.188.102.43   | IPv4         |
| 66.42.97.210    | IPv4         |
| 67.171.114.251  | IPv4         |
| 68.183.200.63   | IPv4         |
| 68.46.232.60    | IPv4         |
| 74.119.194.203  | IPv4         |
| 74.119.194.4    | IPv4         |
| 76.22.236.142   | IPv4         |
| 82.116.32.77    | IPv4         |
| 87.251.67.41    | IPv4         |
| 104.131.30.201  | IPv4         |
| 108.191.224.47  | IPv4         |
| 131.150.216.118 | IPv4         |
| 134.209.88.140  | IPv4         |
| 138.68.227.71   | IPv4         |
| 139.177.192.145 | IPv4         |
| 139.60.160.20   | IPv4         |
| 139.60.161.99   | IPv4         |
| 143.198.110.248 | IPv4         |
| 143.198.131.210 | IPv4         |
| 159.65.246.188  | IPv4         |
| 161.35.137.163  | IPv4         |
| 162.33.177.27   | IPv4         |
| 162.33.178.244  | IPv4         |
| 162.33.179.17   | IPv4         |
| 165.227.219.211 | IPv4         |
| 165.227.23.218  | IPv4         |
| 165.232.154.73  | IPv4         |
| 166.205.190.23  | IPv4         |
| 167.99.160.91   | IPv4         |
| 172.56.42.39    | IPv4         |
| 172.58.220.52   | IPv4         |
| 172.58.239.34   | IPv4         |
| 174.205.239.164 | IPv4         |
| 176.59.109.115  | IPv4         |
| 178.128.171.206 | IPv4         |
| 185.220.100.244 | IPv4         |
| 185.220.101.10  | IPv4         |
| 185.220.101.13  | IPv4         |
| 185.220.101.15  | IPv4         |
| 185.220.101.16  | IPv4         |
| 185.220.101.2   | IPv4         |
| 185.220.101.20  | IPv4         |
| 185.220.101.34  | IPv4         |
| 185.220.101.45  | IPv4         |
| 185.220.101.6   | IPv4         |
| 185.220.101.65  | IPv4         |
| 185.220.101.73  | IPv4         |
| 185.220.101.79  | IPv4         |
| 185.220.102.242 | IPv4         |
| 185.220.102.250 | IPv4         |
| 192.241.133.130 | IPv4         |
| 194.165.16.98   | IPv4         |
| 195.149.87.136  | IPv4         |
| 24.6.144.43     | IPv4         |
| 45.145.67.170   | IPv4         |
| 45.227.255.215  | IPv4         |
| 45.32.141.138   | IPv4         |
| 45.32.228.189   | IPv4         |
| 45.32.228.190   | IPv4         |
| 45.55.36.143    | IPv4         |
| 45.61.136.207   | IPv4         |
| 45.61.136.5     | IPv4         |
| 45.61.136.83    | IPv4         |
| 46.161.27.117   | IPv4         |
| 5.165.200.7     | IPv4         |
| 52.154.0.241    | IPv4         |
| 64.227.0.177    | IPv4         |
| 64.4.238.56     | IPv4         |
| 65.188.102.43   | IPv4         |
| 66.42.97.210    | IPv4         |
| 67.171.114.251  | IPv4         |
| 68.183.200.63   | IPv4         |
| 68.46.232.60    | IPv4         |
| 73.153.192.98   | IPv4         |
| 74.119.194.203  | IPv4         |
| 74.119.194.4    | IPv4         |
| 76.22.236.142   | IPv4         |
| 82.116.32.77    | IPv4         |
| 87.251.67.41    | IPv4         |
| 94.142.241.194  | IPv4         |

### Domains Used
| **IOC Value**                                        | **IOC Type** |
|------------------------------------------------------|--------------|
| [cisco-help.cf](http://cisco-help.cf/)               | Domain       |
| [cisco-helpdesk.cf](http://cisco-helpdesk.cf/)       | Domain       |
| [ciscovpn1.com](http://ciscovpn1.com/)               | Domain       |
| [ciscovpn2.com](http://ciscovpn2.com/)               | Domain       |
| [ciscovpn3.com](http://ciscovpn3.com/)               | Domain       |
| [devcisco.com](http://devcisco.com/)                 | Domain       |
| [devciscoprograms.com](http://devciscoprograms.com/) | Domain       |
| [helpzonecisco.com](http://helpzonecisco.com/)       | Domain       |
| [kazaboldu.net](http://kazaboldu.net/)               | Domain       |
| [mycisco-helpdesk.ml](http://mycisco-helpdesk.ml/)   | Domain       |
| [mycisco.cf](http://mycisco.cf/)                     | Domain       |
| [mycisco.gq](http://mycisco.gq/)                     | Domain       |
| [primecisco.com](http://primecisco.com/)             | Domain       |
| [pwresetcisco.com](http://pwresetcisco.com/)         | Domain       |

### Hashes
| **IOC Value**                                                    | **IOC Type**        |
|------------------------------------------------------------------|---------------------|
| a710f573f73c163d54c95b4175706329db3ed89cd9337c583d0bb24b6a384789 | File Hash (SHA256)  |
| 2c2513e17a23676495f793584d7165900130ed4e8cccf72d9d20078e27770e04 | File Hash (SHA256)  |
| 43f8a66d3f3f1ba574bc932a7bc8e5886fbeeab0b279d1dea654d7119e80a494 | File Hash (SHA256)  |
| 9aa1f37517458d635eae4f9b43cb4770880ea0ee171e7e4ad155bbdee0cbe732 | File Hash (SHA256)  |
| 85fb8a930fa7f4c32c8af86aa204eb4ea4ae404e670a8be17e7ae0adf37a9e2e | File Hash (SHA256)  |
| fe38912d64f6d196ac70673cd2edbdbc1a63e494a2d7903546a6d3afa39dc5c4 | File Hash (SHA256)  |
| c77ff8e3804414618abeae394d3003c4bb65a43d69c57c295f443aeb14eaa447 | File Hash (SHA256)  |
| 2fc5bf9edcfa19d48e235315e8f571638c99a1220be867e24f3965328fe94a03 | File Hash (SHA256)  |
| 4ff503258e23d609e0484ee5df70a1db080875272ab6b4db31463d93ebc3c6dd | File Hash (SHA256)  |
| 1c543ea5c50ef8b0b42f835970fa5f553c2ae5c308d2692b51fb476173653cb3 | File Hash (SHA256)  |
| 0b9219328ebf065db9b26c9a189d72c7d0d9c39eb35e9fd2a5fefa54a7f853e4 | File Hash (SHA256)  |
| b556d90b30f217d5ef20ebe3f15cce6382c4199e900b5ad2262a751909da1b34 | File Hash (SHA256)  |
| 5e03cea2e3b875fdbf1c142b269470a9e728bcfba1f13f4644dcc06d10de8fb4 | File Hash (SHA256)  |
| 49d828087ca77abc8d3ac2e4719719ca48578b265bbb632a1a7a36560ec47f2d | File Hash (SHA256)  |
| 0772f9980d94215f24c01ed5f2a04154                                 | File Hash (MD5)     |
| 1bb339fb7d5e700caa986e27b06a854d9147df84                         | File Hash (SHA1)    |
| 184a2570d71eedc3c77b63fd9d2a066cd025d20ceef0f75d428c6f7e5c6965f3 | File Hash (SHA256)  |
| 2fc5bf9edcfa19d48e235315e8f571638c99a1220be867e24f3965328fe94a03 | File Hash (SHA256)  |
| 542c9da985633d027317e9a226ee70b4f0742dcbc59dfd2d4e59977bb870058d | File Hash (SHA256)  |
| 61176a5756c7b953bc31e5a53580d640629980a344aa5ff147a20fb7d770b610 | File Hash (SHA256)  |
| 753952aed395ea845c52e3037f19738cfc9a415070515de277e1a1baeff20647 | File Hash (SHA256)  |
| 8df89eef51cdf43b2a992ade6ad998b267ebb5e61305aeb765e4232e66eaf79a | File Hash (SHA256)  |
| 8e5733484982d0833abbd9c73a05a667ec2d9d005bbf517b1c8cd4b1daf57190 | File Hash  (SHA256) |
| 99be6e7e31f0a1d7eebd1e45ac3b9398384c1f0fa594565137abb14dc28c8a7f | File Hash (SHA256)  |
| bb62138d173de997b36e9b07c20b2ca13ea15e9e6cd75ea0e8162e0d3ded83b7 | File Hash (SHA256)  |
| eb3452c64970f805f1448b78cd3c05d851d758421896edd5dfbe68e08e783d18 | File Hash (SHA256)  |

### Email Addresses
| **IOC Value**                 | **IOC Type** |
|-------------------------------|--------------|
| costacancordia@protonmail.com | Email        |

### C2C Communication User Agents
| **IOC Value**                                                                                                                                            | **IOC Type** |
|----------------------------------------------------------------------------------------------------------------------------------------------------------|--------------|
| Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.51 Safari/537.36 Edg/99.0.1150.36 Trailer/95.3.1132.33 | User Agent   |

### Command Syntax
| **IOC Value**                                                                                                                                          | **IOC Type**    |
|--------------------------------------------------------------------------------------------------------------------------------------------------------|-----------------|
| `powershell ntdsutil.exe 'ac i ntds' 'ifm' 'create full c:\users\public' q q`                                                                          | Windows Command |
| `C:\Windows\system32\net user z Lh199211\* /add`                                                                                                       | Windows Command |
| `C:\Windows\system32\net localgroup administrators z /add  `                                                                                           | Windows Command |
| `reg save hklm\system system `                                                                                                                         | Windows Command |
| `reg save hklm\sam sam    `                                                                                                                            | Windows Command |
| `reg save HKLM\security sec `                                                                                                                          | Windows Command |
| `tasklist`                                                                                                                                             | Windows Command |
| `rundll32.exe C:\windows\System32\comsvcs.dll, MiniDump [LSASS\_PID] C:\windows\temp\lsass.dmp full`                                                   | Windows Command |
| `wevtutil.exe el`                                                                                                                                      | Windows Command |
| `wevtutil.exe cl [LOGNAME]`                                                                                                                            | Windows Command |
| `net user z /delete `                                                                                                                                  | Windows Command |
| `netsh advfirewall firewall set rule group=remote desktop new enable=Yes   `                                                                           | Windows Command |
| `C:\Windows\System32\msiexec.exe /i C:\Users\[USERNAME]\Pictures\LogMeIn.msi `                                                                         | Windows Command |
| `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\narrator.exe /v Debugger /t REG\_SZ /d C:\windows\system32\cmd.exe /f` | Windows Command |
| `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe /v Debugger /t REG\_SZ /d C:\windows\system32\cmd.exe /f `   | Windows Command |

## Detections
### YARA Rules
```

rule win_yanluowang_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-08-05"
        version = "1"
        description = "Detects win.yanluowang."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.yanluowang"
        malpedia_rule_date = "20220805"
        malpedia_hash = "6ec06c64bcfdbeda64eff021c766b4ce34542b71"
        malpedia_version = "20220808"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    /* DISCLAIMER
     * The strings used in this rule have been automatically selected from the
     * disassembly of memory dumps and unpacked files, using YARA-Signator.
     * The code and documentation is published here:
     * https://github.com/fxb-cocacoding/yara-signator
     * As Malpedia is used as data source, please note that for a given
     * number of families, only single samples are documented.
     * This likely impacts the degree of generalization these rules will offer.
     * Take the described generation method also into consideration when you
     * apply the rules in your use cases and assign them confidence levels.
     */


    strings:
        $sequence_0 = { 8b11 2bc5 50 ff5214 2bee 896f28 5f }
            // n = 7, score = 100
            //   8b11                 | mov                 edx, dword ptr [ecx]
            //   2bc5                 | sub                 eax, ebp
            //   50                   | push                eax
            //   ff5214               | call                dword ptr [edx + 0x14]
            //   2bee                 | sub                 ebp, esi
            //   896f28               | mov                 dword ptr [edi + 0x28], ebp
            //   5f                   | pop                 edi

        $sequence_1 = { 42 0fb606 80b860cb450000 74e9 8a0e 0fb6c1 }
            // n = 6, score = 100
            //   42                   | inc                 edx
            //   0fb606               | movzx               eax, byte ptr [esi]
            //   80b860cb450000       | cmp                 byte ptr [eax + 0x45cb60], 0
            //   74e9                 | je                  0xffffffeb
            //   8a0e                 | mov                 cl, byte ptr [esi]
            //   0fb6c1               | movzx               eax, cl

        $sequence_2 = { 56 8bcf c705????????dc734400 e8???????? 68???????? e8???????? 59 }
            // n = 7, score = 100
            //   56                   | push                esi
            //   8bcf                 | mov                 ecx, edi
            //   c705????????dc734400     |
            //   e8????????           |
            //   68????????           |
            //   e8????????           |
            //   59                   | pop                 ecx

        $sequence_3 = { e8???????? 56 8d45f0 56 50 e8???????? 83c40c }
            // n = 7, score = 100
            //   e8????????           |
            //   56                   | push                esi
            //   8d45f0               | lea                 eax, [ebp - 0x10]
            //   56                   | push                esi
            //   50                   | push                eax
            //   e8????????           |
            //   83c40c               | add                 esp, 0xc

        $sequence_4 = { 33c2 d1c6 33c6 8bfe 337154 c1e707 33fd }
            // n = 7, score = 100
            //   33c2                 | xor                 eax, edx
            //   d1c6                 | rol                 esi, 1
            //   33c6                 | xor                 eax, esi
            //   8bfe                 | mov                 edi, esi
            //   337154               | xor                 esi, dword ptr [ecx + 0x54]
            //   c1e707               | shl                 edi, 7
            //   33fd                 | xor                 edi, ebp

        $sequence_5 = { 66390e 0f848a000000 83c602 83e801 75ef 8b5508 8b7d20 }
            // n = 7, score = 100
            //   66390e               | cmp                 word ptr [esi], cx
            //   0f848a000000         | je                  0x90
            //   83c602               | add                 esi, 2
            //   83e801               | sub                 eax, 1
            //   75ef                 | jne                 0xfffffff1
            //   8b5508               | mov                 edx, dword ptr [ebp + 8]
            //   8b7d20               | mov                 edi, dword ptr [ebp + 0x20]

        $sequence_6 = { 3bd0 0f8336010000 8b45d4 8bd0 2bd1 8955d8 }
            // n = 6, score = 100
            //   3bd0                 | cmp                 edx, eax
            //   0f8336010000         | jae                 0x13c
            //   8b45d4               | mov                 eax, dword ptr [ebp - 0x2c]
            //   8bd0                 | mov                 edx, eax
            //   2bd1                 | sub                 edx, ecx
            //   8955d8               | mov                 dword ptr [ebp - 0x28], edx

        $sequence_7 = { 7445 a90f000000 7518 660fef10 660fef4010 660fef7020 660fef5830 }
            // n = 7, score = 100
            //   7445                 | je                  0x47
            //   a90f000000           | test                eax, 0xf
            //   7518                 | jne                 0x1a
            //   660fef10             | pxor                xmm2, xmmword ptr [eax]
            //   660fef4010           | pxor                xmm0, xmmword ptr [eax + 0x10]
            //   660fef7020           | pxor                xmm6, xmmword ptr [eax + 0x20]
            //   660fef5830           | pxor                xmm3, xmmword ptr [eax + 0x30]

        $sequence_8 = { 33c0 c6855fecffff00 85c0 7407 c6855fecffff01 80bd57ecffff00 7435 }
            // n = 7, score = 100
            //   33c0                 | xor                 eax, eax
            //   c6855fecffff00       | mov                 byte ptr [ebp - 0x13a1], 0
            //   85c0                 | test                eax, eax
            //   7407                 | je                  9
            //   c6855fecffff01       | mov                 byte ptr [ebp - 0x13a1], 1
            //   80bd57ecffff00       | cmp                 byte ptr [ebp - 0x13a9], 0
            //   7435                 | je                  0x37

        $sequence_9 = { 8b4f50 8bf1 8b55ac 8b4754 8b7f58 8b525c 0bca }
            // n = 7, score = 100
            //   8b4f50               | mov                 ecx, dword ptr [edi + 0x50]
            //   8bf1                 | mov                 esi, ecx
            //   8b55ac               | mov                 edx, dword ptr [ebp - 0x54]
            //   8b4754               | mov                 eax, dword ptr [edi + 0x54]
            //   8b7f58               | mov                 edi, dword ptr [edi + 0x58]
            //   8b525c               | mov                 edx, dword ptr [edx + 0x5c]
            //   0bca                 | or                  ecx, edx

    condition:
        7 of them and filesize < 834560
}
```
## Tools-Used-By-Group

- BazarLoader
- ConnectWise
- Adfind
- SoftPerfect Network Scanner
- GrabFF
- GrabChrome
- BrowserPassView
- KeeThief
- secretsdump.exe
- Bloodhound
- Mimikatz
- PCHunter
- Rclone
- Routerscan
- S3Browser
- Warprism
- Foxgrabber

## Potential-Relations
- Fivehands
- Thieflock


## MITRE-ATT&CK-Techniques

| **Domain** | **ID**                                             | **Name**                                                                             | **Use**                                                                                                                                                                                                                                                                                                                                                                                                                         |
|------------|----------------------------------------------------|--------------------------------------------------------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Enterprise | [T1059](https://attack.mitre.org/techniques/T1059) | [Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059)       | [FIVEHANDS](https://attack.mitre.org/software/S0618) can receive a command line argument to limit file encryption to specified directories.[[1]](https://www.fireeye.com/blog/threat-research/2021/04/unc2447-sombrat-and-fivehands-ransomware-sophisticated-financial-threat.html) [[2]](https://research.nccgroup.com/2021/06/15/handy-guide-to-a-new-fivehands-ransomware-variant/)                                          |
| Enterprise | [T1486](https://attack.mitre.org/techniques/T1486) | [Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486)               | [FIVEHANDS](https://attack.mitre.org/software/S0618) can use an embedded NTRU public key to encrypt data for ransom.[[1]](https://www.fireeye.com/blog/threat-research/2021/04/unc2447-sombrat-and-fivehands-ransomware-sophisticated-financial-threat.html) [[3]](https://us-cert.cisa.gov/ncas/analysis-reports/ar21-126a) [[2]](https://research.nccgroup.com/2021/06/15/handy-guide-to-a-new-fivehands-ransomware-variant/) |
| Enterprise | [T1140](https://attack.mitre.org/techniques/T1140) | [Deobfuscate/Decode Files or Information](https://attack.mitre.org/techniques/T1140) | [FIVEHANDS](https://attack.mitre.org/software/S0618) has the ability to decrypt its payload prior to execution.[[1]](https://www.fireeye.com/blog/threat-research/2021/04/unc2447-sombrat-and-fivehands-ransomware-sophisticated-financial-threat.html) [[3]](https://us-cert.cisa.gov/ncas/analysis-reports/ar21-126a) [[2]](https://research.nccgroup.com/2021/06/15/handy-guide-to-a-new-fivehands-ransomware-variant/)      |
| Enterprise | [T1083](https://attack.mitre.org/techniques/T1083) | [File and Directory Discovery](https://attack.mitre.org/techniques/T1083)            | [FIVEHANDS](https://attack.mitre.org/software/S0618) has the ability to enumerate files on a compromised host in order to encrypt files with specific extensions.[[3]](https://us-cert.cisa.gov/ncas/analysis-reports/ar21-126a) [[2]](https://research.nccgroup.com/2021/06/15/handy-guide-to-a-new-fivehands-ransomware-variant/)                                                                                             |
| Enterprise | [T1490](https://attack.mitre.org/techniques/T1490) | [Inhibit System Recovery](https://attack.mitre.org/techniques/T1490)                 | [FIVEHANDS](https://attack.mitre.org/software/S0618) has the ability to delete volume shadow copies on compromised hosts.[[1]](https://www.fireeye.com/blog/threat-research/2021/04/unc2447-sombrat-and-fivehands-ransomware-sophisticated-financial-threat.html) [[3]](https://us-cert.cisa.gov/ncas/analysis-reports/ar21-126a)                                                                                               |
| Enterprise | [T1135](https://attack.mitre.org/techniques/T1135) | [Network Share Discovery](https://attack.mitre.org/techniques/T1135)                 | [FIVEHANDS](https://attack.mitre.org/software/S0618) can enumerate network shares and mounted drives on a network.[[2]](https://research.nccgroup.com/2021/06/15/handy-guide-to-a-new-fivehands-ransomware-variant/)                                                                                                                                                                                                            |
| Enterprise | [T1027](https://attack.mitre.org/techniques/T1027) | [Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027)         | The [FIVEHANDS](https://attack.mitre.org/software/S0618) payload is encrypted with AES-128.[[1]](https://www.fireeye.com/blog/threat-research/2021/04/unc2447-sombrat-and-fivehands-ransomware-sophisticated-financial-threat.html) [[3]](https://us-cert.cisa.gov/ncas/analysis-reports/ar21-126a) [[2]](https://research.nccgroup.com/2021/06/15/handy-guide-to-a-new-fivehands-ransomware-variant/)                          |
| Enterprise | [T1047](https://attack.mitre.org/techniques/T1047) | [Windows Management Instrumentation](https://attack.mitre.org/techniques/T1047)      | [FIVEHANDS](https://attack.mitre.org/software/S0618) can use WMI to delete files on a target machine.[[1]](https://www.fireeye.com/blog/threat-research/2021/04/unc2447-sombrat-and-fivehands-ransomware-sophisticated-financial-threat.html) [[3]](https://us-cert.cisa.gov/ncas/analysis-reports/ar21-126a)                                                                                                                   |
| Enterprise | [T1566](https://attack.mitre.org/techniques/T1566) | [Phishing](https://attack.mitre.org/techniques/T1566)                                | Initial access vector for attacks has been a phishing campaign to internal employees                                                                                                                                                                                                                                                                                                                                            |


## Credits-and-Further-Reading
The intelligence community is a vibrant community that strives to help one another, especially during times of crisis. On that note, below we have compiled various materials we found to be extremely helpful and comprehensive.

- https://blog.talosintelligence.com/2022/08/recent-cyber-attack.html
- https://malpedia.caad.fkie.fraunhofer.de/details/win.yanluowang
- https://socprime.com/blog/cisco-hacked-by-yanluowang-detect-relevant-malicious-activity-with-sigma-rules-kit/
- https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/yanluowang-ransomware-attacks-continue
- https://otx.alienvault.com/pulse/62f4f80e142934c1cc838793/
- https://blog.talosintelligence.com/2022/08/recent-cyber-attack.html
- https://www.pcrisk.com/removal-guides/24226-yanluowang-ransomware
- https://attack.mitre.org/software/S0618/
- https://www.mandiant.com/resources/unc2447-sombrat-and-fivehands-ransomware-sophisticated-financial-threat
- https://github.com/fxb-cocacoding/yara-signator
- https://www.bleepingcomputer.com/news/security/free-decryptor-released-for-yanluowang-ransomware-victims/
- https://cyware.com/news/thieflock-and-yanluowang-ransomware-share-same-genes-8de3bf41

## Contribution
We are always on the lookout for latest indicators, detection mechanisms and relations. If you note something we have missed or which you would like to add, please raise an issue or create a pull request!

