# Red Stealer Lab

## Scenario 

You are part of the Threat Intelligence team in the SOC (Security Operations Center). An executable file has been discovered on a colleague’s computer, and it’s suspected to be linked to a Command and Control (C2) server, indicating a potential malware infection.
Your task is to investigate this executable by analyzing its hash. The goal is to gather and analyze data beneficial to other SOC members, including the Incident Response team, to respond to this suspicious behavior efficiently.

## Le'ts move on to the questions: 

> 1. Categorizing malware enables a quicker and clearer understanding of its unique behaviors and attack vectors. What category has Microsoft identified for that malware in VirusTotal?

1. Categorizing malware enables a quicker and clearer understanding of its unique behaviors and attack vectors. What category has Microsoft identified for that malware in VirusTotal?

![photo1](https://miro.medium.com/v2/resize:fit:720/format:webp/1*9nTaVr4jamFhhOEfabfcjg.png)

**trojan**

> 2. Clearly identifying the name of the malware file improves communication among the SOC team. What is the file name associated with this malware?

So, we can find the name of this malware in the details section:

![photo2](https://miro.medium.com/v2/resize:fit:640/format:webp/1*a7EfODHadbt7AoZnWFF5PA.png)

**Wextract**

> 3. Knowing the exact timestamp of when the malware was first observed can help prioritize response actions. Newly detected malware may require urgent containment and eradication compared to older, well-documented threats. What is the UTC timestamp of the malware’s first submission to VirusTotal?

![photo3](https://miro.medium.com/v2/resize:fit:640/format:webp/1*UiTSqmtQTHOUVTz3mBUr_Q.png)

**2023–10–06 04:41**

> 4. Understanding the techniques used by malware helps in strategic security planning. What is the MITRE ATT&CK technique ID for the malware’s data collection from the system before exfiltration?

We can find the MITRE ATT&CK technique ID in the behavior section:

![photo4](https://miro.medium.com/v2/resize:fit:720/format:webp/1*h-Vj36mWjmpN1HwgJfmUzA.png)

**T1005**

> 5. Following execution, which social media-related domain names did the malware resolve via DNS queries?

![photo5](https://miro.medium.com/v2/resize:fit:640/format:webp/1*O_2ZjYl4qhvR-_blW9ODCQ.png)

**facebook.com**

> 6. Once the malicious IP addresses are identified, network security devices such as firewalls can be configured to block traffic to and from these addresses. Can you provide the IP address and destination port the malware communicates with?

![photo6](https://miro.medium.com/v2/resize:fit:640/format:webp/1*7vNthPrgEiUkzTwUKqlPaA.png)

**77.91.124.55:19071**

> 7. YARA rules are designed to identify specific malware patterns and behaviors. Using MalwareBazaar, what’s the name of the YARA rule created by “Varp0s" that detects the identified malware?

In order to answer this question, we’re going to have to take our hash to a different platform. Let’s check MalwareBazar. Once you’re in the Malware Bazaar database, find the relevant entry by searching for the following:

```bash
sha256:248fcc901aff4e4b4c48c91e4d78a939bf681c9a1bc24addc3551b32768f907b
```

![photo7](https://miro.medium.com/v2/resize:fit:720/format:webp/1*pnkq6EACU6KdPNemk418kA.png)

**detect_Redline_Stealer**

> 8. Understanding which malware families are targeting the organization helps in strategic security planning for the future and prioritizing resources based on the threat. Can you provide the different malware alias associated with the malicious IP address according to ThreatFox?

For this question, I needed to determine the alias for the malware. I utilized ThreatFox, searching “ioc:ip_address” and then find the section labeled Malware Alias to find the answer.

![photo8](https://miro.medium.com/v2/resize:fit:720/format:webp/1*m5F1TchrxjZBVMOyR4Oq0g.png)

**RECORDSTEALER**

> 9. By identifying the malware's imported DLLs, we can configure security tools to monitor for the loading or unusual usage of these specific DLLs. Can you provide the DLL utilized by the malware for privilege escalation?

I was tasked with identifying the DLL that the malware uses for privilege escalation. I returned to VirusTotal, examined the Runtime Modules section under the Behavior tab, and identified several DLLs. I then researched each one to determine which was commonly used for privilege escalation, ultimately finding the correct answer.

![photo9](https://cdn-images-1.medium.com/max/800/1*HA03ZSGdHoWCn0bQY26B0A.png)

**ADVAPI32.dll**