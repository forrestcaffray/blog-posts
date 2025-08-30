---
title: "Boogeyman 2 - TryHackme Write-up"
seoTitle: "Boogeyman 2 - TryHackme Write-up"
seoDescription: "Explore the TryHackMe "Boogeyman 2" room with a detailed cyber threat analysis write-up, revealing tactics, techniques, and procedures"
datePublished: Fri Aug 22 2025 09:50:24 GMT+0000 (Coordinated Universal Time)
cuid: cmemnglve000p02lha3zncjtz
slug: boogeyman-2-tryhackme-write-up
canonical: https://medium.com/@forrestcaffray/boogeyman-2-tryhackme-write-up-f26b372b7156
cover: https://cdn.hashnode.com/res/hashnode/image/upload/v1755703626475/7acb1a83-39fa-4fc1-894c-c4eac228e932.png
tags: cybersecurity, cybersecurity-1, tryhackme, writeup, cybersec, write-up, tryhackme-walkthrough, tryhackmewalkthrough

---

Link to room: [https://tryhackme.com/room/boogeyman2](https://tryhackme.com/room/boogeyman2)

*After having a severe attack from the Boogeyman, Quick Logistics LLC improved its security defences. However, the Boogeyman returns with new and improved tactics, techniques and procedures.*

In this room, you will be tasked to analyse the new tactics, techniques, and procedures (TTPs) of the threat group named Boogeyman.

---

> ### What email was used to send the phishing email?

![Email application for a Junior IT Analyst role, addressed to Maxine, expressing interest and outlining relevant skills and education in computer science. It mentions attached resume and thanks the recipient for considering the application. A Word document is attached.](https://cdn.hashnode.com/res/hashnode/image/upload/v1755770679367/bc1642b5-cb2e-4c0f-b3bf-ca0af696e62c.png align="center")

I opened the **.eml** file in Evolution seeing as it was already on the machine.

We can easily see the **From** header above.

**Answer: westaylor23@outlook.com**

---

> ### What is the email of the victim employee?

Again we can easily see the **To** header.

**Answer:** [**maxine.beck@quicklogisticsorg.onmicrosoft.com**](mailto:maxine.beck@quicklogisticsorg.onmicrosoft.com)

---

> ### What is the name of the attached malicious document?

![An email interface showing an attached Microsoft Word document titled "Resume_WesleyTaylor.doc." The context menu offers the options "Save As," "Open With LibreOffice Writer," and others.](https://cdn.hashnode.com/res/hashnode/image/upload/v1755771404298/19d54322-b8ea-496e-a18f-283adaede4bf.png align="center")

We can easily download and save the file into our **Artefacts** folder.

**Answer: Resume\_WesleyTaylor.doc**

---

> ### What is the MD5 hash of the malicious attachment?

Let’s find the **MD5** hash! We can open terminal in our **Artefacts** location and simply:

![A terminal window on Ubuntu shows the command `md5sum Resume_WesleyTaylor.doc` executed, with the output displaying the hash value `52c4384a0b9e248b95804352ebec6c5b Resume_WesleyTaylor.doc`.](https://cdn.hashnode.com/res/hashnode/image/upload/v1755771554553/ec954ef4-f134-4633-919d-4312efeabe4e.png align="center")

**Answer: 52c4384a0b9e248b95804352ebec6c5b**

---

> ### What URL is used to download the stage 2 payload based on the document's macro?

Looking at the instructions we can see that all we have to do to look deeper into this file is run:

```bash
olevba Resume_WesleyTaylor.doc
```

![Screenshot of a terminal displaying the output of running "olevba" on a document named "Resume_WesleyTaylor.doc." The output includes details about VBA macros found in the document, highlighting macros in "ThisDocument.cls" and "NewMacros.bas" with related code. The code includes creating objects, downloading a file from a URL, and executing a script.](https://cdn.hashnode.com/res/hashnode/image/upload/v1755771863835/b7bfee04-7b00-4b00-9de3-4de170aabc74.png align="center")

Hmm, what about that **xHttp.Open** huh?

**Answer:** [**https://files.boogeymanisback.lol/aa2a9c53cbb80416d3b47d85538d9971/update.png**](https://files.boogeymanisback.lol/aa2a9c53cbb80416d3b47d85538d9971/update.png)

---

> ### What is the name of the process that executed the newly downloaded stage 2 payload?

Looking at the screenshot above we see:

```bash
shell_object.Exec ("wscript.exe C:\ProgramData\update.js")
```

**Answer: wscript.exe**

---

> ### What is the full file path of the malicious stage 2 payload?

Again, all the information is shown from the output of **olevba** (looking near the bottom).

**Answer: C:\\ProgramData\\update.js**

---

> ### What is the PID of the process that executed the stage 2 payload?

Time to try our hands at a new tool - **vol**.

Short for **The Volatility Framework.** A memory analysis tool that we are about to have a look at.

A good starting point is to open terminal and do a:

```bash
vol -f WKSTN-2961.raw -h
```

This will pull up all the plugins available as it explains in the instructions.

<div data-node-type="callout">
<div data-node-type="callout-emoji">💡</div>
<div data-node-type="callout-text">You can then copy and paste this into <strong>Pluma</strong> to always reference to.</div>
</div>

Seeing as we are looking for the PID (Process identifier) lets use **windows.pslist**.

```bash
vol -f WKSTN-2961.raw windows.pslist
```

Some of the results:

![A terminal window displaying a list of processes, with columns for process ID, name, and other attributes. Active processes such as "wscript.exe" are shown. The terminal is running in a Linux environment, indicated by the prompt "ubuntu@tryhackme:~/Desktop/Artefacts$".](https://cdn.hashnode.com/res/hashnode/image/upload/v1755788367799/715b7f72-4dfd-46b9-8872-da2708860481.png align="center")

Looking at **wscript.exe** we can see it has a **PID** of **4260** and a **PPID** (Parent Process Identifier) of **1124**.

**Answer: 4260**

---

> ### What is the parent PID of the process that executed the stage 2 payload?

We already know this from before.

**Answer: 1124**

You can also try using **windows.pstree** to visualize it differently - easier to see parent / child relationships.

![A terminal window in Ubuntu shows a list of processes with details such as names, memory addresses, and timestamps. The command prompt is located at the bottom, indicating the user directory as `~/Desktop/Artefacts`.](https://cdn.hashnode.com/res/hashnode/image/upload/v1755788758409/ea2ec238-c715-4511-8d35-a41655e67020.png align="center")

---

> ### What URL is used to download the malicious binary executed by the stage 2 payload?

This is a bit of repeat of a previous question, specifically *“What URL is used to download the stage 2 payload based on the document's macro?”*

**Answer: https://files.boogeymanisback.lol/aa2a9c53cbb80416d3b47d85538d9971/update.exe**

---

> ### What is the PID of the malicious process used to establish the C2 connection?

If we refer to the previous image, we can see that **wscript.exe** spawns a new process: **updater.exe.**

Lets take a note of its PID - this is the correct process.

**Answer: 6216**

---

> ### What is the full file path of the malicious process used to establish the C2 connection?

Seeing as we are looking at file paths, let’s look closer at **files**, instead of **processes**.

**windows.filescan** looks pretty good to me.

```bash
vol -f WKSTN-2961.raw windows.filescan
```

This might have been a mistaken, there will be a lot of results.

<div data-node-type="callout">
<div data-node-type="callout-emoji">💡</div>
<div data-node-type="callout-text">Ctrl + C to cancel out.</div>
</div>

Lets grep for **updater.exe**.

```bash
vol -f WKSTN-2961.raw windows.filescan | grep updater.exe
```

![A terminal window showing a command that searches for "updater.exe" using Volatility. The search results highlight two occurrences of "updater.exe" found in the Windows Tasks directory, each with an offset and size of 216.](https://cdn.hashnode.com/res/hashnode/image/upload/v1755791677738/8451ec41-0472-45c3-a4db-275a79dfc32c.png align="center")

Much easier to see what we are looking for!

**Answer: C:\\Windows\\Tasks\\updater.exe**

---

> ### What is the IP address and port of the C2 connection initiated by the malicious binary? (Format: IP address:port)

We are now looking at **connections**. No more **file** or **processes** analysis here!

Using **windows.netscan** seems like a good idea to me.

```bash
vol -f WKSTN-2961.raw windows.netscan
```

Scroll to the bottom to see:

![A terminal window displaying network connection information, including local and remote IP addresses, ports, connection status, PIDs, and process names such as "updater.exe," "svchost.exe," and "OUTLOOK.EXE".](https://cdn.hashnode.com/res/hashnode/image/upload/v1755792677468/009eb09c-51fc-4b72-b4ae-e9c4c69c7849.png align="center")

We can see **ForeignAddr** and **ForeignPort** for updater.exe, combine and that’s it!

**Answer: 128.199.95.189:8080**

---

> ### What is the full file path of the malicious email attachment based on the memory dump?

I tried to play around with a few plugins to try and find the path of the **Resume\_WesleyTaylor.doc**.

I couldn’t quite find it so decided to have a look at the **cmdline.**

We can better look at what the different processes are spawning.

Sure enough with a:

```bash
vol -f WKSTN-2961.raw windows.cmdline
```

We get what we are after:

![Screenshot of a command prompt window displaying a list of processes with their corresponding executable names, memory requirements, and file paths. Some entries show error messages about invalid or inaccessible memory. Paths include applications like Outlook and Word, with references to specific user directories.](https://cdn.hashnode.com/res/hashnode/image/upload/v1755793403453/605abfcf-d0b0-4f75-be54-6adc3e3f64e2.png align="center")

We can see the **WINWORD.EXE** process and the **Resume\_WesleyTaylor.doc** along with the full path.

For a cleaner result you can:

```bash
vol -f WKSTN-2961.raw windows.cmdline | grep Resume_WesleyTaylor.doc
```

**Answer: C:\\Users\\maxine.beck\\AppData\\Local\\Microsoft\\Windows\\INetCache\\Content.Outlook\\WQHGZCFI\\Resume\_WesleyTaylor (002).doc**

---

> ### The attacker implanted a scheduled task right after establishing the c2 callback. What is the full command used by the attacker to maintain persistent access?

THM Hint: “*You may use some known keywords that indicate a scheduled task execution to extract the information.”*

The Vol plugin options weren’t really giving me the information I needed.

The data is in the **.raw** file, but let’s look at other ways we can analyse the file.

The strings command could prove useful.

```bash
man strings
```

*“strings - print the sequences of printable characters in files”*

Let’s run that!

```bash
strings WKSTN-2961.raw | grep -i schtasks
```

I forgot to mention that the hint lead us to thinking about **schtasks.exe** the process behind creating scheduled tasks in Windows.

We can use **grep -i** to check for instances of **Schtasks** and **schtasks**.

We will come across this juicy little part:

![A computer terminal displaying various instances of the command "schtasks" in red text, used for scheduling tasks on Windows. Some commands appear to involve daily schedule triggers and persistence mechanisms. The background is a dark gray typical of terminal windows.](https://cdn.hashnode.com/res/hashnode/image/upload/v1755794786974/2f2e64d3-1308-4df9-98c3-06cbb22a0558.png align="center")

We can see an encoded string and a command.

That right there, is the command we need.

<div data-node-type="callout">
<div data-node-type="callout-emoji">💡</div>
<div data-node-type="callout-text">Paste it into AI and see what exactly it does!</div>
</div>

**Answer: schtasks /Create /F /SC DAILY /ST 09:00 /TN Updater /TR 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -NonI -W hidden -c "IEX (\[Text.Encoding\]::UNICODE.GetString(\[Convert\]::FromBase64String((gp HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion debug).debug)))"'**

---

Great little exercise to start out with **Vol**. Running through various plugins to see what they do. We are also building on our forensic analysis brain.

Hope this was useful!

Boogeyman 3 next.