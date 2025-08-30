---
title: "Secret Recipe - TryHackMe Write-up"
seoTitle: "Secret Recipe - TryHackMe Write-up"
seoDescription: "Explore the TryHackMe room "Secret Recipe" as you investigate forensic artifacts on registry files to uncover a secret theft"
datePublished: Thu Aug 14 2025 10:52:59 GMT+0000 (Coordinated Universal Time)
cuid: cmeba69zh000d02lb4g0th25m
slug: secret-recipe-tryhackme-write-up
canonical: https://medium.com/@forrestcaffray/secret-recipe-tryhackme-write-up-1a42d225b728
cover: https://cdn.hashnode.com/res/hashnode/image/upload/v1755091972528/97399b84-8ce7-457d-86dc-62026e657596.png
tags: cybersecurity, cyber, tryhackme, write-up, registry-forensics

---

Link to room: [https://tryhackme.com/room/registry4n6](https://tryhackme.com/room/registry4n6)

> Jasmine owns a famous New York coffee shop **Coffely** which is famous city-wide for its unique taste. Only Jasmine keeps the original copy of the recipe, and she only keeps it on her work laptop. Last week, James from the IT department was consulted to fix Jasmine's laptop. But it is suspected he may have copied the secret recipes from Jasmine's machine and is keeping them on his machine.

> His machine has been confiscated and examined, but no traces could be found. The security department has pulled some important **registry artifacts** from his device and has tasked you to examine these artifacts and determine the presence of secret files on his machine.

---

> Connect with the lab.

---

> How many files are available in the Artefacts folder on the Desktop?

We can see in the folder on the Desktop that there are 6 files.

## \= 6

---

> What is the computer name of the machine found in the registry?

Downloading the Task Files will be pretty handy, open the PDF!

The first one we want to look at here is at the bottom of the image “Computer Name”. For this task we simply open up “Registry Explorer”, conveniently placed at the task bar at the bottom.

**Pro Tip:** Looking at the bottom shows the tools we are most likely to need (thanks THM), we do have access to all tools in the desktop folder also

![A Windows taskbar displays several icons, including Internet Explorer, and a preview popup of "Registry Explorer v1.6.0.0" showing the program's interface with a registry tree.](https://cdn.hashnode.com/res/hashnode/image/upload/v1755093778381/642d3db7-42ff-437b-8e0d-a95b44aa5735.png align="center")

Using Registry Explorer we want to open up the appropriate hive, so let’s open the “SYSTEM” file in the “Artefacts” folder from the Desktop.

Simply navigate to:

`SYSTEM\CurrentControlSet\Control\ComputerName \ComputerName`

![A table with columns: Value Name, Value Type, Data, Value Slack, Is Deleted, and Data Record Realloc. Rows contain information such as default settings, value types as "RegSz," data entries "mmsrvc" and "JAMES," with corresponding Value Slack codes. The Is Deleted column is unchecked for all rows.](https://cdn.hashnode.com/res/hashnode/image/upload/v1755094101309/eb3f2bb5-74ab-4934-9390-7c7a0024b134.png align="center")

## \= James

---

> When was the **Administrator** account created on this machine? (Format: yyyy-mm-dd hh:mm:ss)

Let’s load up the SAM (Security Accounts Manager) file in Registry Explorer.

Referring back to our handy wee PDF we find a section for looking up user information.

Let’s navigate to:

`SAM\Domains\Account\Users`

Clicking on the folder in Registry Explorer will bring up information on the right hand side.

![Screenshot of Registry Explorer version 1.6.0.0 showing data from the SYSTEM and SAM registry hives. The left panel lists key names, values, and subkeys. The right panel displays user account details including User ID, creation date, and last login for Administrator and Guest accounts.](https://cdn.hashnode.com/res/hashnode/image/upload/v1755094730727/0f9768ba-b046-4343-b361-7e3e8a6277bd.png align="center")

**Note:** One might need to adjust windows a bit

## \= 2021-03-17 14:58:48

---

> What is the RID associated with the Administrator account?

We can see from the previous screenshot that the “User Id” is 500. `500` is always the built-in Administrator account’s RID.

## \= 500

---

> How many user accounts were observed on this machine?

Play around with the window sizing and you’ll find 7 accounts:

* Administrator
    
* Guest
    
* DefaultAccount
    
* WDAGUtilityAccount
    
* J. Andreson
    
* art-test
    
* bdoor
    

I’ve got my little peepers on that “bdoor” account.

## \= 7

---

> There seems to be a suspicious account created as a backdoor with RID 1013. What is the account name?

Well well well, if we look at the user with RID 1013, we will find our little friend “bdoor”.

## \= bdoor

---

> What is the VPN connection this host connected to?

**Hint:** Look for NetworkList in Software Hive

Well, lets get to it, open the “SOFTWARE” hive in Registry Explorer.

**Pro Tip:** You can have multiple hives open in Registry Explorer which is very nice

Using the search box at the top and searching for “NetworkList”:

![Screenshot of Registry Explorer showing software registry keys and network information. The left panel displays a directory structure with registry paths under Windows NT, highlighting "NetworkList." The right panel lists known network details, including network names, types, and connection timestamps.](https://cdn.hashnode.com/res/hashnode/image/upload/v1755096900536/c2815fa6-6d25-4b00-b25d-79920fcda1ca.png align="center")

Clicking on “NetworkList” under “Microsoft” we can see on the right a popular VPN provider.

## \= ProtonVPN

---

> When was the first VPN connection observed? (Format: YYYY-MM-DD HH:MM:SS)

Looking at our previous screenshot we can see the “First Connect LOCAL”.

## \= 2022-10-12 19:52:36

---

> There were three shared folders observed on his machine. What is the path of the third share?

I used the search box and looked for “Shares”.

![Screenshot of Registry Explorer version 1.6.0.0 showing a list of registry hives and keys on the left pane, with specific focus on "Shares" under multiple categories. The right pane displays corresponding values such as "Users" and "Recipes" with data details. The search term "Shares" is highlighted throughout the registry paths.](https://cdn.hashnode.com/res/hashnode/image/upload/v1755097991734/ee82595e-bf0b-43b1-b34d-e920c930167f.png align="center")

Under the “SYSTEM” hive we find the “Shares” folder. In there you can see what we need.

## \= RESTRICTED FILES

---

> What is the last DHCP IP assigned to this host?

**Hint:** (HINT: Starts with 172.**.*.***)

**Pro Tip:** You can right click on a selection and select “Collapse subkeys” to collapse everything, handy if you have been looking around previously.

Referring to our PDF helper, we find this section:

`Network Interfaces and Past Networks: SYSTEM\CurrentControlSet\Services\Tcpip \Parameters\Interfaces`

Navigating there under the “SYSTEM” hive we find what we are looking for:

![Screenshot of Registry Explorer v1.6.0.0 displaying registry hives and keys on the left, with detailed network settings on the right. The network settings include columns for IP address, subnet mask, DHCP information, and more.](https://cdn.hashnode.com/res/hashnode/image/upload/v1755098793032/ea0fb5df-c5f4-4b74-8647-d2c3c367dece.png align="center")

Looking under “DHCPIP Address”. DHCP deals with handing out IP’s to devices on a network so this is exactly what we are typically looking for.

## \= 172.31.2.197

---

> The suspect seems to have accessed a file containing the secret coffee recipe. What is the name of the file?

Looking at our trusty PDF, I first looked at “TypedPaths” and “WordWheelQuery” and I didn’t really find what I was looking for. I think scrolled up a bit and looked at “RecentDocs” which makes a lot of sense.

![Screenshot of the Registry Explorer v1.6.0.0 application. The left pane shows a list of registry keys with folders such as Accent, Advanced, and RecentDocs. The right pane displays details of RecentDocs with columns for extension, value name, target name, and others. Entries like "secret-recipe.pdf" and "RESTRICTED FILES" are visible. Hexadecimal data is shown at the bottom.](https://cdn.hashnode.com/res/hashnode/image/upload/v1755099468187/c117c8d9-0154-48e4-b803-8ad1019a1b6b.png align="center")

We can see a bunch of different files with the .txt and .pdf files catching my eye.

## \= secret-recipe.pdf

---

> The suspect executed multiple commands using the Run window. What command was used to enumerate the network interfaces?

I wasn’t sure exactly where to look for this one but felt I was in the right place. Scrolled around a bit and found the “RunRMU” folder. In there we can see a bunch of commands like “ipconfig”, “wmic”, “msconfig” and the like.

Two of them immediately stood out to me `pnputil /enum-interfaces` and `pnputil /enum-devices`. A bit of enumerating I see (listing and gathering information).

![Screenshot of Registry Explorer v1.6.0.0. The window displays a left pane listing registry keys such as "BitBucket," "RecentDocs," and "RunMRU," with details like number of values, subkeys, and last write timestamp. The right pane shows values under "RunMRU" with columns for "Mru Position," "Executable," and "Opened On." The selected row details are shown at the bottom.](https://cdn.hashnode.com/res/hashnode/image/upload/v1755100244228/ecc741bf-bffb-4c6f-a0f3-c9cfa323dcbc.png align="center")

## \= pnputil /enum-interfaces

---

> The user searched for a network utility tool to transfer files using the file explorer. What is the name of that tool?

Ah-ha! This is where the fancy “WordWheelQuery” comes into play. This will tell us about any searches done in file explorer.

![Screenshot of Registry Explorer v1.6.0.0 interface, displaying various registry keys and details under "WordWheelQuery." The right pane shows search terms and metadata such as MRU position and last write timestamp. The bottom displays a hexadecimal type viewer.](https://cdn.hashnode.com/res/hashnode/image/upload/v1755100627890/5593b20d-10cb-490c-918d-05a5f81434fd.png align="center")

We can see it all there! Netcat is such a useful tool in the cyber space, definitely a lil sus if you ask me.

## \= netcat

---

> What is the recent text file opened by the suspect?

We actually found this a little earlier, remember `secret-recipe.pdf`? There was another file that we saw of note also

![Screenshot of Registry Explorer software displaying a list of registry keys on the left and details of recent documents on the right. The recent documents include entries like "secret-recipe.pdf" and "secret-code.txt". The interface shows various columns such as extension, value name, target name, and link name. The bottom section contains hexadecimal and ASCII data.](https://cdn.hashnode.com/res/hashnode/image/upload/v1755100911781/e791034b-8912-40c0-9ba4-be8368005716.png align="center")

## \=secret-code.txt

---

> How many times was PowerShell executed on this host?

Referring to our PDF we are going to be looking under “Evidence of Execution” then specifically look at “UserAssist”.

Navigate to “UserAssist” and you will find a bunch of folders, I simply clicked through them to see what I could find. I had a wee snoop around and found a log of powershell.exe. Under “Run Counter” you will see the answer.

![Screenshot of software "Registry Explorer v1.6.0.0" displaying registry hives, values, subkeys, and timestamps on the left, and program execution details, including program names, run counters, and focus times on the right. Hexadecimal data is shown at the bottom.](https://cdn.hashnode.com/res/hashnode/image/upload/v1755101309679/aa5dc604-e133-47b7-b75e-f9a2e82a7822.png align="center")

## \= 3

---

> The suspect also executed a network monitoring tool. What is the name of the tool?

Snooping around some more we find

![Screenshot of the Registry Explorer v1.6.0.0 software interface, showing a tree structure on the left with various registry keys under "UserAssist" and details on the right, such as program names, run counters, and timestamps. Byte data is displayed at the bottom.](https://cdn.hashnode.com/res/hashnode/image/upload/v1755101561932/ea2cda89-250d-4505-bfa3-28d50c7a2cc4.png align="center")

Wireshark is a well-known networking monitoring tool.

## \= Wireshark

---

> Registry Hives also note the amount of time a process is in focus. Examine the Hives and confirm for how many seconds was ProtonVPN executed?

In the exact same section I noticed “ProtonVPN.exe” and alongside it you can see various details like the one we are currently looking for:

![Screenshot of Registry Explorer v1.6.0.0 showing registry keys and values on the left, with program names, run counters, focus times, and last execution details on the right. Includes hex data view at the bottom.](https://cdn.hashnode.com/res/hashnode/image/upload/v1755101802170/773bf7ad-d4ac-4b45-9867-8405262e19ae.png align="center")

We can see the “Focus Time” of “05m, 43s” which in seconds is 343 seconds (converted for seconds)

## 343

---

> Everything.exe is a utility used to search for files in a Windows machine. What is the full path from which everything.exe was executed?

Again, simply looking around we will find “everything.exe”

![Screenshot of Registry Explorer version 1.6.0.0 showing registry keys and values on the left, a list of program executions on the right with details like run count and last executed time, and a hexadecimal data viewer at the bottom.](https://cdn.hashnode.com/res/hashnode/image/upload/v1755101967947/656010dd-fa47-464b-ad95-96f71311cbb4.png align="center")

Just copy or type out the full path.

## \= `C:\Users\Administrator\Downloads\tools\Everything\Everything.exe`

---

That wraps it up! There are so many tools worth having a look at here but working with Registry Explorer is a nice tool to get familiar with. We also understood a bit more about Windows registry and how things work in Windows which is not a bad thing at all!