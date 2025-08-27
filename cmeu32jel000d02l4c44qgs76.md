---
title: "Introduction to Phishing - TryHackMe Simulator - My Overview"
seoTitle: "Introduction to Phishing - TryHackMe Simulator - My overview"
seoDescription: "Explore the TryHackMe Introduction to Phishing simulator, learn investigative skills, and get insights into SOC Analyst tasks"
datePublished: Wed Aug 27 2025 14:41:45 GMT+0000 (Coordinated Universal Time)
cuid: cmeu32jel000d02l4c44qgs76
slug: introduction-to-phishing-tryhackme-simulator-my-overview
cover: https://cdn.hashnode.com/res/hashnode/image/upload/v1756306151747/68742258-81c7-45cb-ae84-47c01d719f67.png
tags: soc, tryhackme, simulator

---

---

In this post I am going to talk about my experience with the TryHackMe SOC Simulator, so it’s not going to be a walk through but more of an overview of what it is and how it works.

The one we are going to be looking at today is the “Introduction to Phishing” simulation (free!).

Let’s boot up the simulation! Note that I am using **Splunk** in this task, **Elastic** is also available.

![SOC Simulator interface showing "Step 2 of 7: Read the documentation" with instructions for reviewing documentation and a guide textbox. The right section lists steps for SOC analysts, including alert review and investigation processes. Exit simulation button is available.](https://cdn.hashnode.com/res/hashnode/image/upload/v1756301722612/6a7d8149-e595-4395-8532-c6be4e9b4b74.png align="center")

This is how it looks upon entering the simulator:

![Dashboard interface of a phishing simulation tool displaying alert details. It shows 5 total alerts, with none closed. A pie chart represents alert types, and a list on the right details specific alerts with varying severity levels. Sidebar offers navigation options like Dashboard, Alert Queue, SIEM, and Documentation.](https://cdn.hashnode.com/res/hashnode/image/upload/v1756302519085/f982c626-c8e2-4637-ac27-c8aa372cdb4d.png align="center")

We can see we have an overview of the dashboard. Sections include **Total alerts**, **Closed alerts**, **Closed as TP**, **Closed as FP** and section sorting out **Alert types** and **Open alerts**.

A useful overview of what is going on.

The **Alert queue** section:

![Dashboard of an alert queue interface showing a list of alerts with details such as ID, alert rule, severity, type, date, status, and action. A sidebar menu includes options like Dashboard, SIEM, and more. The page indicates no alerts are assigned.](https://cdn.hashnode.com/res/hashnode/image/upload/v1756302578544/c2a65bd5-eb0d-438a-bc68-62005e37ee42.png align="center")

We can see various details **ID** and **Severity**, along with others here in a nice concise list. Along with **Action** where you click to begin investigating that alert.

Below is a look at **Splunk** after clicking the **SIEM** (Security Information and Event Management) link.

![Screenshot of a Splunk Enterprise dashboard showing search results. The interface includes options for search, analytics, and datasets. The results display details of an email event and a blocked access event, with fields such as timestamp, sender, recipient, and subject. A server error is indicated in red.](https://cdn.hashnode.com/res/hashnode/image/upload/v1756301985409/2115de6b-9db1-4169-98dc-5ef565b95ae8.png align="center")

I first learned about **Elastic**, but the more and more I use **Splunk**, the more I like it. It’s very robust and filtering can be super streamlined. You can see by default it uses a wildcard to have everything included.

Clicking on the **Analyst VM** will bring you to a Windows VM:

![Screenshot of a dark-themed interface for "TryDetectThis," a secure file and URL analysis tool. The display shows the "URL/IP Security Check" with text fields for entering a URL or IP address to analyze. The left sidebar includes navigation options like Dashboard, Alert Queue, SIEM, Analyst VM, and more, with a "Reconnect VM" button highlighted in green.](https://cdn.hashnode.com/res/hashnode/image/upload/v1756302087759/138b130d-a066-4805-b8c3-a0cd27e30cdf.png align="center")

There was a folder on the desktop with some attachments in it that I didn’t end up using - might be for another exercise, not sure. The screenshot shows what a shortcut on the desktop brings us to. Some kind of scanning tool/site that we can put files, URL’s and IP’s into.

Below we see Documentation, there’s a fair bit of it, but very useful. With **Company Information** being a particular hot spot.

![A digital dashboard interface showing a table under the "Company Information" tab. The table lists employees, their departments, email addresses, logged-in host names, and IP addresses. On the left side are menu options like Dashboard, Alert Queue, and Documentation.](https://cdn.hashnode.com/res/hashnode/image/upload/v1756302013745/62c99f77-caf1-4e25-8f7c-910fc7bbb295.png align="center")

We have a section for **Playbooks** which I read through before beginning the tasks.

![A screenshot of a cybersecurity simulation interface, labeled "Playbooks." It lists two playbooks: "Suspicious Outbound Connection" under Network Outbound category and "Phishing Email Analysis" under Phishing category. A navigation menu is on the left, including options like Dashboard and Alert Queue.](https://cdn.hashnode.com/res/hashnode/image/upload/v1756302022644/a328e5f8-1892-4866-a824-642762ebaad8.png align="center")

Clicking there will bring you to different nodes that you can click on for further information. I had a weird issue where when I clicked on a node, it wouldn’t let me go “back”. There wasn’t a way to close it or go back to I would have to refresh.

**Case reports** below allows us to navigate to the cases we have submitted.

![A dark-themed interface displaying a case reports section with navigation options on the left, including Dashboard, Alert Queue, SIEM, Analyst VM, Documentation, Playbooks, and Guide. The main area shows empty alert entries with options to filter by severity and alert type.](https://cdn.hashnode.com/res/hashnode/image/upload/v1756302033273/9834452b-7fe4-4f4b-9122-43b4ac7b4fe1.png align="center")

Finally there is a **Guide** which looks to be the same guide that we see while everything loads upon launching the simulation.

![Screenshot of a SOC Simulator interface with a navigation menu on the left featuring options like Dashboard, Alert queue, and Documentation. The main section has a guide titled "A guide to using the SOC Simulator" with a green button labeled "Check guide." The background is dark blue.](https://cdn.hashnode.com/res/hashnode/image/upload/v1756302042221/fca1dc2a-7ad4-44d6-ab51-3afafe0ca7da.png align="center")

I would make sure you read everything and download all this information to your head first as this will make working through the tasks a lot easier.

What we want to do is head to the **Alert Queue** where we will see our **alerts**. We’re looking for True Positives so upon reflection, it would make sense to start with the alerts that have the highest **severity** although I found that looking deeper into the lesser threatening ones really helped build a picture of what actually happened but that might be a waste of time? I certainly took my time!

Once we get the information needed within the alert we can use that information to find out more about the target or victim of the attack. This is where the **Documentation** comes into play.

We can take notes of possible **IOC** (Indicators of Compromise), **IP**’s, **URL**’s and such. Or just paste it into some kind of notepad see we can easily get this information into the **SIEM**.

From there we can start digging, perhaps using the timestamp might be a good start to get the exact alert? Perhaps looking up the email, host name, IP address or anything else noted down. We need to use what we know and continue from there.

Finding suspicious **URL**’s, **IP**’s and **Files** could be than scanned or analysed on the **Analyst VM**.

Once we have a good picture in our minds of what has happened we can then **Write case report**.

Here we need to decide if this event was a **True Positive** or **False Positive**.

A **True Positive** being an event that’s happened and is malicious that may or may not need escalation.

A **False Positive** being an event that’s tripped up or alerts the **SIEM** or other tools by accident or because of some strange behaviour either from someone innocent or faulty hardware/software as an example.

TryHackMe have better examples and explanations, just how I think of it.

We can pick which one we think it is and write a little report. There are some useful headers in there already for us but I felt like it was missing one. A header about what it all means. As is, with all the details taken onboard, what does it mean: Was there damages? Was there an actual breach? Is this something to be concerned about?

I think what happens next is once you find a **True Positive** and post it, that then completes this particular simulation with a wrap up at the end that might look like my first attempt:

[https://tryhackme.com/soc-sim/public-summary/a29c1c9d15710a4aeae9c7b9cf5bd2c22ce51e4ffe05e5f008bbb42c6a658951224dc9c645985c501066488f46f7db57](https://tryhackme.com/soc-sim/public-summary/a29c1c9d15710a4aeae9c7b9cf5bd2c22ce51e4ffe05e5f008bbb42c6a658951224dc9c645985c501066488f46f7db57)

I wrote a little **Linkedin** post about it here:

[https://www.linkedin.com/posts/forrestcaffray\_magnetron-completed-introduction-to-phishing-activity-7366440754891730944-j5zB?utm\_source=share&utm\_medium=member\_desktop&rcm=ACoAAD9Cfa8BkstgiaTvWUFOtaB86qR06a0BTBk](https://www.linkedin.com/posts/forrestcaffray_magnetron-completed-introduction-to-phishing-activity-7366440754891730944-j5zB?utm_source=share&utm_medium=member_desktop&rcm=ACoAAD9Cfa8BkstgiaTvWUFOtaB86qR06a0BTBk)

TLDR: I took my sweet time, learned a lot, had fun and would recommend.

The real skills that we are developing here are extracting information, finding the story of what’s happened, understanding it, elevating it if we have to and being coherent enough to write about it so that others may understand also.

I found the reporting the most valuable part of this exercise.

There are only 2 simulations available for free (or is it premium subscribers?).

I do wish I had access to some other scenarios!

![Screenshot of a SOC Simulator interface showing available scenarios with titles like "APT28: Credential Access" and "APT28: Execution." Options for searching, filtering by scenario length and difficulty are visible. Some scenarios are locked.](https://cdn.hashnode.com/res/hashnode/image/upload/v1756304992086/ce7fbadc-5812-4bf2-a53a-4062a8de7770.png align="center")

If you are new the **SOC** space like I am, I think these offer a great opportunity to step into the shoes of a **SOC Analyst** and try out looking at events, understanding them and writing about them.

A thumbs up from me! 👍