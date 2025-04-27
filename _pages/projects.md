---
title: ""
layout: single
classes: wide
permalink: /projects/
author_profile: true
---

## AurisonPhish - [github](https://github.com/colossalbro/AurisonPhish)
**Overview**<br>
AurisonPhish is a tool I wrote to (legally) test [Aurison](https://aurison.app) employees against phishing attacks. It lets you upload employee emails and names through an Excel file, set start/end dates for your phishing campaign, and then automatically sends out phishing emails with fake links. When employees click these links, they get redirected to a lookalike domain (e.g aurisonn.app) that mimics the real thing. Like most phishing tools, it proxies any submitted credentials to the real Aurison API to check if they're valid. Employees who enter working credentials basically fail the test! Once the campaign wraps up, the tool sends out reports to security emails with all the important analytics like who opened emails, who clicked links, who gave up their passwords, etc.

**Why**<br>
Tools like [Evilginx2](https://github.com/kgretzky/evilginx2) exist, so why reivent the wheel? Aurison required a custom solution they could run, improve and maintain themselves. This requirement stemmed from a need to stay compliant with important health regulations and service provider agreements. The version on my Github is a quick proof-of-concept I threw together during the engagement. Since then, its been beefed up and standardized for internal use.

**Stack**: Python, Javascript, Docker

<br>
<br>

## TelegramBot - [github](https://github.com/colossalbro/the17thSet)
**Overview**:  <br>
[@cu_portrait_bot](https://t.me/cu_portrait_bot) is a simple bot I wrote to help graduating students access their convocation portraits. It uses the grammy-js library to handle communication between the bot and the backend server where portraits are stored. For convenience, the bot also comes with a straightforward one-page website as an alternative way for students to retrieve their portraits.

**Why**<br>
During my undergradate years, Telegram was the main communication platform at the university, with around 90% of students actively using it. When  convocation season arrived, the planning committee was faced with a challenge with distributing digital portraits efficiently to hundreds of graduating students. This bot was the quickest solution recommended at the time 🤷 <br>
Simple, but it got the job done.

**Stack**: Javascript