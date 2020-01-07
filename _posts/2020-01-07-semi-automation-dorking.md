---
layout: post
title:  "Semi-automation of dorking"
date:   2020-01-07
author: dee-see
categories: automation osint
---

[Nahamsec](https://twitter.com/nahamsec) has an [excellent presentation](https://docs.google.com/presentation/d/1xgvEScGZ_ukNY0rmfKz1JN0sn-CgZY_rTp2B_SZvijk/edit#slide=id.g4052c4692d_0_0) about recon in which he discusses, among many other things, the topic of "Digital Dumpster Diving" and google dorking.

![Slide from Nahamsec's It's the Little Things II presentation]({{ '/images/nahamsec_little_things.png' | absolute_url }})  

This is mostly a manual process but I thought I could automate at least some of it, so here's a simple form that will automatically generate the search links. Now all you have to do is open a bunch of tabs and sift through the information! The dorks themselves are from a list I have accumulated over time, sorry if I can't credit the people I got them from.

The "app" is available on this blog page and at <{{ '/dorks' | absolute_url }}>. I will update this over time with dorks that search for error messages and common info disclosures. If you have any ideas feel free to <a href="{{ site.repo }}">open an issue or a PR</a>.

{% include dorks.html %}

