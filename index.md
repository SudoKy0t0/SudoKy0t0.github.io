---
layout: default
title: Home
---

## Notes & Writeups

Personal notes on:
- Enumeration
- CTFs
- Exploitation
- Things worth remembering

---

### Latest posts

{% for post in site.posts %}
- **[{{ post.title }}]({{ post.url }})**  
  <small>{{ post.date | date: "%Y-%m-%d" }}</small>
{% endfor %}
