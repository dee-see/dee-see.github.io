---
layout: post
title:  "Automatically recover Firebase Remote Config information in Android apps"
date:   2019-08-03
categories: android automation
---

[Firebase Remote Config](https://firebase.google.com/docs/remote-config/) is a service that allows developers to host and easily modify settings for their mobiles apps. It's not *supposed* to be secret information and it's not designed to be private, however automating the recovery of Firebase Remote Config is very easy and can reveal some details about the application's inner workings. You can even get lucky and find secrets that should have never been there in the first place (I once saw AWS credentials!).

What you'll need:

- Google API key
- Google app ID
- Google project ID

Luckily all these things available in the `strings.xml` file of a decompiled APK. Here's a Ruby script that recovers the values from a `strings.xml` file and gets the Firebase Remote Config data.

```ruby
require 'nokogiri'
require 'httparty'
require 'json'

def get_string_value(xml, setting_name)
  value = xml.xpath("/resources/string[@name='#{setting_name}']").first
  unless value.nil? || value.content.empty?
    puts "[+] Found value for '#{setting_name}': #{value.content}'"
    value.content
  end
end

strings_path = "resources/res/values/strings.xml" # You'll likely want to take this path as a parameter
if File.exist?(strings_path)
  xml = File.open(strings_path) { |f| Nokogiri::XML(f) }
  google_api_key = get_string_value(xml, 'google_api_key')
  google_app_id = get_string_value(xml, 'google_app_id')
  unless google_app_id.nil?
    project_id = google_app_id.split(':')[1]
    puts '[*] Recovering Firebase Remote Config'
    response = HTTParty.post("https://firebaseremoteconfig.googleapis.com/v1/projects/#{project_id}/namespaces/firebase:fetch?key=#{google_api_key}",
                             body: JSON.generate(appId: google_app_id, appInstanceId: 'required_but_unused_value'),
                             headers: { 'Content-Type' => 'application/json' })

    puts response.body
  end
end
```

If the app doesn't have the necessary config information or if the response from the HTTP request is

```json
{
  "state": "NO_TEMPLATE"
}
```

then it doesn't use Firebase Remote Config.

Finally, a response with data will look like this:

```json
{
  "entries": {
    "key1": "value1",
    "key2": "value2",
    "...": "..."
  },
  "state": "UPDATE"
}
```

There you go! Nothing major but easy enough to include in your automation and Android recon.
