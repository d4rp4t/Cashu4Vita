
```
                     .__             _____       .__  __          
  ____ _____    _____|  |__  __ __  /  |  |___  _|__|/  |______   
_/ ___\\__  \  /  ___/  |  \|  |  \/   |  |\  \/ /  \   __\__  \  
\  \___ / __ \_\___ \|   Y  \  |  /    ^   /\   /|  ||  |  / __ \_
 \___  >____  /____  >___|  /____/\____   |  \_/ |__||__| (____  /
     \/     \/     \/     \/           |__|                    \/ 

```

PS Vita Cashu Wallet.
This project is deeply unserious, probably buggy and was created as a weekend hack.

I also wanted to show that cashu is superior for micropayments. It can literally run on 2012 
handheld game console. 

It runs with [testnut](https://testnut.cashu.space/v1/info) mint as a default. 
You can use any mint you want anyway.

DISCLAIMER 
- Do not use real money unless you’re okay with potentially losing it.
- This is experimental software.
- PS Vita is an old and unsupported platform with many known and unknown vulnerabilities.
- There are very likely bugs here.
- You’ve been warned.

To run tests
```shell
./test.sh
```

To build 
```shell
./build.sh
```
This will run VitaSDK in a docker container, and build it. 
Then you can copy Cashu4Vita.vpk to your vita, and play around with cashu on your dusty handheld.
Running this app requires modded console with HENkaku / enso installed.

Not affiliated with Sony or anything like that. 

You couldn't do that with fiat btw.