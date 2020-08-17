# domainspoof-detector
This utility is a django based project that checks implimentation and configuration of protocols like SPF, DKIM, DMARC and DNS servers configuration to find out if the mailing server is spoofable or not !!

![image1](screenshot/img7.png?raw=true "Results obtained from the tool")

According to our tool,experiment was conducted on the top 10 mailing service providers:
Amongst these, gmail.com, outlook.com and mailbox.com had liberal DMARC policies, which allows us to send spoofed emails to their users without raising any red flags.
msgsafe.io and gmx.com had no DMARC implimentation, thus any email could be easily spoofed and sent to any addresses.
