# domainspoof-detector
This utility is a django based project that checks implimentation and configuration of protocols like SPF, DKIM, DMARC and DNS servers configuration to find out if the mailing server is spoofable or not !!

![image1](screenshot/img7.png?raw=true "Results obtained from the tool")

According to our tool,experiment was conducted on the top 10 mailing service providers:

Amongst these,
# gmail.com, outlook.com and mailbox.com 
had liberal DMARC policies, which allows us to send spoofed emails to their users without raising any red flags.
# msgsafe.io and gmx.com 
had no DMARC implimentation, thus any email could be easily spoofed and sent to any addresses.

Some other experiments were conducted against some of the 
# prestigious educational institutions of India and many of those were found to be spoofable 
and any spoofed email from their facult members email could be sent to these liberal policy and no DMARC implimentation services.(
# Huge Concern
)

# Salient features of my utility:

1) Easy interface and easy to visualize graphs

2) Detailed report of information regarding protocols and DNS server

3) Easily customizable( add your own domain/IP blacklists)

4) Has email parsing features, which parse and segregate email parts for further analysis(have left a dead for integration of virustotal to the scrapped )

