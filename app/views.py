# Create your views here.
from django.shortcuts import render
from .models import Video, Piechart
from .forms import VideoForm
from django.conf import settings 
import time
import os
import subprocess
import pandas
from pandas.io.json import json_normalize
from checkdmarc import get_dmarc_record as dd
from checkdmarc import get_spf_record as sp
from checkdmarc import get_mx_hosts as mx_rec
from checkdmarc import get_nameservers as ns_rec
from checkdmarc import test_dnssec as dnssec
from checkdmarc import test_starttls as checktls
from checkdmarc import query_spf_record as qspf

from checkdmarc import verify_dmarc_report_destination as ver_dmarc

def index(request):
    if "GET" == request.method:
        form = VideoForm()
        mas = "lll"
        return render(request, 'app/index.html', {'mas':mas})
    else:
        tim= None
        truer=None
        falser=None
        dmarc_records_full = None
        records_enum=None 
        extracted_url=None 
        blacklist_domain=None
        blacklist_ip=None
        dmarc_status=None
        dnsec=None
        mx_record=None
        ns_record=None
        meta_header=None
        meta_body=None
        attachment=None 
        dkim_records=None
        spf1=None
        spf11=None
        warn_spf=None
        warn_dmarc=None
        warn_dkim=None
        warn_ldmarc=None
        name=None
        record=None
        dmarc1=None
        dmarc2=None
        dmarc3=None
        dmarc4=None
        dmarc5=None
        dmarc6=None
        dmarc7=None
        dmarc8=None
        dmarc9=None
        dmarc10=None
        dmarc11=None
        spf2=None
        spf3=None
        spf4=None
        spf5=None
        spf6=None
        spf7=None
        length_key=None
        '''
        from virustotal_python import Virustotal
        from pprint import pprint

        # Normal Initialisation.
        vtotal = Virustotal("Insert API Key Here.")

        vtotal = Virustotal(
          "Insert API Key Here.",
          {"http": "http://10.10.1.10:3128", "https": "http://10.10.1.10:1080"})

       resp = vtotal.file_report(
         [
        "75efd85cf6f8a962fe016787a7f57206ea9263086ee496fc62e3fc56734d4b53-1555351539",
        "9f101483662fc071b7c10f81c64bb34491ca4a877191d464ff46fd94c7247115",
         ])
        '''
        
        lastvideo= Video.objects.last()
        name = Video.objects.last
        videofile= lastvideo
 
        form= VideoForm(request.POST or None , request.FILES or None )
        if form.is_valid():
            form.save()
        context= {'videofile': videofile,
              'form': form
              }
        try:
            lastvideo= Video.objects.all().latest('geeks_field')
        except:
            lastvideo= Video.objects.last()
  

        


        if form.is_valid():
            eml_file = (os.path.join(settings.MEDIA_ROOT, str(videofile)))
            command =  form['selector'].value() + "._domainkey." + form['name'].value() 
            name = form['name'].value()
#            nab = 'checkdmarc' + ' ' + form['name'].value()
#            mark = subprocess.Popen(['checkdmarc' , form['name'].value()], stdout=subprocess.PIPE).communicate()
#            dmarc_records_full = os.system('checkdmarc' + ' ' + form['name'].value())
            dws = subprocess.Popen(["dig" ,"-t" , "txt" ,command , "+short"], stdout=subprocess.PIPE).communicate()[0]
            dkim_records = dws.decode("utf-8").replace('" "',"")

            dmarc1 = dd(form['name'].value())['record']
            
            dmarc2= dd(form['name'].value())['parsed']['tags']['v']

            dmarc3 = dd(form['name'].value())['parsed']['tags']['p']

            dmarc4 = dd(form['name'].value())['parsed']['tags']['sp']

            dmarc5 = dd(form['name'].value())['parsed']['tags']['rua']['value'] # 4 entry

            dmarc6 = dd(form['name'].value())['parsed']['tags']['adkim']

            dmarc7 = dd(form['name'].value())['parsed']['tags']['aspf']

            dmarc8 = dd(form['name'].value())['parsed']['tags']['fo']

            dmarc9 = dd(form['name'].value())['parsed']['tags']['pct']

            dmarc10 = dd(form['name'].value())['parsed']['tags']['rf']

            dmarc11 = dd(form['name'].value())['parsed']['tags']['ri']


            spf1 = sp(form['name'].value())['dns_lookups']
            spf11 = qspf(form['name'].value())['record']
            spf2 = sp(form['name'].value())['parsed']['pass']
            spf3 = sp(form['name'].value())['parsed']['neutral']
            spf4 = sp(form['name'].value())['parsed']['softfail']
            spf5 = sp(form['name'].value())['parsed']['fail']
            spf6 = sp(form['name'].value())['parsed']['include']

            spf7 = sp(form['name'].value())['parsed']['redirect']
 
            mx_record = mx_rec(name)['hosts']
            ns_record= ns_rec(name)
            dnsec = dnssec(name)
            #checktls("gmail.com")
            dmarc_status = ver_dmarc(name,name)
            
            length_key = 2054
            warn_spf = 0
            if '~all' in spf11:
                warn_spf = 1
                
            warn_dmarc = 0
            if 'p=none' in dmarc1:
                warn_dmarc = 1
            
            warn_dkim = 0
            if len(dkim_records) < 2:
                warn_dkim =1
    
                
            warn_ldmarc =0  
            if 1 in (warn_dkim, warn_dmarc, warn_spf):
                warn_ldmarc = 1

            if warn_ldmarc == 0:
                yum= True
            else:
                yum = False
            yam = Piechart(ldmarc_rel = yum)
            yam.save()
            truer = Piechart.objects.all().filter(ldmarc_rel=True).count()
            falser = Piechart.objects.all().filter(ldmarc_rel=False).count()
    
            
            import pydnsbl
            import socket
            
            domain_checker = pydnsbl.DNSBLDomainChecker()
            ip_checker = pydnsbl.DNSBLIpChecker()
            
            blacklist_domain=domain_checker.check(form['name'].value())
            blacklist_ip= ip_checker.check(socket.gethostbyname(form['name'].value()))
            
            import datetime
            import json
            import eml_parser
            
            def extractURL(fileName):

                wordsInLine = []
                tempWord = []
                urlList = []

                # open up the file containing the email
                file = open(fileName)
                for line in file:
                 #create a list that contains each word in each line
                    wordsInLine = line.split(' ')
                    #For each word try to split it with :
                    for word in wordsInLine:
                        tempWord = word.split(":")
                        #Check to see if the word is a URL
                        if len(tempWord) == 2:
                            if tempWord[0] == "http" or tempWord[0] == "https":
                                urlList.append(word.rstrip("\n").split("<")[0])

                file.close()

                return urlList
            extracted_url = extractURL(eml_file)
            
            
            
            import dns.resolver


            def get_records(domain):
                ids = [
                         'NONE',
                            'A',
                            'NS',
                            'MD',
                            'MF',
                           'CNAME',
                               'SOA',
                            'MB',
                            'MG',
        'MR',
        'NULL',
        'WKS',
        'PTR',
        'HINFO',
        'MINFO',
        'MX',
        'TXT',
        'RP',
        'AFSDB',
        'X25',
        'ISDN',
        'RT',
        'NSAP',
        'NSAP-PTR',
        'SIG',
        'KEY',
        'PX',
        'GPOS',
        'AAAA',
        'LOC',
        'NXT',
        'SRV',
        'NAPTR',
        'KX',
        'CERT',
        'A6',
        'DNAME',
        'OPT',
        'APL',
        'DS',
        'SSHFP',
        'IPSECKEY',
        'RRSIG',
        'NSEC',
        'DNSKEY',
        'DHCID',
        'NSEC3',
        'NSEC3PARAM',
        'TLSA',
        'HIP',
        'CDS',
        'CDNSKEY',
        'CSYNC',
        'SPF',
        'UNSPEC',
        'EUI48',
        'EUI64',
        'TKEY',
        'TSIG',
        'IXFR',
        'AXFR',
        'MAILB',
        'MAILA',
        'ANY',
        'URI',
        'CAA',
        'TA',
        'DLV',
        'DMARC'
    ]
                records=[]
                for a in ids:
                    try:
                        answers = dns.resolver.query(domain, a)
                        for rdata in answers:
                            d = ( a, ':', rdata.to_text())
                            records.append(d)
                
    
                    except Exception as e:
                       pass  # or pass
                return records

            
            records_enum= get_records(form['name'].value())



            
            def json_serial(obj):
                if isinstance(obj, datetime.datetime):
                    serial = obj.isoformat()
                    return serial


            with open(eml_file, 'rb') as fhdl:
                raw_email = fhdl.read()

            ep = eml_parser.eml_parser
            parsed_eml = ep.decode_email_b(raw_email)

            ss=parsed_eml['attachment']
            attachment=[]
            for s in ss:
                attachment.append(s)
            meta_body = parsed_eml['body']
            meta_header= parsed_eml['header']
            

        else:
            pass

    return render(request, 'app/index.html', {'videofile': videofile,"records_enum":records_enum,'truer':truer,'falser':falser,'extracted_url':extracted_url,'name':name,'blacklist_domain':blacklist_domain,'blacklist_ip':blacklist_ip,'dmarc_status':dmarc_status,'length_key':length_key,'warn_spf':warn_spf,'warn_dkim':warn_dkim,'warn_ldmarc':warn_ldmarc, 'warn_dmarc':warn_dmarc, 'dnsec':dnsec,'mx_record':mx_record,'ns_record':ns_record,'form': form,"meta_header":meta_header,'meta_body':meta_body,'attachment':attachment ,"dkim_records":dkim_records , "metadata":record,'spf1':spf1,'dmarc1':dmarc1,'spf11':spf11 ,'dmarc2':dmarc2,'dmarc3':dmarc3,'dmarc4':dmarc4,'dmarc5':dmarc5,'dmarc6':dmarc6,'dmarc7':dmarc7,'dmarc8':dmarc8,'dmarc9':dmarc9,'dmarc10':dmarc10,'dmarc11':dmarc11,'spf2':spf2,'spf3':spf3,'spf4':spf4,'spf5':spf5,'spf6':spf6,'spf7':spf7})


