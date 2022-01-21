#!/usr/bin/env python3

### MODULES ###

import os, sys  # built-in
import pythonwhois, dns.resolver # third-party

### GLOBAL VARIABLES ###

if len(sys.argv)<2:
    print('Enter a domain'  + '\nUsage: ' + sys.argv[0] + ' domain.com\n' )
    sys.exit()
else:
    dom = sys.argv[1]
    DOMAIN = dom.split('/')[2] if str(dom).startswith('http') else dom
if DOMAIN.startswith('www.'):
    DOMAIN = DOMAIN[4:]
WHOIS = pythonwhois.get_whois(DOMAIN)
NoAnswer = dns.resolver.NoAnswer
RED = '\033[31m'
CYAN = '\033[36m'
RESET = '\033[0m'


### FUNCTIONS ###

def reg_check():
    registrant = WHOIS['contacts']['registrant']
    admin = WHOIS['contacts']['admin']
    if not registrant and not admin:
        try:
            status = WHOIS['status'][0]
        except KeyError:
            status = False
        if not status:
            print('Domain not registered' + '\nCheck for typos\n')
            sys.exit()

def get_records(record,type_):
    list_ = dns.resolver.query(record,type_)
    for data in list_:
        print('{0:30}  {1}'.format(str(record), str(data)))

def get_info(contact):
    name = WHOIS['contacts'][contact]['name']
    try:
        email = WHOIS['contacts'][contact]['email']
    except KeyError:
        email = CYAN+'Email: '+RESET+'Not available'
    return CYAN+contact.title() + RESET + ': ' + name + '\n' + email

def whois_info():
    STATUS_LIST = WHOIS['status']
    FORMAT = '%Y-%m-%d'
    print(RED+'\n' + '='*5, CYAN+'WHOIS info for', DOMAIN , RED + '='*5 + '\n' + RESET)
    try:
        print(CYAN+'Registrar:'+RESET, WHOIS['registrar'][0] + '\n' )
    except KeyError:
        pass
    for status in STATUS_LIST:
        print(CYAN+'Status:'+RESET,status.split()[0])
    try:
        EXPIRES = WHOIS['expiration_date'][0].strftime(FORMAT)
        print('\n\033[36m{0:8}\033[0m  {1}'.format('Expires:', EXPIRES))
        UPDATED = WHOIS['updated_date'][0].strftime(FORMAT)
        print('\033[36m{0:8}\033[0m  {1}'.format('Updated:', UPDATED))
        CREATED = WHOIS['creation_date'][0].strftime(FORMAT)
        print('\033[36m{0:8}\033[0m  {1}'.format('Created:', CREATED))
    except KeyError:
        pass
    try:
        registrant = get_info('registrant')
    except (KeyError,TypeError):
        registrant = False
    if registrant:
        print('\n'+ registrant)
    try:
        admin = get_info('admin')
    except (KeyError,TypeError):
        admin = False
    if admin:
        print('\n'+ admin + '\n')

def record_check(dom):
    try:
        get_records(dom,'CNAME')
        cname = True
    except NoAnswer:
        cname = False
    if not cname:
        try:
            get_records(dom,'A')
        except NoAnswer:
            print('{0:30}  {1}'.format(DOMAIN, 'No record found'))

def main():
    os.system('clear')
    reg_check()
    print(RED+'='*5+CYAN, 'DNS info for', DOMAIN , RED+'='*5 + '\n'+RESET)
    try:
        NS_LIST = dns.resolver.query(DOMAIN, 'NS')
    except NoAnswer:
        print(CYAN+'Nameservers:'+RESET, 'None found')
    if NS_LIST:
        print(CYAN+'Nameservers:'+RESET)
        for ns in NS_LIST:
            get_records(str(ns), 'A')
    print(CYAN+'\nRoot & www:'+RESET)
    record_check(DOMAIN)
    record_check('www.'+DOMAIN)
    try:
        MX_LIST = dns.resolver.query(DOMAIN, 'MX')
    except NoAnswer:
        print(CYAN+'\nMX records:'+RESET, 'None found')
    if MX_LIST:
        print(CYAN+'\nMX records:'+RESET)
        for mx in MX_LIST:
            mx = str(mx)
            fqdn = mx.strip().split()[1]
            try:
                ip_list = dns.resolver.query(fqdn, "A")
                for ip in ip_list:
                    print('{0:30}  {1}'.format(str(mx), str(ip)))
            except dns.resolver.NXDOMAIN:
                print(mx)
    try:
        TXT_LIST = dns.resolver.query(DOMAIN, 'TXT')
        print(CYAN+'\nTXT records:'+RESET)
        for txt in TXT_LIST:
            print(txt)
    except NoAnswer:
        print(CYAN+'\nTXT records:'+RESET, 'None found')
    whois_info()
    print(RED+"=" * 40 + '\n'+RESET)

if __name__ == "__main__":
    main()

