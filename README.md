# checkssl

检查域名证书是否无效或过期。

'''
>python CheckSSL.py
usage: CheckSSL.py [-h] [-u URL] [-f FILE] [-o OUTPUT]

Check SSL certificate expiry for given domain(s).

optional arguments:
  -h, --help            show this help message and exit
  -u URL, --url URL     Check SSL certificate for a single domain.
  -f FILE, --file FILE  Check SSL certificate for domains listed in a file.
  -o OUTPUT, --output OUTPUT
                        Output CSV file to write issues.
'''
