import socket
import ssl
import OpenSSL.crypto as crypto
from datetime import datetime
import csv
import argparse


# 函数：从域名中提取主域名
def extract_main_domain(domain):
    parts = domain.split('.')
    if len(parts) > 2:
        main_domain = '.'.join(parts[-2:])
    else:
        main_domain = domain
    return main_domain


# 函数：检查SSL证书过期时间和域名匹配
def check_ssl_expiry(domain):
    issues = []
    try:
        # 创建socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10)
        s.connect((domain, 443))

        # 创建SSL上下文
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        # 包装socket以使用SSL
        s = context.wrap_socket(s, server_hostname=domain)
        cert = s.getpeercert(True)
        x509 = crypto.load_certificate(crypto.FILETYPE_ASN1, cert)
        common_name = x509.get_subject().commonName

        # 检查域名匹配
        if common_name.startswith('*.'):
            common_main_domain = extract_main_domain(common_name[2:])
            domain_main_domain = extract_main_domain(domain)
            match = common_main_domain.lower() == domain_main_domain.lower()
        else:
            match = common_name.lower() == domain.lower()

        if not match:
            issues.append(f"域名 {domain} 与证书绑定域名 {common_name} 不匹配")

        # 获取证书的过期时间
        expiry_date = datetime.strptime(x509.get_notAfter().decode('ascii'), '%Y%m%d%H%M%SZ')
        if expiry_date < datetime.now():
            issues.append(f"证书过期于 {expiry_date.strftime('%Y-%m-%d %H:%M:%S')}")

        s.close()
    except Exception as e:
        issues.append(f"Error checking {domain}: {e}")

    return issues


# 主程序
def main():
    parser = argparse.ArgumentParser(description='Check SSL certificate expiry for given domain(s).')
    parser.add_argument('-u', '--url', type=str, help='Check SSL certificate for a single domain.')
    parser.add_argument('-f', '--file', type=str, help='Check SSL certificate for domains listed in a file.')
    parser.add_argument('-o', '--output', type=str, default='ssl_issues.csv', help='Output CSV file to write issues.')
    args = parser.parse_args()

    with open(args.output, 'w', newline='',encoding='utf-8') as file:
        writer = csv.writer(file)
        writer.writerow(['Domain', 'Issue', 'Certificate'])

        if args.url:
            issues = check_ssl_expiry(args.url)
            if issues:
                writer.writerow([args.url] + issues)

        elif args.file:
            try:
                with open(args.file, 'r') as domains_file:
                    for domain in domains_file:
                        domain = domain.strip()
                        if domain:
                            issues = check_ssl_expiry(domain)
                            if issues:
                                writer.writerow([args.url] + issues)
            except FileNotFoundError:
                print(f"File not found: {args.file}")
        else:
            parser.print_help()


if __name__ == "__main__":
    main()
