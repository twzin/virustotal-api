#!/usr/bin/env python3

import requests, time, csv, argparse, sys

API_KEY = ''
HEADERS = {
    'x-apikey': API_KEY
}

def args():
    parser = argparse.ArgumentParser(description="VTAPI")
    parser.add_argument('-iplist', '--IPLIST', type=str, help='Arquivo de lista de IPs para consultar')
    parser.add_argument('-ip', '--IP', type=str, help='IP para consultar')
    parser.add_argument('-hashlist', '--HASHLIST', type=str, help='Arquivo de lista de HASHES para consultar')
    parser.add_argument('-hash', '--HASH', type=str, default=None, help='Hash para consultar')
    parser.add_argument('-o', '--OUTPUT', type=str, default=None, help='Arquivo de saida')
    return parser.parse_args()

def send_hash(hash):
    url = f"https://www.virustotal.com/api/v3/files/{hash}"
    response = requests.get(url, headers=HEADERS)
    
    if response.status_code == 200:
        response_json = response.json()
        data = response_json["data"]
        attributes = data["attributes"]
        sha256 = attributes["sha256"]
        name = attributes["meaningful_name"]
        stats = attributes["last_analysis_stats"]
        malicious = stats["malicious"]
        sandbox_veredicts = attributes.get("sandbox_verdicts", {})
        return sha256, malicious, name, sandbox_veredicts
    else:
        return None, None, None, None
    
def check_sandbox(hash):
    sandbox_veredict = send_hash(hash)[3]

    print("--- Resultados das Sandboxes ---")
    for sandbox_name, data in sandbox_veredict.items():
        category = data.get("category", 'N/A')
        sandbox_name = data.get("sandbox_name", [])
        classification = ", ".join(data.get("malware_classification", []))
        malware_names = ", ".join(data.get("malware_names", []))
        confidence = data.get("confidence", "N/A") 
        print(f"    > {sandbox_name} ({category.upper()})")
        print(f"       - Classificacao: {classification}")
        print(f"       - Nomes do Malware: {malware_names}")
        if confidence != "N/A":
            print(f"       - Confianca: {confidence}%")
    print("-------------------------------")


def check_hash(hash):
    sha256, malicious, name, _ = send_hash(hash)
    print(f"Hash: \33[31m{sha256}\033[0m | Mal Score: \33[31m{malicious}\033[0m | File Name: \33[31m{name}\033[0m")
    check_sandbox(hash)

def check_hash_list(file_in, file_out):
    with open(file_in, 'r') as f:
        hashes = [line.strip() for line in f if line.strip()]

    if not file_out.lower().endswith('.csv'):
        file_out += '.csv'

    with open(file_out, 'w', newline='') as csvfile:
        fieldnames = ['Hash', 'Score_Malicioso', 'File_Name']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        
        for hash in hashes:
            sha256, malicious, name, _ = send_hash(hash)
            if malicious is not None:
                if malicious >= 2:
                    print(f"Hash: \33[31m{sha256}\033[0m | Mal Score: \33[31m{malicious}\033[0m | File Name: \33[31m{name}\033[0m")
                    writer.writerow({
                    'Hash': sha256,
                    'Score_Malicioso': malicious,
                    'File_Name': name
            })
            else:
                print(f"Falha ao verificar hash: {sha256}")
                writer.writerow({
                    'Hash': "Error",
                    'Score_Malicioso': "Error",
                    'File_Name': "Error"
                })
            time.sleep(15)

    print(f"\nResultados salvos em {file_out}!")


def send_ip(ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    response = requests.get(url, headers=HEADERS)

    if response.status_code == 200:
        respose_json = response.json()
        data = respose_json['data']
        attributes = data['attributes']
        stats = attributes['last_analysis_stats']
        owner = attributes['as_owner']
        country = attributes['country']
        malicious = stats['malicious']
        suspicious = stats['suspicious']
        return malicious, suspicious, owner, country
    else:
        return None, None, None, None

def check_ip_list(file_in, file_out):
    with open(file_in, 'r') as f:
        ips = [line.strip() for line in f if line.strip()]

    if not file_out.lower().endswith('.csv'):
        file_out += '.csv'

    with open(file_out, 'w', newline='') as csvfile:
        fieldnames = ['IP', 'Malicious', 'Suspicious', 'Owner', 'Country']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

        for ip in ips:
            malicious, suspicious, owner, country = send_ip(ip)
            if malicious is not None:
                if malicious >= 2:
                    print(f"\33[31mIP: {ip}\033[0m | \33[31mMalicious: {malicious}\033[0m | Suspicious: {suspicious} | Owner: {owner} | Country: {country}")
                else:
                    print(f"IP: {ip} | Malicious: {malicious} | Suspicious: {suspicious} | Owner: {owner} | Country: {country}")
                writer.writerow({
                'IP': ip,
                'Malicious': malicious,
                'Suspicious': suspicious,
                'Owner': owner,
                'Country': country
            })
            else:
                print(f"Falha ao verificar IP: {ip}")
                writer.writerow({
                    'IP': ip,
                    'Malicious': 'Error',
                    'Suspicious': 'Error',
                    'Owner': 'Error',
                    'Country': 'Error'
                })
            time.sleep(15)
        print(f"Resultados salvos em {file_out}")


def check_ip(ip):
    malicious, suspicious, owner, country = send_ip(ip)
    if malicious is not None:
        if malicious >= 2:
            print(f"\33[31mIP: {ip}\033[0m | \33[31mMalicious: {malicious}\033[0m | Suspicious: {suspicious} | Owner: {owner} | Country: {country}")
        else:
            print(f"IP: {ip} | Malicious: {malicious} | Suspicious: {suspicious} | Owner: {owner} | Country: {country}")
    

def no_output_exit(output):
    if not output:
            print("Coloque um nome para o arquivo de saida!")
            sys.exit(1)

if __name__ == "__main__":
    args = args()

    if len(sys.argv) < 2:
        print("Usage: python3 vt-api.py -h")
        sys.exit(1)

    if args.IP:
        check_ip(args.IP)
    elif args.HASH:
        check_hash(args.HASH)
    elif args.IPLIST:
        no_output_exit(args.OUTPUT)
        check_ip_list(args.IPLIST, args.OUTPUT)   
    elif args.HASHLIST:
        no_output_exit(args.OUTPUT)
        check_hash_list(args.HASHLIST, args.OUTPUT) 
