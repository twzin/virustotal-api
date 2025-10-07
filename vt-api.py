import requests, time, csv, argparse, sys

API_KEY = ''
HEADERS = {
    'x-apikey': API_KEY
}

def args():
    parser = argparse.ArgumentParser(description="VTAPI")
    parser.add_argument('-lip', '--IPLIST', type=str, help='Lista de IPs para consultar')
    parser.add_argument('-ip', '--IP', type=str, help='IP para consultar')
    parser.add_argument('-lhash', '--HASHLIST', type=str, help='Lista de HASHES para consultar')
    parser.add_argument('-hash', '--HASH', type=str, default=None, help='Hash para consultar')
    parser.add_argument('-o', '--OUTPUT', type=str, default=None, help='Output file')
    return parser.parse_args()

def passa_hash(hash):
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
    
def sandbox_veredict(hash):
    resultado = passa_hash(hash)
    _, _, _, sandbox_veredict = resultado

    if sandbox_veredict is None:
        return None, None, None, None, None

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
    return None, None, None, None, None

def consulta_hash(hash):
    sha256, malicious, name, _ = passa_hash(hash)
    print(f"Hash: \33[31m{sha256}\033[0m | Mal Score: \33[31m{malicious}\033[0m | File Name: \33[31m{name}\033[0m")
    sandbox_veredict(hash)


def passa_ip(ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    response = requests.get(url, headers=HEADERS)

    if response.status_code == 200:
        respose_json = response.json()
        data = respose_json['data']
        attributes = data['attributes']
        stats = attributes['last_analysis_stats']
        owner = attributes['as_owner']
        country = attributes['country']
        maliciosos = stats['malicious']
        suspeitos = stats['suspicious']
        return maliciosos, suspeitos, owner, country
    else:
        return None, None, None, None

def consulta_lista_ip(lista_ips, arquivo_saida):
    with open(lista_ips, 'r') as f:
        ips = [line.strip() for line in f if line.strip()]

    if not arquivo_saida.lower().endswith('.csv'):
        arquivo_saida += '.csv'

    with open(arquivo_saida, 'w', newline='') as csvfile:
        fieldnames = ['IP', 'Maliciosos', 'Suspeitos', 'Owner', 'Country']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

        for ip in ips:
            maliciosos, suspeitos, owner, country = verificar_ip(ip)
            if maliciosos is not None:
                if maliciosos >= 2:
                    print(f"\33[31mIP: {ip}\033[0m | \33[31mMaliciosos: {maliciosos}\033[0m | Suspeitos: {suspeitos} | Owner: {owner} | Country: {country}")
                else:
                    print(f"IP: {ip} | Maliciosos: {maliciosos} | Suspeitos: {suspeitos} | Owner: {owner} | Country: {country}")
                writer.writerow({
                'IP': ip,
                'Maliciosos': maliciosos,
                'Suspeitos': suspeitos,
                'Owner': owner,
                'Country': country
            })
            else:
                print(f"Falha ao verificar IP: {ip}")
                writer.writerow({
                    'IP': ip,
                    'Maliciosos': 'Erro',
                    'Suspeitos': 'Erro',
                    'Owner': 'Erro',
                    'Country': 'Erro'
                })
            time.sleep(15)
        print(f"Resultados salvos em {arquivo_saida}")


def consulta_ip(ip):
    maliciosos, suspeitos, owner, country = verificar_ip(ip)
    if maliciosos is not None:
        if maliciosos >= 2:
            print(f"\33[31mIP: {ip}\033[0m | \33[31mMaliciosos: {maliciosos}\033[0m | Suspeitos: {suspeitos} | Owner: {owner} | Country: {country}")
        else:
            print(f"IP: {ip} | Maliciosos: {maliciosos} | Suspeitos: {suspeitos} | Owner: {owner} | Country: {country}")
    

if __name__ == "__main__":
    args = args()

    if len(sys.argv) < 2:
        print("Usage: python3 vt-api.py -h")
        sys.exit(1)

    if args.IP:
        consulta_ip(args.IP)
    if args.HASH:
        consulta_hash(args.HASH)
    if args.IPLIST:
        if not args.OUTPUT:
            print("Coloque um nome para o arquivo de saida!")
            sys.exit(1)
        consulta_lista_ip(args.IPLIST, args.OUTPUT)   
