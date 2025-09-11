import requests, time, csv

API_KEY = 'a688af4d3094202a9caf7ac4bada1eb066ea318981487ceead3526e3ab939717'
HEADERS = {
    'x-apikey': API_KEY
}

def verificar_ip(ip):
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

def main():
    with open('ips-origem.txt', 'r') as f:
        ips = [line.strip() for line in f if line.strip()]

    with open('resultado.csv', 'w', newline='') as csvfile:
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

if __name__ == "__main__":
    main()
