arquivo_log = open('security_logs.txt', 'r')

# Dicionários vazios:
falhas_por_ip = {}
falhas_por_user = {}
sucessos_por_ip = {}
sucessos_por_user = {}
acessos_negados = {}
eventos_desconhecidos = {}
ips_por_usuario = {}
usuarios_por_ip = {}


# Contadores simples zerados:
total_linhas = 0
total_falhas = 0
total_sucessos = 0
total_acessos_negados = 0
total_eventos_desconhecidos = 0

# Listas:
registros_incompletos = []
possivel_fb_usuario = []
possivel_fb_ip = []
usuarios_multiplos_ips = []
ips_multiplos_usuarios = []

# Loop:
for linha in arquivo_log:
    partes = linha.split("|")
    total_linhas = total_linhas + 1

    try:
        data_hora = partes[0].strip()
        login = partes[1].strip()
        user = partes[2].strip().replace('user=','')
        ip = partes[3].strip().replace('ip=', '')
        recursos = partes[4].strip()
    except IndexError:
        print("LINHA FORA DOS PARÂMETROS [IGNORADA]: ", linha.strip())
        registros_incompletos.append(linha.strip())
        continue


    if 'LOGIN_FAILED' in linha:
        total_falhas = total_falhas + 1

        if user in falhas_por_user:
            falhas_por_user[user] = falhas_por_user[user] + 1
        else:
            falhas_por_user[user] = 1

        if ip in falhas_por_ip:
            falhas_por_ip[ip] = falhas_por_ip[ip] + 1
        else:
            falhas_por_ip[ip] = 1

    elif 'LOGIN_SUCCESS' in linha:
        total_sucessos = total_sucessos + 1

        if user in sucessos_por_user:
            sucessos_por_user[user] = sucessos_por_user[user] + 1
        else:
            sucessos_por_user[user] = 1

        if ip in sucessos_por_ip:
            sucessos_por_ip[ip] = sucessos_por_ip[ip] + 1
        else:
            sucessos_por_ip[ip] = 1

    elif 'ACCESS_DENIED' in linha:
        total_acessos_negados = total_acessos_negados + 1

        if user in acessos_negados:
            acessos_negados[user] = acessos_negados[user] + 1
        else:
            acessos_negados[user] = 1

    else:
        total_eventos_desconhecidos = total_eventos_desconhecidos + 1
        if login in eventos_desconhecidos:
            eventos_desconhecidos[login] = eventos_desconhecidos[login] + 1
        else:
            eventos_desconhecidos[login] = 1

    if user not in ips_por_usuario:
        ips_por_usuario[user] = [ip]
    elif ip not in ips_por_usuario[user]:
        ips_por_usuario[user].append(ip)

    if ip not in usuarios_por_ip:
        usuarios_por_ip[ip] = [user]
    elif user not in usuarios_por_ip[ip]:
        usuarios_por_ip[ip].append(user)

# Investigação para possível ataque de força bruta:
for ip, quantidade in falhas_por_ip.items():
    if quantidade >=5:
        possivel_fb_ip.append(ip)
        

for user, quantidade in falhas_por_user.items():
    if quantidade >=5:
        possivel_fb_usuario.append(user)
        

# Loop de usuário com múltiplos IPs:
for user, lista_ips in ips_por_usuario.items():
    if len(lista_ips) > 1:
        usuarios_multiplos_ips.append(user)
        
# Loop de IPs com múltiplos usuários:
for ip, lista_user in usuarios_por_ip.items():
    if len(lista_user) > 1:
        ips_multiplos_usuarios.append(ip)

# Registros do terminal:
print('=' * 40)
print('EYESENTINEL - SECURITY LOG')
print('=' * 40)

print("\n[• RESUMO DE AUTENTICAÇÃO •]")

print("IPs com falhas de login: ")
for ip, quantidade in falhas_por_ip.items():
    print('-', ip, ':', quantidade)

print("Usuários com falhas de login: ")
for user, quantidade in falhas_por_user.items():
    print('-', user, ':', quantidade)

print('IPs com sucesso de login: ')
for ip, quantidade in sucessos_por_ip.items():
    print('-', ip, ':', quantidade)

print('Usuários com sucesso de login: ')
for user, quantidade in sucessos_por_user.items():
    print('-', user, ':', quantidade)


print("\n[• POSSÍVEIS TENTATIVAS DE FORÇA BRUTA •]")
if len(possivel_fb_ip) == 0 and len(possivel_fb_usuario) == 0:
    print('Nenhuma tentativa suspeita identificada.')
else:
    for ip in possivel_fb_ip:
        print('ATENÇÃO: IP SUSPEITO: ', ip, "-", falhas_por_ip[ip], "falhas")
    for user in possivel_fb_usuario:
        print('ATENÇÃO: USUÁRIO SUSPEITO: ', user, "-", falhas_por_user[user], "falhas")

print("\n[• COMPORTAMENTO PARA INVESTIGAÇÃO •]")
print('Usuários associados a múltiplos IPs: ')
for user in usuarios_multiplos_ips:
    print("-", user, ":", ips_por_usuario[user])

print('IPs associados a múltiplos usuários:')
for ip in ips_multiplos_usuarios:
    print('-', ip, ":", usuarios_por_ip[ip])

print('\n[• REGISTROS INCOMPLETOS •]')
if len(registros_incompletos) == 0:
    print("Nenhum registro incompleto encontrado.")
else:
    for registro in registros_incompletos:
        print('-', registro)

print("\n[• EVENTOS DESCONHECIDOS •]")
print(eventos_desconhecidos)

print("\n" + "=" * 40)