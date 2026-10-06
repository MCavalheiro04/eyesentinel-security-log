# EyeSentinel — Security Log Analyzer

Ferramenta em Python para análise de logs de autenticação, projetada para auxiliar analistas de segurança na triagem inicial de eventos suspeitos — identificando padrões de força bruta, correlacionando identidade e origem, e sinalizando comportamentos que merecem investigação, sem nunca afirmar automaticamente que algo é um ataque confirmado.

## Filosofia do projeto

Ferramentas de segurança mal calibradas tendem a dois extremos: alertar demais (gerando fadiga de alerta, onde analistas passam a ignorar avisos) ou alertar de menos (deixando passar ameaças reais). O EyeSentinel foi desenhado em torno de um princípio central:

> O sistema não deve afirmar que algo é um ataque quando os dados não permitem essa conclusão. Seu papel é identificar, correlacionar, detectar padrões e sinalizar — priorizando para investigação humana, nunca substituindo o julgamento do analista.

Por isso, o relatório distingue explicitamente entre **fatos objetivos** (contagens, correlações), **sinais que merecem atenção** (múltiplas associações usuário/IP) e **possíveis ameaças** (padrões consistentes com força bruta) — sem misturar essas categorias em um único "alerta genérico".

## O que o programa faz

- Lê um arquivo de log de autenticação, linha por linha, tolerando registros malformados sem interromper a análise
- Classifica cada evento em um de quatro tipos: login com sucesso, login com falha, acesso negado, ou evento desconhecido
- Conta falhas e sucessos, agrupados por IP e por usuário
- Correlaciona identidade e origem: para cada usuário, quais IPs ele utilizou; para cada IP, quais usuários o utilizaram
- Identifica possíveis tentativas de força bruta (5 ou mais falhas de autenticação por IP ou por usuário)
- Sinaliza comportamentos para investigação: usuários associados a múltiplos IPs, e IPs associados a múltiplos usuários
- Classifica cada seção do relatório segundo uma severidade formal (Informação, Suspeita, Investigação, Incompleto, Desconhecido), facilitando a priorização por quem lê o relatório
- Gera um relatório final único, organizado por seção, no terminal

## Formato de log esperado

```
2026-09-09 08:14:22 | LOGIN_SUCCESS | user=matheus | ip=192.168.1.10 | resource=/dashboard
2026-09-09 08:19:43 | LOGIN_FAILED | user=carlos | ip=192.168.1.35 | resource=/login
2026-09-09 08:21:17 | ACCESS_DENIED | user=guest | ip=192.168.1.35 | resource=/reports
```

Cada linha segue o padrão: `DATA HORA | EVENTO | user=<usuário> | ip=<ip> | resource=<recurso>`, separados por `|`.

## Tratamento de dados malformados

Logs de produção raramente são perfeitos. O EyeSentinel foi testado deliberadamente contra três categorias de anomalia, cada uma tratada de forma distinta:

- **Linhas estruturalmente quebradas** (sem os campos esperados, ou sem separador algum): capturadas via tratamento de exceção, registradas na lista de registros incompletos, sem interromper o processamento do restante do arquivo
- **Linhas bem formadas com tipo de evento não reconhecido** (ex: `EVENT_UNKNOWN`): identificadas e contabilizadas separadamente, sem serem confundidas com dado corrompido
- **Linhas com campos ausentes mas parcialmente legíveis**: também tratadas como registros incompletos, preservando o conteúdo original para análise manual posterior

## Como rodar

```bash
python eyesentinel.py
```

Por padrão, o script lê `security_logs.txt` na mesma pasta.

## Exemplo de saída

```
========================================
EYESENTINEL - SECURITY LOG
========================================

[• RESUMO DE AUTENTICAÇÃO •]
IPs com falhas de login: 
- 203.0.113.42 : 15
...

[• POSSÍVEIS TENTATIVAS DE FORÇA BRUTA •]
ATENÇÃO: IP SUSPEITO:  203.0.113.42 - 15 falhas
ATENÇÃO: USUÁRIO SUSPEITO:  admin - 16 falhas

[• COMPORTAMENTO PARA INVESTIGAÇÃO •]
Usuários associados a múltiplos IPs: 
- guest : ['192.168.1.35', '10.0.0.15', '203.0.113.42', '10.0.0.25']
...
========================================
```

## O que este projeto exercitou

- Leitura e parsing de arquivos de log com formato delimitado por caractere customizado (`|`)
- Tratamento de exceções para tornar o processamento resiliente a dados malformados, com categorização diferenciada de tipos de anomalia
- Estruturas de decisão em cascata (`if`/`elif`/`else`) para classificação exaustiva de tipos de evento
- Dicionários de contagem (chave → valor numérico) para agregação de dados por IP e por usuário
- Dicionários de correlação (chave → lista) para modelar relações um-para-muitos entre usuários e origens de acesso
- Separação entre construção de dados (dentro de um loop) e apresentação de resultados (após o loop terminar) — e o debugging de bugs sutis causados por posicionamento incorreto de `print()` dentro de blocos de repetição
- Design de relatório: organização por seção, tratamento de listas vazias com mensagens explícitas, e o princípio de não apresentar dado ausente como "ataque não encontrado"

## Tecnologias

- Python 3.14 (apenas biblioteca padrão, sem dependências externas)

## Possíveis evoluções futuras

- Refatorar a lógica repetida de "incrementar contagem em dicionário" em uma função reutilizável
- Detecção de força bruta sensível a janela de tempo (ex: 5 falhas em menos de 1 minuto), não apenas contagem total acumulada
- Exportação do relatório em formato JSON ou HTML
- Interface web (Flask), substituindo a saída de terminal por um dashboard navegável
