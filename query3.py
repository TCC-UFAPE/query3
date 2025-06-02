import pandas as pd
import os
import re
import glob

path = ''
all_files = glob.glob(os.path.join(path, "*.xlsx"))

if not all_files:
    print(f"AVISO: Nenhum arquivo .xlsx foi encontrado no diretório: '{os.path.abspath(path)}'")
    print(f"Diretório de execução atual: {os.getcwd()}")
    print("\nPor favor, verifique se:")
    print("1. O script Python está na mesma pasta que os arquivos .xlsx OU")
    print("2. A variável 'path' está apontando para o local correto.")
    exit() 

print(f"Encontrados {len(all_files)} arquivos para processar.")

dfs = []

for f in all_files:
    df = pd.read_excel(f, header=1)

    filename = os.path.basename(f)
    model_match = re.search(r'-\s(.*?)\.xlsx', filename)
    model_name = model_match.group(1) if model_match else 'unknown'

    df['identificador_modelo'] = model_name
    df['arquivo_fonte'] = filename

    dfs.append(df)

df_consolidado = pd.concat(dfs, ignore_index=True)

df_consolidado.rename(columns={
    'Arquivo': 'arquivo_java',
    'Código Limpo Analisado': 'codigo_analisado',
    'Resultado da Análise': 'resposta_gerada'
}, inplace=True)


pattern = re.compile(
    r"vulnerability:\s*(?P<flag>YES|NO)\s*\|\s*"
    r"vulnerability\s*type:\s*(?P<tipo_predito>.*?)\s*\|\s*"
    r"(?:vulnerability\s*name|explanation):\s*(?P<explicacao>.*)",
    re.IGNORECASE | re.DOTALL
)

extracted_data = df_consolidado['resposta_gerada'].str.extract(pattern)

df_consolidado = pd.concat([df_consolidado, extracted_data], axis=1)

for col in ['flag', 'tipo_predito', 'explicacao']:
    df_consolidado[col] = df_consolidado[col].str.strip()

securibench_ground_truth = {
    'Aliasing': 'Aliasing',
    'Basic': 'Path Traversal',
    'DataStructures': 'Data Leak',
    'Factories': 'Factory',
    'Inter': 'Path Traversal',
    'Predicates': 'Path Traversal',
    'Sanitizers': 'Path Traversal',
    'Scenarios': ['SQL Injection', 'XSS'],
    'Session': 'Session Fixation',
    'StrongUpdates': 'Path Traversal'
}

def get_official_vulnerability(filepath):
    if not isinstance(filepath, str):
        return 'Unknown'
    category = filepath.split('/')[0]
    return securibench_ground_truth.get(category, 'Benign')

df_consolidado['tipo_oficial'] = df_consolidado['arquivo_java'].apply(get_official_vulnerability)


official_types = df_consolidado['tipo_oficial'].explode().dropna().unique()
predicted_types = df_consolidado['tipo_predito'].dropna().unique()

vulnerabilities_of_interest = set([
    'SQL Injection', 'XSS', 'Path Traversal', 'Command Injection',
    'Data Leak', 'Session Fixation', 'Aliasing'
])
all_vuln_types = vulnerabilities_of_interest.union(set(official_types)).union(set(predicted_types))
all_vuln_types.discard('N/A')
all_vuln_types.discard('n/a')
all_vuln_types.discard('Benign')


for vuln in sorted(list(all_vuln_types)):
    vuln_col_name = vuln.replace(' ', '_').upper() 

    df_consolidado[f'real_tem_{vuln_col_name}'] = df_consolidado['tipo_oficial'].apply(
        lambda x: vuln in x if isinstance(x, list) else x == vuln
    )

    df_consolidado[f'pred_tem_{vuln_col_name}'] = df_consolidado['tipo_predito'].str.contains(vuln, case=False, na=False)

colunas_para_exibir = [
    'identificador_modelo',
    'arquivo_java',
    'flag',
    'tipo_predito',
    'tipo_oficial'
]

colunas_para_exibir.extend(sorted([col for col in df_consolidado if col.startswith('real_') or col.startswith('pred_')]))


print("Pré-processamento concluído com sucesso!")
print("\nAmostra do DataFrame final (5 primeiras linhas):")
print(df_consolidado[colunas_para_exibir].head()) 

print("\nResumo do DataFrame:")
df_consolidado[colunas_para_exibir].info()

print("\nSalvando o DataFrame consolidado em 'relatorio_consolidado.csv'...")
df_consolidado.to_csv('relatorio_consolidado.csv', index=False, encoding='utf-8-sig')
print("Arquivo salvo com sucesso!")