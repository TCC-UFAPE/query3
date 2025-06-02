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
    print(f"Processando arquivo: {f}...")
    try:
        df = pd.read_excel(f, header=1)

        filename = os.path.basename(f)
        model_match = re.search(r'-\s(.*?)\.xlsx', filename)
        model_name = model_match.group(1) if model_match else 'unknown_model'

        df['identificador_modelo'] = model_name
        df['arquivo_fonte'] = filename

        dfs.append(df)
    except Exception as e:
        print(f"Erro ao processar o arquivo {f}: {e}")
        continue


if not dfs:
    print("Nenhum DataFrame foi carregado. Verifique os arquivos Excel e os logs de erro.")
    exit()

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
    if col in df_consolidado.columns:
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
    try:
        category = filepath.split('/')[0]
        return securibench_ground_truth.get(category, 'Benign')
    except IndexError:
        return 'Benign'

df_consolidado['tipo_oficial'] = df_consolidado['arquivo_java'].apply(get_official_vulnerability)

official_types_flat = []
for item in df_consolidado['tipo_oficial'].dropna():
    if isinstance(item, list):
        official_types_flat.extend(item)
    else:
        official_types_flat.append(item)
unique_official_types = set(official_types_flat)
unique_predicted_types = df_consolidado['tipo_predito'].dropna().unique()

vulnerabilities_of_interest = {
    'SQL Injection', 'XSS', 'Path Traversal', 'Command Injection',
    'Data Leak', 'Session Fixation', 'Aliasing', 'Factory'
}

all_vuln_types = vulnerabilities_of_interest.union(unique_official_types).union(set(unique_predicted_types))
for benign_indicator in ['N/A', 'n/a', 'Benign', 'Unknown', 'None', 'Not applicable', 'No vulnerability', 'No specific vulnerability type', 'Non vulnerable', 'Secure', 'No direct vulnerability', 'No vulnerability detected', 'Safe', 'None.', 'none', 'no', 'not_applicable', 'not vulnerable', 'no specific vulnerability type', 'non vulnerable', 'no direct vulnerability', 'no vulnerability detected', 'safe', 'none.']:
    all_vuln_types.discard(benign_indicator)
    all_vuln_types.discard(benign_indicator.lower())
    all_vuln_types.discard(benign_indicator.capitalize())

for vuln in sorted(list(all_vuln_types)):
    if not vuln or pd.isna(vuln): 
        continue
    vuln_col_name = str(vuln).replace(' ', '_').replace('-', '_').upper()


    df_consolidado[f'real_tem_{vuln_col_name}'] = df_consolidado['tipo_oficial'].apply(
        lambda x: vuln in x if isinstance(x, list) else x == vuln
    )

    df_consolidado[f'pred_tem_{vuln_col_name}'] = df_consolidado['tipo_predito'].fillna('').astype(str).str.contains(str(vuln), case=False, na=False, regex=True)

colunas_para_exibir = [
    'identificador_modelo',
    'arquivo_fonte', 
    'arquivo_java',
    'flag',
    'tipo_predito',
    'tipo_oficial',
    'explicacao' 
]

colunas_bool_vuln = sorted([col for col in df_consolidado.columns if col.startswith('real_tem_') or col.startswith('pred_tem_')])
colunas_para_exibir.extend(colunas_bool_vuln)

colunas_para_exibir_existentes = [col for col in colunas_para_exibir if col in df_consolidado.columns]


print("\nPré-processamento concluído com sucesso!")

if not df_consolidado.empty:
    print("\nAmostra do DataFrame final (5 primeiras linhas):")
    print(df_consolidado[colunas_para_exibir_existentes].head())

    print("\nResumo do DataFrame:")
    df_consolidado[colunas_para_exibir_existentes].info()

    output_filename = 'relatorio_consolidado.csv'
    try:
        df_consolidado.to_csv(output_filename, index=False, encoding='utf-8-sig', sep=';')
        print(f"\nArquivo salvo com sucesso como '{output_filename}' no diretório '{os.getcwd()}'!")
        print("Este arquivo deve abrir formatado corretamente no Excel.")
    except Exception as e:
        print(f"Erro ao salvar o arquivo CSV: {e}")
else:
    print("\nO DataFrame consolidado está vazio. Nenhum arquivo CSV foi gerado.")
