# Use uma versão estável do Python
FROM python:3.11-slim

# Definir o diretório de trabalho
WORKDIR /fourd-abc-poc

# Copiar o arquivo de requirements para instalar dependências
COPY requirements.txt .

# Instalar as dependências
RUN pip install --no-cache-dir --upgrade pip setuptools && \
    pip install --no-cache-dir -r requirements.txt

# Copiar todo o código da aplicação para dentro do contêiner
COPY . .

# Expor a porta que a aplicação Flask vai rodar
EXPOSE 7423

# Comando para rodar a aplicação com Gunicorn
CMD ["gunicorn", "--bind", "0.0.0.0:7423", "main:app"]