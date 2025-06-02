# Scegli un'immagine Python base. Python 3.11 o 3.12 slim è una buona scelta.
# Verifica la disponibilità di immagini per Python 3.13 se quella è la tua versione di sviluppo.
FROM python:3.11-slim-bookworm

# Imposta la directory di lavoro all'interno del container
WORKDIR /app

# Copia il file dei requisiti e installa le dipendenze
# Questo passaggio viene fatto prima per sfruttare la cache di Docker se i requisiti non cambiano
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Copia il resto dei file dell'applicazione nella directory di lavoro del container
COPY . .

# Imposta la variabile d'ambiente per il percorso del database SQLite
# Così possiamo facilmente montare un volume per la persistenza dei dati.
ENV DATABASE_FILE_PATH=/data/dhcp_server_data.db

# Esponi la porta per l'interfaccia web Flask
EXPOSE 5000

# Esponi la porta per il server DHCP (UDP)
EXPOSE 67/udp
# La porta 68/udp è usata dai client per rispondere al server,
# ma il server non si mette in ascolto su di essa.
# EXPOSE 68/udp # Solitamente non necessario esporla per il server

# Comando per avviare l'applicazione quando il container parte
# Assicura che init_db() venga chiamato all'avvio se il DB non esiste nel volume
CMD ["python", "app.py"]