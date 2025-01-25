# Bazowy obraz Pythona
FROM python:3.9-slim

# Ustaw katalog roboczy w kontenerze
WORKDIR /app

# Skopiuj pliki projektu do kontenera
COPY . /app

# Instalacja zależności
RUN pip install --no-cache-dir -r requirements.txt

# Otwórz port dla aplikacji Flask
EXPOSE 5000

# Komenda do uruchomienia aplikacji Flask
CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:5000", "run:app"]

