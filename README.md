# SecureNotes - Bezpieczna Aplikacja do Zarządzania Notatkami

## Opis Projektu

SecureNotes to zaawansowana aplikacja webowa do bezpiecznego zarządzania notatkami, zbudowana z wykorzystaniem Flask i najnowszych standardów bezpieczeństwa. Aplikacja oferuje kompleksową ochronę danych użytkowników poprzez szyfrowanie, podpisy cyfrowe oraz wielopoziomowe mechanizmy uwierzytelniania.

![SecureNotes](homepage.png)

## Główne Funkcjonalności

### 🔐 Bezpieczeństwo
- **Szyfrowanie AES**: Notatki mogą być szyfrowane kluczem globalnym
- **Podpisy cyfrowe RSA**: Weryfikacja integralności i autentyczności notatek
- **Uwierzytelnianie dwuskładnikowe (TOTP)**: Dodatkowa warstwa zabezpieczeń
- **Bezpieczne hasła**: Walidacja siły hasła z wymaganiami złożoności
- **Ochrona przed atakami brute-force**: Ograniczenie liczby prób logowania
- **CSRF Protection**: Ochrona przed atakami Cross-Site Request Forgery
- **Content Security Policy**: Zabezpieczenie przed atakami XSS

### 📝 Zarządzanie Notatkami
- **Tworzenie i edycja**: Intuicyjny edytor z obsługą Markdown
- **Udostępnianie**: Możliwość udostępniania notatek innym użytkownikom
- **Notatki publiczne**: Opcja publikowania notatek dla wszystkich
- **Podgląd HTML**: Automatyczna konwersja Markdown do HTML z filtrowaniem
- **Weryfikacja podpisów**: Sprawdzanie autentyczności notatek

### 👤 Zarządzanie Użytkownikami
- **Rejestracja z walidacją**: Kompleksowa weryfikacja danych
- **Reset hasła**: Bezpieczny mechanizm resetowania przez email
- **Profil użytkownika**: Zarządzanie ustawieniami TOTP
- **Śledzenie logowań**: Powiadomienia o logowaniu z nowych adresów IP

## Architektura Techniczna

### Backend
- **Framework**: Flask 3.1.0
- **Baza danych**: SQLAlchemy z SQLite
- **Kryptografia**: Python Cryptography Library
- **Uwierzytelnianie**: Flask-Login + PyOTP
- **Formularze**: Flask-WTF z walidacją
- **Email**: SMTP z Gmail

### Frontend
- **Templating**: Jinja2
- **Styling**: Custom CSS z ciemnym motywem
- **Responsywność**: Mobile-friendly design
- **Markdown**: Renderowanie z syntax highlighting

### DevOps i Deployment
- **Konteneryzacja**: Docker + Docker Compose
- **Reverse Proxy**: Nginx z SSL/TLS
- **HTTPS**: Certyfikaty SSL (localhost i publiczny IP)
- **Środowisko**: Konfiguracja przez zmienne środowiskowe

## Instalacja i Uruchomienie

### Wymagania
- Python 3.9+
- Docker i Docker Compose
- Git

### Klonowanie repozytorium
```bash
git clone <repository-url>
cd secure_notes
```

### Konfiguracja środowiska
1. Skopiuj i edytuj plik `.env`:
```bash
cp .env.example .env
```

2. Skonfiguruj zmienne w pliku [`.env`](.env):
```env
SECRET_KEY=your_super_secret_key
DATABASE_URL=sqlite:///site.db
MAIL_SERVER=smtp.gmail.com
MAIL_PORT=587
MAIL_USERNAME=your_email@gmail.com
MAIL_PASSWORD=your_app_password
MAIL_FROM=your_email@gmail.com
LOGIN_ATTEMPT_LIMIT=5
LOGIN_DELAY=1
GLOBAL_ENCRYPTION_KEY=16bytesSecretKey
```

### Uruchomienie z Docker
```bash
# Zbuduj i uruchom kontenery
docker-compose up --build

# Aplikacja będzie dostępna pod adresem:
# HTTP: http://localhost:80 (przekierowanie na HTTPS)
# HTTPS: https://localhost:443
```

### Uruchomienie lokalne (development)
```bash
# Zainstaluj zależności
pip install -r requirements.txt

# Uruchom aplikację
python run.py
```

## Struktura Projektu

```
secure_notes/
├── secure_notes/                 # Główny pakiet aplikacji
│   ├── __init__.py              # Konfiguracja Flask i modele bazy danych
│   ├── app.py                   # Punkt wejścia aplikacji
│   ├── forms.py                 # Formularze WTF z walidacją
│   ├── routes/                  # Blueprinty aplikacji
│   │   ├── auth.py             # Uwierzytelnianie i autoryzacja
│   │   ├── notes.py            # Zarządzanie notatkami
│   │   └── main.py             # Główne strony
│   ├── static/                  # Pliki statyczne
│   │   └── style.css           # Style CSS
│   └── templates/               # Szablony HTML
│       ├── base.html           # Szablon bazowy
│       ├── login.html          # Strona logowania
│       ├── register.html       # Rejestracja
│       ├── notes.html          # Lista notatek
│       └── ...                 # Inne szablony
├── certs/                       # Certyfikaty SSL
├── instance/                    # Instancja bazy danych
├── docker-compose.yml           # Konfiguracja Docker Compose
├── Dockerfile                   # Definicja kontenera
├── nginx.conf                   # Konfiguracja Nginx
├── requirements.txt             # Zależności Python
├── run.py                      # Punkt uruchomienia
└── .env                        # Zmienne środowiskowe
```

## Bezpieczeństwo - Szczegóły Implementacji

### Szyfrowanie Notatek
- **Algorytm**: AES-256 w trybie CFB
- **Klucz**: Globalny klucz szyfrowania z PBKDF2
- **IV**: Statyczny wektor inicjalizacyjny (16 bajtów)

### Podpisy Cyfrowe
- **Algorytm**: RSA-2048 z PSS padding
- **Hash**: SHA-256
- **Weryfikacja**: Automatyczna przy wyświetlaniu notatek

### Klucze Użytkowników
- **Generowanie**: RSA-2048 par kluczy dla każdego użytkownika
- **Przechowywanie**: Klucz prywatny szyfrowany hasłem użytkownika
- **Solenie**: Unikalne salt dla każdego klucza

### Ochrona Haseł
- **Hashing**: Werkzeug PBKDF2 z SHA-256
- **Salt**: Losowy 16-bajtowy salt dla każdego hasła
- **Walidacja**: Minimalna długość, znaki specjalne, cyfry, wielkie/małe litery

## API i Endpointy

### Uwierzytelnianie (`/auth`)
- `GET/POST /auth/login` - Logowanie użytkownika
- `GET/POST /auth/register` - Rejestracja nowego użytkownika
- `GET /auth/logout` - Wylogowanie
- `GET/POST /auth/profile` - Zarządzanie profilem
- `GET /auth/show_qr/<username>` - Wyświetlanie kodu QR dla TOTP
- `GET/POST /auth/forgot` - Reset hasła
- `GET/POST /auth/reset/<token>` - Potwierdzenie resetu hasła

### Notatki (`/notes`)
- `GET/POST /notes/` - Lista notatek i dodawanie nowych
- `GET/POST /notes/edit/<id>` - Edycja notatki
- `GET/POST /notes/share/<id>` - Udostępnianie notatki
- `GET /notes/public` - Publiczne notatki

### Główne (`/`)
- `GET /` - Strona główna
- `GET /static/<filename>` - Pliki statyczne

## Konfiguracja Produkcyjna

### Nginx SSL
Aplikacja zawiera gotową konfigurację Nginx z obsługą SSL/TLS:
- Automatyczne przekierowanie HTTP → HTTPS
- Obsługa plików statycznych
- Proxy dla aplikacji Flask
- Gotowe certyfikaty dla localhost i publicznego IP

### Zmienne Środowiskowe
Wszystkie wrażliwe dane konfigurowane przez zmienne środowiskowe:
- Klucze szyfrowania
- Dane SMTP
- Ustawienia bazy danych
- Limity bezpieczeństwa

### Docker Deployment
```bash
# Produkcyjne uruchomienie
docker-compose -f docker-compose.yml up -d

# Monitoring logów
docker-compose logs -f

# Aktualizacja
docker-compose pull && docker-compose up -d
```

## Testowanie

### Testy Bezpieczeństwa
1. **Weryfikacja szyfrowania**: Test kompletnego cyklu szyfrowania/deszyfrowania
2. **Podpisy cyfrowe**: Weryfikacja integralności podpisów
3. **Uwierzytelnianie**: Test mechanizmów logowania i TOTP
4. **Walidacja**: Test walidacji formularzy i danych wejściowych

### Testy Funkcjonalne
1. **CRUD notatek**: Tworzenie, odczyt, aktualizacja, usuwanie
2. **Udostępnianie**: Test mechanizmów udostępniania
3. **Responsive design**: Test na różnych urządzeniach

## Troubleshooting

### Typowe Problemy

**Błąd certyfikatu SSL:**
```bash
# Regeneracja certyfikatów
openssl req -x509 -newkey rsa:4096 -keyout certs/localhost.key -out certs/localhost.crt -days 365 -nodes
```

**Problemy z bazą danych:**
```bash
# Reset bazy danych
rm instance/site.db
# Aplikacja automatycznie utworzy nową bazę przy starcie
```

**Błędy SMTP:**
- Sprawdź czy używasz App Password dla Gmail
- Weryfikuj ustawienia SMTP w `.env`

## Roadmapa

- [ ] **API REST**: Pełne API dla aplikacji mobilnych
- [ ] **Współdzielenie zespołowe**: Grupy użytkowników i uprawnienia
- [ ] **Backup**: Automatyczne kopie zapasowe
- [ ] **Audyt**: Logi działań użytkowników
- [ ] **Mobile App**: Dedykowana aplikacja mobilna
- [ ] **Advanced Search**: Wyszukiwanie pełnotekstowe
- [ ] **File Attachments**: Obsługa załączników

## Licencja

Projekt udostępniony na licencji MIT.

## Autor

Stworzony jako projekt edukacyjny demonstrujący zaawansowane techniki bezpieczeństwa aplikacji webowych.

---

**⚠️ Ostrzeżenie**: Ta aplikacja została stworzona w celach edukacyjnych. Przed użyciem w środowisku produkcyjnym zaleca się przeprowadzenie pełnego audytu bezpieczeństwa.
