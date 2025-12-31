package main

import (
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"

	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
)

type GeoResponse struct {
	Country string `json:"country_name"`
	City    string `json:"city"`
}

var db *sql.DB

func init() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	if err := godotenv.Load(".env"); err != nil {
		log.Println("Не удалось загрузить .env:", err)
	}
}

func main() {
	// 1. Собираем параметры из env
	host := os.Getenv("DB_HOST")
	port := os.Getenv("DB_PORT")
	user := os.Getenv("DB_USER")
	pass := os.Getenv("DB_PASSWORD")
	dbname := os.Getenv("DB_NAME_DB")

	// Если параметры из env есть, пробуем создать базу, если её нет
	if host != "" && dbname != "" {
		err := ensureDatabaseExists(host, port, user, pass, dbname)
		if err != nil {
			log.Println("Warning: Could not ensure database exists:", err)
		}
	}

	// 2. Формируем строку подключения
	envConnStr := os.Getenv("DATABASE_URL")
	if envConnStr == "" && host != "" {
		envConnStr = fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
			host, port, user, pass, dbname,
		)
	}

	// 3. Флаг позволяет переопределить настройки
	connStr := flag.String("db", envConnStr, "Database connection string")
	flag.Parse()

	finalConnStr := *connStr
	if finalConnStr == "" {
		finalConnStr = "postgres://postgres:postgres@localhost/phoenix_data?sslmode=disable"
	}

	var err error
	db, err = sql.Open("postgres", finalConnStr)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	// 4. Создаем таблицу при запуске, если её нет
	err = createTable()
	if err != nil {
		log.Fatal("Failed to create table:", err)
	}

	// 5. Обработчики
	// Эндпоинт для трекинга (вызывается из JS в index.html)
	http.HandleFunc("/track", trackHandler)

	// Раздача статики (все файлы в текущей папке: index.html, img.jpg, style/, js/)
	// Важно: FileServer должен быть последним, так как он "съедает" все пути
	fs := http.FileServer(http.Dir("."))
	http.Handle("/", fs)

	srvPort := os.Getenv("PORT")
	if srvPort == "" {
		srvPort = "8000"
	}

	log.Printf("Server started at http://localhost:%s", srvPort)
	log.Fatal(http.ListenAndServe(":"+srvPort, nil))
}

func ensureDatabaseExists(host, port, user, pass, dbname string) error {
	// Подключаемся к системной базе postgres, чтобы создать нашу базу
	connStr := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=postgres sslmode=disable",
		host, port, user, pass)

	tempDb, err := sql.Open("postgres", connStr)
	if err != nil {
		return err
	}
	defer tempDb.Close()

	var exists bool
	err = tempDb.QueryRow("SELECT EXISTS(SELECT 1 FROM pg_database WHERE datname = $1)", dbname).Scan(&exists)
	if err != nil {
		return err
	}

	if !exists {
		log.Printf("Database %s does not exist. Creating...", dbname)
		_, err = tempDb.Exec(fmt.Sprintf("CREATE DATABASE %s", dbname))
		if err != nil {
			return err
		}
		log.Printf("Database %s created successfully.", dbname)
	}

	return nil
}

func createTable() error {
	query := `
	CREATE TABLE IF NOT EXISTS visits (
		id SERIAL PRIMARY KEY,
		ip VARCHAR(45),
		country TEXT,
		city TEXT,
		user_agent TEXT,
		visited_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);`
	_, err := db.Exec(query)
	return err
}

func getIP(r *http.Request) string {
	// 4️⃣ Получаем реальный IP
	ip := r.Header.Get("X-Forwarded-For")
	if ip != "" {
		return ip
	}

	ip, _, _ = net.SplitHostPort(r.RemoteAddr)
	return ip
}

func getGeo(ip string) (string, string) {
	// Если мы на локальном хосте, GeoIP API не сможет найти адрес.
	// Для тестов подставим какой-нибудь известный IP (например, 8.8.8.8 - Google).
	isLocal := ip == "127.0.0.1" || ip == "::1" || ip == ""
	lookupIP := ip
	if isLocal {
		log.Printf("Local IP detected (%s). Using fallback 8.8.8.8 for testing GeoIP...", ip)
		lookupIP = "8.8.8.8"
	}

	// 5️⃣ GeoIP (ipapi.co)
	resp, err := http.Get(fmt.Sprintf("https://ipapi.co/%s/json/", lookupIP))
	if err != nil {
		log.Printf("GeoIP Request Error: %v", err)
		return "Unknown", "Unknown"
	}
	defer resp.Body.Close()

	var geo GeoResponse
	if err := json.NewDecoder(resp.Body).Decode(&geo); err != nil {
		log.Printf("GeoIP Decode Error: %v", err)
		return "Unknown", "Unknown"
	}

	// Если это был локальный IP, пометим это
	country := geo.Country
	city := geo.City
	if isLocal {
		country = "[Local] " + country
		city = "[Local] " + city
	}

	return country, city
}

func trackHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	ip := getIP(r)
	ua := r.UserAgent()

	// 7️⃣ Защита от спама (интервал 50 минут)
	var exists bool
	err := db.QueryRow(`
		SELECT EXISTS(
			SELECT 1 FROM visits 
			WHERE ip = $1 AND visited_at > NOW() - INTERVAL '50 minutes'
		)
	`, ip).Scan(&exists)

	if err != nil {
		log.Println("DB Check Error:", err)
	}

	if exists {
		log.Printf("Skip tracking for IP %s (already tracked in last 50m)", ip)
		w.WriteHeader(http.StatusAccepted)
		return
	}

	country, city := getGeo(ip)

	// 6️⃣ Сохраняем в БД
	_, err = db.Exec(`
		INSERT INTO visits (ip, country, city, user_agent)
		VALUES ($1, $2, $3, $4)
	`, ip, country, city, ua)

	if err != nil {
		log.Println("DB Insert Error:", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	log.Printf("Tracked visit: %s (%s, %s)", ip, city, country)
	w.WriteHeader(http.StatusOK)
}
