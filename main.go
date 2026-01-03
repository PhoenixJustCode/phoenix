package main

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
)

type GeoResponse struct {
	Country string `json:"country_name"`
	City    string `json:"city"`
}

type Visit struct {
	ID        int       `json:"id"`
	IP        string    `json:"ip"`
	Country   string    `json:"country"`
	City      string    `json:"city"`
	UA        string    `json:"user_agent"`
	VisitedAt time.Time `json:"visited_at"`
}

var db *sql.DB

func init() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	if err := godotenv.Load(".env"); err != nil {
		log.Println("Не удалось загрузить .env:", err)
	}
}

func main() {
	host := os.Getenv("DB_HOST")
	port := os.Getenv("DB_PORT")
	user := os.Getenv("DB_USER")
	pass := os.Getenv("DB_PASSWORD")
	dbname := os.Getenv("DB_NAME_DB")

	if host != "" && dbname != "" {
		err := ensureDatabaseExists(host, port, user, pass, dbname)
		if err != nil {
			log.Println("Warning: Could not ensure database exists:", err)
		}
	}

	envConnStr := os.Getenv("DATABASE_URL")
	if envConnStr == "" && host != "" {
		envConnStr = fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
			host, port, user, pass, dbname,
		)
	}

	connStr := flag.String("db", envConnStr, "Database connection string")
	createAdmin := flag.Bool("create-admin", false, "Create an admin user and exit")
	adminUser := flag.String("user", "admin", "Admin username")
	adminPass := flag.String("pass", "", "Admin password")
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

	err = createTables()
	if err != nil {
		log.Fatal("Failed to create tables:", err)
	}

	// Check if any admin exists
	var adminCount int
	_ = db.QueryRow("SELECT COUNT(*) FROM admins").Scan(&adminCount)
	if adminCount == 0 {
		log.Println("WARNING: No admin users found in database! Use '-create-admin -user ... -pass ...' to create one.")
	}

	if *createAdmin {
		if *adminPass == "" {
			log.Fatal("Please provide a password using -pass")
		}
		hash := hashPassword(*adminPass)
		_, err = db.Exec("INSERT INTO admins (username, password_hash) VALUES ($1, $2) ON CONFLICT (username) DO UPDATE SET password_hash = $2", *adminUser, hash)
		if err != nil {
			log.Fatal("Failed to create admin:", err)
		}
		log.Printf("Admin user '%s' created/updated successfully.", *adminUser)
		return
	}

	// Handlers
	http.HandleFunc("/track", trackHandler)
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/logout", logoutHandler)
	http.HandleFunc("/api/visits", apiVisitsHandler)

	fs := http.FileServer(http.Dir("."))
	http.Handle("/", safeStaticServer(fs))

	srvPort := os.Getenv("PORT")
	if srvPort == "" {
		srvPort = "8000"
	}

	log.Printf("Server started at http://localhost:%s", srvPort)
	log.Fatal(http.ListenAndServe(":"+srvPort, nil))
}

func ensureDatabaseExists(host, port, user, pass, dbname string) error {
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

func createTables() error {
	queries := []string{
		`CREATE TABLE IF NOT EXISTS visits (
			id SERIAL PRIMARY KEY,
			ip VARCHAR(45),
			country TEXT,
			city TEXT,
			user_agent TEXT,
			visited_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);`,
		`CREATE TABLE IF NOT EXISTS admins (
			id SERIAL PRIMARY KEY,
			username TEXT UNIQUE NOT NULL,
			password_hash TEXT NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS sessions (
			token TEXT PRIMARY KEY,
			username TEXT NOT NULL,
			expires_at TIMESTAMP NOT NULL
		);`,
		`CREATE INDEX IF NOT EXISTS idx_visits_visited_at ON visits(visited_at DESC);`,
	}

	for _, q := range queries {
		if _, err := db.Exec(q); err != nil {
			return err
		}
	}
	return nil
}

func getIP(r *http.Request) string {
	ip := r.Header.Get("X-Forwarded-For")
	if ip != "" {
		return ip
	}

	ip, _, _ = net.SplitHostPort(r.RemoteAddr)
	return ip
}

func getGeo(ip string) (string, string) {
	isLocal := ip == "127.0.0.1" || ip == "::1" || ip == ""
	lookupIP := ip
	if isLocal {
		lookupIP = "8.8.8.8"
	}

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(fmt.Sprintf("https://ipapi.co/%s/json/", lookupIP))
	if err != nil {
		log.Printf("GeoIP Network Error for %s: %v", lookupIP, err)
		return "Unknown", "Unknown"
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("GeoIP API Error for %s: Status %d", lookupIP, resp.StatusCode)
		return "Rate Limited", "Unknown"
	}

	var geo GeoResponse
	if err := json.NewDecoder(resp.Body).Decode(&geo); err != nil {
		log.Printf("GeoIP JSON Error for %s: %v", lookupIP, err)
		return "Unknown", "Unknown"
	}

	country := geo.Country
	if country == "" {
		country = "Unknown"
	}
	city := geo.City
	if city == "" {
		city = "Unknown"
	}

	if isLocal {
		country = "[Local] " + country
		city = "[Local] " + city
	}

	return country, city
}

func trackHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		// Prevent caching so the browser doesn't show the login page after successful login
		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("Expires", "0")

		go recordVisit(r)
		_, err := r.Cookie("session_token")
		log.Printf("GET /track - Cookie presence: %v", err == nil)
		loggedIn := checkSession(r)
		log.Printf("GET /track - LoggedIn: %v", loggedIn)
		if loggedIn {
			http.ServeFile(w, r, "admin.html")
		} else {
			http.ServeFile(w, r, "login.html")
		}
		return
	}

	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	recordVisit(r)
	w.WriteHeader(http.StatusOK)
}

func recordVisit(r *http.Request) {
	ip := getIP(r)
	ua := r.UserAgent()

	// Spam protection (50 minutes)
	var exists bool
	err := db.QueryRow(`
		SELECT EXISTS(
			SELECT 1 FROM visits 
			WHERE ip = $1 AND visited_at > NOW() - INTERVAL '50 minutes'
		)
	`, ip).Scan(&exists)

	if err == nil && exists {
		log.Printf("Skip tracking for IP %s (already tracked in last 50m)", ip)
		return
	}

	country, city := getGeo(ip)

	_, err = db.Exec(`
		INSERT INTO visits (ip, country, city, user_agent)
		VALUES ($1, $2, $3, $4)
	`, ip, country, city, ua)

	if err != nil {
		log.Printf("DB Insert Error for IP %s: %v", ip, err)
		return
	}

	log.Printf("Tracked visit: %s (%s, %s)", ip, city, country)
}

func hashPassword(password string) string {
	hash := sha256.Sum256([]byte(password))
	return hex.EncodeToString(hash[:])
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var creds struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
		log.Printf("Login Decode Error: %v", err)
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	log.Printf("Login attempt for user: %s", creds.Username)

	var dbHash string
	err := db.QueryRow("SELECT password_hash FROM admins WHERE username = $1", creds.Username).Scan(&dbHash)
	if err != nil {
		if err == sql.ErrNoRows {
			log.Printf("Login Failed: User '%s' not found in database", creds.Username)
		} else {
			log.Printf("Login DB Error: %v", err)
		}
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	inputHash := hashPassword(creds.Password)
	if dbHash != inputHash {
		log.Printf("Login Failed: Incorrect password for user '%s'", creds.Username)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	log.Printf("Login Successful: %s", creds.Username)

	token := hex.EncodeToString([]byte(fmt.Sprintf("%d%s", time.Now().UnixNano(), creds.Username)))
	expires := time.Now().Add(24 * time.Hour)

	_, err = db.Exec("INSERT INTO sessions (token, username, expires_at) VALUES ($1, $2, $3)", token, creds.Username, expires)
	if err != nil {
		log.Printf("Session DB Insert Error: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    token,
		MaxAge:   86400, // 24 hours
		HttpOnly: true,
		Path:     "/",
	})

	w.WriteHeader(http.StatusOK)
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session_token")
	if err == nil {
		_, _ = db.Exec("DELETE FROM sessions WHERE token = $1", cookie.Value)
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    "",
		Expires:  time.Now().Add(-1 * time.Hour),
		HttpOnly: true,
		Path:     "/",
	})
	http.Redirect(w, r, "/track", http.StatusSeeOther)
}

func checkSession(r *http.Request) bool {
	cookie, err := r.Cookie("session_token")
	if err != nil {
		return false
	}

	var expiresAt time.Time
	err = db.QueryRow("SELECT expires_at FROM sessions WHERE token = $1", cookie.Value).Scan(&expiresAt)
	if err != nil {
		if err != sql.ErrNoRows {
			log.Printf("Session DB Error: %v", err)
		}
		return false
	}

	return expiresAt.After(time.Now())
}

// Custom handler to protect sensitive files
func safeStaticServer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Block direct access to admin.html and login.html
		if r.URL.Path == "/admin.html" || r.URL.Path == "/login.html" {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func apiVisitsHandler(w http.ResponseWriter, r *http.Request) {
	if !checkSession(r) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	limitStr := r.URL.Query().Get("limit")
	limit, _ := strconv.Atoi(limitStr)
	if limit <= 0 {
		limit = 10
	}

	offsetStr := r.URL.Query().Get("offset")
	offset, _ := strconv.Atoi(offsetStr)

	search := r.URL.Query().Get("search")

	query := `SELECT id, ip, country, city, user_agent, visited_at FROM visits`
	args := []interface{}{}
	if search != "" {
		query += ` WHERE ip ILIKE $1 OR country ILIKE $1 OR city ILIKE $1`
		args = append(args, "%"+search+"%")
		query += ` ORDER BY visited_at DESC LIMIT $2 OFFSET $3`
		args = append(args, limit, offset)
	} else {
		query += ` ORDER BY visited_at DESC LIMIT $1 OFFSET $2`
		args = append(args, limit, offset)
	}

	rows, err := db.Query(query, args...)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var visits []Visit
	for rows.Next() {
		var v Visit
		if err := rows.Scan(&v.ID, &v.IP, &v.Country, &v.City, &v.UA, &v.VisitedAt); err != nil {
			continue
		}
		visits = append(visits, v)
	}

	var total int
	countQuery := "SELECT COUNT(*) FROM visits"
	if search != "" {
		_ = db.QueryRow(countQuery+" WHERE ip ILIKE $1 OR country ILIKE $1 OR city ILIKE $1", "%"+search+"%").Scan(&total)
	} else {
		_ = db.QueryRow(countQuery).Scan(&total)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"visits": visits,
		"total":  total,
		"my_ip":  getIP(r),
	})
}
