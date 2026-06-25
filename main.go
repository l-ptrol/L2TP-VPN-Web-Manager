package main

import (
	_ "embed"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"runtime"
)

//go:embed index.html
var indexHTML []byte

func main() {
	portFlag := flag.Int("port", 0, "Web server port")
	configFlag := flag.String("config", "", "Path to config file")
	flag.Parse()

	configPath := "/opt/etc/l2tp_vpn_config.json"
	if runtime.GOOS == "windows" {
		configPath = "./l2tp_vpn_config.json"
	}
	if *configFlag != "" {
		configPath = *configFlag
	}

	defaultPort := 8081
	if *portFlag > 0 {
		defaultPort = *portFlag
	}

	// Initialize manager
	manager = initManager(defaultPort, configPath)

	// If the port flag was explicitly set, overwrite and save config port
	if *portFlag > 0 && manager.config.WebPort != *portFlag {
		manager.config.WebPort = *portFlag
		_ = manager.SaveConfig()
	}

	manager.ResumeMonitoring()
	manager.TriggerAutostart()

	log.Printf("[L2TP] Starting Manager Web Interface...")
	
	// API Endpoints
	http.HandleFunc("/", handleIndex)
	http.HandleFunc("/api/profiles", handleGetProfiles)
	http.HandleFunc("/api/profiles/add", handleAddProfile)
	http.HandleFunc("/api/profiles/edit", handleEditProfile)
	http.HandleFunc("/api/profiles/delete", handleDeleteProfile)
	http.HandleFunc("/api/profiles/start", handleStartProfile)
	http.HandleFunc("/api/profiles/stop", handleStopProfile)
	http.HandleFunc("/api/status", handleStatus)
	http.HandleFunc("/api/logs", handleLogs)
	http.HandleFunc("/api/interfaces", handleGetInterfaces)

	lanIP := getLANIP()
	listenAddr := fmt.Sprintf("%s:%d", lanIP, manager.config.WebPort)
	log.Printf("[L2TP] Web server listening on http://%s", listenAddr)

	if err := http.ListenAndServe(listenAddr, nil); err != nil {
		log.Fatalf("[L2TP] Failed to start web server: %v", err)
	}
}

func handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(indexHTML)
}

func handleGetProfiles(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	profiles := manager.GetProfiles()
	_ = json.NewEncoder(w).Encode(profiles)
}

func handleAddProfile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var p ConnectionProfile
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if p.Name == "" || p.Server == "" || p.Username == "" || p.Password == "" {
		http.Error(w, "Missing required fields (Name, Server, Username, Password)", http.StatusBadRequest)
		return
	}

	manager.AddProfile(p)
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"status":"success"}`))
}

func handleEditProfile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var p ConnectionProfile
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if p.ID == "" || p.Name == "" || p.Server == "" || p.Username == "" || p.Password == "" {
		http.Error(w, "Missing required fields", http.StatusBadRequest)
		return
	}

	if manager.EditProfile(p) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"success"}`))
	} else {
		http.Error(w, "Profile not found", http.StatusNotFound)
	}
}

type idRequest struct {
	ID string `json:"id"`
}

func handleDeleteProfile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req idRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if manager.DeleteProfile(req.ID) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"success"}`))
	} else {
		http.Error(w, "Profile not found", http.StatusNotFound)
	}
}

func handleStartProfile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req idRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	err := manager.StartTunnel(req.ID)
	w.Header().Set("Content-Type", "application/json")
	if err != nil {
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "error", "message": err.Error()})
	} else {
		_, _ = w.Write([]byte(`{"status":"success"}`))
	}
}

func handleStopProfile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	err := manager.StopTunnel()
	w.Header().Set("Content-Type", "application/json")
	if err != nil {
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "error", "message": err.Error()})
	} else {
		_, _ = w.Write([]byte(`{"status":"success"}`))
	}
}

func handleStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	status := manager.GetStatus()
	_ = json.NewEncoder(w).Encode(status)
}

func handleLogs(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	logs, err := manager.GetLogs()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_ = json.NewEncoder(w).Encode(logs)
}

func getLANIP() string {
	// 1. Try to get IP of "br0" (standard Keenetic LAN interface)
	if iface, err := net.InterfaceByName("br0"); err == nil {
		if addrs, err := iface.Addrs(); err == nil {
			for _, addr := range addrs {
				if ipNet, ok := addr.(*net.IPNet); ok && !ipNet.IP.IsLoopback() {
					if ipNet.IP.To4() != nil {
						return ipNet.IP.String()
					}
				}
			}
		}
	}

	// 2. Fallback: find any non-loopback private IPv4 address
	ifaces, err := net.Interfaces()
	if err == nil {
		for _, iface := range ifaces {
			if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
				continue
			}
			addrs, err := iface.Addrs()
			if err != nil {
				continue
			}
			for _, addr := range addrs {
				if ipNet, ok := addr.(*net.IPNet); ok && !ipNet.IP.IsLoopback() {
					if ipNet.IP.To4() != nil {
						ip := ipNet.IP
						if ip[0] == 10 || (ip[0] == 172 && ip[1] >= 16 && ip[1] <= 31) || (ip[0] == 192 && ip[1] == 168) {
							return ip.String()
						}
					}
				}
			}
		}
	}

	return "127.0.0.1"
}

type InterfaceInfo struct {
	Name        string `json:"name"`
	DisplayName string `json:"display_name"`
}

func handleGetInterfaces(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	ifaces, err := net.Interfaces()
	if err != nil {
		_ = json.NewEncoder(w).Encode([]InterfaceInfo{})
		return
	}

	var result []InterfaceInfo
	for _, iface := range ifaces {
		// Filter out loopback and down interfaces
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		var ipv4 string
		for _, addr := range addrs {
			if ipNet, ok := addr.(*net.IPNet); ok && !ipNet.IP.IsLoopback() {
				if ipNet.IP.To4() != nil {
					ipv4 = ipNet.IP.String()
					break
				}
			}
		}
		if ipv4 != "" {
			result = append(result, InterfaceInfo{
				Name:        iface.Name,
				DisplayName: fmt.Sprintf("%s - %s", iface.Name, ipv4),
			})
		}
	}
	if result == nil {
		result = []InterfaceInfo{}
	}
	_ = json.NewEncoder(w).Encode(result)
}
