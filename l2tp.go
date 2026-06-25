package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
)

type ConnectionProfile struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	Server       string `json:"server"`
	UseIPsec     bool   `json:"use_ipsec"`
	PSK          string `json:"psk"`
	Username     string `json:"username"`
	Password     string `json:"password"`
	TunNum       int    `json:"tun_num"`
	TunIP        string `json:"tun_ip"`
	TunMask      string `json:"tun_mask"`
	OutInterface string `json:"out_interface"`
	AuthType     string `json:"auth_type"`
	Enabled      bool   `json:"enabled"`
	SocksPort    int    `json:"socks_port"`
	Autostart    bool   `json:"autostart"`
}

type L2TPConfig struct {
	WebPort  int                 `json:"web_port"`
	Profiles []ConnectionProfile `json:"profiles"`
	ActiveID string              `json:"active_id"`
}

type SocksServer struct {
	listener   net.Listener
	localIP    string
	deviceName string
	cancel     context.CancelFunc
}

type Manager struct {
	configPath  string
	config      L2TPConfig
	mu          sync.Mutex
	logBuf      *LogBuffer
	cancelFunc  context.CancelFunc
	activeIface string
	isStarting  bool
	socksServer *SocksServer
	socksPort   int
}

type LogBuffer struct {
	mu    sync.Mutex
	lines []string
	max   int
}

func (lb *LogBuffer) Write(p []byte) (n int, err error) {
	lb.mu.Lock()
	defer lb.mu.Unlock()
	line := strings.TrimRight(string(p), "\r\n")
	lb.lines = append(lb.lines, line)
	if len(lb.lines) > lb.max {
		lb.lines = lb.lines[len(lb.lines)-lb.max:]
	}
	return len(p), nil
}

func (lb *LogBuffer) GetLines() []string {
	lb.mu.Lock()
	defer lb.mu.Unlock()
	res := make([]string, len(lb.lines))
	copy(res, lb.lines)
	return res
}

var manager *Manager

func initManager(port int, configPath string) *Manager {
	m := &Manager{
		configPath: configPath,
		logBuf:     &LogBuffer{max: 200},
	}
	log.SetOutput(io.MultiWriter(os.Stderr, m.logBuf))
	m.LoadConfig()
	if m.config.WebPort == 0 {
		m.config.WebPort = port
	}
	if m.config.Profiles == nil {
		m.config.Profiles = []ConnectionProfile{}
	}
	_ = m.SaveConfig()
	return m
}

func (m *Manager) LoadConfig() {
	m.mu.Lock()
	defer m.mu.Unlock()

	data, err := os.ReadFile(m.configPath)
	if err != nil {
		m.config = L2TPConfig{
			WebPort:  8081,
			Profiles: []ConnectionProfile{},
		}
		return
	}
	_ = json.Unmarshal(data, &m.config)
}

func (m *Manager) SaveConfig() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	data, err := json.MarshalIndent(m.config, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(m.configPath, data, 0640)
}

func (m *Manager) GetProfiles() []ConnectionProfile {
	m.mu.Lock()
	defer m.mu.Unlock()
	res := make([]ConnectionProfile, len(m.config.Profiles))
	copy(res, m.config.Profiles)
	return res
}

func (m *Manager) AddProfile(p ConnectionProfile) {
	m.mu.Lock()
	p.ID = fmt.Sprintf("profile_%d", time.Now().UnixNano())
	if p.TunIP == "" {
		p.TunIP = "10.254.254.1"
	}
	if p.TunMask == "" {
		p.TunMask = "255.255.255.0"
	}
	if p.AuthType == "" {
		p.AuthType = "auto"
	}
	m.config.Profiles = append(m.config.Profiles, p)
	m.mu.Unlock()
	_ = m.SaveConfig()
}

func (m *Manager) EditProfile(p ConnectionProfile) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if p.AuthType == "" {
		p.AuthType = "auto"
	}
	for i, existing := range m.config.Profiles {
		if existing.ID == p.ID {
			m.config.Profiles[i] = p
			go m.SaveConfig()
			return true
		}
	}
	return false
}

func (m *Manager) DeleteProfile(id string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	idx := -1
	for i, existing := range m.config.Profiles {
		if existing.ID == id {
			idx = i
			break
		}
	}
	if idx != -1 {
		m.config.Profiles = append(m.config.Profiles[:idx], m.config.Profiles[idx+1:]...)
		if m.config.ActiveID == id {
			m.config.ActiveID = ""
			if m.cancelFunc != nil {
				m.cancelFunc()
				m.cancelFunc = nil
			}
		}
		go m.SaveConfig()
		return true
	}
	return false
}

func (m *Manager) StartTunnel(id string) error {
	var target ConnectionProfile
	found := false

	m.mu.Lock()
	if m.isStarting {
		m.mu.Unlock()
		return fmt.Errorf("tunnel is already starting")
	}
	prevActiveID := m.config.ActiveID
	for i, p := range m.config.Profiles {
		if p.ID == id {
			m.config.Profiles[i].Enabled = true
			target = p
			found = true
		} else {
			m.config.Profiles[i].Enabled = false
		}
	}
	m.config.ActiveID = id
	if m.cancelFunc != nil {
		m.cancelFunc()
		m.cancelFunc = nil
	}
	m.isStarting = true
	m.mu.Unlock()

	if !found {
		m.mu.Lock()
		m.isStarting = false
		m.mu.Unlock()
		return fmt.Errorf("profile not found")
	}

	_ = m.SaveConfig()

	// Run the start sequence in the background to prevent UI switch rollback and web interface freeze
	go func() {
		defer func() {
			m.mu.Lock()
			m.isStarting = false
			m.mu.Unlock()
		}()

		checkActive := func() bool {
			m.mu.Lock()
			defer m.mu.Unlock()
			return m.config.ActiveID == target.ID
		}

		if !checkActive() {
			return
		}

		// Stop any active tunnels first
		log.Printf("[L2TP] Stopping any running L2TP tunnel before starting %s...", target.Name)
		_ = m.StopTunnelInternal(prevActiveID)

		if !checkActive() {
			return
		}

		if runtime.GOOS == "windows" {
			log.Printf("[L2TP-Windows] Simulating starting tunnel %s...", target.Name)
			time.Sleep(2 * time.Second)
			m.mu.Lock()
			if m.config.ActiveID == target.ID {
				m.activeIface = "ppp0"
			}
			m.mu.Unlock()
			log.Printf("[L2TP-Windows] Simulated tunnel started successfully.")
			return
		}

		// Resolve active outbound interface from comma-separated fallback list
		resolvedOutInterface := selectActiveInterface(target.OutInterface)
		targetCopy := target
		targetCopy.OutInterface = resolvedOutInterface

		m.mu.Lock()
		m.activeIface = resolvedOutInterface
		m.mu.Unlock()

		if !checkActive() {
			return
		}

		// 1. Generate Configs
		log.Printf("[L2TP] Generating configurations for profile %s (out interface: %s)...", target.Name, resolvedOutInterface)
		if err := m.writeConfigurations(targetCopy); err != nil {
			log.Printf("[L2TP] Error generating configurations: %v", err)
			return
		}

		if !checkActive() {
			return
		}

		// 3. Start Service (streaming logs line-by-line in real-time)
		log.Printf("[L2TP] Starting L2TP service...")
		cmd := exec.Command("/opt/etc/init.d/S99l2tp-vpn", "start")
		
		stdoutPipe, err := cmd.StdoutPipe()
		if err != nil {
			log.Printf("[L2TP] Error: failed to create stdout pipe: %v", err)
			return
		}
		stderrPipe, err := cmd.StderrPipe()
		if err != nil {
			log.Printf("[L2TP] Error: failed to create stderr pipe: %v", err)
			return
		}

		if err := cmd.Start(); err != nil {
			log.Printf("[L2TP] Error: failed to start service script command: %v", err)
			return
		}

		var wg sync.WaitGroup
		wg.Add(2)

		go func() {
			defer wg.Done()
			scanner := bufio.NewScanner(stdoutPipe)
			for scanner.Scan() {
				log.Printf("[Скрипт] %s", scanner.Text())
			}
		}()

		go func() {
			defer wg.Done()
			scanner := bufio.NewScanner(stderrPipe)
			for scanner.Scan() {
				log.Printf("[Скрипт-Ошибка] %s", scanner.Text())
			}
		}()

		wg.Wait()
		cmdErr := cmd.Wait()

		if cmdErr != nil {
			log.Printf("[L2TP] VPN service start failed: %v", cmdErr)
			return
		}

		if !checkActive() {
			log.Printf("[L2TP] Tunnel stopped during startup. Cleaning up...")
			_ = m.StopTunnelInternal(target.ID)
			return
		}

		log.Printf("[L2TP] VPN service started successfully.")

		// Start SOCKS5 proxy in the background when the connection is established
		go func() {
			for i := 0; i < 35; i++ {
				time.Sleep(1 * time.Second)
				if !checkActive() {
					return
				}
				status := m.GetStatus()
				if status.Status == "CONNECTED" && status.IP != "" {
					ip := status.IP
					if idx := strings.Index(ip, "/"); idx != -1 {
						ip = ip[:idx]
					}
					// Read configured SocksPort
					var socksPort int
					m.mu.Lock()
					for _, p := range m.config.Profiles {
						if p.ID == target.ID {
							socksPort = p.SocksPort
							break
						}
					}
					m.mu.Unlock()
					if socksPort <= 0 {
						socksPort = 1080
					}
					deviceName := status.Device
					m.StartSocks(ip, deviceName, socksPort)
					break
				}
			}
		}()

		// Start monitoring thread for fallback interfaces
		m.mu.Lock()
		ctx, cancel := context.WithCancel(context.Background())
		m.cancelFunc = cancel
		m.mu.Unlock()

		go m.monitorInterface(ctx, target.ID, resolvedOutInterface)
	}()

	return nil
}

func (m *Manager) StopTunnel() error {
	m.StopSocks()
	m.mu.Lock()
	activeID := m.config.ActiveID
	m.config.ActiveID = ""
	m.activeIface = ""
	m.isStarting = false
	for i := range m.config.Profiles {
		m.config.Profiles[i].Enabled = false
	}
	if m.cancelFunc != nil {
		m.cancelFunc()
		m.cancelFunc = nil
	}
	m.mu.Unlock()
	_ = m.SaveConfig()

	return m.StopTunnelInternal(activeID)
}

func (m *Manager) StopTunnelInternal(activeID string) error {
	m.StopSocks()
	if runtime.GOOS == "windows" {
		log.Printf("[L2TP-Windows] Simulating stopping tunnel...")
		return nil
	}



	if _, err := os.Stat("/opt/etc/init.d/S99l2tp-vpn"); os.IsNotExist(err) {
		return nil // Service file doesn't exist yet, nothing to stop
	}

	cmd := exec.Command("/opt/etc/init.d/S99l2tp-vpn", "stop")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	_ = cmd.Run() // Ignore exit code, might already be stopped
	return nil
}

func (m *Manager) writeConfigurations(p ConnectionProfile) error {
	// 1. xl2tpd.conf
	xl2tpdConf := fmt.Sprintf(`[global]
port = 1701
auth file = /opt/etc/xl2tpd/xl2tpd-secrets
debug avp = yes
debug network = yes
debug state = yes
debug tunnel = yes

[lac myvpn]
lns = %s
autodial = yes
redial = yes
redial timeout = 15
require chap = no
require pap = no
require authentication = no
length bit = yes
name = %s
pppoptfile = /opt/etc/xl2tpd/options.l2tp
ppp debug = yes
tx bps = 100000000
rx bps = 100000000
`, p.Server, p.Username)

	_ = os.MkdirAll("/opt/etc/xl2tpd", 0755)
	if err := os.WriteFile("/opt/etc/xl2tpd/xl2tpd.conf", []byte(strings.ReplaceAll(xl2tpdConf, "\r\n", "\n")), 0644); err != nil {
		return err
	}

	// 2. xl2tpd-secrets
	xl2tpdSecrets := fmt.Sprintf(`* * "%s"
`, p.Password)
	if err := os.WriteFile("/opt/etc/xl2tpd/xl2tpd-secrets", []byte(strings.ReplaceAll(xl2tpdSecrets, "\r\n", "\n")), 0600); err != nil {
		return err
	}

	// 3. options.l2tp
	refuseOptions := ""
	switch strings.ToLower(p.AuthType) {
	case "pap":
		refuseOptions = "refuse-chap\nrefuse-mschap\nrefuse-mschap-v2"
	case "chap":
		refuseOptions = "refuse-pap\nrefuse-mschap\nrefuse-mschap-v2"
	case "ms-chap":
		refuseOptions = "refuse-pap\nrefuse-chap\nrefuse-mschap-v2"
	case "ms-chap-v2":
		refuseOptions = "refuse-pap\nrefuse-chap\nrefuse-mschap"
	}

	optionsL2tp := fmt.Sprintf(`noauth
nopcomp
noaccomp
nodeflate
nobsdcomp
novj
novjccomp
noipdefault
defaultroute
usepeerdns
connect-delay 5000
logfile /opt/var/log/ppp-vpn.log
%s
unit %d
name %s
password %s
`, refuseOptions, 10+p.TunNum, p.Username, p.Password)
	if err := os.WriteFile("/opt/etc/xl2tpd/options.l2tp", []byte(strings.ReplaceAll(optionsL2tp, "\r\n", "\n")), 0644); err != nil {
		return err
	}

	// 4. swanctl.conf (if using IPsec)
	if p.UseIPsec {
		swanctlConf := fmt.Sprintf(`connections {
    l2tp-vpn {
        version = 1
        proposals = aes128-sha1-modp1024,3des-sha1-modp1024,aes256-sha1-modp1024,aes256-sha256-modp1024,aes256-sha256-modp2048,default
        local_addrs = %%any
        remote_addrs = %s
        encap = yes
        local {
            auth = psk
        }
        remote {
            auth = psk
        }
        children {
            l2tp-vpn {
                mode = transport
                # Keep both PFS and non-PFS variants for legacy L2TP/IPsec servers.
                # Some servers require a DH group for phase 2, others reject it.
                esp_proposals = aes128-sha1-modp1024,3des-sha1-modp1024,aes256-sha1-modp1024,aes256-sha256-modp2048,aes128-sha1,3des-sha1,aes256-sha1,aes256-sha256
                local_ts = dynamic[udp/l2tp]
                remote_ts = dynamic[udp/l2tp]
                start_action = route
            }
        }
    }
}
secrets {
    ike-psk {
        secret = "%s"
    }
}
`, p.Server, p.PSK)
		_ = os.MkdirAll("/opt/etc/swanctl", 0755)
		if err := os.WriteFile("/opt/etc/swanctl/swanctl.conf", []byte(strings.ReplaceAll(swanctlConf, "\r\n", "\n")), 0600); err != nil {
			return err
		}
	}

	// 5. Generate Service Script /opt/etc/init.d/S99l2tp-vpn
	// We dynamically construct the service script depending on whether IPsec is enabled.
	ipsecStartCode := ""
	ipsecStopCode := ""
	ipsecStatusCheck := ""

	if p.UseIPsec {
		ipsecStartCode = `
    # Запускаем strongSwan (charon), если не запущен
    if ! pidof charon > /dev/null; then
        if [ -x "/opt/lib/ipsec/charon" ]; then
            /opt/lib/ipsec/charon >/opt/var/log/charon-stderr.log 2>&1 &
            sleep 3
        else
            echo "Ошибка: Демон charon не найден в /opt/lib/ipsec."
            return 1
        fi
    fi
    echo "Загрузка конфигурации IPsec..."
    swanctl --load-all --file /opt/etc/swanctl/swanctl.conf
    sleep 1

    # Инициируем IPsec и ждем установления SA (макс. 15 сек)
    echo "Инициализация IPsec SA..."
    swanctl --initiate --child l2tp-vpn --timeout 15 >/opt/var/log/swanctl-initiate.log 2>&1
    IPSEC_INIT_RC=$?
    if [ $IPSEC_INIT_RC -ne 0 ]; then
        echo "Предупреждение: swanctl --initiate вернул код $IPSEC_INIT_RC"
        cat /opt/var/log/swanctl-initiate.log 2>/dev/null
    else
        echo "IPsec SA успешно установлена."
    fi
    sleep 1
`
		ipsecStopCode = `
    swanctl --terminate --ike l2tp-vpn 2>/dev/null
    killall charon 2>/dev/null
`
		ipsecStatusCheck = `
    IPSEC_SA=$(swanctl --list-sas 2>/dev/null | grep -i "l2tp-vpn")
`
	}

	pppDev := fmt.Sprintf("ppp%d", 10+p.TunNum)

	scriptContent := fmt.Sprintf(`#!/bin/sh

export PATH="/opt/bin:/opt/sbin:$PATH"

OUT_INTERFACE="%s"
VPN_SERVER="%s"
PPP_DEV="%s"

IP_BIN="/opt/sbin/ip"
[ ! -x "$IP_BIN" ] && IP_BIN="ip"
VPN_SERVER_IP="$VPN_SERVER"

resolve_vpn_server_ip() {
    case "$VPN_SERVER" in
        *[!0-9.]*)
            if command -v getent >/dev/null 2>&1; then
                RESOLVED_IP=$(getent ahostsv4 "$VPN_SERVER" 2>/dev/null | awk 'NR==1 {print $1; exit}')
                if [ -n "$RESOLVED_IP" ]; then
                    VPN_SERVER_IP="$RESOLVED_IP"
                    return 0
                fi
            fi

            if command -v nslookup >/dev/null 2>&1; then
                RESOLVED_IP=$(nslookup "$VPN_SERVER" 2>/dev/null | awk '/^Address: / {print $2; exit}')
                if [ -n "$RESOLVED_IP" ]; then
                    VPN_SERVER_IP="$RESOLVED_IP"
                    return 0
                fi
            fi
            ;;
    esac

    return 0
}

start() {
    echo "Запуск туннеля L2TP/IPsec NAT-T VPN..."
    
    # Очищаем старые лог-файлы
    mkdir -p /opt/var/log
    > /opt/var/log/swanctl.log
    > /opt/var/log/ppp-vpn.log
    > /opt/var/log/xl2tpd.log
    > /opt/var/log/charon-stderr.log
    > /opt/var/log/swanctl-initiate.log
    resolve_vpn_server_ip
    
    # Маршрутизируем трафик к VPN серверу через выбранный внешний интерфейс
    if [ -n "$OUT_INTERFACE" ]; then
        echo "Настройка маршрута к VPN серверу $VPN_SERVER_IP через интерфейс $OUT_INTERFACE..."
        GW=$(ip route show dev "$OUT_INTERFACE" | grep -m1 "default" | awk '{print $3}')
        if [ -n "$GW" ]; then
            ip route add "$VPN_SERVER_IP" via "$GW" dev "$OUT_INTERFACE" 2>/dev/null || true
            echo "Маршрут к $VPN_SERVER_IP через шлюз $GW на интерфейсе $OUT_INTERFACE добавлен."
        else
            ip route add "$VPN_SERVER_IP" dev "$OUT_INTERFACE" 2>/dev/null || true
            echo "Прямой маршрут к $VPN_SERVER_IP на интерфейсе $OUT_INTERFACE добавлен."
        fi
    else
        echo "Внешний интерфейс не задан, маршрут к VPN-серверу не создается."
    fi

    %s
    # Запускаем xl2tpd (всегда перезапускаем для применения настроек)
    echo "Запуск демона xl2tpd..."
    mkdir -p /var/run/xl2tpd
    killall xl2tpd 2>/dev/null || true
    sleep 1
    rm -f /var/run/xl2tpd/l2tp-control
    
    XL2TPD_BIN=""
    for bin_path in /opt/sbin/xl2tpd /opt/bin/xl2tpd; do
        if [ -x "$bin_path" ]; then
            XL2TPD_BIN="$bin_path"
            break
        fi
    done
    if [ -n "$XL2TPD_BIN" ]; then
        $XL2TPD_BIN -D -c /opt/etc/xl2tpd/xl2tpd.conf -p /var/run/xl2tpd/xl2tpd.pid >/opt/var/log/xl2tpd.log 2>&1 &
        XL2TPD_PID=$!
    else
        echo "Ошибка: Бинарный файл xl2tpd не найден в /opt/sbin или /opt/bin."
        return 1
    fi
    sleep 2

    # Проверяем, что xl2tpd действительно работает
    if ! kill -0 $XL2TPD_PID 2>/dev/null; then
        echo "Ошибка: xl2tpd завершился сразу после запуска. Лог:"
        cat /opt/var/log/xl2tpd.log 2>/dev/null
        return 1
    fi
    echo "xl2tpd запущен с autodial (PID $XL2TPD_PID). Подключение инициировано автоматически."
    sleep 3
    
    # Ждем появление ppp-интерфейса (макс 30 сек)
    echo "Ожидание поднятия интерфейса $PPP_DEV..."
    COUNTER=0
    while [ $COUNTER -lt 30 ]; do
        if $IP_BIN link show "$PPP_DEV" >/dev/null 2>&1; then
            break
        fi
        # Каждые 5 сек выводим диагностику
        if [ $((COUNTER %% 5)) -eq 4 ]; then
            echo "Ожидание $PPP_DEV... ($((COUNTER+1)) сек)"
            if ! kill -0 $XL2TPD_PID 2>/dev/null; then
                echo "Ошибка: xl2tpd (PID $XL2TPD_PID) неожиданно завершился!"
                echo "Последние строки лога xl2tpd:"
                tail -20 /opt/var/log/xl2tpd.log 2>/dev/null
                return 1
            fi
        fi
        sleep 1
        COUNTER=$((COUNTER + 1))
    done
    
    if ! $IP_BIN link show "$PPP_DEV" >/dev/null 2>&1; then
        echo "Ошибка: Интерфейс $PPP_DEV не поднялся за 30 секунд."
        echo "Последние строки лога xl2tpd:"
        tail -20 /opt/var/log/xl2tpd.log 2>/dev/null
        echo "Последние строки лога ppp:"
        tail -10 /opt/var/log/ppp-vpn.log 2>/dev/null
        return 1
    fi
    
    # Настраиваем iptables правила для пересылки трафика
    iptables -t nat -I POSTROUTING -o "$PPP_DEV" -j MASQUERADE

    echo "L2TP успешно подключен."
}

stop() {
    echo "Остановка туннеля L2TP/IPsec NAT-T VPN..."
    resolve_vpn_server_ip
    
    # Удаляем правила iptables
    iptables -t nat -D POSTROUTING -o "$PPP_DEV" -j MASQUERADE 2>/dev/null || true

    echo "d myvpn" > /var/run/xl2tpd/l2tp-control 2>/dev/null
    sleep 1
    killall xl2tpd 2>/dev/null
    %s
    
    if [ -n "$OUT_INTERFACE" ]; then
        ip route del "$VPN_SERVER_IP" dev "$OUT_INTERFACE" 2>/dev/null || true
    fi

    echo "Туннель L2TP/IPsec NAT-T VPN остановлен."
}

status() {
    XL2TPD_RUNNING=0
    if pidof xl2tpd >/dev/null 2>&1; then
        XL2TPD_RUNNING=1
    fi

    %s
    
    PPP_UP=0
    if $IP_BIN link show "$PPP_DEV" >/dev/null 2>&1; then
        PPP_UP=1
    fi

    if [ $PPP_UP -eq 1 ]; then
        STATUS_OK=0
        if [ "%s" = "1" ]; then
            if [ -n "$IPSEC_SA" ]; then
                STATUS_OK=1
            fi
        else
            STATUS_OK=1
        fi
        
        if [ $STATUS_OK -eq 1 ]; then
            echo "STATUS: CONNECTED"
            echo "DEVICE: $PPP_DEV"
            $IP_BIN addr show $PPP_DEV | grep "inet " | awk '{print "IP: " $2}'
        else
            echo "STATUS: CONNECTING"
            echo "DEVICE: $PPP_DEV"
        fi
    else
        if [ $XL2TPD_RUNNING -eq 1 ]; then
            echo "STATUS: CONNECTING"
            echo "DEVICE: $PPP_DEV"
        else
            echo "STATUS: DISCONNECTED"
        fi
    fi
}

case "$1" in
    start)
        start
        ;;
    stop)
        stop
        ;;
    status)
        status
        ;;
    restart)
        stop
        start
        ;;
    *)
        echo "Использование: $0 {start|stop|status|restart}"
        exit 1
        ;;
esac
`, p.OutInterface, p.Server, pppDev, ipsecStartCode, ipsecStopCode, ipsecStatusCheck, mapBool(p.UseIPsec))

	_ = os.MkdirAll("/opt/etc/init.d", 0755)
	if err := os.WriteFile("/opt/etc/init.d/S99l2tp-vpn", []byte(strings.ReplaceAll(scriptContent, "\r\n", "\n")), 0755); err != nil {
		return err
	}

	// Create global control script /opt/bin/ptrol-l2tp
	l2tpControl := `#!/bin/sh
export PATH="/opt/bin:/opt/sbin:$PATH"

if [ "$1" = "port" ]; then
    PORT=$2
    if [ -z "$PORT" ]; then
        echo "Использование: ptrol-l2tp port <номер_порта>"
        exit 1
    fi
    if ! echo "$PORT" | grep -qE '^[0-9]+$' || [ "$PORT" -lt 1 ] || [ "$PORT" -gt 65535 ]; then
        echo "Ошибка: Неверный порт. Порт должен быть числом от 1 до 65535."
        exit 1
    fi
    CONFIG_FILE="/opt/etc/l2tp_vpn_config.json"
    if [ -f "$CONFIG_FILE" ]; then
        echo "[+] Обновление порта веб-панели на $PORT в $CONFIG_FILE..."
        sed -i "s/\"web_port\":\s*[0-9]*/\"web_port\": $PORT/g" "$CONFIG_FILE"
    else
        echo "[-] Ошибка: Конфигурационный файл $CONFIG_FILE не найден."
        exit 1
    fi
    if [ -x "/opt/etc/init.d/S99l2tp-web" ]; then
        echo "[+] Перезапуск службы веб-менеджера..."
        /opt/etc/init.d/S99l2tp-web restart
    else
        echo "[!] Предупреждение: Скрипт запуска /opt/etc/init.d/S99l2tp-web не найден."
    fi
    echo "[+] Порт успешно изменен на $PORT."
    exit 0
fi

if [ -x "/opt/etc/init.d/S99l2tp-vpn" ]; then
    /opt/etc/init.d/S99l2tp-vpn "$@"
else
    echo "Использование: ptrol-l2tp {start|stop|status|restart|port}"
    exit 1
fi
`
	_ = os.MkdirAll("/opt/bin", 0755)
	_ = os.WriteFile("/opt/bin/ptrol-l2tp", []byte(strings.ReplaceAll(l2tpControl, "\r\n", "\n")), 0755)

	return nil
}


func mapBool(b bool) string {
	if b {
		return "1"
	}
	return "0"
}

func runKeeneticRCI(payload any) error {
	url := "http://localhost:79/rci"
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(payload); err != nil {
		return fmt.Errorf("marshal RCI payload: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, &buf)
	if err != nil {
		return fmt.Errorf("build RCI request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read RCI response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("RCI returned status %d: %s", resp.StatusCode, string(body))
	}

	// NDMS returns HTTP 200 even on app errors. Look for error envelope
	if bytes.Contains(body, []byte(`"error"`)) || bytes.Contains(body, []byte(`"message"`)) {
		var result []map[string]any
		if err := json.Unmarshal(body, &result); err == nil && len(result) > 0 {
			if msg, ok := result[0]["message"].(string); ok {
				return fmt.Errorf("NDMS error: %s", msg)
			}
		}
		var resultMap map[string]any
		if err := json.Unmarshal(body, &resultMap); err == nil {
			if errorVal, ok := resultMap["error"].(map[string]any); ok {
				if msg, ok := errorVal["message"].(string); ok {
					return fmt.Errorf("NDMS error: %s", msg)
				}
			}
		}
		return fmt.Errorf("NDMS error: %s", string(body))
	}

	return nil
}

func (m *Manager) registerInterface(p ConnectionProfile) error {
	tunName := fmt.Sprintf("OpkgTun%d", p.TunNum)

	// 1. Try RCI first (modern approach like awg-manager)
	rciPayload := map[string]any{
		"interface": map[string]any{
			tunName: map[string]any{
				"description":    fmt.Sprintf("%s-L2TP", p.Name),
				"security-level": "public",
				"ip": map[string]any{
					"address": map[string]any{
						"address": p.TunIP,
						"mask":    p.TunMask,
					},
					"global": map[string]any{
						"auto": true,
					},
				},
				"up": true,
			},
		},
	}

	log.Printf("[L2TP] Registering interface %s (%s-L2TP) with IP %s/%s via RCI...", tunName, p.Name, p.TunIP, p.TunMask)
	if err := runKeeneticRCI(rciPayload); err == nil {
		savePayload := map[string]any{
			"system": map[string]any{
				"configuration": map[string]any{
					"save": map[string]any{},
				},
			},
		}
		_ = runKeeneticRCI(savePayload)
		log.Printf("[L2TP] Interface %s registered successfully via RCI.", tunName)
		return nil
	} else {
		log.Printf("[L2TP] RCI registration failed: %v. Falling back to ndmc CLI...", err)
	}

	// 2. Fallback to ndmc CLI commands
	commands := []string{
		fmt.Sprintf("interface %s", tunName),
		fmt.Sprintf("interface %s description \"%s-L2TP\"", tunName, p.Name),
		fmt.Sprintf("interface %s security-level public", tunName),
		fmt.Sprintf("interface %s ip address %s %s", tunName, p.TunIP, p.TunMask),
		fmt.Sprintf("interface %s ip global auto", tunName),
		fmt.Sprintf("interface %s up", tunName),
		"system configuration save",
	}

	for _, cmd := range commands {
		if err := runKeeneticCLI(cmd); err != nil {
			return err
		}
	}
	return nil
}

func (m *Manager) unregisterInterface(p ConnectionProfile) error {
	tunName := fmt.Sprintf("OpkgTun%d", p.TunNum)

	// 1. Try RCI first
	rciPayload := map[string]any{
		"interface": map[string]any{
			tunName: map[string]any{
				"up": false,
			},
		},
	}

	log.Printf("[L2TP] Deactivating interface %s via RCI...", tunName)
	if err := runKeeneticRCI(rciPayload); err == nil {
		savePayload := map[string]any{
			"system": map[string]any{
				"configuration": map[string]any{
					"save": map[string]any{},
				},
			},
		}
		_ = runKeeneticRCI(savePayload)
		log.Printf("[L2TP] Interface %s deactivated successfully via RCI.", tunName)
		return nil
	} else {
		log.Printf("[L2TP] RCI deactivation failed: %v. Falling back to ndmc CLI...", err)
	}

	// 2. Fallback to ndmc CLI commands
	commands := []string{
		fmt.Sprintf("interface %s down", tunName),
		"system configuration save",
	}
	for _, cmd := range commands {
		if err := runKeeneticCLI(cmd); err != nil {
			return err
		}
	}
	return nil
}

func (m *Manager) deleteInterface(p ConnectionProfile) error {
	tunName := fmt.Sprintf("OpkgTun%d", p.TunNum)
	gw := getGatewayIP(p.TunIP)

	// Remove the static route first
	_ = runKeeneticCLI(fmt.Sprintf("no ip route 0.0.0.0 0.0.0.0 %s %s", gw, tunName))

	// 1. Try RCI first
	rciPayload := map[string]any{
		"interface": map[string]any{
			tunName: map[string]any{
				"no": true,
			},
		},
	}

	log.Printf("[L2TP] Deleting interface %s via RCI...", tunName)
	if err := runKeeneticRCI(rciPayload); err == nil {
		savePayload := map[string]any{
			"system": map[string]any{
				"configuration": map[string]any{
					"save": map[string]any{},
				},
			},
		}
		_ = runKeeneticRCI(savePayload)
		log.Printf("[L2TP] Interface %s deleted successfully via RCI.", tunName)
		return nil
	} else {
		log.Printf("[L2TP] RCI deletion failed: %v. Falling back to ndmc CLI...", err)
	}

	// 2. Fallback to ndmc CLI commands
	commands := []string{
		fmt.Sprintf("no interface %s", tunName),
		"system configuration save",
	}
	for _, cmd := range commands {
		if err := runKeeneticCLI(cmd); err != nil {
			return err
		}
	}
	return nil
}

func runKeeneticCLI(cmd string) error {
	var ndmqPath string
	var ndmcPath string
	for _, path := range []string{"/bin/ndmq", "/sbin/ndmq", "/usr/sbin/ndmq", "/opt/sbin/ndmq", "/usr/bin/ndmq", "/opt/bin/ndmq"} {
		if _, err := os.Stat(path); err == nil {
			ndmqPath = path
			break
		}
	}
	for _, path := range []string{"/bin/ndmc", "/sbin/ndmc", "/usr/sbin/ndmc", "/opt/sbin/ndmc", "/usr/bin/ndmc", "/opt/bin/ndmc"} {
		if _, err := os.Stat(path); err == nil {
			ndmcPath = path
			break
		}
	}

	if ndmqPath != "" {
		c := exec.Command(ndmqPath, "-p", cmd)
		return c.Run()
	} else if ndmcPath != "" {
		c := exec.Command(ndmcPath, "-c", cmd)
		return c.Run()
	}
	return fmt.Errorf("neither ndmq nor ndmc found")
}

type TunnelStatus struct {
	Status       string `json:"status"` // CONNECTED, CONNECTING, DISCONNECTED
	ActiveID     string `json:"active_id"`
	Device       string `json:"device"`
	IP           string `json:"ip"`
	OutInterface string `json:"out_interface"`
	SocksPort    int    `json:"socks_port,omitempty"`
}

func (m *Manager) GetStatus() TunnelStatus {
	m.mu.Lock()
	activeID := m.config.ActiveID
	activeIface := m.activeIface
	isStarting := m.isStarting
	socksPort := m.socksPort
	m.mu.Unlock()

	if activeID == "" {
		return TunnelStatus{Status: "DISCONNECTED", ActiveID: "", OutInterface: ""}
	}

	if isStarting {
		return TunnelStatus{
			Status:       "CONNECTING",
			ActiveID:     activeID,
			Device:       "",
			IP:           "",
			OutInterface: activeIface,
			SocksPort:    socksPort,
		}
	}

	if runtime.GOOS == "windows" {
		// Simulating connection on Windows
		if socksPort <= 0 {
			m.mu.Lock()
			for _, p := range m.config.Profiles {
				if p.ID == activeID {
					socksPort = p.SocksPort
					break
				}
			}
			m.mu.Unlock()
			if socksPort <= 0 {
				socksPort = 1080
			}
		}
		return TunnelStatus{
			Status:       "CONNECTED",
			ActiveID:     activeID,
			Device:       "ppp0",
			IP:           "10.254.254.2/32",
			OutInterface: "ppp0",
			SocksPort:    socksPort,
		}
	}

	cmd := exec.Command("/opt/etc/init.d/S99l2tp-vpn", "status")
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		return TunnelStatus{
			Status:       "DISCONNECTED",
			ActiveID:     activeID,
			OutInterface: activeIface,
			SocksPort:    socksPort,
		}
	}

	lines := strings.Split(out.String(), "\n")
	status := "DISCONNECTED"
	device := ""
	ip := ""

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "STATUS:") {
			status = strings.TrimSpace(strings.TrimPrefix(line, "STATUS:"))
		} else if strings.HasPrefix(line, "DEVICE:") {
			device = strings.TrimSpace(strings.TrimPrefix(line, "DEVICE:"))
		} else if strings.HasPrefix(line, "IP:") {
			ip = strings.TrimSpace(strings.TrimPrefix(line, "IP:"))
		}
	}

	// Double check if ppp interface exists in the system
	if status == "CONNECTED" && device != "" {
		if _, err := net.InterfaceByName(device); err != nil {
			status = "CONNECTING" // Interface doesn't exist yet, but process is running
		}
	}

	return TunnelStatus{
		Status:       status,
		ActiveID:     activeID,
		Device:       device,
		IP:           ip,
		OutInterface: activeIface,
		SocksPort:    socksPort,
	}
}

var timeRegex = regexp.MustCompile(`\d{2}:\d{2}:\d{2}`)

func extractTime(line string) string {
	match := timeRegex.FindString(line)
	if match != "" {
		return match
	}
	return "00:00:00"
}

func getKeeneticLog() (string, error) {
	var ndmqPath string
	for _, path := range []string{"/bin/ndmq", "/sbin/ndmq", "/usr/sbin/ndmq", "/opt/sbin/ndmq", "/usr/bin/ndmq", "/opt/bin/ndmq"} {
		if _, err := os.Stat(path); err == nil {
			ndmqPath = path
			break
		}
	}
	if ndmqPath != "" {
		c := exec.Command(ndmqPath, "-p", "show log")
		var out bytes.Buffer
		c.Stdout = &out
		if err := c.Run(); err == nil {
			return out.String(), nil
		}
	}
	
	// Fallback to reading file
	for _, filePath := range []string{"/var/log/messages", "/opt/var/log/messages"} {
		if data, err := os.ReadFile(filePath); err == nil {
			return string(data), nil
		}
	}
	return "", fmt.Errorf("no keenetic log found")
}

func (m *Manager) GetLogs() ([]string, error) {
	type logItem struct {
		time string
		text string
	}
	var items []logItem

	// 1. Read Syslog (logread) on Linux
	if runtime.GOOS == "windows" {
		items = append(items, logItem{time: "08:30:00", text: "[08:30:00] [Система] Логи будут отображаться здесь при запуске на роутере..."})
		items = append(items, logItem{time: "08:30:01", text: "[08:30:01] [Система] Имитация соединения: ppp0 успешно поднят"})
	} else {
		var syslogContent string
		// Try logread first
		cmd := exec.Command("logread")
		var out bytes.Buffer
		cmd.Stdout = &out
		if err := cmd.Run(); err == nil && out.Len() > 100 {
			syslogContent = out.String()
		} else {
			// Fallback to Keenetic CLI "show log" or files
			kLog, err := getKeeneticLog()
			if err == nil {
				syslogContent = kLog
			} else {
				items = append(items, logItem{
					time: "00:00:00",
					text: fmt.Sprintf("[00:00:00] [Система] Предупреждение: Не удалось получить логи Keenetic: %v", err),
				})
			}
		}

		if syslogContent != "" {
			lines := strings.Split(syslogContent, "\n")
			for _, line := range lines {
				line = strings.TrimSpace(line)
				if line == "" {
					continue
				}
				if strings.Contains(line, "xl2tpd") ||
					strings.Contains(line, "charon") ||
					strings.Contains(line, "pppd") ||
					strings.Contains(line, "l2tp-vpn") ||
					strings.Contains(line, "l2tp_nv") {
					
					timeStr := extractTime(line)
					items = append(items, logItem{
						time: timeStr,
						text: fmt.Sprintf("[%s] [Система] %s", timeStr, line),
					})
				}
			}
		}
	}

	// 2. Read Go Backend Logs (m.logBuf)
	backendLines := m.logBuf.GetLines()
	for _, line := range backendLines {
		// Фильтруем шум: пропускаем строки о ненайденных плагинах
		if strings.Contains(line, "failed to load") && strings.Contains(line, "not found and no plugin file") {
			continue
		}
		timeStr := extractTime(line)
		msg := line
		if len(line) > 20 && strings.Contains(line[:20], " ") {
			msg = line[20:] // Strip date and time prefix
		}
		items = append(items, logItem{
			time: timeStr,
			text: fmt.Sprintf("[%s] [Менеджер] %s", timeStr, msg),
		})
	}

	// 3. Read swanctl.log (IPsec negotiation details)
	if data, err := os.ReadFile("/opt/var/log/swanctl.log"); err == nil {
		lines := strings.Split(string(data), "\n")
		lastTime := "00:00:00"
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			// Фильтруем шум: пропускаем строки о ненайденных плагинах и некритичных ошибках ядра
			if strings.Contains(line, "failed to load") && strings.Contains(line, "not found and no plugin file") {
				continue
			}
			if strings.Contains(line, "UDP_GRO") || strings.Contains(line, "UDP decapsulation") {
				continue
			}
			timeStr := extractTime(line)
			if timeStr != "00:00:00" {
				lastTime = timeStr
			} else {
				timeStr = lastTime
			}
			msg := line
			if timeStr != "00:00:00" && strings.HasPrefix(line, timeStr) {
				msg = strings.TrimSpace(strings.TrimPrefix(line, timeStr))
			}
			items = append(items, logItem{
				time: timeStr,
				text: fmt.Sprintf("[%s] [IPsec] %s", timeStr, msg),
			})
		}
	}



	// 4. Read ppp-vpn.log (L2TP/PPP negotiation details)
	if data, err := os.ReadFile("/opt/var/log/ppp-vpn.log"); err == nil {
		lines := strings.Split(string(data), "\n")
		lastTime := "00:00:00"
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			timeStr := extractTime(line)
			if timeStr != "00:00:00" {
				lastTime = timeStr
			} else {
				timeStr = lastTime
			}
			msg := line
			if timeStr != "00:00:00" && strings.HasPrefix(line, timeStr) {
				msg = strings.TrimSpace(strings.TrimPrefix(line, timeStr))
			}
			items = append(items, logItem{
				time: timeStr,
				text: fmt.Sprintf("[%s] [L2TP-PPP] %s", timeStr, msg),
			})
		}
	}

	// 5. Read xl2tpd.log (L2TP daemon details)
	if data, err := os.ReadFile("/opt/var/log/xl2tpd.log"); err == nil {
		lines := strings.Split(string(data), "\n")
		lastTime := "00:00:00"
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			timeStr := extractTime(line)
			if timeStr != "00:00:00" {
				lastTime = timeStr
			} else {
				timeStr = lastTime
			}
			msg := line
			if timeStr != "00:00:00" {
				prefixes := []string{
					timeStr,
					"[" + timeStr + "]",
					timeStr + ":",
				}
				for _, pref := range prefixes {
					if strings.HasPrefix(msg, pref) {
						msg = strings.TrimSpace(strings.TrimPrefix(msg, pref))
						break
					}
				}
			}
			items = append(items, logItem{
				time: timeStr,
				text: fmt.Sprintf("[%s] [L2TP] %s", timeStr, msg),
			})
		}
	}

	// 6. Sort chronologically
	sort.Slice(items, func(i, j int) bool {
		return items[i].time < items[j].time
	})

	// 7. Extract text and limit size
	var result []string
	for _, item := range items {
		result = append(result, item.text)
	}

	if len(result) > 250 {
		result = result[len(result)-250:]
	}
	return result, nil
}

// selectActiveInterface parses a comma-separated list of interfaces and returns the highest priority active one
func selectActiveInterface(outInterfaces string) string {
	if outInterfaces == "" {
		return ""
	}
	parts := strings.Split(outInterfaces, ",")
	var candidates []string
	for _, p := range parts {
		iface := strings.TrimSpace(p)
		if iface != "" {
			candidates = append(candidates, iface)
		}
	}
	if len(candidates) == 0 {
		return ""
	}

	// Get all system interfaces
	ifaces, err := net.Interfaces()
	if err != nil {
		return candidates[0]
	}

	// Iterate in priority order
	for _, cand := range candidates {
		for _, iface := range ifaces {
			if iface.Name == cand {
				// Interface must be UP and not Loopback
				if iface.Flags&net.FlagUp != 0 && iface.Flags&net.FlagLoopback == 0 {
					// Check if it has a valid IPv4 address
					addrs, err := iface.Addrs()
					if err == nil {
						hasIPv4 := false
						for _, addr := range addrs {
							if ipNet, ok := addr.(*net.IPNet); ok && !ipNet.IP.IsLoopback() {
								if ipNet.IP.To4() != nil {
									hasIPv4 = true
									break
								}
							}
						}
						if hasIPv4 {
							return cand
						}
					}
				}
			}
		}
	}

	// Default fallback to highest priority candidate if none are active
	log.Printf("[L2TP] Warning: None of the candidate interfaces (%s) are active/up with a valid IPv4. Falling back to the first candidate: '%s'", outInterfaces, candidates[0])
	return candidates[0]
}

func (m *Manager) monitorInterface(ctx context.Context, id string, currentIface string) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			var profile ConnectionProfile
			found := false
			m.mu.Lock()
			for _, p := range m.config.Profiles {
				if p.ID == id && p.Enabled {
					profile = p
					found = true
					break
				}
			}
			m.mu.Unlock()

			if !found {
				return // Profile deleted or disabled
			}

			// Watchdog check: if tunnel is down, restart it
			status := m.GetStatus()
			if status.Status == "DISCONNECTED" {
				log.Printf("[L2TP] Watchdog: Tunnel '%s' is down (DISCONNECTED). Restarting tunnel...", profile.Name)
				go func() {
					_ = m.StartTunnel(id)
				}()
				return
			}

			bestIface := selectActiveInterface(profile.OutInterface)
			if bestIface != currentIface {
				log.Printf("[L2TP] Outbound interface changed from '%s' to '%s'. Restarting tunnel...", currentIface, bestIface)
				// Restart tunnel in a new goroutine to avoid deadlock/blocking ticker
				go func() {
					_ = m.StartTunnel(id)
				}()
				return
			}
		}
	}
}

func (m *Manager) ResumeMonitoring() {
	m.mu.Lock()
	if m.config.ActiveID == "" {
		m.mu.Unlock()
		return
	}

	var target ConnectionProfile
	found := false
	for _, p := range m.config.Profiles {
		if p.ID == m.config.ActiveID && p.Enabled {
			target = p
			found = true
			break
		}
	}

	if !found {
		m.mu.Unlock()
		return
	}

	if m.cancelFunc != nil {
		m.cancelFunc()
	}
	ctx, cancel := context.WithCancel(context.Background())
	m.cancelFunc = cancel

	resolvedOutInterface := selectActiveInterface(target.OutInterface)
	m.activeIface = resolvedOutInterface
	m.mu.Unlock()

	go m.monitorInterface(ctx, target.ID, resolvedOutInterface)

	// If the tunnel is already connected in the system but SOCKS5 is not running in this process,
	// restore SOCKS5 server on the configured port.
	status := m.GetStatus()
	if status.Status == "CONNECTED" && status.Device != "" && status.IP != "" {
		m.mu.Lock()
		isSocksNil := m.socksServer == nil
		socksPort := target.SocksPort
		m.mu.Unlock()

		if isSocksNil {
			if socksPort <= 0 {
				socksPort = 1080
			}
			ipAddr := status.IP
			if idx := strings.Index(ipAddr, "/"); idx != -1 {
				ipAddr = ipAddr[:idx]
			}
			m.StartSocks(ipAddr, status.Device, socksPort)
		}
	}
}


func (m *Manager) TriggerAutostart() {
	var autostartID string
	var autostartName string
	m.mu.Lock()
	for _, p := range m.config.Profiles {
		if p.Autostart {
			autostartID = p.ID
			autostartName = p.Name
			break
		}
	}
	m.mu.Unlock()

	if autostartID != "" {
		log.Printf("[L2TP] Autostart enabled for profile '%s' (%s). Starting tunnel in background...", autostartName, autostartID)
		go func() {
			// Give the system some time to bring up interfaces and network services
			time.Sleep(10 * time.Second)
			if err := m.StartTunnel(autostartID); err != nil {
				log.Printf("[L2TP] Autostart error for profile '%s': %v", autostartName, err)
			}
		}()
	}
}

func getGatewayIP(ipStr string) string {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return ""
	}
	ip = ip.To4()
	if ip == nil {
		return ""
	}
	if ip[3] == 1 {
		return fmt.Sprintf("%d.%d.%d.2", ip[0], ip[1], ip[2])
	}
	return fmt.Sprintf("%d.%d.%d.1", ip[0], ip[1], ip[2])
}

func (m *Manager) StartSocks(localIP string, deviceName string, port int) int {
	m.mu.Lock()
	defer m.mu.Unlock()

	// If already running, stop it first
	if m.socksServer != nil {
		m.socksServer.Close()
		m.socksServer = nil
	}

	addr := fmt.Sprintf("127.0.0.1:%d", port)
	l, err := net.Listen("tcp", addr)
	if err != nil {
		log.Printf("[SOCKS5] Error: failed to listen on %s: %v", addr, err)
		return 0
	}

	log.Printf("[SOCKS5] Starting SOCKS5 proxy on 127.0.0.1:%d bound to outbound IP %s and device %s...", port, localIP, deviceName)
	
	ctx, cancel := context.WithCancel(context.Background())
	s := &SocksServer{
		listener:   l,
		localIP:    localIP,
		deviceName: deviceName,
		cancel:     cancel,
	}
	m.socksServer = s
	m.socksPort = port

	go func() {
		defer l.Close()
		for {
			client, err := l.Accept()
			if err != nil {
				select {
				case <-ctx.Done():
					return
				default:
					return
				}
			}
			go handleSocksClient(client, localIP, deviceName)
		}
	}()

	return port
}

func (m *Manager) StopSocks() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.socksServer != nil {
		m.socksServer.Close()
		m.socksServer = nil
		m.socksPort = 0
		log.Printf("[SOCKS5] Stopped SOCKS5 proxy.")
	}
}

func (s *SocksServer) Close() {
	if s.cancel != nil {
		s.cancel()
	}
	if s.listener != nil {
		_ = s.listener.Close()
	}
}

func handleSocksClient(client net.Conn, localIP string, deviceName string) {
	defer client.Close()

	// 1. Read greeting
	buf := make([]byte, 260)
	if _, err := io.ReadFull(client, buf[:2]); err != nil {
		return
	}
	if buf[0] != 0x05 { // SOCKS5
		return
	}
	nmethods := int(buf[1])
	if _, err := io.ReadFull(client, buf[:nmethods]); err != nil {
		return
	}

	// Respond with Method 0x00 (No authentication)
	if _, err := client.Write([]byte{0x05, 0x00}); err != nil {
		return
	}

	// 2. Read request
	if _, err := io.ReadFull(client, buf[:4]); err != nil {
		return
	}
	if buf[0] != 0x05 || buf[2] != 0x00 {
		return
	}
	cmd := buf[1]
	atyp := buf[3]

	var destAddr string
	switch atyp {
	case 0x01: // IPv4 (4 bytes)
		if _, err := io.ReadFull(client, buf[:4]); err != nil {
			return
		}
		destAddr = net.IP(buf[:4]).String()
	case 0x03: // Domain name
		if _, err := io.ReadFull(client, buf[:1]); err != nil {
			return
		}
		addrLen := int(buf[0])
		if _, err := io.ReadFull(client, buf[:addrLen]); err != nil {
			return
		}
		destAddr = string(buf[:addrLen])
	case 0x04: // IPv6 (16 bytes)
		if _, err := io.ReadFull(client, buf[:16]); err != nil {
			return
		}
		destAddr = net.IP(buf[:16]).String()
	default:
		return
	}

	// Read Port (2 bytes)
	if _, err := io.ReadFull(client, buf[:2]); err != nil {
		return
	}
	destPort := int(buf[0])<<8 | int(buf[1])
	dest := fmt.Sprintf("%s:%d", destAddr, destPort)

	if cmd != 0x01 { // Only CONNECT command is supported
		_, _ = client.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	// Connect to destination binding to localIP / deviceName
	var dialer net.Dialer
	if localIP != "" {
		dialer.LocalAddr = &net.TCPAddr{
			IP: net.ParseIP(localIP),
		}
	}
	if deviceName != "" {
		dialer.Control = func(network, address string, c syscall.RawConn) error {
			var bindErr error
			err := c.Control(func(fd uintptr) {
				bindErr = bindToDevice(fd, deviceName)
			})
			if err != nil {
				return err
			}
			return bindErr
		}
	}
	dialer.Timeout = 10 * time.Second

	target, err := dialer.Dial("tcp", dest)
	if err != nil {
		// Host unreachable
		_, _ = client.Write([]byte{0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer target.Close()

	// Respond connection established
	if _, err := client.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		return
	}

	// Bidirectional pipe
	errChan := make(chan error, 2)
	go func() {
		_, err := io.Copy(target, client)
		errChan <- err
	}()
	go func() {
		_, err := io.Copy(client, target)
		errChan <- err
	}()

	<-errChan
}
