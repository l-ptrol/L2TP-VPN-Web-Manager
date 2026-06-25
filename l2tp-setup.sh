#!/bin/sh

# Установочный скрипт для L2TP VPN Web Manager на Keenetic
# Должен запускаться под root на роутере Keenetic с установленной средой Entware.

echo "=================================================="
echo "   Установка L2TP VPN Web Manager на Keenetic"
echo "=================================================="

# 1. Проверка окружения Entware
if [ ! -d "/opt" ] || [ ! -x "/opt/bin/opkg" ]; then
    echo "Ошибка: Среда Entware не найдена в /opt!"
    echo "Пожалуйста, установите Entware на ваш роутер Keenetic перед установкой."
    exit 1
fi

echo "[+] Среда Entware найдена."

# 2. Проверка и установка пакетов
echo "[+] Проверка и установка необходимых пакетов..."
REQUIRED_PACKAGES="strongswan-default strongswan-swanctl strongswan-mod-openssl xl2tpd ip-full iptables ppp-mod-pppol2tp"
PACKAGES_TO_INSTALL=""

for pkg in $REQUIRED_PACKAGES; do
    if ! opkg list-installed | grep -q "^$pkg "; then
        PACKAGES_TO_INSTALL="$PACKAGES_TO_INSTALL $pkg"
    fi
done

if [ -n "$PACKAGES_TO_INSTALL" ]; then
    echo "[+] Устанавливаем недостающие пакеты: $PACKAGES_TO_INSTALL..."
    opkg update
    opkg install $PACKAGES_TO_INSTALL
fi

# 2.5. Очистка старой конфигурации и процессов (для предотвращения конфликтов)
echo "[+] Очистка предыдущей конфигурации и остановка старых процессов..."
if [ -x "/opt/etc/init.d/S99l2tp-vpn" ]; then
    /opt/etc/init.d/S99l2tp-vpn stop >/dev/null 2>&1 || true
fi
if [ -x "/opt/etc/init.d/S99l2tp-web" ]; then
    /opt/etc/init.d/S99l2tp-web stop >/dev/null 2>&1 || true
fi
# Отключаем стандартный автозапуск xl2tpd из Entware, чтобы избежать конфликтов
for init_script in /opt/etc/init.d/S81xl2tpd /opt/etc/init.d/S80xl2tpd; do
    if [ -f "$init_script" ]; then
        echo "[+] Отключение стандартного скрипта запуска $init_script..."
        "$init_script" stop >/dev/null 2>&1 || true
        chmod -x "$init_script"
    fi
done
killall xl2tpd 2>/dev/null || true
killall charon 2>/dev/null || true
killall l2tp-web 2>/dev/null || true
ip link delete opkgtun0 2>/dev/null || true
rm -f /opt/bin/l2tp 2>/dev/null
rm -f /opt/etc/init.d/S99l2tp-vpn 2>/dev/null

# 3. Устранение предупреждений strongSwan
echo "[+] Настройка strongSwan для устранения предупреждений..."
mkdir -p /opt/var/ipsec
touch /opt/var/ipsec/strongswan.conf

# Мы всегда перезаписываем /opt/etc/strongswan.conf, чтобы гарантировать запись логов в файл
echo "[+] Настройка strongSwan для детального логирования..."
cat <<EOF > /opt/etc/strongswan.conf
charon {
    load_plugins = yes
    filelog {
        charon-log {
            path = /opt/var/log/swanctl.log
            time_format = %H:%M:%S
            ike = 2
            cfg = 2
            net = 1
            default = 1
            flush_line = yes
        }
    }
}
include strongswan.d/*.conf
EOF

# 4. Создание необходимых директорий
mkdir -p /opt/usr/bin
mkdir -p /opt/etc/xl2tpd
mkdir -p /opt/var/log
mkdir -p /opt/var/run

# 5. Определение архитектуры и копирование бинарного файла веб-менеджера
ARCH=$(uname -m)
if [ "$ARCH" = "mips" ]; then
    # Проверка на Little Endian (MT7621)
    if grep -qiE "MediaTek|Ralink|MT76|RT3|RT5|Little" /proc/cpuinfo 2>/dev/null; then
        ARCH="mipsel"
    fi
fi

case "$ARCH" in
    mipsel)
        BIN_NAME="l2tp-web-mipsle"
        ;;
    aarch64)
        BIN_NAME="l2tp-web-arm64"
        ;;
    arm*)
        BIN_NAME="l2tp-web-arm"
        ;;
    *)
        BIN_NAME="l2tp-web-linux"
        ;;
esac

echo "[+] Архитектура роутера: $ARCH. Требуемый файл: $BIN_NAME"

# Проверяем наличие локального файла (например, если скопировали файлы вручную)
if [ -f "./$BIN_NAME" ]; then
    echo "[+] Копирование локального файла ./$BIN_NAME -> /opt/usr/bin/l2tp-web..."
    cp "./$BIN_NAME" /opt/usr/bin/l2tp-web
    chmod +x /opt/usr/bin/l2tp-web
elif [ -f "./l2tp-web" ]; then
    echo "[+] Копирование локального файла ./l2tp-web -> /opt/usr/bin/l2tp-web..."
    cp "./l2tp-web" /opt/usr/bin/l2tp-web
    chmod +x /opt/usr/bin/l2tp-web
else
    # Скачиваем бинарник из GitHub репозитория (ветка main)
    DOWNLOAD_URL="https://raw.githubusercontent.com/l-ptrol/L2TP-VPN-Web-Manager/main/$BIN_NAME"
    echo "[+] Скачивание бинарного файла с GitHub: $DOWNLOAD_URL..."
    
    # Пробуем wget
    wget -qO /opt/usr/bin/l2tp-web "$DOWNLOAD_URL" 2>/dev/null || \
    wget -O /opt/usr/bin/l2tp-web "$DOWNLOAD_URL" 2>/dev/null || \
    curl -sL -o /opt/usr/bin/l2tp-web "$DOWNLOAD_URL"
    
    if [ -s "/opt/usr/bin/l2tp-web" ]; then
        echo "[+] Скачивание завершено успешно."
        chmod +x /opt/usr/bin/l2tp-web
    else
        # Резервный вариант: если файл уже был установлен ранее
        if [ -f "/opt/usr/bin/l2tp-web" ]; then
            echo "[!] Предупреждение: Не удалось скачать файл, используем существующий в /opt/usr/bin/l2tp-web"
            chmod +x /opt/usr/bin/l2tp-web
        else
            echo "[-] Ошибка: Не удалось скачать бинарный файл $BIN_NAME!"
            echo "    Пожалуйста, убедитесь, что на роутере установлен пакет 'wget-ssl' или 'curl' и есть интернет."
            exit 1
        fi
    fi
fi

# 6. Создание дефолтного конфигурационного файла
CONFIG_FILE="/opt/etc/l2tp_vpn_config.json"
if [ ! -f "$CONFIG_FILE" ]; then
    echo "[+] Создание конфигурационного файла по умолчанию в $CONFIG_FILE..."
    cat <<EOF > "$CONFIG_FILE"
{
  "web_port": 8081,
  "profiles": [],
  "active_id": ""
}
EOF
else
    echo "[+] Конфигурационный файл уже существует. Пропускаем создание."
fi

# 7. Создание скрипта автозапуска веб-менеджера в init.d
INIT_SCRIPT="/opt/etc/init.d/S99l2tp-web"
echo "[+] Создание скрипта автозапуска в $INIT_SCRIPT..."

cat <<'EOF' | tr -d '\r' > "$INIT_SCRIPT"
#!/bin/sh

export PATH=/opt/sbin:/opt/bin:/opt/usr/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

PROG="/opt/usr/bin/l2tp-web"
PIDFILE="/opt/var/run/l2tp-web.pid"

case "$1" in
    start)
        killall l2tp-web 2>/dev/null || true
        sleep 1
        echo "Starting L2TP VPN Web Manager..."
        mkdir -p /opt/var/log
        mkdir -p /opt/var/run
        
        $PROG </dev/null >/opt/var/log/l2tp-web.log 2>&1 &
        echo $! > "$PIDFILE"
        echo "Service started."
        ;;
    stop)
        echo "Stopping L2TP VPN Web Manager..."
        if [ -f "$PIDFILE" ]; then
            kill $(cat "$PIDFILE") 2>/dev/null
            rm -f "$PIDFILE"
        fi
        killall l2tp-web 2>/dev/null || true
        echo "Service stopped."
        ;;
    restart)
        $0 stop
        sleep 2
        $0 start
        ;;
    status)
        if pgrep -f "l2tp-web" > /dev/null; then
            echo "Status: running"
        else
            echo "Status: stopped"
        fi
        ;;
    *)
        echo "Usage: $0 {start|stop|restart|status}"
        exit 1
        ;;
esac
EOF

chmod +x "$INIT_SCRIPT"

# 7.5. Создаем глобальную команду управления ptrol-l2tp
mkdir -p /opt/bin
cat <<'EOF' > /opt/bin/ptrol-l2tp
#!/bin/sh
export PATH="/opt/bin:/opt/sbin:$PATH"
/opt/etc/init.d/S99l2tp-vpn "$@"
EOF
chmod +x /opt/bin/ptrol-l2tp

# 8. Детектируем локальный IP роутера (LAN) для вывода ссылки
LOCAL_IP=""
for iface in br0 br-lan; do
    IP=$(ip addr show "$iface" 2>/dev/null | grep -oE 'inet [0-9.]+' | head -n1 | cut -d' ' -f2)
    if [ -n "$IP" ]; then
        LOCAL_IP="$IP"
        break
    fi
done

if [ -z "$LOCAL_IP" ]; then
    LOCAL_IP=$(ip addr show 2>/dev/null | grep -oE 'inet 192\.168\.[0-9.]+|inet 10\.[0-9.]+|inet 172\.(1[6-9]|2[0-9]|3[0-1])\.[0-9.]+' | head -n1 | cut -d' ' -f2)
fi

if [ -z "$LOCAL_IP" ]; then
    LOCAL_IP="192.168.1.1"
fi

# 9. Запуск службы веб-менеджера
if [ -f "/opt/usr/bin/l2tp-web" ]; then
    echo "[+] Запуск службы веб-менеджера..."
    "$INIT_SCRIPT" restart
fi

echo "=================================================="
echo "Установка успешно завершена!"
echo "=================================================="
echo "Веб-интерфейс будет доступен по адресу: http://${LOCAL_IP}:8081"
echo "Управление туннелем через SSH: ptrol-l2tp {start|stop|status|restart}"
echo "=================================================="
