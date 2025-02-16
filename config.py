from datetime import datetime


DOMAIN = "acmesolutions.shop"
START_TIME = datetime(2025, 2, 2, 19, 30, 0)

BENIGN_IPS = [
    '203.0.113.45', '198.51.100.22', '203.0.113.250',
    '192.0.78.13', '192.0.78.14', '185.199.108.154',
    '10.0.0.1', '172.16.0.1', '192.168.1.1',
    '192.168.100.10', '10.1.1.1', '172.31.255.255',
    '203.0.113.10', '198.51.100.100', '192.0.2.5',
    '169.254.169.254', '198.51.100.50', '144.96.23.25'
]
PATH_WEIGHTS = {
    'entry': 65,       # Common entry points
    'deeper': 25,      # Deeper navigation
    'api': 5,          # API endpoints
    'auth': 5           # Authentication paths
}

STATUS_CODES = {
    200: 65,
    304: 10,
    404: 8,
    302: 7,
    403: 5,
    500: 5
}

USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/118.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Safari/605.1.15',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 16_6_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (iPad; CPU OS 16_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (Linux; Android 12; Pixel 5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 11; SM-G991U) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Mobile Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/118.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Safari/605.1.15',
    'Mozilla/5.0 (Linux; Android 10; SM-A505F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 9; Nokia 7.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Mobile Safari/537.36'
]

INTERNAL_TRAFFIC_RATIO = 0.65
API_TRAFFIC_RATIO = 0.05
AUTH_POST_RATIO = 0.4