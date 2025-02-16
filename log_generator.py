import random
from datetime import timedelta
import argparse
import urllib.parse
from config import *
from malicious_profiles import MALICIOUS_PROFILES

def generate_logs(output_file, num_logs, num_malicious, profile):
    NUM_LOGS = num_logs
    NUM_MALICIOUS = num_malicious

    # Site structure (Can be edited)
    COMMON_ENTRY_PATHS = ['/', '/about', '/products', '/blog/post1', '/services']
    DEEPER_PATHS = ['/dashboard', '/checkout', '/cart', '/portfolio', '/testimonials']
    API_PATHS = ['/api/v1/products', '/api/v1/users']
    AUTH_PATHS = ['/login', '/register', '/logout']

    INTERNAL_REFERRERS = [
        f"https://{DOMAIN}/",
        f"https://{DOMAIN}/about",
        f"https://{DOMAIN}/products",
        f"https://{DOMAIN}/blog/post1",
        f"https://{DOMAIN}/services",
        "-"  # Direct traffic
    ]

    EXTERNAL_REFERRERS = [
        'https://www.google.com/',
        'https://www.facebook.com/',
        'https://t.co/',
        'https://www.linkedin.com/',
        'https://www.reddit.com/',
        'https://news.ycombinator.com/'
    ]

    REFERRER_WEIGHTS = [0.65, 0.35]  # 65% internal/direct, 35% external (Matching a standard site visit pattern, can be altered depending on use case.)

    # Query parameters for different sections (add more if needed)
    BENIGN_QUERY_PARAMS = {
        '/products': ['category=electronics', 'sort=price', 'page=2'],
        '/blog': ['tag=security', 'author=admin', 'year=2024'],
        '/search': ['q=product', 'q=contact', 'q=about+us']
    }

    # Malicious configuration updates (called from malicious_profiles.py)
    MALICIOUS_IPS = MALICIOUS_PROFILES[profile]['ips']

    MALICIOUS_USER_AGENTS = MALICIOUS_PROFILES[profile]['user_agents']

    MALICIOUS_PATHS = MALICIOUS_PROFILES[profile]['paths']

    MALICIOUS_COMMANDS = MALICIOUS_PROFILES[profile]['patterns']

    # Helper functions
    def get_weighted_choice(choices_dict):
        total = sum(choices_dict.values())
        rand = random.uniform(0, total)
        current = 0
        for key, weight in choices_dict.items():
            if rand < current + weight:
                return key
            current += weight
        return list(choices_dict.keys())[-1]

    def generate_realistic_path(referrer):
        """Generate paths based on referrer type and site structure"""
        path_type = random.choices(
            list(PATH_WEIGHTS.keys()),
            weights=list(PATH_WEIGHTS.values()),
            k=1
        )[0]
        
        if referrer == "-":  # Direct traffic
            return random.choice(COMMON_ENTRY_PATHS + DEEPER_PATHS)
        
        if referrer.startswith(f"https://{DOMAIN}"):
            # Added for more realistic internal navigation patterns
            if path_type == 'entry':
                return random.choice(DEEPER_PATHS + AUTH_PATHS)
            elif path_type == 'deeper':
                return random.choice(DEEPER_PATHS)
            elif path_type == 'api':
                return random.choice(API_PATHS)
            else:
                return random.choice(AUTH_PATHS)
        else:
            # External referrer behavior
            if random.random() < 0.8:
                return random.choice(COMMON_ENTRY_PATHS)
            else:
                return random.choice(DEEPER_PATHS)

    malicious_indices = random.sample(range(NUM_LOGS), NUM_MALICIOUS)
    logs = []
    current_time = START_TIME

    for i in range(NUM_LOGS):
        time_increment = timedelta(seconds=random.randint(1, 3)) # Can be edited to increase / decrease log density
        current_time += time_increment
        time_str = current_time.strftime('%d/%b/%Y:%H:%M:%S +0000')

        if i in malicious_indices:
            # Malicious entry (keeps existing pattern but uses new domain (set in config.py))
            ip = random.choice(MALICIOUS_IPS)
            path = random.choice(MALICIOUS_PATHS) + urllib.parse.quote(random.choice(MALICIOUS_COMMANDS))
            status = 200
            bytes_sent = random.randint(200, 500)
            referrer = random.choice(EXTERNAL_REFERRERS + ["-"])
            user_agent = random.choice(MALICIOUS_USER_AGENTS)
            request = f'GET {path} HTTP/1.1'
        else:
            # Benign entry
            ip = random.choice(BENIGN_IPS)
            referrer = random.choices(
                [random.choice(INTERNAL_REFERRERS), random.choice(EXTERNAL_REFERRERS)],
                weights=REFERRER_WEIGHTS,
                k=1
            )[0]
            
            path = generate_realistic_path(referrer)
            
            # Add query parameters 30% of the time for GET requests (helps improve correctly simulated user behaviour to a site)
            if random.random() < 0.3 and path in BENIGN_QUERY_PARAMS:
                query = random.choice(BENIGN_QUERY_PARAMS[path])
                path += f'?{query}'
            
            method = 'POST' if path in AUTH_PATHS and random.random() < 0.4 else 'GET'
            status = get_weighted_choice(STATUS_CODES)
            bytes_sent = random.randint(1000, 5000) if status == 200 else random.randint(200, 500)
            user_agent = random.choice(USER_AGENTS)
            request = f'{method} {path} HTTP/1.1'

        log_entry = f'{ip} - - [{time_str}] "{request}" {status} {bytes_sent} "{referrer}" "{user_agent}"\n'
        logs.append(log_entry)

    # Write to file
    with open(output_file, 'w') as f:
        f.writelines(logs)

    print(f"Generated {NUM_LOGS} logs with {NUM_MALICIOUS} malicious entries to {output_file}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Generate realistic NGINX logs')
    parser.add_argument('-o', '--output', default='access.log', help='Output file name')
    parser.add_argument('-n', '--num', type=int, default=8000, help='Total number of logs')
    parser.add_argument('-m', '--malicious', type=int, default=10, help='Number of malicious entries')
    parser.add_argument('-p', '--profile', choices=MALICIOUS_PROFILES.keys(), default='c2', help='Malicious traffic profile')
    
args = parser.parse_args()
    
generate_logs(output_file=args.output, num_logs=args.num, num_malicious=args.malicious, profile=args.profile)