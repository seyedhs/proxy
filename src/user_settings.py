# Please modify the settings below according to your needs.

# List of source URLs to fetch proxy configurations from.
# Add or remove URLs as needed. All URLs in this list are automatically enabled.
SOURCE_URLS = [
   #  "https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/top100.txt",
   "https://raw.githubusercontent.com/inaz266/In-az-26/refs/heads/main/filtee.txt",
    # "https://raw.githubusercontent.com/Delta-Kronecker/V2ray-Config/refs/heads/main/config/countries/us.txt",
    # "https://github.com/Delta-Kronecker/V2ray-Config/raw/refs/heads/main/config/countries/de.txt",
    # "https://github.com/Delta-Kronecker/V2ray-Config/raw/refs/heads/main/config/countries/nl.txt",
   #  "https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/verified/configs_base64.txt",
   #  "https://github.com/Delta-Kronecker/V2ray-Config/raw/refs/heads/main/config/all_configs.txt",
   # "https://raw.githubusercontent.com/mahsanet/MahsaFreeConfig/refs/heads/main/mci/sub_1.txt#mci",
   # "https://raw.githubusercontent.com/mahsanet/MahsaFreeConfig/refs/heads/main/mtn/sub_1.txt#mtn",
  #  "https://raw.githubusercontent.com/zieng2/wl/refs/heads/main/vless_universal.txt",
  "https://raw.githubusercontent.com/patterniha/Free-Configs/main/configs.txt",
    "https://raw.githubusercontent.com/luxxuria/harvester/main/speed_tested.txt",
   # "https://raw.githubusercontent.com/ShadowException/VPN/refs/heads/main/configs/VPN-cat#shadowexception",
   # "https://raw.githubusercontent.com/RKPchannel/RKP_bypass_configs/refs/heads/main/whitelist.txt",
   # "https://gitverse.ru/api/repos/MishaLan/MishaLan/raw/branch/master/MishaLan.txt",
   # "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-CIDR-RU-checked.txt",
   # "https://raw.githubusercontent.com/barry-far/V2ray-config/main/Splitted-By-Protocol/vless.txt",
   # "https://raw.githubusercontent.com/pesarkermani/my_sub/main/sub.txt",
   # "https://raw.githubusercontent.com/Mahdi0024/ProxyCollector/master/sub/proxies.txt",
   # "https://raw.githubusercontent.com/iampedii/whitedns-sub/refs/heads/main/base64.txt",
   # "https://raw.githubusercontent.com/Ashkan-m/v2ray/main/Sub.txt",
    #"https://raw.githubusercontent.com/masir-sefid/Sub/main/@Masir_Sefid.txt",
   # "https://raw.githubusercontent.com/arshiacomplus/v2rayExtractor/refs/heads/main/mix/sub.html",
   # "https://raw.githubusercontent.com/therealaleph/Iran-configs/refs/heads/main/ir_configs.txt",
  #  "https://raw.githubusercontent.com/free1zona/Keyfreetee/refs/heads/main/razlo4ka7",
   # "https://raw.githubusercontent.com/prominbro/sub/refs/heads/main/212.txt#prominbro",
   # "https://raw.githubusercontent.com/v2FreeHub/v2hub-configs/refs/heads/main/Sub-AutoUpdate#v2freehub",
   # "https://raw.githubusercontent.com/IranianCypherpunks/Xray/main/Sub#Ln2Ray",
   # "https://channel.tradeip.store:2096/sub/t.me.TradeIP#TradeIP",
   # "https://square-force.diversant317.workers.dev/#Square Force Heavy",
   # "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/Vless-Reality-White-Lists-Rus-Mobile.txt#igareck",
  #  "https://raw.githubusercontent.com/liketolivefree/kobabi/main/sub_all.txt#like to live free",
  #  "https://raw.githubusercontent.com/flaafix/AetrisVPN/refs/heads/main/AetrisVPN.txt",
  #  "https://raw.githubusercontent.com/mcodersir/DicodeConfigChecker/refs/heads/main/sub.txt",
   # "https://raw.githubusercontent.com/10ium/V2ray-Config/main/Splitted-By-Protocol/hysteria2.txt",
  #  "https://square-force.diversant317.workers.dev",
    #"https://t.me/s/NetliVPN",
   # "https://t.me/GozargahAzad",
  #  "https://t.me/s/PrivateVPNs",
   # "https://t.me/s/DirectVPN",
   # "https://t.me/s/persianvpnhub",
  #  "https://t.me/TabadolConfig",
   # "https://t.me/s/ar14n24b",
  #  "https://t.me/s/SOSkeyNET",
   # "https://t.me/s/marambashi",
  #  "https://t.me/s/meliproxyy",
  #  "https://raw.githubusercontent.com/parvinxs/Submahsanetxsparvin/refs/heads/main/Sub.mahsa.xsparvin",
]

# Set to True to fetch the maximum possible number of configurations.
# If True, SPECIFIC_CONFIG_COUNT will be ignored.
USE_MAXIMUM_POWER = True

# Desired number of configurations to fetch.
# This is used only if USE_MAXIMUM_POWER is False.
SPECIFIC_CONFIG_COUNT = 2000

# Dictionary of protocols to enable or disable.
# Set each protocol to True to enable, False to disable.
ENABLED_PROTOCOLS = {
    "wireguard://": False,
    "hysteria2://": True,
    "vless://": True,
    "vmess://": True,
    "ss://": True,
    "trojan://": True,
    "tuic://": False,
}

# Maximum age of configurations in days.
# Configurations older than this will be considered invalid.
MAX_CONFIG_AGE_DAYS = 1

# --- Sing-box Config Tester Settings ---

# Set to True to enable testing of configs using sing-box.
# If True, sing-box will be used to test all fetched configs and create a 'tested' config file.
# If False, the testing step will be skipped.
ENABLE_SINGBOX_TESTER = True

# Number of parallel workers to use for testing sing-box configs.
# A higher number means faster testing but uses more CPU/RAM.
# (Previously capped at os.cpu_count() ~4 in code regardless of this value —
# that bug is fixed, so this number now actually takes effect. GitHub Actions
# runners handle this fine since each worker just waits on network I/O.)
SINGBOX_TESTER_MAX_WORKERS = 40

# Maximum time (in seconds) to wait for a sing-box config to respond during testing.
# This can be a single number (same timeout every round) OR a list with one
# value per round for STAGED/"pele-ای" testing: round 1 uses a loose timeout
# so nothing is unfairly dropped, and only the survivors move on to round 2,
# which uses a tighter timeout, and so on -- so each stage filters harder than
# the last and only the genuinely fast/stable configs make it to the end.
# The list length should match HEALTHCHECK_ROUNDS below (if it's shorter, the
# last value is repeated; if longer, it's truncated).
# Only one round now (HEALTHCHECK_ROUNDS = 1), so just this single timeout is used.
SINGBOX_TESTER_TIMEOUT_SECONDS = 10

# List of URLs to test sing-box configs against.
# The tester will try each URL in order until one succeeds.
SINGBOX_TESTER_URLS = [
    'https://www.youtube.com/generate_204'
  #  'https://www.gstatic.com/generate_204'
]

# --- Xray Config Tester Settings ---

# Set to True to enable testing of configs using Xray core.
# If True, Xray will be used to test all fetched configs before conversion and create a 'tested' config file.
# If False, the testing step will be skipped.
ENABLE_XRAY_TESTER = True

# Number of parallel workers to use for testing Xray configs.
# A higher number means faster testing but uses more CPU/RAM.
# (Previously capped at os.cpu_count() ~4 in code regardless of this value —
# that bug is fixed, so this number now actually takes effect.)
XRAY_TESTER_MAX_WORKERS = 40

# Maximum time (in seconds) to wait for an Xray config to respond during testing.
# Same staged behaviour as SINGBOX_TESTER_TIMEOUT_SECONDS above: a single
# number applies to every round, or a list gives each round its own
# (decreasing) timeout so later rounds are stricter than earlier ones.
# Only one round now (HEALTHCHECK_ROUNDS = 1), so just this single timeout is used.
XRAY_TESTER_TIMEOUT_SECONDS = 10

# List of URLs to test Xray configs against.
# The tester will try each URL in order until one succeeds.
XRAY_TESTER_URLS = [
    'https://www.youtube.com/generate_204'
   # 'https://www.gstatic.com/generate_204'
]

# --- Health Check Settings ---

# Number of independent, staged test rounds a config must pass to be published.
# Testing once can pass a node that only happened to work for a moment (or
# fail one that had a one-off blip); requiring several independent passes
# filters those out. A config that fails even one round is dropped.
# This also controls how many entries from the *_TIMEOUT_SECONDS lists above
# are used (round 1 = first entry, round 2 = second entry, etc.).
HEALTHCHECK_ROUNDS = 1

# Maximum number of configs to keep in each final published output (the
# plain-text list and the sing-box list). After the health check, surviving
# configs are ordered fastest-first by their median latency across rounds,
# and only the best ones up to this count are kept.
MAX_OUTPUT_CONFIGS = 100

# --- Location API Settings ---

# List of free IP geolocation APIs to identify server countries.
# The system tries APIs in order from top to bottom (first = highest priority).
# If one API fails or is rate-limited, the system automatically tries the next one.
#
# HOW TO ADD AN API:
# Simply add the domain name or full URL. Examples:
#   freeipapi.com
#   ip-api.com
#   https://ipapi.co
#   api.iplocation.net
#
# The system automatically detects the correct API format and endpoint.
# No API key is required for the APIs listed below.
#
# RECOMMENDED FREE APIs (ranked by reliability and rate limits):
#
# 1. freeipapi.com - 60 requests/minute, very fast, no registration
# 2. ip-api.com - 45 requests/minute, very reliable, widely used
# 3. ipapi.co - 1000 requests/day (~30k/month), good accuracy
# 4. ipwhois.app - 10000 requests/month, decent speed
# 5. api.iplocation.net - unlimited, fast, accurate
# 6. api.ip.sb - no published limit, fast, simple JSON (endpoint: /geoip/{ip})
#
LOCATION_APIS = [
    'api.ip.sb'
    'api.iplocation.net',
    'freeipapi.com',
    'ip-api.com',
    'ipapi.co',
]
