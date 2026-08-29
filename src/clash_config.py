import json
import os
import sys
import logging
from typing import Dict, List, Optional

import yaml

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

GROUP_NAME = "زن زندگی آزادی"
AUTO_GROUP_NAME = "بهترین پینگ"


def _tls_fields(tls: Optional[Dict], sni_key: str = 'servername') -> Dict:
    """Fields shared across vmess/vless/trojan/hysteria2 TLS settings.
    sni_key differs by protocol in Clash's schema: 'servername' for
    vmess/vless, 'sni' for trojan/hysteria2."""
    fields: Dict = {}
    if not tls:
        return fields
    if tls.get('server_name'):
        fields[sni_key] = tls['server_name']
    if 'insecure' in tls:
        fields['skip-cert-verify'] = bool(tls.get('insecure'))
    if tls.get('alpn'):
        fields['alpn'] = tls['alpn']
    reality = tls.get('reality') or {}
    if reality.get('enabled'):
        fields['reality-opts'] = {
            'public-key': reality.get('public_key', ''),
            'short-id': reality.get('short_id', ''),
        }
    utls = tls.get('utls') or {}
    if utls.get('enabled') and utls.get('fingerprint'):
        fields['client-fingerprint'] = utls['fingerprint']
    return fields


def _network_opts(transport: Optional[Dict]) -> Dict:
    """ws/grpc are well supported by Clash Meta; other transports (http/quic/
    kcp) are left as plain tcp rather than guessing at a mapping that could
    silently produce a broken proxy entry."""
    opts: Dict = {}
    if not transport:
        return opts
    ttype = transport.get('type')
    if ttype == 'ws':
        opts['network'] = 'ws'
        
        # تصحیح ساختار هدرها برای جلوگیری از خطای Clash Meta
        raw_headers = transport.get('headers', {}) or {}
        clean_headers = {}
        for key, value in raw_headers.items():
            if isinstance(value, list) and len(value) > 0:
                clean_headers[key] = str(value[0])
            else:
                clean_headers[key] = str(value)
                
        opts['ws-opts'] = {
            'path': transport.get('path', '/'),
            'headers': clean_headers,
        }
    elif ttype == 'grpc':
        opts['network'] = 'grpc'
        opts['grpc-opts'] = {
            'grpc-service-name': transport.get('service_name', ''),
        }
    return opts


def convert_outbound(ob: Dict) -> Optional[Dict]:
    ob_type = ob.get('type')
    name = ob.get('tag') or 'unnamed'
    server = ob.get('server')
    port = ob.get('server_port')

    if not server or not port:
        return None

    try:
        if ob_type == 'vmess':
            if not ob.get('uuid'):
                return None
            tls = ob.get('tls') or {}
            proxy = {
                'name': name, 'type': 'vmess', 'server': server, 'port': int(port),
                'uuid': ob['uuid'], 'alterId': int(ob.get('alter_id') or 0),
                'cipher': ob.get('security') or 'auto', 'udp': True,
                'tls': bool(tls.get('enabled')),
            }
            proxy.update(_tls_fields(tls, 'servername'))
            proxy.update(_network_opts(ob.get('transport')))

        elif ob_type == 'vless':
            if not ob.get('uuid'):
                return None
            tls = ob.get('tls') or {}
            proxy = {
                'name': name, 'type': 'vless', 'server': server, 'port': int(port),
                'uuid': ob['uuid'], 'udp': True,
                'tls': bool(tls.get('enabled')),
            }
            if ob.get('flow'):
                proxy['flow'] = ob['flow']
            proxy.update(_tls_fields(tls, 'servername'))
            proxy.update(_network_opts(ob.get('transport')))

        elif ob_type == 'trojan':
            if not ob.get('password'):
                return None
            tls = ob.get('tls') or {}
            proxy = {
                'name': name, 'type': 'trojan', 'server': server, 'port': int(port),
                'password': ob['password'], 'udp': True,
            }
            proxy.update(_tls_fields(tls, 'sni'))
            proxy.update(_network_opts(ob.get('transport')))

        elif ob_type == 'hysteria2':
            if not ob.get('password'):
                return None
            tls = ob.get('tls') or {}
            proxy = {
                'name': name, 'type': 'hysteria2', 'server': server, 'port': int(port),
                'password': ob['password'],
            }
            proxy.update(_tls_fields(tls, 'sni'))

        elif ob_type == 'shadowsocks':
            if not ob.get('method') or not ob.get('password'):
                return None
            proxy = {
                'name': name, 'type': 'ss', 'server': server, 'port': int(port),
                'cipher': ob['method'], 'password': ob['password'], 'udp': True,
            }

        else:
            return None

        return proxy

    except Exception as e:
        logger.warning(f"Failed to convert '{name}' ({ob_type}) to Clash format: {e}")
        return None


def build_clash_config(proxies: List[Dict]) -> Dict:
    proxy_names = [p['name'] for p in proxies]
    return {
        'mixed-port': 7890,
        'allow-lan': False,
        'mode': 'rule',
        'log-level': 'warning',
        'ipv6': False,
        'unified-delay': True,
        'tcp-concurrent': True,
        'dns': {
            'enable': True,
            'ipv6': False,
            'default-nameserver': ['1.1.1.1', '8.8.8.8'],
            'nameserver': [
                'https://dns.google/dns-query',
                'https://cloudflare-dns.com/dns-query',
            ],
        },
        'proxies': proxies,
        'proxy-groups': [
            {
                'name': GROUP_NAME,
                'type': 'select',
                'proxies': [AUTO_GROUP_NAME] + proxy_names + ['DIRECT'],
            },
            {
                'name': AUTO_GROUP_NAME,
                'type': 'url-test',
                'proxies': proxy_names,
                'url': 'https://www.gstatic.com/generate_204',
                'interval': 300,
                'tolerance': 50,
            },
        ],
        'rules': [
            # ۱. مسدودسازی تبلیغات و سرویس‌های آنالیتیکس (Adblock)
            'GEOSITE,category-ads-all,REJECT',
            
            # ۲. بای‌پاس دامنه‌ها و آی‌پی‌های ایران (جایگزینی GEOSITE با DOMAIN-SUFFIX)
            'DOMAIN-SUFFIX,ir,DIRECT',
            'GEOIP,IR,DIRECT',
            
            # ۳. مابقی ترافیک از فیلترشکن رد شود
            f'MATCH,{GROUP_NAME}',
        ],
    }



def main():
    # Built from the secure + tested sing-box set — same trust level as the
    # other final outputs (singbox_configs_secure.json / xray_secure_loadbalanced_config.json).
    input_file = 'configs/singbox_configs_secure.json'
    output_file = 'configs/clash_config.yaml'

    try:
        with open(input_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except FileNotFoundError:
        logger.error(f"{input_file} not found!")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Error reading {input_file}: {e}")
        sys.exit(1)

    proxies = []
    for ob in data.get('outbounds', []):
        if ob.get('type') in ('selector', 'urltest', 'direct', 'block', 'dns'):
            continue
        proxy = convert_outbound(ob)
        if proxy:
            proxies.append(proxy)

    if not proxies:
        logger.error("No proxies could be converted to Clash format")
        sys.exit(1)

    clash_config = build_clash_config(proxies)

    os.makedirs(os.path.dirname(output_file) or '.', exist_ok=True)
    with open(output_file, 'w', encoding='utf-8') as f:
        yaml.safe_dump(clash_config, f, allow_unicode=True, sort_keys=False, default_flow_style=False)

    logger.info(f"Successfully converted {len(proxies)} configs to Clash format: {output_file}")


if __name__ == '__main__':
    main()
