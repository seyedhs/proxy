import re
import os
import time
import json
import logging
import threading
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Optional, Set
import requests
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed
from config import ProxyConfig, ChannelConfig
from config_validator import ConfigValidator
import config_parser as parser

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('proxy_fetcher.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class ConfigFetcher:
    def __init__(self, config: ProxyConfig):
        self.config = config
        self.validator = ConfigValidator()
        self.protocol_counts: Dict[str, int] = {p: 0 for p in config.SUPPORTED_PROTOCOLS}
        self.seen_configs: Set[str] = set()
        self.channel_protocol_counts: Dict[str, Dict[str, int]] = {}
        self.session = requests.Session()
        self.session.headers.update(config.HEADERS)
        self._lock = threading.Lock()

    def extract_config(self, text: str, start_index: int, protocol: str) -> Optional[str]:
        try:
            remaining_text = text[start_index:]
            configs = self.validator.split_configs(remaining_text)
            
            for config in configs:
                if config.startswith(protocol):
                    clean_config = self.validator.clean_config(config)
                    if self.validator.validate_protocol_config(clean_config, protocol):
                        return clean_config
            return None
        except Exception as e:
            logger.error(f"Error in extract_config: {str(e)}")
            return None

    def fetch_with_retry(self, url: str) -> Optional[requests.Response]:
        backoff = 1
        for attempt in range(self.config.MAX_RETRIES):
            try:
                response = self.session.get(url, timeout=self.config.REQUEST_TIMEOUT)
                response.raise_for_status()
                return response
            except requests.RequestException as e:
                if attempt == self.config.MAX_RETRIES - 1:
                    logger.error(f"Failed to fetch {url} after {self.config.MAX_RETRIES} attempts: {str(e)}")
                    return None
                wait_time = min(self.config.RETRY_DELAY * backoff, 60)
                logger.warning(f"Attempt {attempt + 1} failed, retrying in {wait_time}s: {str(e)}")
                time.sleep(wait_time)
                backoff *= 2
        return None

    def fetch_ssconf_configs(self, url: str) -> List[str]:
        https_url = self.validator.convert_ssconf_to_https(url)
        configs = []
        
        response = self.fetch_with_retry(https_url)
        if response and response.text.strip():
            text = response.text.strip()
            if self.validator.is_base64(text):
                decoded = self.validator.decode_base64_text(text)
                if decoded:
                    text = decoded
            
            if text.startswith('ss://'):
                configs.append(text)
            else:
                configs.extend(self.validator.split_configs(text))
            
        return configs

    def check_and_decode_base64(self, text: str) -> str:
        if self.validator.is_base64(text):
            decoded = self.validator.decode_base64_text(text)
            if decoded:
                return decoded
        return text

    def fetch_configs_from_source(self, channel: ChannelConfig) -> List[str]:
        configs: List[str] = []
        channel.metrics.total_configs = 0
        channel.metrics.valid_configs = 0
        channel.metrics.unique_configs = 0
        channel.metrics.protocol_counts = {p: 0 for p in self.config.SUPPORTED_PROTOCOLS}
        
        start_time = time.time()
        
        if channel.url.startswith('ssconf://'):
            configs.extend(self.fetch_ssconf_configs(channel.url))
            if configs:
                response_time = time.time() - start_time
                self.config.update_channel_stats(channel, True, response_time)
            return configs

        response = self.fetch_with_retry(channel.url)
        if not response:
            self.config.update_channel_stats(channel, False)
            return configs

        response_time = time.time() - start_time
        
        if channel.is_telegram:
            soup = BeautifulSoup(response.text, 'html.parser')
            messages = soup.find_all('div', class_='tgme_widget_message_text')
            
            sorted_messages = sorted(
                messages,
                key=lambda message: self.extract_date_from_message(message) or datetime.min.replace(tzinfo=timezone.utc),
                reverse=True
            )
            
            for message in sorted_messages:
                if not message or not message.text:
                    continue
                
                message_date = self.extract_date_from_message(message)
                if not self.is_config_valid(message.text, message_date):
                    continue
                
                text = message.text
                text_parts = text.split()
                
                for part in text_parts:
                    part = part.strip()
                    if not part:
                        continue
                        
                    if part.startswith('ssconf://'):
                        ssconf_configs = self.fetch_ssconf_configs(part)
                        configs.extend(ssconf_configs)
                        channel.metrics.total_configs += len(ssconf_configs)
                    else:
                        decoded_part = self.check_and_decode_base64(part)
                        if decoded_part != part:
                            found_configs = self.validator.split_configs(decoded_part)
                            channel.metrics.total_configs += len(found_configs)
                            configs.extend(found_configs)
                
                found_configs = self.validator.split_configs(text)
                channel.metrics.total_configs += len(found_configs)
                configs.extend(found_configs)
        else:
            text = response.text
            text_parts = text.split()
            
            for part in text_parts:
                part = part.strip()
                if not part:
                    continue
                    
                decoded_part = self.check_and_decode_base64(part)
                if decoded_part != part:
                    found_configs = self.validator.split_configs(decoded_part)
                    channel.metrics.total_configs += len(found_configs)
                    configs.extend(found_configs)
            
            found_configs = self.validator.split_configs(text)
            channel.metrics.total_configs += len(found_configs)
            configs.extend(found_configs)
        
        configs = list(set(configs))
        
        for config in configs[:]:
            for protocol in self.config.SUPPORTED_PROTOCOLS:
                if config.startswith(protocol):
                    processed_configs = self.process_config(config, channel)
                    if not processed_configs:
                        configs.remove(config)
                    break
        
        if len(configs) >= self.config.MIN_CONFIGS_PER_CHANNEL:
            self.config.update_channel_stats(channel, True, response_time)
            self.config.adjust_protocol_limits(channel)
        else:
            self.config.update_channel_stats(channel, False)
            logger.warning(f"Not enough configs found in {channel.url}: {len(configs)} configs")
        
        return configs

    def _server_identity_key(self, clean_config: str, protocol: str) -> str:
        """Exact-string dedup misses configs that point at the same server with
        the same credentials but differ only in remark/tag or query-param
        order (very common when several source lists mirror each other).
        This builds a key from (protocol, address, port, credential) so those
        are caught too, before they ever reach the testers."""
        try:
            data = None
            if protocol == 'vmess://':
                data = parser.decode_vmess(clean_config)
                cred = data.get('id') if data else None
            elif protocol == 'vless://':
                data = parser.parse_vless(clean_config)
                cred = data.get('uuid') if data else None
            elif protocol == 'trojan://':
                data = parser.parse_trojan(clean_config)
                cred = data.get('password') if data else None
            elif protocol in ('hysteria2://', 'hy2://'):
                data = parser.parse_hysteria2(clean_config)
                cred = data.get('password') or data.get('auth') if data else None
            elif protocol == 'ss://':
                data = parser.parse_shadowsocks(clean_config)
                cred = data.get('password') if data else None
            else:
                data = None
                cred = None

            if data and data.get('address') and data.get('port'):
                return f"{protocol}|{data['address'].lower()}|{data['port']}|{cred}"
        except Exception:
            pass
        # Fallback: if we can't parse it, dedup on the exact string only.
        return clean_config

    def process_config(self, config: str, channel: ChannelConfig) -> List[str]:
        processed_configs = []
        
        if config.startswith('hy2://'):
            config = self.validator.normalize_hysteria2_protocol(config)
            
        for protocol in self.config.SUPPORTED_PROTOCOLS:
            aliases = self.config.SUPPORTED_PROTOCOLS[protocol].get('aliases', [])
            protocol_match = False
            
            if config.startswith(protocol):
                protocol_match = True
            else:
                for alias in aliases:
                    if config.startswith(alias):
                        protocol_match = True
                        config = config.replace(alias, protocol, 1)
                        break
                        
            if protocol_match:
                if not self.config.is_protocol_enabled(protocol):
                    break
                if protocol == "vmess://":
                    config = self.validator.clean_vmess_config(config)
                
                clean_config = self.validator.clean_config(config)
                if self.validator.validate_protocol_config(clean_config, protocol):
                    channel.metrics.valid_configs += 1
                    channel.metrics.protocol_counts[protocol] = channel.metrics.protocol_counts.get(protocol, 0) + 1
                    
                    dedup_key = self._server_identity_key(clean_config, protocol)
                    with self._lock:
                        if dedup_key not in self.seen_configs:
                            channel.metrics.unique_configs += 1
                            self.seen_configs.add(dedup_key)
                            processed_configs.append(clean_config)
                            self.protocol_counts[protocol] += 1
                break
                
        return processed_configs

    def extract_date_from_message(self, message) -> Optional[datetime]:
        try:
            time_element = message.find_parent('div', class_='tgme_widget_message').find('time')
            if time_element and 'datetime' in time_element.attrs:
                return datetime.fromisoformat(time_element['datetime'].replace('Z', '+00:00'))
        except Exception:
            pass
        return None

    def is_config_valid(self, config_text: str, date: Optional[datetime]) -> bool:
        if not date:
            return True
        cutoff_date = datetime.now(timezone.utc) - timedelta(days=self.config.MAX_CONFIG_AGE_DAYS)
        return date >= cutoff_date

    def balance_protocols(self, configs: List[str]) -> List[str]:
        protocol_configs: Dict[str, List[str]] = {p: [] for p in self.config.SUPPORTED_PROTOCOLS}
        for config in configs:
            if config.startswith('hy2://'):
                config = self.validator.normalize_hysteria2_protocol(config)
                
            for protocol in self.config.SUPPORTED_PROTOCOLS:
                if config.startswith(protocol):
                    protocol_configs[protocol].append(config)
                    break
        
        total_configs = sum(len(configs) for configs in protocol_configs.values())
        if total_configs == 0:
            return []
            
        balanced_configs: List[str] = []
        sorted_protocols = sorted(
            protocol_configs.items(),
            key=lambda x: (
                self.config.SUPPORTED_PROTOCOLS[x[0]]["priority"],
                len(x[1])
            ),
            reverse=True
        )
        
        for protocol, protocol_config_list in sorted_protocols:
            protocol_info = self.config.SUPPORTED_PROTOCOLS[protocol]
            if len(protocol_config_list) >= protocol_info["min_configs"]:
                max_configs = min(
                    protocol_info["max_configs"],
                    len(protocol_config_list)
                )
                balanced_configs.extend(protocol_config_list[:max_configs])
            elif protocol_info["flexible_max"] and len(protocol_config_list) > 0:
                balanced_configs.extend(protocol_config_list)
        
        return balanced_configs

    def fetch_all_configs(self, max_workers: int = 12) -> List[str]:
        all_configs: List[str] = []
        enabled_channels = self.config.get_enabled_channels()
        total_channels = len(enabled_channels)
        completed = 0

        # Channels are independent network sources, so fetch them concurrently
        # instead of one-at-a-time with a fixed 2s gap between each — that
        # serial loop (plus per-channel retry backoff on failures) was the
        # main reason this step could take many minutes on its own.
        with ThreadPoolExecutor(max_workers=min(max_workers, total_channels or 1)) as executor:
            futures = {
                executor.submit(self.fetch_configs_from_source, channel): channel
                for channel in enabled_channels
            }
            for future in as_completed(futures):
                channel = futures[future]
                completed += 1
                try:
                    channel_configs = future.result()
                    all_configs.extend(channel_configs)
                    logger.info(f"[{completed}/{total_channels}] {channel.url}: {len(channel_configs)} configs")
                except Exception as e:
                    logger.error(f"[{completed}/{total_channels}] {channel.url} failed: {e}")
        
        if all_configs:
            all_configs = self.balance_protocols(sorted(set(all_configs)))
            return all_configs
        return []

def save_configs(configs: List[str], config: ProxyConfig):
    try:
        os.makedirs(os.path.dirname(config.OUTPUT_FILE), exist_ok=True)
        with open(config.OUTPUT_FILE, 'w', encoding='utf-8') as f:
            header = """//profile-title: base64:2LLZhiDYstmG2K/ar9uMINii2LLYp9iv24wg
//profile-update-interval: 1
//subscription-userinfo: upload=0; download=0; total=10737418240000000; expire=2546249531
//support-url: https://t.me/SeyedNG
//profile-web-page-url: https://github.com/SeyedNG

"""
            f.write(header)
            for config in configs:
                f.write(config + '\n\n')
        logger.info(f"Successfully saved {len(configs)} configs to {config.OUTPUT_FILE}")
    except Exception as e:
        logger.error(f"Error saving configs: {str(e)}")

def save_channel_stats(config: ProxyConfig):
    try:
        stats = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'channels': []
        }
        
        for channel in config.SOURCE_URLS:
            channel_stats = {
                'url': channel.url,
                'enabled': channel.enabled,
                'metrics': {
                    'total_configs': channel.metrics.total_configs,
                    'valid_configs': channel.metrics.valid_configs,
                    'unique_configs': channel.metrics.unique_configs,
                    'avg_response_time': round(channel.metrics.avg_response_time, 2),
                    'success_count': channel.metrics.success_count,
                    'fail_count': channel.metrics.fail_count,
                    'overall_score': round(channel.metrics.overall_score, 2),
                    'last_success': channel.metrics.last_success_time.replace(tzinfo=timezone.utc).isoformat() if channel.metrics.last_success_time else None,
                    'protocol_counts': channel.metrics.protocol_counts
                }
            }
            stats['channels'].append(channel_stats)
            
        os.makedirs(os.path.dirname(config.STATS_FILE), exist_ok=True)
        with open(config.STATS_FILE, 'w', encoding='utf-8') as f:
            json.dump(stats, f, indent=2)
            
        logger.info(f"Channel statistics saved to {config.STATS_FILE}")
    except Exception as e:
        logger.error(f"Error saving channel statistics: {str(e)}")

def main():
    try:
        config = ProxyConfig()
        fetcher = ConfigFetcher(config)
        configs = fetcher.fetch_all_configs()
        
        if configs:
            save_configs(configs, config)
            logger.info(f"Successfully processed {len(configs)} configs at {datetime.now(timezone.utc)}")
            
            for protocol, count in fetcher.protocol_counts.items():
                logger.info(f"{protocol}: {count} configs")
        else:
            logger.error("No valid configs found!")
            
        save_channel_stats(config)
            
    except Exception as e:
        logger.error(f"Error in main execution: {str(e)}")

if __name__ == '__main__':
    main()