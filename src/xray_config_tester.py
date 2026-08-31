import os
import json
import subprocess
import tempfile
import logging
import statistics
from typing import List, Dict, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
import requests
import signal
import socket
import sys
from contextlib import closing, contextmanager
from config import ProxyConfig
import config_parser as parser
import transport_builder

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


def find_free_port() -> int:
    max_attempts = 10
    for attempt in range(max_attempts):
        with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
            try:
                s.bind(('127.0.0.1', 0))
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                port = s.getsockname()[1]
                
                with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as test_sock:
                    test_sock.settimeout(0.1)
                    try:
                        test_sock.connect(('127.0.0.1', port))
                        continue
                    except (socket.error, socket.timeout):
                        return port
            except OSError as e:
                if attempt == max_attempts - 1:
                    logger.error(f"Failed to find free port after {max_attempts} attempts: {e}")
                    raise
                time.sleep(0.1)
                continue
    raise RuntimeError("Could not find a free port")


@contextmanager
def managed_process(command: List[str], config_file: str):
    process = None
    try:
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            preexec_fn=os.setsid
        )
        yield process
    finally:
        if process:
            try:
                if process.poll() is None:
                    os.killpg(os.getpgid(process.pid), signal.SIGTERM)
                    try:
                        process.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        os.killpg(os.getpgid(process.pid), signal.SIGKILL)
                        process.wait(timeout=1)
            except (ProcessLookupError, OSError) as e:
                logger.debug(f"Process cleanup error (ignorable): {e}")
            except Exception as e:
                logger.warning(f"Unexpected error during process cleanup: {e}")


def _wait_for_ready(process, port: int, max_wait: float = 2.0, interval: float = 0.1) -> bool:
    """Poll the local inbound port instead of blindly sleeping a fixed 3s per
    config. Most cores are ready in well under a second; this returns as soon
    as the port accepts a connection (or the process dies), which is the
    single biggest per-config time saving across thousands of tests."""
    deadline = time.time() + max_wait
    while time.time() < deadline:
        if process.poll() is not None:
            return False
        with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
            s.settimeout(interval)
            try:
                s.connect(('127.0.0.1', port))
                return True
            except (socket.error, socket.timeout):
                time.sleep(interval)
    return process.poll() is None


class XrayTester:
    def __init__(self, xray_path: str = 'xray', timeout: int = 10, test_urls: List[str] = None):
        self.xray_path = xray_path
        self.timeout = timeout
        self.test_urls = test_urls if test_urls else ['https://www.youtube.com/generate_204']
        self.unsupported_protocols = ['tuic://', 'wireguard://']
        self._verify_xray()
    
    def _verify_xray(self):
        try:
            result = subprocess.run(
                [self.xray_path, 'version'],
                capture_output=True,
                timeout=5
            )
            if result.returncode != 0:
                raise RuntimeError(f"xray verification failed: {result.stderr.decode()}")
        except FileNotFoundError:
            raise RuntimeError(f"xray not found at: {self.xray_path}")
        except Exception as e:
            raise RuntimeError(f"xray verification error: {e}")
        
    def is_supported_protocol(self, config_str: str) -> bool:
        config_lower = config_str.lower()
        for protocol in self.unsupported_protocols:
            if config_lower.startswith(protocol):
                return False
        return True
        
    def parse_config_string(self, config_str: str) -> Optional[Dict]:
        try:
            config_lower = config_str.lower()
            data = None
            outbound = None
            
            if config_lower.startswith('vmess://'):
                data = parser.decode_vmess(config_str)
                if not data: return None
                outbound = {
                    "protocol": "vmess",
                    "settings": {
                        "vnext": [{
                            "address": data.get('add'),
                            "port": int(data.get('port')),
                            "users": [{
                                "id": data.get('id'),
                                "alterId": int(data.get('aid', 0)),
                                "security": data.get('scy', 'auto')
                            }]
                        }]
                    },
                    "streamSettings": transport_builder.build_xray_settings(data)
                }
            
            elif config_lower.startswith('vless://'):
                data = parser.parse_vless(config_str)
                if not data: return None
                outbound = {
                    "protocol": "vless",
                    "settings": {
                        "vnext": [{
                            "address": data['address'],
                            "port": data['port'],
                            "users": [{
                                "id": data['uuid'],
                                "encryption": "none",
                                "flow": data.get('flow', '')
                            }]
                        }]
                    },
                    "streamSettings": transport_builder.build_xray_settings(data)
                }
                
            elif config_lower.startswith('trojan://'):
                data = parser.parse_trojan(config_str)
                if not data: return None
                outbound = {
                    "protocol": "trojan",
                    "settings": {
                        "servers": [{
                            "address": data['address'],
                            "port": data['port'],
                            "password": data['password']
                        }]
                    },
                    "streamSettings": transport_builder.build_xray_settings(data)
                }
                
            elif config_lower.startswith('ss://'):
                data = parser.parse_shadowsocks(config_str)
                if not data: return None
                outbound = {
                    "protocol": "shadowsocks",
                    "settings": {
                        "servers": [{
                            "address": data['address'],
                            "port": data['port'],
                            "method": data['method'],
                            "password": data['password']
                        }]
                    }
                }
            
            return outbound
            
        except Exception as e:
            logger.debug(f"Failed to parse config: {str(e)}")
            return None
    
    def create_xray_config(self, outbound: Dict, socks_port: int, http_port: int) -> Dict:
        return {
            "log": {
                "loglevel": "error"
            },
            "inbounds": [
                {
                    "port": socks_port,
                    "protocol": "socks",
                    "settings": {
                        "auth": "noauth",
                        "udp": False
                    }
                },
                {
                    "port": http_port,
                    "protocol": "http"
                }
            ],
            "outbounds": [outbound]
        }
    
    def test_config(self, config_str: str, timeout: Optional[int] = None) -> Tuple[bool, Optional[int], str]:
        if not self.is_supported_protocol(config_str):
            protocol = config_str.split('://')[0].upper()
            logger.info(f"⊘ Skipping {protocol} (not supported by Xray core)")
            return True, 0, config_str
        
        effective_timeout = timeout if timeout is not None else self.timeout
        config_file = None
        
        try:
            outbound = self.parse_config_string(config_str)
            if not outbound:
                logger.warning(f"✗ Failed to parse config")
                return False, None, config_str
            
            socks_port = find_free_port()
            http_port = find_free_port()
            
            xray_config = self.create_xray_config(outbound, socks_port, http_port)
            
            fd, config_file = tempfile.mkstemp(suffix='.json', text=True, prefix='xray_')
            try:
                with os.fdopen(fd, 'w') as f:
                    json.dump(xray_config, f, indent=2)
            except Exception as e:
                os.close(fd)
                raise
            
            with managed_process(
                [self.xray_path, 'run', '-c', config_file],
                config_file
            ) as process:
                _wait_for_ready(process, http_port, max_wait=2.0)
                
                if process.poll() is not None:
                    stderr = process.stderr.read().decode('utf-8', errors='ignore') if process.stderr else ''
                    logger.warning(f"✗ Process crashed: {stderr[:200]}")
                    return False, None, config_str
                
                proxies = {
                    'http': f'http://127.0.0.1:{http_port}',
                    'https': f'http://127.0.0.1:{http_port}'
                }
                
                session = requests.Session()
                session.proxies.update(proxies)
                
                for url in self.test_urls:
                    domain = url.split('/')[2] if '/' in url[8:] else 'unknown'
                    start_time = time.time()
                    try:
                        response = session.get(
                            url,
                            timeout=effective_timeout
                        )
                        delay = int((time.time() - start_time) * 1000)
                        
                        if response.status_code in [200, 204]:
                            logger.info(f"✓ OK ({delay}ms via {domain})")
                            return True, delay, config_str
                        else:
                            logger.warning(f"✗ HTTP {response.status_code} on {domain}")
                            
                    except requests.exceptions.ProxyError as e:
                        logger.warning(f"✗ Proxy error: {str(e)[:100]}")
                        return False, None, config_str
                    except requests.exceptions.Timeout:
                        logger.warning(f"✗ Timeout on {domain}")
                    except requests.exceptions.ConnectionError as e:
                        logger.warning(f"✗ Connection error on {domain}: {str(e)[:100]}")
                    except Exception as e:
                        logger.warning(f"✗ {type(e).__name__} on {domain}: {str(e)[:100]}")
                
                logger.warning(f"✗ Failed all test URLs")
                return False, None, config_str
                
        except Exception as e:
            logger.error(f"✗ Setup error: {str(e)}")
            return False, None, config_str
            
        finally:
            if config_file and os.path.exists(config_file):
                try:
                    os.unlink(config_file)
                except Exception as e:
                    logger.debug(f"Failed to remove temp file {config_file}: {e}")
            
            time.sleep(0.05)


def config_identity_key(config_str: str) -> Optional[str]:
    """Address+port+id/password identity for a config link, so configs that
    are the *same server* but differ only in remark/tag or query-param order
    are recognized as duplicates -- matching how clients like v2rayNG define
    'duplicate' when it dedupes a subscription. Returns None for protocols
    we don't specifically parse here (e.g. tuic/wireguard); callers should
    fall back to exact-string identity in that case."""
    try:
        low = config_str.lower()
        if low.startswith('vmess://'):
            d = parser.decode_vmess(config_str)
            if not d:
                return None
            return f"vmess|{d.get('add')}|{d.get('port')}|{d.get('id')}"
        if low.startswith('vless://'):
            d = parser.parse_vless(config_str)
            if not d:
                return None
            return f"vless|{d['address']}|{d['port']}|{d['uuid']}"
        if low.startswith('trojan://'):
            d = parser.parse_trojan(config_str)
            if not d:
                return None
            return f"trojan|{d['address']}|{d['port']}|{d['password']}"
        if low.startswith('ss://'):
            d = parser.parse_shadowsocks(config_str)
            if not d:
                return None
            return f"ss|{d['address']}|{d['port']}|{d['method']}|{d['password']}"
    except Exception as e:
        logger.debug(f"Identity-key parse failed, will fall back to exact-string: {str(e)}")
        return None
    return None


def dedupe_configs(configs: List[str]) -> List[str]:
    seen = set()
    deduped = []
    removed = 0
    for cfg in configs:
        key = config_identity_key(cfg) or cfg.strip()
        if key in seen:
            removed += 1
            continue
        seen.add(key)
        deduped.append(cfg)
    if removed:
        logger.info(f"Removed {removed} duplicate config(s) (same address+port+id, different remark) before testing")
    return deduped


class ParallelXrayTester:
    def __init__(self, xray_path: str = 'xray', max_workers: int = 8,
                 timeouts: List[int] = None, test_urls: List[str] = None):
        timeouts = timeouts if timeouts else [10]
        # XrayTester's own .timeout is only the fallback default; the real
        # per-round values come from self.round_timeouts below.
        self.tester = XrayTester(xray_path, timeouts[0], test_urls)
        # NOTE: this workload is I/O-bound (network + subprocess wait), not CPU-bound,
        # so it must NOT be capped at os.cpu_count() (that was silently forcing ~4
        # workers on GitHub Actions runners no matter what max_workers was set to).
        self.max_workers = max(1, min(max_workers, 200))
        # Staged ("پله‌ای") testing: one timeout per round, meant to decrease.
        # A config must pass every round -- with progressively tighter
        # timeouts -- to be published, so only the fastest/most reliable
        # configs survive to the final list.
        self.round_timeouts = [max(1, int(t)) for t in timeouts]
        self.rounds = len(self.round_timeouts)

    def _test_round(self, configs: List[str], timeout: int) -> Dict[str, Optional[int]]:
        """Run one independent pass over ``configs`` using ``timeout`` for
        this round's requests. Returns {config_str: delay_ms} for everything
        that passed this round; delay is 0 for the unsupported-protocol skip
        case (no real request made)."""
        passed: Dict[str, Optional[int]] = {}
        tested = 0

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {
                executor.submit(self.tester.test_config, cfg, timeout): cfg
                for cfg in configs
            }

            for future in as_completed(futures):
                tested += 1
                try:
                    success, delay, config_str = future.result(timeout=timeout + 10)
                    if success:
                        passed[config_str] = delay
                    if tested % 25 == 0 or tested == len(configs):
                        logger.info(f"  Progress: {tested}/{len(configs)} ({len(passed)} passed)")
                except Exception as e:
                    logger.error(f"Test error: {str(e)}")

        return passed

    def test_all(self, configs: List[str]) -> List[str]:
        logger.info(
            f"Testing {len(configs)} configs with {self.max_workers} workers,"
            f" {self.rounds} staged round(s), timeouts={self.round_timeouts}s..."
        )
        logger.info(f"Test URLs: {self.tester.test_urls}")

        survivors = list(configs)
        # Per-config list of real (non-skip) round latencies, used to rank
        # the survivors fastest-first once every round is done.
        latencies: Dict[str, List[int]] = {cfg: [] for cfg in configs}
        skip_flag: Dict[str, bool] = {}

        for round_num, round_timeout in enumerate(self.round_timeouts, start=1):
            if not survivors:
                break
            logger.info(
                f"Round {round_num}/{self.rounds}: testing {len(survivors)} configs"
                f" (timeout={round_timeout}s)"
            )
            round_results = self._test_round(survivors, round_timeout)
            survivors = [cfg for cfg in survivors if cfg in round_results]
            for cfg in survivors:
                delay = round_results[cfg]
                if delay == 0:
                    skip_flag[cfg] = True
                else:
                    latencies[cfg].append(delay)
            logger.info(f"  {len(survivors)} passed round {round_num}")

        if not survivors:
            logger.info(f"Results: 0/{len(configs)} passed all {self.rounds} round(s)")
            return []

        # Unsupported-protocol configs skip the real test every round, so
        # they have no latency to rank by -- keep them, but after everything
        # that was actually measured.
        tested_ok = [cfg for cfg in survivors if not skip_flag.get(cfg)]
        skipped_ok = [cfg for cfg in survivors if skip_flag.get(cfg)]
        tested_ok.sort(key=lambda cfg: statistics.median(latencies[cfg]))
        working = tested_ok + skipped_ok

        success_rate = (len(working) * 100) // max(1, len(configs))
        logger.info(
            f"Results: {len(working)}/{len(configs)} passed all {self.rounds} round(s)"
            f" ({success_rate}%) - {len(skipped_ok)} unsupported-protocol pass-through"
        )
        return working


def main():
    config_settings = ProxyConfig()

    if len(sys.argv) < 3:
        print("Usage: python xray_config_tester.py <input.txt> <output.txt>")
        sys.exit(1)
    
    input_file = sys.argv[1]
    output_file = sys.argv[2]

    if not config_settings.ENABLE_XRAY_TESTER:
        logger.info("Xray testing is disabled in user_settings.py. Skipping.")
        try:
            with open(input_file, 'r', encoding='utf-8') as f_in:
                content = f_in.read()
            os.makedirs(os.path.dirname(output_file) or '.', exist_ok=True)
            with open(output_file, 'w', encoding='utf-8') as f_out:
                f_out.write(content)
            logger.info(f"Copied {input_file} to {output_file} as testing is disabled.")
            sys.exit(0)
        except Exception as e:
            logger.error(f"Failed to copy {input_file} to {output_file}: {str(e)}")
            sys.exit(1)

    max_workers = config_settings.XRAY_TESTER_MAX_WORKERS
    timeouts = config_settings.XRAY_TESTER_TIMEOUTS
    test_urls = config_settings.XRAY_TESTER_URLS
    max_output = config_settings.MAX_OUTPUT_CONFIGS
    
    logger.info(f"Loading configs from {input_file}")
    
    try:
        with open(input_file, 'r', encoding='utf-8') as f:
            lines = f.readlines()
    except FileNotFoundError:
        logger.error(f"Input file not found: {input_file}")
        sys.exit(1)
    
    configs = []
    header_lines = []
    
    for line in lines:
        line = line.strip()
        if line.startswith('//') or not line:
            if not configs:
                header_lines.append(line)
        else:
            configs.append(line)
    
    if not configs:
        logger.error("No configs found")
        sys.exit(1)
    
    logger.info(f"Found {len(configs)} configs")

    configs = dedupe_configs(configs)
    logger.info(f"{len(configs)} configs remain after dedup")

    tester = ParallelXrayTester(max_workers=max_workers, timeouts=timeouts, test_urls=test_urls)
    working = tester.test_all(configs)

    if len(working) > max_output:
        logger.info(f"Limiting output to the best {max_output} configs (of {len(working)} passing)")
        working = working[:max_output]
    
    os.makedirs(os.path.dirname(output_file) or '.', exist_ok=True)
    with open(output_file, 'w', encoding='utf-8') as f:
        for header in header_lines:
            f.write(header + '\n')
        if header_lines:
            f.write('\n')
        for config in working:
            f.write(config + '\n\n')
    
    if working:
        logger.info(f"Saved {len(working)} working configs to {output_file}")
        sys.exit(0)
    else:
        logger.error("No working configs found")
        sys.exit(0)


if __name__ == '__main__':
    main()