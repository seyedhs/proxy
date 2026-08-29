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
    config; returns as soon as the port is accepting connections or the
    process has died."""
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


class SingBoxTester:
    def __init__(self, singbox_path: str = 'sing-box', timeout: int = 10, test_urls: List[str] = None):
        self.singbox_path = singbox_path
        self.timeout = timeout
        self.test_urls = test_urls if test_urls else ['https://www.youtube.com/generate_204']
        self._verify_singbox()
    
    def _verify_singbox(self):
        try:
            result = subprocess.run(
                [self.singbox_path, 'version'],
                capture_output=True,
                timeout=5
            )
            if result.returncode != 0:
                raise RuntimeError(f"sing-box verification failed: {result.stderr.decode()}")
        except FileNotFoundError:
            raise RuntimeError(f"sing-box not found at: {self.singbox_path}")
        except Exception as e:
            raise RuntimeError(f"sing-box verification error: {e}")
        
    def create_minimal_config(self, outbound: Dict, mixed_port: int) -> Dict:
        return {
            "log": {
                "level": "panic",
                "timestamp": False
            },
            "inbounds": [
                {
                    "type": "mixed",
                    "listen": "127.0.0.1",
                    "listen_port": mixed_port
                }
            ],
            "outbounds": [outbound],
            "route": {
                "final": outbound.get('tag', 'proxy')
            }
        }
    
    def test_config(self, outbound: Dict, timeout: Optional[int] = None) -> Tuple[bool, Optional[int], str]:
        tag = outbound.get('tag', 'unknown')
        effective_timeout = timeout if timeout is not None else self.timeout
        config_file = None
        
        try:
            mixed_port = find_free_port()
        except RuntimeError as e:
            logger.error(f"✗ {tag} - Port allocation failed: {e}")
            return False, None, tag
        
        try:
            config = self.create_minimal_config(outbound, mixed_port)
            
            fd, config_file = tempfile.mkstemp(suffix='.json', text=True, prefix='singbox_')
            try:
                with os.fdopen(fd, 'w') as f:
                    json.dump(config, f, indent=2)
            except Exception as e:
                os.close(fd)
                raise
            
            with managed_process(
                [self.singbox_path, 'run', '-c', config_file],
                config_file
            ) as process:
                _wait_for_ready(process, mixed_port, max_wait=2.0)
                
                if process.poll() is not None:
                    stderr = process.stderr.read().decode('utf-8', errors='ignore') if process.stderr else ''
                    logger.warning(f"✗ {tag} - Process crashed: {stderr[:200]}")
                    return False, None, tag
                
                proxies = {
                    'http': f'http://127.0.0.1:{mixed_port}',
                    'https': f'http://127.0.0.1:{mixed_port}'
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
                            logger.info(f"✓ {tag} - OK ({delay}ms via {domain})")
                            return True, delay, tag
                        else:
                            logger.warning(f"✗ {tag} - HTTP {response.status_code} on {domain}")
                            
                    except requests.exceptions.ProxyError as e:
                        logger.warning(f"✗ {tag} - Proxy error: {str(e)[:100]}")
                        return False, None, tag
                    except requests.exceptions.Timeout:
                        logger.warning(f"✗ {tag} - Timeout on {domain}")
                    except requests.exceptions.ConnectionError as e:
                        logger.warning(f"✗ {tag} - Connection error on {domain}: {str(e)[:100]}")
                    except Exception as e:
                        logger.warning(f"✗ {tag} - {type(e).__name__} on {domain}: {str(e)[:100]}")
                
                logger.warning(f"✗ {tag} - Failed all test URLs")
                return False, None, tag
                
        except Exception as e:
            logger.error(f"✗ {tag} - Setup error: {str(e)}")
            return False, None, tag
            
        finally:
            if config_file and os.path.exists(config_file):
                try:
                    os.unlink(config_file)
                except Exception as e:
                    logger.debug(f"Failed to remove temp file {config_file}: {e}")
            
            time.sleep(0.05)


class ParallelConfigTester:
    def __init__(self, singbox_path: str = 'sing-box', max_workers: int = 8,
                 timeouts: List[int] = None, test_urls: List[str] = None):
        timeouts = timeouts if timeouts else [10]
        # SingBoxTester's own .timeout is only the fallback default (used if a
        # round is ever run without an explicit override); real per-round
        # values come from self.round_timeouts below.
        self.tester = SingBoxTester(singbox_path, timeouts[0], test_urls)
        # NOTE: I/O-bound workload — do not cap at os.cpu_count(), that silently
        # forced ~4 workers on GitHub Actions runners regardless of max_workers.
        self.max_workers = max(1, min(max_workers, 200))
        # Staged ("پله‌ای") testing: one timeout per round, meant to decrease.
        # A config must pass every round to be published, and only the round's
        # survivors move on to the next (tighter) round -- so each stage
        # filters harder than the last and only the fastest/most reliable
        # configs make it to the final list.
        self.round_timeouts = [max(1, int(t)) for t in timeouts]
        self.rounds = len(self.round_timeouts)

    def _test_round(self, outbounds: List[Dict], timeout: int) -> Dict[str, int]:
        """Run one independent pass over ``outbounds`` using ``timeout`` for
        this round's requests. Returns {tag: delay_ms} for everything that
        passed."""
        passed: Dict[str, int] = {}
        tested = 0

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {
                executor.submit(self.tester.test_config, ob, timeout): ob
                for ob in outbounds
            }

            for future in as_completed(futures):
                outbound = futures[future]
                tested += 1
                try:
                    success, delay, tag = future.result(timeout=timeout + 10)
                    if success and delay is not None:
                        passed[tag] = delay
                    if tested % 25 == 0 or tested == len(outbounds):
                        logger.info(f"  Progress: {tested}/{len(outbounds)} ({len(passed)} passed)")
                except Exception as e:
                    logger.error(f"Test error for {outbound.get('tag', 'unknown')}: {str(e)}")

        return passed

    def test_all(self, outbounds: List[Dict]) -> List[Dict]:
        logger.info(
            f"Testing {len(outbounds)} configs with {self.max_workers} workers,"
            f" {self.rounds} staged round(s), timeouts={self.round_timeouts}s..."
        )
        logger.info(f"Test URLs: {self.tester.test_urls}")

        by_tag = {ob['tag']: ob for ob in outbounds}
        survivor_tags = list(by_tag.keys())
        latencies: Dict[str, List[int]] = {tag: [] for tag in survivor_tags}

        for round_num, round_timeout in enumerate(self.round_timeouts, start=1):
            if not survivor_tags:
                break
            logger.info(
                f"Round {round_num}/{self.rounds}: testing {len(survivor_tags)} configs"
                f" (timeout={round_timeout}s)"
            )
            round_results = self._test_round([by_tag[tag] for tag in survivor_tags], round_timeout)
            survivor_tags = [tag for tag in survivor_tags if tag in round_results]
            for tag in survivor_tags:
                latencies[tag].append(round_results[tag])
            logger.info(f"  {len(survivor_tags)} passed round {round_num}")

        if not survivor_tags:
            logger.info(f"Results: 0/{len(outbounds)} passed all {self.rounds} round(s)")
            return []

        survivor_tags.sort(key=lambda tag: statistics.median(latencies[tag]))
        working = [by_tag[tag] for tag in survivor_tags]

        success_rate = (len(working) * 100) // max(1, len(outbounds))
        logger.info(
            f"Results: {len(working)}/{len(outbounds)} passed all {self.rounds} round(s) ({success_rate}%)"
        )
        return working


def update_config_with_working_outbounds(config: Dict, working_outbounds: List[Dict]) -> Dict:
    if not working_outbounds:
        logger.warning("No working outbounds - keeping original config")
        return config
    
    working_tags = {ob['tag'] for ob in working_outbounds}
    
    new_outbounds = []
    
    for ob in config.get('outbounds', []):
        ob_type = ob.get('type')
        
        if ob_type == 'selector':
            new_list = []
            for tag in ob.get('outbounds', []):
                if tag in working_tags or tag in ['Best Ping 🚀', 'auto', 'direct', 'block']:
                    new_list.append(tag)
            if new_list:
                ob['outbounds'] = new_list
                new_outbounds.append(ob)
            else:
                logger.warning(f"Selector '{ob.get('tag')}' has no working outbounds, skipping")
            
        elif ob_type == 'urltest':
            new_list = [tag for tag in ob.get('outbounds', []) if tag in working_tags]
            if new_list:
                ob['outbounds'] = new_list
                new_outbounds.append(ob)
            else:
                logger.warning(f"URLTest '{ob.get('tag')}' has no working outbounds, skipping")
            
        elif ob_type in ['direct', 'block', 'dns']:
            new_outbounds.append(ob)
            
        elif ob.get('tag') in working_tags:
            new_outbounds.append(ob)
    
    config['outbounds'] = new_outbounds
    return config


def main():
    config_settings = ProxyConfig()

    if len(sys.argv) < 3:
        print("Usage: python config_tester.py <input.json> <output.json>")
        sys.exit(1)
    
    input_file = sys.argv[1]
    output_file = sys.argv[2]

    if not config_settings.ENABLE_CONFIG_TESTER:
        logger.info("Config testing is disabled in user_settings.py. Skipping.")
        try:
            with open(input_file, 'r', encoding='utf-8') as f_in:
                config_data = json.load(f_in)
            os.makedirs(os.path.dirname(output_file) or '.', exist_ok=True)
            with open(output_file, 'w', encoding='utf-8') as f_out:
                json.dump(config_data, f_out, indent=4, ensure_ascii=False)
            logger.info(f"Copied {input_file} to {output_file} as testing is disabled.")
            sys.exit(0)
        except Exception as e:
            logger.error(f"Failed to copy {input_file} to {output_file}: {str(e)}")
            sys.exit(1)

    max_workers = config_settings.TESTER_MAX_WORKERS
    timeouts = config_settings.TESTER_TIMEOUTS
    test_urls = config_settings.TESTER_URLS
    max_output = config_settings.MAX_OUTPUT_CONFIGS
    
    logger.info(f"Loading config from {input_file}")
    
    try:
        with open(input_file, 'r', encoding='utf-8') as f:
            config = json.load(f)
    except FileNotFoundError:
        logger.error(f"Input file not found: {input_file}")
        sys.exit(1)
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON in {input_file}: {e}")
        sys.exit(1)
    
    proxy_outbounds = [
        ob for ob in config.get('outbounds', [])
        if ob.get('type') not in ['selector', 'urltest', 'direct', 'block', 'dns']
    ]
    
    if not proxy_outbounds:
        logger.error("No proxy outbounds found")
        sys.exit(1)
    
    logger.info(f"Found {len(proxy_outbounds)} proxy outbounds")
    
    tester = ParallelConfigTester(max_workers=max_workers, timeouts=timeouts, test_urls=test_urls)
    working = tester.test_all(proxy_outbounds)

    if len(working) > max_output:
        logger.info(f"Limiting output to the best {max_output} configs (of {len(working)} passing)")
        working = working[:max_output]
    
    if working:
        config = update_config_with_working_outbounds(config, working)
        
        os.makedirs(os.path.dirname(output_file) or '.', exist_ok=True)
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(config, f, indent=4, ensure_ascii=False)
        
        logger.info(f"Saved {len(working)} working configs to {output_file}")
        sys.exit(0)
    else:
        logger.error("No working configs found - saving original config")
        
        os.makedirs(os.path.dirname(output_file) or '.', exist_ok=True)
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(config, f, indent=4, ensure_ascii=False)
        
        sys.exit(0)


if __name__ == '__main__':
    main()