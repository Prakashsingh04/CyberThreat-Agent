"""System network monitor that samples Windows network stats and posts anomalies to the pipeline.

Lightweight, best-effort: uses psutil if available; degrades gracefully if not.
it inspects connections and interface IO deltas to
heuristically flag suspicious behavior and then triggers the pipeline.
"""
from __future__ import annotations
import threading
import time
import logging
from typing import Optional, Dict
from collections import deque
from config import settings

import requests

logger = logging.getLogger(__name__)

try:
    import psutil  # type: ignore
    _PSUTIL_OK = True
except Exception as e:  # pragma: no cover - import error path
    logger.warning(f"psutil not available for SystemNetworkMonitor: {e}")
    psutil = None  # type: ignore
    _PSUTIL_OK = False


class SystemNetworkMonitor:
    def __init__(self, pipeline_endpoint: str, interval: float = 2.0):
        self.pipeline_endpoint = pipeline_endpoint
        self.interval = max(0.5, float(interval))
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self._last_status: Optional[dict] = None
        # Adaptive baselines (rolling window last N samples)
        self._baseline_window = 30
        self._hist_conn_total = deque(maxlen=self._baseline_window)
        self._hist_bytes_sent = deque(maxlen=self._baseline_window)
        self._hist_unique_remotes = deque(maxlen=self._baseline_window)
        self._last_alert_ts: float = 0.0
        self._consecutive_suspicious: int = 0

    def start(self) -> bool:
        if self._thread and self._thread.is_alive():
            return False
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()
        logger.info("SystemNetworkMonitor started")
        return True

    def stop(self) -> bool:
        if not self._thread:
            return False
        self._stop.set()
        self._thread = None
        logger.info("SystemNetworkMonitor stopped")
        return True

    def _loop(self):
        if not _PSUTIL_OK:
            logger.warning("psutil not installed; SystemNetworkMonitor is idle.")
            return
        last_io = psutil.net_io_counters(pernic=False)
        last_time = time.time()
        while not self._stop.is_set():
            try:
                time.sleep(self.interval)
                now = time.time()
                elapsed = max(1e-3, now - last_time)

                io = psutil.net_io_counters(pernic=False)
                bytes_sent_rate = (io.bytes_sent - last_io.bytes_sent) / elapsed
                bytes_recv_rate = (io.bytes_recv - last_io.bytes_recv) / elapsed
                last_io, last_time = io, now

                # Connection snapshot
                try:
                    conns = psutil.net_connections(kind='tcp')
                except Exception:
                    conns = []
                states = {}
                unique_remotes = set()
                for c in conns:
                    s = c.status or 'NONE'
                    states[s] = states.get(s, 0) + 1
                    if c.raddr and c.raddr.ip:
                        unique_remotes.add(c.raddr.ip)

                metrics = {
                    'bytes_sent_rate': bytes_sent_rate,
                    'bytes_recv_rate': bytes_recv_rate,
                    'conn_total': len(conns),
                    'conn_established': states.get('ESTABLISHED', 0),
                    'conn_syn_sent': states.get('SYN_SENT', 0),
                    'conn_time_wait': states.get('TIME_WAIT', 0),
                    'conn_close_wait': states.get('CLOSE_WAIT', 0),
                    'unique_remotes': len(unique_remotes),
                }

                suspicious, reason = self._is_suspicious(metrics)
                # Save last status snapshot
                self._last_status = {
                    'timestamp': now,
                    'metrics': metrics,
                    'suspicious': bool(suspicious),
                    'reason': reason,
                }
                if suspicious:
                    # Cooldown / throttling
                    if (now - self._last_alert_ts) >= settings.SYSTEM_MONITOR_COOLDOWN_SECONDS or reason == 'critical':
                        feats = self._features_from_metrics(metrics)
                        self._post_pipeline(feats, entry_point='web_server')
                        self._last_alert_ts = now
                # Otherwise: stay quiet to avoid spamming the pipeline
            except Exception as e:
                logger.debug(f"SystemNetworkMonitor loop error: {e}")
                continue

    def _is_suspicious(self, m: Dict[str, float]) -> (bool, str):
        """Adaptive heuristic to reduce false positives on normal hotspot/wifi usage.

        Returns (suspicious: bool, reason: str)
        Reasons: 'none', 'baseline-exceeded', 'absolute-threshold', 'critical'
        """
        # Update baselines
        self._hist_conn_total.append(m['conn_total'])
        self._hist_bytes_sent.append(m['bytes_sent_rate'])
        self._hist_unique_remotes.append(m['unique_remotes'])

        # Compute rolling averages
        avg_conn = sum(self._hist_conn_total) / max(1, len(self._hist_conn_total))
        avg_sent = sum(self._hist_bytes_sent) / max(1, len(self._hist_bytes_sent))
        avg_remotes = sum(self._hist_unique_remotes) / max(1, len(self._hist_unique_remotes))

        ratio_conn = (m['conn_total'] / avg_conn) if avg_conn > 50 else 0
        ratio_sent = (m['bytes_sent_rate'] / avg_sent) if avg_sent > 10_000 else 0
        ratio_remotes = (m['unique_remotes'] / avg_remotes) if avg_remotes > 1 else 0

        # Absolute thresholds (critical)
        if m['conn_total'] >= settings.SYSTEM_MONITOR_CONN_TOTAL_THRESHOLD * 2 or m['bytes_sent_rate'] / 1_000_000.0 >= settings.SYSTEM_MONITOR_BYTES_SENT_MBPS_THRESHOLD * 2:
            self._consecutive_suspicious += 1
            return True, 'critical'

        # Absolute suspicious if combination satisfied
        abs_conditions = [
            (m['conn_syn_sent'] >= settings.SYSTEM_MONITOR_CONN_SYN_SENT_THRESHOLD and m['unique_remotes'] >= settings.SYSTEM_MONITOR_UNIQUE_REMOTES_THRESHOLD),
            (m['bytes_sent_rate'] / 1_000_000.0 >= settings.SYSTEM_MONITOR_BYTES_SENT_MBPS_THRESHOLD and m['conn_established'] >= settings.SYSTEM_MONITOR_CONN_SYN_SENT_THRESHOLD),
            (m['conn_time_wait'] >= settings.SYSTEM_MONITOR_CONN_TIME_WAIT_THRESHOLD and m['unique_remotes'] >= settings.SYSTEM_MONITOR_UNIQUE_REMOTES_THRESHOLD),
            (m['conn_total'] >= settings.SYSTEM_MONITOR_CONN_TOTAL_THRESHOLD and m['unique_remotes'] >= settings.SYSTEM_MONITOR_UNIQUE_REMOTES_THRESHOLD),
        ]
        if any(abs_conditions):
            self._consecutive_suspicious += 1
            if self._consecutive_suspicious >= settings.SYSTEM_MONITOR_CONSECUTIVE_REQUIRED:
                return True, 'absolute-threshold'
            return False, 'warming'

        # Baseline ratio exceed (only if remotes also somewhat elevated)
        if (
            ratio_conn >= settings.SYSTEM_MONITOR_RATIO and m['unique_remotes'] >= max(5, settings.SYSTEM_MONITOR_UNIQUE_REMOTES_THRESHOLD // 2)
        ) or (
            ratio_sent >= settings.SYSTEM_MONITOR_RATIO and m['unique_remotes'] >= max(5, settings.SYSTEM_MONITOR_UNIQUE_REMOTES_THRESHOLD // 2)
        ) or (
            ratio_remotes >= settings.SYSTEM_MONITOR_RATIO and m['unique_remotes'] >= settings.SYSTEM_MONITOR_UNIQUE_REMOTES_THRESHOLD
        ):
            self._consecutive_suspicious += 1
            if self._consecutive_suspicious >= settings.SYSTEM_MONITOR_CONSECUTIVE_REQUIRED:
                return True, 'baseline-exceeded'
            return False, 'warming'

        # Reset counter if benign
        self._consecutive_suspicious = 0
        return False, 'none'

    def _features_from_metrics(self, m: Dict[str, float]):
        # Map a handful of metrics to first positions; rest zeros
        vec = [0.0] * 70
        vec[0] = float(m['bytes_sent_rate'] / 1_000_000.0)  # MB/s
        vec[1] = float(m['bytes_recv_rate'] / 1_000_000.0)
        vec[2] = float(m['conn_total'])
        vec[3] = float(m['conn_established'])
        vec[4] = float(m['conn_syn_sent'])
        vec[5] = float(m['conn_time_wait'])
        vec[6] = float(m['conn_close_wait'])
        vec[7] = float(m['unique_remotes'])
        # leave remaining as zeros; the scaler/autoencoder will still accept 70 dims
        return vec

    def _post_pipeline(self, features, entry_point: str = 'web_server'):
        try:
            requests.post(
                self.pipeline_endpoint,
                params={'entry_point': entry_point, 'max_steps': 3},
                json={'features': features},
                timeout=5
            )
        except Exception as e:
            logger.debug(f"SystemNetworkMonitor failed to POST pipeline: {e}")

    def get_status(self) -> Optional[dict]:
        """Return last sample status (timestamp, metrics, suspicious) or None."""
        return self._last_status
