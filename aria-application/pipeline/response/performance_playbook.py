"""
Performance Playbook Generator.

Generates Ansible playbooks for performance auto-remediation.
Part of the Server Performance Monitoring System (v1.0).
"""

import structlog
from typing import Dict, Any, Optional

from config import get_settings

logger = structlog.get_logger()

PLAYBOOK_TEMPLATES = {
    "cpu_high_nginx": """---
- name: Restart nginx workers
  hosts: {{ host }}
  become: yes
  tasks:
    - name: Check nginx status
      command: systemctl status nginx
      register: nginx_status
      failed_when: false

    - name: Reload nginx configuration
      command: nginx -t
      register: nginx_test
      changed_when: false

    - name: Graceful nginx reload
      command: systemctl reload nginx
      when: nginx_test.rc == 0

    - name: Kill excessive nginx workers
      shell: pkill -USR1 nginx || true
      when: nginx_status.rc == 0
""",

    "cpu_high_apache": """---
- name: Restart Apache workers
  hosts: {{ host }}
  become: yes
  tasks:
    - name: Graceful Apache restart
      command: apachectl graceful
      changed_when: false
      failed_when: false
""",

    "cpu_high_java": """---
- name: Restart Java application
  hosts: {{ host }}
  become: yes
  tasks:
    - name: Find Java processes with high CPU
      command: ps -eo pid,pcpu,comm --no-headers | sort -k2 -rn | head -5
      register: java_procs
      changed_when: false

    - name: Graceful restart Java app
      shell: |
        pkill -SIGTERM java || true
        sleep 5
        systemctl restart {{ java_service | default('tomcat') }}
      failed_when: false
""",

    "memory_high_redis": """---
- name: Clear Redis memory
  hosts: {{ host }}
  become: yes
  tasks:
    - name: Get Redis memory info
      command: redis-cli info memory
      register: redis_mem
      changed_when: false
      failed_when: false

    - name: Flush expired keys
      command: redis-cli FLUSHDB
      changed_when: false
      failed_when: false

    - name: Save Redis snapshot
      command: redis-cli BGSAVE
      changed_when: false
      failed_when: false
""",

    "memory_high_java": """---
- name: Clear Java heap
  hosts: {{ host }}
  become: yes
  tasks:
    - name: Trigger Java GC
      shell: |
        jcmd $(pgrep -f java) GC.run || true
      changed_when: false
      failed_when: false
""",

    "disk_full_logs": """---
- name: Clear log files
  hosts: {{ host }}
  become: yes
  tasks:
    - name: Find and truncate large log files
      shell: |
        find /var/log -type f -size +100M -exec truncate -s 0 {} \\; 2>/dev/null || true
      changed_when: true

    - name: Clear old journal logs
      command: journalctl --vacuum-time=7d
      changed_when: true
      failed_when: false

    - name: Clear tmp files
      shell: |
        find /tmp -type f -mtime +7 -delete 2>/dev/null || true
      changed_when: true
""",

    "disk_full_temp": """---
- name: Clear temporary files
  hosts: {{ host }}
  become: yes
  tasks:
    - name: Clear /tmp
      shell: |
        find /tmp -type f -atime +1 -delete 2>/dev/null || true
      changed_when: true

    - name: Clear /var/tmp
      shell: |
        find /var/tmp -type f -atime +1 -delete 2>/dev/null || true
      changed_when: true
""",

    "disk_full_root": """---
- name: Clean root partition disk space
  hosts: {{ host }}
  become: yes
  vars:
    free_space_target_mb: 10000
  tasks:
    - name: Get disk usage for root partition
      shell: df -BG / | tail -1 | awk '{print $4}' | sed 's/G//'
      register: root_free_gb
      changed_when: false

    - name: Clean journal logs (keep last 3 days)
      command: journalctl --vacuum-time=3d
      changed_when: true
      failed_when: false

    - name: Clean apt cache
      shell: |
        apt-get clean
        apt-get autoclean
        rm -rf /var/cache/apt/archives/*
      changed_when: true
      failed_when: false

    - name: Clean old snap versions
      shell: |
        snap list --all | awk '/disabled/{print $1, $3}' | while read snapname rev; do snap remove "$snapname" --revision="$rev" 2>/dev/null || true; done
      changed_when: true
      failed_when: false

    - name: Clear thumbnail cache
      shell: |
        rm -rf /root/.cache/thumbnails/*
        rm -rf ~/.cache/thumbnails/*
      changed_when: true
      failed_when: false

    - name: Clean old log files (> 100MB)
      shell: |
        find /var/log -type f -size +100M -exec truncate -s 0 {} \\; 2>/dev/null || true
      changed_when: true
      failed_when: false

    - name: Report freed space
      shell: df -BG / | tail -1 | awk '{print "Free space after cleanup: " $4 " (" $5 " used)"}'
      register: final_space
      changed_when: false
""",

    "disk_full_var_log": """---
- name: Clean /var/log directory
  hosts: {{ host }}
  become: yes
  tasks:
    - name: List large log files
      shell: find /var/log -type f -size +100M -exec ls -lh {} \\; 2>/dev/null | head -20
      register: large_logs
      changed_when: false
      failed_when: false

    - name: Truncate old log files
      shell: |
        find /var/log -type f -name "*.log" -mtime +7 -exec truncate -s 0 {} \\; 2>/dev/null || true
        find /var/log -type f -name "*.log.*" -mtime +7 -delete 2>/dev/null || true
      changed_when: true
      failed_when: false

    - name: Compress old rotated logs
      shell: |
        find /var/log -type f -name "*.log.[0-9]" ! -name "*.gz" -exec gzip {} \\; 2>/dev/null || true
      changed_when: true
      failed_when: false

    - name: Clean old systemd journal
      shell: |
        journalctl --vacuum-time=7d
        journalctl --rotate
      changed_when: true
      failed_when: false

    - name: Clean fail2ban logs
      shell: |
        rm -f /var/log/fail2ban.log.*
        truncate -s 0 /var/log/fail2ban.log 2>/dev/null || true
      changed_when: true
      failed_when: false

    - name: Report disk space after cleanup
      shell: df -h /var
      register: final_space
      changed_when: false
""",

    "disk_full_docker": """---
- name: Clean Docker disk space
  hosts: {{ host }}
  become: yes
  tasks:
    - name: Get Docker disk usage
      shell: docker system df
      register: docker_df
      changed_when: false
      failed_when: false

    - name: Remove stopped containers
      shell: docker container prune -f
      changed_when: true
      failed_when: false

    - name: Remove unused volumes
      shell: docker volume prune -f
      changed_when: true
      failed_when: false

    - name: Remove unused networks
      shell: docker network prune -f
      changed_when: true
      failed_when: false

    - name: Remove unused images
      shell: docker image prune -a -f --filter "until=168h"
      changed_when: true
      failed_when: false

    - name: Remove build cache
      shell: docker builder prune -f
      changed_when: true
      failed_when: false

    - name: Report Docker disk space after cleanup
      shell: docker system df
      register: final_df
      changed_when: false
""",

    "disk_full_tmp": """---
- name: Clean /tmp directory
  hosts: {{ host }}
  become: yes
  tasks:
    - name: Get /tmp size before cleanup
      shell: du -sh /tmp 2>/dev/null | cut -f1
      register: tmp_size_before
      changed_when: false

    - name: Remove old temp files (7+ days)
      shell: |
        find /tmp -type f -atime +7 -delete 2>/dev/null || true
        find /tmp -type d -empty -atime +7 -delete 2>/dev/null || true
      changed_when: true

    - name: Remove system temp files
      shell: |
        rm -rf /tmp/systemd-private-*
        rm -rf /tmp/.ICE-unix
        rm -rf /tmp/.X11-unix
      changed_when: true
      failed_when: false

    - name: Get /tmp size after cleanup
      shell: du -sh /tmp 2>/dev/null | cut -f1
      register: tmp_size_after
      changed_when: false

    - name: Show cleanup results
      debug:
        msg: "tmp size before: {{ tmp_size_before.stdout }}, after: {{ tmp_size_after.stdout }}"
""",
}


async def generate_performance_playbook(
    alert_type: str,
    host: str,
    metrics: Dict[str, Any]
) -> Optional[str]:
    """Generate an Ansible playbook for performance remediation."""
    
    template = PLAYBOOK_TEMPLATES.get(alert_type)
    
    if not template:
        logger.warning("no_playbook_template", alert_type=alert_type)
        return None
    
    try:
        playbook = template.replace("{{ host }}", host)
        
        if "{{ java_service }}" in playbook:
            java_service = metrics.get("java_service", "tomcat")
            playbook = playbook.replace("{{ java_service }}", java_service)
        
        logger.info(
            "performance_playbook_generated",
            alert_type=alert_type,
            host=host
        )
        
        return playbook
        
    except Exception as e:
        logger.error("playbook_generation_failed", alert_type=alert_type, error=str(e))
        return None


def get_available_playbooks() -> list[str]:
    """Get list of available playbook types."""
    return list(PLAYBOOK_TEMPLATES.keys())