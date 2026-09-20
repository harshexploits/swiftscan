"""
swiftscan/fingerprint.py
Service fingerprinting based on port number and banner content.
"""

from __future__ import annotations
from typing import Optional

# Port → (service_name, default_protocol)
PORT_MAP: dict[int, tuple[str, str]] = {
    21:    ("FTP",              "tcp"),
    22:    ("SSH",              "tcp"),
    23:    ("Telnet",           "tcp"),
    25:    ("SMTP",             "tcp"),
    53:    ("DNS",              "tcp/udp"),
    67:    ("DHCP",             "udp"),
    68:    ("DHCP",             "udp"),
    69:    ("TFTP",             "udp"),
    80:    ("HTTP",             "tcp"),
    110:   ("POP3",             "tcp"),
    111:   ("RPC",              "tcp"),
    119:   ("NNTP",             "tcp"),
    123:   ("NTP",              "udp"),
    135:   ("MSRPC",            "tcp"),
    139:   ("NetBIOS",          "tcp"),
    143:   ("IMAP",             "tcp"),
    161:   ("SNMP",             "udp"),
    194:   ("IRC",              "tcp"),
    389:   ("LDAP",             "tcp"),
    443:   ("HTTPS",            "tcp"),
    445:   ("SMB",              "tcp"),
    465:   ("SMTPS",            "tcp"),
    514:   ("Syslog",           "udp"),
    515:   ("LPD/LPR",          "tcp"),
    543:   ("Kerberos",         "tcp"),
    587:   ("SMTP-Submission",  "tcp"),
    631:   ("IPP/CUPS",         "tcp"),
    636:   ("LDAPS",            "tcp"),
    873:   ("rsync",            "tcp"),
    993:   ("IMAPS",            "tcp"),
    995:   ("POP3S",            "tcp"),
    1080:  ("SOCKS",            "tcp"),
    1433:  ("MSSQL",            "tcp"),
    1521:  ("Oracle DB",        "tcp"),
    1723:  ("PPTP",             "tcp"),
    2049:  ("NFS",              "tcp"),
    2375:  ("Docker",           "tcp"),
    2376:  ("Docker TLS",       "tcp"),
    3000:  ("Dev Server",       "tcp"),
    3306:  ("MySQL/MariaDB",    "tcp"),
    3389:  ("RDP",              "tcp"),
    4369:  ("RabbitMQ EPMD",    "tcp"),
    5432:  ("PostgreSQL",       "tcp"),
    5672:  ("AMQP/RabbitMQ",    "tcp"),
    5900:  ("VNC",              "tcp"),
    5985:  ("WinRM HTTP",       "tcp"),
    5986:  ("WinRM HTTPS",      "tcp"),
    6379:  ("Redis",            "tcp"),
    6443:  ("Kubernetes API",   "tcp"),
    7001:  ("WebLogic",         "tcp"),
    8000:  ("HTTP-Alt",         "tcp"),
    8080:  ("HTTP-Proxy",       "tcp"),
    8443:  ("HTTPS-Alt",        "tcp"),
    8888:  ("HTTP-Alt",         "tcp"),
    9000:  ("SonarQube/PHP-FPM","tcp"),
    9090:  ("Prometheus",       "tcp"),
    9200:  ("Elasticsearch",    "tcp"),
    9300:  ("Elasticsearch",    "tcp"),
    10250: ("Kubelet",          "tcp"),
    11211: ("Memcached",        "tcp"),
    27017: ("MongoDB",          "tcp"),
    27018: ("MongoDB",          "tcp"),
    50000: ("SAP",              "tcp"),
    50070: ("Hadoop",           "tcp"),
}

# Banner keywords → service identification
BANNER_PATTERNS: list[tuple[list[str], str]] = [
    (["SSH-"],                          "SSH"),
    (["220 ", "SMTP", "Postfix", "Exim","sendmail"], "SMTP"),
    (["220 ", "FTP", "FileZilla", "vsftpd", "ProFTPD"], "FTP"),
    (["HTTP/1", "HTTP/2", "Server:"],   "HTTP"),
    (["MySQL", "MariaDB", "\x4a\x00\x00\x00"], "MySQL"),
    (["PostgreSQL", "FATAL", "pg_hba"], "PostgreSQL"),
    (["Redis", "+PONG", "-ERR"],        "Redis"),
    (["Memcached", "VERSION"],          "Memcached"),
    (["MongoDB", "ismaster"],           "MongoDB"),
    (["220 ", "Telnet"],                "Telnet"),
    (["* OK", "CAPABILITY", "IMAP"],    "IMAP"),
    (["RFB 00"],                        "VNC"),
    (["SMB", "\xff\x53\x4d\x42"],       "SMB"),
]


def identify_service(port: int, banner: Optional[str] = None) -> str:
    """
    Return a human-readable service name for a port/banner combo.
    Banner-based detection takes priority over port-based.
    """
    if banner:
        banner_upper = banner.upper()
        for keywords, service in BANNER_PATTERNS:
            if any(kw.upper() in banner_upper for kw in keywords):
                return service

    name, _ = PORT_MAP.get(port, ("Unknown", "tcp"))
    return name


def is_high_value(port: int, service: str) -> bool:
    """Return True if this port/service is typically high-value for pentesters."""
    high_value_services = {
        "SSH", "RDP", "Telnet", "FTP", "SMB", "MySQL/MariaDB",
        "PostgreSQL", "MongoDB", "Redis", "Memcached", "Docker",
        "Elasticsearch", "Kubernetes API", "Kubelet", "WinRM HTTP",
        "WinRM HTTPS", "VNC", "MSSQL", "Oracle DB", "WebLogic",
    }
    high_value_ports = {22, 23, 3389, 5900, 445, 1433, 3306, 5432,
                        27017, 6379, 2375, 9200, 10250}
    return service in high_value_services or port in high_value_ports
