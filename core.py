from scapy.all import *


def identificar_servico_tcp(porta):
    servicos = {
        20: "FTP-Data",
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        143: "IMAP",
        443: "HTTPS",
        587: "SMTP",
        993: "IMAPS",
        995: "POP3S",
    }

    return servicos.get(porta, "Desconhecido")


def identificar_servico_udp(porta):
    servicos = {
        53: "DNS",
        67: "DHCP",
        68: "DHCP",
        123: "NTP",
        161: "SNMP",
        443: "QUIC/HTTPS",
    }

    return servicos.get(porta, "Desconhecido")
