from scapy.all import (
    AsyncSniffer,
    IP,
    TCP,
    UDP,
    ICMP,
    wrpcap,
)

from threading import Lock


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


def analisar_pacote(pkt):
    """
    Analisa um pacote Scapy e devolve os dados
    necessários para a CLI e para a interface gráfica.
    """

    if IP not in pkt:
        return None

    ip = pkt[IP]

    dados = {
        "source": ip.src,
        "destination": ip.dst,
        "protocol": "Outro",
        "service": "-",
        "port": "-",
        "length": len(pkt),
    }

    if TCP in pkt:
        tcp = pkt[TCP]
        dados["protocol"] = "TCP"

        portas_conhecidas = {
            20, 21, 22, 23, 25, 53, 80,
            110, 143, 443, 587, 993, 995
        }

        if tcp.dport in portas_conhecidas:
            porta = tcp.dport
        elif tcp.sport in portas_conhecidas:
            porta = tcp.sport
        else:
            porta = None

        if porta is not None:
            dados["service"] = identificar_servico_tcp(porta)
            dados["port"] = porta
        else:
            dados["service"] = "Desconhecido"

    elif UDP in pkt:
        udp = pkt[UDP]
        dados["protocol"] = "UDP"

        portas_conhecidas = {
            53, 67, 68, 123, 161, 443
        }

        if udp.dport in portas_conhecidas:
            porta = udp.dport
        elif udp.sport in portas_conhecidas:
            porta = udp.sport
        else:
            porta = None

        if porta is not None:
            dados["service"] = identificar_servico_udp(porta)
            dados["port"] = porta
        else:
            dados["service"] = "Desconhecido"

    elif ICMP in pkt:
        dados["protocol"] = "ICMP"
        dados["service"] = "-"

    return dados


class PacketSniffer:

    def __init__(self):
        self.sniffer = None
        self.callback = None

        # Pacotes originais, não reconstruídos.
        self.packets = []
        self.lock = Lock()

    @property
    def running(self):
        return (
            self.sniffer is not None
            and self.sniffer.running
        )

    def start(self, callback=None, interface=None):
        """
        Inicia a captura numa thread de fundo.
        callback recebe cada pacote Scapy capturado.
        """

        if self.running:
            return

        self.callback = callback

        with self.lock:
            self.packets.clear()

        self.sniffer = AsyncSniffer(
            iface=interface,
            prn=self._receber_pacote,
            store=False,
            filter="ip",
        )

        self.sniffer.start()

    def _receber_pacote(self, pkt):
        if IP not in pkt:
            return

        with self.lock:
            self.packets.append(pkt)

        if self.callback is not None:
            try:
                self.callback(pkt)
            except Exception as erro:
                print(f"Erro no callback: {erro}")

    def stop(self):
        """Interrompe a captura, se estiver ativa."""

        if self.running:
            self.sniffer.stop()

    def obter_pacotes(self):
        """Devolve uma cópia da lista de pacotes capturados."""

        with self.lock:
            return list(self.packets)

    def exportar_pcap(self, caminho, pacotes=None):
        """Exporta os pacotes originais para um ficheiro PCAP."""

        if pacotes is None:
            pacotes = self.obter_pacotes()

        wrpcap(caminho, pacotes)