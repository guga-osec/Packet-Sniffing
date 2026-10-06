from core import *


def analisar(pkt):

    if IP not in pkt:
        return

    ip = pkt[IP]

    print("=" * 60)
    print(f"Origem:       {ip.src}")
    print(f"Destino:      {ip.dst}")
    print(f"Tamanho:      {len(pkt)} bytes")

    # TCP
    if TCP in pkt:

        tcp = pkt[TCP]

        # Protocolo de transporte
        protocolo = "TCP"

        # Descobrir o serviço pela porta
        if tcp.dport in [20, 21, 22, 23, 25, 53, 80, 110, 143, 443, 587, 993, 995]:
            servico = identificar_servico_tcp(tcp.dport)
            porta_servico = tcp.dport

        elif tcp.sport in [20, 21, 22, 23, 25, 53, 80, 110, 143, 443, 587, 993, 995]:
            servico = identificar_servico_tcp(tcp.sport)
            porta_servico = tcp.sport

        else:
            servico = "Desconhecido"
            porta_servico = "-"

        print(f"Protocolo:    {protocolo}")
        print(f"Serviço:      {servico}")
        print(f"Porta:        {porta_servico}")
        print(f"TCP:          {tcp.sport} -> {tcp.dport}")

    # UDP
    elif UDP in pkt:

        udp = pkt[UDP]

        protocolo = "UDP"

        if udp.dport in [53, 67, 68, 123, 161, 443]:
            servico = identificar_servico_udp(udp.dport)
            porta_servico = udp.dport

        elif udp.sport in [53, 67, 68, 123, 161, 443]:
            servico = identificar_servico_udp(udp.sport)
            porta_servico = udp.sport

        else:
            servico = "Desconhecido"
            porta_servico = "-"

        print(f"Protocolo:    {protocolo}")
        print(f"Serviço:      {servico}")
        print(f"Porta:        {porta_servico}")
        print(f"UDP:          {udp.sport} -> {udp.dport}")

    # ICMP
    elif ICMP in pkt:

        print("Protocolo:    ICMP")
        print("Serviço:      -")


sniff(prn=analisar)