from core import PacketSniffer, analisar_pacote


def apresentar_pacote(pkt):
    dados = analisar_pacote(pkt)

    if dados is None:
        return

    print("=" * 60)
    print(f"Origem:       {dados['source']}")
    print(f"Destino:      {dados['destination']}")
    print(f"Tamanho:      {dados['length']} bytes")
    print(f"Protocolo:    {dados['protocol']}")
    print(f"Serviço:      {dados['service']}")
    print(f"Porta:        {dados['port']}")


def executar_cli():
    sniffer = PacketSniffer()

    try:
        print("A iniciar captura de pacotes...")
        print("Pressiona CTRL+C para parar.\n")

        sniffer.start(callback=apresentar_pacote)

        while True:
            import time
            time.sleep(0.5)

    except KeyboardInterrupt:
        print("\nA parar a captura...")

    finally:
        sniffer.stop()

        print(
            f"Captura terminada. "
            f"Pacotes guardados: {len(sniffer.obter_pacotes())}"
        )


if __name__ == "__main__":
    executar_cli()