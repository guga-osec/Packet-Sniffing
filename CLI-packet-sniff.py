from core import PacketSniffer, analisar_pacote
import time

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
        print("Starting the Scan...")
        print("Enter CTRL+C to stop.\n")
        time.sleep(1.75)

        sniffer.start(callback=apresentar_pacote)

        while True:
            
            time.sleep(0.5)

    except KeyboardInterrupt:
        print("\nStoping the scan...")

    finally:
        sniffer.stop()

        print(
            f"Scan ended. "
            f"Captured Packets: {len(sniffer.obter_pacotes())}"
        )


if __name__ == "__main__":
    choice = input('Start the Scan (Y/n): ').lower()
    if choice == 'y' or choice == 'yes' or choice == '':
        executar_cli()
    else:
        exit()