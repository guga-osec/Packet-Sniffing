import customtkinter as ctk
import queue

from tkinter import filedialog, messagebox
from scapy.utils import PcapWriter

from core import PacketSniffer, analisar_pacote


class MainFrame(ctk.CTkFrame):

    def __init__(self, parent):
        super().__init__(parent, fg_color="transparent")

        self.grid_rowconfigure(2, weight=1)
        self.grid_columnconfigure(0, weight=1)

        self.sniffer = PacketSniffer()
        self.packet_count = 0
        self.packet_queue = queue.Queue()
        self.exporting = False

        # TÍTULO

        self.label = ctk.CTkLabel(
            self,
            text="PACKET SNIFFING",
            font=("Arial", 24)
        )
        self.label.grid(
            row=0,
            column=0,
            pady=(30, 10)
        )

        # BOTÕES

        self.buttons_frame = ctk.CTkFrame(
            self,
            fg_color="transparent"
        )
        self.buttons_frame.grid(
            row=1,
            column=0,
            pady=(0, 15)
        )

        self.start_button = ctk.CTkButton(
            self.buttons_frame,
            text="START",
            fg_color="#1b8817",
            hover_color="#297718",
            font=("Arial", 14, "bold"),
            width=120,
            height=35,
            command=self.toggle_sniffing
        )
        self.start_button.grid(
            row=0,
            column=0,
            padx=8
        )

        self.download_button = ctk.CTkButton(
            self.buttons_frame,
            text="DOWNLOAD PCAP",
            fg_color="#2463a6",
            hover_color="#174778",
            font=("Arial", 14, "bold"),
            width=160,
            height=35,
            command=self.download_pcap
        )
        self.download_button.grid(
            row=0,
            column=1,
            padx=8
        )

        # TABELA

        self.data_frame = ctk.CTkScrollableFrame(
            self,
            corner_radius=15,
            fg_color="#2b2b2b",
            scrollbar_button_color="#555555",
            scrollbar_button_hover_color="#666666"
        )
        self.data_frame.grid(
            row=2,
            column=0,
            padx=40,
            pady=(10, 40),
            sticky="nsew"
        )

        self.colunas = [
            "#",
            "Source",
            "Destination",
            "Protocol",
            "Service",
            "Length"
        ]

        pesos = [1, 2, 2, 1, 1, 1]

        for i, peso in enumerate(pesos):
            self.data_frame.grid_columnconfigure(
                i,
                weight=peso
            )

        for i, coluna in enumerate(self.colunas):
            label = ctk.CTkLabel(
                self.data_frame,
                text=coluna,
                font=("Arial", 14, "bold"),
                text_color="#ffffff",
                fg_color="#3a3a3a",
                corner_radius=5
            )
            label.grid(
                row=0,
                column=i,
                padx=5,
                pady=5,
                sticky="nsew"
            )

        # INICIAR A VERIFICAÇÃO DA FILA

        self.after(100, self.processar_fila)

    # START / STOP

    def toggle_sniffing(self):

        if self.sniffer.running:
            self.sniffer.stop()

            self.start_button.configure(
                text="START",
                fg_color="#1b8817",
                hover_color="#297718"
            )

        else:
            # Evitar misturar pacotes antigos na tabela.
            self.limpar_tabela()

            try:
                self.sniffer.start(
                    callback=self.packet_queue.put
                )

                self.start_button.configure(
                    text="STOP",
                    fg_color="#c0392b",
                    hover_color="#a93226"
                )

            except Exception as erro:
                messagebox.showerror(
                    "Erro de captura",
                    f"Não foi possível iniciar a captura:\n{erro}"
                )

    # LIMPAR A TABELA ANTES DE UMA NOVA CAPTURA

    def limpar_tabela(self):

        while not self.packet_queue.empty():
            try:
                self.packet_queue.get_nowait()
            except queue.Empty:
                break

        for widgets in self.data_frame.winfo_children():
            info = widgets.grid_info()

            if info and int(info.get("row", 0)) > 0:
                widgets.destroy()

        self.packet_count = 0

    # PROCESSAR OS PACOTES NA THREAD DA INTERFACE

    def processar_fila(self):

        try:
            while True:
                pkt = self.packet_queue.get_nowait()

                dados = analisar_pacote(pkt)

                if dados is not None:
                    self.adicionar_pacote(dados)

        except queue.Empty:
            pass

        self.after(100, self.processar_fila)

    # ADICIONAR LINHA À TABELA

    def adicionar_pacote(self, dados):

        self.packet_count += 1
        row = self.packet_count

        valores = [
            row,
            dados["source"],
            dados["destination"],
            dados["protocol"],
            dados["service"],
            f'{dados["length"]} B'
        ]

        cor = "#303030" if row % 2 == 0 else "#2b2b2b"

        for column, valor in enumerate(valores):
            label = ctk.CTkLabel(
                self.data_frame,
                text=str(valor),
                font=("Arial", 13),
                text_color="#dddddd",
                fg_color=cor,
                anchor="w"
            )

            label.grid(
                row=row,
                column=column,
                padx=5,
                pady=2,
                sticky="nsew"
            )

    # EXPORTAR PCAP

    def download_pcap(self):

        pacotes = self.sniffer.obter_pacotes()

        if not pacotes:
            messagebox.showwarning(
                "Sem pacotes",
                "Ainda não existem pacotes capturados.\n\n"
                "Carrega em START e aguarda a captura."
            )
            return

        caminho = filedialog.asksaveasfilename(
            title="Guardar captura PCAP",
            defaultextension=".pcap",
            filetypes=[("Ficheiros PCAP", "*.pcap")],
            initialfile="scan.pcap"
        )

        if not caminho:
            return

        self.popup = ctk.CTkToplevel(self)
        self.popup.title("Exportar PCAP")
        self.popup.geometry("420x190")
        self.popup.resizable(False, False)
        self.popup.transient(self.winfo_toplevel())
        self.popup.grab_set()

        ctk.CTkLabel(
            self.popup,
            text="A exportar pacotes capturados...",
            font=("Arial", 16, "bold")
        ).pack(pady=(22, 12))

        self.progress_bar = ctk.CTkProgressBar(
            self.popup,
            width=340
        )
        self.progress_bar.pack(pady=8)
        self.progress_bar.set(0)

        self.progress_label = ctk.CTkLabel(
            self.popup,
            text="0%",
            font=("Arial", 14)
        )
        self.progress_label.pack(pady=4)

        self.status_label = ctk.CTkLabel(
            self.popup,
            text="A preparar exportação..."
        )
        self.status_label.pack(pady=3)

        self.export_packets = pacotes
        self.export_total = len(pacotes)
        self.export_index = 0
        self.export_path = caminho
        self.exporting = True

        try:
            self.pcap_writer = PcapWriter(
                caminho,
                append=False,
                sync=True
            )

        except Exception as erro:
            self.exporting = False
            self.popup.grab_release()
            self.popup.destroy()

            messagebox.showerror(
                "Erro",
                f"Não foi possível criar o PCAP:\n{erro}"
            )
            return

        self.processar_exportacao()

    # EXPORTAR PACOTES PROGRESSIVAMENTE

    def processar_exportacao(self):

        try:
            if self.export_index < self.export_total:

                pkt = self.export_packets[self.export_index]
                self.pcap_writer.write(pkt)

                self.export_index += 1

                percentagem = (
                    self.export_index / self.export_total
                ) * 100

                self.progress_bar.set(percentagem / 100)
                self.progress_label.configure(
                    text=f"{percentagem:.0f}%"
                )
                self.status_label.configure(
                    text=(
                        f"Pacote {self.export_index} "
                        f"de {self.export_total}"
                    )
                )

                self.after(1, self.processar_exportacao)

            else:
                self.pcap_writer.close()
                self.exporting = False

                self.progress_bar.set(1)
                self.progress_label.configure(text="100%")
                self.status_label.configure(
                    text="Exportação concluída!"
                )

                self.after(400, self.download_concluido)

        except Exception as erro:
            self.exporting = False

            try:
                self.pcap_writer.close()
            except Exception:
                pass

            try:
                self.popup.grab_release()
                self.popup.destroy()
            except Exception:
                pass

            messagebox.showerror(
                "Erro na exportação",
                f"Não foi possível exportar o PCAP:\n{erro}"
            )

    def download_concluido(self):

        caminho = self.export_path
        quantidade = self.export_total

        self.popup.grab_release()
        self.popup.destroy()

        messagebox.showinfo(
            "Exportação concluída",
            f"PCAP guardado com sucesso!\n\n"
            f"Pacotes: {quantidade}\n"
            f"Ficheiro: {caminho}"
        )


class App(ctk.CTk):

    def __init__(self):
        super().__init__()

        self.title("Packet Sniffing")
        self.geometry("1200x700")
        self.minsize(1000, 600)

        self.main_frame = MainFrame(self)
        self.main_frame.pack(
            fill="both",
            expand=True
        )

        self.protocol(
            "WM_DELETE_WINDOW",
            self.fechar_aplicacao
        )

    def fechar_aplicacao(self):

        if self.main_frame.sniffer.running:
            self.main_frame.sniffer.stop()

        self.destroy()


if __name__ == "__main__":
    app = App()
    app.mainloop()