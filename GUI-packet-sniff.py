import customtkinter as ctk
import random


class MainFrame(ctk.CTkFrame):
    def __init__(self, parent):
        super().__init__(parent, fg_color="transparent")

        # CONFIGURAÇÃO DO LAYOUT

        self.grid_rowconfigure(2, weight=1)
        self.grid_columnconfigure(0, weight=1)

        # Estado do sniffing
        self.running = False

        # Número da próxima linha
        self.packet_count = 0


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


        self.start_button = ctk.CTkButton(
            self,
            text="START",
            fg_color="#1b8817",
            hover_color="#297718",
            font=("Arial", 14, "bold"),
            width=120,
            height=35,
            command=self.toggle_sniffing
        )

        self.start_button.grid(
            row=1,
            column=0,
            pady=(0, 15)
        )

        # FRAME DA TABELA

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
            padx=80,
            pady=(10, 50),
            sticky="nsew"
        )

        # COLUNAS

        self.colunas = [
            "Ip",
            "Source",
            "Destination",
            "Protocol",
            "Service",
            "Length"
        ]

        # Proporção das colunas
        pesos = [
            1,  # IP
            2,  # Source
            2,  # Destination
            1,  # Protocol
            1,  # Service
            1   # Length
        ]

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

        # LISTA DE LABELS DOS PACOTES


        self.dados_labels = []

        
        # DADOS FICTÍCIOS

        self.pacotes_ficticios = []



    def toggle_sniffing(self):

        self.running = not self.running

        if self.running:

            self.start_button.configure(
                text="STOP",
                fg_color="#c0392b",
                hover_color="#a93226"
            )

        else:

            self.start_button.configure(
                text="START",
                fg_color="#1b8817",
                hover_color="#297718"
            )

    # ADICIONAR UM PACOTE

    def adicionar_pacote(self, dados):

        self.packet_count += 1

        row = self.packet_count

        row_labels = []

        for column, dado in enumerate(dados):

            label = ctk.CTkLabel(
                self.data_frame,
                text=dado,
                font=("Arial", 13),
                text_color="#dddddd",
                anchor="w"
            )

            # Alternar a cor das linhas
            if row % 2 == 0:

                label.configure(
                    fg_color="#303030"
                )

            else:

                label.configure(
                    fg_color="#2b2b2b"
                )

            label.grid(
                row=row,
                column=column,
                padx=5,
                pady=2,
                sticky="nsew"
            )

            row_labels.append(label)

        self.dados_labels.append(row_labels)

    # GERAR UM PACOTE FICTÍCIO


    def gerar_pacote(self):

        # Escolhe aleatoriamente um pacote da lista
        pacote = random.choice(
            self.pacotes_ficticios
        )

        # Criamos uma cópia para não alterar o original
        pacote = pacote.copy()

        # Podemos variar o tamanho
        tamanho = random.randint(60, 6500)

        if tamanho >= 1024:

            pacote[5] = f"{tamanho / 1024:.1f} KB"

        else:

            pacote[5] = f"{tamanho} B"

        return pacote

    def capturar_pacote(self):

        if self.running:

            pacote = self.gerar_pacote()

            self.adicionar_pacote(
                pacote
            )

        # Verifica novamente daqui a 300ms
        self.after(
            300,
            self.capturar_pacote
        )


class App(ctk.CTk):

    def __init__(self):

        super().__init__()

        self.geometry(
            "1200x700"
        )

        self.minsize(
            1000,
            600
        )

        # Frame principal
        self.main_frame = MainFrame(
            self
        )

        self.main_frame.pack(
            fill="both",
            expand=True
        )

        # Começar o loop de captura
        self.main_frame.capturar_pacote()



app = App()

app.mainloop()