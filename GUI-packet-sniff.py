import customtkinter as ctk
import core


class MainFrame(ctk.CTkFrame):
    def __init__(self, parent):
        super().__init__(parent, fg_color="transparent")

        # Layout principal
        self.grid_rowconfigure(1, weight=1)
        self.grid_columnconfigure(0, weight=1)

        # Título
        self.label = ctk.CTkLabel(
            self,
            text="PACKET SNIFFING",
            font=("Arial", 24)
        )
        self.label.grid(
            row=0,
            column=0,
            pady=(30, 15)
        )

        # Frame principal dos dados
        self.data_frame = ctk.CTkFrame(
            self,
            corner_radius=15,
            fg_color="#2b2b2b"
        )

        self.data_frame.grid(
            row=1,
            column=0,
            padx=80,
            pady=(10, 50),
            sticky="nsew"
        )

        # Colunas da tabela
        colunas = [
            "Ip",
            "Source",
            "Destination",
            "Protocol",
            "Service",
            "Length"
        ]

        # Faz as colunas crescerem proporcionalmente
        for i in range(len(colunas)):
            self.data_frame.grid_columnconfigure(i, weight=1)

        # Cabeçalho
        for i, coluna in enumerate(colunas):

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

        # Dados fictícios
        dados_ficticios = [
            "Exemplo",
            "ABC123",
            "XYZ789",
            "Teste",
            "Demo",
            "123 KB"
        ]

        # Labels que vão mostrar os dados
        self.dados_labels = []

        for i, dado in enumerate(dados_ficticios):

            label = ctk.CTkLabel(
                self.data_frame,
                text=dado,
                font=("Arial", 13),
                text_color="#dddddd"
            )

            label.grid(
                row=1,
                column=i,
                padx=5,
                pady=(5, 10),
                sticky="nsew"
            )

            self.dados_labels.append(label)

    def atualizar_dados(self, valor):

        # Exemplo de atualização dos dados
        dados = [
            f"Exemplo {valor}",
            "ABC123",
            "XYZ789",
            "Teste",
            "Demo",
            f"{valor} KB"
        ]

        for label, dado in zip(self.dados_labels, dados):
            label.configure(text=dado)


class App(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.geometry("1200x700")
        self.minsize(1000, 600)

        self.main_frame = MainFrame(self)
        self.main_frame.pack(
            fill="both",
            expand=True
        )

        self.atualizar()

    def atualizar(self):

        valor = 10

        self.main_frame.atualizar_dados(valor)

        self.after(200, self.atualizar)


app = App()
app.mainloop()
