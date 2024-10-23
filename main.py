import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter import ttk
import re

# Diccionario con los tokens en base a la tabla
tokens = {
    'Palabras Reservadas': ['entero', 'decimal', 'booleano', 'cadena', 'si', 'sino', 'mientras', 'hacer', 'verdadero', 'falso'],
    'Operadores': ['+', '-', '*', '/', '%', '=', '==', '<', '>', '>=', '<='],
    'Signos': ['(', ')', '{', '}', '"', ';', '[', ']'],
    'Numeros': r'\d+',
    'Identificadores': r'[a-zA-Z_][a-zA-Z0-9_]*'
}


class AnalizadorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Analizador Léxico")
        self.root.geometry("1000x600")
        self.root.config(bg="#f4f4f4")

        # Notebook para pestañas
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True)

        # Pestaña para contenido del archivo
        self.frame_contenido = tk.Frame(self.notebook, bg="#f4f4f4")
        self.notebook.add(self.frame_contenido, text="Contenido del Archivo")

        # Pestaña para resultados del análisis
        self.frame_resultados = tk.Frame(self.notebook, bg="#f4f4f4")
        self.notebook.add(self.frame_resultados, text="Resultados del Análisis")

        # Frame superior para título
        self.frame_titulo = tk.Frame(self.frame_contenido, bg="#007BFF")
        self.frame_titulo.pack(fill=tk.X)

        # Etiqueta del título
        self.lbl_titulo = tk.Label(self.frame_titulo, text="Analizador Léxico", font=("Helvetica", 24, "bold"), bg="#007BFF", fg="#ffffff")
        self.lbl_titulo.pack(pady=20)

        # Botones para acciones
        self.btns_frame = tk.Frame(self.frame_contenido, bg="#f4f4f4")
        self.btns_frame.pack(side=tk.LEFT, fill=tk.Y)

        # Botón para abrir archivo
        self.btn_abrir = tk.Button(self.btns_frame, text="Abrir Archivo", command=self.abrir_archivo, bg="#28A745", fg="white", font=("Helvetica", 12))
        self.btn_abrir.pack(pady=10, padx=10)

        # Botón para guardar archivo
        self.btn_guardar = tk.Button(self.btns_frame, text="Guardar Archivo", command=self.guardar_archivo, bg="#FFC107", fg="black", font=("Helvetica", 12))
        self.btn_guardar.pack(pady=10, padx=10)

        # Botón para análisis léxico
        self.btn_analizar = tk.Button(self.btns_frame, text="Análisis Léxico", command=self.analizar, bg="#007BFF", fg="white", font=("Helvetica", 12))
        self.btn_analizar.pack(pady=10, padx=10)

        # Botón para análisis sintáctico
        self.btn_sintactico = tk.Button(self.btns_frame, text="Análisis Sintáctico", command=self.analizar_sintactico, bg="#17A2B8", fg="white", font=("Helvetica", 12))
        self.btn_sintactico.pack(pady=10, padx=10)

        # Botón para análisis semántico
        self.btn_semantico = tk.Button(self.btns_frame, text="Análisis Semántico", command=self.analizar_semantico, bg="#DC3545", fg="white", font=("Helvetica", 12))
        self.btn_semantico.pack(pady=10, padx=10)

        # Botón para limpiar texto
        self.btn_limpiar = tk.Button(self.btns_frame, text="Limpiar", command=self.limpiar_texto, bg="#6C757D", fg="white", font=("Helvetica", 12))
        self.btn_limpiar.pack(pady=10, padx=10)

        # Área de texto para mostrar el contenido del archivo
        self.textbox = tk.Text(self.frame_contenido, height=30, width=50, bg="#ffffff", fg="#000000", font=("Helvetica", 11), wrap=tk.WORD)
        self.textbox.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

        # Treeview para mostrar los resultados del análisis
        self.tree = ttk.Treeview(self.frame_resultados, columns=("Token", "Tipo", "Cantidad"), show="headings", height=15)
        self.tree.heading("Token", text="Token")
        self.tree.heading("Tipo", text="Tipo")
        self.tree.heading("Cantidad", text="Cantidad")
        self.tree.column("Token", anchor="center", width=200)
        self.tree.column("Tipo", anchor="center", width=150)
        self.tree.column("Cantidad", anchor="center", width=100)
        self.tree.pack(fill=tk.BOTH, expand=True)

        # Área de texto para mostrar los errores
        self.text_errores = tk.Text(self.frame_resultados, height=10, bg="#f8d7da", fg="#721c24", font=("Helvetica", 11), wrap=tk.WORD)
        self.text_errores.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

    # Método para abrir archivos
    def abrir_archivo(self):
        archivo = filedialog.askopenfilename(filetypes=[("Archivos de texto", "*.txt")])
        if archivo:
            with open(archivo, 'r') as file:
                contenido = file.read()
                self.textbox.delete(1.0, tk.END)
                self.textbox.insert(tk.END, contenido)

    # Método para guardar archivos
    def guardar_archivo(self):
        archivo = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Archivos de texto", "*.txt")])
        if archivo:
            with open(archivo, 'w') as file:
                contenido = self.textbox.get(1.0, tk.END)
                file.write(contenido)
            messagebox.showinfo("Guardado", "El archivo ha sido guardado correctamente.")

    # Método para limpiar texto
    def limpiar_texto(self):
        self.textbox.delete(1.0, tk.END)
        self.tree.delete(*self.tree.get_children())
        self.text_errores.delete(1.0, tk.END)

    # Método para análisis léxico
    def analizar(self):
        contenido = self.textbox.get(1.0, tk.END).strip()
        tokens_encontrados = self.obtener_tokens(contenido)
        self.mostrar_resultados(tokens_encontrados)

    # Método para análisis sintáctico
    def analizar_sintactico(self):
        contenido = self.textbox.get(1.0, tk.END).strip()
        errores_sintacticos = self.verificar_sintaxis(contenido)
        self.mostrar_errores(errores_sintacticos)

    # Método para análisis semántico
    def analizar_semantico(self):
        contenido = self.textbox.get(1.0, tk.END).strip()
        errores_semanticos = self.verificar_semantica(contenido)
        self.mostrar_errores(errores_semanticos)

    # Método para obtener tokens
    def obtener_tokens(self, contenido):
        tokens_encontrados = {}
        lineas = contenido.splitlines()
        for linea in lineas:
            for token in linea.split():
                tipo_token = self.obtener_tipo_token(token)
                if tipo_token != "Desconocido":
                    if token in tokens_encontrados:
                        tokens_encontrados[token] += 1
                    else:
                        tokens_encontrados[token] = 1
        return tokens_encontrados

    # Método para mostrar resultados en la tabla
    def mostrar_resultados(self, tokens_encontrados):
        self.tree.delete(*self.tree.get_children())
        self.text_errores.delete(1.0, tk.END)  # Limpiar errores al mostrar nuevos resultados
        for token, cantidad in tokens_encontrados.items():
            tipo_token = self.obtener_tipo_token(token)
            self.tree.insert("", "end", values=(token, tipo_token, cantidad))

    # Método para mostrar errores en el área de texto
    def mostrar_errores(self, errores):
        self.text_errores.delete(1.0, tk.END)  # Limpiar errores anteriores
        if errores:
            for error in errores:
                self.text_errores.insert(tk.END, error + "\n")
        else:
            self.text_errores.insert(tk.END, "No se encontraron errores.")

    # Método para verificar sintaxis
    def verificar_sintaxis(self, contenido):
        errores = []
        lineas = contenido.splitlines()
        pila_llaves = []

        for linea in lineas:
            if 'si' in linea and not re.search(r'\bsi\b\s*\(.*\)', linea):
                errores.append(f"Error en la línea: '{linea}' - estructura 'si' incorrecta.")

            # Puedes agregar más reglas sintácticas aquí

        return errores

    # Método para verificar semántica
    def verificar_semantica(self, contenido):
        errores = []
        # Aquí se agregarían las reglas semánticas para verificar

        return errores

    # Método para obtener tipo de token
    def obtener_tipo_token(self, token):
        for tipo, expresiones in tokens.items():
            if isinstance(expresiones, list):
                if token in expresiones:
                    return tipo
            else:
                if re.fullmatch(expresiones, token):
                    return tipo
        return "Desconocido"

# Crear la aplicación y ejecutar
if __name__ == "__main__":
    root = tk.Tk()
    app = AnalizadorApp(root)
    root.mainloop()
