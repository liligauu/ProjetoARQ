import tkinter as tk
from tkinter import filedialog
import re

class MIPSSimulator:
    def __init__(self, root):
        self.root = root
        self.root.title("Simulador MIPS (.o)")
        self.root.configure(bg="#f0f0f0")

        self.memory = {}
        self.program = []
        self.pc = 0

        self.registers = {f"${i}": 0 for i in range(32)}
        self.register_names = [
            "zero", "at", "v0", "v1", "a0", "a1", "a2", "a3",
            "t0", "t1", "t2", "t3", "t4", "t5", "t6", "t7",
            "s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7",
            "t8", "t9", "k0", "k1", "gp", "sp", "fp", "ra"
        ]

        self.setup_ui()

    def setup_ui(self):
        button_frame = tk.Frame(self.root, bg="#f0f0f0")
        button_frame.pack(fill=tk.X, padx=10, pady=5)

        tk.Button(button_frame, text="Carregar .o", command=self.load_file, bg="#4a90e2", fg="white").pack(side=tk.LEFT)
        tk.Button(button_frame, text="Executar Próxima", command=self.execute_next, bg="#4caf50", fg="white").pack(side=tk.LEFT, padx=5)
        tk.Button(button_frame, text="Executar Tudo", command=self.execute_all, bg="#f39c12", fg="white").pack(side=tk.LEFT, padx=5)
        tk.Button(button_frame, text="Limpar", command=self.clear_all, bg="#e74c3c", fg="white").pack(side=tk.LEFT, padx=5)

        main_frame = tk.Frame(self.root, bg="#f0f0f0")
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        self.console = tk.Text(main_frame, height=10, bg="#1e1e1e", fg="lime", insertbackground="white", font=("Consolas", 11))
        self.console.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.console.insert(tk.END, "Carregue um arquivo .o\n")

        reg_frame = tk.Frame(main_frame, bg="#f0f0f0")
        reg_frame.pack(side=tk.RIGHT, fill=tk.Y, padx=10)

        tk.Label(reg_frame, text="Registradores", bg="#f0f0f0", font=("Consolas", 12, "bold")).pack()

        self.reg_listbox_frame = tk.Frame(reg_frame)
        self.reg_listbox_frame.pack(fill=tk.BOTH, expand=True)

        self.reg_scrollbar = tk.Scrollbar(self.reg_listbox_frame)
        self.reg_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.reg_listbox = tk.Listbox(self.reg_listbox_frame, font=("Consolas", 11), yscrollcommand=self.reg_scrollbar.set, height=20, bg="white", fg="black")
        self.reg_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.reg_scrollbar.config(command=self.reg_listbox.yview)

        self.update_register_display()

    def load_file(self):
        file_path = filedialog.askopenfilename(filetypes=[("Object Files", "*.o"), ("Todos arquivos", "*.*")])
        if file_path:
            with open(file_path, "r") as f:
                self.program = [line.strip() for line in f if line.strip() and not line.startswith("#")]
            self.pc = 0
            self.console.insert(tk.END, f"\nArquivo carregado: {file_path}\n")
            self.console.insert(tk.END, f"{len(self.program)} instruções carregadas.\n")

    def execute_all(self):
        while self.pc < len(self.program):
            self.execute_next()

    def execute_next(self):
        if not self.program:
            self.console.insert(tk.END, "Nenhum arquivo foi inserido.\n")
        elif self.pc < len(self.program):
            instr = self.program[self.pc]
            self.console.insert(tk.END, f"> {instr}\n")
            result = self.run_instruction(instr)
            if "print" in instr:
                self.console.insert(tk.END, result + "\n")
            self.console.see(tk.END)
            self.pc += 1
            self.update_register_display()
        else:
            self.console.insert(tk.END, "Fim do programa.\n")

    def clear_all(self):
        self.console.delete("1.0", tk.END)
        self.registers = {f"${i}": 0 for i in range(32)}
        self.memory = {}
        self.program = []
        self.pc = 0
        self.update_register_display()
        self.console.insert(tk.END, "Simulador reiniciado.\n")

    def get_register_value(self, name):
        return self.registers.get(name, 0)

    def set_register_value(self, name, value):
        if name != "$0":
            self.registers[name] = value

    def update_register_display(self):
        self.reg_listbox.delete(0, tk.END)
        for i in range(32):
            reg_num = f"R{i:<2}"
            reg_name = self.register_names[i]
            value = self.get_register_value(f"${i}")
            self.reg_listbox.insert(tk.END, f"{reg_num} [{reg_name:<3}] = {value}")

    def run_instruction(self, instr):
        try:
            parts = re.split(r"[\s,()]+", instr.lower())
            op = parts[0]

            if op == "add":
                rd, rs, rt = map(self.alias, parts[1:4])
                self.set_register_value(rd, self.get_register_value(rs) + self.get_register_value(rt))
                return f"{rd} = {self.get_register_value(rd)}"

            elif op == "addi":
                rt, rs, imm = self.alias(parts[1]), self.alias(parts[2]), int(parts[3])
                self.set_register_value(rt, self.get_register_value(rs) + imm)
                return f"{rt} = {self.get_register_value(rt)}"

            elif op == "sub":
                rd, rs, rt = map(self.alias, parts[1:4])
                self.set_register_value(rd, self.get_register_value(rs) - self.get_register_value(rt))
                return f"{rd} = {self.get_register_value(rd)}"

            elif op == "and":
                rd, rs, rt = map(self.alias, parts[1:4])
                self.set_register_value(rd, self.get_register_value(rs) & self.get_register_value(rt))
                return f"{rd} = {self.get_register_value(rd)}"

            elif op == "or":
                rd, rs, rt = map(self.alias, parts[1:4])
                self.set_register_value(rd, self.get_register_value(rs) | self.get_register_value(rt))
                return f"{rd} = {self.get_register_value(rd)}"

            elif op == "sll":
                rd, rt, shamt = self.alias(parts[1]), self.alias(parts[2]), int(parts[3])
                self.set_register_value(rd, self.get_register_value(rt) << shamt)
                return f"{rd} = {self.get_register_value(rd)}"

            elif op == "lui":
                rt, imm = self.alias(parts[1]), int(parts[2])
                self.set_register_value(rt, imm << 16)
                return f"{rt} = {self.get_register_value(rt)}"

            elif op == "lw":
                rt, offset, base = self.alias(parts[1]), int(parts[2]), self.alias(parts[3])
                addr = self.get_register_value(base) + offset
                val = self.memory.get(addr, 0)
                self.set_register_value(rt, val)
                return f"{rt} = Mem[{addr}] = {val}"

            elif op == "sw":
                rt, offset, base = self.alias(parts[1]), int(parts[2]), self.alias(parts[3])
                addr = self.get_register_value(base) + offset
                self.memory[addr] = self.get_register_value(rt)
                return f"Mem[{addr}] = {self.get_register_value(rt)}"

            elif op == "slt":
                rd, rs, rt = map(self.alias, parts[1:4])
                self.set_register_value(rd, 1 if self.get_register_value(rs) < self.get_register_value(rt) else 0)
                return f"{rd} = {self.get_register_value(rd)}"

            elif op == "slti":
                rt, rs, imm = self.alias(parts[1]), self.alias(parts[2]), int(parts[3])
                self.set_register_value(rt, 1 if self.get_register_value(rs) < imm else 0)
                return f"{rt} = {self.get_register_value(rt)}"

            elif op == "print":
                reg = self.alias(parts[1])
                return f"{reg} = {self.get_register_value(reg)}"

            return f"Instrução não reconhecida: {op}"

        except Exception as e:
            return f"Erro ao executar: {e}"

    def alias(self, reg):
        reg = reg.replace("$", "")
        if reg.isdigit():
            return f"${reg}"
        elif reg in self.register_names:
            idx = self.register_names.index(reg)
            return f"${idx}"
        else:
            raise ValueError(f"Registrador inválido: {reg}")

if __name__ == "__main__":
    root = tk.Tk()
    app = MIPSSimulator(root)
    root.mainloop()
