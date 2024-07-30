import tkinter as tk
from tkinter import ttk, simpledialog, messagebox
import subprocess
import threading
import time
import psutil
import pickle
import os

class ProcessManager:
    def __init__(self, master):
        self.master = master
        master.title("Modern Process Manager")
        master.geometry("900x600")
        master.configure(bg='#2c3e50')

        self.common_processes = [
            "System", "System Idle Process", "Registry", "smss.exe", "csrss.exe",
            "wininit.exe", "services.exe", "lsass.exe", "svchost.exe", "fontdrvhost.exe",
            "dwm.exe", "winlogon.exe", "rundll32.exe", "taskhostw.exe", "explorer.exe",
            "RuntimeBroker.exe", "ShellExperienceHost.exe", "SearchUI.exe", "SearchApp.exe",
            "StartMenuExperienceHost.exe", "Cortana.exe",
            "WindowsInternal.ComposableShell.Experiences.TextInput.InputApp.exe",
            "ApplicationFrameHost.exe", "SystemSettings.exe", "WmiPrvSE.exe", "dllhost.exe",
            "sihost.exe", "ctfmon.exe", "taskmgr.exe", "conhost.exe", "SearchIndexer.exe",
            "SecurityHealthService.exe", "spoolsv.exe", "MsMpEng.exe", "NisSrv.exe",
            "MemCompression", "Secure System", "TrustedInstaller.exe"
        ]

        style = ttk.Style()
        style.theme_use('clam')
        style.configure("Treeview", background="#34495e", fieldbackground="#34495e", foreground="white")
        style.configure("Treeview.Heading", background="#2c3e50", foreground="white", relief="flat")
        style.map('Treeview', background=[('selected', '#3498db')])

        # Snapshot management
        self.snapshots = {}
        self.current_snapshot = None

        # Main content frame
        content_frame = tk.Frame(master, bg='#2c3e50')
        content_frame.pack(expand=True, fill=tk.BOTH, padx=10, pady=10)

        # Process list frame (left side)
        process_frame = tk.Frame(content_frame, bg='#2c3e50')
        process_frame.pack(side=tk.LEFT, expand=True, fill=tk.BOTH)

        # Search frame
        search_frame = tk.Frame(process_frame, bg='#2c3e50')
        search_frame.pack(pady=10, fill=tk.X)

        self.search_var = tk.StringVar()
        self.search_var.trace("w", self.search_processes)
        search_entry = tk.Entry(search_frame, textvariable=self.search_var,
                                bg='#34495e', fg='white', insertbackground='white')
        search_entry.pack(side=tk.LEFT, expand=True, fill=tk.X)

        # Create treeview with scrollbar
        tree_frame = tk.Frame(process_frame)
        tree_frame.pack(expand=True, fill=tk.BOTH)

        self.tree = ttk.Treeview(tree_frame, columns=('PID', 'Name', 'CPU %'), show='headings')
        self.tree.heading('PID', text='PID')
        self.tree.heading('Name', text='Name')
        self.tree.heading('CPU %', text='CPU %')
        self.tree.column('PID', width=100)
        self.tree.column('Name', width=300)
        self.tree.column('CPU %', width=100)

        scrollbar = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscroll=scrollbar.set)

        self.tree.pack(side=tk.LEFT, expand=True, fill=tk.BOTH)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Snapshot frame (right side)
        snapshot_frame = tk.Frame(content_frame, bg='#2c3e50', width=200)
        snapshot_frame.pack(side=tk.RIGHT, fill=tk.Y, padx=(10, 0))

        snapshot_label = tk.Label(snapshot_frame, text="Snapshots", bg='#2c3e50', fg='white', font=('Arial', 14))
        snapshot_label.pack(pady=(0, 10))

        self.snapshot_listbox = tk.Listbox(snapshot_frame, bg='#34495e', fg='white', selectbackground='#3498db')
        self.snapshot_listbox.pack(expand=True, fill=tk.BOTH)

        snapshot_button_frame = tk.Frame(snapshot_frame, bg='#2c3e50')
        snapshot_button_frame.pack(pady=10, fill=tk.X)

        create_snapshot_button = tk.Button(snapshot_button_frame, text="Create",
                                           command=self.create_snapshot,
                                           bg='#27ae60', fg='white', relief=tk.FLAT)
        create_snapshot_button.pack(side=tk.LEFT, padx=2, expand=True, fill=tk.X)

        load_snapshot_button = tk.Button(snapshot_button_frame, text="Load",
                                         command=self.load_selected_snapshot,
                                         bg='#f39c12', fg='white', relief=tk.FLAT)
        load_snapshot_button.pack(side=tk.LEFT, padx=2, expand=True, fill=tk.X)

        delete_snapshot_button = tk.Button(snapshot_button_frame, text="Delete",
                                           command=self.delete_selected_snapshot,
                                           bg='#e74c3c', fg='white', relief=tk.FLAT)
        delete_snapshot_button.pack(side=tk.LEFT, padx=2, expand=True, fill=tk.X)

        clear_snapshot_button = tk.Button(snapshot_button_frame, text="Clear",
                                          command=self.clear_snapshot,
                                          bg='#95a5a6', fg='white', relief=tk.FLAT)
        clear_snapshot_button.pack(side=tk.LEFT, padx=2, expand=True, fill=tk.X)

        # Button frame
        button_frame = tk.Frame(master, bg='#2c3e50')
        button_frame.pack(pady=10, padx=10, fill=tk.X)

        kill_button = tk.Button(button_frame, text="Kill Process", command=self.kill_process,
                                bg='#e74c3c', fg='white', relief=tk.FLAT)
        kill_button.pack(side=tk.LEFT, padx=5)

        self.auto_refresh = True
        self.toggle_button = tk.Button(button_frame, text="Stop Auto-refresh",
                                       command=self.toggle_auto_refresh,
                                       bg='#2980b9', fg='white', relief=tk.FLAT)
        self.toggle_button.pack(side=tk.LEFT, padx=5)

        self.status_label = tk.Label(master, text="", bg='#2c3e50', fg='white')
        self.status_label.pack(pady=5)

        self.all_processes = {}
        self.start_auto_refresh()

        self.load_snapshots()

    def save_snapshots(self):
        with open('snapshots.pkl', 'wb') as f:
            pickle.dump(self.snapshots, f)

    def load_snapshots(self):
        if os.path.exists('snapshots.pkl'):
            with open('snapshots.pkl', 'rb') as f:
                self.snapshots = pickle.load(f)
            if hasattr(self, 'snapshot_listbox'):
                self.update_snapshot_list()
    def refresh_processes(self):
        new_processes = {}
        try:
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent']):
                try:
                    proc_info = proc.info
                    if proc_info['name'] not in self.common_processes:
                        new_processes[proc_info['pid']] = {
                            'name': proc_info['name'],
                            'cpu': proc_info['cpu_percent']
                        }
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    pass

            # Check for suspicious activity
            for pid, info in new_processes.items():
                if pid in self.all_processes:
                    if info['cpu'] > self.all_processes[pid]['cpu'] + 20:  # CPU usage increased by more than 20%
                        info['suspicious'] = True
                    else:
                        info['suspicious'] = False
                else:
                    info['suspicious'] = False

            self.all_processes = new_processes
        except Exception as e:
            self.status_label.config(text=f"Error refreshing process list: {str(e)}")

        self.update_process_display()

    def update_process_display(self):
        self.tree.delete(*self.tree.get_children())
        search_term = self.search_var.get().lower()
        for pid, info in self.all_processes.items():
            if search_term in info['name'].lower():
                if self.current_snapshot is None or pid not in self.current_snapshot:
                    tags = ('suspicious',) if info.get('suspicious', False) else ()
                    self.tree.insert('', 'end', values=(pid, info['name'], f"{info['cpu']:.1f}"), tags=tags)

        self.tree.tag_configure('suspicious', background='#e74c3c')

    def search_processes(self, *args):
        self.update_process_display()

    def create_snapshot(self):
        snapshot_name = simpledialog.askstring("Create Snapshot", "Enter a name for this snapshot:")
        if snapshot_name:
            if snapshot_name in self.snapshots:
                messagebox.showerror("Error", f"Snapshot '{snapshot_name}' already exists.")
                return
            self.snapshots[snapshot_name] = set(self.all_processes.keys())
            self.status_label.config(text=f"Snapshot '{snapshot_name}' created.")
            self.update_snapshot_list()
            self.save_snapshots()  # Save after creating

    def load_selected_snapshot(self):
        selection = self.snapshot_listbox.curselection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a snapshot to load.")
            return
        snapshot_name = self.snapshot_listbox.get(selection[0])
        self.current_snapshot = self.snapshots[snapshot_name]
        self.status_label.config(text=f"Snapshot '{snapshot_name}' loaded.")
        self.update_process_display()

    def delete_selected_snapshot(self):
        selection = self.snapshot_listbox.curselection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a snapshot to delete.")
            return
        snapshot_name = self.snapshot_listbox.get(selection[0])
        confirm = messagebox.askyesno("Confirm Deletion",
                                      f"Are you sure you want to delete the snapshot '{snapshot_name}'?")
        if confirm:
            del self.snapshots[snapshot_name]
            self.status_label.config(text=f"Snapshot '{snapshot_name}' deleted.")
            if self.current_snapshot == self.snapshots.get(snapshot_name):
                self.current_snapshot = None
            self.update_snapshot_list()
            self.update_process_display()
            self.save_snapshots()  # Save after deleting

    def clear_snapshot(self):
        self.current_snapshot = None
        self.status_label.config(text="Snapshot cleared. Showing all processes.")
        self.update_process_display()

    def update_snapshot_list(self):
        if hasattr(self, 'snapshot_listbox'):
            self.snapshot_listbox.delete(0, tk.END)
            for snapshot_name in self.snapshots.keys():
                self.snapshot_listbox.insert(tk.END, snapshot_name)

    def clear_snapshot(self):
        self.current_snapshot = None
        self.status_label.config(text="Snapshot cleared.")
        self.update_process_display()

    def search_processes(self, *args):
        self.tree.delete(*self.tree.get_children())
        search_term = self.search_var.get().lower()
        for pid, info in self.all_processes.items():
            if search_term in info['name'].lower():
                tags = ('suspicious',) if info.get('suspicious', False) else ()
                self.tree.insert('', 'end', values=(pid, info['name'], f"{info['cpu']:.1f}"), tags=tags)

        self.tree.tag_configure('suspicious', background='#e74c3c')

    def kill_process(self):
        selected_item = self.tree.selection()
        if not selected_item:
            return

        pid = int(self.tree.item(selected_item)['values'][0])
        try:
            process = psutil.Process(pid)
            process.terminate()
            self.status_label.config(text=f"Process {pid} terminated.")
        except psutil.NoSuchProcess:
            self.status_label.config(text=f"Process {pid} not found.")
        except psutil.AccessDenied:
            self.status_label.config(text=f"Access denied to terminate process {pid}.")

        self.refresh_processes()

    def start_auto_refresh(self):
        def auto_refresh():
            while self.auto_refresh:
                self.master.after(0, self.refresh_processes)
                time.sleep(3)

        self.refresh_thread = threading.Thread(target=auto_refresh)
        self.refresh_thread.daemon = True
        self.refresh_thread.start()

    def toggle_auto_refresh(self):
        self.auto_refresh = not self.auto_refresh
        if self.auto_refresh:
            self.toggle_button.config(text="Stop Auto-refresh")
            self.start_auto_refresh()
        else:
            self.toggle_button.config(text="Start Auto-refresh")

    def on_closing(self):
        self.save_snapshots()
        self.master.destroy()


if __name__ == "__main__":
    root = tk.Tk()
    app = ProcessManager(root)
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    root.mainloop()