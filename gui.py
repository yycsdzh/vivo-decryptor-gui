#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tkinter GUI for vivo Suite / PC Backup Decryptor.

Uses stdlib + vivo_engine + cryptography only.
Never logs or displays passwords or derived keys.
"""

import atexit
import os
import queue
import shutil
import sys
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)

import vivo_engine

ALL_CONTAINERS = "All containers"
CHECKED = "\u2611"
UNCHECKED = "\u2610"


def _format_size(num_bytes):
    """Format byte size into a human-readable string."""
    if num_bytes < 1024:
        return f"{num_bytes} B"
    if num_bytes < 1024 * 1024:
        return f"{num_bytes / 1024:.1f} KB"
    if num_bytes < 1024 * 1024 * 1024:
        return f"{num_bytes / (1024 * 1024):.2f} MB"
    return f"{num_bytes / (1024 * 1024 * 1024):.2f} GB"


class VivoDecryptGUI:
    """Main Tkinter application for decrypting vivo PC backups."""

    def __init__(self, root):
        self.root = root
        self.root.title("vivo Backup Decryptor")
        self.root.geometry("860x700")
        self.root.minsize(720, 580)

        self.msg_queue = queue.Queue()
        self.cancel_event = threading.Event()
        self.worker_thread = None
        self.is_busy = False

        # Cached temp file from "Refresh file list"
        self.cached_tmp_path = None
        self.cached_backup_dir = None
        self.cached_container = None

        # File list state: item_id -> {"name": str, "size": int, "checked": bool}
        self.file_items = {}

        # Tk variables
        self.backup_dir_var = tk.StringVar()
        self.output_dir_var = tk.StringVar()
        self.password_var = tk.StringVar()
        self.show_password_var = tk.BooleanVar(value=False)
        self.container_var = tk.StringVar(value=ALL_CONTAINERS)
        self.status_var = tk.StringVar(value="Ready.")
        self.selection_info_var = tk.StringVar(value="No files loaded.")

        self._build_menu()
        self._build_ui()

        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        atexit.register(self._cleanup_cached_temp)

        # Start polling the worker queue on the main thread
        self.root.after(100, self._poll_queue)

    # ------------------------------------------------------------------ UI ---

    def _build_menu(self):
        menubar = tk.Menu(self.root)

        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="Select Backup Folder...", command=self._browse_backup)
        file_menu.add_command(label="Select Output Folder...", command=self._browse_output)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self._on_close)
        menubar.add_cascade(label="File", menu=file_menu)

        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="About", command=self._show_about)
        menubar.add_cascade(label="Help", menu=help_menu)

        self.root.config(menu=menubar)

    def _build_ui(self):
        main = ttk.Frame(self.root, padding=10)
        main.pack(fill=tk.BOTH, expand=True)

        # --- Top form: folders, password, container ---
        form = ttk.LabelFrame(main, text="Backup Settings", padding=8)
        form.pack(fill=tk.X, pady=(0, 8))
        form.columnconfigure(1, weight=1)

        # Backup folder
        ttk.Label(form, text="Backup folder:").grid(row=0, column=0, sticky=tk.W, padx=(0, 6), pady=3)
        self.backup_entry = ttk.Entry(form, textvariable=self.backup_dir_var)
        self.backup_entry.grid(row=0, column=1, sticky=tk.EW, pady=3)
        self.backup_entry.bind("<FocusOut>", lambda _e: self._reload_containers())
        self.backup_btn = ttk.Button(form, text="Browse...", command=self._browse_backup)
        self.backup_btn.grid(row=0, column=2, padx=(6, 0), pady=3)

        # Output folder
        ttk.Label(form, text="Output folder:").grid(row=1, column=0, sticky=tk.W, padx=(0, 6), pady=3)
        self.output_entry = ttk.Entry(form, textvariable=self.output_dir_var)
        self.output_entry.grid(row=1, column=1, sticky=tk.EW, pady=3)
        self.output_btn = ttk.Button(form, text="Browse...", command=self._browse_output)
        self.output_btn.grid(row=1, column=2, padx=(6, 0), pady=3)

        # Password with show/hide toggle
        ttk.Label(form, text="Password:").grid(row=2, column=0, sticky=tk.W, padx=(0, 6), pady=3)
        self.password_entry = ttk.Entry(form, textvariable=self.password_var, show="*")
        self.password_entry.grid(row=2, column=1, sticky=tk.EW, pady=3)
        self.show_pw_chk = ttk.Checkbutton(
            form,
            text="Show",
            variable=self.show_password_var,
            command=self._toggle_password_visibility,
        )
        self.show_pw_chk.grid(row=2, column=2, sticky=tk.W, padx=(6, 0), pady=3)

        # Container dropdown
        ttk.Label(form, text="Container:").grid(row=3, column=0, sticky=tk.W, padx=(0, 6), pady=3)
        self.container_combo = ttk.Combobox(
            form,
            textvariable=self.container_var,
            values=[ALL_CONTAINERS],
            state="readonly",
        )
        self.container_combo.grid(row=3, column=1, sticky=tk.EW, pady=3)
        self.container_combo.bind("<<ComboboxSelected>>", self._on_container_changed)
        self.refresh_btn = ttk.Button(
            form,
            text="Refresh file list",
            command=self._on_refresh_file_list,
        )
        self.refresh_btn.grid(row=3, column=2, padx=(6, 0), pady=3)

        # --- Two-step file list section ---
        files_frame = ttk.LabelFrame(main, text="Container File List (Optional Selective Extraction)", padding=8)
        files_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 8))

        note_lbl = ttk.Label(
            files_frame,
            text=(
                "Two-step listing: Encrypted containers cannot be inspected in place. "
                "Select a single container above and click 'Refresh file list' to decrypt it "
                "to a temporary file first, then choose files below before clicking 'Start'."
            ),
            wraplength=800,
            justify=tk.LEFT,
        )
        note_lbl.pack(fill=tk.X, pady=(0, 6))

        toolbar = ttk.Frame(files_frame)
        toolbar.pack(fill=tk.X, pady=(0, 4))
        self.select_all_btn = ttk.Button(toolbar, text="Select all", command=self._select_all)
        self.select_all_btn.pack(side=tk.LEFT, padx=(0, 6))
        self.select_none_btn = ttk.Button(toolbar, text="Select none", command=self._select_none)
        self.select_none_btn.pack(side=tk.LEFT)
        ttk.Label(toolbar, textvariable=self.selection_info_var).pack(side=tk.RIGHT)

        tree_container = ttk.Frame(files_frame)
        tree_container.pack(fill=tk.BOTH, expand=True)

        self.tree = ttk.Treeview(
            tree_container,
            columns=("check", "name", "size"),
            show="headings",
            selectmode="browse",
            height=8,
        )
        self.tree.heading("check", text="Pick")
        self.tree.heading("name", text="File Path")
        self.tree.heading("size", text="Size")
        self.tree.column("check", width=48, minwidth=40, stretch=False, anchor=tk.CENTER)
        self.tree.column("name", width=560, minwidth=200, stretch=True, anchor=tk.W)
        self.tree.column("size", width=110, minwidth=80, stretch=False, anchor=tk.E)

        tree_scroll_y = ttk.Scrollbar(tree_container, orient=tk.VERTICAL, command=self.tree.yview)
        tree_scroll_x = ttk.Scrollbar(tree_container, orient=tk.HORIZONTAL, command=self.tree.xview)
        self.tree.configure(yscrollcommand=tree_scroll_y.set, xscrollcommand=tree_scroll_x.set)

        self.tree.grid(row=0, column=0, sticky=tk.NSEW)
        tree_scroll_y.grid(row=0, column=1, sticky=tk.NS)
        tree_scroll_x.grid(row=1, column=0, sticky=tk.EW)
        tree_container.rowconfigure(0, weight=1)
        tree_container.columnconfigure(0, weight=1)

        self.tree.bind("<Button-1>", self._on_tree_click)
        self.tree.bind("<space>", self._on_tree_space)

        # --- Controls & Progress ---
        ctrl_frame = ttk.Frame(main)
        ctrl_frame.pack(fill=tk.X, pady=(0, 8))

        self.start_btn = ttk.Button(ctrl_frame, text="Start", command=self._on_start)
        self.start_btn.pack(side=tk.LEFT, padx=(0, 8))
        self.cancel_btn = ttk.Button(
            ctrl_frame,
            text="Cancel",
            command=self._on_cancel,
            state=tk.DISABLED,
        )
        self.cancel_btn.pack(side=tk.LEFT, padx=(0, 12))

        self.progress_bar = ttk.Progressbar(ctrl_frame, mode="determinate", maximum=100)
        self.progress_bar.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))

        self.status_lbl = ttk.Label(ctrl_frame, textvariable=self.status_var, width=28, anchor=tk.E)
        self.status_lbl.pack(side=tk.RIGHT)

        # --- Live Read-Only Log Pane ---
        log_frame = ttk.LabelFrame(main, text="Log", padding=6)
        log_frame.pack(fill=tk.BOTH, expand=True)

        self.log_text = scrolledtext.ScrolledText(
            log_frame,
            height=9,
            state=tk.DISABLED,
            wrap=tk.WORD,
        )
        self.log_text.pack(fill=tk.BOTH, expand=True)

    # ------------------------------------------------------------- Helpers ---

    def _append_log(self, message):
        """Append a line to the read-only log pane (main thread only)."""
        self.log_text.configure(state=tk.NORMAL)
        self.log_text.insert(tk.END, message + "\n")
        self.log_text.see(tk.END)
        self.log_text.configure(state=tk.DISABLED)

    def _set_busy(self, busy):
        """Enable or disable controls while a background operation is running."""
        self.is_busy = busy
        state = tk.DISABLED if busy else tk.NORMAL
        combo_state = tk.DISABLED if busy else "readonly"

        self.backup_entry.configure(state=state)
        self.backup_btn.configure(state=state)
        self.output_entry.configure(state=state)
        self.output_btn.configure(state=state)
        self.password_entry.configure(state=state)
        self.show_pw_chk.configure(state=state)
        self.container_combo.configure(state=combo_state)
        self.refresh_btn.configure(state=state)
        self.select_all_btn.configure(state=state)
        self.select_none_btn.configure(state=state)
        self.start_btn.configure(state=state)
        self.cancel_btn.configure(state=tk.NORMAL if busy else tk.DISABLED)

    def _toggle_password_visibility(self):
        if self.show_password_var.get():
            self.password_entry.configure(show="")
        else:
            self.password_entry.configure(show="*")

    def _clear_password(self):
        self.password_var.set("")
        self.show_password_var.set(False)
        self.password_entry.configure(show="*")

    def _browse_backup(self):
        path = filedialog.askdirectory(title="Select vivo Backup Folder")
        if path:
            self.backup_dir_var.set(path)
            self._reload_containers()

    def _browse_output(self):
        path = filedialog.askdirectory(title="Select Output Folder")
        if path:
            self.output_dir_var.set(path)

    def _reload_containers(self):
        backup_dir = self.backup_dir_var.get().strip()
        self._clear_file_list()
        self._cleanup_cached_temp()

        if not backup_dir or not os.path.isdir(backup_dir):
            self.container_combo.configure(values=[ALL_CONTAINERS])
            self.container_var.set(ALL_CONTAINERS)
            return

        containers = vivo_engine.list_containers(backup_dir)
        values = [ALL_CONTAINERS] + containers
        self.container_combo.configure(values=values)
        self.container_var.set(ALL_CONTAINERS)
        self._append_log(f"Found {len(containers)} container(s) in backup folder.")

    def _on_container_changed(self, _event=None):
        chosen = self.container_var.get()
        if chosen != self.cached_container:
            self._clear_file_list()
            self._cleanup_cached_temp()

    def _clear_file_list(self):
        for item_id in self.tree.get_children():
            self.tree.delete(item_id)
        self.file_items.clear()
        self.selection_info_var.set("No files loaded.")

    def _cleanup_cached_temp(self):
        tmp = self.cached_tmp_path
        self.cached_tmp_path = None
        self.cached_backup_dir = None
        self.cached_container = None
        if tmp and os.path.exists(tmp):
            try:
                os.remove(tmp)
            except OSError:
                pass

    def _populate_file_list(self, entries):
        self._clear_file_list()
        for entry in entries:
            name = entry["name"]
            size = entry.get("size", 0)
            item_id = self.tree.insert("", tk.END, values=(CHECKED, name, _format_size(size)))
            self.file_items[item_id] = {
                "name": name,
                "size": size,
                "checked": True,
            }
        self._update_selection_info()

    def _update_selection_info(self):
        total = len(self.file_items)
        if total == 0:
            self.selection_info_var.set("No files loaded.")
            return
        selected = sum(1 for item in self.file_items.values() if item["checked"])
        sel_bytes = sum(item["size"] for item in self.file_items.values() if item["checked"])
        self.selection_info_var.set(
            f"Selected: {selected}/{total} ({_format_size(sel_bytes)})"
        )

    def _toggle_item(self, item_id):
        if self.is_busy or item_id not in self.file_items:
            return
        info = self.file_items[item_id]
        info["checked"] = not info["checked"]
        glyph = CHECKED if info["checked"] else UNCHECKED
        self.tree.item(item_id, values=(glyph, info["name"], _format_size(info["size"])))
        self._update_selection_info()

    def _on_tree_click(self, event):
        if self.is_busy:
            return
        item_id = self.tree.identify_row(event.y)
        if item_id:
            self._toggle_item(item_id)

    def _on_tree_space(self, _event):
        if self.is_busy:
            return
        selection = self.tree.selection()
        if selection:
            self._toggle_item(selection[0])

    def _select_all(self):
        if self.is_busy:
            return
        for item_id, info in self.file_items.items():
            info["checked"] = True
            self.tree.item(item_id, values=(CHECKED, info["name"], _format_size(info["size"])))
        self._update_selection_info()

    def _select_none(self):
        if self.is_busy:
            return
        for item_id, info in self.file_items.items():
            info["checked"] = False
            self.tree.item(item_id, values=(UNCHECKED, info["name"], _format_size(info["size"])))
        self._update_selection_info()

    def _show_about(self):
        messagebox.showinfo(
            "About vivo Backup Decryptor",
            "vivo Backup Decryptor GUI\n\n"
            "Decrypts vivo Suite / PC Backup containers (AES-256-GCM / CTR).\n\n"
            "Credits:\n"
            "Based on awakaze/vivo-backup-decryptor\n"
            "Licensed under the MIT License.",
        )

    def _on_close(self):
        if self.is_busy:
            if not messagebox.askyesno(
                "Operation in progress",
                "A decryption task is still running. Cancel it and exit?",
            ):
                return
            self.cancel_event.set()
        self._cleanup_cached_temp()
        self.root.destroy()

    # --------------------------------------------------------------- Actions ---

    def _on_refresh_file_list(self):
        if self.is_busy:
            return

        backup_dir = self.backup_dir_var.get().strip()
        password = self.password_var.get()
        container = self.container_var.get()

        if not backup_dir or not os.path.isdir(backup_dir):
            messagebox.showwarning("Missing Backup Folder", "Please select a valid backup folder.")
            return
        if not password:
            messagebox.showwarning("Missing Password", "Please enter the backup password.")
            return
        if container == ALL_CONTAINERS:
            messagebox.showinfo(
                "Select a Container",
                "Please select a single container from the dropdown to decrypt to a temporary file "
                "and list its contents.",
            )
            return

        self._cleanup_cached_temp()
        self._clear_file_list()
        self.cancel_event.clear()
        self.progress_bar["value"] = 0
        self.status_var.set("Decrypting to temp...")
        self._set_busy(True)
        self._append_log(f"Decrypting container '{container}' to temporary file to list entries...")

        self.worker_thread = threading.Thread(
            target=self._worker_refresh_list,
            args=(backup_dir, container, password),
            daemon=True,
        )
        self.worker_thread.start()

    def _on_start(self):
        if self.is_busy:
            return

        backup_dir = self.backup_dir_var.get().strip()
        out_dir = self.output_dir_var.get().strip()
        password = self.password_var.get()
        container = self.container_var.get()

        if not backup_dir or not os.path.isdir(backup_dir):
            messagebox.showwarning("Missing Backup Folder", "Please select a valid backup folder.")
            return
        if not out_dir:
            messagebox.showwarning("Missing Output Folder", "Please select an output folder.")
            return

        use_cached = (
            container != ALL_CONTAINERS
            and self.cached_tmp_path is not None
            and os.path.isfile(self.cached_tmp_path)
            and self.cached_backup_dir == backup_dir
            and self.cached_container == container
            and len(self.file_items) > 0
        )

        selected_names = None
        if use_cached:
            selected_names = [
                info["name"] for info in self.file_items.values() if info["checked"]
            ]
            if not selected_names:
                messagebox.showwarning(
                    "No Files Selected",
                    "Please check at least one file to extract.",
                )
                return
        else:
            if not password:
                messagebox.showwarning("Missing Password", "Please enter the backup password.")
                return

        self.cancel_event.clear()
        self.progress_bar["value"] = 0
        self.status_var.set("Starting...")
        self._set_busy(True)

        if use_cached:
            self._append_log(
                f"Extracting {len(selected_names)} selected file(s) from '{container}'..."
            )
            self.worker_thread = threading.Thread(
                target=self._worker_extract_cached,
                args=(self.cached_tmp_path, container, selected_names, out_dir),
                daemon=True,
            )
        else:
            only = None if container == ALL_CONTAINERS else container
            target_desc = "all containers" if only is None else f"container '{only}'"
            self._append_log(f"Starting decryption of {target_desc}...")
            self.worker_thread = threading.Thread(
                target=self._worker_decrypt_backup,
                args=(backup_dir, out_dir, password, only),
                daemon=True,
            )
        self.worker_thread.start()

    def _on_cancel(self):
        if not self.is_busy:
            return
        self.cancel_event.set()
        self.cancel_btn.configure(state=tk.DISABLED)
        self.status_var.set("Cancelling...")
        self._append_log("Cancellation requested. Stopping and cleaning up partial output...")

    # --------------------------------------------------------------- Workers ---

    def _make_progress_cb(self):
        def _cb(current, total, message=""):
            self.msg_queue.put(("progress", (current, total, message)))

        return _cb

    def _make_log_cb(self):
        def _cb(message):
            self.msg_queue.put(("log", str(message)))

        return _cb

    def _cleanup_partial_output(self, out_dir, out_dir_existed, created_subdirs):
        """Remove partial output directories created during a cancelled run."""
        for subdir in created_subdirs:
            if os.path.isdir(subdir):
                try:
                    shutil.rmtree(subdir, ignore_errors=True)
                except OSError:
                    pass
        if not out_dir_existed and os.path.isdir(out_dir):
            try:
                shutil.rmtree(out_dir, ignore_errors=True)
            except OSError:
                pass

    def _worker_refresh_list(self, backup_dir, container, password):
        tmp_path = None
        try:
            metadata = vivo_engine.load_metadata(backup_dir)
            key = vivo_engine.derive_keys(password, metadata)
            self.msg_queue.put(("log", "Backup key derived successfully."))

            tmp_path = vivo_engine.decrypt_container_to_temp(
                backup_dir,
                container,
                key,
                progress_cb=self._make_progress_cb(),
                cancel_event=self.cancel_event,
            )
            self.msg_queue.put(("log", f"Scanning entries in '{container}'..."))
            entries = vivo_engine.list_zip_entries(tmp_path, cancel_event=self.cancel_event)
            self.msg_queue.put(("entries", (backup_dir, container, tmp_path, entries)))
        except vivo_engine.WrongPasswordError:
            self._remove_file_quietly(tmp_path)
            self.msg_queue.put(
                ("wrong_password", "Incorrect backup password. Please check and try again.")
            )
        except vivo_engine.CancelledError:
            self._remove_file_quietly(tmp_path)
            self.msg_queue.put(("cancelled", "File list refresh cancelled."))
        except vivo_engine.InsufficientSpaceError as exc:
            self._remove_file_quietly(tmp_path)
            self.msg_queue.put(("error", str(exc)))
        except Exception as exc:
            self._remove_file_quietly(tmp_path)
            self.msg_queue.put(("error", f"Failed to list container files: {exc}"))

    def _worker_extract_cached(self, tmp_path, container, selected_names, out_dir):
        out_dir_existed = os.path.exists(out_dir)
        sub_out = os.path.join(out_dir, container)
        sub_existed = os.path.exists(sub_out)
        created_subdirs = [] if sub_existed else [sub_out]

        try:
            os.makedirs(sub_out, exist_ok=True)
            n_files, total_bytes = vivo_engine.extract_selected(
                tmp_path,
                selected_names,
                sub_out,
                progress_cb=self._make_progress_cb(),
                cancel_event=self.cancel_event,
                log_cb=self._make_log_cb(),
            )
            result = {
                "files": n_files,
                "bytes": total_bytes,
                "containers": {container: {"files": n_files, "bytes": total_bytes}},
            }
            self.msg_queue.put(("done", result))
        except vivo_engine.CancelledError:
            self._cleanup_partial_output(out_dir, out_dir_existed, created_subdirs)
            self.msg_queue.put(("cancelled", "Extraction cancelled and partial output removed."))
        except vivo_engine.InsufficientSpaceError as exc:
            self._cleanup_partial_output(out_dir, out_dir_existed, created_subdirs)
            self.msg_queue.put(("error", str(exc)))
        except Exception as exc:
            self._cleanup_partial_output(out_dir, out_dir_existed, created_subdirs)
            self.msg_queue.put(("error", f"Extraction failed: {exc}"))

    def _worker_decrypt_backup(self, backup_dir, out_dir, password, only):
        out_dir_existed = os.path.exists(out_dir)
        if only is not None:
            target_containers = [only]
        else:
            target_containers = vivo_engine.list_containers(backup_dir)

        created_subdirs = [
            os.path.join(out_dir, c)
            for c in target_containers
            if not os.path.exists(os.path.join(out_dir, c))
        ]

        try:
            result = vivo_engine.decrypt_backup(
                backup_dir,
                out_dir,
                password,
                only=only,
                selected_files=None,
                progress_cb=self._make_progress_cb(),
                cancel_event=self.cancel_event,
                log_cb=self._make_log_cb(),
            )
            self.msg_queue.put(("done", result))
        except vivo_engine.WrongPasswordError:
            self._cleanup_partial_output(out_dir, out_dir_existed, created_subdirs)
            self.msg_queue.put(
                ("wrong_password", "Incorrect backup password. Please check and try again.")
            )
        except vivo_engine.CancelledError:
            self._cleanup_partial_output(out_dir, out_dir_existed, created_subdirs)
            self.msg_queue.put(("cancelled", "Decryption cancelled and partial output removed."))
        except vivo_engine.InsufficientSpaceError as exc:
            self._cleanup_partial_output(out_dir, out_dir_existed, created_subdirs)
            self.msg_queue.put(("error", str(exc)))
        except Exception as exc:
            self._cleanup_partial_output(out_dir, out_dir_existed, created_subdirs)
            self.msg_queue.put(("error", f"Decryption failed: {exc}"))

    @staticmethod
    def _remove_file_quietly(path):
        if path and os.path.exists(path):
            try:
                os.remove(path)
            except OSError:
                pass

    # --------------------------------------------------------- Queue Polling ---

    def _poll_queue(self):
        try:
            while True:
                msg_type, payload = self.msg_queue.get_nowait()
                self._handle_message(msg_type, payload)
        except queue.Empty:
            pass
        self.root.after(100, self._poll_queue)

    def _handle_message(self, msg_type, payload):
        if msg_type == "log":
            self._append_log(payload)

        elif msg_type == "progress":
            current, total, message = payload
            if total and total > 0:
                pct = max(0.0, min(100.0, (current / total) * 100.0))
                self.progress_bar["value"] = pct
                self.status_var.set(f"{pct:.1f}% - {message}" if message else f"{pct:.1f}%")
            elif message:
                self.status_var.set(message)

        elif msg_type == "entries":
            backup_dir, container, tmp_path, entries = payload
            self.cached_backup_dir = backup_dir
            self.cached_container = container
            self.cached_tmp_path = tmp_path
            self._populate_file_list(entries)
            self.progress_bar["value"] = 100
            self.status_var.set(f"Listed {len(entries)} file(s).")
            self._append_log(
                f"Loaded {len(entries)} file(s) from '{container}'. "
                "Select files and click Start to extract."
            )
            self._set_busy(False)

        elif msg_type == "done":
            files = payload.get("files", 0)
            total_bytes = payload.get("bytes", 0)
            total_mb = total_bytes / (1024 * 1024)
            self.progress_bar["value"] = 100
            summary = f"Finished: {files} file(s), {total_mb:.2f} MB"
            self.status_var.set(summary)
            self._append_log(summary)
            self._clear_password()
            self._set_busy(False)
            messagebox.showinfo("Decryption Complete", summary)

        elif msg_type == "wrong_password":
            self.progress_bar["value"] = 0
            self.status_var.set("Wrong password.")
            self._append_log(payload)
            self._set_busy(False)
            messagebox.showerror("Wrong Password", payload)

        elif msg_type == "cancelled":
            self.progress_bar["value"] = 0
            self.status_var.set("Cancelled.")
            self._append_log(payload)
            self._set_busy(False)

        elif msg_type == "error":
            self.progress_bar["value"] = 0
            self.status_var.set("Error.")
            self._append_log(f"Error: {payload}")
            self._set_busy(False)
            messagebox.showerror("Error", payload)


def main():
    root = tk.Tk()
    VivoDecryptGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
