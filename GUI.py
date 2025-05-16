import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading
import json
import pandas as pd
import subprocess
import os
import logging
from AnalyzeData import (
    check_processes,
    check_unusual_processes,
    check_unauthorized_software,
    check_firewall_modifications,
    analyze_event_ids_from_file,
    analyze_application_logs,
    analyze_system_logs,
    analyze_scheduled_tasks,
    analyze_recent_file_changes,
    csv_to_json,
    process_connection,
    check_suspicious_startup_entries,
    systemInfo,
    hardwareInfo,
    runningProcesses,
    installedSoftware,
    userAccounts,
    USB,
    merged,
    API_KEYS,
    Gemini_Key,
    firewallModificationEvents,
    powershellLogs,
    startupEntries,
    recentFileChanges,
    applicationLogs,
    systemLogs,
    scheduledTasks,
    arp_table,
    dns_cache,
    env_vars,
    open_shares,
    loaded_dlls,
    disk_info,
    volume_info,
    smb,
    analyze_arp_table,
    analyze_dns_cache,
    analyze_environment_variables,
    analyze_open_shares,
    analyze_loaded_dlls,
    analyze_disk_info,
    analyze_volume_info,
    analyze_smb_sessions
)
from concurrent.futures import ThreadPoolExecutor, as_completed

class CybersecurityAnalyzerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("ForensieghtCybersecurity Analyzer")
        self.root.geometry("1600x1000")

        # Notebook for tabs
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        self.create_tabs()
        
        # Add PowerShell button
        self.run_ps_button = ttk.Button(self.root, text="Run PowerShell as Admin", command=self.run_powershell_as_admin)
        self.run_ps_button.pack(pady=10)
        
        # Add input fields for business hours
        self.opening_hour_var = tk.IntVar(value=1)
        self.closing_hour_var = tk.IntVar(value=24)
        self.add_hour_inputs()
        
        # Analyze button
        self.process_button = ttk.Button(self.root, text="Analyze All", command=self.run_analysis)
        self.process_button.pack(pady=10)

    def create_tabs(self):
        tabs = [
            "System Info", "Hardware Info", "Network Connections",
            "Suspicious Processes", "Unusual Processes", "Unauthorized Software",
            "USB Devices", "Suspicious Files", "Startup Entries",
            "Firewall Modifications", "Recent File Changes", 
            "Security Logs", "Application Logs", "System Logs", "Scheduled Tasks",
            "ARP Table", "DNS Cache", "Environment Variables", "Open Shares", "Loaded DLLs",
            "Disk Info", "Volume Info", "SMB Sessions"
        ]
        self.text_widgets = {}
        self.search_entries = {}
        self.tables = {}
        
        for tab_name in tabs:
            frame = ttk.Frame(self.notebook)
            self.notebook.add(frame, text=tab_name)
            search_frame = ttk.Frame(frame)
            search_frame.pack(fill=tk.X)
            search_label = ttk.Label(search_frame, text=f"Search in {tab_name}:")
            search_label.pack(side=tk.LEFT, padx=5)
            search_entry = ttk.Entry(search_frame, width=30)
            search_entry.pack(side=tk.LEFT, padx=5)
            search_button = ttk.Button(search_frame, text="Search", command=lambda t=tab_name, e=search_entry: self.search_tab(t, e))
            search_button.pack(side=tk.LEFT, padx=5)
            self.search_entries[tab_name] = search_entry
            
            text_widget = scrolledtext.ScrolledText(frame, wrap=tk.WORD, font=("Courier", 10))
            text_widget.pack(fill=tk.BOTH, expand=True)
            self.text_widgets[tab_name] = text_widget

    def add_hour_inputs(self):
        frame = ttk.Frame(self.root)
        frame.pack(pady=10)
        ttk.Label(frame, text="Opening Hour:").grid(row=0, column=0, padx=5)
        ttk.Entry(frame, textvariable=self.opening_hour_var, width=5).grid(row=0, column=1, padx=5)
        ttk.Label(frame, text="Closing Hour:").grid(row=0, column=2, padx=5)
        ttk.Entry(frame, textvariable=self.closing_hour_var, width=5).grid(row=0, column=3, padx=5)
        
    def run_powershell_as_admin(self):
        try:
            script_path = os.path.abspath("CollectData.ps1")
            command = f"powershell -ExecutionPolicy Bypass -File \"{script_path}\""
            subprocess.run(["powershell", "Start-Process", "powershell", "-ArgumentList", f"'{command}'", "-Verb", "RunAs"])
            messagebox.showinfo("PowerShell", "PowerShell script is running as administrator.")
        except Exception as e:
            messagebox.showerror("Error", f"Error running PowerShell script as admin: {e}")
            
    def run_analysis(self):
        opening_hour = self.opening_hour_var.get()
        closing_hour = self.closing_hour_var.get()
        threading.Thread(target=self.analyze_all, args=(opening_hour, closing_hour)).start()


    def analyze_all(self,opening_hour, closing_hour):
        try:
            
            # System and Hardware Info as tables
            self.display_dict_as_table("System Info", systemInfo.iloc[0].to_dict() if not systemInfo.empty else {})
            self.display_dict_as_table("Hardware Info", hardwareInfo.iloc[0].to_dict() if not hardwareInfo.empty else {})
            
            # Network Connections as threaded analysis
            connections_list = merged.to_dict(orient='records')
            networkresults = []
            with ThreadPoolExecutor(max_workers=len(API_KEYS)) as executor:
                futures = {
                    executor.submit(process_connection, conn, API_KEYS[i % len(API_KEYS)]): conn
                    for i, conn in enumerate(connections_list)
                }
                for future in as_completed(futures):
                    try:
                        result = future.result()
                        if result:
                            networkresults.append(result)
                    except Exception as e:
                        logging.warning(f"Connection analysis error: {e}")
            self.display_list_of_dicts_as_table("Network Connections", networkresults)
            self.display_list_of_dicts_as_table("Suspicious Processes", check_processes(runningProcesses))
            self.display_list_of_dicts_as_table("Unusual Processes", check_unusual_processes(runningProcesses))
            self.display_list_of_dicts_as_table("Unauthorized Software", check_unauthorized_software(installedSoftware, userAccounts, opening_hour, closing_hour))
            self.display_list_of_dicts_as_table("USB Devices", [USB.iloc[i].to_dict() for i in range(len(USB))])
            self.display_list_of_dicts_as_table("Suspicious Files", csv_to_json().get('files', []))
            self.display_list_of_dicts_as_table("Startup Entries", check_suspicious_startup_entries(startupEntries, Gemini_Key, max_workers=10))
            self.display_list_of_dicts_as_table("Recent File Changes", analyze_recent_file_changes(recentFileChanges))
            self.display_list_of_dicts_as_table("Firewall Modifications", check_firewall_modifications(firewallModificationEvents, Gemini_Key, max_workers=10)) 
            self.display_list_of_dicts_as_table("ARP Table", analyze_arp_table(arp_table))
            self.display_list_of_dicts_as_table("DNS Cache", analyze_dns_cache(dns_cache))
            self.display_list_of_dicts_as_table("Environment Variables", analyze_environment_variables(env_vars))
            self.display_list_of_dicts_as_table("Open Shares", analyze_open_shares(open_shares))
            self.display_list_of_dicts_as_table("Loaded DLLs", analyze_loaded_dlls(loaded_dlls))
            self.display_list_of_dicts_as_table("Disk Info", analyze_disk_info(disk_info))
            self.display_list_of_dicts_as_table("Volume Info", analyze_volume_info(volume_info))
            self.display_list_of_dicts_as_table("SMB Sessions", analyze_smb_sessions(smb))
            self.display_security_logs()
            self.display_application_logs()
            self.display_system_logs()
            self.display_list_of_dicts_as_table("Scheduled Tasks", analyze_scheduled_tasks(scheduledTasks))
            messagebox.showinfo("Analysis", "Analysis completed successfully.")
        except Exception as e:
            logging.error(f"Error during analysis: {e}")
            messagebox.showerror("Error", f"Error during analysis: {e}")

    def display_security_logs(self):
        try:
            security_logs = analyze_event_ids_from_file(Gemini_Key)
            self.display_json_as_text("Security Logs", security_logs)
        except Exception as e:
            logging.error(f"Error processing security logs: {e}")
            messagebox.showerror("Error", f"Error processing security logs: {e}")

    def display_application_logs(self):
        try:
            app_logs = analyze_application_logs(Gemini_Key)
            self.display_json_as_text("Application Logs", app_logs)
        except Exception as e:
            logging.error(f"Error processing application logs: {e}")
            messagebox.showerror("Error", f"Error processing application logs: {e}")

    def display_system_logs(self):
        try:
            sys_logs = analyze_system_logs(Gemini_Key)
            self.display_json_as_text("System Logs", sys_logs)
        except Exception as e:
            logging.error(f"Error processing system logs: {e}")
            messagebox.showerror("Error", f"Error processing system logs: {e}")

    def display_json_as_text(self, tab_name, data_list):
        text_widget = self.text_widgets.get(tab_name)
        if text_widget:
            text_widget.delete(1.0, tk.END)
            formatted_json = json.dumps(data_list[8:], indent=4)
            text_widget.insert(tk.END, f"\n{formatted_json}\n")
    

    def display_dict_as_table(self, tab_name, data_dict):
        text_widget = self.text_widgets.get(tab_name)
        if text_widget:
            text_widget.delete(1.0, tk.END)
            if data_dict:
                max_key_len = max(len(key) for key in data_dict.keys())
                for key, value in data_dict.items():
                    text_widget.insert(tk.END, f"{key:<{max_key_len}} : {value}\n")
            else:
                text_widget.insert(tk.END, "No data available.\n")

    def display_list_of_dicts_as_table(self, tab_name, data_list):
        frame = self.text_widgets.get(tab_name)
        if frame:
            for widget in frame.winfo_children():
                widget.destroy()
            
            if data_list:
                # Create a Treeview table
                table = ttk.Treeview(frame, show="headings")
                headers = list(data_list[0].keys())
                table['columns'] = headers
                for col in headers:
                    table.heading(col, text=col, command=lambda c=col: self.sort_table(table, c, False))
                    table.column(col, width=150, anchor=tk.W)
                for row in data_list:
                    values = [str(row.get(col, '')) for col in headers]
                    row_id = table.insert('', 'end', values=values)
                    # Add double-click event
                    table.bind("<Double-1>", lambda e, t=table: self.show_row_details(t))
                table.pack(fill=tk.BOTH, expand=True)
                self.tables[tab_name] = table
            else:
                label = tk.Label(frame, text="No data available.", font=("Arial", 12))
                label.pack(pady=10)
        
    def show_row_details(self, table):
        selected_item = table.focus()
        if selected_item:
            row_data = table.item(selected_item)['values']
            headers = table['columns']
            detail_window = tk.Toplevel(self.root)
            detail_window.title("Row Details")
            detail_window.geometry("800x600")
            
            # Scrollable Frame for Row Details
            canvas = tk.Canvas(detail_window)
            scrollbar = ttk.Scrollbar(detail_window, orient="vertical", command=canvas.yview)
            scrollable_frame = ttk.Frame(canvas)
            scrollable_frame.bind(
                "<Configure>",
                lambda e: canvas.configure(
                    scrollregion=canvas.bbox("all")
                )
            )
            canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
            canvas.configure(yscrollcommand=scrollbar.set)
            canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
            scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
            
            all_text = ""
            for header, value in zip(headers, row_data):
                label = ttk.Label(scrollable_frame, text=f"{header}:", font=("Arial", 10, "bold"))
                label.pack(anchor=tk.W)
                text_widget = scrolledtext.ScrolledText(scrollable_frame, wrap=tk.WORD, font=("Courier", 10), height=4)
                text_widget.insert(tk.END, value)
                text_widget.config(state=tk.DISABLED)
                text_widget.pack(fill=tk.BOTH, expand=True, pady=5)
                all_text += f"{header}: {value}\n\n"
            
            # Add copy button
            copy_button = ttk.Button(scrollable_frame, text="Copy All", command=lambda: self.copy_to_clipboard(all_text))
            copy_button.pack(pady=10)

    def copy_to_clipboard(self, text):
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        messagebox.showinfo("Copied", "Row details copied to clipboard.")
                
    def search_tab(self, tab_name, entry_widget):
        search_term = entry_widget.get().strip().lower()
        if not search_term:
            messagebox.showwarning("Search", "Please enter a search term.")
            return
        
        # Handle Treeview tables
        if tab_name in self.tables:
            table = self.tables[tab_name]
            for item in table.get_children():
                values = [str(table.set(item, col)).lower() for col in table['columns']]
                if any(search_term in val for val in values):
                    table.see(item)
                    table.selection_add(item)
                else:
                    table.selection_remove(item)
            return
        
        # Handle ScrolledText widgets (plain text tabs)
        text_widget = self.text_widgets.get(tab_name)
        if text_widget:
            content = text_widget.get("1.0", tk.END).lower()
            lines = content.splitlines()
            results = [line for line in lines if search_term in line]
            if results:
                text_widget.delete("1.0", tk.END)
                text_widget.insert(tk.END, "\n".join(results))
            else:
                messagebox.showinfo("Search", f"No matches found for '{search_term}' in {tab_name}.")
                
    def sort_table(self, table, col, data_list, reverse=False):
        # Sort the data list
        sorted_list = sorted(data_list, key=lambda x: str(x.get(col, '')).lower(), reverse=reverse)
    
        # Clear the existing rows
        for row in table.get_children():
            table.delete(row)
        
        # Insert the sorted data
        for row in sorted_list:
            values = [str(row.get(c, '')) for c in table['columns']]
            table.insert('', 'end', values=values)
    
        # Toggle the sort order for the next click
        table.heading(col, command=lambda: self.sort_table(table, col, sorted_list, not reverse))

if __name__ == "__main__":
    root = tk.Tk()
    app = CybersecurityAnalyzerApp(root)
    root.mainloop()
