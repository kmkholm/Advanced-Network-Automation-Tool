#!/usr/bin/env python3
"""
Advanced Network Automation Tool
Version: 2.4 Final
Author: Dr. Mohammed Tawfik (kmkhol01@gmail.com)
Description: Comprehensive GUI-based network automation and monitoring tool
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog, scrolledtext
import threading
import socket
import subprocess
import time
import os
import sys
import json
import csv
import re
import ipaddress
import concurrent.futures
from datetime import datetime
import logging

try:
    import paramiko
    PARAMIKO_AVAILABLE = True
except ImportError:
    PARAMIKO_AVAILABLE = False

class NetworkAutomationTool:
    def __init__(self, root):
        """Initialize the network automation tool"""
        self.root = root
        self.root.title("Advanced Network Automation Tool v2.4 Final - Dr. Mohammed Tawfik")
        self.root.geometry("1200x800")
        self.root.minsize(1000, 700)
        
        # Initialize variables
        self.scan_thread = None
        self.port_scan_thread = None
        self.ping_monitor_thread = None
        self.ssh_thread = None
        self.backup_thread = None
        self.snmp_thread = None
        self.network_tool_thread = None
        
        self.scanning = False
        self.port_scanning = False
        self.monitoring = False
        self.ssh_connected = False
        self.backup_running = False
        self.snmp_running = False
        self.tool_running = False
        
        # Initialize data storage
        self.devices = {}
        self.scan_results = []
        self.port_scan_results = []
        self.ping_results = []
        
        # Configure logging
        self.setup_logging()
        
        # Create main interface
        self.create_menu()
        self.create_main_interface()
        self.load_settings()
        
        # Log startup
        self.log_message("Network Automation Tool v2.4 Final started successfully")
    
    def setup_logging(self):
        """Setup logging configuration"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('network_tool.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
    
    def log_message(self, message):
        """Log a message"""
        if hasattr(self, 'logger'):
            self.logger.info(message)
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {message}")
    
    def create_menu(self):
        """Create application menu"""
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)
        
        # File menu
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Export Scan Results", command=self.export_scan_results)
        file_menu.add_command(label="Export Port Results", command=self.export_port_results)
        file_menu.add_command(label="Import Device List", command=self.import_device_list)
        file_menu.add_command(label="Export Device List", command=self.export_device_list)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)
        
        # Tools menu
        tools_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Tools", menu=tools_menu)
        tools_menu.add_command(label="Network Calculator", command=self.show_network_calculator)
        tools_menu.add_command(label="Subnet Calculator", command=self.show_subnet_calculator)
        tools_menu.add_command(label="MAC Address Lookup", command=self.show_mac_lookup)
        
        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="About", command=self.show_about)
        help_menu.add_command(label="Documentation", command=self.show_documentation)
    
    def create_main_interface(self):
        """Create main tabbed interface"""
        # Create notebook for tabs
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill='both', expand=True, padx=5, pady=5)
        
        # Create all tabs
        self.create_network_scanner_tab()
        self.create_port_scanner_tab()
        self.create_ping_monitor_tab()
        self.create_ssh_automation_tab()
        self.create_config_backup_tab()
        self.create_snmp_monitor_tab()
        self.create_network_tools_tab()
        self.create_device_inventory_tab()
        self.create_settings_tab()
    
    def create_network_scanner_tab(self):
        """Create network scanner tab"""
        scanner_frame = ttk.Frame(self.notebook)
        self.notebook.add(scanner_frame, text="Network Scanner")
        
        # Controls frame
        controls_frame = ttk.LabelFrame(scanner_frame, text="Scan Configuration", padding=15)
        controls_frame.pack(fill='x', padx=10, pady=5)
        
        # IP Range
        ttk.Label(controls_frame, text="IP Range:").grid(row=0, column=0, sticky='w', padx=5)
        self.scanner_ip_range = ttk.Entry(controls_frame, width=25)
        self.scanner_ip_range.grid(row=0, column=1, padx=5, pady=2)
        self.scanner_ip_range.insert(0, "192.168.1.0/24")
        
        # Threads
        ttk.Label(controls_frame, text="Threads:").grid(row=0, column=2, sticky='w', padx=15)
        self.scanner_threads = ttk.Spinbox(controls_frame, from_=1, to=50, width=10)
        self.scanner_threads.grid(row=0, column=3, padx=5, pady=2)
        self.scanner_threads.set("10")
        
        # Timeout
        ttk.Label(controls_frame, text="Timeout (ms):").grid(row=1, column=0, sticky='w', padx=5)
        self.scanner_timeout = ttk.Spinbox(controls_frame, from_=100, to=5000, increment=100, width=15)
        self.scanner_timeout.grid(row=1, column=1, padx=5, pady=2)
        self.scanner_timeout.set("1000")
        
        # Buttons
        btn_frame = ttk.Frame(controls_frame)
        btn_frame.grid(row=1, column=2, columnspan=2, pady=10)
        
        self.scan_btn = ttk.Button(btn_frame, text="Start Scan", command=self.start_network_scan)
        self.scan_btn.pack(side='left', padx=5)
        
        ttk.Button(btn_frame, text="Stop", command=self.stop_network_scan).pack(side='left', padx=5)
        ttk.Button(btn_frame, text="Clear", command=self.clear_scan_results).pack(side='left', padx=5)
        ttk.Button(btn_frame, text="Export", command=self.export_scan_results).pack(side='left', padx=5)
        
        # Progress bar
        self.scan_progress = ttk.Progressbar(controls_frame, mode='determinate')
        self.scan_progress.grid(row=2, column=0, columnspan=4, sticky='ew', padx=5, pady=5)
        
        # Results
        results_frame = ttk.LabelFrame(scanner_frame, text="Scan Results", padding=5)
        results_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        # Treeview for results
        columns = ("IP Address", "Hostname", "Status", "Response Time", "MAC Address", "Vendor")
        self.scan_tree = ttk.Treeview(results_frame, columns=columns, show='tree headings', height=12)
        
        for col in columns:
            self.scan_tree.heading(col, text=col)
            self.scan_tree.column(col, width=150)
        
        scan_scrollbar = ttk.Scrollbar(results_frame, orient='vertical', command=self.scan_tree.yview)
        self.scan_tree.config(yscrollcommand=scan_scrollbar.set)
        
        self.scan_tree.pack(side='left', fill='both', expand=True)
        scan_scrollbar.pack(side='right', fill='y')
        
        # Bind double-click
        self.scan_tree.bind('<Double-1>', lambda e: self.show_host_details())
    
    def create_port_scanner_tab(self):
        """Create port scanner tab"""
        port_frame = ttk.Frame(self.notebook)
        self.notebook.add(port_frame, text="Port Scanner")
        
        # Controls
        controls_frame = ttk.LabelFrame(port_frame, text="Port Scan Configuration", padding=15)
        controls_frame.pack(fill='x', padx=10, pady=5)
        
        # Target
        ttk.Label(controls_frame, text="Target:").grid(row=0, column=0, sticky='w', padx=5)
        self.port_target = ttk.Entry(controls_frame, width=25)
        self.port_target.grid(row=0, column=1, padx=5, pady=2)
        
        # Port range
        ttk.Label(controls_frame, text="Port Range:").grid(row=0, column=2, sticky='w', padx=15)
        self.port_range = ttk.Entry(controls_frame, width=15)
        self.port_range.grid(row=0, column=3, padx=5, pady=2)
        self.port_range.insert(0, "1-1000")
        
        # Scan type
        ttk.Label(controls_frame, text="Scan Type:").grid(row=1, column=0, sticky='w', padx=5)
        self.scan_type = ttk.Combobox(controls_frame, values=["TCP Connect", "TCP SYN"], width=15)
        self.scan_type.grid(row=1, column=1, padx=5, pady=2)
        self.scan_type.set("TCP Connect")
        
        # Buttons
        btn_frame = ttk.Frame(controls_frame)
        btn_frame.grid(row=1, column=2, columnspan=2, pady=10)
        
        ttk.Button(btn_frame, text="Start Scan", command=self.start_port_scan).pack(side='left', padx=5)
        ttk.Button(btn_frame, text="Stop", command=self.stop_port_scan).pack(side='left', padx=5)
        ttk.Button(btn_frame, text="Clear", command=self.clear_port_results).pack(side='left', padx=5)
        ttk.Button(btn_frame, text="Export", command=self.export_port_results).pack(side='left', padx=5)
        
        # Progress
        self.port_progress = ttk.Progressbar(controls_frame, mode='determinate')
        self.port_progress.grid(row=2, column=0, columnspan=4, sticky='ew', padx=5, pady=5)
        
        # Quick scan buttons
        quick_frame = ttk.LabelFrame(port_frame, text="Quick Scans", padding=10)
        quick_frame.pack(fill='x', padx=10, pady=5)
        
        common_ports = [
            ("Web Ports", "80,443"),
            ("Mail Ports", "25,110,143,993,995"),
            ("SSH/FTP", "21,22"),
            ("Database", "3306,5432,1433"),
            ("All Common", "21,22,23,25,53,80,110,143,443,993,995,3306,5432,3389")
        ]
        
        for i, (name, ports) in enumerate(common_ports):
            col = i % 5
            row = i // 5
            ttk.Button(quick_frame, text=name, 
                      command=lambda p=ports: self.port_range.insert(0, p)).grid(
                row=row, column=col, padx=5, pady=2)
        
        # Results
        results_frame = ttk.LabelFrame(port_frame, text="Port Scan Results", padding=5)
        results_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        columns = ("Port", "Protocol", "Status", "Service", "Banner")
        self.port_tree = ttk.Treeview(results_frame, columns=columns, show='tree headings', height=12)
        
        for col in columns:
            self.port_tree.heading(col, text=col)
            self.port_tree.column(col, width=120)
        
        port_scrollbar = ttk.Scrollbar(results_frame, orient='vertical', command=self.port_tree.yview)
        self.port_tree.config(yscrollcommand=port_scrollbar.set)
        
        self.port_tree.pack(side='left', fill='both', expand=True)
        port_scrollbar.pack(side='right', fill='y')
    
    def create_ping_monitor_tab(self):
        """Create ping monitor tab"""
        monitor_frame = ttk.Frame(self.notebook)
        self.notebook.add(monitor_frame, text="Ping Monitor")
        
        # Controls
        controls_frame = ttk.LabelFrame(monitor_frame, text="Monitor Configuration", padding=15)
        controls_frame.pack(fill='x', padx=10, pady=5)
        
        # Target
        ttk.Label(controls_frame, text="Target:").grid(row=0, column=0, sticky='w', padx=5)
        self.monitor_target = ttk.Entry(controls_frame, width=25)
        self.monitor_target.grid(row=0, column=1, padx=5, pady=2)
        
        # Interval
        ttk.Label(controls_frame, text="Interval (sec):").grid(row=0, column=2, sticky='w', padx=15)
        self.monitor_interval = ttk.Spinbox(controls_frame, from_=1, to=60, width=10)
        self.monitor_interval.grid(row=0, column=3, padx=5, pady=2)
        self.monitor_interval.set("5")
        
        # Timeout
        ttk.Label(controls_frame, text="Timeout (sec):").grid(row=1, column=0, sticky='w', padx=5)
        self.monitor_timeout = ttk.Spinbox(controls_frame, from_=1, to=30, width=10)
        self.monitor_timeout.grid(row=1, column=1, padx=5, pady=2)
        self.monitor_timeout.set("5")
        
        # Buttons
        btn_frame = ttk.Frame(controls_frame)
        btn_frame.grid(row=1, column=2, columnspan=2, pady=10)
        
        ttk.Button(btn_frame, text="Start Monitor", command=self.start_ping_monitor).pack(side='left', padx=5)
        ttk.Button(btn_frame, text="Stop Monitor", command=self.stop_ping_monitor).pack(side='left', padx=5)
        ttk.Button(btn_frame, text="Clear", command=self.clear_ping_results).pack(side='left', padx=5)
        ttk.Button(btn_frame, text="Export", command=self.export_ping_results).pack(side='left', padx=5)
        
        # Statistics
        stats_frame = ttk.LabelFrame(monitor_frame, text="Statistics", padding=10)
        stats_frame.pack(fill='x', padx=10, pady=5)
        
        self.stats_labels = {}
        stats_items = [
            ("Sent:", "sent"),
            ("Received:", "received"),
            ("Lost:", "lost"),
            ("Success Rate:", "success_rate"),
            ("Avg Latency:", "avg_latency"),
            ("Min Latency:", "min_latency"),
            ("Max Latency:", "max_latency")
        ]
        
        for i, (label, key) in enumerate(stats_items):
            col = i % 4
            row = i // 4
            ttk.Label(stats_frame, text=label).grid(row=row, column=col*2, sticky='w', padx=5, pady=2)
            self.stats_labels[key] = ttk.Label(stats_frame, text="0", relief='sunken')
            self.stats_labels[key].grid(row=row, column=col*2+1, sticky='ew', padx=5, pady=2)
        
        # Results
        results_frame = ttk.LabelFrame(monitor_frame, text="Ping Results", padding=5)
        results_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        self.ping_results_text = scrolledtext.ScrolledText(results_frame, height=15, wrap='word')
        self.ping_results_text.pack(fill='both', expand=True)
    
    def create_ssh_automation_tab(self):
        """Create SSH automation tab"""
        ssh_frame = ttk.Frame(self.notebook)
        self.notebook.add(ssh_frame, text="SSH Automation")
        
        # Connection settings
        conn_frame = ttk.LabelFrame(ssh_frame, text="Connection Settings", padding=15)
        conn_frame.pack(fill='x', padx=10, pady=5)
        
        # Host
        ttk.Label(conn_frame, text="Host:").grid(row=0, column=0, sticky='w', padx=5)
        self.ssh_host = ttk.Entry(conn_frame, width=20)
        self.ssh_host.grid(row=0, column=1, padx=5, pady=2)
        
        # Port
        ttk.Label(conn_frame, text="Port:").grid(row=0, column=2, sticky='w', padx=15)
        self.ssh_port = ttk.Entry(conn_frame, width=10)
        self.ssh_port.grid(row=0, column=3, padx=5, pady=2)
        self.ssh_port.insert(0, "22")
        
        # Username
        ttk.Label(conn_frame, text="Username:").grid(row=1, column=0, sticky='w', padx=5)
        self.ssh_username = ttk.Entry(conn_frame, width=20)
        self.ssh_username.grid(row=1, column=1, padx=5, pady=2)
        
        # Password/Key
        ttk.Label(conn_frame, text="Password/Key:").grid(row=1, column=2, sticky='w', padx=15)
        self.ssh_password = ttk.Entry(conn_frame, width=20, show='*')
        self.ssh_password.grid(row=1, column=3, padx=5, pady=2)
        
        # Buttons
        btn_frame = ttk.Frame(conn_frame)
        btn_frame.grid(row=2, column=0, columnspan=4, pady=10)
        
        ttk.Button(btn_frame, text="Connect", command=self.connect_ssh).pack(side='left', padx=5)
        ttk.Button(btn_frame, text="Disconnect", command=self.disconnect_ssh).pack(side='left', padx=5)
        
        # Status
        self.ssh_status = ttk.Label(conn_frame, text="Disconnected", foreground='red')
        self.ssh_status.grid(row=3, column=0, columnspan=4, pady=5)
        
        # Command execution
        cmd_frame = ttk.LabelFrame(ssh_frame, text="Command Execution", padding=15)
        cmd_frame.pack(fill='x', padx=10, pady=5)
        
        ttk.Label(cmd_frame, text="Command:").pack(anchor='w')
        self.ssh_command = ttk.Entry(cmd_frame, width=50)
        self.ssh_command.pack(fill='x', pady=2)
        
        cmd_btn_frame = ttk.Frame(cmd_frame)
        cmd_btn_frame.pack(fill='x', pady=5)
        
        ttk.Button(cmd_btn_frame, text="Execute", command=self.execute_ssh_command).pack(side='left', padx=5)
        ttk.Button(cmd_btn_frame, text="Execute on Multiple", command=self.execute_on_multiple).pack(side='left', padx=5)
        
        # Script execution
        script_frame = ttk.LabelFrame(ssh_frame, text="Script Execution", padding=15)
        script_frame.pack(fill='x', padx=10, pady=5)
        
        ttk.Button(script_frame, text="Load Script", command=self.load_script).pack(side='left', padx=5)
        ttk.Button(script_frame, text="Run Script", command=self.run_script).pack(side='left', padx=5)
        
        # Results
        results_frame = ttk.LabelFrame(ssh_frame, text="SSH Results", padding=5)
        results_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        self.ssh_results = scrolledtext.ScrolledText(results_frame, height=15, wrap='word')
        self.ssh_results.pack(fill='both', expand=True)
    
    def create_config_backup_tab(self):
        """Create configuration backup tab"""
        backup_frame = ttk.Frame(self.notebook)
        self.notebook.add(backup_frame, text="Config Backup")
        
        # Device list
        devices_frame = ttk.LabelFrame(backup_frame, text="Device List", padding=15)
        devices_frame.pack(fill='x', padx=10, pady=5)
        
        # Add device controls
        add_frame = ttk.Frame(devices_frame)
        add_frame.pack(fill='x', pady=5)
        
        ttk.Label(add_frame, text="IP/Hostname:").pack(side='left')
        self.backup_device_ip = ttk.Entry(add_frame, width=20)
        self.backup_device_ip.pack(side='left', padx=5)
        
        ttk.Label(add_frame, text="Username:").pack(side='left')
        self.backup_device_user = ttk.Entry(add_frame, width=15)
        self.backup_device_user.pack(side='left', padx=5)
        
        ttk.Label(add_frame, text="Password:").pack(side='left')
        self.backup_device_pass = ttk.Entry(add_frame, width=15, show='*')
        self.backup_device_pass.pack(side='left', padx=5)
        
        ttk.Button(add_frame, text="Add Device", command=self.add_backup_device).pack(side='left', padx=5)
        
        # Device tree
        columns = ("IP/Hostname", "Username", "Status", "Last Backup", "Backup Path")
        self.backup_tree = ttk.Treeview(devices_frame, columns=columns, show='tree headings', height=8)
        
        for col in columns:
            self.backup_tree.heading(col, text=col)
            self.backup_tree.column(col, width=150)
        
        backup_scrollbar = ttk.Scrollbar(devices_frame, orient='vertical', command=self.backup_tree.yview)
        self.backup_tree.config(yscrollcommand=backup_scrollbar.set)
        
        self.backup_tree.pack(side='left', fill='both', expand=True)
        backup_scrollbar.pack(side='right', fill='y')
        
        # Backup controls
        control_frame = ttk.LabelFrame(backup_frame, text="Backup Controls", padding=15)
        control_frame.pack(fill='x', padx=10, pady=5)
        
        ttk.Button(control_frame, text="Start Backup", command=self.start_config_backup).pack(side='left', padx=5)
        ttk.Button(control_frame, text="Stop Backup", command=self.stop_config_backup).pack(side='left', padx=5)
        ttk.Button(control_frame, text="Schedule Backup", command=self.schedule_backup).pack(side='left', padx=5)
        
        # Backup settings
        settings_frame = ttk.LabelFrame(backup_frame, text="Backup Settings", padding=15)
        settings_frame.pack(fill='x', padx=10, pady=5)
        
        ttk.Label(settings_frame, text="Backup Directory:").grid(row=0, column=0, sticky='w', padx=5)
        self.backup_dir = ttk.Entry(settings_frame, width=30)
        self.backup_dir.grid(row=0, column=1, padx=5, pady=2)
        self.backup_dir.insert(0, "./backups")
        
        ttk.Button(settings_frame, text="Browse", command=self.browse_backup_dir).grid(row=0, column=2, padx=5)
        
        ttk.Label(settings_frame, text="Backup Format:").grid(row=1, column=0, sticky='w', padx=5, pady=(5,0))
        self.backup_format = ttk.Combobox(settings_frame, values=["TXT", "JSON", "Both"], width=15)
        self.backup_format.grid(row=1, column=1, padx=5, pady=(5,2))
        self.backup_format.set("Both")
    
    def create_snmp_monitor_tab(self):
        """Create SNMP monitor tab"""
        snmp_frame = ttk.Frame(self.notebook)
        self.notebook.add(snmp_frame, text="SNMP Monitor")
        
        # Settings frame
        settings_frame = ttk.LabelFrame(snmp_frame, text="SNMP Settings", padding=15)
        settings_frame.pack(fill='x', padx=10, pady=5)
        
        # SNMP inputs
        ttk.Label(settings_frame, text="Target:").grid(row=0, column=0, sticky='w', padx=5)
        self.snmp_target = ttk.Entry(settings_frame, width=20)
        self.snmp_target.grid(row=0, column=1, padx=5, pady=2)
        
        ttk.Label(settings_frame, text="Community:").grid(row=0, column=2, sticky='w', padx=15)
        self.snmp_community = ttk.Entry(settings_frame, width=15)
        self.snmp_community.grid(row=0, column=3, padx=5, pady=2)
        self.snmp_community.insert(0, "public")
        
        ttk.Label(settings_frame, text="Version:").grid(row=1, column=0, sticky='w', padx=5)
        self.snmp_version = ttk.Combobox(settings_frame, values=["1", "2c", "3"], width=10)
        self.snmp_version.grid(row=1, column=1, padx=5, pady=2)
        self.snmp_version.set("2c")
        
        ttk.Label(settings_frame, text="OID:").grid(row=1, column=2, sticky='w', padx=15)
        self.snmp_oid = ttk.Entry(settings_frame, width=25)
        self.snmp_oid.grid(row=1, column=3, padx=5, pady=2)
        self.snmp_oid.insert(0, "1.3.6.1.2.1.1.1.0")
        
        # Buttons
        btn_frame = ttk.Frame(settings_frame)
        btn_frame.grid(row=2, column=0, columnspan=4, pady=10)
        
        ttk.Button(btn_frame, text="Get Value", command=self.snmp_get_value).pack(side='left', padx=5)
        ttk.Button(btn_frame, text="Walk OIDs", command=self.snmp_walk).pack(side='left', padx=5)
        ttk.Button(btn_frame, text="Bulk Walk", command=self.snmp_bulk_walk).pack(side='left', padx=5)
        ttk.Button(btn_frame, text="Monitor", command=self.start_snmp_monitor).pack(side='left', padx=5)
        
        # MIB browser
        mib_frame = ttk.LabelFrame(snmp_frame, text="Common OIDs", padding=10)
        mib_frame.pack(fill='x', padx=10, pady=5)
        
        common_oids = [
            ("System Description", "1.3.6.1.2.1.1.1.0"),
            ("System Uptime", "1.3.6.1.2.1.1.3.0"),
            ("Interface Count", "1.3.6.1.2.1.2.1.0"),
            ("CPU Usage", "1.3.6.1.4.1.2021.11.9.0"),
            ("Memory Usage", "1.3.6.1.4.1.2021.4.5.0")
        ]
        
        for i, (name, oid) in enumerate(common_oids):
            btn = ttk.Button(mib_frame, text=name, 
                           command=lambda o=oid: self.snmp_oid.insert(0, o))
            btn.grid(row=0, column=i, padx=3, pady=2)
        
        # Results
        results_frame = ttk.LabelFrame(snmp_frame, text="SNMP Results", padding=5)
        results_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        self.snmp_results = tk.Text(results_frame, height=15, wrap='word')
        snmp_scrollbar = ttk.Scrollbar(results_frame, orient='vertical', command=self.snmp_results.yview)
        self.snmp_results.config(yscrollcommand=snmp_scrollbar.set)
        
        self.snmp_results.pack(side='left', fill='both', expand=True)
        snmp_scrollbar.pack(side='right', fill='y')
    
    def create_network_tools_tab(self):
        """Create network tools tab"""
        tools_frame = ttk.Frame(self.notebook)
        self.notebook.add(tools_frame, text="Network Tools")
        
        # Tools selection
        tools_select_frame = ttk.LabelFrame(tools_frame, text="Tool Selection", padding=15)
        tools_select_frame.pack(fill='x', padx=10, pady=5)
        
        self.tool_var = tk.StringVar(value="traceroute")
        
        tools = [("Traceroute", "traceroute"), ("DNS Lookup", "dns"), 
                ("Whois Lookup", "whois"), ("Bandwidth Test", "bandwidth")]
        
        for text, value in tools:
            ttk.Radiobutton(tools_select_frame, text=text, variable=self.tool_var, 
                          value=value).pack(side='left', padx=10)
        
        # Input frame
        input_frame = ttk.LabelFrame(tools_frame, text="Tool Configuration", padding=15)
        input_frame.pack(fill='x', padx=10, pady=5)
        
        # Target input
        ttk.Label(input_frame, text="Target:").grid(row=0, column=0, sticky='w', padx=5)
        self.tool_target = ttk.Entry(input_frame, width=30)
        self.tool_target.grid(row=0, column=1, padx=5, pady=2)
        
        # Additional options based on tool
        self.tool_options_frame = ttk.Frame(input_frame)
        self.tool_options_frame.grid(row=1, column=0, columnspan=2, pady=10)
        
        # Traceroute options
        self.traceroute_max_hops = ttk.Spinbox(self.tool_options_frame, from_=1, to=30, width=10)
        self.traceroute_max_hops.set("30")
        traceroute_frame = ttk.Frame(self.tool_options_frame)
        traceroute_frame.pack(anchor='w')
        ttk.Label(traceroute_frame, text="Max Hops:").pack(side='left')
        self.traceroute_max_hops.pack(side='left', padx=5)
        
        # DNS options
        self.dns_record_type = ttk.Combobox(self.tool_options_frame, values=["A", "AAAA", "MX", "NS", "CNAME", "TXT"], width=10)
        self.dns_record_type.set("A")
        
        # Bandwidth test options
        self.bandwidth_test_server = ttk.Entry(self.tool_options_frame, width=20)
        self.bandwidth_test_server.insert(0, "8.8.8.8")
        
        # Buttons
        btn_frame = ttk.Frame(input_frame)
        btn_frame.grid(row=2, column=0, columnspan=2, pady=10)
        
        ttk.Button(btn_frame, text="Run Tool", command=self.run_network_tool).pack(side='left', padx=5)
        ttk.Button(btn_frame, text="Stop", command=self.stop_network_tool).pack(side='left', padx=5)
        
        # Results
        results_frame = ttk.LabelFrame(tools_frame, text="Tool Results", padding=5)
        results_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        self.tool_results = tk.Text(results_frame, height=15, wrap='word')
        tool_scrollbar = ttk.Scrollbar(results_frame, orient='vertical', command=self.tool_results.yview)
        self.tool_results.config(yscrollcommand=tool_scrollbar.set)
        
        self.tool_results.pack(side='left', fill='both', expand=True)
        tool_scrollbar.pack(side='right', fill='y')
        
        # Update tool options based on selection
        self.tool_var.trace('w', self.update_tool_options)
    
    def create_device_inventory_tab(self):
        """Create device inventory tab"""
        inventory_frame = ttk.Frame(self.notebook)
        self.notebook.add(inventory_frame, text="Device Inventory")
        
        # Controls frame
        controls_frame = ttk.Frame(inventory_frame)
        controls_frame.pack(fill='x', padx=10, pady=5)
        
        ttk.Button(controls_frame, text="Add Device", command=self.add_device_dialog).pack(side='left', padx=5)
        ttk.Button(controls_frame, text="Edit Device", command=self.edit_device_dialog).pack(side='left', padx=5)
        ttk.Button(controls_frame, text="Delete Device", command=self.delete_device).pack(side='left', padx=5)
        ttk.Button(controls_frame, text="Import List", command=self.import_device_list).pack(side='left', padx=5)
        ttk.Button(controls_frame, text="Export List", command=self.export_device_list).pack(side='left', padx=5)
        
        # Search frame
        search_frame = ttk.Frame(inventory_frame)
        search_frame.pack(fill='x', padx=10, pady=5)
        
        ttk.Label(search_frame, text="Search:").pack(side='left')
        self.device_search = ttk.Entry(search_frame, width=30)
        self.device_search.pack(side='left', padx=5)
        ttk.Button(search_frame, text="Search", command=self.search_devices).pack(side='left', padx=5)
        ttk.Button(search_frame, text="Clear", command=self.clear_device_search).pack(side='left', padx=5)
        
        # Device list
        list_frame = ttk.LabelFrame(inventory_frame, text="Devices", padding=5)
        list_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        columns = ("Name", "IP Address", "Type", "Location", "Status", "Last Check", "Notes")
        self.device_tree = ttk.Treeview(list_frame, columns=columns, show='tree headings', height=12)
        
        for col in columns:
            self.device_tree.heading(col, text=col)
            self.device_tree.column(col, width=120)
        
        device_scrollbar = ttk.Scrollbar(list_frame, orient='vertical', command=self.device_tree.yview)
        self.device_tree.config(yscrollcommand=device_scrollbar.set)
        
        self.device_tree.pack(side='left', fill='both', expand=True)
        device_scrollbar.pack(side='right', fill='y')
        
        # Double click to edit
        self.device_tree.bind('<Double-1>', lambda e: self.edit_device_dialog())
    
    def create_settings_tab(self):
        """Create settings tab"""
        settings_frame = ttk.Frame(self.notebook)
        self.notebook.add(settings_frame, text="Settings")
        
        # General settings
        general_frame = ttk.LabelFrame(settings_frame, text="General Settings", padding=15)
        general_frame.pack(fill='x', padx=10, pady=5)
        
        ttk.Label(general_frame, text="Default Timeout (seconds):").grid(row=0, column=0, sticky='w', padx=5)
        self.default_timeout = ttk.Spinbox(general_frame, from_=1, to=60, width=10)
        self.default_timeout.grid(row=0, column=1, padx=5, pady=2)
        self.default_timeout.set("5")
        
        ttk.Label(general_frame, text="Max Threads:").grid(row=0, column=2, sticky='w', padx=15)
        self.max_threads = ttk.Spinbox(general_frame, from_=1, to=100, width=10)
        self.max_threads.grid(row=0, column=3, padx=5, pady=2)
        self.max_threads.set("20")
        
        # Theme settings
        theme_frame = ttk.LabelFrame(settings_frame, text="Theme Settings", padding=15)
        theme_frame.pack(fill='x', padx=10, pady=5)
        
        ttk.Label(theme_frame, text="Theme:").pack(anchor='w')
        self.theme_var = tk.StringVar(value="dark")
        ttk.Radiobutton(theme_frame, text="Dark", variable=self.theme_var, value="dark").pack(anchor='w')
        ttk.Radiobutton(theme_frame, text="Light", variable=self.theme_var, value="light").pack(anchor='w')
        ttk.Button(theme_frame, text="Apply Theme", command=self.apply_theme).pack(pady=5)
        
        # Logging settings
        log_frame = ttk.LabelFrame(settings_frame, text="Logging Settings", padding=15)
        log_frame.pack(fill='x', padx=10, pady=5)
        
        ttk.Checkbutton(log_frame, text="Enable file logging").pack(anchor='w')
        ttk.Label(log_frame, text="Log level:").pack(anchor='w')
        ttk.Combobox(log_frame, values=["DEBUG", "INFO", "WARNING", "ERROR"], width=15).pack(anchor='w')
        
        # Network settings
        net_frame = ttk.LabelFrame(settings_frame, text="Network Settings", padding=15)
        net_frame.pack(fill='x', padx=10, pady=5)
        
        ttk.Label(net_frame, text="Default SSH Port:").grid(row=0, column=0, sticky='w', padx=5)
        self.default_ssh_port = ttk.Entry(net_frame, width=10)
        self.default_ssh_port.grid(row=0, column=1, padx=5, pady=2)
        self.default_ssh_port.insert(0, "22")
        
        ttk.Label(net_frame, text="Default SNMP Community:").grid(row=1, column=0, sticky='w', padx=5, pady=(5,0))
        self.default_snmp_community = ttk.Entry(net_frame, width=15)
        self.default_snmp_community.grid(row=1, column=1, padx=5, pady=(5,2))
        self.default_snmp_community.insert(0, "public")
        
        # Save/Load buttons
        save_btn_frame = ttk.Frame(settings_frame)
        save_btn_frame.pack(fill='x', padx=10, pady=20)
        
        ttk.Button(save_btn_frame, text="Save Settings", command=self.save_settings).pack(side='left', padx=5)
        ttk.Button(save_btn_frame, text="Load Settings", command=self.load_settings).pack(side='left', padx=5)
        ttk.Button(save_btn_frame, text="Reset to Defaults", command=self.reset_settings).pack(side='left', padx=5)
    
    # Threading and async methods
    def start_thread(self, target, args=()):
        """Start a background thread"""
        thread = threading.Thread(target=target, args=args, daemon=True)
        thread.start()
        return thread
        
    def update_progress(self, progress_bar, value, maximum=None):
        """Update progress bar in main thread"""
        def update():
            if maximum is not None:
                progress_bar['maximum'] = maximum
            progress_bar['value'] = value
            self.root.update_idletasks()
        
        self.root.after(0, update)
        
    def add_result_to_tree(self, tree, values, parent=''):
        """Add result to treeview in main thread"""
        def add():
            tree.insert(parent, 'end', values=values)
            self.root.update_idletasks()
        
        self.root.after(0, add)
        
    def clear_tree(self, tree):
        """Clear treeview in main thread"""
        def clear():
            for item in tree.get_children():
                tree.delete(item)
            self.root.update_idletasks()
        
        self.root.after(0, clear)
    
    # Network scanning methods
    def start_network_scan(self):
        """Start network scanning in background thread"""
        ip_range = self.scanner_ip_range.get()
        max_threads = int(self.scanner_threads.get())
        timeout = int(self.scanner_timeout.get()) / 1000
        
        self.scan_btn.config(state='disabled')
        self.clear_tree(self.scan_tree)
        self.scanning = True
        
        # Start scan in background
        self.scan_thread = self.start_thread(self._network_scan_worker, (ip_range, max_threads, timeout))
        
    def _network_scan_worker(self, ip_range, max_threads, timeout):
        """Background worker for network scanning"""
        try:
            network = ipaddress.ip_network(ip_range, strict=False)
            total_hosts = network.num_addresses - 2  # Exclude network and broadcast
            
            self.update_progress(self.scan_progress, 0, total_hosts)
            completed = 0
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
                futures = {}
                
                for ip in network.hosts():
                    if not self.scanning:
                        break
                    future = executor.submit(self._scan_host, str(ip), timeout)
                    futures[future] = ip
                
                for future in concurrent.futures.as_completed(futures):
                    if not self.scanning:
                        break
                    ip = futures[future]
                    try:
                        result = future.result()
                        if result['status'] == 'Online':
                            self.add_result_to_tree(self.scan_tree, (
                                result['ip'],
                                result.get('hostname', 'Unknown'),
                                result['status'],
                                f"{result.get('response_time', 0):.2f}ms",
                                result.get('mac', 'Unknown'),
                                result.get('vendor', 'Unknown')
                            ))
                    except Exception as e:
                        print(f"Error scanning {ip}: {e}")
                    
                    completed += 1
                    self.update_progress(self.scan_progress, completed, total_hosts)
                    
        except Exception as e:
            messagebox.showerror("Scan Error", f"Error during network scan: {e}")
        finally:
            self.root.after(0, lambda: self.scan_btn.config(state='normal'))
            self.scanning = False
            self.log_message(f"Network scan completed. Found {completed} hosts.")
    
    def _scan_host(self, ip, timeout):
        """Scan individual host"""
        try:
            # Ping check
            response_time = 0
            start_time = time.time()
            
            # Try ping
            if os.name == 'nt':  # Windows
                ping_cmd = ['ping', '-n', '1', '-w', str(int(timeout * 1000)), ip]
            else:  # Linux/Mac
                ping_cmd = ['ping', '-c', '1', '-W', str(int(timeout)), ip]
            
            result = subprocess.run(ping_cmd, capture_output=True, timeout=timeout)
            
            if result.returncode == 0:
                response_time = (time.time() - start_time) * 1000
                hostname = self._get_hostname(ip)
                mac, vendor = self._get_mac_vendor(ip)
                
                return {
                    'ip': ip,
                    'hostname': hostname,
                    'status': 'Online',
                    'response_time': response_time,
                    'mac': mac,
                    'vendor': vendor
                }
            else:
                return {'ip': ip, 'hostname': 'Unknown', 'status': 'Offline', 'response_time': 0}
                
        except Exception as e:
            return {'ip': ip, 'hostname': 'Unknown', 'status': 'Error', 'response_time': 0}
    
    def _get_hostname(self, ip):
        """Get hostname for IP"""
        try:
            return socket.gethostbyaddr(ip)[0]
        except:
            return 'Unknown'
    
    def _get_mac_vendor(self, ip):
        """Get MAC address and vendor (basic implementation)"""
        try:
            # This is a simplified implementation
            # In a real tool, you'd use ARP tables or vendor lookup
            if os.name == 'nt':  # Windows
                arp_cmd = ['arp', '-a', ip]
            else:  # Linux/Mac
                arp_cmd = ['arp', '-n', ip]
            
            result = subprocess.run(arp_cmd, capture_output=True, text=True, timeout=5)
            
            if result.returncode == 0:
                output = result.stdout
                # Parse MAC from arp output
                mac_match = re.search(r'([0-9A-Fa-f]{2}:){5}([0-9A-Fa-f]{2})', output)
                if mac_match:
                    mac = mac_match.group()
                    vendor = self._lookup_vendor(mac[:8].upper())
                    return mac, vendor
            
            return 'Unknown', 'Unknown'
        except:
            return 'Unknown', 'Unknown'
    
    def _lookup_vendor(self, mac_prefix):
        """Look up vendor by MAC prefix (simplified)"""
        # This would typically use a vendor database
        # For now, return Unknown
        return 'Unknown'
    
    def stop_network_scan(self):
        """Stop network scan"""
        self.scanning = False
        self.log_message("Network scan stopped by user")
    
    def clear_scan_results(self):
        """Clear scan results"""
        self.clear_tree(self.scan_tree)
        self.update_progress(self.scan_progress, 0)
    
    def export_scan_results(self):
        """Export scan results to file"""
        try:
            filename = filedialog.asksaveasfilename(
                defaultextension=".csv",
                filetypes=[("CSV files", "*.csv"), ("JSON files", "*.json"), ("Text files", "*.txt")]
            )
            
            if filename:
                with open(filename, 'w', newline='') as f:
                    if filename.endswith('.csv'):
                        writer = csv.writer(f)
                        writer.writerow(["IP Address", "Hostname", "Status", "Response Time", "MAC Address", "Vendor"])
                        for item in self.scan_tree.get_children():
                            writer.writerow(self.scan_tree.item(item)['values'])
                    elif filename.endswith('.json'):
                        results = []
                        for item in self.scan_tree.get_children():
                            values = self.scan_tree.item(item)['values']
                            results.append({
                                "IP Address": values[0],
                                "Hostname": values[1],
                                "Status": values[2],
                                "Response Time": values[3],
                                "MAC Address": values[4],
                                "Vendor": values[5]
                            })
                        json.dump(results, f, indent=2)
                    else:
                        f.write("IP Address,Hostname,Status,Response Time,MAC Address,Vendor\n")
                        for item in self.scan_tree.get_children():
                            f.write(",".join(map(str, self.scan_tree.item(item)['values'])) + "\n")
                
                messagebox.showinfo("Export", f"Scan results exported to {filename}")
                
        except Exception as e:
            messagebox.showerror("Export Error", f"Error exporting results: {e}")
    
    def show_host_details(self):
        """Show detailed information about selected host"""
        selection = self.scan_tree.selection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select a host to view details")
            return
        
        values = self.scan_tree.item(selection[0])['values']
        details = f"""
Host Details:
IP Address: {values[0]}
Hostname: {values[1]}
Status: {values[2]}
Response Time: {values[3]}
MAC Address: {values[4]}
Vendor: {values[5]}
        """
        messagebox.showinfo("Host Details", details)
    
    # Port scanning methods
    def start_port_scan(self):
        """Start port scanning"""
        target = self.port_target.get()
        port_range = self.port_range.get()
        scan_type = self.scan_type.get()
        
        if not target:
            messagebox.showerror("Error", "Please enter a target IP or hostname")
            return
        
        # Parse port range
        try:
            if '-' in port_range:
                start_port, end_port = map(int, port_range.split('-'))
            else:
                start_port = end_port = int(port_range)
                
            ports = list(range(start_port, end_port + 1))
        except:
            messagebox.showerror("Error", "Invalid port range format")
            return
        
        self.clear_tree(self.port_tree)
        self.port_scanning = True
        self.port_scan_thread = self.start_thread(self._port_scan_worker, (target, ports, scan_type))
    
    def _port_scan_worker(self, target, ports, scan_type):
        """Background worker for port scanning"""
        total_ports = len(ports)
        completed = 0
        
        self.update_progress(self.port_progress, 0, total_ports)
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            futures = {executor.submit(self._scan_port, target, port, scan_type): port for port in ports}
            
            for future in concurrent.futures.as_completed(futures):
                if not self.port_scanning:
                    break
                port = futures[future]
                try:
                    result = future.result()
                    if result['status'] == 'open':
                        self.add_result_to_tree(self.port_tree, (
                            port,
                            result['protocol'],
                            result['status'],
                            result.get('service', 'unknown'),
                            result.get('banner', 'N/A')
                        ))
                except Exception as e:
                    print(f"Error scanning port {port}: {e}")
                
                completed += 1
                self.update_progress(self.port_progress, completed, total_ports)
        
        self.port_scanning = False
        self.log_message(f"Port scan completed for {target}")
    
    def _scan_port(self, target, port, scan_type):
        """Scan individual port"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            
            if scan_type == "TCP Connect":
                result = sock.connect_ex((target, port))
                if result == 0:
                    # Try to get banner
                    banner = self._get_banner(sock, port)
                    return {'status': 'open', 'protocol': 'TCP', 'service': self._get_service_name(port), 'banner': banner}
                    
            elif scan_type == "TCP SYN":
                # Simplified SYN scan - in real implementation would use raw sockets
                result = sock.connect_ex((target, port))
                if result == 0:
                    return {'status': 'open', 'protocol': 'TCP', 'service': self._get_service_name(port)}
                    
            sock.close()
            return {'status': 'closed', 'protocol': 'TCP'}
            
        except Exception as e:
            return {'status': 'error', 'protocol': 'TCP', 'error': str(e)}
    
    def _get_banner(self, sock, port):
        """Get service banner"""
        try:
            # Send a generic request
            if port == 80:
                sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
            elif port == 21:
                pass  # FTP, wait for banner
            elif port == 22:
                pass  # SSH, wait for banner
            else:
                sock.send(b"\r\n")
                
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            return banner[:100] if banner else 'N/A'
        except:
            return 'N/A'
    
    def _get_service_name(self, port):
        """Get service name by port"""
        common_ports = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
            80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS', 993: 'IMAPS',
            995: 'POP3S', 3389: 'RDP', 5432: 'PostgreSQL', 3306: 'MySQL'
        }
        return common_ports.get(port, 'Unknown')
    
    def stop_port_scan(self):
        """Stop port scan"""
        self.port_scanning = False
        self.log_message("Port scan stopped by user")
    
    def clear_port_results(self):
        """Clear port scan results"""
        self.clear_tree(self.port_tree)
        self.update_progress(self.port_progress, 0)
    
    def export_port_results(self):
        """Export port scan results to file"""
        try:
            filename = filedialog.asksaveasfilename(
                defaultextension=".csv",
                filetypes=[("CSV files", "*.csv"), ("JSON files", "*.json"), ("Text files", "*.txt")]
            )
            
            if filename:
                with open(filename, 'w', newline='') as f:
                    if filename.endswith('.csv'):
                        writer = csv.writer(f)
                        writer.writerow(["Port", "Protocol", "Status", "Service", "Banner"])
                        for item in self.port_tree.get_children():
                            writer.writerow(self.port_tree.item(item)['values'])
                    elif filename.endswith('.json'):
                        results = []
                        for item in self.port_tree.get_children():
                            values = self.port_tree.item(item)['values']
                            results.append({
                                "Port": values[0],
                                "Protocol": values[1],
                                "Status": values[2],
                                "Service": values[3],
                                "Banner": values[4]
                            })
                        json.dump(results, f, indent=2)
                    else:
                        f.write("Port,Protocol,Status,Service,Banner\n")
                        for item in self.port_tree.get_children():
                            f.write(",".join(map(str, self.port_tree.item(item)['values'])) + "\n")
                
                messagebox.showinfo("Export", f"Port scan results exported to {filename}")
                
        except Exception as e:
            messagebox.showerror("Export Error", f"Error exporting results: {e}")
    
    # Ping monitoring methods
    def start_ping_monitor(self):
        """Start ping monitoring"""
        target = self.monitor_target.get()
        interval = int(self.monitor_interval.get())
        timeout = int(self.monitor_timeout.get())
        
        if not target:
            messagebox.showerror("Error", "Please enter a target to monitor")
            return
        
        self.monitoring = True
        self.ping_stats = {'sent': 0, 'received': 0, 'lost': 0, 'times': []}
        
        self.ping_monitor_thread = self.start_thread(self._ping_monitor_worker, (target, interval, timeout))
    
    def _ping_monitor_worker(self, target, interval, timeout):
        """Background worker for ping monitoring"""
        while self.monitoring:
            start_time = time.time()
            success = self._ping_host(target, timeout)
            end_time = time.time()
            
            response_time = (end_time - start_time) * 1000
            
            self.ping_stats['sent'] += 1
            if success:
                self.ping_stats['received'] += 1
                self.ping_stats['times'].append(response_time)
            else:
                self.ping_stats['lost'] += 1
            
            # Update UI
            self.root.after(0, self._update_ping_display, target, response_time, success)
            
            time.sleep(interval)
    
    def _ping_host(self, target, timeout):
        """Ping a single host"""
        try:
            if os.name == 'nt':  # Windows
                ping_cmd = ['ping', '-n', '1', '-w', str(timeout * 1000), target]
            else:  # Linux/Mac
                ping_cmd = ['ping', '-c', '1', '-W', str(timeout), target]
            
            result = subprocess.run(ping_cmd, capture_output=True, timeout=timeout + 1)
            return result.returncode == 0
        except:
            return False
    
    def _update_ping_display(self, target, response_time, success):
        """Update ping monitoring display"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        status = "✓" if success else "✗"
        
        result_text = f"[{timestamp}] {status} {target}: "
        if success:
            result_text += f"time={response_time:.2f}ms"
        else:
            result_text += "timeout"
        
        self.ping_results_text.insert('end', result_text + '\n')
        self.ping_results_text.see('end')
        
        # Update statistics
        if len(self.ping_stats['times']) > 0:
            avg_time = sum(self.ping_stats['times']) / len(self.ping_stats['times'])
            min_time = min(self.ping_stats['times'])
            max_time = max(self.ping_stats['times'])
            success_rate = (self.ping_stats['received'] / self.ping_stats['sent']) * 100
        else:
            avg_time = min_time = max_time = success_rate = 0
        
        self.stats_labels['sent'].config(text=str(self.ping_stats['sent']))
        self.stats_labels['received'].config(text=str(self.ping_stats['received']))
        self.stats_labels['lost'].config(text=str(self.ping_stats['lost']))
        self.stats_labels['success_rate'].config(text=f"{success_rate:.1f}%")
        self.stats_labels['avg_latency'].config(text=f"{avg_time:.2f}ms")
        self.stats_labels['min_latency'].config(text=f"{min_time:.2f}ms")
        self.stats_labels['max_latency'].config(text=f"{max_time:.2f}ms")
    
    def stop_ping_monitor(self):
        """Stop ping monitoring"""
        self.monitoring = False
        self.log_message("Ping monitoring stopped by user")
    
    def clear_ping_results(self):
        """Clear ping monitoring results"""
        self.ping_results_text.delete('1.0', 'end')
        for label in self.stats_labels.values():
            label.config(text="0")
    
    def export_ping_results(self):
        """Export ping monitoring results"""
        try:
            filename = filedialog.asksaveasfilename(
                defaultextension=".txt",
                filetypes=[("Text files", "*.txt"), ("CSV files", "*.csv")]
            )
            
            if filename:
                content = self.ping_results_text.get('1.0', 'end')
                with open(filename, 'w') as f:
                    f.write(f"Ping Monitoring Results\n")
                    f.write(f"Target: {self.monitor_target.get()}\n")
                    f.write(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write("=" * 50 + "\n\n")
                    f.write(content)
                
                messagebox.showinfo("Export", f"Ping results exported to {filename}")
                
        except Exception as e:
            messagebox.showerror("Export Error", f"Error exporting results: {e}")
    
    # SSH automation methods
    def connect_ssh(self):
        """Connect to SSH device"""
        if not PARAMIKO_AVAILABLE:
            messagebox.showerror("Error", "Paramiko library not installed. Please install with: pip install paramiko")
            return
        
        host = self.ssh_host.get()
        port = int(self.ssh_port.get())
        username = self.ssh_username.get()
        password = self.ssh_password.get()
        
        if not all([host, username, password]):
            messagebox.showerror("Error", "Please fill in all connection details")
            return
        
        self.ssh_thread = self.start_thread(self._ssh_connect_worker, (host, port, username, password))
    
    def _ssh_connect_worker(self, host, port, username, password):
        """Background worker for SSH connection"""
        try:
            self.ssh_client = paramiko.SSHClient()
            self.ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.ssh_client.connect(host, port=port, username=username, password=password, timeout=10)
            
            self.ssh_connected = True
            self.root.after(0, lambda: self.ssh_status.config(text=f"Connected to {host}:{port}", foreground='green'))
            self.log_message(f"SSH connection established to {host}:{port}")
            
        except Exception as e:
            self.root.after(0, lambda: messagebox.showerror("SSH Error", f"Failed to connect: {str(e)}"))
            self.log_message(f"SSH connection failed to {host}: {str(e)}")
    
    def disconnect_ssh(self):
        """Disconnect SSH connection"""
        if hasattr(self, 'ssh_client') and self.ssh_connected:
            self.ssh_client.close()
            self.ssh_connected = False
            self.ssh_status.config(text="Disconnected", foreground='red')
            self.log_message("SSH connection closed")
    
    def execute_ssh_command(self):
        """Execute SSH command"""
        if not self.ssh_connected:
            messagebox.showerror("Error", "Not connected to SSH device")
            return
        
        command = self.ssh_command.get()
        if not command:
            messagebox.showerror("Error", "Please enter a command")
            return
        
        self.ssh_thread = self.start_thread(self._ssh_execute_worker, (command,))
    
    def _ssh_execute_worker(self, command):
        """Background worker for SSH command execution"""
        try:
            stdin, stdout, stderr = self.ssh_client.exec_command(command)
            output = stdout.read().decode('utf-8')
            error = stderr.read().decode('utf-8')
            
            result = f"$ {command}\n"
            if output:
                result += output
            if error:
                result += f"Error: {error}"
            
            self.root.after(0, lambda: self.ssh_results.insert('end', result + '\n' + '='*50 + '\n'))
            
        except Exception as e:
            error_msg = f"Error executing command: {str(e)}"
            self.root.after(0, lambda: self.ssh_results.insert('end', error_msg + '\n'))
    
    def execute_on_multiple(self):
        """Execute command on multiple devices"""
        # This would open a dialog to select multiple devices
        messagebox.showinfo("Feature", "Execute on Multiple feature - Coming Soon!")
    
    def load_script(self):
        """Load script from file"""
        filename = filedialog.askopenfilename(
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        
        if filename:
            try:
                with open(filename, 'r') as f:
                    script_content = f.read()
                self.ssh_results.insert('end', f"Loaded script from {filename}:\n")
                self.ssh_results.insert('end', script_content + '\n' + '='*50 + '\n')
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load script: {str(e)}")
    
    def run_script(self):
        """Run loaded script"""
        if not self.ssh_connected:
            messagebox.showerror("Error", "Not connected to SSH device")
            return
        
        messagebox.showinfo("Feature", "Script execution feature - Coming Soon!")
    
    # Configuration backup methods
    def add_backup_device(self):
        """Add device to backup list"""
        ip = self.backup_device_ip.get()
        username = self.backup_device_user.get()
        password = self.backup_device_pass.get()
        
        if not all([ip, username, password]):
            messagebox.showerror("Error", "Please fill in all device details")
            return
        
        self.add_result_to_tree(self.backup_tree, (ip, username, "Pending", "Never", ""))
        
        # Clear inputs
        self.backup_device_ip.delete(0, 'end')
        self.backup_device_user.delete(0, 'end')
        self.backup_device_pass.delete(0, 'end')
    
    def start_config_backup(self):
        """Start configuration backup"""
        if self.backup_running:
            messagebox.showwarning("Warning", "Backup is already running")
            return
        
        devices = []
        for item in self.backup_tree.get_children():
            values = self.backup_tree.item(item)['values']
            devices.append({
                'ip': values[0],
                'username': values[1],
                'status': values[2]
            })
        
        if not devices:
            messagebox.showerror("Error", "No devices in backup list")
            return
        
        self.backup_running = True
        self.backup_thread = self.start_thread(self._backup_worker, (devices,))
    
    def _backup_worker(self, devices):
        """Background worker for configuration backup"""
        backup_dir = self.backup_dir.get()
        os.makedirs(backup_dir, exist_ok=True)
        
        for device in devices:
            if not self.backup_running:
                break
            
            try:
                self.root.after(0, lambda d=device: self._update_backup_status(d['ip'], "Backing up..."))
                
                # Execute backup commands
                commands = ["show running-config", "show startup-config"]
                backup_data = {}
                
                for cmd in commands:
                    if not self.backup_running:
                        break
                    output = self._execute_device_command(device, cmd)
                    backup_data[cmd] = output
                
                # Save backup
                if self.backup_running:
                    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                    filename = f"{backup_dir}/{device['ip']}_{timestamp}"
                    
                    format_choice = self.backup_format.get()
                    if format_choice in ["TXT", "Both"]:
                        with open(f"{filename}.txt", 'w') as f:
                            for cmd, output in backup_data.items():
                                f.write(f"=== {cmd} ===\n{output}\n\n")
                    
                    if format_choice in ["JSON", "Both"]:
                        with open(f"{filename}.json", 'w') as f:
                            json.dump(backup_data, f, indent=2)
                    
                    self.root.after(0, lambda d=device: self._update_backup_status(d['ip'], "Completed", filename))
                
            except Exception as e:
                self.root.after(0, lambda d=device, e=str(e): self._update_backup_status(d['ip'], f"Error: {e}"))
        
        self.backup_running = False
        self.log_message("Configuration backup completed")
    
    def _execute_device_command(self, device, command):
        """Execute command on device (simplified)"""
        # This would use SSH or device-specific APIs
        # For now, return placeholder
        return f"Mock output for {command} on {device['ip']}"
    
    def _update_backup_status(self, ip, status, backup_path=None):
        """Update backup status in UI"""
        for item in self.backup_tree.get_children():
            values = self.backup_tree.item(item)['values']
            if values[0] == ip:
                new_values = list(values)
                new_values[2] = status
                new_values[3] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                if backup_path:
                    new_values[4] = backup_path
                self.backup_tree.item(item, values=new_values)
                break
    
    def stop_config_backup(self):
        """Stop configuration backup"""
        self.backup_running = False
        self.log_message("Configuration backup stopped by user")
    
    def schedule_backup(self):
        """Schedule automatic backups"""
        messagebox.showinfo("Feature", "Scheduled backup feature - Coming Soon!")
    
    def browse_backup_dir(self):
        """Browse for backup directory"""
        directory = filedialog.askdirectory(initialdir=self.backup_dir.get())
        if directory:
            self.backup_dir.delete(0, 'end')
            self.backup_dir.insert(0, directory)
    
    # SNMP monitoring methods
    def snmp_get_value(self):
        """Get SNMP value"""
        messagebox.showinfo("Feature", "SNMP get value feature - Coming Soon!")
    
    def snmp_walk(self):
        """Walk SNMP OIDs"""
        messagebox.showinfo("Feature", "SNMP walk feature - Coming Soon!")
    
    def snmp_bulk_walk(self):
        """Bulk SNMP walk"""
        messagebox.showinfo("Feature", "SNMP bulk walk feature - Coming Soon!")
    
    def start_snmp_monitor(self):
        """Start SNMP monitoring"""
        messagebox.showinfo("Feature", "SNMP monitoring feature - Coming Soon!")
    
    # Network tools methods
    def update_tool_options(self, *args):
        """Update tool options based on selection"""
        # Clear current options
        for widget in self.tool_options_frame.winfo_children():
            widget.destroy()
        
        tool = self.tool_var.get()
        
        if tool == "traceroute":
            self.traceroute_max_hops = ttk.Spinbox(self.tool_options_frame, from_=1, to=30, width=10)
            self.traceroute_max_hops.set("30")
            frame = ttk.Frame(self.tool_options_frame)
            frame.pack(anchor='w')
            ttk.Label(frame, text="Max Hops:").pack(side='left')
            self.traceroute_max_hops.pack(side='left', padx=5)
        
        elif tool == "dns":
            self.dns_record_type = ttk.Combobox(self.tool_options_frame, 
                                              values=["A", "AAAA", "MX", "NS", "CNAME", "TXT"], 
                                              width=10)
            self.dns_record_type.set("A")
            frame = ttk.Frame(self.tool_options_frame)
            frame.pack(anchor='w')
            ttk.Label(frame, text="Record Type:").pack(side='left')
            self.dns_record_type.pack(side='left', padx=5)
        
        elif tool == "bandwidth":
            self.bandwidth_test_server = ttk.Entry(self.tool_options_frame, width=20)
            self.bandwidth_test_server.insert(0, "8.8.8.8")
            frame = ttk.Frame(self.tool_options_frame)
            frame.pack(anchor='w')
            ttk.Label(frame, text="Test Server:").pack(side='left')
            self.bandwidth_test_server.pack(side='left', padx=5)
    
    def run_network_tool(self):
        """Run selected network tool"""
        tool = self.tool_var.get()
        target = self.tool_target.get()
        
        if not target:
            messagebox.showerror("Error", "Please enter a target")
            return
        
        self.tool_running = True
        self.network_tool_thread = self.start_thread(self._tool_worker, (tool, target))
    
    def _tool_worker(self, tool, target):
        """Background worker for network tools"""
        try:
            if tool == "traceroute":
                max_hops = int(self.traceroute_max_hops.get())
                result = self._run_traceroute(target, max_hops)
            elif tool == "dns":
                record_type = self.dns_record_type.get()
                result = self._run_dns_lookup(target, record_type)
            elif tool == "whois":
                result = self._run_whois_lookup(target)
            elif tool == "bandwidth":
                server = self.bandwidth_test_server.get()
                result = self._run_bandwidth_test(server, target)
            else:
                result = f"Unknown tool: {tool}"
            
            self.root.after(0, lambda: self.tool_results.insert('end', result + '\n' + '='*50 + '\n'))
            
        except Exception as e:
            error_msg = f"Error running {tool}: {str(e)}"
            self.root.after(0, lambda: self.tool_results.insert('end', error_msg + '\n'))
        
        self.tool_running = False
    
    def _run_traceroute(self, target, max_hops):
        """Run traceroute command"""
        try:
            if os.name == 'nt':  # Windows
                cmd = ['tracert', '-h', str(max_hops), target]
            else:  # Linux/Mac
                cmd = ['traceroute', '-m', str(max_hops), target]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            return f"Traceroute to {target}:\n{result.stdout}"
        except Exception as e:
            return f"Traceroute failed: {str(e)}"
    
    def _run_dns_lookup(self, target, record_type):
        """Run DNS lookup"""
        try:
            if record_type == "A":
                result = socket.gethostbyname(target)
                return f"A record for {target}: {result}"
            else:
                # This would use dnspython library for full DNS support
                return f"DNS {record_type} lookup for {target}: (Feature requires dnspython)"
        except Exception as e:
            return f"DNS lookup failed: {str(e)}"
    
    def _run_whois_lookup(self, target):
        """Run whois lookup"""
        try:
            result = subprocess.run(['whois', target], capture_output=True, text=True, timeout=10)
            return f"Whois lookup for {target}:\n{result.stdout}"
        except Exception as e:
            return f"Whois lookup failed: {str(e)}"
    
    def _run_bandwidth_test(self, server, target):
        """Run bandwidth test"""
        return f"Bandwidth test from {server} to {target}: (Feature requires iperf3)"
    
    def stop_network_tool(self):
        """Stop network tool"""
        self.tool_running = False
        self.log_message("Network tool stopped by user")
    
    # Device inventory methods
    def add_device_dialog(self):
        """Add device dialog"""
        dialog = tk.Toplevel(self.root)
        dialog.title("Add Device")
        dialog.geometry("400x300")
        dialog.resizable(False, False)
        
        # Device form fields
        ttk.Label(dialog, text="Name:").grid(row=0, column=0, sticky='w', padx=10, pady=5)
        name_entry = ttk.Entry(dialog, width=25)
        name_entry.grid(row=0, column=1, padx=10, pady=5)
        
        ttk.Label(dialog, text="IP Address:").grid(row=1, column=0, sticky='w', padx=10, pady=5)
        ip_entry = ttk.Entry(dialog, width=25)
        ip_entry.grid(row=1, column=1, padx=10, pady=5)
        
        ttk.Label(dialog, text="Type:").grid(row=2, column=0, sticky='w', padx=10, pady=5)
        type_combo = ttk.Combobox(dialog, values=["Router", "Switch", "Server", "Firewall", "Access Point", "Other"], width=22)
        type_combo.grid(row=2, column=1, padx=10, pady=5)
        
        ttk.Label(dialog, text="Location:").grid(row=3, column=0, sticky='w', padx=10, pady=5)
        location_entry = ttk.Entry(dialog, width=25)
        location_entry.grid(row=3, column=1, padx=10, pady=5)
        
        ttk.Label(dialog, text="Notes:").grid(row=4, column=0, sticky='w', padx=10, pady=5)
        notes_entry = tk.Text(dialog, width=25, height=4)
        notes_entry.grid(row=4, column=1, padx=10, pady=5)
        
        def save_device():
            name = name_entry.get()
            ip = ip_entry.get()
            device_type = type_combo.get()
            location = location_entry.get()
            notes = notes_entry.get('1.0', 'end').strip()
            
            if not all([name, ip]):
                messagebox.showerror("Error", "Name and IP Address are required")
                return
            
            self.add_result_to_tree(self.device_tree, (name, ip, device_type, location, "Unknown", "Never", notes))
            dialog.destroy()
        
        btn_frame = ttk.Frame(dialog)
        btn_frame.grid(row=5, column=0, columnspan=2, pady=20)
        
        ttk.Button(btn_frame, text="Save", command=save_device).pack(side='left', padx=10)
        ttk.Button(btn_frame, text="Cancel", command=dialog.destroy).pack(side='left', padx=10)
    
    def edit_device_dialog(self):
        """Edit selected device"""
        selection = self.device_tree.selection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select a device to edit")
            return
        
        values = self.device_tree.item(selection[0])['values']
        
        dialog = tk.Toplevel(self.root)
        dialog.title("Edit Device")
        dialog.geometry("400x300")
        dialog.resizable(False, False)
        
        # Pre-fill form with current values
        ttk.Label(dialog, text="Name:").grid(row=0, column=0, sticky='w', padx=10, pady=5)
        name_entry = ttk.Entry(dialog, width=25)
        name_entry.insert(0, values[0])
        name_entry.grid(row=0, column=1, padx=10, pady=5)
        
        ttk.Label(dialog, text="IP Address:").grid(row=1, column=0, sticky='w', padx=10, pady=5)
        ip_entry = ttk.Entry(dialog, width=25)
        ip_entry.insert(0, values[1])
        ip_entry.grid(row=1, column=1, padx=10, pady=5)
        
        ttk.Label(dialog, text="Type:").grid(row=2, column=0, sticky='w', padx=10, pady=5)
        type_combo = ttk.Combobox(dialog, values=["Router", "Switch", "Server", "Firewall", "Access Point", "Other"], width=22)
        type_combo.set(values[2])
        type_combo.grid(row=2, column=1, padx=10, pady=5)
        
        ttk.Label(dialog, text="Location:").grid(row=3, column=0, sticky='w', padx=10, pady=5)
        location_entry = ttk.Entry(dialog, width=25)
        location_entry.insert(0, values[3])
        location_entry.grid(row=3, column=1, padx=10, pady=5)
        
        ttk.Label(dialog, text="Notes:").grid(row=4, column=0, sticky='w', padx=10, pady=5)
        notes_entry = tk.Text(dialog, width=25, height=4)
        notes_entry.insert('1.0', values[6] if len(values) > 6 else "")
        notes_entry.grid(row=4, column=1, padx=10, pady=5)
        
        def save_changes():
            new_values = (
                name_entry.get(),
                ip_entry.get(),
                type_combo.get(),
                location_entry.get(),
                values[4],  # Status unchanged
                values[5],  # Last check unchanged
                notes_entry.get('1.0', 'end').strip()
            )
            self.device_tree.item(selection[0], values=new_values)
            dialog.destroy()
        
        btn_frame = ttk.Frame(dialog)
        btn_frame.grid(row=5, column=0, columnspan=2, pady=20)
        
        ttk.Button(btn_frame, text="Save", command=save_changes).pack(side='left', padx=10)
        ttk.Button(btn_frame, text="Cancel", command=dialog.destroy).pack(side='left', padx=10)
    
    def delete_device(self):
        """Delete selected device"""
        selection = self.device_tree.selection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select a device to delete")
            return
        
        if messagebox.askyesno("Confirm", "Are you sure you want to delete the selected device?"):
            self.device_tree.delete(selection[0])
    
    def search_devices(self):
        """Search devices"""
        search_term = self.device_search.get().lower()
        if not search_term:
            return
        
        # Clear current selection
        for item in self.device_tree.get_children():
            self.device_tree.set(item, "#0", "")
        
        # Search and highlight
        for item in self.device_tree.get_children():
            values = self.device_tree.item(item)['values']
            for value in values:
                if search_term in str(value).lower():
                    self.device_tree.set(item, "#0", "★")
                    break
    
    def clear_device_search(self):
        """Clear device search"""
        self.device_search.delete(0, 'end')
        for item in self.device_tree.get_children():
            self.device_tree.set(item, "#0", "")
    
    def import_device_list(self):
        """Import device list from file"""
        filename = filedialog.askopenfilename(
            filetypes=[("CSV files", "*.csv"), ("JSON files", "*.json"), ("Text files", "*.txt")]
        )
        
        if filename:
            try:
                if filename.endswith('.csv'):
                    with open(filename, 'r') as f:
                        reader = csv.reader(f)
                        next(reader)  # Skip header
                        for row in reader:
                            if len(row) >= 7:
                                self.add_result_to_tree(self.device_tree, row[:7])
                elif filename.endswith('.json'):
                    with open(filename, 'r') as f:
                        devices = json.load(f)
                        for device in devices:
                            self.add_result_to_tree(self.device_tree, [
                                device.get('name', ''),
                                device.get('ip', ''),
                                device.get('type', ''),
                                device.get('location', ''),
                                device.get('status', 'Unknown'),
                                device.get('last_check', 'Never'),
                                device.get('notes', '')
                            ])
                
                messagebox.showinfo("Import", f"Devices imported from {filename}")
                
            except Exception as e:
                messagebox.showerror("Import Error", f"Error importing devices: {str(e)}")
    
    def export_device_list(self):
        """Export device list to file"""
        filename = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("JSON files", "*.json"), ("Text files", "*.txt")]
        )
        
        if filename:
            try:
                with open(filename, 'w', newline='') as f:
                    if filename.endswith('.csv'):
                        writer = csv.writer(f)
                        writer.writerow(["Name", "IP Address", "Type", "Location", "Status", "Last Check", "Notes"])
                        for item in self.device_tree.get_children():
                            writer.writerow(self.device_tree.item(item)['values'])
                    elif filename.endswith('.json'):
                        devices = []
                        for item in self.device_tree.get_children():
                            values = self.device_tree.item(item)['values']
                            devices.append({
                                "name": values[0],
                                "ip": values[1],
                                "type": values[2],
                                "location": values[3],
                                "status": values[4],
                                "last_check": values[5],
                                "notes": values[6] if len(values) > 6 else ""
                            })
                        json.dump(devices, f, indent=2)
                    else:
                        f.write("Name,IP Address,Type,Location,Status,Last Check,Notes\n")
                        for item in self.device_tree.get_children():
                            f.write(",".join(map(str, self.device_tree.item(item)['values'])) + "\n")
                
                messagebox.showinfo("Export", f"Device list exported to {filename}")
                
            except Exception as e:
                messagebox.showerror("Export Error", f"Error exporting devices: {str(e)}")
    
    # Settings methods
    def save_settings(self):
        """Save application settings"""
        settings = {
            'default_timeout': self.default_timeout.get(),
            'max_threads': self.max_threads.get(),
            'theme': self.theme_var.get(),
            'default_ssh_port': self.default_ssh_port.get(),
            'default_snmp_community': self.default_snmp_community.get()
        }
        
        try:
            with open('network_tool_settings.json', 'w') as f:
                json.dump(settings, f, indent=2)
            messagebox.showinfo("Settings", "Settings saved successfully")
        except Exception as e:
            messagebox.showerror("Settings Error", f"Error saving settings: {str(e)}")
    
    def load_settings(self):
        """Load application settings"""
        try:
            if os.path.exists('network_tool_settings.json'):
                with open('network_tool_settings.json', 'r') as f:
                    settings = json.load(f)
                
                self.default_timeout.delete(0, 'end')
                self.default_timeout.insert(0, settings.get('default_timeout', '5'))
                
                self.max_threads.delete(0, 'end')
                self.max_threads.insert(0, settings.get('max_threads', '20'))
                
                self.theme_var.set(settings.get('theme', 'dark'))
                
                self.default_ssh_port.delete(0, 'end')
                self.default_ssh_port.insert(0, settings.get('default_ssh_port', '22'))
                
                self.default_snmp_community.delete(0, 'end')
                self.default_snmp_community.insert(0, settings.get('default_snmp_community', 'public'))
                
                self.log_message("Settings loaded successfully")
        except Exception as e:
            self.log_message(f"Error loading settings: {str(e)}")
    
    def reset_settings(self):
        """Reset settings to defaults"""
        self.default_timeout.set("5")
        self.max_threads.set("20")
        self.theme_var.set("dark")
        self.default_ssh_port.insert(0, "22")
        self.default_snmp_community.insert(0, "public")
        messagebox.showinfo("Settings", "Settings reset to defaults")
    
    def apply_theme(self):
        """Apply theme changes"""
        theme = self.theme_var.get()
        # This would implement theme switching
        messagebox.showinfo("Theme", f"Theme switched to {theme}")
    
    # Utility and help methods
    def show_network_calculator(self):
        """Show network calculator dialog"""
        dialog = tk.Toplevel(self.root)
        dialog.title("Network Calculator")
        dialog.geometry("400x300")
        
        ttk.Label(dialog, text="Enter IP Address and Subnet Mask:").pack(pady=10)
        
        frame = ttk.Frame(dialog)
        frame.pack(pady=10)
        
        ttk.Label(frame, text="IP:").grid(row=0, column=0, sticky='w', padx=5)
        ip_entry = ttk.Entry(frame, width=20)
        ip_entry.grid(row=0, column=1, padx=5)
        
        ttk.Label(frame, text="Subnet Mask:").grid(row=1, column=0, sticky='w', padx=5)
        mask_entry = ttk.Entry(frame, width=20)
        mask_entry.grid(row=1, column=1, padx=5)
        
        def calculate():
            ip = ip_entry.get()
            mask = mask_entry.get()
            try:
                network = ipaddress.ip_network(f"{ip}/{mask}", strict=False)
                result = f"""
Network Address: {network.network}
Broadcast Address: {network.broadcast_address}
First Usable IP: {network.network + 1}
Last Usable IP: {network.broadcast_address - 1}
Total Hosts: {network.num_addresses - 2}
Subnet Mask: {network.netmask}
Wildcard Mask: {network.hostmask}
                """
                messagebox.showinfo("Network Information", result)
            except Exception as e:
                messagebox.showerror("Error", f"Invalid IP or subnet mask: {str(e)}")
        
        ttk.Button(frame, text="Calculate", command=calculate).grid(row=2, column=0, columnspan=2, pady=10)
    
    def show_subnet_calculator(self):
        """Show subnet calculator dialog"""
        messagebox.showinfo("Feature", "Subnet calculator feature - Coming Soon!")
    
    def show_mac_lookup(self):
        """Show MAC address lookup dialog"""
        messagebox.showinfo("Feature", "MAC address lookup feature - Coming Soon!")
    
    def show_about(self):
        """Show about dialog"""
        about_text = """
Advanced Network Automation Tool v2.4 Final

Author: Dr. Mohammed Tawfik (kmkhol01@gmail.com)

Features:
• Network Scanner with multi-threading
• Port Scanner with various scan types
• Ping Monitor with statistics
• SSH Automation with Paramiko
• Configuration Backup
• SNMP Monitor
• Network Tools (Traceroute, DNS, etc.)
• Device Inventory Management

Built with Python and tkinter.
        """
        messagebox.showinfo("About", about_text)
    
    def show_documentation(self):
        """Show documentation"""
        doc_text = """
NETWORK AUTOMATION TOOL DOCUMENTATION

1. NETWORK SCANNER
   - Enter IP range (e.g., 192.168.1.0/24)
   - Configure threads and timeout
   - Click "Start Scan" to begin
   - Results show: IP, hostname, status, response time, MAC, vendor

2. PORT SCANNER
   - Enter target IP or hostname
   - Specify port range (e.g., 1-1000 or 80,443)
   - Choose scan type (TCP Connect/SYN)
   - View open ports and services

3. PING MONITOR
   - Enter target to monitor
   - Set interval and timeout
   - View real-time statistics
   - Export monitoring results

4. SSH AUTOMATION
   - Connect to devices via SSH
   - Execute commands remotely
   - Run scripts on devices

5. CONFIG BACKUP
   - Add devices to backup list
   - Backup configurations automatically
   - Schedule regular backups

6. SNMP MONITOR
   - Monitor devices via SNMP
   - Browse MIBs
   - Get device information

7. NETWORK TOOLS
   - Traceroute, DNS lookup, Whois
   - Bandwidth testing
   - Various network diagnostics

8. DEVICE INVENTORY
   - Manage device database
   - Import/export device lists
   - Search and filter devices

For support, contact: kmkhol01@gmail.com
        """
        messagebox.showinfo("Documentation", doc_text)

def main():
    """Main application entry point"""
    root = tk.Tk()
    app = NetworkAutomationTool(root)
    
    # Handle window closing
    def on_closing():
        if messagebox.askokcancel("Quit", "Do you want to quit?"):
            # Stop all background threads
            app.scanning = False
            app.port_scanning = False
            app.monitoring = False
            app.backup_running = False
            app.snmp_running = False
            app.tool_running = False
            
            # Disconnect SSH if connected
            if hasattr(app, 'ssh_connected') and app.ssh_connected:
                app.disconnect_ssh()
            
            root.destroy()
    
    root.protocol("WM_DELETE_WINDOW", on_closing)
    
    # Start the application
    root.mainloop()

if __name__ == "__main__":
    main()