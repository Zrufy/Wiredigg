import tkinter as tk
from tkinter import ttk, messagebox, filedialog, scrolledtext
import threading
import queue
import time
import numpy as np
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import pickle
import networkx as nx
import ipaddress
import os
import re
import socket
import warnings
import traceback
from ctypes import windll
from add_ico_hook import resource_path

import ctypes
try:
    ctypes.windll.shcore.SetProcessDpiAwareness(2)
except:
    try:
        ctypes.windll.user32.SetProcessDPIAware()
    except:
        pass

ico_path = resource_path("wiredigg.ico")


warnings.filterwarnings('ignore')

class NetworkAnalyzer:
    def __init__(self, root):
        self.root = root
        self.root.title("Wiredigg - Advanced Network Analysis Tool")
        self.root.geometry("1200x900")
        self.root.configure(bg="#2e3440")
        root.iconbitmap(ico_path)
        
        # Nordic dark theme setup

        self.style = ttk.Style()
        self.style.theme_use("clam")
        
        # Basic setup -dark theme with light text

        self.style.configure(".", background="#2e3440", foreground="#eceff4")
        self.style.configure("TFrame", background="#2e3440")
        self.style.configure("TLabel", background="#2e3440", foreground="#eceff4")
        self.style.configure("TButton", background="#5e81ac", foreground="#eceff4")
        self.style.configure("TNotebook", background="#2e3440", foreground="#eceff4")
        self.style.configure("TNotebook.Tab", background="#3b4252", foreground="#eceff4")
        self.style.configure("TCheckbutton", background="#2e3440", foreground="#eceff4")
        
        # Mapping to keep text visible in all states

        self.style.map("TButton",
            foreground=[("active", "#ffffff"), ("disabled", "#a0a0a0")],
            background=[("active", "#7799cc"), ("disabled", "#4c6a8f")]
        )
        self.style.map("TNotebook.Tab", background=[("selected", "#5e81ac")])
        
        # Styles for black text dialogs

        self.style.configure("Dialog.TFrame", background="white")
        self.style.configure("Dialog.TLabel", background="white", foreground="black")
        self.style.configure("Dialog.TButton", background="#e0e0e0", foreground="black")
        self.style.map("Dialog.TButton",
            foreground=[("active", "black"), ("disabled", "gray")],
            background=[("active", "#d0d0d0"), ("disabled", "#f0f0f0")]
        )
        self.style.configure("Dialog.TCheckbutton", background="white", foreground="black")
        self.style.configure("Dialog.TCombobox", foreground="black", fieldbackground="white")
        self.style.map("TCombobox",
            foreground=[("active", "black"), ("disabled", "gray")],
            fieldbackground=[("readonly", "white")]
        )
        
        # Global configuration for black text widgets

        root.option_add('*TCombobox*Listbox.foreground', 'black')
        root.option_add('*TCombobox*Listbox.background', 'white')
        
        # State variables

        self.is_capturing = False
        self.captured_packets = []
        self.packet_queue = queue.Queue()
        self.ml_model = None
        self.ml_model_trained = False
        self.threat_db = None
        self.initialize_ml_model()
        self.start_background_training()
        self.selected_interface = tk.StringVar()
        self.filter_text = tk.StringVar()
        self.dark_mode = tk.BooleanVar(value=True)
        self.promisc_mode = tk.BooleanVar(value=False)
        
        # Initialize threat database

        self.init_threat_database()
        
        # Load ML model

        self.load_ml_model()
        
        # Create main layout

        self.create_main_layout()
        
        # Initialize network interfaces

        self.interfaces = self.get_network_interfaces()
        self.interface_dropdown['values'] = self.interfaces
        if self.interfaces:
            self.selected_interface.set(self.interfaces[0])
        
        # Configure timer for UI refresh

        self.root.after(100, self.process_packet_queue)

    def create_main_layout(self):
        # Main frame

        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Top frame for controls

        control_frame = ttk.Frame(main_frame)
        control_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Frame for the first row of controls (interface, filters, buttons)

        top_row_frame = ttk.Frame(control_frame)
        top_row_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Dropdown for interfaces

        ttk.Label(top_row_frame, text="Interface:", style="BlackText.TLabel",foreground="white").pack(side=tk.LEFT, padx=2)
        self.interface_dropdown = ttk.Combobox(top_row_frame, textvariable=self.selected_interface, width=20, foreground="black")
        self.interface_dropdown.pack(side=tk.LEFT, padx=2)
                
        # Protocol filter

        ttk.Label(top_row_frame, text="Protocol:", style="BlackText.TLabel",foreground="white").pack(side=tk.LEFT, padx=2)
        self.proto_filter_var = tk.StringVar()
        proto_combo = ttk.Combobox(top_row_frame, textvariable=self.proto_filter_var, 
                                values=["", "TCP", "UDP", "ICMP", "HTTP", "HTTPS", "DNS"], width=6, foreground="black")
        proto_combo.pack(side=tk.LEFT, padx=2)
        
        # IP filter

        ttk.Label(top_row_frame, text="IP:", style="BlackText.TLabel",foreground="white").pack(side=tk.LEFT, padx=2)
        self.ip_filter_var = tk.StringVar()
        ip_entry = ttk.Entry(top_row_frame, textvariable=self.ip_filter_var, width=12, foreground="black")
        ip_entry.pack(side=tk.LEFT, padx=2)
        
        # Port filter

        ttk.Label(top_row_frame, text="Port:", style="BlackText.TLabel",foreground="white").pack(side=tk.LEFT, padx=2)
        self.port_filter_var = tk.StringVar()
        port_entry = ttk.Entry(top_row_frame, textvariable=self.port_filter_var, width=5, foreground="black")
        port_entry.pack(side=tk.LEFT, padx=2)
        
        # Filter buttons

        apply_btn = ttk.Button(top_row_frame, text="Apply", command=self.apply_filters, width=7)
        apply_btn.pack(side=tk.LEFT, padx=2)
        
        reset_btn = ttk.Button(top_row_frame, text="Reset", command=self.reset_filters, width=6)
        reset_btn.pack(side=tk.LEFT, padx=2)
                
        # Promiscuous Mode

        promisc_check = ttk.Checkbutton(top_row_frame, text="Promiscuous Mode", variable=self.promisc_mode)
        promisc_check.pack(side=tk.LEFT, padx=2)
    
        
        # Frame for the filter status line (below the first line)

        filter_status_frame = ttk.Frame(control_frame)
        filter_status_frame.pack(fill=tk.X, padx=5, pady=10)
        
        # Filter status label

        self.filter_status = ttk.Label(filter_status_frame, text="No active filters", font=("Arial", 8), foreground="white")
        self.filter_status.pack(side=tk.LEFT, padx=5,pady=15)
        
        # Add tooltip to help user

        self.create_tooltip(proto_combo, "Select the protocol to filter")
        self.create_tooltip(ip_entry, "Filter by source or destination IP address")
        self.create_tooltip(port_entry, "Filter by source or destination port")
        self.create_tooltip(apply_btn, "Apply selected filters")
        self.create_tooltip(reset_btn, "Remove all filters")
        
        # Control buttons

        self.start_button = ttk.Button(control_frame, text="Start capture", command=self.start_capture)
        self.start_button.pack(side=tk.LEFT, padx=5)
        
        self.stop_button = ttk.Button(control_frame, text="Stop capture", command=self.stop_capture, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=5)
        
        save_button = ttk.Button(control_frame, text="Save capture", command=self.save_capture)
        save_button.pack(side=tk.LEFT, padx=5)
        
        load_button = ttk.Button(control_frame, text="Load capture", command=self.load_capture)
        load_button.pack(side=tk.LEFT, padx=5)

        mlbutton_button = ttk.Button(control_frame, text="Reset ML Model", command=self.reset_ml_model)
        mlbutton_button.pack(side=tk.LEFT, padx=5)

        test_button = ttk.Button(control_frame, text="Generate test traffic", command=self.generate_test_traffic)
        test_button.pack(side=tk.LEFT, padx=5)
        
        info_button = ttk.Button(control_frame, text="Interface info", command=self.show_interface_info)
        info_button.pack(side=tk.LEFT, padx=5)

        simple_send_button = ttk.Button(control_frame, text="Send Simple Package", command=self.send_simple_packet)
        simple_send_button.pack(side=tk.LEFT, padx=5)
        
        # Notebook for cards

        self.notebook = ttk.Notebook(main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Packages tab

        packets_frame = ttk.Frame(self.notebook)
        self.notebook.add(packets_frame, text="Pacchetti")
        
        # First define the columns

        packet_columns = ("No.", "Time", "Source", "Destination", "Protocol", "Length", "Information")

        # Then create and configure the package table

        self.setup_virtual_treeview = ttk.Treeview(packets_frame, columns=packet_columns, show="headings")
        self.setup_virtual_treeview.bind("<KeyRelease-Up>", self.on_packet_select)
        self.setup_virtual_treeview.bind("<KeyRelease-Down>", self.on_packet_select)
        self.setup_virtual_treeview.bind("<<TreeviewSelect>>", self.on_packet_select)
                
        for col in packet_columns:
            self.setup_virtual_treeview.heading(col, text=col)
            width = 100 if col != "Information" else 300
            self.setup_virtual_treeview.column(col, width=width)

        self.setup_virtual_treeview.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.setup_virtual_treeview.bind("<ButtonRelease-1>", self.on_packet_select)

        # Scrollbar for package table

        packet_scrollbar = ttk.Scrollbar(packets_frame, orient=tk.VERTICAL, command=self.setup_virtual_treeview.yview)
        packet_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.setup_virtual_treeview.configure(yscrollcommand=packet_scrollbar.set)

        # Package details frame

        self.packet_details_frame = ttk.Frame(packets_frame)
        self.packet_details_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        self.packet_details = ttk.Treeview(self.packet_details_frame, show="tree")
        self.packet_details.pack(fill=tk.BOTH, expand=True, side=tk.LEFT)

        packet_details_scrollbar = ttk.Scrollbar(self.packet_details_frame, orient=tk.VERTICAL, command=self.packet_details.yview)
        packet_details_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.packet_details.configure(yscrollcommand=packet_details_scrollbar.set)

        # Now that packets_frame is configured, add the options frame

        view_options_frame = ttk.LabelFrame(self.root, text="Viewing options")
        view_options_frame.pack(fill=tk.X, padx=10, pady=5)

        # Variable for auto-scroll state

        self.auto_scroll_var = tk.BooleanVar(value=True)  # Active by default


        # Checkbox for automatic scrolling

        auto_scroll_check = ttk.Checkbutton(
            view_options_frame,
            text="Scroll automatico",
            variable=self.auto_scroll_var
        )
        auto_scroll_check.pack(side=tk.LEFT, padx=10, pady=5)

        # Optional tooltip

        if hasattr(self, 'create_tooltip'):
            self.create_tooltip(auto_scroll_check, 
                            "If enabled, the view automatically scrolls to show new packages")
        
        # Statistics tab

        stats_frame = ttk.Frame(self.notebook)
        self.notebook.add(stats_frame, text="Statistics")
        
        # Graphs for statistics

        self.stats_notebook = ttk.Notebook(stats_frame)
        self.stats_notebook.pack(fill=tk.BOTH, expand=True)
        
        # Protocols tab

        protocols_frame = ttk.Frame(self.stats_notebook)
        self.stats_notebook.add(protocols_frame, text="Protocols")
        
        self.protocol_fig = plt.Figure(figsize=(6, 5), dpi=100)
        self.protocol_canvas = FigureCanvasTkAgg(self.protocol_fig, protocols_frame)
        self.protocol_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
        # Flows tab

        flows_frame = ttk.Frame(self.stats_notebook)
        self.stats_notebook.add(flows_frame, text="Network flows")
        
        self.flow_fig = plt.Figure(figsize=(6, 5), dpi=100)
        self.flow_canvas = FigureCanvasTkAgg(self.flow_fig, flows_frame)
        self.flow_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
        # Safety tab

        security_frame = ttk.Frame(self.notebook)
        self.notebook.add(security_frame, text="Security Analysis")

        # Add control buttons

        security_controls = ttk.Frame(security_frame)
        security_controls.pack(fill=tk.X, padx=5, pady=5)

        ttk.Button(security_controls, text="Analyze Threats", command=self.analyze_threats).pack(side=tk.LEFT, padx=5)
        ttk.Button(security_controls, text="ML Detection", command=self.run_anomaly_detection).pack(side=tk.LEFT, padx=5)
        ttk.Button(security_controls, text="Batch Actions", command=self.create_batch_action_dialog).pack(side=tk.LEFT, padx=5)

        # Create tree frame to contain table and scrollbars

        tree_frame = ttk.Frame(security_frame)
        tree_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Create threat table with multi-selection support

        threat_columns = ("Timestamp", "Source", "Destination", "Threat type", "Severity", "Description")
        self.threat_tree = ttk.Treeview(tree_frame, columns=threat_columns, show="headings")

        for col in threat_columns:
            self.threat_tree.heading(col, text=col)
            width = 100 if col not in ("Description", "Threat type") else 200
            self.threat_tree.column(col, width=width)

        # Vertical scrollbar

        vsb = ttk.Scrollbar(tree_frame, orient="vertical", command=self.threat_tree.yview)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)

        # Horizontal scrollbar

        hsb = ttk.Scrollbar(tree_frame, orient="horizontal", command=self.threat_tree.xview)
        hsb.pack(side=tk.BOTTOM, fill=tk.X)

        # Configure the Treeview to use scrollbars

        self.threat_tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        self.threat_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # Configure tag colors for threat severity

        self.threat_tree.tag_configure('high_severity', background='#ffcccc')
        self.threat_tree.tag_configure('medium_severity', background='#ffffcc')
        self.threat_tree.tag_configure('low_severity', background='#e6ffe6')
        self.threat_tree.tag_configure('false_positive', foreground='gray')
        
        # Configure keyboard shortcuts for multi-selection operations

        self.threat_tree.bind("<Control-a>", self.select_all_threats)  # Ctrl+A to select all

        
        # Double-click still shows details

        self.threat_tree.bind("<Double-1>", self.show_threat_details)
        
        # IoT/Cloud Tab

        iot_frame = ttk.Frame(self.notebook)
        self.notebook.add(iot_frame, text="IoT/Cloud")
        
        iot_controls = ttk.Frame(iot_frame)
        iot_controls.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Button(iot_controls, text="Identify IoT devices", command=self.detect_iot_devices).pack(side=tk.LEFT, padx=5)
        ttk.Button(iot_controls, text="Analyze cloud protocols", command=self.analyze_cloud_protocols).pack(side=tk.LEFT, padx=5)
        
        # IoT device table

        iot_columns = ("IP", "Device type", "Manufacturer", "Protocols", "Traffic", "Risk")
        self.iot_tree = ttk.Treeview(iot_frame, columns=iot_columns, show="headings")
        
        for col in iot_columns:
            self.iot_tree.heading(col, text=col)
            self.iot_tree.column(col, width=100)
        
        self.iot_tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Predictive analysis card

        predictive_frame = ttk.Frame(self.notebook)
        self.notebook.add(predictive_frame, text="Predictive analytics")
        
        predict_controls = ttk.Frame(predictive_frame)
        predict_controls.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Button(predict_controls, text="Generate predictions", command=self.generate_predictions).pack(side=tk.LEFT, padx=5)
        
        self.predict_fig = plt.Figure(figsize=(6, 5), dpi=100)
        self.predict_canvas = FigureCanvasTkAgg(self.predict_fig, predictive_frame)
        self.predict_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
        # Status bar

        self.status_bar = ttk.Label(self.root, text="Wiredigg Ready - Select an Interface and Start Capturing", relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)



    def initialize_ml_model(self):
        """Initialize the machine learning model with incremental support"""
        from sklearn.linear_model import SGDOneClassSVM
        from sklearn.preprocessing import StandardScaler
        
        # Initialize the model and scaler

        self.ml_model = SGDOneClassSVM(nu=0.05, random_state=42)
        self.scaler = StandardScaler()
        self.ml_model_trained = False
        
        # Variables for automatic training

        self.training_in_progress = False
        self.last_trained_packet_count = 0
        self.training_threshold = 500  # Number of new packages that trigger training

        
        # Try loading a pre-trained model if it exists

        self.load_ml_model()
        
        print("Initialized incremental ML model")

    def start_background_training(self):
        """Start the automatic training process in the background"""
        def check_for_training():
            #Check if we have enough new packages to justify a training

            if hasattr(self, 'captured_packets') and len(self.captured_packets) > 0:
                current_packet_count = len(self.captured_packets)
                new_packets = current_packet_count - self.last_trained_packet_count
                
                # If we have enough new packages and there is no training already underway

                if new_packets >= self.training_threshold and not self.training_in_progress:
                    self.background_train_model()
            
            # Check again after 30 seconds

            self.root.after(30000, check_for_training)
        
        # Start the first check after 10 seconds from the application startup

        self.root.after(10000, check_for_training)
        print("Automatic background training configured")

    def background_train_model(self):
        """Train the model in the background with incremental learning"""
        if self.training_in_progress:
            return
            
        self.training_in_progress = True
        
        # Update status in status bar

        original_status = self.status_bar.cget("text")
        self.status_bar.config(text="ML model training in the background...")
        
        def run_training():
            try:
                # Check the model type

                from sklearn.linear_model import SGDOneClassSVM
                from sklearn.ensemble import IsolationForest
                
                if isinstance(self.ml_model, IsolationForest):
                    print("WARNING: IsolationForest model detected instead of SGDOneClassSVM")
                    print("Reinitializing the model to support incremental learning...")
                    
                    # Create a new SGDOneClassSVM model

                    self.ml_model = SGDOneClassSVM(nu=0.05, random_state=42)
                    self.ml_model_trained = False
                    print("Model replaced with SGDOneClassSVM")
                
                # Use only new packages for incremental upgrade

                if self.ml_model_trained:
                    packets_to_train = self.captured_packets[self.last_trained_packet_count:]
                    training_mode = "incremental"
                else:
                    # For the first training, use all packages

                    packets_to_train = self.captured_packets
                    training_mode = "initial"
                
                if not packets_to_train:
                    print("No training packages available")
                    return
                    
                print(f"Start training {training_mode} in background with {len(packets_to_train)} packets")
                
                # Extract features with validity checks

                features = []
                for packet in packets_to_train:
                    packet_features = self.extract_ml_features(packet)
                    if packet_features:
                        # Make sure all features are numbers

                        try:
                            numeric_features = [float(f) for f in packet_features]
                            features.append(numeric_features)
                        except (ValueError, TypeError) as e:
                            print(f"Ignored non-numeric feature: {e}")
                
                if not features:
                    print("Unable to extract valid features from packages")
                    return
                    
                # Make sure all lines are the same length

                feature_lengths = [len(f) for f in features]
                if len(set(feature_lengths)) > 1:
                    print(f"NOTICE: Different lengths of features: {set(feature_lengths)}")
                    # Find the most common length

                    from collections import Counter
                    common_length = Counter(feature_lengths).most_common(1)[0][0]
                    print(f"Normalization to length {common_length}")
                    
                    # Normalize all lines to the most common length

                    normalized_features = []
                    for f in features:
                        if len(f) == common_length:
                            normalized_features.append(f)
                        elif len(f) < common_length:
                            # If too short, add zeros

                            normalized_features.append(f + [0.0] * (common_length - len(f)))
                        else:
                            # If too long, cut it off

                            normalized_features.append(f[:common_length])
                    
                    features = normalized_features
                
                # Convert to numpy array with explicit type

                try:
                    X = np.array(features, dtype=np.float64)
                    print(f"Array X created successfully: shape {X.shape}")
                except Exception as e:
                    print(f"Error converting to numpy array: {str(e)}")
                    return
                
                # Different management for first training vs subsequent updates

                if not self.ml_model_trained:
                    # First time: Full fit with scaler adaptation

                    print("Running fit_transform on scaler")
                    X_scaled = self.scaler.fit_transform(X)
                    print("Initial model training")
                    self.ml_model.fit(X_scaled)
                    self.ml_model_trained = True
                else:
                    # Later updates: use partial_fit and existing scaler

                    print("Running transform on existing scaler")
                    X_scaled = self.scaler.transform(X)
                    print("Updating model with partial_fit")
                    
                    # Check that the model supports partial_fit

                    if hasattr(self.ml_model, 'partial_fit'):
                        self.ml_model.partial_fit(X_scaled)
                    else:
                        print("NOTICE: The model does not support partial_fit. Use full fit.")
                        self.ml_model.fit(X_scaled)
                
                # Update the processed packet counter

                self.last_trained_packet_count = len(self.captured_packets)
                
                # Save the model

                self.save_ml_model()
                
                print(f"Training {training_mode} in background completato con {len(features)} pacchetti")
                
                # Update the status in the status bar in the main thread

                self.root.after(0, lambda: self.status_bar.config(
                    text=f"Training ML {training_mode} completato ({len(features)} pacchetti analizzati)"))
                
                # Restore the original state after 5 seconds

                self.root.after(5000, lambda: self.status_bar.config(text=original_status))
                
            except Exception as e:
                print(f"Error in background training: {str(e)}")
                traceback.print_exc()
            finally:
                # Always set training_in_progress to False when it finishes

                self.training_in_progress = False
        
        # Start training in a separate thread

        training_thread = threading.Thread(target=run_training)
        training_thread.daemon = True
        training_thread.start()

    def save_ml_model(self):
        """Save the ML model on disk"""
        if not hasattr(self, 'ml_model') or not self.ml_model_trained:
            return
            
        try:
            import pickle
            import os
            
            # Create directories if it doesn't exist

            os.makedirs('models', exist_ok=True)
            
            # Save the model with updated name

            with open('models/sgd_oneclass_svm_model.pkl', 'wb') as f:
                pickle.dump(self.ml_model, f)
                
            # Save the scaler

            with open('models/scaler.pkl', 'wb') as f:
                pickle.dump(self.scaler, f)
                
            # Also save the meter of processed packages

            with open('models/last_trained_count.pkl', 'wb') as f:
                pickle.dump(self.last_trained_packet_count, f)
                
            print("Modello ML incrementale salvato su disco")
        except Exception as e:
            print(f"Errore nel salvataggio del modello: {str(e)}")

    def load_ml_model(self):
        """Load incremental ML model from disk if it exists"""
        try:
            import pickle
            import os
            
            # Check if the files exist

            model_path = 'models/sgd_oneclass_svm_model.pkl'
            scaler_path = 'models/scaler.pkl'
            count_path = 'models/last_trained_count.pkl'
            
            if os.path.exists(model_path) and os.path.exists(scaler_path):
                # Load the model

                with open(model_path, 'rb') as f:
                    self.ml_model = pickle.load(f)
                    
                # Load the scaler

                with open(scaler_path, 'rb') as f:
                    self.scaler = pickle.load(f)
                    
                # Load the processed packet counter if it exists

                if os.path.exists(count_path):
                    with open(count_path, 'rb') as f:
                        self.last_trained_packet_count = pickle.load(f)
                
                self.ml_model_trained = True
                print(f"Incremental ML model loaded from disk (trained on {self.last_trained_packet_count} packets)")
                return True
                
            # Check if old Isolation Forest template files exist
            # for backwards compatibility

            elif os.path.exists('models/isolation_forest_model.pkl'):
                print("Found old Isolation Forest model. A new SGDOneClassSVM model will be created")
                # We don't load the old model, let a new model be created

                
        except Exception as e:
            print(f"Error loading template: {str(e)}")
        
        return False

    def setup_virtual_treeview(self):
        """Set up a virtual Treeview that loads only visible items"""        
        # Create the standard Treeview

        self.setup_virtual_treeview = ttk.Treeview(self.packets_frame, columns=self.packet_columns, show="headings")
        
        # Create a separate data structure to store all the packets

        if not hasattr(self, 'all_packets'):
            self.all_packets = []  # Store all package data here

        
        # Configure scrolling events

        vsb = ttk.Scrollbar(self.packets_frame, orient="vertical", command=self.on_treeview_scroll)
        self.setup_virtual_treeview.configure(yscrollcommand=vsb.set)
        vsb.pack(side='right', fill='y')
        self.setup_virtual_treeview.pack(expand=True, fill='both')
        
        # Also configure the window resize event

        self.root.bind("<Configure>", lambda e: self.after(100, self.update_visible_items))
        
        # Number of items to display (buffer)

        self.visible_buffer = 100  # Visible elements + buffers above and below

        
        # Configure the scroll event handler

        self.setup_virtual_treeview.bind("<<TreeviewSelect>>", self.on_packet_select)

    def on_treeview_scroll(self, *args):
        """# Configure the scroll event handler"""
        # Apply normal scrolling

        self.setup_virtual_treeview.yview(*args)
        
        # Update visible items

        self.after(10, self.update_visible_items)

    def update_visible_items(self):
        """Refresh the visible items in the Treeview"""
        if not hasattr(self, 'all_packets') or not self.all_packets:
            return
        
        # Get the current scroll position

        try:
            first, last = self.setup_virtual_treeview.yview()
        except:
            return
        
        # Calculate which elements should be visible

        total_items = len(self.all_packets)
        if total_items == 0:
            return
            
        # Calculate the approximate index of visible elements

        first_visible_index = int(first * total_items)
        last_visible_index = int(last * total_items) + 1
        
        # Add a buffer for smooth scrolling

        buffer_size = self.visible_buffer // 2
        start_index = max(0, first_visible_index - buffer_size)
        end_index = min(total_items, last_visible_index + buffer_size)
        
        # Get the IDs of the currently displayed items

        current_items = self.setup_virtual_treeview.get_children()
        
        # If there are too many elements, remove the ones out of view

        if len(current_items) > self.visible_buffer * 2:
            # Calculate which elements are outside the visible area + buffer

            visible_range = set(range(start_index, end_index))
            
            # Create a mapping between the indices and the ID of the elements

            item_indices = {}
            for i, item_id in enumerate(current_items):
                values = self.setup_virtual_treeview.item(item_id, 'values')
                if values and len(values) > 0:
                    try:
                        packet_index = int(values[0]) - 1  # The first value is the package index

                        item_indices[packet_index] = item_id
                    except:
                        continue
            
            # Remove the elements that are outside the sight

            for idx, item_id in item_indices.items():
                if idx not in visible_range:
                    self.setup_virtual_treeview.delete(item_id)
        
        # Add the missing elements in the current view

        existing_indices = set()
        for item_id in self.setup_virtual_treeview.get_children():
            values = self.setup_virtual_treeview.item(item_id, 'values')
            if values and len(values) > 0:
                try:
                    existing_indices.add(int(values[0]) - 1)  # The first value is the package index

                except:
                    continue
        
        # Add the missing elements

        for i in range(start_index, end_index):
            if i < len(self.all_packets) and i not in existing_indices:
                # Enter the element from our All_packets archive

                self.setup_virtual_treeview.insert("", "end", values=self.all_packets[i])


    def on_packet_select(self, event=None):
        """Manages the selection of a package in the list"""
        selected_items = self.setup_virtual_treeview.selection()
        if not selected_items:
            return
            
        # Get the selected element

        item_id = selected_items[0]
        
        # Make sure the element is visible

        self.setup_virtual_treeview.see(item_id)
        
        # Get the package index

        values = self.setup_virtual_treeview.item(item_id, 'values')
        if values:
            try:
                packet_index = int(values[0]) - 1  # I subtract 1 for the indices to start from 0

                if 0 <= packet_index < len(self.captured_packets):
                    packet = self.captured_packets[packet_index]
                    # Clean the previous details

                    for item in self.packet_details.get_children():
                        self.packet_details.delete(item)
                    
                    # View details of the package

                    self.display_packet_details(packet)
            except (ValueError, IndexError) as e:
                print(f"Error in the recovery of the package: {e}")

    
    def create_tooltip(self, widget, text):
        "" "Create a tooltip for specified widget" ""
        def enter(event):
            x, y, _, _ = widget.bbox("insert")
            x += widget.winfo_rootx() + 25
            y += widget.winfo_rooty() + 20
            
            # Create a top-level window

            self.tooltip = tk.Toplevel(widget)
            self.tooltip.wm_overrideredirect(True)
            self.tooltip.wm_geometry(f"+{x}+{y}")
            
            label = ttk.Label(self.tooltip, text=text, background="#ffffe0", relief="solid", borderwidth=1,foreground="black")
            label.pack()
        
        def leave(event):
            if hasattr(self, 'tooltip'):
                self.tooltip.destroy()
        
        widget.bind("<Enter>", enter)
        widget.bind("<Leave>", leave)

    def apply_filters(self):
        "" "Apply the selected filters" ""
        # Get the values ​​of the filters

        proto = self.proto_filter_var.get()
        ip = self.ip_filter_var.get()
        port = self.port_filter_var.get()
        
        # Check if there are active filters

        if not proto and not ip and not port:
            messagebox.showinfo("Filters", "No specified filter")
            self.reset_filters()
            return
        
        # Update the State of the Filter

        filter_desc = []
        if proto:
            filter_desc.append(f"Protocol: {proto}")
        if ip:
            filter_desc.append(f"IP: {ip}")
        if port:
            filter_desc.append(f"Port: {port}")
        
        status_text = "Active filters: " + ", ".join(filter_desc)
        self.filter_status.config(text=status_text)
        
        # If we are in capture mode, apply the filters immediately

        if self.is_capturing:
            # Delete the current view

            for item in self.setup_virtual_treeview.get_children():
                self.setup_virtual_treeview.delete(item)
            
            # Reset the indexes

            self.packet_indices = {}
            
            # Reapply the filters you packages already captured and update the view

            self.apply_filters_to_captured_packets()
        
        messagebox.showinfo("Filters", "Successful filters applied")

    def reset_filters(self):
        """Removes all filters"""
        # Reset controls

        self.proto_filter_var.set("")
        self.ip_filter_var.set("")
        self.port_filter_var.set("")
        
        # Update the state

        self.filter_status.config(text="No active filter")
        
        # If we are in capture mode, update the view

        if self.is_capturing:
            # Delete the current view

            for item in self.setup_virtual_treeview.get_children():
                self.setup_virtual_treeview.delete(item)
            
            # Reset the indexes

            self.packet_indices = {}
            
            # Reapply the packages without filter

            self.apply_filters_to_captured_packets()
        
        messagebox.showinfo("Filters", "Removed filters")

        

    def apply_filters_to_captured_packets(self):
        """Apply the filters to the packages already captured and update the view"""
        # Get the values ​​of the filters

        proto_filter = self.proto_filter_var.get().upper()
        ip_filter = self.ip_filter_var.get()
        port_filter = self.port_filter_var.get()
        
        # Elaborates all packages

        filtered_packets = []
        for packet in self.captured_packets:
            # Apply filters

            should_include = True
            
            # Protocol filter

            if proto_filter:
                if proto_filter == "TCP" and packet.get('proto_name') not in ['TCP', 'HTTP', 'HTTPS']:
                    should_include = False
                elif proto_filter == "UDP" and packet.get('proto_name') not in ['UDP', 'DNS']:
                    should_include = False
                elif proto_filter == "ICMP" and packet.get('proto_name') != 'ICMP':
                    should_include = False
                elif proto_filter == "HTTP" and packet.get('proto_name') != 'HTTP':
                    should_include = False
                elif proto_filter == "HTTPS" and packet.get('proto_name') != 'HTTPS':
                    should_include = False
                elif proto_filter == "DNS" and packet.get('proto_name') != 'DNS':
                    should_include = False
            
            # IP filter

            if should_include and ip_filter:
                if ip_filter not in packet['src'] and ip_filter not in packet['dst']:
                    should_include = False
            
            # Port filter

            if should_include and port_filter:
                try:
                    port_num = int(port_filter)
                    if ('sport' not in packet or packet['sport'] != port_num) and \
                    ('dport' not in packet or packet['dport'] != port_num):
                        should_include = False
                except ValueError:
                    # If it is not a valid number, we ignore this filter

                    pass
            
            if should_include:
                filtered_packets.append(packet)
        
        # Update the view with filtered packages

        for i, packet in enumerate(filtered_packets):
            # Format the data for viewing

            time_str = time.strftime('%H:%M:%S', time.localtime(packet['time']))
            ms = int((packet['time'] % 1) * 1000)
            time_str = f"{time_str}.{ms:03d}"
            
            proto_name = packet.get('proto_name', 'Unknown')
            
            # Prepare the information on the doors if available

            port_info = ""
            if 'sport' in packet and 'dport' in packet:
                port_info = f":{packet['sport']} → :{packet['dport']}"
            
            # Prepare specific additional information for protocol

            info = ""
            if proto_name == 'TCP':
                info = packet.get('flags_str', '')
            elif proto_name == 'ICMP':
                icmp_type = packet.get('type', 0)
                if icmp_type == 8:
                    info = "Echo request"
                elif icmp_type == 0:
                    info = "Echo reply"
                else:
                    info = f"Type {icmp_type}"
            elif proto_name == 'HTTP':
                # Extract the first line of the Payload Http if present

                if 'payload' in packet:
                    try:
                        payload_str = packet['payload'].decode('utf-8', errors='ignore')
                        first_line = payload_str.split('\r\n')[0]
                        info = first_line[:50]  # Limit the length

                    except:
                        info = "HTTP Data"
            
            # Insert the table

            item_id = self.setup_virtual_treeview.insert('', 'end', values=(
                i + 1,  # Sequential number

                time_str,
                proto_name,
                packet['dst'],
                packet['src'],
                port_info,
                packet['len'],
                info
            ))
            
            # Associates the index of the ED of the element package in the table

            self.packet_indices[item_id] = self.captured_packets.index(packet)
        
        # Update the status bar

        self.status_bar.config(text=f"Packets displayed: {len(filtered_packets)} di {len(self.captured_packets)}")


    def send_simple_packet(self):
        """Send a packet using high-level socket with input validation"""
        try:
            # Create a simplified window

            send_window = tk.Toplevel(self.root)
            send_window.title("Send simple packet")
            send_window.geometry("400x350")  # Optimized height

            send_window.transient(self.root)
            send_window.iconbitmap(ico_path)
            send_window.grab_set()
            send_window.resizable(False, False)  # Prevents downsizing


            # Main frame with uniform padding

            main_frame = ttk.Frame(send_window, padding="10 10 10 10")
            main_frame.pack(fill=tk.BOTH, expand=True)

            # Input fields with more compact grid

            ttk.Label(main_frame, text="IP destination:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
            dst_ip_var = tk.StringVar(value="127.0.0.1")
            dst_ip_entry = ttk.Entry(main_frame, textvariable=dst_ip_var, width=20,foreground="black")
            dst_ip_entry.grid(row=0, column=1, padx=5, pady=5, sticky=tk.W)

            # Error message for IP (inline)

            ip_error_var = tk.StringVar()
            ip_error_label = ttk.Label(main_frame, textvariable=ip_error_var, foreground="red")
            ip_error_label.grid(row=0, column=2, padx=5, pady=5, sticky=tk.W)

            ttk.Label(main_frame, text="Protocol:").grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
            protocol_var = tk.StringVar(value="TCP")
            protocol_combo = ttk.Combobox(main_frame, textvariable=protocol_var, values=["TCP", "UDP"], state="readonly", width=18,foreground="black")
            protocol_combo.grid(row=1, column=1, padx=5, pady=5, sticky=tk.W)

            ttk.Label(main_frame, text="Port:").grid(row=2, column=0, padx=5, pady=5, sticky=tk.W)
            port_var = tk.IntVar(value=80)
            port_entry = ttk.Entry(main_frame, textvariable=port_var, width=20,foreground="black")
            port_entry.grid(row=2, column=1, padx=5, pady=5, sticky=tk.W)

            # IR PORTE ERROR MESSAGE (INLINE)

            port_error_var = tk.StringVar()
            port_error_label = ttk.Label(main_frame, textvariable=port_error_var, foreground="red")
            port_error_label.grid(row=2, column=2, padx=5, pady=5, sticky=tk.W)

            ttk.Label(main_frame, text="Data:").grid(row=3, column=0, padx=5, pady=5, sticky=tk.W)
            data_var = tk.StringVar(value="Wiredigg Test Packet")
            data_entry = ttk.Entry(main_frame, textvariable=data_var, width=30,foreground="black")
            data_entry.grid(row=3, column=1, padx=5, pady=5, columnspan=2, sticky=tk.EW)

            # Visual separator

            ttk.Separator(main_frame, orient='horizontal').grid(row=4, column=0, columnspan=3, sticky=tk.EW, pady=10)

            # State area with style

            status_frame = ttk.LabelFrame(main_frame, text="Stato")
            status_frame.grid(row=5, column=0, columnspan=3, sticky=tk.EW, padx=5, pady=5)
            status_label = ttk.Label(status_frame, text="Ready for sending", padding="5 5 5 5")
            status_label.pack(fill=tk.X)

            # Suggestion for common services (more compact)

            hint_frame = ttk.LabelFrame(main_frame, text="Common ports")
            hint_frame.grid(row=6, column=0, columnspan=3, sticky=tk.EW, padx=5, pady=5)
            hint_text = "HTTP: 80 • HTTPS: 443 • SSH: 22 • DNS: 53 (UDP) • SMTP: 25"
            ttk.Label(hint_frame, text=hint_text, padding="5 5 5 5").pack(fill=tk.X)

            # Frames for the buttons (aligned on the right)

            button_frame = ttk.Frame(main_frame)
            button_frame.grid(row=7, column=0, columnspan=3, sticky=tk.E, pady=10)
            
            # Function to validate the IP address

            def validate_ip(ip):
                try:
                    # Valid the IP using the iPaddress library

                    ipaddress.ip_address(ip)
                    return True
                except ValueError:
                    return False
            
            # Function to validate the number of door

            def validate_port(port):
                try:
                    port_int = int(port)
                    return 1 <= port_int <= 65535
                except ValueError:
                    return False
            
            # Function to send the package

            def do_send_simple_packet():
                # Reset error messages

                ip_error_var.set("")
                port_error_var.set("")
                
                # Validate IP

                dst_ip = dst_ip_var.get()
                if not validate_ip(dst_ip):
                    ip_error_var.set("Not Valid IP")
                    return
                    
                # Validate port

                try:
                    port = port_var.get()
                    if not validate_port(port):
                        port_error_var.set("Port not valid (1-65535)")
                        return
                except:
                    port_error_var.set("Port non valid")
                    return
                    
                protocol = protocol_var.get()
                data = data_var.get().encode()
                
                status_label.config(text=f"Connection attempt to {dst_ip}:{port}...")
                send_window.update()
                
                if protocol == "TCP":
                    # Create a TCP socket

                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    # Timeout Setout to avoid blocks

                    s.settimeout(3)
                    
                    try:
                        # Connect

                        s.connect((dst_ip, port))
                        status_label.config(text=f"Connected to {dst_ip}:{port}, sending data...")
                        send_window.update()
                        
                        # Send data

                        s.send(data)
                        status_label.config(text="Data sent, awaiting response...")
                        send_window.update()
                        
                        # Receive reply (optional)

                        try:
                            response = s.recv(1024)
                            messagebox.showinfo("Submission completed", f"TCP packet successfully sent to {dst_ip}:{port}\n\response: {response.decode('utf-8', errors='ignore')}")
                        except socket.timeout:
                            messagebox.showinfo("Submission completed", f"TCP packet successfully sent to {dst_ip}:{port}\n\nNo response received.")
                    except ConnectionRefusedError:
                        status_label.config(text="Connection refused! Check if the service is listening.")
                        messagebox.showerror("Error", f"Connection refused from {dst_ip}:{port}\n\nPossible causes:\n- No service listening on port {port}\n- Blocking firewall\n- Service unavailable")
                        return
                    except socket.timeout:
                        status_label.config(text="Connection timeout! The server is not responding.")
                        messagebox.showerror("Error", f"Timeout while connecting to {dst_ip}:{port}")
                        return
                    finally:
                        # Close socket

                        s.close()
                    
                elif protocol == "UDP":
                    # Create a UDP socket

                    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    
                    try:
                        # Send data

                        status_label.config(text=f"Sending UDP packet to {dst_ip}:{port}...")
                        send_window.update()
                        
                        s.sendto(data, (dst_ip, port))
                        status_label.config(text="UDP packet sent, awaiting response...")
                        send_window.update()
                        
                        # Timeout tax for reception

                        s.settimeout(3)
                        # Try to receive an answer (optional)

                        try:
                            response, addr = s.recvfrom(1024)
                            messagebox.showinfo("Sending completed", f"UDP packet successfully sent to {dst_ip}:{port}\n\nResponse from {addr}: {response.decode('utf-8', errors='ignore')}")
                        except socket.timeout:
                            messagebox.showinfo("Sending completed", f"UDP packet successfully sent to {dst_ip}:{port}\n\nNo response received.")
                    except Exception as e:
                        if "refused" in str(e).lower():
                            status_label.config(text="UDP port unreachable!")
                            messagebox.showerror("Error", f"UDP port {port} is unreachable on {dst_ip}")
                        else:
                            status_label.config(text=f"Errore: {str(e)}")
                            messagebox.showerror("Error", f"Error sending UDP packet: {str(e)}")
                        return
                    finally:
                        # Close socket

                        s.close()
                
                send_window.destroy()
                
            # Function to check if the door is open

            def check_port():
                # Reset error messages

                ip_error_var.set("")
                port_error_var.set("")
                
                # Validate IP

                dst_ip = dst_ip_var.get()
                if not validate_ip(dst_ip):
                    ip_error_var.set("Not valid IP")
                    return
                    
                # Validate port

                try:
                    port = port_var.get()
                    if not validate_port(port):
                        port_error_var.set("Invalid port (1-65535)")
                        return
                except:
                    port_error_var.set("Invalid port")
                    return
                    
                protocol = protocol_var.get()
                
                status_label.config(text=f"Check port {port} on {dst_ip}...")
                send_window.update()
                
                if protocol == "TCP":
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(2)
                    result = s.connect_ex((dst_ip, port))
                    s.close()
                    
                    if result == 0:
                        status_label.config(text=f"Port {port} is open on {dst_ip}")
                        messagebox.showinfo("Check port", f"The TCP port {port} is OPEN on {dst_ip}")
                    else:
                        status_label.config(text=f"Port {port} is closed on {dst_ip}")
                        messagebox.showinfo("Check port", f"The TCP port {port} is CLOSED on {dst_ip}")
                else:
                    # For UDP it is more difficult to check, we can only try to send

                    status_label.config(text="Direct UDP port testing is not reliable")
                    messagebox.showinfo("Verify port", "Directly probing UDP ports is not reliable.\nTry sending a packet.")
            
            # Custom style buttons for black text

            self.style.configure("Black.TButton", foreground="black")
            ttk.Button(button_frame, text="Send", command=do_send_simple_packet,).pack(side=tk.RIGHT, padx=5)
            ttk.Button(button_frame, text="Check Port", command=check_port).pack(side=tk.RIGHT, padx=5)
            ttk.Button(button_frame, text="Cancel", command=send_window.destroy).pack(side=tk.RIGHT, padx=5)
            
        except Exception as e:
            messagebox.showerror("Error", f"Error opening window: {str(e)}")


    def get_network_interfaces(self):
        """Gets the list of available network interfaces with only IPv4 addresses"""
        try:
            import netifaces
            
            interfaces = []
            interface_details = {}
            
            for iface in netifaces.interfaces():
                addrs = netifaces.ifaddresses(iface)
                
                # Check only if there is an IPV4 address

                if netifaces.AF_INET in addrs:
                    ip_address = addrs[netifaces.AF_INET][0]['addr']
                    
                    # Get Mac if available

                    mac_address = None
                    if netifaces.AF_LINK in addrs and 'addr' in addrs[netifaces.AF_LINK][0]:
                        mac_address = addrs[netifaces.AF_LINK][0]['addr']
                    
                    # Create a descriptive name

                    if mac_address:
                        description = f"{iface} - {ip_address} ({mac_address})"
                    else:
                        description = f"{iface} - {ip_address}"
                    
                    # Store the mapping and add to the list only interfaces with IPV4

                    interface_details[description] = iface
                    interfaces.append(description)
            
            # Save the details for future use

            self.interface_details = interface_details
            
            return interfaces
        except Exception as e:
            print(f"Error getting interfaces: {str(e)}")
            messagebox.showerror("Error", f"Failed to get network interfaces: {str(e)}")
            return []

    def show_interface_info(self):
        self.root.attributes('-topmost', False)
        """Show detailed information about network interfaces"""
        try:
            import netifaces
            
            info_window = tk.Toplevel(self.root)
            info_window.title("Network interface information")
            info_window.geometry("600x400")
            info_window.transient(self.root)
            info_window.iconbitmap(ico_path)
            info_window.grab_set()
            # Create a scroll text widget

            text_frame = ttk.Frame(info_window)
            text_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
            
            text_widget = tk.Text(text_frame, wrap=tk.WORD)
            text_widget.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
            
            scrollbar = ttk.Scrollbar(text_frame, command=text_widget.yview)
            scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
            text_widget.config(yscrollcommand=scrollbar.set)
            
            # Get and show interface information

            text_widget.insert(tk.END, "AVAILABLE NETWORK INTERFACES:\n\n")
            
            for iface in netifaces.interfaces():
                text_widget.insert(tk.END, f"Interface: {iface}\n")
                
                # Get addresses

                addrs = netifaces.ifaddresses(iface)
                
                # I pv4

                if netifaces.AF_INET in addrs:
                    for addr in addrs[netifaces.AF_INET]:
                        text_widget.insert(tk.END, f"  IPv4: {addr['addr']}\n")
                        if 'netmask' in addr:
                            text_widget.insert(tk.END, f"  Netmask: {addr['netmask']}\n")
                        if 'broadcast' in addr:
                            text_widget.insert(tk.END, f"  Broadcast: {addr['broadcast']}\n")
                
                # In PV6

                if netifaces.AF_INET6 in addrs:
                    for addr in addrs[netifaces.AF_INET6]:
                        text_widget.insert(tk.END, f"  IPv6: {addr['addr']}\n")
                
                # Mac

                if netifaces.AF_LINK in addrs:
                    for addr in addrs[netifaces.AF_LINK]:
                        if 'addr' in addr:
                            text_widget.insert(tk.END, f"  MAC: {addr['addr']}\n")
                
                text_widget.insert(tk.END, "\n")
            
            # Make the text of reading

            text_widget.config(state=tk.DISABLED)

            # Cent on the window compared to the main window

            info_window.update_idletasks()  # Update to obtain correct dimensions


            # Get position and size of the main window

            parent_x = self.root.winfo_x()
            parent_y = self.root.winfo_y()
            parent_width = self.root.winfo_width()
            parent_height = self.root.winfo_height()

            # Get info window size

            window_width = info_window.winfo_width()
            window_height = info_window.winfo_height()

            # Calculate position centered compared to the main window

            position_x = parent_x + (parent_width - window_width) // 2
            position_y = parent_y + (parent_height - window_height) // 2

            # Apply the location

            info_window.geometry(f"+{position_x}+{position_y}")
        
        except Exception as e:
            messagebox.showerror("Error", f"Failed to get interface information: {str(e)}")

    def start_capture(self):
        """Start packet capture"""
        if not self.selected_interface.get():
            messagebox.showerror("Error", "Select a network interface")
            return
        
        # Get the real name of the interface from the selection

        selected_description = self.selected_interface.get()
        if hasattr(self, 'interface_details') and selected_description in self.interface_details:
            real_interface = self.interface_details[selected_description]
        else:
            real_interface = selected_description
            
        self.is_capturing = True
        self.captured_packets = []
        self.clear_setup_virtual_treeview()
        
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        
        # Memorizes the royal interface for use in capture functions

        self.real_interface = real_interface
        
        # Start capture thread

        self.capture_thread = threading.Thread(target=self.capture_packets)
        self.capture_thread.daemon = True
        self.capture_thread.start()
        
        self.status_bar.config(text=f"Capturing on {selected_description}...")

    def stop_capture(self):
        """Stop packet capture"""
        self.is_capturing = False
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        # Empty the packets tail to avoid further processing

        try:
            while not self.packet_queue.empty():
                self.packet_queue.get_nowait()
        except:
            pass
        
        self.status_bar.config(text=f"Capture stopped. Total packets: {len(self.captured_packets)}")
        print("Capture stopped")
        self.update_statistics()

    def capture_packets(self):
        """Packet capture thread with security improvements"""
        try:
            import socket
            import struct
            import time
            import sys
            import os
            
            # Check if the program is running as administrator

            admin_mode = False
            try:
                if sys.platform.startswith('win'):
                    import ctypes
                    admin_mode = ctypes.windll.shell32.IsUserAnAdmin() != 0
                else:
                    admin_mode = os.geteuid() == 0
            except Exception as e:
                print(f"Error verifying administrator privileges: {str(e)}")
                admin_mode = False
                
            if not admin_mode:
                print("WARNING: Program not running as administrator/root")
                self.status_bar.config(text="WARNING: Run as administrator to capture real packets")
                messagebox.showwarning("Insufficient permissions",
                "To capture network packets, you must run the software as an administrator.\n\n"
                "Simulation mode will be used.")
                if self.is_capturing:
                    self.generate_test_traffic()
                return
            
            # Limit the doors monitored for safety if not in promiscuous mode

            restricted_monitoring = not self.promisc_mode.get()
            
            if restricted_monitoring:
                # Warns the user that the capture is limited

                self.status_bar.config(text="Capture in standard mode (host-bound packets only). Enable promiscuous mode for all packets.")
                
            # Create a raw socket

            try:
                if sys.platform.startswith('win'):
                    # On Windows, Ipiproto_ip can capture all protocols

                    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
                    print("Using socket IPPROTO_IP (Windows)")
                else:
                    # On Linux/Unix, we use AF_Packet to capture everything

                    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
                    print("Using socket AF_PACKET (Linux/Unix)")
            except PermissionError:
                print("Permissions Error: Run the software as administrator/root")
                messagebox.showerror("Permissions error",
                "To capture packets you need to run the software as administrator/root")
                if self.is_capturing:
                    self.generate_test_traffic()
                return
            except socket.error as e:
                print(f"Failed to create primary raw socket: {str(e)}")
                try:
                    # Alternative option with socket.ipiproto_ip

                    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
                    print("Using alternative IPPROTO_IP socket")
                except socket.error as e:
                    print(f"Unable to create alternate raw socket: {str(e)}")
                # As a last resource, try TCP
                    try:
                        # Note: This will only catch TCP
                        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
                        print("WARNING: Using IPPROTO_TCP socket - will only capture TCP packets")
                    except PermissionError:
                        print("Permissions Error: Run this software as administrator/root")
                        messagebox.showerror("Permissions error",
                        "To capture packets you need to run the software as administrator/root")
                        if self.is_capturing:
                            self.generate_test_traffic()
                        return
                    except socket.error as e:
                        print(f"Unable to create any raw socket: {str(e)}")
                        messagebox.showerror("Socket Error",
                        f"Unable to create raw socket: {str(e)}\n\n"
                        f"This error is often caused by insufficient permissions.\n"
                        f"Simulation mode will be used.")
                        # Fallback with simulated packages

                        if self.is_capturing:
                            self.generate_test_traffic()
                        return
            
            # Get the IP address of the selected interface

            import netifaces
            ip = None
            
            try:
                addrs = netifaces.ifaddresses(self.real_interface)
                if netifaces.AF_INET in addrs:
                    ip = addrs[netifaces.AF_INET][0]['addr']
                    print(f"Interface IP address: {ip}")
            except Exception as e:
                print(f"Error getting interface IP: {str(e)}")
                # Fallback in Localhost if we cannot get the IP

                ip = "127.0.0.1"
            
            # To also capture Loopback traffic

            if '127.0.0.1' in ip or 'localhost' in ip:
                try:
                    # Configures the socket to also capture Loopback traffic

                    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    print("Configured to capture loopback traffic")
                except Exception as e:
                    print(f"Error configuring for loopback: {str(e)}")
            
            # Socket bind at the interface

            try:
                if not sys.platform.startswith('win') and hasattr(socket, 'AF_PACKET') and s.family == socket.AF_PACKET:
                    # For AF_Packet you don't need the bind
                    pass
                else:
                    s.bind((ip, 0))
                    print(f"Socket bind to {ip}")
            except Exception as e:
                print(f"Socket binding error: {str(e)}")
                if self.is_capturing:
                    self.generate_test_traffic()
                return
            
            # On Windows, we have to set the socket in promiscuous mode if requested
            # Management of capture methods
            # Management of capture methods

            if hasattr(socket, 'SIO_RCVALL'):
                try:
                    if self.promisc_mode.get():
                        # Promiscua mode -All packages

                        s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
                        print("Promiscuous mode enabled")
                    else:
                        # Tries a different approach for standard mode

                        if not hasattr(socket, 'RCVALL_SOCKETLEVELONLY'):
                            socket.RCVALL_SOCKETLEVELONLY = 1
                        
                        # First test with socketlevelonly

                        try:
                            s.ioctl(socket.SIO_RCVALL, socket.RCVALL_SOCKETLEVELONLY)
                            print("Standard mode activated with SOCKETLEVELONLY")
                        except:
                            # If it fails, try with Rcvall_on but filter manually

                            s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
                            print("Standard mode activated with RCVALL_ON (manual filtering)")
                            self.manual_filter = True
                except Exception as e:
                    print(f"Error setting capture mode: {str(e)}")
            
            # Timeout tax not to block indefinitely

            s.settimeout(1)
            
            # Warns the user on the types of packets captured

            if hasattr(s, 'proto') and socket.IPPROTO_TCP == s.proto:
                self.status_bar.config(text="Capture limited to TCP packets only! Run as administrator for all packets")
            
            # Start capture

            print(f"Starting capture on {self.real_interface} ({ip})...")
            self.status_bar.config(text=f"Capturing on {self.real_interface} ({ip})...")
            
            # We configure security limits to avoid dos

            max_packets_per_second = 1000  # Maximum limit of packages per second

            max_packet_size = 65535        # Maximum package size

            packet_count = 0
            last_second_packets = 0
            last_second_time = time.time()
            
            # Rate limiting for source

            rate_limits = {}  # Dictionary to trace Source IP packages

            rate_limit_threshold = 200  # Maximum packages per second by a single IP

            
            while self.is_capturing:
                try:
                    # Limit the processing speed to avoid dos

                    current_time = time.time()
                    if current_time - last_second_time >= 1:
                        # Reset couunter every second

                        last_second_packets = 0
                        last_second_time = current_time
                        # Reset anche rate limits

                        rate_limits = {}
                    
                    if last_second_packets >= max_packets_per_second:
                        # Too many packages in a second, wait before continuing

                        print(f"Rate limiting enabled: {last_second_packets} packets/sec")
                        time.sleep(0.1)
                        continue
                    
                    # Receive package with size limit

                    raw_packet = s.recv(max_packet_size)
                    last_second_packets += 1
                    
                    # Check the size of the package

                    if len(raw_packet) == 0 or len(raw_packet) > max_packet_size:
                        continue  # Skip empty or too large packages

                    
                    # If we use AF_Packet, the header Ethernet is included

                    if not sys.platform.startswith('win') and hasattr(socket, 'AF_PACKET') and s.family == socket.AF_PACKET:
                        # Salta l'header Ethernet (14 byte)

                        eth_length = 14
                        ip_header = raw_packet[eth_length:eth_length+20]
                    else:
                        # Otherwise we start directly from the Heder IP

                        ip_header = raw_packet[0:20]
                    
                    # Crea timestamp

                    timestamp = time.time()
                    
                    # Analyze IP package

                    iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
                    
                    version_ihl = iph[0]
                    version = version_ihl >> 4
                    ihl = version_ihl & 0xF
                    
                    iph_length = ihl * 4
                    
                    ttl = iph[5]
                    protocol = iph[6]
                    s_addr = socket.inet_ntoa(iph[8])
                    d_addr = socket.inet_ntoa(iph[9])
                    
                    # Rate Limiting for IP Source

                    if s_addr in rate_limits:
                        rate_limits[s_addr] += 1
                        if rate_limits[s_addr] > rate_limit_threshold:
                            # Too many packages from this source, jump

                            print(f"Rate limiting for source IP: {s_addr} ({rate_limits[s_addr]} packets/sec)")
                            continue
                    else:
                        rate_limits[s_addr] = 1
                    
                    # Create a package object

                    packet = {
                        'time': timestamp,
                        'version': version,
                        'ihl': ihl,
                        'ttl': ttl,
                        'protocol': protocol,
                        'src': s_addr,
                        'dst': d_addr,
                        'raw': raw_packet,
                        'len': len(raw_packet)
                    }
                    
                    # Calculate the offset for the header of the protocol

                    if not sys.platform.startswith('win') and hasattr(socket, 'AF_PACKET') and s.family == socket.AF_PACKET:
                        proto_offset = eth_length + iph_length
                    else:
                        proto_offset = iph_length
                    
                    # Analyze specific protocol

                    if protocol == 6:  # Tcp

                        tcp_header = raw_packet[proto_offset:proto_offset+20]
                        tcph = struct.unpack('!HHLLBBHHH', tcp_header)
                        
                        source_port = tcph[0]
                        dest_port = tcph[1]
                        sequence = tcph[2]
                        acknowledgement = tcph[3]
                        doff_reserved = tcph[4]
                        tcph_length = doff_reserved >> 4
                        flags = tcph[5]
                        
                        packet['proto_name'] = 'TCP'
                        packet['sport'] = source_port
                        packet['dport'] = dest_port
                        packet['seq'] = sequence
                        packet['ack'] = acknowledgement
                        packet['flags'] = flags
                        packet['flags_str'] = self.parse_tcp_flags(flags)
                        
                        # Fit Payload

                        h_size = proto_offset + tcph_length * 4
                        data_size = len(raw_packet) - h_size
                        
                        if data_size > 0:
                            packet['payload'] = raw_packet[h_size:]
                            
                            # Check if it's HTTP

                            try:
                                payload_str = raw_packet[h_size:h_size+20].decode('utf-8', errors='ignore')
                                if 'HTTP/' in payload_str or 'GET ' in payload_str or 'POST ' in payload_str:
                                    packet['proto_name'] = 'HTTP'
                                elif 'TLS' in payload_str or '\x16\x03' in payload_str[:2]:
                                    packet['proto_name'] = 'HTTPS'
                            except:
                                pass
                        
                    elif protocol == 17:  # Udp

                        udp_header = raw_packet[proto_offset:proto_offset+8]
                        udph = struct.unpack('!HHHH', udp_header)
                        
                        source_port = udph[0]
                        dest_port = udph[1]
                        length = udph[2]
                        
                        packet['proto_name'] = 'UDP'
                        packet['sport'] = source_port
                        packet['dport'] = dest_port
                        packet['length'] = length
                        
                        # Fit Payload

                        h_size = proto_offset + 8
                        if len(raw_packet) > h_size:
                            packet['payload'] = raw_packet[h_size:]
                            
                            # Check if it's DNS

                            if source_port == 53 or dest_port == 53:
                                packet['proto_name'] = 'DNS'
                        
                    elif protocol == 1:  # Icmp

                        icmp_header = raw_packet[proto_offset:proto_offset+4]
                        icmph = struct.unpack('!BBH', icmp_header)
                        
                        icmp_type = icmph[0]
                        code = icmph[1]
                        checksum = icmph[2]
                        
                        packet['proto_name'] = 'ICMP'
                        packet['type'] = icmp_type
                        packet['code'] = code
                        
                        # Fit Payload

                        h_size = proto_offset + 4
                        if len(raw_packet) > h_size:
                            packet['payload'] = raw_packet[h_size:]
                    
                    else:
                        packet['proto_name'] = f'IP ({protocol})'
                    
                    # Apply filters

                    proto_filter = self.proto_filter_var.get().upper() if hasattr(self, 'proto_filter_var') else ""
                    ip_filter = self.ip_filter_var.get() if hasattr(self, 'ip_filter_var') else ""
                    port_filter = self.port_filter_var.get() if hasattr(self, 'port_filter_var') else ""
                    
                    # Protocol filter

                    if proto_filter:
                        if proto_filter == "TCP" and packet.get('proto_name') not in ['TCP', 'HTTP', 'HTTPS']:
                            continue
                        elif proto_filter == "UDP" and packet.get('proto_name') not in ['UDP', 'DNS']:
                            continue
                        elif proto_filter == "ICMP" and packet.get('proto_name') != 'ICMP':
                            continue
                        elif proto_filter == "HTTP" and packet.get('proto_name') != 'HTTP':
                            continue
                        elif proto_filter == "HTTPS" and packet.get('proto_name') != 'HTTPS':
                            continue
                        elif proto_filter == "DNS" and packet.get('proto_name') != 'DNS':
                            continue
                    
                    # IP filter

                    if ip_filter:
                        if ip_filter not in packet['src'] and ip_filter not in packet['dst']:
                            continue
                    
                    # Port filter

                    if port_filter:
                        try:
                            port_num = int(port_filter)
                            if ('sport' not in packet or packet['sport'] != port_num) and \
                            ('dport' not in packet or packet['dport'] != port_num):
                                continue
                        except ValueError:
                            # If it is not a valid number, we ignore this filter

                            pass
                    
                    # Add package to the list and tail

                    self.captured_packets.append(packet)
                    self.packet_queue.put(packet)
                    
                    packet_count += 1
                    if packet_count % 10 == 0:
                        print(f"Captured {packet_count} packets")
                        self.status_bar.config(text=f"Captured Packets: {packet_count}")
                    
                except socket.timeout:
                    # Normal timeout, the cycle continues

                    continue
                except Exception as e:
                    print(f"Error while capturing: {str(e)}")
                    if not self.is_capturing:
                        break
            
            # Close socket

            if hasattr(socket, 'SIO_RCVALL') and self.promisc_mode.get():
                try:
                    s.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
                except:
                    pass
            s.close()
            
            print(f"Capture finished: {packet_count} packets")
            
        except Exception as e:
            print(f"General capture error: {str(e)}")
            self.is_capturing = False
            messagebox.showerror("Capture error", str(e))
            self.root.after(0, lambda: self.status_bar.config(text=f"Error: {str(e)}"))
            self.root.after(0, lambda: self.start_button.config(state=tk.NORMAL))
            self.root.after(0, lambda: self.stop_button.config(state=tk.DISABLED))

    def parse_tcp_flags(self, flags):
        """Interprets TCP flags and returns a descriptive string"""
        flag_str = []
        
        if flags & 0x01:  # Fin

            flag_str.append("FIN")
        if flags & 0x02:  # Syn

            flag_str.append("SYN")
        if flags & 0x04:  # Rst

            flag_str.append("RST")
        if flags & 0x08:  # Psh

            flag_str.append("PSH")
        if flags & 0x10:  # Ack

            flag_str.append("ACK")
        if flags & 0x20:  # Urg

            flag_str.append("URG")
        if flags & 0x40:  # Ece

            flag_str.append("ECE")
        if flags & 0x80:  # Sore

            flag_str.append("CWR")
        
        return " ".join(flag_str) if flag_str else "NONE"

    def generate_test_traffic(self):
        """Generate simulated traffic safely with greater controls"""
        import threading
        import time
        import random
        import ipaddress
        
        print("Test traffic generation...")
        self.status_bar.config(text="Test traffic generation (simulation mode)")
        
        # Define the number of packages to generate

        num_packets_to_generate = 1000
        
        # Ask confirmation for large quantities of packages

        if num_packets_to_generate > 500:
            response = messagebox.askyesno("Confirm",
            f"You are about to generate {num_packets_to_generate} test packages.\n" 
            "This may take a few seconds.\n\n"
            "Do you want to continue?")
            if not response:
                self.status_bar.config(text="Test traffic generation cancelled")
                return
        
        packets_generated = 0
        
        def generate_packets():
            nonlocal packets_generated
            
            # Limit generation of valid and reasonable IP addresses packages

            protocols = ["TCP", "UDP", "ICMP", "HTTP", "DNS", "HTTPS"]
            
            # Mainly use private addresses for simulation

            private_ips = [
                "192.168.1." + str(i) for i in range(1, 20)
            ] + [
                "10.0.0." + str(i) for i in range(1, 20)
            ] + [
                "172.16.0." + str(i) for i in range(1, 20)
            ]
            
            # Add some well -known public IP SAIP

            public_ips = ["8.8.8.8", "1.1.1.1", "208.67.222.222"]
            
            # Combines lists with greater weight to private addresses

            ips = private_ips + public_ips
            
            ports_tcp = [80, 443, 22, 21, 25, 110, 143, 3389, 8080]
            ports_udp = [53, 67, 68, 123, 161, 5353]
            
            # Limit the generation speed to avoid overloads

            packet_rate = 50  # Packages per second

            
            # Configures weights for different types of packages for a more realistic simulation

            protocol_weights = {
                "TCP": 45,     # 45% probability

                "UDP": 25,     # 25% probability

                "HTTP": 20,    # 20% probability

                "HTTPS": 5,    # 5% probability

                "DNS": 3,      # 3% probability

                "ICMP": 2      # 2% probability

            }
            
            # Calculate the cumulative distribution for the weighted sampling

            cumulative_weights = []
            current_sum = 0
            for proto in protocols:
                weight = protocol_weights.get(proto, 5)  # default 5% for not specified protocols

                current_sum += weight
                cumulative_weights.append(current_sum)
            
            def weighted_choice(choices, cum_weights):
                r = random.uniform(0, cum_weights[-1])
                for i, w in enumerate(cum_weights):
                    if r <= w:
                        return choices[i]
                return choices[-1]  # Failsafe

            
            start_time = time.time()
            
            while self.is_capturing and packets_generated < num_packets_to_generate:
                # Check the generation speed

                elapsed = time.time() - start_time
                expected_packets = min(num_packets_to_generate, int(elapsed * packet_rate))
                
                if packets_generated >= expected_packets:
                    # We are generating too quickly, wait

                    time.sleep(0.01)
                    continue
                
                # Select Protocol with weights

                proto = weighted_choice(protocols, cumulative_weights)
                
                # Choose IP more realistic way
                # To simulate conversations, keep the same IP for short sequences

                if packets_generated % 5 == 0 or packets_generated == 0:
                    # New "conversation"

                    src_ip = random.choice(ips)
                    dst_ip = random.choice(ips)
                    
                    # Avoid IP Source and Destination Equal

                    while dst_ip == src_ip:
                        dst_ip = random.choice(ips)
                
                timestamp = time.time()
                
                # Create basic package

                packet = {
                    'time': timestamp,
                    'version': 4,
                    'ihl': 5,
                    'ttl': random.randint(32, 128),
                    'protocol': 6 if proto in ["TCP", "HTTP", "HTTPS"] else (17 if proto in ["UDP", "DNS"] else 1),
                    'src': src_ip,
                    'dst': dst_ip,
                    'raw': b'SIMULATED_PACKET',
                    'len': random.randint(64, 1500)
                }
                
                if proto in ["TCP", "HTTP", "HTTPS"]:
                    packet['proto_name'] = proto
                    
                    # Per HTTP/HTTPS, usa porte standard

                    if proto == "HTTP":
                        packet['sport'] = random.choice([10000 + i for i in range(1000)])  # Casuali client door> 10000

                        packet['dport'] = 80
                    elif proto == "HTTPS":
                        packet['sport'] = random.choice([10000 + i for i in range(1000)])
                        packet['dport'] = 443
                    else:  # TCP generico

                        packet['sport'] = random.choice([10000 + i for i in range(1000)])
                        packet['dport'] = random.choice(ports_tcp)
                    
                    packet['seq'] = random.randint(1000000, 9999999)
                    packet['ack'] = random.randint(1000000, 9999999)
                    
                    # Simula various states of the connection

                    flags_options = [
                        0x02,           # Syn

                        0x12,           # Vision+ack

                        0x10,           # Ack

                        0x18,           # Psh+ack

                        0x11,           # Fine+ack

                        0x04            # Rst

                    ]
                    
                    # Logic for a more realistic TCP conversation

                    if packets_generated % 50 < 3:
                        # Connection start

                        packet['flags'] = 0x02  # Syn

                    elif packets_generated % 50 < 6:
                        # Connection establishment

                        packet['flags'] = 0x12  # SYN+ACK o ACK

                    elif packets_generated % 50 > 45:
                        # Connection closure

                        packet['flags'] = 0x11  # Fine+ack

                    else:
                        # Data transmission

                        packet['flags'] = 0x18  # Psh+ack

                    
                    packet['flags_str'] = self.parse_tcp_flags(packet['flags'])
                    
                    if proto == "HTTP" or proto == "HTTPS":
                        # Simula payload HTTP/HTTPS

                        http_methods = ["GET", "POST", "PUT", "DELETE"]
                        http_paths = ["/", "/index.html", "/api/data", "/login", "/images/logo.png"]
                        http_versions = ["HTTP/1.1", "HTTP/2"]
                        
                        method = random.choice(http_methods)
                        path = random.choice(http_paths)
                        version = random.choice(http_versions)
                        
                        # Create a realistic payload without including potentially harmful content

                        if random.random() < 0.5:  # Request

                            payload = f"{method} {path} {version}\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n"
                        else:  # Answer

                            status_codes = [200, 301, 302, 400, 404, 500]
                            status = random.choice(status_codes)
                            status_text = {200: "OK", 301: "Moved Permanently", 302: "Found", 
                                        400: "Bad Request", 404: "Not Found", 500: "Internal Server Error"}
                            
                            payload = f"{version} {status} {status_text[status]}\r\nContent-Type: text/html\r\nContent-Length: 0\r\n\r\n"
                        
                        packet['payload'] = payload.encode()
                
                elif proto == "UDP" or proto == "DNS":
                    packet['proto_name'] = proto
                    
                    # Per DNS, usa porte standard

                    if proto == "DNS":
                        # DNS packages are typically from the client to door 53

                        packet['sport'] = random.choice([10000 + i for i in range(1000)])
                        packet['dport'] = 53
                    else:  # UDP generico

                        packet['sport'] = random.choice([10000 + i for i in range(1000)])
                        packet['dport'] = random.choice(ports_udp)
                    
                    packet['length'] = random.randint(8, 512)
                    
                    if proto == "DNS":
                        # Starting payload DNS

                        domains = ["example.com", "google.com", "github.com", "microsoft.com", "wikipedia.org"]
                        domain = random.choice(domains)
                        
                        # We do not create a realistic DNS package, just a placeholder

                        packet['payload'] = f"DNS Query/Response for {domain}".encode()
                    else:
                        packet['payload'] = b"UDP data placeholder"
                
                elif proto == "ICMP":
                    packet['proto_name'] = "ICMP"
                    packet['type'] = 8 if random.random() < 0.5 else 0  # Echo request o echo reply

                    packet['code'] = 0
                    # Starting Payload ICMP

                    packet['payload'] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                
                # Apply filter if necessary

                if hasattr(self, 'proto_filter_var') and self.proto_filter_var.get():
                    proto_filter = self.proto_filter_var.get().upper()
                    if proto_filter == "TCP" and packet.get('proto_name') not in ['TCP', 'HTTP', 'HTTPS']:
                        continue
                    elif proto_filter == "UDP" and packet.get('proto_name') not in ['UDP', 'DNS']:
                        continue
                    elif proto_filter == "ICMP" and packet.get('proto_name') != 'ICMP':
                        continue
                    elif proto_filter == "HTTP" and packet.get('proto_name') != 'HTTP':
                        continue
                    elif proto_filter == "HTTPS" and packet.get('proto_name') != 'HTTPS':
                        continue
                    elif proto_filter == "DNS" and packet.get('proto_name') != 'DNS':
                        continue
                
                if hasattr(self, 'ip_filter_var') and self.ip_filter_var.get():
                    ip_filter = self.ip_filter_var.get()
                    if ip_filter not in packet['src'] and ip_filter not in packet['dst']:
                        continue
                
                if hasattr(self, 'port_filter_var') and self.port_filter_var.get():
                    try:
                        port_filter = int(self.port_filter_var.get())
                        if ('sport' not in packet or packet['sport'] != port_filter) and \
                        ('dport' not in packet or packet['dport'] != port_filter):
                            continue
                    except ValueError:
                        pass
                
                # Add package to the list and tail

                self.captured_packets.append(packet)
                self.packet_queue.put(packet)
                packets_generated += 1
                
                # Update the status bar with progress

                if packets_generated % 50 == 0:  # Update every 50 packages

                    self.status_bar.config(text=f"Generating test traffic... {packets_generated}/{num_packets_to_generate} packets")
                
                # Light delay to avoid overloading the CPU

                time.sleep(0.001)
            
            # When the generation is completed, it shows a message

            if packets_generated >= num_packets_to_generate:
                self.is_capturing = False  # Stop it capture

                self.root.after(0, lambda: self.show_completion_message(packets_generated))
        
        # Function to show the completion message

        def show_completion_message(self, count):
            messagebox.showinfo("Generation Complete", f"Test traffic generation completed.\n\n{count} packets were generated.")
            self.status_bar.config(text=f"Test traffic generation completed. {count} packets generated.")
            self.start_button.config(state=tk.NORMAL)
            self.stop_button.config(state=tk.DISABLED)
        
        # Start generation thread

        self.is_capturing = True
        sim_thread = threading.Thread(target=generate_packets)
        sim_thread.daemon = True
        sim_thread.start()
        
        self.status_bar.config(text="Generating test traffic...")
    
    
    def process_packet_queue(self):
        """Processes packets in queue and updates UI with sequential numbering"""
        try:
            queue_size = self.packet_queue.qsize()
            
            # Let's make sure that there is a global counter for packages

            if not hasattr(self, 'packet_counter'):
                self.packet_counter = 0
            
            if queue_size > 0:
                print(f"Queue size: {queue_size}")
            
            packets_to_process = min(queue_size, 50)  # Reduced from 100 to 50

            batch_items = []
            
            for _ in range(packets_to_process):
                if self.packet_queue.empty():
                    break
                    
                packet = self.packet_queue.get_nowait()
                
                # Increases the global counter for each package

                self.packet_counter += 1
                packet_index = self.packet_counter  # Use the global counter

                
                # Extract information from the package

                timestamp = time.strftime("%H:%M:%S", time.localtime(packet['time']))
                
                # Use correctly source and destination without reversing them

                src = packet['src']
                dst = packet['dst']
                
                proto = packet.get('proto_name', 'Unknown')
                length = packet['len']
                
                # Create string info

                if proto == 'TCP':
                    info = f"Port src: {packet['sport']}, Port dst: {packet['dport']}"
                    if 'flags_str' in packet:
                        info += f", Flags: {packet['flags_str']}"
                elif proto == 'UDP':
                    info = f"Port src: {packet['sport']}, Port dst: {packet['dport']}"
                    if 'length' in packet:
                        info += f", Len: {packet['length']}"
                elif proto == 'ICMP':
                    icmp_type = packet.get('type', 0)
                    if icmp_type == 8:
                        info = "Echo request"
                    elif icmp_type == 0:
                        info = "Echo reply"
                    else:
                        info = f"Type {icmp_type}"
                else:
                    info = f"TTL: {packet.get('ttl', '?')}"
                
                # Add to the Batch list with the sequential index

                batch_items.append((packet_index, timestamp, src, dst, proto, length, info))
            
            # Update the UI in a batch

            if batch_items:
                for item in batch_items:
                    self.setup_virtual_treeview.insert("", tk.END, values=item)
                
                # Automatic scroll if activated

                if hasattr(self, 'auto_scroll_var') and self.auto_scroll_var.get():
                    self.setup_virtual_treeview.yview_moveto(1.0)
                    
        except Exception as e:
            print(f"Error processing packets: {str(e)}")
            traceback.print_exc()
                
        # Update packages count

        if self.is_capturing:
            # Verification that self.real_ interface exists before using it

            interface_name = getattr(self, 'real_interface', 'interfaccia sconosciuta')
            self.status_bar.config(text=f"Capturing on {interface_name}... Packets: {self.packet_counter} (Queue: {queue_size})")
                
        # Fixed interval instead of dynamic

        interval = 20  # Fixed 20ms for a more regular view
            
        self.root.after(interval, self.process_packet_queue)
    
    def on_packet_select(self, event):
        """Manages the selection of a package in the table"""
        selected_items = self.setup_virtual_treeview.selection()
        if not selected_items:
            return
            
        # Clean the previous details

        for item in self.packet_details.get_children():
            self.packet_details.delete(item)
            
        # Get the selected package index

        item_values = self.setup_virtual_treeview.item(selected_items[0], "values")
        if not item_values:
            return
            
        packet_index = int(item_values[0]) - 1
        if packet_index >= len(self.captured_packets):
            return
            
        packet = self.captured_packets[packet_index]
        
        # View the details of the package in a hierarchical way

        self.display_packet_details(packet)

    def display_packet_details(self, packet):
        """View package details in a tree view"""
        # Ip

        ip_id = self.packet_details.insert("", tk.END, text="Internet Protocol", open=True)
        self.packet_details.insert(ip_id, tk.END, text=f"Version: {packet['version']}")
        self.packet_details.insert(ip_id, tk.END, text=f"Header Length: {packet['ihl']} x 4 bytes")
        self.packet_details.insert(ip_id, tk.END, text=f"TTL: {packet['ttl']}")
        self.packet_details.insert(ip_id, tk.END, text=f"Protocol: {packet['protocol']}")
        
        # Use the SRC and DST fields correctly without reversing them

        self.packet_details.insert(ip_id, tk.END, text=f"Source: {packet['src']}")
        self.packet_details.insert(ip_id, tk.END, text=f"Destination: {packet['dst']}")
        
        # Tcp

        if packet.get('proto_name') == 'TCP':
            tcp_id = self.packet_details.insert("", tk.END, text="Transmission Control Protocol", open=True)
            
            # Use Sports and Dport fields correctly

            self.packet_details.insert(tcp_id, tk.END, text=f"Source Port: {packet['sport']}")
            self.packet_details.insert(tcp_id, tk.END, text=f"Destination Port: {packet['dport']}")
            
            self.packet_details.insert(tcp_id, tk.END, text=f"Sequence: {packet['seq']}")
            self.packet_details.insert(tcp_id, tk.END, text=f"Acknowledgment: {packet['ack']}")
            
            # TCP Flags

            flags_id = self.packet_details.insert(tcp_id, tk.END, text="Flags", open=True)
            flags = packet['flags']
            self.packet_details.insert(flags_id, tk.END, text=f"FIN: {1 if flags & 0x01 else 0}")
            self.packet_details.insert(flags_id, tk.END, text=f"SYN: {1 if flags & 0x02 else 0}")
            self.packet_details.insert(flags_id, tk.END, text=f"RST: {1 if flags & 0x04 else 0}")
            self.packet_details.insert(flags_id, tk.END, text=f"PSH: {1 if flags & 0x08 else 0}")
            self.packet_details.insert(flags_id, tk.END, text=f"ACK: {1 if flags & 0x10 else 0}")
            self.packet_details.insert(flags_id, tk.END, text=f"URG: {1 if flags & 0x20 else 0}")
            
            # Payload (it appears)

            if 'payload' in packet:
                payload_id = self.packet_details.insert(tcp_id, tk.END, text="Payload", open=True)
                self.display_hex_payload(payload_id, packet['payload'])
        
        # Udp

        elif packet.get('proto_name') == 'UDP':
            udp_id = self.packet_details.insert("", tk.END, text="User Datagram Protocol", open=True)
            
            # Use Sports and Dport fields correctly

            self.packet_details.insert(udp_id, tk.END, text=f"Source Port: {packet['sport']}")
            self.packet_details.insert(udp_id, tk.END, text=f"Destination Port: {packet['dport']}")
            
            self.packet_details.insert(udp_id, tk.END, text=f"Length: {packet.get('length', 'N/A')}")
            
            # Payload (it appears)

            if 'payload' in packet:
                payload_id = self.packet_details.insert(udp_id, tk.END, text="Payload", open=True)
                self.display_hex_payload(payload_id, packet['payload'])


    def display_hex_payload(self, parent_id, payload_data):
        """View payload in hexadecimal and ASCII format"""
        if not payload_data:
            return
            
        # Limit the 512 byte display for performance

        display_limit = min(512, len(payload_data))
        
        # Create a main knot for payload

        payload_parent = self.packet_details.insert(parent_id, tk.END, text="Payload Hex Dump", open=True)
        
        # Add header

        header_id = self.packet_details.insert(payload_parent, tk.END, 
                                            text="Offset    00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F    ASCII")
        
        # Add separator

        self.packet_details.insert(payload_parent, tk.END, 
                                text="-------------------------------------------------------------------")
        
        offset = 0
        while offset < display_limit:
            # Take 16 bytes at a time

            chunk = payload_data[offset:offset+16]
            
            # Format the Hex values

            hex_values = ' '.join(f'{b:02x}' for b in chunk).ljust(47)
            
            # Converts into printed ASCII characters

            ascii_values = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
            
            # L'OFFSET in format

            offset_text = f"0x{offset:04x}"
            
            # Insert the complete line

            row_text = f"{offset_text}    {hex_values}    {ascii_values}"
            self.packet_details.insert(payload_parent, tk.END, text=row_text)
            
            offset += 16
            
        if len(payload_data) > display_limit:
            self.packet_details.insert(payload_parent, tk.END, 
                                    text="-------------------------------------------------------------------")
            self.packet_details.insert(payload_parent, tk.END, 
                    text=f"... {len(payload_data) - display_limit} additional bytes not displayed")

    def clear_setup_virtual_treeview(self):
        """Clears the Treeview and resets the counters"""
        # Empty the tree using the correct name of the variable

        for item in self.setup_virtual_treeview.get_children():
            self.setup_virtual_treeview.delete(item)
        
        # Reset the package meter

        self.packet_counter = 0
        
        # Empty the tail of the packages if it exists

        if hasattr(self, 'packet_queue'):
            while not self.packet_queue.empty():
                try:
                    self.packet_queue.get_nowait()
                except:
                    break

    def update_statistics(self):
        """Update statistical graphs with zoom and mouse navigation capabilities"""
        if not self.captured_packets:
            return
                
        # Statistics Protocols

        protocols = {}
        for packet in self.captured_packets:
            proto = packet.get('proto_name', 'Unknown')
            protocols[proto] = protocols.get(proto, 0) + 1
                
        # Protocol graphics

        self.protocol_fig.clear()
        ax = self.protocol_fig.add_subplot(111)
        
        protocols_sorted = dict(sorted(protocols.items(), key=lambda x: x[1], reverse=True))
        bars = ax.bar(protocols_sorted.keys(), protocols_sorted.values(), color='#5e81ac')
        
        ax.set_title('Distribuzione protocolli')
        ax.set_ylabel('Numero pacchetti')
        ax.tick_params(axis='x', rotation=45)
        
        for bar in bars:
            height = bar.get_height()
            ax.annotate(f'{height}',
                        xy=(bar.get_x() + bar.get_width() / 2, height),
                        xytext=(0, 3),
                        textcoords="offset points",
                        ha='center', va='bottom')
        
        self.protocol_fig.tight_layout()
        self.protocol_canvas.draw()
        
        # Configure simple navigation with the mouse

        self._setup_simple_navigation(self.protocol_canvas)
        
        # Network flows graph

        self.flow_fig.clear()
        ax = self.flow_fig.add_subplot(111)
        
        # Create flowers graph

        G = nx.DiGraph()
        
        # Add knots and strings

        for packet in self.captured_packets:
            src = packet['dst']  # Inverted

            dst = packet['src']  # Inverted

            
            if src not in G:
                G.add_node(src)
            if dst not in G:
                G.add_node(dst)
                    
            if G.has_edge(src, dst):
                G[src][dst]['weight'] += 1
            else:
                G.add_edge(src, dst, weight=1)
        
        # Limit to 20 knots for readability

        if len(G.nodes) > 20:
            # Take the knots with multiple connections

            top_nodes = sorted(G.nodes, key=lambda x: G.degree(x), reverse=True)[:20]
            G = G.subgraph(top_nodes)
        
        # Draw graph

        pos = nx.spring_layout(G)
        
        # Nodes based on the degree

        node_size = [G.degree(n) * 100 for n in G.nodes]
        
        # Weight -based strings width

        edge_width = [G[u][v]['weight'] / 5 for u, v in G.edges]
        
        nx.draw_networkx_nodes(G, pos, node_color='#5e81ac', node_size=node_size, alpha=0.8, ax=ax)
        nx.draw_networkx_edges(G, pos, width=edge_width, alpha=0.5, edge_color='#d8dee9', ax=ax)
        
        nx.draw_networkx_labels(G, pos, font_size=8, font_color='black', ax=ax)
        
        ax.set_title('Flussi di rete')
        ax.set_axis_off()
        
        self.flow_fig.tight_layout()
        self.flow_canvas.draw()
        
        # Configure simple navigation with the mouse

        self._setup_simple_navigation(self.flow_canvas)

    def _setup_simple_navigation(self, canvas):
        """Implement simple but stable mouse navigation"""
        from matplotlib.backend_bases import MouseButton
        
        # Remove existing connections

        if hasattr(canvas, '_nav_callbacks'):
            for cid in canvas._nav_callbacks:
                canvas.mpl_disconnect(cid)
        
        # Initialize variables for Panning

        canvas._nav_pan_active = False
        canvas._nav_last_cursor = None
        canvas._nav_callbacks = []
        
        # Function to manage PANING

        def on_press(event):
            if event.inaxes and event.button == MouseButton.LEFT:
                canvas._nav_pan_active = True
                canvas._nav_start_x = event.x
                canvas._nav_start_y = event.y
                canvas._nav_axes = event.inaxes
                canvas._nav_xlim_start = event.inaxes.get_xlim()
                canvas._nav_ylim_start = event.inaxes.get_ylim()
                
                # Change the cursor

                canvas._nav_last_cursor = canvas.get_tk_widget().cget('cursor')
                canvas.get_tk_widget().config(cursor='fleur')
        
        def on_release(event):
            if canvas._nav_pan_active:
                canvas._nav_pan_active = False
                
                # Restore the cursor

                if canvas._nav_last_cursor:
                    canvas.get_tk_widget().config(cursor=canvas._nav_last_cursor)
                else:
                    canvas.get_tk_widget().config(cursor='')
                
                # Come on a complete update in the end

                canvas.draw_idle()
        
        def on_motion(event):
            if canvas._nav_pan_active and event.inaxes == canvas._nav_axes:
                # Calculate the movement in pixels

                dx = event.x - canvas._nav_start_x
                dy = event.y - canvas._nav_start_y
                
                # Convert the movement to data units

                ax = canvas._nav_axes
                xlim = canvas._nav_xlim_start
                ylim = canvas._nav_ylim_start
                
                # Get the size of the graphic designer in pixel

                bbox = ax.get_window_extent().transformed(canvas.figure.dpi_scale_trans.inverted())
                width_inches, height_inches = bbox.width, bbox.height
                width_pixels = width_inches * canvas.figure.dpi
                height_pixels = height_inches * canvas.figure.dpi
                
                # Calculate the movement to data units

                x_range = xlim[1] - xlim[0]
                y_range = ylim[1] - ylim[0]
                
                x_scale = x_range / width_pixels
                y_scale = y_range / height_pixels
                
                # Calculate the new limits

                new_xlim = (xlim[0] - dx * x_scale, xlim[1] - dx * x_scale)
                new_ylim = (ylim[0] + dy * y_scale, ylim[1] + dy * y_scale)
                
                # Set the new limits

                ax.set_xlim(new_xlim)
                ax.set_ylim(new_ylim)
                
                # Update Canvas

                canvas.draw_idle()
        
        def on_scroll(event):
            if event.inaxes:
                ax = event.inaxes
                # Zoom factor

                base_scale = 1.1
                # Zoom direction

                if event.button == 'up':
                    scale_factor = 1 / base_scale
                else:
                    scale_factor = base_scale
                
                # Current limits

                x_min, x_max = ax.get_xlim()
                y_min, y_max = ax.get_ylim()
                
                # Calculate the central point of the zoom (mouse position)

                x_center = event.xdata
                y_center = event.ydata
                
                # Calculate the new limits

                new_width = (x_max - x_min) * scale_factor
                new_height = (y_max - y_min) * scale_factor
                
                # Calculate the relative position of the mouse within the current limits

                x_rel = (x_center - x_min) / (x_max - x_min)
                y_rel = (y_center - y_min) / (y_max - y_min)
                
                # Calculate the new limits while keeping the fixed mouse point

                new_x_min = x_center - x_rel * new_width
                new_x_max = new_x_min + new_width
                new_y_min = y_center - y_rel * new_height
                new_y_max = new_y_min + new_height
                
                # Set the new limits

                ax.set_xlim(new_x_min, new_x_max)
                ax.set_ylim(new_y_min, new_y_max)
                
                # Update Canvas

                canvas.draw_idle()
        
        # Connect events

        canvas._nav_callbacks.append(canvas.mpl_connect('button_press_event', on_press))
        canvas._nav_callbacks.append(canvas.mpl_connect('button_release_event', on_release))
        canvas._nav_callbacks.append(canvas.mpl_connect('motion_notify_event', on_motion))
        canvas._nav_callbacks.append(canvas.mpl_connect('scroll_event', on_scroll))
        
        # Remove the existing toolbar if present

        if hasattr(self, 'protocol_toolbar') and canvas == self.protocol_canvas:
            self.protocol_toolbar.pack_forget()
            del self.protocol_toolbar
        
        if hasattr(self, 'flow_toolbar') and canvas == self.flow_canvas:
            self.flow_toolbar.pack_forget()
            del self.flow_toolbar

    def save_capture(self):
        """Save current capture to file with secure management"""
        if not self.captured_packets:
            messagebox.showinfo("Information", "No packages to save")
            return
                
        filename = filedialog.asksaveasfilename(
            defaultextension=".pcap",
            filetypes=[("PCAP files", "*.pcap"), ("All files", "*.*")]
        )
        
        if not filename:
            return  # User cancelled operation

        
        try:
            # Check destination directory

            save_dir = os.path.dirname(filename)
            if not os.path.exists(save_dir):
                messagebox.showerror("Error", f"Directory does not exist: {save_dir}")
                return
                
            # Check writing permits

            if not os.access(save_dir, os.W_OK):
                messagebox.showerror("Error", f"Insufficient permissions to write to: {save_dir}")
                return
                
            with open(filename, 'wb') as f:
                pickle.dump(self.captured_packets, f)
            messagebox.showinfo("Saving", f"Saved {len(self.captured_packets)} packages to {filename}")
            
        except PermissionError:
            messagebox.showerror("Error", f"Insufficient permissions to write file: {filename}")
        except OSError as e:
            messagebox.showerror("Error", f"I/O error while saving: {str(e)}")
        except Exception as e:
            messagebox.showerror("Error", f"Unable to save file: {str(e)}")

    def load_capture(self):
        """Load a capture from file"""
        filename = filedialog.askopenfilename(
            filetypes=[("PCAP files", "*.pcap"), ("All files", "*.*")]
        )
        
        if filename:
            try:
                with open(filename, 'rb') as f:
                    self.captured_packets = pickle.load(f)
                self.clear_setup_virtual_treeview()
                
                # Add packages to the table

                for packet in self.captured_packets:
                    self.packet_queue.put(packet)
                
                messagebox.showinfo("Loading", f"Loaded {len(self.captured_packets)} packages from {filename}")
                self.status_bar.config(text=f"File uploaded: {filename} - {len(self.captured_packets)} packages")
                
                # Update statistics

                self.update_statistics()
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load file: {str(e)}")
    

    def init_threat_database(self):
        """Initialize the threat database using free sources and extensive local data"""
        try:
            import requests
            import json
            import re
            from datetime import datetime
            
            # Extended threat database

            self.threat_db = {
                "ip": {
                    "185.220.100.240": {"type": "TOR Exit Node", "severity": "Medium", "description": "Potential source of anonymous attacks"},
                    "45.227.255.206": {"type": "Botnet C&C", "severity": "High", "description": "Emote Botnet Command and Control Servert"},
                    "185.176.27.132": {"type": "Ransomware C&C", "severity": "High", "description": "C&C Server associated with REvil/Sodinokibi"},
                    "91.92.136.130": {"type": "APT Infrastructure", "severity": "High", "description": "APT29/Cozy Bear Infrastructure"},
                    "194.5.250.123": {"type": "Cryptominer", "severity": "Medium", "description": "Unauthorized mining server"},
                    "217.12.204.100": {"type": "Phishing Host", "severity": "High", "description": "Host of banking phishing campaigns"},
                    "37.49.230.74": {"type": "Malware Distribution", "severity": "High", "description": "Trickbot/Emotet Distribution"},
                    "5.188.206.18": {"type": "Brute Force Scanner", "severity": "Medium", "description": "Aggressive SSH/RDP Scanner"},
                    "193.35.18.49": {"type": "DDoS Infrastructure", "severity": "High", "description": "Part of Mirai botnet"},
                    "89.44.9.178": {"type": "Credential Harvester", "severity": "High", "description": "Credential collection via fake login"},
                    "23.106.223.55": {"type": "Exploit Kit", "severity": "High", "description": "Server hosting RIG Exploit Kit"}
                },
                "domains": {
                    "evil-domain.xyz": {"type": "Malware Distribution", "severity": "High", "description": "Malware distribution"},
                    "bank-secure-login.com": {"type": "Phishing", "severity": "High", "description": "Bank phishing"},
                    "update-adobe-flash.net": {"type": "Fake Software", "severity": "High", "description": "Fake software update"},
                    "cryptominer-pool.cc": {"type": "Cryptomining", "severity": "Medium", "description": "Unauthorized mining pool"},
                    "secure-document-view.info": {"type": "Credential Theft", "severity": "High", "description": "Office 365 Credential Theft"},
                    "system-update-required.co": {"type": "Scareware", "severity": "Medium", "description": "Fake security warning"},
                    "tracking-package-delivery.info": {"type": "Phishing", "severity": "High", "description": "Package delivery phishing"}
                },
                "patterns": [
                    # Credential leakage

                    {"regex": r"password|pwd|pass", "type": "Clear credentials", "severity": "High", "description": "Possible exposure of credentials"},
                    {"regex": r"apikey|api_key|api-key|secretkey|secret_key|token", "type": "API key exposure", "severity": "High", "description": "Potential exposure of API keys"},
                    {"regex": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b:[^@\s]+", "type": "Email:Password", "severity": "High", "description": "Email:password pair exposed"},
                    
                    # SQL Injection

                    {"regex": r"SELECT.*FROM|INSERT.*INTO|UPDATE.*SET|DELETE.*FROM", "type": "SQL Injection", "severity": "High", "description": "Potential SQL injection"},
                    {"regex": r"UNION.*SELECT|ORDER BY \d+|HAVING \d+=\d+", "type": "SQL Injection avanzata", "severity": "High", "description": "UNION injection technique"},
                    {"regex": r"--[^\n]*$|#[^\n]*$|\/\*.*?\*\/", "type": "SQL Comment Injection", "severity": "High", "description": "Injection with SQL comments"},
                    
                    # Xss

                    {"regex": r"<script.*?>.*?<\/script>", "type": "XSS", "severity": "High", "description": "Cross-site scripting with script tags"},
                    {"regex": r"javascript:|onerror=|onload=|onclick=|onmouseover=", "type": "XSS Event Handlers", "severity": "High", "description": "XSS with event handlers"},
                    {"regex": r"data:text\/html|data:application\/javascript", "type": "XSS Data URI", "severity": "High", "description": "XSS with Data URI scheme"},
                    
                    # Command Injection

                    {"regex": r";\s*rm\s|;\s*cat\s|;\s*bash|;\s*wget|;\s*curl", "type": "Command Injection", "severity": "High", "description": "Shell command injection"},
                    {"regex": r"\|\s*nc\s|\|\s*netcat|\|\s*ncat|>\s*/dev/tcp/", "type": "Reverse Shell", "severity": "High", "description": "Reverse shell attempt"},
                    
                    # File inclusion/path traversal

                    {"regex": r"\.\.\/\.\.\/|\.\.\\\.\.\\|\/etc\/passwd|\/etc\/shadow|c:\\windows\\", "type": "Path Traversal", "severity": "High", "description": "Directory traversal"},
                    {"regex": r"php:\/\/input|php:\/\/filter|data:\/\/", "type": "PHP Wrapper", "severity": "High", "description": "PHP wrapper exploitation"},
                    
                    # Malware indicators

                    {"regex": r"powershell\s+-enc|powershell\s+-w\s+hidden|cmd\.exe\s+\/c", "type": "Suspicious PowerShell", "severity": "High", "description": "Suspicious PowerShell Commands"},
                    {"regex": r"certutil\s+-urlcache|bitsadmin\s+\/transfer", "type": "LOLBin Usage", "severity": "High", "description": "Using legitimate binaries for malicious purposes"},
                    
                    # Data exfiltration

                    {"regex": r"base64\s+[A-Za-z0-9+/=]{100,}", "type": "Base64 Encoded Data", "severity": "Medium", "description": "Possible exfiltration of encrypted data"},
                    {"regex": r"document\.cookie.*?send|navigator\.geolocation.*?send", "type": "Client Data Exfiltration", "severity": "High", "description": "Client-side data exfiltration"}
                ],
                "ports": {
                    "21": {"type": "FTP (unencrypted)", "severity": "Medium", "description": "Unencrypted file transfer"},
                    "22": {"type": "SSH", "severity": "Low", "description": "Secure shell access (monitor brute force attempts)"},
                    "23": {"type": "Telnet (insecure)", "severity": "High", "description": "Unencrypted remote access protocol"},
                    "25": {"type": "SMTP", "severity": "Medium", "description": "Email Server (monitor open relays)"},
                    "53": {"type": "DNS", "severity": "Medium", "description": "DNS server (monitor DNS tunneling)"},
                    "80": {"type": "HTTP", "severity": "Medium", "description": "Unencrypted Web (MITM Vulnerable)"},
                    "135": {"type": "RPC", "severity": "High", "description": "Windows RPC (potential attack vector)"},
                    "139": {"type": "NetBIOS", "severity": "High", "description": "NetBIOS (Windows Share Access)"},
                    "389": {"type": "Unencrypted LDAP", "severity": "High", "description": "Unencrypted directory service"},
                    "445": {"type": "SMB", "severity": "High", "description": "File sharing Windows (EternalBlue/BlueKeep)"},
                    "1433": {"type": "MSSQL", "severity": "High", "description": "Database Microsoft SQL Server"},
                    "1521": {"type": "Oracle DB", "severity": "High", "description": "Database Oracle"},
                    "3306": {"type": "MySQL", "severity": "High", "description": "Database MySQL/MariaDB"},
                    "3389": {"type": "RDP", "severity": "High", "description": "Remote Desktop Protocol (BlueKeep)"},
                    "4444": {"type": "Metasploit", "severity": "High", "description": "Default Metasploit Port"},
                    "5000": {"type": "Docker Registry", "severity": "Medium", "description": "Docker Registry not protected"},
                    "5432": {"type": "PostgreSQL", "severity": "High", "description": "Database PostgreSQL"},
                    "5900": {"type": "VNC", "severity": "High", "description": "Virtual Network Computing"},
                    "6379": {"type": "Redis", "severity": "High", "description": "Redis database not authenticated"},
                    "8080": {"type": "Web Proxy/Alt HTTP", "severity": "Medium", "description": "Web proxy or alternative HTTP server"},
                    "8443": {"type": "HTTPS Alt", "severity": "Low", "description": "Alternative HTTPS"},
                    "9200": {"type": "Elasticsearch", "severity": "High", "description": "Elasticsearch not protected"}
                },
                "file_extensions": {
                    "exe": {"type": "Eseguibile Windows", "severity": "High", "description": "Windows executable"},
                    "dll": {"type": "Windows Library", "severity": "High", "description": "Potential Malicious DLL"},
                    "ps1": {"type": "PowerShell Script", "severity": "High", "description": "Potentially dangerous PowerShell script"},
                    "bat": {"type": "Batch Script", "severity": "High", "description": "Script batch Windows"},
                    "sh": {"type": "Shell Script", "severity": "High", "description": "Script shell Linux/Unix"},
                    "js": {"type": "JavaScript", "severity": "Medium", "description": "Potentially malicious JavaScript code"},
                    "vbs": {"type": "VBScript", "severity": "High", "description": "Visual Basic Script (often used in malware)"},
                    "hta": {"type": "HTML Application", "severity": "High", "description": "HTML Application (Bypass Controls)"},
                    "jar": {"type": "Java Archive", "severity": "High", "description": "Potentially malicious Java application"},
                    "py": {"type": "Python Script", "severity": "Medium", "description": "Potentially dangerous Python script"},
                    "php": {"type": "PHP Script", "severity": "High", "description": "PHP script (web shell or malware)"},
                    "aspx": {"type": "ASP.NET", "severity": "High", "description": "Script ASP.NET (web shell)"},
                    "jsp": {"type": "Java Server Pages", "severity": "High", "description": "Script JSP (web shell)"},
                    "doc": {"type": "Word Document", "severity": "Medium", "description": "Document potentially with malicious macro"},
                    "docm": {"type": "Word Macro Document", "severity": "High", "description": "Word document with macros enabled"},
                    "xls": {"type": "Excel Spreadsheet", "severity": "Medium", "description": "Excel spreadsheet potentially with malicious macro"},
                    "xlsm": {"type": "Excel Macro Spreadsheet", "severity": "High", "description": "Excel spreadsheet with macros enabled"},
                    "pdf": {"type": "PDF Document", "severity": "Medium", "description": "PDF potentially with malicious JavaScript"}
                },
                "user_agents": {
                    "zgrab": {"type": "Network Scanner", "severity": "Medium", "description": "Automated Network Scanner"},
                    "nmap": {"type": "Port Scanner", "severity": "Medium", "description": "Port Scanner with Nmap"},
                    "nikto": {"type": "Web Vulnerability Scanner", "severity": "Medium", "description": "Web Vulnerability Scanner"},
                    "sqlmap": {"type": "SQL Injection Scanner", "severity": "High", "description": "SQL injection automatic tool"},
                    "gobuster": {"type": "Directory Brute Force", "severity": "Medium", "description": "Brute force directory web"},
                    "dirbuster": {"type": "Directory Brute Force", "severity": "Medium", "description": "Brute force directory web"},
                    "hydra": {"type": "Credential Brute Force", "severity": "High", "description": "Brute force credential"},
                    "python-requests": {"type": "Automated Script", "severity": "Medium", "description": "Automated Python Script"},
                    "curl": {"type": "Command Line Tool", "severity": "Low", "description": "Data transfer from command line"},
                    "wget": {"type": "Command Line Tool", "severity": "Low", "description": "Download from command line"},
                    "go-http-client": {"type": "Automated Scanner", "severity": "Medium", "description": "HTTP Client in Go (often scanner)"}
                },
                "hashes": {
                    # Malware noti (SHA256)

                    "000a542a14b8e8d536a352a0d6bbb9e8f8bb01026eb33e8667e704d54d4607ed": {"type": "Ransomware", "severity": "High", "family": "WannaCry"},
                    "27c7c06a56e204800cf1f7059d2f6d2c9c8a03c4d8ec485132cd611d5e57bbad": {"type": "Backdoor", "severity": "High", "family": "Cobalt Strike"},
                    "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa": {"type": "Ransomware", "severity": "High", "family": "NotPetya"},
                    "fc1dae93ff2b6ad864a6a74af247e355d6e36a8fb6ef0f5da059c40b0e3a14b5": {"type": "Trojan", "severity": "High", "family": "Emotet"},
                    "b4e6d97dafd9224ed9a547d52c26ce02d72c2091b6c2d4ac39563383d1e7ff9a": {"type": "Banking Trojan", "severity": "High", "family": "TrickBot"}
                },
                "last_updated": datetime.now().isoformat()
            }
            
            # Tries to add data from free external sources

            try:
                # 1. TOR Exit Nodes

                tor_exit_nodes = requests.get("https://check.torproject.org/exit-addresses", timeout=5)
                if tor_exit_nodes.status_code == 200:
                    for line in tor_exit_nodes.text.split('\n'):
                        if line.startswith('ExitAddress'):
                            ip = line.split()[1]
                            self.threat_db["ip"][ip] = {
                                "type": "TOR Exit Node",
                                "severity": "Medium",
                                "description": "TOR exit node, potential source of anonymous traffic",
                                "source": "TorProject"
                            }
                    print(f"Added TOR exit nodes to the database")
            except Exception as e:
                print(f"Error retrieving TOR nodes: {str(e)}")
                
            try:
                # 2. Blocklist.de (free IP list that attacked server)

                blocklist = requests.get("https://lists.blocklist.de/lists/all.txt", timeout=5)
                if blocklist.status_code == 200:
                    count = 0
                    for ip in blocklist.text.split('\n'):
                        if ip.strip() and count < 100:  # We limit to 100 IP so as not to weigh too much

                            self.threat_db["ip"][ip] = {
                                "type": "Attacking IP",
                                "severity": "Medium",
                                "description": "IP that attempted attacks on public services",
                                "source": "Blocklist.de"
                            }
                            count += 1
                    print(f"Added {count} IPs from Blocklist.de")
            except Exception as e:
                print(f"Error retrieving blocklist: {str(e)}")
                
            # Add Signoutures of common malware

            self.threat_db["signatures"] = {
                "ransomware_extensions": [".crypt", ".locked", ".encrypted", ".crypted", ".cerber", ".locky", ".cryptolocker", ".wallet", ".wcry", ".wncry", ".wncryt", ".onion", ".cryp1", ".zepto"],
                "suspicious_processes": ["mimikatz", "psexec", "lsass.exe dump", "wceservice", "pwdump", "procdump -ma lsass.exe", "regsvr32 /s /u /i:http", "certutil -urlcache -split -f"],
                "c2_patterns": ["beacon.dll", "127.0.0.1,0.0.0.0,", "5jFh3rEn1fJb0GJ6", "POST /submit.php?id=", "GET /news.php?id="],
                "webshell_indicators": ["passthru", "shell_exec", "system(", "eval(base64_decode", "exec(", "eval(gzinflate", "eval($_", "eval(str_rot13", "eval($", "assert("]
            }
            
            # Add common iocs for apt

            self.threat_db["apt"] = {
                "apt29": {
                    "name": "APT29 (Cozy Bear)",
                    "ips": ["185.86.148.227", "103.208.86.230", "185.174.102.60"],
                    "domains": ["pandorasong.com", "worldhostingservice.org", "nopiexchange.com"],
                    "tools": ["PowerDuke", "HAMMERTOSS", "SeaDuke", "CozyCar"]
                },
                "apt28": {
                    "name": "APT28 (Fancy Bear)",
                    "ips": ["176.31.112.10", "95.215.46.27", "86.105.18.116"],
                    "domains": ["acledit.com", "securityprotectingcorp.com", "mvtband.net"],
                    "tools": ["X-Tunnel", "CHOPSTICK", "X-Agent", "Zebrocy"]
                },
                "lazarus": {
                    "name": "Lazarus Group",
                    "ips": ["175.100.189.174", "125.215.173.59", "122.10.41.51"],
                    "domains": ["celasllc.com", "moirafashion.com", "redbankcommunications.com"],
                    "tools": ["BLINDINGCAN", "HOPLIGHT", "ELECTRICFISH", "BADCALL"]
                }
            }
            
            # Add simplified Yara rules

            self.threat_db["yara_rules"] = [
                {
                    "name": "Emotet_Document",
                    "pattern": r"auto_open|document_open|auto_close|workbook_open",
                    "description": "Possible Emotet document with macro"
                },
                {
                    "name": "Cobalt_Strike_Beacon",
                    "pattern": r"MZ.*This program cannot be run in DOS mode.*ReflectiveLoader",
                    "description": "Possible Cobalt Strike Beacon"
                },
                {
                    "name": "Mimikatz_Strings",
                    "pattern": r"kuhl|sekurlsa|kerberos|mimikatz|mimilib|dcsync",
                    "description": "Possible Mimikatz strings"
                }
            ]
                
            print(f"- {len(self.threat_db['ip'])} malicious IPs")
            print(f"- {len(self.threat_db['domains'])} malicious domains")
            print(f"- {len(self.threat_db['patterns'])} attack pattern")
            print(f"- {len(self.threat_db['ports'])} monitored ports")
            print(f"- {len(self.threat_db['file_extensions'])} dangerous file extensions")
            print(f"- {len(self.threat_db['user_agents'])} suspicious user agents")
            print(f"- {len(self.threat_db['hashes'])} hashes of known malware")
            print(f"- {len(self.threat_db['signatures']['ransomware_extensions'])} ransomware extensions")
            print(f"- {len(self.threat_db['apt'])} APT groups")
            print(f"- {len(self.threat_db['yara_rules'])} simplified YARA rules")
        except Exception as e:
            print(f"Error initializing threat database: {str(e)}")
            self.threat_db = {}
        
    # Method to check an IP against the database

    def check_ip(self, ip_address):
        """Check if an IP is present in the threat database"""
        if ip_address in self.threat_db.get("ip", {}):
            return self.threat_db["ip"][ip_address]
        
        # Also check in the APT IP

        for apt_group, apt_data in self.threat_db.get("apt", {}).items():
            if ip_address in apt_data.get("ips", []):
                return {
                    "type": f"APT Infrastructure ({apt_data['name']})",
                    "severity": "High",
                    "description": f"IP associated with APT group {apt_data['name']}"
                }
        
        return None
        
    # Method to verify a domain against the database

    def check_domain(self, domain):
        """Check if a domain is present in the threat database"""
        if domain in self.threat_db.get("domains", {}):
            return self.threat_db["domains"][domain]
        
        # Also check in the APT domains

        for apt_group, apt_data in self.threat_db.get("apt", {}).items():
            if domain in apt_data.get("domains", []):
                return {
                    "type": f"APT Infrastructure ({apt_data['name']})",
                    "severity": "High",
                    "description": f"Domain associated with APT group {apt_data['name']}"
                }
        
        return None
    
    def reset_ml_model(self):
        """Reinitialize the machine learning model and clear all training data"""
        try:
            import os
            from sklearn.linear_model import SGDOneClassSVM
            from sklearn.preprocessing import StandardScaler
            import tkinter as tk
            from tkinter import messagebox
            
            # Ask confirmation before proceeding

            confirm=messagebox.askyesno(
                "Confirm reset",
                "Are you sure you want to reinitialize the ML model?\n\n"
                "This operation will erase all training data, "
                "the false positives stored and the anomalies detected.",
                icon='warning'
            )
            
            if not confirm:
                return False
            
            # Create a new Sgoneclasssvm model

            self.ml_model = SGDOneClassSVM(nu=0.05, random_state=42)
            
            # Reiniziarize the Scaler

            self.scaler = StandardScaler()
            
            # Reset the training flag

            self.ml_model_trained = False
            
            # Reset the meter of processed packages

            self.last_trained_packet_count = 0
            
            # Delete any stored features

            if hasattr(self, 'features'):
                self.features = []
            
            # Delete saved files of the model, if they exist

            models_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "models")
            
            # Make sure the directory exists

            if not os.path.exists(models_dir):
                os.makedirs(models_dir)
            
            # List of possible files to be removed (old and new)

            model_files = [
                os.path.join(models_dir, "isolation_forest_model.pkl"),
                os.path.join(models_dir, "sgd_oneclass_svm_model.pkl"),
                os.path.join(models_dir, "scaler.pkl"),
                os.path.join(models_dir, "last_trained_count.pkl"),
                os.path.join(models_dir, "isolation_forest.joblib"),
                os.path.join(models_dir, "scaler.joblib")
            ]
            
            # Remove all files if they exist

            files_removed = 0
            for file_path in model_files:
                if os.path.exists(file_path):
                    try:
                        os.remove(file_path)
                        print(f"File removed: {file_path}")
                        files_removed += 1
                    except Exception as e:
                        print(f"Unable to remove file: {file_path}, error: {str(e)}")
            
            # Delete any historical data

            if hasattr(self, 'historical_features'):
                self.historical_features = None
            
            # Clear false positives stored

            if hasattr(self, 'known_good_packets'):
                self.known_good_packets = []
            
            # Delete anomalies detected

            if hasattr(self, 'ml_detected_anomalies'):
                self.ml_detected_anomalies = []
            
            print(f"ML model successfully reinitialized ({files_removed} files removed)")
            
            # Update the user interface, if available

            if hasattr(self, 'status_bar'):
                self.status_bar.config(text="ML model reinitialized with SGDOneClassSVM")
            
            # Show confirmation window

            messagebox.showinfo(
                "Done", 
                f"The ML model has been successfully reinitialized!\n\n"
                f"- New Model: SGDOneClassSVM\n"
                f"- {files_removed} files removed\n"
                f"- All training data and false positives deleted"
            )
            
            return True
        
        except Exception as e:
            print(f"Error in reinitializing the ML model: {str(e)}")
            traceback.print_exc()
            
            # Make sure Messagebox is imported here too

            from tkinter import messagebox
            messagebox.showerror("Error", f"Error in reinitializing the ML model: {str(e)}")
            return False


    def is_sql_comment_injection(self, payload):
        """
        Specialized function to determine if a payload contains SQL Comment Injection
        with better detection for binary data and reduced false positives
        
        Returns:
            bool: True if the payload contains SQL Comment Injection, False otherwise
        """
        # If the payload is empty or too short, it cannot be an injection

        if not payload or len(payload) < 20:
            return False
            
        # Calculate distribution and statistics of bytes in the Payload

        byte_counts = {}
        for byte in payload:
            byte_counts[byte] = byte_counts.get(byte, 0) + 1
        
        # Calculate entropy to identify encrypted/compressed data

        import math
        entropia = 0
        for count in byte_counts.values():
            probability = count / len(payload)
            entropia -= probability * math.log2(probability)
        
        # Data with high entropy are probably encrypted, not SQL INJECTION

        if entropia > 6.8:
            return False
        
        # Calculate percentage of binary data in the Payload (more precise)

        printable_ascii = set(range(32, 127))
        binary_count = sum(1 for byte in payload if byte not in printable_ascii)
        binary_percentage = (binary_count / len(payload)) * 100
        
        # If more than 60% of the data are binary, it is unlikely that it is SQL Comment Injection

        if binary_percentage > 60:
            return False
        
        # Check common protocols that generate false positives

        common_protocols = [
            b'SMB', b'HTTP', b'FTP', b'SSH', b'TLS', b'\x00\x00\x00', 
            b'\xff\xff\xff', b'\xfe\xed\xfa\xce'
        ]
        
        for proto in common_protocols:
            if proto in payload:
                # Requires a more rigorous verification for these protocols

                protocol_detected = True
                break
        else:
            protocol_detected = False
        
        # Sql comment relevant patterns

        sql_comment_patterns = [b'--', b'/*', b'*/', b'#']
        
        # Check if there are SQL patterns in the Payload with appropriate context

        has_pattern_with_context = False
        for pattern in sql_comment_patterns:
            pattern_positions = []
            start = 0
            
            # Find all the occurrences of the pattern

            while True:
                index = payload.find(pattern, start)
                if index == -1:
                    break
                pattern_positions.append(index)
                start = index + 1
            
            for pos in pattern_positions:
                # Check context before and after the pattern

                pre_context_start = max(0, pos - 15)
                pre_context = payload[pre_context_start:pos]
                
                post_context_start = pos + len(pattern)
                post_context_end = min(len(payload), post_context_start + 20)
                post_context = payload[post_context_start:post_context_end]
                
                # Valid context: must have legible ASCII characters
                # and a structure that resembles SQL

                
                # It counts ASCII characters readable in the post-Pattern context

                readable_chars = sum(1 for b in post_context if b in printable_ascii)
                if len(post_context) == 0:
                    continue
                    
                readable_ratio = readable_chars / len(post_context)
                
                # Requires a significant sequence of ASCII characters after the pattern
                # and check that it is not a repetitive or random sequence

                if readable_ratio >= 0.7 and len(post_context) >= 8:
                    # Check that it is not a repetitive sequence

                    unique_chars = len(set(post_context))
                    if unique_chars >= min(5, len(post_context) * 0.5):
                        # Also check the previous context

                        pre_readable = sum(1 for b in pre_context if b in printable_ascii)
                        if len(pre_context) > 0 and pre_readable / len(pre_context) >= 0.5:
                            has_pattern_with_context = True
                            break
            
            if has_pattern_with_context:
                break
        
        if not has_pattern_with_context:
            return False
        
        # Check the presence of Keywords SQL with appropriate context

        sql_keywords = [
            b'SELECT', b'INSERT', b'UPDATE', b'DELETE', b'DROP', b'UNION',
            b'FROM', b'WHERE', b'ORDER BY', b'GROUP BY', b'HAVING', b'JOIN',
            b'AND ', b'OR ', b'NOT ', b'IN ', b'LIKE ', b'IS NULL',
            b'select', b'insert', b'update', b'delete', b'drop', b'union',
            b'from', b'where', b'order by', b'group by', b'having', b'join'
        ]
        
        # Check the presence of SQL keywords with appropriate context

        keyword_with_context = False
        for keyword in sql_keywords:
            keyword_positions = []
            start = 0
            
            # Find all the occurrences of the keyword

            while True:
                index = payload.find(keyword, start)
                if index == -1:
                    break
                keyword_positions.append(index)
                start = index + 1
            
            for pos in keyword_positions:
                # Analyze the context around the keyword

                context_start = max(0, pos - 20)
                context_end = min(len(payload), pos + len(keyword) + 20)
                context = payload[context_start:context_end]
                
                # Check that the context is mainly legible ascii

                readable_chars = sum(1 for b in context if b in printable_ascii)
                if len(context) == 0:
                    continue
                    
                context_readable_ratio = readable_chars / len(context)
                
                # Check that the context contains a plausible SQL structure

                if context_readable_ratio >= 0.7:
                    # Check that there are other SQL elements in the context

                    sql_elements = [b'=', b'(', b')', b',', b';', b'\'', b'"']
                    has_sql_elements = any(elem in context for elem in sql_elements)
                    
                    if has_sql_elements:
                        keyword_with_context = True
                        break
            
            if keyword_with_context:
                break
        
        # Check repetitive patterns (municipalities in overflow buffer, not in SQL Injection)

        def has_repetitive_pattern(data, threshold=5):
            if len(data) < threshold * 2:
                return False
            
            # Search for repetitive threshold length patterns

            for i in range(len(data) - threshold):
                pattern = data[i:i+threshold]
                # If the same pattern appears at least 3 times, it is probably repetitive

                if data.count(pattern) >= 3:
                    return True
            return False
        
        # If it contains repetitive repetition patterns of overflow buffer, it is probably not SQL INJECTION

        if has_repetitive_pattern(payload):
            # If it has repetitive patterns, it requires stronger evidence of SQL Injection

            if not keyword_with_context:
                return False
        
        # For known protocols, request more stringent criteria

        if protocol_detected:
            # Requires both patterns and keywords with appropriate context

            return has_pattern_with_context and keyword_with_context
        
        # Character distribution analysis to better identify binary data

        char_distribution = {}
        for byte in payload:
            char_distribution[byte] = char_distribution.get(byte, 0) + 1
        
        # Calculate the standard deviation of the features distribution
        # A uniform distribution is typical of encrypted/compressed data

        mean = len(payload) / len(char_distribution) if char_distribution else 0
        variance = sum((count - mean) ** 2 for count in char_distribution.values()) / len(char_distribution) if char_distribution else 0
        std_dev = math.sqrt(variance)
        
        # Data with low standard deviation are probably encrypted/compressed

        if std_dev < 2.0 and len(char_distribution) > 30:
            return False
        
        # Check the presence of consecutive sequences that form plausible SQL phrases

        def has_sql_phrase(data, min_length=12):
            # Search consecutive ASCII sequences of significant length

            current_seq = 0
            max_seq = 0
            for b in data:
                if b in printable_ascii:
                    current_seq += 1
                    max_seq = max(max_seq, current_seq)
                else:
                    current_seq = 0
            
            # If there is an ASCII ASCII sequence, check if it contains SQL elements

            if max_seq >= min_length:
                # Extract all the ASCII sequences of significant length

                ascii_seqs = []
                current_seq = []
                for b in data:
                    if b in printable_ascii:
                        current_seq.append(b)
                    elif current_seq:
                        if len(current_seq) >= min_length:
                            ascii_seqs.append(bytes(current_seq))
                        current_seq = []
                
                if current_seq and len(current_seq) >= min_length:
                    ascii_seqs.append(bytes(current_seq))
                
                # Check whether these sequences contain SQL elements

                sql_indicators = [b'SELECT', b'INSERT', b'UPDATE', b'DELETE', b'FROM', b'WHERE',
                                b'select', b'insert', b'update', b'delete', b'from', b'where',
                                b'--', b'/*', b'*/', b'#', b'UNION', b'union']
                
                for seq in ascii_seqs:
                    if any(ind in seq for ind in sql_indicators):
                        return True
                
            return False
        
        # Check the presence of SQL phrases in the Payload

        has_sql_phrases = has_sql_phrase(payload)
        
        # If a SQL comment pattern has been detected with appropriate context
        # And the Payload contains SQL or Keywords SQL phrases with context,
        # It is likely that it is SQL Comment Injection

        if has_pattern_with_context and (has_sql_phrases or keyword_with_context):
            return True
        
        # If the percentage of binary data is very low (<30%) and we have an SQL pattern,
        # It could be SQL INJECTION even without explicit keywords

        if has_pattern_with_context and binary_percentage < 30:
            # Check further that it is not a false positive
            # Analyzing the overall Payload structure

            
            # It counts the transitions between ASCII characters and tracks

            transitions = 0
            prev_is_binary = False
            for byte in payload:
                is_binary = byte not in printable_ascii
                if is_binary != prev_is_binary:
                    transitions += 1
                    prev_is_binary = is_binary
            
            # Typical Payload SQLs have few transitions between ASCII and Binary
            # while random binary data can have many transitions

            transition_ratio = transitions / len(payload)
            
            # If it has few length transitions, it is more likely to be SQL

            if transition_ratio < 0.05:
                return True
        
        # Specific verification for Brevi Payload (<100 Byte) with SQL pattern

        if len(payload) < 100 and has_pattern_with_context:
            # For short payloads, we request an even lower percentage of binary data
            # and a stronger presence of SQL elements

            ascii_percentage = 100 - binary_percentage
            if ascii_percentage > 75 and (has_sql_phrases or keyword_with_context):
                return True
        
        # If none of the previous conditions are satisfied, it is probably not SQL comment injection

        return False
    
    
        
    
    def is_binary_encrypted_data(self, payload):
        """
        Determine whether a payload is likely encrypted or encoded binary data.
        With improvements to reduce false positives and negatives.
        """
        if not payload or len(payload) < 16:
            return False
        
        # 1. Entrine analysis with errors protection

        try:
            import math
            
            # It counts for any bytes

            byte_counts = {}
            for byte in payload:
                byte_counts[byte] = byte_counts.get(byte, 0) + 1
            
            # Calculate entropy -the higher it is, the more random (probably encrypted)

            entropy = 0
            for count in byte_counts.values():
                probability = count / len(payload)
                entropy -= probability * math.log2(probability)
        except Exception as e:
            print(f"Error in the calculation of entropy: {str(e)}")
            entropy = 0  # Conservative default

        
        # It counts ASCII VS Non-ASCII characters

        ascii_count = sum(1 for byte in payload if 32 <= byte <= 126)
        binary_count = len(payload) - ascii_count
        binary_percentage = (binary_count / len(payload)) * 100
        
        # Calculate the number of unique bytes (important for encrypted data)

        unique_bytes = len(byte_counts)
        unique_percentage = (unique_bytes / min(256, len(payload))) * 100
        
        # 3. Analysis of the sequences

        
        # Search for repetitive sequences (an indication of structured data vs. cryptic)

        repeating_sequences = 0
        for length in [3, 4]:  # Search sequences of 3-4 bytes

            sequences = {}
            for i in range(len(payload) - length):
                seq = bytes(payload[i:i+length])
                sequences[seq] = sequences.get(seq, 0) + 1
            
            # Counts sequences that appear more than 3 times

            repeating_sequences += sum(1 for count in sequences.values() if count > 3)
        
        # 4

        
        # Innocui encrypted data criteria (high entropy, few repetitions, many unique bytes)

        is_likely_encrypted = (
            entropy > 7.0 and  
            repeating_sequences < 5 and
            binary_percentage > 50 and
            unique_percentage > 30  
        )
        
        # Innocui coded data criteria (e.g. innocui protocols)

        is_likely_binary_protocol = (
            5.0 <= entropy <= 7.5 and  
            binary_percentage > 50
        )
        
        # Criteria for very small packages with high entropy

        is_small_encrypted_packet = (
            len(payload) < 50 and
            entropy > 6.5 and
            binary_percentage > 70
        )
        
        # Criteria for very large data packages with high entropy

        is_large_data_packet = (
            len(payload) > 200 and
            entropy > 6.8 and
            unique_percentage > 25 and
            binary_percentage > 60
        )
        
        # Pattern of common headers for safe track protocols

        safe_headers = [
            b'\x00\x00\x01\x00',  # Common header in some binary protocols

            b'\xff\xd8\xff',      # Header JPEG

            b'\x89\x50\x4e\x47',  # Header PNG

            b'\x1f\x8b',          # Header GZIP

            b'\x50\x4b\x03\x04',  # Header ZIP/JAR

            b'\x42\x5a\x68',      # Header BZ2

            b'\xd0\xcf\x11\xe0',  # Header MS Office

            b'\x4d\x5a',          # Header EXE

            b'\x7f\x45\x4c\x46',  # Header ELF

            b'\x23\x21'           # Header script

        ]
        
        has_safe_header = any(payload.startswith(header) for header in safe_headers if len(header) <= len(payload))
        
        # Check also common initial bytes in safe protocols

        common_initial_bytes = [0x00, 0xff, 0x1f, 0x50, 0x89, 0x42, 0x4e, 0xd0, 0x4d, 0x7f, 0x23]
        starts_with_common_byte = len(payload) > 0 and payload[0] in common_initial_bytes
        
        # Check the uniform distribution of bytes (important for encrypted data)

        max_count = max(byte_counts.values()) if byte_counts else 0
        uniform_distribution = max_count < (len(payload) * 0.1)  # No bytes> 10% of the total

        
        # Check obvious repetitive patterns (unusual in encrypted data)

        has_obvious_patterns = any(pattern in payload and payload.count(pattern) > 3 
                                for pattern in [b'\x00\x00\x00\x00', b'\xff\xff\xff\xff', 
                                                b'\x90\x90\x90\x90', b'\x41\x41\x41\x41'])
        
        # Check the presence of long ASCII strings (unusual in encrypted data)

        current_ascii_run = 0
        has_long_ascii_strings = False
        for byte in payload:
            if 32 <= byte <= 126:
                current_ascii_run += 1
                if current_ascii_run >= 10:  # 10+ consecutive ASCII characters

                    has_long_ascii_strings = True
                    break
            else:
                current_ascii_run = 0
                # Additional verification for packages with potential hidden threats

        is_suspicious_despite_entropy = False
        if entropy > 6.5:
            try:
                # Check if there are attack patterns hidden in the binary data

                suspicious_patterns = [
                    b'eval(', b'exec(', b'shell_exec(', b'system(',   # PHP/Command

                    b'cmd.exe', b'powershell', b'/bin/sh', b'/bin/bash',  # Shell

                    b'SELECT ', b'UNION SELECT', b'INSERT INTO',      # Sql

                    b'<script>', b'javascript:', b'onerror='          # Xss

                ]
                is_suspicious_despite_entropy = any(pattern in payload for pattern in suspicious_patterns)
            except:
                pass
        
        # Further control for data that are not unequivocally threats

        likely_not_threat = (
            has_safe_header or 
            starts_with_common_byte or
            is_likely_encrypted or 
            is_likely_binary_protocol or
            is_small_encrypted_packet or
            is_large_data_packet or
            (entropy > 6.5 and uniform_distribution and not has_obvious_patterns and not has_long_ascii_strings)
        )
        
        # A threat could be hidden in data that seem encrypted

        if likely_not_threat and is_suspicious_despite_entropy:
            return False  # Don't consider it as harmless data

        
        return likely_not_threat


    def is_legitimate_smb_traffic(self, packet, session_context=None):
        """
        Check if SMB traffic is legitimate to reduce false positives.
        It uses in-depth payload analysis, network context, and session information.
        
        Args:
            packet (dict): Network packet with keys such as 'src', 'dst', 'sport', 'dport', 'payload', 'tcp_flags'
            session_context (dict, optional): Current session context (previous packets, state)
            
        Returns:
            tuple: (is_legitimate, explanation) where:
                - is_legitimate (bool): True if SMB traffic is considered legitimate
                - explanation (str): Detailed explanation of the packet/traffic type
        """
        # Check if it's SMB traffic

        src_port = packet.get('sport')
        dst_port = packet.get('dport')
        
        # If it is not SMB traffic, it is not relevant for this function

        if not (src_port == 445 or dst_port == 445 or src_port == 139 or dst_port == 139):
            return False, "It's not SMB traffic"
        
        # Extract essential information

        src_ip = packet.get('src', '')
        dst_ip = packet.get('dst', '')
        payload = packet.get('payload', b'')
        tcp_flags = packet.get('tcp_flags', {})
        packet_len = packet.get('length', 0)
        timestamp = packet.get('timestamp', 0)
        
        # Function to check if an IP is private (RFC1918 networks)

        def is_private_ip(ip):
            if not ip:
                return False
            
            # Check common private networks

            if ip.startswith('192.168.') or ip.startswith('10.') or ip.startswith('127.'):
                return True
            
            # Check range 172.16.0.0/12

            if ip.startswith('172.'):
                try:
                    second_octet = int(ip.split('.')[1])
                    if 16 <= second_octet <= 31:
                        return True
                except (ValueError, IndexError):
                    pass
            
            return False
        
        # Determine if it is private network traffic

        in_private_network = is_private_ip(src_ip) and is_private_ip(dst_ip)
        
        # Client-Server communication pattern

        client_server_pattern = ((src_port == 445 or src_port == 139) and dst_port > 1023) or \
                            ((dst_port == 445 or dst_port == 139) and src_port > 1023)
        
        # Management of Payload Packages

        if not payload or len(payload) < 4:
            # TCP Flag analysis to determine the type of package

            if tcp_flags:
                # Handshake TCP

                if tcp_flags.get('syn') and not tcp_flags.get('ack'):
                    return True, "Handshake TCP: SYN (SMB connection initialization)"
                
                if tcp_flags.get('syn') and tcp_flags.get('ack'):
                    return True, "Handshake TCP: SYN-ACK (SMB initialization response)"
                
                if tcp_flags.get('ack') and not any([tcp_flags.get(f) for f in ['syn', 'fin', 'rst', 'psh']]):
                    return True, "TCP: ACK (SMB Packet Confirmation)"
                
                # Connection termination

                if tcp_flags.get('fin'):
                    return True, "TCP: FIN (SMB connection closure)"
                
                if tcp_flags.get('rst'):
                    # RST can be legitimate (abnormal closure) or suspicion (port scanning)

                    if session_context and session_context.get('established', False):
                        return True, "TCP: RST (Abnormal termination of SMB connection established)"
                    else:
                        # If there is no established session, it could be a port scan

                        if in_private_network:
                            return True, "TCP: RST (Possible early termination or SMB error)"
                        else:
                            return False, "TCP: RST without established session (SMB port scanning possible)"
                
                # Keepalive o window update

                if tcp_flags.get('ack') and packet_len <= 60:  # Typically Header TCP without data

                    return True, "TCP: Keepalive or window update SMB"
            
            # If we have no information on the TCP flag, we evaluate according to other factors

            if in_private_network:
                if client_server_pattern:
                    return True, "SMB control packet on private network (no payload)"
                elif dst_ip.endswith('.255') or dst_ip == '255.255.255.255':
                    return True, "SMB broadcast/discovery packet (without payload)"
                else:
                    return True, "SMB packet without payload on private network"
            else:
                # For external traffic, we are more cautious with payloadless packages

                if client_server_pattern:
                    # Check session context if available

                    if session_context and session_context.get('established', False):
                        return True, "External SMB control packet in established session"
                    else:
                        # We consider legitimate initialization packages

                        if not session_context or len(session_context.get('packets', [])) < 5:
                            return True, "Possible External SMB Session Initialization"
                        else:
                            return False, "Multiple external SMB packets without payload (scanning possible)"
                else:
                    return False, "External SMB packet without payload with unusual port pattern"
        
        # Rule #1: Check Standard Marker SMB

        has_smb_marker = b'SMB' in payload or b'\xffSMB' in payload
        
        # Adjust #2: verification of evident exploit patterns

        exploit_patterns = [
            # Buffer overflow patterns

            b'\x41\x41\x41\x41\x41\x41\x41\x41',  # 8+ 'A' consecutive

            b'\x90\x90\x90\x90\x90\x90\x90\x90',  # 8+ nop consecutivi

            
            # Command injection patterns

            b'cmd.exe', b'powershell', b'/bin/sh', b'/bin/bash',
            
            # Path traversal patterns

            b'../../../', b'..\\..\\..\\',
            
            # Shellcode markers

            b'\xfc\xe8\x82\x00\x00\x00\x60\x89',  # Common shellcode header

            b'\x31\xc0\x50\x68\x2f\x2f\x73\x68',  # Common shellcode pattern

            
            # EternalBlue/DoublePulsar indicators

            b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',  # Suspicious padding

            b'\x57\x00\x69\x00\x6e\x00\x64\x00\x6f\x00\x77\x00\x73\x00\x20\x00'  # "Windows " in UTF-16LE (comune in exploit)

        ]
        
        has_exploit_pattern = False
        exploit_details = []
        
        for pattern in exploit_patterns:
            if pattern in payload:
                # Check that the pattern occupies a significant portion

                pattern_occurrences = payload.count(pattern)
                pattern_coverage = (pattern_occurrences * len(pattern)) / len(payload)
                
                # If the pattern covers more than 15% of the payload, we consider suspicion

                if pattern_coverage > 0.15:
                    has_exploit_pattern = True
                    exploit_details.append(f"Suspicious pattern: {pattern[:8]}... ({pattern_coverage:.1%} payload)")
                    if len(exploit_details) >= 2:  # Limit to 2 details not to overload

                        break
        
        # Rule #3: analysis of the structure of the SMB package

        def analyze_smb_structure(data):
            """Parse the SMB structure and return (is_valid, details)"""
            # SMB1 header check

            if len(data) >= 8 and data.startswith(b'\xff\x53\x4d\x42'):
                command_code = data[4] if len(data) > 4 else 0
                # Map of the SMB1 Commands

                smb1_commands = {
                    0x72: "Negotiate Protocol",
                    0x73: "Session Setup",
                    0x75: "Tree Connect",
                    0x2d: "Trans2 (Secondary)",
                    0x2e: "Trans2",
                    0x2f: "Trans2 (Reply)",
                    0x25: "Trans",
                    0x26: "Trans (Secondary)",
                    0x27: "Trans (Reply)",
                    0xa2: "NT Create/Open",
                    0x24: "Locking",
                    0x08: "Query Information",
                    0x71: "Tree Disconnect",
                    0x74: "Logoff"
                }
                command_name = smb1_commands.get(command_code, f"Unknown ({command_code:02x})")
                return True, f"SMB1 {command_name}"
                
            # SMB2 header check

            if len(data) >= 8 and data.startswith(b'\xfe\x53\x4d\x42'):
                command_code = data[12] if len(data) > 12 else 0
                # SMB2 control map of the Municipalities

                smb2_commands = {
                    0x00: "Negotiate",
                    0x01: "Session Setup",
                    0x02: "Logoff",
                    0x03: "Tree Connect",
                    0x04: "Tree Disconnect",
                    0x05: "Create",
                    0x06: "Close",
                    0x07: "Flush",
                    0x08: "Read",
                    0x09: "Write",
                    0x0a: "Lock",
                    0x0b: "IOCtl",
                    0x0c: "Cancel",
                    0x0d: "Echo",
                    0x0e: "Query Directory",
                    0x0f: "Change Notify",
                    0x10: "Query Info",
                    0x11: "Set Info"
                }
                command_name = smb2_commands.get(command_code, f"Unknown ({command_code:02x})")
                return True, f"SMB2 {command_name}"
                
            # NetBIOS session header check

            if len(data) >= 4 and data[0] in [0x00, 0x81, 0x82, 0x83, 0x84]:
                message_types = {
                    0x00: "Session Message",
                    0x81: "Session Request",
                    0x82: "Positive Session Response",
                    0x83: "Negative Session Response",
                    0x84: "Retarget Session Response",
                    0x85: "Session Keep Alive"
                }
                message_type = message_types.get(data[0], f"Unknown ({data[0]:02x})")
                
                # Check that the declared length is coherent

                declared_length = (data[1] << 16) + (data[2] << 8) + data[3]
                if declared_length <= len(data) - 4:
                    # Check if the payload after Header Netbios contains SMB

                    if len(data) >= 8 and (b'SMB' in data[4:8] or b'\xffSMB' in data[4:8]):
                        # Recursive analysis of the Internal Payload Smb

                        is_valid_inner, details_inner = analyze_smb_structure(data[4:])
                        if is_valid_inner:
                            return True, f"NetBIOS {message_type} con {details_inner}"
                    return True, f"NetBIOS {message_type}"
                else:
                    return False, f"NetBIOS {message_type} with invalid declared length"
            
            # Smb Marker in any position in the first 16 bytes

            if len(data) >= 16 and (b'SMB' in data[:16] or b'\xffSMB' in data[:16]):
                return True, "Contains SMB markers (non-standard position)"
            
            return False, "SMB structure not recognized"
        
        valid_structure, structure_details = analyze_smb_structure(payload)
        
        # Rule #4: Verification typical dimensions of SMB packages
        # Note: we lowered the minimum 8 byte threshold instead of 32

        valid_size = 8 <= len(payload) <= 4096  # Typical size SMB packages

        
        # Rule #5: behavior analysis over time (if the session context is available)

        session_anomalies = []
        if session_context:
            # Check package frequency

            session_packets = session_context.get('packets', [])
            if len(session_packets) >= 5:
                # Calculate medium interval between packages

                timestamps = [p.get('timestamp', 0) for p in session_packets if p.get('timestamp', 0) > 0]
                if len(timestamps) >= 2:
                    intervals = [timestamps[i] - timestamps[i-1] for i in range(1, len(timestamps))]
                    avg_interval = sum(intervals) / len(intervals)
                    
                    # Packages too quickly could indicate scanning or dos

                    if avg_interval < 0.01 and len(session_packets) > 10:  # More than 10 packages with less than 10ms of interval

                        session_anomalies.append("Abnormal packet rate (possible DoS)")
            
            # Check multiple connection attempts

            syn_count = sum(1 for p in session_packets if p.get('tcp_flags', {}).get('syn', False))
            if syn_count >= 3:
                session_anomalies.append("Multiple connection attempts (possible scanning)")
        
        
        # If it is on a private network, we apply more permissive but still rigorous criteria

        if in_private_network:
            # If it has SMB Marker and valid structure, it is almost certainly legitimate

            if has_smb_marker and valid_structure:
                # Unless it contains evident exploit patterns

                if has_exploit_pattern:
                    return False, f"SMB traffic on private network with exploit pattern: {', '.join(exploit_details)}"
                
                # Unless there are serious session anomalies

                if session_anomalies and len(session_anomalies) >= 2:
                    return False, f"SMB traffic on private network with session anomalies: {', '.join(session_anomalies)}"
                    
                return True, f"Legitimate SMB traffic on private network: {structure_details}"
                
            # If it has a valid structure and typical size, it is probably legitimate

            if valid_structure and valid_size and client_server_pattern:
                if has_exploit_pattern:
                    return False, f"SMB traffic on private network with valid structure but suspicious patterns: {', '.join(exploit_details)}"
                return True, f"Legitimate SMB traffic on private network: {structure_details}"
                
            # If you have no SMB Marker but it has a typical size and client-server patterns
            # It could be an incomplete fragment or package

            if valid_size and client_server_pattern:
                # Check further characteristics typical of SMB packages
                # as specific initial bytes

                if len(payload) > 0 and payload[0] in [0x00, 0x81, 0x82, 0x83, 0x84, 0xff, 0xfe]:
                    return True, f"Legitimate SMB fragment on private network (initial byte: 0x{payload[0]:02x})"
                    
                # If it is part of an established session, it could be a legitimate fragment

                if session_context and session_context.get('established', False):
                    return True, "Session-Established SMB Fragment (Private Network)"
                
                # If it is a small package, it could be part of a negotiation

                if len(payload) < 20:
                    return True, "Small SMB packet in private network (negotiation possible)"
                    
                # Otherwise, it is suspicious but not necessarily malicious

                return False, "SMB package on private network with non-standard structure"
                    
            # Special Rule for Netbios/Smb Broadcast packages

            if dst_ip.endswith('.255') or dst_ip == '255.255.255.255':
                if valid_size and len(payload) < 200:  # Broadcast packages are typically small

                    return True, "SMB/NetBIOS broadcast package on private network"
                
            # For packages that do not fall within the previous categories
            # But I'm on a private network, we make a more in -depth analysis

            
            # Check if the package contains legible aste astes (it could be a message)

            printable_ascii = set(range(32, 127))
            ascii_ratio = sum(1 for b in payload if b in printable_ascii) / len(payload) if payload else 0
            
            if ascii_ratio > 0.7 and len(payload) > 20:
                # It could be a SMB message or command
                # But let's check that it does not contain exploit patterns

                if has_exploit_pattern:
                    return False, f"SMB packet on private network with high ASCII content and suspicious patterns: {', '.join(exploit_details)}"
                return True, "SMB packet on private network with high ASCII content (possible message/command)"
            
            # If it does not correspond to any of the previous categories, we consider suspicion

            return False, "SMB packet on private network with unrecognized anomalous structure"
        else:
            # For external traffic, we require much more rigorous criteria

            
            # Must have Marker SMB, valid structure and no exploit patterns

            if has_smb_marker and valid_structure and client_server_pattern:
                if has_exploit_pattern:
                    return False, f"External SMB traffic with exploit pattern: {', '.join(exploit_details)}"
                    
                if session_anomalies:
                    return False, f"External SMB traffic with session anomalies: {', '.join(session_anomalies)}"
                    
                return True, f"Legitimate external SMB traffic: {structure_details}"
            
            # For external SMB traffic without marker SMB or unrealized structure

            if client_server_pattern and valid_size:
                # If it is part of an established session, it could be a legitimate fragment

                if session_context and session_context.get('established', False) and not has_exploit_pattern:
                    return True, "SMB fragment in established session (external traffic)"
                
                # Otherwise, we consider suspicion

                return False, "External SMB package with non-standard structure"
            
            # For any other type of external SMB traffic, we consider suspicion

            return False, "External SMB traffic with anomalous characteristics"
        
        # This point should never be reached, but for safety

        return False, "Analisi SMB inconclusiva"



    def is_potential_threat(self, packet):
        """Determines if a packet is a potential threat with a reduced probability of false positives"""
        try:
            # 0. Debug Logging to help understand why a package is reported

            is_debug = False  # True tax to activate the debug

            packet_id = id(packet)
            
            def debug_log(message):
                if is_debug:
                    print(f"[Debug][Packet {packet_id}] {message}")

            # Private IP check helper function with better error handling

            def is_private_ip(ip):
                try:
                    return ipaddress.ip_address(ip).is_private
                except (ValueError, TypeError):
                    # Return False for invalid IPs or None values

                    return False

            # Check for common administration traffic that shouldn't be flagged

            if 'src' in packet and 'dst' in packet:
                # If both source and destination are private IPs, less likely to be a threat

                if is_private_ip(packet.get('src', '')) and is_private_ip(packet.get('dst', '')):
                    # Check common management protocols and ports

                    management_ports = {22, 3389, 636, 389, 445, 88, 5985, 5986}
                    src_port = packet.get('sport', 0)
                    dst_port = packet.get('dport', 0)
                    
                    # Common management traffic between private IPs is less suspicious

                    if src_port in management_ports or dst_port in management_ports:
                        debug_log(f"Internal management traffic on port {src_port if src_port in management_ports else dst_port}")
                        # Don't immediately return False -still check for dangerous payloads

            
            if 'payload' in packet:
                # 0.1 Preliminary verification for generic encrypted binary data
                # This check can intercept many non -classified binary anomalies

                if self.is_binary_encrypted_data(packet['payload']):
                    debug_log("Possibly harmless encrypted/encoded binary data detected")
                    return False
                
                # 0.2 Improvement: verification of non -classified common track protocols

                common_protocols = [
                    (b'HTTP/', "HTTP"),
                    (b'GET ', "HTTP GET"),
                    (b'POST ', "HTTP POST"),
                    (b'SSH-', "SSH"),
                    (b'\x16\x03', "TLS/SSL"),
                    (b'SMTP', "SMTP"),
                    (b'220 ', "SMTP Server Response"),
                    (b'IMAP', "IMAP"),
                    (b'POP3', "POP3"),
                    (b'RTSP/', "RTSP"),
                    (b'SIP/', "SIP"),
                    (b'INVITE ', "SIP INVITE"),
                    (b'REGISTER ', "SIP REGISTER"),
                    (b'\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00', "DNS Query")
                ]
                
                for pattern, protocol_name in common_protocols:
                    if pattern in packet['payload'][:20]:  # Search in the first 20 bytes

                        debug_log(f"Legitimate protocol traffic detected {protocol_name}")
                        return False
                
                # 0.3 Improvement: Check common file formats in packages

                file_signatures = [
                    (b'PK\x03\x04', "ZIP"),
                    (b'\x50\x4b\x03\x04', "ZIP"),
                    (b'\x1f\x8b\x08', "GZIP"),
                    (b'\x42\x5a\x68', "BZIP2"),
                    (b'\x89\x50\x4e\x47\x0d\x0a\x1a\x0a', "PNG"),
                    (b'\xff\xd8\xff', "JPEG"),
                    (b'GIF8', "GIF"),
                    (b'%PDF', "PDF"),
                    (b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1', "MS Office"),
                    (b'\x50\x4b\x03\x04\x14\x00\x06\x00', "DOCX/XLSX/PPTX")
                ]
                
                for signature, file_type in file_signatures:
                    if packet['payload'].startswith(signature):
                        debug_log(f"Legitimate file transfer of type detected {file_type}")
                        return False
                
                # Check payload for actual threats (script injections, etc.)

                try:
                    payload_str = packet['payload'].decode('utf-8', errors='ignore')
                    
                    # Check for web attacks

                    web_attack_patterns = [
                        r'(?:<script>|<img[^>]+onerror=|javascript:)',  # Xss

                        r'(?:SELECT.*FROM|INSERT.*INTO|UPDATE.*SET).*(?:--|#|\/\*)(?:.*=.*\bOR\b)',  # SQL Injection

                        r'(?:\.\.\/\.\.\/|\.\.\\\.\.\\|\/etc\/passwd|\/etc\/shadow)', # Path traversal

                        r'(?:eval\s*\(\s*base64_decode|system\s*\(|exec\s*\(|passthru\s*\()',  # Code injection

                        r'(?:wget\s+http|curl\s+\-O|powershell\s+\-enc)'  # Command injection

                    ]
                    for pattern in web_attack_patterns:
                        if re.search(pattern, payload_str, re.IGNORECASE):
                            debug_log(f"Web attack pattern detected: {pattern}")
                            return True
                except:
                    pass  # Binary data that can't be decoded as UTF-8

            
            # Check IP against known threats

            if 'src' in packet and hasattr(self, 'threat_db') and 'ip' in self.threat_db:
                if packet['src'] in self.threat_db['ip']:
                    debug_log(f"Source IP {packet['src']} known as malicious")
                    return True
            
            if 'dst' in packet and hasattr(self, 'threat_db') and 'ip' in self.threat_db:
                if packet['dst'] in self.threat_db['ip']:
                    debug_log(f"Destination IP {packet['dst']} known as malicious")
                    return True
            
            # Check for suspicious port usage

            if packet.get('proto_name') == 'TCP' or packet.get('proto_name') == 'UDP':
                suspicious_ports = {
                    4444, 1337, 31337,  # Common backdoor/reverse shell ports

                    6660, 6661, 6662, 6663, 6664, 6665, 6666, 6667, 6668, 6669,  # IRC (botnet C&C)

                    9001, 9030  # Tor

                }
                
                # Check source port

                if packet.get('sport') in suspicious_ports:
                    debug_log(f"Suspicious source port: {packet.get('sport')}")
                    return True
                    
                # Check destination port

                if packet.get('dport') in suspicious_ports:
                    debug_log(f"Suspicious Destination Port: {packet.get('dport')}")
                    return True
            
            # Port scanning detection

            if packet.get('proto_name') == 'TCP' and 'flags' in packet:
                # TCP SYN scan -minimal packet with just SYN flag

                flags = packet.get('flags', 0)
                syn_only = (flags & 0x02) and not (flags & ~0x02)
                
                if syn_only and 'payload' in packet and len(packet['payload']) == 0:
                    # Check if we have history of multiple ports being scanned

                    if hasattr(self, 'scan_detection'):
                        src_ip = packet.get('src', '')
                        timestamp = packet.get('time', 0)
                        
                        # First seen or more than 60s since last seen -reset counter

                        if src_ip not in self.scan_detection or (timestamp - self.scan_detection[src_ip]['last_time']) > 60:
                            self.scan_detection[src_ip] = {
                                'ports': {packet.get('dport', 0)},
                                'last_time': timestamp,
                                'count': 1
                            }
                        else:
                            # Update existing entry

                            self.scan_detection[src_ip]['ports'].add(packet.get('dport', 0))
                            self.scan_detection[src_ip]['last_time'] = timestamp
                            self.scan_detection[src_ip]['count'] += 1
                            
                            # If the same IP has connected to multiple different ports in a short time, it's likely scanning

                            if len(self.scan_detection[src_ip]['ports']) >= 5:
                                debug_log(f"Possible port scan detected by {src_ip} ({len(self.scan_detection[src_ip]['ports'])} ports)")
                                return True
                    else:
                        # Initialize scan detection

                        self.scan_detection = {}
                        
            return False
            
        except Exception as e:
            print(f"Error in threat verification: {str(e)}")
            # In case of error, it is better to be cautious and not report as a threat

            return False
        
    
    def classify_threat(self, packet):
        """Classify threat type and severity with advanced analytics"""
        try:
            src_ip = packet.get('src', '')
            dst_ip = packet.get('dst', '')
            proto = packet.get('proto_name', '')
            sport = packet.get('sport', 0)
            dport = packet.get('dport', 0)
            
            # 1. IP control known in the threat database

            
            if src_ip in self.threat_db.get("ip", {}):
                return self.threat_db["ip"][src_ip]["type"], self.threat_db["ip"][src_ip]["severity"]
            
            if dst_ip in self.threat_db.get("ip", {}):
                return self.threat_db["ip"][dst_ip]["type"], self.threat_db["ip"][dst_ip]["severity"]
            
            # 2. Note APT groups control

            
            if hasattr(self, 'threat_db') and 'apt' in self.threat_db:
                for apt_id, apt_data in self.threat_db['apt'].items():
                    if src_ip in apt_data.get('ips', []) or dst_ip in apt_data.get('ips', []):
                        return f"APT Infrastructure ({apt_data['name']})", "High"
            
            # 3.1 Doors control notes as malicious

            if proto in ['TCP', 'UDP']:
                sport_str = str(sport)
                dport_str = str(dport)
                
                if sport_str in self.threat_db.get("ports", {}):
                    return self.threat_db["ports"][sport_str]["type"], self.threat_db["ports"][sport_str]["severity"]
                
                if dport_str in self.threat_db.get("ports", {}):
                    return self.threat_db["ports"][dport_str]["type"], self.threat_db["ports"][dport_str]["severity"]
            
            # 3.2 Specific detection by type of protocol

            
            # Port Scan detection

            if proto == 'TCP' and 'flags_str' in packet:
                flags_str = packet.get('flags_str', '')
                
                # SYN scan

                if 'S' in flags_str and 'A' not in flags_str and ('payload' not in packet or len(packet.get('payload', b'')) == 0):
                    return "Port Scan (SYN)", "Medium"
                
                # FIN/XMAS scan

                if ('F' in flags_str or 'U' in flags_str or 'P' in flags_str) and 'A' not in flags_str and 'S' not in flags_str:
                    return "Port Scan (FIN/XMAS)", "Medium"
                
                # NULL scan

                if flags_str == '' or flags_str == '0':
                    return "Port Scan (NULL)", "Medium"
            
            # 4. Payload analysis to identify specific types of attack

            
            if 'payload' in packet and packet['payload']:
                payload = packet['payload']
                
                try:
                    # Decodifies the payload for analysis

                    payload_str = payload.decode('latin-1', errors='ignore')
                    
                    # 4.1 Analysis based on pattern in database

                    if hasattr(self, 'threat_db') and 'patterns' in self.threat_db:
                        matched_patterns = []
                        
                        for pattern_info in self.threat_db['patterns']:
                            pattern = pattern_info['regex']
                            if re.search(pattern, payload_str, re.IGNORECASE):
                                # Exclusions to reduce false positives

                                if proto == 'DNS' and ('_services' in payload_str or '_dns-sd' in payload_str):
                                    continue
                                    
                                matched_patterns.append(pattern_info)
                        
                        # If we have found correspondences, use the one with higher severity

                        if matched_patterns:
                            # Order for severity (high> media> low)

                            severity_order = {"High": 3, "Medium": 2, "Low": 1}
                            matched_patterns.sort(key=lambda x: severity_order.get(x['severity'], 0), reverse=True)
                            
                            return matched_patterns[0]['type'], matched_patterns[0]['severity']
                    
                    
                    # 4.2.1 Web attacks

                    if proto == 'HTTP':
                        # SQL Injection

                        sql_patterns = [
                            r'(?:union\s+select|select\s+.*\s+from|insert\s+into|update\s+.*\s+set|delete\s+from)',
                            r'(?:--\s|#\s|\/\*.*?\*\/)',
                            r'(?:or\s+1=1|and\s+1=1|\'\s+or\s+\'1\'=\'1)',
                            r'(?:exec\s+xp_|sp_executesql)'
                        ]
                        
                        for pattern in sql_patterns:
                            if re.search(pattern, payload_str, re.IGNORECASE):
                                return "SQL Injection", "High"
                        
                        # XSS (Cross-Site Scripting)

                        xss_patterns = [
                            r'<script.*?>.*?<\/script>',
                            r'javascript:.*?\(.*?\)',
                            r'(?:onload|onerror|onmouseover|onclick|onfocus)\s*=',
                            r'document\.(?:cookie|location|referrer)',
                            r'(?:alert|confirm|prompt)\s*\('
                        ]
                        
                        for pattern in xss_patterns:
                            if re.search(pattern, payload_str, re.IGNORECASE):
                                return "Cross-Site Scripting (XSS)", "High"
                        
                        # Path Traversal /LFI

                        path_patterns = [
                            r'(?:\.\.\/){2,}',
                            r'(?:\.\.\\){2,}',
                            r'\/etc\/(?:passwd|shadow|hosts)',
                            r'c:\\windows\\',
                            r'\/var\/www\/',
                            r'\/proc\/self\/'
                        ]
                        
                        for pattern in path_patterns:
                            if re.search(pattern, payload_str, re.IGNORECASE):
                                return "Path Traversal / LFI", "High"
                        
                        # Command Injection

                        cmd_patterns = [
                            r';.*?(?:bash|sh|cmd\.exe|powershell)',
                            r'(?:\||&|\$\(|\`)\s*(?:wget|curl|nc|netcat|bash)',
                            r'>\s*\/dev\/tcp\/',
                            r'2>&1'
                        ]
                        
                        for pattern in cmd_patterns:
                            if re.search(pattern, payload_str, re.IGNORECASE):
                                return "Command Injection", "High"
                    
                    # 4.2.2 Malware e backdoor

                    
                    # Webshell detection

                    webshell_patterns = [
                        r'(?:eval|assert)\s*\(\s*(?:\$_POST|\$_GET|\$_REQUEST|\$_COOKIE)',
                        r'base64_decode\s*\(\s*[\'"]',
                        r'system\s*\(\s*(?:\$_POST|\$_GET)',
                        r'passthru\s*\(',
                        r'shell_exec\s*\(',
                        r'preg_replace\s*\([\'"].*\/e'
                    ]
                    
                    for pattern in webshell_patterns:
                        if re.search(pattern, payload_str, re.IGNORECASE):
                            return "Web Shell", "High"
                    
                    # C&C traffic detection

                    cc_patterns = [
                        r'beacon\.dll',
                        r'(?:POST|GET)\s+\/[a-zA-Z0-9]{16,}',
                        r'User-Agent:\s+(?:Mozilla\/4\.0|MSIE\s+7\.0).{0,30}Windows\s+NT\s+\d\.\d;\s+WOW64;\s+Trident\/\d\.\d;',
                        r'(?:check|command|status|result)=[a-zA-Z0-9+\/]{20,}'
                    ]
                    
                    for pattern in cc_patterns:
                        if re.search(pattern, payload_str, re.IGNORECASE):
                            return "Command & Control Traffic", "High"
                    
                    # 4.2.3 Data Esfiltration

                    exfil_patterns = [
                        r'(?:username|password|passwd|pwd|user|login|email)=.{5,}',
                        r'(?:credit|card|cvv|expir)=\d{12,}',
                        r'(?:ssn|social|tax)=\d{3}-\d{2}-\d{4}',
                        r'base64[,;:=][A-Za-z0-9+\/]{100,}='
                    ]
                    
                    for pattern in exfil_patterns:
                        if re.search(pattern, payload_str, re.IGNORECASE):
                            return "Data Exfiltration", "High"
                    
                    # 4.2.4 Crypto mining

                    mining_patterns = [
                        r'(?:stratum\+tcp|mining|miner)',
                        r'(?:xmr|monero|btc|bitcoin|eth|ethereum)',
                        r'(?:hashrate|difficulty|nonce)',
                        r'(?:cryptonight|ethash|equihash)'
                    ]
                    
                    for pattern in mining_patterns:
                        if re.search(pattern, payload_str, re.IGNORECASE):
                            return "Crypto Mining", "Medium"
                    
                    # 4.2.5 Vulnerability scan/exploit

                    scan_patterns = [
                        r'(?:nmap|nikto|gobuster|dirb|wpscan|sqlmap)',
                        r'(?:CVE-\d{4}-\d{4,})',
                        r'(?:metasploit|meterpreter|reverse_tcp)',
                        r'(?:exploit|vulnerability|injection)'
                    ]
                    
                    for pattern in scan_patterns:
                        if re.search(pattern, payload_str, re.IGNORECASE):
                            return "Vulnerability Scanning", "Medium"
                
                except Exception as e:
                    print(f"Error parsing the payload: {str(e)}")
            
            # 5. Classification based on network behavior

            
            # 5.1 RILEVAL OF/DDOS

            if proto == 'TCP' and 'flags_str' in packet:
                flags_str = packet.get('flags_str', '')
                
                # SYN flood

                if 'S' in flags_str and 'A' not in flags_str:
                    return "DoS/DDoS (SYN Flood)", "High"
                
                # ACK flood

                if 'A' in flags_str and 'S' not in flags_str and 'P' not in flags_str and 'F' not in flags_str:
                    return "DoS/DDoS (ACK Flood)", "High"
            
            # 5.2 DNS tunnel detection

            if proto == 'DNS' and 'payload' in packet:
                payload = packet['payload']
                
                # DNS Tunneling often has very long queries

                if len(payload) > 150:
                    # Search typical DNS tunneling patterns

                    dns_tunnel_patterns = [
                        r'[a-zA-Z0-9+\/]{30,}\.', # Base64/encoded data in subdomain

                        r'[0-9a-f]{30,}\.',      # Hex encoded data

                        r'[a-zA-Z0-9]{40,}\.'    # Long random-looking subdomains

                    ]
                    
                    payload_str = payload.decode('latin-1', errors='ignore')
                    
                    for pattern in dns_tunnel_patterns:
                        if re.search(pattern, payload_str):
                            return "DNS Tunneling", "High"
            
            # 5.3 Anomalous traffic on non -standard doors

            if proto in ['TCP', 'UDP']:
                # Common doors and their standard uses

                common_services = {
                    22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS', 
                    80: 'HTTP', 443: 'HTTPS', 20: 'FTP-data', 21: 'FTP',
                    110: 'POP3', 143: 'IMAP', 161: 'SNMP', 3306: 'MySQL',
                    3389: 'RDP', 5900: 'VNC', 8080: 'HTTP-ALT'
                }
                
                # If the destination door is <1024 but it is not in Common_Services

                if dport < 1024 and dport not in common_services:
                    return f"Traffico anomalo su porta {dport}", "Medium"
                
                # If the source holder is <1024 but it is not in Common_Services (as common but possible)

                if sport < 1024 and sport not in common_services:
                    return f"Traffico anomalo da porta {sport}", "Medium"
            
            # 6. User-age (for HTTP) analysis

            if proto == 'HTTP' and 'payload' in packet:
                payload_str = packet['payload'].decode('latin-1', errors='ignore')
                
                # Estures User-Agent if present

                user_agent_match = re.search(r'User-Agent:\s*([^\r\n]+)', payload_str)
                
                if user_agent_match:
                    user_agent = user_agent_match.group(1)
                    
                    # Check User Suspicious Agent

                    if hasattr(self, 'threat_db') and 'user_agents' in self.threat_db:
                        for ua_key, ua_info in self.threat_db['user_agents'].items():
                            if ua_key.lower() in user_agent.lower():
                                return ua_info["type"], ua_info["severity"]
                    
                    # Common penetration testing scanner/tool

                    scanner_uas = ['nikto', 'sqlmap', 'nmap', 'zgrab', 'gobuster', 'dirbuster', 'masscan', 'wpscan']
                    for scanner in scanner_uas:
                        if scanner.lower() in user_agent.lower():
                            return "Vulnerability Scanner", "Medium"
                    
                    # User-agent/unusual users

                    suspicious_uas = ['wget', 'curl', 'python-requests', 'go-http-client', 'ruby', 'perl']
                    for sus_ua in suspicious_uas:
                        if sus_ua.lower() in user_agent.lower():
                            return "Automated Tool", "Low"
                    
                    # List of common and legitimate browsers

                    legitimate_browsers = [
                        'mozilla', 'firefox', 'chrome', 'safari', 'edge', 'opera', 'msie', 'trident',
                        'webkit', 'android', 'iphone', 'ipad', 'mobile', 'windows nt'
                    ]
                    
                    # If the User Agent contains a legitimate browser, do not report as an anomaly

                    for browser in legitimate_browsers:
                        if browser.lower() in user_agent.lower():
                            return None, None  # No threats, normal browser traffic

                
                # Check if it's a standard HTTP package

                if 'GET ' in payload_str or 'POST ' in payload_str or 'HTTP/' in payload_str:
                    # Check if the traffic is from internal client to external server

                    src_ip = packet.get('src', '')
                    is_internal = src_ip.startswith('192.168.') or src_ip.startswith('10.') or src_ip.startswith('172.16.')
                    src_port = packet.get('sport', 0)
                    
                    # If it is traffic out of an internal client and the source holder is high (client)

                    if is_internal and src_port > 1024:
                        return None, None  # HTTP traffic out of normal output

                
                # If we have not been able to classify specifically but it seems HTTP standard

                if 'HTTP/' in payload_str:
                    return None, None  # Standard HTTP traffic, do not report

                    
            # If we have not been able to classify specifically

            return "Unclassified anomaly", "Low"
            
        except Exception as e:
            print(f"Error in threat classification: {str(e)}")
            return "Classification error", "Low"
        

    def select_all_threats(self, event):
        """Select all items in the threat tree"""
        for item in self.threat_tree.get_children():
            self.threat_tree.selection_add(item)
        return "break"  # Prevent default behavior

        
    def create_batch_action_dialog(self):
        """Create a dialog for batch actions on multiple selected threats"""
        # Get selected items
        selected_items = self.threat_tree.selection()
        if not selected_items:
            messagebox.showinfo("Information", "No threat selected")
            return
        
        # Create dialog window
        batch_window = tk.Toplevel(self.root)
        batch_window.title("Batch Actions")
        batch_window.transient(self.root)
        batch_window.iconbitmap(ico_path)
        batch_window.grab_set()
        batch_window.resizable(False, False)
        
        # Create content frame with padding
        content_frame = ttk.Frame(batch_window, padding=10)
        content_frame.pack(fill=tk.BOTH, expand=True)
        
        # Show selection summary
        ttk.Label(content_frame, text=f"Selected {len(selected_items)} items", font=("Arial", 10, "bold")).pack(pady=(0, 10))
        
        # Count severity levels
        severity_counts = {"High": 0, "Medium": 0, "Low": 0}
        ml_anomalies_count = 0
        
        # Get details about selection
        for item_id in selected_items:
            values = self.threat_tree.item(item_id, "values")
            if len(values) > 4:  # Make sure we have enough values
                severity = values[4]
                threat_type = values[3]
                
                if severity in severity_counts:
                    severity_counts[severity] += 1
                    
                if "Anomalia ML" in threat_type:
                    ml_anomalies_count += 1
        
        # Display selection info
        info_text = f"High severity: {severity_counts['High']}\n"
        info_text += f"Medium severity: {severity_counts['Medium']}\n"
        info_text += f"Low severity: {severity_counts['Low']}\n\n"
        info_text += f"ML Anomalies: {ml_anomalies_count}"
        
        ttk.Label(content_frame, text=info_text).pack(anchor=tk.W, pady=(0, 10))
        
        # Create action buttons frame
        button_frame = ttk.Frame(content_frame)
        button_frame.pack(fill=tk.X, pady=(10, 0))
        
        # Function to mark all selected as false positives
        def mark_all_as_false_positives():
            ml_items_marked = 0
            
            for item_id in selected_items:
                values = self.threat_tree.item(item_id, "values")
                if len(values) > 3 and "Anomalia ML" in values[3]:
                    # Extract packet index if possible
                    packet_idx = None
                    description = values[5] if len(values) > 5 else ""
                    match = re.search(r"packet_idx: (\d+)", description)
                    if match:
                        packet_idx = int(match.group(1))
                    
                    # Update the item as false positive
                    new_description = description.replace(
                        "Anomaly detected by ML", 
                        "False positive (previously reported as an anomaly)"
                    )
                    
                    # Update tree item
                    self.threat_tree.item(
                        item_id, 
                        values=(
                            values[0],  # Timestamp
                            values[1],  # Source
                            values[2],  # Destination
                            "False Positive",  # Change type
                            values[4],  # Severity
                            new_description  # Updated description
                        ),
                        tags=('false_positive',)
                    )
                    
                    # Store for future model training if we have a packet index
                    if packet_idx is not None and packet_idx < len(self.captured_packets):
                        if not hasattr(self, 'known_good_packets'):
                            self.known_good_packets = []
                        
                        self.known_good_packets.append(self.captured_packets[packet_idx])
                    
                    ml_items_marked += 1
            
            # Offer to retrain if enough items marked
            if ml_items_marked > 0:
                batch_window.destroy()
                
                if hasattr(self, 'known_good_packets') and len(self.known_good_packets) >= 5:
                    retrain = messagebox.askyesno(
                        "Model Enhancement", 
                        f"You have reported {len(self.known_good_packets)} packets as false positives.\n\n"
                        "You want to update the ML model to improve accuracy?\n"
                        "This process will use the reported packets as known examples of normal traffic."
                    )
                    
                    if retrain:
                        self.retrain_model_with_false_positives()
                else:
                    messagebox.showinfo(
                        "Action completed", 
                        f"Marked {ml_items_marked} elements such as false positives.\n\n"
                        "You need at least 5 examples to retrain the ML model."
                    )
            else:
                messagebox.showinfo(
                    "No action", 
                    "No selected ML anomaly to report as false positive."
                )
                batch_window.destroy()
        
        # Function to export selection
        def export_selection():
            # Ask for file name
            file_path = filedialog.asksaveasfilename(
                defaultextension=".csv",
                filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
                title="Export all as CSV"
            )
            
            if not file_path:
                return
                
            try:
                # Prepare data for CSV
                csv_data = []
                header = ["Timestamp", "Source", "Destination", "Threat Type", "Severity", "Description"]
                csv_data.append(header)
                
                # Add selected items
                for item_id in selected_items:
                    values = self.threat_tree.item(item_id, "values")
                    csv_data.append(list(values))
                
                # Write to CSV
                with open(file_path, 'w', newline='') as f:
                    import csv
                    writer = csv.writer(f)
                    writer.writerows(csv_data)
                
                messagebox.showinfo(
                    "Export Complete", 
                    f"Exported {len(selected_items)} items to {file_path}"
                )
                batch_window.destroy()
            except Exception as e:
                messagebox.showerror("Error", f"Error exporting to CSV: {str(e)}")
        
        # Create the buttons with consistent style
        style = ttk.Style()
        style.configure('TButton', padding=(5, 5))
        
        # Add buttons
        if ml_anomalies_count > 0:
            ttk.Button(
                button_frame, 
                text="Mark All as False Positives", 
                command=mark_all_as_false_positives,
                width=25
            ).pack(side=tk.LEFT, padx=5, pady=5)
        
        ttk.Button(
            button_frame, 
            text="Export Selection as CSV", 
            command=export_selection,
            width=24
        ).pack(side=tk.LEFT, padx=5, pady=5)
        
        ttk.Button(
            button_frame, 
            text="Cancel", 
            command=batch_window.destroy,
            width=10
        ).pack(side=tk.RIGHT, padx=5, pady=5)
        
        # After adding all the widgets, update and adapt the window
        batch_window.update_idletasks()
        batch_window.geometry('')  # This means that the window adapts to the content

        # Get position and size of the main window
        parent_x = self.root.winfo_x()
        parent_y = self.root.winfo_y()
        parent_width = self.root.winfo_width()
        parent_height = self.root.winfo_height()
        
        # Get size of the dialog box
        window_width = batch_window.winfo_width()
        window_height = batch_window.winfo_height()
        
        # Calculate position centered compared to the main window
        position_x = parent_x + (parent_width - window_width) // 2
        position_y = parent_y + (parent_height - window_height) // 2
        
        # Apply the location
        batch_window.geometry(f"+{position_x}+{position_y}")

    def add_threat(self, timestamp, src, dst, threat_type, severity, description, packet_index=None):
        """Adds a threat to the threat table"""
        # If we don't have a package index, let's try to find it

        if packet_index is None and "packet" in description:
            match = re.search(r"packet (\d+)", description)
            if match:
                packet_index = int(match.group(1))
        
        # Add the ID of the package to the description

        if packet_index is not None and "packet" not in description:
            if description:
                description = f"{description} (Packet {packet_index})"
            else:
                description = f"Packet {packet_index}"
        
        # Insert the table

        item_id = self.threat_tree.insert('', 'end', values=(
            timestamp,
            src,
            dst,
            threat_type,
            severity,
            description
        ))
        
        # Color the line according to severity

        if severity == "High":
            self.threat_tree.item(item_id, tags=('high_severity',))
        elif severity == "Medium":
            self.threat_tree.item(item_id, tags=('medium_severity',))
        elif severity == "Low":
            self.threat_tree.item(item_id, tags=('low_severity',))
        
        # Make sure the color tags are configured

        self.threat_tree.tag_configure('high_severity', background='#ffcccc')
        self.threat_tree.tag_configure('medium_severity', background='#ffffcc')
        self.threat_tree.tag_configure('low_severity', background='#e6ffe6')
        self.threat_tree.tag_configure('false_positive', foreground='gray')
        
        # Perform the Scroll only if the option is activated

        if hasattr(self, 'auto_scroll_var') and self.auto_scroll_var.get():
            self.threat_tree.yview_moveto(1.0)
        
        return item_id

    def analyze_threats(self):
        """Performs a comprehensive threat analysis on captured packets with severity filtering"""
        if not self.captured_packets:
            messagebox.showinfo("Information", "No packages to analyze")
            return
        
        # Create severity filter dialog first

        filter_window = tk.Toplevel(self.root)
        filter_window.title("Filter by Severity")
        filter_window.transient(self.root)
        filter_window.iconbitmap(ico_path)
        filter_window.grab_set()
        filter_window.resizable(False, False)
        
        # Create severity filter options

        filter_frame = ttk.Frame(filter_window, padding=10)
        filter_frame.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(filter_frame, text="Select the level of Severity you want:", font=("Arial", 10, "bold")).pack(pady=(0,10))
        
        # Create variables for checkbuttons

        self.show_high_severity = tk.BooleanVar(value=True)
        self.show_medium_severity = tk.BooleanVar(value=True)  
        self.show_low_severity = tk.BooleanVar(value=True)
        
        # Create checkbuttons

        ttk.Checkbutton(filter_frame, text="High Severity", variable=self.show_high_severity).pack(anchor=tk.W)
        ttk.Checkbutton(filter_frame, text="Medium Severity", variable=self.show_medium_severity).pack(anchor=tk.W)
        ttk.Checkbutton(filter_frame, text="Low Severity", variable=self.show_low_severity).pack(anchor=tk.W)
        
        # Buttons

        button_frame = ttk.Frame(filter_frame)
        button_frame.pack(fill=tk.X, pady=(10, 0))
        
        def proceed_with_analysis():
            filter_window.destroy()
            self._run_threat_analysis()

        # Create the buttons

        style = ttk.Style()
        style.configure('TButton', padding=(5, 5))
        
        ttk.Button(button_frame, text="Proceed", command=proceed_with_analysis, width=10).pack(side=tk.RIGHT, padx=5, pady=5)
        ttk.Button(button_frame, text="Clear", command=filter_window.destroy, width=10).pack(side=tk.RIGHT, padx=5, pady=5)
        
        # After adding all the widgets, update and adapt the window

        filter_window.update_idletasks()
        filter_window.geometry('')  # This means that the window adapts to the content


        # Get position and size of the main window

        parent_x = self.root.winfo_x()
        parent_y = self.root.winfo_y()
        parent_width = self.root.winfo_width()
        parent_height = self.root.winfo_height()
        
        # Get size of the dialog box

        window_width = filter_window.winfo_width()
        window_height = filter_window.winfo_height()
        
        # Calculate position centered compared to the main window

        position_x = parent_x + (parent_width - window_width) // 2
        position_y = parent_y + (parent_height - window_height) // 2
        
        # Apply the location

        filter_window.geometry(f"+{position_x}+{position_y}")

    def _run_threat_analysis(self):
        """Performs threat analysis with severity filters applied"""
        # Variable to check if the analysis has been interrupted

        self.threat_analysis_running = True
        
        # Create a dialog to show progress

        progress_window = tk.Toplevel(self.root)
        progress_window.title("Ongoing threat analysis")
        progress_window.transient(self.root)
        try:
            progress_window.iconbitmap(ico_path)
        except:
            pass
        progress_window.grab_set()
        progress_window.resizable(False, False)
        
        # Create the main frame with Padding

        main_frame = ttk.Frame(progress_window, padding=10)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Add label and progress bar

        ttk.Label(main_frame, text="Ongoing threat analysis...", 
                font=("Arial", 10, "bold")).pack(pady=(0, 10))
        
        progress = ttk.Progressbar(main_frame, orient="horizontal", length=350, mode="determinate")
        progress.pack(pady=5)
        
        status_label = ttk.Label(main_frame, text="Initialization...", font=("Arial", 10))
        status_label.pack(pady=5)
        
        # Add button to stop analysis

        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, pady=(10, 0))
        
        def stop_threat_analysis():
            self.threat_analysis_running = False
            progress_window.destroy()
            self.status_bar.config(text="Threat analysis stopped")
        
        self.stop_threat_analysis = stop_threat_analysis
        
        style = ttk.Style()
        style.configure('TButton', padding=(5, 5))
        
        stop_button = ttk.Button(button_frame, text="Stop", command=self.stop_threat_analysis, width=10)
        stop_button.pack(side=tk.RIGHT, padx=5, pady=5)
        
        # Manage the closing of the window

        progress_window.protocol("WM_DELETE_WINDOW", self.stop_threat_analysis)
        
        # After adding all the widgets, update and adapt the window

        progress_window.update_idletasks()
        progress_window.geometry('')  # This means that the window adapts to the content


        # Now the window is hit
        # Cent on the window compared to the main window

        window_width = progress_window.winfo_width()
        window_height = progress_window.winfo_height()

        # Get position and size of the main window

        parent_x = self.root.winfo_x()
        parent_y = self.root.winfo_y()
        parent_width = self.root.winfo_width() 
        parent_height = self.root.winfo_height()

        # Calculate position centered compared to the main window

        position_x = parent_x + (parent_width - window_width) // 2
        position_y = parent_y + (parent_height - window_height) // 2

        # Apply the location

        progress_window.geometry(f"+{position_x}+{position_y}")
        
        # Function to update the progress bar

        def update_progress(value, message):
            if not self.threat_analysis_running:
                return False  # Report to stop analysis

            
            progress["value"] = value
            status_label.config(text=message)
            progress_window.update_idletasks()
            return True  # The analysis continues

            
        # Perform the analysis in a separate thread so as not to block the UI

        def run_analysis():
            try:
                # Clean threat table

                self.root.after(0, lambda: [self.threat_tree.delete(item) for item in self.threat_tree.get_children()])
                
                if not update_progress(10, "Analysis preparation..."):
                    return
                
                # Analyze packages

                threat_count = 0
                total_packets = len(self.captured_packets)
                
                if not update_progress(15, f"Packet Analyzer (0/{total_packets})..."):
                    return
                
                for i, packet in enumerate(self.captured_packets):
                    # Check if the analysis has been interrupted

                    if not self.threat_analysis_running:
                        return
                    
                    # Check if it's a threat

                    if self.is_potential_threat(packet):
                        threat_type, severity = self.classify_threat(packet)
                        
                        # Apply severity filter

                        if (severity == "High" and not self.show_high_severity.get()) or \
                        (severity == "Medium" and not self.show_medium_severity.get()) or \
                        (severity == "Low" and not self.show_low_severity.get()):
                            continue
                        
                        timestamp = time.strftime("%H:%M:%S", time.localtime(packet['time']))
                        src = packet['src']
                        dst = packet['dst']
                        
                        # Add to the threat table (it must be done in the main thread)

                        def add_threat_to_tree(ts, s, d, tt, sev, idx):
                            self.add_threat(ts, s, d, tt, sev, f"Potential threat detected (Packet {idx})")
                        
                        self.root.after(0, lambda ts=timestamp, s=src, d=dst, tt=threat_type, sev=severity, idx=i: 
                                        add_threat_to_tree(ts, s, d, tt, sev, idx))
                        threat_count += 1
                    
                    # Upded progress every 50 packages or at the last package

                    if i % 50 == 0 or i == total_packets - 1:
                        progress_percent = 15 + (i / total_packets) * 75
                        if not update_progress(progress_percent, f"Packet Parser ({i+1}/{total_packets})... Threats found: {threat_count}"):
                            return
                
                # Make sure the double -click event is configured

                if not update_progress(90, "Interface configuration..."):
                    return
                    
                self.root.after(0, self.setup_threat_details)
                
                # Set up context menu for threat tree

                self.root.after(0, self.setup_threat_context_menu)
                
                # Complete the analysis

                if not update_progress(95, f"Scan complete: {threat_count} threats detected"):
                    return
                
                # If we found threats and the analysis has not been interrupted, highlight the first

                if threat_count > 0 and self.threat_analysis_running:
                    def select_first_threat():
                        if self.threat_tree.get_children():  # Check that there are elements

                            first_item = self.threat_tree.get_children()[0]
                            self.threat_tree.selection_set(first_item)
                            self.threat_tree.focus(first_item)
                            self.status_bar.config(text=f"Scan complete: {threat_count} threats detected. Double-click for details.")
                    
                    self.root.after(0, select_first_threat)
                
                # Finalizes

                if not update_progress(100, "Viewing results..."):
                    return
                
                # Close the progress window and show the result only if the analysis has not been interrupted

                if self.threat_analysis_running:
                    self.root.after(1000, progress_window.destroy)  # Wait 1 second before closing

                    self.root.after(1100, lambda: messagebox.showinfo("Analysis completed", 
                                                                    f"Detect {threat_count} potential threats.\n\n" +
                                                                    "Double-click a threat in the table to view the details."))
                    self.root.after(1200, lambda: self.status_bar.config(text=f"Scan complete: {threat_count} threats detected"))
            
            except Exception as e:
                print(f"Error in threat analysis: {str(e)}")
                traceback.print_exc()
                if self.threat_analysis_running:  # Check that the analysis has not been interrupted

                    self.root.after(0, lambda: messagebox.showerror("Error", f"Error in threat analysis: {str(e)}"))
                    self.root.after(0, progress_window.destroy)
        
        # Start the analysis in a separate thread

        if not update_progress(5, "Start analysis..."):
            return
            
        analysis_thread = threading.Thread(target=run_analysis)
        analysis_thread.daemon = True
        analysis_thread.start()

    def train_model_with_progress(self):
        """Train the ML model with a progress window that closes automatically"""
        # Create a dialog to show progress

        progress_window = tk.Toplevel(self.root)
        progress_window.title("ML Model Training")
        progress_window.geometry("400x150")
        try:
            progress_window.iconbitmap(ico_path)
        except:
            pass  # Icon file might be missing

        progress_window.resizable(False, False)
        progress_window.transient(self.root)
        
        # Hit the window

        window_width = 400
        window_height = 150
        position_right = int(self.root.winfo_screenwidth()/2 - window_width/2)
        position_down = int(self.root.winfo_screenheight()/2 - window_height/2)
        progress_window.geometry(f"+{position_right}+{position_down}")
        
        # Add label and progress bar

        label = tk.Label(progress_window, text="ML Model Training...", font=("Arial", 12))
        label.pack(pady=10)
        progress = ttk.Progressbar(progress_window, orient="horizontal", length=350, mode="determinate")
        progress.pack(pady=10)
        
        status_label = tk.Label(progress_window, text="Initialization...", font=("Arial", 10))
        status_label.pack(pady=10)
        
        # Function to update the progress bar

        def update_progress(value, message):
            progress["value"] = value
            status_label.config(text=message)
            progress_window.update_idletasks()
        
        # Perform training in a separate thread

        def run_training():
            try:
                # Phase 1: initialization

                update_progress(5, "Initializing the Model...")
                
                # Check if we have packages

                if not hasattr(self, 'captured_packets') or len(self.captured_packets) == 0:
                    update_progress(100, "No training package available")
                    self.root.after(2000, progress_window.destroy)  # Closes after 2 seconds

                    return
                
                # Phase 2: features extraction

                update_progress(10, f"Extracting features from {len(self.captured_packets)} packages...")
                
                features = []
                for i, packet in enumerate(self.captured_packets):
                    packet_features = self.extract_ml_features(packet)
                    if packet_features:
                        # Check that all features are single numbers

                        valid_features = True
                        for j, feature in enumerate(packet_features):
                            if not isinstance(feature, (int, float)) or isinstance(feature, bool):
                                print(f"Invalid feature in package {i}: index {j}, value {feature}")
                                valid_features = False
                                break
                        
                        if valid_features:
                            features.append([float(f) for f in packet_features])
                    
                    # Update progress every 100 packages

                    if i % 100 == 0:
                        progress_value = 10 + int((i / len(self.captured_packets)) * 40)
                        update_progress(progress_value, f"Feature extraction ({i}/{len(self.captured_packets)})...")
                
                if not features:
                    update_progress(100, "Unable to extract valid features from packages")
                    self.root.after(2000, progress_window.destroy)  # Closes after 2 seconds

                    return
                
                # Phase 3: Data Preparation

                update_progress(50, "Data preparation...")
                
                # Check that all lines have the same length

                feature_lengths = [len(f) for f in features]
                if len(set(feature_lengths)) > 1:
                    print(f"ERROR: Different feature lengths: {set(feature_lengths)}")
                    # Find the most common length

                    from collections import Counter
                    common_length = Counter(feature_lengths).most_common(1)[0][0]
                    print(f"Normalization to length {common_length}")
                    
                    # Normalizes all lines to the most common length

                    normalized_features = []
                    for f in features:
                        if len(f) == common_length:
                            normalized_features.append(f)
                        elif len(f) < common_length:
                            # If too short, add zeri

                            normalized_features.append(f + [0.0] * (common_length - len(f)))
                        else:
                            # If too long, truncated

                            normalized_features.append(f[:common_length])
                    
                    features = normalized_features
                
                # Converti in array numpy

                try:
                    X = np.array(features, dtype=np.float64)
                    print(f"Successfully created X array: shape {X.shape}")
                except Exception as e:
                    update_progress(100, f"Error converting to numpy array: {str(e)}")
                    self.root.after(2000, progress_window.destroy)  # Closes after 2 seconds

                    return
                
                # Phase 4: training

                update_progress(60, "Model Training...")
                
                # Normalizes data

                X_scaled = self.scaler.fit_transform(X)
                
                # Train the model

                update_progress(80, "Finalizing the Model...")
                self.ml_model.fit(X_scaled)
                self.ml_model_trained = True
                
                # Update the processed package meter

                self.last_trained_packet_count = len(self.captured_packets)
                
                # Save the model

                update_progress(90, "Saving the Model...")
                self.save_ml_model()
                
                # Completed

                update_progress(100, f"Successfully completed training ({len(features)} packages)")
                self.status_bar.config(text=f"ML model trained with {len(features)} packages")
                
                # Show success message and close the window after 2 seconds

                self.root.after(1000, lambda: messagebox.showinfo(
                    "Training Completed", 
                    f"The ML model has been successfully trained using {len(features)} packages."
                ))
                self.root.after(2000, progress_window.destroy)
                
            except Exception as e:
                print(f"Failure to train the model: {str(e)}")
                traceback.print_exc()
                update_progress(100, f"Error: {str(e)}")
                
                # Show error message and close the window after 2 seconds

                self.root.after(1000, lambda: messagebox.showerror(
                    "Error", 
                    f"Error training model: {str(e)}"
                ))
                self.root.after(2000, progress_window.destroy)
        
        # Start training in a separate thread

        training_thread = threading.Thread(target=run_training)
        training_thread.daemon = True
        training_thread.start()
    
        
    def run_anomaly_detection(self):
        """Performs anomaly detection with machine learning and support for severity filters"""
        if not self.captured_packets:
            messagebox.showinfo("Information", "No package to analyze")
            return
        
        # Check if the model has been trained

        if not hasattr(self, 'ml_model_trained') or not self.ml_model_trained:
            # If we don't have a trained model, show a message
            # and starts a quick training before proceeding

            response = messagebox.askyesno("Untrained model", 
                                        "The machine learning model has not yet been trained. "
                                        "Do you want to train him now before proceeding with the survey?")
            if response:
                # Use the version with a progress bar for initial training

                self.train_model_with_progress()
                return  # We will go out and draw this function after training

            else:
                messagebox.showinfo("Information," "Anomaly detection requires a trained model.")
                return
        
        # Create severity filter dialog first

        filter_window = tk.Toplevel(self.root)
        filter_window.title("Filtra per Severità")
        filter_window.transient(self.root)
        filter_window.iconbitmap(ico_path)
        filter_window.grab_set()
        filter_window.resizable(False, False)
        
        # Create severity filter options

        filter_frame = ttk.Frame(filter_window, padding=10)
        filter_frame.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(filter_frame, text="Select the level of Severity you want:", font=("Arial", 10, "bold")).pack(pady=(0,10))
        
        # Create variables for checkbuttons

        self.show_high_severity = tk.BooleanVar(value=True)
        self.show_medium_severity = tk.BooleanVar(value=True)  
        self.show_low_severity = tk.BooleanVar(value=True)
        
        # Create checkbuttons

        ttk.Checkbutton(filter_frame, text="High Severity", variable=self.show_high_severity).pack(anchor=tk.W)
        ttk.Checkbutton(filter_frame, text="Medium Severity", variable=self.show_medium_severity).pack(anchor=tk.W)
        ttk.Checkbutton(filter_frame, text="Low Severity", variable=self.show_low_severity).pack(anchor=tk.W)
        
        # Buttons

        button_frame = ttk.Frame(filter_frame)
        button_frame.pack(fill=tk.X, pady=(10, 0))
        
        def proceed_with_analysis():
            filter_window.destroy()
            self._run_ml_analysis()  # This method should be defined elsewhere in the class

        
        # Create the buttons

        style = ttk.Style()
        style.configure('TButton', padding=(5, 5))
        
        ttk.Button(button_frame, text="Proceed", command=proceed_with_analysis, width=10).pack(side=tk.RIGHT, padx=5, pady=5)
        ttk.Button(button_frame, text="Clear", command=filter_window.destroy, width=10).pack(side=tk.RIGHT, padx=5, pady=5)
        
        # After adding all the widgets, update and adapt the window

        filter_window.update_idletasks()
        filter_window.geometry('')  # This means that the window adapts to the content


        # Now the window is hit
        # Cent on the window compared to the main window

        window_width = filter_window.winfo_width()
        window_height = filter_window.winfo_height()

        # Get position and size of the main window

        parent_x = self.root.winfo_x()
        parent_y = self.root.winfo_y()
        parent_width = self.root.winfo_width()
        parent_height = self.root.winfo_height()

        # Calculate position centered compared to the main window

        position_x = parent_x + (parent_width - window_width) // 2
        position_y = parent_y + (parent_height - window_height) // 2

        # Apply the location

        filter_window.geometry(f"+{position_x}+{position_y}")
            

    def _run_ml_analysis(self):
        """In-house anomaly detection implementation with real-time anomaly addition"""
        # Variable to check if the analysis has been interrupted

        self.ml_analysis_running = True
        
        # Create a dialog to show progress

        progress_window = tk.Toplevel(self.root)
        progress_window.title("ML analysis in progress")
        progress_window.transient(self.root)
        try:
            progress_window.iconbitmap(ico_path)
        except:
            pass  # Icon file might be missing

        progress_window.grab_set()
        progress_window.resizable(False, False)
        
        # Create the main frame with Padding

        main_frame = ttk.Frame(progress_window, padding=10)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Add label and progress bar

        ttk.Label(main_frame, text="Trait extraction from packages...", 
                font=("Arial", 10, "bold")).pack(pady=(0, 10))
        
        progress = ttk.Progressbar(main_frame, orient="horizontal", length=350, mode="determinate")
        progress.pack(pady=5)
        
        status_label = ttk.Label(main_frame, text="Initialization...", font=("Arial", 10))
        status_label.pack(pady=5)
        
        # Add button to stop analysis

        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, pady=(10, 0))
        
        style = ttk.Style()
        style.configure('TButton', padding=(5, 5))
        
        stop_button = ttk.Button(button_frame, text="Stop", command=lambda: self.stop_ml_analysis(), width=10)
        stop_button.pack(side=tk.RIGHT, padx=5, pady=5)
        
        # Manage the closing of the window

        progress_window.protocol("WM_DELETE_WINDOW", lambda: self.stop_ml_analysis())
        
        # After adding all the widgets, update and adapt the window

        progress_window.update_idletasks()
        progress_window.geometry('')  # This means that the window adapts to the content


        # Now the window is hit

        window_width = progress_window.winfo_width()
        window_height = progress_window.winfo_height()
        position_right = int(self.root.winfo_screenwidth()/2 - window_width/2)
        position_down = int(self.root.winfo_screenheight()/2 - window_height/2)
        progress_window.geometry(f"+{position_right}+{position_down}")
        
        # Function to update the progress bar

        def update_progress(value, message):
            if not self.ml_analysis_running:
                return False  # Report to stop analysis

                
            progress["value"] = value
            status_label.config(text=message)
            progress_window.update_idletasks()
            return True  # The analysis continues

        
        # Function to stop analysis

        def stop_ml_analysis():
            self.ml_analysis_running = False
            progress_window.destroy()
            self.status_bar.config(text="ML analysis stopped")
        
        self.stop_ml_analysis = stop_ml_analysis
        
        # Clear previous threat tree before starting new analysis

        for item in self.threat_tree.get_children():
            self.threat_tree.delete(item)
            
        # Store anomalies for reference

        self.ml_detected_anomalies = []
        
        # Function to add an anomaly to the threat table in real time

        def add_anomaly_to_table(packet_idx, score, packet, severity):
            timestamp = time.strftime("%H:%M:%S", time.localtime(packet['time']))
            src = packet['src']
            dst = packet['dst']
            
            # Add to the threat table in the main thread

            def add_to_ui():
                item_id = self.add_threat(timestamp, src, dst, "ML Anomaly", severity, 
                            f"Anomaly detected by ML (score: {score:.3f}, packet_idx: {packet_idx})")
                
                # Memorizes information on anomaly

                self.ml_detected_anomalies.append({
                    'item_id': item_id,
                    'packet_idx': packet_idx,
                    'score': score,
                    'severity': severity,
                    'is_false_positive': False  # Initially set to False

                })
                
            self.root.after(0, add_to_ui)
        
        # Perform the analysis in a separate thread so as not to block the UI

        def run_analysis():
            try:
                # Extract features from the packages

                features = []
                packet_indices = []  # Memorizes the original packages of the packages

                total_packets = len(self.captured_packets)
                
                if not update_progress(5, f"Trait extraction (0/{total_packets})..."):
                    return
                
                # Processes the batch packages to improve performance

                batch_size = 100
                batch_features = []
                batch_indices = []
                
                for i, packet in enumerate(self.captured_packets):
                    # Check if the analysis has been interrupted

                    if not self.ml_analysis_running:
                        return
                        
                    packet_features = self.extract_ml_features(packet)
                    if packet_features:
                        batch_features.append(packet_features)
                        batch_indices.append(i)
                    
                    # When we reach the size of the batch, the batch processes

                    if len(batch_features) >= batch_size or i == total_packets - 1:
                        if batch_features:
                            # Converti in array numpy

                            X_batch = np.array(batch_features)
                            
                            # Normalizes data

                            X_scaled_batch = self.scaler.transform(X_batch)
                            
                            # Predic with the model

                            predictions_batch = self.ml_model.predict(X_scaled_batch)
                            scores_batch = self.ml_model.decision_function(X_scaled_batch)
                            
                            # Identify the anomalies (values ​​-1) and add them in real time

                            for j, (pred, score, packet_idx) in enumerate(zip(predictions_batch, scores_batch, batch_indices)):
                                if pred == -1:
                                    # Determines severity based on the score

                                    if score < -0.3:
                                        severity = "High"
                                        if not self.show_high_severity.get():
                                            continue  # Jump if filtered

                                    elif score < -0.2:
                                        severity = "Medium"
                                        if not self.show_medium_severity.get():
                                            continue  # Jump if filtered

                                    else:
                                        severity = "Low"
                                        if not self.show_low_severity.get():
                                            continue  # Jump if filtered

                                    
                                    # Add the anomaly to the table in real time

                                    add_anomaly_to_table(packet_idx, score, self.captured_packets[packet_idx], severity)
                            
                            # Save all the features for future reference

                            features.extend(batch_features)
                            packet_indices.extend(batch_indices)
                        
                        # Reset the batch

                        batch_features = []
                        batch_indices = []
                    
                    # Upded progress every 50 packages so as not to overload the UI

                    if i % 50 == 0 or i == total_packets - 1:
                        progress_percent = 5 + (i / total_packets) * 85
                        if not update_progress(progress_percent, f"Packet Analyzer ({i+1}/{total_packets})..."):
                            return
                
                if not features:
                    self.root.after(0, lambda: messagebox.showinfo("Information", "Unable to extract features from packages"))
                    self.root.after(0, progress_window.destroy)
                    return
                
                # Store for later use if needed

                self.last_ml_features = features
                self.last_ml_packet_indices = packet_indices
                
                # Enable context menu for marking as false positive

                self.setup_threat_context_menu()
                
                # Save the trained model

                if not update_progress(95, "Saving the model..."):
                    return
                    
                self.save_ml_model()
                
                if not update_progress(100, "Analysis completed!"):
                    return
                
                # Close the progress window and show the result only if the analysis has not been interrupted

                if self.ml_analysis_running:
                    anomaly_count = len(self.ml_detected_anomalies)
                    self.root.after(1000, progress_window.destroy)  # Wait 1 second before closing

                    self.root.after(1100, lambda: messagebox.showinfo("ML analysis completed", f"Anomalies detected {anomaly_count}"))
                    self.root.after(1200, lambda: self.status_bar.config(text=f"ML scan completed: {anomaly_count} anomalies detected"))
            
            except Exception as e:
                print(f"Error in ML analysis: {str(e)}")
                traceback.print_exc()
                if self.ml_analysis_running:  # Check that the analysis has not been interrupted

                    self.root.after(0, lambda: messagebox.showerror("Error", f"Error in ML analysis: {str(e)}"))
                    self.root.after(0, progress_window.destroy)
        
        # Start the analysis in a separate thread

        analysis_thread = threading.Thread(target=run_analysis)
        analysis_thread.daemon = True
        analysis_thread.start()

    def setup_threat_context_menu(self):
        """Configure the context menu for the threat table"""
        # Create context menu

        self.threat_context_menu = tk.Menu(self.root, tearoff=0)
        self.threat_context_menu.add_command(
            label="Mark Selected as False Positives", 
            command=self.mark_selected_as_false_positives  # New function to manage multiple selections

        )
        self.threat_context_menu.add_command(
            label="View Packet Details", 
            command=self.show_threat_details
        )
        
        # Enable multiple selection

        self.threat_tree.configure(selectmode='extended')
        
        # Bind right-click to show context menu

        self.threat_tree.bind("<Button-3>", self.show_threat_context_menu)

    
    def show_threat_context_menu(self, event):
        """Show context menu when right-clicking on a threat"""
        # Get item under cursor

        item = self.threat_tree.identify('item', event.x, event.y)
        if item:
            # If the item is not already selected, select it (otherwise keep the multiple selection)

            if item not in self.threat_tree.selection():
                self.threat_tree.selection_set(item)
            
            # Check if at least one selected item is an ML anomaly

            has_ml_anomaly = False
            for selected_item in self.threat_tree.selection():
                values = self.threat_tree.item(selected_item, "values")
                if values and len(values) > 3 and "ML Anomaly" in values[3]:
                    has_ml_anomaly = True
                    break
            
            if has_ml_anomaly:
                # Show context menu

                self.threat_context_menu.post(event.x_root, event.y_root)

    def mark_selected_as_false_positives(self):
        """Mark all selected anomalies as false positives"""
        # Get selected items
        selected_items = self.threat_tree.selection()
        
        if not selected_items:
            messagebox.showinfo("Information", "Nessun elemento selezionato. Seleziona almeno un'anomalia ML nella lista.")
            return
        
        # Filter only ML anomalies
        ml_items = []
        non_ml_items = 0
        
        for item_id in selected_items:
            values = self.threat_tree.item(item_id, "values")
            # Controlla sia "Anomalia ML" che "ML Anomaly" per supportare entrambe le lingue
            if values and len(values) > 3 and ("Anomalia ML" in values[3] or "ML Anomaly" in values[3]):
                ml_items.append(item_id)
            else:
                non_ml_items += 1
        
        if not ml_items:
            if non_ml_items > 0:
                messagebox.showinfo("Information", 
                    f"Hai selezionato {non_ml_items} elementi, ma nessuno di questi è un'anomalia ML.\n"
                    "Solo le anomalie rilevate tramite Machine Learning possono essere segnalate come falsi positivi.")
            else:
                messagebox.showinfo("Information", "Nessuna anomalia ML selezionata")
            return
        
        # Initialize counters and lists for tracking
        already_marked = []
        to_be_marked = []
        invalid_items = []
        
        # Check which are already marked and which ones not
        for item_id in ml_items:
            values = self.threat_tree.item(item_id, "values")
            description = values[5] if len(values) > 5 else ""
            
            # Migliora il pattern di ricerca per essere più robusto
            match = re.search(r"packet_idx:?\s*(\d+)", description)
            
            if match:
                packet_idx = int(match.group(1))
                
                # Check if it has already been marked as a false positive
                is_already_marked = False
                for anomaly in self.ml_detected_anomalies:
                    if anomaly['packet_idx'] == packet_idx and anomaly['is_false_positive']:
                        is_already_marked = True
                        already_marked.append(item_id)
                        break
                
                if not is_already_marked:
                    to_be_marked.append(item_id)
            else:
                invalid_items.append(item_id)
        
        # Avvisa in caso di elementi non validi
        if invalid_items:
            messagebox.showwarning(
                "Attenzione", 
                f"{len(invalid_items)} elementi selezionati non contengono un indice pacchetto valido."
            )
        
        # If everyone has already been marked, warn the user
        if not to_be_marked and already_marked:
            messagebox.showinfo(
                "Information", 
                f"Tutti i {len(already_marked)} pacchetti selezionati sono già stati contrassegnati come falsi positivi."
            )
            return
        
        # If nothing to mark after filtering, exit
        if not to_be_marked:
            if not already_marked and not invalid_items:
                messagebox.showinfo("Information", "Nessun pacchetto valido da contrassegnare come falso positivo.")
            return
        
        # If some are already marked and others are not, ask for confirmation
        message = ""
        if to_be_marked and already_marked:
            message = (f"Hai selezionato {len(ml_items)} anomalie:\n"
                    f"- {len(already_marked)} sono già state contrassegnate come falsi positivi\n"
                    f"- {len(to_be_marked)} saranno contrassegnate come nuovi falsi positivi\n\n"
                    "Vuoi procedere con la marcatura dei nuovi falsi positivi?")
        elif to_be_marked:
            message = (f"Vuoi segnalare {len(to_be_marked)} anomalie come falsi positivi?\n\n"
                    "Questo aiuterà il modello ad apprendere e migliorare la sua precisione.")
        
        # Ask confirmation
        confirm = messagebox.askyesno("Conferma", message)
        if not confirm:
            return
        
        # Process only the elements not yet marked
        marked_count = 0
        for item_id in to_be_marked:
            values = self.threat_tree.item(item_id, "values")
            description = values[5] if len(values) > 5 else ""
            match = re.search(r"packet_idx:?\s*(\d+)", description)
            
            if match:
                packet_idx = int(match.group(1))
                
                # Update the state of anomaly
                for anomaly in self.ml_detected_anomalies:
                    if anomaly['packet_idx'] == packet_idx:
                        anomaly['is_false_positive'] = True
                        break
                
                # Testi multilingua per supportare sia italiano che inglese
                if "Anomaly detected by ML" in description:
                    new_description = description.replace(
                        "Anomaly detected by ML", 
                        "False positive (previously reported as an anomaly)"
                    )
                else:
                    new_description = description.replace(
                        "Anomalia rilevata da ML", 
                        "Falso positivo (precedentemente segnalato come anomalia)"
                    )
                
                self.threat_tree.item(
                    item_id, 
                    values=(
                        values[0],  # Timestamp
                        values[1],  # Source
                        values[2],  # Destination
                        "False Positive",  # Change type
                        values[4],  # Severity
                        new_description  # Updated description
                    ),
                    tags=('false_positive',)
                )
                
                # Configures the style for false positives
                self.threat_tree.tag_configure('false_positive', foreground='gray')
                
                # Save as a well-known example
                if not hasattr(self, 'known_good_packets'):
                    self.known_good_packets = []
                
                if packet_idx < len(self.captured_packets):
                    packet = self.captured_packets[packet_idx]
                    # Check if the package is already on the list
                    is_duplicate = False
                    for existing_packet in self.known_good_packets:
                        if (existing_packet['time'] == packet['time'] and 
                            existing_packet['src'] == packet['src'] and 
                            existing_packet['dst'] == packet['dst']):
                            is_duplicate = True
                            break
                    
                    if not is_duplicate:
                        self.known_good_packets.append(packet)
                        marked_count += 1
        
        # Notification to the user and offer retraining if there are quite examples
        if marked_count > 0:
            messagebox.showinfo(
                "Operazione completata", 
                f"{marked_count} nuovi pacchetti contrassegnati come falsi positivi."
            )
            
            if len(self.known_good_packets) >= 10:  # Augmented threshold
                retrain = messagebox.askyesno(
                    "Miglioramento del modello", 
                    f"Hai segnalato {len(self.known_good_packets)} pacchetti come falsi positivi.\n\n"
                    "Vuoi aggiornare il modello ML per migliorare la precisione?\n"
                    "Questo processo utilizzerà i pacchetti segnalati come esempi noti di traffico normale."
                )
                if retrain:
                    self.retrain_model_with_false_positives()

    def retrain_model_with_false_positives(self):
        """Update the SGDOneClassSVM model using false positives as normal examples with anti-degradation protection"""
        # Create Progress Window with the style of the Analyze_threats window

        progress_window = tk.Toplevel(self.root)
        progress_window.title("Aggiornamento Modello ML")
        progress_window.transient(self.root)
        progress_window.iconbitmap(ico_path)
        progress_window.grab_set()
        progress_window.resizable(False, False)
        
        # Create the main frame with Padding

        main_frame = ttk.Frame(progress_window, padding=10)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Add progress bar and label

        ttk.Label(main_frame, text="Updating the model with false positives...", 
                font=("Arial", 10, "bold")).pack(pady=(0, 10))
        
        progress = ttk.Progressbar(main_frame, orient="horizontal", length=350, mode="determinate")
        progress.pack(pady=5)
        
        status_label = ttk.Label(main_frame, text="Initialization...", font=("Arial", 10))
        status_label.pack(pady=5)
        
        # Update function

        def update_progress(value, text):
            progress['value'] = value
            status_label.config(text=text)
            progress_window.update_idletasks()
        
        # After adding all the widgets, update and adapt the window

        progress_window.update_idletasks()
        progress_window.geometry('')  # This means that the window adapts to the content


        # Now the window is hit

        window_width = progress_window.winfo_width()
        window_height = progress_window.winfo_height()
        position_right = int(self.root.winfo_screenwidth()/2 - window_width/2)
        position_down = int(self.root.winfo_screenheight()/2 - window_height/2)
        progress_window.geometry(f"+{position_right}+{position_down}")
        
        # Run in a separate thread

        def run_retraining():
            try:
                import pickle
                import os
                import copy
                
                # Create a backup of the current model before retraining

                backup_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "models", "backups")
                os.makedirs(backup_dir, exist_ok=True)
                
                update_progress(5, "Backup creation of the current model...")
                
                # Save backup of the current model

                with open(os.path.join(backup_dir, "model_pre_retraining.pkl"), 'wb') as f:
                    pickle.dump(self.ml_model, f)
                with open(os.path.join(backup_dir, "scaler_pre_retraining.pkl"), 'wb') as f:
                    pickle.dump(self.scaler, f)
                with open(os.path.join(backup_dir, "count_pre_retraining.pkl"), 'wb') as f:
                    pickle.dump(self.last_trained_packet_count, f)
                
                if not hasattr(self, 'known_good_packets') or not self.known_good_packets:
                    update_progress(100, "No package to use for retraining")
                    time.sleep(1)
                    progress_window.destroy()
                    return
                
                # Check if there are quite positive quite false

                if len(self.known_good_packets) < 8:
                    proceed = messagebox.askyesno(
                        "A few examples", 
                        f"You only have {len(self.known_good_packets)} false positives. This may not be "
                        f"sufficient for effective training and may degrade the model.\n\n"
                        "Do you want to proceed anyway?"
                    )
                    if not proceed:
                        update_progress(100, "Operation cancelled")
                        time.sleep(1)
                        progress_window.destroy()
                        return
                
                update_progress(10, "Extracting features from normal packages...")
                
                # Extract features from good packets (false positives)

                good_features = []
                for packet in self.known_good_packets:
                    features = self.extract_ml_features(packet)
                    if features:
                        # Make sure all the features are float

                        good_features.append([float(f) for f in features])
                
                if not good_features:
                    update_progress(100, "Unable to extract features")
                    time.sleep(1)
                    progress_window.destroy()
                    messagebox.showinfo("Error", "Unable to extract features from packages")
                    return
                
                update_progress(20, "Packet sampling for testing..")
                
                # Sampling some normal packages to test the model

                test_features = []
                if hasattr(self, 'captured_packets') and len(self.captured_packets) > 0:
                    import random
                    # Take a random sample of packages (maximum 200)

                    sample_size = min(200, len(self.captured_packets))
                    test_packets = random.sample(self.captured_packets, sample_size)
                    
                    for packet in test_packets:
                        features = self.extract_ml_features(packet)
                        if features:
                            test_features.append([float(f) for f in features])
                
                update_progress(30, "Data Preparation for Training...")
                
                # Convert to numpy array and normalize

                import numpy as np
                X_good = np.array(good_features, dtype=np.float64)
                X_good_scaled = self.scaler.transform(X_good)
                
                # Create a copy of the model to test the effect of updating

                update_progress(40, "Test Template Creation...")
                test_model = copy.deepcopy(self.ml_model)
                
                # Train the test model

                update_progress(50, "Testing the update on a temporary model...")
                for _ in range(3):  # Use 3 iterations instead of 5 to be more conservative

                    test_model.partial_fit(X_good_scaled)
                
                # Evaluate if the test model has become too sensitive

                if test_features:
                    update_progress(60, "Evaluation of the test model...")
                    
                    X_test = np.array(test_features, dtype=np.float64)
                    X_test_scaled = self.scaler.transform(X_test)
                    
                    # Counts anomalies with the original model

                    original_predictions = self.ml_model.predict(X_test_scaled)
                    original_anomalies = sum(1 for p in original_predictions if p == -1)
                    
                    # Counts anomalies with the test model

                    test_predictions = test_model.predict(X_test_scaled)
                    test_anomalies = sum(1 for p in test_predictions if p == -1)
                    
                    # Calculate the percentage increase in anomalies

                    if original_anomalies > 0:
                        anomaly_increase_factor = test_anomalies / original_anomalies
                    else:
                        anomaly_increase_factor = float('inf') if test_anomalies > 0 else 1.0
                    
                    update_progress(70, f"Analisi risultati: {original_anomalies} vs {test_anomalies} anomalie")
                    
                    # If the increase is excessive, warn and ask for confirmation

                    if anomaly_increase_factor > 3.0 and (test_anomalies - original_anomalies) > 10:
                        proceed = messagebox.askyesno(
                            "Warning: Possible degradation", 
                            f"The update may significantly increase the number of anomalies detected:\n\n"
                            f"- Anomalies with current model: {original_anomalies}\n"
                            f"- Expected anomalies after the update: {test_anomalies}\n"
                            f"- Increase: {anomaly_increase_factor:.1f}x\n\n"
                            "This could indicate that the model will become too sensitive.\n"
                            "Do you still want to proceed with the update?"
                        )
                        if not proceed:
                            update_progress(100, "Operation canceled")
                            time.sleep(1)
                            progress_window.destroy()
                            return
                
                # Proceed with the update of the main model

                update_progress(80, "Updating the main model...")
                
                # Use less iterations to be more conservative

                iterations = 2 if len(good_features) < 10 else 3
                for _ in range(iterations):
                    self.ml_model.partial_fit(X_good_scaled)
                
                update_progress(85, "Validation of the updated model...")
                
                # Valid the model on the well -known samples good

                predictions = self.ml_model.predict(X_good_scaled)
                false_anomalies = sum(1 for p in predictions if p == -1)
                
                # Calculate the percentage of false positives still detected

                false_positive_rate = false_anomalies / len(good_features) if good_features else 1.0
                
                # Save the updated model

                update_progress(90, "Saving the updated model...")
                self.save_ml_model()
                
                update_progress(100, "Updated model!")
                time.sleep(1)
                progress_window.destroy()
                
                # Show an appropriate message based on the results

                if false_positive_rate < 0.3:
                    # Show success message

                    messagebox.showinfo(
                        "Updated Model", 
                        f"The ML model has been successfully updated using {len(good_features)} examples.\n\n"
                        f"The model now correctly recognizes {100 - int(false_positive_rate * 100)}% of reported false positives.\n\n"
                    )
                else:
                    # Show message of partial success

                    messagebox.showinfo(
                        "partially updated model", 
                        f"The model has been updated, but it only recognizes {100 - int(false_positive_rate * 100)}% of false positives.\n\n"
                        "To further improve the model:\n"
                        "1. Report multiple false positive examples (at least 10-15)\n"
                        "2. Upgrade again\n"
                        "3. Consider completely reinitializing the model\n\n"
                    )
                
            except Exception as e:
                update_progress(100, f"Error: {str(e)}")
                time.sleep(1)
                progress_window.destroy()
                messagebox.showerror("Error", f" Error updating model: {str(e)}")
                traceback.print_exc()
        
        # Start the retraining thread

        threading.Thread(target=run_retraining, daemon=True).start()

    def extract_ml_features(self, packet):
        """Extracts machine learning features from a package in a robust way"""
        try:
            features = []
            
            # ---Basic characteristics ---

            features.append(float(packet['len']))
            features.append(float(packet['ttl']))
            features.append(float(packet['protocol']))
            
            # ---IP characteristics ---

            try:
                src_ip_value = sum(int(x) for x in packet['src'].split('.'))
                dst_ip_value = sum(int(x) for x in packet['dst'].split('.'))
            except:
                # Fallback in the case of error in the IP conversion

                src_ip_value = 0
                dst_ip_value = 0
            
            features.append(float(src_ip_value))
            features.append(float(dst_ip_value))
            
            # ---features for protocol ---

            if packet.get('proto_name') == 'TCP':
                # TCP ports

                features.append(float(packet.get('sport', 0)))
                features.append(float(packet.get('dport', 0)))
                
                # TCP flags

                tcp_flags = packet.get('flags', 0)
                features.append(float(tcp_flags))
                
                # Individual flags

                features.append(float(1 if tcp_flags & 0x01 else 0))  # Fin

                features.append(float(1 if tcp_flags & 0x02 else 0))  # Syn

                features.append(float(1 if tcp_flags & 0x04 else 0))  # Rst

                features.append(float(1 if tcp_flags & 0x08 else 0))  # Psh

                features.append(float(1 if tcp_flags & 0x10 else 0))  # Ack

                
                # Payload length

                try:
                    payload_len = len(packet.get('payload', b''))
                except:
                    payload_len = 0
                features.append(float(payload_len))
                
                # Placeholder for other protocols

                features.append(0.0)
                features.append(0.0)
                features.append(0.0)
                
            elif packet.get('proto_name') == 'UDP':
                # UDP ports

                features.append(float(packet.get('sport', 0)))
                features.append(float(packet.get('dport', 0)))
                
                # Placeholder per TCP flags

                features.append(0.0)  # Flags

                features.append(0.0)  # Fin

                features.append(0.0)  # Syn

                features.append(0.0)  # Rst

                features.append(0.0)  # Psh

                features.append(0.0)  # Ack

                
                # Payload length

                try:
                    payload_len = len(packet.get('payload', b''))
                except:
                    payload_len = 0
                features.append(float(payload_len))
                
                # Placeholder for other protocols

                features.append(0.0)
                features.append(0.0)
                features.append(0.0)
                
            elif packet.get('proto_name') == 'ICMP':
                # Placeholder per porte

                features.append(0.0)
                features.append(0.0)
                
                # Placeholder per TCP flags

                features.append(0.0)  # Flags

                features.append(0.0)  # Fin

                features.append(0.0)  # Syn

                features.append(0.0)  # Rst

                features.append(0.0)  # Psh

                features.append(0.0)  # Ack

                
                # ICMP type e code

                features.append(float(packet.get('type', 0)))
                features.append(float(packet.get('code', 0)))
                features.append(float(packet.get('type', 0) * 256 + packet.get('code', 0)))
                
                # Payload length

                try:
                    payload_len = len(packet.get('payload', b''))
                except:
                    payload_len = 0
                features.append(float(payload_len))
                
            else:
                # Other packages

                features.extend([0.0] * 12)  # 12 placeholders

            
            # Check that all features are single numbers

            for i in range(len(features)):
                if not isinstance(features[i], (int, float)) or isinstance(features[i], bool):
                    print(f"Notice: Feature {i} is not a number: {features[i]}, type: {type(features[i])}")
                    features[i] = 0.0
            
            return features
        except Exception as e:
            print(f"Error in feature extraction: {str(e)}")
            traceback.print_exc()
            return None


    def is_private_ip(self, ip):
        """Check if an IP is private"""
        try:
            return ipaddress.ip_address(ip).is_private
        except:
            return False

    def classify_iot_device(self, ip, info):
        """Classify an IoT device based on network behavior"""
        # Get information from the info dictionary
        ports = info["ports"]
        protocols = info["protocols"]
        traffic = info["traffic"]
        
        # Get the manufacturer using the IP address
        # The guess_manufacturer function now accepts IP and will attempt to resolve MAC or use the IP as a fallback
        manufacturer = self.guess_manufacturer(ip)
        
        # Use the identified manufacturer to improve the classification
        if manufacturer != "Manufacturer unknown":
            # Classificazione basata sul produttore
            if any(brand in manufacturer.lower() for brand in ["amazon", "amazon technologies"]):
                if 5353 in ports and "UDP" in protocols:
                    return "Amazon Echo/Alexa Device"
                return "Amazon Smart Device"
                    
            elif any(brand in manufacturer.lower() for brand in ["google", "google inc"]):
                if 5353 in ports and "UDP" in protocols:
                    return "Google Home/Nest Device"
                elif 8008 in ports or 8009 in ports:
                    return "Google Chromecast"
                return "Google Smart Device"
                    
            elif any(brand in manufacturer.lower() for brand in ["apple", "apple inc"]):
                if 5353 in ports and "UDP" in protocols:
                    return "Apple HomePod"
                return "Apple IoT Device"
                    
            elif any(brand in manufacturer.lower() for brand in ["samsung", "samsung electronics"]):
                if traffic > 100000:
                    return "Samsung Smart TV"
                return "Samsung Smart Device"
                    
            elif any(brand in manufacturer.lower() for brand in ["philips", "signify", "philips lighting"]):
                return "Philips Hue/Smart Lighting"
                    
            elif any(brand in manufacturer.lower() for brand in ["xiaomi", "mi", "tuya"]):
                if traffic < 10000:
                    return "Xiaomi/Tuya Sensor"
                return "Xiaomi/Tuya Smart Device"
                    
            elif any(brand in manufacturer.lower() for brand in ["tp-link"]):
                if 67 in ports or 68 in ports or 53 in ports:
                    return "TP-Link Router"
                return "TP-Link Smart Device"
                    
            elif any(brand in manufacturer.lower() for brand in ["netgear"]):
                if 67 in ports or 68 in ports or 53 in ports:
                    return "Netgear Router"
                return "Netgear Smart Device"
                    
            elif any(brand in manufacturer.lower() for brand in ["huawei", "hisilicon"]):
                if 67 in ports or 68 in ports or 53 in ports:
                    return "Huawei Router"
                return "Huawei Smart Device"
                    
            elif any(brand in manufacturer.lower() for brand in ["espressif", "esp"]):
                return "ESP IoT Device/Sensor"
                    
            elif any(brand in manufacturer.lower() for brand in ["raspberry", "pi"]):
                return "Raspberry Pi IoT Device"
                    
            elif any(brand in manufacturer.lower() for brand in ["arduino"]):
                return "Arduino IoT Device"
                    
            # If we have the manufacturer but not a specific classification
            return f"{manufacturer} IoT Device"
        
        # Fallback to behavioral classification if the manufacturer doesn't help
        
        # Smart Hub/Gateway IoT
        if (1883 in ports or 8883 in ports) and (80 in ports or 443 in ports):
            if 8883 in ports:
                return "Smart Hub (Secure)"
            else:
                return "Smart Hub"
        
        # Smart Speaker/Assistant
        if 5353 in ports and "UDP" in protocols:
            if 1900 in ports:
                return "Smart Speaker (Media)"
            elif 80 in ports or 443 in ports:
                return "Smart Assistant"
            else:
                return "Smart Speaker"
        
        # Telecamere di sicurezza
        if (554 in ports or 1935 in ports) or (traffic > 100000 and (80 in ports or 443 in ports)):
            if 554 in ports:
                return "Security Camera (RTSP)"
            elif 1935 in ports:
                return "Security Camera (RTMP)"
            else:
                return "Smart Camera"
        
        # Smart TV/Media Devices
        if (1900 in ports or 5353 in ports) and traffic > 50000:
            if 8008 in ports or 8009 in ports:
                return "Chromecast Device"
            elif traffic > 200000:
                return "Smart TV"
            else:
                return "Media Device"
        
        # Router/Gateway/Network Devices
        if 53 in ports or 67 in ports or 68 in ports:
            if 53 in ports and (67 in ports or 68 in ports):
                return "Router"
            elif 53 in ports:
                return "DNS Server"
            else:
                return "Network Gateway"
        
        # Low-power sensors and devices
        if traffic < 10000:
            if 1883 in ports or 5683 in ports:
                return "IoT Sensor"
            elif len(ports) < 3:
                return "Smart Sensor/Actuator" 
        
        # Smart Appliances
        if (80 in ports or 443 in ports) and traffic < 50000 and traffic > 10000:
            return "Smart Appliance"
        
        # Lighting Devices
        if 5353 in ports and traffic < 5000:
            return "Smart Lighting"
        
        # Thermostats and climate control
        if (80 in ports or 443 in ports) and 1883 in ports and traffic < 15000:
            return "Smart Thermostat"
        
        # Generic for devices with significant traffic
        if traffic > 100000:
            return "High-Bandwidth IoT Device"
        elif traffic > 50000:
            return "Medium-Bandwidth IoT Device"
        elif traffic > 10000:
            return "Low-Bandwidth IoT Device"
        
        # If we can't categorize specifically
        return "Unknown IoT Device"

    def get_mac_by_arp(self, ip):
        """Gets the MAC address corresponding to an IP using ARP (requires privileges)"""
        import subprocess
        import re
        import platform
        
        try:
            os_type = platform.system().lower()
            
            if os_type == "windows":
                # Comando ARP di Windows
                output = subprocess.check_output(f"arp -a {ip}", shell=True).decode('utf-8')
                matches = re.search(r"([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})", output)
                if matches:
                    return matches.group(0)
            elif os_type in ["linux", "darwin"]:  # Linux o macOS
                # Comando ARP di Linux/Mac
                output = subprocess.check_output(f"arp -n {ip}", shell=True).decode('utf-8')
                matches = re.search(r"([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})", output)
                if matches:
                    return matches.group(0)
        except Exception as e:
            print(f"Error in obtaining MAC via ARP: {e}")
        
        return None

    def guess_manufacturer(self, identifier):
        """Estimate the manufacturer of a device using OUI MAC databases"""
        import csv
        import os
        
        # Percorso al file CSV scaricato
        oui_csv_path = "oui_database.csv"
        
        # Verifica se l'identificatore è un MAC o un IP
        is_mac = ':' in identifier or '-' in identifier or len(identifier) == 12
        
        if is_mac:
            # Normalizza il MAC address
            mac = identifier.replace(':', '').replace('-', '').replace('.', '').upper()
            oui = mac[:6]
        else:
            # È un IP, prova a ottenere il MAC corrispondente
            mac_address = self.get_mac_by_arp(identifier)
            if mac_address:
                mac = mac_address.replace(':', '').replace('-', '').replace('.', '').upper()
                oui = mac[:6]
            else:
                # Se non riesci a ottenere il MAC, usa la vecchia implementazione basata su IP
                manufacturers = ["Google", "Amazon", "Samsung", "Apple", "Xiaomi", "Philips", "TP-Link", "Huawei"]
                ip_sum = sum(int(octet) for octet in identifier.split('.'))
                return manufacturers[ip_sum % len(manufacturers)]
        
        # Cerca nel database OUI se abbiamo un MAC
        if os.path.exists(oui_csv_path):
            try:
                with open(oui_csv_path, 'r', encoding='utf-8', errors='ignore') as f:
                    reader = csv.reader(f)
                    next(reader)  # Salta l'intestazione
                    
                    for row in reader:
                        if len(row) >= 3:
                            mac_prefix = row[1].strip().upper().replace('-', '').replace(':', '')
                            if mac_prefix == oui:
                                return row[2].strip()
            except Exception as e:
                print(f"Error reading OUI database: {e}")
        
        # Se arriviamo qui, non abbiamo trovato corrispondenze nel database OUI
        return "Manufacturer unknown"

    def detect_iot_devices(self):
        """Discovers IoT devices in the network"""
        if not self.captured_packets:
            messagebox.showinfo("Information", "No packages to be analysed")
            return
            
        # Pulisce tabella IOT
        for item in self.iot_tree.get_children():
            self.iot_tree.delete(item)
            
        # Analizza pacchetti per identificare dispositivi
        devices = {}
        
        for packet in self.captured_packets:
            src_ip = packet.get('src', '')
            dst_ip = packet.get('dst', '')
            
            if not src_ip or not dst_ip:
                continue
            
            # Aggiungi dispositivi se non già presenti
            for ip in [src_ip, dst_ip]:
                if ip not in devices and self.is_private_ip(ip):
                    devices[ip] = {
                        "protocols": set(),
                        "traffic": 0,
                        "ports": set()
                    }
            
            # Aggiorna informazioni sui dispositivi
            if src_ip in devices:
                devices[src_ip]["traffic"] += packet.get('len', 0)
                
                if packet.get('proto_name') == 'TCP':
                    devices[src_ip]["protocols"].add("TCP")
                    if 'sport' in packet:
                        devices[src_ip]["ports"].add(packet['sport'])
                elif packet.get('proto_name') == 'UDP':
                    devices[src_ip]["protocols"].add("UDP")
                    if 'sport' in packet:
                        devices[src_ip]["ports"].add(packet['sport'])
                elif packet.get('proto_name') == 'ICMP':
                    devices[src_ip]["protocols"].add("ICMP")
            
            if dst_ip in devices:
                devices[dst_ip]["traffic"] += packet.get('len', 0)
                
                if packet.get('proto_name') == 'TCP':
                    devices[dst_ip]["protocols"].add("TCP")
                    if 'dport' in packet:
                        devices[dst_ip]["ports"].add(packet['dport'])
                elif packet.get('proto_name') == 'UDP':
                    devices[dst_ip]["protocols"].add("UDP")
                    if 'dport' in packet:
                        devices[dst_ip]["ports"].add(packet['dport'])
        
        # Classifica dispositivi
        for ip, info in devices.items():
            device_type = self.classify_iot_device(ip, info)
            
            # Passa l'indirizzo IP direttamente alla funzione guess_manufacturer
            # che ora può gestire sia IP che MAC
            manufacturer = self.guess_manufacturer(ip)
            
            protocols = ", ".join(info["protocols"])
            traffic = self.format_size(info["traffic"])
            
            risk = self.evaluate_device_risk(ip, info, device_type)
            
            self.iot_tree.insert("", tk.END, values=(ip, device_type, manufacturer, protocols, traffic, risk))
        
        messagebox.showinfo("Device scan", f"Detected {len(devices)} devices in the network")
        self.status_bar.config(text=f"Device scan completed: {len(devices)} devices detected")

    def evaluate_device_risk(self, ip, info, device_type):
        """Assess the security risk of a device"""
        risk_score = 0
        
        # Risky open doors

        risky_ports = {23, 21, 25, 445, 135, 139}
        for port in info["ports"]:
            if port in risky_ports:
                risk_score += 2
        
        # Device type

        if "Camera" in device_type:
            risk_score += 1
        
        # Traffic volume

        if info["traffic"] > 100000:
            risk_score += 1
        
        # Unsafe protocols

        if "TCP" in info["protocols"] and not 443 in info["ports"]:
            risk_score += 1
        
        # Risk ranking

        if risk_score >= 3:
            return "High"
        elif risk_score >= 1:
            return "Medium"
        else:
            return "Low"

    def format_size(self, size_bytes):
        """Format size in bytes in readable format"""
        if size_bytes < 1024:
            return f"{size_bytes} B"
        elif size_bytes < 1024 * 1024:
            return f"{size_bytes/1024:.1f} KB"
        else:
            return f"{size_bytes/(1024*1024):.1f} MB"

    def analyze_cloud_protocols(self):
        """Analyze cloud protocols in captured packets with advanced detection"""
        if not self.captured_packets:
            messagebox.showinfo("Information", "No package to analyze")
            return
            
        # Definizione ampliata dei protocolli cloud con categorie e provider
        cloud_protocols = {
            # Web/API
            80: ["HTTP", "Web/API", "Generic"],
            443: ["HTTPS/TLS", "Web/API", "Generic"],
            8080: ["HTTP alternativo", "Web/API", "Generic"],
            8443: ["HTTPS alternativo", "Web/API", "Generic"],
            
            # AWS specific
            22: ["SSH", "Amministrazione", "AWS EC2", 5], # Il valore numerico indica la soglia minima di pacchetti
            2049: ["NFS", "Storage", "AWS EFS", 5],
            3306: ["MySQL", "Database", "AWS RDS", 5],
            5432: ["PostgreSQL", "Database", "AWS RDS", 5],
            5439: ["Redshift", "Data Warehouse", "AWS", 3],
            
            # Azure specific - richiede conferma aggiuntiva
            445: ["SMB", "Storage", "File sharing", 10],  # Non più Azure Files a meno che non ci sia conferma DNS
            1433: ["SQL Server", "Database", "Database SQL", 5],
            3389: ["RDP", "Amministrazione", "Remote Desktop", 5],
            
            # Google Cloud specific
            9000: ["Cloud Storage", "Storage", "Storage provider", 5],
            8086: ["InfluxDB", "Monitoring", "Time Series DB", 3],
            
            # Kubernetes/Container
            6443: ["Kubernetes API", "Orchestration", "Kubernetes", 3],
            2379: ["etcd", "Orchestration", "Kubernetes", 3],
            10250: ["Kubelet", "Orchestration", "Kubernetes", 3],
            
            # Messaging/Queue
            1883: ["MQTT", "IoT/Messaging", "IoT Cloud", 2],
            8883: ["MQTT-SSL", "IoT/Messaging", "IoT Cloud", 2],
            5672: ["AMQP", "Messaging", "Message Queue", 3],
            9092: ["Kafka", "Streaming", "Data Streaming", 3],
            4222: ["NATS", "Messaging", "NATS.io", 3],
            
            # Database
            6379: ["Redis", "Database", "In-Memory DB", 3],
            27017: ["MongoDB", "Database", "NoSQL DB", 3],
            9200: ["Elasticsearch", "Search/Analytics", "Search Engine", 3],
            
            # Infrastructure
            53: ["DNS", "Infrastructure", "Name Resolution", 1],
            123: ["NTP", "Infrastructure", "Synchronization", 2],
            2181: ["ZooKeeper", "Infrastructure", "Coordination", 3],
            
            # Storage
            21: ["FTP", "Storage", "File Transfer", 3],
            
            # Machine Learning
            8501: ["MLflow/AI", "Machine Learning", "ML Services", 3],
            
            # VPN/Sicurezza
            1194: ["OpenVPN", "Safety", "VPN", 3],
            500: ["IKE/IPsec", "Safety", "VPN", 3],
            4500: ["IPsec NAT-T", "Safety", "VPN", 3]
        }
        
        # Domini cloud noti per rilevamento basato su hostname
        cloud_domains = {
            "amazonaws.com": "AWS",
            "amazon.com": "AWS",
            "aws.amazon.com": "AWS",
            "azure.com": "Azure Microsoft",
            "azurewebsites.net": "Azure Microsoft",
            "microsoftonline.com": "Azure Microsoft",
            "windows.net": "Azure Microsoft",
            "googlecloud.com": "Google Cloud",
            "cloud.google.com": "Google Cloud",
            "appspot.com": "Google Cloud",
            "cloudflare.com": "Cloudflare",
            "akamai.net": "Akamai",
            "fastly.net": "Fastly",
            "digitalocean.com": "DigitalOcean",
            "heroku.com": "Heroku",
            "github.com": "GitHub",
            "cloudfront.net": "AWS CDN",
            "s3.amazonaws.com": "AWS S3",
            "blob.core.windows.net": "Azure Storage",
            "servicebus.windows.net": "Azure Service Bus"
        }
        
        # Counting and data collection
        protocol_counts = {}                # Protocol Count
        provider_counts = {}                # Counting by provider
        category_counts = {}                # Count by category
        cloud_connections = []              # Connection details
        dns_mappings = {}                   # IP to hostname mappings
        port_packet_counts = {}             # Packet Count per Port
        confirmed_services = set()          # Services confirmed by more evidence
        
        # First pass: Registers DNS mappings and counts packets per port
        for packet in self.captured_packets:
            # Conta pacchetti per porta
            if packet.get('proto_name') in ['TCP', 'UDP']:
                dst_port = packet.get('dport', 0)
                src_port = packet.get('sport', 0)
                
                if dst_port in cloud_protocols:
                    port_packet_counts[dst_port] = port_packet_counts.get(dst_port, 0) + 1
                if src_port in cloud_protocols:
                    port_packet_counts[src_port] = port_packet_counts.get(src_port, 0) + 1
                
            # Registra mappature DNS
            if packet.get('proto_name') == 'DNS' and 'payload' in packet:
                try:
                    payload = packet.get('payload', '')
                    if len(payload) > 20:
                        for domain in cloud_domains:
                            if domain in payload:
                                dns_mappings[packet['dst']] = domain
                                # Mark as confirmed any service associated with this domain
                                confirmed_services.add(cloud_domains[domain])
                                break
                except:
                    pass
        
        # Second pass: Analyze cloud protocols with thresholds
        for packet in self.captured_packets:
            src_ip = packet.get('src', '')
            dst_ip = packet.get('dst', '')
            protocol = packet.get('proto_name', '')
            timestamp = time.strftime("%H:%M:%S", time.localtime(packet.get('time', 0)))
            
            # Check if there is a known cloud domain in the package
            cloud_provider = None
            domain_match = None
            
            #Check if IP addresses match known cloud domains
            for ip in [src_ip, dst_ip]:
                if ip in dns_mappings:
                    domain = dns_mappings[ip]
                    domain_match = domain
                    cloud_provider = cloud_domains.get(domain, "Cloud Provider")
                    break
            
            # Scan ports for cloud protocols whether TCP or UDP
            if protocol in ['TCP', 'UDP']:
                dst_port = packet.get('dport', 0)
                src_port = packet.get('sport', 0)
                
                # Controls both source and destination ports
                for port in [dst_port, src_port]:
                    if port in cloud_protocols:
                        protocol_info = cloud_protocols[port]
                        
                        #Check the minimum packet threshold for this port
                        min_packets = protocol_info[3] if len(protocol_info) > 3 else 2
                        if port_packet_counts.get(port, 0) < min_packets:
                            continue  # Salta se non ci sono abbastanza pacchetti
                        
                        protocol_name = protocol_info[0]
                        category = protocol_info[1]
                        
                        # Using the provider based on DNS confirmation or reducing to genericity
                        provider = protocol_info[2]
                        if cloud_provider:
                            if "Azure" in protocol_info[2] and cloud_provider != "Azure Microsoft":
                                provider = "General Service"  # Reduce Azure false positives
                            elif "AWS" in protocol_info[2] and cloud_provider != "AWS":
                                provider = "General Service"  # Reduce AWS false positives
                            elif "Google" in protocol_info[2] and cloud_provider != "Google Cloud":
                                provider = "General Service"  # Reduce Google False Positives
                            else:
                                provider = cloud_provider
                        
                        # Update Counts
                        protocol_counts[protocol_name] = protocol_counts.get(protocol_name, 0) + 1
                        provider_counts[provider] = provider_counts.get(provider, 0) + 1
                        category_counts[category] = category_counts.get(category, 0) + 1
                        
                        # Determine direction (IN/OUT)
                        direction = "OUT" if src_ip.startswith(('10.', '192.168.', '172.')) else "IN"
                        
                        # Add connection data
                        connection_details = {
                            "timestamp": timestamp,
                            "src": src_ip,
                            "dst": dst_ip,
                            "protocol": protocol_name,
                            "port": port,
                            "category": category,
                            "provider": provider,
                            "direction": direction,
                            "domain": domain_match,
                            "description": f"{category} - {provider}"
                        }
                        
                        cloud_connections.append(connection_details)
                        break  # We avoid duplicates for the same package
            
            # Analysis of non-port-based protocols
            elif protocol == 'ICMP' and (dst_ip in dns_mappings or src_ip in dns_mappings):
                provider = cloud_provider or "Cloud Provider"
                provider_counts[provider] = provider_counts.get(provider, 0) + 1
                category_counts["Monitoring"] = category_counts.get("Monitoring", 0) + 1
                
                cloud_connections.append({
                    "timestamp": timestamp,
                    "src": src_ip,
                    "dst": dst_ip,
                    "protocol": "ICMP",
                    "port": "-",
                    "category": "Monitoring",
                    "provider": provider,
                    "direction": "OUT" if src_ip.startswith(('10.', '192.168.', '172.')) else "IN",
                    "domain": domain_match,
                    "description": f"Monitoring - {provider} (ICMP)"
                })
        
        #Interface constants
        PADDING = 10
        WINDOW_SIZE = "900x650"
        SMALL_COLUMN_WIDTH = 100
        MEDIUM_COLUMN_WIDTH = 150
        LARGE_COLUMN_WIDTH = 200
        
        # Create Results Window
        cloud_window = tk.Toplevel(self.root)
        cloud_window.title("Advanced Cloud Services Analytics")
        cloud_window.geometry(WINDOW_SIZE)
        cloud_window.transient(self.root)
        cloud_window.iconbitmap(ico_path)
        cloud_window.grab_set()
        
        # Create notebooks with tabs
        cloud_notebook = ttk.Notebook(cloud_window)
        cloud_notebook.pack(fill=tk.BOTH, expand=True, padx=PADDING, pady=PADDING)
        
        #--- Tab 1: Dashboard ---#
        dashboard_frame = ttk.Frame(cloud_notebook)
        cloud_notebook.add(dashboard_frame, text="Dashboard")
        
        # Grid layouts for charts
        dashboard_frame.columnconfigure(0, weight=1)
        dashboard_frame.columnconfigure(1, weight=1)
        dashboard_frame.rowconfigure(0, weight=1)
        dashboard_frame.rowconfigure(1, weight=1)
        
        if protocol_counts or provider_counts:
            # Chart 1: Cloud protocols
            if protocol_counts:
                fig1 = plt.Figure(figsize=(4, 3), dpi=100)
                ax1 = fig1.add_subplot(111)
                
                # Limit to top 6 protocols
                top_protocols = dict(sorted(protocol_counts.items(), key=lambda x: x[1], reverse=True)[:6])
                
                protocols = list(top_protocols.keys())
                counts = list(top_protocols.values())
                
                bars = ax1.bar(protocols, counts, color='#5e81ac')
                ax1.set_title('Top Cloud Protocols')
                ax1.set_ylabel('Packets')
                ax1.tick_params(axis='x', rotation=45)
                fig1.tight_layout()
                
                frame1 = ttk.Frame(dashboard_frame)
                frame1.grid(row=0, column=0, sticky="nsew", padx=5, pady=5)
                
                canvas1 = FigureCanvasTkAgg(fig1, frame1)
                canvas1.get_tk_widget().pack(fill=tk.BOTH, expand=True)
            
            # Chart 2: Cloud providers
            if provider_counts:
                fig2 = plt.Figure(figsize=(4, 3), dpi=100)
                ax2 = fig2.add_subplot(111)
                
                providers = list(provider_counts.keys())
                counts = list(provider_counts.values())
                
                wedges, texts, autotexts = ax2.pie(counts, labels=None, autopct='%1.1f%%',
                                                shadow=False, startangle=90, 
                                                colors=['#5e81ac', '#a3be8c', '#ebcb8b', '#d08770', '#b48ead'])
                ax2.set_title('Provider Cloud')
                ax2.legend(wedges, providers, loc="center left", bbox_to_anchor=(1, 0, 0.5, 1))
                fig2.tight_layout()
                
                frame2 = ttk.Frame(dashboard_frame)
                frame2.grid(row=0, column=1, sticky="nsew", padx=5, pady=5)
                
                canvas2 = FigureCanvasTkAgg(fig2, frame2)
                canvas2.get_tk_widget().pack(fill=tk.BOTH, expand=True)
            
            # Figure 3: Categories of services
            if category_counts:
                fig3 = plt.Figure(figsize=(4, 3), dpi=100)
                ax3 = fig3.add_subplot(111)
                
                categories = list(category_counts.keys())
                counts = list(category_counts.values())
                
                bars = ax3.bar(categories, counts, color='#a3be8c')
                ax3.set_title('Categories Cloud Services')
                ax3.set_ylabel('Packets')
                ax3.tick_params(axis='x', rotation=45)
                fig3.tight_layout()
                
                frame3 = ttk.Frame(dashboard_frame)
                frame3.grid(row=1, column=0, sticky="nsew", padx=5, pady=5)
                
                canvas3 = FigureCanvasTkAgg(fig3, frame3)
                canvas3.get_tk_widget().pack(fill=tk.BOTH, expand=True)
            
            # Chart 4: Security/Connections Summary
            fig4 = plt.Figure(figsize=(4, 3), dpi=100)
            ax4 = fig4.add_subplot(111)
            
            # Calculate security statistics
            secure_count = sum(1 for conn in cloud_connections if conn['protocol'].endswith(('SSL', 'TLS', 'HTTPS')))
            insecure_count = len(cloud_connections) - secure_count
            
            security_data = [secure_count, insecure_count]
            labels = ['Sicure', 'Non sicure']
            
            wedges, texts, autotexts = ax4.pie(security_data, labels=labels, autopct='%1.1f%%',
                                            shadow=False, startangle=90,
                                            colors=['#a3be8c', '#d08770'])
            ax4.set_title('Cloud Connection Security')
            fig4.tight_layout()
            
            frame4 = ttk.Frame(dashboard_frame)
            frame4.grid(row=1, column=1, sticky="nsew", padx=5, pady=5)
            
            canvas4 = FigureCanvasTkAgg(fig4, frame4)
            canvas4.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        else:
            ttk.Label(dashboard_frame, text="No cloud services detected in capture").pack(pady=20)
        
        #--- Tab 2: Connection details --- #
        connections_frame = ttk.Frame(cloud_notebook)
        cloud_notebook.add(connections_frame, text="Connessioni")
        
        # Frames for table and scrollbar
        table_frame = ttk.Frame(connections_frame)
        table_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        if cloud_connections:
            # Table Column Definition
            columns = ("Timestamp", "Direction", "Source", "Destination", "Protocol", "Port", "Category", "Provider", "Domain")
            conn_tree = ttk.Treeview(table_frame, columns=columns, show="headings")
            
            # Configura colonne e larghezze
            conn_tree.heading("Timestamp", text="Ora")
            conn_tree.column("Timestamp", width=SMALL_COLUMN_WIDTH)
            
            conn_tree.heading("Direction", text="Dir")
            conn_tree.column("Direction", width=50)
            
            conn_tree.heading("Source", text="Source")
            conn_tree.column("Source", width=MEDIUM_COLUMN_WIDTH)
            
            conn_tree.heading("Destination", text="Destination")
            conn_tree.column("Destination", width=MEDIUM_COLUMN_WIDTH)
            
            conn_tree.heading("Protocol", text="Protocol")
            conn_tree.column("Protocol", width=SMALL_COLUMN_WIDTH)
            
            conn_tree.heading("Port", text="Port")
            conn_tree.column("Port", width=60)
            
            conn_tree.heading("Category", text="Category")
            conn_tree.column("Category", width=MEDIUM_COLUMN_WIDTH)
            
            conn_tree.heading("Provider", text="Provider")
            conn_tree.column("Provider", width=MEDIUM_COLUMN_WIDTH)
            
            conn_tree.heading("Domain", text="Domain")
            conn_tree.column("Domain", width=LARGE_COLUMN_WIDTH)
            
            # Vertical scrollbar
            v_scrollbar = ttk.Scrollbar(table_frame, orient=tk.VERTICAL, command=conn_tree.yview)
            v_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
            
            # Horizontal scrollbar
            h_scrollbar = ttk.Scrollbar(table_frame, orient=tk.HORIZONTAL, command=conn_tree.xview)
            h_scrollbar.pack(side=tk.BOTTOM, fill=tk.X)
            
            # Configure the table to use both scrollbars
            conn_tree.configure(yscrollcommand=v_scrollbar.set, xscrollcommand=h_scrollbar.set)
            conn_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
            
            # Populate the table with data
            for conn in cloud_connections:
                # Highlight insecure connections with colors
                tags = ()
                if not any(secure in conn["protocol"] for secure in ["SSL", "TLS", "HTTPS"]):
                    tags = ("insecure",)
                
                conn_tree.insert("", tk.END, values=(
                    conn["timestamp"],
                    conn["direction"],
                    conn["src"],
                    conn["dst"],
                    conn["protocol"],
                    conn["port"],
                    conn["category"],
                    conn["provider"],
                    conn["domain"] or "-"
                ), tags=tags)
            
            # Configure tags to color unsafe rows
            conn_tree.tag_configure("insecure", background="#ffcccc")
            
        else:
            # Message if there are no cloud connections detected
            ttk.Label(table_frame, text="No cloud connection detected in capture").pack(pady=20)
        
        #--- Tab 3: Recommendations --- #
        recommendations_frame = ttk.Frame(cloud_notebook)
        cloud_notebook.add(recommendations_frame, text="Recommendations")
        
        # Configuration to fill the entire space
        recommendations_frame.columnconfigure(0, weight=1)
        recommendations_frame.rowconfigure(0, weight=1)
        
        # Scrollable frame for fixed-width recommendations
        scrollable_frame_container = ttk.Frame(recommendations_frame)
        scrollable_frame_container.grid(row=0, column=0, sticky="nsew")
        scrollable_frame_container.columnconfigure(0, weight=1)
        scrollable_frame_container.rowconfigure(0, weight=1)
        
        # Canvas per scrolling
        canvas = tk.Canvas(scrollable_frame_container)
        scrollbar = ttk.Scrollbar(scrollable_frame_container, orient="vertical", command=canvas.yview)
        
        # Sliding inner container
        scrollable_frame = ttk.Frame(canvas)
        
        # Configuring scrollable_frame to Occupy Full Width
        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(
                scrollregion=canvas.bbox("all"),
                width=e.width
            )
        )
        
        # Inserting the frame into the canvas
        canvas_window = canvas.create_window((0, 0), window=scrollable_frame, anchor="nw", width=canvas.winfo_width())
        
        # Configuring the canvas to accommodate scaling
        def configure_canvas(event):
            canvas_width = event.width
            canvas.itemconfig(canvas_window, width=canvas_width)
        
        canvas.bind('<Configure>', configure_canvas)
        canvas.configure(yscrollcommand=scrollbar.set)
        
        # Positioning of canvas and scrollbar
        canvas.grid(row=0, column=0, sticky="nsew")
        scrollbar.grid(row=0, column=1, sticky="ns")
        
        # Full-width title
        title_label = ttk.Label(scrollable_frame, text="Cloud Security Recommendations", 
                            font=("Arial", 12, "bold"), anchor="center")
        title_label.pack(fill="x", expand=True, padx=10, pady=10)
        
        # Generation of recommendations based on analysis
        recommendations = []
        
        # Check for insecure connections
        insecure_connections = [c for c in cloud_connections if not any(secure in c["protocol"] for secure in ["SSL", "TLS", "HTTPS"])]
        if insecure_connections:
            recommendations.append({
                "title": "Insecure connections detected",
                "desc": f"Detect {len(insecure_connections)} unencrypted cloud connections. The use of secure protocols (HTTPS, TLS) is recommended.",
                "severity": "High"
            })
        
        # Azure/AWS/GCP Data Volume Control
        cloud_traffic = {}
        for provider in ["AWS", "Azure Microsoft", "Google Cloud"]:
            provider_conns = [c for c in cloud_connections if provider in c["provider"]]
            if provider_conns:
                cloud_traffic[provider] = len(provider_conns)
                
        if len(cloud_traffic) > 1:
            recommendations.append({
                "title": "Multi-cloud rilevato",
                "desc": f"Using {len(cloud_traffic)} different cloud providers. Consider a multi-cloud management strategy to optimize cost and security.",
                "severity": "Medium"
            })
        
        # Sensitive Services Control
        sensitive_services = ["Database", "Storage", "Amministrazione"]
        for service in sensitive_services:
            service_conns = [c for c in cloud_connections if c["category"] == service]
            if service_conns:
                recommendations.append({
                    "title": f"Exposed {service} services",
                    "desc": f"Detect {len(service_conns)} connections to {service.lower()} services. Verify that access is secure and restricted.",
                    "severity": "High" if service in ["Database", "Amministrazione"] else "Medium"
                })
        
        # Add general recommendations if there are no specific ones
        if not recommendations:
            if cloud_connections:
                recommendations.append({
                    "title": "Secure cloud traffic",
                    "desc": "No specific issues were found in cloud connections. Continue to monitor regularly.",
                    "severity": "Low"
                })
            else:
                recommendations.append({
                    "title": "No cloud traffic detected",
                    "desc": "No cloud connections were detected in the capture. If you plan to use cloud services, check connectivity.",
                    "severity": "Info"
                })
        
        # View recommendations
        for i, rec in enumerate(recommendations):
            frame = ttk.Frame(scrollable_frame, relief="groove", borderwidth=1)
            frame.pack(fill="x", expand=True, padx=10, pady=5)
            
            # Configuration to fill the full width
            frame.columnconfigure(0, weight=1)
            
            # Color based on severity
            severity_colors = {
                "High": "#ff6666",
                "Medium": "#ffcc66",
                "Low": "#99cc99",
                "Info": "#99ccff"
            }
            
            # Title of the recommendation (broad)
            title_frame = ttk.Frame(frame)
            title_frame.pack(fill="x", expand=True)
            
            title_label = ttk.Label(title_frame, text=rec["title"], font=("Arial", 10, "bold"))
            title_label.pack(side="left", anchor="w", padx=10, pady=5)
            
            severity_label = ttk.Label(title_frame, text=rec["severity"], background=severity_colors.get(rec["severity"], "#ffffff"))
            severity_label.pack(side="right", padx=10, pady=5)
            
            # Description (wide)
            desc_label = ttk.Label(frame, text=rec["desc"], wraplength=750, justify="left")
            desc_label.pack(fill="x", anchor="w", padx=10, pady=5)
        
        # Center the window relative to the main window
        cloud_window.update_idletasks()
        
        # Main window position and size
        parent_x = self.root.winfo_x()
        parent_y = self.root.winfo_y()
        parent_width = self.root.winfo_width()
        parent_height = self.root.winfo_height()
        
        # Cloud window size
        window_width = cloud_window.winfo_width()
        window_height = cloud_window.winfo_height()
        
        # Calculate Position Centered Relative to Main Window
        position_x = parent_x + (parent_width - window_width) // 2
        position_y = parent_y + (parent_height - window_height) // 2
        
        # Apply Location
        cloud_window.geometry(f"+{position_x}+{position_y}")
        
        #Show summary in a message
        num_secure = len([c for c in cloud_connections if any(secure in c["protocol"] for secure in ["SSL", "TLS", "HTTPS"])])
        num_insecure = len(cloud_connections) - num_secure
        
        messagebox.showinfo("Cloud analytics", 
                        f"Detected {len(protocol_counts)} cloud protocols with {len(cloud_connections)} connections\n"
                        f"Provider: {', '.join(provider_counts.keys()) if provider_counts else 'None'}\n"
                        f"Secure connections: {num_secure}, Unsafe: {num_insecure}")

    def setup_threat_details(self):
        """Configure the listener to show threat details when they are selected"""
        self.threat_tree.bind("<Double-1>", self.show_threat_details)



    def show_threat_details(self, event=None):
        """Shows details of a selected threat with improved hex-to-text conversion"""
        try:
            # Get the selected element

            selected_items = self.threat_tree.selection()
            if not selected_items:
                messagebox.showinfo("Information", "No Threats Selected")
                return
            
            item_id = selected_items[0]
            values = self.threat_tree.item(item_id, "values")
            
            if not values or len(values) < 5:
                messagebox.showinfo("Error", "Invalid threat information")
                return
            
            # Extract information from the selection

            timestamp = values[0]
            src_ip = values[1]
            dst_ip = values[2]
            threat_type = values[3]
            severity = values[4]
            description = values[5] if len(values) > 5 else ""
            
            # Search for the package ID in the description

            packet_id = None
            if "Packet" in description.lower():
                match = re.search(r"Packet\s+(\d+)", description.lower())
                if match:
                    try:
                        packet_id = int(match.group(1))
                        print(f"Found reference to Packet ID: {packet_id}")
                    except:
                        pass
            
            # Find the original package

            threat_packet = None
            
            # If we have an ID package, try using it directly

            if packet_id is not None and 0 <= packet_id < len(self.captured_packets):
                threat_packet = self.captured_packets[packet_id]
                print(f"Found Packet Directly by ID: {packet_id}")
            else:
                # Otherwise look for TimesTamp, IP Source and Destination

                for i, packet in enumerate(self.captured_packets):
                    packet_time = time.strftime("%H:%M:%S", time.localtime(packet['time']))
                    if (packet_time == timestamp and 
                        packet['src'] == src_ip and 
                        packet['dst'] == dst_ip):
                        threat_packet = packet
                        packet_id = i
                        print(f"Packet found via timestamp and IP match: {i}")
                        break
            
            if not threat_packet:
                messagebox.showinfo("Error", "The package associated with the threat could not be found.")
                return
            
            # Create a simplified window

            details_window = tk.Toplevel(self.root)
            details_window.title(f"Threat: {threat_type} - Package #{packet_id}")
            details_window.geometry("900x700")
            details_window.transient(self.root)
            details_window.iconbitmap(ico_path)
            details_window.grab_set()
            
            # Main frame

            main_frame = ttk.Frame(details_window)
            main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
            
            # Header

            header_frame = ttk.Frame(main_frame)
            header_frame.pack(fill=tk.X, pady=(0, 10))
            
            ttk.Label(header_frame, text=f"Threat: {threat_type}", font=("Arial", 16, "bold")).pack(anchor=tk.W)
            ttk.Label(header_frame, text=f"Packet #{packet_id} • {timestamp} • Severità: {severity}").pack(anchor=tk.W)
            ttk.Label(header_frame, text=f"Source: {src_ip} → Destination: {dst_ip}").pack(anchor=tk.W)
            
            if 'proto_name' in threat_packet:
                proto_info = f"Protocol: {threat_packet.get('proto_name', 'Unknown')}"
                if 'sport' in threat_packet and 'dport' in threat_packet:
                    proto_info += f" • Porte: {threat_packet['sport']} → {threat_packet['dport']}"
                ttk.Label(header_frame, text=proto_info).pack(anchor=tk.W)
            
            # Notebook for cards

            notebook = ttk.Notebook(main_frame)
            notebook.pack(fill=tk.BOTH, expand=True, pady=10)
            
            # Card for the content

            content_frame = ttk.Frame(notebook)
            notebook.add(content_frame, text="Package Contents")
            
            # Text widget per il payload

            payload_text = scrolledtext.ScrolledText(content_frame, wrap=tk.WORD, height=20, font=("Consolas", 10))
            payload_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
            
            # Add tags for formatting

            payload_text.tag_configure("header", font=("Arial", 11, "bold"), foreground="blue")
            payload_text.tag_configure("subheader", font=("Arial", 10, "bold"), foreground="dark blue")
            payload_text.tag_configure("highlight", background="#FFFF99")
            payload_text.tag_configure("addr", foreground="#555555")
            payload_text.tag_configure("hex", foreground="#0066CC")
            payload_text.tag_configure("ascii", foreground="#009900")
            payload_text.tag_configure("alert", foreground="red", font=("Arial", 10, "bold"))
            
            # View Payload

            if 'payload' in threat_packet and threat_packet['payload']:
                payload_data = threat_packet['payload']
                
                # Intelligent interpretation section

                payload_text.insert(tk.END, "=== INTELLIGENT INTERPRETATION ===\n", "header")
                
                # Determine the type of protocol

                proto_name = threat_packet.get('proto_name', '').upper()
                
                # Specific analysis for protocol

                if proto_name == 'HTTP':
                    try:
                        payload_str = payload_data.decode('utf-8', errors='replace')
                        payload_text.insert(tk.END, "\nInquiry/Response HTTP:\n\n", "subheader")
                        
                        # Highlights Header and HTTP methods

                        lines = payload_str.split('\n')
                        for line in lines:
                            if any(method in line for method in ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS']):
                                payload_text.insert(tk.END, f"{line}\n", "highlight")
                            elif ': ' in line:
                                parts = line.split(': ', 1)
                                payload_text.insert(tk.END, f"{parts[0]}: ", "subheader")
                                payload_text.insert(tk.END, f"{parts[1]}\n")
                            else:
                                payload_text.insert(tk.END, f"{line}\n")
                        
                        # Search for suspicious patterns

                        suspicious_patterns = [
                            ('SQL Injection', r'(SELECT|INSERT|UPDATE|DELETE).*FROM'),
                            ('XSS', r'<script|javascript:|onerror=|onload='),
                            ('Path Traversal', r'\.\.\/|\.\.\\'),
                            ('Command Injection', r';.*rm\s|;.*wget|;.*curl')
                        ]
                        
                        for pattern_name, pattern in suspicious_patterns:
                            if re.search(pattern, payload_str, re.IGNORECASE):
                                payload_text.insert(tk.END, f"\n⚠️ WARNING: Possible {pattern_name} detected!\n", "alert")
                                
                    except Exception as e:
                        payload_text.insert(tk.END, f"HTTP parsing error: {str(e)}\n")
                
                elif proto_name == 'DNS':
                    payload_text.insert(tk.END, "\nQuery/Answer DNS:\n\n", "subheader")
                    try:
                        # Simplified DNS analysis

                        if len(payload_data) >= 12:  # Header DNS minimo
                            # Estrai Transaction ID

                            trans_id = int.from_bytes(payload_data[0:2], byteorder='big')
                            payload_text.insert(tk.END, f"Transaction ID: 0x{trans_id:04x}\n")
                            
                            # Flags

                            flags = int.from_bytes(payload_data[2:4], byteorder='big')
                            qr = (flags >> 15) & 1
                            opcode = (flags >> 11) & 0xF
                            aa = (flags >> 10) & 1
                            tc = (flags >> 9) & 1
                            rd = (flags >> 8) & 1
                            ra = (flags >> 7) & 1
                            z = (flags >> 4) & 7
                            rcode = flags & 0xF
                            
                            payload_text.insert(tk.END, f"Type: {'Answer' if qr else 'Query'}\n")
                            payload_text.insert(tk.END, f"OpCode: {opcode}\n")
                            payload_text.insert(tk.END, f"Flags: AA={aa}, TC={tc}, RD={rd}, RA={ra}, Z={z}, RCODE={rcode}\n")
                            
                            # Counters

                            qdcount = int.from_bytes(payload_data[4:6], byteorder='big')
                            ancount = int.from_bytes(payload_data[6:8], byteorder='big')
                            nscount = int.from_bytes(payload_data[8:10], byteorder='big')
                            arcount = int.from_bytes(payload_data[10:12], byteorder='big')
                            
                            payload_text.insert(tk.END, f"Questions: {qdcount}, Answers: {ancount}, NS: {nscount}, AR: {arcount}\n\n")
                            
                            # Try to extract the domain name (simplified)

                            if qdcount > 0:
                                try:
                                    # Start after the header

                                    pos = 12
                                    domain_parts = []
                                    
                                    while True:
                                        length = payload_data[pos]
                                        pos += 1
                                        if length == 0:
                                            break
                                        
                                        domain_part = payload_data[pos:pos+length].decode('ascii', errors='replace')
                                        domain_parts.append(domain_part)
                                        pos += length
                                    
                                    domain = '.'.join(domain_parts)
                                    payload_text.insert(tk.END, f"Domain requesto: {domain}\n", "highlight")
                                    
                                    # Type of record

                                    qtype = int.from_bytes(payload_data[pos:pos+2], byteorder='big')
                                    qtypes = {1: "A", 2: "NS", 5: "CNAME", 15: "MX", 16: "TXT", 28: "AAAA"}
                                    qtype_str = qtypes.get(qtype, str(qtype))
                                    payload_text.insert(tk.END, f"Record type: {qtype_str}\n")
                                    
                                except Exception as e:
                                    payload_text.insert(tk.END, f"Error in domain parsing: {str(e)}\n")
                    except Exception as e:
                        payload_text.insert(tk.END, f"DNS parsing error: {str(e)}\n")
                
                elif proto_name == 'ICMP':
                    payload_text.insert(tk.END, "\nMessage ICMP:\n\n", "subheader")
                    icmp_type = threat_packet.get('type', -1)
                    icmp_code = threat_packet.get('code', -1)
                    
                    icmp_types = {
                        0: "Echo Reply",
                        3: "Destination Unreachable",
                        5: "Redirect",
                        8: "Echo Request",
                        11: "Time Exceeded"
                    }
                    
                    type_str = icmp_types.get(icmp_type, f"Type {icmp_type}")
                    payload_text.insert(tk.END, f"Message: {type_str}, Code: {icmp_code}\n\n")
                    
                    # For Echo Request/Reply, it shows the identifier and the sequence

                    if icmp_type in [0, 8] and len(payload_data) >= 4:
                        identifier = int.from_bytes(payload_data[0:2], byteorder='big')
                        sequence = int.from_bytes(payload_data[2:4], byteorder='big')
                        payload_text.insert(tk.END, f"Identifier: {identifier}, Sequence: {sequence}\n")
                
                # View as a text

                payload_text.insert(tk.END, "\n\n=== CONTENT AS TEXT ===\n", "header")
                try:
                    # Try different codes

                    encodings = ['utf-8', 'ascii', 'latin-1', 'windows-1252']
                    decoded = False
                    
                    for encoding in encodings:
                        try:
                            payload_str = payload_data.decode(encoding, errors='strict')
                            payload_text.insert(tk.END, f"\nEncoding detected: {encoding}\n\n", "subheader")
                            payload_text.insert(tk.END, payload_str)
                            decoded = True
                            break
                        except UnicodeDecodeError:
                            continue
                    
                    if not decoded:
                        # Fallback a replace

                        payload_str = payload_data.decode('utf-8', errors='replace')
                        payload_text.insert(tk.END, "\nUnable to decode with standard encoding, monster with character substitution:\n\n", "subheader")
                        payload_text.insert(tk.END, payload_str)
                except Exception as e:
                    payload_text.insert(tk.END, f"\nError in decoding: {str(e)}\n")
                
                # View as Hex with interpretation

                payload_text.insert(tk.END, "\n\n=== CONTENT AS HEX ===\n", "header")
                
                # Format the hexadecimal dump

                addr = 0
                while addr < len(payload_data):
                    line_data = payload_data[addr:addr+16]
                    hex_data = ' '.join(f'{b:02x}' for b in line_data)
                    
                    # Pad with spaces to align the ASCII part

                    if len(line_data) < 16:
                        hex_data += '   ' * (16 - len(line_data))
                    
                    # ASCII part

                    ascii_data = ''.join(chr(b) if 32 <= b < 127 else '.' for b in line_data)
                    
                    # Insert with formatting

                    payload_text.insert(tk.END, f'{addr:04x}  ', "addr")
                    payload_text.insert(tk.END, f'{hex_data}  ', "hex")
                    payload_text.insert(tk.END, f'|{ascii_data}|\n', "ascii")
                    addr += 16
                
                # Add a section for the advanced interpretation of hexadecimal data

                payload_text.insert(tk.END, "\n\n=== ADVANCED INTERPRETING ===\n", "header")
                
                # Search common patterns in data
                # 1. ASCII string

                payload_text.insert(tk.END, "\nASCII strings detected:\n", "subheader")
                ascii_strings = []
                current_string = ""
                
                for byte in payload_data:
                    if 32 <= byte < 127:  # Printed ascii character

                        current_string += chr(byte)
                    else:
                        if len(current_string) >= 4:  # Only strings of at least 4 characters

                            ascii_strings.append(current_string)
                        current_string = ""
                
                # Add the last string if present

                if len(current_string) >= 4:
                    ascii_strings.append(current_string)
                
                if ascii_strings:
                    for i, string in enumerate(ascii_strings):
                        payload_text.insert(tk.END, f"{i+1}. \"{string}\"\n")
                else:
                    payload_text.insert(tk.END, "No significant ASCII strings detected.\n")
                
                # 2. IP addresses

                payload_text.insert(tk.END, "\nPossible IP addresses:\n", "subheader")
                found_ips = False
                
                # Search for IPV4 addresses patterns

                for i in range(len(payload_data) - 3):
                    if all(0 <= b <= 255 for b in payload_data[i:i+4]):
                        ip_addr = '.'.join(str(b) for b in payload_data[i:i+4])
                        payload_text.insert(tk.END, f"Offset 0x{i:04x}: {ip_addr}\n")
                        found_ips = True
                
                if not found_ips:
                    payload_text.insert(tk.END, "No possible IPv4 address detected.\n")
                
                # 3. Timestamp

                payload_text.insert(tk.END, "\nPossible timestamps:\n", "subheader")
                found_timestamps = False
                
                # Cerca timestamp UNIX a 32 bit

                for i in range(0, len(payload_data) - 3, 4):
                    try:
                        timestamp_value = int.from_bytes(payload_data[i:i+4], byteorder='little')
                        # Reasonable timestamp between 2000 and 2030

                        if 946684800 <= timestamp_value <= 1893456000:
                            timestamp_date = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(timestamp_value))
                            payload_text.insert(tk.END, f"Offset 0x{i:04x}: {timestamp_date} (Unix: {timestamp_value})\n")
                            found_timestamps = True
                    except:
                        pass
                
                if not found_timestamps:
                    payload_text.insert(tk.END, "No UNIX timestamps detected.\n")
                
                # 4. File formats

                payload_text.insert(tk.END, "\nFile signatures detected:\n", "subheader")
                file_signatures = {
                    b'PK\x03\x04': 'ZIP archive',
                    b'MZ': 'Windows executable (EXE/DLL)',
                    b'\x89PNG\r\n\x1a\n': 'PNG image',
                    b'\xff\xd8\xff': 'JPEG image',
                    b'GIF8': 'GIF image',
                    b'%PDF': 'PDF document',
                    b'ID3': 'MP3 audio (with ID3)',
                    b'\x7fELF': 'ELF executable (Linux)',
                    b'RIFF': 'RIFF container (AVI/WAV)',
                    b'\x1f\x8b\x08': 'GZIP compressed',
                    b'BZh': 'BZIP2 compressed',
                    b'7z\xbc\xaf\x27\x1c': '7-Zip archive',
                    b'\xca\xfe\xba\xbe': 'Java class file',
                    b'\xed\xab\xee\xdb': 'RPM package',
                    b'OggS': 'Ogg container',
                    b'\x00\x01\x00\x00\x00': 'TrueType font',
                    b'<?xml': 'XML document'
                }
                
                found_files = False
                for signature, file_type in file_signatures.items():
                    sig_len = len(signature)
                    for i in range(len(payload_data) - sig_len + 1):
                        if payload_data[i:i+sig_len] == signature:
                            payload_text.insert(tk.END, f"Offset 0x{i:04x}: {file_type}\n")
                            found_files = True
                
                if not found_files:
                    payload_text.insert(tk.END, "No file signatures detected.\n")
                
                # 5. Specific analysis based on the type of threat

                if "SQL Injection" in threat_type:
                    payload_text.insert(tk.END, "\nSQL Injection Analysis:\n", "subheader")
                    try:
                        sql_patterns = [
                            r'SELECT\s+.*\s+FROM',
                            r'INSERT\s+INTO',
                            r'UPDATE\s+.*\s+SET',
                            r'DELETE\s+FROM',
                            r'UNION\s+SELECT',
                            r'DROP\s+TABLE',
                            r'--\s',  # SQL comment

                            r'/\*.*?\*/',  # SQL block comment

                            r'1=1',
                            r'OR\s+\d+=\d+',
                            r'EXEC\s+xp_'
                        ]
                        
                        payload_str = payload_data.decode('utf-8', errors='replace')
                        for pattern in sql_patterns:
                            for match in re.finditer(pattern, payload_str, re.IGNORECASE):
                                start, end = match.span()
                                context_start = max(0, start - 10)
                                context_end = min(len(payload_str), end + 10)
                                context = payload_str[context_start:context_end]
                                payload_text.insert(tk.END, f"Found: {match.group(0)}\n")
                                payload_text.insert(tk.END, f"Context: ...{context}...\n\n", "highlight")
                    except Exception as e:
                        payload_text.insert(tk.END, f"Error in SQL parsing: {str(e)}\n")
                
                elif "XSS" in threat_type:
                    payload_text.insert(tk.END, "\nCross-Site Scripting Analysis (XSS):\n", "subheader")
                    try:
                        xss_patterns = [
                            r'<script.*?>.*?</script>',
                            r'javascript:',
                            r'onerror=',
                            r'onload=',
                            r'onclick=',
                            r'onmouseover=',
                            r'eval\(',
                            r'document\.cookie',
                            r'alert\(',
                            r'String\.fromCharCode\(',
                            r'<img[^>]*src=[^>]*>'
                        ]
                        
                        payload_str = payload_data.decode('utf-8', errors='replace')
                        for pattern in xss_patterns:
                            for match in re.finditer(pattern, payload_str, re.IGNORECASE):
                                start, end = match.span()
                                context_start = max(0, start - 10)
                                context_end = min(len(payload_str), end + 10)
                                context = payload_str[context_start:context_end]
                                payload_text.insert(tk.END, f"Found: {match.group(0)}\n")
                                payload_text.insert(tk.END, f"Context: ...{context}...\n\n", "highlight")
                    except Exception as e:
                        payload_text.insert(tk.END, f"Error in XSS parsing: {str(e)}\n")
            else:
                payload_text.insert(tk.END, "This package does not contain any payload.\n\n", "header")
                payload_text.insert(tk.END, "Control packets or some types of protocol packets often do not contain data.")

            # Details for details

            details_frame = ttk.Frame(notebook)
            notebook.add(details_frame, text="Package Details")

            # Treeview for details

            details_tree = ttk.Treeview(details_frame, columns=("Field", "Value"), show="headings")
            details_tree.heading("Field", text="Field")
            details_tree.heading("Value", text="Value")
            details_tree.column("Field", width=200)
            details_tree.column("Value", width=550)
            details_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)

            # Scrollbar

            scrollbar = ttk.Scrollbar(details_frame, orient=tk.VERTICAL, command=details_tree.yview)
            scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
            details_tree.configure(yscrollcommand=scrollbar.set)

            # Populate the details

            for key, value in sorted(threat_packet.items()):
                if key in ['raw', 'payload']:
                    if key == 'payload' and value:
                        details_tree.insert("", "end", values=(key, f"[{len(value)} bytes]"))
                    continue
                
                # Format the value

                if isinstance(value, bytes):
                    formatted_value = f"[{len(value)} bytes]"
                else:
                    formatted_value = str(value)
                
                details_tree.insert("", "end", values=(key, formatted_value))

            # Recommendation sheet

            recommendations_frame = ttk.Frame(notebook)
            notebook.add(recommendations_frame, text="Recommendations")

            # Text Widget for Recommendations

            recommendations_text = scrolledtext.ScrolledText(recommendations_frame, wrap=tk.WORD, height=20, font=("Arial", 10))
            recommendations_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

            # Add tags for formatting

            recommendations_text.tag_configure("header", font=("Arial", 12, "bold"), foreground="blue")
            recommendations_text.tag_configure("subheader", font=("Arial", 11, "bold"), foreground="dark blue")
            recommendations_text.tag_configure("important", foreground="red")

            # Add recommendations based on the type of threat

            recommendations_text.insert(tk.END, "SAFETY RECOMMENDATIONS\n\n", "header")

            # Specific recommendations by type of threat

            if "SQL Injection" in threat_type:
                recommendations_text.insert(tk.END, "To prevent SQL Injection attacks:\n\n", "subheader")
                recommendations_text.insert(tk.END, "1. Always use prepared statements or parameterized procedures\n")
                recommendations_text.insert(tk. END, "2. Implement rigorous input validation\n")
                recommendations_text.insert(tk. END, "3. Use a Web Application Firewall (WAF)\n")
                recommendations_text.insert(tk. END, "4. Enforce the principle of least privilege for database accounts\n")
                recommendations_text.insert(tk. END, "5. Run vulnerability scanners regularly\n\n")
                recommendations_text.insert(tk. END, "IMMEDIATE ACTION:", "important")
                recommendations_text.insert(tk. END, "Test the application code that handles this endpoint and make sure it uses prepared statements.\n")

            elif "XSS" in threat_type:
                recommendations_text.insert(tk.END, "To prevent Cross-Site Scripting (XSS) attacks:\n\n", "subheader")
                recommendations_text.insert(tk.END, "1. Implement contextual escaping of all outputs\n")
                recommendations_text.insert(tk.END, "2. Use security HTTP headers such as Content-Security-Policy\n")
                recommendations_text.insert(tk.END, "3. Strictly validates all server-side inputs\n")
                recommendations_text.insert(tk.END, "4. Use modern libraries that handle escaping automatically\n")
                recommendations_text.insert(tk.END, "5. Set cookies as HttpOnly to prevent theft via JavaScript\n\n")
                recommendations_text.insert(tk.END, "IMMEDIATE ACTION: ", "important")
                recommendations_text.insert(tk.END, "Implement Content-Security-Policy and verify the sanitization of inputs in the application.\n")

            elif "Port Scan" in threat_type:
                recommendations_text.insert(tk.END, "To protect your system from port scanning:\n\n", "subheader")
                recommendations_text.insert(tk.END, "1. Properly configure the firewall to restrict port access\n")
                recommendations_text.insert(tk.END, "2. Implements intrusion detection systems (IDS/IPS)\n")
                recommendations_text.insert(tk.END, "3. Consider using non-standard ports for critical services\n")
                recommendations_text.insert(tk.END, "4. Disable all unnecessary services\n")
                recommendations_text.insert(tk.END, "5. Implement rate limiting for connections from single IPs\n\n")
                recommendations_text.insert(tk.END, "IMMEDIATE ACTION: ", "important")
                recommendations_text.insert(tk.END, "Verify the firewall configuration and block the source IP if suspicious activity continues.\n")

            elif "DoS" in threat_type or "DDoS" in threat_type:
                recommendations_text.insert(tk.END, "To mitigate denial of service attacks:\n\n", "subheader")
                recommendations_text.insert(tk.END, "1. Implementa rate limiting e traffic shaping\n")
                recommendations_text.insert(tk.END, "2. Use DDoS protection services like Cloudflare or AWS Shield\n")
                recommendations_text.insert(tk.END, "3. Configure appropriate timeouts on servers\n")
                recommendations_text.insert(tk.END, "4. Deploy infrastructure across multiple data centers\n")
                recommendations_text.insert(tk.END, "5. Implement auto-scaling systems to handle traffic spikes\n\n")
                recommendations_text.insert(tk.END, "IMMEDIATE ACTION: ", "important")
                recommendations_text.insert(tk.END, "Set up rate limiting rules on your firewall and contact your network provider if the attack persists.\n")
            
            elif "Malware" in threat_type:
                recommendations_text.insert(tk.END, "To deal with potential malware infections:\n\n", "subheader")
                recommendations_text.insert(tk.END, "1. Run a full system virus scan immediately\n")
                recommendations_text.insert(tk.END, "2. Update all software and operating systems to the latest version\n")
                recommendations_text.insert(tk.END, "3. Implement an Endpoint Detection and Response (EDR) solution\n")
                recommendations_text.insert(tk.END, "4. Configure stricter security policies\n")
                recommendations_text.insert(tk.END, "5. Consider temporarily isolating compromised systems\n\n")
                recommendations_text.insert(tk.END, "IMMEDIATE ACTION: ", "important")
                recommendations_text.insert(tk.END, "Isolate the affected system from the network and start a thorough virus scan.\n")
            
            elif "Data Exfiltration" in threat_type:
                recommendations_text.insert(tk.END, "To prevent data exfiltration:\n\n", "subheader")
                recommendations_text.insert(tk.END, "1. Implement Data Loss Prevention (DLP) to monitor outbound traffic\n")
                recommendations_text.insert(tk.END, "2. Use encryption for all sensitive data\n")
                recommendations_text.insert(tk.END, "3. Segment your network to restrict access to sensitive data\n")
                recommendations_text.insert(tk.END, "4. Monitor and limit the use of unauthorized cloud storage services\n")
                recommendations_text.insert(tk.END, "5. Implement least-privilege access controls\n\n")
                recommendations_text.insert(tk.END, "IMMEDIATE ACTION: ", "important")
                recommendations_text.insert(tk.END, "Check what data may have been compromised and block the suspicious destination IP.\n")
            
            else:
                # Generic recommendations

                recommendations_text.insert(tk.END, "General Safety Recommendations:\n\n", "subheader")
                recommendations_text.insert(tk.END, "1. Keep all systems and applications up to date\n")
                recommendations_text.insert(tk.END, "2. Implement a properly configured firewall\n")
                recommendations_text.insert(tk.END, "3. Uses intrusion detection systems\n")
                recommendations_text.insert(tk.END, "4. Run regular vulnerability scans\n")
                recommendations_text.insert(tk.END, "5. Implement multi-factor authentication where possible\n")
                recommendations_text.insert(tk.END, "6. Segment your network to limit threat propagation\n")
                recommendations_text.insert(tk.END, "7. Regularly monitors system and network logs\n\n")
                recommendations_text.insert(tk.END, "RECOMMENDED ACTION: ", "important")
                recommendations_text.insert(tk.END, "Further analyze this threat to determine its origin and potential impact.\n")
            
            # Add context information

            recommendations_text.insert(tk.END, "\nADDITIONAL INFORMATION\n", "subheader")
            
            # Check if the source ip is known

            src_info = "No information available"
            if hasattr(self, 'threat_db') and 'ip' in self.threat_db:
                if src_ip in self.threat_db['ip']:
                    src_info = f"IP conosciuto: {self.threat_db['ip'][src_ip]['type']}, Severità: {self.threat_db['ip'][src_ip]['severity']}"
                    if 'description' in self.threat_db['ip'][src_ip]:
                        src_info += f", {self.threat_db['ip'][src_ip]['description']}"
            
            recommendations_text.insert(tk.END, f"\nSource IP Information ({src_ip}):\n{src_info}\n\n")
            
            # Check if there are notes involved doors

            if 'sport' in threat_packet and 'dport' in threat_packet:
                sport = threat_packet['sport']
                dport = threat_packet['dport']
                
                port_info = ""
                if hasattr(self, 'threat_db') and 'ports' in self.threat_db:
                    if str(sport) in self.threat_db['ports']:
                        port_info += f"Source Port {sport}: {self.threat_db['ports'][str(sport)]['type']}, "
                        port_info += f"Severity: {self.threat_db['ports'][str(sport)]['severity']}\n"
                    
                    if str(dport) in self.threat_db['ports']:
                        port_info += f"Destination Port {dport}: {self.threat_db['ports'][str(dport)]['type']}, "
                        port_info += f"Severity: {self.threat_db['ports'][str(dport)]['severity']}\n"
                
                if port_info:
                    recommendations_text.insert(tk.END, f"Port Information:\n{port_info}\n")
            
            # Buttons

            button_frame = ttk.Frame(main_frame)
            button_frame.pack(fill=tk.X, pady=(10, 0))
            
            # Button to export

            export_btn = ttk.Button(button_frame, text="Export Report", 
                                command=lambda: self.export_threat_report(threat_packet, threat_type, severity))
            export_btn.pack(side=tk.LEFT, padx=5)
            
            # Button to copy payload

            copy_btn = ttk.Button(button_frame, text="Copy Payload",
                            command=lambda: self.copy_to_clipboard(payload_data))
            copy_btn.pack(side=tk.LEFT, padx=5)
            
            # Button to close

            close_btn = ttk.Button(button_frame, text="Close", command=details_window.destroy)
            close_btn.pack(side=tk.RIGHT, padx=5)
            
        except Exception as e:
            # Errors management

            import traceback
            print(f"Errore in show_threat_details: {str(e)}")
            print(traceback.format_exc())
            messagebox.showerror("Error", f"An error occurred while viewing details: {str(e)}")

    def copy_to_clipboard(self, data):
        """Copy data to clipboard"""
        try:
            # If it is bytes, convert to string

            if isinstance(data, bytes):
                # Try first as a text

                try:
                    clipboard_text = data.decode('utf-8', errors='replace')
                except:
                    # Fallback with hexadecimal representation

                    clipboard_text = ' '.join(f'{b:02x}' for b in data)
            else:
                clipboard_text = str(data)
            
            # Copy in the notes

            self.root.clipboard_clear()
            self.root.clipboard_append(clipboard_text)
            messagebox.showinfo("Copy", "Data copied to clipboard")
        except Exception as e:
            messagebox.showerror("Error", f"Unable to copy to clipboard: {str(e)}")       

    def export_threat_report(self, packet, threat_type, severity):
        """Export a detailed threat report with path traversal protection"""
        try:
            # Ask the user where to save the file

            file_path = filedialog.asksaveasfilename(
                defaultextension=".txt",
                filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
                title="Save threat report"
            )
            
            if not file_path:
                return
            
            # Sanitize file path -protect against path traversal

            file_path = os.path.abspath(file_path)
            if not file_path.endswith(('.txt', '.TXT')):
                file_path += '.txt'  # Ensure it has a safe extension

            
            # Check if directory exists and is writable

            save_dir = os.path.dirname(file_path)
            if not os.path.exists(save_dir):
                messagebox.showerror("Error", f"Destination directory does not exist: {save_dir}")
                return
                
            if not os.access(save_dir, os.W_OK):
                messagebox.showerror("Error", f"Insufficient write permissions in: {save_dir}")
                return
            
            # Create the contents of the report

            report = []
            report.append("=" * 80)
            report.append(f"THREAT REPORT: {threat_type}")
            report.append("=" * 80)
            report.append("")
            report.append(f"Date/Now: {time.strftime('%Y-%m-%d %H:%M:%S')}")
            report.append(f"Severity: {severity}")
            report.append("")
            report.append("PACKAGE INFORMATION")
            report.append("-" * 40)
            report.append(f"Timestamp: {time.strftime('%H:%M:%S', time.localtime(packet['time']))}")
            report.append(f"Source IP: {packet['src']}")
            report.append(f"Destination IP: {packet['dst']}")
            report.append(f"Protocol: {packet.get('proto_name', 'Unknown')}")
            
            if 'sport' in packet:
                report.append(f"Source Port: {packet['sport']}")
            if 'dport' in packet:
                report.append(f"Destination Port: {packet['dport']}")
            
            report.append(f"Package size: {packet['len']} bytes")
            report.append("")
            
            # Add information on the threat database

            report.append("THREAT DETAILS")
            report.append("-" * 40)
            
            threat_found = False
            
            # Check IP in the database

            if 'ip' in self.threat_db and packet['src'] in self.threat_db["ip"]:
                threat_info = self.threat_db["ip"][packet['src']]
                report.append(f"Source IP {packet['src']} found in the threat database:")
                report.append(f"  Type: {threat_info.get('type', 'Unspecified')}")
                report.append(f"  Severity: {threat_info.get('severity', 'Unspecified')}")
                report.append(f"  Description: {threat_info.get('description', 'No description available')}")
                threat_found = True
            
            if 'ip' in self.threat_db and packet['dst'] in self.threat_db["ip"]:
                threat_info = self.threat_db["ip"][packet['dst']]
                report.append(f"Destination IP {packet['dst']} found in the threat database:")
                report.append(f"  Type: {threat_info.get('type', 'Unspecified')}")
                report.append(f"  Severity: {threat_info.get('severity', 'Unspecified')}")
                report.append(f"  Description: {threat_info.get('description', 'No description available')}")
                threat_found = True
            
            # Check doors in the database

            if 'sport' in packet and 'ports' in self.threat_db and str(packet['sport']) in self.threat_db["ports"]:
                port_info = self.threat_db["ports"][str(packet['sport'])]
                report.append(f"Source port {packet['sport']} found in the threat database:")
                report.append(f"  Type: {port_info.get('type', 'Unspecified')}")
                report.append(f"  Severity: {port_info.get('severity', 'Unspecified')}")
                report.append(f"  Description: {port_info.get('description', 'No description available')}")
                threat_found = True
            
            if 'dport' in packet and 'ports' in self.threat_db and str(packet['dport']) in self.threat_db["ports"]:
                port_info = self.threat_db["ports"][str(packet['dport'])]
                report.append(f"Destination port {packet['dport']} found in the threat database:")
                report.append(f"  Type: {port_info.get('type', 'Unspecified')}")
                report.append(f"  Severity: {port_info.get('severity', 'Unspecified')}")
                report.append(f"  Description: {port_info.get('description', 'No description available')}")
                threat_found = True
            
            # Check patterns in the payload

            if 'payload' in packet:
                try:
                    payload = packet['payload'].decode('latin-1', errors='ignore')
                    for pattern in self.threat_db.get("patterns", []):
                        if re.search(pattern["regex"], payload, re.IGNORECASE):
                            report.append(f"Suspicious pattern found in the payload:")
                            report.append(f"  Type: {pattern.get('type', 'Unspecified')}")
                            report.append(f"  Severity: {pattern.get('severity', 'Unspecified')}")
                            report.append(f"  Description: {pattern.get('description', 'No description available')}")
                            
                            # Find and report the corresponding text

                            match = re.search(pattern["regex"], payload, re.IGNORECASE)
                            if match:
                                matched_text = match.group(0)
                                report.append(f"  Pattern rilevato: '{matched_text}'")
                            
                            threat_found = True
                except:
                    pass
            
            if not threat_found:
                report.append("No specific details available in the threat database.")
            
            report.append("")
            
            # Add Payload In Text format if available

            if 'payload' in packet:
                report.append("PAYLOAD (TEXT FORMAT)")
                report.append("-" * 40)
                try:
                    payload_text = packet['payload'].decode('utf-8', errors='replace')
                    # Limit the length to avoid huge files

                    if len(payload_text) > 1000:
                        payload_text = payload_text[:1000] + "... (troncato)"
                    report.append(payload_text)
                except:
                    report.append("The payload could not be decoded as text.")
                report.append("")
            
            # Add recommendations

            report.append("RECOMMENDATIONS")
            report.append("-" * 40)
            
            if "scan" in threat_type.lower() or "reconnaissance" in threat_type.lower():
                report.append("1. Verify Firewall: Make sure your firewall is blocking unused ports correctly.")
                report.append("2. Implement IDS/IPS: Consider implementing an intrusion detection/prevention system.")
                report.append("3. Limit the information exposed: Minimize the information your servers expose.")
                report.append("4. Monitor: Continues to monitor for persistent scan tasks.")
            elif "malware" in threat_type.lower() or "virus" in threat_type.lower():
                report.append("1. Isolate the system: Immediately disconnect the infected system from the network.")
                report.append("2. Scan: Run a full scan with up-to-date antivirus software.")
                report.append("3. Update: Make sure all systems are up to date with the latest security patches.")
                report.append("4. Analyze: Examines system logs to identify how the infection occurred.")
            elif "dos" in threat_type.lower() or "denial" in threat_type.lower():
                report.append("1. Implement rate limiting: Configure your firewall or router to limit the number of connections.")
                report.append("2. Use anti-DDoS services: Consider using specialized services to protect against DDoS attacks.")
                report.append("3. Configure shorter timeouts: Reduce connection timeouts to free up resources faster.")
                report.append("4. Increase capacity: If possible, temporarily increase server bandwidth or resources.")
            elif "exploit" in threat_type.lower() or "vulnerability" in threat_type.lower():
                report.append("1. Patch: Immediately update vulnerable software to the latest version.")
                report.append("2. Implement WAF: Consider using a Web Application Firewall to protect web applications.")
                report.append("3. Principle of least privilege: Ensure that all services run with the least privileges needed.")
                report.append("4. Code audit: Perform regular code reviews to identify and fix vulnerabilities.")
            else:
                report.append("1. Update systems and software: Keep all systems and applications up to date.")
                report.append("2. Check your firewall and rules: Review your firewall rules and make sure that unauthorized access is blocked.")
                report.append("3. Implement multi-factor authentication: Where possible, enable two-factor authentication.")
                report.append("4. Monitor network traffic: Continue to monitor traffic to identify suspicious behavior.")
                report.append("5. Run vulnerability scans: Regularly run vulnerability scans on your network.")
            
            # Add Footer

            report.append("")
            report.append("=" * 80)
            report.append("Report generated by Wiredigg")
            report.append(f"Data: {time.strftime('%Y-%m-%d %H:%M:%S')}")
            report.append("=" * 80)
            # Use a secure way to write to file with proper error handling

            try:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write('\n'.join(report))
                
                messagebox.showinfo("Export Complete", f"Report Successfully Saved To:\n{file_path}", parent=self.root)
            except PermissionError:
                messagebox.showerror("Error", f"Insufficient permissions to write to: {file_path}", parent=self.root)
            except OSError as e:
                messagebox.showerror("Error", f"I/O Error When Saving: {str(e)}", parent=self.root)
            except Exception as e:
                messagebox.showerror("Error", f"Unable to save report: {str(e)}", parent=self.root)
        
        except Exception as e:
            messagebox.showerror("Error", f" Error creating report: {str(e)}", parent=self.root)

    def generate_predictions(self):
        """Generate network traffic forecasts with advanced statistical methods"""
        import pandas as pd
        from statsmodels.tsa.statespace.sarimax import SARIMAX
        from statsmodels.tsa.seasonal import seasonal_decompose
        from sklearn.metrics import mean_absolute_error, mean_squared_error
        from scipy import stats
        import warnings
        warnings.filterwarnings("ignore")

        if not self.captured_packets:
            messagebox.showinfo("Information", "No package to analyze")
            return
            
        # Create DataFrame with timestamps
        packets_data = pd.DataFrame([{'timestamp': float(packet['time']), 'count': 1} 
                                for packet in self.captured_packets])
        
        # Sort by timestamp
        packets_data = packets_data.sort_values('timestamp')
        
        # Resample to regular time intervals (1 second bins)
        start_time = packets_data['timestamp'].min()
        packets_data['normalized_time'] = packets_data['timestamp'] - start_time
        packets_data['time_bin'] = packets_data['normalized_time'].apply(lambda x: int(x))
        
        # Group by time bins and count packets
        time_series = packets_data.groupby('time_bin')['count'].sum().reset_index()
        time_series = time_series.rename(columns={'time_bin': 'time', 'count': 'packets'})
        
        # Fill missing time periods with zeros
        full_range = pd.DataFrame({'time': range(int(time_series['time'].min()), 
                                                int(time_series['time'].max()) + 1)})
        time_series = pd.merge(full_range, time_series, on='time', how='left').fillna(0)
        
        if len(time_series) < 10:
            messagebox.showinfo("Information", "Insufficient data to generate forecasts")
            return

        # Preprocessing: remove outliers (Z-score method)
        z_scores = stats.zscore(time_series['packets'])
        abs_z_scores = np.abs(z_scores)
        filtered_entries = (abs_z_scores < 3)  # Keep values within 3 standard deviations
        time_series_cleaned = time_series[filtered_entries]
        
        # If too many points were filtered, revert to original
        if len(time_series_cleaned) < 8:
            time_series_cleaned = time_series

        # Create time series dataset
        y = time_series_cleaned['packets'].values

        # Try to detect seasonal pattern
        try:
            # Determine if there's seasonality in the data
            if len(y) >= 12:
                decomposition = seasonal_decompose(y, model='additive', period=min(6, len(y)//2))
                seasonal = decomposition.seasonal
                has_seasonality = np.std(seasonal) > 0.1 * np.std(y)
            else:
                has_seasonality = False
                
            # Set SARIMA parameters based on data characteristics
            if has_seasonality:
                # With seasonality
                order = (1, 1, 1)
                seasonal_order = (1, 0, 1, min(6, len(y)//2))
            else:
                # Without seasonality
                order = (2, 1, 2)
                seasonal_order = (0, 0, 0, 0)
                
            # Fit SARIMA model
            model = SARIMAX(y, order=order, seasonal_order=seasonal_order,
                            enforce_stationarity=False, enforce_invertibility=False)
            model_fit = model.fit(disp=False)
            
            # Forecast future values
            forecast_steps = 20
            forecast = model_fit.get_forecast(steps=forecast_steps)
            predicted_counts = forecast.predicted_mean
            
            # Confidence intervals
            confidence_intervals = forecast.conf_int(alpha=0.05)
            lower_bounds = np.maximum(confidence_intervals.iloc[:, 0].values, 0)
            upper_bounds = confidence_intervals.iloc[:, 1].values
            
        except Exception:
            # Fallback to simpler method if SARIMA fails
            z = np.polyfit(range(len(y)), y, 3)
            p = np.poly1d(z)
            
            # Generate forecast points
            predicted_counts = p(range(len(y), len(y) + forecast_steps))
            predicted_counts = np.maximum(predicted_counts, 0)
            
            # Calculate confidence interval
            confidence = np.std(y) * 1.96  # 95% Confidence interval
            lower_bounds = np.maximum(predicted_counts - confidence, 0)
            upper_bounds = predicted_counts + confidence
        
        # Calculate forecast metrics
        if len(y) > 10:
            # Simple validation: use last 3 points for testing
            train = y[:-3]
            test = y[-3:]
            
            try:
                if has_seasonality:
                    temp_model = SARIMAX(train, order=order, seasonal_order=seasonal_order,
                                enforce_stationarity=False, enforce_invertibility=False)
                    temp_model_fit = temp_model.fit(disp=False)
                    temp_forecast = temp_model_fit.get_forecast(steps=3)
                    validation_pred = temp_forecast.predicted_mean
                else:
                    z_val = np.polyfit(range(len(train)), train, 3)
                    p_val = np.poly1d(z_val)
                    validation_pred = p_val(range(len(train), len(train) + 3))
                    
                mae = mean_absolute_error(test, validation_pred)
                rmse = np.sqrt(mean_squared_error(test, validation_pred))
                accuracy_metric = f"MAE: {mae:.2f}, RMSE: {rmse:.2f}"
            except:
                accuracy_metric = "Metrics unavailable"
        else:
            accuracy_metric = "Insufficient data for validation"
        
        # View graphic
        self.predict_fig.clear()
        ax = self.predict_fig.add_subplot(111)
        
        # Original timestamps for display
        original_times = time_series_cleaned['time'].values
        future_times = np.array(range(max(original_times) + 1, max(original_times) + forecast_steps + 1))
        
        # Real data
        ax.plot(original_times, y, 'o-', color='#5e81ac', label='Real data')
        
        # Forecast
        ax.plot(future_times, predicted_counts, '--', color='#bf616a', label='Forecast')
        
        # Add confidence area
        ax.fill_between(future_times, lower_bounds, upper_bounds, color='#bf616a', alpha=0.2)
        
        ax.set_title(f'Network traffic forecast\n{accuracy_metric}')
        ax.set_xlabel('Time (seconds)')
        ax.set_ylabel('Packages per second')
        ax.legend()
        
        self.predict_fig.tight_layout()
        self.predict_canvas.draw()
        
        # Advanced anomaly detection
        warnings = []
        
        # Check trends and patterns
        if len(predicted_counts) > 0:
            # Detect sudden spikes
            max_pred = np.max(predicted_counts)
            avg_history = np.mean(y)
            if max_pred > avg_history * 2:
                peak_time = future_times[np.argmax(predicted_counts)]
                warnings.append(f"Traffic spike predicted at t+{peak_time - max(original_times)} seconds")
            
            # Detect dramatic drops
            min_pred = np.min(predicted_counts)
            if min_pred < avg_history * 0.5 and avg_history > 1:
                drop_time = future_times[np.argmin(predicted_counts)]
                warnings.append(f"Traffic drop predicted at t+{drop_time - max(original_times)} seconds")
            
            # Detect overall trend
            if len(predicted_counts) >= 3:
                start_avg = np.mean(predicted_counts[:3])
                end_avg = np.mean(predicted_counts[-3:])
                percent_change = ((end_avg - start_avg) / max(start_avg, 1)) * 100
                
                if percent_change > 50:
                    warnings.append(f"Strong increasing trend detected (+{percent_change:.1f}%)")
                elif percent_change < -50:
                    warnings.append(f"Strong decreasing trend detected ({percent_change:.1f}%)")
                
            # Detect unusual volatility
            pred_volatility = np.std(predicted_counts) / max(np.mean(predicted_counts), 1)
            hist_volatility = np.std(y) / max(np.mean(y), 1)
            
            if pred_volatility > hist_volatility * 2:
                warnings.append("Unstable traffic pattern predicted with high volatility")
        
        # Show Notices
        if warnings:
            warning_text = "\n".join(warnings)
            messagebox.showwarning("Traffic Forecast", 
                                f"Forecast generated with the following alerts:\n\n{warning_text}")
        else:
            messagebox.showinfo("Traffic Forecast", 
                            f"Forecast generated with no anomalies detected\n{accuracy_metric}")

if __name__ == "__main__":
    root = tk.Tk()
    app = NetworkAnalyzer(root)
    root.mainloop()