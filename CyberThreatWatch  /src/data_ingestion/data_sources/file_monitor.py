import os
import time
import hashlib
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from datetime import datetime
import threading

class FileMonitor:
    def __init__(self, directory_path, callback, file_patterns=None):
        self.directory_path = directory_path
        self.callback = callback
        self.file_patterns = file_patterns or ["*.log", "*.txt", "*.csv", "*.json"]
        self.observer = Observer()
        self.processed_files = {}
        
    def start(self):
        """Start monitoring the directory"""
        event_handler = FileChangeHandler(self)
        self.observer.schedule(event_handler, self.directory_path, recursive=True)
        self.observer.start()
        print(f"Started monitoring directory: {self.directory_path}")
        
        # Process existing files
        self.process_existing_files()
        
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            self.observer.stop()
        self.observer.join()
    
    def process_existing_files(self):
        """Process files that already exist in the directory"""
        for root, _, files in os.walk(self.directory_path):
            for file in files:
                if any(file.endswith(pattern.replace("*", "")) for pattern in self.file_patterns):
                    file_path = os.path.join(root, file)
                    self.process_file(file_path)
    
    def process_file(self, file_path):
        """Process a single file"""
        file_hash = self.get_file_hash(file_path)
        if file_path in self.processed_files and self.processed_files[file_path] == file_hash:
            return  # File hasn't changed
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                self.callback({
                    'file_path': file_path,
                    'content': content,
                    'timestamp': datetime.now(),
                    'file_size': os.path.getsize(file_path),
                    'file_type': os.path.splitext(file_path)[1]
                })
                
            self.processed_files[file_path] = file_hash
            print(f"Processed file: {file_path}")
            
        except Exception as e:
            print(f"Error processing file {file_path}: {e}")
    
    def get_file_hash(self, file_path):
        """Calculate file hash to detect changes"""
        try:
            with open(file_path, 'rb') as f:
                return hashlib.md5(f.read()).hexdigest()
        except:
            return ""

class FileChangeHandler(FileSystemEventHandler):
    def __init__(self, file_monitor):
        self.file_monitor = file_monitor
    
    def on_created(self, event):
        if not event.is_directory:
            self.file_monitor.process_file(event.src_path)
    
    def on_modified(self, event):
        if not event.is_directory:
            # Add a small delay to ensure file write is complete
            threading.Timer(1.0, self.file_monitor.process_file, args=[event.src_path]).start()