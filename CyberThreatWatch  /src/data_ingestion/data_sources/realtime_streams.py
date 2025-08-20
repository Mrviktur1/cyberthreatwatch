import socket
import select
import threading
from datetime import datetime
import ssl
import json

class RealTimeStream:
    def __init__(self, host: str, port: int, protocol: str = "tcp"):
        self.host = host
        self.port = port
        self.protocol = protocol
        self.running = False
        self.callback = None
        self.socket = None
    
    def start(self, callback: callable):
        """Start listening to the stream"""
        self.callback = callback
        self.running = True
        
        try:
            if self.protocol == "tcp":
                self._start_tcp_stream()
            elif self.protocol == "udp":
                self._start_udp_stream()
            elif self.protocol == "tls":
                self._start_tls_stream()
                
        except Exception as e:
            print(f"Error starting {self.protocol.upper()} stream: {e}")
            self.running = False
    
    def _start_tcp_stream(self):
        """Start TCP stream"""
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect((self.host, self.port))
        
        print(f"Connected to TCP stream at {self.host}:{self.port}")
        
        while self.running:
            try:
                data = self.socket.recv(4096)
                if data:
                    self._process_data(data.decode('utf-8', errors='ignore'))
                else:
                    time.sleep(0.1)
            except Exception as e:
                print(f"TCP stream error: {e}")
                break
    
    def _start_udp_stream(self):
        """Start UDP stream"""
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind((self.host, self.port))
        
        print(f"Listening to UDP stream on {self.host}:{self.port}")
        
        while self.running:
            try:
                data, addr = self.socket.recvfrom(4096)
                self._process_data(data.decode('utf-8', errors='ignore'))
            except Exception as e:
                print(f"UDP stream error: {e}")
    
    def _start_tls_stream(self):
        """Start TLS-encrypted stream"""
        context = ssl.create_default_context()
        raw_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket = context.wrap_socket(raw_socket, server_hostname=self.host)
        self.socket.connect((self.host, self.port))
        
        print(f"Connected to TLS stream at {self.host}:{self.port}")
        
        while self.running:
            try:
                data = self.socket.recv(4096)
                if data:
                    self._process_data(data.decode('utf-8', errors='ignore'))
            except Exception as e:
                print(f"TLS stream error: {e}")
                break
    
    def _process_data(self, data: str):
        """Process incoming stream data"""
        if self.callback:
            self.callback({
                'timestamp': datetime.now(),
                'data': data,
                'source': f"{self.protocol}://{self.host}:{self.port}",
                'protocol': self.protocol
            })
    
    def stop(self):
        """Stop the stream"""
        self.running = False
        if self.socket:
            self.socket.close()

class SyslogStream(RealTimeStream):
    def __init__(self, host: str = "0.0.0.0", port: int = 514):
        super().__init__(host, port, "udp")
    
    def _process_data(self, data: str):
        """Process syslog data"""
        if self.callback:
            self.callback({
                'timestamp': datetime.now(),
                'message': data.strip(),
                'source': 'syslog',
                'protocol': 'udp',
                'port': self.port
            })

class WebhookReceiver:
    def __init__(self, host: str = "0.0.0.0", port: int = 8080):
        self.host = host
        self.port = port
        self.running = False
        self.callback = None
    
    def start(self, callback: callable):
        """Start webhook receiver"""
        self.callback = callback
        self.running = True
        
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((self.host, self.port))
        server_socket.listen(5)
        
        print(f"Webhook receiver listening on {self.host}:{self.port}")
        
        while self.running:
            client_socket, addr = server_socket.accept()
            threading.Thread(target=self._handle_client, args=(client_socket, addr)).start()
    
    def _handle_client(self, client_socket, addr):
        """Handle incoming webhook connection"""
        try:
            data = client_socket.recv(4096).decode('utf-8')
            
            # Try to parse as JSON
            try:
                payload = json.loads(data)
            except json.JSONDecodeError:
                payload = {'raw_data': data}
            
            if self.callback:
                self.callback({
                    'timestamp': datetime.now(),
                    'payload': payload,
                    'source': f"webhook:{addr[0]}",
                    'client_address': addr[0]
                })
            
            client_socket.send(b"HTTP/1.1 200 OK\r\n\r\n")
            
        except Exception as e:
            print(f"Webhook error: {e}")
        finally:
            client_socket.close()
    
    def stop(self):
        """Stop webhook receiver"""
        self.running = False