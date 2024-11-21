import socket
import ssl
import threading
import hashlib
import time
import random
import logging
import csv
import os
import matplotlib.pyplot as plt

# Constants for setting up communication
HOST = '192.168.1.109'  # Controller's IP address
PORT = 65432            # Port for communication
CERT_FILE = 'server.crt'  # Path to the server's certificate (self-signed)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')
logger = logging.getLogger()

# CSV file setup for logging experiment results
csv_file = "experiment_results.csv"
csv_headers = ["Message", "Tampered", "Loss", "Delay (s)", "Latency (ms)", "Integrity"]

# Write CSV header if the file doesn't exist
try:
    with open(csv_file, mode='x', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(csv_headers)
except FileExistsError:
    pass  # File already exists, no need to write header again

# Function to create a message with integrity hash
def create_message(content):
    """Creates a message with content and appends SHA-256 hash for integrity."""
    hash_object = hashlib.sha256(content.encode())
    message_hash = hash_object.hexdigest()
    return f"{content}|{message_hash}"

def verify_message(message):
    """Verifies the integrity of the message by comparing hashes."""
    try:
        content, received_hash = message.rsplit('|', 1)
        computed_hash = hashlib.sha256(content.encode()).hexdigest()
        return computed_hash == received_hash, content
    except ValueError:
        return False, None  # Handle improperly formatted messages

# Controller class
class Controller:
    def __init__(self):
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(certfile="server.crt", keyfile="server.key")  # Load the certificate and private key
        self.server_socket = context.wrap_socket(socket.socket(socket.AF_INET, socket.SOCK_STREAM), server_side=True)
        self.server_socket.bind((HOST, PORT))
        self.server_socket.listen()
        logger.info("Controller listening for connections...")

    def handle_client(self, client_socket):
        while True:
            try:
                message = client_socket.recv(1024).decode()
                if not message:  # Client disconnected
                    logger.info("[Controller] Client disconnected.")
                    break
                
                start_time = time.time()
                is_valid, content = verify_message(message)
                latency = (time.time() - start_time) * 1000  # in ms

                # Append results to the CSV file
                with open(csv_file, mode='a', newline='') as file:
                    writer = csv.writer(file)
                    writer.writerow([content, not is_valid, False, 0, latency, "Valid" if is_valid else "Invalid"])

                if is_valid:
                    logger.info(f"[Controller] Valid message received: '{content}' | Latency: {latency:.2f} ms")
                else:
                    logger.warning("[Controller] Integrity check failed for received message.")
            
            except (ConnectionResetError, socket.error) as e:
                logger.error(f"[Controller] Connection error: {e}")
                break  # Exit loop if connection is lost
            
            except Exception as e:
                logger.error(f"[Controller] Unexpected error: {e}")
                break

        client_socket.close()
        logger.info("[Controller] Socket closed.")

    def start(self):
        while True:
            client_socket, _ = self.server_socket.accept()
            logger.info("[Controller] Client connected.")
            client_thread = threading.Thread(target=self.handle_client, args=(client_socket,))
            client_thread.start()

# Client class with SSL verification disabled
class Client:
    def __init__(self, tamper_prob=0.2, loss_prob=0.2, delay_range=(0.5, 2.0)):
        # Create SSL context with SERVER_AUTH purpose
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        
        # Disable certificate verification
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE  # Disable verification of the server certificate

        # Wrap the socket with SSL
        self.client_socket = context.wrap_socket(socket.socket(socket.AF_INET, socket.SOCK_STREAM), server_hostname=HOST)
        self.client_socket.connect((HOST, PORT))
        
        self.tamper_prob = tamper_prob
        self.loss_prob = loss_prob
        self.delay_range = delay_range
        logger.info("[Client] Connected to controller.")

        # Lists to store latencies for encrypted vs unencrypted messages
        self.encrypted_latencies = []
        self.unencrypted_latencies = []

    def simulate_tampering(self, message):
        """Simulate tampering with a given probability."""
        if random.random() < self.tamper_prob:
            tampered_message = message[::-1]  # Reverse message as an example of tampering
            logger.warning("[Client] Message tampered.")
            return tampered_message
        return message

    def simulate_packet_loss(self):
        """Simulate packet loss with a given probability."""
        if random.random() < self.loss_prob:
            logger.warning("[Client] Simulated message loss.")
            return True
        return False

    def simulate_delay(self):
        """Simulate network delay."""
        delay = random.uniform(*self.delay_range)
        logger.info(f"[Client] Simulating delay of {delay:.2f} seconds.")
        time.sleep(delay)
        return delay

    def send_message(self, content, encrypted=True):
        message = create_message(content)

        # Simulate tampering
        tampered_message = self.simulate_tampering(message)

        # Simulate message loss
        if self.simulate_packet_loss():
            return  # Skip sending message to simulate loss

        # Simulate delay
        delay = self.simulate_delay()

        # Send the message
        start_time = time.time()
        self.client_socket.sendall(tampered_message.encode())
        latency = (time.time() - start_time) * 1000  # Calculate latency in ms

        # Append experiment data to CSV
        with open(csv_file, mode='a', newline='') as file:
            writer = csv.writer(file)
            writer.writerow([content, tampered_message != message, False, delay, latency, "Valid" if tampered_message == message else "Tampered"])

        if encrypted:
            self.encrypted_latencies.append(latency)
        else:
            self.unencrypted_latencies.append(latency)

        logger.info(f"[Client] Sent message: '{content}' | Latency: {latency:.2f} ms")

    def plot_latencies(self):
        """Plot latency comparison between encrypted and unencrypted messages."""
        plt.figure(figsize=(10, 6))
        plt.plot(self.encrypted_latencies, label="Encrypted Latency", color='blue', marker='o')
        plt.plot(self.unencrypted_latencies, label="Unencrypted Latency", color='red', marker='x')
        plt.xlabel('Message Number')
        plt.ylabel('Latency (ms)')
        plt.title('Impact of Encryption on Latency')
        plt.legend()
        plt.grid(True)
        plt.show()

    def close(self):
        try:
            self.client_socket.shutdown(socket.SHUT_RDWR)  # Gracefully shutdown the socket
            self.client_socket.close()
            logger.info("[Client] Connection closed.")
        except Exception as e:
            logger.error(f"[Client] Error during socket closure: {e}")

# Initialize and run the controller in a separate thread
controller = Controller()
controller_thread = threading.Thread(target=controller.start)
controller_thread.daemon = True
controller_thread.start()

# Experiment parameters
tamper_prob = 0.3     # Probability of tampering
loss_prob = 0.3       # Probability of packet loss
delay_range = (0.5, 2.0)  # Delay range in seconds

# Initialize the client with experiment configurations
client = Client(tamper_prob=tamper_prob, loss_prob=loss_prob, delay_range=delay_range)

# Send a series of test messages from the client to the controller
messages = ["Hello Controller", "Request Data", "Status Update", "Shutdown Signal"]

# Test encrypted messages
for msg in messages:
    client.send_message(msg, encrypted=True)
    time.sleep(1)  # Simulate a delay between messages

# Test unencrypted messages
for msg in messages:
    client.send_message(msg, encrypted=False)
    time.sleep(1)  # Simulate a delay between messages

# Close the client connection
client.close()

# Plot latency results
client.plot_latencies()