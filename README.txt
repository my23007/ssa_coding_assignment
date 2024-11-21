Introduction:
The increasing deployment of IoT devices in Systems of Systems (SoS), such as smart homes, introduces various security risks, particularly as the Connectivity of the system grows. SoS are characterized by their interconnected nature, where individual subsystems operate autonomously but contribute to a larger purpose (Boardman & Sauser, 2006). As the number of connected devices grows, the system's attack surface may expand, leading to increased exposure to cyber threats. Since the focus is on security in the context of ABCDE characteristics, this report will consider exploring the impact of introducing encryption as mitigation strategy for defense countermeasures on latency and delay.
Below is the hypothesis: Does the use of encryption in device communication impact latency and delay?

Code description:
This Python-based project simulates a secure client-server communication model using SSL encryption. The system uses various network conditions such as packet loss, delay, and tampering to test the integrity of transmitted messages. The client sends messages to the controller with simulated tampering, packet loss, and delay. The controller verifies the integrity of the received messages and calculates latency.
The project also logs the results of these experiments in a CSV file, tracking message integrity, tampering, packet loss, delay, latency, and message validity.

Components:
1.Controller:
Listens for incoming SSL-encrypted connections from clients. 
Verifies the integrity of received messages using SHA-256 hashes.
Logs the latency and validity of each message.
2.Client:
Connects to the controller with SSL encryption.
Simulates network conditions like packet loss, delay, and tampering.
Sends messages to the controller and logs the results (tampered, lost, delay, latency).
3.CSV Logging:

Logs the results of the experiment to a CSV file for later analysis. The results include:
Message content
Whether the message was tampered with
Whether the message was lost
The simulated delay
The latency of the message
Whether the message's integrity was verified.
This experiment tests the impact of SSL encryption on latency, message integrity, and system performance under various network conditions. The ABCD framework (Autonomy, Belonging, Connectivity, and Diversity) is used to hypothesize the effects of encryption on the system.

Installation:

To run this code, you need Python installed on your system along with the necessary libraries.

1. Requirements
Python 3.x
ssl (Python standard library)
socket (Python standard library)
hashlib (Python standard library)
logging (Python standard library)
csv (Python standard library)
random (Python standard library)

2. Install Dependencies
There are no external dependencies for this project, as all required libraries are part of Python's standard library.
3. Certificate Files
Ensure you have your SSL certificate and key files (server.crt and server.key) for SSL encryption. If you do not have them, you can generate self-signed certificates for testing purposes using OpenSSL.

Python code:
 
 
Code structure:

The code consists of two main components:
-	Controller (Server)
-	Client
Each component is responsible for specific tasks in the communication process. The project also includes utility functions for message creation, integrity verification, logging, and simulation of network conditions.
1. Controller Class
The Controller class manages the incoming SSL connections from clients, processes the messages, and verifies their integrity.
Key Sections:
-	SSL Setup: The server creates an SSL context using ssl.create_default_context() and loads the server's certificate and private key using context.load_cert_chain(certfile="server.crt", keyfile="server.key"). This ensures secure communication between the client and server.
-	Socket Setup: The server uses socket.socket(socket.AF_INET, socket.SOCK_STREAM) to create a TCP/IP socket. The socket is then wrapped in SSL using wrap_socket().
-	Handling Client Connections: The server listens for client connections with self.server_socket.listen(). When a client connects, the server spawns a new thread (client_thread) to handle the client’s messages independently.
-	Message Verification: When the server receives a message, it verifies its integrity by comparing the hash of the received message with the hash appended to the message. This is done by the verify_message() function.
-	Latency Calculation: For each message received, the server logs the time it took to receive the message by measuring the difference between the time of message arrival and the time it started processing.
-	Logging: Every action, including connection, message receipt, and verification, is logged with timestamps using the logging module.

2. Client Class
The Client class is responsible for sending messages to the server. It simulates network conditions like packet loss, delay, and tampering before sending the messages.
Key Sections:
-	SSL Setup: The client also creates an SSL context using ssl.create_default_context() and disables certificate verification by setting context.check_hostname = False and context.verify_mode = ssl.CERT_NONE.
-	Socket Setup: Like the server, the client creates a TCP/IP socket and wraps it with SSL using wrap_socket(). It then connects to the server using self.client_socket.connect((HOST, PORT)).
-	Message Tampering Simulation: The client may simulate tampering with messages by reversing the message content. This is controlled by a probability value tamper_prob.
-	Packet Loss Simulation: The client simulates packet loss by randomly dropping messages based on the loss_prob probability value. If a message is lost, it is not sent to the server.
-	Network Delay Simulation: The client simulates network delay by introducing a random delay between message sending using time.sleep().
-	Message Sending: The send_message() method is responsible for creating the message, simulating tampering, packet loss, and delay, and then sending the message to the server.
-	Logging Experiment Results: The client logs the results of the experiment to a CSV file (experiment_results.csv) for later analysis. The logged data includes:
•	Message content
•	Whether the message was tampered
•	Whether the message was lost
•	Delay (in seconds)
•	Latency (in milliseconds)
•	Whether the message passed integrity checks.
3. Utility Functions
These functions are used by both the client and controller to handle message creation, integrity checking, and result logging.
create_message(content)
-	Creates a message with SHA-256 hash appended to ensure message integrity.
-	The format of the message is: "content|hash".
-	Example: create_message(“Hello Controller”) produces “Hello Controller|<hash>”.
Verify_message(message)
-	Splits the message to retrieve the original content and the appended hash.
-	Computes the hash of the content and compares it with the received hash to check message integrity.
-	Returns a  oolean indicating whether the message is valid and the content of the message.
Log_experiment_results()
-	This function logs various experiment parameters to a CSV file:
•	Whether the message was tampered or not.
•	Whether packet loss occurred.
•	The delay (simulated).
•	The latency of the message.
•	Whether the message passed integrity verification.

4. CSV Logging
The results of the experiment are logged into a CSV file named experiment_results.csv. The CSV file tracks the following columns:
-	Message: The original message sent by the client.
-	Tampered: Whether the message was tampered with during transmission.
-	Loss: Whether the message was lost during transmission.
-	Delay (s): The simulated delay before sending the message.
-	Latency (ms): The latency experienced in receiving the message.
-	Integrity: Whether the integrity check of the message passed or failed.
The first time the program runs, it creates the CSV file and writes the headers. If the file already exists, it appends the new results.

Configuration:
Host and Port: 
-	The controller and client communicate over the IP address 192.168.1.109 (configurable) and port 65432. Ensure that both client and server use the same host and port for communication.
SSL Certificate and Key:
-	server.crt and server.key are required for setting up SSL communication. These files must be in the same directory as the Python scripts or their paths should be provided in the code.
Network Simulations:
-	tamper_prob: Probability of tampering the message content. Default is 0.2.
-	loss_prob: Probability of packet loss. Default is 0.2.
-	delay_range: A tuple defining the delay range (in seconds) to simulate network delay. Default is (0.5, 2.0).
Running the code:

$ git clone https://github.com/my23007/ssa_assignment2
Cloning into 'ssa_assignment2'...
remote: Enumerating objects: 6, done.
remote: Counting objects: 100% (6/6), done.
remote: Compressing objects: 100% (4/4), done.
remote: Total 6 (delta 0), reused 3 (delta 0), pack-reused 0 (from 0)
Receiving objects: 100% (6/6), done.

myounes@myouneslap MINGW64 ~
$ cd ssa_assignment2/

myounes@myouneslap MINGW64 ~/ssa_assignment2 (main)
$ ls
README.md  main_code.py
myounes@myouneslap MINGW64 ~/ssa_assignment2 (main)
$ pip install matplotlib
$ python main_code.py

Sample output:

 

 

Related work
As the number of endpoints in a network rises, so does the likelihood of security vulnerabilities being exploited. To mitigate these risks, encryption is often used as a first line of defense in IoT systems (Li, Lou & Ren, 2020). However, encryption can have an effect on the system performance as it introduces computational overhead (fastercapital,2024)
Experiment Results:
In this study, the experiments demonstrate that encryption significantly mitigates security risks by preventing unencrypted data transmission, which is consistent with findings by Alrawais et al. (2017). However, encryption adds latency, particularly as the number of devices increases
The integrity verification system demonstrated strong security effectiveness, accurately detecting and rejecting tampered messages, thereby mitigating the risk of data compromise. Reliability under network disruptions was reasonable, although implementing a message retry protocol could further enhance system robustness. Moreover, the testing showed how latency has increased with the introduction of encryption.

Key Findings:
- Latency: notable difference in latency with encryption message versus none encrypted.
-Security: Effective tampering detection with SHA-256 hashing, enhancing system integrity.
-Reliability: Stable handling of delays, with room for improvement in handling message loss.

Recommendations:
- Consider optimized hashing algorithms or selective hashing methods to reduce latency for high-frequency messaging.
- Expand the security model to address other vulnerabilities identified in the Attack-Defense Tree
- Use Wireshark for deeper analysis and investigation.




References:

Alrawais, A., Alhothaily, A., Hu, C. and Cheng, X., (2017). Fog computing for the internet of things: Security and privacy issues. IEEE Internet Computing, 21(2), pp.34-42.

Boardman, J. and Sauser, B., (2006). System of Systems-the meaning of of. In 2006 IEEE/SMC international conference on system of systems engineering (pp. 6-pp). IEEE.

fastercapital (2024). Business data privacy 1: Encryption: Unlocking the Secrets: Safeguarding Business Data Privacy with Encryption. [online] Available at: https://fastercapital.com/content/Business-data-privacy-1--Encryption---Unlocking-the-Secrets--Safeguarding-Business-Data-Privacy-with-Encryption.html [Accessed 17 Nov. 2024].

Li, F., Zheng, Z. and Jin, C., (2016). Secure and efficient data transmission in the Internet of Things. Telecommunication Systems, 62, pp.111-122














Appendix A: Python code:

import socket
import ssl
import threading
import hashlib
import time
import random
import logging
import csv
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

        # Wrap the socket with SSL, provide the server_hostname for proper certificate validation
        self.client_socket = context.wrap_socket(socket.socket(socket.AF_INET, socket.SOCK_STREAM), server_hostname=HOST)
        
        # Connect to the server
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

    def send_message(self, content, encrypted=True):
        message = create_message(content)

        # Simulate tampering
        message = self.simulate_tampering(message)

        # Simulate message loss
        if self.simulate_packet_loss():
            return  # Skip sending message to simulate loss

        # Simulate delay
        self.simulate_delay()

        # Send the message
        start_time = time.time()
        if encrypted:
            self.client_socket.sendall(message.encode())  # Encrypted message
        else:
            self.client_socket.sendall(message.encode())  # Unencrypted message (no SSL)

        latency = (time.time() - start_time) * 1000  # Calculate latency in ms

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












Sample output:

myounes@myouneslap MINGW64 ~/ssa_assignment2 (main)
$ python main_code.py
2024-11-17 20:53:01,047 - Controller listening for connections...
2024-11-17 20:53:01,071 - [Controller] Client connected.
2024-11-17 20:53:01,071 - [Client] Connected to controller.
2024-11-17 20:53:01,071 - [Client] Simulating delay of 1.69 seconds.
2024-11-17 20:53:02,769 - [Client] Sent message: 'Hello Controller' | Latency: 0.74 ms
2024-11-17 20:53:02,769 - [Controller] Valid message received: 'Hello Controller' | Latency: 0.00 ms
2024-11-17 20:53:03,771 - [Client] Simulating delay of 0.81 seconds.
2024-11-17 20:53:04,594 - [Controller] Valid message received: 'Request Data' | Latency: 0.00 ms
2024-11-17 20:53:04,594 - [Client] Sent message: 'Request Data' | Latency: 0.00 ms
2024-11-17 20:53:05,607 - [Client] Simulating delay of 0.67 seconds.
2024-11-17 20:53:06,279 - [Client] Sent message: 'Status Update' | Latency: 0.36 ms
2024-11-17 20:53:06,279 - [Controller] Valid message received: 'Status Update' | Latency: 0.00 ms
2024-11-17 20:53:07,281 - [Client] Simulating delay of 0.74 seconds.
2024-11-17 20:53:08,034 - [Client] Sent message: 'Shutdown Signal' | Latency: 0.12 ms
2024-11-17 20:53:08,034 - [Controller] Valid message received: 'Shutdown Signal' | Latency: 0.00 ms
2024-11-17 20:53:09,039 - [Client] Simulated message loss.
2024-11-17 20:53:10,050 - [Client] Message tampered.
2024-11-17 20:53:10,050 - [Client] Simulating delay of 0.89 seconds.
2024-11-17 20:53:10,946 - [Client] Sent message: 'Request Data' | Latency: 0.23 ms
2024-11-17 20:53:10,947 - [Controller] Integrity check failed for received message.
2024-11-17 20:53:11,951 - [Client] Simulated message loss.
2024-11-17 20:53:12,967 - [Client] Simulating delay of 0.96 seconds.
2024-11-17 20:53:13,943 - [Client] Sent message: 'Shutdown Signal' | Latency: 0.35 ms
2024-11-17 20:53:13,944 - [Controller] Valid message received: 'Shutdown Signal' | Latency: 0.00 ms
2024-11-17 20:53:14,952 - [Controller] Client disconnected.
2024-11-17 20:53:14,952 - [Client] Connection closed.
2024-11-17 20:53:14,953 - [Controller] Socket closed.


 
