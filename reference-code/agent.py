import zmq
import json
import threading
import time
import random
context = zmq.Context()
socket = context.socket(zmq.DEALER)
socket.connect("tcp://localhost:5555")  

def receive_messages():
    while True:
        try:
            message = socket.recv_string()
            print(f"\n[Daemon reply] {message}", end='')
        except zmq.ZMQError:
            break

# Start background thread to listen for messages
thread = threading.Thread(target=receive_messages, daemon=True)
thread.start()

print("Agent started. Enter messages to send to the daemon.")

try:
    while True:
        x = {
            "type": "read_db",
            "body": {}
            }

        y = {
            "type": "req_decision",
            "body": {
                "syscall_id": 123,
                "parameter": "some_parameter"
                }
            }    
        x = random.choice([x, y])    
        print(f" \n [Agent] Sending: {json.dumps(x)}")
        socket.send_multipart([b'', json.dumps(x).encode()])
        time.sleep(5)
except KeyboardInterrupt:
    print("Shutting down agent...")
finally:
    socket.close()
    context.term()