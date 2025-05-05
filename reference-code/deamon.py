import zmq
import json
context = zmq.Context()
socket = context.socket(zmq.ROUTER)
socket.bind("tcp://*:5555")  
print("Daemon is running...")

while True:
    try:
        # Receive message: [identity, delimiter, message]
        identity, _, message = socket.recv_multipart()
        # process recived json dump
        try:
            message = json.loads(message.decode())
            print(f"Agent {identity} JSON: {message}")
            print(message['type'])
            match message['type']:
                case 'read_db':
                    print("Read DB request received")
                    # Handle read_db request
                case 'req_decision':
                    print("Request decision received")
                    # Handle req_decision request
                case _:
                    print("Unknown message type")

        except json.JSONDecodeError:
            print("Failed to decode JSON")
            continue
        # Process the message and prepare a response
        
        # Echo the message back to the agent
        socket.send_multipart([identity, b'', json.dumps(message).encode()])
    except KeyboardInterrupt:
        print("Shutting down daemon...")
        break

socket.close()
context.term()