import zmq
import json
import time

def main():
    context = zmq.Context()
    socket = context.socket(zmq.DEALER)  # Create a DEALER socket
    socket.identity = b"mock-client"  # Set a unique identity for the client
    socket.connect("tcp://localhost:5556")  # Connect to the user-tool's ROUTER socket

    # Prepare a test message
    test_message = {
                        "type":"req_decision",
                        "body":{
                            "program":"/home/user/file-access",
                            "syscall_id":123,
                            "parameter":"some_parameter"
                        }
                    }

    print("Sending test message to user-tool...")
    socket.send_multipart([b'', json.dumps(test_message).encode()])  # Send the message

    # Wait for a response
    try:
        while True:
                _, response = socket.recv_multipart()
                response_data = json.loads(response.decode())
                print("Received response from user-tool:", response_data)
                break
    except KeyboardInterrupt:
        print("Exiting mock client...")
    finally:
        socket.close()
        context.term()

if __name__ == "__main__":
    main()
