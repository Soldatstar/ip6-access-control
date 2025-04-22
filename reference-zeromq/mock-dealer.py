import zmq
import json

def main():
    context = zmq.Context()
    socket = context.socket(zmq.DEALER)  # Create a DEALER socket
    socket.identity = b"mock-client"  # Set a unique identity for the client
    socket.connect("tcp://localhost:5556")  # Connect to the user-tool's ROUTER socket

    # Prepare test messages
    test_message = {
        "type": "req_decision",
        "body": {
            "program": "/home/user/file-access",
            "syscall_id": 123,
            "parameter": "some_parameter"
        }
    }
    test_message_read_db = {
        "type": "read_db",
        "body": {
            "program": "/home/user/file-access"
        }
    }

    # Send the first message
    print("Sending first test message to user-tool...")
    socket.send_multipart([b'', json.dumps(test_message).encode()])

    # Wait for the first response
    try:
        _, response = socket.recv_multipart()
        response_data = json.loads(response.decode())
        print("Received response for first message:", response_data)

        # Send the second message after receiving the first response
        print("Sending second test message to user-tool...")
        socket.send_multipart([b'', json.dumps(test_message_read_db).encode()])

        # Wait for the second response
        _, response = socket.recv_multipart()
        response_data = json.loads(response.decode())
        print("Received response for second message:", response_data)

    except KeyboardInterrupt:
        print("Exiting mock client...")
    finally:
        socket.close()
        context.term()

if __name__ == "__main__":
    main()
