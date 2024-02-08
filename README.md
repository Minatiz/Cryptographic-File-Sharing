# Cryptographic-File-Sharing

First run server, then run client.

# How to run server

When running server it creates a binary file called server_file.bin in same folder directory.
Running the server: python3 server.py server_file.bin "port number"
Remember to use port number between 1024-49151

# How to run client

Client connects to the server IP address with port number (Same port number as server). When connecting the client downloads a file from server called received_plaintext.bin
Running the client with: python3 client.py 127.0.0.1 "port number"
