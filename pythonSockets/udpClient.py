import socket

target_host = "127.0.0.1"
target_port = 9997
target_address = (target_host, target_port)

# create a socket object
client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
client.bind(target_address)

# send some data
client.sendto(b"AAABBBCCC", target_address)

# receive some data
data = client.recvfrom(1024)

print(data[0].decode())
client.close()
