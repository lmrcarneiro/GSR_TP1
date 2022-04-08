import socket

localhost = "127.0.0.1"

class UDPCommunication:

    @staticmethod
    def recv_UDP_block(port, buff_size):
        while True:
            yield UDPCommunication.recv_UDP(port, buff_size)
    
    @staticmethod
    def recv_UDP(port, buff_size):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((localhost, port))
        data, addr = sock.recvfrom(buff_size)
        return data

    @staticmethod
    def send_UDP(msg_bytes: bytes, port):
        UDPClientSocket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
        UDPClientSocket.sendto(msg_bytes, (localhost, port))