# Test for SYNwall 

import socket
import sys
import traceback
import time
from threading import Thread

port = 44144
message = b'CANYOUREAD'

def main(host):
    try:
       Thread(target=start_server,args=(host,port,message)).start()
    except:
       print('[!] Server not started')
       traceback.print_exc()

    time.sleep(1)
    print('[+] Starting client')
    start_client(host,port,message)

def start_server(host,port,message):

    soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    soc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) 
    soc.settimeout(5)
    print('[+] Socket created')

    try:
        soc.bind((host, port))
    except:
        print('[!] Bind failed. Error : ' + str(sys.exc_info()))
        sys.exit(1)

    soc.listen(1)
    print('[+] Socket listening')

    connection, address = soc.accept()
    ip, port = str(address[0]), str(address[1])
    print('[+] Connected with ' + ip + ':' + port)
    client_input = connection.recv(16)
    print('[+] Received: ' + str(client_input))
    soc.close()

    # Test the result
    if client_input == message:
        print('[+] Test OK!')
        sys.exit(0)
    else:
        print('[!] Test FAILED!')
        sys.exit(1)

def start_client(host,port,message):
    soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    soc.settimeout(5)
    try:
        soc.connect((host, port))
    except:
        print('[!] Client connection error')
        sys.exit(1)
    soc.sendall(message)
    soc.close()

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print('Usage: test.py <IP address>')
        sys.exit(1) 

    if socket.gethostbyname(sys.argv[1]).startswith('127'):
        print('[!] Do not use LOCALHOST for testing!')
        sys.exit(1)

    main(sys.argv[1])
