import MainWindow as mw
import sys

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("DEFAULT")
        mainWindow = mw.MainWindow()
    else:
        print(sys.argv[1])
        mainWindow = mw.MainWindow(listenerPort=sys.argv[1], senderPort=sys.argv[2],title="BSK: Secure p2p chat")