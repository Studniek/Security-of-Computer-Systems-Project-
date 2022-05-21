import MainWindow as mw
import sys

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("ZLE")
    else:
        print(sys.argv[1])
        mainWindow = mw.MainWindow(sys.argv[1], sys.argv[2],title="BSK: Secure p2p chat")