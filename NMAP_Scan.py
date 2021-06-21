import threading

import nmap
import argparse
from threading import *

screenLock = Semaphore(value=1)


def main():
    parser = argparse.ArgumentParser(description='-t <target host> -ps <target start port> -pe <target end port>')

    parser.add_argument('-t', dest='targetHost', type=str, help='specify target host')
    parser.add_argument('-ps', dest='targetStartPort', type=str, help='specify start port')
    parser.add_argument('-pe', dest='targetEndPort', type=str, help='specify end port')

    args = parser.parse_args()

    targetHost = args.targetHost
    targetStartPort = args.targetStartPort
    targetEndPort = args.targetEndPort

    minPort = int(targetStartPort) - 1
    maxPort = int(targetEndPort)

    for Port in range(minPort, maxPort):
        Port += 1

        thread = Thread(target=nmapScan, args=(targetHost, Port))
        thread.start()

    return


def nmapScan(tgtHost, tgtPort):
    nmScan = nmap.PortScanner()
    nmScan.scan(tgtHost, str(tgtPort))
    state = nmScan[tgtHost]['tcp'][int(tgtPort)]['state']

    if state == 'open':
        screenLock.acquire()
        print(" [*] " + tgtHost + " tcp/" + str(tgtPort) + " " + state)
        screenLock.release()

    return state


if __name__ == '__main__':
    main()
