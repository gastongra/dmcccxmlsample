#!/usr/bin/env python
import socket
import ssl
# import pprint
import struct
from time import sleep
import logging
from threading import Thread

# This program is a short python version of "ExampleCmapiXML.java" sample code
# included in the Avaya DMCC XML SDK
#
# Ported to python just for fun!
#


class ExampleCmapiXML(object):
    def __init__(self, ip, port):
        self.__responses__ = {}  # response dictionary (invokeID:Message)
        self.__allDone__ = False
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.__dmccConn__ = ssl.wrap_socket(s, ca_certs="TrustedRootCAs.crt",
                                            cert_reqs=ssl.CERT_REQUIRED)
        self.__dmccConn__.settimeout(5.0)
        self.__dmccConn__.connect((ip, port))
        # logging.debug(repr(self.__dmccConn__.getpeername()))
        # logging.debug(self.__dmccConn__.cipher())
        # logging.debug(pprint.pformat(self.__dmccConn__.getpeercert()))
        self.__readerRunnable__ = Thread(target=self.responseListener)
        self.__readerRunnable__.setName("responseListener")
        self.__readerRunnable__.start()

    def responseListener(self):
        # According to CSTA-ECMA 323 Standard ANNEX G Section J.2.
        # CSTA XML without SOAP, the Header is  8 bytes long:

        # | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 |
        # |VERSION|LENGTH |   INVOKE ID   |   XML PAYLOAD

        # VERSION: 2 bytes
        # LENGTH: 2 bytes information that contains the total size
        # (XML payload + Header)
        # INVOKE ID: 4 bytes.  The id should be unique
        while not self.__allDone__:
            try:
                cstaHeader = self.__dmccConn__.recv(8)
            except socket.timeout:
                logging.debug('No data received. Iterating ...')
            else:
                version, length, invokeID = struct.unpack('>hh4s', cstaHeader)
                message = self.__dmccConn__.recv(length).decode("utf-8")
                strInvokeID = str(invokeID, 'UTF-8')
                self.__responses__[strInvokeID] = message
                logging.debug("message received - InvokeID = "+strInvokeID)
                sleep(1)
        logging.debug("All Done. Nos vamos!!!")

    def getConn(self):
        return self.__dmccConn__

    @classmethod
    def getStartAppSession(cls):
        # Read the XML data from a file:
        f = open('appsession.xml', 'r')
        line = f.read()
        f.close()
        return(line)

    @classmethod
    def getGetDeviceIdMessage(cls):
        message = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><GetDeviceId xmlns=\"http://www.avaya.com/csta\"><switchName>x.x.x.x</switchName><extension>12345</extension></GetDeviceId>"
        return(message)

    def sendRequest(self, message, invokeID):
        # According to CSTA-ECMA 323 Standard ANNEX G Section J.2.
        # CSTA XML without SOAP, the Header is  8 bytes long:

        # | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 |
        # |VERSION|LENGTH |   INVOKE ID   |   XML PAYLOAD

        # VERSION: 2 bytes
        # LENGTH: 2 bytes information that contains the total size
        # (XML payload + Header)
        # INVOKE ID: 4 bytes.  The id should be unique

        global responses
        version = 0
        length = len(message)+8
        self.__dmccConn__.sendall(struct.pack('>h', version))
        self.__dmccConn__.sendall(struct.pack('>h', length))
        self.__dmccConn__.sendall(bytes(invokeID, 'UTF-8'))
        self.__dmccConn__.sendall(bytes(message, 'UTF-8'))

    def readResponse(self, invokeID, timeToWait):
        for timer in range(timeToWait):
            sleep(1)
            if invokeID in self.__responses__:
                break
        return(self.__responses__.get(invokeID, None))

    def setAlldone(self):
        self.__allDone__ = True


def main():

    logging.basicConfig(level=logging.DEBUG, format='%(relativeCreated)6d|%(threadName)s|%(message)s')
    logging.debug("opening secure connection to DMCC server")

    global responses
    ip = 'x.x.x.x'
    port = 4722
    cmapi = ExampleCmapiXML(ip, port)
    cmapi.sendRequest(ExampleCmapiXML.getStartAppSession(), '0001')
    logging.debug(cmapi.readResponse('0001', 5))
    cmapi.sendRequest(ExampleCmapiXML.getGetDeviceIdMessage(), '0002')
    logging.debug(cmapi.readResponse('0002', 5))
    '''
    for key, value in responses.items():
        print(key)
        print(value)
        print("************************************************")
    '''

    sleep(1)
    cmapi.setAlldone()
    sleep(5)
    cmapi.getConn().close()
    logging.debug('Graceful shutdown completed. Ending program ...')


if __name__ == '__main__':
    responses = {}
    main()
