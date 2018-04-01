#!/usr/bin/env python
# Gaston Graces
# Feb 2018

import socket
import ssl
import pprint
import struct
from time import sleep
import logging
from threading import Thread


class DmccBroker(object):
    def __init__(self, ip, port, hostname):
        self.__responses__ = {}  # response dictionary (invokeID:Message)
        self.__allDone__ = False
        self.__responseListener__ = None
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tlsContext = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        tlsContext.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1
        tlsContext.verify_mode = ssl.CERT_REQUIRED
        tlsContext.check_hostname = True
        # tlsContext.load_verify_locations("cacerts.pem", None)
        self.__dmccConn__ = tlsContext.wrap_socket(sock,
                                                   server_hostname=hostname)
        self.__dmccConn__.settimeout(5.0)
        try:
            self.__dmccConn__.connect((ip, port))
        except socket.timeout:
            logging.debug("Timeout when trying to connect to AES. Check AES server availability.")
            raise
        except Exception as e:
            logging.debug(str(e) + " exception when trying to connect to AES.")
            raise
        logging.debug("Connected to: " + self.__dmccConn__.server_hostname + " " +  repr(self.__dmccConn__.getpeername()))
        #New in version 3.5 - Not valid for python 3.4
        #logging.debug("Ciphers offered to the server (cipher name,protocol version,secret bits #): ")
        #logging.debug(self.__dmccConn__.shared_ciphers())
        #logging.debug("SSL version negotiated with server: ")
        #logging.debug(self.__dmccConn__.version)
        logging.debug("Cipher negotiated with server (cipher name,protocol version,secret bits #): ")
        logging.debug(self.__dmccConn__.cipher())
        logging.debug("******************************\nServer identifies itself as follows:\n\n")
        logging.debug(pprint.pformat(self.__dmccConn__.getpeercert()))
        logging.debug("******************************\n\n")
        self.__responseListener__ = Thread(target=self.responseListener)
        self.__responseListener__.setName("responseListener")
        self.__responseListener__.start()

    def responseListener(self):
        # According to CSTA-ECMA 323 Standard ANNEX J Section J.2.
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

    def getGetDeviceIdMessage(switchName, extension):
        message = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><GetDeviceId xmlns=\"http://www.avaya.com/csta\"><switchName>"+switchName+"</switchName><extension>"+extension+"</extension></GetDeviceId>"
        return(message)

    def getMonitorStartMessage(switchConnName, switchName, extension):
        message = '''<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<MonitorStart xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns="http://www.ecma-international.org/standards/ecma-323/csta/ed3">
    <monitorObject>
        <deviceObject typeOfNumber="other" mediaClass="notKnown">''' + extension + ":" + switchConnName+":"+switchName+''':0</deviceObject>
    </monitorObject>
    <requestedMonitorFilter>
        <physicalDeviceFeature>
            <displayUpdated>true</displayUpdated>
            <hookswitch>true</hookswitch>
            <lampMode>true</lampMode>
            <ringerStatus>true</ringerStatus>
        </physicalDeviceFeature>
    </requestedMonitorFilter>
    <extensions>
        <privateData>
            <private>
                <AvayaEvents xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns="">
                    <invertFilter xmlns="http://www.avaya.com/csta">true</invertFilter>
                    <terminalUnregisteredEvent xmlns="http://www.avaya.com/csta">
                        <unregistered>true</unregistered>
                        <reregistered>true</reregistered>
                    </terminalUnregisteredEvent>
                    <physicalDeviceFeaturesPrivateEvents xmlns="http://www.avaya.com/csta">
                        <serviceLinkStatusChanged>true</serviceLinkStatusChanged>
                    </physicalDeviceFeaturesPrivateEvents>
                </AvayaEvents>
            </private>
        </privateData>
    </extensions>
</MonitorStart>
'''
        return(message)

    @classmethod
    def getMonitorStopMessage(cls):
        message = '''<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<MonitorStop xmlns=\"http://www.avaya.com/csta\">
<monitorCrossRefID>1111111</monitorCrossRefID>
</MonitorStop>
'''
        return(message)

    def getSnapshotDeviceMessage(switchConnName, switchName, extension):
        '''#########################################################################
        message = <?xml version="1.0" encoding="utf-8"?>
<SnapshotDevice xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns="http://www.ecma-international.org/standards/ecma-323/csta/ed3">
<snapshotObject>''' + extension +":"+switchConnName+":"+switchName+ ''':1</snapshotObject>
<extensions>
<privateData>
<private>
<SnapshotDevicePrivateData xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns="http://www.avaya.com/csta">
<getStationStatus>true</getStationStatus>
</SnapshotDevicePrivateData>
</private>
</privateData>
</extensions>
</SnapshotDevice>
#########################################################################'''
        message = '''<?xml version="1.0" encoding="utf-8"?>
<SnapshotDevice xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns="http://www.ecma-international.org/standards/ecma-323/csta/ed3">
<snapshotObject>'''+extension+":"+switchConnName+":"+switchName+''':1</snapshotObject>
<extensions>
<privateData>
<private>
<SnapshotDevicePrivateData xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns="http://www.avaya.com/csta">
<getStationStatus>true</getStationStatus>
</SnapshotDevicePrivateData>
</private>
</privateData>
</extensions>
</SnapshotDevice>
'''
        return(message)

    def sendRequest(self, message, invokeID):
        # According to CSTA-ECMA 323 Standard ANNEX J Section J.2.
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
        logging.debug("message sent - InvokeID = " + invokeID)
        logging.debug(message + "\n")

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
    ip = '192.168.1.23' #AES server´s IP address
    port = 4722 #Secure DMCC service´s port #
    hostname = "myaesserver.example.com" #AES server´s FQDN
    switchConnName = "CM" #switch connection name as configured in the AES server´s switch connections section
    switchName = "192.168.1.32" #IP address or FQDN of the CM server
    extension = "12345"
    try:
        broker = DmccBroker(ip, port, hostname)
    except Exception as e:
        logging.debug(str(e) + " exception. Goodbye :(")
        return
    broker.sendRequest(DmccBroker.getStartAppSession(), '0001')
    logging.debug(broker.readResponse('0001', 5))
    broker.sendRequest(DmccBroker.getGetDeviceIdMessage(switchName, extension), '0002')
    logging.debug(broker.readResponse('0002', 5))
    broker.sendRequest(DmccBroker.getMonitorStartMessage(switchConnName, switchName, extension), '0003')
    logging.debug(broker.readResponse('0003', 5))
    broker.sendRequest(DmccBroker.getSnapshotDeviceMessage(switchConnName,switchName, extension), '0004')
    logging.debug(broker.readResponse('0004', 5))
    broker.sendRequest(DmccBroker.getMonitorStopMessage(), '0005')
    logging.debug(broker.readResponse('0005', 5))

    '''
    for key, value in responses.items():
        print(key)
        print(value)
        print("************************************************")
    '''

    sleep(1)
    broker.setAlldone()
    sleep(5)
    broker.getConn().close()
    logging.debug('Graceful shutdown completed. Ending program ...')


if __name__ == '__main__':
    responses = {}
    main()
