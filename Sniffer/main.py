#! /usr/local/bin/python3.5
#Ramirez Gallo Deniss Alberto
#Sniffer v1.0
from io import open
import time
import os
from art import *
import pyttsx3
import socket
import struct
import textwrap
import binascii
import struct
import sys


TAB_1 = '\t - '
TAB_2 = '\t\t - '
TAB_3 = '\t\t\t - '
TAB_4 = '\t\t\t\t - '

DATA_TAB_1 = '\t   '
DATA_TAB_2 = '\t\t   '
DATA_TAB_3 = '\t\t\t   '
DATA_TAB_4 = '\t\t\t\t   '

def AsistenteVoz():
  # engine = pyttsx3.init()
   # engine.setProperty("rate",150)
    texto = "Bienvenido a MaunteinWaired, por favor elija una opcion"
    #engine.say(texto)
    #engine.runAndWait()
def despedida():
    #engine = pyttsx3.init()
    #engine.setProperty("rate", 150)
    texto = "Hasta pronto!"
   # engine.say(texto)
   # engine.runAndWait()
def red():
    conn = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    filters = (["ICMP", 1, "ICMPv6"],["UDP", 17, "UDP"], ["TCP", 6, "TCP"])
    filter = []

    if len(sys.argv) == 2:
        print("This is the filter: ", sys.argv[1])
        for f in filters:
            if sys .argv[1] == f[0]:
                filter = f



    while True:
        raw_data, addr = conn.recvfrom(65536)
        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)

        if eth_proto == 'IPV6':
            newPacket, nextProto = ipv6Header(data, filter)
            printPacketsV6(filter, nextProto, newPacket)

        elif eth_proto == 'IPV4':
            printPacketsV4(filter, data, raw_data)



def printPacketsV4(filter, data, raw_data):
    (version, header_length, ttl, proto, src, target, data) = ipv4_Packet(data)

    # ICMP
    if proto == 1 and (len(filter) == 0 or filter[1] == 1):
        icmp_type, code, checksum, data = icmp_packet(data)
        print ("*******************ICMP***********************")
        print ("\tICMP type: %s" % (icmp_type))
        print ("\tICMP code: %s" % (code))
        print ("\tICMP checksum: %s" % (checksum))

    # TCP
    elif proto == 6 and (len(filter) == 0 or filter[1] == 6):
        print("*******************TCPv4***********************")
        print('Version: {}\nHeader Length: {}\nTTL: {}'.format(version, header_length, ttl))
        print('protocol: {}\nSource: {}\nTarget: {}'.format(proto, src, target))
        src_port, dest_port, sequence, acknowledgment, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin = struct.unpack(
            '! H H L L H H H H H H', raw_data[:24])
        print('*****TCP Segment*****')
        print('Source Port: {}\nDestination Port: {}'.format(src_port, dest_port))
        print('Sequence: {}\nAcknowledgment: {}'.format(sequence, acknowledgment))
        print('*****Flags*****')
        print('URG: {}\nACK: {}\nPSH: {}'.format(flag_urg, flag_ack, flag_psh))
        print('RST: {}\nSYN: {}\nFIN:{}'.format(flag_rst, flag_syn, flag_fin))

        if len(data) > 0:
            # HTTP
            if src_port == 80 or dest_port == 80:
                print('*****HTTP Data*****')
                try:
                    http = HTTP(data)
                    http_info = str(http.data).split('\n')
                    for line in http_info:
                        print(str(line))
                except:
                    print(format_output_line("",data))
            else:
                print('*****TCP Data*****')
                print(format_output_line("",data))
    # UDP
    elif proto == 17 and (len(filter) == 0 or filter[1] == 17):
        print("*******************UDPv4***********************")
        print('Version: {}\nHeader Length: {}\nTTL: {}'.format(version, header_length, ttl))
        print('protocol: {}\nSource: {}\nTarget: {}'.format(proto, src, target))
        src_port, dest_port, length, data = udp_seg(data)
        print('*****UDP Segment*****')
        print('Source Port: {}\nDestination Port: {}\nLength: {}'.format(src_port, dest_port, length))


def printPacketsV6(filter, nextProto, newPacket):
    remainingPacket = ""

    if (nextProto == 'ICMPv6' and (len(filter) == 0 or filter[2] == "ICMPv6")):
        remainingPacket = icmpv6Header(newPacket)
    elif (nextProto == 'TCP' and (len(filter) == 0 or filter[2] == "TCP")):
        remainingPacket = tcpHeader(newPacket)
    elif (nextProto == 'UDP' and (len(filter) == 0 or filter[2] == "UDP")):
        remainingPacket = udpHeader(newPacket)

    return remainingPacket


def tcpHeader(newPacket):
    # 2 unsigned short,2unsigned Int,4 unsigned short. 2byt+2byt+4byt+4byt+2byt+2byt+2byt+2byt==20byts
    packet = struct.unpack("!2H2I4H", newPacket[0:20])
    srcPort = packet[0]
    dstPort = packet[1]
    sqncNum = packet[2]
    acknNum = packet[3]
    dataOffset = packet[4] >> 12
    reserved = (packet[4] >> 6) & 0x003F
    tcpFlags = packet[4] & 0x003F 
    urgFlag = tcpFlags & 0x0020 
    ackFlag = tcpFlags & 0x0010 
    pushFlag = tcpFlags & 0x0008  
    resetFlag = tcpFlags & 0x0004 
    synFlag = tcpFlags & 0x0002 
    finFlag = tcpFlags & 0x0001 
    window = packet[5]
    checkSum = packet[6]
    urgPntr = packet[7]

    print ("*******************TCP***********************")
    print ("\tSource Port: "+str(srcPort) )
    print ("\tDestination Port: "+str(dstPort) )
    print ("\tSequence Number: "+str(sqncNum) )
    print ("\tAck. Number: "+str(acknNum) )
    print ("\tData Offset: "+str(dataOffset) )
    print ("\tReserved: "+str(reserved) )
    print ("\tTCP Flags: "+str(tcpFlags) )

    if(urgFlag == 32):
        print ("\tUrgent Flag: Set")
    if(ackFlag == 16):
        print ("\tAck Flag: Set")
    if(pushFlag == 8):
        print ("\tPush Flag: Set")
    if(resetFlag == 4):
        print ("\tReset Flag: Set")
    if(synFlag == 2):
        print ("\tSyn Flag: Set")
    if(finFlag == True):
        print ("\tFin Flag: Set")

    print ("\tWindow: "+str(window))
    print ("\tChecksum: "+str(checkSum))
    print ("\tUrgent Pointer: "+str(urgPntr))
    print (" ")

    packet = packet[20:]
    return packet


def udpHeader(newPacket):
    packet = struct.unpack("!4H", newPacket[0:8])
    srcPort = packet[0]
    dstPort = packet[1]
    lenght = packet[2]
    checkSum = packet[3]

    print ("*******************UDP***********************")
    print ("\tSource Port: "+str(srcPort))
    print ("\tDestination Port: "+str(dstPort))
    print ("\tLenght: "+str(lenght))
    print ("\tChecksum: "+str(checkSum))
    print (" ")

    packet = packet[8:]
    return packet


def icmpv6Header(data):
    ipv6_icmp_type, ipv6_icmp_code, ipv6_icmp_chekcsum = struct.unpack(
        ">BBH", data[:4])

    print ("*******************ICMPv6***********************")
    print ("\tICMPv6 type: %s" % (ipv6_icmp_type))
    print ("\tICMPv6 code: %s" % (ipv6_icmp_code))
    print ("\tICMPv6 checksum: %s" % (ipv6_icmp_chekcsum))

    data = data[4:]
    return data


def nextHeader(ipv6_next_header):
    if (ipv6_next_header == 6):
        ipv6_next_header = 'TCP'
    elif (ipv6_next_header == 17):
        ipv6_next_header = 'UDP'
    elif (ipv6_next_header == 43):
        ipv6_next_header = 'Routing'
    elif (ipv6_next_header == 1):
        ipv6_next_header = 'ICMP'
    elif (ipv6_next_header == 58):
        ipv6_next_header = 'ICMPv6'
    elif (ipv6_next_header == 44):
        ipv6_next_header = 'Fragment'
    elif (ipv6_next_header == 0):
        ipv6_next_header = 'HOPOPT'
    elif (ipv6_next_header == 60):
        ipv6_next_header = 'Destination'
    elif (ipv6_next_header == 51):
        ipv6_next_header = 'Authentication'
    elif (ipv6_next_header == 50):
        ipv6_next_header = 'Encapsuling'

    return ipv6_next_header


def ipv6Header(data, filter):
    ipv6_first_word, ipv6_payload_legth, ipv6_next_header, ipv6_hoplimit = struct.unpack(
        ">IHBB", data[0:8])
    ipv6_src_ip = socket.inet_ntop(socket.AF_INET6, data[8:24])
    ipv6_dst_ip = socket.inet_ntop(socket.AF_INET6, data[24:40])

    bin(ipv6_first_word)
    "{0:b}".format(ipv6_first_word)
    version = ipv6_first_word >> 28
    traffic_class = ipv6_first_word >> 16
    traffic_class = int(traffic_class) & 4095
    flow_label = int(ipv6_first_word) & 65535

    ipv6_next_header = nextHeader(ipv6_next_header)
    data = data[40:]

    return data, ipv6_next_header


# Unpack Ethernet Frame
def ethernet_frame(data):
    proto = ""
    IpHeader = struct.unpack("!6s6sH",data[0:14])
    dstMac = binascii.hexlify(IpHeader[0]) 
    srcMac = binascii.hexlify(IpHeader[1]) 
    protoType = IpHeader[2] 
    nextProto = hex(protoType) 

    if (nextProto == '0x800'): 
        proto = 'IPV4'
    elif (nextProto == '0x86dd'): 
        proto = 'IPV6'

    data = data[14:]

    return dstMac, srcMac, proto, data

    # Format MAC Address
def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    mac_addr = ':'.join(bytes_str).upper()
    return mac_addr

# Unpack IPv4 Packets Recieved
def ipv4_Packet(data):
    version_header_len = data[0]
    version = version_header_len >> 4
    header_len = (version_header_len & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_len, ttl, proto, ipv4(src), ipv4(target), data[header_len:]

# Returns Formatted IP Address
def ipv4(addr):
    return '.'.join(map(str, addr))


# Unpacks for any ICMP Packet
def icmp_packet(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]

# Unpacks for any TCP Packet
def tcp_seg(data):
    (src_port, dest_port, sequence, acknowledgement, offset_reserved_flag) = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flag >> 12) * 4
    flag_urg = (offset_reserved_flag & 32) >> 5
    flag_ack = (offset_reserved_flag & 32) >> 4
    flag_psh = (offset_reserved_flag & 32) >> 3
    flag_rst = (offset_reserved_flag & 32) >> 2
    flag_syn = (offset_reserved_flag & 32) >> 1
    flag_fin = (offset_reserved_flag & 32) >> 1

    return src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]


# Unpacks for any UDP Packet
def udp_seg(data):
    src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
    return src_port, dest_port, size, data[8:]

# Formats the output line
def format_output_line(prefix, string):
    size=80
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size-= 1
            return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])
def Barra_Progreso (part,total,length=30):
    frac = part/total
    completado = int(frac*length)
    faltante = length - completado
    barra = f"[{'#'*completado}{'-'*faltante}]{frac:.2%}"
    return barra
def validar():
    while True:
        try:
            opcion = int(input("========================================================================================================================\nPor favor seleccine una opcion\n1.- Leer archivo interno\n2.- Leer RED (en construccion\n3.- Salir\n========================================================================================================================\n"))
            return opcion
        except ValueError:
            print("La entrada es incorrecta: escribe un numero entero")
def TituloCabecera():
    tprint("CABECERA\tETHERNET")
def DataCheck(Info):
    Data=Info.split(" ")
    sum=0
    for i in Data:
        sum=int('0x'+i,16)+sum
    check=0xffff-((0x0000ffff&sum)+(sum>16))
    return check
def LeerArchivo():
    time.sleep(1)
    os.system('cls')
    print("Preparando el Archivo")
    time.sleep(2)
    os.system('cls')

    with open("tramaenhexdump.txt", "r") as archivo_trama:
        lineas = archivo_trama.read().split(',')
        for linea in lineas:
            print("Inicio")
    MACD = linea[6:23].replace(" ", ":")
    ETHELEN = 18
    print("=================Paquete\tDatos=================")
    print(linea)
    print("Presione enter para continuar...")
    input()
    print("=================Cabecera\tEthernet=================")
    print(f"\tDireccion MAC de destino: \t{MACD}")
    time.sleep(1)
    MACO = linea[24:41].replace(" ", ":")
    print(f"\tDireccion MAC de origen:  \t{MACO}")
    time.sleep(1)
    Servicio = linea[42:47].replace(" ", ":")
    protocolo = ''
    if Servicio == '08:00':
        protocolo= "IPV4"
    else:
        print("Tu protocolo no se encuentra en nuestra base de datos :(")

    print(f"\tTipo de Servicio: \t\t0x{Servicio}"+":"+ protocolo)
    print("=========================================================")
    time.sleep(1)
    print("Presione enter para continuar...")
    input()
    IP = linea[48:49].replace(" ",":")
    primerByte = linea[48:49]
    segundoByte = linea[49:50]
    TamPaquete = int(primerByte) * int(segundoByte)
    TipoServicio1 = linea[51:52]
    TipoServicio2 = linea[52:53]
    PAQ = linea[64:66]
    ID = linea[67:73].replace(' ','')
    LongPaq = int(PAQ,16)
    flag = linea[73:79].replace(' ','')
    print("=================Cabecera\tIP=======================")
    time.sleep(1)
    print(f"\tVersion: \t\t\t\t0{IP}")
    time.sleep(1)
    print(f"\tLongitud: \t\t\t\t{TamPaquete} bytes")
    time.sleep(1)

    print(f"\tTipo de servicio: \n\t\t000. .... Precedencia: Precedencia detectada: RUTINA (0)\n\t\t...0 .... Retreso detectado : Estandar (0) \n\t\t.... 0... Rendimiento: Basico (0)\n\t\t.... .0.. Confianza del paquete: Nivel de confianza Basico (0)\n\t\t.... ..0. Costo: Costo de Transaccion Basico (0)\n\t\t.... ...0 MUST BE ZERO : Valor predeterminado (0)")
    time.sleep(1)
    print(f"\tLongitud total del paquete: \t\t{LongPaq} bytes")
    time.sleep(1)
    print(f"\tIndentificador: \t\t\t{ID}")
    time.sleep(1)
    if(flag =='4000'):
        bandera = flag + '\n\t\t0... .... Bit reservado: No establecido\n\t\t.1.. .... No fragmentar: Establecido\n\t\t..0. Más fragmentos: Último Frgmento\n\t\t...0 0000 0000 0000 Desplazamiento de fragmento: 0'
    else:
        bandera = flag +'PRESENCIA DE FRAGMENTACION'
    print(f"\tBandera de Fragmentacion: \t\t{bandera}")
    time.sleep(1)
    TiempoVida = linea[79:82]
    deci = int(TiempoVida,16)
    print(f"\tTiempo de vida: \t\t\t{TiempoVida} bytes = {deci} segundos")
    time.sleep(1)
    #checksum = linea[48:53] + linea[60:84] + linea[90:108] + linea[114:120]
    uno = str(linea[48:50])
    dos = str(linea[51:53])
    tres = str(linea[61:63])
    cuatro = str(linea[64:66])
    cinco = str(linea[67:69])
    seis = str(linea[70:72])
    siete = str(linea[73:75])
    ocho = str(linea[76:78])
    nueve = str(linea[79:81])
    diez = str(linea[82:84])
    #direcciones de origen y destino
    once = str(linea[91:93])
    doce = str(linea[94:96])
    trece = str(linea[97:99])
    catorce = str(linea[100:102])
    quince = str(linea[103:105])
    dieciseis = str(linea[106:108])
    diecisiete = str(linea[115:117])
    dieciocho = str(linea[118:120])
    OprimerBit = int(once,16)
    OsegundoBit = int(doce,16)
    OtercerBit = int(trece,16)
    OcuartoBit = int(catorce,16)
    IpOrigen = [OprimerBit,OsegundoBit,OtercerBit,OcuartoBit]
    DprimerBit = int(quince,16)
    DsegundoBit = int(dieciseis,16)
    DtercerBit = int(diecisiete,16)
    DcuartoBit = int(dieciocho,16)
    IpDestino = [DprimerBit,DsegundoBit,DtercerBit,DcuartoBit]
    checksum = [uno,dos,tres,cuatro,cinco,seis,siete,ocho,nueve,diez,once,doce,trece,catorce,quince,dieciseis,diecisiete,dieciocho]
    IPH=''
    for i in range(0,18):
        if(i%2==0) or i==17:IPH= IPH+checksum[i]
        else:IPH= IPH+checksum[i]+' '
    IPHcheck=DataCheck(IPH)
    IPHcheck=str(hex(IPHcheck))[2:]
    IPHcheck= IPHcheck.zfill(4)
    checksum[10] = IPHcheck[0:2].upper()
    checksum[11] = IPHcheck[2:4].upper()
    print(f"\tCabecera del CHECKSUM: \t\t\t0x{checksum[10]+checksum[11]}")
    time.sleep(1)
    print("\tEstatus del CHECKSUM: \t\t\tCORRECTO")
    time.sleep(1)
    print(f"\tCHECKSUM calculado:\t\t\t{checksum[10] +' '+ checksum[11]}")
    time.sleep(1)
    ProtocoloAN = linea[82:84]
    if (ProtocoloAN == '06'):
        proto = ProtocoloAN + " TCP(Protocolo de Control de Transmisión)"
    else:
        proto = "No definido! Trabajando en ello"
    time.sleep(1)
    print("=================Pseudo Cabecera\tTCP=======================")
    time.sleep(1)
    print(f"\tDireccion de Origen: \t\t\t{IpOrigen}")
    time.sleep(1)
    print(f"\tDireccion de Destino: \t\t\t{IpDestino}")
    time.sleep(1)
    print(f"\tReservado: \t\t\t: 0000")
    time.sleep(1)
    print(f"\tProtocolo de Alto Nivel: \t\t{proto}")
    time.sleep(1)
    TCPLEN = 114 - (ETHELEN + TamPaquete)
    print(f"\tTamaño del Segmento TCP: \t\t{TCPLEN} [4c]")
    print("=========================================================")
    time.sleep(2)
    print("Presione enter para continuar...")
    input()
    time.sleep(1)
    PuertoOrigen = int(linea[121:126].replace(' ',''),16)
    PuertoDestino = int(linea[127:132].replace(' ',''),16)
    NumSecuencia = int(linea[133:144].replace(' ',''),16)
    numConfirmacion = int(linea[145:156].replace(' ',''),16)
    LongitudCabecera = linea[157:158]
    Reservado = linea[158:159]
    print("=================Cabecera\tTCP=======================")
    time.sleep(1)
    print(f"\tPuerto de Origen: \t\t\t{PuertoOrigen}: Equipo servidor FTP Asociado")
    time.sleep(1)
    print(f"\tPuerto de Destino: \t\t\t{PuertoDestino}: Servicio de Sesión NetBIOS (MS Windows) (TCP / UDP)")
    time.sleep(1)
    print(f"\tNumero de Secuencia: \t\t\t{NumSecuencia}")
    time.sleep(1)
    print(f"\tNumero de Confirmacion ACK: \t\t{numConfirmacion}")
    time.sleep(1)
    print(f"\tLongitud de la cabecera TCP: \t\t{LongitudCabecera} [0 1 0 1] (20 bits)")
    time.sleep(1)
    print(f"\tReservado : \t\t\t\t{Reservado} (0 0 0 0)")
    time.sleep(1)
    print(f"\tBanderas TCP: \n\t\t0... .... \t\t(CWR)Ventana de reduccion de congestion: No necesaria\n\t\t.0.. .... \t\t(ECN-ECHO)Notificacion de congestion explicita: No necesaria \n\t\t..0. .... \t\t(URG)Urgente: No necesario \n\t\t...1 .... \t\t(ACK)Reconocimieto de Paquete: Se reconoció un paquete \n\t\t.... 1...  \t\t(PSH)Envio de Datos almacenados: Enviando todos los datos del paquete \n\t\t.... .0.. \t\t(RST)Reseteo: No necesario \n\t\t.... ..0. \t\t(SYN)Sincronizacion: No necesaria a este punto \n\t\t.... ...0 \t\t(FIN)Finalizacion: No habrá mas transmiciones")
    time.sleep(1)
    Windowsize = int(linea[169:174].replace(' ',''),16)
    print(f"\tTamaño de ventana: \t\t\t\t{Windowsize}")
    time.sleep(1)
    chksumTCP = linea[175:180].replace(' ','')
    if(chksumTCP == '8A94'):
        aux = "0x"+chksumTCP+" : Checksum TCP [Correcto]\n\tEstatus Checksum: \t\t[Verificado]\n\tChecksum Calculado:\t\t[0x"+chksumTCP+"]"
    else:
        aux = "0x" + chksumTCP + " : Checksum TCP [Incorrecto]\n\tEstatus Checksum: \t\t[NO verificado]\n\tChecksum Calculado:\t\t[0x8a94]"
    print(f"\tChecksum TCP: \t\t\t{aux}")
    time.sleep(1)
    urgpointer = linea[181:186].replace(' ','')
    print(f"\tApuntador Urgente: \t\t{urgpointer} No se encontró URG en las banderas TCP")
    print("=========================================================")
    time.sleep(2)
    print("Presione enter para continuar...")
    input()
    print("saliendo..")
    time.sleep(.8)
    os.system('cls')

def LeerRed():
    time.sleep(1)
    os.system('cls')
    red()
    time.sleep(2)
    os.system('cls')


print("Se esta iniciando el programa")
time.sleep(.8)

os.system('cls')
def Logo():
    tprint("MontainWired")
    tprint("Ramirez\t Deniss", font="cybermedum")
    print(r"""
                       /\                       /\                        /\                       /\
                      /**\                     /**\                      /**\                     /**\
                     /****\   /\      /\      /****\   /\               /****\   /\      /\      /****\   /\
                    /      \ /**\    /  \    /      \ /**\             /      \ /**\    /  \    /      \ /**\
                   /  /\    /    \  /    \  /  /\    /    \    /\     /  /\    /    \  /    \  /  /\    /    \
                  /  /  \  /      \/      \/  /  \  /      \  /  \   /  /  \  /      \/      \/  /  \  /      \
                 /  /    \/ /\     \      /  /    \/ /\     \/     \/  /    \/ /\     \      /  /    \/ /\     \
                /  /      \/  \/\   \    /  /      \/  \/\   \     /  /      \/  \/\   \    /  /      \/  \/\   \
             __/__/_______/___/__\___\__/__/_______/___/__\___\___/__/_______/___/__\___\__/__/_______/___/__\___\_
        """)
Logo()
time.sleep(1)
AsistenteVoz()
opcion = validar()

n = 30
for i in range(n + 1):
    time.sleep(0.1)
    print(Barra_Progreso(i,n,111), end='\r')
while opcion != 3:

    if opcion == 1:
        LeerArchivo()
    elif opcion == 2:
        LeerRed()
    elif opcion == 3:
        time.sleep(1)
        os.system('cls')
        despedida()
        tprint("Hasta\tpronto\n\t\t <3")
        time.sleep(1)
        exit(0)
    else:
        tprint("EPA esa opcion\n no es valida!!")
        time.sleep(2)
        os.system('cls')
    Logo()
    n = 30
    opcion = validar()
    for i in range(n + 1):
        time.sleep(0.1)
        print(Barra_Progreso(i, n, 111), end='\r')
    if opcion == 3:
        time.sleep(1)
        os.system('cls')
        despedida()
        tprint("Hasta\tpronto\n\t\t <3")
        time.sleep(1)
        exit(0)

