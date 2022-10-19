#Ramirez Gallo Deniss Alberto
#Sniffer v1.0
from io import open
import time
import os
from art import *
import pyttsx3


def AsistenteVoz():
    engine = pyttsx3.init()
    engine.setProperty("rate",150)
    texto = "Bienvenido a MaunteinWaired, por favor elija una opcion"
    engine.say(texto)
    engine.runAndWait()
def despedida():
    engine = pyttsx3.init()
    engine.setProperty("rate", 150)
    texto = "Hasta pronto!"
    engine.say(texto)
    engine.runAndWait()
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

