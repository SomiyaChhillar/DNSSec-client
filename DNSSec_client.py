# DNS-project for 
# The following are the required system libraries.
import sys #
import struct
import socket
import random
import time
import binascii
import codecs
import base64
import hashlib
import signal
import sys

########### details for creating socket #########################################
quad = '8.8.8.8'
port = 53



#############  Main function ####################################################

    ############################## DNS_query -  generate a random 16-bit binary number ###########################

def main(host_name,count):
    binary_number = bin(random.randint(0, 2**16-1))[2:].zfill(16)



    ################### convert binary number to hexadecimal ##################################
    hex_num = hex(int(binary_number, 2))[2:].zfill(4)

    updated_hex_num = f"{chr(92)}x{hex_num[:2]}{chr(92)}x{hex_num[2:]}"


    #time.sleep(2)
    print(" DNS query being created......")

    #time.sleep(2)

########### creating query ###################

    query = updated_hex_num + "\\x01\\x20" + "\\x00\\x01" + "\\x00\\x00" + "\\x00\\x00" + "\\x00\\x01"
    query = bytes(query.encode().decode('unicode_escape').encode("raw_unicode_escape"))



    d = bytes("" , 'utf-8')
    for a in host_name.split('.'):
        d = d + struct.pack("!b" + str(len(a)) + "s" , len(a) , bytes(a,"utf-8"))

    query = query + d + bytes("\x00", 'utf-8') #################### DNS_query  terminate domain with zero len

    query = query + bytes("\x00\x30" + "\x00\x01", 'utf-8') ########## DNS_query   type A, class IN #############

    query = query + bytes("\x00"+"\x00\x29" + "\x10\x00"+ "\x00"+ "\x00"+ "\x80\x00"+ "\x00\x00" , 'utf-8')

    #print('query was created :  ', query)


###############################  Socket Creation and sending query #############################################
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(15)
    print("Socket Connection Created Successfully")

    print("Sending DNS Query..........")
    #time.sleep(2)

    
    sock.sendto (query, (quad, port))
    reply,addr = sock. recvfrom (4096)
  
    #time.sleep(3)
    print("/////////DNS Response Received/////////")
    print("//////Attempt" , str(count) , "of 3///////////////////")
    print("////////////////////////////Reading DNS Response//////////////////////")
    
    
##############################################   DNS response processing ###############################################

    print("the following is the response from dns 8.8.8.8 ->> ")



    header_items = struct.unpack("!HHHHHH",reply[:12])
    ANCount = int(header_items[3])
    if(ANCount == 0):
        print("No DNSKEY found\n")
        return -2
    print("header.ID = "+str(hex(header_items[0])))
    flags = bin(int(hex(header_items[1]),16))

    print("header.QR = " + flags[2])
    print("header.OPCODE = " + flags[3:7])
    auth = flags[12]
    auth = int(auth,16)
    print("header.QDCount = "+str(header_items[2]))
    print("header.ANCount = "+str(header_items[3]))
    print("header.NSCount = "+str(header_items[4]))
    print("header.ARCount = "+str(header_items[5]))
    ARCount = int(header_items[5])

    print()

    response_items = reply[12:]
   
    response_items2 = binascii.hexlify(response_items).decode('utf-8')
   
    query_question = response_items2[:response_items2.find("00")]
    
    print("QUERY SECTION")
    length = int(query_question[0:2])
    prev = 2
    print("\tQuestion.QName = ", end="")
    for i in range (prev, len(query_question)):
        print((bytes.fromhex(query_question[prev:prev+length*2])).decode('utf-8'), end="")
        prev = prev+length*2
        if(prev >= len(query_question)):
            break
        print(".", end="")
        length = int(query_question[prev:prev+2])
        prev = prev+2
        i = prev
      
    print()  
    next = response_items2.find("00")+2
    query_question_type = int(response_items2[next:next+4])
    query_question_class = int(response_items2[next+4:next+8])
    print("\tQuestion.QType = "+ str(query_question_type))
    print("\tQuestion.QClass = "+ str(query_question_class))

    print()
   
    next = next+8
    
    
    response_answer = response_items2[response_items2.find("00010001")+8:]
    response_answer2 = response_items2[next+4:]
    

    print("ANSWER SECTION")
    current_pos = 0
    current_pos2 = 0
    m = hashlib.sha256()
    

    for i in range (ANCount):
        
        response_answer_type = int(response_answer2[current_pos:current_pos+4],16)
        response_answer_class = int(response_answer2[current_pos+4:current_pos+8],16)
        response_answer_ttl = int(response_answer2[current_pos+8:current_pos+16],16)
        response_answer_length = int(response_answer2[current_pos+16:current_pos+20],16)
        answer_length = response_answer_length*2
        response_answer_IP = response_answer2[current_pos+20:current_pos+20+answer_length]

        print("\tAnswer.Type = " + str(response_answer_type), end="")
        if(response_answer_type == 48):
            print(" (DNSKEY)")
        else:
            print(" (RRSIG)")
        print("\tAnswer.Class = " + str(response_answer_class))
        print("\tAnswer.TTL = " + str(response_answer_ttl))
        print("\tAnswer.Length = " + str(response_answer_length))

        if(response_answer_type == 5):
            print("\tCName = ", end="")
            k=0
            for i in range (2,len(response_answer_IP),2):
                try:
                    print(bytes.fromhex(response_answer_IP[k:i]).decode('utf-8'), end="")
                except:
                    continue
                k=i
            #print(bytes.fromhex(response_answer_IP).decode())
            #print(str(response_answer_IP))
            print()

        if(response_answer_type == 1):
            print("\tIP = ", end="")
            print(int(response_answer_IP[:2],16),end="")
            print(".",end="")
            print(int(response_answer_IP[2:4],16),end="")
            print(".",end="")
            print(int(response_answer_IP[4:6],16),end="")
            print(".",end="")
            print(int(response_answer_IP[6:8],16),end="")
            print()

        if(response_answer_type == 48):
            PKflags = response_answer_IP[:4]
            PKprotocol = response_answer_IP[4:6]
            PKalgo = response_answer_IP[6:8]
            PK = response_answer_IP[8:]
            if(int(PK[:2],16) == 0):
                exponent_length = int(PK[2:6],16)
                next_pointer = 6
            else:
                exponent_length = int(PK[:2],16)
                #print(exponent_length)
                next_pointer = 2

            exponent = int(PK[next_pointer:next_pointer+exponent_length*2],16)
            next_pointer = next_pointer+exponent_length*2
            #print(exponent)
            modulus = int(PK[next_pointer:],16)
            #print(modulus)

            hash = m.update(bytes.fromhex(PK))
            #print(m.digest)
            #dns.dnssec.key_id(PK)
                
            PK = codecs.encode(codecs.decode(PK, 'hex'), 'base64').decode().replace("\n", "")
            print("\tPublic Key flags = "+ str(PKflags))
            print("\tPublic Key protocol = "+ str(PKprotocol))
            print("\tPublic Key algorithm = "+ str(PKalgo))
            print("\tPublic Key = "+ str(PK))

            

        if(response_answer_type == 46):
            TypeCovered = response_answer_IP[:4]
            Algo = response_answer_IP[4:6]
            Label = response_answer_IP[6:8]
            OriginalTTL = response_answer_IP[8:16]
            SigExp = response_answer_IP[16:24]
            SigInc = response_answer_IP[24:32]
            KeyTag = response_answer_IP[32:36]
            new = response_answer_IP[36:]
            SignerName = response_answer_IP[36:response_answer_IP[36:].find("00")+36]
            RRSig = response_answer_IP[response_answer_IP[36:].find("00")+38:]

            #print(int(RRSig,16))

            RRSig = codecs.encode(codecs.decode(RRSig, 'hex'), 'base64').decode().replace("\n", "")
            print("\tType Covered = "+ str(int(TypeCovered,16)))
            print("\tRRSig Algorithm = "+ str(Algo))
            print("\tLabels = "+ str(int(Label,16)))
            print("\tOriginal TTL = "+ str(int(OriginalTTL,16)))
            print("\tSignature Expiration = "+ str(SigExp))
            print("\tSignature Inception = "+ str(SigInc))
            print("\tKey Tag = "+ str(KeyTag))
            #print("Signer Name = "+ str(SignerName))
            length = int(SignerName[0:2])
            prev = 2
            print("\tSigner Name = ", end="")
            for i in range (prev, len(SignerName)):
                print((bytes.fromhex(SignerName[prev:prev+length*2])).decode('utf-8'), end="")
                prev = prev+length*2
                if(prev >= len(SignerName)):
                    break
                print(".", end="")
                length = int(SignerName[prev:prev+2])
                prev = prev+2
                i = prev
            print() 
            print("\tRRSig = "+ str(RRSig))


        current_pos = (current_pos+20+(answer_length)+4)
        print()

    for j in range (ARCount):
        if(int(response_answer2[current_pos-4:current_pos-2],16)==0 and int(response_answer2[current_pos-2:current_pos+2],16)==41):
            print("OPT PSEUDOSECTION")
            print("\tName : Root")
            print("\tType : OPT")
            print("\tUDP Payload : "+str(int(response_answer2[current_pos+2:current_pos+6],16)))
            print("\tEDNS Version : "+str(int(response_answer2[current_pos+8:current_pos+10],16)))
            print("\tflags : "+str(response_answer2[current_pos+10:current_pos+14]))

    if(auth == 1):
        print("\nVALIDATED\n")
    else:
        print("\nNOT VALIDATED\n")

    return 1






##########################################################################################################################
################################### calling the Main function ############################################################


n = len(sys.argv)
if(n != 4):
    print("Insufficient arguments!\n")
    exit(0)

trust_store = sys.argv[1]
host_name = sys.argv[2]
try:
    RR_type = int(sys.argv[3])
except:
    print("Wrong RR Type")
    exit(0)

if(RR_type != 48):
    print(RR_type)
    print("Wrong RR Type\n")
    exit(0)
try:
    f = open(trust_store, "r")
except:
    print("File doesn't exist\n")
    exit(0)


count = 1
for _ in range(3):
    try:
        resp = main(host_name, count)
    except:
        print("//////////////////////////////////Request Timed Out ////////////////////////\n")
        if(_ <3):
            count +=1
            continue
        else:
            break
    if(resp == 0):
        print("////////////////////////////////////// Error //////////////////////////////////\n")
        print("\nTRYING AGAIN..\n")
        
    elif resp>=1:
        print("//////////////////////////////////////DNS Request Successful //////////////////\n")
        break

    if(resp == -2):
        break


    #######################################################################################
