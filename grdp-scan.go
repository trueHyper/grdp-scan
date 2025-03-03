package main

import (
	"crypto/tls"
	"fmt"
	"net"
	"log"
	"encoding/hex"
	"strings"
	"encoding/binary"
	"time"

)

type NTLMChallenge struct {
	TargetName           string
	NetBIOSDomainName    string
	NetBIOSComputerName  string
	DNSDomainName        string
	DNSComputerName      string
	DNSTreeName          string
	ProductVersion       string
	SystemTime           string
}

const (
	signature = "NTLMSSP\x00"
	ntEpochOffset = 11644473600
)

// wireshark
//char peer0_0[] = 
//{ /* Packet 4 */
//	0x03, 0x00, 0x00, 0x13,  TPKT Header (версия 3, длина 19 байт)
//	0x0e, 					 
//	0xe0, 
//	0x00, 0x00, 
//	0x00, 0x00, 
//	0x00, 
//	0x01, 0x00, 0x08,  		 RDP Negotiation Request (Type: 1, Flags: 0, len: 8)
//	0x00, 0x0b, 0x00,  		 Requested Protocols (PROTOCOL_RDP | PROTOCOL_SSL | PROTOCOL_HYBRID) а где четвертый?
//	0x00, 0x00 		         Padding ??
//};

func main() {
	server := "157.90.41.185:3389" // Замените на IP-адрес вашего RDP-сервера
	conn, err := net.Dial("tcp", server)
	if err != nil {
		log.Fatalf("Ошибка подключения: %v", err)
	}
	defer conn.Close()

	// X.224 Connection Request PDU (TPKT + X.224)
	syncPacket := []byte {
	
		0x03, 0x00, 0x00, 0x13,  // TPKT Header (версия 3, длина 19 байт) //19 c
		0x0e, 					 // X.224 Length Indicator //14 без
		0xe0,                    // X.224 CR(0xe) CDT(0x0) -> 0xe
		0x00, 0x00,              // X.224 DST-REF
		0x00, 0x00,              // X.224 SRC-REF 
		0x00,                    // X.224 CLASS OPTION
		0x01, 0x00, 0x0008,  	 // X.224 RDP Negotiation Request (Type: 0x01, Flags: 0x00, Length: 0x08)
		0x00, 0x0b, 0x00, 0x00,  // Requested Protocols (PROTOCOL_RDP | PROTOCOL_SSL | PROTOCOL_HYBRID) 
		0x00,					 // Padding
	}

	_, err = conn.Write(syncPacket)
	if err != nil {
		log.Fatalf("Ошибка отправки данных: %v", err)
	}

	// read response
	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil {
		log.Fatalf("Ошибка чтения ответа: %v", err)
	}

	fmt.Printf("\nServer response\n%s", hex.Dump(buffer[:n]))
	
	// switch to tls cipher
	tlsConn := tls.Client(conn, &tls.Config{InsecureSkipVerify: true})
	defer tlsConn.Close()
	
	ntlmNegotiate := []byte {
		0x30, 0x37, 0xA0, 0x03, 0x02, 0x01, 0x60, 0xA1, 0x30, 0x30, 0x2E, 0x30, 0x2C, 0xA0, 0x2A, 0x04, 0x28, // ASN header
		0x4E, 0x54, 0x4C, 0x4D, 0x53, 0x53, 0x50, 0x00, // "NTLMSSP" Signature
		0x01, 0x00, 0x00, 0x00, // NTLM Message Type 1
		0xB7, 0x82, 0x08, 0xE2, // Flags
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Domain Name Fields
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Workstation Fields
		0x0A, 0x00, // Product Major Version (Windows 10 = 10)
		0x63, 0x45, // Product Build (17763)
		0x00, 0x00, 0x00, // Reserved
		0x0F, // NTLM Revision
	}
	
	_, err = tlsConn.Write(ntlmNegotiate)
	if err != nil {
		fmt.Println("Ошибка отправки NTLM Negotiate:", err)
		return
	}	
	
	n, err = tlsConn.Read(buffer)
	if err != nil {
		fmt.Println("Ошибка чтения NTLM Challenge:", err)
		return
	}
	
	//fmt.Println("NTLM Challenge:", buffer[:n])
	
	parseNTLMChallenge(buffer[:n])
}


func parseNTLMChallenge(challenge []byte) {
	if len(challenge) < 48 {
		fmt.Println("Ошибка: NTLM Challenge слишком короткий")
		return
	}

	fmt.Printf("\nTarget Info\n%s", hex.Dump(challenge))
	
	printNTLMTargetInfo(challenge)
}

func printNTLMTargetInfo(data []byte) {
	
	var challenge NTLMChallenge
	var targetLen, targetOffset int
	
	pos := strings.Index(string(data), signature)
	if pos == -1 {
		//return nil, fmt.Errorf("NTLM signature not found")
	}
	
	buffer := data[pos:] // discard ASN header
	
	msgType := int(binary.LittleEndian.Uint16(buffer[8:12]))  // 4byte LE
	if msgType != 0x2 { 
		//return nil, fmt.Errorf("NTLM Challenge (Type 2) was expected, type received %d", messageType)
	}
	
	targetLen =  int(binary.LittleEndian.Uint16(buffer[12:14]))  // 2byte LE
	targetOffset = int(binary.LittleEndian.Uint16(buffer[16:20])) // 4byte LE
	
	if targetLen > 0 {
	// get TargetName
		challenge.TargetName = string(removeNullBytes(buffer[targetOffset:targetOffset + targetLen]))
		//fmt.Println(challenge.TargetName)
	}
	
	var domainLen, domainOffset int
	
	domainLen = int(binary.LittleEndian.Uint16(buffer[40:42])) 
	domainOffset = int(binary.LittleEndian.Uint16(buffer[44:48])) 
	
	// win95 check...?
	
	// get version major/minor/build
	challenge.ProductVersion = fmt.Sprintf("%d.%d.%d", buffer[48], buffer[49], 
					int(binary.LittleEndian.Uint16(buffer[50:52])))
	
	//fmt.Println("ver:",challenge.ProductVersion)
	
	if domainLen == 0 {
	// no TargetInfoFields
		//return
		fmt.Printf("hahahah")
	}
	
	var dataLen, offset, fieldType, fieldLen int
	
	dataLen = len(buffer)
	offset = domainOffset // type pos
	
	for flag := true; flag; {
	
		if offset >= dataLen {
			break
		}
		
		fieldType = int(buffer[offset])
		fieldLen = int(binary.LittleEndian.Uint16(buffer[offset+2:offset+4])) 
		
		offset += 4
		
		if fieldLen == 0 {
			continue
		}
		
		switch fieldType {
			case 0x2:
				challenge.NetBIOSDomainName = 
					string(removeNullBytes(buffer[offset:offset+fieldLen]))
			case 0x1:
				challenge.NetBIOSComputerName = 
					string(removeNullBytes(buffer[offset:offset+fieldLen]))
			case 0x3:
				challenge.DNSComputerName = 
					string(removeNullBytes(buffer[offset:offset+fieldLen]))
			case 0x4:
				challenge.DNSDomainName = 
					string(removeNullBytes(buffer[offset:offset+fieldLen]))
			case 0x5:
				challenge.DNSTreeName = 
					string(removeNullBytes(buffer[offset:offset+fieldLen]))
			case 0x7:
				challenge.SystemTime = 
					ConvertFILETIME(buffer[offset:offset+fieldLen])
		}
		
		offset += fieldLen
	}
	
	fmt.Println("\n|Target_Name:", challenge.TargetName)
	fmt.Println("|NetBIOS_Domain_Name:", challenge.NetBIOSDomainName)
	fmt.Println("|NetBIOS_Computer_Name:", challenge.NetBIOSComputerName)
	fmt.Println("|DNS_Domain_Name:", challenge.DNSDomainName)
	fmt.Println("|DNS_Computer_Name:", challenge.DNSComputerName)
	fmt.Println("|DNS_Tree_Name:", challenge.DNSTreeName)
	fmt.Println("|Product_Version:", challenge.ProductVersion)
	fmt.Println("|System_Time:", challenge.SystemTime)
}

func removeNullBytes(data []byte) []byte {
	var result []byte
	for _, b := range data {
		if b != 0x0 { 
			result = append(result, b)
		}
	}
	return result
}

func ConvertFILETIME(filetime []byte) string {
	if len(filetime) != 8 {
		panic("Invalid FILETIME length")
	}

	ft := binary.LittleEndian.Uint64(filetime)

	seconds := int64(ft/10000000) - ntEpochOffset
	nanoseconds := int64(ft%10000000) * 100
	t := time.Unix(seconds, nanoseconds).UTC()
	
	return t.Format(time.RFC3339)
}

