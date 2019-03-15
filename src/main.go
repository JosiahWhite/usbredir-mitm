package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash/crc32"
	"io"
	"log"
	"math/rand"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

type URBHdr struct {
	HdrLen    uint16
	HdrFunc   uint16
	HdrStatus uint32
	HdrHandle uint64
	HdrFlags  uint32
	Padding   [4]byte
}

type ADBCmd struct {
	Cmd           uint32
	Arg0          uint32
	Arg1          uint32
	PayloadLength uint32
	PayloadCRC32  uint32
	Magic         uint32
}

type SyncSession struct {
	state      int
	outputFile *os.File
	chunkLeft  int
	fileOffset int
	fileName   string
	hijackFile bool
	syncCmd    string
	cmdBuffer  []byte
	savedInt   int
}

var proxyIP string
var tablePolynomial *crc32.Table = crc32.MakeTable(0xedb88320)

func main() {
	rand.Seed(time.Now().UTC().UnixNano())
	if len(os.Args) < 2 {
		fmt.Println("app <target ip>")
		return
	}

	proxyIP = os.Args[1]

	l, err := net.Listen("tcp", "0.0.0.0:32038")
	if err != nil {
		fmt.Println("Error listening:", err.Error())
		os.Exit(1)
	}

	defer l.Close()
	fmt.Println("Listening on 0.0.0.0:32038")
	for {
		conn, err := l.Accept()
		if err != nil {
			fmt.Println("Error accepting: ", err.Error())
			os.Exit(1)
		}
		log.Println("got connection from:", conn.RemoteAddr().String())
		go handleConnection(conn)
	}
}

func handleUnknownProxy(targetConn net.Conn, clientConn net.Conn) {
	fmt.Println("handling generic data")

	bufConn := bufio.NewReader(clientConn)
	errCh := make(chan error, 2)
	go proxy(targetConn, bufConn, errCh)
	go proxy(clientConn, targetConn, errCh)

	// Wait
	for i := 0; i < 2; i++ {
		e := <-errCh
		if e != nil {
			return
		}
	}

	return
}

func ADBChecksum(data []byte) uint32 {
	var checksum uint32
	for i := 0; i < len(data); i++ {
		checksum += uint32(data[i])
	}

	return checksum
}

func hexToByte(hexChar string) byte {
	b, _ := hex.DecodeString(hexChar)
	return b[0]
}

func FindIDASignature(sig string, buf []byte) int {
	sigParts := strings.Split(sig, " ")
	sigPos := 0
	for i := 0; i < len(buf); i++ {
		if sigPos == len(sigParts) {
			return i
		}

		if sigParts[sigPos] == "?" || buf[i] == hexToByte(sigParts[sigPos]) {
			sigPos++
		} else {
			sigPos = 0
		}
	}
	return -1
}

func readExactly(conn net.Conn, length int, timeout time.Duration) []byte {
	var output []byte
	var read int

	for read < length {
		buf := make([]byte, length-read)
		conn.SetReadDeadline(time.Now().Add(timeout))
		got, err := conn.Read(buf)
		conn.SetReadDeadline(time.Time{})
		output = append(output, buf[0:got]...)
		if err != nil {
			return output
		}
		read += got
	}

	return output
}

func readUSBRedirCmd(conn net.Conn) chan []byte {
	outputChan := make(chan []byte)

	go func() {
		buf := make([]byte, 8)
		got, err := conn.Read(buf)
		if err != nil || got != 8 {
			outputChan <- nil
			return
		}

		packetID := uint32(0)
		packetSize := uint32(0)

		p := bytes.NewBuffer(buf)
		binary.Read(p, binary.LittleEndian, &packetID)
		binary.Read(p, binary.LittleEndian, &packetSize)

		if packetSize > 0 {
			payload := readExactly(conn, int(packetSize), 5*time.Second)
			if payload == nil || len(payload) != int(packetSize) {
				outputChan <- nil
				return
			}

			buf = append(buf, payload...)
		}

		outputChan <- buf
	}()

	return outputChan
}

func handleDataConnectionHandshake(targetConn net.Conn, clientConn net.Conn) bool {
	var buf []byte

	// TODO: maybe parse more packets?
	// do we really need to parse if its just static packet sizes in the handshake?

	{
		buf = readExactly(clientConn, 8, 5*time.Second)
		if buf == nil {
			handleUnknownProxy(targetConn, clientConn)
			return false
		}
		targetConn.Write(buf)
		if len(buf) != 8 {
			handleUnknownProxy(targetConn, clientConn)
			return false
		}
	}
	fmt.Println("handshake stage 1 done")

	{
		buf = readExactly(targetConn, 0x5C, 5*time.Second)
		if buf == nil {
			handleUnknownProxy(targetConn, clientConn)
			return false
		}
		clientConn.Write(buf)
		if len(buf) != 0x5C {
			handleUnknownProxy(targetConn, clientConn)
			return false
		}
	}
	fmt.Println("handshake stage 2 done")

	{
		buf = readExactly(clientConn, 16, 5*time.Second)
		if buf == nil {
			handleUnknownProxy(targetConn, clientConn)
			return false
		}
		targetConn.Write(buf)
		if len(buf) != 16 {
			handleUnknownProxy(targetConn, clientConn)
			return false
		}
	}
	fmt.Println("handshake stage 3 done")

	{
		buf = readExactly(targetConn, 1, 5*time.Second)
		if buf == nil {
			handleUnknownProxy(targetConn, clientConn)
			return false
		}
		clientConn.Write(buf)
		if len(buf) != 1 || buf[0] != 0x37 {
			handleUnknownProxy(targetConn, clientConn)
			return false
		}
	}
	fmt.Println("handshake stage 4 done")

	{
		buf = readExactly(clientConn, 1, 5*time.Second)
		if buf == nil {
			handleUnknownProxy(targetConn, clientConn)
			return false
		}
		targetConn.Write(buf)
		if len(buf) != 1 {
			handleUnknownProxy(targetConn, clientConn)
			return false
		}
	}
	fmt.Println("handshake stage 5 done")

	{
		buf = readExactly(targetConn, 4, 5*time.Second)
		if buf == nil {
			handleUnknownProxy(targetConn, clientConn)
			return false
		}
		clientConn.Write(buf)
		if len(buf) != 4 {
			handleUnknownProxy(targetConn, clientConn)
			return false
		}
	}
	fmt.Println("handshake stage 6 done")

	{
		buf = readExactly(clientConn, 5, 5*time.Second)
		if buf == nil {
			fmt.Println("stage 7 failed")
			time.Sleep(100 * time.Second)
			handleUnknownProxy(targetConn, clientConn)
			return false
		}
		targetConn.Write(buf)
		if len(buf) != 5 {
			handleUnknownProxy(targetConn, clientConn)
			return false
		}
	}
	fmt.Println("handshake stage 7 done")

	{
		buf = readExactly(targetConn, 5, 5*time.Second)
		if buf == nil {
			handleUnknownProxy(targetConn, clientConn)
			return false
		}
		clientConn.Write(buf)
		if len(buf) != 5 || buf[0] != 0x34 {
			handleUnknownProxy(targetConn, clientConn)
			return false
		}
	}
	fmt.Println("handshake stage 8 done")

	{
		buf = readExactly(clientConn, 4, 5*time.Second)
		if buf == nil {
			handleUnknownProxy(targetConn, clientConn)
			return false
		}
		targetConn.Write(buf)
		if len(buf) != 4 {
			handleUnknownProxy(targetConn, clientConn)
			return false
		}
	}
	fmt.Println("handshake stage 9 done")

	{
		buf = readExactly(targetConn, 4, 5*time.Second)
		if buf == nil {
			handleUnknownProxy(targetConn, clientConn)
			return false
		}
		clientConn.Write(buf)
		if len(buf) != 4 {
			handleUnknownProxy(targetConn, clientConn)
			return false
		}
	}
	fmt.Println("handshake stage 10 done")

	{
		buf = readExactly(clientConn, 9, 5*time.Second)
		if buf == nil {
			handleUnknownProxy(targetConn, clientConn)
			return false
		}
		targetConn.Write(buf)
		if len(buf) != 9 || buf[0] != 0x32 {
			handleUnknownProxy(targetConn, clientConn)
			return false
		}
	}

	textSize1 := uint32(0)
	textSize2 := uint32(0)

	p := bytes.NewBuffer(buf[1:])
	binary.Read(p, binary.LittleEndian, &textSize1)
	binary.Read(p, binary.LittleEndian, &textSize2)

	fmt.Println("textsize:", textSize1, "-", textSize2)

	fmt.Println("len:", len(buf), "-", (textSize1 + textSize2 + 9))
	if len(buf) < int(textSize1+textSize2+9) {
		leftOver := int(textSize1+textSize2+9) - len(buf)
		buf = readExactly(clientConn, leftOver, 5*time.Second)
		if buf == nil {
			handleUnknownProxy(targetConn, clientConn)
			return false
		}
		targetConn.Write(buf)
		if len(buf) != leftOver {
			handleUnknownProxy(targetConn, clientConn)
			return false
		}
	}
	fmt.Println("handshake stage 11 done")

	return true
}

func handleConnection(clientConn net.Conn) {
	var buf []byte
	var err error

	defer clientConn.Close()
	targetConn, err := net.Dial("tcp", proxyIP)
	if err != nil {
		fmt.Println("proxy dial:", err)
		return
	}
	defer targetConn.Close()

	buf = readExactly(targetConn, 1, 5*time.Second)
	if buf == nil {
		handleUnknownProxy(targetConn, clientConn)
		return
	}
	clientConn.Write(buf)
	if len(buf) != 1 || buf[0] != 0x10 {
		handleUnknownProxy(targetConn, clientConn)
		return
	}

	buf = readExactly(clientConn, 9, 5*time.Second)
	if buf == nil {
		handleUnknownProxy(targetConn, clientConn)
		return
	}
	targetConn.Write(buf)
	if len(buf) != 9 || !strings.HasPrefix(string(buf), "USBT") {
		handleUnknownProxy(targetConn, clientConn)
		return
	}

	buf = readExactly(targetConn, 6, 5*time.Second)
	if buf == nil {
		handleUnknownProxy(targetConn, clientConn)
		return
	}
	clientConn.Write(buf)
	if len(buf) != 6 {
		handleUnknownProxy(targetConn, clientConn)
		return
	}

	buf = readExactly(clientConn, 1, 5*time.Second)
	if buf == nil {
		handleUnknownProxy(targetConn, clientConn)
		return
	}
	targetConn.Write(buf)
	if len(buf) != 1 || buf[0] != 0x47 {
		if buf[0] == 0x46 {
			fmt.Println("ignoring control connection")
		}
		handleUnknownProxy(targetConn, clientConn)
		return
	}

	if !handleDataConnectionHandshake(targetConn, clientConn) {
		return
	}

	fmt.Println("done data handshake")

	adbEndpoint := []byte{255, 255}

	dropSequenceMutex := &sync.Mutex{}
	dropSequenceNumbers := make([][2]int, 0)

	openSyncMutex := &sync.Mutex{}
	openSyncSessions := make(map[uint32]*SyncSession, 0)

	adbPayloadExpected := make([]bool, 2)

	var deviceHandle uint64
	var adbWRTEBuffer []byte
	var hostAdbPkt, devAdbPkt ADBCmd

	endpointModules := make(map[uint64][2]int)

	handleCommand := func(buf *[]byte, direction int) bool {
		var packetType uint32

		p := bytes.NewBuffer(*buf)
		binary.Read(p, binary.LittleEndian, &packetType)
		if packetType != 3 {
			return false
		}
		//skip packet length
		p.Next(4)
		var packetSeq uint32
		binary.Read(p, binary.LittleEndian, &packetSeq)
		var dropIndex int = -1
		dropSequenceMutex.Lock()
		for k, v := range dropSequenceNumbers {
			if int(packetSeq) == v[0] && direction == v[1] {
				dropIndex = k
				break
			}
		}
		if dropIndex != -1 {
			dropSequenceNumbers = append(dropSequenceNumbers[:dropIndex], dropSequenceNumbers[dropIndex+1:]...)
		}
		dropSequenceMutex.Unlock()
		if dropIndex != -1 {
			return true
		}
		// skip pad
		p.Next(4)

		//skip unknown 16 byte header
		p.Next(16)

		URB := URBHdr{}
		if binary.Read(p, binary.LittleEndian, &URB) != nil {
			fmt.Println("1: packet parse error")
			return false
		}
		switch URB.HdrFunc {
		case 0:
			fmt.Println("select configuration packet")
			// skip rest of URB before data
			p.Next(0x10)

			if p.Len() > (int(URB.HdrLen) - 40) {
				p.Truncate(int(URB.HdrLen) - 40)
			}

			for p.Len() > 0 {
				var interfaceLength uint16
				binary.Read(p, binary.LittleEndian, &interfaceLength)
				p.Next(2)

				var intfClass uint8
				binary.Read(p, binary.LittleEndian, &intfClass)
				var intfSubClass uint8
				binary.Read(p, binary.LittleEndian, &intfSubClass)
				var intfProtocol uint8
				binary.Read(p, binary.LittleEndian, &intfProtocol)

				p.Next(9)

				var numOfPipes uint32
				binary.Read(p, binary.LittleEndian, &numOfPipes)
				p.Next(4)

				if numOfPipes > 10 {
					numOfPipes = 0
				}

				interfaceLength -= 24

				read := 0
				for i := numOfPipes; i > 0; i-- {
					p.Next(2)
					var endpointAddress uint8
					binary.Read(p, binary.LittleEndian, &endpointAddress)
					p.Next(1)
					var endpointType uint32
					binary.Read(p, binary.LittleEndian, &endpointType)
					var endpointHandle uint64
					binary.Read(p, binary.LittleEndian, &endpointHandle)
					p.Next(8)

					if endpointHandle != 0 {
						deviceHandle = URB.HdrHandle
						if intfClass == 0xFF && intfSubClass == 0x42 && intfProtocol == 0x01 && numOfPipes == 2 {
							adbEndpoint[2-i] = byte(endpointAddress)
							fmt.Println("found ADB interface:", endpointAddress)
						}
						endpointModules[endpointHandle] = [2]int{int(endpointAddress), int(endpointType)}
					}

					fmt.Printf("endpoint: %02X, handle: %08X\n", endpointAddress, endpointHandle)
					read += 24
				}

				if read < int(interfaceLength) {
					p.Next(int(interfaceLength) - read)
				}
			}
		case 1:
			fmt.Println("select interface packet")
			// skip rest of URB before data
			p.Next(0x8)

			if p.Len() > (int(URB.HdrLen) - 40) {
				p.Truncate(int(URB.HdrLen) - 40)
			}

			for p.Len() > 0 {
				var interfaceLength uint16
				binary.Read(p, binary.LittleEndian, &interfaceLength)
				p.Next(2)

				var intfClass uint8
				binary.Read(p, binary.LittleEndian, &intfClass)
				var intfSubClass uint8
				binary.Read(p, binary.LittleEndian, &intfSubClass)
				var intfProtocol uint8
				binary.Read(p, binary.LittleEndian, &intfProtocol)

				p.Next(9)
				var numOfPipes uint32
				binary.Read(p, binary.LittleEndian, &numOfPipes)
				p.Next(4)

				if numOfPipes > 10 {
					numOfPipes = 0
				}

				interfaceLength -= 24

				read := 0
				for i := numOfPipes; i > 0; i-- {
					p.Next(2)
					var endpointAddress uint8
					binary.Read(p, binary.LittleEndian, &endpointAddress)
					p.Next(1)
					var endpointType uint32
					binary.Read(p, binary.LittleEndian, &endpointType)
					var endpointHandle uint64
					binary.Read(p, binary.LittleEndian, &endpointHandle)
					p.Next(8)

					if endpointHandle != 0 {
						if intfClass == 0xFF && intfSubClass == 0x42 && intfProtocol == 0x01 && numOfPipes == 2 {
							adbEndpoint[2-i] = byte(endpointAddress)
							fmt.Println("found ADB interface:", endpointAddress)
						}
						endpointModules[endpointHandle] = [2]int{int(endpointAddress), int(endpointType)}
					}

					fmt.Printf("endpoint: %02X, handle: %08X\n", endpointAddress, endpointHandle)
					read += 24
					numOfPipes--
				}

				if read < int(interfaceLength) {
					p.Next(int(interfaceLength) - read)
				}
			}

		case 9:
			if adbEndpoint[1] == 255 {
				return false
			}

			var pipeHandle uint64
			binary.Read(p, binary.LittleEndian, &pipeHandle)
			if _, ok := endpointModules[pipeHandle]; !ok {
				return false
			}
			var adbDirection int
			if adbEndpoint := bytes.IndexByte(adbEndpoint, byte(endpointModules[pipeHandle][0])); adbEndpoint == -1 {
				return false
			} else {
				if endpointModules[pipeHandle][0]&0x80 == 0x80 {
					adbDirection = 0
				} else {
					adbDirection = 1
				}
			}
			p.Next(4)

			//fmt.Println("adb endpoint write")

			var bufferSize uint32
			binary.Read(p, binary.LittleEndian, &bufferSize)

			p.Next(88)

			if adbDirection == 0 && direction == 0 {
				adbData := p.Next(int(bufferSize))
				adb := bytes.NewBuffer(adbData)

				// we dont need to tamper with device->host adb packets currently
				if adbPayloadExpected[0] {
					adbPayloadExpected[0] = false
					return false
				}

				binary.Read(adb, binary.BigEndian, &devAdbPkt)
				if devAdbPkt.PayloadLength > 0 {
					adbPayloadExpected[0] = true
				}

				// devAdbPkt.Cmd == "OKAY"
				if devAdbPkt.Cmd == 0x4F4B4159 {
					openSyncMutex.Lock()
					if sesh, ok := openSyncSessions[devAdbPkt.Arg1]; ok && sesh.state == 0 {
						fmt.Println("sync session opened:", devAdbPkt.Arg1)
						openSyncSessions[devAdbPkt.Arg1].state = 1
					}
					openSyncMutex.Unlock()
				}

				//fmt.Println("d2h >", hex.EncodeToString(adbData))
			} else if adbDirection == 1 && direction == 1 {
				if bufferSize == 0 {
					return false
				}

				adbData := p.Next(int(bufferSize))
				//fmt.Println("h2d(", len(adbData), ") >", hex.EncodeToString(adbData))

				adb := bytes.NewBuffer(adbData)

				if adbPayloadExpected[1] {
					adbPayloadExpected[1] = false

					// it was an open command
					// hostAdbPkt.Cmd == "OPEN"
					if hostAdbPkt.Cmd == 0x4F50454E {
						// trim ending null byte
						adbData := adbData[:len(adbData)-1]

						if string(adbData) == "sync:" {
							openSyncMutex.Lock()
							openSyncSessions[hostAdbPkt.Arg0] = &SyncSession{}
							openSyncMutex.Unlock()
						}

						if strings.HasPrefix(string(adbData), "reboot:") {
							fmt.Println("device reboot:", string(adbData))
						}

						if strings.HasPrefix(string(adbData), "shell:") {
							if len(adbData) > 6 {
								fmt.Println("device shell command:", string(adbData[6:]))
							} else {
								fmt.Println("device shell session opened")
								//todo: write all shell session data to a file
							}
						}

						fmt.Println("OPEN stream:", string(adbData))
					}

					var syncSesh *SyncSession
					openSyncMutex.Lock()
					// only care about sync sessions for now
					if s, ok := openSyncSessions[hostAdbPkt.Arg0]; !ok {
						openSyncMutex.Unlock()
						if adbWRTEBuffer != nil {
							clientConn.Write(adbWRTEBuffer)
							clientConn.Write(*buf)

							adbWRTEBuffer = nil

							return true
						}

						return false
					} else {
						syncSesh = s
					}
					openSyncMutex.Unlock()

					if adbWRTEBuffer != nil {

						for adb.Len() >= 4 {
							// if no partial command received
							if syncSesh.state == 1 {
								syncSesh.syncCmd = string(adb.Next(4))
							}

							fmt.Println("syncCmd:", syncSesh.syncCmd)

							switch syncSesh.syncCmd {
							case "SEND":
								if syncSesh.state != 3 {
									if adb.Len() < 4 {
										syncSesh.state = 2
										break
									}
									var nameLength uint32
									binary.Read(adb, binary.LittleEndian, &nameLength)
									syncSesh.savedInt = int(nameLength)
									syncSesh.cmdBuffer = nil
								}

								if adb.Len()+len(syncSesh.cmdBuffer) < syncSesh.savedInt {
									if adb.Len() > 0 {
										syncSesh.cmdBuffer = append(syncSesh.cmdBuffer, adb.Next(adb.Len())...)
									}
									syncSesh.state = 3
									break
								}
								needed := syncSesh.savedInt - len(syncSesh.cmdBuffer)
								syncSesh.savedInt = 0
								syncSesh.state = 1

								fileNameMode := string(syncSesh.cmdBuffer)
								if needed > 0 {
									fileNameMode += string(adb.Next(needed))
								}
								syncSesh.cmdBuffer = nil

								fmt.Println("sending file:", fileNameMode)
								syncSesh.fileName = strings.Split(fileNameMode, ",")[0]

								saveFileName := "uploaded_files/" + strings.Replace(syncSesh.fileName, "/", "_", -1)

								for {
									if _, err := os.Stat(saveFileName); err == nil {
										saveFileName = saveFileName + "_1"
									} else {
										break
									}
								}

								out, err := os.Create(saveFileName)
								if err != nil {
									fmt.Println("failed to open file:", saveFileName)
									break
								}
								syncSesh.outputFile = out
								syncSesh.chunkLeft = 0
								syncSesh.fileOffset = 0
							case "DATA":
								if syncSesh.state != 3 {
									if adb.Len() < 4 {
										syncSesh.state = 2
										break
									}
									var chunkSize uint32
									binary.Read(adb, binary.LittleEndian, &chunkSize)
									syncSesh.chunkLeft = int(chunkSize)
									syncSesh.savedInt = 0
									syncSesh.cmdBuffer = nil

									// if file is bigger than 40k and
									// filename contains "/data/local/tmp", hijack
									/*
										if strings.Contains(syncSesh.fileName, "/data/local/tmp") && chunkSize > 40000 {
											fmt.Println("in-flight rewrite enabled")
											syncSesh.hijackFile = true
										}
									*/
								}

								syncSesh.state = 3

								availableBytes := syncSesh.chunkLeft
								if availableBytes > adb.Len() {
									availableBytes = adb.Len()
								}

								fileContent := adb.Next(availableBytes)
								/*
									if index := FindIDASignature("39 00 53 E3 ? ? ? 9A 2C 00 1B E5 ? ? ? EB", fileContent); syncSesh.hijackFile && index != -1 {
										fmt.Println("found sig at index:", index, index+syncSesh.fileOffset)
										copy(fileContent[index-4:index], []byte{0x00, 0xF0, 0x20, 0xE3})

										binary.LittleEndian.PutUint32(adbWRTEBuffer[0xB0:0xB4], ADBChecksum((*buf)[0xA0:]))

										fmt.Println(hex.EncodeToString(*buf))
									}
								*/

								if syncSesh.outputFile != nil {
									syncSesh.outputFile.Write(fileContent)
								}
								syncSesh.fileOffset += availableBytes
								syncSesh.chunkLeft -= availableBytes

								if syncSesh.chunkLeft == 0 {
									syncSesh.state = 1
								}
							case "DONE":
								// dont care about file modification time tbh, this could be logged in the future
								if syncSesh.state != 3 {
									if adb.Len() < 4 {
										syncSesh.state = 2
										break
									}
									adb.Next(4)
									syncSesh.savedInt = 0
									syncSesh.cmdBuffer = nil
								}
								if syncSesh.outputFile != nil {
									syncSesh.outputFile.Close()
								}
								syncSesh.outputFile = nil
								syncSesh.hijackFile = false
								syncSesh.fileName = ""
								syncSesh.chunkLeft = 0
								syncSesh.fileOffset = 0
								syncSesh.state = 1
							case "STAT":
								if syncSesh.state != 3 {
									if adb.Len() < 4 {
										syncSesh.state = 2
										break
									}
									var fileNameLength uint32
									binary.Read(adb, binary.LittleEndian, &fileNameLength)
									syncSesh.savedInt = int(fileNameLength)
									syncSesh.cmdBuffer = nil
								}

								if adb.Len()+len(syncSesh.cmdBuffer) < syncSesh.savedInt {
									if adb.Len() > 0 {
										syncSesh.cmdBuffer = append(syncSesh.cmdBuffer, adb.Next(adb.Len())...)
									}
									syncSesh.state = 3
									break
								}

								needed := syncSesh.savedInt - len(syncSesh.cmdBuffer)
								syncSesh.savedInt = 0
								syncSesh.state = 1

								fileName := string(syncSesh.cmdBuffer)
								if needed > 0 {
									fileName += string(adb.Next(needed))
								}
								syncSesh.cmdBuffer = nil

								fmt.Println("STAT:", fileName)
							case "RECV":
								if syncSesh.state != 3 {
									if adb.Len() < 4 {
										syncSesh.state = 2
										break
									}
									var fileNameLength uint32
									binary.Read(adb, binary.LittleEndian, &fileNameLength)
									syncSesh.savedInt = int(fileNameLength)
									syncSesh.cmdBuffer = nil
								}

								if adb.Len()+len(syncSesh.cmdBuffer) < syncSesh.savedInt {
									if adb.Len() > 0 {
										syncSesh.cmdBuffer = append(syncSesh.cmdBuffer, adb.Next(adb.Len())...)
									}
									syncSesh.state = 3
									break
								}

								needed := syncSesh.savedInt - len(syncSesh.cmdBuffer)
								syncSesh.savedInt = 0
								syncSesh.state = 1

								fileName := string(syncSesh.cmdBuffer)
								if needed > 0 {
									fileName += string(adb.Next(needed))
								}
								syncSesh.cmdBuffer = nil

								fmt.Println("file downloaded from device:", fileName)
							case "QUIT":
								if adb.Len() < 4 {
									syncSesh.state = 2
									break
								}
								adb.Next(4)
								syncSesh.savedInt = 0
								syncSesh.cmdBuffer = nil

								if _, ok := openSyncSessions[hostAdbPkt.Arg1]; ok {
									delete(openSyncSessions, hostAdbPkt.Arg1)
								}
							default:
								fmt.Println("syncCmd:", syncSesh.syncCmd, ", unknown message:", hex.EncodeToString(adb.Next(adb.Len())))
							}
						}

						if adb.Len() > 0 {
							fmt.Println("unconsumed sync bytes:", hex.EncodeToString(adb.Next(adb.Len())))
						}

						clientConn.Write(adbWRTEBuffer)
						clientConn.Write(*buf)

						adbWRTEBuffer = nil

						return true
					}

					return false
				}

				hostAdbPkt = ADBCmd{0, 0, 0, 0, 0, 0}
				binary.Read(adb, binary.BigEndian, &hostAdbPkt)

				if hostAdbPkt.PayloadLength > 0 {
					adbPayloadExpected[1] = true
				}

				// hostAdbPkt.Cmd == "CLSE"
				if hostAdbPkt.Cmd == 0x434C5345 {
					if _, ok := openSyncSessions[hostAdbPkt.Arg1]; ok {
						delete(openSyncSessions, hostAdbPkt.Arg1)
					}
				}

				// hostAdbPkt.Cmd == "WRTE"
				if hostAdbPkt.Cmd == 0x57525445 && adbPayloadExpected[1] {
					if adbWRTEBuffer != nil {
						fmt.Println("!!!!!!!!!ADB PROTOCOL CORUPTION!!!!!!!!!")
						// i mean i guess we can ignore it?
						// we should probably not ignore it tho
					}
					adbWRTEBuffer = make([]byte, len(*buf))
					copy(adbWRTEBuffer, *buf)

					fmt.Println("ADB write buffered")
					//fmt.Printf("wrote device handle: %08X\n", deviceHandle)
					binary.LittleEndian.PutUint64((*buf)[0x28:], deviceHandle)
					// should we zero out the extra content padding?
					// *buf = (*buf)[0 : len(*buf)-int(bufferSize)]

					dropSequenceMutex.Lock()
					dropSequenceNumbers = append(dropSequenceNumbers, [2]int{int(packetSeq), 0})
					dropSequenceMutex.Unlock()

					// send buffered/fake success URB
					targetConn.Write(*buf)

					return true
				}
			}
		default:
			fmt.Println("URB Function:", URB.HdrFunc)
		}

		return false
	}

	closedConn := make(chan bool)
	go func() {
		for {
			buf := <-readUSBRedirCmd(targetConn)
			if buf == nil {
				fmt.Println("target closed")
				closedConn <- true
				return
			}
			if !handleCommand(&buf, 1) {
				clientConn.Write(buf)
			}
		}
	}()

	go func() {
		for {
			buf := <-readUSBRedirCmd(clientConn)
			if buf == nil {
				fmt.Println("client closed")
				closedConn <- true
				return
			}
			if !handleCommand(&buf, 0) {
				targetConn.Write(buf)
			}
		}
	}()

	<-closedConn
	fmt.Println("connection closed")
}

type closeWriter interface {
	CloseWrite() error
}

func proxy(dst io.Writer, src io.Reader, errCh chan error) {
	_, err := io.Copy(dst, src)
	if tcpConn, ok := dst.(closeWriter); ok {
		tcpConn.CloseWrite()
	}
	errCh <- err
}
