//
// This work is based largely on the info and reverse eng effort HclX did:
// https://hclxing.wordpress.com/2019/06/06/reverse-engineering-wyzesense-bridge-protocol-part-iii/
// https://github.com/HclX/WyzeSensePy
//

package gosense

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
)

type cmdType int

const (
	syncCommand  = cmdType(0x43)
	asyncCommand = cmdType(0x53)

	// Sync packets
	// Commands initiated from host side
	cmdGetEnr  = syncCommand<<8 | 0x02
	cmdGetMac  = syncCommand<<8 | 0x04
	cmdGetKey  = syncCommand<<8 | 0x06
	cmdInquiry = syncCommand<<8 | 0x27

	// Async packets
	asyncAck = cmdType(asyncCommand<<8 | 0xff)

	// Commands initiated from dongle side
	cmdFinishAuth       = asyncCommand<<8 | 0x14
	cmdGetDongleVersion = asyncCommand<<8 | 0x16
	cmdEnableScan       = asyncCommand<<8 | 0x1c
	cmdGetSensorR1      = asyncCommand<<8 | 0x21
	cmdVerifySensor     = asyncCommand<<8 | 0x23
	cmdDelSensor        = asyncCommand<<8 | 0x25
	cmdGetSensorCount   = asyncCommand<<8 | 0x2e
	cmdGetSensorList    = asyncCommand<<8 | 0x30

	// Notifications initiated from dongle side
	notifyButtonPressed = asyncCommand<<8 | 0x18
	notifySensorAlarm   = asyncCommand<<8 | 0x19
	notifySensorScan    = asyncCommand<<8 | 0x20
	notifySyncTime      = asyncCommand<<8 | 0x32
	notifyEventLog      = asyncCommand<<8 | 0x35
)

type SensorType byte

// These are the different sensor types.
const (
	// Not known yet
	SenseUnknown SensorType = 0
	// Magnetic Switch
	SenseSwitch SensorType = 1
	// IR motion sensor
	SenseMotion SensorType = 2
)

// Convert the SensorType to a string.
func (s SensorType) String() string {
	if b, err := s.MarshalText(); err == nil {
		return string(b)
	}
	return "unknown"
}

// ParseSensorType takes a string sensor type and returns the SensorType constant.
func ParseSensorType(sts string) (SensorType, error) {
	switch strings.ToLower(sts) {
	case "0":
		fallthrough
	case "unknown":
		return SenseUnknown, nil
	case "1":
		fallthrough
	case "switch":
		return SenseSwitch, nil
	case "2":
		fallthrough
	case "motionsensor":
		return SenseMotion, nil
	}
	var s SensorType
	return s, fmt.Errorf("not a valid SensorType: %q", sts)
}

// UnmarshalText implements encoding.TextUnmarshaler.
func (s *SensorType) UnmarshalText(text []byte) error {
	l, err := ParseSensorType(string(text))
	if err != nil {
		return err
	}

	*s = SensorType(l)

	return nil
}

func (s SensorType) MarshalText() ([]byte, error) {
	switch s {
	case SenseUnknown:
		return []byte("unknown"), nil
	case SenseSwitch:
		return []byte("switch"), nil
	case SenseMotion:
		return []byte("motionsensor"), nil
	}

	return nil, fmt.Errorf("not a valid SensorType %d", s)
}

type SenseSensor struct {
	MAC        string
	SensorType SensorType
	Present    bool
}

type Event struct {
	MAC         string
	SensorFlags byte
	SensorType  SensorType
	Timestamp   time.Time
}

type Alarm struct {
	Event
	SignalStrength byte
	Battery        byte
	State          byte
}

// Packet defines packets going to and coming from the device.
type packet struct {
	cmd     cmdType
	payload []byte
}

func newPacket(cmd cmdType, payload []byte) packet {
	p := packet{
		cmd:     cmd,
		payload: payload,
	}

	return p
}

func parsePacket(buf []byte) (packet, error) {
	var err error
	p := packet{}

	if len(buf) < 5 {
		err = fmt.Errorf("Invalid packet lenght: %d", len(buf))
		log.Error(err)
		return p, err
	}

	magic := binary.BigEndian.Uint16(buf)
	ct := int(buf[2])
	b2 := buf[3]
	cmdID := int(buf[4])

	if magic != 0x55AA && magic != 0xAA55 {
		err = fmt.Errorf("Invalid packet magic: %x", magic)
		log.Error(err)
		return p, err
	}

	cmd := cmdType(ct<<8 | cmdID)
	var payload []byte

	if cmd == asyncAck {
		if len(buf) < 7 {
			err = fmt.Errorf("Invalid packet len for asyncAck")
			log.Error(err)
			return p, err
		}
		buf = buf[:7]
		payload = nil //cm << 8 | b2
	} else {
		if len(buf) < int(b2+4) {
			err = fmt.Errorf("Invalid packet len for regular response")
			log.Error(err)
			return p, err
		}
		buf = buf[:b2+4]
		payload = buf[5 : len(buf)-2]
	}

	l := len(buf)
	csRemote := int(buf[l-2])<<8 + int(buf[l-1])
	checksum := 0
	for _, i := range buf[:l-2] {
		checksum = checksum + int(i)
	}

	if csRemote != checksum {
		err = fmt.Errorf("Mismatched checksum, remote=%04X, local=%04X", csRemote, checksum)
		log.Error(err)
		return p, err
	}
	p = newPacket(cmd, payload)

	return p, nil
}

// Packet creation helpers

func inquiry() packet    { return newPacket(cmdInquiry, make([]byte, 0)) }
func getMac() packet     { return newPacket(cmdGetMac, make([]byte, 0)) }
func getVersion() packet { return newPacket(cmdGetDongleVersion, make([]byte, 0)) }

func enableScan(state byte) packet {
	pay := make([]byte, 1)
	pay[0] = state
	return newPacket(cmdEnableScan, pay)
}

func getSensorR1(MAC string, code string) packet {
	if len(MAC) != 8 {
		panic("len MAC is not 8!")
	}
	if len(code) != 16 {
		panic("len code is not 16!")
	}
	pay := []byte(MAC + code)
	return newPacket(cmdGetSensorR1, pay)
}

func verifySensor(MAC string) packet {
	if len(MAC) != 8 {
		panic("len MAC is not 8!")
	}
	pay := []byte(MAC + "\xFF\x04")
	return newPacket(cmdVerifySensor, pay)
}

func deleteSensor(MAC string) packet {
	if len(MAC) != 8 {
		panic("len MAC is not 8!")
	}
	pay := []byte(MAC)
	return newPacket(cmdDelSensor, pay)
}
func getSensorCount() packet { return newPacket(cmdGetSensorCount, make([]byte, 0)) }
func getSensorList(count byte) packet {
	pay := make([]byte, 1)
	pay[0] = count
	return newPacket(cmdGetSensorList, pay)
}
func finishAuth() packet {
	pay := make([]byte, 1)
	pay[0] = byte(0xff)
	return newPacket(cmdFinishAuth, pay)
}

func AsyncAck(cmd cmdType) packet {
	pay := make([]byte, 1)
	pay[0] = byte(cmd)
	return newPacket(asyncAck, pay)
}

func syncTimeAck(cmd cmdType) packet {
	pay := make([]byte, 8)
	t := uint64(time.Now().Unix() * 1000)
	binary.BigEndian.PutUint64(pay, t)
	return newPacket(cmd+1, pay)
}

func (p *packet) lenght() int {
	if p.cmd == asyncAck {
		return 7
	} else {
		return len(p.payload) + 7
	}
}

func (p *packet) toString() string {
	var str string
	if p.cmd == asyncAck {
		str = fmt.Sprintf("Packet: Cmd:%04x, Payload: ACK[%04x]", p.cmd, p.payload[0])
	} else {
		str = fmt.Sprintf("Packet: Cmd:%04x, Payload: [%s]", p.cmd, hex.EncodeToString(p.payload))
	}

	return str
}

func (p *packet) send(fd *os.File) error {
	var err error
	var b bytes.Buffer
	w := bufio.NewWriter(&b)

	err = binary.Write(w, binary.BigEndian, uint16(0xaa55))
	err = binary.Write(w, binary.BigEndian, byte(p.cmd>>8))
	if p.cmd == asyncAck {
		err = binary.Write(w, binary.BigEndian, p.payload[0])
		err = binary.Write(w, binary.BigEndian, byte(p.cmd&0xff))
	} else {
		err = binary.Write(w, binary.BigEndian, byte(len(p.payload)+3))
		err = binary.Write(w, binary.BigEndian, byte(p.cmd&0xff))
		if len(p.payload) > 0 {
			err = binary.Write(w, binary.BigEndian, p.payload)
		}
	}
	err = binary.Write(w, binary.BigEndian, uint16(0x0000))
	w.Flush()
	buf := b.Bytes()

	checksum := 0
	for _, i := range buf {
		checksum = checksum + int(i)
	}
	binary.BigEndian.PutUint16(buf[len(buf)-2:], uint16(checksum&0xffff))

	log.Debugf("Sending: %s", hex.EncodeToString(buf))
	l, err := fd.Write(buf)
	if l < len(buf) || err != nil {
		return err
	}

	return nil
}
