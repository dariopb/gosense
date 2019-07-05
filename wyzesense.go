package gosense

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"os"
	"time"

	log "github.com/sirupsen/logrus"
)

// WyzeSense defines a WyzeSense USB device.
type WyzeSense struct {
	Name string

	fd       *os.File
	handlers map[cmdType]func(*WyzeSense, packet, context.CancelFunc) error
	alarmch  chan (Alarm)
	sensorch chan (SenseSensor)

	ctx              context.Context
	currentCmdCancel context.CancelFunc
	currentResponse  *packet
}

// NewWyzeSense creates a new WyzeSense object.
func NewWyzeSense(devicename string,
	alarmch chan (Alarm),
	sensorch chan (SenseSensor)) (*WyzeSense, error) {
	log.Infof("NewWyzeSense: trying to open device: [%s]", devicename)

	s := &WyzeSense{
		handlers: make(map[cmdType]func(*WyzeSense, packet, context.CancelFunc) error),
		ctx:      context.Background(),
		alarmch:  alarmch,
		sensorch: sensorch,
	}

	fs, err := os.OpenFile(devicename, os.O_RDWR, 0777)
	if err != nil {
		log.Errorf("Failed opening device: {%s}", err)
		return s, err
	}

	s.fd = fs

	// Register the async cmd handlers
	s.handlers[notifySyncTime] = onSyncTime
	s.handlers[notifySensorAlarm] = onSensorAlarm
	s.handlers[notifyEventLog] = onEventLog

	//--------
	// start processing
	go s.readerLoop()

	return s, nil
}

func (s *WyzeSense) Start() error {
	err := s.inquiry()
	if err != nil {
		log.Debugf("Inquiry failed: %s", err)
		return err
	}

	err = s.getMac()
	if err != nil {
		log.Debugf("GetMac failed: %s", err)
		return err
	}

	ver, err := s.getVersion()
	if err != nil {
		log.Debugf("GetVersion failed: %s", err)
		return err
	}
	log.Debugf("GetVersion: ver: [%s]", ver)

	sensors, err := s.GetSensorList()
	if err != nil {
		log.Debugf("GetSensorList failed: %s", err)
		return err
	}
	log.Debugf("GetSensorList: sensors: [%v]", sensors)

	err = s.finishAuth()
	if err != nil {
		log.Debugf("FinishAuth failed: %s", err)
		return err
	}
	log.Debugf("FinishAuth: success!")

	return nil
}

func (s *WyzeSense) Close() {
	if s.fd != nil {
		s.fd.Close()
	}
}

func findMagic(buf []byte) int {
	next := false
	for i, n := range buf {
		if 0x55 == n {
			next = true
			continue
		}
		if next && 0xaa == n {
			return i - 1
		}
		next = false
	}

	return -1
}

func (s *WyzeSense) readerLoop() {
	var err error
	buf := make([]byte, 0x4)
	buf = nil

	//--------
	// set up the async handlers

	for {
		i := findMagic(buf)
		if i < 0 {
			buf, err = s.readRawHid()
			if err != nil {
				continue
			}
			continue
		}

		buf = buf[i:]
		l := len(buf)
		log.Debugf("Trying to parse: %d bytes: [ %s ]",
			l, hex.EncodeToString(buf))

		//--------
		// Handle the response
		p, err := parsePacket(buf)
		if err != nil {
			log.Error("Error parsing buffer as packet")
			buf = buf[l:]
			continue
		}

		if cmdType(p.cmd>>8) == asyncCommand && p.cmd != asyncAck {
			log.Debugf("    ==> Sending ACK packet for cmd %04x", p.cmd)
			s.sendPacket(AsyncAck(p.cmd))
		}

		buf = buf[p.lenght():]
		if handler, ok := s.handlers[p.cmd]; ok {
			err = handler(s, p, s.currentCmdCancel)
		}
	}
}

func (s *WyzeSense) readRawHid() ([]byte, error) {

	buf := make([]byte, 0x80)
	_, err := s.fd.Read(buf)

	if err != nil {
		log.Errorf("Failed reading from device: ", err)
		return nil, err
	}

	l := buf[0]
	buf = buf[1 : l+1]

	log.Debugf("readRawHid: %d bytes: [ %s ]",
		l, hex.EncodeToString(buf))

	return buf, nil
}

func (s *WyzeSense) sendPacket(p packet) error {
	log.Debugf("====> sending: [%s]", p.toString())
	return p.send(s.fd)
}

func (s *WyzeSense) doCommand(cmd packet,
	handler func(*WyzeSense, packet, context.CancelFunc) error) (*packet, error) {
	var err error

	s.handlers[cmd.cmd+1] = handler

	ctxTimeout, cancelFunc := context.WithTimeout(s.ctx, 5*time.Second)
	s.currentCmdCancel = cancelFunc

	// Write the command
	err = cmd.send(s.fd)
	if err != nil {
		log.Errorf("Failed sending to device: %s", err.Error())
		return nil, err
	}

	// Wait for the response(s)
	select {
	case <-ctxTimeout.Done():
		break
	}
	cancelFunc()

	delete(s.handlers, cmd.cmd+1)

	return s.currentResponse, err
}

func (s *WyzeSense) doSimpleCommand(cmd packet) (*packet, error) {
	var err error

	p, err := s.doCommand(cmd, func(s *WyzeSense, cmd packet, cancelFun context.CancelFunc) error {
		s.currentResponse = &cmd
		cancelFun()
		return nil
	})

	return p, err
}

// inquiry sends the Inquiry cmd
func (s *WyzeSense) inquiry() error {
	var err error

	log.Debug("Start Inquiry...")

	p, err := s.doSimpleCommand(inquiry())
	if err != nil {
		return err
	}

	if p == nil {
		log.Debug("Inquiry timed out")
	}

	ret := p.payload[0]
	log.Debugf("Inquiry returned: %d", ret)
	return nil
}

// getMac sends the getmac cmd
func (s *WyzeSense) getMac() error {
	var err error

	log.Debug("Start GetMac...")

	p, err := s.doSimpleCommand(getMac())
	if err != nil {
		return err
	}

	if p == nil {
		log.Debug("GetMac timed out")
	}

	log.Debugf("GetMac returned: %s", (p.payload))
	return nil
}

// getVersion gets the dongle version
func (s *WyzeSense) getVersion() ([]byte, error) {
	var err error

	log.Debug("Start GetVersion...")

	p, err := s.doSimpleCommand(getVersion())
	if err != nil {
		return nil, err
	}

	if p == nil {
		log.Debug("GetVersion timed out")
	}

	log.Debugf("GetVersion returned: %s", (p.payload))
	return p.payload, nil
}

// GetSensorList enumerates the sensors registered with the dongle
func (s *WyzeSense) GetSensorList() ([]string, error) {
	var err error

	log.Debug("Start GetSensorList...")

	p, err := s.doSimpleCommand(getSensorCount())
	if err != nil {
		return nil, err
	}

	if p == nil {
		log.Debug("GetSensorList timed out")
	}

	if len(p.payload) != 1 {
		panic("Payload is not 1!")
	}
	count := p.payload[0]
	log.Debugf("GetSensorCount returned: %d", count)

	index := byte(0)
	sensors := make([]string, count)

	if count > 0 {
		_, err := s.doCommand(getSensorList(count), func(s *WyzeSense, pkt packet, cancelFun context.CancelFunc) error {
			if len(pkt.payload) != 8 {
				panic("Payload is not 8!")
			}
			log.Debugf("Sensor %d/%d, MAC: [%s]", index+1, count, pkt.payload)
			sensors[index] = string(pkt.payload)
			index = index + 1

			if index == count {
				cancelFun()
			}
			return nil
		})

		if err != nil {
			return nil, err
		}
	}

	return sensors, nil
}

// ScanSensor scans for sensor and adds it to the dongle
func (s *WyzeSense) ScanSensor() (string, error) {
	var err error

	log.Debug("Start ScanSensor...")

	p, err := s.doSimpleCommand(enableScan(1))
	if err != nil {
		return "", err
	}

	if p == nil {
		log.Debug("EnableScan (start) timed out")
	}

	//--------
	// Wait for a new sensor to come
	var MAC string
	var version byte

	ctxTimeout, cancelFuncScan := context.WithTimeout(s.ctx, 30*time.Second)

	onNewSensor := func(s *WyzeSense, pkt packet, cancelFun context.CancelFunc) error {
		if len(pkt.payload) != 11 {
			panic("Payload is not 11!")
		}

		MAC = string(pkt.payload[1:9])

		sensor := SenseSensor{
			MAC:        string(MAC),
			SensorType: SensorType(pkt.payload[9]),
			Present:    true,
		}
		version = pkt.payload[10]

		log.Debugf("New sensor: MAC: [%s], type: %d, version: %d", sensor.MAC, sensor.SensorType, version)
		cancelFuncScan()

		if s.sensorch != nil {
			s.sensorch <- sensor
		}
		return nil
	}

	// Register the async handler for scan results
	s.handlers[notifySensorScan] = onNewSensor

	// Wait for the response(s)
	select {
	case <-ctxTimeout.Done():
		break
	}
	cancelFuncScan()

	delete(s.handlers, notifySensorScan)

	if len(MAC) > 0 {
		p, err = s.doSimpleCommand(getSensorR1(string(MAC), "Ok5HPNQ4lf77u754"))
		if err != nil {
			return "", err
		}

		if p == nil {
			log.Debug("GetSensorR1 (stop) timed out")
		}
	}

	// Stop scanning
	p, err = s.doSimpleCommand(enableScan(0))
	if err != nil {
		return "", err
	}

	if p == nil {
		log.Debug("EnableScan (stop) timed out")
	}

	if len(MAC) > 0 {
		// Verify sensor
		p, err = s.doSimpleCommand(verifySensor(string(MAC)))
		if err != nil {
			return "", err
		}

		if p == nil {
			log.Debug("VerifySensor timed out")
		}

	}

	return string(MAC), nil
}

// DeleteSensor removes a sensor from the dongle
func (s *WyzeSense) DeleteSensor(MAC string) error {
	var err error

	log.Debug("Start DeleteSensor...")

	p, err := s.doSimpleCommand(deleteSensor(MAC))
	if err != nil {
		return err
	}

	if p == nil {
		log.Debug("DeleteSensor timed out")
	}

	if len(p.payload) != 9 {
		panic("Payload is not 9!")
	}
	ackMac := string(p.payload[:7])
	ackCode := p.payload[8]
	log.Debugf("DeleteSensor returned: [%s], code: %d", ackMac, ackCode)

	if ackCode == 0xff {
		sensor := SenseSensor{
			MAC:     string(MAC),
			Present: false,
		}

		s.sensorch <- sensor
	}

	return nil
}

// VerifySensor validates the sensor is responsive
func (s *WyzeSense) VerifySensor(MAC string) error {
	var err error

	log.Debug("Start VerifySensor...")

	p, err := s.doSimpleCommand(verifySensor(MAC))
	if err != nil {
		return err
	}

	if p == nil {
		log.Debug("VerifySensor timed out")
	}
	return nil
}

// FinishAuth finish the dongle initialization
func (s *WyzeSense) finishAuth() error {
	var err error

	log.Debug("Start FinishAuth...")

	p, err := s.doSimpleCommand(finishAuth())
	if err != nil {
		return err
	}

	if p == nil {
		log.Debug("FinishAuth timed out")
	}

	return nil
}

func onSyncTime(s *WyzeSense, p packet, finished context.CancelFunc) error {
	log.Debugf("    onSyncTime ==> Sending SyncTypeAck packet for cmd %04x", p.cmd)
	s.sendPacket(syncTimeAck(p.cmd))
	return nil
}

func onSensorAlarm(s *WyzeSense, p packet, finished context.CancelFunc) error {
	/*
		8 bytes: big endian timestamp in milliseconds
		1 byte:  sensor flags?, 0xa2 for both contact and motion sensor
		8 bytes: sensor MAC
		1 byte:  sensor type
		1 byte:  signal strength
		1 byte:  remaining battery percentage
		1 byte:  unknown, referred to as p1329
		1 byte:  unknown
		1 byte:  binary sensor state (1: opened/motion detected, 0: closed/no motion detected)
		2 bytes: big endian counter for when the sensor is triggered
		1 byte:  signal strength, presumably something like absolute value of RSSI (lower is better)
	*/
	pay := p.payload
	ts := binary.BigEndian.Uint64(pay) / 1000

	alarm := Alarm{
		SensorFlags:    pay[8],
		MAC:            string(pay[9 : 9+8]),
		SensorType:     SensorType(pay[17]),
		SignalStrength: pay[25],
		Battery:        pay[19],
		State:          pay[22],
		Timestamp:      time.Unix(int64(ts), 0),
	}

	msg := pay[19:]

	log.Infof("ALARM: time=%s, mac: %s, type: %x, battery: %d, signal: %d, state: %d, data=%s",
		alarm.Timestamp.Format(time.RFC822Z),
		alarm.MAC,
		alarm.SensorType,
		alarm.Battery,
		alarm.SignalStrength,
		alarm.State,
		hex.EncodeToString(msg))

	if s.alarmch != nil {
		s.alarmch <- alarm
	}

	return nil
}

func onEventLog(s *WyzeSense, p packet, finished context.CancelFunc) error {
	if len(p.payload) < 9 {
		panic("payload < 9!")
	}

	pay := p.payload
	ts := binary.BigEndian.Uint64(pay) / 1000
	//l := pay[8]
	t := time.Unix(int64(ts), 0)
	msg := pay[9:]

	log.Infof("LOG: time=%s, data=%s", t.Format(time.RFC822Z), (msg))

	return nil
}
