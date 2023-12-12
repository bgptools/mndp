package mndp

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"
)

type MMDPPacket struct {
	SeqNo uint32
	Parts []MMDPPart
}

type MMDPPart struct {
	Type  MMDPTLVType
	Value interface{}
}

type MMDPTLVType uint16

const (
	MMDPTypeMACAddress    = MMDPTLVType(1)
	MMDPTypeIdentity      = MMDPTLVType(5)
	MMDPTypeVersion       = MMDPTLVType(7)
	MMDPTypePlatform      = MMDPTLVType(8)
	MMDPTypeUptime        = MMDPTLVType(10)
	MMDPTypeSoftwareID    = MMDPTLVType(11)
	MMDPTypeBoard         = MMDPTLVType(12)
	MMDPTypeUnpack        = MMDPTLVType(14)
	MMDPTypeIPv6Address   = MMDPTLVType(15)
	MMDPTypeInterfaceName = MMDPTLVType(16)
	MMDPTypeIPv4Address   = MMDPTLVType(17)
)

func (t MMDPTLVType) String() string {
	switch t {
	case MMDPTypeMACAddress:
		return "MACAddress"
	case MMDPTypeIdentity:
		return "Identity"
	case MMDPTypeVersion:
		return "Version"
	case MMDPTypePlatform:
		return "Platform"
	case MMDPTypeUptime:
		return "Uptime"
	case MMDPTypeSoftwareID:
		return "SoftwareID"
	case MMDPTypeBoard:
		return "Board"
	case MMDPTypeUnpack:
		return "Unpack"
	case MMDPTypeIPv6Address:
		return "IPv6Address"
	case MMDPTypeInterfaceName:
		return "InterfaceName"
	case MMDPTypeIPv4Address:
		return "IPv4Address"
	default:
		return fmt.Sprintf("Unknown-%d", t)
	}
}

func DecodePacket(contents []byte) (out *MMDPPacket, err error) {
	pkt := MMDPPacket{
		SeqNo: 0,
		Parts: make([]MMDPPart, 0),
	}

	breader := bytes.NewReader(contents)
	err = binary.Read(breader, binary.LittleEndian, &pkt.SeqNo)
	if err != nil {
		return nil, err
	}

	for {
		Part := MMDPPart{}
		err = binary.Read(breader, binary.BigEndian, &Part.Type)
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}
		ContentsLength := uint16(0)
		err = binary.Read(breader, binary.BigEndian, &ContentsLength)
		if err != nil {
			return nil, err
		}

		switch Part.Type {
		case MMDPTypeMACAddress:
			MAC := make(net.HardwareAddr, ContentsLength)
			_, err = io.ReadFull(breader, MAC)
			Part.Value = MAC
			if err != nil {
				return nil, err
			}
		case MMDPTypeIdentity, MMDPTypeVersion, MMDPTypePlatform, MMDPTypeSoftwareID, MMDPTypeBoard, MMDPTypeInterfaceName:
			s := make([]byte, ContentsLength)
			_, err = io.ReadFull(breader, s)
			Part.Value = string(s)
			if err != nil {
				return nil, err
			}
		case MMDPTypeUptime:
			t := uint32(0)
			err = binary.Read(breader, binary.LittleEndian, &t)
			if err != nil {
				return nil, err
			}
			Part.Value = time.Duration(time.Second * time.Duration(t))
		case MMDPTypeUnpack:
			dunno := make([]byte, ContentsLength)
			_, err = io.ReadFull(breader, dunno)
			Part.Value = dunno
			if err != nil {
				return nil, err
			}
		case MMDPTypeIPv6Address, MMDPTypeIPv4Address:
			ip := make(net.IP, ContentsLength)
			_, err = io.ReadFull(breader, ip)
			Part.Value = ip
			if err != nil {
				return nil, err
			}
		default:
			dunno := make([]byte, ContentsLength)
			_, err = io.ReadFull(breader, dunno)
			Part.Value = dunno
			if err != nil {
				return nil, err
			}
		}
		pkt.Parts = append(pkt.Parts, Part)
	}

	return &pkt, nil
}
