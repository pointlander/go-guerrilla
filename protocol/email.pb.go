// Code generated by protoc-gen-go.
// source: email.proto
// DO NOT EDIT!

/*
Package protocol is a generated protocol buffer package.

It is generated from these files:
	email.proto

It has these top-level messages:
	Email
	Encrypted
	PasswordEncrypted
	PublicKey
	PrivateKey
*/
package protocol

import proto "github.com/golang/protobuf/proto"
import fmt "fmt"
import math "math"

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion2 // please upgrade the proto package

type Email struct {
	Id               *uint64 `protobuf:"varint,1,req,name=id" json:"id,omitempty"`
	Date             *uint64 `protobuf:"varint,2,req,name=date" json:"date,omitempty"`
	To               *string `protobuf:"bytes,3,req,name=to" json:"to,omitempty"`
	From             *string `protobuf:"bytes,4,req,name=from" json:"from,omitempty"`
	Subject          *string `protobuf:"bytes,5,req,name=subject" json:"subject,omitempty"`
	Mail             *string `protobuf:"bytes,6,req,name=mail" json:"mail,omitempty"`
	Address          *string `protobuf:"bytes,7,req,name=address" json:"address,omitempty"`
	XXX_unrecognized []byte  `json:"-"`
}

func (m *Email) Reset()                    { *m = Email{} }
func (m *Email) String() string            { return proto.CompactTextString(m) }
func (*Email) ProtoMessage()               {}
func (*Email) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{0} }

func (m *Email) GetId() uint64 {
	if m != nil && m.Id != nil {
		return *m.Id
	}
	return 0
}

func (m *Email) GetDate() uint64 {
	if m != nil && m.Date != nil {
		return *m.Date
	}
	return 0
}

func (m *Email) GetTo() string {
	if m != nil && m.To != nil {
		return *m.To
	}
	return ""
}

func (m *Email) GetFrom() string {
	if m != nil && m.From != nil {
		return *m.From
	}
	return ""
}

func (m *Email) GetSubject() string {
	if m != nil && m.Subject != nil {
		return *m.Subject
	}
	return ""
}

func (m *Email) GetMail() string {
	if m != nil && m.Mail != nil {
		return *m.Mail
	}
	return ""
}

func (m *Email) GetAddress() string {
	if m != nil && m.Address != nil {
		return *m.Address
	}
	return ""
}

type Encrypted struct {
	Key              []byte `protobuf:"bytes,1,req,name=key" json:"key,omitempty"`
	Data             []byte `protobuf:"bytes,2,req,name=data" json:"data,omitempty"`
	XXX_unrecognized []byte `json:"-"`
}

func (m *Encrypted) Reset()                    { *m = Encrypted{} }
func (m *Encrypted) String() string            { return proto.CompactTextString(m) }
func (*Encrypted) ProtoMessage()               {}
func (*Encrypted) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{1} }

func (m *Encrypted) GetKey() []byte {
	if m != nil {
		return m.Key
	}
	return nil
}

func (m *Encrypted) GetData() []byte {
	if m != nil {
		return m.Data
	}
	return nil
}

type PasswordEncrypted struct {
	Timestamp        *int64 `protobuf:"varint,1,req,name=timestamp" json:"timestamp,omitempty"`
	Salt             []byte `protobuf:"bytes,2,req,name=salt" json:"salt,omitempty"`
	Data             []byte `protobuf:"bytes,3,req,name=data" json:"data,omitempty"`
	XXX_unrecognized []byte `json:"-"`
}

func (m *PasswordEncrypted) Reset()                    { *m = PasswordEncrypted{} }
func (m *PasswordEncrypted) String() string            { return proto.CompactTextString(m) }
func (*PasswordEncrypted) ProtoMessage()               {}
func (*PasswordEncrypted) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{2} }

func (m *PasswordEncrypted) GetTimestamp() int64 {
	if m != nil && m.Timestamp != nil {
		return *m.Timestamp
	}
	return 0
}

func (m *PasswordEncrypted) GetSalt() []byte {
	if m != nil {
		return m.Salt
	}
	return nil
}

func (m *PasswordEncrypted) GetData() []byte {
	if m != nil {
		return m.Data
	}
	return nil
}

type PublicKey struct {
	Timestamp        *int64 `protobuf:"varint,1,req,name=timestamp" json:"timestamp,omitempty"`
	N                []byte `protobuf:"bytes,2,req,name=n" json:"n,omitempty"`
	E                *int64 `protobuf:"varint,3,req,name=e" json:"e,omitempty"`
	XXX_unrecognized []byte `json:"-"`
}

func (m *PublicKey) Reset()                    { *m = PublicKey{} }
func (m *PublicKey) String() string            { return proto.CompactTextString(m) }
func (*PublicKey) ProtoMessage()               {}
func (*PublicKey) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{3} }

func (m *PublicKey) GetTimestamp() int64 {
	if m != nil && m.Timestamp != nil {
		return *m.Timestamp
	}
	return 0
}

func (m *PublicKey) GetN() []byte {
	if m != nil {
		return m.N
	}
	return nil
}

func (m *PublicKey) GetE() int64 {
	if m != nil && m.E != nil {
		return *m.E
	}
	return 0
}

type PrivateKey struct {
	D                []byte   `protobuf:"bytes,2,req,name=d" json:"d,omitempty"`
	Primes           [][]byte `protobuf:"bytes,3,rep,name=primes" json:"primes,omitempty"`
	XXX_unrecognized []byte   `json:"-"`
}

func (m *PrivateKey) Reset()                    { *m = PrivateKey{} }
func (m *PrivateKey) String() string            { return proto.CompactTextString(m) }
func (*PrivateKey) ProtoMessage()               {}
func (*PrivateKey) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{4} }

func (m *PrivateKey) GetD() []byte {
	if m != nil {
		return m.D
	}
	return nil
}

func (m *PrivateKey) GetPrimes() [][]byte {
	if m != nil {
		return m.Primes
	}
	return nil
}

func init() {
	proto.RegisterType((*Email)(nil), "protocol.email")
	proto.RegisterType((*Encrypted)(nil), "protocol.encrypted")
	proto.RegisterType((*PasswordEncrypted)(nil), "protocol.password_encrypted")
	proto.RegisterType((*PublicKey)(nil), "protocol.public_key")
	proto.RegisterType((*PrivateKey)(nil), "protocol.private_key")
}

func init() { proto.RegisterFile("email.proto", fileDescriptor0) }

var fileDescriptor0 = []byte{
	// 231 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x09, 0x6e, 0x88, 0x02, 0xff, 0x6c, 0x8d, 0xc1, 0x4e, 0xeb, 0x30,
	0x14, 0x44, 0x95, 0x38, 0x6d, 0x9f, 0x27, 0xd1, 0x43, 0x78, 0xe5, 0x65, 0x94, 0x05, 0xca, 0x8a,
	0x1d, 0x5f, 0xc0, 0x87, 0x54, 0x6e, 0x7c, 0x91, 0x4c, 0x92, 0xda, 0xb2, 0x5d, 0x50, 0xfe, 0x1e,
	0xf9, 0x92, 0xc2, 0x86, 0x95, 0x35, 0x9e, 0x7b, 0xce, 0xa0, 0xa5, 0xd5, 0xb8, 0xe5, 0x39, 0x44,
	0x9f, 0xbd, 0xfa, 0xc7, 0xcf, 0xe4, 0x97, 0x61, 0xc6, 0x81, 0x0b, 0x05, 0xd4, 0xce, 0xea, 0xaa,
	0xaf, 0xc7, 0x46, 0x75, 0x68, 0xac, 0xc9, 0xa4, 0x6b, 0x4e, 0x40, 0x9d, 0xbd, 0x16, 0x7d, 0x3d,
	0xca, 0xd2, 0xbc, 0x45, 0xbf, 0xea, 0x86, 0xd3, 0x03, 0x4e, 0xe9, 0x76, 0x79, 0xa7, 0x29, 0xeb,
	0xc3, 0xbd, 0x2e, 0x32, 0x7d, 0xbc, 0xd7, 0xc6, 0xda, 0x48, 0x29, 0xe9, 0x53, 0xf9, 0x18, 0x9e,
	0x20, 0xe9, 0x3a, 0xc5, 0x2d, 0x64, 0xb2, 0xaa, 0x85, 0x98, 0x69, 0xe3, 0xc5, 0x6e, 0x5f, 0x34,
	0xbc, 0xd8, 0x0d, 0xaf, 0x50, 0xc1, 0xa4, 0xf4, 0xe9, 0xa3, 0x3d, 0xff, 0x02, 0x8f, 0x90, 0xd9,
	0xad, 0x94, 0xb2, 0x59, 0x03, 0x63, 0xa2, 0x60, 0xc9, 0x2c, 0xf9, 0x1b, 0xfb, 0x91, 0x08, 0x96,
	0xbc, 0x00, 0xe1, 0x76, 0x59, 0xdc, 0x74, 0x9e, 0x69, 0xfb, 0x0b, 0x96, 0xa8, 0xae, 0x3b, 0x29,
	0x51, 0x11, 0x63, 0x62, 0x18, 0xd1, 0x86, 0xe8, 0x3e, 0x4c, 0x26, 0xe6, 0x24, 0x2a, 0xbb, 0x1f,
	0xfd, 0xc7, 0x31, 0xc4, 0xe2, 0xd0, 0xa2, 0x17, 0x63, 0xf7, 0x15, 0x00, 0x00, 0xff, 0xff, 0x60,
	0x94, 0xb9, 0xfd, 0x52, 0x01, 0x00, 0x00,
}
