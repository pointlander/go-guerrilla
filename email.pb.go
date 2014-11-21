// Code generated by protoc-gen-go.
// source: email.proto
// DO NOT EDIT!

package main

import proto "code.google.com/p/goprotobuf/proto"
import json "encoding/json"
import math "math"

// Reference proto, json, and math imports to suppress error if they are not otherwise used.
var _ = proto.Marshal
var _ = &json.SyntaxError{}
var _ = math.Inf

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

func (m *Email) Reset()         { *m = Email{} }
func (m *Email) String() string { return proto.CompactTextString(m) }
func (*Email) ProtoMessage()    {}

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

func init() {
}
