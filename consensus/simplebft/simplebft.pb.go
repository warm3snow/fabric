// Code generated by protoc-gen-go.
// source: simplebft.proto
// DO NOT EDIT!

/*
Package simplebft is a generated protocol buffer package.

It is generated from these files:
	simplebft.proto

It has these top-level messages:
	Config
	Msg
	Request
	SeqView
	BatchHeader
	Batch
	Preprepare
	Subject
	ViewChange
	Signed
	NewView
	Checkpoint
*/
package simplebft

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

type Config struct {
	N                  uint64 `protobuf:"varint,1,opt,name=n" json:"n,omitempty"`
	F                  uint64 `protobuf:"varint,2,opt,name=f" json:"f,omitempty"`
	BatchDurationNsec  uint64 `protobuf:"varint,3,opt,name=batch_duration_nsec,json=batchDurationNsec" json:"batch_duration_nsec,omitempty"`
	BatchSizeBytes     uint64 `protobuf:"varint,4,opt,name=batch_size_bytes,json=batchSizeBytes" json:"batch_size_bytes,omitempty"`
	RequestTimeoutNsec uint64 `protobuf:"varint,5,opt,name=request_timeout_nsec,json=requestTimeoutNsec" json:"request_timeout_nsec,omitempty"`
}

func (m *Config) Reset()                    { *m = Config{} }
func (m *Config) String() string            { return proto.CompactTextString(m) }
func (*Config) ProtoMessage()               {}
func (*Config) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{0} }

type Msg struct {
	// Types that are valid to be assigned to Type:
	//	*Msg_Request
	//	*Msg_Preprepare
	//	*Msg_Prepare
	//	*Msg_Commit
	//	*Msg_ViewChange
	//	*Msg_NewView
	//	*Msg_Checkpoint
	//	*Msg_Hello
	Type isMsg_Type `protobuf_oneof:"type"`
}

func (m *Msg) Reset()                    { *m = Msg{} }
func (m *Msg) String() string            { return proto.CompactTextString(m) }
func (*Msg) ProtoMessage()               {}
func (*Msg) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{1} }

type isMsg_Type interface {
	isMsg_Type()
}

type Msg_Request struct {
	Request *Request `protobuf:"bytes,1,opt,name=request,oneof"`
}
type Msg_Preprepare struct {
	Preprepare *Preprepare `protobuf:"bytes,2,opt,name=preprepare,oneof"`
}
type Msg_Prepare struct {
	Prepare *Subject `protobuf:"bytes,3,opt,name=prepare,oneof"`
}
type Msg_Commit struct {
	Commit *Subject `protobuf:"bytes,4,opt,name=commit,oneof"`
}
type Msg_ViewChange struct {
	ViewChange *Signed `protobuf:"bytes,5,opt,name=view_change,json=viewChange,oneof"`
}
type Msg_NewView struct {
	NewView *NewView `protobuf:"bytes,6,opt,name=new_view,json=newView,oneof"`
}
type Msg_Checkpoint struct {
	Checkpoint *Checkpoint `protobuf:"bytes,7,opt,name=checkpoint,oneof"`
}
type Msg_Hello struct {
	Hello *Batch `protobuf:"bytes,8,opt,name=hello,oneof"`
}

func (*Msg_Request) isMsg_Type()    {}
func (*Msg_Preprepare) isMsg_Type() {}
func (*Msg_Prepare) isMsg_Type()    {}
func (*Msg_Commit) isMsg_Type()     {}
func (*Msg_ViewChange) isMsg_Type() {}
func (*Msg_NewView) isMsg_Type()    {}
func (*Msg_Checkpoint) isMsg_Type() {}
func (*Msg_Hello) isMsg_Type()      {}

func (m *Msg) GetType() isMsg_Type {
	if m != nil {
		return m.Type
	}
	return nil
}

func (m *Msg) GetRequest() *Request {
	if x, ok := m.GetType().(*Msg_Request); ok {
		return x.Request
	}
	return nil
}

func (m *Msg) GetPreprepare() *Preprepare {
	if x, ok := m.GetType().(*Msg_Preprepare); ok {
		return x.Preprepare
	}
	return nil
}

func (m *Msg) GetPrepare() *Subject {
	if x, ok := m.GetType().(*Msg_Prepare); ok {
		return x.Prepare
	}
	return nil
}

func (m *Msg) GetCommit() *Subject {
	if x, ok := m.GetType().(*Msg_Commit); ok {
		return x.Commit
	}
	return nil
}

func (m *Msg) GetViewChange() *Signed {
	if x, ok := m.GetType().(*Msg_ViewChange); ok {
		return x.ViewChange
	}
	return nil
}

func (m *Msg) GetNewView() *NewView {
	if x, ok := m.GetType().(*Msg_NewView); ok {
		return x.NewView
	}
	return nil
}

func (m *Msg) GetCheckpoint() *Checkpoint {
	if x, ok := m.GetType().(*Msg_Checkpoint); ok {
		return x.Checkpoint
	}
	return nil
}

func (m *Msg) GetHello() *Batch {
	if x, ok := m.GetType().(*Msg_Hello); ok {
		return x.Hello
	}
	return nil
}

// XXX_OneofFuncs is for the internal use of the proto package.
func (*Msg) XXX_OneofFuncs() (func(msg proto.Message, b *proto.Buffer) error, func(msg proto.Message, tag, wire int, b *proto.Buffer) (bool, error), func(msg proto.Message) (n int), []interface{}) {
	return _Msg_OneofMarshaler, _Msg_OneofUnmarshaler, _Msg_OneofSizer, []interface{}{
		(*Msg_Request)(nil),
		(*Msg_Preprepare)(nil),
		(*Msg_Prepare)(nil),
		(*Msg_Commit)(nil),
		(*Msg_ViewChange)(nil),
		(*Msg_NewView)(nil),
		(*Msg_Checkpoint)(nil),
		(*Msg_Hello)(nil),
	}
}

func _Msg_OneofMarshaler(msg proto.Message, b *proto.Buffer) error {
	m := msg.(*Msg)
	// type
	switch x := m.Type.(type) {
	case *Msg_Request:
		b.EncodeVarint(1<<3 | proto.WireBytes)
		if err := b.EncodeMessage(x.Request); err != nil {
			return err
		}
	case *Msg_Preprepare:
		b.EncodeVarint(2<<3 | proto.WireBytes)
		if err := b.EncodeMessage(x.Preprepare); err != nil {
			return err
		}
	case *Msg_Prepare:
		b.EncodeVarint(3<<3 | proto.WireBytes)
		if err := b.EncodeMessage(x.Prepare); err != nil {
			return err
		}
	case *Msg_Commit:
		b.EncodeVarint(4<<3 | proto.WireBytes)
		if err := b.EncodeMessage(x.Commit); err != nil {
			return err
		}
	case *Msg_ViewChange:
		b.EncodeVarint(5<<3 | proto.WireBytes)
		if err := b.EncodeMessage(x.ViewChange); err != nil {
			return err
		}
	case *Msg_NewView:
		b.EncodeVarint(6<<3 | proto.WireBytes)
		if err := b.EncodeMessage(x.NewView); err != nil {
			return err
		}
	case *Msg_Checkpoint:
		b.EncodeVarint(7<<3 | proto.WireBytes)
		if err := b.EncodeMessage(x.Checkpoint); err != nil {
			return err
		}
	case *Msg_Hello:
		b.EncodeVarint(8<<3 | proto.WireBytes)
		if err := b.EncodeMessage(x.Hello); err != nil {
			return err
		}
	case nil:
	default:
		return fmt.Errorf("Msg.Type has unexpected type %T", x)
	}
	return nil
}

func _Msg_OneofUnmarshaler(msg proto.Message, tag, wire int, b *proto.Buffer) (bool, error) {
	m := msg.(*Msg)
	switch tag {
	case 1: // type.request
		if wire != proto.WireBytes {
			return true, proto.ErrInternalBadWireType
		}
		msg := new(Request)
		err := b.DecodeMessage(msg)
		m.Type = &Msg_Request{msg}
		return true, err
	case 2: // type.preprepare
		if wire != proto.WireBytes {
			return true, proto.ErrInternalBadWireType
		}
		msg := new(Preprepare)
		err := b.DecodeMessage(msg)
		m.Type = &Msg_Preprepare{msg}
		return true, err
	case 3: // type.prepare
		if wire != proto.WireBytes {
			return true, proto.ErrInternalBadWireType
		}
		msg := new(Subject)
		err := b.DecodeMessage(msg)
		m.Type = &Msg_Prepare{msg}
		return true, err
	case 4: // type.commit
		if wire != proto.WireBytes {
			return true, proto.ErrInternalBadWireType
		}
		msg := new(Subject)
		err := b.DecodeMessage(msg)
		m.Type = &Msg_Commit{msg}
		return true, err
	case 5: // type.view_change
		if wire != proto.WireBytes {
			return true, proto.ErrInternalBadWireType
		}
		msg := new(Signed)
		err := b.DecodeMessage(msg)
		m.Type = &Msg_ViewChange{msg}
		return true, err
	case 6: // type.new_view
		if wire != proto.WireBytes {
			return true, proto.ErrInternalBadWireType
		}
		msg := new(NewView)
		err := b.DecodeMessage(msg)
		m.Type = &Msg_NewView{msg}
		return true, err
	case 7: // type.checkpoint
		if wire != proto.WireBytes {
			return true, proto.ErrInternalBadWireType
		}
		msg := new(Checkpoint)
		err := b.DecodeMessage(msg)
		m.Type = &Msg_Checkpoint{msg}
		return true, err
	case 8: // type.hello
		if wire != proto.WireBytes {
			return true, proto.ErrInternalBadWireType
		}
		msg := new(Batch)
		err := b.DecodeMessage(msg)
		m.Type = &Msg_Hello{msg}
		return true, err
	default:
		return false, nil
	}
}

func _Msg_OneofSizer(msg proto.Message) (n int) {
	m := msg.(*Msg)
	// type
	switch x := m.Type.(type) {
	case *Msg_Request:
		s := proto.Size(x.Request)
		n += proto.SizeVarint(1<<3 | proto.WireBytes)
		n += proto.SizeVarint(uint64(s))
		n += s
	case *Msg_Preprepare:
		s := proto.Size(x.Preprepare)
		n += proto.SizeVarint(2<<3 | proto.WireBytes)
		n += proto.SizeVarint(uint64(s))
		n += s
	case *Msg_Prepare:
		s := proto.Size(x.Prepare)
		n += proto.SizeVarint(3<<3 | proto.WireBytes)
		n += proto.SizeVarint(uint64(s))
		n += s
	case *Msg_Commit:
		s := proto.Size(x.Commit)
		n += proto.SizeVarint(4<<3 | proto.WireBytes)
		n += proto.SizeVarint(uint64(s))
		n += s
	case *Msg_ViewChange:
		s := proto.Size(x.ViewChange)
		n += proto.SizeVarint(5<<3 | proto.WireBytes)
		n += proto.SizeVarint(uint64(s))
		n += s
	case *Msg_NewView:
		s := proto.Size(x.NewView)
		n += proto.SizeVarint(6<<3 | proto.WireBytes)
		n += proto.SizeVarint(uint64(s))
		n += s
	case *Msg_Checkpoint:
		s := proto.Size(x.Checkpoint)
		n += proto.SizeVarint(7<<3 | proto.WireBytes)
		n += proto.SizeVarint(uint64(s))
		n += s
	case *Msg_Hello:
		s := proto.Size(x.Hello)
		n += proto.SizeVarint(8<<3 | proto.WireBytes)
		n += proto.SizeVarint(uint64(s))
		n += s
	case nil:
	default:
		panic(fmt.Sprintf("proto: unexpected type %T in oneof", x))
	}
	return n
}

type Request struct {
	Payload []byte `protobuf:"bytes,1,opt,name=payload,proto3" json:"payload,omitempty"`
}

func (m *Request) Reset()                    { *m = Request{} }
func (m *Request) String() string            { return proto.CompactTextString(m) }
func (*Request) ProtoMessage()               {}
func (*Request) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{2} }

type SeqView struct {
	View uint64 `protobuf:"varint,1,opt,name=view" json:"view,omitempty"`
	Seq  uint64 `protobuf:"varint,2,opt,name=seq" json:"seq,omitempty"`
}

func (m *SeqView) Reset()                    { *m = SeqView{} }
func (m *SeqView) String() string            { return proto.CompactTextString(m) }
func (*SeqView) ProtoMessage()               {}
func (*SeqView) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{3} }

type BatchHeader struct {
	Seq      uint64 `protobuf:"varint,1,opt,name=seq" json:"seq,omitempty"`
	PrevHash []byte `protobuf:"bytes,2,opt,name=prev_hash,json=prevHash,proto3" json:"prev_hash,omitempty"`
	DataHash []byte `protobuf:"bytes,3,opt,name=data_hash,json=dataHash,proto3" json:"data_hash,omitempty"`
}

func (m *BatchHeader) Reset()                    { *m = BatchHeader{} }
func (m *BatchHeader) String() string            { return proto.CompactTextString(m) }
func (*BatchHeader) ProtoMessage()               {}
func (*BatchHeader) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{4} }

type Batch struct {
	Header     []byte            `protobuf:"bytes,1,opt,name=header,proto3" json:"header,omitempty"`
	Payloads   [][]byte          `protobuf:"bytes,2,rep,name=payloads,proto3" json:"payloads,omitempty"`
	Signatures map[uint64][]byte `protobuf:"bytes,3,rep,name=signatures" json:"signatures,omitempty" protobuf_key:"varint,1,opt,name=key" protobuf_val:"bytes,2,opt,name=value,proto3"`
}

func (m *Batch) Reset()                    { *m = Batch{} }
func (m *Batch) String() string            { return proto.CompactTextString(m) }
func (*Batch) ProtoMessage()               {}
func (*Batch) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{5} }

func (m *Batch) GetSignatures() map[uint64][]byte {
	if m != nil {
		return m.Signatures
	}
	return nil
}

type Preprepare struct {
	Seq   *SeqView `protobuf:"bytes,1,opt,name=seq" json:"seq,omitempty"`
	Batch *Batch   `protobuf:"bytes,2,opt,name=batch" json:"batch,omitempty"`
}

func (m *Preprepare) Reset()                    { *m = Preprepare{} }
func (m *Preprepare) String() string            { return proto.CompactTextString(m) }
func (*Preprepare) ProtoMessage()               {}
func (*Preprepare) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{6} }

func (m *Preprepare) GetSeq() *SeqView {
	if m != nil {
		return m.Seq
	}
	return nil
}

func (m *Preprepare) GetBatch() *Batch {
	if m != nil {
		return m.Batch
	}
	return nil
}

type Subject struct {
	Seq    *SeqView `protobuf:"bytes,1,opt,name=seq" json:"seq,omitempty"`
	Digest []byte   `protobuf:"bytes,2,opt,name=digest,proto3" json:"digest,omitempty"`
}

func (m *Subject) Reset()                    { *m = Subject{} }
func (m *Subject) String() string            { return proto.CompactTextString(m) }
func (*Subject) ProtoMessage()               {}
func (*Subject) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{7} }

func (m *Subject) GetSeq() *SeqView {
	if m != nil {
		return m.Seq
	}
	return nil
}

type ViewChange struct {
	View     uint64     `protobuf:"varint,1,opt,name=view" json:"view,omitempty"`
	Pset     []*Subject `protobuf:"bytes,2,rep,name=pset" json:"pset,omitempty"`
	Qset     []*Subject `protobuf:"bytes,3,rep,name=qset" json:"qset,omitempty"`
	Executed uint64     `protobuf:"varint,4,opt,name=executed" json:"executed,omitempty"`
}

func (m *ViewChange) Reset()                    { *m = ViewChange{} }
func (m *ViewChange) String() string            { return proto.CompactTextString(m) }
func (*ViewChange) ProtoMessage()               {}
func (*ViewChange) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{8} }

func (m *ViewChange) GetPset() []*Subject {
	if m != nil {
		return m.Pset
	}
	return nil
}

func (m *ViewChange) GetQset() []*Subject {
	if m != nil {
		return m.Qset
	}
	return nil
}

type Signed struct {
	Data      []byte `protobuf:"bytes,1,opt,name=data,proto3" json:"data,omitempty"`
	Signature []byte `protobuf:"bytes,2,opt,name=signature,proto3" json:"signature,omitempty"`
}

func (m *Signed) Reset()                    { *m = Signed{} }
func (m *Signed) String() string            { return proto.CompactTextString(m) }
func (*Signed) ProtoMessage()               {}
func (*Signed) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{9} }

type NewView struct {
	View  uint64             `protobuf:"varint,1,opt,name=view" json:"view,omitempty"`
	Vset  map[uint64]*Signed `protobuf:"bytes,2,rep,name=vset" json:"vset,omitempty" protobuf_key:"varint,1,opt,name=key" protobuf_val:"bytes,2,opt,name=value"`
	Xset  *Subject           `protobuf:"bytes,3,opt,name=xset" json:"xset,omitempty"`
	Batch *Batch             `protobuf:"bytes,4,opt,name=batch" json:"batch,omitempty"`
}

func (m *NewView) Reset()                    { *m = NewView{} }
func (m *NewView) String() string            { return proto.CompactTextString(m) }
func (*NewView) ProtoMessage()               {}
func (*NewView) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{10} }

func (m *NewView) GetVset() map[uint64]*Signed {
	if m != nil {
		return m.Vset
	}
	return nil
}

func (m *NewView) GetXset() *Subject {
	if m != nil {
		return m.Xset
	}
	return nil
}

func (m *NewView) GetBatch() *Batch {
	if m != nil {
		return m.Batch
	}
	return nil
}

type Checkpoint struct {
	Seq       uint64 `protobuf:"varint,1,opt,name=seq" json:"seq,omitempty"`
	Digest    []byte `protobuf:"bytes,2,opt,name=digest,proto3" json:"digest,omitempty"`
	Signature []byte `protobuf:"bytes,3,opt,name=signature,proto3" json:"signature,omitempty"`
}

func (m *Checkpoint) Reset()                    { *m = Checkpoint{} }
func (m *Checkpoint) String() string            { return proto.CompactTextString(m) }
func (*Checkpoint) ProtoMessage()               {}
func (*Checkpoint) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{11} }

func init() {
	proto.RegisterType((*Config)(nil), "simplebft.Config")
	proto.RegisterType((*Msg)(nil), "simplebft.Msg")
	proto.RegisterType((*Request)(nil), "simplebft.Request")
	proto.RegisterType((*SeqView)(nil), "simplebft.SeqView")
	proto.RegisterType((*BatchHeader)(nil), "simplebft.BatchHeader")
	proto.RegisterType((*Batch)(nil), "simplebft.Batch")
	proto.RegisterType((*Preprepare)(nil), "simplebft.Preprepare")
	proto.RegisterType((*Subject)(nil), "simplebft.Subject")
	proto.RegisterType((*ViewChange)(nil), "simplebft.ViewChange")
	proto.RegisterType((*Signed)(nil), "simplebft.Signed")
	proto.RegisterType((*NewView)(nil), "simplebft.NewView")
	proto.RegisterType((*Checkpoint)(nil), "simplebft.Checkpoint")
}

func init() { proto.RegisterFile("simplebft.proto", fileDescriptor0) }

var fileDescriptor0 = []byte{
	// 727 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x09, 0x6e, 0x88, 0x02, 0xff, 0x8c, 0x55, 0xdb, 0x6e, 0xd3, 0x4c,
	0x10, 0xfe, 0x5d, 0xe7, 0x38, 0xa9, 0xfe, 0xb6, 0x4b, 0x41, 0x56, 0xe9, 0x45, 0x65, 0x50, 0xe9,
	0x05, 0x4a, 0xab, 0x80, 0x04, 0xaa, 0x84, 0x84, 0x5a, 0x10, 0x15, 0x12, 0x15, 0x72, 0xab, 0x4a,
	0x70, 0x13, 0x39, 0xf6, 0x24, 0x36, 0x4d, 0xec, 0xc4, 0x5e, 0xb7, 0x0d, 0xcf, 0xc0, 0x33, 0xf0,
	0x0c, 0x3c, 0x00, 0x6f, 0xc4, 0x4b, 0xb0, 0x3b, 0xbb, 0xb1, 0x4d, 0x0e, 0x08, 0x29, 0x17, 0x3b,
	0xf3, 0x7d, 0xb3, 0x3b, 0xdf, 0x1c, 0x1c, 0xd8, 0x48, 0xc3, 0xd1, 0x78, 0x88, 0xbd, 0x3e, 0x6f,
	0x8f, 0x93, 0x98, 0xc7, 0xac, 0x99, 0x3b, 0xec, 0x1f, 0x06, 0xd4, 0x4e, 0xe3, 0xa8, 0x1f, 0x0e,
	0xd8, 0x3a, 0x18, 0x91, 0x65, 0xec, 0x19, 0x07, 0x15, 0xc7, 0x88, 0xa4, 0xd5, 0xb7, 0xd6, 0x94,
	0xd5, 0x67, 0x6d, 0xb8, 0xd7, 0x73, 0xb9, 0x17, 0x74, 0xfd, 0x2c, 0x71, 0x79, 0x18, 0x47, 0xdd,
	0x28, 0x45, 0xcf, 0x32, 0x09, 0xdf, 0x22, 0xe8, 0x8d, 0x46, 0xce, 0x05, 0xc0, 0x0e, 0x60, 0x53,
	0xf1, 0xd3, 0xf0, 0x2b, 0x76, 0x7b, 0x53, 0x8e, 0xa9, 0x55, 0x21, 0xf2, 0xff, 0xe4, 0xbf, 0x10,
	0xee, 0x13, 0xe9, 0x65, 0x47, 0xb0, 0x9d, 0xe0, 0x24, 0xc3, 0x94, 0x77, 0x79, 0x38, 0xc2, 0x38,
	0xe3, 0xea, 0xea, 0x2a, 0xb1, 0x99, 0xc6, 0x2e, 0x15, 0x24, 0xef, 0xb6, 0xbf, 0x9b, 0x60, 0x7e,
	0x48, 0x07, 0x22, 0xa7, 0xba, 0x46, 0x29, 0xeb, 0x56, 0x87, 0xb5, 0x0b, 0xa1, 0x8e, 0x42, 0xce,
	0xfe, 0x73, 0x66, 0x24, 0xf6, 0x02, 0x60, 0x9c, 0xa0, 0xfc, 0xb9, 0x09, 0x92, 0xb4, 0x56, 0xe7,
	0x7e, 0x29, 0xe4, 0x63, 0x0e, 0x8a, 0xa8, 0x12, 0x55, 0x3e, 0x34, 0x8b, 0x32, 0x17, 0x1e, 0xba,
	0xc8, 0x7a, 0x5f, 0xd0, 0xa3, 0x87, 0x66, 0xfc, 0xa7, 0x50, 0xf3, 0xe2, 0xd1, 0x28, 0xe4, 0x24,
	0x79, 0x15, 0x5d, 0x73, 0xd8, 0x73, 0x68, 0xdd, 0x84, 0x78, 0xdb, 0xf5, 0x02, 0x37, 0x1a, 0x20,
	0xe9, 0x6e, 0x75, 0xb6, 0xca, 0x21, 0xe1, 0x20, 0x42, 0x5f, 0xe6, 0x24, 0x79, 0xa7, 0x44, 0x63,
	0x87, 0xd0, 0x88, 0x44, 0x90, 0xf4, 0x58, 0xb5, 0x85, 0x57, 0xce, 0xf1, 0xf6, 0x4a, 0x20, 0x32,
	0xa9, 0x48, 0x1d, 0xa5, 0x7a, 0x2f, 0x40, 0xef, 0x7a, 0x1c, 0x87, 0x11, 0xb7, 0xea, 0x0b, 0xea,
	0x4f, 0x73, 0x50, 0xbe, 0x54, 0x50, 0x45, 0x2b, 0xab, 0x01, 0x0e, 0x87, 0xb1, 0xd5, 0xa0, 0x98,
	0xcd, 0x52, 0xcc, 0x89, 0x6c, 0xa5, 0xa0, 0x2b, 0xc2, 0x49, 0x0d, 0x2a, 0x7c, 0x3a, 0x46, 0xfb,
	0x11, 0xd4, 0x75, 0xf9, 0x99, 0x25, 0x4a, 0xe7, 0x4e, 0x87, 0xb1, 0xeb, 0x53, 0x8f, 0xd6, 0x9d,
	0x99, 0x69, 0x1f, 0x42, 0xfd, 0x02, 0x27, 0x94, 0x1a, 0x83, 0x0a, 0xe9, 0x50, 0xb3, 0x47, 0x67,
	0xb6, 0x09, 0x66, 0x8a, 0x13, 0x3d, 0x80, 0xf2, 0x68, 0x7f, 0x82, 0x96, 0x7a, 0x0f, 0x5d, 0x1f,
	0x93, 0x19, 0xc1, 0xc8, 0x09, 0xec, 0x21, 0x34, 0x45, 0x07, 0x6e, 0xba, 0x81, 0x9b, 0x06, 0x14,
	0xb8, 0xee, 0x34, 0xa4, 0xe3, 0x4c, 0xd8, 0x12, 0xf4, 0x5d, 0xee, 0x2a, 0xd0, 0x54, 0xa0, 0x74,
	0x48, 0xd0, 0xfe, 0x69, 0x40, 0x95, 0xee, 0x66, 0x0f, 0xa0, 0x16, 0xd0, 0xfd, 0x3a, 0x5d, 0x6d,
	0xb1, 0x1d, 0x68, 0xe8, 0xc4, 0x53, 0x71, 0xb5, 0x49, 0x57, 0x6b, 0x9b, 0xbd, 0x06, 0x48, 0x45,
	0x8b, 0x5c, 0x9e, 0x25, 0x62, 0xca, 0x4d, 0x81, 0xb6, 0x3a, 0x7b, 0xf3, 0x55, 0xa2, 0x2e, 0x2a,
	0xca, 0xdb, 0x88, 0x27, 0x53, 0xa7, 0x14, 0xb3, 0xf3, 0x0a, 0x36, 0xe6, 0x60, 0x29, 0xef, 0x1a,
	0xa7, 0x33, 0x79, 0xe2, 0xc8, 0xb6, 0xa1, 0x7a, 0xe3, 0x0e, 0x33, 0xd4, 0xd2, 0x94, 0x71, 0xbc,
	0xf6, 0xd2, 0xb0, 0x3f, 0x03, 0x14, 0xb3, 0xcb, 0x1e, 0x17, 0x85, 0x99, 0x1b, 0x3d, 0x55, 0x6e,
	0x55, 0xac, 0x7d, 0xa8, 0xd2, 0x22, 0xea, 0x3d, 0x58, 0xe8, 0xaa, 0xa3, 0x60, 0xfb, 0x9d, 0x68,
	0x93, 0x1a, 0xd9, 0x7f, 0xbc, 0x58, 0x54, 0xd0, 0x0f, 0x07, 0x72, 0x29, 0x55, 0x9e, 0xda, 0xb2,
	0xbf, 0x19, 0x00, 0x57, 0xc5, 0xfc, 0x2e, 0xeb, 0xf9, 0x3e, 0x54, 0xc6, 0x29, 0x72, 0x2a, 0xf0,
	0xd2, 0xad, 0x71, 0x08, 0x97, 0xbc, 0x89, 0xe4, 0x99, 0xab, 0x79, 0x12, 0x97, 0x4d, 0xc3, 0x3b,
	0xf4, 0x32, 0x8e, 0xbe, 0xfe, 0xf8, 0xe4, 0xb6, 0x7d, 0x0c, 0x35, 0xb5, 0x57, 0x32, 0x13, 0x39,
	0x08, 0xba, 0xe1, 0x74, 0x66, 0xbb, 0xd0, 0xcc, 0xdb, 0xa3, 0x75, 0x14, 0x0e, 0xfb, 0x97, 0x01,
	0x75, 0xbd, 0x61, 0x4b, 0x75, 0x1c, 0x09, 0x5f, 0xa1, 0x63, 0x77, 0x71, 0x2f, 0xdb, 0x57, 0x02,
	0x56, 0x63, 0x40, 0x4c, 0xa9, 0xe8, 0x4e, 0x29, 0x32, 0x56, 0x29, 0xba, 0x53, 0x3c, 0xdd, 0xb5,
	0xca, 0x5f, 0xbb, 0xb6, 0xf3, 0x1e, 0x9a, 0xf9, 0x13, 0x4b, 0x46, 0xe9, 0x49, 0x79, 0x94, 0x96,
	0x7d, 0x6c, 0xca, 0xd3, 0x75, 0x09, 0x50, 0x7c, 0x1b, 0x96, 0xac, 0xdd, 0x8a, 0x86, 0xff, 0x59,
	0x43, 0x73, 0xae, 0x86, 0xbd, 0x1a, 0xfd, 0x13, 0x3d, 0xfb, 0x1d, 0x00, 0x00, 0xff, 0xff, 0x63,
	0xf4, 0x2e, 0x0e, 0x9c, 0x06, 0x00, 0x00,
}