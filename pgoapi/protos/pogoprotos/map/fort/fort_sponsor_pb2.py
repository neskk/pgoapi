# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: pogoprotos/map/fort/fort_sponsor.proto

import sys
_b=sys.version_info[0]<3 and (lambda x:x) or (lambda x:x.encode('latin1'))
from google.protobuf.internal import enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
from google.protobuf import descriptor_pb2
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor.FileDescriptor(
  name='pogoprotos/map/fort/fort_sponsor.proto',
  package='pogoprotos.map.fort',
  syntax='proto3',
  serialized_pb=_b('\n&pogoprotos/map/fort/fort_sponsor.proto\x12\x13pogoprotos.map.fort*\xba\x02\n\x0b\x46ortSponsor\x12\x11\n\rUNSET_SPONSOR\x10\x00\x12\r\n\tMCDONALDS\x10\x01\x12\x11\n\rPOKEMON_STORE\x10\x02\x12\x08\n\x04TOHO\x10\x03\x12\x0c\n\x08SOFTBANK\x10\x04\x12\t\n\x05GLOBE\x10\x05\x12\x0b\n\x07SPATULA\x10\x06\x12\x0f\n\x0bTHERMOMETER\x10\x07\x12\t\n\x05KNIFE\x10\x08\x12\t\n\x05GRILL\x10\t\x12\n\n\x06SMOKER\x10\n\x12\x07\n\x03PAN\x10\x0b\x12\x07\n\x03\x42\x42Q\x10\x0c\x12\t\n\x05\x46RYER\x10\r\x12\x0b\n\x07STEAMER\x10\x0e\x12\x08\n\x04HOOD\x10\x0f\x12\x0e\n\nSLOWCOOKER\x10\x10\x12\t\n\x05MIXER\x10\x11\x12\x0b\n\x07SCOOPER\x10\x12\x12\r\n\tMUFFINTIN\x10\x13\x12\x0e\n\nSALAMANDER\x10\x14\x12\x0b\n\x07PLANCHA\x10\x15\x12\x0b\n\x07NIA_OPS\x10\x16\x62\x06proto3')
)
_sym_db.RegisterFileDescriptor(DESCRIPTOR)

_FORTSPONSOR = _descriptor.EnumDescriptor(
  name='FortSponsor',
  full_name='pogoprotos.map.fort.FortSponsor',
  filename=None,
  file=DESCRIPTOR,
  values=[
    _descriptor.EnumValueDescriptor(
      name='UNSET_SPONSOR', index=0, number=0,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='MCDONALDS', index=1, number=1,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='POKEMON_STORE', index=2, number=2,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='TOHO', index=3, number=3,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='SOFTBANK', index=4, number=4,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='GLOBE', index=5, number=5,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='SPATULA', index=6, number=6,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='THERMOMETER', index=7, number=7,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='KNIFE', index=8, number=8,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='GRILL', index=9, number=9,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='SMOKER', index=10, number=10,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='PAN', index=11, number=11,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='BBQ', index=12, number=12,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='FRYER', index=13, number=13,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='STEAMER', index=14, number=14,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='HOOD', index=15, number=15,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='SLOWCOOKER', index=16, number=16,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='MIXER', index=17, number=17,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='SCOOPER', index=18, number=18,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='MUFFINTIN', index=19, number=19,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='SALAMANDER', index=20, number=20,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='PLANCHA', index=21, number=21,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='NIA_OPS', index=22, number=22,
      options=None,
      type=None),
  ],
  containing_type=None,
  options=None,
  serialized_start=64,
  serialized_end=378,
)
_sym_db.RegisterEnumDescriptor(_FORTSPONSOR)

FortSponsor = enum_type_wrapper.EnumTypeWrapper(_FORTSPONSOR)
UNSET_SPONSOR = 0
MCDONALDS = 1
POKEMON_STORE = 2
TOHO = 3
SOFTBANK = 4
GLOBE = 5
SPATULA = 6
THERMOMETER = 7
KNIFE = 8
GRILL = 9
SMOKER = 10
PAN = 11
BBQ = 12
FRYER = 13
STEAMER = 14
HOOD = 15
SLOWCOOKER = 16
MIXER = 17
SCOOPER = 18
MUFFINTIN = 19
SALAMANDER = 20
PLANCHA = 21
NIA_OPS = 22


DESCRIPTOR.enum_types_by_name['FortSponsor'] = _FORTSPONSOR


# @@protoc_insertion_point(module_scope)
