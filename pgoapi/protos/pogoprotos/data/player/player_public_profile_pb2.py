# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: pogoprotos/data/player/player_public_profile.proto

import sys
_b=sys.version_info[0]<3 and (lambda x:x) or (lambda x:x.encode('latin1'))
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
from google.protobuf import descriptor_pb2
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()


from pogoprotos.data.player import player_avatar_pb2 as pogoprotos_dot_data_dot_player_dot_player__avatar__pb2
from pogoprotos.enums import team_color_pb2 as pogoprotos_dot_enums_dot_team__color__pb2


DESCRIPTOR = _descriptor.FileDescriptor(
  name='pogoprotos/data/player/player_public_profile.proto',
  package='pogoprotos.data.player',
  syntax='proto3',
  serialized_pb=_b('\n2pogoprotos/data/player/player_public_profile.proto\x12\x16pogoprotos.data.player\x1a*pogoprotos/data/player/player_avatar.proto\x1a!pogoprotos/enums/team_color.proto\"\x99\x01\n\x13PlayerPublicProfile\x12\x0c\n\x04name\x18\x01 \x01(\t\x12\r\n\x05level\x18\x02 \x01(\x05\x12\x34\n\x06\x61vatar\x18\x03 \x01(\x0b\x32$.pogoprotos.data.player.PlayerAvatar\x12/\n\nteam_color\x18\x04 \x01(\x0e\x32\x1b.pogoprotos.enums.TeamColorb\x06proto3')
  ,
  dependencies=[pogoprotos_dot_data_dot_player_dot_player__avatar__pb2.DESCRIPTOR,pogoprotos_dot_enums_dot_team__color__pb2.DESCRIPTOR,])
_sym_db.RegisterFileDescriptor(DESCRIPTOR)




_PLAYERPUBLICPROFILE = _descriptor.Descriptor(
  name='PlayerPublicProfile',
  full_name='pogoprotos.data.player.PlayerPublicProfile',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='name', full_name='pogoprotos.data.player.PlayerPublicProfile.name', index=0,
      number=1, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='level', full_name='pogoprotos.data.player.PlayerPublicProfile.level', index=1,
      number=2, type=5, cpp_type=1, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='avatar', full_name='pogoprotos.data.player.PlayerPublicProfile.avatar', index=2,
      number=3, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='team_color', full_name='pogoprotos.data.player.PlayerPublicProfile.team_color', index=3,
      number=4, type=14, cpp_type=8, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=158,
  serialized_end=311,
)

_PLAYERPUBLICPROFILE.fields_by_name['avatar'].message_type = pogoprotos_dot_data_dot_player_dot_player__avatar__pb2._PLAYERAVATAR
_PLAYERPUBLICPROFILE.fields_by_name['team_color'].enum_type = pogoprotos_dot_enums_dot_team__color__pb2._TEAMCOLOR
DESCRIPTOR.message_types_by_name['PlayerPublicProfile'] = _PLAYERPUBLICPROFILE

PlayerPublicProfile = _reflection.GeneratedProtocolMessageType('PlayerPublicProfile', (_message.Message,), dict(
  DESCRIPTOR = _PLAYERPUBLICPROFILE,
  __module__ = 'pogoprotos.data.player.player_public_profile_pb2'
  # @@protoc_insertion_point(class_scope:pogoprotos.data.player.PlayerPublicProfile)
  ))
_sym_db.RegisterMessage(PlayerPublicProfile)


# @@protoc_insertion_point(module_scope)
