# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: pogoprotos/enums/activity_type.proto

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
  name='pogoprotos/enums/activity_type.proto',
  package='pogoprotos.enums',
  syntax='proto3',
  serialized_pb=_b('\n$pogoprotos/enums/activity_type.proto\x12\x10pogoprotos.enums*\xbf\x07\n\x0c\x41\x63tivityType\x12\x14\n\x10\x41\x43TIVITY_UNKNOWN\x10\x00\x12\x1a\n\x16\x41\x43TIVITY_CATCH_POKEMON\x10\x01\x12!\n\x1d\x41\x43TIVITY_CATCH_LEGEND_POKEMON\x10\x02\x12\x19\n\x15\x41\x43TIVITY_FLEE_POKEMON\x10\x03\x12\x18\n\x14\x41\x43TIVITY_DEFEAT_FORT\x10\x04\x12\x1b\n\x17\x41\x43TIVITY_EVOLVE_POKEMON\x10\x05\x12\x16\n\x12\x41\x43TIVITY_HATCH_EGG\x10\x06\x12\x14\n\x10\x41\x43TIVITY_WALK_KM\x10\x07\x12\x1e\n\x1a\x41\x43TIVITY_POKEDEX_ENTRY_NEW\x10\x08\x12\x1e\n\x1a\x41\x43TIVITY_CATCH_FIRST_THROW\x10\t\x12\x1d\n\x19\x41\x43TIVITY_CATCH_NICE_THROW\x10\n\x12\x1e\n\x1a\x41\x43TIVITY_CATCH_GREAT_THROW\x10\x0b\x12\"\n\x1e\x41\x43TIVITY_CATCH_EXCELLENT_THROW\x10\x0c\x12\x1c\n\x18\x41\x43TIVITY_CATCH_CURVEBALL\x10\r\x12%\n!ACTIVITY_CATCH_FIRST_CATCH_OF_DAY\x10\x0e\x12\x1c\n\x18\x41\x43TIVITY_CATCH_MILESTONE\x10\x0f\x12\x1a\n\x16\x41\x43TIVITY_TRAIN_POKEMON\x10\x10\x12\x18\n\x14\x41\x43TIVITY_SEARCH_FORT\x10\x11\x12\x1c\n\x18\x41\x43TIVITY_RELEASE_POKEMON\x10\x12\x12\"\n\x1e\x41\x43TIVITY_HATCH_EGG_SMALL_BONUS\x10\x13\x12#\n\x1f\x41\x43TIVITY_HATCH_EGG_MEDIUM_BONUS\x10\x14\x12\"\n\x1e\x41\x43TIVITY_HATCH_EGG_LARGE_BONUS\x10\x15\x12 \n\x1c\x41\x43TIVITY_DEFEAT_GYM_DEFENDER\x10\x16\x12\x1e\n\x1a\x41\x43TIVITY_DEFEAT_GYM_LEADER\x10\x17\x12+\n\'ACTIVITY_CATCH_FIRST_CATCH_STREAK_BONUS\x10\x18\x12)\n%ACTIVITY_SEARCH_FORT_FIRST_OF_THE_DAY\x10\x19\x12%\n!ACTIVITY_SEARCH_FORT_STREAK_BONUS\x10\x1a\x12 \n\x1c\x41\x43TIVITY_DEFEAT_RAID_POKEMON\x10\x1b\x12\x17\n\x13\x41\x43TIVITY_FEED_BERRY\x10\x1c\x12\x17\n\x13\x41\x43TIVITY_SEARCH_GYM\x10\x1d\x62\x06proto3')
)
_sym_db.RegisterFileDescriptor(DESCRIPTOR)

_ACTIVITYTYPE = _descriptor.EnumDescriptor(
  name='ActivityType',
  full_name='pogoprotos.enums.ActivityType',
  filename=None,
  file=DESCRIPTOR,
  values=[
    _descriptor.EnumValueDescriptor(
      name='ACTIVITY_UNKNOWN', index=0, number=0,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='ACTIVITY_CATCH_POKEMON', index=1, number=1,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='ACTIVITY_CATCH_LEGEND_POKEMON', index=2, number=2,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='ACTIVITY_FLEE_POKEMON', index=3, number=3,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='ACTIVITY_DEFEAT_FORT', index=4, number=4,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='ACTIVITY_EVOLVE_POKEMON', index=5, number=5,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='ACTIVITY_HATCH_EGG', index=6, number=6,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='ACTIVITY_WALK_KM', index=7, number=7,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='ACTIVITY_POKEDEX_ENTRY_NEW', index=8, number=8,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='ACTIVITY_CATCH_FIRST_THROW', index=9, number=9,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='ACTIVITY_CATCH_NICE_THROW', index=10, number=10,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='ACTIVITY_CATCH_GREAT_THROW', index=11, number=11,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='ACTIVITY_CATCH_EXCELLENT_THROW', index=12, number=12,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='ACTIVITY_CATCH_CURVEBALL', index=13, number=13,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='ACTIVITY_CATCH_FIRST_CATCH_OF_DAY', index=14, number=14,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='ACTIVITY_CATCH_MILESTONE', index=15, number=15,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='ACTIVITY_TRAIN_POKEMON', index=16, number=16,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='ACTIVITY_SEARCH_FORT', index=17, number=17,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='ACTIVITY_RELEASE_POKEMON', index=18, number=18,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='ACTIVITY_HATCH_EGG_SMALL_BONUS', index=19, number=19,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='ACTIVITY_HATCH_EGG_MEDIUM_BONUS', index=20, number=20,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='ACTIVITY_HATCH_EGG_LARGE_BONUS', index=21, number=21,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='ACTIVITY_DEFEAT_GYM_DEFENDER', index=22, number=22,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='ACTIVITY_DEFEAT_GYM_LEADER', index=23, number=23,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='ACTIVITY_CATCH_FIRST_CATCH_STREAK_BONUS', index=24, number=24,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='ACTIVITY_SEARCH_FORT_FIRST_OF_THE_DAY', index=25, number=25,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='ACTIVITY_SEARCH_FORT_STREAK_BONUS', index=26, number=26,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='ACTIVITY_DEFEAT_RAID_POKEMON', index=27, number=27,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='ACTIVITY_FEED_BERRY', index=28, number=28,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='ACTIVITY_SEARCH_GYM', index=29, number=29,
      options=None,
      type=None),
  ],
  containing_type=None,
  options=None,
  serialized_start=59,
  serialized_end=1018,
)
_sym_db.RegisterEnumDescriptor(_ACTIVITYTYPE)

ActivityType = enum_type_wrapper.EnumTypeWrapper(_ACTIVITYTYPE)
ACTIVITY_UNKNOWN = 0
ACTIVITY_CATCH_POKEMON = 1
ACTIVITY_CATCH_LEGEND_POKEMON = 2
ACTIVITY_FLEE_POKEMON = 3
ACTIVITY_DEFEAT_FORT = 4
ACTIVITY_EVOLVE_POKEMON = 5
ACTIVITY_HATCH_EGG = 6
ACTIVITY_WALK_KM = 7
ACTIVITY_POKEDEX_ENTRY_NEW = 8
ACTIVITY_CATCH_FIRST_THROW = 9
ACTIVITY_CATCH_NICE_THROW = 10
ACTIVITY_CATCH_GREAT_THROW = 11
ACTIVITY_CATCH_EXCELLENT_THROW = 12
ACTIVITY_CATCH_CURVEBALL = 13
ACTIVITY_CATCH_FIRST_CATCH_OF_DAY = 14
ACTIVITY_CATCH_MILESTONE = 15
ACTIVITY_TRAIN_POKEMON = 16
ACTIVITY_SEARCH_FORT = 17
ACTIVITY_RELEASE_POKEMON = 18
ACTIVITY_HATCH_EGG_SMALL_BONUS = 19
ACTIVITY_HATCH_EGG_MEDIUM_BONUS = 20
ACTIVITY_HATCH_EGG_LARGE_BONUS = 21
ACTIVITY_DEFEAT_GYM_DEFENDER = 22
ACTIVITY_DEFEAT_GYM_LEADER = 23
ACTIVITY_CATCH_FIRST_CATCH_STREAK_BONUS = 24
ACTIVITY_SEARCH_FORT_FIRST_OF_THE_DAY = 25
ACTIVITY_SEARCH_FORT_STREAK_BONUS = 26
ACTIVITY_DEFEAT_RAID_POKEMON = 27
ACTIVITY_FEED_BERRY = 28
ACTIVITY_SEARCH_GYM = 29


DESCRIPTOR.enum_types_by_name['ActivityType'] = _ACTIVITYTYPE


# @@protoc_insertion_point(module_scope)
