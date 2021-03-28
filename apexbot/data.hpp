#pragma once

#include <cstdint>

namespace data {
	const uint32_t TIME_DATE_STAMP = 0x6052a902;
	const uint32_t CHECKSUM = 0x1ff251d;

	const uint32_t GLOBAL_VARS = 0x1278220;

	const uint32_t ENTITY_LIST = 0x18da3d8;
	const uint32_t LOCAL_ENTITY = 0x1c89a38;

	const uint32_t CLIENT_STATE = 0x1278510;
	const uint32_t CLIENT_SIGNON_STATE = 0x12785a8;
	const uint32_t CLIENT_LEVEL_NAME = 0x12786c0;

	const uint32_t NST_WEAPON_NAMES = 0x0408e118;

	const uint32_t VIEW_RENDER = 0x408b8e8;
	const uint32_t VIEW_MATRIX = 0x1b3bd0;

	const uint32_t INPUT_SYSTEM = 0x012f0ec0;
	const uint32_t INPUT_BUTTON_STATE = 0xb0;

	const uint32_t NAME_LIST = 0x8133270;

	const uint32_t IN_ATTACK = 0x0408e230;
	const uint32_t IN_JUMP = 0x0408e2a8;
	const uint32_t IN_RELOAD = 0x0408e250;

	const uint32_t ENTITY_MODEL_NAME = 0x0030;
	const uint32_t ENTITY_FLAGS = 0x0098;
	const uint32_t ENTITY_ORIGIN = 0x014c;
	const uint32_t ENTITY_SHIELDS = 0x0170;
	const uint32_t ENTITY_HEALTH = 0x0420;
	const uint32_t ENTITY_TEAM_NUM = 0x0430;
	const uint32_t ENTITY_VELOCITY = 0x0464;
	const uint32_t ENTITY_MAX_HEALTH = 0x0558;
	const uint32_t ENTITY_SIGNIFIER_NAME = 0x0560;
	const uint32_t ENTITY_LIFE_STATE = 0x0798;

	const uint32_t ANIMATING_BONE_ARRAY = 0xF38;
	const uint32_t ANIMATING_STUDIOHDR = 0x1110;

	const uint32_t BCC_LATEST_PRIMARY_WEAPONS = 0x1a0c;
	const uint32_t BCC_LAST_VISIBLE_TIME = 0x1a6c;

	const uint32_t PLAYER_ZOOM_STATE = 0x1b80;
	const uint32_t PLAYER_CAMERA_DATA = 0x1e6c;
	const uint32_t PLAYER_BLEEDOUT_STATE = 0x25F0;
	const uint32_t PLAYER_OBSERVER_MODE = 0x32d4;
	const uint32_t PLAYER_HELMET_ARMOR_TYPE = 0x4294;

	const uint32_t WEAPONX_WEAPON_OWNER = 0x1600;
	const uint32_t WEAPONX_NEXT_PRIMARY_ATTACK = 0x160c;
	const uint32_t WEAPONX_AMMO_IN_CLIP = 0x1634;
	const uint32_t WEAPONX_PLAYER_DATA_ZOOM_FOV = 0x1668 + 0x00bc;
	const uint32_t WEAPONX_MOD_BITFIELD = 0x179c;
	const uint32_t WEAPONX_WEAPON_NAME_INDEX = 0x17b8;
	const uint32_t WEAPONX_PROJECTILE_SPEED = 0x1E50;

	const uint32_t VEHICLE_DRIVER = 0x1984;
	const uint32_t VEHICLE_VELOCITY = 0x19c0;

	const uint32_t PROP_SURVIVAL = 0x1604;
	const uint32_t WORLD_DEATH_FIELD = 0x0a80;
};
