#include <lua.h>
#include <lauxlib.h>
#include <stdlib.h>

#include "xxtea.h"

static int encrypt( lua_State* L )
{
	size_t len;
	const char* data = luaL_checklstring(L, 1, &len);
    size_t key_len;
	const char* key = luaL_checklstring(L, 2, &key_len);

    xxtea_long ret_length = 0;
    unsigned char* buf = xxtea_encrypt((unsigned char* )data, (xxtea_long)len, (unsigned char* )key, (xxtea_long)key_len, &ret_length);

	lua_pushlstring(L, (const char*)buf, (size_t)ret_length);
	free(buf);
	return 1;
}

static int decrypt( lua_State* L ){
    size_t len;
	const char* data = luaL_checklstring(L, 1, &len);
    size_t key_len;
	const char* key = luaL_checklstring(L, 2, &key_len);

    xxtea_long ret_length = 0;
    unsigned char* buf = xxtea_decrypt((unsigned char* )data, (xxtea_long)len, (unsigned char* )key, (xxtea_long)key_len, &ret_length);

	lua_pushlstring(L, (const char*)buf, (size_t)ret_length);
	free(buf);
	return 1;
}

static const luaL_Reg apis[] =
{
	{"encrypt", encrypt},
	{"decrypt", decrypt},
	{NULL, NULL}
};

LUALIB_API int luaopen_cctea( lua_State *L )
{
    lua_newtable(L);

#if LUA_VERSION_NUM >= 502 // LUA 5.2 or above
	luaL_setfuncs(L, apis, 0);
#else
	luaL_register(L, NULL, apis);
#endif
    return 1;
}
