/* radare - LGPL - Copyright 2017 - Oscar Salvador */

#include <r_debug.h>
#include <r_list.h>
#include <r_core.h>

#define MMAP_SIZE	4096 * 2
#define ADDITIONAL_SIZE	4096


R_API bool r_debug_env_sync (RDebug *dbg) {
	bool ret = false;
	const char *regname = r_reg_get_name (dbg->reg, R_REG_NAME_SP);
	RRegItem *r = r_reg_get (dbg->reg, regname, -1);
	ut64 sp_addr = r_reg_get_value (dbg->reg, r);

	r_debug_map_sync (dbg);
        RDebugMap *map = r_debug_map_get (dbg, sp_addr);
	if (map && dbg->h->env_get) {
		RDebugEnvTrack *p = dbg->h->env_get (dbg, map->addr_end, map->addr);
		if (p) {
			RCore* core = dbg->corebind.core;
			char *orig_addr = dbg->corebind.cmdstr (core, "s");
			dbg->corebind.cmdstrf (core, "s 0x%lx", map->addr_end - 1);
			RDebugEnv *env;
			RListIter *iter;

			r_list_foreach (p->envs, iter, env) {
				char *aux = dbg->corebind.cmdstrf (core, "/b %s=", env->key);
				char *addr_name = strtok (aux, " ");
				char conv[18] = {0};
				int i;
				ut64 addr_pointer;
				{
					char *p = addr_name + 2;
					int j = strlen (p);
					int leaps = j / 2;
					int z;
					for (z = 0, i = 0; z < leaps; i += 2, z++) {
						conv[i] = p[j - 2];
						conv[i + 1] = p[j - 1];
						j -= 2;
					}
				}
				conv[i] = '\0';
				aux = dbg->corebind.cmdstrf (core, "/bx %s", conv);
				sscanf (aux, "%lx", &addr_pointer);
				env->addr = addr_pointer;
			}

			dbg->env = p;
			ret = true;
			dbg->corebind.cmdstrf (core, "s %s", orig_addr);
		}
	}
        return ret;
}


R_API void r_debug_print_env (RDebug *dbg, bool long_output) {
	RDebugEnvTrack *envs = dbg->env;
	RDebugEnv *env;
	RListIter *iter;
	r_list_foreach (envs->envs, iter, env) {
		eprintf ("%s=%s%s", env->key, env->value ? env->value : "", long_output ? "" : "\n");
		if (long_output) {
			eprintf (" [0x%lx - (modified? %c)]\n",
							env->addr,
							env->modified ? 'y' : 'n');
		}
	}
	eprintf ("n_envs_vars: %d\n", envs->n_env_vars);
}

static RDebugEnv *get_env_by_name (RDebugEnvTrack *envs, const char *name) {
	RDebugEnv *env;
	RListIter *iter;

	r_list_foreach (envs->envs, iter, env) {
		if (!strcmp (env->key, name)) {
			return env;
		}
	}
	return NULL;
}

R_API bool r_debug_env_name_get (RDebug *dbg, const char *name, bool long_output) {
	RDebugEnvTrack *envs = dbg->env;
	RDebugEnv *env;

	eprintf ("r_debug_env_name_get: name: %s, %s\n", name, long_output ? "true" : "false");
	env = get_env_by_name (envs, name);
	if (env) {
		eprintf ("%s=%s%s", env->key, env->value, long_output ? "" : "\n");
		if (long_output) {
			eprintf (" [0x%lx - (modified? %c)]\n",
							env->addr,
							env->modified ? 'y' : 'n');
		}
	}
	return true;
}

static RDebugEnvMap* init_env_map (void) {
	RDebugEnvMap *env_map = R_NEW0 (RDebugEnvMap);
	if (env_map) {
		env_map->bytes_left = MMAP_SIZE;
		env_map->current_pos = 0;
		env_map->map = NULL;
	}
	return env_map;
}

static bool write_at_new_map(RDebug *dbg, RDebugEnv *env, char *name, char *val) {
	RDebugMap *map = dbg->h->map_alloc (dbg, -1, MMAP_SIZE);
	if (!map) {
		return false;
	}

	RDebugEnvMap *env_map = init_env_map ();
	char *str = r_str_newf ("%s=%s", name, val);
	int len = strlen (str);
	ut8 *buf = (ut8 *)malloc(12);

	r_write_le64 (buf, map->addr);
	dbg->iob.write_at (dbg->iob.io, map->addr, str, len);

	eprintf ("r_debug_env_name_set: env->addr: 0x%lx\n", env->addr);
	eprintf ("r_debug_env_name_set: map->addr: 0x%lx\n", map->addr);

	dbg->iob.write_at (dbg->iob.io, env->addr, buf, 12);
	env->addr = map->addr;
	if (env->value) {
		free (env->value);
	}
	env->value = strdup (val);

	env->pos_map = 0;
	env_map->bytes_left -= len;
	env_map->current_pos += len;
	env->map = env_map->map = map;
	r_list_append (dbg->env->env_maps, env_map);
	dbg->env->current_map = env_map;

	free (str);
	free (buf);

	return true;
}

static RDebugEnvMap *get_best_fitting_map(RDebug *dbg, int len)
{
	RDebugEnvTrack *envs = dbg->env;
	RDebugEnvMap *env_map;
	RDebugEnvMap *best_env_map = NULL;
	RListIter *iter;
	int bytes_left = 0;

		r_list_foreach (envs->env_maps, iter, env_map) {
			if (env_map->bytes_left >= len + 1) {
				if (env_map->bytes_left < bytes_left) {
					best_env_map = env_map;
					bytes_left = env_map->bytes_left;
				}
			}
		}

	return best_env_map;
}

R_API bool r_debug_env_name_set(RDebug *dbg, const char *name, const char *val) {
	RDebugEnvTrack *envs = dbg->env;
	RDebugEnv *env;
	bool found = false;
	bool ret = false;

	eprintf ("r_debug_env_name_set: %s=%s\n", name, val);

	if (dbg->h && dbg->h->map_alloc) {
		env = get_env_by_name (envs, name);
		if (env) {
			if (!envs->current_map) {
				ret = write_at_new_map (dbg, env, name, val);
			} else if (!env->modified) {
				int len = strlen (name) + strlen(val) + 1;
				RDebugEnvMap *map = get_best_fitting_map (dbg, len);

				if (map) {
					char *str = r_str_newf ("%s=%s", name, val);
					int len = strlen (str);
					dbg->iob.write_at (dbg->iob.io, map->current_pos, str, len);
					env->pos_map = map->current_pos;
					map->bytes_left -= len;
					map->current_pos += len;
				} else {
					ret = write_at_new_map (dbg, env, name, val);
				}	
			} else {
				// env has been modified
				int new_env_len = strlen (name) + strlen(val) + 1;
				int cur_env_len = strlen (env->key) + strlen (env->value) + 1;
				char *str = r_str_newf ("%s=%s", name, val);
				RDebugEnvMap *env_map = env->map;
				RDebugMap *map = env_map->map;
				
				ut64 offset = env->pos_map;
				char *zero = calloc (MMAP_SIZE - offset, 1);

				RBuffer *buf = r_io_read_buf (dbg->iob.io,
									map->addr + offset + cur_env_len,
									MMAP_SIZE - offset - cur_env_len);
				dbg->iob.write_at (dbg->iob.io, map->addr + offset, zero, MMAP_SIZE - offset);

				if (new_env_len < cur_env_len) {
					dbg->iob.write_at (dbg->iob.io, map->addr + offset, str, new_env_len);
					dbg->iob.write_at (dbg->iob.io,
									map->addr + offset + new_env_len + 1,
									buf->buf, buf->length);
					env_map->bytes_left += cur_env_len - new_env_len;
					env_map->current_pos -= cur_env_len - new_env_len;
				} else {
					if (new_env_len > env_map->bytes_left) {
						// We do not need to call init_env_map()
						ret = write_at_new_map (dbg, env, name, val);
					} else {
						dbg->iob.write_at (dbg->iob.io, map->addr + offset, buf->buf, buf->length);
						dbg->iob.write_at (dbg->iob.io,
										map->addr + offset + buf->length,
										str, new_env_len);
						env_map->bytes_left -= new_env_len - cur_env_len;
						env_map->current_pos += new_env_len - cur_env_len;
						env->pos_map = env_map->current_pos -= new_env_len;
					}
				}
			}
			env->modified = true;
		} else {
			eprintf ("r_debug_env_name_set: No environment with the name %s found\n", name);
		}
	} else {
		eprintf ("r_debug_env_name_set: Cannot allocate a map\n");
	}
	return true;
}
