/* radare - Copyright 2008-2018 - LGPL -- pancake */

#include <r_types.h>
#include <r_util.h>
#include <r_syscall.h>
#include <stdio.h>
#include <string.h>
#include "fastcall.h"

R_LIB_VERSION (r_syscall);

// TODO: now we use sdb
extern RSyscallPort sysport_x86[];
extern RSyscallPort sysport_avr[];

R_API RSyscall* r_syscall_ref(RSyscall *sc) {
	sc->refs++;
	return sc;
}

R_API RSyscall* r_syscall_new() {
	RSyscall *rs = R_NEW0 (RSyscall);
	if (rs) {
		rs->sysport = sysport_x86;
		rs->regs = fastcall_x86_32;
		rs->srdb = sdb_new0 (); // sysregs database
		rs->db = sdb_new0 ();
	}
	return rs;
}

R_API void r_syscall_free(RSyscall *s) {
	if (s) {
		if (s->refs > 0) {
			s->refs--;
			return;
		}
		sdb_free (s->srdb);
		sdb_free (s->db);
		free (s->os);
		free (s);
	}
}

/* return fastcall register argument 'idx' for a syscall with 'num' args */
R_API const char *r_syscall_reg(RSyscall *s, int idx, int num) {
	if (num < 0 || num >= R_SYSCALL_ARGS || idx < 0 || idx >= R_SYSCALL_ARGS) {
		return NULL;
	}
	return s->regs[num].arg[idx];
}

static Sdb *openDatabase(Sdb *db, const char *name) {
#define SYSCALLPATH "/share/radare2/" R2_VERSION
	const char *file = sdb_fmt (0, "%s/%s/%s.sdb",
		r_sys_prefix (NULL), SYSCALLPATH, name);
	if (!r_file_exists (file)) {
	//	eprintf ("r_syscall_setup: Cannot find '%s'\n", file);
		return false;
	}
	if (!db) {
		return sdb_new (0, file, 0);
	}
	sdb_reset (db);
	sdb_open (db, file);
	return db;
}

// TODO: should be renamed to r_syscall_use();
R_API bool r_syscall_setup(RSyscall *s, const char *arch, int bits, const char *cpu, const char *os) {
	if (!os || !*os) {
		os = R_SYS_OS;
	}
	if (!arch) {
		arch = R_SYS_ARCH;
	}
	free (s->os);
	s->os = strdup (os);

	if (!strcmp (os, "any")) { // ignored
		return true;
	}
	if (!strcmp (arch, "mips")) {
		s->regs = fastcall_mips;
	} else if (!strcmp (arch, "avr")) {
		s->sysport = sysport_avr;
	} else if (!strcmp (os, "osx") || !strcmp (os, "macos")) {
		os = "darwin";
	} else if (!strcmp (arch,"sh")) {
		s->regs = fastcall_sh;
	} else if (!strcmp (arch, "arm")) {
		switch (bits) {
		case 16:
		case 32:
			s->regs = fastcall_arm;
			break;
		case 64:
			s->regs = fastcall_arm64;
			break;
		}
	} else if (!strcmp (arch, "x86")) {
		s->sysport = sysport_x86;
		switch (bits) {
		case 8:
			s->regs = fastcall_x86_8;
			break;
		case 32:
			s->regs = fastcall_x86_32;
			break;
		case 64:
			s->regs = fastcall_x86_64;
			break;
		}
	}

	char *dbName = r_str_newf ("syscall/%s-%s-%d", os, arch, bits);
	s->db = openDatabase (s->db, dbName);
	free (dbName);

	dbName = r_str_newf ("sysregs/%s-%d-%s", arch, bits, cpu ? cpu: arch);
	sdb_free (s->srdb);
	s->srdb = openDatabase (s->srdb, dbName);
	free (dbName);
	if (s->fd) {
		fclose (s->fd);
		s->fd = NULL;
	}
	return true;
}

R_API RSyscallItem *r_syscall_item_new_from_string(const char *name, const char *s) {
	RSyscallItem *si;
	char *o;
	if (!name || !s) {
		return NULL;
	}
	o = strdup (s);
	int cols = r_str_split (o, ',');
	if (cols < 3) {
		free (o);
		return NULL;
	}

	si = R_NEW0 (RSyscallItem);
	if (!si) {
		return NULL;
	}
	si->name = strdup (name);
	si->swi = (int)r_num_get (NULL, r_str_word_get0 (o, 0));
	si->num = (int)r_num_get (NULL, r_str_word_get0 (o, 1));
	si->args = (int)r_num_get (NULL, r_str_word_get0 (o, 2));
	//in a definition such as syscall=0x80,0,4,
	//the string at index 3 is 0 causing oob read afterwards
	si->sargs = calloc (si->args + 1, sizeof (char));
	if (!si->sargs) {
		free (si);
		free (o);
		return NULL;
	}
	strncpy (si->sargs, r_str_word_get0 (o, 3), si->args);
	free (o);
	return si;
}

R_API void r_syscall_item_free(RSyscallItem *si) {
	if (!si) {
		return;
	}
	free (si->name);
	free (si->sargs);
	free (si);
}

static int getswi(RSyscall *s, int swi) {
	if (s && swi == -1) {
		return r_syscall_get_swi (s);
	}
	return swi;
}

R_API int r_syscall_get_swi(RSyscall *s) {
	return (int)sdb_array_get_num (s->db, "_", 0, NULL);
}

R_API RSyscallItem *r_syscall_get(RSyscall *s, int num, int swi) {
	const char *ret, *ret2, *key;
	if (!s || !s->db) {
		eprintf ("Syscall database not loaded\n");
		return NULL;
	}
	swi = getswi (s, swi);
	if (swi < 16) {
		key = sdb_fmt (0, "%d.%d", swi, num);
	} else {
		key = sdb_fmt (0, "0x%02x.%d", swi, num);
	}
	ret = sdb_const_get (s->db, key, 0);
	if (!ret) {
		key = sdb_fmt (0, "0x%02x.0x%02x", swi, num); // Workaround until Syscall SDB is fixed 
		ret = sdb_const_get (s->db, key, 0);
		if (!ret) {
			return NULL;
		}	
	}
	ret2 = sdb_const_get (s->db, ret, 0);
	if (!ret2) {
		return NULL;
	}
	return r_syscall_item_new_from_string (ret, ret2);
}

R_API int r_syscall_get_num(RSyscall *s, const char *str) {
	if (!s || !s->db) {
		return -1;
	}
	return (int)sdb_array_get_num (s->db, str, 1, NULL);
}

R_API const char *r_syscall_get_i(RSyscall *s, int num, int swi) {
	char foo[32];
	if (!s || !s->db) {
		return NULL;
	}
	swi = getswi (s, swi);
	snprintf (foo, sizeof (foo), "0x%x.%d", swi, num);
	return sdb_const_get (s->db, foo, 0);
}

static int callback_list(void *u, const char *k, const char *v) {
	RList *list = (RList*)u;
	if (!strchr (k, '.')) {
		RSyscallItem *si = r_syscall_item_new_from_string (k, v);
		if (!si) {
			return 1;
		}
		if (!strchr (si->name, '.')) {
			r_list_append (list, si);
		}
	}
	return 1; // continue loop
}

R_API RList *r_syscall_list(RSyscall *s) {
	RList *list;
	if (!s || !s->db) {
		return NULL;
	}
	// show list of syscalls to stdout
	list = r_list_newf ((RListFree)r_syscall_item_free);
	sdb_foreach (s->db, callback_list, list);
	return list;
}

/* io and sysregs */
R_API const char *r_syscall_get_io(RSyscall *s, int ioport) {
	int i;
	if (!s) {
		return NULL;
	}
	const char *name = r_syscall_sysreg (s, "io", ioport);
	if (name) {
		return name;
	}
	for (i = 0; s->sysport[i].name; i++) {
		if (ioport == s->sysport[i].port) {
			return s->sysport[i].name;
		}
	}
	return NULL;
}

R_API const char* r_syscall_sysreg(RSyscall *s, const char *type, ut64 num) {
	if (!s || !s->db) {
		return NULL;
	}
	const char *key = sdb_fmt (0, "%s,%"PFMT64d, type, num);
	return sdb_const_get (s->db, key, 0);
}
