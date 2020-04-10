/* Copyright (C) 2001, 2002, 2003, 2005, 2007, 2009, 2010 Red Hat, Inc.
	 Written by Alexander Larsson <alexl@redhat.com>, 2002
	 Based on code by Jakub Jelinek <jakub@redhat.com>, 2001.

	 This program is free software; you can redistribute it and/or modify
	 it under the terms of the GNU General Public License as published by
	 the Free Software Foundation; either version 2, or (at your option)
	 any later version.

	 This program is distributed in the hope that it will be useful,
	 but WITHOUT ANY WARRANTY; without even the implied warranty of
	 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	 GNU General Public License for more details.

	 You should have received a copy of the GNU General Public License
	 along with this program; if not, write to the Free Software Foundation,
	 Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.  */


/* Needed for libelf */
#define _FILE_OFFSET_BITS 64

#include <assert.h>
#if defined(__linux__)
#include <byteswap.h>
#include <endian.h>
#endif
#include <errno.h>
#if !defined(__FreeBSD__)
#include <error.h>
#else
#include <err.h>
#define error(x, y, format, args...) errx(1, format, ## args)
#endif
#include <limits.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <popt.h>

#include <gelf.h>
#include <sys/elf_common.h>
#include "dwarf.h"
#include "hashtab.h"

#define DW_TAG_partial_unit 0x3c
#define DW_FORM_sec_offset 0x17
#define DW_FORM_exprloc 0x18
#define DW_FORM_flag_present 0x19
#define DW_FORM_ref_sig8 0x20

#if !defined(R_390_32)
#define R_390_32 0x04
#endif
#if !defined(R_IA64_SECREL32LSB)
#define R_IA64_SECREL32LSB 0x65
#endif

char *base_dir = NULL;
char *dest_dir = NULL;
char *list_file = NULL;
int win_path = 0;
int list_file_fd = -1;
int use_newline = 0;
int list_only_files = 0;
FILE *debug_fd;
int be_quiet = 0;

typedef struct
{
	Elf *elf;
	GElf_Ehdr ehdr;
	Elf_Scn **scn;
	const char *filename;
	int lastscn;
	GElf_Shdr shdr[0];
} DSO;

typedef struct
{
	unsigned char *ptr;
	uint32_t addend;
} REL;

#define read_uleb128(ptr) ({        \
		unsigned int ret = 0;            \
		unsigned int c;            \
		int shift = 0;            \
		do                    \
		{                    \
		c = *ptr++;            \
		ret |= (c & 0x7f) << shift;    \
		shift += 7;            \
		} while (c & 0x80);            \
		\
		if (shift >= 35)            \
		ret = UINT_MAX;            \
		ret;                    \
		})
	static inline uint16_t
buf_read_ule16 (unsigned char *data)
{
	return data[0] | (data[1] << 8);
}

	static inline uint16_t
buf_read_ube16 (unsigned char *data)
{
	return data[1] | (data[0] << 8);
}

	static inline uint32_t
buf_read_ule32 (unsigned char *data)
{
	return data[0] | (data[1] << 8) | (data[2] << 16) | (data[3] << 24);
}

	static inline uint32_t
buf_read_ube32 (unsigned char *data)
{
	return data[3] | (data[2] << 8) | (data[1] << 16) | (data[0] << 24);
}

	static const char *
strptr (DSO *dso, int sec, off_t offset)
{
	Elf_Scn *scn;
	Elf_Data *data;

	scn = dso->scn[sec];
	if (offset >= 0 && (GElf_Addr) offset < dso->shdr[sec].sh_size)
	{
		data = NULL;
		while ((data = elf_getdata (scn, data)) != NULL)
		{
			if (data->d_buf
					&& offset >= data->d_off
					&& offset < data->d_off + data->d_size)
				return (const char *) data->d_buf + (offset - data->d_off);
		}
	}

	return NULL;
}


#define read_1(ptr) *ptr++

#define read_16(ptr) ({                    \
		uint16_t ret = do_read_16 (ptr);            \
		ptr += 2;                        \
		ret;                            \
		})

#define read_32(ptr) ({                    \
		uint32_t ret = do_read_32 (ptr);            \
		ptr += 4;                        \
		ret;                            \
		})

REL *relptr, *relend;
int reltype;

#define do_read_32_relocated(ptr) ({            \
		uint32_t dret = do_read_32 (ptr);            \
		if (relptr)                        \
		{                            \
		while (relptr < relend && relptr->ptr < ptr)    \
		++relptr;                    \
		if (relptr < relend && relptr->ptr == ptr)    \
		{                        \
		if (reltype == SHT_REL)            \
		dret += relptr->addend;            \
		else                        \
		dret = relptr->addend;            \
		}                        \
		}                            \
		dret;                            \
		})

#define read_32_relocated(ptr) ({            \
		uint32_t ret = do_read_32_relocated (ptr);        \
		ptr += 4;                        \
		ret;                            \
		})
static struct
{
	const char *name;
	unsigned char *data;
	Elf_Data *elf_data;
	size_t size;
	int sec, relsec;
} debug_sections[] =
{
#define DEBUG_INFO    0
#define DEBUG_ABBREV    1
#define DEBUG_LINE    2
#define DEBUG_ARANGES    3
#define DEBUG_PUBNAMES    4
#define DEBUG_PUBTYPES    5
#define DEBUG_MACINFO    6
#define DEBUG_LOC    7
#define DEBUG_STR    8
#define DEBUG_FRAME    9
#define DEBUG_RANGES    10
#define DEBUG_TYPES    11
#define DEBUG_MACRO    12
#define DEBUG_GDB_SCRIPT    13
#define DEBUG_SYMTAB    14
#define DEBUG_STRTAB    15
#define DEBUG_DYNSYMTAB    16

	{ ".debug_info", NULL, NULL, 0, 0, 0 },
	{ ".debug_abbrev", NULL, NULL, 0, 0, 0 },
	{ ".debug_line", NULL, NULL, 0, 0, 0 },
	{ ".debug_aranges", NULL, NULL, 0, 0, 0 },
	{ ".debug_pubnames", NULL, NULL, 0, 0, 0 },
	{ ".debug_pubtypes", NULL, NULL, 0, 0, 0 },
	{ ".debug_macinfo", NULL, NULL, 0, 0, 0 },
	{ ".debug_loc", NULL, NULL, 0, 0, 0 },
	{ ".debug_str", NULL, NULL, 0, 0, 0 },
	{ ".debug_frame", NULL, NULL, 0, 0, 0 },
	{ ".debug_ranges", NULL, NULL, 0, 0, 0 },
	{ ".debug_types", NULL, NULL, 0, 0, 0 },
	{ ".debug_macro", NULL, NULL, 0, 0, 0 },
	{ ".debug_gdb_scripts", NULL, NULL, 0, 0, 0 },
	{ ".symtab", NULL, NULL, 0, 0, 0 },
	{ ".strtab", NULL, NULL, 0, 0, 0 },
	{ ".dynsym", NULL, NULL, 0, 0, 0 },
	{ NULL, NULL, NULL, 0, 0, 0 }
};

#define IS_DIR_SEPARATOR(c) ((c)=='/')

void make_win_path(char * path)
{
	int k = 0;
	while (path[k] != '\0')
	{
		if (path[k] == '/') path[k] = '\\';
		k++;
	}
}
void make_string_obfuscation(char * s)
{
	int k = 0;
	while (s[k] != '\0')
	{
		s[k] = 'x';
		k++;
	}
}


#define LST_FILE 0
#define LST_DIR 1
	static void
edit_symtab (DSO *dso, Elf_Data *data)
{
	GElf_Sym sym;
	GElf_Shdr shdr;
	unsigned long stridx = -1;
	int i;
	char *s;
	int sec = debug_sections[DEBUG_SYMTAB].sec;
	Elf_Data *strtab_data;
	gelf_getshdr(dso->scn[sec], &shdr);

	stridx = shdr.sh_link;

	strtab_data = elf_getdata(dso->scn[stridx], NULL);

	i = 0;
	while (gelf_getsym(data, i++, &sym) != NULL) 
	{
		s = elf_strptr(dso->elf, stridx, sym.st_name);

		if (GELF_ST_TYPE(sym.st_info) == STT_FILE)
		{
			fprintf(debug_fd, "file %s\n", s);
			fprintf(debug_fd, "obfuscate symbol file %s\n", s);
			make_string_obfuscation(s);
			elf_flagdata (strtab_data, ELF_C_SET, ELF_F_DIRTY);
		}
		else
		{
			fprintf(debug_fd, "obfuscate symbol %s\n", s);
			make_string_obfuscation(s);
			elf_flagdata (strtab_data, ELF_C_SET, ELF_F_DIRTY);
		}
	}
}

	static void
edit_dynsymtab (DSO *dso, Elf_Data *data)
{
	GElf_Sym sym;
	GElf_Shdr shdr;
	unsigned long stridx = -1;
	int i;
	char *s;
	int sec = debug_sections[DEBUG_DYNSYMTAB].sec;
	Elf_Data *strtab_data;
	gelf_getshdr(dso->scn[sec], &shdr);

	stridx = shdr.sh_link;

	strtab_data = elf_getdata(dso->scn[stridx], NULL);

	i = 0;
	while (gelf_getsym(data, i++, &sym) != NULL) 
	{
		s = elf_strptr(dso->elf, stridx, sym.st_name);

		if (GELF_ST_TYPE(sym.st_info) == STT_FILE)
		{
			fprintf(debug_fd, "file %s\n", s);
			fprintf(debug_fd, "obfuscate dynamic symbol file %s\n", s);
			make_string_obfuscation(s);
			elf_flagdata (strtab_data, ELF_C_SET, ELF_F_DIRTY);
		}
		else
		{
			fprintf(debug_fd, "obfuscate dynamic symbol %s\n", s);
			make_string_obfuscation(s);
			elf_flagdata (strtab_data, ELF_C_SET, ELF_F_DIRTY);
		}
	}
}

static void edit_debugstr (DSO *dso, Elf_Data *data)
{
	off_t offset = data->d_off;
	size_t size = data->d_size;
	size_t consume_size = 0;
	while (consume_size < size) {
		char *strptr = (char *)data->d_buf + offset + consume_size;
		fprintf(debug_fd, "debug string: current string %s, consume size %ld size %ld\n", strptr, consume_size, size);
		make_string_obfuscation(strptr);
		consume_size += strlen(strptr) + 1;
	}
	elf_flagdata (data, ELF_C_SET, ELF_F_DIRTY);
}

static struct poptOption optionsTable[] =
{
	{
		"base-dir",  'b', POPT_ARG_STRING, &base_dir, 0,
		"base build directory of objects", NULL
	},
	{
		"dest-dir",  'd', POPT_ARG_STRING, &dest_dir, 0,
		"directory to rewrite base-dir into", NULL
	},
	{
		"list-file", 'l', POPT_ARG_STRING, &list_file, 0,
		"file where to put list of source and header file names", NULL
	},
	{
		"win-path",  'w', POPT_ARG_NONE, &win_path, 0,
		"change the path delimiter to be Windows compatible", NULL
	},
	{
		"use-newline",  'n', POPT_ARG_NONE, &use_newline, 0,
		"separate strings in the list file with \\n, not \\0", NULL
	},
	{
		"files-only", 'f', POPT_ARG_NONE, &list_only_files, 0,
		"do not include directories into the list file", NULL
	},
	{
		"quiet", 'q', POPT_ARG_NONE, &be_quiet, 0,
		"quiet mode, do  not write anything to standard output", NULL
	},
	POPT_AUTOHELP
	{ NULL, 0, 0, NULL, 0, NULL, NULL }
};

	static DSO *
fdopen_dso (int fd, const char *name, int readonly)
{
	Elf *elf = NULL;
	GElf_Ehdr ehdr;
	int i;
	DSO *dso = NULL;

	elf = elf_begin (fd, (readonly == 0) ? ELF_C_RDWR : ELF_C_READ, NULL);
	if (elf == NULL)
	{
		error (0, 0, "cannot open ELF file: %s", elf_errmsg (-1));
		goto error_out;
	}

	if (elf_kind (elf) != ELF_K_ELF)
	{
		error (0, 0, "\"%s\" is not an ELF file", name);
		goto error_out;
	}

	if (gelf_getehdr (elf, &ehdr) == NULL)
	{
		error (0, 0, "cannot get the ELF header: %s",
				elf_errmsg (-1));
		goto error_out;
	}

	if (ehdr.e_type != ET_DYN && ehdr.e_type != ET_EXEC && ehdr.e_type != ET_REL)
	{
		error (0, 0, "\"%s\" is not a shared library", name);
		goto error_out;
	}

	/* Allocate DSO structure. Leave place for additional 20 new section
		 headers.  */
	dso = (DSO *)
		malloc (sizeof(DSO) + (ehdr.e_shnum + 20) * sizeof(GElf_Shdr)
				+ (ehdr.e_shnum + 20) * sizeof(Elf_Scn *));
	if (!dso)
	{
		error (0, ENOMEM, "Could not open DSO");
		goto error_out;
	}

	elf_flagelf (elf, ELF_C_SET, ELF_F_LAYOUT);

	memset (dso, 0, sizeof(DSO));
	dso->elf = elf;
	dso->ehdr = ehdr;
	dso->scn = (Elf_Scn **) &dso->shdr[ehdr.e_shnum + 20];

	for (i = 0; i < ehdr.e_shnum; ++i)
	{
		dso->scn[i] = elf_getscn (elf, i);
		gelf_getshdr (dso->scn[i], dso->shdr + i);
	}

	dso->filename = (const char *) strdup (name);
	return dso;

error_out:
	if (dso)
	{
		free ((char *) dso->filename);
		free (dso);
	}
	if (elf)
		elf_end (elf);
	if (fd != -1)
		close (fd);
	return NULL;
}

	int
main (int argc, char *argv[])
{
	DSO *dso;
	int fd, i, readonly;
	const char *file;
	poptContext optCon;   /* context for parsing command-line options */
	int nextopt;
	const char **args;
	struct stat stat_buf;

	debug_fd = stdout;
	optCon = poptGetContext("debugedit", argc, (const char **)argv, optionsTable, 0);

	while ((nextopt = poptGetNextOpt (optCon)) > 0 || nextopt == POPT_ERROR_BADOPT)
		/* do nothing */ ;

	if (nextopt != -1)
	{
		fprintf (stderr, "Error on option %s: %s.\nRun '%s --help' to see a full list of available command line options.\n",
				poptBadOption (optCon, 0),
				poptStrerror (nextopt),
				argv[0]);
		exit (1);
	}

	args = poptGetArgs (optCon);
	if (args == NULL || args[0] == NULL || args[1] != NULL)
	{
		poptPrintHelp(optCon, stdout, 0);
		exit (1);
	}

	if (be_quiet != 0)
	{
		debug_fd = fopen("/dev/null", "w");
		if (debug_fd == NULL)
		{
			fprintf (stderr, "Can't open /dev/null\n");
			exit (1);
		}
	}

	file = args[0];

	if (elf_version(EV_CURRENT) == EV_NONE)
	{
		fprintf (stderr, "library out of date\n");
		exit (1);
	}

	if (stat(file, &stat_buf) < 0)
	{
		fprintf (stderr, "Failed to open input file '%s': %s\n", file, strerror(errno));
		exit (1);
	}

	/* Make sure we can read and write */
	readonly = 0;

	if (readonly == 0)
		chmod (file, stat_buf.st_mode | S_IRUSR | S_IWUSR);

	fd = open (file, (readonly == 0) ? O_RDWR : O_RDONLY);
	if (fd < 0)
	{
		fprintf (stderr, "Failed to open input file '%s': %s\n", file, strerror(errno));
		exit (1);
	}

	dso = fdopen_dso (fd, file, readonly);
	if (dso == NULL)
		exit (1);

	for (i = 0; debug_sections[i].name; ++i)
	{
		debug_sections[i].data = NULL;
		debug_sections[i].size = 0;
		debug_sections[i].sec = 0;
		debug_sections[i].relsec = 0;
	}

	for (i = 1; i < dso->ehdr.e_shnum; i++)
	{
    Elf_Data *data;
    Elf_Scn *scn;

		const char *name;
		name = strptr (dso, dso->ehdr.e_shstrndx, dso->shdr[i].sh_name);

		//fprintf (debug_fd, "sh:%d, sh_type: %d, sh_name: %s\n", i, dso->shdr[i].sh_type, name);
		if (strncmp (name, ".debug_str", sizeof (".debug_str") - 1) == 0)
		{
			scn = dso->scn[i];
			data = elf_getdata (scn, NULL);
			debug_sections[DEBUG_STR].data = data->d_buf;
			debug_sections[DEBUG_STR].elf_data = data;
			debug_sections[DEBUG_STR].size = data->d_size;
			debug_sections[DEBUG_STR].sec = i;
			fprintf(debug_fd, "Record debug string section %d name %s data size %ld\n", i, name, data->d_size);
			edit_debugstr(dso, data);
		}
		else if (strncmp (name, ".symtab", sizeof (".symtab") - 1) == 0)
		{
			//fprintf(debug_fd, "########.symtab sec %d\n", i);
			scn = dso->scn[i];
			data = elf_getdata (scn, NULL);
			debug_sections[DEBUG_SYMTAB].data = data->d_buf;
			debug_sections[DEBUG_SYMTAB].elf_data = data;
			debug_sections[DEBUG_SYMTAB].size = data->d_size;
			debug_sections[DEBUG_SYMTAB].sec = i;
			fprintf(debug_fd, "Record symbol section %d name %s data size %ld\n", i, name, data->d_size);

			edit_symtab(dso, data);
		}
		else if (strncmp(name, ".dynsym", sizeof(".dynsym") - 1) == 0)
		{
			scn = dso->scn[i];
			data = elf_getdata (scn, NULL);
			debug_sections[DEBUG_DYNSYMTAB].data = data->d_buf;
			debug_sections[DEBUG_DYNSYMTAB].elf_data = data;
			debug_sections[DEBUG_DYNSYMTAB].size = data->d_size;
			debug_sections[DEBUG_DYNSYMTAB].sec = i;
			fprintf(debug_fd, "Record dynamic symbol section %d name %s data size %ld\n", i, name, data->d_size);
			edit_dynsymtab(dso, data);
		}

	}

	if (readonly == 0 && elf_update (dso->elf, ELF_C_WRITE) < 0)
	{
		fprintf (stderr, "Failed to write file: %s\n", elf_errmsg (elf_errno()));
		exit (1);
	}

	if (elf_end (dso->elf) < 0)
	{
		fprintf (stderr, "elf_end failed: %s\n", elf_errmsg (elf_errno()));
		exit (1);
	}

	close (fd);

	/* Restore old access rights */
	if (readonly == 0)
		chmod (file, stat_buf.st_mode);

	poptFreeContext (optCon);

	return 0;
}
