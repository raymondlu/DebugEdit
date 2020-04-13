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
//#define _FILE_OFFSET_BITS 64

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
//#include <sys/elf_common.h>
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
static void edit_debugstr (Elf_Data *data)
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
	//elf_flagdata (data, ELF_C_SET, ELF_F_DIRTY);
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
	int new_section_count = 20;
	dso = (DSO *)
		malloc (sizeof(DSO) + (ehdr.e_shnum + new_section_count) * sizeof(GElf_Shdr)
				+ (ehdr.e_shnum + new_section_count) * sizeof(Elf_Scn *));
	if (!dso)
	{
		error (0, ENOMEM, "Could not open DSO");
		goto error_out;
	}

	//elf_flagelf (elf, ELF_C_SET, ELF_F_LAYOUT);

	memset (dso, 0, sizeof(DSO));
	dso->elf = elf;
	dso->ehdr = ehdr;
	dso->scn = (Elf_Scn **) &dso->shdr[ehdr.e_shnum + new_section_count];

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

	for (i = 1; i < dso->ehdr.e_shnum; i++)
	{
		Elf_Data *data;
		Elf_Scn *scn;

		const char *name;
		name = strptr (dso, dso->ehdr.e_shstrndx, dso->shdr[i].sh_name);

		fprintf (debug_fd, "sh:%d, sh_type: %d, sh_name: %s\n", i, dso->shdr[i].sh_type, name);
		if (/*strncmp (name, ".debug_str", sizeof (".debug_str") - 1) == 0 ||*/
				strncmp (name, ".strtab", sizeof (".strtab") - 1) == 0 ||	
				strncmp (name, ".dynstr", sizeof (".dynstr") - 1) == 0	
			 )
		{
			scn = dso->scn[i];
			data = NULL;
			size_t subsction_index = 0;
			while ((data = elf_getdata (scn, data)) != NULL)
			{
				edit_debugstr(data);
				fprintf(debug_fd, "Record string section %d name %s data size %ld subSection index %ld\n", i, name, data->d_size, subsction_index++);
			}
		}
	}
	
	elf_flagelf(dso->elf, ELF_C_SET, ELF_F_DIRTY);

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
