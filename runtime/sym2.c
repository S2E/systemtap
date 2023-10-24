static void _stp_filename_lookup_5(struct _stp_module *mod, char ** filename,
                                   uint8_t *dirsecp, uint8_t *enddirsecp,
                                   unsigned int length,
                                   unsigned fileidx, int user, int compat_task,
                                   struct context *c)
{
  // Demonstrate how we are able to access the context struct and display
  // some of its content...  This is a proof of concept for future use of
  // the context struct within this function.
  _stp_printf("XXX CONTEXT: %s\n", ((c->probe_type == stp_probe_type_uprobe) ? "uprobe-yes" : "uprobe-no"));

  // Pointer to the .debug_line section
  // pointing at just after standard_opcode_lengths
  // which is the last header item common to DWARF v4 and v5.
  uint8_t *debug_line_p = dirsecp;
  // Pointer to the beginning of .debug_line_str section
  uint8_t *debug_line_str_p = mod->debug_line_str;
  uint8_t *endstrsecp = mod->debug_line_str + mod->debug_line_str_len;

  uint8_t directory_entry_format_count = 0, file_name_entry_format_count = 0,
          directories_count = 0, file_names_count = 0;

  struct encpair { uint16_t desc; uint16_t form; };
  struct encpair dir_enc[STP_MAX_DW_SOURCES], file_enc[STP_MAX_DW_SOURCES];

  // Source files and directories
  struct dirinfo { uint8_t offset; char *name; };
  struct dirinfo src_dir[STP_MAX_DW_SOURCES];
  struct fileinfo { uint8_t offset; uint8_t dirindex; char *name; };
  struct fileinfo src_file[STP_MAX_DW_SOURCES];
  static char fullpath [MAXSTRINGLEN];

  // Reusable loop iterators.  As the producer records show, the rhel8 kbuild
  // system uses -std=gnu90 not allowing initial loop declarations, while the
  // rhel9 build system allows that.  We need to stay compatible though..
  // https://lwn.net/Articles/885941/
  int i = 0, j = 0;

  // Initialize the *filename
  *filename = "unknown";

  // Next comes directory_entry_format_count
  if (debug_line_str_p + 1 > enddirsecp)
    return;
  directory_entry_format_count = *debug_line_p++;
  if (directory_entry_format_count > STP_MAX_DW_SOURCES)
    return;

  // Next comes directory_entry_format
  for (i = 0; i < directory_entry_format_count; i++)
    {
      dir_enc[i].desc = read_pointer ((const uint8_t **) &debug_line_p, enddirsecp, DW_EH_PE_leb128, user, compat_task);
      dir_enc[i].form = read_pointer ((const uint8_t **) &debug_line_p, enddirsecp, DW_EH_PE_leb128, user, compat_task);
    }

  // Next comes directories_count
  directories_count = read_pointer ((const uint8_t **) &debug_line_p, enddirsecp, DW_EH_PE_leb128, user, compat_task);
  if (directories_count > STP_MAX_DW_SOURCES)
    return;

  // Next come directories
  // See elfutil's print_form_data() in readelf.c for an analogy of what happens below
  for (i=0; i < directories_count; i++)
      for (j=0; j < directory_entry_format_count; j++)
          switch (dir_enc[j].form)
            {
              case DW_FORM_line_strp:
                src_dir[i].offset = (uint8_t) read_pointer ((const uint8_t **) &debug_line_p, enddirsecp, DW_EH_PE_data4, user, compat_task);
                if ((uint8_t *) mod->debug_line_str + src_dir[i].offset > endstrsecp)
                  return;
                src_dir[i].name = mod->debug_line_str + src_dir[i].offset;
                break;
              default:
                _stp_error("BUG: Unknown form %d encountered while parsing source dir\n", dir_enc[j].form);
                return;
            }

  // Next comes file_name_entry_format_count
  if (debug_line_p + 1 > enddirsecp)
    return;
  file_name_entry_format_count = *debug_line_p++;
  if (file_name_entry_format_count > STP_MAX_DW_SOURCES)
    return;


  // Next comes file_name_entry_format
  for (i = 0; i < file_name_entry_format_count; i++)
    {
      file_enc[i].desc = read_pointer ((const uint8_t **) &debug_line_p, enddirsecp, DW_EH_PE_leb128, user, compat_task);
      file_enc[i].form = read_pointer ((const uint8_t **) &debug_line_p, enddirsecp, DW_EH_PE_leb128, user, compat_task);
    }

  // Next comes the file_names_count
  // See elfutil's print_form_data() in readelf.c for an analogy of what happens below
  file_names_count = read_pointer ((const uint8_t **) &debug_line_p, enddirsecp, DW_EH_PE_leb128, user, compat_task);
  if (file_names_count > STP_MAX_DW_SOURCES)
    return;

  // Next come the files
  for (i=0; i < file_names_count; i++)
      for (j=0; j < file_name_entry_format_count; j++)
          switch (file_enc[j].form)
            {
              case DW_FORM_line_strp:
                src_file[i].offset = (uint8_t) read_pointer ((const uint8_t **) &debug_line_p, enddirsecp, DW_EH_PE_data4, user, compat_task);
                if ((uint8_t *) mod->debug_line_str + src_file[i].offset > endstrsecp)
                  return;
                src_file[i].name = mod->debug_line_str + src_file[i].offset;
                break;
              case DW_FORM_data16:
                // This is how clang encodes the md5sum, skip it
                if (debug_line_p + 16 > enddirsecp)
                  return;
                debug_line_p += 16;
                break;
              case DW_FORM_udata:
                src_file[i].dirindex = (uint8_t) read_pointer ((const uint8_t **) &debug_line_p, enddirsecp, DW_EH_PE_leb128, user, compat_task);
                break;
              default:
                _stp_error("BUG: Unknown form %d encountered while parsing source file\n", file_enc[j].form);
                return;
            }

  // Put it together
  // - requested file index is fileidx
  //   (based on the line number program)
  // - find directory respective to this file
  // - and attach slash and the file name itself
  strlcpy(fullpath, src_dir[src_file[fileidx].dirindex].name, MAXSTRINGLEN);
  strlcat(fullpath, "/", MAXSTRINGLEN);
  strlcat(fullpath, src_file[fileidx].name, MAXSTRINGLEN);
  *filename = fullpath;

}
