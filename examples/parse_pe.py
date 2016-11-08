#!/usr/bin/env python

from pynpac import *
f = open("samples/2016-09-14-pseudoDarkleech-Rig-EK-payload-CrypMIC-from-first-example.exe")

p = Parser(f)

dos_header = Record()
logging.debug("Parsing dos_header")
dos_header["signature"]                = p.parse("2s")
dos_header["UsedBytesInTheLastPage"]   = p.parse(uint16)
dos_header["FileSizeInPages"]          = p.parse(uint16)
dos_header["NumberOfRelocationItems"]  = p.parse(uint16)
dos_header["HeaderSizeInParagraphs"]   = p.parse(uint16)
dos_header["MinimumExtraParagraphs"]   = p.parse(uint16)
dos_header["MaximumExtraParagraphs"]   = p.parse(uint16)
dos_header["InitialRelativeSS"]        = p.parse(uint16)
dos_header["InitialSP"]                = p.parse(uint16)
dos_header["Checksum"]                 = p.parse(uint16)
dos_header["InitialIP"]                = p.parse(uint16)
dos_header["InitialRelativeCS"]        = p.parse(uint16)
dos_header["AddressOfRelocationTable"] = p.parse(uint16)
dos_header["OverlayNumber"]            = p.parse(uint16)
dos_header["Reserved"]                 = p.parse(uint16*4)
dos_header["OEMid"]                    = p.parse(uint16)
dos_header["OEMinfo"]                  = p.parse(uint16)
dos_header["Reserved2"]                = p.parse(uint16*10)
dos_header["AddressOfNewExeHeader"]    = p.parse(uint32)

p.data["dos_header"] = dos_header

dos_code = ""
logging.debug("Parsing dos_code")
if p.data["dos_header"]["AddressOfNewExeHeader"] > 64:
    dos_code = p.parse("%ds" % (p.data["dos_header"]["AddressOfNewExeHeader"] - 64))

#p.data["dos_code"] = dos_code

nt_headers = Record()
logging.debug("Parsing nt_header")
nt_headers["PESignature"] = p.parse(uint32)

logging.debug("Parsing file_header")
file_header = Record()
file_header["Machine"]              = p.parse(uint16)
file_header["NumberOfSections"]     = p.parse(uint16)
file_header["TimeDateStamp"]        = p.parse(uint32)
file_header["PointerToSymbolTable"] = p.parse(uint32)
file_header["NumberOfSymbols"]      = p.parse(uint32)
file_header["SizeOfOptionalHeader"] = p.parse(uint16)
file_header["Characteristics"]      = p.parse(uint16)

logging.debug("Resuming parsing nt_header")
nt_headers["file_header"] = file_header
nt_headers["is_exe"] = nt_headers["file_header"]["SizeOfOptionalHeader"] > 0
p.data["nt_headers"] = nt_headers

if ( nt_headers["is_exe"] ):
    logging.debug("Parsing optional_header")

    optional_header = Record()
    optional_header["magic"]                = p.parse(uint16)
    optional_header["major_linker_version"] = p.parse(uint8)
    optional_header["minor_linker_version"] = p.parse(uint8)
    optional_header["size_of_code"]         = p.parse(uint32)
    optional_header["size_of_init_data"]    = p.parse(uint32)
    optional_header["size_of_uninit_data"]  = p.parse(uint32)
    optional_header["addr_of_entry_point"]  = p.parse(uint32)
    optional_header["base_of_code"]         = p.parse(uint32)

    optional_header["is_pe32_plus"] = optional_header["magic"] == 0x20b

    if ( not optional_header["is_pe32_plus"] ):
        optional_header["base_of_data"] = p.parse(uint32)
        optional_header["image_base"]   = p.parse(uint32)
    else:
        optional_header["image_base"]   = p.parse(uint64)

    optional_header["section_alignment"]    = p.parse(uint32)
    optional_header["file_alignment"]       = p.parse(uint32)
    optional_header["os_version_major"]     = p.parse(uint16)
    optional_header["os_version_minor"]     = p.parse(uint16)
    optional_header["major_image_version"]  = p.parse(uint16)
    optional_header["minor_image_version"]  = p.parse(uint16)
    optional_header["major_subsys_version"] = p.parse(uint16)
    optional_header["minor_subsys_version"] = p.parse(uint16)
    optional_header["win32_version"]        = p.parse(uint32)
    optional_header["size_of_image"]        = p.parse(uint32)
    optional_header["size_of_headers"]      = p.parse(uint32)
    optional_header["checksum"]             = p.parse(uint32)
    optional_header["subsystem"]            = p.parse(uint16)
    optional_header["dll_characteristics"]  = p.parse(uint16)

    if ( optional_header["is_pe32_plus"] ):
        mem_info_size = uint64
    else:
        mem_info_size = uint32

    optional_header["mem_info_size_of_stack_reserve"] = p.parse(mem_info_size)
    optional_header["mem_info_size_of_stack_commit"]  = p.parse(mem_info_size)
    optional_header["mem_info_size_of_heap_reserve"]  = p.parse(mem_info_size)
    optional_header["mem_info_size_of_heap_commit"]   = p.parse(mem_info_size)

    optional_header["loader_flags"]            = p.parse(uint32)
    optional_header["number_of_rva_and_sizes"] = p.parse(uint32)

    p.data["nt_headers"]["optional_header"] = optional_header

    rvas = []
    for i in range(optional_header["number_of_rva_and_sizes"]):
        rva = Record()
        logging.debug("Parsing rva")
        rva["virtual_address"] = p.parse(uint32)
        rva["size"] = p.parse(uint32)
        rvas.append(rva)
    p.data["nt_headers"]["optional_header"]["rvas"] = rvas

section_headers = []
for i in range(p.data["nt_headers"]["file_header"]["NumberOfSections"]):
    logging.debug("Parsing section_header")
    section_header = Record()
    section_header["name"]                      = p.parse("8s")
    section_header["virtual_size"]              = p.parse(uint32)
    section_header["virtual_addr"]              = p.parse(uint32)
    section_header["size_of_raw_data"]          = p.parse(uint32)
    section_header["ptr_to_raw_data"]           = p.parse(uint32)
    section_header["non_used_ptr_to_relocs"]    = p.parse(uint32)
    section_header["non_used_ptr_to_line_nums"] = p.parse(uint32)
    section_header["non_used_num_of_relocs"]    = p.parse(uint16)
    section_header["non_used_num_of_line_nums"] = p.parse(uint16)
    section_header["characteristics"]           = p.parse(uint32)
    section_headers.append(section_header)

p.data["section_headers"] = section_headers

print p.print_data()

f.close()

