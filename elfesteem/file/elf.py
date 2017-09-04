#! /usr/bin/env python

from elfesteem.core.cell import *

log = logging.getLogger("elfparse")
console_handler = logging.StreamHandler()
console_handler.setFormatter(logging.Formatter("%(levelname)-5s: %(message)s"))
log.addHandler(console_handler)
log.setLevel(logging.WARN)

glob = globals()

# ################################################################
# 1. HEADERS

class EhdrPtrsizeEndianess(Byte):
    # Two bytes in the headers determine ptrsize and endianess.
    # We call 'update_ptrsize_endianess' every time this object is created.
    def unwork(self, value):
        Byte.unwork(self, value)
        self.update_ptrsize_endianess()
    def unpack(self, data, **kargs):
        Byte.unpack(self, data, **kargs)
        self.update_ptrsize_endianess()

# Legal values for e_ident[EI_CLASS]
ELFCLASS = NamedConstants((
    (0, 'ELFCLASSNONE', 'NONE'),        # Invalid class
    (1, 'ELFCLASS32',   'ELF32'),       # 32-bit objects
    (2, 'ELFCLASS64',   'ELF64'),       # 64-bit objects
    ), glob=glob)

class EhdrClass(EhdrPtrsizeEndianess):
    _enum = ELFCLASS
    _default = 'ELFCLASS32'
    def update_ptrsize_endianess(self):
        self._parent._parent._parent._ptrsize = {
            ELFCLASS['ELFCLASS32']: 32,
            ELFCLASS['ELFCLASS64']: 64,
            }.get(self.work(), None)

# Legal values for e_ident[EI_DATA]
ELFDATA  = NamedConstants((
    (0, 'ELFDATANONE',  'NONE'),     # Invalid data encoding
    (1, 'ELFDATA2LSB',  "2's complement, little endian"), # Least significant byte at lowest address
    (2, 'ELFDATA2MSB',  "2's complement, big endian"),    # Most significant byte at lowest address
    ), glob=glob)

class EhdrData(Byte):
    _enum = ELFDATA
    _default = 'ELFDATA2LSB'
    def generate(self):
        self._parent._parent._parent._endianess = {
            ELFDATA['ELFDATA2LSB']: '<',
            ELFDATA['ELFDATA2MSB']: '>',
            }.get(self.work(), None)

class EhdrIdent(Struct):
    _fields = [
        ('magic',      Str[4].fixed('\x7fELF')),
        ('e_class',    EhdrClass),
        ('e_data',     EhdrData),
        ('version',    Byte.default(1)),
        ('osabi',      Byte),
        ('abiversion', Byte),
        ('padding',    Str[7]),
        ]

# Legal values for e_type (object file type).
ET = NamedConstants((
    (0, 'ET_NONE'),                        # No file type
    (1, 'ET_REL'),                         # Relocatable file
    (2, 'ET_EXEC'),                        # Executable file
    (3, 'ET_DYN'),                         # Shared object file
    (4, 'ET_CORE'),                        # Core file
    (5, 'ET_NUM'),                         # Number of defined types
    (0xfe00, 'ET_LOOS'),                   # OS-specific range start
    (0xfeff, 'ET_HIOS'),                   # OS-specific range end
    (0xff00, 'ET_LOPROC'),                 # Processor-specific range start
    (0xffff, 'ET_HIPROC'),                 # Processor-specific range end
    ), glob=glob)

# Legal values for e_machine (architecture).
EM = NamedConstants((
    (0, 'EM_NONE'),          # No machine
    (1, 'EM_M32'),           # AT&T WE 32100
    (2, 'EM_SPARC'),         # SUN SPARC
    (3, 'EM_386'),           # Intel 80386
    (4, 'EM_68K'),           # Motorola m68k family
    (5, 'EM_88K'),           # Motorola m88k family
    (6, 'EM_486'),           # Intel 80486
    (7, 'EM_860'),           # Intel 80860
    (8, 'EM_MIPS'),          # MIPS R3000 big-endian
    (9, 'EM_S370'),          # IBM System/370
    (10, 'EM_MIPS_RS3_LE'),  # MIPS R3000 little-endian
    (15, 'EM_PARISC'),       # HPPA
    (17, 'EM_VPP500'),       # Fujitsu VPP500
    (18, 'EM_SPARC32PLUS'),  # Sun's "v8plus"
    (19, 'EM_960'),          # Intel 80960
    (20, 'EM_PPC'),          # PowerPC
    (21, 'EM_PPC64'),        # PowerPC 64-bit
    (22, 'EM_S390'),         # IBM S390
    (23, 'EM_SPU'),          # Cell Broadband Engine SPU
    (36, 'EM_V800'),         # NEC V800 series
    (37, 'EM_FR20'),         # Fujitsu FR20
    (38, 'EM_RH32'),         # TRW RH-32
    (39, 'EM_RCE'),          # Motorola RCE
    (40, 'EM_ARM'),          # ARM
    (41, 'EM_FAKE_ALPHA'),   # Digital Alpha
    (42, 'EM_SH'),           # Hitachi SH
    (43, 'EM_SPARCV9'),      # SPARC v9 64-bit
    (44, 'EM_TRICORE'),      # Siemens Tricore
    (45, 'EM_ARC'),          # Argonaut RISC Core
    (46, 'EM_H8_300'),       # Hitachi H8/300
    (47, 'EM_H8_300H'),      # Hitachi H8/300H
    (48, 'EM_H8S'),          # Hitachi H8S
    (49, 'EM_H8_500'),       # Hitachi H8/500
    (50, 'EM_IA_64'),        # Intel Merced
    (51, 'EM_MIPS_X'),       # Stanford MIPS-X
    (52, 'EM_COLDFIRE'),     # Motorola Coldfire
    (53, 'EM_68HC12'),       # Motorola M68HC12
    (54, 'EM_MMA'),          # Fujitsu MMA Multimedia Accelerator*/
    (55, 'EM_PCP'),          # Siemens PCP
    (56, 'EM_NCPU'),         # Sony nCPU embeeded RISC
    (57, 'EM_NDR1'),         # Denso NDR1 microprocessor
    (58, 'EM_STARCORE'),     # Motorola Start*Core processor
    (59, 'EM_ME16'),         # Toyota ME16 processor
    (60, 'EM_ST100'),        # STMicroelectronic ST100 processor
    (61, 'EM_TINYJ'),        # Advanced Logic Corp. Tinyj emb.fam*/
    (62, 'EM_X86_64'),       # AMD x86-64 architecture
    (63, 'EM_PDSP'),         # Sony DSP Processor
    (64, 'EM_PDP10'),        # Digital Equipment Corp. PDP-10
    (65, 'EM_PDP11'),        # Digital Equipment Corp. PDP-11
    (66, 'EM_FX66'),         # Siemens FX66 microcontroller
    (67, 'EM_ST9PLUS'),      # STMicroelectronics ST9+ 8/16 mc
    (68, 'EM_ST7'),          # STmicroelectronics ST7 8 bit mc
    (69, 'EM_68HC16'),       # Motorola MC68HC16 microcontroller
    (70, 'EM_68HC11'),       # Motorola MC68HC11 microcontroller
    (71, 'EM_68HC08'),       # Motorola MC68HC08 microcontroller
    (72, 'EM_68HC05'),       # Motorola MC68HC05 microcontroller
    (73, 'EM_SVX'),          # Silicon Graphics SVx
    (74, 'EM_ST19'),         # STMicroelectronics ST19 8 bit mc
    (75, 'EM_VAX'),          # Digital VAX
    (76, 'EM_CRIS'),         # Axis Communications 32-bit embedded processor
    (77, 'EM_JAVELIN'),      # Infineon Technologies 32-bit embedded processor
    (78, 'EM_FIREPATH'),     # Element 14 64-bit DSP Processor
    (79, 'EM_ZSP'),          # LSI Logic 16-bit DSP Processor
    (80, 'EM_MMIX'),         # Donald Knuth's educational 64-bit processor
    (81, 'EM_HUANY'),        # Harvard University machine-independent object files
    (82, 'EM_PRISM'),        # SiTera Prism
    (83, 'EM_AVR'),          # Atmel AVR 8-bit microcontroller
    (84, 'EM_FR30'),         # Fujitsu FR30
    (85, 'EM_D10V'),         # Mitsubishi D10V
    (86, 'EM_D30V'),         # Mitsubishi D30V
    (87, 'EM_V850'),         # NEC v850
    (88, 'EM_M32R'),         # Mitsubishi M32R
    (89, 'EM_MN10300'),      # Matsushita MN10300
    (90, 'EM_MN10200'),      # Matsushita MN10200
    (91, 'EM_PJ'),           # picoJava
    (92, 'EM_OPENRISC'),     # OpenRISC 32-bit embedded processor
    (93, 'EM_ARC_A5'),       # ARC Cores Tangent-A5
    (94, 'EM_XTENSA'),       # Tensilica Xtensa Architecture
    (95, 'EM_VIDEOCORE'),    # Alphamosaic VideoCore processor
    (96, 'EM_TMM_GPP'),      # Thompson Multimedia General Purpose Processor
    (97, 'EM_NS32K'),        # National Semiconductor 32000 series
    (98, 'EM_TPC'),          # Tenor Network TPC processor
    (99, 'EM_SNP1K'),        # Trebia SNP 1000 processor
    (100, 'EM_ST200'),       # STMicroelectronics (www.st.com) ST200
    (101, 'EM_IP2K'),        # Ubicom IP2xxx microcontroller family
    (102, 'EM_MAX'),         # MAX Processor
    (103, 'EM_CR'),          # National Semiconductor CompactRISC microprocessor
    (104, 'EM_F2MC16'),      # Fujitsu F2MC16
    (105, 'EM_MSP430'),      # Texas Instruments embedded microcontroller msp430
    (106, 'EM_BLACKFIN'),    # Analog Devices Blackfin (DSP) processor
    (107, 'EM_SE_C33'),      # S1C33 Family of Seiko Epson processors
    (108, 'EM_SEP'),         # Sharp embedded microprocessor
    (109, 'EM_ARCA'),        # Arca RISC Microprocessor
    (110, 'EM_UNICORE'),     # Microprocessor series from PKU-Unity Ltd. and MPRC of Peking University
    (111, 'EM_EXCESS'),      # eXcess: 16/32/64-bit configurable embedded CPU
    (112, 'EM_DXP'),         # Icera Semiconductor Inc. Deep Execution Processor
    (113, 'EM_ALTERA_NIOS2'),# Altera Nios II soft-core processor
    (114, 'EM_CRX'),         # National Semiconductor CompactRISC CRX
    (115, 'EM_XGATE'),       # Motorola XGATE embedded processor
    (116, 'EM_C166'),        # Infineon C16x/XC16x processor
    (117, 'EM_M16C'),        # Renesas M16C series microprocessors
    (118, 'EM_DSPIC30F'),    # Microchip Technology dsPIC30F Digital Signal Controller
    (119, 'EM_CE'),          # Freescale Communication Engine RISC core
    (120, 'EM_M32C'),        # Renesas M32C series microprocessors
    (131, 'EM_TSK3000'),     # Altium TSK3000 core
    (132, 'EM_RS08'),        # Freescale RS08 embedded processor
    (133, 'EM_SHARC'),       # Analog Devices SHARC family of 32-bit DSP processors
    (134, 'EM_ECOG2'),       # Cyan Technology eCOG2 microprocessor
    (135, 'EM_SCORE7'),      # Sunplus S+core7 RISC processor
    (136, 'EM_DSP24'),       # New Japan Radio (NJR) 24-bit DSP Processor
    (137, 'EM_VIDEOCORE3'),  # Broadcom VideoCore III processor
    (138, 'EM_LATTICEMICO32'), # RISC processor for Lattice FPGA architecture
    (139, 'EM_SE_C17'),      # Seiko Epson C17 family
    (140, 'EM_TI_C6000'),    # The Texas Instruments TMS320C6000 DSP family
    (141, 'EM_TI_C2000'),    # The Texas Instruments TMS320C2000 DSP family
    (142, 'EM_TI_C5500'),    # The Texas Instruments TMS320C55x DSP family
    (160, 'EM_MMDSP_PLUS'),  # STMicroelectronics 64bit VLIW Data Signal Processor
    (161, 'EM_CYPRESS_M8C'), # Cypress M8C microprocessor
    (162, 'EM_R32C'),        # Renesas R32C series microprocessors
    (163, 'EM_TRIMEDIA'),    # NXP Semiconductors TriMedia architecture family
    (164, 'EM_HEXAGON'),     # Qualcomm Hexagon processor
    (165, 'EM_8051'),        # Intel 8051 and variants
    (166, 'EM_STXP7X'),      # STMicroelectronics STxP7x family of configurable and extensible RISC processors
    (167, 'EM_NDS32'),       # Andes Technology compact code size embedded RISC processor family
    (168, 'EM_ECOG1', None), # Cyan Technology eCOG1X family
    (168, 'EM_ECOG1X'),      # Cyan Technology eCOG1X family
    (169, 'EM_MAXQ30'),      # Dallas Semiconductor MAXQ30 Core Micro-controllers
    (170, 'EM_XIMO16'),      # New Japan Radio (NJR) 16-bit DSP Processor
    (171, 'EM_MANIK'),       # M2000 Reconfigurable RISC Microprocessor
    (172, 'EM_CRAYNV2'),     # Cray Inc. NV2 vector architecture
    (173, 'EM_RX'),          # Renesas RX family
    (174, 'EM_METAG'),       # Imagination Technologies META processor architecture
    (175, 'EM_MCST_ELBRUS'), # MCST Elbrus general purpose hardware architecture
    (176, 'EM_ECOG16'),      # Cyan Technology eCOG16 family
    (177, 'EM_CR16'),        # National Semiconductor CompactRISC CR16 16-bit microprocessor
    (178, 'EM_ETPU'),        # Freescale Extended Time Processing Unit
    (179, 'EM_SLE9X'),       # Infineon Technologies SLE9X core
    (180, 'EM_L10M'),        # Intel L10M
    (181, 'EM_K10M'),        # Intel K10M
    (183, 'EM_AARCH64'),     # ARM AArch64
    (185, 'EM_AVR32'),       # Atmel Corporation 32-bit microprocessor family
    (186, 'EM_STM8'),        # STMicroeletronics STM8 8-bit microcontroller
    (187, 'EM_TILE64'),      # Tilera TILE64 multicore architecture family
    (188, 'EM_TILEPRO'),     # Tilera TILEPro multicore architecture family
    (189, 'EM_MICROBLAZE'),  # Xilinx MicroBlaze
    (190, 'EM_CUDA'),        # NVIDIA CUDA architecture
    (191, 'EM_TILEGX'),      # Tilera TILE-Gx multicore architecture family
    (192, 'EM_CLOUDSHIELD'), # CloudShield architecture family
    (193, 'EM_COREA_1ST'),   # KIPO-KAIST Core-A 1st generation processor family
    (194, 'EM_COREA_2ND'),   # KIPO-KAIST Core-A 2nd generation processor family
    (195, 'EM_ARC_COMPACT2'),# Synopsys ARCompact V2
    (196, 'EM_OPEN8'),       # Open8 8-bit RISC soft processor core
    (197, 'EM_RL78'),        # Renesas RL78 family
    (198, 'EM_VIDEOCORE5'),  # Broadcom VideoCore V processor
    (199, 'EM_78KOR'),       # Renesas 78KOR family
    (200, 'EM_56800EX'),     # Freescale 56800EX Digital Signal Controller (DSC)
    (201, 'EM_BA1'),         # Beyond BA1 CPU architecture
    (202, 'EM_BA2'),         # Beyond BA2 CPU architecture
    (203, 'EM_XCORE'),       # XMOS xCORE processor family
    (204, 'EM_MCHP_PIC'),    # Microchip 8-bit PIC(r) family
    (205, 'EM_INTEL205'),    # Reserved by Intel
    (206, 'EM_INTEL206'),    # Reserved by Intel
    (207, 'EM_INTEL207'),    # Reserved by Intel
    (208, 'EM_INTEL208'),    # Reserved by Intel
    (209, 'EM_INTEL209'),    # Reserved by Intel
    (210, 'EM_KM32'),        # KM211 KM32 32-bit processor
    (211, 'EM_KMX32'),       # KM211 KMX32 32-bit processor
    (212, 'EM_KMX16'),       # KM211 KMX16 16-bit processor
    (213, 'EM_KMX8'),        # KM211 KMX8 8-bit processor
    (214, 'EM_KVARC'),       # KM211 KVARC processor
    (215, 'EM_CDP'),         # Paneve CDP architecture family
    (216, 'EM_COGE'),        # Cognitive Smart Memory Processor
    (217, 'EM_COOL'),        # iCelero CoolEngine
    (218, 'EM_NORC'),        # Nanoradio Optimized RISC
    (219, 'EM_CSR_KALIMBA'), # CSR Kalimba architecture family
    (221, 'EM_VISIUM'),      # 
    (222, 'EM_FT32'),        # FTDI FT32
    (223, 'EM_MOXIE'),       # Moxie
    (224, 'EM_AMDGPU'),      # AMD GPU architecture
    (243, 'EM_RISCV'),       # RISC-V
    (244, 'EM_LANAI'),       # Lanai 32-bit processor
    (247, 'EM_BPF'),         # Linux kernel bpf virtual machine
    (0x1223, 'EM_EPIPHANY'), # Adapteva's Epiphany
    (0x5441, 'EM_FRV'),         
    (0xad45, 'EM_STORMY16'),    
    (0xfeba, 'EM_IQ2000'),   # Vitesse IQ2000
    (0x9026, 'EM_ALPHA'),       
    ), glob=glob)

class Ehdr(AttributesElfesteem,Struct):
    _fields = [
        ('ident',     EhdrIdent),
        ('type',      Short    .default(ET['ET_REL'])),
        ('machine',   Short    .default(EM['EM_386'])),
        ('version',   Int      .default(1)),
        ('entry',     Ptr),
        ('phoff',     Ptr),
        ('shoff',     Ptr),
        ('flags',     Int),
        # [TODO]
        #('ehsize',    Short[property(lambda self:
        #                    { 32:52, 64:64 }[self.get_ptrsize()])]),
        ('ehsize',    Short),
        ('phentsize', Short),
        ('phnum',     Short),
        ('shentsize', Short),
        ('shnum',     Short),
        ('shstrndx',  Short),
        ]

# ################################################################
# 2. SEGMENTS

# When the ELF is loaded in memory, Program Header information is
# used to load each segment: 'memsz' bytes are loaded at address
# 'vaddr'. If 'filesz' is zero, then only zeroes are loaded; else,
# 'filesz' bytes from the file starting at offset 'offset' are loaded.
# On most systems 'paddr' is ignored.
class Phdr32(AttributesElfesteem,Struct):
    _fields = [
        ('type',   Int),
        ('offset', Ptr),
        ('vaddr',  Ptr),
        ('paddr',  Ptr),
        ('filesz', Ptr),
        ('memsz',  Ptr),
        ('flags',  Int),
        ('align',  Ptr),
        ]
    def shlist(self):
        """ List the sections that are entirely in the segment.
            Same result as readelf's "Section to Segment mapping"; does not
            list the sections that partially overlap the segment.
        """
        shl = []
        for sect in self._get_attr_ancestor('sh'):
            stype = sect['content'].type_txt
            if stype == 'NULL':
                continue
            flags = sect.flags
            ptype = self.type
            # .tbss is special.  It doesn't contribute memory space
            # to normal segments.
            if ptype != PT['PT_TLS'] and \
               (flags & SHF['SHF_TLS']) and \
               stype == 'NOBITS':
                continue
            # Compare allocated sections by VMA, unallocated
            # sections by file offset.
            if flags & SHF['SHF_ALLOC']:
                pi, ps = self.vaddr, self.memsz
                si, ss = sect.addr,  sect.size
            else:
                pi, ps = self.offset, self.filesz
                si, ss = sect.offset, sect.size
            if   (pi <= si) and (si+ss <= pi+ps):
                #sect.phparent = self
                shl.append(sect)
        return shl
    shlist = property(shlist)

class Phdr64(Phdr32):
    _fields = [
        ('type',   Int),
        ('flags',  Int),
        ('offset', Ptr),
        ('vaddr',  Ptr),
        ('paddr',  Ptr),
        ('filesz', Ptr),
        ('memsz',  Ptr),
        ('align',  Ptr),
        ]

# Legal values for p_type (segment type).
PT = NamedConstants((
    (0,          'PT_NULL'),         # Program header table entry unused
    (1,          'PT_LOAD'),         # Loadable program segment
    (2,          'PT_DYNAMIC'),      # Dynamic linking information
    (3,          'PT_INTERP'),       # Program interpreter
    (4,          'PT_NOTE'),         # Auxiliary information
    (5,          'PT_SHLIB'),        # Reserved
    (6,          'PT_PHDR'),         # Entry for header table itself
    (7,          'PT_TLS'),          # Thread-local storage segment
    (8,          'PT_NUM'),          # Number of defined types
    (0x60000000, 'PT_LOOS', None),   # Start of OS-specific
    (0x6474e550, 'PT_GNU_EH_FRAME'), # GCC .eh_frame_hdr segment
    (0x6474e551, 'PT_GNU_STACK'),    # Indicates stack executability
    (0x6474e552, 'PT_GNU_RELRO'),
    (0x6ffffffa, 'PT_LOSUNW', None), # Start of SunOS-specific
    (0x6ffffffa, 'PT_SUNWBSS'),      # Sun Specific segment
    (0x6ffffffb, 'PT_SUNWSTACK'),    # Stack segment
    (0x6fffffff, 'PT_HISUNW', None), # End of SunOS-specific
    (0x6fffffff, 'PT_HIOS', None),   # End of OS-specific
    (0x70000000, 'PT_LOPROC', None), # Start of processor-specific
    (0x7fffffff, 'PT_HIPROC', None), # End of processor-specific
    ), glob=glob)

class PHList(VarArray):
    _type = property(lambda self: { 32:Phdr32, 64:Phdr64 }[self._ptrsize])
    def elfesteem_repr(self):
        rep = [ "   offset filesz vaddr    memsz" ]
        for i, p in enumerate(self):
            rep.append( "%2i %07x %06x %08x %07x %02x %01x" % (i,
                p['offset'],
                p['filesz'],
                p['vaddr'],
                p['memsz'],
                p['type'],
                p['flags']) )
            rep.append("   "+" ".join([ str(_['name']) for _ in p.shlist]))
        return "\n".join(rep)
    _ptrsize = property(lambda _: _._parent._get_attr_ancestor('_ptrsize'))

# ################################################################
# 3. SECTIONS
# 3.1. Section headers

class NameInStrtab(Leaf):
    _encoding = 'latin1'
    def work(self):
        strtab = self._get_attr_ancestor('sh')[self.strndx]['content']
        pos = self._parent['name_idx'].work()
        name = strtab[pos]
        if not isinstance(name, str): # python3
            name = name.decode(self._encoding)
        return name
    work2repr = lambda self, val: val
    def show(self):
        return "<%s value=%s>" % (self.__class__.__name__, self.work())
    def __getitem__(self, item):
        return self.work().__getitem__(item)
    def __str__(self):
        return self.work()

class SectionName(NameInStrtab):
    strndx = property(lambda self: self._get_attr_ancestor('Ehdr').shstrndx)

# Legal values for sh_flags (section flags).
SHF = NamedConstants((
    (1 <<  0,    'SHF_WRITE'),            # Writable
    (1 <<  1,    'SHF_ALLOC'),            # Occupies memory during execution
    (1 <<  2,    'SHF_EXECINSTR'),        # Executable
    (1 <<  4,    'SHF_MERGE'),            # Might be merged
    (1 <<  5,    'SHF_STRINGS'),          # Contains nul-terminated strings
    (1 <<  6,    'SHF_INFO_LINK'),        # `sh_info' contains SHT index
    (1 <<  7,    'SHF_LINK_ORDER'),       # Preserve order after combining
    (1 <<  8,    'SHF_OS_NONCONFORMING'), # Non-standard OS specific handling required
    (1 <<  9,    'SHF_GROUP'),            # Section is member of a group.
    (1 << 10,    'SHF_TLS'),              # Section hold thread-local data.
    (0x000ff808, 'SHF_UNKNOWN'),          # (bits not defined above)
    (0x0ff00000, 'SHF_MASKOS'),           # OS-specific.
    (0xf0000000, 'SHF_MASKPROC'),         # Processor-specific
    (1 << 30, '   SHF_ORDERED'),          # Special ordering requirement (Solaris)
    (1 << 31,    'SHF_EXCLUDE'),          # Section is excluded unless references or allocated (Solaris)
    ), glob=glob)

class Shdr(AttributesElfesteem,Struct):
    _fields = [
        ('name_idx',  Int),
        ('type',      Int),
        ('flags',     Ptr),
        ('addr',      Ptr),
        ('offset',    Ptr),
        ('size',      Ptr),
        ('link',      Int),
        ('info',      Int),
        ('addralign', Ptr),
        ('entsize',   Ptr),
        ]
    _virtual_fields = [ 'name', 'content' ]
    registered = {}
    def unpack(self, data, offset=0, **kargs):
        """ We unpack the section header and the section content. """
        Struct.unpack(self, data, offset=offset, **kargs)
        section_class = self.registered.get(self['type'].work(), Section)
        self._subcells['content'] = section_class(_parent=self,_name='content')
        self._subcells['content'].unpack(data,
                            offset=self['offset'].work(),
                            size=self['size'].work(),
                            **kargs)
        self._subcells['name'] = SectionName(_parent=self,_name='name')
    def __getitem__(self, item):
        if item in self._subcells: return self._subcells[item]
        else:                      return self._subcells['content'][item]
    def flags_txt(self):
        flags = self['flags'].work()
        ret = ""
        if flags & SHF['SHF_WRITE']:            ret += "W"
        if flags & SHF['SHF_ALLOC']:            ret += "A"
        if flags & SHF['SHF_EXECINSTR']:        ret += "X"
        if flags & SHF['SHF_MERGE']:            ret += "M"
        if flags & SHF['SHF_STRINGS']:          ret += "S"
        if flags & SHF['SHF_INFO_LINK']:        ret += "I"
        if flags & SHF['SHF_LINK_ORDER']:       ret += "L"
        if flags & SHF['SHF_OS_NONCONFORMING']: ret += "O"
        if flags & SHF['SHF_GROUP']:            ret += "G"
        if flags & SHF['SHF_TLS']:              ret += "T"
        if flags & SHF['SHF_EXCLUDE']:          ret += "E"
        if flags & SHF['SHF_MASKOS']:           ret += "o"
        if flags & SHF['SHF_MASKPROC']:         ret += "p"
        if flags & SHF['SHF_UNKNOWN']:          ret += "x"
        return ret
    def readelf_display_oneliner(self):
        value = self.work()
        for idx in self._parent._subcells:
            if self is self._parent._subcells[idx]:
                value['idx'] = idx
                break
        else:
            value['idx'] = None
        value['name17'] = self['name'][:17]
        value['type_txt'] = self['content'].type_txt
        value['flags_txt'] = self.flags_txt()
        format = {
            32: "  [%(idx)2d] %(name17)-17s %(type_txt)-15s %(addr)08x %(offset)06x %(size)06x %(entsize)02x %(flags_txt)3s %(link)2d %(info)3d %(addralign)2d",
            64: "  [%(idx)2d] %(name17)-17s %(type_txt)-15s  %(addr)016x  %(offset)08x\n       %(size)016x  %(entsize)016x %(flags_txt)3s      %(link)2d    %(info)2d    %(addralign)2d",
            } [self._ptrsize]
        return format % value
    def readelf_display(self):
        return self._subcells['content'].readelf_display()
    _ptrsize = property(lambda _: _._parent._get_attr_ancestor('_ptrsize'))

class SHList(VarArray):
    _type = Shdr
    def readelf_display(self):
        rep = [ "There are %d section headers, starting at offset %#x:"
                % (self['count'].work(), self._parent.Ehdr.shoff),
                "",
                "Section Headers:" ]
        header = {
            32: "  [Nr] Name              Type            Addr     Off    Size   ES Flg Lk Inf Al",
            64: "  [Nr] Name              Type             Address           Offset\n       Size              EntSize          Flags  Link  Info  Align",
            } [self._ptrsize]
        rep.append(header)
        rep.extend([ _.readelf_display_oneliner() for _ in self ])
        rep.extend([ # Footer
"Key to Flags:",
"  W (write), A (alloc), X (execute), M (merge), S (strings)",
"  I (info), L (link order), G (group), T (TLS), E (exclude), x (unknown)",
"  O (extra OS processing required) o (OS specific), p (processor specific)",
            ])
        return "\n".join(rep)
    def elfesteem_repr(self):
        rep = [ "#  section         offset   size   addr     flags" ]
        rep.extend([ "%2i %-15s %08x %06x %08x %x %s" % (i,
                s['name'],
                s['offset'],
                s['size'],
                s['addr'],
                s['flags'],
                s['content'].elfesteem_classname)
            for i, s in enumerate(self) ])
        return "\n".join(rep)
    _ptrsize = property(lambda _: _._parent._get_attr_ancestor('_ptrsize'))

# 3.2. Section content
# 3.2.1. Section content: generic

SHT = NamedConstants((), glob=glob)
def register_section_type(TYPE):
    # Could be used as a decorator, but decorators don't exist in python2.3
    sh_type = TYPE.type
    Shdr.registered[sh_type] = TYPE
    SHT.extend(TYPE.type, 'SHT_%s'%TYPE.type_txt)

class Section(Data):
    """ Section with unstructured content: raw bytestring. """
    def type_txt(self):
        t = self._parent['type'].work()
        if   SHT['SHT_LOOS']   <= t <= SHT['SHT_HIOS']:
            return 'LOOS+%x' % (t-SHT['SHT_LOOS'])
        elif SHT['SHT_LOPROC'] <= t <= SHT['SHT_HIPROC']:
            return 'LOPROC+%x' % (t-SHT['SHT_LOPROC'])
        elif SHT['SHT_LOUSER'] <= t <= SHT['SHT_HIUSER']:
            return 'LOUSER+%x' % (t-SHT['SHT_LOUSER'])
        else:
            return hex(t)
    type_txt = property(type_txt)
    elfesteem_classname = 'Section'

# 3.2.2. Section content: symbols

# Legal values for ST_BIND subfield of st_info (symbol binding).
# bind = Sym.info >> 4
STB = NamedConstants((
    ( 0, 'STB_LOCAL'),        # Local symbol
    ( 1, 'STB_GLOBAL'),       # Global symbol
    ( 2, 'STB_WEAK'),         # Weak symbol
    ( 3, 'STB_NUM'),          # Number of defined types.
    (10, 'STB_GNU_UNIQUE'),
    (10, 'STB_LOOS', None),   # Start of OS-specific
    (12, 'STB_HIOS', None),   # End of OS-specific
    (13, 'STB_LOPROC', None), # Start of processor-specific
    (15, 'STB_HIPROC', None), # End of processor-specific
    ), glob=glob)

# Legal values for ST_TYPE subfield of st_info (symbol type).
# val = Sym.info 0xf
STT = NamedConstants((
    ( 0, 'STT_NOTYPE'),       # Symbol type is unspecified
    ( 1, 'STT_OBJECT'),       # Symbol is a data object
    ( 2, 'STT_FUNC'),         # Symbol is a code object
    ( 3, 'STT_SECTION'),      # Symbol associated with a section
    ( 4, 'STT_FILE'),         # Symbol's name is file name
    ( 5, 'STT_COMMON'),       # Symbol is a common data object
    ( 6, 'STT_TLS'),          # Symbol is thread-local data object*/
    ( 7, 'STT_NUM'),          # Number of defined types.
    (10, 'STT_GNU_IFUNC'),    # GNU indirect function
    (10, 'STT_LOOS', None),   # Start of OS-specific
    # AMDGPU symbol types
    (10, 'STT_AMDGPU_HSA_KERNEL'),
    (11, 'STT_AMDGPU_HSA_INDIRECT_FUNCTION'),
    (12, 'STT_AMDGPU_HSA_METADATA'),
    (12, 'STT_HIOS', None),   # End of OS-specific
    (13, 'STT_LOPROC', None), # Start of processor-specific
    (15, 'STT_HIPROC', None), # End of processor-specific
    ), glob=glob)

# Symbol visibility specification encoded in the st_other field.
STV = NamedConstants((
    ( 0, 'STV_DEFAULT'),   # Default symbol visibility rules
    ( 1, 'STV_INTERNAL'),  # Processor specific hidden class
    ( 2, 'STV_HIDDEN'),    # Sym unavailable to other modules
    ( 3, 'STV_PROTECTED'), # Not preemptible, not exported
    ), glob=glob)

# Special section indices.
SHN = NamedConstants((
    (0,      'SHN_UNDEF'),           # Undefined section
    (0xff00, 'SHN_LORESERVE', None), # Start of reserved indices
    (0xff00, 'SHN_LOPROC', None),    # Start of processor-specific
    (0xff00, 'SHN_BEFORE'),          # Order section before all others (Solaris)
    (0xff01, 'SHN_AFTER'),           # Order section after all others (Solaris)
    (0xff1f, 'SHN_HIPROC', None),    # End of processor-specific
    (0xff20, 'SHN_LOOS', None),      # Start of OS-specific
    (0xff3f, 'SHN_HIOS', None),      # End of OS-specific
    (0xfff1, 'SHN_ABS'),             # Associated symbol is absolute
    (0xfff2, 'SHN_COMMON'),          # Associated symbol is common
    (0xffff, 'SHN_XINDEX'),          # Index is in extra table.
    (0xffff, 'SHN_HIRESERVE', None), # End of reserved indices
    ), glob=glob)

class SymName(NameInStrtab):
    strndx = property(lambda self: self._get_attr_ancestor('link'))

class SymBase(AttributesElfesteem,Struct):
    _virtual_fields = [ 'name' ]
    def __getitem__(self, args):
        if   args == 'idx':
            for k, v in self._parent._subcells.items():
                if v is self: return k
        elif args == 'type':
            val = self._subcells['info'].work() & 0xf
            return STT.text.get(val, 'STT_<unknown>: %d'%val)[4:]
        elif args == 'bind':
            val = self._subcells['info'].work() >> 4
            return STB.text.get(val, 'STB_<unknown>: %d'%val)[4:]
        elif args == 'visibility':
            val = self._subcells['other'].work()
            return STV.text.get(val, 'STV_DEFAULT [<other>: %x] '%val)[4:]
        elif args == 'ndx':
            val = self._subcells['shndx'].work()
            return SHN.text.get(val, 'SHN_%3d'%val)[4:7]
        elif args == 'name':
            return SymName(_parent=self,_name='name')
        else:
            return self._subcells[args]
    def readelf_display(self):
        return self.format % self

class Sym32(SymBase):
    _fields = [
        ('name_idx', Int),
        ('value',    Int),
        ('size',     Int),
        ('info',     Byte),
        ('other',    Byte),
        ('shndx',    Short),
        ]
    format = '%(idx)6d: %(value)08x %(size)5d %(type)-7s %(bind)-6s %(visibility)-7s  %(ndx)-3s %(name)s'

class Sym64(SymBase):
    _fields = [
        ('name_idx', Int),
        ('info',     Byte),
        ('other',    Byte),
        ('shndx',    Short),
        ('value',    Quad),
        ('size',     Quad),
        ]
    format = '%(idx)6d: %(value)016x %(size)5d %(type)-7s %(bind)-6s %(visibility)-7s  %(ndx)-3s %(name)s'

class Section_with_symtab(VarArray):
    _type = property(lambda self: { 32:Sym32, 64:Sym64 } [self._ptrsize])
    __len__ = lambda self: len(self.symtab)
    symtab = property(lambda self: self._wrapped._subcells)
    def __getitem__(self,item):
        if isinstance(item, str):
            for sym in self:
                if item == sym['name'].work():
                    return sym
        return self._wrapped[item]
    def readelf_display(self):
        rep = [ "Symbol table '%s' contains %d entries:"
                % (self._parent['name'], len(self)) ]
        rep.append({
          32:"   Num:    Value  Size Type    Bind   Vis      Ndx Name",
          64:"   Num:    Value          Size Type    Bind   Vis      Ndx Name",
          }[self._ptrsize])
        rep.extend([ _.readelf_display() for _ in self ])
        return "\n".join(rep)
    _ptrsize = property(lambda _: _._parent._get_attr_ancestor('_ptrsize'))

# 3.2.3. Section content: relocations

R = {
# Motorola 68k relocations
'68K': NamedConstants((
    (0, 'R_68K_NONE'),             # No reloc
    (1, 'R_68K_32'),               # Direct 32 bit 
    (2, 'R_68K_16'),               # Direct 16 bit 
    (3, 'R_68K_8'),                # Direct 8 bit 
    (4, 'R_68K_PC32'),             # PC relative 32 bit
    (5, 'R_68K_PC16'),             # PC relative 16 bit
    (6, 'R_68K_PC8'),              # PC relative 8 bit
    (7, 'R_68K_GOT32'),            # 32 bit PC relative GOT entry
    (8, 'R_68K_GOT16'),            # 16 bit PC relative GOT entry
    (9, 'R_68K_GOT8'),             # 8 bit PC relative GOT entry
    (10, 'R_68K_GOT32O'),          # 32 bit GOT offset
    (11, 'R_68K_GOT16O'),          # 16 bit GOT offset
    (12, 'R_68K_GOT8O'),           # 8 bit GOT offset
    (13, 'R_68K_PLT32'),           # 32 bit PC relative PLT address
    (14, 'R_68K_PLT16'),           # 16 bit PC relative PLT address
    (15, 'R_68K_PLT8'),            # 8 bit PC relative PLT address
    (16, 'R_68K_PLT32O'),          # 32 bit PLT offset
    (17, 'R_68K_PLT16O'),          # 16 bit PLT offset
    (18, 'R_68K_PLT8O'),           # 8 bit PLT offset
    (19, 'R_68K_COPY'),            # Copy symbol at runtime
    (20, 'R_68K_GLOB_DAT'),        # Create GOT entry
    (21, 'R_68K_JMP_SLOT'),        # Create PLT entry
    (22, 'R_68K_RELATIVE'),        # Adjust by program base
    (25, 'R_68K_TLS_GD32'),        # 32 bit GOT offset for GD
    (26, 'R_68K_TLS_GD16'),        # 16 bit GOT offset for GD
    (27, 'R_68K_TLS_GD8'),         # 8 bit GOT offset for GD
    (28, 'R_68K_TLS_LDM32'),       # 32 bit GOT offset for LDM
    (29, 'R_68K_TLS_LDM16'),       # 16 bit GOT offset for LDM
    (30, 'R_68K_TLS_LDM8'),        # 8 bit GOT offset for LDM
    (31, 'R_68K_TLS_LDO32'),       # 32 bit module-relative offset
    (32, 'R_68K_TLS_LDO16'),       # 16 bit module-relative offset
    (33, 'R_68K_TLS_LDO8'),        # 8 bit module-relative offset
    (34, 'R_68K_TLS_IE32'),        # 32 bit GOT offset for IE
    (35, 'R_68K_TLS_IE16'),        # 16 bit GOT offset for IE
    (36, 'R_68K_TLS_IE8'),         # 8 bit GOT offset for IE
    (37, 'R_68K_TLS_LE32'),        # 32 bit offset relative to static TLS block
    (38, 'R_68K_TLS_LE16'),        # 16 bit offset relative to static TLS block
    (39, 'R_68K_TLS_LE8'),         # 8 bit offset relative to static TLS block
    (40, 'R_68K_TLS_DTPMOD32'),    # 32 bit module number
    (41, 'R_68K_TLS_DTPREL32'),    # 32 bit module-relative offset
    (42, 'R_68K_TLS_TPREL32'),     # 32 bit TP-relative offset
    (43, 'R_68K_NUM', None),       # Keep this the last entry. 
    ), glob=glob),

# Intel 80386 relocations
'386': NamedConstants((
    (0, 'R_386_NONE'),              # No reloc
    (1, 'R_386_32'),                # Direct 32 bit
    (2, 'R_386_PC32'),              # PC relative 32 bit
    (3, 'R_386_GOT32'),             # 32 bit GOT entry
    (4, 'R_386_PLT32'),             # 32 bit PLT address
    (5, 'R_386_COPY'),              # Copy symbol at runtime
    (6, 'R_386_GLOB_DAT'),          # Create GOT entry
    (7, 'R_386_JMP_SLOT'),          # Create PLT entry
    (8, 'R_386_RELATIVE'),          # Adjust by program base
    (9, 'R_386_GOTOFF'),            # 32 bit offset to GOT
    (10, 'R_386_GOTPC'),            # 32 bit PC relative offset to GOT
    (11, 'R_386_32PLT'),         
    (12, 'R_386_TLS_GD_PLT'),       # This relocation is handled as if it were a R_386_PLT32 relocation referencing the ___tls_get_addr() function
    (13, 'R_386_TLS_LDM_PLT'),      # ?
    (14, 'R_386_TLS_TPOFF'),        # Offset in static TLS block
    (15, 'R_386_TLS_IE'),           # Address of GOT entry for static TLS block offset
    (16, 'R_386_TLS_GOTIE'),        # GOT entry for static TLS block offset
    (17, 'R_386_TLS_LE'),           # Offset relative to static TLS block
    (18, 'R_386_TLS_GD'),           # Direct 32 bit for GNU version of general dynamic thread local data
    (19, 'R_386_TLS_LDM'),          # Direct 32 bit for GNU version of local dynamic thread local data in LE code
    (20, 'R_386_16'),            
    (21, 'R_386_PC16'),          
    (22, 'R_386_8'),             
    (23, 'R_386_PC8'),           
    (24, 'R_386_TLS_GD_32'),        # Direct 32 bit for general dynamic thread local data
    (25, 'R_386_TLS_GD_PUSH'),      # Tag for pushl in GD TLS code
    (26, 'R_386_TLS_GD_CALL'),      # Relocation for call to __tls_get_addr()
    (27, 'R_386_TLS_GD_POP'),       # Tag for popl in GD TLS code
    (28, 'R_386_TLS_LDM_32'),       # Direct 32 bit for local dynamic thread local data in LE code
    (29, 'R_386_TLS_LDM_PUSH'),     # Tag for pushl in LDM TLS code
    (30, 'R_386_TLS_LDM_CALL'),     # Relocation for call to __tls_get_addr() in LDM code
    (31, 'R_386_TLS_LDM_POP'),      # Tag for popl in LDM TLS code
    (32, 'R_386_TLS_LDO_32'),       # Offset relative to TLS block
    (33, 'R_386_TLS_IE_32'),        # GOT entry for negated static TLS block offset
    (34, 'R_386_TLS_LE_32'),        # Negated offset relative to static TLS block
    (35, 'R_386_TLS_DTPMOD32'),     # ID of module containing symbol
    (36, 'R_386_TLS_DTPOFF32'),     # Offset in TLS block
    (37, 'R_386_TLS_TPOFF32'),      # Negated offset in static TLS block
# 38?
    (39, 'R_386_TLS_GOTDESC'),      # GOT offset for TLS descriptor. 
    (40, 'R_386_TLS_DESC_CALL'),    # Marker of call through TLS descriptor for relaxation. 
    (41,  'R_386_TLS_DESC'),        # TLS descriptor containing pointer to code and to argument, returning the TLS offset for the symbol. 
    (42, 'R_386_IRELATIVE'),        # Adjust indirectly by program base
    (43, 'R_386_NUM', None),        # Keep this the last entry. 
    ), glob=glob),

# SUN SPARC relocations
'SPARC': NamedConstants((
    (0, 'R_SPARC_NONE'),                    # No reloc
    (1, 'R_SPARC_8'),                       # Direct 8 bit
    (2, 'R_SPARC_16'),                      # Direct 16 bit
    (3, 'R_SPARC_32'),                      # Direct 32 bit
    (4, 'R_SPARC_DISP8'),                   # PC relative 8 bit
    (5, 'R_SPARC_DISP16'),                  # PC relative 16 bit
    (6, 'R_SPARC_DISP32'),                  # PC relative 32 bit
    (7, 'R_SPARC_WDISP30'),                 # PC relative 30 bit shifted
    (8, 'R_SPARC_WDISP22'),                 # PC relative 22 bit shifted
    (9, 'R_SPARC_HI22'),                    # High 22 bit
    (10, 'R_SPARC_22'),                     # Direct 22 bit
    (11, 'R_SPARC_13'),                     # Direct 13 bit
    (12, 'R_SPARC_LO10'),                   # Truncated 10 bit
    (13, 'R_SPARC_GOT10'),                  # Truncated 10 bit GOT entry
    (14, 'R_SPARC_GOT13'),                  # 13 bit GOT entry
    (15, 'R_SPARC_GOT22'),                  # 22 bit GOT entry shifted
    (16, 'R_SPARC_PC10'),                   # PC relative 10 bit truncated
    (17, 'R_SPARC_PC22'),                   # PC relative 22 bit shifted
    (18, 'R_SPARC_WPLT30'),                 # 30 bit PC relative PLT address
    (19, 'R_SPARC_COPY'),                   # Copy symbol at runtime
    (20, 'R_SPARC_GLOB_DAT'),               # Create GOT entry
    (21, 'R_SPARC_JMP_SLOT'),               # Create PLT entry
    (22, 'R_SPARC_RELATIVE'),               # Adjust by program base
    (23, 'R_SPARC_UA32'),                   # Direct 32 bit unaligned
    # Additional Sparc64 relocs. 
    (24, 'R_SPARC_PLT32'),                  # Direct 32 bit ref to PLT entry
    (25, 'R_SPARC_HIPLT22'),                # High 22 bit PLT entry
    (26, 'R_SPARC_LOPLT10'),                # Truncated 10 bit PLT entry
    (27, 'R_SPARC_PCPLT32'),                # PC rel 32 bit ref to PLT entry
    (28, 'R_SPARC_PCPLT22'),                # PC rel high 22 bit PLT entry
    (29, 'R_SPARC_PCPLT10'),                # PC rel trunc 10 bit PLT entry
    (30, 'R_SPARC_10'),                     # Direct 10 bit
    (31, 'R_SPARC_11'),                     # Direct 11 bit
    (32, 'R_SPARC_64'),                     # Direct 64 bit
    (33, 'R_SPARC_OLO10'),                  # 10bit with secondary 13bit addend
    (34, 'R_SPARC_HH22'),                   # Top 22 bits of direct 64 bit
    (35, 'R_SPARC_HM10'),                   # High middle 10 bits of ...
    (36, 'R_SPARC_LM22'),                   # Low middle 22 bits of ...
    (37, 'R_SPARC_PC_HH22'),                # Top 22 bits of pc rel 64 bit
    (38, 'R_SPARC_PC_HM10'),                # High middle 10 bit of ...
    (39, 'R_SPARC_PC_LM22'),                # Low miggle 22 bits of ...
    (40, 'R_SPARC_WDISP16'),                # PC relative 16 bit shifted
    (41, 'R_SPARC_WDISP19'),                # PC relative 19 bit shifted
    (42, 'R_SPARC_GLOB_JMP'),               # was part of v9 ABI but was removed
    (43, 'R_SPARC_7'),                      # Direct 7 bit
    (44, 'R_SPARC_5'),                      # Direct 5 bit
    (45, 'R_SPARC_6'),                      # Direct 6 bit
    (46, 'R_SPARC_DISP64'),                 # PC relative 64 bit
    (47, 'R_SPARC_PLT64'),                  # Direct 64 bit ref to PLT entry
    (48, 'R_SPARC_HIX22'),                  # High 22 bit complemented
    (49, 'R_SPARC_LOX10'),                  # Truncated 11 bit complemented
    (50, 'R_SPARC_H44'),                    # Direct high 12 of 44 bit
    (51, 'R_SPARC_M44'),                    # Direct mid 22 of 44 bit
    (52, 'R_SPARC_L44'),                    # Direct low 10 of 44 bit
    (53, 'R_SPARC_REGISTER'),               # Global register usage
    (54, 'R_SPARC_UA64'),                   # Direct 64 bit unaligned
    (55, 'R_SPARC_UA16'),                   # Direct 16 bit unaligned
    (56, 'R_SPARC_TLS_GD_HI22'),      
    (57, 'R_SPARC_TLS_GD_LO10'),      
    (58, 'R_SPARC_TLS_GD_ADD'),       
    (59, 'R_SPARC_TLS_GD_CALL'),      
    (60, 'R_SPARC_TLS_LDM_HI22'),     
    (61, 'R_SPARC_TLS_LDM_LO10'),     
    (62, 'R_SPARC_TLS_LDM_ADD'),      
    (63, 'R_SPARC_TLS_LDM_CALL'),     
    (64, 'R_SPARC_TLS_LDO_HIX22'),    
    (65, 'R_SPARC_TLS_LDO_LOX10'),    
    (66, 'R_SPARC_TLS_LDO_ADD'),      
    (67, 'R_SPARC_TLS_IE_HI22'),      
    (68, 'R_SPARC_TLS_IE_LO10'),      
    (69, 'R_SPARC_TLS_IE_LD'),        
    (70, 'R_SPARC_TLS_IE_LDX'),       
    (71, 'R_SPARC_TLS_IE_ADD'),       
    (72, 'R_SPARC_TLS_LE_HIX22'),     
    (73, 'R_SPARC_TLS_LE_LOX10'),     
    (74, 'R_SPARC_TLS_DTPMOD32'),     
    (75, 'R_SPARC_TLS_DTPMOD64'),     
    (76, 'R_SPARC_TLS_DTPOFF32'),     
    (77, 'R_SPARC_TLS_DTPOFF64'),     
    (78, 'R_SPARC_TLS_TPOFF32'),      
    (79, 'R_SPARC_TLS_TPOFF64'),      
    (80, 'R_SPARC_GOTDATA_HIX22'),    
    (81, 'R_SPARC_GOTDATA_LOX10'),    
    (82, 'R_SPARC_GOTDATA_OP_HIX22'),         
    (83, 'R_SPARC_GOTDATA_OP_LOX10'),         
    (84, 'R_SPARC_GOTDATA_OP'),       
    (85, 'R_SPARC_H34'),              
    (86, 'R_SPARC_SIZE32'),           
    (87, 'R_SPARC_SIZE64'),           
    (248, 'R_SPARC_JMP_IREL'),         
    (249, 'R_SPARC_IRELATIVE'),        
    (250, 'R_SPARC_GNU_VTINHERIT'),    
    (251, 'R_SPARC_GNU_VTENTRY'),      
    (252, 'R_SPARC_REV32'),            
    (253, 'R_SPARC_NUM', None),              # Keep this the last entry. 
    ), glob=glob),

# MIPS R3000 relocations
'MIPS': NamedConstants((
    (0, 'R_MIPS_NONE'),             # No reloc
    (1, 'R_MIPS_16'),               # Direct 16 bit
    (2, 'R_MIPS_32'),               # Direct 32 bit
    (3, 'R_MIPS_REL32'),            # PC relative 32 bit
    (4, 'R_MIPS_26'),               # Direct 26 bit shifted
    (5, 'R_MIPS_HI16'),             # High 16 bit
    (6, 'R_MIPS_LO16'),             # Low 16 bit
    (7, 'R_MIPS_GPREL16'),          # GP relative 16 bit
    (8, 'R_MIPS_LITERAL'),          # 16 bit literal entry
    (9, 'R_MIPS_GOT16'),            # 16 bit GOT entry
    (10, 'R_MIPS_PC16'),            # PC relative 16 bit
    (11, 'R_MIPS_CALL16'),          # 16 bit GOT entry for function
    (12, 'R_MIPS_GPREL32'),         # GP relative 32 bit
    (16, 'R_MIPS_SHIFT5'),            
    (17, 'R_MIPS_SHIFT6'),            
    (18, 'R_MIPS_64'),                
    (19, 'R_MIPS_GOT_DISP'),          
    (20, 'R_MIPS_GOT_PAGE'),          
    (21, 'R_MIPS_GOT_OFST'),          
    (22, 'R_MIPS_GOT_HI16'),          
    (23, 'R_MIPS_GOT_LO16'),          
    (24, 'R_MIPS_SUB'),               
    (25, 'R_MIPS_INSERT_A'),          
    (26, 'R_MIPS_INSERT_B'),          
    (27, 'R_MIPS_DELETE'),            
    (28, 'R_MIPS_HIGHER'),            
    (29, 'R_MIPS_HIGHEST'),           
    (30, 'R_MIPS_CALL_HI16'),         
    (31, 'R_MIPS_CALL_LO16'),         
    (32, 'R_MIPS_SCN_DISP'),          
    (33, 'R_MIPS_REL16'),             
    (34, 'R_MIPS_ADD_IMMEDIATE'),     
    (35, 'R_MIPS_PJUMP'),             
    (36, 'R_MIPS_RELGOT'),            
    (37, 'R_MIPS_JALR'),              
    (38, 'R_MIPS_TLS_DTPMOD32'),    # Module number 32 bit
    (39, 'R_MIPS_TLS_DTPREL32'),    # Module-relative offset 32 bit
    (40, 'R_MIPS_TLS_DTPMOD64'),    # Module number 64 bit
    (41, 'R_MIPS_TLS_DTPREL64'),    # Module-relative offset 64 bit
    (42, 'R_MIPS_TLS_GD'),          # 16 bit GOT offset for GD
    (43, 'R_MIPS_TLS_LDM'),         # 16 bit GOT offset for LDM
    (44, 'R_MIPS_TLS_DTPREL_HI16'), # Module-relative offset, high 16 bits
    (45, 'R_MIPS_TLS_DTPREL_LO16'), # Module-relative offset, low 16 bits
    (46, 'R_MIPS_TLS_GOTTPREL'),    # 16 bit GOT offset for IE
    (47, 'R_MIPS_TLS_TPREL32'),     # TP-relative offset, 32 bit
    (48, 'R_MIPS_TLS_TPREL64'),     # TP-relative offset, 64 bit
    (49, 'R_MIPS_TLS_TPREL_HI16'),  # TP-relative offset, high 16 bits
    (50, 'R_MIPS_TLS_TPREL_LO16'),  # TP-relative offset, low 16 bits
    (51, 'R_MIPS_GLOB_DAT'),          
    (126, 'R_MIPS_COPY'),              
    (127, 'R_MIPS_JUMP_SLOT'),         
    (128, 'R_MIPS_NUM', None),      # Keep this the last entry. 
    ), glob=glob),

# HPPA relocations
'PARISC': NamedConstants((
    (0, 'R_PARISC_NONE'),             # No reloc. 
    (1, 'R_PARISC_DIR32'),            # Direct 32-bit reference. 
    (2, 'R_PARISC_DIR21L'),           # Left 21 bits of eff. address. 
    (3, 'R_PARISC_DIR17R'),           # Right 17 bits of eff. address. 
    (4, 'R_PARISC_DIR17F'),           # 17 bits of eff. address. 
    (6, 'R_PARISC_DIR14R'),           # Right 14 bits of eff. address. 
    (9, 'R_PARISC_PCREL32'),          # 32-bit rel. address. 
    (10, 'R_PARISC_PCREL21L'),        # Left 21 bits of rel. address. 
    (11, 'R_PARISC_PCREL17R'),        # Right 17 bits of rel. address. 
    (12, 'R_PARISC_PCREL17F'),        # 17 bits of rel. address. 
    (14, 'R_PARISC_PCREL14R'),        # Right 14 bits of rel. address. 
    (18, 'R_PARISC_DPREL21L'),        # Left 21 bits of rel. address. 
    (22, 'R_PARISC_DPREL14R'),        # Right 14 bits of rel. address. 
    (26, 'R_PARISC_GPREL21L'),        # GP-relative, left 21 bits. 
    (30, 'R_PARISC_GPREL14R'),        # GP-relative, right 14 bits. 
    (34, 'R_PARISC_LTOFF21L'),        # LT-relative, left 21 bits. 
    (38, 'R_PARISC_LTOFF14R'),        # LT-relative, right 14 bits. 
    (41, 'R_PARISC_SECREL32'),        # 32 bits section rel. address. 
    (48, 'R_PARISC_SEGBASE'),         # No relocation, set segment base. 
    (49, 'R_PARISC_SEGREL32'),        # 32 bits segment rel. address. 
    (50, 'R_PARISC_PLTOFF21L'),       # PLT rel. address, left 21 bits. 
    (54, 'R_PARISC_PLTOFF14R'),       # PLT rel. address, right 14 bits. 
    (57, 'R_PARISC_LTOFF_FPTR32'),    # 32 bits LT-rel. function pointer.
    (58, 'R_PARISC_LTOFF_FPTR21L'),   # LT-rel. fct ptr, left 21 bits.
    (62, 'R_PARISC_LTOFF_FPTR14R'),   # LT-rel. fct ptr, right 14 bits.
    (64, 'R_PARISC_FPTR64'),          # 64 bits function address. 
    (65, 'R_PARISC_PLABEL32'),        # 32 bits function address. 
    (66, 'R_PARISC_PLABEL21L'),       # Left 21 bits of fdesc address. 
    (70, 'R_PARISC_PLABEL14R'),       # Right 14 bits of fdesc address. 
    (72, 'R_PARISC_PCREL64'),         # 64 bits PC-rel. address. 
    (74, 'R_PARISC_PCREL22F'),        # 22 bits PC-rel. address. 
    (75, 'R_PARISC_PCREL14WR'),       # PC-rel. address, right 14 bits. 
    (76, 'R_PARISC_PCREL14DR'),       # PC rel. address, right 14 bits. 
    (77, 'R_PARISC_PCREL16F'),        # 16 bits PC-rel. address. 
    (78, 'R_PARISC_PCREL16WF'),       # 16 bits PC-rel. address. 
    (79, 'R_PARISC_PCREL16DF'),       # 16 bits PC-rel. address. 
    (80, 'R_PARISC_DIR64'),           # 64 bits of eff. address. 
    (83, 'R_PARISC_DIR14WR'),         # 14 bits of eff. address. 
    (84, 'R_PARISC_DIR14DR'),         # 14 bits of eff. address. 
    (85, 'R_PARISC_DIR16F'),          # 16 bits of eff. address. 
    (86, 'R_PARISC_DIR16WF'),         # 16 bits of eff. address. 
    (87, 'R_PARISC_DIR16DF'),         # 16 bits of eff. address. 
    (88, 'R_PARISC_GPREL64'),         # 64 bits of GP-rel. address. 
    (91, 'R_PARISC_GPREL14WR'),       # GP-rel. address, right 14 bits. 
    (92, 'R_PARISC_GPREL14DR'),       # GP-rel. address, right 14 bits. 
    (93, 'R_PARISC_GPREL16F'),        # 16 bits GP-rel. address. 
    (94, 'R_PARISC_GPREL16WF'),       # 16 bits GP-rel. address. 
    (95, 'R_PARISC_GPREL16DF'),       # 16 bits GP-rel. address. 
    (96, 'R_PARISC_LTOFF64'),         # 64 bits LT-rel. address. 
    (99, 'R_PARISC_LTOFF14WR'),       # LT-rel. address, right 14 bits. 
    (100, 'R_PARISC_LTOFF14DR'),      # LT-rel. address, right 14 bits. 
    (101, 'R_PARISC_LTOFF16F'),       # 16 bits LT-rel. address. 
    (102, 'R_PARISC_LTOFF16WF'),      # 16 bits LT-rel. address. 
    (103, 'R_PARISC_LTOFF16DF'),      # 16 bits LT-rel. address. 
    (104, 'R_PARISC_SECREL64'),       # 64 bits section rel. address. 
    (112, 'R_PARISC_SEGREL64'),       # 64 bits segment rel. address. 
    (115, 'R_PARISC_PLTOFF14WR'),     # PLT-rel. address, right 14 bits. 
    (116, 'R_PARISC_PLTOFF14DR'),     # PLT-rel. address, right 14 bits. 
    (117, 'R_PARISC_PLTOFF16F'),      # 16 bits LT-rel. address. 
    (118, 'R_PARISC_PLTOFF16WF'),     # 16 bits PLT-rel. address. 
    (119, 'R_PARISC_PLTOFF16DF'),     # 16 bits PLT-rel. address. 
    (120, 'R_PARISC_LTOFF_FPTR64'),   # 64 bits LT-rel. function ptr. 
    (123, 'R_PARISC_LTOFF_FPTR14WR'), # LT-rel. fct. ptr., right 14 bits.
    (124, 'R_PARISC_LTOFF_FPTR14DR'), # LT-rel. fct. ptr., right 14 bits.
    (125, 'R_PARISC_LTOFF_FPTR16F'),  # 16 bits LT-rel. function ptr. 
    (126, 'R_PARISC_LTOFF_FPTR16WF'), # 16 bits LT-rel. function ptr. 
    (127, 'R_PARISC_LTOFF_FPTR16DF'), # 16 bits LT-rel. function ptr. 
    (128, 'R_PARISC_LORESERVE', None),       
    (128, 'R_PARISC_COPY'),           # Copy relocation. 
    (129, 'R_PARISC_IPLT'),           # Dynamic reloc, imported PLT
    (130, 'R_PARISC_EPLT'),           # Dynamic reloc, exported PLT
    (153, 'R_PARISC_TPREL32'),        # 32 bits TP-rel. address. 
    (153, 'R_PARISC_TLS_TPREL32'),    # idem
    (154, 'R_PARISC_TPREL21L'),       # TP-rel. address, left 21 bits. 
    (154, 'R_PARISC_TLS_LE21L'),      # idem
    (158, 'R_PARISC_TPREL14R'),       # TP-rel. address, right 14 bits. 
    (158, 'R_PARISC_TLS_LE14R'),      # idem
    (162, 'R_PARISC_LTOFF_TP21L'),    # LT-TP-rel. address, left 21 bits.
    (162, 'R_PARISC_TLS_IE21L'),      # idem
    (166, 'R_PARISC_LTOFF_TP14R'),    # LT-TP-rel. address, right 14 bits.
    (166, 'R_PARISC_TLS_IE14R'),      # idem
    (167, 'R_PARISC_LTOFF_TP14F'),    # 14 bits LT-TP-rel. address. 
    (216, 'R_PARISC_TPREL64'),        # 64 bits TP-rel. address. 
    (216, 'R_PARISC_TLS_TPREL64'),    # idem
    (219, 'R_PARISC_TPREL14WR'),      # TP-rel. address, right 14 bits. 
    (220, 'R_PARISC_TPREL14DR'),      # TP-rel. address, right 14 bits. 
    (221, 'R_PARISC_TPREL16F'),       # 16 bits TP-rel. address. 
    (222, 'R_PARISC_TPREL16WF'),      # 16 bits TP-rel. address. 
    (223, 'R_PARISC_TPREL16DF'),      # 16 bits TP-rel. address. 
    (224, 'R_PARISC_LTOFF_TP64'),     # 64 bits LT-TP-rel. address. 
    (227, 'R_PARISC_LTOFF_TP14WR'),   # LT-TP-rel. address, right 14 bits.
    (228, 'R_PARISC_LTOFF_TP14DR'),   # LT-TP-rel. address, right 14 bits.
    (229, 'R_PARISC_LTOFF_TP16F'),    # 16 bits LT-TP-rel. address. 
    (230, 'R_PARISC_LTOFF_TP16WF'),   # 16 bits LT-TP-rel. address. 
    (231, 'R_PARISC_LTOFF_TP16DF'),   # 16 bits LT-TP-rel. address. 
    (232, 'R_PARISC_GNU_VTENTRY'),     
    (233, 'R_PARISC_GNU_VTINHERIT'),   
    (234, 'R_PARISC_TLS_GD21L'),      # GD 21-bit left. 
    (235, 'R_PARISC_TLS_GD14R'),      # GD 14-bit right. 
    (236, 'R_PARISC_TLS_GDCALL'),     # GD call to __t_g_a. 
    (237, 'R_PARISC_TLS_LDM21L'),     # LD module 21-bit left. 
    (238, 'R_PARISC_TLS_LDM14R'),     # LD module 14-bit right. 
    (239, 'R_PARISC_TLS_LDMCALL'),    # LD module call to __t_g_a. 
    (240, 'R_PARISC_TLS_LDO21L'),     # LD offset 21-bit left. 
    (241, 'R_PARISC_TLS_LDO14R'),     # LD offset 14-bit right. 
    (242, 'R_PARISC_TLS_DTPMOD32'),   # DTP module 32-bit. 
    (243, 'R_PARISC_TLS_DTPMOD64'),   # DTP module 64-bit. 
    (244, 'R_PARISC_TLS_DTPOFF32'),   # DTP offset 32-bit. 
    (245, 'R_PARISC_TLS_DTPOFF64'),   # DTP offset 32-bit. 
    (255, 'R_PARISC_HIRESERVE', None),       
    ), glob=glob),

# Alpha relocations
'ALPHA': NamedConstants((
    (0, 'R_ALPHA_NONE'),            # No reloc
    (1, 'R_ALPHA_REFLONG'),         # Direct 32 bit
    (2, 'R_ALPHA_REFQUAD'),         # Direct 64 bit
    (3, 'R_ALPHA_GPREL32'),         # GP relative 32 bit
    (4, 'R_ALPHA_LITERAL'),         # GP relative 16 bit w/optimization
    (5, 'R_ALPHA_LITUSE'),          # Optimization hint for LITERAL
    (6, 'R_ALPHA_GPDISP'),          # Add displacement to GP
    (7, 'R_ALPHA_BRADDR'),          # PC+4 relative 23 bit shifted
    (8, 'R_ALPHA_HINT'),            # PC+4 relative 16 bit shifted
    (9, 'R_ALPHA_SREL16'),          # PC relative 16 bit
    (10, 'R_ALPHA_SREL32'),         # PC relative 32 bit
    (11, 'R_ALPHA_SREL64'),         # PC relative 64 bit
    (17, 'R_ALPHA_GPRELHIGH'),      # GP relative 32 bit, high 16 bits
    (18, 'R_ALPHA_GPRELLOW'),       # GP relative 32 bit, low 16 bits
    (19, 'R_ALPHA_GPREL16'),        # GP relative 16 bit
    (24, 'R_ALPHA_COPY'),           # Copy symbol at runtime
    (25, 'R_ALPHA_GLOB_DAT'),       # Create GOT entry
    (26, 'R_ALPHA_JMP_SLOT'),       # Create PLT entry
    (27, 'R_ALPHA_RELATIVE'),       # Adjust by program base
    (28, 'R_ALPHA_TLS_GD_HI'),        
    (29, 'R_ALPHA_TLSGD'),            
    (30, 'R_ALPHA_TLS_LDM'),          
    (31, 'R_ALPHA_DTPMOD64'),         
    (32, 'R_ALPHA_GOTDTPREL'),        
    (33, 'R_ALPHA_DTPREL64'),         
    (34, 'R_ALPHA_DTPRELHI'),         
    (35, 'R_ALPHA_DTPRELLO'),         
    (36, 'R_ALPHA_DTPREL16'),         
    (37, 'R_ALPHA_GOTTPREL'),         
    (38, 'R_ALPHA_TPREL64'),          
    (39, 'R_ALPHA_TPRELHI'),          
    (40, 'R_ALPHA_TPRELLO'),          
    (41, 'R_ALPHA_TPREL16'),          
    (46, 'R_ALPHA_NUM', None),      # Keep this the last entry. 
    ), glob=glob),

# PowerPC relocations
'PPC': NamedConstants((
    (0, 'R_PPC_NONE'),               
    (1, 'R_PPC_ADDR32'),          # 32bit absolute address
    (2, 'R_PPC_ADDR24'),          # 26bit address, 2 bits ignored. 
    (3, 'R_PPC_ADDR16'),          # 16bit absolute address
    (4, 'R_PPC_ADDR16_LO'),       # lower 16bit of absolute address
    (5, 'R_PPC_ADDR16_HI'),       # high 16bit of absolute address
    (6, 'R_PPC_ADDR16_HA'),       # adjusted high 16bit
    (7, 'R_PPC_ADDR14'),          # 16bit address, 2 bits ignored
    (8, 'R_PPC_ADDR14_BRTAKEN'),     
    (9, 'R_PPC_ADDR14_BRNTAKEN'),    
    (10, 'R_PPC_REL24'),          # PC relative 26 bit
    (11, 'R_PPC_REL14'),          # PC relative 16 bit
    (12, 'R_PPC_REL14_BRTAKEN'),      
    (13, 'R_PPC_REL14_BRNTAKEN'),     
    (14, 'R_PPC_GOT16'),              
    (15, 'R_PPC_GOT16_LO'),           
    (16, 'R_PPC_GOT16_HI'),           
    (17, 'R_PPC_GOT16_HA'),           
    (18, 'R_PPC_PLTREL24'),           
    (19, 'R_PPC_COPY'),               
    (20, 'R_PPC_GLOB_DAT'),           
    (21, 'R_PPC_JMP_SLOT'),           
    (22, 'R_PPC_RELATIVE'),           
    (23, 'R_PPC_LOCAL24PC'),          
    (24, 'R_PPC_UADDR32'),            
    (25, 'R_PPC_UADDR16'),            
    (26, 'R_PPC_REL32'),              
    (27, 'R_PPC_PLT32'),              
    (28, 'R_PPC_PLTREL32'),           
    (29, 'R_PPC_PLT16_LO'),           
    (30, 'R_PPC_PLT16_HI'),           
    (31, 'R_PPC_PLT16_HA'),           
    (32, 'R_PPC_SDAREL16'),           
    (33, 'R_PPC_SECTOFF'),            
    (34, 'R_PPC_SECTOFF_LO'),         
    (35, 'R_PPC_SECTOFF_HI'),         
    (36, 'R_PPC_SECTOFF_HA'),         
    # PowerPC relocations defined for the TLS access ABI. 
    (67, 'R_PPC_TLS'),                 # none       (sym+add)@tls
    (68, 'R_PPC_DTPMOD32'),            # word32     (sym+add)@dtpmod
    (69, 'R_PPC_TPREL16'),             # half16*    (sym+add)@tprel
    (70, 'R_PPC_TPREL16_LO'),          # half16     (sym+add)@tprel@l
    (71, 'R_PPC_TPREL16_HI'),          # half16     (sym+add)@tprel@h
    (72, 'R_PPC_TPREL16_HA'),          # half16     (sym+add)@tprel@ha
    (73, 'R_PPC_TPREL32'),             # word32     (sym+add)@tprel
    (74, 'R_PPC_DTPREL16'),            # half16*    (sym+add)@dtprel
    (75, 'R_PPC_DTPREL16_LO'),         # half16     (sym+add)@dtprel@l
    (76, 'R_PPC_DTPREL16_HI'),         # half16     (sym+add)@dtprel@h
    (77, 'R_PPC_DTPREL16_HA'),         # half16     (sym+add)@dtprel@ha
    (78, 'R_PPC_DTPREL32'),            # word32     (sym+add)@dtprel
    (79, 'R_PPC_GOT_TLSGD16'),         # half16*    (sym+add)@got@tlsgd
    (80, 'R_PPC_GOT_TLSGD16_LO'),      # half16     (sym+add)@got@tlsgd@l
    (81, 'R_PPC_GOT_TLSGD16_HI'),      # half16     (sym+add)@got@tlsgd@h
    (82, 'R_PPC_GOT_TLSGD16_HA'),      # half16     (sym+add)@got@tlsgd@ha
    (83, 'R_PPC_GOT_TLSLD16'),         # half16*    (sym+add)@got@tlsld
    (84, 'R_PPC_GOT_TLSLD16_LO'),      # half16     (sym+add)@got@tlsld@l
    (85, 'R_PPC_GOT_TLSLD16_HI'),      # half16     (sym+add)@got@tlsld@h
    (86, 'R_PPC_GOT_TLSLD16_HA'),      # half16     (sym+add)@got@tlsld@ha
    (87, 'R_PPC_GOT_TPREL16'),         # half16*    (sym+add)@got@tprel
    (88, 'R_PPC_GOT_TPREL16_LO'),      # half16     (sym+add)@got@tprel@l
    (89, 'R_PPC_GOT_TPREL16_HI'),      # half16     (sym+add)@got@tprel@h
    (90, 'R_PPC_GOT_TPREL16_HA'),      # half16     (sym+add)@got@tprel@ha
    (91, 'R_PPC_GOT_DTPREL16'),        # half16*    (sym+add)@got@dtprel
    (92, 'R_PPC_GOT_DTPREL16_LO'),     # half16*    (sym+add)@got@dtprel@l
    (93, 'R_PPC_GOT_DTPREL16_HI'),     # half16*    (sym+add)@got@dtprel@h
    (94, 'R_PPC_GOT_DTPREL16_HA'),     # half16*    (sym+add)@got@dtprel@ha
    # The remaining relocs are from the Embedded ELF ABI, and are not in the SVR4 ELF ABI. 
    (101, 'R_PPC_EMB_NADDR32'),        
    (102, 'R_PPC_EMB_NADDR16'),        
    (103, 'R_PPC_EMB_NADDR16_LO'),     
    (104, 'R_PPC_EMB_NADDR16_HI'),     
    (105, 'R_PPC_EMB_NADDR16_HA'),     
    (106, 'R_PPC_EMB_SDAI16'),         
    (107, 'R_PPC_EMB_SDA2I16'),        
    (108, 'R_PPC_EMB_SDA2REL'),        
    (109, 'R_PPC_EMB_SDA21'),               # 16 bit offset in SDA
    (110, 'R_PPC_EMB_MRKREF'),         
    (111, 'R_PPC_EMB_RELSEC16'),       
    (112, 'R_PPC_EMB_RELST_LO'),       
    (113, 'R_PPC_EMB_RELST_HI'),       
    (114, 'R_PPC_EMB_RELST_HA'),       
    (115, 'R_PPC_EMB_BIT_FLD'),        
    (116, 'R_PPC_EMB_RELSDA'),              # 16 bit relative offset in SDA
    # Diab tool relocations. 
    (180, 'R_PPC_DIAB_SDA21_LO'),     # like EMB_SDA21, but lower 16 bit
    (181, 'R_PPC_DIAB_SDA21_HI'),     # like EMB_SDA21, but high 16 bit
    (182, 'R_PPC_DIAB_SDA21_HA'),     # like EMB_SDA21, adjusted high 16
    (183, 'R_PPC_DIAB_RELSDA_LO'),    # like EMB_RELSDA, but lower 16 bit
    (184, 'R_PPC_DIAB_RELSDA_HI'),    # like EMB_RELSDA, but high 16 bit
    (185, 'R_PPC_DIAB_RELSDA_HA'),    # like EMB_RELSDA, adjusted high 16
    # GNU extension to support local ifunc. 
    (248, 'R_PPC_IRELATIVE'),          
    # GNU relocs used in PIC code sequences. 
    (249, 'R_PPC_REL16'),             # half16   (sym+add-.)
    (250, 'R_PPC_REL16_LO'),          # half16   (sym+add-.)@l
    (251, 'R_PPC_REL16_HI'),          # half16   (sym+add-.)@h
    (252, 'R_PPC_REL16_HA'),          # half16   (sym+add-.)@ha
    # This is a phony reloc to handle any old fashioned TOC16 references that may still be in object files. 
    (255, 'R_PPC_TOC16'),              
    ), glob=glob),

# PowerPC64 relocations defined by the ABIs
"""
'PPC64': NamedConstants((
R_PPC64_NONE            = R_PPC_NONE,
R_PPC64_ADDR32          = R_PPC_ADDR32, # 32bit absolute address
R_PPC64_ADDR24          = R_PPC_ADDR24, # 26bit address, word aligned
R_PPC64_ADDR16          = R_PPC_ADDR16, # 16bit absolute address
R_PPC64_ADDR16_LO       = R_PPC_ADDR16_LO, # lower 16bits of address
R_PPC64_ADDR16_HI       = R_PPC_ADDR16_HI, # high 16bits of address.
R_PPC64_ADDR16_HA       = R_PPC_ADDR16_HA, # adjusted high 16bits. 
R_PPC64_ADDR14          = R_PPC_ADDR14, # 16bit address, word aligned
R_PPC64_ADDR14_BRTAKEN  = R_PPC_ADDR14_BRTAKEN,
R_PPC64_ADDR14_BRNTAKEN = R_PPC_ADDR14_BRNTAKEN,
R_PPC64_REL24           = R_PPC_REL24, # PC-rel. 26 bit, word aligned
R_PPC64_REL14           = R_PPC_REL14, # PC relative 16 bit
R_PPC64_REL14_BRTAKEN   = R_PPC_REL14_BRTAKEN,
R_PPC64_REL14_BRNTAKEN  = R_PPC_REL14_BRNTAKEN,
R_PPC64_GOT16           = R_PPC_GOT16,
R_PPC64_GOT16_LO        = R_PPC_GOT16_LO,
R_PPC64_GOT16_HI        = R_PPC_GOT16_HI,
R_PPC64_GOT16_HA        = R_PPC_GOT16_HA,

R_PPC64_COPY            = R_PPC_COPY,
R_PPC64_GLOB_DAT        = R_PPC_GLOB_DAT,
R_PPC64_JMP_SLOT        = R_PPC_JMP_SLOT,
R_PPC64_RELATIVE        = R_PPC_RELATIVE,

R_PPC64_UADDR32         = R_PPC_UADDR32,
R_PPC64_UADDR16         = R_PPC_UADDR16,
R_PPC64_REL32           = R_PPC_REL32,
R_PPC64_PLT32           = R_PPC_PLT32,
R_PPC64_PLTREL32        = R_PPC_PLTREL32,
R_PPC64_PLT16_LO        = R_PPC_PLT16_LO,
R_PPC64_PLT16_HI        = R_PPC_PLT16_HI,
R_PPC64_PLT16_HA        = R_PPC_PLT16_HA,

R_PPC64_SECTOFF         = R_PPC_SECTOFF,
R_PPC64_SECTOFF_LO      = R_PPC_SECTOFF_LO,
R_PPC64_SECTOFF_HI      = R_PPC_SECTOFF_HI,
R_PPC64_SECTOFF_HA      = R_PPC_SECTOFF_HA,
    (37, 'R_PPC64_ADDR30'),            # word30 (S + A - P) >> 2
    (38, 'R_PPC64_ADDR64'),            # doubleword64 S + A
    (39, 'R_PPC64_ADDR16_HIGHER'),     # half16 #higher(S + A)
    (40, 'R_PPC64_ADDR16_HIGHERA'),    # half16 #highera(S + A)
    (41, 'R_PPC64_ADDR16_HIGHEST'),    # half16 #highest(S + A)
    (42, 'R_PPC64_ADDR16_HIGHESTA'),   # half16 #highesta(S + A)
    (43, 'R_PPC64_UADDR64'),           # doubleword64 S + A
    (44, 'R_PPC64_REL64'),             # doubleword64 S + A - P
    (45, 'R_PPC64_PLT64'),             # doubleword64 L + A
    (46, 'R_PPC64_PLTREL64'),          # doubleword64 L + A - P
    (47, 'R_PPC64_TOC16'),             # half16* S + A - .TOC
    (48, 'R_PPC64_TOC16_LO'),          # half16 #lo(S + A - .TOC.)
    (49, 'R_PPC64_TOC16_HI'),          # half16 #hi(S + A - .TOC.)
    (50, 'R_PPC64_TOC16_HA'),          # half16 #ha(S + A - .TOC.)
    (51, 'R_PPC64_TOC'),               # doubleword64 .TOC
    (52, 'R_PPC64_PLTGOT16'),          # half16* M + A
    (53, 'R_PPC64_PLTGOT16_LO'),       # half16 #lo(M + A)
    (54, 'R_PPC64_PLTGOT16_HI'),       # half16 #hi(M + A)
    (55, 'R_PPC64_PLTGOT16_HA'),       # half16 #ha(M + A)

    (56, 'R_PPC64_ADDR16_DS'),         # half16ds* (S + A) >> 2
    (57, 'R_PPC64_ADDR16_LO_DS'),      # half16ds  #lo(S + A) >> 2
    (58, 'R_PPC64_GOT16_DS'),          # half16ds* (G + A) >> 2
    (59, 'R_PPC64_GOT16_LO_DS'),       # half16ds  #lo(G + A) >> 2
    (60, 'R_PPC64_PLT16_LO_DS'),       # half16ds  #lo(L + A) >> 2
    (61, 'R_PPC64_SECTOFF_DS'),        # half16ds* (R + A) >> 2
    (62, 'R_PPC64_SECTOFF_LO_DS'),     # half16ds  #lo(R + A) >> 2
    (63, 'R_PPC64_TOC16_DS'),          # half16ds* (S + A - .TOC.) >> 2
    (64, 'R_PPC64_TOC16_LO_DS'),       # half16ds  #lo(S + A - .TOC.) >> 2
    (65, 'R_PPC64_PLTGOT16_DS'),       # half16ds* (M + A) >> 2
    (66, 'R_PPC64_PLTGOT16_LO_DS'),    # half16ds  #lo(M + A) >> 2

# PowerPC64 relocations defined for the TLS access ABI. 
    (67, 'R_PPC64_TLS'),               # none       (sym+add)@tls
    (68, 'R_PPC64_DTPMOD64'),          # doubleword64 (sym+add)@dtpmod
    (69, 'R_PPC64_TPREL16'),           # half16*    (sym+add)@tprel
    (70, 'R_PPC64_TPREL16_LO'),        # half16     (sym+add)@tprel@l
    (71, 'R_PPC64_TPREL16_HI'),        # half16     (sym+add)@tprel@h
    (72, 'R_PPC64_TPREL16_HA'),        # half16     (sym+add)@tprel@ha
    (73, 'R_PPC64_TPREL64'),           # doubleword64 (sym+add)@tprel
    (74, 'R_PPC64_DTPREL16'),          # half16*    (sym+add)@dtprel
    (75, 'R_PPC64_DTPREL16_LO'),       # half16     (sym+add)@dtprel@l
    (76, 'R_PPC64_DTPREL16_HI'),       # half16     (sym+add)@dtprel@h
    (77, 'R_PPC64_DTPREL16_HA'),       # half16     (sym+add)@dtprel@ha
    (78, 'R_PPC64_DTPREL64'),          # doubleword64 (sym+add)@dtprel
    (79, 'R_PPC64_GOT_TLSGD16'),       # half16*    (sym+add)@got@tlsgd
    (80, 'R_PPC64_GOT_TLSGD16_LO'),    # half16     (sym+add)@got@tlsgd@l
    (81, 'R_PPC64_GOT_TLSGD16_HI'),    # half16     (sym+add)@got@tlsgd@h
    (82, 'R_PPC64_GOT_TLSGD16_HA'),    # half16     (sym+add)@got@tlsgd@ha
    (83, 'R_PPC64_GOT_TLSLD16'),       # half16*    (sym+add)@got@tlsld
    (84, 'R_PPC64_GOT_TLSLD16_LO'),    # half16     (sym+add)@got@tlsld@l
    (85, 'R_PPC64_GOT_TLSLD16_HI'),    # half16     (sym+add)@got@tlsld@h
    (86, 'R_PPC64_GOT_TLSLD16_HA'),    # half16     (sym+add)@got@tlsld@ha
    (87, 'R_PPC64_GOT_TPREL16_DS'),    # half16ds*  (sym+add)@got@tprel
    (88, 'R_PPC64_GOT_TPREL16_LO_DS'),   # half16ds (sym+add)@got@tprel@l
    (89, 'R_PPC64_GOT_TPREL16_HI'),    # half16     (sym+add)@got@tprel@h
    (90, 'R_PPC64_GOT_TPREL16_HA'),    # half16     (sym+add)@got@tprel@ha
    (91, 'R_PPC64_GOT_DTPREL16_DS'),   # half16ds*  (sym+add)@got@dtprel
    (92, 'R_PPC64_GOT_DTPREL16_LO_DS'),   # half16ds (sym+add)@got@dtprel@l
    (93, 'R_PPC64_GOT_DTPREL16_HI'),   # half16     (sym+add)@got@dtprel@h
    (94, 'R_PPC64_GOT_DTPREL16_HA'),   # half16     (sym+add)@got@dtprel@ha
    (95, 'R_PPC64_TPREL16_DS'),        # half16ds*  (sym+add)@tprel
    (96, 'R_PPC64_TPREL16_LO_DS'),     # half16ds   (sym+add)@tprel@l
    (97, 'R_PPC64_TPREL16_HIGHER'),    # half16     (sym+add)@tprel@higher
    (98, 'R_PPC64_TPREL16_HIGHERA'),   # half16     (sym+add)@tprel@highera
    (99, 'R_PPC64_TPREL16_HIGHEST'),   # half16     (sym+add)@tprel@highest
    (100, 'R_PPC64_TPREL16_HIGHESTA'),   # half16   (sym+add)@tprel@highesta
    (101, 'R_PPC64_DTPREL16_DS'),       # half16ds* (sym+add)@dtprel
    (102, 'R_PPC64_DTPREL16_LO_DS'),    # half16ds  (sym+add)@dtprel@l
    (103, 'R_PPC64_DTPREL16_HIGHER'),   # half16    (sym+add)@dtprel@higher
    (104, 'R_PPC64_DTPREL16_HIGHERA'),   # half16   (sym+add)@dtprel@highera
    (105, 'R_PPC64_DTPREL16_HIGHEST'),   # half16   (sym+add)@dtprel@highest
    (106, 'R_PPC64_DTPREL16_HIGHESTA'),   # half16  (sym+add)@dtprel@highesta

# GNU extension to support local ifunc. 
    (247, 'R_PPC64_JMP_IREL'),         
    (248, 'R_PPC64_IRELATIVE'),        
    (249, 'R_PPC64_REL16'),                 # half16   (sym+add-.)
    (250, 'R_PPC64_REL16_LO'),              # half16   (sym+add-.)@l
    (251, 'R_PPC64_REL16_HI'),              # half16   (sym+add-.)@h
    (252, 'R_PPC64_REL16_HA'),              # half16   (sym+add-.)@ha
    ), glob=glob),
"""

# ARM relocations
'ARM': NamedConstants((
    (0, 'R_ARM_NONE'),              # No reloc
    (1, 'R_ARM_PC24'),              # PC relative 26 bit branch
    (2, 'R_ARM_ABS32'),             # Direct 32 bit 
    (3, 'R_ARM_REL32'),             # PC relative 32 bit
    (4, 'R_ARM_PC13'),               
    (5, 'R_ARM_ABS16'),             # Direct 16 bit
    (6, 'R_ARM_ABS12'),             # Direct 12 bit
    (7, 'R_ARM_THM_ABS5'),           
    (8, 'R_ARM_ABS8'),              # Direct 8 bit
    (9, 'R_ARM_SBREL32'),            
    (10, 'R_ARM_THM_PC22'),           
    (11, 'R_ARM_THM_PC8'),            
    (12, 'R_ARM_AMP_VCALL9'),         
    (13, 'R_ARM_TLS_DESC'),         # Dynamic relocation. 
    (13, 'R_ARM_SWI24', None),      # Obsolete static relocation. 
    (14, 'R_ARM_THM_SWI8'),           
    (15, 'R_ARM_XPC25'),              
    (16, 'R_ARM_THM_XPC22'),          
    (17, 'R_ARM_TLS_DTPMOD32'),     # ID of module containing symbol
    (18, 'R_ARM_TLS_DTPOFF32'),     # Offset in TLS block
    (19, 'R_ARM_TLS_TPOFF32'),      # Offset in static TLS block
    (20, 'R_ARM_COPY'),             # Copy symbol at runtime
    (21, 'R_ARM_GLOB_DAT'),         # Create GOT entry
    (22, 'R_ARM_JUMP_SLOT'),        # Create PLT entry
    (23, 'R_ARM_RELATIVE'),         # Adjust by program base
    (24, 'R_ARM_GOTOFF'),           # 32 bit offset to GOT
    (25, 'R_ARM_GOTPC'),            # 32 bit PC relative offset to GOT
    (26, 'R_ARM_GOT32'),            # 32 bit GOT entry
    (27, 'R_ARM_PLT32'),            # 32 bit PLT address
    (32, 'R_ARM_ALU_PCREL_7_0'),      
    (33, 'R_ARM_ALU_PCREL_15_8'),     
    (34, 'R_ARM_ALU_PCREL_23_15'),    
    (35, 'R_ARM_LDR_SBREL_11_0'),     
    (36, 'R_ARM_ALU_SBREL_19_12'),    
    (37, 'R_ARM_ALU_SBREL_27_20'),    
    (90, 'R_ARM_TLS_GOTDESC'),        
    (91, 'R_ARM_TLS_CALL'),           
    (92, 'R_ARM_TLS_DESCSEQ'),        
    (93, 'R_ARM_THM_TLS_CALL'),       
    (100, 'R_ARM_GNU_VTENTRY'),        
    (101, 'R_ARM_GNU_VTINHERIT'),      
    (102, 'R_ARM_THM_PC11'),        # thumb unconditional branch
    (103, 'R_ARM_THM_PC9'),         # thumb conditional branch
    (104, 'R_ARM_TLS_GD32'),        # PC-rel 32 bit for global dynamic thread local data
    (105, 'R_ARM_TLS_LDM32'),       # PC-rel 32 bit for local dynamic thread local data
    (106, 'R_ARM_TLS_LDO32'),       # 32 bit offset relative to TLS block
    (107, 'R_ARM_TLS_IE32'),        # PC-rel 32 bit for GOT entry of static TLS block offset
    (108, 'R_ARM_TLS_LE32'),        # 32 bit offset relative to static TLS block
    (129, 'R_ARM_THM_TLS_DESCSEQ'),    
    (160, 'R_ARM_IRELATIVE'),          
    (249, 'R_ARM_RXPC25'),             
    (250, 'R_ARM_RSBREL32'),           
    (251, 'R_ARM_THM_RPC22'),          
    (252, 'R_ARM_RREL32'),             
    (253, 'R_ARM_RABS22'),             
    (254, 'R_ARM_RPC24'),              
    (255, 'R_ARM_RBASE'),              
    (256, 'R_ARM_NUM', None),       # Keep this the last entry. 
    ), glob=glob),

# IA-64 relocations
'IA64': NamedConstants((
    (0x00, 'R_IA64_NONE'),                  # none
    (0x21, 'R_IA64_IMM14'),                 # symbol + addend, add imm14
    (0x22, 'R_IA64_IMM22'),                 # symbol + addend, add imm22
    (0x23, 'R_IA64_IMM64'),                 # symbol + addend, mov imm64
    (0x24, 'R_IA64_DIR32MSB'),              # symbol + addend, data4 MSB
    (0x25, 'R_IA64_DIR32LSB'),              # symbol + addend, data4 LSB
    (0x26, 'R_IA64_DIR64MSB'),              # symbol + addend, data8 MSB
    (0x27, 'R_IA64_DIR64LSB'),              # symbol + addend, data8 LSB
    (0x2a, 'R_IA64_GPREL22'),               # @gprel(sym + add), add imm22
    (0x2b, 'R_IA64_GPREL64I'),              # @gprel(sym + add), mov imm64
    (0x2c, 'R_IA64_GPREL32MSB'),            # @gprel(sym + add), data4 MSB
    (0x2d, 'R_IA64_GPREL32LSB'),            # @gprel(sym + add), data4 LSB
    (0x2e, 'R_IA64_GPREL64MSB'),            # @gprel(sym + add), data8 MSB
    (0x2f, 'R_IA64_GPREL64LSB'),            # @gprel(sym + add), data8 LSB
    (0x32, 'R_IA64_LTOFF22'),               # @ltoff(sym + add), add imm22
    (0x33, 'R_IA64_LTOFF64I'),              # @ltoff(sym + add), mov imm64
    (0x3a, 'R_IA64_PLTOFF22'),              # @pltoff(sym + add), add imm22
    (0x3b, 'R_IA64_PLTOFF64I'),             # @pltoff(sym + add), mov imm64
    (0x3e, 'R_IA64_PLTOFF64MSB'),           # @pltoff(sym + add), data8 MSB
    (0x3f, 'R_IA64_PLTOFF64LSB'),           # @pltoff(sym + add), data8 LSB
    (0x43, 'R_IA64_FPTR64I'),               # @fptr(sym + add), mov imm64
    (0x44, 'R_IA64_FPTR32MSB'),             # @fptr(sym + add), data4 MSB
    (0x45, 'R_IA64_FPTR32LSB'),             # @fptr(sym + add), data4 LSB
    (0x46, 'R_IA64_FPTR64MSB'),             # @fptr(sym + add), data8 MSB
    (0x47, 'R_IA64_FPTR64LSB'),             # @fptr(sym + add), data8 LSB
    (0x48, 'R_IA64_PCREL60B'),              # @pcrel(sym + add), brl
    (0x49, 'R_IA64_PCREL21B'),              # @pcrel(sym + add), ptb, call
    (0x4a, 'R_IA64_PCREL21M'),              # @pcrel(sym + add), chk.s
    (0x4b, 'R_IA64_PCREL21F'),              # @pcrel(sym + add), fchkf
    (0x4c, 'R_IA64_PCREL32MSB'),            # @pcrel(sym + add), data4 MSB
    (0x4d, 'R_IA64_PCREL32LSB'),            # @pcrel(sym + add), data4 LSB
    (0x4e, 'R_IA64_PCREL64MSB'),            # @pcrel(sym + add), data8 MSB
    (0x4f, 'R_IA64_PCREL64LSB'),            # @pcrel(sym + add), data8 LSB
    (0x52, 'R_IA64_LTOFF_FPTR22'),          # @ltoff(@fptr(s+a)), imm22
    (0x53, 'R_IA64_LTOFF_FPTR64I'),         # @ltoff(@fptr(s+a)), imm64
    (0x54, 'R_IA64_LTOFF_FPTR32MSB'),       # @ltoff(@fptr(s+a)), data4 MSB
    (0x55, 'R_IA64_LTOFF_FPTR32LSB'),       # @ltoff(@fptr(s+a)), data4 LSB
    (0x56, 'R_IA64_LTOFF_FPTR64MSB'),       # @ltoff(@fptr(s+a)), data8 MSB
    (0x57, 'R_IA64_LTOFF_FPTR64LSB'),       # @ltoff(@fptr(s+a)), data8 LSB
    (0x5c, 'R_IA64_SEGREL32MSB'),           # @segrel(sym + add), data4 MSB
    (0x5d, 'R_IA64_SEGREL32LSB'),           # @segrel(sym + add), data4 LSB
    (0x5e, 'R_IA64_SEGREL64MSB'),           # @segrel(sym + add), data8 MSB
    (0x5f, 'R_IA64_SEGREL64LSB'),           # @segrel(sym + add), data8 LSB
    (0x64, 'R_IA64_SECREL32MSB'),           # @secrel(sym + add), data4 MSB
    (0x65, 'R_IA64_SECREL32LSB'),           # @secrel(sym + add), data4 LSB
    (0x66, 'R_IA64_SECREL64MSB'),           # @secrel(sym + add), data8 MSB
    (0x67, 'R_IA64_SECREL64LSB'),           # @secrel(sym + add), data8 LSB
    (0x6c, 'R_IA64_REL32MSB'),              # data 4 + REL
    (0x6d, 'R_IA64_REL32LSB'),              # data 4 + REL
    (0x6e, 'R_IA64_REL64MSB'),              # data 8 + REL
    (0x6f, 'R_IA64_REL64LSB'),              # data 8 + REL
    (0x74, 'R_IA64_LTV32MSB'),              # symbol + addend, data4 MSB
    (0x75, 'R_IA64_LTV32LSB'),              # symbol + addend, data4 LSB
    (0x76, 'R_IA64_LTV64MSB'),              # symbol + addend, data8 MSB
    (0x77, 'R_IA64_LTV64LSB'),              # symbol + addend, data8 LSB
    (0x79, 'R_IA64_PCREL21BI'),             # @pcrel(sym + add), 21bit inst
    (0x7a, 'R_IA64_PCREL22'),               # @pcrel(sym + add), 22bit inst
    (0x7b, 'R_IA64_PCREL64I'),              # @pcrel(sym + add), 64bit inst
    (0x80, 'R_IA64_IPLTMSB'),               # dynamic reloc, imported PLT, MSB
    (0x81, 'R_IA64_IPLTLSB'),               # dynamic reloc, imported PLT, LSB
    (0x84, 'R_IA64_COPY'),                  # copy relocation
    (0x85, 'R_IA64_SUB'),                   # Addend and symbol difference
    (0x86, 'R_IA64_LTOFF22X'),              # LTOFF22, relaxable. 
    (0x87, 'R_IA64_LDXMOV'),                # Use of LTOFF22X. 
    (0x91, 'R_IA64_TPREL14'),               # @tprel(sym + add), imm14
    (0x92, 'R_IA64_TPREL22'),               # @tprel(sym + add), imm22
    (0x93, 'R_IA64_TPREL64I'),              # @tprel(sym + add), imm64
    (0x96, 'R_IA64_TPREL64MSB'),            # @tprel(sym + add), data8 MSB
    (0x97, 'R_IA64_TPREL64LSB'),            # @tprel(sym + add), data8 LSB
    (0x9a, 'R_IA64_LTOFF_TPREL22'),         # @ltoff(@tprel(s+a)), imm2
    (0xa6, 'R_IA64_DTPMOD64MSB'),           # @dtpmod(sym + add), data8 MSB
    (0xa7, 'R_IA64_DTPMOD64LSB'),           # @dtpmod(sym + add), data8 LSB
    (0xaa, 'R_IA64_LTOFF_DTPMOD22'),        # @ltoff(@dtpmod(sym + add)), imm22
    (0xb1, 'R_IA64_DTPREL14'),              # @dtprel(sym + add), imm14
    (0xb2, 'R_IA64_DTPREL22'),              # @dtprel(sym + add), imm22
    (0xb3, 'R_IA64_DTPREL64I'),             # @dtprel(sym + add), imm64
    (0xb4, 'R_IA64_DTPREL32MSB'),           # @dtprel(sym + add), data4 MSB
    (0xb5, 'R_IA64_DTPREL32LSB'),           # @dtprel(sym + add), data4 LSB
    (0xb6, 'R_IA64_DTPREL64MSB'),           # @dtprel(sym + add), data8 MSB
    (0xb7, 'R_IA64_DTPREL64LSB'),           # @dtprel(sym + add), data8 LSB
    (0xba, 'R_IA64_LTOFF_DTPREL22'),        # @ltoff(@dtprel(s+a)), imm22
    ), glob=glob),

# SH relocations
'SH': NamedConstants((
    (0, 'R_SH_NONE'),                
    (1, 'R_SH_DIR32'),               
    (2, 'R_SH_REL32'),               
    (3, 'R_SH_DIR8WPN'),             
    (4, 'R_SH_IND12W'),              
    (5, 'R_SH_DIR8WPL'),             
    (6, 'R_SH_DIR8WPZ'),             
    (7, 'R_SH_DIR8BP'),              
    (8, 'R_SH_DIR8W'),               
    (9, 'R_SH_DIR8L'),               
    (25, 'R_SH_SWITCH16'),            
    (26, 'R_SH_SWITCH32'),            
    (27, 'R_SH_USES'),                
    (28, 'R_SH_COUNT'),               
    (29, 'R_SH_ALIGN'),               
    (30, 'R_SH_CODE'),                
    (31, 'R_SH_DATA'),                
    (32, 'R_SH_LABEL'),               
    (33, 'R_SH_SWITCH8'),             
    (34, 'R_SH_GNU_VTINHERIT'),       
    (35, 'R_SH_GNU_VTENTRY'),         
    (144, 'R_SH_TLS_GD_32'),           
    (145, 'R_SH_TLS_LD_32'),           
    (146, 'R_SH_TLS_LDO_32'),          
    (147, 'R_SH_TLS_IE_32'),           
    (148, 'R_SH_TLS_LE_32'),           
    (149, 'R_SH_TLS_DTPMOD32'),        
    (150, 'R_SH_TLS_DTPOFF32'),        
    (151, 'R_SH_TLS_TPOFF32'),         
    (160, 'R_SH_GOT32'),               
    (161, 'R_SH_PLT32'),               
    (162, 'R_SH_COPY'),                
    (163, 'R_SH_GLOB_DAT'),            
    (164, 'R_SH_JMP_SLOT'),            
    (165, 'R_SH_RELATIVE'),            
    (166, 'R_SH_GOTOFF'),              
    (167, 'R_SH_GOTPC'),               
    (256, 'R_SH_NUM', None),                 # Keep this the last entry. 
    ), glob=glob),

# S/390 relocations
'390': NamedConstants((
    (0, 'R_390_NONE'),                      # No reloc. 
    (1, 'R_390_8'),                         # Direct 8 bit. 
    (2, 'R_390_12'),                        # Direct 12 bit. 
    (3, 'R_390_16'),                        # Direct 16 bit. 
    (4, 'R_390_32'),                        # Direct 32 bit. 
    (5, 'R_390_PC32'),                      # PC relative 32 bit.  
    (6, 'R_390_GOT12'),                     # 12 bit GOT offset. 
    (7, 'R_390_GOT32'),                     # 32 bit GOT offset. 
    (8, 'R_390_PLT32'),                     # 32 bit PC relative PLT address. 
    (9, 'R_390_COPY'),                      # Copy symbol at runtime. 
    (10, 'R_390_GLOB_DAT'),                 # Create GOT entry. 
    (11, 'R_390_JMP_SLOT'),                 # Create PLT entry. 
    (12, 'R_390_RELATIVE'),                 # Adjust by program base. 
    (13, 'R_390_GOTOFF32'),                 # 32 bit offset to GOT. 
    (14, 'R_390_GOTPC'),                    # 32 bit PC relative offset to GOT. 
    (15, 'R_390_GOT16'),                    # 16 bit GOT offset. 
    (16, 'R_390_PC16'),                     # PC relative 16 bit.  
    (17, 'R_390_PC16DBL'),                  # PC relative 16 bit shifted by 1. 
    (18, 'R_390_PLT16DBL'),                 # 16 bit PC rel. PLT shifted by 1. 
    (19, 'R_390_PC32DBL'),                  # PC relative 32 bit shifted by 1. 
    (20, 'R_390_PLT32DBL'),                 # 32 bit PC rel. PLT shifted by 1. 
    (21, 'R_390_GOTPCDBL'),                 # 32 bit PC rel. GOT shifted by 1. 
    (22, 'R_390_64'),                       # Direct 64 bit. 
    (23, 'R_390_PC64'),                     # PC relative 64 bit.  
    (24, 'R_390_GOT64'),                    # 64 bit GOT offset. 
    (25, 'R_390_PLT64'),                    # 64 bit PC relative PLT address. 
    (26, 'R_390_GOTENT'),                   # 32 bit PC rel. to GOT entry >> 1.
    (27, 'R_390_GOTOFF16'),                 # 16 bit offset to GOT.
    (28, 'R_390_GOTOFF64'),                 # 64 bit offset to GOT.
    (29, 'R_390_GOTPLT12'),                 # 12 bit offset to jump slot.  
    (30, 'R_390_GOTPLT16'),                 # 16 bit offset to jump slot.  
    (31, 'R_390_GOTPLT32'),                 # 32 bit offset to jump slot.  
    (32, 'R_390_GOTPLT64'),                 # 64 bit offset to jump slot.  
    (33, 'R_390_GOTPLTENT'),                # 32 bit rel. offset to jump slot. 
    (34, 'R_390_PLTOFF16'),                 # 16 bit offset from GOT to PLT.
    (35, 'R_390_PLTOFF32'),                 # 32 bit offset from GOT to PLT.
    (36, 'R_390_PLTOFF64'),                 # 16 bit offset from GOT to PLT.
    (37, 'R_390_TLS_LOAD'),                 # Tag for load insn in TLS code. 
    (38, 'R_390_TLS_GDCALL'),               # Tag for function call in general dynamic TLS code.
    (39, 'R_390_TLS_LDCALL'),               # Tag for function call in local dynamic TLS code.
    (40, 'R_390_TLS_GD32'),                 # Direct 32 bit for general dynamic thread local data. 
    (41, 'R_390_TLS_GD64'),                 # Direct 64 bit for general dynamic thread local data. 
    (42, 'R_390_TLS_GOTIE12'),              # 12 bit GOT offset for static TLS block offset. 
    (43, 'R_390_TLS_GOTIE32'),              # 32 bit GOT offset for static TLS block offset. 
    (44, 'R_390_TLS_GOTIE64'),              # 64 bit GOT offset for static TLS block offset.
    (45, 'R_390_TLS_LDM32'),                # Direct 32 bit for local dynamic thread local data in LE code. 
    (46, 'R_390_TLS_LDM64'),                # Direct 64 bit for local dynamic thread local data in LE code. 
    (47, 'R_390_TLS_IE32'),                 # 32 bit address of GOT entry for negated static TLS block offset. 
    (48, 'R_390_TLS_IE64'),                 # 64 bit address of GOT entry for negated static TLS block offset. 
    (49, 'R_390_TLS_IEENT'),                # 32 bit rel. offset to GOT entry for negated static TLS block offset. 
    (50, 'R_390_TLS_LE32'),                 # 32 bit negated offset relative to static TLS block. 
    (51, 'R_390_TLS_LE64'),                 # 64 bit negated offset relative to static TLS block. 
    (52, 'R_390_TLS_LDO32'),                # 32 bit offset relative to TLS block. 
    (53, 'R_390_TLS_LDO64'),                # 64 bit offset relative to TLS block. 
    (54, 'R_390_TLS_DTPMOD'),               # ID of module containing symbol. 
    (55, 'R_390_TLS_DTPOFF'),               # Offset in TLS block.  
    (56, 'R_390_TLS_TPOFF'),                # Negated offset in static TLS block. 
    (57, 'R_390_20'),                       # Direct 20 bit. 
    (58, 'R_390_GOT20'),                    # 20 bit GOT offset. 
    (59, 'R_390_GOTPLT20'),                 # 20 bit offset to jump slot. 
    (60, 'R_390_TLS_GOTIE20'),              # 20 bit GOT offset for static TLS block offset. 
    (61, 'R_390_NUM', None),                # Keep this the last entry. 
    ), glob=glob),

# CRIS relocations. 
'CRIS': NamedConstants((
    (0, 'R_CRIS_NONE'),              
    (1, 'R_CRIS_8'),                 
    (2, 'R_CRIS_16'),                
    (3, 'R_CRIS_32'),                
    (4, 'R_CRIS_8_PCREL'),           
    (5, 'R_CRIS_16_PCREL'),          
    (6, 'R_CRIS_32_PCREL'),          
    (7, 'R_CRIS_GNU_VTINHERIT'),     
    (8, 'R_CRIS_GNU_VTENTRY'),       
    (9, 'R_CRIS_COPY'),              
    (10, 'R_CRIS_GLOB_DAT'),          
    (11, 'R_CRIS_JUMP_SLOT'),         
    (12, 'R_CRIS_RELATIVE'),          
    (13, 'R_CRIS_16_GOT'),            
    (14, 'R_CRIS_32_GOT'),            
    (15, 'R_CRIS_16_GOTPLT'),         
    (16, 'R_CRIS_32_GOTPLT'),         
    (17, 'R_CRIS_32_GOTREL'),         
    (18, 'R_CRIS_32_PLT_GOTREL'),     
    (19, 'R_CRIS_32_PLT_PCREL'),      
    (20, 'R_CRIS_NUM', None),               
    ), glob=glob),

# AMD x86-64 relocations. 
'X86_64': NamedConstants((
    (0, 'R_X86_64_NONE'),                   # No reloc
    (1, 'R_X86_64_64'),                     # Direct 64 bit 
    (2, 'R_X86_64_PC32'),                   # PC relative 32 bit signed
    (3, 'R_X86_64_GOT32'),                  # 32 bit GOT entry
    (4, 'R_X86_64_PLT32'),                  # 32 bit PLT address
    (5, 'R_X86_64_COPY'),                   # Copy symbol at runtime
    (6, 'R_X86_64_GLOB_DAT'),               # Create GOT entry
    (7, 'R_X86_64_JUMP_SLOT'),              # Create PLT entry
    (8, 'R_X86_64_RELATIVE'),               # Adjust by program base
    (9, 'R_X86_64_GOTPCREL'),               # 32 bit signed PC relative offset to GOT
    (10, 'R_X86_64_32'),                    # Direct 32 bit zero extended
    (11, 'R_X86_64_32S'),                   # Direct 32 bit sign extended
    (12, 'R_X86_64_16'),                    # Direct 16 bit zero extended
    (13, 'R_X86_64_PC16'),                  # 16 bit sign extended pc relative
    (14, 'R_X86_64_8'),                     # Direct 8 bit sign extended 
    (15, 'R_X86_64_PC8'),                   # 8 bit sign extended pc relative
    (16, 'R_X86_64_DTPMOD64'),              # ID of module containing symbol
    (17, 'R_X86_64_DTPOFF64'),              # Offset in module's TLS block
    (18, 'R_X86_64_TPOFF64'),               # Offset in initial TLS block
    (19, 'R_X86_64_TLSGD'),                 # 32 bit signed PC relative offset to two GOT entries for GD symbol
    (20, 'R_X86_64_TLSLD'),                 # 32 bit signed PC relative offset to two GOT entries for LD symbol
    (21, 'R_X86_64_DTPOFF32'),              # Offset in TLS block
    (22, 'R_X86_64_GOTTPOFF'),              # 32 bit signed PC relative offset to GOT entry for IE symbol
    (23, 'R_X86_64_TPOFF32'),               # Offset in initial TLS block
    (24, 'R_X86_64_PC64'),                  # PC relative 64 bit
    (25, 'R_X86_64_GOTOFF64'),              # 64 bit offset to GOT
    (26, 'R_X86_64_GOTPC32'),               # 32 bit signed pc relative offset to GOT
    (27, 'R_X86_64_GOT64'),                 # 64-bit GOT entry offset
    (28, 'R_X86_64_GOTPCREL64'),            # 64-bit PC relative offset to GOT entry
    (29, 'R_X86_64_GOTPC64'),               # 64-bit PC relative offset to GOT
    (30, 'R_X86_64_GOTPLT64'),              # like GOT64, says PLT entry needed
    (31, 'R_X86_64_PLTOFF64'),              # 64-bit GOT relative offset to PLT entry
    (32, 'R_X86_64_SIZE32'),                # Size of symbol plus 32-bit addend
    (33, 'R_X86_64_SIZE64'),                # Size of symbol plus 64-bit addend
    (34, 'R_X86_64_GOTPC32_TLSDESC'),       # GOT offset for TLS descriptor. 
    (35, 'R_X86_64_TLSDESC_CALL'),          # Marker for call through TLS descriptor. 
    (36, 'R_X86_64_TLSDESC'),               # TLS descriptor. 
    (37, 'R_X86_64_IRELATIVE'),             # Adjust indirectly by program base
    (38, 'R_X86_64_NUM', None),             
    ), glob=glob),

# AM33 relocations. 
'MN10300': NamedConstants((
    (0, 'R_MN10300_NONE'),                  # No reloc. 
    (1, 'R_MN10300_32'),                    # Direct 32 bit. 
    (2, 'R_MN10300_16'),                    # Direct 16 bit. 
    (3, 'R_MN10300_8'),                     # Direct 8 bit. 
    (4, 'R_MN10300_PCREL32'),               # PC-relative 32-bit. 
    (5, 'R_MN10300_PCREL16'),               # PC-relative 16-bit signed. 
    (6, 'R_MN10300_PCREL8'),                # PC-relative 8-bit signed. 
    (7, 'R_MN10300_GNU_VTINHERIT'),         # Ancient C++ vtable garbage...
    (8, 'R_MN10300_GNU_VTENTRY'),           # ... collection annotation. 
    (9, 'R_MN10300_24'),                    # Direct 24 bit. 
    (10, 'R_MN10300_GOTPC32'),              # 32-bit PCrel offset to GOT. 
    (11, 'R_MN10300_GOTPC16'),              # 16-bit PCrel offset to GOT. 
    (12, 'R_MN10300_GOTOFF32'),             # 32-bit offset from GOT. 
    (13, 'R_MN10300_GOTOFF24'),             # 24-bit offset from GOT. 
    (14, 'R_MN10300_GOTOFF16'),             # 16-bit offset from GOT. 
    (15, 'R_MN10300_PLT32'),                # 32-bit PCrel to PLT entry. 
    (16, 'R_MN10300_PLT16'),                # 16-bit PCrel to PLT entry. 
    (17, 'R_MN10300_GOT32'),                # 32-bit offset to GOT entry. 
    (18, 'R_MN10300_GOT24'),                # 24-bit offset to GOT entry. 
    (19, 'R_MN10300_GOT16'),                # 16-bit offset to GOT entry. 
    (20, 'R_MN10300_COPY'),                 # Copy symbol at runtime. 
    (21, 'R_MN10300_GLOB_DAT'),             # Create GOT entry. 
    (22, 'R_MN10300_JMP_SLOT'),             # Create PLT entry. 
    (23, 'R_MN10300_RELATIVE'),             # Adjust by program base. 
    (24, 'R_MN10300_NUM', None),            
    ), glob=glob),

# M32R relocs. 
'M32R': NamedConstants((
    (0, 'R_M32R_NONE'),                # No reloc.
    (1, 'R_M32R_16'),                  # Direct 16 bit.
    (2, 'R_M32R_32'),                  # Direct 32 bit.
    (3, 'R_M32R_24'),                  # Direct 24 bit.
    (4, 'R_M32R_10_PCREL'),            # PC relative 10 bit shifted.
    (5, 'R_M32R_18_PCREL'),            # PC relative 18 bit shifted.
    (6, 'R_M32R_26_PCREL'),            # PC relative 26 bit shifted.
    (7, 'R_M32R_HI16_ULO'),            # High 16 bit with unsigned low.
    (8, 'R_M32R_HI16_SLO'),            # High 16 bit with signed low.
    (9, 'R_M32R_LO16'),                # Low 16 bit.
    (10, 'R_M32R_SDA16'),              # 16 bit offset in SDA.
    (11, 'R_M32R_GNU_VTINHERIT'),     
    (12, 'R_M32R_GNU_VTENTRY'),       
    # M32R relocs use SHT_RELA. 
    (33, 'R_M32R_16_RELA'),            # Direct 16 bit.
    (34, 'R_M32R_32_RELA'),            # Direct 32 bit.
    (35, 'R_M32R_24_RELA'),            # Direct 24 bit.
    (36, 'R_M32R_10_PCREL_RELA'),      # PC relative 10 bit shifted.
    (37, 'R_M32R_18_PCREL_RELA'),      # PC relative 18 bit shifted.
    (38, 'R_M32R_26_PCREL_RELA'),      # PC relative 26 bit shifted.
    (39, 'R_M32R_HI16_ULO_RELA'),      # High 16 bit with unsigned low
    (40, 'R_M32R_HI16_SLO_RELA'),      # High 16 bit with signed low
    (41, 'R_M32R_LO16_RELA'),          # Low 16 bit
    (42, 'R_M32R_SDA16_RELA'),         # 16 bit offset in SDA
    (43, 'R_M32R_RELA_GNU_VTINHERIT'),        
    (44, 'R_M32R_RELA_GNU_VTENTRY'),  
    (45, 'R_M32R_REL32'),              # PC relative 32 bit. 
    (48, 'R_M32R_GOT24'),              # 24 bit GOT entry
    (49, 'R_M32R_26_PLTREL'),          # 26 bit PC relative to PLT shifted
    (50, 'R_M32R_COPY'),               # Copy symbol at runtime
    (51, 'R_M32R_GLOB_DAT'),           # Create GOT entry
    (52, 'R_M32R_JMP_SLOT'),           # Create PLT entry
    (53, 'R_M32R_RELATIVE'),           # Adjust by program base
    (54, 'R_M32R_GOTOFF'),             # 24 bit offset to GOT
    (55, 'R_M32R_GOTPC24'),            # 24 bit PC relative offset to GOT
    (56, 'R_M32R_GOT16_HI_ULO'),       # High 16 bit GOT entry with unsigned low
    (57, 'R_M32R_GOT16_HI_SLO'),       # High 16 bit GOT entry with signed low
    (58, 'R_M32R_GOT16_LO'),           # Low 16 bit GOT entry
    (59, 'R_M32R_GOTPC_HI_ULO'),       # High 16 bit PC relative offset to GOT with unsigned low
    (60, 'R_M32R_GOTPC_HI_SLO'),       # High 16 bit PC relative offset to GOT with signed low
    (61, 'R_M32R_GOTPC_LO'),           # Low 16 bit PC relative offset to GOT
    (62, 'R_M32R_GOTOFF_HI_ULO'),      # High 16 bit offset to GOT with unsigned low
    (63, 'R_M32R_GOTOFF_HI_SLO'),      # High 16 bit offset to GOT with signed low
    (64, 'R_M32R_GOTOFF_LO'),          # Low 16 bit offset to GOT
    (256, 'R_M32R_NUM', None),         # Keep this the last entry.
    ), glob=glob),

# NEC/Renesas V8xx series
'V800': NamedConstants((
    (0x30, 'R_V800_NONE'),                  # V810
    (0x31, 'R_V800_BYTE'),                  # V810
    (0x32, 'R_V800_HWORD'),                 # V810
    (0x33, 'R_V800_WORD'),                  # V810
    (0x34, 'R_V800_WLO'),                   # V810
    (0x35, 'R_V800_WHI'),                   # V810
    (0x36, 'R_V800_WHI1'),                  # V810
    (0x37, 'R_V800_GPBYTE'),                # V810
    (0x38, 'R_V800_GPHWORD'),               # V810
    (0x39, 'R_V800_GPWORD'),                # V810
    (0x3a, 'R_V800_GPWLO'),                 # V810
    (0x3b, 'R_V800_GPWHI'),                 # V810
    (0x3c, 'R_V800_GPWHI1'),                # V810
    (0x3d, 'R_V800_HWLO'),                  # V850
    ), glob=glob),
}

import sys
if sys.version_info[0:2] == (2, 3):
    mask32 = (eval("1L")<<32)-1 # 'eval' avoids SyntaxError with python3.x
else:
    mask32 = eval("0xffffffff") # 'eval' avoids warnings with python2.3

class RelBase(AttributesElfesteem,Struct):
    def __getitem__(self, args):
        if   args == 'symbol':
            link = self._parent._get_attr_ancestor('link')
            linksection = self._get_attr_ancestor('sh')[link]
            return linksection['content'].symtab[self.sym_idx]
        elif args == 'shndx':
            return self['symbol'].shndx
        elif args == 'value':
            return self['symbol'].value
        elif args == 'sym':
            return self['symbol'].name
        elif args == 'name':
            sym = self['symbol'].name
            if sym != '': return sym
            return self._get_attr_ancestor('sh')[self.shndx].name
        elif args == 'type17':
            machine = self._machine
            if machine in ('SPARC32PLUS', 'SPARCV9'): machine = 'SPARC'
            if not machine in R:
                ret = '%d aka. %#x' % (self.type, self.type)
            elif hasattr(self, 'type1'): # MIPS64
                ret = R[machine].text[self.type1]
            else:
                ret = R[machine].text[self.type]
            return ret[:17] # truncated by readelf!
        else:
            return self._subcells[args]
    def readelf_display(self):
        res = self.format % self
        if self._get_attr_ancestor('type_txt') == 'RELA':
            if self.addend < 0: res += " - %x" % -self.addend
            else:               res += " + %x" %  self.addend
        if hasattr(self, 'type1'):
            res += "\n                    Type2: %-16s" % R[self._machine].text[self.type2]
            res += "\n                    Type3: %-16s" % R[self._machine].text[self.type3]
        return res
    _machine = property(lambda self:
        EM.text[self._get_attr_ancestor('Ehdr')['machine'].work()][3:])


class Rel32(RelBase):
    # sym_idx is 24-bit long, cannot be defined as a field type
    # we get it by parsing 'info'
    _fields = [
        ('offset',   Ptr),
        ('info',     Int),
        ]
    format = '%(offset)08x  %(info)08x %(type17)-17s %(value)08x   %(name)s'
    type = property(lambda _: _.info & 0xff)
    sym_idx = property(lambda _:_.info>>8)

class Rel64(RelBase):
    _fields = [
        ('offset',   Ptr),
        ('info',     Quad),
        ]
    format = '%(offset)012x  %(info)012x %(type17)-17s %(value)016x %(name)s'
    type = property(lambda _: _.info & mask32)
    sym_idx = property(lambda _:_.info>>32)

class Rel64MIPS(RelBase):
    # e.g. http://www.openwall.com/lists/musl/2016/01/22/2
    _fields = [
        ('offset',   Ptr),
        ('sym_idx',  Int),
        ('ssym',     Byte),
        ('type3',    Byte),
        ('type2',    Byte),
        ('type1',    Byte),
        ]
    def type(self):
        raise ValueError("MIPS64 relocation type is a combination of 3 relocation types each of size 1 byte")
    type = property(type)
    info = property(lambda _:_.type1 + (_.type2<<8) + (_.type3<<16) + (_.ssym<<24) + (_.sym_idx<<32))

class Rela32(Rel32):
    _fields = [
        ('offset',   Ptr),
        ('info',     Int),
        ('addend',   Int), # signed
        ]

class Rela64(Rel64):
    _fields = [
        ('offset',   Ptr),
        ('info',     Quad),
        ('addend',   Quad), # signed
        ]

class Section_with_reltab(VarArray):
    def _type(self):
        if self._machine == 'EM_MIPS' and self._ptrsize == 64:
            return Rel64MIPS
        return {
            (32, 'REL'):  Rel32,
            (32, 'RELA'): Rela32,
            (64, 'REL'):  Rel64,
            (64, 'RELA'): Rela64,
            } [(self._ptrsize,self.type_txt)]
    _type = property(_type)
    __len__ = lambda self: len(self.reltab)
    reltab = property(lambda self: self._wrapped._subcells)
    def readelf_display(self):
        header = {
            32: " Offset     Info    Type            Sym.Value  Sym. Name",
            64: "  Offset          Info           Type           Sym. Value    Sym. Name",
            }[self._ptrsize]
        if self.type_txt == 'RELA':
            header += " + Addend"
        rep = [ "Relocation section %r at offset 0x%x contains %d entries:"
                % (self._parent['name'].work(), self._parent['offset'], len(self)), header ]
        rep.extend([ _.readelf_display() for _ in self ])
        return "\n".join(rep)
    _ptrsize = property(lambda _: _._parent._get_attr_ancestor('_ptrsize'))
    _machine = property(lambda self:
        EM.text[self._get_attr_ancestor('Ehdr')['machine'].work()][3:])

# 3.3. Sections, by type index

class SectionNull(Section):
    """ Section header table entry unused """
    type = 0
    type_txt = 'NULL'
    elfesteem_classname = 'NullSection'
register_section_type(SectionNull)

class SectionProgbits(Section):
    """ Program data """
    type = 1
    type_txt = 'PROGBITS'
    elfesteem_classname = 'ProgBits'
register_section_type(SectionProgbits)

class SectionSymtab(Section_with_symtab):
    """ Symbol table """
    type = 2
    type_txt = 'SYMTAB'
    elfesteem_classname = 'SymTable'
register_section_type(SectionSymtab)

class SectionStrtab(Section):
    """ String table """
    type = 3
    type_txt = 'STRTAB'
    elfesteem_classname = 'StrTable'
    def __getitem__(self, pos):
        end = self._content.index(struct.pack('B',0), pos)
        return self._content[pos:end]
register_section_type(SectionStrtab)

class SectionRelA(Section_with_reltab):
    """ Relocation entries with addends """
    type = 4
    type_txt = 'RELA'
    elfesteem_classname = 'RelATable'
register_section_type(SectionRelA)

class SectionHash(Section):
    """ Symbol hash table """
    type = 5
    type_txt = 'HASH'
    elfesteem_classname = 'HashSection'
register_section_type(SectionHash)

class SectionDynamic(Section):
    """ Dynamic linking information """
    type = 6
    type_txt = 'DYNAMIC'
    elfesteem_classname = 'Dynamic'
register_section_type(SectionDynamic)

class SectionNote(Section):
    """ Notes """
    type = 7
    type_txt = 'NOTE'
    elfesteem_classname = 'NoteSection'
register_section_type(SectionNote)

class SectionNobits(Section):
    """ Program space with no data (bss) """
    type = 8
    type_txt = 'NOBITS'
    elfesteem_classname = 'NoBitsSection'
    def unpack(self, data, offset=0, **kargs):
        self._content = data[:0]
        return self
register_section_type(SectionNobits)

class SectionRel(Section_with_reltab):
    """ Relocation entries, no addends """
    type = 9
    type_txt = 'REL'
    elfesteem_classname = 'RelTable'
register_section_type(SectionRel)

class SectionShlib(Section):
    """ Reserved """
    type = 10
    type_txt = 'SHLIB'
    elfesteem_classname = 'ShLibSection'
register_section_type(SectionShlib)

class SectionDynsym(Section_with_symtab):
    """ Dynamic linker symbol table """
    type = 11
    type_txt = 'DYNSYM'
    elfesteem_classname = 'DynSymTable'
register_section_type(SectionDynsym)

class SectionInitArray(Section):
    """ Array of constructors """
    type = 14
    type_txt = 'INIT_ARRAY'
    elfesteem_classname = 'InitArray'
register_section_type(SectionInitArray)

class SectionFiniArray(Section):
    """ Array of destructors """
    type = 15
    type_txt = 'FINI_ARRAY'
    elfesteem_classname = 'FiniArray'
register_section_type(SectionFiniArray)

class SectionPreinitArray(Section):
    """ Array of pre-constructors """
    type = 16
    type_txt = 'PREINIT_ARRAY'
register_section_type(SectionPreinitArray)

class SectionGroup(Section):
    """ Section group """
    type = 17
    type_txt = 'GROUP'
    elfesteem_classname = 'GroupSection'
register_section_type(SectionGroup)

class SectionSymtabShndx(Section):
    """ Extended section indeces """
    type =  18
    type_txt = 'SYMTAB_SHNDX'
    elfesteem_classname = 'SymTabSHIndeces'
register_section_type(SectionSymtabShndx)

SHT.extend(19, 'SHT_NUM', None) # Number of defined types

# OS-specific sections
# TODO
SHT.extend(0x60000000, 'SHT_LOOS', None)    # Start OS-specific
SHT.extend(0x6ffffffa, 'SHT_LOSUNW', None), # Sun-specific low bound.
SHT.extend(0x6fffffff, 'SHT_HISUNW', None), # Sun-specific high bound.
SHT.extend(0x6fffffff, 'SHT_HIOS', None),   # End OS-specific type

class SectionGnuHash(Section):
    type = 0x6ffffff6
    type_txt = 'GNU_HASH'
register_section_type(SectionGnuHash)

class SectionGnuLiblist(Section):
    """ Prelink library list """
    type = 0x6ffffff7
    type_txt = 'GNU_LIBLIST'
    elfesteem_classname = 'GNULibLIst'
register_section_type(SectionGnuLiblist)

class SectionChecksum(Section):
    """ Checksum for DSO content """
    type = 0x6ffffff8
    type_txt = 'CHECKSUM'
    elfesteem_classname = 'CheckSumSection'
register_section_type(SectionChecksum)

class SectionGnuVerdef(Section):
    """ GNU Version definition section """
    type = 0x6ffffffd
    type_txt = 'VERDEF'
    elfesteem_classname = 'GNUVerDef'
register_section_type(SectionGnuVerdef)

class SectionGnuVerneed(Section):
    """ GNU Version needs section """
    type = 0x6ffffffe
    type_txt = 'VERNEED'
    elfesteem_classname = 'GNUVerNeed'
register_section_type(SectionGnuVerneed)

class SectionGnuVersym(Section):
    """ GNU Version symbol table """
    type = 0x6fffffff
    type_txt = 'VERSYM'
    elfesteem_classname = 'GNUVerSym'
register_section_type(SectionGnuVersym)

#SHT_SUNW_move =     0x6ffffffa, 
#SHT_SUNW_COMDAT =   0x6ffffffb, 
#SHT_SUNW_syminfo =  0x6ffffffc, 

# Processor-specific sections
# TODO
SHT.extend(0x70000000, 'SHT_LOPROC', None), # Start of processor-specific
SHT.extend(0x7fffffff, 'SHT_HIPROC', None), # End of processor-specific

"""
# http://infocenter.arm.com/help/topic/com.arm.doc.ihi0044c/IHI0044C_aaelf.pdf
SHT_ARM_EXIDX =          0x70000001, # Exception Index table
SHT_ARM_PREEMPTMAP =     0x70000002, # DLL dynamic linking pre-emption map
SHT_ARM_ATTRIBUTES =     0x70000003, # Object file compatibility attributes
SHT_ARM_DEBUGOVERLAY =   0x70000004,
SHT_ARM_OVERLAYSECTION = 0x70000005,

# https://refspecs.linuxfoundation.org/elf/elf-pa.pdf
# https://sourceware.org/ml/binutils/2005-08/msg00141.html
SHT_PARISC_EXT =    0x70000000, # Section contains product-specific extension bits
SHT_PARISC_UNWIND = 0x70000001, # Section contains unwind table entries
SHT_PARISC_DOC =    0x70000002, # Section contains debug information for optimized code
SHT_PARISC_ANNOT =  0x70000003, # Section contains code annotations
SHT_PARISC_DLKM =   0x70000004, # DLKM special section

# https://dmz-portal.mips.com/wiki/MIPS_section_types
SHT_MIPS_LIBLIST =       0x70000000, # DSO library information used to link
SHT_MIPS_MSYM =          0x70000001, # MIPS symbol table extension
SHT_MIPS_CONFLICT =      0x70000002, # Symbol conflicting with DSO defined symbols
SHT_MIPS_GPTAB =         0x70000003, # Global pointer table
SHT_MIPS_UCODE =         0x70000004, # Reserved
SHT_MIPS_DEBUG =         0x70000005, # Reserved (obsolete debug information)
SHT_MIPS_REGINFO =       0x70000006, # Register usage information
SHT_MIPS_PACKAGE =       0x70000007, # OSF reserved
SHT_MIPS_PACKSYM =       0x70000008, # OSF reserved
SHT_MIPS_RELD =          0x70000009, # Dynamic relocations (obsolete)
#                        0x7000000a,
SHT_MIPS_IFACE =         0x7000000b, # Subprogram interface information
SHT_MIPS_CONTENT =       0x7000000c, # Section content information
SHT_MIPS_OPTIONS =       0x7000000d, # General options
#                        0x7000000e,
#                        0x7000000f,
SHT_MIPS_SHDR =          0x70000010,
SHT_MIPS_FDESC =         0x70000011,
SHT_MIPS_EXTSYM =        0x70000012,
SHT_MIPS_DENSE =         0x70000013,
SHT_MIPS_PDESC =         0x70000014,
SHT_MIPS_LOCSYM =        0x70000015,
SHT_MIPS_AUXSYM =        0x70000016,
SHT_MIPS_OPTSYM =        0x70000017,
SHT_MIPS_LOCSTR =        0x70000018,
SHT_MIPS_LINE =          0x70000019,
SHT_MIPS_RFDESC =        0x7000001a,
SHT_MIPS_DELTASYM =      0x7000001b, # Delta C++ symbol table (obsolete)
SHT_MIPS_DELTAINST =     0x7000001c, # Delta C++ instance table (obsolete)
SHT_MIPS_DELTACLASS =    0x7000001d, # Delta C++ class table (obsolete)
SHT_MIPS_DWARF =         0x7000001e, # Dwarf debug information
SHT_MIPS_DELTADECL =     0x7000001f, # Delta C++ declarations (obsolete)
SHT_MIPS_SYMBOL_LIB =    0x70000020, # Symbol to library mapping
SHT_MIPS_EVENTS =        0x70000021, # Section event mapping
SHT_MIPS_TRANSLATE =     0x70000022, # Old pixie translation table (obsolete)
SHT_MIPS_PIXIE =         0x70000023, # Pixie specific sections (SGI)
SHT_MIPS_XLATE =         0x70000024, # Address translation table
SHT_MIPS_XLATE_DEBUG =   0x70000025, # SGI internal address translation table
SHT_MIPS_WHIRL =         0x70000026, # Intermediate code (MipsPro compiler)
SHT_MIPS_EH_REGION =     0x70000027, # C++ exception handling region information
SHT_MIPS_XLATE_OLD =     0x70000028,
SHT_MIPS_PDR_EXCEPTION = 0x70000029, # Runtime procedure descriptor table exception information (ucode)
SHT_MIPS_ABIFLAGS =      0x7000002a,

"""

# Application-specific sections

SHT.extend(0x80000000, 'SHT_LOUSER', None), # Start of application-specific
SHT.extend(0x8fffffff, 'SHT_HIUSER', None), # End of application-specific

# ################################################################
# 4. ELF file

class Virtual(object):
    # Compatibility with elfesteem API.
    def __init__(self, file):
        self.file = file
    def __getitem__(self, item):
        return self.file.getbyvad(item)
    def __setitem__(self, item, value):
        return self.file.setbyvad(item, value)
    def is_addr_in(self, ad):
        return self.file.is_in_virt_address(ad)
    def max_addr(self):
        # the maximum virtual address is found by retrieving the maximum
        # possible virtual address, either from the program entries, and
        # section entries. if there is no such object, raise an error.
        sh = [ x.addr+x.size   for x in self.file.sh ]
        ph = [ x.vaddr+x.memsz for x in self.file.ph ]
        return max(sh+ph)
    def find(self, pattern, offset = 0):
        segments = []
        for x in self.file.ph:
            s_max = x.memsz
            if offset < x.vaddr + s_max:
                segments.append(x)
        if not segments:
            return -1
        offset -= segments[0].vaddr
        if offset < 0:
            offset = 0
        for x in segments:
            data = self.file.pack()[x.offset:x.offset+x.filesz]
            ret = data.find(pattern, offset)
            if ret != -1:
                return ret  + x.vaddr
            offset = 0
        return -1
    # Deprecated elfesteem API
    def __call__(self, start, stop):
        return self[start:stop]
    def __len__(self):
        # __len__ should not be used: Python returns an int object, which
        # will cap values to 0x7FFFFFFF on 32 bit systems. A binary can have
        # a base address higher than this, resulting in the impossibility to
        # handle such programs.
        log.warning("__len__ deprecated")
        return self.max_addr()

def elf_default_content_reloc(self):
    self.ph.unwork([])
    self.sh.unwork([])

class ELF(AttributesElfesteem,Node):
    _layout = [
        ('Ehdr',     (Ehdr,   lambda s,k:0)),
        ('ph',       (PHList, lambda s,k:s.Ehdr.phoff)),
        ('sh',       (SHList, lambda s,k:s.Ehdr.shoff)),
        ]
    _rules = [
        RuleEqual('Ehdr.phnum', 'ph.count'),
        RuleEqual('Ehdr.shnum', 'sh.count'),
        ]
    def unpack(self, data, **kargs):
        Node.unpack(self, data, **kargs)
        # Add verifications that the file is well-formed.
        assert self.Ehdr.ehsize == self.Ehdr.packlen()
        """
        assert self.Ehdr.ehsize <= self.Ehdr.phoff
        assert self.Ehdr.shentsize == self.sh[0].packlen()
        assert self.Ehdr.phentsize == self.ph[0].packlen()
        """
        # Generate same log errors as elfesteem
        if not self.Ehdr.ident.e_class in ('ELFCLASS32', 'ELFCLASS64'):
            log.error("Invalid ELF, wordsize defined to %s",
                      self.Ehdr.ident.e_class)
        if not self.Ehdr.ident.e_data in ('ELFDATA2LSB', 'ELFDATA2MSB'):
            log.error("Invalid ELF, endianess defined to %s",
                      self.Ehdr.ident.e_data)
        if self.Ehdr.shoff > getattr(self, 'filesize', self.Ehdr.shoff):
            log.error("Offset to section headers after end of file")
        elif self.Ehdr.shnum == 0:
            log.warning('No section (e.g. core file)')
        if self.Ehdr.version != 1:
            log.error("Ehdr version is %d instead of 1" % self.Ehdr.version)
        return self
    def generate(self):
        OLD_VERSION
        if self.Ehdr.type == ET['ET_REL']:
            elf_default_content_reloc(self)
    def unwork(self, value):
        print("ELF.unwork %r"%value)
        TODO
    def binrepr(self):
        res = Node.binrepr(self)
        # Section data is not automatically rebuilt when 'sh' is packed,
        # because it is not part of the Struct.
        for s in self['sh']:
            data = s['content'].pack()
            if 8 == s['type'].work(): assert len(data) == 0 # NOBITS aka. .bss
            else:                     assert len(data) == s['size'].work()
            res[s['offset'].work()] = data
        return res
    def __getitem__(self, item):
        if isinstance(item, slice): return self.pack()[item]
        else:                       return Node.__getitem__(self, item)
    def getsectionsbyname(self, name):
        if ',' in name: name = name[:name.index(',')]
        return [s for s in self.sh if s['name'].work().strip('\x00') == name]
    def getsectionbyname(self, name):
        s = self.getsectionsbyname(name)
        if len(s) == 0: return None
        return s[0]['content']
    def getsectionsbytype(self, sectiontype):
        return [s for s in self.sh if s['type'].work() == sectiontype]
    def getsectionbytype(self, sectiontype):
        s = self.getsectionsbytype(sectiontype)
        if len(s) == 0: return None
        return s[0]['content']
    def get_byte_at_vad(self, ad):
        """ Get what is at a given virtual address """
        # Matching Section Headers and Program Headers
        sh = [ x for x in self.sh if x.addr <= ad < x.addr+x.size ]
        ph = [ x for x in self.ph if x.vaddr <= ad < x.vaddr+x.memsz ]
        # Corresponding offsets in the file
        so = [ ad-x.addr+x.offset for x in sh ]
        po = [ ad-x.vaddr+x.offset for x in ph ]
        if len(so) == 0 and len(po) == 0:
            raise ValueError('unknown rva address! %x' % ad)
        if len(so) == 1 and len(po) == 1:
            # Executable usually returns a section and a PH, with the same
            # offset in the file.
            assert so == po
            ad -= sh[0].addr
            return sh[0]['content'][ad:ad+1]
            return sh[0]['content'].pack()[ad:ad+1]
            assert self.pack()[so[0]] == sh[0]['content'][ad]
        # TODO: we need to deal with possible inconsistencies between
        # Section Headers and Program Headers.
        print( [sh, ph, so, po] )
        TODO
    def set_byte_at_vad(self, ad, value):
        """ Set a byte at a given virtual address """
        # Matching Section Headers and Program Headers
        sh = [ x for x in self.sh if x.addr <= ad < x.addr+x.size ]
        ph = [ x for x in self.ph if x.vaddr <= ad < x.vaddr+x.memsz ]
        # Corresponding offsets in the file
        so = [ ad-x.addr+x.offset for x in sh ]
        po = [ ad-x.vaddr+x.offset for x in ph ]
        if len(so) == 0 and len(po) == 0:
            raise ValueError('unknown rva address! %x' % ad)
        if len(so) == 1 and len(po) == 1:
            # Executable usually returns a section and a PH, with the same
            # offset in the file.
            assert so == po
            sh[0]['content'][ad-sh[0].addr] = value
            return
        # TODO: we need to deal with possible inconsistencies between
        # Section Headers and Program Headers.
        print( [sh, ph, so, po] )
        TODO
    def getbyvad(self, item):
        # TODO: faster version that does not read the bytes one by one
        ret = struct.pack('')
        for ad in range(item.start, item.stop):
            ret += self.get_byte_at_vad(ad)
        return ret
    def setbyvad(self, item, value):
        # TODO: faster version that does not write the bytes one by one
        if isinstance(item, slice): start, stop = item.start, item.stop
        else:                       start, stop = item, item+len(value)
        for ad in range(start, stop):
            self.set_byte_at_vad(ad, value[ad-start:ad-start+1])
    def getsectionbyvad(self, ad, section = None):
        if section:
            s = self.getsectionbyname(section)
            if s.sh.addr <= ad < s.sh.addr + s.sh.size:
                return s
        sh = [ x for x in self.sh if x.addr <= ad < x.addr+x.size ]
        ph = [ x for x in self.ph if x.vaddr <= ad < x.vaddr+x.memsz ]
        if len(sh) == 1 and len(ph) == 1:
            # Executable returns a section and a PH
            if not sh[0] in ph[0].shlist:
                raise ValueError("Mismatch: section not in segment")
            return sh[0]['content']
        if len(sh) == 1 and len(ph) > 1:
            # Executable may also return a section and many PH
            # e.g. the start of the .got section
            return sh[0]['content']
        if len(sh) == 0 and len(ph) == 1:
            # Core returns a PH
            return ph[0]['content']
        if len(ph) == 0 and len(sh) > 1:
            # Relocatable returns many sections, all at address 0
            # The priority given to .text is heuristic
            for s in sh:
                if s.sh.name == '.text':
                    return s['content']
            for s in sh:
                if s.sh.name.startswith('.text'):
                    return s['content']
            return sh[0]['content']
        return None
    def is_in_virt_address(self, ad):
        sh = [ s for s in self.sh if s.addr <= ad < s.addr+s.size ]
        return len(sh) > 0
    virt = property(lambda self: Virtual(self))
    # Deprecated elfesteem API
    _content = property(lambda self: self.pack())

if __name__ == "__main__":
    import sys, code
    if len(sys.argv) > 2:
        for f in sys.argv[1:]:
            print('File: %s'%f)
            e = ELF(open(f, 'rb').read())
            print (e.display())
        sys.exit(0)
    if len(sys.argv) == 2:
        file = open(sys.argv[1], 'rb').read()
        e = ELF(file)
        print (e.show())
        print (e.sh.readelf_display())
        print (e.not_parsed.ranges)
        #print (e.not_parsed.data.data.x) # all zeroes
        data = e.pack(paddingbyte=0)
        assert data == file
    code.interact('Interactive Python Console', None, locals())

