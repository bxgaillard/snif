# ----------------------------------------------------------------------------
#
# Snif: a packet sniffer and analyzer
# Copyright (C) 2005 Benjamin Gaillard & Yannick Schuffenecker
#
# ----------------------------------------------------------------------------
#
#        File: mkfiles/flags.mk
#
# Description: Compilation Flags
#
# ----------------------------------------------------------------------------
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the Free
# Software Foundation; either version 2 of the License, or (at your option)
# any later version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
# more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc., 59
# Temple Place - Suite 330, Boston, MA 02111-1307, USA.
#
# ----------------------------------------------------------------------------


# OS-specific Definitions
ifneq ($(OS),Windows)
    # Programs
    CC     ?= gcc
    CXX    ?= g++
    RM     ?= rm -f
    AR     ?= ar
    RANLIB ?= ranlib

    # Compiling Flags
    CFLAGS   ?= -march=$(shell uname -m) -O2 -fomit-frame-pointer -pipe
    CFLAGS   := $(CFLAGS)
    CXXFLAGS ?= $(CFLAGS)
    CXXFLAGS := $(CXXFLAGS)

    # Additional Flags
    EXESUFFIX =

    # Windows Resources
    RCFILES =
else
    # Programs
    CC     ?= gcc.exe
    CXX    ?= g++.exe
    RC     ?= windres.exe
    RM     ?= rm.exe -f
    AR     ?= ar.exe
    RANLIB ?= ranlib.exe

    # Compiling Flags
    CFLAGS   ?= -march=i386 -mtune=i686 -O2 -fomit-frame-pointer -pipe
    CXXFLAGS ?= $(CFLAGS)
    CXXFLAGS := $(CXXFLAGS)
    LDFLAGS  += -mwindows -Wl,--subsystem,windows

    # Additional Flags
    EXESUFFIX = .exe

    # Windows Resources
    RCFILES := $(wildcard *.rc)
endif

# Custom Additions to Flags
WARN      = -Wall -Wextra
CFLAGS   += $(WARN)
CXXFLAGS += -fno-check-new -fno-rtti $(WARN)
CPPFLAGS += $(INCLUDES) -MD -MP
LDFLAGS  += -s

# End of File
