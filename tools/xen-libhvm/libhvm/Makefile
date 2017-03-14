XEN_ROOT = $(CURDIR)/../../..
include $(XEN_ROOT)/tools/Rules.mk

LIBHVM_OBJS = xenhvm.o smbios_module.o acpi_module.o xh_internal.o

LIBHVM_PIC_OBJS = $(patsubst %.o,%.opic,$(LIBHVM_OBJS))
LIBHVM_LIBS = $(LDLIBS_libxenstore)
$(LIBHVM_OBJS) $(LIBHVM_PIC_OBJS): CFLAGS += $(CFLAGS_libxenstore)

MAJOR = 1.0
MINOR = 0

CFLAGS += -I.

.PHONY: all
all: libxenhvm.so libxenhvm.a

libxenhvm.so: libxenhvm.so.$(MAJOR)
	ln -sf $< $@

libxenhvm.so.$(MAJOR): libxenhvm.so.$(MAJOR).$(MINOR)
	ln -sf $< $@

libxenhvm.so.$(MAJOR).$(MINOR): $(LIBHVM_PIC_OBJS)
	$(CC) $(LDFLAGS) -Wl,$(SONAME_LDFLAG) -Wl,libxenhvm.so.$(MAJOR) $(SHLIB_LDFLAGS) -o $@ $^ $(LIBHVM_LIBS) $(APPEND_LDFLAGS)

libxenhvm.a: $(LIBHVM_OBJS)
	$(AR) rcs libxenhvm.a $^

.PHONY: install
install: all
	$(INSTALL_DIR) $(DESTDIR)$(libdir)
	$(INSTALL_DIR) $(DESTDIR)$(includedir)
	$(INSTALL_SHLIB) libxenhvm.so.$(MAJOR).$(MINOR) $(DESTDIR)$(libdir)
	$(SYMLINK_SHLIB) libxenhvm.so.$(MAJOR).$(MINOR) $(DESTDIR)$(libdir)/libxenhvm.so.$(MAJOR)
	$(SYMLINK_SHLIB) libxenhvm.so.$(MAJOR) $(DESTDIR)$(libdir)/libxenhvm.so
	$(INSTALL_DATA) libxenhvm.a $(DESTDIR)$(libdir)
	$(INSTALL_DATA) xenhvm.h $(DESTDIR)$(includedir)

.PHONY: clean
clean:
	$(RM) -f *.o *.opic *.so* *.a $(DEPS)

distclean: clean

-include $(DEPS)
