################################################################################
#
# Keystone examples
#
################################################################################

ifeq ($(KEYSTONE_EXAMPLES),)
$(error KEYSTONE_EXAMPLES directory not defined)
else
include $(KEYSTONE)/mkutils/pkg-keystone.mk
endif

KEYSTONE_EXAMPLES_DEPENDENCIES += host-keystone-sdk keystone-runtime opensbi
KEYSTONE_EXAMPLES_CONF_OPTS += -DKEYSTONE_SDK_DIR=$(HOST_DIR)/usr/share/keystone/sdk \
                                -DKEYSTONE_EYRIE_RUNTIME=$(KEYSTONE_RUNTIME_BUILDDIR) \
                                -DKEYSTONE_BITS=${KEYSTONE_BITS}

KEYSTONE_EXAMPLES_MAKE_ENV += KEYSTONE_SDK_DIR=$(HOST_DIR)/usr/share/keystone/sdk
KEYSTONE_EXAMPLES_MAKE_OPTS += examples

# Install only .ke files
define KEYSTONE_EXAMPLES_INSTALL_TARGET_CMDS
	find $(@D) -name '*.ke' | \
                xargs -i{} $(INSTALL) -D -m 755 -t $(TARGET_DIR)/usr/share/keystone/examples/ {}
	$(INSTALL) -D -m 755 -t $(TARGET_DIR)/usr/share/keystone/examples/ $(@D)/clients/aesclient
	$(INSTALL) -D -m 755 -t $(TARGET_DIR)/usr/share/keystone/examples/ $(@D)/clients/signclient
	$(INSTALL) -D -m 755 -t $(TARGET_DIR)/usr/share/keystone/examples/ $(@D)/clients/client
	$(INSTALL) -D -m 755 -t $(TARGET_DIR)/usr/share/keystone/examples/ $(@D)/clients/server
	$(INSTALL) -D -m 755 -t $(TARGET_DIR)/usr/share/keystone/examples/ $(@D)/clients/input.txt
endef

define KEYSTONE_EXAMPLES_CUSTOM_PATCH
	patch -d $(@D)/tiny-AES-c -p1 -i $(KEYSTONE)/overlays/keystone/package/keystone-examples/0001-aes256.patch
endef

KEYSTONE_EXAMPLES_PRE_CONFIGURE_HOOKS += KEYSTONE_EXAMPLES_CUSTOM_PATCH

$(eval $(keystone-package))
$(eval $(cmake-package))

