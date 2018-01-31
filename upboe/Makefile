#
# Copyright (C) 2011-2012 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=upboe
PKG_RELEASE:=1.0
PKG_MAINTAINER:=khls27 <khls27@126.com>

LUAC = luac
LUAC_OPTIONS = -s
PKG_BUILD_DIR := $(BUILD_DIR)/$(PKG_NAME)

include $(INCLUDE_DIR)/package.mk

define Package/upboe
  SECTION:=base
  CATEGORY:=Network
  DEPENDS:=+lua +ripple-base +kmod_kpboe
  TITLE:=PPP Bridge over ethernet management
  URL:=http://www.rippletek.com
  VERSION:=$(PKG_RELEASE)
endef

define Package/upboe/description
 This package is the management of PPP Bridge over Ethernet kernel module.
endef

define Package/upboe/conffiles
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./files $(PKG_BUILD_DIR)/
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Build/Configure
endef

define Build/Compile
	$(MAKE) -C $(PKG_BUILD_DIR) \
	CC="$(TARGET_CC)" \
	CFLAGS="$(TARGET_CFLAGS) -Wall" \
	LDFLAGS="$(TARGET_LDFLAGS)"

	for i in $(shell find $$(PKG_BUILD_DIR) -name *.lua -not -name debug.lua); \
		do $(LUAC) $(LUAC_OPTIONS) -o $(PKG_BUILD_DIR)/$$$$i $(PKG_BUILD_DIR)/$$$$i; \
	done
endef

define Package/upboe/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/upboe $(1)/usr/sbin/
	$(INSTALL_DIR) $(1)
	$(CP) $(PKG_BUILD_DIR)/files/* $(1)/
endef

$(eval $(call BuildPackage,upboe))

