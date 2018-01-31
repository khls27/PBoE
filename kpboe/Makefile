#
# Copyright (C) 2008-2012 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:=kpboe
PKG_RELEASE:=1

include $(INCLUDE_DIR)/package.mk

define KernelPackage/kpboe
  SUBMENU:=Other modules
  TITLE:=PPP Bridge over Ethernet
  FILES:=$(PKG_BUILD_DIR)/kpboe.ko
  AUTOLOAD:=$(call AutoLoad,80,kpboe,1)
  KCONFIG:=
endef

define KernelPackage/kpboe/description
  PPP bridge over ethernet kernel module 
endef

MAKE_OPTS:= \
    ARCH="$(LINUX_KARCH)" \
    CROSS_COMPILE="$(TARGET_CROSS)" \
    SUBDIRS="$(PKG_BUILD_DIR)"

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Build/Compile
	$(MAKE) -C "$(LINUX_DIR)" \
	$(MAKE_OPTS) \
	modules
endef

$(eval $(call KernelPackage,kpboe))
