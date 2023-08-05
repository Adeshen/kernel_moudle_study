obj-m += http_hook.o
CUR_PATH := $(shell pwd)    #当前模块所在目录
KERN_PATH := /usr/src/linux-headers-$(shell uname -r) #linux内核元代的当前版本
all:
	make -C ${KERN_PATH} M=${CUR_PATH} modules
clean:
	make -C ${KERN_PATH} M=${CUR_PATH} clean
