/*
 * drivers/input/tablet/wacom_sys.c
 *
 *  USB Wacom tablet support - system specific code
 */

/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include "wacom.h"
#include "wacom_wac.h"

/* defines to get HID report descriptor */
#define HID_DEVICET_HID		(USB_TYPE_CLASS | 0x01)
#define HID_DEVICET_REPORT	(USB_TYPE_CLASS | 0x02)
#define HID_USAGE_UNDEFINED		0x00
#define HID_USAGE_PAGE			0x05
#define HID_USAGE_PAGE_DIGITIZER	0x0d
#define HID_USAGE_PAGE_DESKTOP		0x01
#define HID_USAGE			0x09
#define HID_USAGE_X			0x30
#define HID_USAGE_Y			0x31
#define HID_USAGE_X_TILT		0x3d
#define HID_USAGE_Y_TILT		0x3e
#define HID_USAGE_FINGER		0x22
#define HID_USAGE_STYLUS		0x20
#define HID_USAGE_CONTACTMAX		0x55
#define HID_COLLECTION			0xc0

enum {
	WCM_UNDEFINED = 0,
	WCM_DESKTOP,
	WCM_DIGITIZER,
};

struct hid_descriptor {
	struct usb_descriptor_header header;
	__le16   bcdHID;
	u8       bCountryCode;
	u8       bNumDescriptors;
	u8       bDescriptorType;
	__le16   wDescriptorLength;
} __attribute__ ((packed));

/* defines to get/set USB message */
#define USB_REQ_GET_REPORT	0x01
#define USB_REQ_SET_REPORT	0x09

#define WAC_HID_OUTPUT_REPORT	0x01
#define WAC_HID_FEATURE_REPORT	0x03
#define WAC_MSG_RETRIES		5

#define WAC_CMD_LED_CONTROL	0x20
#define WAC_CMD_ICON_START	0x21
#define WAC_CMD_ICON_XFER	0x23
#define WAC_CMD_RETRIES		10
#define WAC_CMD_DELETE_PAIRING	0x20
#define WAC_CMD_UNPAIR_ALL	0xFF
#define WAC_REMOTE_SERIAL_MAX_STRLEN	9

#define DEV_ATTR_RO_PERM (S_IRUSR | S_IRGRP)

static ssize_t wacom_show_remote_mode(struct kobject *kobj,
				      struct kobj_attribute *kattr,
				      char *buf, int index)
{
	struct device *dev = container_of(kobj->parent, struct device, kobj);
	struct wacom *wacom = dev_get_drvdata(dev);			\
	u8 mode;

	mode = wacom->led.select[index];
	if (mode >= 0 && mode < 3)
		return snprintf(buf, PAGE_SIZE, "%d\n", mode);
	else
		return snprintf(buf, PAGE_SIZE, "%d\n", -1);
}

#define DEVICE_EKR_ATTR_GROUP(SET_ID)					\
static ssize_t wacom_show_remote##SET_ID##_mode(struct kobject *kobj,	\
			       struct kobj_attribute *kattr, char *buf)	\
{									\
	return wacom_show_remote_mode(kobj, kattr, buf, SET_ID);	\
}									\
static struct kobj_attribute remote##SET_ID##_mode_attr = {		\
	.attr = {.name = "remote_mode",					\
		.mode = DEV_ATTR_RO_PERM},				\
	.show = wacom_show_remote##SET_ID##_mode,			\
};									\
static struct attribute *remote##SET_ID##_serial_attrs[] = {		\
	&remote##SET_ID##_mode_attr.attr,				\
	NULL								\
};									\
static struct attribute_group remote##SET_ID##_serial_group = {		\
	.name = NULL,							\
	.attrs = remote##SET_ID##_serial_attrs,				\
}

DEVICE_EKR_ATTR_GROUP(0);
DEVICE_EKR_ATTR_GROUP(1);
DEVICE_EKR_ATTR_GROUP(2);
DEVICE_EKR_ATTR_GROUP(3);
DEVICE_EKR_ATTR_GROUP(4);

int wacom_remote_create_attr_group(void *wcombo, __u32 serial, int index)
{
	struct wacom_combo *wacom_combo = wcombo;
	struct wacom *wacom = wacom_combo->wacom;
	int error = 0;
	char *buf;
	struct wacom_wac *wacom_wac = wacom->wacom_wac;

	wacom_wac->serial[index] = serial;

	buf = kzalloc(WAC_REMOTE_SERIAL_MAX_STRLEN, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;
	snprintf(buf, WAC_REMOTE_SERIAL_MAX_STRLEN, "%d", serial);
	wacom->remote_group[index].name = buf;

	error = sysfs_create_group(wacom->remote_dir,
				   &wacom->remote_group[index]);
	if (error) {
		printk("wacom: cannot create sysfs group err: %d\n", error);
		kobject_put(wacom->remote_dir);
		return error;
	}

	return 0;
}

void wacom_remote_destroy_attr_group(void *wcombo, __u32 serial)
{
	struct wacom_combo *wacom_combo = wcombo;
	struct wacom *wacom = wacom_combo->wacom;
	struct wacom_wac *wacom_wac = wacom->wacom_wac;
	int i;

	if (!serial)
		return;

	for (i = 0; i < WACOM_MAX_REMOTES; i++) {
		if (wacom_wac->serial[i] == serial) {
			wacom_wac->serial[i] = 0;
			wacom->led.select[i] = WACOM_STATUS_UNKNOWN;
			if (wacom->remote_group[i].name) {
				sysfs_remove_group(wacom->remote_dir,
						   &wacom->remote_group[i]);
				kfree(wacom->remote_group[i].name);
				wacom->remote_group[i].name = NULL;
			}
		}
	}
}

static int wacom_set_report(struct usb_interface *intf, u8 type, u8 id,
			    void *buf, size_t size, unsigned int retries);

static int wacom_cmd_unpair_remote(struct wacom *wacom, unsigned char selector)
{
	const size_t buf_size = 2;
	unsigned char *buf;
	int retval;

	buf = kzalloc(buf_size, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	buf[0] = WAC_CMD_DELETE_PAIRING;
	buf[1] = selector;

	retval = wacom_set_report(wacom->intf, WAC_HID_OUTPUT_REPORT,
				  WAC_CMD_DELETE_PAIRING, buf,
				  buf_size, WAC_CMD_RETRIES);
	kfree(buf);

	return retval;
}

static ssize_t wacom_store_unpair_remote(struct kobject *kobj,
					 struct kobj_attribute *attr,
					 const char *buf, size_t count)
{
	unsigned char selector = 0;
	struct device *dev = container_of(kobj->parent, struct device, kobj);
	struct wacom *wacom = dev_get_drvdata(dev);
	int err;

	if (!strncmp(buf, "*\n", 2)) {
		selector = WAC_CMD_UNPAIR_ALL;
	} else {
		printk(KERN_INFO "wacom: remote: unrecognized unpair code: "
		       "%s\n", buf);
		return -1;
	}

	mutex_lock(&wacom->lock);

	err = wacom_cmd_unpair_remote(wacom, selector);
	mutex_unlock(&wacom->lock);

	return err < 0 ? err : count;
}

static struct kobj_attribute unpair_remote_attr = {
	.attr = {.name = "unpair_remote", .mode = 0200},
	.store = wacom_store_unpair_remote,
};

static const struct attribute *remote_unpair_attrs[] = {
	&unpair_remote_attr.attr,
	NULL
};

static int wacom_initialize_remote(struct wacom *wacom)
{
	int error = 0;
	struct wacom_wac *wacom_wac = wacom->wacom_wac;
	int i;

	if (wacom->wacom_wac->features.type != REMOTE)
		return 0;

	wacom->remote_group[0] = remote0_serial_group;
	wacom->remote_group[1] = remote1_serial_group;
	wacom->remote_group[2] = remote2_serial_group;
	wacom->remote_group[3] = remote3_serial_group;
	wacom->remote_group[4] = remote4_serial_group;

	wacom->remote_dir = kobject_create_and_add("wacom_remote",
						   &wacom->intf->dev.kobj);

	if (!wacom->remote_dir)
		return -ENOMEM;

	error = sysfs_create_files(wacom->remote_dir, remote_unpair_attrs);

	if (error) {
		printk(KERN_ERR "wacom: cannot create sysfs group err: %d\n",
		       error);
		return error;
	}

	for (i = 0; i < WACOM_MAX_REMOTES; i++) {
		wacom->led.select[i] = WACOM_STATUS_UNKNOWN;
		wacom_wac->serial[i] = 0;
	}

	return 0;
}

static void wacom_destroy_remotes(struct wacom *wacom)
{
	int i;

	if (!wacom->remote_dir)
		return;

	for (i = 0; i < WACOM_MAX_REMOTES; i++) {
		if (wacom->remote_group[i].name) {
			sysfs_remove_group(wacom->remote_dir,
					   &wacom->remote_group[i]);
			kfree(wacom->remote_group[i].name);
			wacom->remote_group[i].name = NULL;
		}
	}
	kobject_put(wacom->remote_dir);
}

static int wacom_get_report(struct usb_interface *intf, u8 type, u8 id,
			    void *buf, size_t size, unsigned int retries)
{
	struct usb_device *dev = interface_to_usbdev(intf);
	int retval;

	do {
		retval = usb_control_msg(dev, usb_rcvctrlpipe(dev, 0),
				USB_REQ_GET_REPORT,
				USB_DIR_IN | USB_TYPE_CLASS |
				USB_RECIP_INTERFACE,
				(type << 8) + id,
				intf->altsetting[0].desc.bInterfaceNumber,
				buf, size, 100);
	} while ((retval == -ETIMEDOUT || retval == -EPIPE) && --retries);

	return retval;
}

static int wacom_set_report(struct usb_interface *intf, u8 type, u8 id,
			    void *buf, size_t size, unsigned int retries)
{
	struct usb_device *dev = interface_to_usbdev(intf);
	int retval;

	do {
		retval = usb_control_msg(dev, usb_sndctrlpipe(dev, 0),
				USB_REQ_SET_REPORT,
				USB_TYPE_CLASS | USB_RECIP_INTERFACE,
				(type << 8) + id,
				intf->altsetting[0].desc.bInterfaceNumber,
				buf, size, 1000);
	} while ((retval == -ETIMEDOUT || retval == -EPIPE) && --retries);

	return retval;
}

static struct input_dev * get_input_dev(struct wacom_combo *wcombo)
{
	return wcombo->wacom->dev;
}

static void wacom_sys_irq(struct urb *urb)
{
	struct wacom *wacom = urb->context;
	struct wacom_combo wcombo;
	int retval;

	switch (urb->status) {
	case 0:
		/* success */
		break;
	case -ECONNRESET:
	case -ENOENT:
	case -ESHUTDOWN:
		/* this urb is terminated, clean up */
		dbg("%s - urb shutting down with status: %d", __func__, urb->status);
		return;
	default:
		dbg("%s - nonzero urb status received: %d", __func__, urb->status);
		goto exit;
	}

	wcombo.wacom = wacom;
	wcombo.urb = urb;

	if (wacom_wac_irq(wacom->wacom_wac, (void *)&wcombo))
		input_sync(get_input_dev(&wcombo));

 exit:
	usb_mark_last_busy(wacom->usbdev);
	retval = usb_submit_urb (urb, GFP_ATOMIC);
	if (retval)
		err ("%s - usb_submit_urb failed with result %d",
		     __func__, retval);
}

void wacom_report_key(void *wcombo, unsigned int key_type, int key_data)
{
	input_report_key(get_input_dev((struct wacom_combo *)wcombo), key_type, key_data);
}

void wacom_report_abs(void *wcombo, unsigned int abs_type, int abs_data)
{
	input_report_abs(get_input_dev((struct wacom_combo *)wcombo), abs_type, abs_data);
}

void wacom_report_rel(void *wcombo, unsigned int rel_type, int rel_data)
{
	input_report_rel(get_input_dev((struct wacom_combo *)wcombo), rel_type, rel_data);
}

void wacom_input_event(void *wcombo, unsigned int type, unsigned int code, int value)
{
	input_event(get_input_dev((struct wacom_combo *)wcombo), type, code, value);
}

void wacom_mt_slot(void *wcombo, int slot)
{
	input_mt_slot(get_input_dev(wcombo), slot);
}

void wacom_mt_report_slot_state(void *wcombo, unsigned int tool_type,
				bool active)
{
	input_mt_report_slot_state(get_input_dev(wcombo), tool_type, active);
}

void wacom_mt_report_pointer_emulation(void *wcombo, bool value)
{
	input_mt_report_pointer_emulation(get_input_dev(wcombo), value);
}

__u16 wacom_be16_to_cpu(unsigned char *data)
{
	__u16 value;
	value = be16_to_cpu(*(__be16 *) data);
	return value;
}

__u16 wacom_le16_to_cpu(unsigned char *data)
{
	__u16 value;
	value = le16_to_cpu(*(__le16 *) data);
	return value;
}

void wacom_input_sync(void *wcombo)
{
	input_sync(get_input_dev((struct wacom_combo *)wcombo));
}

int wacom_mt_get_slot_by_key(void *wcombo, int key)
{
	return input_mt_get_slot_by_key(get_input_dev((struct wacom_combo *)wcombo), key);
}

int wacom_wac_finger_count_touches(void *wc)
{
	struct wacom_combo *wcombo = (struct wacom_combo *)wc;
	struct wacom *wacom = wcombo->wacom;
	struct input_dev *input = wacom->dev;
	int count = 0;
	int i;

	for (i = 0; i < input->mt->num_slots; i++) {
		struct input_mt_slot *ps = &input->mt->slots[i];
		int id = input_mt_get_value(ps, ABS_MT_TRACKING_ID);
		if (id >= 0)
			count++;
	}

	return count;
}


static int wacom_open(struct input_dev *dev)
{
	struct wacom *wacom = input_get_drvdata(dev);
	int retval = 0;

	if (usb_autopm_get_interface(wacom->intf) < 0)
		return -EIO;

	mutex_lock(&wacom->lock);

	if (usb_submit_urb(wacom->irq, GFP_KERNEL)) {
		retval = -EIO;
		goto out;
	}

	wacom->open = 1;
	wacom->intf->needs_remote_wakeup = 1;

out:
	if (retval)
		usb_autopm_put_interface(wacom->intf);
	mutex_unlock(&wacom->lock);
	return retval;
}

static void wacom_close(struct input_dev *dev)
{
	struct wacom *wacom = input_get_drvdata(dev);

	mutex_lock(&wacom->lock);
	usb_kill_urb(wacom->irq);
	wacom->open = 0;
	wacom->intf->needs_remote_wakeup = 0;
	mutex_unlock(&wacom->lock);

	usb_autopm_put_interface(wacom->intf);
}

void input_dev_mo(struct input_dev *input_dev, struct wacom_wac *wacom_wac)
{
	input_dev->keybit[BIT_WORD(BTN_MISC)] |= BIT_MASK(BTN_1) |
		BIT_MASK(BTN_5);
	input_set_abs_params(input_dev, ABS_WHEEL, 0, 71, 0, 0);
}

void input_dev_g4(struct input_dev *input_dev, struct wacom_wac *wacom_wac)
{
	input_dev->evbit[0] |= BIT_MASK(EV_MSC);
	input_dev->mscbit[0] |= BIT_MASK(MSC_SERIAL);
	input_dev->keybit[BIT_WORD(BTN_DIGI)] |= BIT_MASK(BTN_TOOL_FINGER);
	input_dev->keybit[BIT_WORD(BTN_MISC)] |= BIT_MASK(BTN_0) |
		BIT_MASK(BTN_4);
}

void input_dev_g(struct input_dev *input_dev, struct wacom_wac *wacom_wac)
{
	input_dev->evbit[0] |= BIT_MASK(EV_REL);
	input_dev->relbit[0] |= BIT_MASK(REL_WHEEL);
	input_dev->keybit[BIT_WORD(BTN_MOUSE)] |= BIT_MASK(BTN_LEFT) |
		BIT_MASK(BTN_RIGHT) | BIT_MASK(BTN_MIDDLE);
	input_dev->keybit[BIT_WORD(BTN_DIGI)] |= BIT_MASK(BTN_TOOL_RUBBER) |
		BIT_MASK(BTN_TOOL_PEN) | BIT_MASK(BTN_STYLUS) |
		BIT_MASK(BTN_TOOL_MOUSE) | BIT_MASK(BTN_STYLUS2);
	input_set_abs_params(input_dev, ABS_DISTANCE, 0, wacom_wac->features.distance_max, 0, 0);
}

void input_dev_24hd(struct input_dev *input_dev, struct wacom_wac *wacom_wac)
{
	input_dev->keybit[BIT_WORD(BTN_GAMEPAD)] |= BIT_MASK(BTN_A) | BIT_MASK(BTN_B) | BIT_MASK(BTN_C);
	input_dev->keybit[BIT_WORD(BTN_GAMEPAD)] |= BIT_MASK(BTN_X) | BIT_MASK(BTN_Y) | BIT_MASK(BTN_Z);
	input_dev->keybit[BIT_WORD(BTN_MISC)] |= BIT_MASK(BTN_0) | BIT_MASK(BTN_1) | BIT_MASK(BTN_2) |
						 BIT_MASK(BTN_3) | BIT_MASK(BTN_4) | BIT_MASK(BTN_5) |
						 BIT_MASK(BTN_6) | BIT_MASK(BTN_7) | BIT_MASK(BTN_8) |
						 BIT_MASK(BTN_9);
	input_dev->keybit[BIT_WORD(KEY_PROG1)] |= BIT_MASK(KEY_PROG1) | BIT_MASK(KEY_PROG2);
	input_dev->keybit[BIT_WORD(KEY_PLAYCD)] |= BIT_MASK(KEY_PROG3);

	input_set_abs_params(input_dev, ABS_Z, -900, 899, 0, 0);
	input_set_abs_params(input_dev, ABS_THROTTLE, 0, 71, 0, 0);
	input_set_capability(input_dev, EV_MSC, MSC_SERIAL);

	input_dev->keybit[BIT_WORD(BTN_TOOL_RUBBER)] |= BIT_MASK(BTN_TOOL_RUBBER) | BIT_MASK(BTN_TOOL_PEN) |
						BIT_MASK(BTN_TOOL_BRUSH) | BIT_MASK(BTN_TOOL_PENCIL) |
						BIT_MASK(BTN_TOOL_AIRBRUSH) | BIT_MASK(BTN_STYLUS) |
						BIT_MASK(BTN_STYLUS2);

	input_set_abs_params(input_dev, ABS_DISTANCE,
			     0, wacom_wac->features.distance_max, 0, 0);
	input_set_abs_params(input_dev, ABS_WHEEL, 0, 1023, 0, 0);
	input_set_abs_params(input_dev, ABS_TILT_X, 0, 127, 0, 0);
	input_set_abs_params(input_dev, ABS_TILT_Y, 0, 127, 0, 0);
}

void input_dev_c22hd(struct input_dev *input_dev, struct wacom_wac *wacom_wac)
{
	input_dev->keybit[BIT_WORD(KEY_PROG1)] |= BIT_MASK(KEY_PROG1);
	input_dev->keybit[BIT_WORD(KEY_PROG2)] |= BIT_MASK(KEY_PROG2);
	input_dev->keybit[BIT_WORD(KEY_PROG3)] |= BIT_MASK(KEY_PROG3);
}

void input_dev_c21ux2(struct input_dev *input_dev, struct wacom_wac *wacom_wac)
{
	input_dev->keybit[BIT_WORD(BTN_GAMEPAD)] |= BIT_MASK(BTN_A) | BIT_MASK(BTN_B) | BIT_MASK(BTN_C);
	input_dev->keybit[BIT_WORD(BTN_GAMEPAD)] |= BIT_MASK(BTN_X) | BIT_MASK(BTN_Y) | BIT_MASK(BTN_Z);
	input_dev->keybit[BIT_WORD(BTN_JOYSTICK)] |= BIT_MASK(BTN_BASE) | BIT_MASK(BTN_BASE2);
}

void input_dev_i3s(struct input_dev *input_dev, struct wacom_wac *wacom_wac)
{
	input_dev->keybit[BIT_WORD(BTN_DIGI)] |= BIT_MASK(BTN_TOOL_FINGER);
	input_dev->keybit[BIT_WORD(BTN_MISC)] |= BIT_MASK(BTN_0) |
		BIT_MASK(BTN_1) | BIT_MASK(BTN_2) | BIT_MASK(BTN_3);
	input_set_abs_params(input_dev, ABS_RX, 0, 4096, 0, 0);
	input_set_abs_params(input_dev, ABS_Z, -900, 899, 0, 0);
}

void input_dev_i3(struct input_dev *input_dev, struct wacom_wac *wacom_wac)
{
	input_dev->keybit[BIT_WORD(BTN_MISC)] |= BIT_MASK(BTN_4) |
		BIT_MASK(BTN_5) | BIT_MASK(BTN_6) | BIT_MASK(BTN_7);
	input_set_abs_params(input_dev, ABS_RY, 0, 4096, 0, 0);
}

int input_dev_i4s(struct input_dev *input_dev, struct wacom_wac *wacom_wac)
{
	struct wacom_features *features = &wacom_wac->features;

	input_dev->keybit[BIT_WORD(BTN_DIGI)] |= BIT_MASK(BTN_TOOL_FINGER);
	input_dev->keybit[BIT_WORD(BTN_MISC)] |= BIT_MASK(BTN_0) | BIT_MASK(BTN_1) | BIT_MASK(BTN_2) | BIT_MASK(BTN_3);
	input_dev->keybit[BIT_WORD(BTN_MISC)] |= BIT_MASK(BTN_4) | BIT_MASK(BTN_5) | BIT_MASK(BTN_6);
	input_set_abs_params(input_dev, ABS_Z, -900, 899, 0, 0);

	if (features->device_type == BTN_TOOL_FINGER) {
		__clear_bit(ABS_MISC, input_dev->absbit);
		input_mt_init_slots(input_dev, features->touch_max, 0);
		input_set_abs_params(input_dev, ABS_MT_TOUCH_MAJOR, 0, features->x_max, 0, 0);
		input_set_abs_params(input_dev, ABS_MT_WIDTH_MAJOR, 0, features->x_max, 0, 0);
		input_set_abs_params(input_dev, ABS_MT_WIDTH_MINOR, 0, features->y_max, 0, 0);
		input_set_abs_params(input_dev, ABS_MT_ORIENTATION, 0, 1, 0, 0);
		input_set_abs_params(input_dev, ABS_MT_POSITION_X,
				     0, features->x_max, 0, 0);
		input_set_abs_params(input_dev, ABS_MT_POSITION_Y,
				     0, features->y_max, 0, 0);
	}
	return 0;
}

void input_dev_i4(struct input_dev *input_dev, struct wacom_wac *wacom_wac)
{
	input_dev->keybit[BIT_WORD(BTN_MISC)] |= BIT_MASK(BTN_7) | BIT_MASK(BTN_8);
}

void input_dev_bee(struct input_dev *input_dev, struct wacom_wac *wacom_wac)
{
	input_dev->keybit[BIT_WORD(BTN_MISC)] |= BIT_MASK(BTN_8) | BIT_MASK(BTN_9);
}

void input_dev_cintiq(struct input_dev *input_dev, struct wacom_wac *wacom_wac)
{
	input_dev->keybit[BIT_WORD(BTN_MISC)] |= BIT_MASK(BTN_0) | BIT_MASK(BTN_1) | BIT_MASK(BTN_2) | BIT_MASK(BTN_3);
	input_dev->keybit[BIT_WORD(BTN_MISC)] |= BIT_MASK(BTN_4) | BIT_MASK(BTN_5) | BIT_MASK(BTN_6) | BIT_MASK(BTN_7);
	input_dev->keybit[BIT_WORD(BTN_DIGI)] |= BIT_MASK(BTN_TOOL_FINGER);

	input_set_abs_params(input_dev, ABS_RX, 0, 4096, 0, 0);
	input_set_abs_params(input_dev, ABS_RY, 0, 4096, 0, 0);
	input_set_abs_params(input_dev, ABS_Z, -900, 899, 0, 0);

	input_dev->evbit[0] |= BIT_MASK(EV_MSC);
	input_dev->mscbit[0] |= BIT_MASK(MSC_SERIAL);
	input_dev->keybit[BIT_WORD(BTN_DIGI)] |= BIT_MASK(BTN_TOOL_RUBBER) |
		BIT_MASK(BTN_TOOL_PEN) | BIT_MASK(BTN_TOOL_BRUSH) |
		BIT_MASK(BTN_TOOL_PENCIL) | BIT_MASK(BTN_TOOL_AIRBRUSH);
	input_dev->keybit[BIT_WORD(BTN_DIGI)] |= BIT_MASK(BTN_STYLUS) | BIT_MASK(BTN_STYLUS2);

	input_set_abs_params(input_dev, ABS_DISTANCE, 0, wacom_wac->features.distance_max, 0, 0);
	input_set_abs_params(input_dev, ABS_WHEEL, 0, 1023, 0, 0);
	input_set_abs_params(input_dev, ABS_TILT_X, 0, 127, 0, 0);
	input_set_abs_params(input_dev, ABS_TILT_Y, 0, 127, 0, 0);
}


void input_dev_i(struct input_dev *input_dev, struct wacom_wac *wacom_wac)
{
	input_dev->evbit[0] |= BIT_MASK(EV_MSC) | BIT_MASK(EV_REL);
	input_dev->mscbit[0] |= BIT_MASK(MSC_SERIAL);
	input_dev->relbit[0] |= BIT_MASK(REL_WHEEL);
	input_dev->keybit[BIT_WORD(BTN_MOUSE)] |= BIT_MASK(BTN_LEFT) |
		BIT_MASK(BTN_RIGHT) | BIT_MASK(BTN_MIDDLE) |
		BIT_MASK(BTN_SIDE) | BIT_MASK(BTN_EXTRA);
	input_dev->keybit[BIT_WORD(BTN_DIGI)] |= BIT_MASK(BTN_TOOL_RUBBER) |
		BIT_MASK(BTN_TOOL_PEN) | BIT_MASK(BTN_STYLUS) |
		BIT_MASK(BTN_TOOL_MOUSE) | BIT_MASK(BTN_TOOL_BRUSH) |
		BIT_MASK(BTN_TOOL_PENCIL) | BIT_MASK(BTN_TOOL_AIRBRUSH) |
		BIT_MASK(BTN_TOOL_LENS) | BIT_MASK(BTN_STYLUS2);
	input_set_abs_params(input_dev, ABS_DISTANCE,
			     0, wacom_wac->features.distance_max, 0, 0);
	input_set_abs_params(input_dev, ABS_WHEEL, 0, 1023, 0, 0);
	input_set_abs_params(input_dev, ABS_TILT_X, 0, 127, 0, 0);
	input_set_abs_params(input_dev, ABS_TILT_Y, 0, 127, 0, 0);
	input_set_abs_params(input_dev, ABS_RZ, -900, 899, 0, 0);
	input_set_abs_params(input_dev, ABS_THROTTLE, -1023, 1023, 0, 0);
}

void input_dev_pl(struct input_dev *input_dev, struct wacom_wac *wacom_wac)
{
	input_dev->keybit[BIT_WORD(BTN_DIGI)] |= BIT_MASK(BTN_TOOL_PEN) |
		BIT_MASK(BTN_STYLUS) | BIT_MASK(BTN_STYLUS2);
}

void input_dev_pt(struct input_dev *input_dev, struct wacom_wac *wacom_wac)
{
	input_dev->keybit[BIT_WORD(BTN_DIGI)] |= BIT_MASK(BTN_TOOL_RUBBER);
}

void input_dev_bamboo_pt(struct input_dev *input_dev, struct wacom_wac *wacom_wac)
{
	struct wacom_features *features = &wacom_wac->features;

	input_dev->absbit[BIT_WORD(ABS_MISC)] &= ~ABS_MISC;

	if (features->type == BAMBOO_PT) {
		/* for now, BAMBOO_PT will only handle pen */
		input_dev->keybit[BIT_WORD(BTN_DIGI)] |= BIT_MASK(BTN_TOOL_RUBBER) |
			BIT_MASK(BTN_STYLUS2);
		input_set_abs_params(input_dev, ABS_DISTANCE, 0,
				     wacom_wac->features.distance_max, 0, 0);
		return;
	}

	if (features->device_type == BTN_TOOL_FINGER) {
		__set_bit(BTN_LEFT, input_dev->keybit);
		__set_bit(BTN_FORWARD, input_dev->keybit);
		__set_bit(BTN_BACK, input_dev->keybit);
		__set_bit(BTN_RIGHT, input_dev->keybit);

		if (features->touch_max) {
			/* touch interface */
			unsigned int flags = INPUT_MT_POINTER;

			__set_bit(INPUT_PROP_POINTER, input_dev->propbit);
			if (features->pktlen == WACOM_PKGLEN_BBTOUCH3) {
				input_set_abs_params(input_dev,
					     ABS_MT_TOUCH_MAJOR,
					     0, features->x_max, 0, 0);
				input_set_abs_params(input_dev,
					     ABS_MT_TOUCH_MINOR,
					     0, features->y_max, 0, 0);
			} else {
				__set_bit(BTN_TOOL_FINGER, input_dev->keybit);
				__set_bit(BTN_TOOL_DOUBLETAP, input_dev->keybit);
				flags = 0;
			}
			if (features->touch_max > 1) {
				input_set_abs_params(input_dev, ABS_MT_POSITION_X,
						     0, features->x_max, 0, 0);
				input_set_abs_params(input_dev, ABS_MT_POSITION_Y,
						     0, features->y_max, 0, 0);
			}
			input_mt_init_slots(input_dev, features->touch_max, flags);
		} else {
			/* buttons/keys only interface */
			__clear_bit(ABS_X, input_dev->absbit);
			__clear_bit(ABS_Y, input_dev->absbit);
			__clear_bit(BTN_TOUCH, input_dev->keybit);
		}
	} else if (features->device_type == BTN_TOOL_PEN) {
		__set_bit(INPUT_PROP_POINTER, input_dev->propbit);
		__set_bit(BTN_TOOL_RUBBER, input_dev->keybit);
		__set_bit(BTN_TOOL_PEN, input_dev->keybit);
		__set_bit(BTN_STYLUS, input_dev->keybit);
		__set_bit(BTN_STYLUS2, input_dev->keybit);
		input_set_abs_params(input_dev, ABS_DISTANCE, 0,
				     features->distance_max,
				     0, 0);
	}
}

void input_dev_tpc(struct input_dev *input_dev, struct wacom_wac *wacom_wac)
{
	if (wacom_wac->features.device_type == BTN_TOOL_FINGER ||
	    wacom_wac->features.device_type == BTN_TOOL_PEN) {
		input_set_abs_params(input_dev, ABS_RX, 0, wacom_wac->features.x_phy, 0, 0);
		input_set_abs_params(input_dev, ABS_RY, 0, wacom_wac->features.y_phy, 0, 0);
	}
}

void input_dev_24hdt(struct input_dev *input_dev, struct wacom_wac *wacom_wac)
{
	struct wacom_features *features = &wacom_wac->features;

	if (features->device_type == BTN_TOOL_FINGER) {
		input_set_abs_params(input_dev, ABS_MT_TOUCH_MAJOR, 0, features->x_max, 0, 0);
		input_set_abs_params(input_dev, ABS_MT_WIDTH_MAJOR, 0, features->x_max, 0, 0);
		input_set_abs_params(input_dev, ABS_MT_WIDTH_MINOR, 0, features->y_max, 0, 0);
		input_set_abs_params(input_dev, ABS_MT_ORIENTATION, 0, 1, 0, 0);
	}
}

int input_dev_tpc2fg(struct input_dev *input_dev, struct wacom_wac *wacom_wac)
{
	if (wacom_wac->features.device_type == BTN_TOOL_FINGER) {
		input_dev->absbit[BIT_WORD(ABS_MISC)] &= ~BIT_MASK(ABS_MISC);

		input_mt_init_slots(input_dev, 2, 0);
		input_set_abs_params(input_dev, ABS_MT_POSITION_X,
				     0, wacom_wac->features.x_max, 0, 0);
		input_set_abs_params(input_dev, ABS_MT_POSITION_Y,
				     0, wacom_wac->features.y_max, 0, 0);
	}
	return 0;
}

void input_dev_ipro(struct input_dev *input_dev, struct wacom_wac *wacom_wac)
{
	if (wacom_wac->features.device_type == BTN_TOOL_PEN) {
		__set_bit(BTN_7, input_dev->keybit);
		__set_bit(BTN_8, input_dev->keybit);
	}
}

void input_dev_ipros(struct input_dev *input_dev, struct wacom_wac *wacom_wac)
{
	int i;

	if (wacom_wac->features.device_type == BTN_TOOL_PEN) {
		for (i = 0; i < 7; i++)
			__set_bit(BTN_0 + i, input_dev->keybit);

		input_set_abs_params(input_dev, ABS_DISTANCE, 0,
				     wacom_wac->features.distance_max,
				     0, 0);

		input_set_abs_params(input_dev, ABS_Z, -900, 899, 0, 0);

		input_set_capability(input_dev, EV_REL, REL_WHEEL);

		input_set_capability(input_dev, EV_MSC, MSC_SERIAL);

		__set_bit(BTN_TOOL_RUBBER, input_dev->keybit);
		__set_bit(BTN_TOOL_PEN, input_dev->keybit);
		__set_bit(BTN_TOOL_BRUSH, input_dev->keybit);
		__set_bit(BTN_TOOL_PENCIL, input_dev->keybit);
		__set_bit(BTN_TOOL_AIRBRUSH, input_dev->keybit);
		__set_bit(BTN_STYLUS, input_dev->keybit);
		__set_bit(BTN_STYLUS2, input_dev->keybit);

		input_set_abs_params(input_dev, ABS_WHEEL, 0, 1023, 0, 0);
		input_set_abs_params(input_dev, ABS_TILT_X, 0, 127, 0, 0);
		input_set_abs_params(input_dev, ABS_TILT_Y, 0, 127, 0, 0);

		__set_bit(BTN_LEFT, input_dev->keybit);
		__set_bit(BTN_RIGHT, input_dev->keybit);
		__set_bit(BTN_MIDDLE, input_dev->keybit);
		__set_bit(BTN_SIDE, input_dev->keybit);
		__set_bit(BTN_EXTRA, input_dev->keybit);
		__set_bit(BTN_TOOL_MOUSE, input_dev->keybit);
		__set_bit(BTN_TOOL_LENS, input_dev->keybit);

		input_set_abs_params(input_dev, ABS_RZ, -900, 899, 0, 0);
		input_set_abs_params(input_dev, ABS_THROTTLE, -1023, 1023, 0, 0);
	} else if (wacom_wac->features.device_type == BTN_TOOL_FINGER) {
		__clear_bit(ABS_MISC, input_dev->absbit);

		input_set_abs_params(input_dev, ABS_MT_TOUCH_MAJOR, 0,
				     wacom_wac->features.x_max, 0, 0);
		input_set_abs_params(input_dev, ABS_MT_TOUCH_MINOR, 0,
				     wacom_wac->features.y_max, 0, 0);
		input_set_abs_params(input_dev, ABS_MT_POSITION_X,
				     0, wacom_wac->features.x_max, 0, 0);
		input_set_abs_params(input_dev, ABS_MT_POSITION_Y,
				     0, wacom_wac->features.y_max, 0, 0);
		input_mt_init_slots(input_dev, 16, INPUT_MT_POINTER);
	}
}

void input_dev_remote(struct input_dev *input_dev, struct wacom_wac *wacom_wac)
{
	/*
	 * Upstream has these figured out by the HID layer, we have to do it
	 * manually here
	 */
	__set_bit(BTN_0, input_dev->keybit);
	__set_bit(BTN_1, input_dev->keybit);
	__set_bit(BTN_2, input_dev->keybit);
	__set_bit(BTN_3, input_dev->keybit);
	__set_bit(BTN_4, input_dev->keybit);
	__set_bit(BTN_5, input_dev->keybit);
	__set_bit(BTN_6, input_dev->keybit);
	__set_bit(BTN_7, input_dev->keybit);
	__set_bit(BTN_8, input_dev->keybit);
	__set_bit(BTN_9, input_dev->keybit);
	__set_bit(BTN_A, input_dev->keybit);
	__set_bit(BTN_B, input_dev->keybit);
	__set_bit(BTN_C, input_dev->keybit);
	__set_bit(BTN_X, input_dev->keybit);
	__set_bit(BTN_Y, input_dev->keybit);
	__set_bit(BTN_Z, input_dev->keybit);
	__set_bit(BTN_BASE, input_dev->keybit);
	__set_bit(BTN_BASE2, input_dev->keybit);
	__set_bit(BTN_TOOL_PEN, input_dev->keybit);
	__set_bit(BTN_TOOL_RUBBER, input_dev->keybit);
	__clear_bit(BTN_TOUCH, input_dev->keybit);
	__set_bit(BTN_STYLUS, input_dev->keybit);
	input_set_abs_params(input_dev, ABS_X, 0, 1, 0, 0);
	input_set_abs_params(input_dev, ABS_Y, 0, 1, 0, 0);
	input_set_abs_params(input_dev, ABS_WHEEL, 0, 71, 0, 0);
	__clear_bit(ABS_PRESSURE, input_dev->absbit);
	__set_bit(ABS_MISC, input_dev->absbit);
	__set_bit(EV_MSC, input_dev->evbit);
}

void input_dev_cintiq27qhd(struct input_dev *input_dev, struct wacom_wac *wacom_wac)
{
	__set_bit(KEY_PROG1, input_dev->keybit);
	__set_bit(KEY_PROG2, input_dev->keybit);
	__set_bit(KEY_PROG3, input_dev->keybit);
	__set_bit(INPUT_PROP_ACCELEROMETER, input_dev->propbit);
}

static void wacom_retrieve_report_data(struct usb_interface *intf,
				       struct wacom_features *features)
{
	int result = 0;
	unsigned char *rep_data;

	rep_data = kmalloc(2, GFP_KERNEL);
	if (rep_data) {

		rep_data[0] = 12;
		result = wacom_get_report(intf, WAC_HID_FEATURE_REPORT,
					  rep_data[0], rep_data, 2,
					  WAC_MSG_RETRIES);

		if (result >= 0 && rep_data[1] > 2)
			features->touch_max = rep_data[1];

		kfree(rep_data);
	}
}

static int wacom_parse_hid(struct usb_interface *intf, struct hid_descriptor *hid_desc,
			   struct wacom_features *features)
{
	struct usb_device *dev = interface_to_usbdev(intf);
	char limit = 0;
	/* result has to be defined as int for some devices */
 	int result = 0;
	int i = 0, usage = WCM_UNDEFINED, finger = 0, pen = 0;
	unsigned char *report;

	report = kzalloc(hid_desc->wDescriptorLength, GFP_KERNEL);
	if (!report)
		return -ENOMEM;

	/* retrive report descriptors */
	do {
		result = usb_control_msg(dev, usb_rcvctrlpipe(dev, 0),
			USB_REQ_GET_DESCRIPTOR,
			USB_RECIP_INTERFACE | USB_DIR_IN,
			HID_DEVICET_REPORT << 8,
			intf->altsetting[0].desc.bInterfaceNumber, /* interface */
			report,
			hid_desc->wDescriptorLength,
			5000); /* 5 secs */
	} while (result < 0 && limit++ < 5);

	/* No need to parse the Descriptor. It isn't an error though */
	if (result < 0)
		goto out;

	for (i = 0; i < hid_desc->wDescriptorLength; i++) {

		switch (report[i]) {
		case HID_USAGE_PAGE:
			switch (report[i + 1]) {
			case HID_USAGE_PAGE_DIGITIZER:
				usage = WCM_DIGITIZER;
				i++;
				break;

			case HID_USAGE_PAGE_DESKTOP:
				usage = WCM_DESKTOP;
				i++;
				break;
			}
			break;

		case HID_USAGE:
			switch (report[i + 1]) {
			case HID_USAGE_X:
				if (usage == WCM_DESKTOP) {
					if (finger) {
						features->device_type = BTN_TOOL_FINGER;
						if (features->type == TABLETPC2FG) {
							/* need to reset back */
							features->pktlen = WACOM_PKGLEN_TPC2FG;
						}

						if (features->type == MTSCREEN ||
						    features->type == WACOM_24HDT)
							features->pktlen = WACOM_PKGLEN_MTOUCH;

						if (features->type == WACOM_24HDT) {
							features->x_max =
								wacom_le16_to_cpu(&report[i + 3]);
							features->x_phy =
								wacom_le16_to_cpu(&report[i + 8]);
							features->unit = report[i - 1];
							features->unitExpo = report[i - 3];
							i += 12;
						} else {
							features->x_max =
								wacom_le16_to_cpu(&report[i + 3]);
							features->x_phy =
								wacom_le16_to_cpu(&report[i + 6]);
							features->unit = report[i + 9];
							features->unitExpo = report[i + 11];
							i += 12;
						}
					} else if (pen) {
						/* penabled only accepts exact bytes of data */
						if (features->type == TABLETPC2FG ||
						    (features->type >= INTUOS5S && features->type <= INTUOSPL))
							features->pktlen = WACOM_PKGLEN_PENABLED;
						features->device_type = BTN_TOOL_PEN;
						features->x_max =
							wacom_le16_to_cpu(&report[i + 3]);
						i += 4;
					}
				} else if (usage == WCM_DIGITIZER) {
					/* max pressure isn't reported
					features->pressure_max = (unsigned short)
							(report[i+4] << 8  | report[i + 3]);
					*/
					features->pressure_max = 255;
					i += 4;
				}
				break;

			case HID_USAGE_Y:
				if (usage == WCM_DESKTOP) {
					if (finger) {
						if (features->type == TABLETPC2FG || features->type == MTSCREEN) {
							features->y_max =
								wacom_le16_to_cpu(&report[i + 3]);
							features->y_phy =
								wacom_le16_to_cpu(&report[i + 6]);
							i += 7;
						} else if (features->type == WACOM_24HDT) {
							features->y_max =
								wacom_le16_to_cpu(&report[i + 3]);
							features->y_phy =
								wacom_le16_to_cpu(&report[i - 2]);
							i += 7;
						} else {
							features->y_max =
								features->x_max;
							features->y_phy =
								wacom_le16_to_cpu(&report[i + 3]);
							i += 4;
						}
					} else if (pen) {
						features->y_max =
							wacom_le16_to_cpu(&report[i + 3]);
						i += 4;
					}
				}
				break;

			case HID_USAGE_FINGER:
				finger = 1;
				i++;
				break;

			case HID_USAGE_STYLUS:
				pen = 1;
				i++;
				break;

			case HID_USAGE_CONTACTMAX:
				if (!features->touch_max)
					wacom_retrieve_report_data(intf, features);
				i++;
				break;
			}
			break;

		case HID_COLLECTION:
			/* reset UsagePage and Finger */
			finger = usage = 0;
			break;
		}
	}

 out:
	result = 0;
	kfree(report);
	return result;
}

static int wacom_set_device_mode(struct usb_interface *intf, int report_id, int length, int mode)
{
	unsigned char *rep_data;
	int error = -ENOMEM, limit = 0;

	rep_data = kzalloc(length, GFP_KERNEL);
	if (!rep_data)
		return error;

	do {
		rep_data[0] = report_id;
		rep_data[1] = mode;

		error = wacom_set_report(intf, WAC_HID_FEATURE_REPORT,
		                         report_id, rep_data, length, 1);
		if (error >= 0)
			error = wacom_get_report(intf, WAC_HID_FEATURE_REPORT,
			                         report_id, rep_data, length, 1);
	} while ((error < 0 || rep_data[1] != mode) && limit++ < WAC_MSG_RETRIES);

	kfree(rep_data);

	return error < 0 ? error : 0;
}

/*
 * Switch the tablet into its most-capable mode. Wacom tablets are
 * typically configured to power-up in a mode which sends mouse-like
 * reports to the OS. To get absolute position, pressure data, etc.
 * from the tablet, it is necessary to switch the tablet out of this
 * mode and into one which sends the full range of tablet data.
 */
static int wacom_query_tablet_data(struct usb_interface *intf, struct wacom_features *features)
{
	if (features->device_type == BTN_TOOL_FINGER) {
		if (features->type > TABLETPC) {
			/* MT Tablet PC touch */
			return wacom_set_device_mode (intf, 3, 4, 4);
		}
		else if (features->type == WACOM_24HDT) {
			return wacom_set_device_mode(intf, 18, 3, 2);
		}
		else if (features->type == WACOM_27QHDT) {
			return wacom_set_device_mode(intf, 131, 3, 2);
		}
	} else if (features->device_type == BTN_TOOL_PEN) {
		if (features->type <= BAMBOO_PT && features->type != WIRELESS) {
			return wacom_set_device_mode(intf, 2, 2, 2);
		}
	}

	return 0;
}

static int wacom_retrieve_hid_descriptor(struct usb_interface *intf,
					 struct wacom_features *features)
{
	int error = 0;
	struct usb_host_interface *interface = intf->cur_altsetting;
	struct hid_descriptor *hid_desc;

	/* default device to penabled */
	features->device_type = BTN_TOOL_PEN;

	/*
	 * The wireless device HID is basic and layout conflicts with
	 * other tablets (monitor and touch interface can look like pen).
	 * Skip the query for this type and modify defaults based on
	 * interface number.
	 */
	if (features->type == WIRELESS) {
		if (intf->cur_altsetting->desc.bInterfaceNumber == 0) {
			features->device_type = 0;
		} else if (intf->cur_altsetting->desc.bInterfaceNumber == 2) {
			features->device_type = BTN_TOOL_DOUBLETAP;
			features->pktlen = WACOM_PKGLEN_BBTOUCH3;
		}
	}

	/* only Tablet PCs and Bamboo P&T need to retrieve the info */
	if (features->type < WACOM_24HDT &&
	    (features->type < INTUOS5S || features->type > INTUOSPL) &&
	    features->type != MTSCREEN)
		goto out;

	/*
	 * REMOTE upstream does use HID parsing but for RHEL6 we have it
	 * statically defined
	 */
	if (features->type == REMOTE)
		goto out;

	if (usb_get_extra_descriptor(interface, HID_DEVICET_HID, &hid_desc)) {
		if (usb_get_extra_descriptor(&interface->endpoint[0],
				HID_DEVICET_REPORT, &hid_desc)) {
			printk("wacom: can not retrieve extra class descriptor\n");
			error = 1;
			goto out;
		}
	}
	error = wacom_parse_hid(intf, hid_desc, features);
	if (error)
		goto out;

 out:
	return error;
}

static int wacom_led_control(struct wacom *wacom)
{
	struct wacom_features *features = &wacom->wacom_wac->features;
	unsigned char *buf;
	int retval;

	buf = kzalloc(9, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	if (features->type >= INTUOS5S &&
	    features->type <= INTUOSPL) {
		/*
		 * Touch Ring and crop mark LED luminance may take on
		 * one of four values:
		 *    0 = Low; 1 = Medium; 2 = High; 3 = Off
		 */
		int ring_led = wacom->led.select[0] & 0x03;
		int ring_lum = (((wacom->led.llv & 0x60) >> 5) - 1) & 0x03;
		int crop_lum = 0;

		buf[0] = WAC_CMD_LED_CONTROL;
		buf[1] = (crop_lum << 4) | (ring_lum << 2) | (ring_led);
	}
	else {
		int led = wacom->led.select[0] | 0x4;

		if (features->type == WACOM_21UX2 ||
		    features->type == WACOM_24HD)
			led |= (wacom->led.select[1] << 4) | 0x40;

		buf[0] = WAC_CMD_LED_CONTROL;
		buf[1] = led;
		buf[2] = wacom->led.llv;
		buf[3] = wacom->led.hlv;
		buf[4] = wacom->led.img_lum;
	}

	retval = wacom_set_report(wacom->intf, 0x03, WAC_CMD_LED_CONTROL,
				  buf, 9, WAC_CMD_RETRIES);
	kfree(buf);

	return retval;
}

static int wacom_led_putimage(struct wacom *wacom, int button_id, const void *img)
{
	unsigned char *buf;
	int i, retval;

	buf = kzalloc(259, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	/* Send 'start' command */
	buf[0] = WAC_CMD_ICON_START;
	buf[1] = 1;
	retval = wacom_set_report(wacom->intf, 0x03, WAC_CMD_ICON_START,
				  buf, 2, WAC_CMD_RETRIES);
	if (retval < 0)
		goto out;

	buf[0] = WAC_CMD_ICON_XFER;
	buf[1] = button_id & 0x07;
	for (i = 0; i < 4; i++) {
		buf[2] = i;
		memcpy(buf + 3, img + i * 256, 256);

		retval = wacom_set_report(wacom->intf, 0x03, WAC_CMD_ICON_XFER,
					  buf, 259, WAC_CMD_RETRIES);
		if (retval < 0)
			break;
	}

	/* Send 'stop' */
	buf[0] = WAC_CMD_ICON_START;
	buf[1] = 0;
	wacom_set_report(wacom->intf, 0x03, WAC_CMD_ICON_START,
			 buf, 2, WAC_CMD_RETRIES);

out:
	kfree(buf);
	return retval;
}

static ssize_t wacom_led_select_store(struct device *dev, int set_id,
				      const char *buf, size_t count)
{
	struct wacom *wacom = dev_get_drvdata(dev);
	unsigned int id;
	int err;

	id = simple_strtoul(buf, NULL, 0);

	mutex_lock(&wacom->lock);

	wacom->led.select[set_id] = id & 0x3;
	err = wacom_led_control(wacom);

	mutex_unlock(&wacom->lock);

	return err < 0 ? err : count;
}

#define DEVICE_LED_SELECT_ATTR(SET_ID)					\
static ssize_t wacom_led##SET_ID##_select_store(struct device *dev,	\
	struct device_attribute *attr, const char *buf, size_t count)	\
{									\
	return wacom_led_select_store(dev, SET_ID, buf, count);		\
}									\
static ssize_t wacom_led##SET_ID##_select_show(struct device *dev,	\
	struct device_attribute *attr, char *buf)			\
{									\
	struct wacom *wacom = dev_get_drvdata(dev);			\
	return snprintf(buf, 2, "%d\n", wacom->led.select[SET_ID]);	\
}									\
static DEVICE_ATTR(status_led##SET_ID##_select, S_IWUSR | S_IRUSR,	\
		    wacom_led##SET_ID##_select_show,			\
		    wacom_led##SET_ID##_select_store)

DEVICE_LED_SELECT_ATTR(0);
DEVICE_LED_SELECT_ATTR(1);

static ssize_t wacom_luminance_store(struct wacom *wacom, u8 *dest,
				     const char *buf, size_t count)
{
	unsigned int value;
	int err;

	value = simple_strtoul(buf, NULL, 0);

	mutex_lock(&wacom->lock);

	*dest = value & 0x7f;
	err = wacom_led_control(wacom);

	mutex_unlock(&wacom->lock);

	return err < 0 ? err : count;
}

#define DEVICE_LUMINANCE_ATTR(name, field)				\
static ssize_t wacom_##name##_luminance_store(struct device *dev,	\
	struct device_attribute *attr, const char *buf, size_t count)	\
{									\
	struct wacom *wacom = dev_get_drvdata(dev);			\
									\
	return wacom_luminance_store(wacom, &wacom->led.field,		\
				     buf, count);			\
}									\
static DEVICE_ATTR(name##_luminance, S_IWUSR,				\
		   NULL, wacom_##name##_luminance_store)

DEVICE_LUMINANCE_ATTR(status0, llv);
DEVICE_LUMINANCE_ATTR(status1, hlv);
DEVICE_LUMINANCE_ATTR(buttons, img_lum);

static ssize_t wacom_button_image_store(struct device *dev, int button_id,
					const char *buf, size_t count)
{
	struct wacom *wacom = dev_get_drvdata(dev);
	int err;

	if (count != 1024)
		return -EINVAL;

	mutex_lock(&wacom->lock);

	err = wacom_led_putimage(wacom, button_id, buf);

	mutex_unlock(&wacom->lock);

	return err < 0 ? err : count;
}

#define DEVICE_BTNIMG_ATTR(BUTTON_ID)					\
static ssize_t wacom_btnimg##BUTTON_ID##_store(struct device *dev,	\
	struct device_attribute *attr, const char *buf, size_t count)	\
{									\
	return wacom_button_image_store(dev, BUTTON_ID, buf, count);	\
}									\
static DEVICE_ATTR(button##BUTTON_ID##_rawimg, S_IWUSR,			\
		   NULL, wacom_btnimg##BUTTON_ID##_store)

DEVICE_BTNIMG_ATTR(0);
DEVICE_BTNIMG_ATTR(1);
DEVICE_BTNIMG_ATTR(2);
DEVICE_BTNIMG_ATTR(3);
DEVICE_BTNIMG_ATTR(4);
DEVICE_BTNIMG_ATTR(5);
DEVICE_BTNIMG_ATTR(6);
DEVICE_BTNIMG_ATTR(7);

static struct attribute *cintiq_led_attrs[] = {
	&dev_attr_status_led0_select.attr,
	&dev_attr_status_led1_select.attr,
	NULL
};

static struct attribute_group cintiq_led_attr_group = {
	.name = "wacom_led",
	.attrs = cintiq_led_attrs,
};

static struct attribute *intuos4_led_attrs[] = {
	&dev_attr_status0_luminance.attr,
	&dev_attr_status1_luminance.attr,
	&dev_attr_status_led0_select.attr,
	&dev_attr_buttons_luminance.attr,
	&dev_attr_button0_rawimg.attr,
	&dev_attr_button1_rawimg.attr,
	&dev_attr_button2_rawimg.attr,
	&dev_attr_button3_rawimg.attr,
	&dev_attr_button4_rawimg.attr,
	&dev_attr_button5_rawimg.attr,
	&dev_attr_button6_rawimg.attr,
	&dev_attr_button7_rawimg.attr,
	NULL
};

static struct attribute_group intuos4_led_attr_group = {
	.name = "wacom_led",
	.attrs = intuos4_led_attrs,
};

static struct attribute *intuos5_led_attrs[] = {
	&dev_attr_status0_luminance.attr,
	&dev_attr_status_led0_select.attr,
	NULL
};

static struct attribute_group intuos5_led_attr_group = {
	.name = "wacom_led",
	.attrs = intuos5_led_attrs,
};

static int wacom_initialize_leds(struct wacom *wacom)
{
	int error;

	/* Initialize default values */
	switch (wacom->wacom_wac->features.type) {
	case INTUOS4S:
	case INTUOS4:
	case INTUOS4L:
		wacom->led.select[0] = 0;
		wacom->led.select[1] = 0;
		wacom->led.llv = 10;
		wacom->led.hlv = 20;
		wacom->led.img_lum = 10;
		error = sysfs_create_group(&wacom->intf->dev.kobj,
					   &intuos4_led_attr_group);
		break;

	case WACOM_24HD:
	case WACOM_21UX2:
		wacom->led.select[0] = 0;
		wacom->led.select[1] = 0;
		wacom->led.llv = 0;
		wacom->led.hlv = 0;
		wacom->led.img_lum = 0;

		error = sysfs_create_group(&wacom->intf->dev.kobj,
					   &cintiq_led_attr_group);
		break;

	case INTUOS5S:
	case INTUOS5:
	case INTUOS5L:
	case INTUOSPS:
	case INTUOSPM:
	case INTUOSPL:
		if (wacom->wacom_wac->features.device_type == BTN_TOOL_PEN) {
			wacom->led.select[0] = 0;
			wacom->led.select[1] = 0;
			wacom->led.llv = 32;
			wacom->led.hlv = 0;
			wacom->led.img_lum = 0;

			error = sysfs_create_group(&wacom->intf->dev.kobj,
						   &intuos5_led_attr_group);
		} else
			return 0;
		break;

	default:
		return 0;
	}

	if (error) {
		dev_err(&wacom->intf->dev,
			"cannot create sysfs group err: %d\n", error);
		return error;
	}
	wacom_led_control(wacom);

	return 0;
}

static void wacom_destroy_leds(struct wacom *wacom)
{
	switch (wacom->wacom_wac->features.type) {
	case INTUOS4S:
	case INTUOS4:
	case INTUOS4L:
		sysfs_remove_group(&wacom->intf->dev.kobj,
				   &intuos4_led_attr_group);
		break;

	case WACOM_24HD:
	case WACOM_21UX2:
		sysfs_remove_group(&wacom->intf->dev.kobj,
				   &cintiq_led_attr_group);
		break;

	case INTUOS5S:
	case INTUOS5:
	case INTUOS5L:
	case INTUOSPS:
	case INTUOSPM:
	case INTUOSPL:
		if (wacom->wacom_wac->features.device_type == BTN_TOOL_PEN)
			sysfs_remove_group(&wacom->intf->dev.kobj,
					   &intuos5_led_attr_group);
		break;
	}
}

void wacom_set_led_status(void *wcombo, int idx, int status)
{
	struct wacom_combo *wacom_combo = wcombo;
	struct wacom *wacom = wacom_combo->wacom;

	wacom->led.select[idx] = status;
}

struct wacom_usbdev_data {
	struct list_head list;
	struct kref kref;
	struct usb_device *dev;
	struct wacom_shared shared;
};

static LIST_HEAD(wacom_udev_list);
static DEFINE_MUTEX(wacom_udev_list_lock);

static struct usb_device *wacom_get_sibling(struct usb_device *dev, int vendor, int product)
{
	int port1;
	struct usb_device *sibling;

	if (vendor == 0 && product == 0)
		return dev;

	if (dev->parent == NULL)
		return NULL;

	usb_hub_for_each_child(dev->parent, port1, sibling) {
		struct usb_device_descriptor *d;
		if (sibling == NULL)
			continue;

		d = &sibling->descriptor;
		if (d->idVendor == vendor && d->idProduct == product)
			return sibling;
	}

	return NULL;
}

static struct wacom_usbdev_data *wacom_get_usbdev_data(struct usb_device *dev)
{
	struct wacom_usbdev_data *data;

	list_for_each_entry(data, &wacom_udev_list, list) {
		if (data->dev == dev) {
			kref_get(&data->kref);
			return data;
		}
	}

	return NULL;
}

static int wacom_add_shared_data(struct wacom_wac *wacom,
				 struct usb_device *dev)
{
	struct wacom_usbdev_data *data;
	int retval = 0;

	mutex_lock(&wacom_udev_list_lock);

	data = wacom_get_usbdev_data(dev);
	if (!data) {
		data = kzalloc(sizeof(struct wacom_usbdev_data), GFP_KERNEL);
		if (!data) {
			retval = -ENOMEM;
			goto out;
		}

		kref_init(&data->kref);
		data->dev = dev;
		list_add_tail(&data->list, &wacom_udev_list);
	}

	wacom->shared = &data->shared;

out:
	mutex_unlock(&wacom_udev_list_lock);
	return retval;
}

static void wacom_release_shared_data(struct kref *kref)
{
	struct wacom_usbdev_data *data =
		container_of(kref, struct wacom_usbdev_data, kref);

	mutex_lock(&wacom_udev_list_lock);
	list_del(&data->list);
	mutex_unlock(&wacom_udev_list_lock);

	kfree(data);
}

static void wacom_remove_shared_data(struct wacom_wac *wacom)
{
	struct wacom_usbdev_data *data;

	if (wacom->shared) {
		data = container_of(wacom->shared, struct wacom_usbdev_data, shared);
		kref_put(&data->kref, wacom_release_shared_data);
		wacom->shared = NULL;
	}
}

void wacom_setup_device_quirks(struct wacom_features *features)
{
	/* touch device found but size is not defined. use default */
	if (features->device_type == BTN_TOOL_FINGER && !features->x_max) {
		features->x_max = 1023;
		features->y_max = 1023;
	}

	/* these device have multiple inputs */
	if (features->type == TABLETPC || features->type == TABLETPC2FG ||
	    (features->type >= INTUOS5S && features->type <= INTUOSPL) ||
	    features->type == WIRELESS || (features->oVid && features->oPid) ||
	    features->type == MTSCREEN || features->type == INTUOSHT)
		features->quirks |= WACOM_QUIRK_MULTI_INPUT;

	if (features->type == WIRELESS) {

		/* monitor never has input and pen/touch have delayed create */
		features->quirks |= WACOM_QUIRK_NO_INPUT;

		/* must be monitor interface if no device_type set */
		if (!features->device_type)
			features->quirks |= WACOM_QUIRK_MONITOR;
	}
}

static int wacom_register_input(struct wacom *wacom)
{
	struct input_dev *input_dev;
	struct usb_interface *intf = wacom->intf;
	struct usb_device *dev = interface_to_usbdev(intf);
	struct wacom_wac *wacom_wac = wacom->wacom_wac;
	struct wacom_features *features = &(wacom_wac->features);
	int error;

	input_dev = input_allocate_device();
	if (!input_dev) {
		error = -ENOMEM;
		goto fail1;
	}

	input_dev->name = wacom_wac->name;
	input_dev->dev.parent = &intf->dev;
	input_dev->open = wacom_open;
	input_dev->close = wacom_close;
	usb_to_input_id(dev, &input_dev->id);
	input_set_drvdata(input_dev, wacom);

	wacom->dev = input_dev;
	input_dev->evbit[0] |= BIT_MASK(EV_KEY) | BIT_MASK(EV_ABS);
	input_dev->keybit[BIT_WORD(BTN_DIGI)] |= BIT_MASK(BTN_TOUCH);
	input_set_abs_params(input_dev, ABS_X, features->x_min, features->x_max, 4, 0);
	input_set_abs_params(input_dev, ABS_Y, features->y_min, features->y_max, 4, 0);
	input_dev->absbit[BIT_WORD(ABS_MISC)] |= BIT_MASK(ABS_MISC);

	if (features->device_type == BTN_TOOL_PEN)
		input_set_abs_params(input_dev, ABS_PRESSURE, 0, features->pressure_max, 0, 0);

	error = wacom_init_input_dev(input_dev, wacom_wac);
	if (error)
		goto fail1;

	error = input_register_device(input_dev);
	if (error)
		goto fail2;

	return 0;

fail2:
	input_free_device(input_dev);
	wacom->dev = NULL;
fail1:
	return error;
}

static void wacom_wireless_work(struct work_struct *work)
{
	struct wacom *wacom = container_of(work, struct wacom, work);
	struct usb_device *usbdev = wacom->usbdev;
	struct wacom_wac *wacom_wac = wacom->wacom_wac;

	/*
	 * Regardless if this is a disconnect or a new tablet,
	 * remove any existing input devices.
	 */

	/* Stylus interface */
	wacom = usb_get_intfdata(usbdev->config->interface[1]);
	if (wacom->dev)
		input_unregister_device(wacom->dev);
	wacom->dev = 0;

	/* Touch interface */
	wacom = usb_get_intfdata(usbdev->config->interface[2]);
	if (wacom->dev)
		input_unregister_device(wacom->dev);
	wacom->dev = 0;

	if (wacom_wac->pid == 0) {
		printk(KERN_INFO "wacom: wireless tablet disconnected\n");
	} else {
		const struct usb_device_id *id = wacom_ids;

		printk(KERN_INFO
		       "wacom: wireless tablet connected with PID %x\n",
		       wacom_wac->pid);

		while (id->match_flags) {
			if (id->idVendor == USB_VENDOR_ID_WACOM &&
			    id->idProduct == wacom_wac->pid)
				break;
			id++;
		}

		if (!id->match_flags) {
			printk(KERN_INFO
			       "wacom: ignorning unknown PID.\n");
			return;
		}

		/* Stylus interface */
		wacom = usb_get_intfdata(usbdev->config->interface[1]);
		wacom_wac = wacom->wacom_wac;
		wacom_wac->features = *get_wacom_feature(id);
		wacom_wac->features.device_type = BTN_TOOL_PEN;
		wacom_register_input(wacom);

		/* Touch interface */
		wacom = usb_get_intfdata(usbdev->config->interface[2]);
		wacom_wac = wacom->wacom_wac;
		wacom_wac->features = *get_wacom_feature(id);
		wacom_wac->features.pktlen = WACOM_PKGLEN_BBTOUCH3;
		wacom_wac->features.device_type = BTN_TOOL_FINGER;
		wacom_wac->features.x_max = wacom_wac->features.y_max = 4096;
		wacom_register_input(wacom);
	}
}

static int wacom_probe(struct usb_interface *intf, const struct usb_device_id *id)
{
	struct usb_device *dev = interface_to_usbdev(intf);
	struct usb_endpoint_descriptor *endpoint;
	struct wacom *wacom;
	struct wacom_wac *wacom_wac;
	struct wacom_features *features;
	int error;

	wacom = kzalloc(sizeof(struct wacom), GFP_KERNEL);
	wacom_wac = kzalloc(sizeof(struct wacom_wac), GFP_KERNEL);
	if (!wacom || !wacom_wac) {
		error = -ENOMEM;
		goto fail1;
	}

	wacom_wac->data = usb_buffer_alloc(dev, WACOM_PKGLEN_MAX, GFP_KERNEL, &wacom->data_dma);
	if (!wacom_wac->data) {
		error = -ENOMEM;
		goto fail1;
	}

	wacom->irq = usb_alloc_urb(0, GFP_KERNEL);
	if (!wacom->irq) {
		error = -ENOMEM;
		goto fail2;
	}

	wacom->usbdev = dev;
	wacom->intf = intf;
	mutex_init(&wacom->lock);
	INIT_WORK(&wacom->work, wacom_wireless_work);
	usb_make_path(dev, wacom->phys, sizeof(wacom->phys));
	strlcat(wacom->phys, "/input0", sizeof(wacom->phys));

	wacom_wac->features = *get_wacom_feature(id);
	features = &wacom_wac->features;
	if (features->pktlen > WACOM_PKGLEN_MAX) {
		error = -EINVAL;
		goto fail3;
	}

	wacom->wacom_wac = wacom_wac;

	endpoint = &intf->cur_altsetting->endpoint[0].desc;

	/* Retrieve the physical and logical size for touch devices */
	error = wacom_retrieve_hid_descriptor(intf, features);
	if (error)
		goto fail3;

	/*
	 * Intuos5 has no useful data about its touch interface in its
	 * HID descriptor. If this is the touch interface (wMaxPacketSize
	 * of WACOM_PKGLEN_BBTOUCH3), override the table values.
	 */
	if (features->type >= INTUOS5S && features->type <= INTUOSHT) {
		if (endpoint->wMaxPacketSize == WACOM_PKGLEN_BBTOUCH3) {
			features->device_type = BTN_TOOL_FINGER;
			features->pktlen = WACOM_PKGLEN_BBTOUCH3;

			features->x_max = 4096;
			features->y_max = 4096;
		} else {
			features->device_type = BTN_TOOL_PEN;
		}
	}

	wacom_setup_device_quirks(features);

	strlcpy(wacom_wac->name, features->name, sizeof(wacom_wac->name));

	if (features->quirks & WACOM_QUIRK_MULTI_INPUT) {
		struct usb_device *other_dev;

		/* Append the device type to the name */
		strlcat(wacom_wac->name,
			features->device_type == BTN_TOOL_PEN ?
				" Pen" : " Finger",
			sizeof(wacom_wac->name));

		other_dev = wacom_get_sibling(dev, features->oVid, features->oPid);
		if (other_dev == NULL || wacom_get_usbdev_data(other_dev) == NULL)
			other_dev = dev;
		error = wacom_add_shared_data(wacom_wac, other_dev);
		if (error)
			goto fail3;
	}

	usb_fill_int_urb(wacom->irq, dev,
			 usb_rcvintpipe(dev, endpoint->bEndpointAddress),
			 wacom_wac->data, features->pktlen,
			 wacom_sys_irq, wacom, endpoint->bInterval);
	wacom->irq->transfer_dma = wacom->data_dma;
	wacom->irq->transfer_flags |= URB_NO_TRANSFER_DMA_MAP;

	error = wacom_initialize_leds(wacom);
	if (error)
		goto fail4;

	error = wacom_initialize_remote(wacom);
	if (error)
		goto fail5;

	if (!(features->quirks & WACOM_QUIRK_NO_INPUT)) {
		error = wacom_register_input(wacom);
		if (error)
			goto fail6;
	}

	/* Note that if query fails it is not a hard failure */
	wacom_query_tablet_data(intf, features);

	usb_set_intfdata(intf, wacom);

	if (features->quirks & WACOM_QUIRK_MONITOR) {
		if (usb_submit_urb(wacom->irq, GFP_KERNEL))
			goto fail7;
	}

	return 0;

 fail7: input_unregister_device(wacom->dev);
 fail6:	wacom_destroy_remotes(wacom);
 fail5: wacom_destroy_leds(wacom);
 fail4:	wacom_remove_shared_data(wacom_wac);
 fail3:	usb_free_urb(wacom->irq);
 fail2:	usb_buffer_free(dev, WACOM_PKGLEN_MAX, wacom_wac->data, wacom->data_dma);
 fail1: kfree(wacom);
	kfree(wacom_wac);
	return error;
}

static void wacom_disconnect(struct usb_interface *intf)
{
	struct wacom *wacom = usb_get_intfdata(intf);

	usb_set_intfdata(intf, NULL);

	usb_kill_urb(wacom->irq);
	cancel_work_sync(&wacom->work);
	if (wacom->dev)
		input_unregister_device(wacom->dev);
	wacom_destroy_leds(wacom);
	usb_free_urb(wacom->irq);
	usb_buffer_free(interface_to_usbdev(intf), WACOM_PKGLEN_MAX,
			wacom->wacom_wac->data, wacom->data_dma);
	wacom_destroy_remotes(wacom);
	wacom_remove_shared_data(wacom->wacom_wac);
	kfree(wacom->wacom_wac);
	kfree(wacom);
}

static int wacom_suspend(struct usb_interface *intf, pm_message_t message)
{
	struct wacom *wacom = usb_get_intfdata(intf);

	mutex_lock(&wacom->lock);
	usb_kill_urb(wacom->irq);
	mutex_unlock(&wacom->lock);

	return 0;
}

static int wacom_resume(struct usb_interface *intf)
{
	struct wacom *wacom = usb_get_intfdata(intf);
	struct wacom_features *features = &wacom->wacom_wac->features;
	int rv = 0;

	mutex_lock(&wacom->lock);

	/* switch to wacom mode if needed */
	if (!wacom_retrieve_hid_descriptor(intf, features))
		wacom_query_tablet_data(intf, features);
	wacom_led_control(wacom);

	if ((wacom->open || features->quirks & WACOM_QUIRK_MONITOR)
	     && usb_submit_urb(wacom->irq, GFP_NOIO) < 0)
		rv = -EIO;

	mutex_unlock(&wacom->lock);

	return rv;
}

static int wacom_reset_resume(struct usb_interface *intf)
{
	return wacom_resume(intf);
}

static struct usb_driver wacom_driver = {
	.name =		"wacom",
	.probe =	wacom_probe,
	.disconnect =	wacom_disconnect,
	.suspend =	wacom_suspend,
	.resume =	wacom_resume,
	.reset_resume =	wacom_reset_resume,
	.supports_autosuspend = 1,
};

static int __init wacom_init(void)
{
	int result;
	wacom_driver.id_table = get_device_table();
	result = usb_register(&wacom_driver);
	if (result == 0)
		printk(KERN_INFO KBUILD_MODNAME ": " DRIVER_VERSION ":"
		       DRIVER_DESC "\n");
	return result;
}

static void __exit wacom_exit(void)
{
	usb_deregister(&wacom_driver);
}

module_init(wacom_init);
module_exit(wacom_exit);
