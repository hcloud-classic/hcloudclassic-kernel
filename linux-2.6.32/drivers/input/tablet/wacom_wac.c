/*
 * drivers/input/tablet/wacom_wac.c
 *
 *  USB Wacom tablet support - Wacom specific code
 *
 */

/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */
#include <linux/hid.h>
#include <linux/input/mt.h>
#include "wacom.h"
#include "wacom_wac.h"

/* Newer Cintiq and DTU have an offset between tablet and screen areas */
#define WACOM_DTU_OFFSET	200
#define WACOM_CINTIQ_OFFSET	400

static int wacom_penpartner_irq(struct wacom_wac *wacom, void *wcombo)
{
	unsigned char *data = wacom->data;

	switch (data[0]) {
		case 1:
			if (data[5] & 0x80) {
				wacom->tool[0] = (data[5] & 0x20) ? BTN_TOOL_RUBBER : BTN_TOOL_PEN;
				wacom->id[0] = (data[5] & 0x20) ? ERASER_DEVICE_ID : STYLUS_DEVICE_ID;
				wacom_report_key(wcombo, wacom->tool[0], 1);
				wacom_report_abs(wcombo, ABS_MISC, wacom->id[0]); /* report tool id */
				wacom_report_abs(wcombo, ABS_X, wacom_le16_to_cpu(&data[1]));
				wacom_report_abs(wcombo, ABS_Y, wacom_le16_to_cpu(&data[3]));
				wacom_report_abs(wcombo, ABS_PRESSURE, (signed char)data[6] + 127);
				wacom_report_key(wcombo, BTN_TOUCH, ((signed char)data[6] > -127));
				wacom_report_key(wcombo, BTN_STYLUS, (data[5] & 0x40));
			} else {
				wacom_report_key(wcombo, wacom->tool[0], 0);
				wacom_report_abs(wcombo, ABS_MISC, 0); /* report tool id */
				wacom_report_abs(wcombo, ABS_PRESSURE, -1);
				wacom_report_key(wcombo, BTN_TOUCH, 0);
			}
			break;
		case 2:
			wacom_report_key(wcombo, BTN_TOOL_PEN, 1);
			wacom_report_abs(wcombo, ABS_MISC, STYLUS_DEVICE_ID); /* report tool id */
			wacom_report_abs(wcombo, ABS_X, wacom_le16_to_cpu(&data[1]));
			wacom_report_abs(wcombo, ABS_Y, wacom_le16_to_cpu(&data[3]));
			wacom_report_abs(wcombo, ABS_PRESSURE, (signed char)data[6] + 127);
			wacom_report_key(wcombo, BTN_TOUCH, ((signed char)data[6] > -80) && !(data[5] & 0x20));
			wacom_report_key(wcombo, BTN_STYLUS, (data[5] & 0x40));
			break;
		default:
			printk(KERN_INFO "wacom_penpartner_irq: received unknown report #%d\n", data[0]);
			return 0;
        }
	return 1;
}

static int wacom_pl_irq(struct wacom_wac *wacom, void *wcombo)
{
	struct wacom_features *features = &wacom->features;
	unsigned char *data = wacom->data;
	int prox, pressure;

	if (data[0] != 2) {
		dbg("wacom_pl_irq: received unknown report #%d", data[0]);
		return 0;
	}

	prox = data[1] & 0x40;

	if (prox) {
		wacom->id[0] = ERASER_DEVICE_ID;
		pressure = (signed char)((data[7] << 1) | ((data[4] >> 2) & 1));
		if (features->pressure_max > 255)
			pressure = (pressure << 1) | ((data[4] >> 6) & 1);
		pressure += (features->pressure_max + 1) / 2;

		/*
		 * if going from out of proximity into proximity select between the eraser
		 * and the pen based on the state of the stylus2 button, choose eraser if
		 * pressed else choose pen. if not a proximity change from out to in, send
		 * an out of proximity for previous tool then a in for new tool.
		 */
		if (!wacom->tool[0]) {
			/* Eraser bit set for DTF */
			if (data[1] & 0x10)
				wacom->tool[1] = BTN_TOOL_RUBBER;
			else
				/* Going into proximity select tool */
				wacom->tool[1] = (data[4] & 0x20) ? BTN_TOOL_RUBBER : BTN_TOOL_PEN;
		} else {
			/* was entered with stylus2 pressed */
			if (wacom->tool[1] == BTN_TOOL_RUBBER && !(data[4] & 0x20)) {
				/* report out proximity for previous tool */
				wacom_report_key(wcombo, wacom->tool[1], 0);
				wacom_input_sync(wcombo);
				wacom->tool[1] = BTN_TOOL_PEN;
				return 0;
			}
		}
		if (wacom->tool[1] != BTN_TOOL_RUBBER) {
			/* Unknown tool selected default to pen tool */
			wacom->tool[1] = BTN_TOOL_PEN;
			wacom->id[0] = STYLUS_DEVICE_ID;
		}
		wacom_report_key(wcombo, wacom->tool[1], prox); /* report in proximity for tool */
		wacom_report_abs(wcombo, ABS_MISC, wacom->id[0]); /* report tool id */
		wacom_report_abs(wcombo, ABS_X, data[3] | (data[2] << 7) | ((data[1] & 0x03) << 14));
		wacom_report_abs(wcombo, ABS_Y, data[6] | (data[5] << 7) | ((data[4] & 0x03) << 14));
		wacom_report_abs(wcombo, ABS_PRESSURE, pressure);

		wacom_report_key(wcombo, BTN_TOUCH, data[4] & 0x08);
		wacom_report_key(wcombo, BTN_STYLUS, data[4] & 0x10);
		/* Only allow the stylus2 button to be reported for the pen tool. */
		wacom_report_key(wcombo, BTN_STYLUS2, (wacom->tool[1] == BTN_TOOL_PEN) && (data[4] & 0x20));
	} else {
		/* report proximity-out of a (valid) tool */
		if (wacom->tool[1] != BTN_TOOL_RUBBER) {
			/* Unknown tool selected default to pen tool */
			wacom->tool[1] = BTN_TOOL_PEN;
		}
		wacom_report_key(wcombo, wacom->tool[1], prox);
	}

	wacom->tool[0] = prox; /* Save proximity state */
	return 1;
}

static int wacom_ptu_irq(struct wacom_wac *wacom, void *wcombo)
{
	unsigned char *data = wacom->data;

	if (data[0] != 2) {
		printk(KERN_INFO "wacom_ptu_irq: received unknown report #%d\n", data[0]);
		return 0;
	}

	if (data[1] & 0x04) {
		wacom_report_key(wcombo, BTN_TOOL_RUBBER, data[1] & 0x20);
		wacom_report_key(wcombo, BTN_TOUCH, data[1] & 0x08);
		wacom->id[0] = ERASER_DEVICE_ID;
	} else {
		wacom_report_key(wcombo, BTN_TOOL_PEN, data[1] & 0x20);
		wacom_report_key(wcombo, BTN_TOUCH, data[1] & 0x01);
		wacom->id[0] = STYLUS_DEVICE_ID;
	}
	wacom_report_abs(wcombo, ABS_MISC, wacom->id[0]); /* report tool id */
	wacom_report_abs(wcombo, ABS_X, wacom_le16_to_cpu(&data[2]));
	wacom_report_abs(wcombo, ABS_Y, wacom_le16_to_cpu(&data[4]));
	wacom_report_abs(wcombo, ABS_PRESSURE, wacom_le16_to_cpu(&data[6]));
	wacom_report_key(wcombo, BTN_STYLUS, data[1] & 0x02);
	wacom_report_key(wcombo, BTN_STYLUS2, data[1] & 0x10);
	return 1;
}

static int wacom_dtu_irq(struct wacom_wac *wacom, void *wcombo)
{
	struct wacom_features *features = &wacom->features;
	char *data = wacom->data;
	int prox = data[1] & 0x20, pressure;

	dbg("wacom_dtu_irq: received report #%d", data[0]);

	if (prox) {
		/* Going into proximity select tool */
		wacom->tool[0] = (data[1] & 0x0c) ? BTN_TOOL_RUBBER : BTN_TOOL_PEN;
		if (wacom->tool[0] == BTN_TOOL_PEN)
			wacom->id[0] = STYLUS_DEVICE_ID;
		else
			wacom->id[0] = ERASER_DEVICE_ID;
	}
	wacom_report_key(wcombo, BTN_STYLUS, data[1] & 0x02);
	wacom_report_key(wcombo, BTN_STYLUS2, data[1] & 0x10);
	wacom_report_abs(wcombo, ABS_X, le16_to_cpup((__le16 *)&data[2]));
	wacom_report_abs(wcombo, ABS_Y, le16_to_cpup((__le16 *)&data[4]));
	pressure = ((data[7] & 0x01) << 8) | data[6];
	if (pressure < 0)
		pressure = features->pressure_max + pressure + 1;
	wacom_report_abs(wcombo, ABS_PRESSURE, pressure);
	wacom_report_key(wcombo, BTN_TOUCH, data[1] & 0x05);
	if (!prox) /* out-prox */
		wacom->id[0] = 0;
	wacom_report_key(wcombo, wacom->tool[0], prox);
	wacom_report_abs(wcombo, ABS_MISC, wacom->id[0]);
	wacom_input_sync(wcombo);
	return 1;
}

static int wacom_graphire_irq(struct wacom_wac *wacom, void *wcombo)
{
	struct wacom_features *features = &wacom->features;
	unsigned char *data = wacom->data;
	int x, y, rw;

	if (data[0] != 2) {
		dbg("wacom_graphire_irq: received unknown report #%d", data[0]);
		return 0;
	}

	if (data[1] & 0x80) {
		/* in prox and not a pad data */

		switch ((data[1] >> 5) & 3) {

			case 0:	/* Pen */
				wacom->tool[0] = BTN_TOOL_PEN;
				wacom->id[0] = STYLUS_DEVICE_ID;
				break;

			case 1: /* Rubber */
				wacom->tool[0] = BTN_TOOL_RUBBER;
				wacom->id[0] = ERASER_DEVICE_ID;
				break;

			case 2: /* Mouse with wheel */
				wacom_report_key(wcombo, BTN_MIDDLE, data[1] & 0x04);
				if (features->type == WACOM_G4 || features->type == WACOM_MO) {
					rw = data[7] & 0x04 ? (data[7] & 0x03)-4 : (data[7] & 0x03);
					wacom_report_rel(wcombo, REL_WHEEL, -rw);
				} else
					wacom_report_rel(wcombo, REL_WHEEL, -(signed char) data[6]);
				/* fall through */

			case 3: /* Mouse without wheel */
				wacom->tool[0] = BTN_TOOL_MOUSE;
				wacom->id[0] = CURSOR_DEVICE_ID;
				wacom_report_key(wcombo, BTN_LEFT, data[1] & 0x01);
				wacom_report_key(wcombo, BTN_RIGHT, data[1] & 0x02);
				if (features->type == WACOM_G4 || features->type == WACOM_MO)
					wacom_report_abs(wcombo, ABS_DISTANCE, data[6] & 0x3f);
				else
					wacom_report_abs(wcombo, ABS_DISTANCE, data[7] & 0x3f);
				break;
		}
		x = wacom_le16_to_cpu(&data[2]);
		y = wacom_le16_to_cpu(&data[4]);
		wacom_report_abs(wcombo, ABS_X, x);
		wacom_report_abs(wcombo, ABS_Y, y);
		if (wacom->tool[0] != BTN_TOOL_MOUSE) {
			wacom_report_abs(wcombo, ABS_PRESSURE, data[6] | ((data[7] & 0x01) << 8));
			wacom_report_key(wcombo, BTN_TOUCH, data[1] & 0x01);
			wacom_report_key(wcombo, BTN_STYLUS, data[1] & 0x02);
			wacom_report_key(wcombo, BTN_STYLUS2, data[1] & 0x04);
		}
		wacom_report_abs(wcombo, ABS_MISC, wacom->id[0]); /* report tool id */
		wacom_report_key(wcombo, wacom->tool[0], 1);
	} else if (wacom->id[0]) {
		wacom_report_abs(wcombo, ABS_X, 0);
		wacom_report_abs(wcombo, ABS_Y, 0);
		if (wacom->tool[0] == BTN_TOOL_MOUSE) {
			wacom_report_key(wcombo, BTN_LEFT, 0);
			wacom_report_key(wcombo, BTN_RIGHT, 0);
			wacom_report_abs(wcombo, ABS_DISTANCE, 0);
		} else {
			wacom_report_abs(wcombo, ABS_PRESSURE, 0);
			wacom_report_key(wcombo, BTN_TOUCH, 0);
			wacom_report_key(wcombo, BTN_STYLUS, 0);
			wacom_report_key(wcombo, BTN_STYLUS2, 0);
		}
		wacom->id[0] = 0;
		wacom_report_abs(wcombo, ABS_MISC, 0); /* reset tool id */
		wacom_report_key(wcombo, wacom->tool[0], 0);
	}

	/* send pad data */
	switch (features->type) {
	    case WACOM_G4:
		if (data[7] & 0xf8) {
			wacom_input_sync(wcombo); /* sync last event */
			wacom->id[1] = PAD_DEVICE_ID;
			wacom_report_key(wcombo, BTN_0, (data[7] & 0x40));
			wacom_report_key(wcombo, BTN_4, (data[7] & 0x80));
			rw = ((data[7] & 0x18) >> 3) - ((data[7] & 0x20) >> 3);
			wacom_report_rel(wcombo, REL_WHEEL, rw);
			wacom_report_key(wcombo, BTN_TOOL_FINGER, 0xf0);
			wacom_report_abs(wcombo, ABS_MISC, wacom->id[1]);
			wacom_input_event(wcombo, EV_MSC, MSC_SERIAL, 0xf0);
		} else if (wacom->id[1]) {
			wacom_input_sync(wcombo); /* sync last event */
			wacom->id[1] = 0;
			wacom_report_key(wcombo, BTN_0, (data[7] & 0x40));
			wacom_report_key(wcombo, BTN_4, (data[7] & 0x80));
			wacom_report_key(wcombo, BTN_TOOL_FINGER, 0);
			wacom_report_abs(wcombo, ABS_MISC, 0);
			wacom_input_event(wcombo, EV_MSC, MSC_SERIAL, 0xf0);
		}
		break;
	    case WACOM_MO:
		if ((data[7] & 0xf8) || (data[8] & 0xff)) {
			wacom_input_sync(wcombo); /* sync last event */
			wacom->id[1] = PAD_DEVICE_ID;
			wacom_report_key(wcombo, BTN_0, (data[7] & 0x08));
			wacom_report_key(wcombo, BTN_1, (data[7] & 0x20));
			wacom_report_key(wcombo, BTN_4, (data[7] & 0x10));
			wacom_report_key(wcombo, BTN_5, (data[7] & 0x40));
			wacom_report_abs(wcombo, ABS_WHEEL, (data[8] & 0x7f));
			wacom_report_key(wcombo, BTN_TOOL_FINGER, 0xf0);
			wacom_report_abs(wcombo, ABS_MISC, wacom->id[1]);
			wacom_input_event(wcombo, EV_MSC, MSC_SERIAL, 0xf0);
		} else if (wacom->id[1]) {
			wacom_input_sync(wcombo); /* sync last event */
			wacom->id[1] = 0;
			wacom_report_key(wcombo, BTN_0, (data[7] & 0x08));
			wacom_report_key(wcombo, BTN_1, (data[7] & 0x20));
			wacom_report_key(wcombo, BTN_4, (data[7] & 0x10));
			wacom_report_key(wcombo, BTN_5, (data[7] & 0x40));
			wacom_report_abs(wcombo, ABS_WHEEL, (data[8] & 0x7f));
			wacom_report_key(wcombo, BTN_TOOL_FINGER, 0);
			wacom_report_abs(wcombo, ABS_MISC, 0);
			wacom_input_event(wcombo, EV_MSC, MSC_SERIAL, 0xf0);
		}
		break;
	}
	return 1;
}

static int wacom_intuos_inout(struct wacom_wac *wacom, void *wcombo)
{
	struct wacom_features *features = &wacom->features;
	unsigned char *data = wacom->data;
	int idx = 0;

	/* tool number */
	if (features->type == INTUOS)
		idx = data[1] & 0x01;

	/* Enter report */
	if ((data[1] & 0xfc) == 0xc0) {
		if (features->quirks & WACOM_QUIRK_MULTI_INPUT)
			wacom->shared->stylus_in_proximity = true;

		/* serial number of the tool */
		wacom->serial[idx] = ((data[3] & 0x0f) << 28) +
			(data[4] << 20) + (data[5] << 12) +
			(data[6] << 4) + (data[7] >> 4);

		wacom->id[idx] = (data[2] << 4) | (data[3] >> 4) |
			((data[7] & 0x0f) << 20) | ((data[8] & 0xf0) << 12);

		switch (wacom->id[idx] & 0xfffff) {
			case 0x812: /* Inking pen */
			case 0x801: /* Intuos3 Inking pen */
			case 0x20802: /* Intuos4 Classic Pen */
			case 0x012:
				wacom->tool[idx] = BTN_TOOL_PENCIL;
				break;
			case 0x822: /* Pen */
			case 0x842:
			case 0x852:
			case 0x823: /* Intuos3 Grip Pen */
			case 0x813: /* Intuos3 Classic Pen */
			case 0x885: /* Intuos3 Marker Pen */
			case 0x802: /* Intuos4 General Pen Eraser */
			case 0x804: /* Intuos4 Marker Pen */
			case 0x40802: /* Intuos4 Inking Pen */
			case 0x022:
				wacom->tool[idx] = BTN_TOOL_PEN;
				break;
			case 0x832: /* Stroke pen */
			case 0x032:
				wacom->tool[idx] = BTN_TOOL_BRUSH;
				break;
			case 0x007: /* Mouse 4D and 2D */
		        case 0x09c:
			case 0x094:
			case 0x017: /* Intuos3 2D Mouse */
			case 0x806: /* Intuos4 Mouse */
				wacom->tool[idx] = BTN_TOOL_MOUSE;
				break;
			case 0x096: /* Lens cursor */
			case 0x097: /* Intuos3 Lens cursor */
			case 0x006: /* Intuos4 Lens cursor */
				wacom->tool[idx] = BTN_TOOL_LENS;
				break;
			case 0x82a: /* Eraser */
			case 0x85a:
		        case 0x91a:
			case 0xd1a:
			case 0x0fa:
			case 0x82b: /* Intuos3 Grip Pen Eraser */
			case 0x81b: /* Intuos3 Classic Pen Eraser */
			case 0x91b: /* Intuos3 Airbrush Eraser */
			case 0x80c: /* Intuos4 Marker Pen Eraser */
			case 0x80a: /* Intuos4 General Pen Eraser */
			case 0x4080a: /* Intuos4 Classic Pen Eraser */
			case 0x90a: /* Intuos4 Airbrush Eraser */
				wacom->tool[idx] = BTN_TOOL_RUBBER;
				break;
			case 0xd12:
			case 0x912:
			case 0x112:
			case 0x913: /* Intuos3 Airbrush */
			case 0x902: /* Intuos4 Airbrush */
				wacom->tool[idx] = BTN_TOOL_AIRBRUSH;
				break;
			default: /* Unknown tool */
				wacom->tool[idx] = BTN_TOOL_PEN;
		}
		return 1;
	}

	/* older I4 styli don't work with new Cintiqs */
	if (!((wacom->id[idx] >> 20) & 0x01) &&
			(features->type >= WACOM_21UX2 &&
			 features->type <= WACOM_24HD))
		return 1;

	/* Exit report */
	if ((data[1] & 0xfe) == 0x80) {
		/*
		 * Reset all states otherwise we lose the initial states
		 * when in-prox next time
		 */
		if (features->quirks & WACOM_QUIRK_MULTI_INPUT)
			wacom->shared->stylus_in_proximity = false;

		wacom_report_abs(wcombo, ABS_X, 0);
		wacom_report_abs(wcombo, ABS_Y, 0);
		wacom_report_abs(wcombo, ABS_DISTANCE, 0);
		wacom_report_abs(wcombo, ABS_TILT_X, 0);
		wacom_report_abs(wcombo, ABS_TILT_Y, 0);
		if (wacom->tool[idx] >= BTN_TOOL_MOUSE) {
			wacom_report_key(wcombo, BTN_LEFT, 0);
			wacom_report_key(wcombo, BTN_MIDDLE, 0);
			wacom_report_key(wcombo, BTN_RIGHT, 0);
			wacom_report_key(wcombo, BTN_SIDE, 0);
			wacom_report_key(wcombo, BTN_EXTRA, 0);
			wacom_report_abs(wcombo, ABS_THROTTLE, 0);
			wacom_report_abs(wcombo, ABS_RZ, 0);
		} else {
			wacom_report_abs(wcombo, ABS_PRESSURE, 0);
			wacom_report_key(wcombo, BTN_STYLUS, 0);
			wacom_report_key(wcombo, BTN_STYLUS2, 0);
			wacom_report_key(wcombo, BTN_TOUCH, 0);
			wacom_report_abs(wcombo, ABS_WHEEL, 0);
			if (features->type >= INTUOS3S)
				wacom_report_abs(wcombo, ABS_Z, 0);
		}
		wacom_report_key(wcombo, wacom->tool[idx], 0);
		wacom_report_abs(wcombo, ABS_MISC, 0); /* reset tool id */
		wacom_input_event(wcombo, EV_MSC, MSC_SERIAL, wacom->serial[idx]);
		wacom->id[idx] = 0;
		return 2;
	}
	return 0;
}

static int wacom_remote_irq(struct wacom_wac *wacom_wac, size_t len,
			    void *wcombo)
{
	unsigned char *data = wacom_wac->data;
	__u32 serial;
	int i, touch_ring_mode;

	if (data[0] != WACOM_REPORT_REMOTE) {
		printk(KERN_DEBUG
			"%s: received unknown report #%d", __func__, data[0]);
		return 0;
	}

	serial = data[3] + (data[4] << 8) + (data[5] << 16);
	wacom_wac->id[0] = PAD_DEVICE_ID;

	wacom_report_key(wcombo, BTN_0, (data[9] & 0x01));
	wacom_report_key(wcombo, BTN_1, (data[9] & 0x02));
	wacom_report_key(wcombo, BTN_2, (data[9] & 0x04));
	wacom_report_key(wcombo, BTN_3, (data[9] & 0x08));
	wacom_report_key(wcombo, BTN_4, (data[9] & 0x10));
	wacom_report_key(wcombo, BTN_5, (data[9] & 0x20));
	wacom_report_key(wcombo, BTN_6, (data[9] & 0x40));
	wacom_report_key(wcombo, BTN_7, (data[9] & 0x80));

	wacom_report_key(wcombo, BTN_8, (data[10] & 0x01));
	wacom_report_key(wcombo, BTN_9, (data[10] & 0x02));
	wacom_report_key(wcombo, BTN_A, (data[10] & 0x04));
	wacom_report_key(wcombo, BTN_B, (data[10] & 0x08));
	wacom_report_key(wcombo, BTN_C, (data[10] & 0x10));
	wacom_report_key(wcombo, BTN_X, (data[10] & 0x20));
	wacom_report_key(wcombo, BTN_Y, (data[10] & 0x40));
	wacom_report_key(wcombo, BTN_Z, (data[10] & 0x80));

	wacom_report_key(wcombo, BTN_BASE, (data[11] & 0x01));
	wacom_report_key(wcombo, BTN_BASE2, (data[11] & 0x02));

	if (data[12] & 0x80)
		wacom_report_abs(wcombo, ABS_WHEEL, (data[12] & 0x7f));
	else
		wacom_report_abs(wcombo, ABS_WHEEL, 0);

	if (data[9] | data[10] | (data[11] & 0x03) | data[12])
		wacom_report_abs(wcombo, ABS_MISC, PAD_DEVICE_ID);
	else
		wacom_report_abs(wcombo, ABS_MISC, 0);

	wacom_input_event(wcombo, EV_MSC, MSC_SERIAL, serial);

	/*Which mode select (LED light) is currently on?*/
	touch_ring_mode = (data[11] & 0xC0) >> 6;

	for (i = 0; i < WACOM_MAX_REMOTES; i++) {
		if (wacom_wac->serial[i] == serial)
			wacom_set_led_status(wcombo, i, touch_ring_mode);
	}

	return 1;
}

static int wacom_remote_status_irq(struct wacom_wac *wacom_wac, size_t len, void *wcombo)
{
	unsigned char *data = wacom_wac->data;
	int i;

	if (data[0] != WACOM_REPORT_DEVICE_LIST)
		return 0;

	for (i = 0; i < WACOM_MAX_REMOTES; i++) {
		int j = i * 6;
		int serial = (data[j+6] << 16) + (data[j+5] << 8) + data[j+4];
		bool connected = data[j+2];

		if (connected) {
			int k;

			if (wacom_wac->serial[i] == serial)
				continue;

			if (wacom_wac->serial[i]) {
				wacom_remote_destroy_attr_group(wcombo,
							wacom_wac->serial[i]);
			}

			/* A remote can pair more than once with an EKR,
			 * check to make sure this serial isn't already paired.
			 */
			for (k = 0; k < WACOM_MAX_REMOTES; k++) {
				if (wacom_wac->serial[k] == serial)
					break;
			}

			if (k < WACOM_MAX_REMOTES) {
				wacom_wac->serial[i] = serial;
				continue;
			}
			wacom_remote_create_attr_group(wcombo, serial, i);
		} else if (wacom_wac->serial[i]) {
			wacom_remote_destroy_attr_group(wcombo,
							wacom_wac->serial[i]);
		}
	}

	return 0;
}

static void wacom_intuos_general(struct wacom_wac *wacom, void *wcombo)
{
	struct wacom_features *features = &wacom->features;
	unsigned char *data = wacom->data;
	unsigned int t;

	/* general pen packet */
	if ((data[1] & 0xb8) == 0xa0) {
		t = (data[6] << 2) | ((data[7] >> 6) & 3);
		if ((features->type >= INTUOS4S && features->type <= INTUOS4L) ||
                    (features->type >= INTUOS5S && features->type <= INTUOSPL) ||
			(features->type >= WACOM_21UX2 &&
			 features->type <= WACOM_24HD)) {
			t = (t << 1) | (data[1] & 1);
		}
		wacom_report_abs(wcombo, ABS_PRESSURE, t);
		wacom_report_abs(wcombo, ABS_TILT_X,
				((data[7] << 1) & 0x7e) | (data[8] >> 7));
		wacom_report_abs(wcombo, ABS_TILT_Y, data[8] & 0x7f);
		wacom_report_key(wcombo, BTN_STYLUS, data[1] & 2);
		wacom_report_key(wcombo, BTN_STYLUS2, data[1] & 4);
		wacom_report_key(wcombo, BTN_TOUCH, t > 10);
	}

	/* airbrush second packet */
	if ((data[1] & 0xbc) == 0xb4) {
		wacom_report_abs(wcombo, ABS_WHEEL,
				(data[6] << 2) | ((data[7] >> 6) & 3));
		wacom_report_abs(wcombo, ABS_TILT_X,
				((data[7] << 1) & 0x7e) | (data[8] >> 7));
		wacom_report_abs(wcombo, ABS_TILT_Y, data[8] & 0x7f);
	}
	return;
}

static int wacom_intuos_irq(struct wacom_wac *wacom, void *wcombo)
{
	struct wacom_features *features = &wacom->features;
	unsigned char *data = wacom->data;
	unsigned int t;
	int idx = 0, result;

	if (data[0] != 2 && data[0] != 3 && data[0] != 5 && data[0] != 6 &&
	    data[0] != 12 &&
	    data[0] != 16 &&	/* WACOM_REPORT_CINTIQ */
	    data[0] != 17) {	/* WACOM_REPORT_CINTIQPAD */
		dbg("wacom_intuos_irq: received unknown report #%d", data[0]);
                return 0;
	}

	/* tool number */
	if (features->type == INTUOS)
		idx = data[1] & 0x01;

	/* pad packets. Works as a second tool and is always in prox */
	if (data[0] == 12 || data[0] == 3 ||
	    data[0] == WACOM_REPORT_CINTIQPAD) {
		/* initiate the pad as a device */
		if (wacom->tool[1] != BTN_TOOL_FINGER)
			wacom->tool[1] = BTN_TOOL_FINGER;

		if (features->type >= INTUOS4S && features->type <= INTUOS4L) {
			wacom_report_key(wcombo, BTN_0, (data[2] & 0x01));
			wacom_report_key(wcombo, BTN_1, (data[3] & 0x01));
			wacom_report_key(wcombo, BTN_2, (data[3] & 0x02));
			wacom_report_key(wcombo, BTN_3, (data[3] & 0x04));
			wacom_report_key(wcombo, BTN_4, (data[3] & 0x08));
			wacom_report_key(wcombo, BTN_5, (data[3] & 0x10));
			wacom_report_key(wcombo, BTN_6, (data[3] & 0x20));
			if (data[1] & 0x80) {
				wacom_report_abs(wcombo, ABS_WHEEL, (data[1] & 0x7f));
			} else {
				/* Out of proximity, clear wheel value. */
				wacom_report_abs(wcombo, ABS_WHEEL, 0);
			}
			if (features->type != INTUOS4S) {
				wacom_report_key(wcombo, BTN_7, (data[3] & 0x40));
				wacom_report_key(wcombo, BTN_8, (data[3] & 0x80));
			}
			if (data[1] | (data[2] & 0x01) | data[3]) {
				wacom_report_key(wcombo, wacom->tool[1], 1);
				wacom_report_abs(wcombo, ABS_MISC, PAD_DEVICE_ID);
			} else {
				wacom_report_key(wcombo, wacom->tool[1], 0);
				wacom_report_abs(wcombo, ABS_MISC, 0);
			}
		} else if (features->type == WACOM_24HD) {
			wacom_report_key(wcombo, BTN_0, (data[6] & 0x01));
			wacom_report_key(wcombo, BTN_1, (data[6] & 0x02));
			wacom_report_key(wcombo, BTN_2, (data[6] & 0x04));
			wacom_report_key(wcombo, BTN_3, (data[6] & 0x08));
			wacom_report_key(wcombo, BTN_4, (data[6] & 0x10));
			wacom_report_key(wcombo, BTN_5, (data[6] & 0x20));
			wacom_report_key(wcombo, BTN_6, (data[6] & 0x40));
			wacom_report_key(wcombo, BTN_7, (data[6] & 0x80));
			wacom_report_key(wcombo, BTN_8, (data[8] & 0x01));
			wacom_report_key(wcombo, BTN_9, (data[8] & 0x02));
			wacom_report_key(wcombo, BTN_A, (data[8] & 0x04));
			wacom_report_key(wcombo, BTN_B, (data[8] & 0x08));
			wacom_report_key(wcombo, BTN_C, (data[8] & 0x10));
			wacom_report_key(wcombo, BTN_X, (data[8] & 0x20));
			wacom_report_key(wcombo, BTN_Y, (data[8] & 0x40));
			wacom_report_key(wcombo, BTN_Z, (data[8] & 0x80));

			/*
			 * Three "buttons" are available on the 24HD which are
			 * physically implemented as a touchstrip. Each button
			 * is approximately 3 bits wide with a 2 bit spacing.
			 * The raw touchstrip bits are stored at:
			 *    ((data[3] & 0x1f) << 8) | data[4])
			 */
			wacom_report_key(wcombo, KEY_PROG1, data[4] & 0x07);
			wacom_report_key(wcombo, KEY_PROG2, data[4] & 0xE0);
			wacom_report_key(wcombo, KEY_PROG3, data[3] & 0x1C);

			if (data[1] & 0x80) {
				wacom_report_abs(wcombo, ABS_WHEEL, (data[1] & 0x7f));
			} else {
				/* Out of proximity, clear wheel value. */
				wacom_report_abs(wcombo, ABS_WHEEL, 0);
			}

			if (data[2] & 0x80) {
				wacom_report_abs(wcombo, ABS_THROTTLE, (data[2] & 0x7f));
			} else {
				/* Out of proximity, clear second wheel value. */
				wacom_report_abs(wcombo, ABS_THROTTLE, 0);
			}

			if (data[1] | data[2] | (data[3] & 0x1f) | data[4] | data[6] | data[8]) {
				wacom_report_key(wcombo, wacom->tool[1], 1);
				wacom_report_abs(wcombo, ABS_MISC, PAD_DEVICE_ID);
			} else {
				wacom_report_key(wcombo, wacom->tool[1], 0);
				wacom_report_abs(wcombo, ABS_MISC, 0);
			}
		} else if (features->type >= INTUOS5S && features->type <= INTUOSPL) {
			int i;

			/* Touch ring mode switch has no capacitive sensor */
			wacom_report_key(wcombo, BTN_0, (data[3] & 0x01));

			/*
			 * ExpressKeys on Intuos5/Intuos Pro have a capacitive sensor in
			 * addition to the mechanical switch. Switch data is
			 * stored in data[4], capacitive data in data[5].
			 */
			for (i = 0; i < 8; i++)
				wacom_report_key(wcombo, BTN_1 + i, data[4] & (1 << i));

			if (data[2] & 0x80) {
				wacom_report_abs(wcombo, ABS_WHEEL, (data[2] & 0x7f));
			} else {
				/* Out of proximity, clear wheel value. */
				wacom_report_abs(wcombo, ABS_WHEEL, 0);
			}

			if (data[2] | (data[3] & 0x01) | data[4]) {
				wacom_report_key(wcombo, wacom->tool[1], 1);
				wacom_report_abs(wcombo, ABS_MISC, PAD_DEVICE_ID);
			} else {
				wacom_report_key(wcombo, wacom->tool[1], 0);
				wacom_report_abs(wcombo, ABS_MISC, 0);
			}
		} else if (features->type == WACOM_27QHD) {
			wacom_report_key(wcombo, KEY_PROG1, data[2] & 0x01);
			wacom_report_key(wcombo, KEY_PROG2, data[2] & 0x02);
			wacom_report_key(wcombo, KEY_PROG3, data[2] & 0x04);
			wacom_report_abs(wcombo, ABS_X, be16_to_cpup((__be16 *)&data[4]));
			wacom_report_abs(wcombo, ABS_Y, be16_to_cpup((__be16 *)&data[6]));
			wacom_report_abs(wcombo, ABS_Z, be16_to_cpup((__be16 *)&data[8]));
			if ((data[2] & 0x07) | data[4] | data[5] | data[6] | data[7] | data[8] | data[9]) {
				wacom_report_abs(wcombo, ABS_MISC, PAD_DEVICE_ID);
			} else {
				wacom_report_abs(wcombo, ABS_MISC, 0);
			}
		} else {
			if (features->type == WACOM_21UX2 ||
			    features->type == WACOM_22HD) {
				wacom_report_key(wcombo, BTN_0, (data[5] & 0x01));
				wacom_report_key(wcombo, BTN_1, (data[6] & 0x01));
				wacom_report_key(wcombo, BTN_2, (data[6] & 0x02));
				wacom_report_key(wcombo, BTN_3, (data[6] & 0x04));
				wacom_report_key(wcombo, BTN_4, (data[6] & 0x08));
				wacom_report_key(wcombo, BTN_5, (data[6] & 0x10));
				wacom_report_key(wcombo, BTN_6, (data[6] & 0x20));
				wacom_report_key(wcombo, BTN_7, (data[6] & 0x40));
				wacom_report_key(wcombo, BTN_8, (data[6] & 0x80));
				wacom_report_key(wcombo, BTN_9, (data[7] & 0x01));
				wacom_report_key(wcombo, BTN_A, (data[8] & 0x01));
				wacom_report_key(wcombo, BTN_B, (data[8] & 0x02));
				wacom_report_key(wcombo, BTN_C, (data[8] & 0x04));
				wacom_report_key(wcombo, BTN_X, (data[8] & 0x08));
				wacom_report_key(wcombo, BTN_Y, (data[8] & 0x10));
				wacom_report_key(wcombo, BTN_Z, (data[8] & 0x20));
				wacom_report_key(wcombo, BTN_BASE, (data[8] & 0x40));
				wacom_report_key(wcombo, BTN_BASE2, (data[8] & 0x80));
				if (features->type == WACOM_22HD) {
					wacom_report_key(wcombo, KEY_PROG1, data[9] & 0x01);
					wacom_report_key(wcombo, KEY_PROG2, data[9] & 0x02);
					wacom_report_key(wcombo, KEY_PROG3, data[9] & 0x04);
				}
			} else {
				wacom_report_key(wcombo, BTN_0, (data[5] & 0x01));
				wacom_report_key(wcombo, BTN_1, (data[5] & 0x02));
				wacom_report_key(wcombo, BTN_2, (data[5] & 0x04));
				wacom_report_key(wcombo, BTN_3, (data[5] & 0x08));
				wacom_report_key(wcombo, BTN_4, (data[6] & 0x01));
				wacom_report_key(wcombo, BTN_5, (data[6] & 0x02));
				wacom_report_key(wcombo, BTN_6, (data[6] & 0x04));
				wacom_report_key(wcombo, BTN_7, (data[6] & 0x08));
				wacom_report_key(wcombo, BTN_8, (data[5] & 0x10));
				wacom_report_key(wcombo, BTN_9, (data[6] & 0x10));
			}
			wacom_report_abs(wcombo, ABS_RX, ((data[1] & 0x1f) << 8) | data[2]);
			wacom_report_abs(wcombo, ABS_RY, ((data[3] & 0x1f) << 8) | data[4]);

			if ((data[5] & 0x1f) | data[6] | (data[1] & 0x1f) |
				data[2] | (data[3] & 0x1f) | data[4] | data[8] |
				(data[7] & 0x01)) {
				wacom_report_key(wcombo, wacom->tool[1], 1);
				wacom_report_abs(wcombo, ABS_MISC, PAD_DEVICE_ID);
			} else {
				wacom_report_key(wcombo, wacom->tool[1], 0);
				wacom_report_abs(wcombo, ABS_MISC, 0);
			}
		}
		wacom_input_event(wcombo, EV_MSC, MSC_SERIAL, 0xffffffff);
                return 1;
	}

	/* process in/out prox events */
	result = wacom_intuos_inout(wacom, wcombo);
	if (result)
                return result-1;

	/* don't proceed if we don't know the ID */
	if (!wacom->id[idx])
		return 0;

	/* Only large Intuos support Lense Cursor */
	if ((wacom->tool[idx] == BTN_TOOL_LENS)
			&& ((features->type == INTUOS3)
			|| (features->type == INTUOS3S)
			|| (features->type == INTUOS4)
			|| (features->type == INTUOS4S)
			|| (features->type == INTUOS5)
			|| (features->type == INTUOS5S)
			|| (features->type == INTUOSPM)
			|| (features->type == INTUOSPL)))
		return 0;

	/* Cintiq doesn't send data when RDY bit isn't set */
	if ((features->type == CINTIQ) && !(data[1] & 0x40))
                 return 0;

	if (features->type >= INTUOS3S) {
		wacom_report_abs(wcombo, ABS_X, (data[2] << 9) | (data[3] << 1) | ((data[9] >> 1) & 1));
		wacom_report_abs(wcombo, ABS_Y, (data[4] << 9) | (data[5] << 1) | (data[9] & 1));
		wacom_report_abs(wcombo, ABS_DISTANCE, ((data[9] >> 2) & 0x3f));
	} else {
		wacom_report_abs(wcombo, ABS_X, wacom_be16_to_cpu(&data[2]));
		wacom_report_abs(wcombo, ABS_Y, wacom_be16_to_cpu(&data[4]));
		wacom_report_abs(wcombo, ABS_DISTANCE, ((data[9] >> 3) & 0x1f));
	}

	/* process general packets */
	wacom_intuos_general(wacom, wcombo);

	/* 4D mouse, 2D mouse, marker pen rotation, tilt mouse, or Lens cursor packets */
	if ((data[1] & 0xbc) == 0xa8 || (data[1] & 0xbe) == 0xb0 || (data[1] & 0xbc) == 0xac) {

		if (data[1] & 0x02) {
			/* Rotation packet */
			if (features->type >= INTUOS3S) {
				/* I3 marker pen rotation */
				t = (data[6] << 3) | ((data[7] >> 5) & 7);
				t = (data[7] & 0x20) ? ((t > 900) ? ((t-1) / 2 - 1350) :
					((t-1) / 2 + 450)) : (450 - t / 2) ;
				wacom_report_abs(wcombo, ABS_Z, t);
			} else {
				/* 4D mouse rotation packet */
				t = (data[6] << 3) | ((data[7] >> 5) & 7);
				wacom_report_abs(wcombo, ABS_RZ, (data[7] & 0x20) ?
					((t - 1) / 2) : -t / 2);
			}

		} else if (!(data[1] & 0x10) && features->type < INTUOS3S) {
			/* 4D mouse packet */
			wacom_report_key(wcombo, BTN_LEFT,   data[8] & 0x01);
			wacom_report_key(wcombo, BTN_MIDDLE, data[8] & 0x02);
			wacom_report_key(wcombo, BTN_RIGHT,  data[8] & 0x04);

			wacom_report_key(wcombo, BTN_SIDE,   data[8] & 0x20);
			wacom_report_key(wcombo, BTN_EXTRA,  data[8] & 0x10);
			t = (data[6] << 2) | ((data[7] >> 6) & 3);
			wacom_report_abs(wcombo, ABS_THROTTLE, (data[8] & 0x08) ? -t : t);

		} else if (wacom->tool[idx] == BTN_TOOL_MOUSE) {
			/* I4 mouse */
			if ((features->type >= INTUOS4S && features->type <= INTUOS4L) ||
			    (features->type >= INTUOS5S && features->type <= INTUOSPL)) {
				wacom_report_key(wcombo, BTN_LEFT,   data[6] & 0x01);
				wacom_report_key(wcombo, BTN_MIDDLE, data[6] & 0x02);
				wacom_report_key(wcombo, BTN_RIGHT,  data[6] & 0x04);
				wacom_report_rel(wcombo, REL_WHEEL, ((data[7] & 0x80) >> 7)
						 - ((data[7] & 0x40) >> 6));
				wacom_report_key(wcombo, BTN_SIDE,   data[6] & 0x08);
				wacom_report_key(wcombo, BTN_EXTRA,  data[6] & 0x10);

				wacom_report_abs(wcombo, ABS_TILT_X,
					((data[7] << 1) & 0x7e) | (data[8] >> 7));
				wacom_report_abs(wcombo, ABS_TILT_Y, data[8] & 0x7f);
			} else {
				/* 2D mouse packet */
				wacom_report_key(wcombo, BTN_LEFT,   data[8] & 0x04);
				wacom_report_key(wcombo, BTN_MIDDLE, data[8] & 0x08);
				wacom_report_key(wcombo, BTN_RIGHT,  data[8] & 0x10);
				wacom_report_rel(wcombo, REL_WHEEL, (data[8] & 0x01)
						 - ((data[8] & 0x02) >> 1));

				/* I3 2D mouse side buttons */
				if (features->type >= INTUOS3S && features->type <= INTUOS3L) {
					wacom_report_key(wcombo, BTN_SIDE,   data[8] & 0x40);
					wacom_report_key(wcombo, BTN_EXTRA,  data[8] & 0x20);
				}
			}
		} else if ((features->type < INTUOS3S || features->type == INTUOS3L ||
			   features->type == INTUOS4L || features->type == INTUOS5L ||
			   features->type == INTUOSPL) && wacom->tool[idx] == BTN_TOOL_LENS) {
			/* Lens cursor packets */
			wacom_report_key(wcombo, BTN_LEFT,   data[8] & 0x01);
			wacom_report_key(wcombo, BTN_MIDDLE, data[8] & 0x02);
			wacom_report_key(wcombo, BTN_RIGHT,  data[8] & 0x04);
			wacom_report_key(wcombo, BTN_SIDE,   data[8] & 0x10);
			wacom_report_key(wcombo, BTN_EXTRA,  data[8] & 0x08);
		}
	}

	wacom_report_abs(wcombo, ABS_MISC, wacom->id[idx]); /* report tool id */
	wacom_report_key(wcombo, wacom->tool[idx], 1);
	wacom_input_event(wcombo, EV_MSC, MSC_SERIAL, wacom->serial[idx]);
	return 1;
}

static int wacom_mt_touch(struct wacom_wac *wacom, void *wcombo)
{
	char *data = wacom->data;
	int i;
	int current_num_contacts = data[2];
	int contacts_to_send = 0;

	/*
	 * First packet resets the counter since only the first
	 * packet in series will have non-zero current_num_contacts.
	 */
	if (current_num_contacts)
		wacom->num_contacts_left = current_num_contacts;

	/* There are at most 5 contacts per packet */
	contacts_to_send = min(5, wacom->num_contacts_left);

	for (i = 0; i < contacts_to_send; i++) {
		int offset = (WACOM_BYTES_PER_MT_PACKET * i) + 3;
		bool touch = data[offset] & 0x1;
		int slot = wacom_mt_get_slot_by_key(wcombo, data[offset + 1]);

		if (slot < 0)
			continue;

		wacom_mt_slot(wcombo, slot);
		wacom_mt_report_slot_state(wcombo, MT_TOOL_FINGER, touch);
		if (touch) {
			int x = le16_to_cpup((__le16 *)&data[offset + 7]);
			int y = le16_to_cpup((__le16 *)&data[offset + 9]);
			wacom_report_abs(wcombo, ABS_MT_POSITION_X, x);
			wacom_report_abs(wcombo, ABS_MT_POSITION_Y, y);
		}
	}

	wacom_mt_report_pointer_emulation(wcombo, true);

	wacom->num_contacts_left -= contacts_to_send;
	if (wacom->num_contacts_left < 0)
		wacom->num_contacts_left = 0;

	return 1;
}

static int int_dist(int x1, int y1, int x2, int y2)
{
	int x = x2 - x1;
	int y = y2 - y1;

	return int_sqrt(x*x + y*y);
}

static int wacom_24hdt_irq(struct wacom_wac *wacom, void *wcombo)
{
	char *data = wacom->data;
	int i;
	int current_num_contacts = 0;
	int contacts_to_send = 0;
	int num_contacts_left = 4; /* maximum contacts per packet */
	int byte_per_packet = WACOM_BYTES_PER_24HDT_PACKET;
	int y_offset = 2;

	if (wacom->features.type == WACOM_27QHDT) {
		current_num_contacts = data[63];
		num_contacts_left = 10;
		byte_per_packet = WACOM_BYTES_PER_QHDTHID_PACKET;
		y_offset = 0;
	} else {
		current_num_contacts = data[61];
	}

	/*
	 * First packet resets the counter since only the first
	 * packet in series will have non-zero current_num_contacts.
	 */
	if (current_num_contacts)
		wacom->num_contacts_left = current_num_contacts;

	contacts_to_send = min(num_contacts_left, wacom->num_contacts_left);

	for (i = 0; i < contacts_to_send; i++) {
		int offset = (byte_per_packet * i) + 1;
		bool touch = data[offset] & 0x1 && !wacom->shared->stylus_in_proximity;
		int id = data[offset + 1];
		int slot = wacom_mt_get_slot_by_key(wcombo, id);

		if (slot < 0)
			continue;
		wacom_mt_slot(wcombo, slot);
		wacom_mt_report_slot_state(wcombo, MT_TOOL_FINGER, touch);

		if (touch) {
			int t_x = get_unaligned_le16(&data[offset + 2]);
			int t_y = get_unaligned_le16(&data[offset + 4 + y_offset]);

			wacom_report_abs(wcombo, ABS_MT_POSITION_X, t_x);
			wacom_report_abs(wcombo, ABS_MT_POSITION_Y, t_y);

			if (wacom->features.type != WACOM_27QHDT) {
				int c_x = get_unaligned_le16(&data[offset + 4]);
				int c_y = get_unaligned_le16(&data[offset + 8]);
				int w = get_unaligned_le16(&data[offset + 10]);
				int h = get_unaligned_le16(&data[offset + 12]);

				wacom_report_abs(wcombo, ABS_MT_TOUCH_MAJOR, min(w,h));
				wacom_report_abs(wcombo, ABS_MT_WIDTH_MAJOR,
						 min(w, h) + int_dist(t_x, t_y, c_x, c_y));
				wacom_report_abs(wcombo, ABS_MT_WIDTH_MINOR, min(w, h));
				wacom_report_abs(wcombo, ABS_MT_ORIENTATION, w > h);
			}
		}
	}

	wacom_mt_report_pointer_emulation(wcombo, true);

	wacom->num_contacts_left -= contacts_to_send;
	if (wacom->num_contacts_left <= 0)
		wacom->num_contacts_left = 0;

	wacom_input_sync(wcombo);

	return 1;
}

static int wacom_tpc_mt_touch(struct wacom_wac *wacom, void *wcombo)
{
	unsigned char *data = wacom->data;
	int i;

	for (i = 0; i < 2; i++) {
		int p = data[1] & (1 << i);
		bool touch = p && !wacom->shared->stylus_in_proximity;

		wacom_mt_slot(wcombo, i);
		wacom_mt_report_slot_state(wcombo, MT_TOOL_FINGER, touch);
		if (touch) {
			int x = le16_to_cpup((__le16 *)&data[i * 2 + 2]) & 0x7fff;
			int y = le16_to_cpup((__le16 *)&data[i * 2 + 6]) & 0x7fff;

			wacom_report_abs(wcombo, ABS_MT_POSITION_X, x);
			wacom_report_abs(wcombo, ABS_MT_POSITION_Y, y);
		}
	}

	/* keep touch state for pen event */
	wacom->shared->touch_down = wacom_wac_finger_count_touches(wcombo);

	wacom_mt_report_pointer_emulation(wcombo, true);

	return 1;
}

static int wacom_tpc_single_touch(struct wacom_wac *wacom, void *wcombo, size_t len)
{
	char *data = wacom->data;
	bool prox;
	int x = 0, y = 0;

	if (wacom->features.touch_max > 1 || len > WACOM_PKGLEN_TPC2FG)
		return 0;

	if (!wacom->shared->stylus_in_proximity) {
		if (len == WACOM_PKGLEN_TPC1FG) {
			prox = data[0] & 0x01;
			x = get_unaligned_le16(&data[1]);
			y = get_unaligned_le16(&data[3]);
		} else { /* with capacity */
			prox = data[1] & 0x01;
			x = le16_to_cpup((__le16 *)&data[2]);
			y = le16_to_cpup((__le16 *)&data[4]);
		}
	} else
		/* force touch out when pen is in prox */
		prox = 0;

	if (prox) {
		wacom_report_abs(wcombo, ABS_X, x);
		wacom_report_abs(wcombo, ABS_Y, y);
	}
	wacom_report_key(wcombo, BTN_TOUCH, prox);

	/* keep touch state for pen events */
	wacom->shared->touch_down = prox;

	return 1;
}

static int wacom_tpc_pen(struct wacom_wac *wacom, void *wcombo)
{
	struct wacom_features *features = &wacom->features;
	char *data = wacom->data;
	int pressure;
	bool prox = data[1] & 0x20;

	if (!wacom->shared->stylus_in_proximity) /* first in prox */
		/* Going into proximity select tool */
		wacom->tool[0] = (data[1] & 0x0c) ? BTN_TOOL_RUBBER : BTN_TOOL_PEN;

	/* keep pen state for touch events */
	wacom->shared->stylus_in_proximity = prox;

	/* send pen events only when touch is up or forced out */
	if (!wacom->shared->touch_down) {
		wacom_report_key(wcombo, BTN_STYLUS, data[1] & 0x02);
		wacom_report_key(wcombo, BTN_STYLUS2, data[1] & 0x10);
		wacom_report_abs(wcombo, ABS_X, le16_to_cpup((__le16 *)&data[2]));
		wacom_report_abs(wcombo, ABS_Y, le16_to_cpup((__le16 *)&data[4]));
		pressure = ((data[7] & 0x01) << 8) | data[6];
		if (pressure < 0)
			pressure = features->pressure_max + pressure + 1;
		wacom_report_abs(wcombo, ABS_PRESSURE, pressure);
		wacom_report_key(wcombo, BTN_TOUCH, data[1] & 0x05);
		wacom_report_key(wcombo, wacom->tool[0], prox);
		wacom_report_abs(wcombo, ABS_MISC, wacom->id[0]);
		return 1;
	}

	return 0;
}

static int wacom_tpc_irq(struct wacom_wac *wacom, void *wcombo)
{
	char *data = wacom->data;
	struct urb *urb = ((struct wacom_combo *)wcombo)->urb;

	dbg("wacom_tpc_irq: received report #%d", data[0]);

	if (urb->actual_length == WACOM_PKGLEN_TPC1FG || data[0] == 6) /* Touch data */
		return wacom_tpc_single_touch(wacom, wcombo, urb->actual_length);
	else if (data[0] == 13)
		return wacom_tpc_mt_touch(wacom, wcombo);
	else if (data[0] == WACOM_REPORT_TPCMT)
		return wacom_mt_touch(wacom, wcombo);
	else if (data[0] == 2)
		return wacom_tpc_pen(wacom, wcombo);

	return 0;
}

static int wacom_bpt_pen(struct wacom_wac *wacom, struct wacom_combo *wcombo)
{
	struct wacom_features *features = &wacom->features;
	struct input_dev *input = wcombo->wacom->dev;
	unsigned char *data = wacom->data;
	int prox = 0, x = 0, y = 0, p = 0, d = 0, pen = 0, btn1 = 0, btn2 = 0;

	if (data[0] != WACOM_REPORT_PENABLED)
	    return 0;

	prox = (data[1] & 0x20) == 0x20;

	/*
	 * All reports shared between PEN and RUBBER tool must be
	 * forced to a known starting value (zero) when transitioning to
	 * out-of-prox.
	 *
	 * If not reset then, to userspace, it will look like lost events
	 * if new tool comes in-prox with same values as previous tool sent.
	 *
	 * Hardware does report zero in most out-of-prox cases but not all.
	 */
	if (!wacom->shared->stylus_in_proximity) {
		if (data[1] & 0x08) {
			wacom->tool[0] = BTN_TOOL_RUBBER;
			wacom->id[0] = ERASER_DEVICE_ID;
		} else {
			wacom->tool[0] = BTN_TOOL_PEN;
			wacom->id[0] = STYLUS_DEVICE_ID;
		}
	}

	wacom->shared->stylus_in_proximity = prox;
	if (wacom->shared->touch_down)
		return 0;

	if (prox) {
		x = le16_to_cpup((__le16 *)&data[2]);
		y = le16_to_cpup((__le16 *)&data[4]);
		p = le16_to_cpup((__le16 *)&data[6]);
		/*
		 * Convert distance from out prox to distance from tablet.
		 * distance will be greater than distance_max once
		 * touching and applying pressure; do not report negative
		 * distance.
		 */
		if (data[8] <= features->distance_max)
			d = features->distance_max - data[8];

		pen = data[1] & 0x01;
		btn1 = data[1] & 0x02;
		btn2 = data[1] & 0x04;
	} else {
		wacom->id[0] = 0;
	}

	input_report_key(input, BTN_TOUCH, pen);
	input_report_key(input, BTN_STYLUS, btn1);
	input_report_key(input, BTN_STYLUS2, btn2);

	input_report_abs(input, ABS_X, x);
	input_report_abs(input, ABS_Y, y);
	input_report_abs(input, ABS_PRESSURE, p);
	input_report_abs(input, ABS_DISTANCE, d);

	input_report_key(input, wacom->tool[0], prox); /* PEN or RUBBER */
	input_report_abs(input, ABS_MISC, wacom->id[0]); /* TOOL ID */

	if (!prox)
		wacom->tool[0] = 0;

	return 1;

}

static void wacom_bpt3_touch_msg(struct wacom_wac *wacom, void *wcombo,
				 unsigned char *data)
{
	struct wacom_features *features = &wacom->features;
	bool touch = data[1] & 0x80;
	int slot = wacom_mt_get_slot_by_key(wcombo, data[0]);

	if (slot < 0)
		return;

	touch = touch && !wacom->shared->stylus_in_proximity;

	wacom_mt_slot(wcombo, slot);
	wacom_mt_report_slot_state(wcombo, MT_TOOL_FINGER, touch);

	if (touch) {
		int x = (data[2] << 4) | (data[4] >> 4);
		int y = (data[3] << 4) | (data[4] & 0x0f);
		int width = 0, height = 0;

		if (features->type >= INTUOS5S && features->type <= INTUOSHT) {
			width  = data[5];
			height = data[6];
		}

		wacom_report_abs(wcombo, ABS_MT_POSITION_X, x);
		wacom_report_abs(wcombo, ABS_MT_POSITION_Y, y);
		wacom_report_abs(wcombo, ABS_MT_TOUCH_MAJOR, width);
		wacom_report_abs(wcombo, ABS_MT_TOUCH_MINOR, height);
	}
}

static void wacom_bpt3_button_msg(struct wacom_wac *wacom, void *wcombo,
				  unsigned char *data)
{
	struct wacom_features *features = &wacom->features;

	if (features->type == INTUOSHT) {
		wacom_report_key(wcombo, BTN_LEFT, (data[1] & 0x02) != 0);
		wacom_report_key(wcombo, BTN_BACK, (data[1] & 0x08) != 0);
	} else {
		wacom_report_key(wcombo, BTN_BACK, (data[1] & 0x02) != 0);
		wacom_report_key(wcombo, BTN_LEFT, (data[1] & 0x08) != 0);
	}
        wacom_report_key(wcombo, BTN_FORWARD, (data[1] & 0x04) != 0);
        wacom_report_key(wcombo, BTN_RIGHT, (data[1] & 0x01) != 0);
}

static int wacom_bpt3_touch(struct wacom_wac *wacom, void *wcombo)
{
	unsigned char *data = wacom->data;
	int count = data[1] & 0x07;
	int touch_changed = 0, i;

	if (data[0] != 0x02)
		return 0;

	/* data has up to 7 fixed sized 8-byte messages starting at data[2] */
	for (i = 0; i < count; i++) {
		int offset = (8 * i) + 2;
		int msg_id = data[offset];

		if (msg_id >= 2 && msg_id <= 17) {
			wacom_bpt3_touch_msg(wacom, wcombo, data + offset);
			touch_changed++;
		}
		else if (msg_id == 128)
			wacom_bpt3_button_msg(wacom, wcombo, data + offset);
	}
	if (touch_changed) {
		wacom_mt_report_pointer_emulation(wcombo, true);
		wacom->shared->touch_down = wacom_wac_finger_count_touches(wcombo);
	}

	wacom_input_sync(wcombo);

	return 0;
}

static int wacom_bpt_irq(struct wacom_wac *wacom, void *wcombo)
{
	struct wacom_combo *wc = wcombo;
	int len = wc->urb->actual_length;

	if (len == WACOM_PKGLEN_BBTOUCH3)
		return wacom_bpt3_touch(wacom, wcombo);

	return wacom_bpt_pen(wacom, wc);
}

static int wacom_wireless_irq(struct wacom_wac *wacom, size_t len,
			      void *wcombo)
{
	unsigned char *data = wacom->data;
	int connected;

	if (len != WACOM_PKGLEN_WIRELESS || data[0] != WACOM_REPORT_WL)
		return 0;

	connected = data[1] & 0x01;
	if (connected) {
		int pid;

		pid = get_unaligned_be16(&data[6]);
		if (wacom->pid != pid) {
			wacom->pid = pid;
			wacom_schedule_work(wcombo);
		}
	} else if (wacom->pid != 0) {
		/* disconnected while previously connected */
		wacom->pid = 0;
		wacom_schedule_work(wcombo);
	}

	return 0;
}

int wacom_wac_irq(struct wacom_wac *wacom_wac, void *wcombo)
{
	struct urb *urb = ((struct wacom_combo *)wcombo)->urb;
	int len = urb->actual_length;

	switch (wacom_wac->features.type) {
		case PENPARTNER:
			return wacom_penpartner_irq(wacom_wac, wcombo);

		case PL:
			return wacom_pl_irq(wacom_wac, wcombo);

		case WACOM_G4:
		case GRAPHIRE:
		case WACOM_MO:
			return wacom_graphire_irq(wacom_wac, wcombo);

		case PTU:
			return wacom_ptu_irq(wacom_wac, wcombo);

		case DTU:
			return wacom_dtu_irq(wacom_wac, wcombo);

		case INTUOS5S:
		case INTUOS5:
		case INTUOS5L:
		case INTUOSPS:
		case INTUOSPM:
		case INTUOSPL:
			if (len == WACOM_PKGLEN_BBTOUCH3)
				return wacom_bpt3_touch(wacom_wac, wcombo);
			else
				return wacom_intuos_irq(wacom_wac, wcombo);
			break;

		case WACOM_24HDT:
		case WACOM_27QHDT:
			return wacom_24hdt_irq(wacom_wac, wcombo);

		case INTUOS:
		case INTUOS3S:
		case INTUOS3:
		case INTUOS3L:
		case INTUOS4S:
		case INTUOS4:
		case INTUOS4L:
		case CINTIQ:
		case WACOM_BEE:
		case WACOM_21UX2:
		case WACOM_22HD:
		case WACOM_24HD:
		case WACOM_27QHD:
			return wacom_intuos_irq(wacom_wac, wcombo);

		case TABLETPC:
		case TABLETPC2FG:
		case MTSCREEN:
			return wacom_tpc_irq(wacom_wac, wcombo);
		case BAMBOO_PT:
		case INTUOSHT:
			return wacom_bpt_irq(wacom_wac, wcombo);

		case WIRELESS:
			return wacom_wireless_irq(wacom_wac, len, wcombo);

		case REMOTE:
			if (wacom_wac->data[0] == WACOM_REPORT_DEVICE_LIST)
				return wacom_remote_status_irq(wacom_wac, len, wcombo);
			else
				return wacom_remote_irq(wacom_wac, len, wcombo);
			break;

		default:
			return 0;
	}
	return 0;
}

int wacom_init_input_dev(struct input_dev *input_dev, struct wacom_wac *wacom_wac)
{
	struct wacom_features *features = &wacom_wac->features;
	int rc;

	switch (features->type) {
		case WACOM_MO:
			input_dev_mo(input_dev, wacom_wac);
		case WACOM_G4:
			input_dev_g4(input_dev, wacom_wac);
			/* fall through */
		case GRAPHIRE:
			input_dev_g(input_dev, wacom_wac);
			break;
		case WACOM_27QHD:
			input_dev_cintiq27qhd(input_dev, wacom_wac);
			/* fall through */
		case WACOM_24HD:
			input_dev_24hd(input_dev, wacom_wac);
			break;
		case WACOM_22HD:
			input_dev_c22hd(input_dev, wacom_wac);
			/* fall through */
		case WACOM_21UX2:
			input_dev_c21ux2(input_dev, wacom_wac);
			/* fall through */
		case WACOM_BEE:
			input_dev_bee(input_dev, wacom_wac);
                        /* fall through */
		case INTUOS3:
		case INTUOS3L:
			input_dev_i3(input_dev, wacom_wac);
			/* fall through */
		case INTUOS3S:
			input_dev_i3s(input_dev, wacom_wac);
			/* fall through */
		case INTUOS:
			input_dev_i(input_dev, wacom_wac);
			break;
		case INTUOSPM:
		case INTUOSPL:
			input_dev_ipro(input_dev, wacom_wac);
			/* fall through */
		case INTUOSPS:
			input_dev_ipros(input_dev, wacom_wac);
			break;
		case INTUOS5:
		case INTUOS5L:
		case INTUOS4:
		case INTUOS4L:
			input_dev_i4(input_dev, wacom_wac);
			/* fall through */
		case INTUOS5S:
		case INTUOS4S:
			rc = input_dev_i4s(input_dev, wacom_wac);
			if (rc)
				return rc;
			input_dev_i(input_dev, wacom_wac);
			break;
		case WACOM_27QHDT:
		case WACOM_24HDT:
			input_dev_24hdt(input_dev, wacom_wac);
			/* fall through */
		case TABLETPC2FG:
			rc = input_dev_tpc2fg(input_dev, wacom_wac);
			if (rc)
				return rc;
			/* fall through */
		case TABLETPC:
			input_dev_tpc(input_dev, wacom_wac);
			if (features->device_type != BTN_TOOL_PEN)
				break;  /* no need to process stylus stuff */

			/* fall through */
		case PL:
		case PTU:
		case DTU:
			input_dev_pl(input_dev, wacom_wac);
			/* fall through */
		case PENPARTNER:
			input_dev_pt(input_dev, wacom_wac);
			break;
                case CINTIQ:
                        input_dev_cintiq(input_dev, wacom_wac);
                        break;
		case BAMBOO_PT:
		case INTUOSHT:
			input_dev_bamboo_pt(input_dev, wacom_wac);
			break;
		case REMOTE:
			input_dev_remote(input_dev, wacom_wac);
	}
	return 0;
}

static struct wacom_features wacom_features[] = {
	{ "Wacom Penpartner",    WACOM_PKGLEN_PENPRTN,   5040,  3780,  255,  0, PENPARTNER },
	{ "Wacom Graphire",      WACOM_PKGLEN_GRAPHIRE,  10206,  7422,  511, 63, GRAPHIRE },
	{ "Wacom Graphire2 4x5", WACOM_PKGLEN_GRAPHIRE,  10206,  7422,  511, 63, GRAPHIRE },
	{ "Wacom Graphire2 5x7", WACOM_PKGLEN_GRAPHIRE,  13918, 10206,  511, 63, GRAPHIRE },
	{ "Wacom Graphire3",     WACOM_PKGLEN_GRAPHIRE,  10208,  7424,  511, 63, GRAPHIRE },
	{ "Wacom Graphire3 6x8", WACOM_PKGLEN_GRAPHIRE,  16704, 12064,  511, 63, GRAPHIRE },
	{ "Wacom Graphire4 4x5", WACOM_PKGLEN_GRAPHIRE,  10208,  7424,  511, 63, WACOM_G4 },
	{ "Wacom Graphire4 6x8", WACOM_PKGLEN_GRAPHIRE,  16704, 12064,  511, 63, WACOM_G4 },
	{ "Wacom BambooFun 4x5", WACOM_PKGLEN_BBFUN,  14760,  9225,  511, 63, WACOM_MO },
	{ "Wacom BambooFun 6x8", WACOM_PKGLEN_BBFUN,  21648, 13530,  511, 63, WACOM_MO },
	{ "Wacom Bamboo1 Medium",WACOM_PKGLEN_GRAPHIRE,  16704, 12064,  511, 63, GRAPHIRE },
	{ "Wacom Volito",        WACOM_PKGLEN_GRAPHIRE,   5104,  3712,  511, 63, GRAPHIRE },
	{ "Wacom PenStation2",   WACOM_PKGLEN_GRAPHIRE,   3250,  2320,  255, 63, GRAPHIRE },
	{ "Wacom Volito2 4x5",   WACOM_PKGLEN_GRAPHIRE,   5104,  3712,  511, 63, GRAPHIRE },
	{ "Wacom Volito2 2x3",   WACOM_PKGLEN_GRAPHIRE,   3248,  2320,  511, 63, GRAPHIRE },
	{ "Wacom PenPartner2",   WACOM_PKGLEN_GRAPHIRE,   3250,  2320,  511, 63, GRAPHIRE },
	{ "Wacom Bamboo",        WACOM_PKGLEN_BBFUN,  14760,  9225,  511, 63, WACOM_MO },
	{ "Wacom Bamboo1",       WACOM_PKGLEN_GRAPHIRE,   5104,  3712,  511, 63, GRAPHIRE },
	{ "Wacom Intuos 4x5",    WACOM_PKGLEN_INTUOS,  12700, 10600, 1023, 31, INTUOS },
	{ "Wacom Intuos 6x8",    WACOM_PKGLEN_INTUOS,  20320, 16240, 1023, 31, INTUOS },
	{ "Wacom Intuos 9x12",   WACOM_PKGLEN_INTUOS,  30480, 24060, 1023, 31, INTUOS },
	{ "Wacom Intuos 12x12",  WACOM_PKGLEN_INTUOS,  30480, 31680, 1023, 31, INTUOS },
	{ "Wacom Intuos 12x18",  WACOM_PKGLEN_INTUOS,  45720, 31680, 1023, 31, INTUOS },
	{ "Wacom PL400",         WACOM_PKGLEN_GRAPHIRE,   5408,  4056,  255,  0, PL },
	{ "Wacom PL500",         WACOM_PKGLEN_GRAPHIRE,   6144,  4608,  255,  0, PL },
	{ "Wacom PL600",         WACOM_PKGLEN_GRAPHIRE,   6126,  4604,  255,  0, PL },
	{ "Wacom PL600SX",       WACOM_PKGLEN_GRAPHIRE,   6260,  5016,  255,  0, PL },
	{ "Wacom PL550",         WACOM_PKGLEN_GRAPHIRE,   6144,  4608,  511,  0, PL },
	{ "Wacom PL800",         WACOM_PKGLEN_GRAPHIRE,   7220,  5780,  511,  0, PL },
	{ "Wacom PL700",         WACOM_PKGLEN_GRAPHIRE,   6758,  5406,  511,  0, PL },
	{ "Wacom PL510",         WACOM_PKGLEN_GRAPHIRE,   6282,  4762,  511,  0, PL },
	{ "Wacom DTU710",        WACOM_PKGLEN_GRAPHIRE,  34080, 27660,  511,  0, PL },
	{ "Wacom DTF521",        WACOM_PKGLEN_GRAPHIRE,   6282,  4762,  511,  0, PL },
	{ "Wacom DTF720",        WACOM_PKGLEN_GRAPHIRE,   6858,  5506,  511,  0, PL },
	{ "Wacom DTF720a",       WACOM_PKGLEN_GRAPHIRE,   6858,  5506,  511,  0, PL },
	{ "Wacom Cintiq Partner",WACOM_PKGLEN_GRAPHIRE,  20480, 15360,  511,  0, PTU },
	{ "Wacom Intuos2 4x5",   WACOM_PKGLEN_INTUOS, 12700, 10600, 1023, 31, INTUOS },
	{ "Wacom Intuos2 6x8",   WACOM_PKGLEN_INTUOS, 20320, 16240, 1023, 31, INTUOS },
	{ "Wacom Intuos2 9x12",  WACOM_PKGLEN_INTUOS, 30480, 24060, 1023, 31, INTUOS },
	{ "Wacom Intuos2 12x12", WACOM_PKGLEN_INTUOS, 30480, 31680, 1023, 31, INTUOS },
	{ "Wacom Intuos2 12x18", WACOM_PKGLEN_INTUOS, 45720, 31680, 1023, 31, INTUOS },
	{ "Wacom Intuos3 4x5",   WACOM_PKGLEN_INTUOS, 25400, 20320, 1023, 63, INTUOS3S },
	{ "Wacom Intuos3 6x8",   WACOM_PKGLEN_INTUOS, 40640, 30480, 1023, 63, INTUOS3 },
	{ "Wacom Intuos3 9x12",  WACOM_PKGLEN_INTUOS, 60960, 45720, 1023, 63, INTUOS3 },
	{ "Wacom Intuos3 12x12", WACOM_PKGLEN_INTUOS, 60960, 60960, 1023, 63, INTUOS3L },
	{ "Wacom Intuos3 12x19", WACOM_PKGLEN_INTUOS, 97536, 60960, 1023, 63, INTUOS3L },
	{ "Wacom Intuos3 6x11",  WACOM_PKGLEN_INTUOS, 54204, 31750, 1023, 63, INTUOS3 },
	{ "Wacom Intuos3 4x6",   WACOM_PKGLEN_INTUOS, 31496, 19685, 1023, 63, INTUOS3S },
	{ "Wacom Intuos4 4x6",   WACOM_PKGLEN_INTUOS, 31496, 19685, 2047, 63, INTUOS4S },
	{ "Wacom Intuos4 6x9",   WACOM_PKGLEN_INTUOS, 44704, 27940, 2047, 63, INTUOS4 },
	{ "Wacom Intuos4 8x13",  WACOM_PKGLEN_INTUOS, 65024, 40640, 2047, 63, INTUOS4L },
	{ "Wacom Intuos4 12x19", WACOM_PKGLEN_INTUOS, 97536, 60960, 2047, 63, INTUOS4L },
	{ "Wacom Intuos4 WL",    WACOM_PKGLEN_INTUOS, 40840, 25400, 2047, 63, INTUOS4 },
	{ "Wacom Cintiq 21UX",   WACOM_PKGLEN_INTUOS, 87200, 65600, 1023, 63, CINTIQ },
	{ "Wacom Cintiq 20WSX",  WACOM_PKGLEN_INTUOS, 86680, 54180, 1023, 63, WACOM_BEE },
	{ "Wacom Cintiq 12WX",   WACOM_PKGLEN_INTUOS, 53020, 33440, 1023, 63, WACOM_BEE },
	{ "Wacom DTU1931",       WACOM_PKGLEN_GRAPHIRE, 37832, 30305,  511,  0, PL },
	{ "Wacom Cintiq 21UX2",  WACOM_PKGLEN_INTUOS, 87200, 65600, 2047, 63, WACOM_21UX2,
		.x_min = WACOM_CINTIQ_OFFSET, .y_min = WACOM_CINTIQ_OFFSET, },
	{ "Wacom ISDv4 90",      WACOM_PKGLEN_GRAPHIRE, 26202, 16325,  255,  0, TABLETPC },
	{ "Wacom ISDv4 93",      WACOM_PKGLEN_GRAPHIRE, 26202, 16325,  255,  0, TABLETPC },
	{ "Wacom ISDv4 9A",      WACOM_PKGLEN_GRAPHIRE, 26202, 16325,  255,  0, TABLETPC },
	{ "Wacom Intuos2 6x8",   WACOM_PKGLEN_INTUOS, 20320, 16240, 1023, 31, INTUOS },
	{ "Wacom DTU2231",       WACOM_PKGLEN_GRAPHIRE, 47864, 27011,  511,  0, DTU },
	{ "Wacom DTU1631",       WACOM_PKGLEN_GRAPHIRE, 34623, 19553,  511,  0, DTU },
	{ "Wacom Cintiq 24HD",   WACOM_PKGLEN_INTUOS,104480, 65600, 2047, 63, WACOM_24HD,
		.x_min = WACOM_CINTIQ_OFFSET, .y_min = WACOM_CINTIQ_OFFSET, },
	{ "Wacom Intuos5 touch S", WACOM_PKGLEN_INTUOS,31496,19685, 2047, 63, INTUOS5S,
	  .touch_max = 16 },
	{ "Wacom Intuos5 touch M", WACOM_PKGLEN_INTUOS,44704,27940, 2047, 63, INTUOS5,
	  .touch_max = 16 },
	{ "Wacom Intuos5 touch L", WACOM_PKGLEN_INTUOS,65024,40640, 2047, 63, INTUOS5L,
	  .touch_max = 16 },
	{ "Wacom Intuos5 S",     WACOM_PKGLEN_INTUOS, 31496, 19685, 2047, 63, INTUOS5S },
	{ "Wacom Intuos5 M",     WACOM_PKGLEN_INTUOS, 44704, 27940, 2047, 63, INTUOS5 },
	{ "Wacom Bamboo Pen",	 WACOM_PKGLEN_BBFUN, 14720,  9200, 1023, 31, BAMBOO_PT },
	{ "Wacom Cintiq 22HD",	 WACOM_PKGLEN_INTUOS, 95840, 54260, 2047, 63, WACOM_22HD,
		.x_min = WACOM_CINTIQ_OFFSET, .y_min = WACOM_CINTIQ_OFFSET, },
	{ "Wacom ISDv4 E6",      WACOM_PKGLEN_TPC2FG, 27760, 15694,  255,  0, TABLETPC2FG,
	  .touch_max = 16 },
	{ "Wacom Intuos Pro S",  WACOM_PKGLEN_INTUOS, 31496, 19685, 2047, 63, INTUOSPS },
	{ "Wacom Intuos Pro M",  WACOM_PKGLEN_INTUOS, 44704, 27940, 2047, 63, INTUOSPM },
	{ "Wacom Intuos Pro L",  WACOM_PKGLEN_INTUOS, 65024, 40640, 2047, 63, INTUOSPL },
	{ "Wacom Wireless Receiver", WACOM_PKGLEN_WIRELESS, 0,   0,    0,  0, WIRELESS },
#if 0	/* Disabled until tested with hardware */
	{ "Wacom ISDv4 E5",      WACOM_PKGLEN_MTOUCH, 26202, 16325,  255,  0, MTSCREEN },
	{ "Wacom Cintiq 24HD touch", WACOM_PKGLEN_INTUOS,104480,65600,2047,63, WACOM_24HD,
	  .oVid = USB_VENDOR_ID_WACOM, .oPid = 0xf6, .x_min = WACOM_CINTIQ_OFFSET,
	  .y_min = WACOM_CINTIQ_OFFSET, },/* Pen */
	{ "Wacom Cintiq 24HD touch", .type = WACOM_24HDT, /* Touch */
	  .oVid = USB_VENDOR_ID_WACOM, .oPid = 0xf8, .touch_max = 10 },
#endif
	{ "Wacom Cintiq 22HDT",  WACOM_PKGLEN_INTUOS, 95840, 54260, 2047, 63, WACOM_22HD,
	  .oVid = USB_VENDOR_ID_WACOM, .oPid = 0x5e, .x_min = WACOM_CINTIQ_OFFSET,
	  .y_min = WACOM_CINTIQ_OFFSET, },
	{ "Wacom Cintiq 22HDT",  WACOM_PKGLEN_INTUOS, 95840, 54260, 2047, 63, WACOM_24HDT,
	  .oVid = USB_VENDOR_ID_WACOM, .oPid = 0x5b, .touch_max = 10 },
	/*
	 * Upstream doesn't use pktlen anymore. Using WACOM_PKGLEN_INTUOS,
	 * it can be adjusted later in the HID parsing
	 */
	{ "Wacom Cintiq 27QHD", WACOM_PKGLEN_INTUOS, 119740, 67520, 2047, 63, WACOM_27QHD,
		.x_min = WACOM_CINTIQ_OFFSET, .y_min = WACOM_CINTIQ_OFFSET, },
	{ "Wacom Cintiq 27QHD touch", WACOM_PKGLEN_INTUOS, 119740, 67520, 2047, 63, WACOM_27QHD,
	  .oVid = USB_VENDOR_ID_WACOM, .oPid = 0x32C },
	{ "Wacom Cintiq 27QHD touch", WACOM_PKGLEN_INTUOS, 119740, 67520, 2047, 63, WACOM_27QHDT,
	  .oVid = USB_VENDOR_ID_WACOM, .oPid = 0x32B, .touch_max = 10 },
	{ "Wacom Express Key Remote", WACOM_PKGLEN_WIRELESS, 1, 1, 0, 0, REMOTE },
	{ "Wacom Intuos PT S", WACOM_PKGLEN_BBPEN, 15200,  9500, 1023, 31, INTUOSHT,
	  .touch_max = 16 },
	{ "Wacom Intuos PT M", WACOM_PKGLEN_BBPEN, 21600, 13500, 1023, 31, INTUOSHT,
	  .touch_max = 16 },
	{ "Wacom Intuos S", WACOM_PKGLEN_BBPEN, 15200, 9500, 1023, 31, INTUOSHT },
	{ }
};

#define USB_DEVICE_DETAILED(prod, class, sub, proto)			\
	USB_DEVICE_AND_INTERFACE_INFO(USB_VENDOR_ID_WACOM, prod, class, \
			      sub, proto),
const struct usb_device_id wacom_ids[] = {
	{ USB_DEVICE(USB_VENDOR_ID_WACOM, 0x00) },
	{ USB_DEVICE(USB_VENDOR_ID_WACOM, 0x10) },
	{ USB_DEVICE(USB_VENDOR_ID_WACOM, 0x11) },
	{ USB_DEVICE(USB_VENDOR_ID_WACOM, 0x12) },
	{ USB_DEVICE(USB_VENDOR_ID_WACOM, 0x13) },
	{ USB_DEVICE(USB_VENDOR_ID_WACOM, 0x14) },
	{ USB_DEVICE(USB_VENDOR_ID_WACOM, 0x15) },
	{ USB_DEVICE(USB_VENDOR_ID_WACOM, 0x16) },
	{ USB_DEVICE(USB_VENDOR_ID_WACOM, 0x17) },
	{ USB_DEVICE(USB_VENDOR_ID_WACOM, 0x18) },
	{ USB_DEVICE(USB_VENDOR_ID_WACOM, 0x19) },
	{ USB_DEVICE(USB_VENDOR_ID_WACOM, 0x60) },
	{ USB_DEVICE(USB_VENDOR_ID_WACOM, 0x61) },
	{ USB_DEVICE(USB_VENDOR_ID_WACOM, 0x62) },
	{ USB_DEVICE(USB_VENDOR_ID_WACOM, 0x63) },
	{ USB_DEVICE(USB_VENDOR_ID_WACOM, 0x64) },
	{ USB_DEVICE(USB_VENDOR_ID_WACOM, 0x65) },
	{ USB_DEVICE(USB_VENDOR_ID_WACOM, 0x69) },
	{ USB_DEVICE(USB_VENDOR_ID_WACOM, 0x20) },
	{ USB_DEVICE(USB_VENDOR_ID_WACOM, 0x21) },
	{ USB_DEVICE(USB_VENDOR_ID_WACOM, 0x22) },
	{ USB_DEVICE(USB_VENDOR_ID_WACOM, 0x23) },
	{ USB_DEVICE(USB_VENDOR_ID_WACOM, 0x24) },
	{ USB_DEVICE(USB_VENDOR_ID_WACOM, 0x30) },
	{ USB_DEVICE(USB_VENDOR_ID_WACOM, 0x31) },
	{ USB_DEVICE(USB_VENDOR_ID_WACOM, 0x32) },
	{ USB_DEVICE(USB_VENDOR_ID_WACOM, 0x33) },
	{ USB_DEVICE(USB_VENDOR_ID_WACOM, 0x34) },
	{ USB_DEVICE(USB_VENDOR_ID_WACOM, 0x35) },
	{ USB_DEVICE(USB_VENDOR_ID_WACOM, 0x37) },
	{ USB_DEVICE(USB_VENDOR_ID_WACOM, 0x38) },
	{ USB_DEVICE(USB_VENDOR_ID_WACOM, 0x39) },
	{ USB_DEVICE(USB_VENDOR_ID_WACOM, 0xC4) },
	{ USB_DEVICE(USB_VENDOR_ID_WACOM, 0xC0) },
	{ USB_DEVICE(USB_VENDOR_ID_WACOM, 0xC2) },
	{ USB_DEVICE(USB_VENDOR_ID_WACOM, 0x03) },
	{ USB_DEVICE(USB_VENDOR_ID_WACOM, 0x41) },
	{ USB_DEVICE(USB_VENDOR_ID_WACOM, 0x42) },
	{ USB_DEVICE(USB_VENDOR_ID_WACOM, 0x43) },
	{ USB_DEVICE(USB_VENDOR_ID_WACOM, 0x44) },
	{ USB_DEVICE(USB_VENDOR_ID_WACOM, 0x45) },
	{ USB_DEVICE(USB_VENDOR_ID_WACOM, 0xB0) },
	{ USB_DEVICE(USB_VENDOR_ID_WACOM, 0xB1) },
	{ USB_DEVICE(USB_VENDOR_ID_WACOM, 0xB2) },
	{ USB_DEVICE(USB_VENDOR_ID_WACOM, 0xB3) },
	{ USB_DEVICE(USB_VENDOR_ID_WACOM, 0xB4) },
	{ USB_DEVICE(USB_VENDOR_ID_WACOM, 0xB5) },
	{ USB_DEVICE(USB_VENDOR_ID_WACOM, 0xB7) },
	{ USB_DEVICE(USB_VENDOR_ID_WACOM, 0xB8) },
	{ USB_DEVICE(USB_VENDOR_ID_WACOM, 0xB9) },
	{ USB_DEVICE(USB_VENDOR_ID_WACOM, 0xBA) },
	{ USB_DEVICE(USB_VENDOR_ID_WACOM, 0xBB) },
	{ USB_DEVICE(USB_VENDOR_ID_WACOM, 0xBC) },
	{ USB_DEVICE(USB_VENDOR_ID_WACOM, 0x3F) },
	{ USB_DEVICE(USB_VENDOR_ID_WACOM, 0xC5) },
	{ USB_DEVICE(USB_VENDOR_ID_WACOM, 0xC6) },
	{ USB_DEVICE(USB_VENDOR_ID_WACOM, 0xC7) },
	{ USB_DEVICE(USB_VENDOR_ID_WACOM, 0xCC) },
	{ USB_DEVICE(USB_VENDOR_ID_WACOM, 0x90) },
	{ USB_DEVICE(USB_VENDOR_ID_WACOM, 0x93) },
	{ USB_DEVICE(USB_VENDOR_ID_WACOM, 0x9A) },
	{ USB_DEVICE(USB_VENDOR_ID_WACOM, 0x47) },
	/*
	 * DTU-2231 has two interfaces on the same configuration, only one is
 	 * used
 	 */
	{ USB_DEVICE_DETAILED(0xCE, USB_CLASS_HID,
			      USB_INTERFACE_SUBCLASS_BOOT,
			      USB_INTERFACE_PROTOCOL_MOUSE) },
	{ USB_DEVICE(USB_VENDOR_ID_WACOM, 0xF0) },
	{ USB_DEVICE(USB_VENDOR_ID_WACOM, 0xF4) },
	{ USB_DEVICE(USB_VENDOR_ID_WACOM, 0x26) },
	{ USB_DEVICE(USB_VENDOR_ID_WACOM, 0x27) },
	{ USB_DEVICE(USB_VENDOR_ID_WACOM, 0x28) },
	{ USB_DEVICE_DETAILED(0x29, USB_CLASS_HID,
			      USB_INTERFACE_SUBCLASS_BOOT,
			      USB_INTERFACE_PROTOCOL_MOUSE) },
	{ USB_DEVICE_DETAILED(0x2A, USB_CLASS_HID,
			      USB_INTERFACE_SUBCLASS_BOOT,
			      USB_INTERFACE_PROTOCOL_MOUSE) },
	{ USB_DEVICE_DETAILED(0xD4, USB_CLASS_HID,
			      USB_INTERFACE_SUBCLASS_BOOT,
			      USB_INTERFACE_PROTOCOL_MOUSE) },
	{ USB_DEVICE_DETAILED(0xFA, USB_CLASS_HID,
			      USB_INTERFACE_SUBCLASS_BOOT,
			      USB_INTERFACE_PROTOCOL_MOUSE) },
	{ USB_DEVICE(USB_VENDOR_ID_WACOM, 0xE6) },
	{ USB_DEVICE_DETAILED(0x314, USB_CLASS_HID, 0, 0) },
	{ USB_DEVICE_DETAILED(0x315, USB_CLASS_HID, 0, 0) },
	{ USB_DEVICE_DETAILED(0x317, USB_CLASS_HID, 0, 0) },
	{ USB_DEVICE(USB_VENDOR_ID_WACOM, 0x84) },
#if 0	/* Disabled until tested with hardware */
	{ USB_DEVICE(USB_VENDOR_ID_WACOM, 0xE5) },
	{ USB_DEVICE_WACOM(0xF8) },
	{ USB_DEVICE_WACOM(0xF6) },
#endif
	{ USB_DEVICE(USB_VENDOR_ID_WACOM, 0x5B) },
	{ USB_DEVICE_DETAILED(0x5E, USB_CLASS_HID, 0, 0) },
	{ USB_DEVICE(USB_VENDOR_ID_WACOM, 0x32A) },
	{ USB_DEVICE(USB_VENDOR_ID_WACOM, 0x32B) },
	{ USB_DEVICE(USB_VENDOR_ID_WACOM, 0x32C) },
	{ USB_DEVICE(USB_VENDOR_ID_WACOM, 0x331) },
	{ USB_DEVICE_DETAILED(0x302, USB_CLASS_HID, 0, 0) },
	{ USB_DEVICE_DETAILED(0x303, USB_CLASS_HID, 0, 0) },
	{ USB_DEVICE_DETAILED(0x30E, USB_CLASS_HID, 0, 0) },
	{ }
};

const struct usb_device_id *get_device_table(void)
{
        const struct usb_device_id *id_table = wacom_ids;

        return id_table;
}

struct wacom_features * get_wacom_feature(const struct usb_device_id *id)
{
        int index = id - wacom_ids;
        struct wacom_features *wf = &wacom_features[index];

        return wf;
}

MODULE_DEVICE_TABLE(usb, wacom_ids);
