/*
 * rlm_raw.c
 *
 * Version:	$Id$
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 *
 * Copyright 2000,2006  The FreeRADIUS server project
 * Copyright 2000  your name <your address>
 */


#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>

#ifndef RADIUS_HDR_LEN
#define RADIUS_HDR_LEN 20
#endif

#ifndef VENDORPEC_USR
#define VENDORPEC_USR 429
#endif
/*
*/

/*
 *	Define a structure for our module configuration.
 *
 *	These variables do not need to be in a structure, but it's
 *	a lot cleaner to do so, and a pointer to the structure can
 *	be used as the instance handle.
 */
typedef struct rlm_raw_t {
	char const *name;
} rlm_raw_t;

/*
 *	A mapping of configuration file names to internal variables.
 */
static const CONF_PARSER mod_config[] = {
	{ "name", FR_CONF_OFFSET(PW_TYPE_STRING, rlm_raw_t, name), "raw" },
	CONF_PARSER_TERMINATOR
};

typedef struct radius_packet_t {
	uint8_t code;
	uint8_t id;
	uint8_t length[2];
	uint8_t vector[AUTH_VECTOR_LEN];
	uint8_t data[1];
} radius_packet_t;

/*
 *	Dynamically xlat for %{raw:...} out of the
 *	decoded RADIUS attributes of the raw packet.
 */
static ssize_t raw_xlat(void *instance, REQUEST *request, char const *fmt, char *out, size_t freespace)
{
	uint8_t strvalue[MAX_STRING_LEN];
	uint32_t lvalue;
	uint32_t vendorcode = 0;
	int attribute = 0;
	int vendorlen = 0;
	int sublen;
	int offset;
	char name[40];
	int attr;
	int type = PW_TYPE_OCTETS;
	ATTR_FLAGS flags;
	const DICT_ATTR *da;
	DICT_VALUE *dv;
	char buf[1024];
	char *a = NULL;
	radius_packet_t *hdr = (radius_packet_t *)request->packet->data;
	uint8_t *ptr = hdr->data;
	uint8_t *subptr;
	int length = request->packet->data_len - RADIUS_HDR_LEN;
	int attrlen = ptr[1];
	time_t t;
	struct tm s_tm;

	/*
	 *	The "format" string is the attribute name.
	 */
	if (!(da = dict_attrbyname(fmt)))
		return 0;
	strncpy(name, da->name, sizeof(name));
	attr = da->attr;
	type = da->type;
	flags = da->flags;

	while (length > 0) {
		if (vendorlen > 0) {
			attribute = *ptr++ | (vendorcode << 16);
			attrlen = *ptr++;
		} else {
			attribute = *ptr++;
			attrlen = *ptr++;
		}

		attrlen -= 2;
		length -= 2;

		/*
		 *	This could be a Vendor-Specific attribute.
		 */
		if ((vendorlen <= 0) && (attribute == PW_VENDOR_SPECIFIC)) {
			/* The attrlen was checked to be >= 6, in rad_recv */
			memcpy(&lvalue, ptr, 4);
			vendorcode = ntohl(lvalue);

			/*
			 *	This is an implementation issue.
			 *	We currently pack vendor into the upper
			 *	16 bits of a 32-bit attribute number,
			 *	so we can't handle vendor numbers larger
			 *	than 16 bits.
			 */
			if (vendorcode <= 65535) {
				/*
				 *	First, check to see if the
				 *	sub-attributes fill the VSA, as
				 *	defined by the RFC.  If not, then it
				 *	may be a USR-style VSA, or it may be a
				 *	vendor who packs all of the
				 *	information into one nonsense
				 *	attribute.
				 */
				subptr = ptr + 4;
				sublen = attrlen - 4;

				while (sublen > 0) {
					/* Too short or too long */
					if ((subptr[1] < 2) || (subptr[1] > sublen))
						break;

					/* Just right */
					sublen -= subptr[1];
					subptr += subptr[1];
				}

				if (!sublen) {
					ptr += 4;
					vendorlen = attrlen - 4;
					attribute = *ptr++ | (vendorcode << 16);
					attrlen = *ptr++;
					attrlen -= 2;
					length -= 6;
				} else if ((vendorcode == VENDORPEC_USR) &&
						((ptr[4] == 0) && (ptr[5] == 0)) &&
						(attrlen >= 8) &&
						(dict_attrbyvalue((vendorcode << 16) | (ptr[6] << 8) | ptr[7], 0))) {
					attribute = ((vendorcode << 16) | (ptr[6] << 8) | ptr[7]);
					ptr += 8;
					attrlen -= 8;
					length -= 8;
				}
			}
		}

		if (attribute == attr)
			break;

		ptr += attrlen;
		length -= attrlen;
		if (vendorlen > 0)
			vendorlen -= (attrlen + 2);
	}

	if (attribute != attr)
		return 0;

	switch (type) {
		/*
		 *	The attribute may be zero length,
		 *	or it may have a tag, and then no data...
		 */
		case PW_TYPE_STRING:
			offset = 0;
			if (flags.has_tag && (attrlen > 0) && (TAG_VALID_ZERO(*ptr) || (flags.encrypt == FLAG_ENCRYPT_TUNNEL_PASSWORD))) {
				attrlen--;
				offset = 1;
			}
			memcpy(strvalue, ptr + offset, attrlen);

			/*
			 *	NAS-Port may have multiple integer values?
			 *	This is an internal server extension...
			 */
			if (attribute == PW_NAS_PORT)
				a = (char *)strvalue;
			else {
               fr_prints(buf, sizeof(buf), strvalue, attrlen, 0);
				a = buf;
			}
			break;

		case PW_TYPE_OCTETS:
			/* attrlen always < MAX_STRING_LEN */
			memcpy(strvalue, ptr, attrlen);
			break;

		case PW_TYPE_INTEGER:
		case PW_TYPE_DATE:
		case PW_TYPE_IPV4_ADDR:
			/*
			 *	Check for RFC compliance.  If the
			 *	attribute isn't compliant, turn it
			 *	into a string of raw octets.
			 *
			 *	Also set the lvalue to something
			 *	which should never match anything.
			 */
			if (attrlen != 4) {
				type = PW_TYPE_OCTETS;
				memcpy(strvalue, ptr, attrlen);
				break;
			}

			memcpy(&lvalue, ptr, 4);

			if (type != PW_TYPE_IPV4_ADDR) {
				lvalue = ntohl(lvalue);

				/*
				 *	Tagged attributes of type integer have
				 *	special treatment.
				 */
				if (type == PW_TYPE_INTEGER) {
					if (flags.has_tag)
						lvalue &= 0x00ffffff;

					/*
					 *	Try to get the name for integer
					 *	attributes.
					 */
					if ((dv = dict_valbyattr(attribute, 0, lvalue)))
						a = dv->name;
					else {
						snprintf(buf, sizeof(buf), "%u", lvalue);
						a = buf;
					}
				} else {
					t = lvalue;
					strftime(buf, sizeof(buf), "%b %e %Y %H:%M:%S %Z", localtime_r(&t, &s_tm));
					a = buf;
				}
			} else
				a =(char *) ip_ntoa(buf, lvalue);
			break;

		/*
		 *	IPv6 interface ID is 8 octets long.
		 */
		case PW_TYPE_IFID:
			memcpy(strvalue, ptr, attrlen);
			if (attrlen != 8)
				type = PW_TYPE_OCTETS;
			else
				a = ifid_ntoa(buf, sizeof(buf), strvalue);
			break;

		/*
		 *	IPv6 addresses are 16 octets long.
		 */
		case PW_TYPE_IPV6_ADDR:
			memcpy(strvalue, ptr, attrlen);
			if (attrlen != 16)
				type = PW_TYPE_OCTETS;
			else
                inet_ntop(AF_INET6, strvalue, buf, sizeof(buf));
			break;

		default:
			DEBUG("rlm_raw: %s (Unknown Type %d)", name, type);
			break;
	}

	if (type == PW_TYPE_OCTETS) {
		strcpy(buf, "0x");
		a = buf + 2;
		for (t = 0; t < attrlen; t++) {
			sprintf(a, "%02x", strvalue[t]);
			a += 2;
		}
		a = buf;
	}

	strncpy(out, a?a:"UNKNOWN-TYPE", freespace);
	DEBUG2("rlm_raw: %s = %s", name, out);

	return strlen(out);
}


/*
 *	Do any per-module initialization that is separate to each
 *	configured instance of the module.  e.g. set up connections
 *	to external databases, read configuration files, set up
 *	dictionary entries, etc.
 */
static int mod_instantiate(CONF_SECTION *conf, void *instance)
{
	return 0;
}

static int mod_bootstrap(CONF_SECTION *conf, void *instance)
{
	rlm_raw_t *inst = instance;
	xlat_register(inst->name, raw_xlat, NULL, inst); 
	return 0;
}

/*
 *	Only free memory we allocated.  The strings allocated via
 *	cf_section_parse() do not need to be freed.
 */
static int mod_detach(void *instance)
{
	rlm_raw_t *inst = instance;
	xlat_unregister(inst->name, raw_xlat, instance);
	return 0;
}

/*
 *	The module name should be the only globally exported symbol.
 *	That is, everything else should be 'static'.
 *
 *	If the module needs to temporarily modify it's instantiation
 *	data, the type should be changed to RLM_TYPE_THREAD_UNSAFE.
 *	The server will then take care of ensuring that the module
 *	is single-threaded.
 */

extern module_t rlm_raw;
module_t rlm_raw = {
   .magic      = RLM_MODULE_INIT,
   .name       = "raw",
   .type       = RLM_TYPE_THREAD_SAFE,
   .inst_size  = sizeof(rlm_raw_t),
   .config     = mod_config,
   .instantiate    = mod_instantiate,
   .bootstrap    = mod_bootstrap,
   .detach     = mod_detach,
   .methods = {
       [MOD_AUTHENTICATE]  = NULL,
       [MOD_AUTHORIZE]     = NULL,
   },
};
