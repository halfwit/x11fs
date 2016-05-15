#include "win_oper.h"
#include "win_xcb.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <syslog.h>
#include "x11fs.h"

//Specific read and write functions for each file

void border_color_write(int wid, const char *buf)
{
	errno = 0;
	long color = strtol(buf, NULL, 16);
	int errsv = errno;
	if ( errsv ) {
		syslog(LOG_ERR, "failed to parse color in %s: %s\n", __func__, strerror(errsv));
	}

	set_border_color(wid, color);
}

#define DECLARE_NORM_READER(cat, prop, getter) \
	char * cat##_##prop##_read (int wid) {\
		int i = getter(wid);\
		if ( i == -1 ) {\
			errno = -EIO;\
			return NULL;\
		}\
		\
		char * str = malloc(snprintf(NULL, 0, "%d\n", i) + 1);\
		if ( !str ) {\
			syslog(LOG_ERR, "failed to allocate in %s: %s\n", __func__, strerror(ENOMEM));\
		}\
		\
		if ( sprintf(str, "%d\n", i) < 0 ) {\
			syslog(LOG_ERR, "failed to store value in %s\n", __func__);\
		}\
		\
		return str;\
	}

DECLARE_NORM_READER(border,   width,  get_border_width);
DECLARE_NORM_READER(geometry, width,  get_width);
DECLARE_NORM_READER(geometry, height, get_height);
DECLARE_NORM_READER(geometry, x,      get_x);
DECLARE_NORM_READER(geometry, y,      get_y);

#define DECLARE_NORM_WRITER(cat, prop, setter) \
	void cat##_##prop##_write (int wid, const char * buf) {\
		setter(wid, atoi(buf));\
	}

DECLARE_NORM_WRITER(border,   width,  set_border_width);
DECLARE_NORM_WRITER(geometry, width,  set_width);
DECLARE_NORM_WRITER(geometry, height, set_height);
DECLARE_NORM_WRITER(geometry, x,      set_x);
DECLARE_NORM_WRITER(geometry, y,      set_y);

char *root_width_read(int wid)
{
	(void) wid;
	return geometry_width_read(-1);
}

char *root_height_read(int wid)
{
	(void) wid;
	return geometry_height_read(-1);
}

char *mapped_read(int wid)
{
	return strdup(get_mapped(wid) ? "true\n" : "false\n");
}

void mapped_write(int wid, const char *buf)
{
	set_mapped(wid, !strcmp(buf, "true\n"));
}

char *ignored_read(int wid)
{
	return strdup(get_ignored(wid) ? "true\n" : "false\n");
}

void ignored_write(int wid, const char *buf)
{
	set_ignored(wid, !strcmp(buf, "true\n"));
}

void stack_write(int wid, const char *buf)
{
	if(!strcmp(buf, "raise\n"))
		raise(wid);
	if(!strcmp(buf, "lower\n"))
		lower(wid);
}

char *title_read(int wid)
{
	char *title=get_title(wid);
	size_t title_len = strlen(title);
	char *title_string=malloc(title_len+2);
	if ( !title_string ) {
		syslog(LOG_ERR, "failed to allocate in %s: %s\n", __func__, strerror(ENOMEM));
	}

	memset(title_string, 0, title_len+2);
	if ( title_len && sprintf(title_string, "%s\n", title) < 0 ) {
		syslog(LOG_ERR, "failed to store title string in %s\n", __func__);
	}

	free(title);
	return title_string;
}

char *class_read(int wid)
{
	char **classes=get_class(wid);
	size_t class0_len = strlen(classes[0]), class1_len = strlen(classes[1]);
	char *class_string=malloc(class0_len + class1_len + 3);
	if ( !class_string ) {
		syslog(LOG_ERR, "failed to allocate in %s: %s\n", __func__, strerror(ENOMEM));
	}

	if ( class0_len && sprintf(class_string, "%s\n", classes[0]) < 0) {
		syslog(LOG_ERR, "failed to store first class in %s\n", __func__);
	}
	if ( class1_len && sprintf(class_string + class0_len + 1, "%s\n", classes[1]) < 0) {
		syslog(LOG_ERR, "failed to store second class in %s\n", __func__);
	}

	free(classes[0]);
	free(classes[1]);
	free(classes);
	return class_string;
}

char *event_read(int wid)
{
  (void) wid;
	return get_events();
}

char *focused_read(int wid)
{
	(void) wid;
	int focusedid=focused();
	char * focusedwin = malloc(focusedid ? WID_STRING_LENGTH + 1 : 6);
	if ( !focusedwin ) {
		syslog(LOG_ERR, "failed to allocate in %s: %s\n", __func__, strerror(ENOMEM));
	}

	int stat = 0;
	if ( !focusedid ) {
		stat = sprintf(focusedwin, "root\n");
	} else {
		stat = sprintf(focusedwin, "0x%08x\n", focusedid);
	}

	if ( stat < 0 ) {
		syslog(LOG_ERR, "failed to store focused window in %s\n", __func__);
	}

	return focusedwin;
}

void focused_write(int wid, const char *buf)
{
	(void) wid;
	errno = 0;
	long id = strtol(buf, NULL, 16);
	int errsv = errno;
	if ( errsv ) {
		syslog(LOG_ERR, "failed to parse id to focus in %s: %s\n", __func__, strerror(errsv));
	}

	focus(id);
}


/* Search if needle s1 exists in haystack s2 */

int search_str(char * s1, char * s2) {
  char * token;
  while((token = strtok(s2, "\n")))
  {
    if (strcmp(token, s1)) 
      return 1;
  }
  return 0;
}


/* Return wid _GROUP atom: */

char *window_group_read(int wid) 
{ 
  return get_window_group(wid); 
}


/* Set windows group ATOM: 
 * If mapped and string is not in _ACTIVE, append string
 * If unmapped and string is not in _INACTIVE, append string
 * Set wid _GROUP atom to buf 
 */

void window_group_write(int wid, const char *buf) 
{ 
  char * groups = get_mapped(wid) ? get_active_groups() : get_inactive_groups();
  if(search_str(strdup(buf), groups)) {
    char * reply = malloc(snprintf(NULL, 0, "%s%s", groups, buf)+1);
    sprintf(reply, "%s%s", groups, buf);
    set_active_groups(reply);
    free(reply);
  }
  set_window_group(wid, buf);
}


/* Remove false entries:  
 * groups in active or inactive that don't map to real windows 
 * groups in active that map to inactive windows
 * groups in inactive that map to active windows 
 */

void clean_atoms()
{
 
}


/* Read root window _ACTIVE atom: */

char *active_groups_read(int wid)
{
  (void) wid;
  clean_atoms();
  return get_active_groups();
}


/* Set root window _ACTIVE atom:
 * If window is mapped but isn't on this list, unmap it. 
 * If window is unmapped but is on this list, map it 
 */

void active_groups_write(int wid, const char *buf)
{
 
  int * windows = list_windows();
  while((wid=*(windows++))) {
    if(get_mapped(wid)) {
      if(!search_str(get_window_group(wid), get_active_groups()))
        set_mapped(wid, "false\n");
    } else {
      if(search_str(get_window_group(wid), get_active_groups()))
        set_mapped(wid, "true\n");
    }
  }
  clean_atoms();
  set_active_groups(buf);
}


/* Return root window _INACTIVE atom: */

char *inactive_groups_read(int wid)
{
  (void) wid;
  clean_atoms();
  return get_inactive_groups();
}
