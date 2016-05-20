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

/* Search if needle s1 exists in haystack s2 
 * if we reach a control char, exit loop 0, if two chars don't match exit loop 1
 */

int search_str(char * s1, const char * s2) {
  /* If our query is longer than the groups array */
  if(strlen(s1) > strlen(s2))
    return 0;
  for (unsigned long i = 0; i < strlen(s1); i++) {
    if(s1[i] == '\n' || s1[i] == '\0' || s2[i] == '\n' || s2[i] == '\0')
      return 1;
    if(s1[i] != s2[i])
      return 0;
  }
  return 1;
}


/* Return wid _GROUP atom: */

char *window_group_read(int wid) 
{ 
  return get_window_group(wid); 
}


/* Set windows group ATOM: 
 * Set wid _GROUP atom to buf 
 */

void window_group_write(int wid, const char *buf) 
{ 
  set_window_group(wid, buf);
}

char *append(char *s1, char *s2) {
  if (strlen(s1) < 1)
    return strdup(s2);
  unsigned long maxsize = 20;
  char *reply = malloc(maxsize);
  if(strlen(s1)+strlen(s2) >= maxsize)
    reply = realloc(reply, maxsize*2);
  for(unsigned long i = 0; i < strlen(s1); i++) {
    reply[i] = s1[i];
  }
  reply[strlen(s1)] = '\n';
  for(unsigned long i = 0; i < strlen(s2); i++) {
    reply[strlen(s1)+i+1] = s2[i];
  }
  reply[strlen(s1)+strlen(s2)+1] = '\0';
  
  return strdup(reply);
}

char *active_groups_read(int wid)
{

  (void) wid;  
  int *windows = list_windows(); 
  char * group;
  char * reply;
  while((wid=*(windows++))) {
    if((group = strtok(get_window_group(wid), " \n\t\0"))) {
      if(get_mapped(wid) && !search_str(group, reply))
        reply = append(strdup(reply), strdup(group));
    }
  }
  return strdup(reply);
}


/* Return list of inactive groups: */

char *inactive_groups_read(int wid)
{
  (void) wid;
  int *windows = list_windows();
  char * group;
  char * reply;
  while((wid=*(windows++))) {
    if((group = strtok(get_window_group(wid), " \n\t\0"))) {
      if(!get_mapped(wid))
        reply = append(strdup(reply), strdup(group));
    }
  }
  return strdup(reply);
}



void group_write(int wid, const char *buf, int map)
{
  int * windows = list_windows();
  char * group;
  while((wid=*(windows++))) {
    if((group = strtok(get_window_group(wid), " \n\t\0")) && search_str(strdup(group), strdup(buf))) {
      set_mapped(wid, map);
    }
  }
}

/* echo "4" > x11fs/inactive */
void inactive_groups_write(int wid, const char *buf)
{
  /* TODO: Sanitize input */
  group_write(wid, buf, 0);
 }

/* echo "4" > x11fs/active */

void active_groups_write(int wid, const char *buf)
{
  /* TODO: Sanitize input */
  group_write(wid, buf, 1);
}
