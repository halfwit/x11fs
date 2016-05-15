#pragma once
#include <unistd.h>

char *root_width_read(int wid);
char *root_height_read(int wid);

void border_color_write(int wid, const char *buf);

char *border_width_read(int wid);
void border_width_write(int wid, const char *buf);


char *geometry_width_read(int wid);
void geometry_width_write(int wid, const char *buf);

char *geometry_height_read(int wid);
void geometry_height_write(int wid, const char *buf);

char *geometry_x_read(int wid);
void geometry_x_write(int wid, const char *buf);

char *geometry_y_read(int wid);
void geometry_y_write(int wid, const char *buf);


char *mapped_read(int wid);
void mapped_write(int wid, const char *buf);


char *ignored_read(int wid);
void ignored_write(int wid, const char *buf);


void stack_write(int wid, const char *buf);


char *title_read(int wid);


char *class_read(int wid);


char *event_read(int wid);


char *focused_read(int wid);
void focused_write(int wid, const char *buf);


char *window_group_read(int wid);
void window_group_write(int wid, const char *buf);


char *active_groups_read(int wid);
void active_groups_write(int wid, const char *buf);


char *inactive_groups_read(int wid);
