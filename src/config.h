#pragma once

#define MAX_HIDE_ENTITIES 255

/*
  config globals are currently defined in nootkit_main.c
  as module parameters
*/

extern char *hide_filenames[MAX_HIDE_ENTITIES];
extern int hide_filenames_count;

extern unsigned long hide_inodes[MAX_HIDE_ENTITIES];
extern int hide_inodes_count;
