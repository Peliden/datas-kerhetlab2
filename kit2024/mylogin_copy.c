/*
 * Shows user info from local pwfile.
 *  
 * Usage: userinfo username
 */

#define _XOPEN_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "pwdblib.h"   /* include header declarations for pwdblib.c */

/* Define some constants. */
#define USERNAME_SIZE (32)
#define PASSWORD_SIZE (32)
#define NOUSER (-1)

int authenticate(const char *username, const char *password) {
    struct pwdb_passwd *p = pwdb_getpwnam(username);
    if (p != NULL && strcmp(p->pw_passwd, password) == 0) {
        return 1; // Authentication successful

    } else {
        return 0; // Authentication failed
    }
}


int print_info(const char *username)
{
  struct pwdb_passwd *p = pwdb_getpwnam(username);
  if (p != NULL) {
    printf("Name: %s\n", p->pw_name);
    printf("Passwd: %s\n", p->pw_passwd);
    printf("Uid: %u\n", p->pw_uid);
    printf("Gid: %u\n", p->pw_gid);
    printf("Real name: %s\n", p->pw_gecos);
    printf("Home dir: %s\n",p->pw_dir);
    printf("Shell: %s\n", p->pw_shell);
	return 0;
  } else {
    return NOUSER;
  }
}

void read_username(char *username)
{
  printf("login: ");
  fgets(username, USERNAME_SIZE, stdin);

  /* remove the newline included by getline() */
  username[strlen(username) - 1] = '\0';
}

void read_password(char *password)
{
    printf("password: ");
    fgets(password,PASSWORD_SIZE, stdin);

    password[strlen(password) - 1] = '\0';
}

int main(int argc, char **argv)
{
  char username[USERNAME_SIZE];
  char password[32];
  int authsucc = 0;
  struct pwdb_passwd *cu = pwdb_getpwnam(username);
  
  /* 
   * Write "login: " and read user input. Copies the username to the
   * username variable.
   */
  do{  
    read_username(username);
    if (cu != NULL && cu->pw_failed > 4){
      printf("Too many failed attempts for this account. Please contact your administrator to unlock it.");
      exit(0);
    }
    read_password(password);

  /* Show user info from our local pwfile. */
    if (authenticate(username, password)) {
      printf("\nUser authenticated successfully\n");
      cu->pw_failed = 0;
      cu->pw_age++;
      if(cu->pw_age > 10){
        printf("User should update their password");
      }
      pwdb_update_user(cu);
      authsucc = 1;  
    } else {
      printf("Unknown user or incorrect password, try again.\n");
      if (cu != NULL){
        cu->pw_failed++;
        pwdb_update_user(cu);
      }
     memset(username,'\0',sizeof(username));
    } } while (authsucc == 0);
     return 0;
}