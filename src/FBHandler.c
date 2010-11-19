/**
 * SSP: This file has been added for System Security Project.
 * It contains the new code required for the project.
 **/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "main.h"
#include "network.h"
#include "FBHandler.h"


void send_FBLogin_Request(struct user_t *user)
{
	send_to_user(FBHANDLER_FBLOGIN_REQ, user);
	return;
}

/**
 * SSP: Adding handler for $FBUser command.
 **/

void validate_fbuser(char *fbuser, struct user_t *user)
{
	char *validateNickCmd	= "$ValidateNick ";
	char *command			= NULL;

	if(fbuser)
	{
		command = (char *)malloc(strlen(validateNickCmd) + strlen(fbuser) + 1);

		if(command)
		{
			strcpy(command, validateNickCmd);
			strcat(command, fbuser);
			validate_nick(command, user);
			free(command);
		}
		else
		{
			logprintf(4, "Malloc failed. validate_fbuser()");
		}
	}
}
