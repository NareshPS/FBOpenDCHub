/**
 * SSP: This file has been added for System Security Project.
 * It contains the new code required for the project.
 **/

#pragma once

#define	FBHANDLER_FBLOGIN_REQ	"$FBLoginReq "
#define FBHANDLER_FBUSER		"$FBUser "

void send_FBLogin_Request(struct user_t *user);

void validate_fbuser(char *fbuser, struct user_t *user);
